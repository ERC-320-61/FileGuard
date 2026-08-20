"""Static FileGuard PDF security analysis wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import pymupdf as fitz
    import pikepdf
except ImportError:
    fitz = None
    pikepdf = None


SCANNER_VERSION = "0.1.0"
DIDIER_COMMIT = "dea6816048fb2fd3a3597f2e131449fc87f60138"
PDFID_PATH = "/opt/pdf-tools/pdfid.py"
PDFPARSER_PATH = "/opt/pdf-tools/pdf-parser.py"
MAX_INPUT_BYTES = 250 * 1024 * 1024
MAX_CHILDREN = 100
MAX_CHILD_BYTES = 50 * 1024 * 1024
MAX_TOTAL_CHILD_BYTES = 200 * 1024 * 1024
MAX_SCRIPT_BYTES = 1024 * 1024
MAX_OBJECT_DEPTH = 12
SECURITY_TOKENS = (
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/Launch",
    "/URI",
    "/EmbeddedFile",
    "/ObjStm",
    "/AcroForm",
    "/XFA",
    "/RichMedia",
    "/SubmitForm",
    "/GoToR",
)
ACTION_KEYS = {
    "/AA",
    "/OpenAction",
    "/Launch",
    "/SubmitForm",
    "/GoToR",
    "/RichMedia",
}


class UnsupportedPDFError(RuntimeError):
    pass


class EncryptedPDFError(RuntimeError):
    pass


class MalformedPDFError(RuntimeError):
    pass


class PDFToolError(RuntimeError):
    pass


class PDFResourceError(RuntimeError):
    pass


class PDFTimeoutError(RuntimeError):
    pass


def _require_tools() -> None:
    if fitz is None or pikepdf is None:
        raise PDFToolError(
            "pikepdf and PyMuPDF are required; install the pinned dependencies"
        )


def _object_ref(value: Any) -> str | None:
    try:
        number, generation = value.objgen
        if number:
            return f"{number} {generation} R"
    except Exception:
        pass
    return None


def _safe_text(value: Any, limit: int = MAX_SCRIPT_BYTES) -> str:
    try:
        if pikepdf is not None and isinstance(value, pikepdf.Stream):
            data = value.read_bytes()
            if len(data) > limit:
                data = data[:limit]
            return data.decode("utf-8", errors="replace")
        text = str(value)
        return text[:limit]
    except Exception as error:
        return f"<unavailable: {error}>"


def _walk_pdf_objects(pdf: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    javascript: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    seen_nodes: set[tuple[int, int]] = set()
    seen_results: set[tuple[str, str, str]] = set()

    def walk(value: Any, owner: str, path: str, depth: int) -> None:
        if depth > MAX_OBJECT_DEPTH:
            return
        try:
            objgen = value.objgen
            if objgen != (0, 0):
                if objgen in seen_nodes:
                    return
                seen_nodes.add(objgen)
        except Exception:
            pass

        if pikepdf is not None and isinstance(value, (pikepdf.Dictionary, pikepdf.Stream)):
            for key in value.keys():
                key_name = str(key)
                try:
                    child = value[key]
                except Exception:
                    continue
                child_path = f"{path}/{key_name.lstrip('/')}"
                child_ref = _object_ref(child) or owner
                if key_name in {"/JS", "/JavaScript"}:
                    content = _safe_text(child)
                    result_key = (child_ref, key_name, content)
                    if result_key not in seen_results:
                        seen_results.add(result_key)
                        javascript.append(
                            {
                                "object_ref": child_ref,
                                "key": key_name,
                                "path": child_path,
                                "content": content,
                            }
                        )
                if key_name == "/URI":
                    actions.append(
                        {
                            "type": "URI",
                            "object_ref": child_ref,
                            "path": child_path,
                            "target": _safe_text(child, 8192),
                        }
                    )
                elif key_name in ACTION_KEYS:
                    actions.append(
                        {
                            "type": key_name.lstrip("/"),
                            "object_ref": child_ref,
                            "path": child_path,
                            "target": _safe_text(child, 8192),
                        }
                    )
                walk(child, child_ref, child_path, depth + 1)
        elif pikepdf is not None and isinstance(value, pikepdf.Array):
            for index, child in enumerate(value):
                walk(child, _object_ref(child) or owner, f"{path}[{index}]", depth + 1)

    for index, obj in enumerate(pdf.objects):
        owner = _object_ref(obj) or f"object-index:{index}"
        walk(obj, owner, "", 0)
    return javascript, actions


def _run_tool(command: list[str], timeout_seconds: int) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise PDFTimeoutError(f"Tool timed out: {command[1]}") from error
    if result.returncode != 0:
        detail = "\n".join(
            stream.strip() for stream in (result.stdout, result.stderr) if stream.strip()
        ) or "unknown tool failure"
        raise PDFToolError(
            f"{Path(command[1]).name} failed with exit code {result.returncode}: {detail}"
        )
    return result.stdout


def _pdfid_findings(output: str) -> tuple[dict[str, int], list[dict[str, Any]]]:
    counts: dict[str, int] = {}
    structural: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(/\S+)\s+(\d+)", line)
        if match:
            counts[match.group(1)] = int(match.group(2))
        if "entropy" in line.lower():
            structural.append({"tool": "pdfid", "detail": line.strip()})
    return counts, structural


def _token_indicators(data: bytes, pdfid_counts: dict[str, int]) -> list[dict[str, Any]]:
    indicators = []
    for token in SECURITY_TOKENS:
        raw_count = data.count(token.encode("ascii"))
        count = max(raw_count, pdfid_counts.get(token, 0))
        if count:
            indicators.append(
                {
                    "indicator": token,
                    "count": count,
                    "source": "pdfid/raw-token-scan",
                }
            )
    return indicators


def _extract_children(document: Any, output_directory: Path) -> list[dict[str, Any]]:
    names = list(document.embfile_names())
    if len(names) > MAX_CHILDREN:
        raise PDFResourceError(f"Embedded child count exceeds {MAX_CHILDREN}")
    children = []
    total_bytes = 0
    if names:
        output_directory.mkdir(parents=True, exist_ok=True)
    for index, original_name in enumerate(names):
        content = document.embfile_get(original_name)
        if len(content) > MAX_CHILD_BYTES:
            raise PDFResourceError(
                f"Embedded child exceeds {MAX_CHILD_BYTES} bytes: {original_name}"
            )
        total_bytes += len(content)
        if total_bytes > MAX_TOTAL_CHILD_BYTES:
            raise PDFResourceError(
                f"Total embedded output exceeds {MAX_TOTAL_CHILD_BYTES} bytes"
            )
        safe_name = Path(str(original_name)).name or f"attachment-{index}.bin"
        output_name = f"{index:03d}-{safe_name}"
        destination = output_directory / output_name
        with destination.open("xb") as handle:
            handle.write(content)
        info = document.embfile_info(original_name) or {}
        children.append(
            {
                "original_name": str(original_name),
                "output_path": str(destination),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "source": "PyMuPDF embedded file",
                "object_ref": str(info.get("xref")) if info.get("xref") else None,
            }
        )
    return children


def _pymupdf_analysis(path: Path, output_directory: Path) -> dict[str, Any]:
    try:
        document = fitz.open(str(path))
    except Exception as error:
        raise MalformedPDFError(f"PyMuPDF could not open PDF: {error}") from error
    try:
        if document.needs_pass:
            raise EncryptedPDFError("PDF requires a password")
        metadata = {
            str(key): value
            for key, value in (document.metadata or {}).items()
            if value not in (None, "")
        }
        urls = []
        for page_number in range(document.page_count):
            for link in document.load_page(page_number).get_links():
                uri = link.get("uri")
                file_target = link.get("file")
                if uri or file_target:
                    urls.append(
                        {
                            "page": page_number + 1,
                            "uri": uri,
                            "file": file_target,
                            "kind": link.get("kind"),
                            "xref": link.get("xref"),
                        }
                    )
        embedded_files = [
            {
                "name": str(name),
                "info": document.embfile_info(name) or {},
            }
            for name in document.embfile_names()
        ]
        children = _extract_children(document, output_directory)
        return {
            "page_count": document.page_count,
            "metadata": metadata,
            "urls": urls,
            "embedded_files": embedded_files,
            "children": children,
            "repaired": bool(getattr(document, "is_repaired", False)),
        }
    finally:
        document.close()


def scan_file(
    file_path: str | Path,
    output_directory: str | Path,
    tool_timeout_seconds: int = 60,
) -> dict[str, Any]:
    _require_tools()
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Sample does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Sample is not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise PDFResourceError(f"PDF exceeds input limit of {MAX_INPUT_BYTES} bytes")
    with path.open("rb") as handle:
        data = handle.read()
    if not data.startswith(b"%PDF-"):
        raise UnsupportedPDFError("File does not begin with a PDF header")

    try:
        pdf = pikepdf.open(str(path))
    except pikepdf.PasswordError as error:
        raise EncryptedPDFError("PDF requires a password") from error
    except pikepdf.PdfError as error:
        raise MalformedPDFError(f"pikepdf could not parse PDF: {error}") from error
    except Exception as error:
        raise PDFToolError(f"pikepdf failed: {error}") from error

    try:
        pdf_version = str(pdf.pdf_version)
        object_count = len(pdf.objects)
        javascript, object_actions = _walk_pdf_objects(pdf)
        warnings = [str(item) for item in pdf.get_warnings()]
    finally:
        pdf.close()

    pdfid_output = _run_tool(
        [sys.executable, PDFID_PATH, "-e", str(path)], tool_timeout_seconds
    )
    parser_output = _run_tool(
        [sys.executable, PDFPARSER_PATH, "--stats", str(path)],
        tool_timeout_seconds,
    )
    document_result = _pymupdf_analysis(path, Path(output_directory))
    pdfid_counts, pdfid_structural = _pdfid_findings(pdfid_output)
    urls = document_result["urls"]
    for action in object_actions:
        if action["type"] == "URI":
            urls.append(
                {
                    "page": None,
                    "uri": action.get("target"),
                    "file": None,
                    "kind": "object-action",
                    "xref": action.get("object_ref"),
                }
            )
    structural = pdfid_structural
    structural.extend({"tool": "pikepdf", "detail": warning} for warning in warnings)
    if document_result["repaired"]:
        structural.append(
            {"tool": "PyMuPDF", "detail": "Document required structural repair"}
        )
    structural.append(
        {
            "tool": "pdf-parser",
            "detail": parser_output.strip()[:16384],
        }
    )
    return {
        "scanner": "pdf-analysis",
        "scanner_version": SCANNER_VERSION,
        "status": "complete",
        "analyzed": True,
        "pdf_version": pdf_version,
        "page_count": document_result["page_count"],
        "object_count": object_count,
        "encrypted": False,
        "metadata": document_result["metadata"],
        "javascript": javascript,
        "urls": urls,
        "actions": object_actions,
        "embedded_files": document_result["embedded_files"],
        "suspicious_indicators": _token_indicators(data, pdfid_counts),
        "structural_findings": structural,
        "tool_versions": {
            "pikepdf": str(pikepdf.__version__),
            "PyMuPDF": str(fitz.VersionBind),
            "pdfid.py": DIDIER_COMMIT,
            "pdf-parser.py": DIDIER_COMMIT,
        },
        "children": document_result["children"],
    }


def _error_result(status: str, error: Exception) -> dict[str, Any]:
    return {
        "scanner": "pdf-analysis",
        "scanner_version": SCANNER_VERSION,
        "status": status,
        "analyzed": False,
        "pdf_version": None,
        "page_count": None,
        "object_count": None,
        "encrypted": status == "encrypted",
        "metadata": {},
        "javascript": [],
        "urls": [],
        "actions": [],
        "embedded_files": [],
        "suspicious_indicators": [],
        "structural_findings": [],
        "tool_versions": {
            "pikepdf": str(getattr(pikepdf, "__version__", "unknown")),
            "PyMuPDF": str(getattr(fitz, "VersionBind", "unknown")),
            "pdfid.py": DIDIER_COMMIT,
            "pdf-parser.py": DIDIER_COMMIT,
        },
        "children": [],
        "error": {"code": type(error).__name__, "message": str(error)},
    }


def _timeout_handler(_signum: int, _frame: Any) -> None:
    raise PDFTimeoutError("Overall PDF analysis timeout exceeded")


def main() -> int:
    parser = argparse.ArgumentParser(description="Perform static PDF security analysis.")
    parser.add_argument("file", help="Path to the mounted PDF")
    parser.add_argument("--output-dir", default="/output")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(args.timeout)
    try:
        output = scan_file(args.file, args.output_dir, min(args.timeout, 60))
        exit_code = 0
    except EncryptedPDFError as error:
        output, exit_code = _error_result("encrypted", error), 4
    except MalformedPDFError as error:
        output, exit_code = _error_result("malformed", error), 5
    except UnsupportedPDFError as error:
        output, exit_code = _error_result("unsupported", error), 3
    except (PDFTimeoutError, PDFResourceError) as error:
        output, exit_code = _error_result("resource_error", error), 6
    except Exception as error:
        output, exit_code = _error_result("error", error), 2
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    print(json.dumps(output, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
