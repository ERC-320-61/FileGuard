"""Thin FileGuard wrapper around upstream oletools."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

try:
    import olefile
    import oletools
    from oletools import crypto
    from oletools.olevba import VBA_Parser
except ImportError:
    olefile = None
    oletools = None
    crypto = None
    VBA_Parser = None


SCANNER_VERSION = "0.1.0"
MAX_RELATIONSHIP_BYTES = 5 * 1024 * 1024


def oletools_version() -> str:
    try:
        return version("oletools")
    except PackageNotFoundError:
        return "unknown"


class UnsupportedOfficeFileError(RuntimeError):
    """Raised when the sample is not a supported Office container."""


class OfficeScannerError(RuntimeError):
    """Raised when an upstream analysis component fails."""


def _require_tools() -> None:
    if any(tool is None for tool in (olefile, oletools, crypto, VBA_Parser)):
        raise OfficeScannerError(
            "oletools is unavailable; install the pinned scanner requirements"
        )


def _ole_stream_names(path: Path) -> list[str]:
    if olefile is None:
        raise OfficeScannerError("olefile is unavailable")
    try:
        with olefile.OleFileIO(str(path)) as container:
            return ["/".join(parts) for parts in container.listdir()]
    except Exception as error:
        raise OfficeScannerError(f"Unable to inspect OLE container: {error}") from error


def detect_document_type(path: Path) -> str:
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                names = {name.lower() for name in archive.namelist()}
        except (OSError, zipfile.BadZipFile) as error:
            raise OfficeScannerError(f"Unable to inspect OOXML container: {error}") from error
        macro_enabled = any(name.endswith("/vbaproject.bin") for name in names)
        if any(name.startswith("word/") for name in names):
            return "docm" if macro_enabled else "docx"
        if any(name.startswith("xl/") for name in names):
            return "xlsm" if macro_enabled else "xlsx"
        if any(name.startswith("ppt/") for name in names):
            return "pptm" if macro_enabled else "pptx"
        raise UnsupportedOfficeFileError("ZIP file is not a recognized Office document")

    if olefile is not None and olefile.isOleFile(str(path)):
        streams = {name.lower() for name in _ole_stream_names(path)}
        if "encryptedpackage" in streams and "encryptioninfo" in streams:
            return "encrypted_office"
        if "worddocument" in streams:
            return "doc"
        if "workbook" in streams or "book" in streams:
            return "xls"
        if "powerpoint document" in streams:
            return "ppt"
        raise UnsupportedOfficeFileError(
            "OLE file is not a recognized Word, Excel, or PowerPoint document"
        )

    raise UnsupportedOfficeFileError("File is not a supported Office container")


def detect_encryption(path: Path) -> bool:
    if crypto is None:
        raise OfficeScannerError("oletools.crypto is unavailable")
    try:
        return bool(crypto.is_encrypted(str(path)))
    except Exception as error:
        raise OfficeScannerError(f"Encryption inspection failed: {error}") from error


def _finding_severity(kind: str) -> str:
    normalized = kind.lower()
    if normalized == "autoexec":
        return "high"
    if normalized in {"suspicious", "ioc"}:
        return "medium"
    return "informational"


def analyze_vba(path: Path) -> tuple[bool, list[dict[str, Any]]]:
    if VBA_Parser is None:
        raise OfficeScannerError("oletools.olevba is unavailable")
    parser = None
    try:
        parser = VBA_Parser(str(path))
        has_macros = bool(parser.detect_vba_macros())
        if not has_macros:
            return False, []
        findings = []
        for kind, keyword, description in parser.analyze_macros():
            findings.append(
                {
                    "type": str(kind),
                    "keyword": str(keyword),
                    "description": str(description),
                    "severity": _finding_severity(str(kind)),
                }
            )
        return True, findings
    except Exception as error:
        raise OfficeScannerError(f"VBA analysis failed: {error}") from error
    finally:
        if parser is not None:
            parser.close()


def find_embedded_objects(path: Path) -> list[dict[str, str]]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return [
                {"path": name, "container": "ooxml"}
                for name in sorted(archive.namelist())
                if "/embeddings/" in name.lower() and not name.endswith("/")
            ]
    objects = []
    for stream in _ole_stream_names(path):
        lowered = stream.lower()
        if "objectpool" in lowered or "ole10native" in lowered:
            objects.append({"path": stream, "container": "ole"})
    return sorted(objects, key=lambda item: item["path"])


def find_external_links(path: Path) -> list[dict[str, str]]:
    if not zipfile.is_zipfile(path):
        return []
    links: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.filename.lower().endswith(".rels"):
                    continue
                if info.file_size > MAX_RELATIONSHIP_BYTES:
                    raise OfficeScannerError(
                        f"Relationship file is too large: {info.filename}"
                    )
                root = ElementTree.fromstring(archive.read(info))
                for relationship in root:
                    target = relationship.attrib.get("Target", "")
                    target_mode = relationship.attrib.get("TargetMode", "")
                    if target_mode.lower() == "external" or target.lower().startswith(
                        ("http://", "https://", "file://", "ftp://")
                    ):
                        links.append(
                            {
                                "source": info.filename,
                                "target": target,
                                "relationship_type": relationship.attrib.get("Type", ""),
                            }
                        )
    except (OSError, zipfile.BadZipFile, ElementTree.ParseError) as error:
        raise OfficeScannerError(
            f"External relationship inspection failed: {error}"
        ) from error
    return sorted(links, key=lambda item: (item["source"], item["target"]))


def scan_file(file_path: str | Path) -> dict[str, Any]:
    _require_tools()
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Sample does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Sample is not a regular file: {path}")

    document_type = detect_document_type(path)
    encrypted = detect_encryption(path)
    if encrypted:
        has_macros: bool | None = None
        macro_findings: list[dict[str, Any]] = []
    else:
        has_macros, macro_findings = analyze_vba(path)

    return {
        "scanner": "office-analysis",
        "scanner_version": SCANNER_VERSION,
        "status": "complete",
        "analyzed": True,
        "document_type": document_type,
        "has_macros": has_macros,
        "macro_findings": macro_findings,
        "embedded_objects": find_embedded_objects(path),
        "external_links": find_external_links(path),
        "encrypted": encrypted,
        "tool_version": oletools_version(),
    }


def _error_result(status: str, error: Exception) -> dict[str, Any]:
    return {
        "scanner": "office-analysis",
        "scanner_version": SCANNER_VERSION,
        "status": status,
        "analyzed": False,
        "document_type": "unknown",
        "has_macros": None,
        "macro_findings": [],
        "embedded_objects": [],
        "external_links": [],
        "encrypted": None,
        "tool_version": oletools_version(),
        "error": {"code": type(error).__name__, "message": str(error)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze one Office document.")
    parser.add_argument("file", help="Path to the mounted Office document")
    args = parser.parse_args()
    try:
        output = scan_file(args.file)
    except UnsupportedOfficeFileError as error:
        output = _error_result("unsupported", error)
        print(json.dumps(output, sort_keys=True))
        return 3
    except Exception as error:
        output = _error_result("error", error)
        print(json.dumps(output, sort_keys=True))
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
