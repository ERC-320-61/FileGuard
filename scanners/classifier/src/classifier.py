"""FileGuard content-based file classifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

try:
    import magic
except ImportError:  # Allows basic local testing before container dependencies exist.
    magic = None


VERSION = "0.1.0"
HASH_CHUNK_SIZE = 1024 * 1024

CATEGORY_EXTENSIONS = {
    "pe": {".exe", ".dll", ".sys", ".scr"},
    "office": {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm"},
    "pdf": {".pdf"},
    "archive": {".zip", ".7z", ".tar", ".gz", ".gzip", ".tgz"},
    "script": {".bat", ".cmd", ".js", ".ps1", ".py", ".sh", ".vbs"},
    "text": {".csv", ".json", ".log", ".md", ".txt", ".xml", ".yaml", ".yml"},
    "image": {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"},
}


def _hashes(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as sample:
        for chunk in iter(lambda: sample.read(HASH_CHUNK_SIZE), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def _libmagic(path: Path) -> tuple[str | None, str | None]:
    if magic is None:
        return None, None
    try:
        return magic.from_file(str(path), mime=True), magic.from_file(str(path))
    except (OSError, magic.MagicException):
        return None, None


def _is_text(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(character.isprintable() or character in "\r\n\t" for character in text)


def _is_pe(path: Path, header: bytes) -> bool:
    if len(header) < 64 or header[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(header[60:64], "little")
    with path.open("rb") as sample:
        sample.seek(pe_offset)
        return sample.read(4) == b"PE\x00\x00"


def _zip_details(path: Path) -> tuple[str, bool]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = {name.lower() for name in archive.namelist()}
            encrypted = any(info.flag_bits & 0x1 for info in archive.infolist())
            office_markers = ("word/", "xl/", "ppt/")
            category = "office" if "[content_types].xml" in names and any(
                name.startswith(office_markers) for name in names
            ) else "archive"
            return category, encrypted
    except (OSError, zipfile.BadZipFile):
        return "archive", False


def _detect(path: Path) -> dict[str, Any]:
    with path.open("rb") as sample:
        header = sample.read(8192)

    magic_mime, magic_description = _libmagic(path)
    mime_type = magic_mime or "application/octet-stream"
    description = magic_description or "Unknown data"
    category = "unknown"
    is_archive = False
    encrypted: bool | None = None

    if _is_pe(path, header):
        category, mime_type, description = "pe", "application/x-dosexec", "Windows PE executable"
        encrypted = False
    elif header.startswith(b"%PDF-"):
        category, mime_type, description = "pdf", "application/pdf", "PDF document"
        encrypted = b"/Encrypt" in header
    elif header.startswith(b"PK\x03\x04"):
        category, encrypted = _zip_details(path)
        is_archive = category == "archive"
        mime_type = (
            "application/zip"
            if category == "archive"
            else "application/vnd.openxmlformats-officedocument"
        )
        description = "ZIP archive" if category == "archive" else "Office Open XML document"
    elif header.startswith(b"7z\xbc\xaf'\x1c"):
        category, mime_type, description = "archive", "application/x-7z-compressed", "7-Zip archive"
        is_archive, encrypted = True, None
    elif header.startswith(b"\x1f\x8b"):
        category, mime_type, description = "archive", "application/gzip", "Gzip archive"
        is_archive, encrypted = True, False
    elif tarfile.is_tarfile(path):
        category, mime_type, description = "archive", "application/x-tar", "TAR archive"
        is_archive, encrypted = True, False
    elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        category, mime_type, description = "office", "application/x-ole-storage", "OLE compound document"
        encrypted = None
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        category, mime_type, description = "image", "image/png", "PNG image"
        encrypted = False
    elif header.startswith((b"GIF87a", b"GIF89a")):
        category, mime_type, description = "image", "image/gif", "GIF image"
        encrypted = False
    elif header.startswith(b"\xff\xd8\xff"):
        category, mime_type, description = "image", "image/jpeg", "JPEG image"
        encrypted = False
    elif header.startswith(b"#!"):
        category, mime_type, description = "script", "text/x-script", "Script with shebang"
        encrypted = False
    elif _is_text(header):
        category, mime_type, description = "text", magic_mime or "text/plain", magic_description or "UTF-8 text"
        encrypted = False
    elif magic_mime and magic_mime.startswith("image/"):
        category, encrypted = "image", False
    elif magic_mime and (magic_mime.startswith("text/") or "script" in magic_mime):
        category, encrypted = ("script" if "script" in magic_mime else "text"), False

    if mime_type == "application/octet-stream":
        mime_type = mimetypes.guess_type(path.name)[0] or mime_type

    return {
        "detected_type": category,
        "mime_type": mime_type,
        "magic_description": description,
        "is_archive": is_archive,
        "archive_format": description if is_archive else None,
        "is_encrypted": encrypted,
        "routing_tags": [category],
    }


def _extension_mismatch(extension: str, category: str) -> bool:
    if not extension or category == "unknown":
        return False
    expected = CATEGORY_EXTENSIONS.get(category, set())
    return extension not in expected


def classify_file(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Sample does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Sample is not a regular file: {path}")

    extension = path.suffix.lower()
    classification = _detect(path)
    classification["extension_mismatch"] = _extension_mismatch(
        extension, classification["detected_type"]
    )
    return {
        "schema_version": "1.0.0",
        "scanner": "classifier",
        "scanner_version": VERSION,
        "status": "complete",
        "sample": {
            "filename": path.name,
            "extension": extension or None,
            "size_bytes": path.stat().st_size,
            "hashes": _hashes(path),
        },
        "classification": classification,
        "warnings": [] if magic is not None else ["libmagic unavailable; signature fallback used"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify an untrusted file without executing it.")
    parser.add_argument("file", help="Path to the sample to inspect")
    args = parser.parse_args()
    try:
        result = classify_file(args.file)
    except Exception as error:
        result = {
            "schema_version": "1.0.0",
            "scanner": "classifier",
            "scanner_version": VERSION,
            "status": "error",
            "error": {"code": type(error).__name__, "message": str(error)},
        }
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
