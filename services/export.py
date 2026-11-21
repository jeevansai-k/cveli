"""
Multi-format export service.

Security (B9): output paths are resolved (symlinks followed) and must land in
the working directory, the home directory or the system temp directory unless
``allow_outside=True``; system directories are always refused and an existing
symlink is never written through. CSV cells that start with formula characters
are neutralised (CSV/formula injection).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from core.formatter import format_cve_json, format_cve_markdown, format_cvss
from core.models import CVEModel
from core.text import one_line
from utils.errors import FormatError, ValidationError
from utils.helpers import format_csv

SYSTEM_DIRS = (
    "/etc",
    "/bin",
    "/sbin",
    "/usr",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/lib",
    "/lib64",
    "/var",
    "/opt",
    "/root",
    "/System",
    "/Library",
    "C:\\Windows",
    "C:\\Program Files",
)
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
CSV_FIELDS = [
    "cve_id",
    "severity",
    "cvss",
    "epss",
    "vendor",
    "published",
    "kev",
    "public_exploit_count",
    "summary",
]


def csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_output_path(path_str: str, allow_outside: bool = False) -> Path:
    cleaned = (path_str or "").strip()
    if not cleaned or "\x00" in cleaned:
        raise ValidationError("output_path", path_str, "Output path is empty/invalid.")
    raw = Path(cleaned).expanduser()
    if raw.is_symlink():
        raise ValidationError(
            "output_path", path_str, "Refusing to write through a symbolic link."
        )
    resolved = raw.resolve()
    for system_dir in SYSTEM_DIRS:
        root = Path(system_dir)
        if resolved == root or _is_within(resolved, root):
            allowed_tmp = Path(tempfile.gettempdir()).resolve()
            if _is_within(resolved, allowed_tmp):
                break
            raise ValidationError(
                "output_path", path_str, "Refusing to write into a system directory."
            )
    safe_roots = [
        Path.cwd().resolve(),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    if not allow_outside and not any(_is_within(resolved, r) for r in safe_roots):
        raise ValidationError(
            "output_path",
            path_str,
            "Path is outside the working, home and temp directories "
            "(use --force to allow).",
        )
    if resolved.exists() and resolved.is_dir():
        raise ValidationError("output_path", path_str, "Output path is a directory.")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    if not os.access(resolved.parent, os.W_OK):
        raise ValidationError("output_path", path_str, "Directory is not writable.")
    return resolved


def _csv_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        values = {
            "cve_id": row.get("id", ""),
            "severity": row.get("severity") or "",
            "cvss": "" if row.get("cvss") is None else row.get("cvss"),
            "epss": "" if row.get("epss") is None else row.get("epss"),
            "vendor": row.get("vendor") or "",
            "published": row.get("published", ""),
            "kev": bool(row.get("kev", False)),
            "public_exploit_count": int(row.get("public_exploit_count", 0) or 0),
            "summary": one_line(row.get("summary", "")),
        }
        out.append({key: csv_safe(value) for key, value in values.items()})
    return out


class ExportService:
    SUPPORTED_FORMATS = {"json", "csv", "markdown", "txt"}

    def export(
        self,
        cves: list[CVEModel | dict[str, Any]],
        output_path: str,
        export_format: str = "json",
        allow_outside: bool = False,
    ) -> str:
        if not cves:
            raise ValidationError(field="cves", message="No CVE records to export")

        fmt = export_format.lower().strip()
        if fmt == "md":
            fmt = "markdown"
        if fmt not in self.SUPPORTED_FORMATS:
            raise FormatError(
                format_type=fmt, error=Exception(f"unsupported format: {fmt}")
            )

        destination = validate_output_path(output_path, allow_outside=allow_outside)
        rows = [item.to_dict() if isinstance(item, CVEModel) else item for item in cves]

        try:
            if fmt == "json":
                content = format_cve_json(cves, indent=2)
            elif fmt == "csv":
                content = format_csv(_csv_rows(rows), field_order=CSV_FIELDS)
            elif fmt == "markdown":
                content = format_cve_markdown(cves)
            else:
                content = "\n".join(
                    " | ".join(
                        [
                            str(row.get("id")),
                            str(row.get("severity") or "N/A"),
                            f"CVSS {format_cvss(row.get('cvss'))}",
                            str(row.get("vendor") or "N/A"),
                            one_line(row.get("summary", ""), 60),
                        ]
                    )
                    for row in rows
                )
            destination.write_text(content, encoding="utf-8")
            return str(destination)
        except Exception as error:
            raise FormatError(format_type=fmt, error=error) from error
