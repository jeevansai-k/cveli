from pathlib import Path
from typing import Any

from core.formatter import format_cve_json, format_cve_markdown
from core.models import CVEModel
from utils.errors import FormatError, ValidationError
from utils.helpers import format_csv, truncate_text


class ExportService:
    SUPPORTED_FORMATS = {"json", "csv", "markdown", "txt"}

    def export(
        self,
        cves: list[CVEModel | dict[str, Any]],
        output_path: str,
        export_format: str = "json",
    ) -> str:
        if not cves:
            raise ValidationError(field="cves", message="No CVE records to export")

        fmt = export_format.lower().strip()
        if fmt not in self.SUPPORTED_FORMATS:
            raise FormatError(
                format_type=fmt, error=Exception(f"unsupported format: {fmt}")
            )

        destination = self._validate_and_resolve_path(output_path)
        rows = [item.to_dict() if isinstance(item, CVEModel) else item for item in cves]

        try:
            if fmt == "json":
                content = format_cve_json(cves, indent=2)
            elif fmt == "csv":
                content = format_csv(
                    [
                        {
                            "cve_id": row.get("id", ""),
                            "severity": row.get("severity", ""),
                            "cvss": row.get("cvss", 0.0),
                            "epss": row.get("epss", 0.0),
                            "vendor": row.get("vendor", ""),
                            "published": row.get("published", ""),
                            "exploit_available": row.get("exploit_available", False),
                            "summary": row.get("summary", ""),
                        }
                        for row in rows
                    ],
                    field_order=[
                        "cve_id",
                        "severity",
                        "cvss",
                        "epss",
                        "vendor",
                        "published",
                        "exploit_available",
                        "summary",
                    ],
                )
            elif fmt == "markdown":
                content = format_cve_markdown(cves)
            else:
                content = "\n".join(
                    " | ".join(
                        [
                            str(row.get("id")),
                            str(row.get("severity")),
                            f"CVSS {row.get('cvss')}",
                            str(row.get("vendor")),
                            truncate_text(row.get("summary", ""), 60),
                        ]
                    )
                    for row in rows
                )
            destination.write_text(content, encoding="utf-8")
            return str(destination)
        except Exception as error:
            raise FormatError(format_type=fmt, error=error) from error

    def _validate_and_resolve_path(self, path_str: str) -> Path:
        cleaned = path_str.strip()
        if ".." in cleaned or cleaned.startswith("/etc") or cleaned.startswith("/var"):
            raise ValidationError(
                field="output_path",
                value=path_str,
                message="Invalid or restricted export file path",
            )
        path = Path(cleaned).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
