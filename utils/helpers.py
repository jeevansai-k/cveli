import csv
import json
from datetime import datetime
from io import StringIO


def format_json(data: dict | list, indent: int = 2) -> str:
    return json.dumps(
        data, indent=indent, default=str, sort_keys=isinstance(data, dict)
    )


def format_csv(rows: list[dict], field_order: list[str] | None = None) -> str:
    if not rows:
        return ""
    columns = field_order or list(rows[0])
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(
        {column: row.get(column, "") for column in columns} for row in rows
    )
    return buffer.getvalue()


def parse_date(date_str: str, default: datetime | None = None) -> datetime | None:
    if not date_str:
        return default
    cleaned = date_str.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(cleaned.split(".")[0])
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%d-%m-%Y", "%Y%m%d"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            pass
    return default


def format_datetime(dt: datetime, output_format: str | None = None) -> str:
    if not isinstance(dt, datetime):
        return str(dt)
    return dt.strftime(output_format or "%Y-%m-%dT%H:%M:%SZ")


def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def calculate_time_diff(start: datetime, end: datetime) -> tuple[int, str]:
    total_seconds = int((end - start).total_seconds())
    if total_seconds < 60:
        return total_seconds, f"{total_seconds} seconds ago"
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return total_seconds, f"{days}d {hours}h"
    if hours:
        return total_seconds, f"{hours}h {minutes}m"
    return total_seconds, f"{minutes} minutes ago"
