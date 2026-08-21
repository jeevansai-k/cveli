"""
Input Validation.

Purpose: Validate all user inputs before processing.
Inputs: User-provided strings, data structures.
Outputs: None (raises exceptions for invalid input) or returns validated data.
Responsibilities: Ensure data integrity and security.
Dependencies: Standard library (re) for pattern matching, utils.errors.ValidationError.

Functions/Classes:
    - ValidationError: Custom exception class (re-exported from utils.errors)
    - validate_cve_id(cve_id): Validate CVE identifier format
    - validate_date(date_str): Validate date string format
    - validate_severity(severity): Validate severity level
    - validate_cwe_id(cwe_id): Validate CWE identifier format
    - sanitize_input(text): Sanitize potentially dangerous input
"""

import calendar
import re
from typing import Any

from utils.errors import ValidationError


def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE identifier format (e.g., CVE-2024-1234, CVE-2021-44228)."""
    if not cve_id or not isinstance(cve_id, str):
        raise ValidationError(
            field="cve_id",
            value=str(cve_id),
            message="CVE ID must be a non-empty string",
        )

    cleaned = cve_id.strip().upper()
    pattern = r"^CVE-\d{4}-\d{4,7}$"

    if re.match(pattern, cleaned):
        return True

    raise ValidationError(
        field="cve_id",
        value=cve_id,
        message=(
            "Invalid CVE ID format. Must match pattern "
            "'CVE-YYYY-NNNN+' (e.g., CVE-2024-12345)"
        ),
    )


def validate_date(date_str: str) -> bool:
    """Validate date string format (YYYY-MM-DD)."""
    if not date_str or not isinstance(date_str, str):
        raise ValidationError(
            field="date", value=str(date_str), message="Date must be a string"
        )

    cleaned = date_str.strip()
    pattern = r"^\d{4}-\d{2}-\d{2}$"
    if not re.match(pattern, cleaned):
        raise ValidationError(
            field="date",
            value=date_str,
            message="Invalid date format. Must be YYYY-MM-DD",
        )

    try:
        year = int(cleaned[0:4])
        month = int(cleaned[5:7])
        day = int(cleaned[8:10])

        if not (1 <= month <= 12):
            raise ValidationError(
                field="date", value=date_str, message=f"Invalid month: {month}"
            )

        max_days = calendar.monthrange(year, month)[1]
        if not (1 <= day <= max_days):
            raise ValidationError(
                field="date",
                value=date_str,
                message=f"Invalid day: {day} for month {month}",
            )

    except ValueError as e:
        raise ValidationError(
            field="date", value=date_str, message=f"Invalid date components: {e}"
        ) from e

    return True


def validate_severity(severity: str) -> bool:
    """Validate CVE severity level (Low, Medium, High, Critical, Info)."""
    if not severity or not isinstance(severity, str):
        raise ValidationError(
            field="severity", value=str(severity), message="Severity must be a string"
        )

    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"]
    normalized = severity.upper().strip()

    if normalized in valid_severities:
        return True

    raise ValidationError(
        field="severity",
        value=severity,
        message=f"Invalid severity. Must be one of: {', '.join(valid_severities)}",
    )


def validate_cwe_id(cwe_id: str) -> bool:
    """Validate CWE identifier format (e.g., CWE-79, CWE-089)."""
    if not cwe_id or not isinstance(cwe_id, str):
        raise ValidationError(
            field="cwe_id", value=str(cwe_id), message="CWE ID must be a string"
        )

    pattern = r"^CWE-\d{1,5}$"
    if re.match(pattern, cwe_id.strip().upper()):
        return True

    raise ValidationError(
        field="cwe_id",
        value=cwe_id,
        message="CWE ID format should be CWE-N (e.g., CWE-79)",
    )


def validate_epss_score(value: Any, allow_percentage: bool = True) -> bool:
    """Validate EPSS exploitation probability score."""
    if isinstance(value, str):
        try:
            val_float = float(value.strip())
        except ValueError as error:
            raise ValidationError(
                field="epss_score", value=value, message="EPSS score must be numeric"
            ) from error
    elif isinstance(value, (int, float)):
        val_float = float(value)
    else:
        raise ValidationError(
            field="epss_score", value=str(value), message="EPSS score must be numeric"
        )

    val_normalized = (
        val_float / 100.0 if (allow_percentage and val_float > 1.0) else val_float
    )

    if not (0.0 <= val_normalized <= 1.0):
        raise ValidationError(
            field="epss_score",
            value=str(value),
            message="EPSS score must be between 0.0 and 1.0",
        )

    return True


def validate_cvss_vector(vector: str) -> bool:
    """Validate CVSS vector string format."""
    if not vector or not isinstance(vector, str):
        raise ValidationError(
            field="cvss_vector",
            value=str(vector),
            message="CVSS vector must be a non-empty string",
        )

    normalized = vector.upper().replace(" ", "")

    if not any(c in normalized for c in "/:;,"):
        raise ValidationError(
            field="cvss_vector",
            value=vector,
            message="CVSS vector requires metric separators",
        )

    basic_fields = ["AV:", "AC:"]
    if not any(field in normalized for field in basic_fields):
        raise ValidationError(
            field="cvss_vector",
            value=vector,
            message="CVSS vector missing standard metrics",
        )

    return True


def sanitize_input(text: str) -> str:
    """Sanitize input against traversal and null-byte injection."""
    if not isinstance(text, str):
        return ""

    cleaned = text.strip().replace("\x00", "")
    # Remove path traversal tokens if sanitized for filenames
    cleaned = cleaned.replace("..", "")
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned)

    return cleaned
