"""
Search Query Processing.

Purpose: Parse and execute search queries against indexed CVE data.
Inputs: Raw query string, optional filters dictionary.
Outputs: List of matching CVE records or parsed query dict.
Responsibilities: Handle query parsing, fuzzy matching, boolean operators.
Dependencies: rapidfuzz for fuzzy matching, utils.errors.ValidationError.
"""

import json
import re
from typing import Any


def parse_query(query: str) -> dict[str, Any]:
    """Parse a raw query string into internal search format."""
    if not query or not isinstance(query, str):
        return {
            "raw": "",
            "keywords": [],
            "filters": {},
            "boolean_op": "AND",
            "fuzzy_threshold": 0.6,
        }

    raw = query.strip()

    # Check for JSON query structure
    if raw.startswith("{") and raw.endswith("}"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return normalize_json_search(data)
        except (json.JSONDecodeError, TypeError):
            pass

    # Extract keywords and check for operators
    tokens = re.findall(r"\b\w+\b", raw.lower())
    operators = {"and", "or", "not"}

    keywords = [t for t in tokens if t not in operators and len(t) > 1]
    boolean_op = "OR" if "or" in [t.lower() for t in tokens] else "AND"

    return {
        "raw": raw,
        "keywords": keywords,
        "filters": {},
        "boolean_op": boolean_op,
        "fuzzy_threshold": 0.6,
        "exact_match_only": False,
    }


def normalize_json_search(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize JSON-formatted query input."""
    keywords = data.get("keywords") or data.get("q") or []
    if isinstance(keywords, str):
        keywords = [keywords]

    filters = data.get("filters") or {}

    return {
        "raw": json.dumps(data),
        "keywords": keywords,
        "filters": filters,
        "boolean_op": data.get("boolean_op", "AND"),
        "fuzzy_threshold": data.get("fuzzy_threshold", 0.6),
        "exact_match_only": data.get("exact_match_only", False),
    }


def fuzzy_match(text: str, query_part: str) -> float:
    """Calculate fuzzy match score (0.0 to 1.0) between text and keyword."""
    if not text or not query_part:
        return 0.0

    text_lower = text.lower().strip()
    query_lower = query_part.lower().strip()

    if query_lower in text_lower:
        return 1.0

    try:
        from rapidfuzz import fuzz

        score = fuzz.partial_ratio(query_lower, text_lower)
        return float(score) / 100.0
    except Exception:
        return 0.0


def execute_search(search_data: dict[str, Any], records: list[dict | Any]) -> list[Any]:
    """Execute parsed search against a list of CVE records or models."""
    if not records:
        return []

    keywords = search_data.get("keywords", [])
    if not keywords and search_data.get("raw"):
        keywords = [search_data["raw"].lower()]

    if not keywords:
        return records

    boolean_op = search_data.get("boolean_op", "AND")
    threshold = search_data.get("fuzzy_threshold", 0.6)

    matched = []
    for item in records:
        rec_dict = (
            item
            if isinstance(item, dict)
            else (item.to_dict() if hasattr(item, "to_dict") else item.__dict__)
        )

        text_content = " ".join(
            [
                str(rec_dict.get("id", "")),
                str(rec_dict.get("summary", "")),
                str(rec_dict.get("vendor", "")),
                str(rec_dict.get("cwe", "")),
            ]
        ).lower()

        scores = [fuzzy_match(text_content, kw) for kw in keywords]

        if boolean_op == "AND":
            if all(s >= threshold for s in scores):
                matched.append(item)
        else:  # OR
            if any(s >= threshold for s in scores):
                matched.append(item)

    return matched
