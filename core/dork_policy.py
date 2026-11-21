"""
Google Dork safety policy.

Purpose: Validate user input and block query patterns aimed at credentials,
secrets, private keys, database dumps, breach data or non-public
infrastructure. The policy is applied to the *final* query string of every
template and to custom queries, after unicode/whitespace normalization so that
spacing, case, zero-width characters or look-alike glyphs cannot bypass it.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

from utils.errors import PolicyError, ValidationError

ALLOWED_FILETYPES = ("pdf", "doc", "docx", "ppt", "pptx", "txt", "md")
LOW, MEDIUM, HIGH = "low", "medium", "high"
MAX_QUERY_LENGTH = 512

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
USERNAME_RE = re.compile(r"^[\w][\w.\- @]{0,63}$", re.UNICODE)
DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
PRIVATE_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".private",
    ".test",
    ".invalid",
    ".example.internal",
)

# (rule id, compiled regex over the normalized query, human reason)
_BLOCK_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "secret-terms",
        re.compile(
            r"\b(passw(or)?d|passwd|pwd|secrets?|tokens?|bearer|api[\s_\-]?keys?|"
            r"access[\s_\-]?keys?|client[\s_\-]?secret|private[\s_\-]?keys?|"
            r"credentials?|creds|auth[\s_\-]?key|session[\s_\-]?id|ssh[\s_\-]?key|"
            r"id_rsa|id_dsa|id_ed25519|htpasswd|etc/shadow|keystore|kdbx|"
            r"aws_access_key_id|aws_secret)\b"
        ),
        "Queries for passwords, tokens, keys or credentials are not allowed.",
    ),
    (
        "key-material",
        re.compile(r"begin\s+(rsa|dsa|ec|openssh|pgp|encrypted)?\s*private|ssh-rsa"),
        "Queries for private key material are not allowed.",
    ),
    (
        "dump-breach",
        re.compile(
            r"\b(dumps?|sql[\s_\-]?dump|db[\s_\-]?dump|database[\s_\-]?dump|"
            r"leak(ed|s)?|breach(ed|es)?|combo[\s_\-]?lists?|pastebin[\s_\-]?dump|"
            r"stealer[\s_\-]?logs?)\b"
        ),
        "Queries for database dumps, leaks or breach data are not allowed.",
    ),
    (
        "sensitive-files",
        re.compile(
            r"(wp-config|\.git\b|\.svn\b|\.env\b|\.htaccess|config\.php|"
            r"web\.config|phpinfo|server-status|\.ds_store|\.bash_history|"
            r"\.npmrc|\.pypirc|\.netrc|\.pgpass|\.aws/)"
        ),
        "Queries for configuration or secret files are not allowed.",
    ),
    (
        "risky-filetype",
        re.compile(
            r"\b(filetype|ext):\s*\"?(env|sql|log|bak|backup|old|key|pem|ppk|p12|"
            r"pfx|cfg|conf|config|ini|db|dbf|mdb|sqlite3?|dump|kdbx|json|xml|yml|"
            r"yaml|csv|xls|xlsx|zip|tar|gz|rar|7z|sh|ps1|rdp|ovpn)\b"
        ),
        "That file type is commonly used to expose secrets or data; only "
        f"{', '.join(ALLOWED_FILETYPES)} are allowed.",
    ),
    (
        "risky-inurl",
        re.compile(
            r"\binurl:\s*\"?(admin|administrator|config|backup|phpmyadmin|"
            r"cgi-bin|setup|install|debug|console|jenkins|grafana|kibana|"
            r"\.git|\.svn|\.env|upload)"
        ),
        "Queries targeting admin consoles, setup pages or backups are not allowed.",
    ),
    (
        "sensitive-index",
        re.compile(
            r"index\s+of.*\b(backup|private|confidential|parent\s+directory|"
            r"etc|root|home|mail|database|bak)\b"
        ),
        "Directory-listing queries for backups or private paths are not allowed.",
    ),
    (
        "cache-operator",
        re.compile(r"\bcache:"),
        "The cache: operator is not supported.",
    ),
]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk_level: str
    reason: str = ""
    rule: str = ""


def normalize(text: str) -> str:
    """NFKC fold, drop zero-width chars, lowercase, collapse whitespace."""
    folded = unicodedata.normalize("NFKC", text or "").translate(ZERO_WIDTH)
    return re.sub(r"\s+", " ", folded).strip().lower()


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch).startswith("C") for ch in text)


def validate_username(value: str) -> str:
    cleaned = unicodedata.normalize("NFKC", value or "").translate(ZERO_WIDTH).strip()
    if not cleaned:
        raise ValidationError("username", value, "Username cannot be empty.")
    if _has_control(cleaned) or not USERNAME_RE.match(cleaned):
        raise ValidationError(
            "username",
            value,
            "Username may contain letters, digits, spaces, '.', '_', '-' and '@' "
            "(max 64 characters) and no search operators or quotes.",
        )
    return cleaned


def validate_domain(value: str) -> str:
    raw = (value or "").strip().lower()
    raw = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", raw)
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    raw = raw.split("@")[-1].split(":", 1)[0].rstrip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    if raw.startswith("www."):
        raw = raw[4:]
    if not raw:
        raise ValidationError(
            "target_domain", value, "Enter a domain like example.com."
        )
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValidationError(
            "target_domain", value, "IP addresses are not allowed; use a public domain."
        )
    try:
        ascii_domain = raw.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValidationError("target_domain", value, "Invalid domain name.") from error
    labels = ascii_domain.split(".")
    if (
        len(ascii_domain) > 253
        or len(labels) < 2
        or not all(DOMAIN_LABEL_RE.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise ValidationError("target_domain", value, "Invalid domain name.")
    if ascii_domain == "localhost" or ascii_domain.endswith(PRIVATE_SUFFIXES):
        raise ValidationError(
            "target_domain",
            value,
            "Internal or reserved domains are not allowed; CVELI only builds "
            "queries for public sites.",
        )
    return ascii_domain


def validate_phrase(value: str, field: str = "phrase") -> str:
    cleaned = unicodedata.normalize("NFKC", value or "").translate(ZERO_WIDTH).strip()
    if not cleaned:
        raise ValidationError(field, value, "Phrase cannot be empty.")
    if len(cleaned) > 80 or _has_control(cleaned) or '"' in cleaned:
        raise ValidationError(
            field, value, "Phrases must be under 80 characters without quotes."
        )
    return cleaned


def validate_filetype(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    cleaned = value.strip().lower().lstrip(".")
    if cleaned not in ALLOWED_FILETYPES:
        raise PolicyError(
            f"File type '{cleaned}' is not allowed; choose one of "
            f"{', '.join(ALLOWED_FILETYPES)}.",
            rule="risky-filetype",
        )
    return cleaned


def evaluate(query: str, base_risk: str = LOW) -> PolicyDecision:
    normalized = normalize(query)
    if not normalized:
        return PolicyDecision(False, HIGH, "Query is empty.", "empty")
    if len(normalized) > MAX_QUERY_LENGTH:
        return PolicyDecision(False, HIGH, "Query is too long.", "length")
    if _has_control(query.translate(ZERO_WIDTH).replace("\n", " ").replace("\t", " ")):
        return PolicyDecision(
            False, HIGH, "Query contains control characters.", "control"
        )
    for rule, pattern, reason in _BLOCK_RULES:
        if pattern.search(normalized):
            return PolicyDecision(False, HIGH, reason, rule)
    risk = base_risk
    if risk == LOW and re.search(
        r"intitle:\s*\"?index of|site:\s*\*\.|"
        r"inurl:\s*\"?(login|signin|sign-in|auth|portal|sso)",
        normalized,
    ):
        risk = MEDIUM
    return PolicyDecision(True, risk)


def enforce(query: str, base_risk: str = LOW) -> str:
    """Return the risk level or raise ``PolicyError`` with the reason."""
    decision = evaluate(query, base_risk)
    if not decision.allowed:
        raise PolicyError(decision.reason, rule=decision.rule)
    return decision.risk_level
