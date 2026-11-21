"""
Safety labels and responsible-use notices.

Purpose: Deterministic, rule-based labelling of exploit references and CVE
references so the UI always communicates provenance and intended use.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.models import ExploitModel, Reference, SafetyLabel

POC_TYPES = {"remote", "local", "webapps", "dos"}

EXPLOIT_NOTICE = (
    "Public exploit references do not imply safe, legal, or authorized use. "
    "Use only in environments you are explicitly authorized to test."
)
EXPLOITDB_ATTRIBUTION = (
    "Exploit metadata from Exploit-DB (OffSec), "
    "https://www.exploit-db.com — repository licensed GPL-2.0. "
    "See https://www.exploit-db.com/terms for terms of use."
)
AUTHORIZED_USE_DISCLAIMER = (
    "CVELI is for authorized security research, defensive triage and "
    "vulnerability management only. You are responsible for having written "
    "authorization for any system you test."
)
RESEARCH_CONFIRMATION_PROMPT = (
    "I confirm this template is for research or an authorized engagement with "
    "written permission, defined scope, and a non-production validation plan."
)


def exploit_labels(exploit: ExploitModel) -> list[str]:
    labels = [SafetyLabel.RESEARCH_ONLY, SafetyLabel.REQUIRES_AUTHORIZED_ENV]
    if exploit.type.lower() in POC_TYPES:
        labels.append(SafetyLabel.POC_REFERENCE)
    else:
        labels.append(SafetyLabel.INFORMATIONAL)
    if not exploit.verified:
        labels.append(SafetyLabel.UNVERIFIED)
    return [str(label) for label in labels]


def reference_labels(reference: Reference) -> list[str]:
    tags = {tag.lower() for tag in reference.tags}
    labels: list[str] = []
    if tags & {"patch", "mitigation", "release notes"}:
        labels.append(str(SafetyLabel.PATCH_REFERENCE))
    if tags & {"exploit"}:
        labels.extend(
            [
                str(SafetyLabel.POC_REFERENCE),
                str(SafetyLabel.RESEARCH_ONLY),
            ]
        )
    if not labels:
        labels.append(str(SafetyLabel.INFORMATIONAL))
    return labels


def label_style(label: str) -> str:
    """Rich style name for a label (see ``cli.tui.theme.to_rich_theme``)."""
    return {
        str(SafetyLabel.RESEARCH_ONLY): "label.research",
        str(SafetyLabel.REQUIRES_AUTHORIZED_ENV): "label.research",
        str(SafetyLabel.POC_REFERENCE): "label.poc",
        str(SafetyLabel.UNVERIFIED): "label.unverified",
        str(SafetyLabel.PATCH_REFERENCE): "label.patch",
    }.get(label, "muted")


def format_labels(labels: Iterable[str]) -> str:
    return " · ".join(f"[{label}]" for label in labels)
