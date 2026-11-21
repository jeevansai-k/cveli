"""
Source-aware CVE record merging.

Purpose: Combine partial records from NVD, CVE.org, CISA KEV and FIRST EPSS —
both inside one sync and against what is already stored — without ever
replacing richer data with empty values (fixes B1: KEV/EPSS-only saves used to
wipe CVSS, severity and dates).

Precedence for descriptive fields: NVD > CVE.org > other sources. A field is
replaced only when the incoming value is present and the incoming record ranks
at least as high as the existing one (or the existing value is missing).
"""

from __future__ import annotations

from core.models import CVEModel, Reference

SOURCE_RANK = {"NVD": 3, "CVE.org": 2, "CISA KEV": 1, "FIRST EPSS": 1}


def source_rank(model: CVEModel) -> int:
    return max((SOURCE_RANK.get(source, 1) for source in model.sources), default=0)


def _union(first: list, second: list) -> list:
    return list(dict.fromkeys([*first, *second]))


def _union_refs(first: list[Reference], second: list[Reference]) -> list[Reference]:
    merged: dict[str, Reference] = {ref.url: ref for ref in first}
    for ref in second:
        if ref.url in merged:
            existing = merged[ref.url]
            merged[ref.url] = Reference(
                url=ref.url,
                source=existing.source or ref.source,
                tags=_union(existing.tags, ref.tags),
            )
        else:
            merged[ref.url] = ref
    return list(merged.values())


def merge_models(current: CVEModel, incoming: CVEModel) -> CVEModel:
    """Return ``current`` updated with ``incoming`` (``current`` is mutated)."""
    wins = source_rank(incoming) >= source_rank(current)

    def take(present: bool, existing_missing: bool) -> bool:
        return present and (existing_missing or wins)

    if take(incoming.cvss is not None, current.cvss is None):
        current.cvss = incoming.cvss
        current.severity = incoming.severity
        current.vector = incoming.vector or current.vector
    elif current.severity is None and incoming.severity:
        current.severity = incoming.severity
    if incoming.vector and not current.vector:
        current.vector = incoming.vector
    if incoming.summary and (
        not current.summary
        or (wins and source_rank(incoming) > 1)
        or (source_rank(current) <= 1 and len(incoming.summary) > len(current.summary))
    ):
        current.summary = incoming.summary
    if take(bool(incoming.published), not current.published):
        current.published = incoming.published
    if incoming.updated and (not current.updated or incoming.updated > current.updated):
        current.updated = incoming.updated
    if incoming.kev_date and not current.kev_date:
        current.kev_date = incoming.kev_date
    if take(bool(incoming.vendor), not current.vendor):
        current.vendor = incoming.vendor
    if take(incoming.cwe is not None, current.cwe is None):
        current.cwe = incoming.cwe
    if take(bool(incoming.affected_products), not current.affected_products):
        current.affected_products = incoming.affected_products
    if incoming.epss is not None:
        current.epss = incoming.epss
    if incoming.epss_percentile is not None:
        current.epss_percentile = incoming.epss_percentile
    current.kev = current.kev or incoming.kev
    if incoming.public_exploit_count:
        current.public_exploit_count = incoming.public_exploit_count
    current.exploit_available = (
        current.exploit_available
        or incoming.exploit_available
        or current.kev
        or current.public_exploit_count > 0
    )
    current.references = _union(current.references, incoming.references)
    current.reference_details = _union_refs(
        current.reference_details, incoming.reference_details
    )
    current.tags = _union(current.tags, incoming.tags)
    current.sources = _union(current.sources, incoming.sources)
    if incoming.fetched_at:
        current.fetched_at = incoming.fetched_at
    return current
