"""
Google Dork Builder service.

Builds previewable, explained, policy-checked search queries from a username
and a target site. Guardrails:
- validation of every input and the final query (``core.dork_policy``);
- no automated searching or scraping — ``open`` hands one URL to the user's
  browser, only after an authorization attestation and within rate limits;
- inputs are redacted from logs and are persisted only via an explicit save.
"""

from __future__ import annotations

import time
import webbrowser
from collections.abc import Callable
from urllib.parse import quote_plus

from config.settings import get_settings
from core.dork_policy import (
    LOW,
    enforce,
    normalize,
    validate_domain,
    validate_filetype,
    validate_phrase,
    validate_username,
)
from core.dork_templates import (
    CATEGORIES,
    CATEGORY_RISK,
    FALSE_POSITIVE_EXCLUSIONS,
    NEEDS_USERNAME,
    SITE_PRESETS,
    TEMPLATES,
    TEMPLATES_BY_ID,
    explain_operators,
    templates_for,
)
from core.models import DorkInput, DorkQuery
from services.audit import audit
from services.metrics import feature_used
from utils.errors import (
    AuthorizationRequiredError,
    FeatureDisabledError,
    PolicyError,
    RateLimitError,
    ValidationError,
)
from utils.logger import get_logger, sensitive

log = get_logger(__name__)

GOOGLE_SEARCH_URL = "https://www.google.com/search?q={query}"
AUTHORIZATION_WARNING = (
    "Only research people and organisations you are authorized to investigate or "
    "that you have a lawful purpose to research. Respect platform terms and "
    "privacy law. CVELI does not run searches for you."
)
OPEN_LOG_KEY = "dork_open_log"  # epoch timestamps only — never the query


class OpenRateLimiter:
    """Persistent limit on manual browser opens (min interval + per hour)."""

    def __init__(
        self,
        min_interval: float | None = None,
        per_hour: int | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        settings = get_settings()
        self.min_interval = (
            settings.dork_open_min_interval if min_interval is None else min_interval
        )
        self.per_hour = settings.dork_open_per_hour if per_hour is None else per_hour
        self.clock = clock

    def _load(self) -> list[float]:
        from storage.system_repositories import SettingsRepository

        now = self.clock()
        stamps = SettingsRepository().get(OPEN_LOG_KEY, []) or []
        return [float(s) for s in stamps if now - float(s) < 3600]

    def check(self) -> None:
        stamps = self._load()
        now = self.clock()
        if stamps and now - stamps[-1] < self.min_interval:
            wait = self.min_interval - (now - stamps[-1])
            raise RateLimitError(
                f"Please wait {wait:.0f}s before opening another search.", wait
            )
        if len(stamps) >= self.per_hour:
            wait = 3600 - (now - stamps[0])
            raise RateLimitError(
                f"Hourly limit of {self.per_hour} browser opens reached; try again "
                f"in {wait / 60:.0f} min.",
                wait,
            )

    def record(self) -> None:
        from storage.system_repositories import SettingsRepository

        stamps = self._load()
        stamps.append(self.clock())
        SettingsRepository().set(OPEN_LOG_KEY, stamps[-max(self.per_hour, 1) :])


class DorkBuilder:
    def __init__(
        self,
        opener: Callable[[str], bool] | None = None,
        limiter: OpenRateLimiter | None = None,
    ) -> None:
        self.opener = opener or (lambda url: webbrowser.open(url, new=2))
        self.limiter = limiter or OpenRateLimiter()

    @staticmethod
    def _require_enabled() -> None:
        if not get_settings().feature_dorks:
            raise FeatureDisabledError("dorks")

    @staticmethod
    def templates() -> list[dict[str, str]]:
        return [
            {
                "id": t.id,
                "label": t.label,
                "category": t.category,
                "category_label": CATEGORIES[t.category],
                "risk_level": t.risk_level,
                "pattern": t.pattern,
            }
            for t in TEMPLATES
        ]

    @staticmethod
    def sites() -> list[tuple[str, str]]:
        return list(SITE_PRESETS)

    def _decorate(self, base: str, data: DorkInput, filetype: str | None) -> str:
        parts = [base]
        for phrase in data.include_phrases:
            parts.append(f'"{validate_phrase(phrase, "include_phrases")}"')
        for phrase in data.exclude_phrases:
            parts.append(f'-"{validate_phrase(phrase, "exclude_phrases")}"')
        if data.exclude_false_positives:
            parts.extend(FALSE_POSITIVE_EXCLUSIONS)
        if filetype and "filetype:" not in base:
            parts.append(f"filetype:{filetype}")
        return " ".join(parts)

    def _make(
        self,
        template_id: str,
        label: str,
        category: str,
        query: str,
        explanation: str,
        base_risk: str,
        data: DorkInput,
        extra_warnings: tuple[str, ...] = (),
    ) -> DorkQuery:
        risk = enforce(query, base_risk)
        warnings = [AUTHORIZATION_WARNING, *extra_warnings]
        return DorkQuery(
            id=template_id,
            label=label,
            category=category,
            target_domain=data.target_domain,
            username=data.username,
            query=query,
            operators=explain_operators(query),  # type: ignore[arg-type]
            explanation=explanation,
            risk_level=risk,
            requires_authorization=True,
            warnings=warnings,
            google_url=GOOGLE_SEARCH_URL.format(query=quote_plus(query)),
        )

    def build(self, data: DorkInput) -> list[DorkQuery]:
        """Validate inputs and render every template of the chosen category."""
        self._require_enabled()
        category = data.category.strip().lower()
        if category not in CATEGORIES:
            raise ValidationError(
                "category", data.category, f"Choose one of: {', '.join(CATEGORIES)}"
            )
        with sensitive(data.username, data.target_domain):
            domain = validate_domain(data.target_domain)
            username = ""
            if data.username.strip() or category in NEEDS_USERNAME:
                username = validate_username(data.username)
            clean = data.model_copy(
                update={
                    "target_domain": domain,
                    "username": username,
                    "category": category,
                }
            )
            filetype = validate_filetype(data.filetype)
            if category == "custom":
                return [self._custom(clean, filetype)]
            user_term = f'"{username}"' if data.exact_match else username
            values = {
                "domain": domain,
                "user": user_term,
                "user_url": username.replace(" ", ""),
                "filetype": filetype or "pdf",
            }
            results = []
            for template in templates_for(category):
                base = template.render(**values)
                query = self._decorate(base, clean, filetype)
                results.append(
                    self._make(
                        template.id,
                        template.label,
                        category,
                        query,
                        template.explanation.format(**values),
                        CATEGORY_RISK.get(category, template.risk_level),
                        clean,
                        template.warnings,
                    )
                )
            feature_used("dorks", category=category)
            log.debug(f"Built {len(results)} dork(s) for category {category}")
            return results

    def _custom(self, data: DorkInput, filetype: str | None) -> DorkQuery:
        raw = data.custom_query.strip()
        if not raw:
            raise ValidationError("custom_query", raw, "Enter a custom query.")
        query = raw
        if data.restrict_domain and f"site:{data.target_domain}" not in normalize(raw):
            query = f"site:{data.target_domain} {raw}"
        if data.username and data.username.lower() not in normalize(query):
            user = f'"{data.username}"' if data.exact_match else data.username
            query = f"{query} {user}"
        query = self._decorate(query, data, filetype)
        return self._make(
            "custom",
            "Custom query",
            "custom",
            query,
            "Custom query (checked against CVELI's safety policy).",
            LOW,
            data,
        )

    def open(self, dork: DorkQuery, attested: bool) -> str:
        """Open one query in the user's browser (attestation + rate limit)."""
        self._require_enabled()
        if not attested:
            raise AuthorizationRequiredError()
        enforce(dork.query, dork.risk_level)  # re-check in case it was edited
        if not dork.google_url.startswith("https://www.google.com/search?q="):
            raise PolicyError("Only Google search URLs can be opened.")
        self.limiter.check()
        self.opener(dork.google_url)
        self.limiter.record()
        audit(
            "dork_opened",
            object_kind="dork_template",
            object_id=dork.id,
            risk_level=dork.risk_level,
            category=dork.category,
        )
        feature_used("dorks_open", category=dork.category)
        return dork.google_url

    def get_template(self, template_id: str):
        return TEMPLATES_BY_ID.get(template_id)
