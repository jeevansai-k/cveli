"""
Metasploit research-template service.

Builds non-weaponized module scaffolds + research reports for a CVE and/or an
Exploit-DB entry, supports preview (review) before export, and requires an
explicit research-only confirmation to write files. Exports are audited.
"""

from __future__ import annotations

from pathlib import Path

from config.settings import get_settings
from core.models import CVEModel, ExploitModel, TemplateBundle
from core.msf import (
    FORBIDDEN_PRIMITIVES,
    PREFLIGHT_CHECKLIST,
    TemplateContext,
    render_json,
    render_markdown,
    render_ruby,
)
from core.msf.render import file_stem, to_json_text
from core.validator import validate_cve_id
from services.audit import audit
from services.export import validate_output_path
from services.metrics import feature_used
from storage.exploit_repository import ExploitRepository
from storage.repositories import CVERepository
from utils.errors import (
    AuthorizationRequiredError,
    FeatureDisabledError,
    PolicyError,
    ValidationError,
)

EXPORT_FORMATS = ("rb", "md", "json")


class MsfTemplateService:
    def __init__(
        self,
        cve_repo: CVERepository | None = None,
        exploit_repo: ExploitRepository | None = None,
    ) -> None:
        self.cve_repo = cve_repo or CVERepository()
        self.exploit_repo = exploit_repo or ExploitRepository()

    @staticmethod
    def _require_enabled() -> None:
        if not get_settings().feature_msf:
            raise FeatureDisabledError("msf")

    def _load_cve(self, cve_id: str, live: bool) -> CVEModel | None:
        validate_cve_id(cve_id)
        cve_id = cve_id.strip().upper()
        cve = self.cve_repo.get_by_id(cve_id)
        if cve is None and live:
            from services.sync import SyncService

            SyncService(repo=self.cve_repo).sync_sources(
                sources=["nvd", "cve_org", "cisa_kev", "epss"], query=cve_id, limit=5
            )
            cve = self.cve_repo.get_by_id(cve_id)
        return cve

    def build_context(
        self,
        cve_id: str | None = None,
        edb_id: int | None = None,
        module_type: str = "auto",
        author: str = "CVELI Research",
        live: bool = True,
    ) -> TemplateContext:
        if not cve_id and edb_id is None:
            raise ValidationError("target", None, "Provide a CVE ID and/or an EDB-ID.")
        exploits: list[ExploitModel] = []
        if edb_id is not None:
            exploit = self.exploit_repo.get(int(edb_id))
            if exploit is None:
                raise ValidationError(
                    "edb_id",
                    str(edb_id),
                    f"EDB-{edb_id} is not in the local index (run `cveli exploits "
                    "refresh`).",
                )
            exploits.append(exploit)
            if not cve_id and exploit.cve_ids:
                cve_id = exploit.cve_ids[0]
        cve = self._load_cve(cve_id, live) if cve_id else None
        if cve_id and cve is None and not exploits:
            raise ValidationError(
                "cve_id", cve_id, f"{cve_id} not found locally or in live sources."
            )
        if cve is not None:
            known = {e.edb_id for e in exploits}
            exploits += [
                e for e in self.exploit_repo.for_cve(cve.id) if e.edb_id not in known
            ]
        return TemplateContext(
            cve=cve,
            exploits=exploits,
            module_type=module_type,
            author=author,
            explicit_edb=edb_id is not None,
        )

    def generate(
        self,
        cve_id: str | None = None,
        edb_id: int | None = None,
        module_type: str = "auto",
        author: str = "CVELI Research",
        live: bool = True,
    ) -> TemplateBundle:
        """Render (preview) a template bundle. Nothing is written to disk."""
        self._require_enabled()
        if module_type not in ("auto", "exploit", "auxiliary", "post"):
            raise ValidationError(
                "module_type", module_type, "Use auto, exploit, auxiliary or post."
            )
        context = self.build_context(cve_id, edb_id, module_type, author, live)
        try:
            ruby, resolved_type, superclass = render_ruby(context)
        except ValueError as error:
            raise ValidationError("module_type", module_type, str(error)) from error
        assert_safe(ruby)
        stem = file_stem(context)
        feature_used("msf_template", module_type=resolved_type)
        return TemplateBundle(
            id=stem,
            module_type=resolved_type,
            module_class=superclass,
            cve_id=context.cve_id,
            edb_id=context.edb_id,
            ruby=ruby,
            markdown=render_markdown(context, resolved_type, stem),
            metadata=render_json(context, resolved_type, superclass),
            preflight=list(PREFLIGHT_CHECKLIST),
        )

    def export(
        self,
        bundle: TemplateBundle,
        out_dir: str,
        formats: tuple[str, ...] | list[str] = EXPORT_FORMATS,
        confirmed: bool = False,
        allow_outside: bool = False,
        project: str | None = None,
    ) -> list[str]:
        """Write the bundle. Requires an explicit research-only confirmation."""
        self._require_enabled()
        if not confirmed:
            raise AuthorizationRequiredError(
                "Exporting a template requires the research-only confirmation."
            )
        chosen = [fmt.lower().strip(".") for fmt in formats]
        unknown = set(chosen) - set(EXPORT_FORMATS)
        if unknown or not chosen:
            raise ValidationError(
                "formats", ",".join(chosen), f"Formats: {', '.join(EXPORT_FORMATS)}"
            )
        assert_safe(bundle.ruby)
        contents = {
            "rb": bundle.ruby,
            "md": bundle.markdown,
            "json": to_json_text(bundle.metadata),
        }
        written: list[str] = []
        for fmt in chosen:
            target = validate_output_path(
                str(Path(out_dir) / f"{bundle.id}.{fmt}"), allow_outside=allow_outside
            )
            target.write_text(contents[fmt], encoding="utf-8")
            written.append(str(target))
        project_id = None
        if project:
            from services.projects import ProjectService

            service = ProjectService()
            project_id = service.projects.get_or_create(project)["id"]
        from storage.research_repositories import ReportRepository

        report = ReportRepository().record(
            bundle.module_type,
            chosen,
            written,
            cve_id=bundle.cve_id,
            edb_id=bundle.edb_id,
            project_id=project_id,
        )
        if project_id:
            from storage.research_repositories import ProjectRepository

            ProjectRepository().add_item(project_id, "report", report["id"])
        audit(
            "template_exported",
            object_kind="cve" if bundle.cve_id else "exploit",
            object_id=bundle.cve_id or bundle.edb_id or "",
            module_type=bundle.module_type,
            formats=chosen,
        )
        return written


def code_only(ruby: str) -> str:
    """Ruby source with comments, %q{} bodies and string literals removed."""
    import re

    without_q = re.sub(r"%q\{.*?\n\s*\}", "%q{}", ruby, flags=re.DOTALL)
    without_strings = re.sub(r"'(?:\\.|[^'\\])*'", "''", without_q)
    return re.sub(r"#[^\n]*", "", without_strings)


def assert_safe(ruby: str) -> None:
    """Defence in depth: refuse to emit anything resembling exploitation code.

    Only executable code is inspected: feed text inside comments, string
    literals and the %q{} description is inert (and escaped).
    """
    lowered = code_only(ruby).lower()
    for primitive in FORBIDDEN_PRIMITIVES:
        if primitive.lower() in lowered:
            raise PolicyError(
                f"Generated template contained forbidden primitive {primitive!r}.",
                rule="msf-primitive",
            )
