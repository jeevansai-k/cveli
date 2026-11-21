"""
Renderers for Metasploit research templates (.rb), research reports (.md)
and metadata (.json).

Safety contract (enforced by tests/test_msf_templates.py):
- no payload generation, encoding or delivery code;
- no network I/O primitives (requests, sockets, command execution);
- ``exploit``/``run`` always stop with ``fail_with``; ``check`` returns
  ``CheckCode::Unknown``;
- every feed-derived string is escaped for its Ruby context.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from string import Template
from typing import Any

from config.version import __version__
from core.models import CVEModel, ExploitModel
from core.msf.escape import (
    module_slug,
    ruby_comment,
    ruby_q_block,
    ruby_single,
    safe_reference_url,
)
from core.safety import (
    AUTHORIZED_USE_DISCLAIMER,
    EXPLOIT_NOTICE,
    EXPLOITDB_ATTRIBUTION,
)

PREFLIGHT_CHECKLIST = [
    "Written authorization from the system owner (signed rules of engagement)",
    "Defined scope: hosts, time window, permitted techniques, contacts",
    "Target product and version confirmed by non-destructive fingerprinting",
    "Backup and rollback plan agreed with the system owner",
    "Validation performed first in a non-production lab replica",
    "Responsible disclosure / remediation reporting plan in place",
]

# Strings that must never appear in a generated template.
FORBIDDEN_PRIMITIVES = (
    "payload.encoded",
    "payload.raw",
    "generate_payload",
    "send_request_cgi",
    "send_request_raw",
    "sock.put",
    "sock.write",
    "connect(",
    "cmd_exec",
    "execute_command",
    "execute_cmdstager",
    "Rex::Text.rand",
    "shellcode",
    "\\x90",
    "eval(",
    "system(",
    "`",
)

MODULE_TYPES = ("exploit", "auxiliary", "post")

PLATFORM_MAP = {
    "linux": "linux",
    "windows": "win",
    "win32": "win",
    "win64": "win",
    "php": "php",
    "java": "java",
    "python": "python",
    "unix": "unix",
    "osx": "osx",
    "macos": "osx",
    "hardware": "unix",
    "multiple": "multi",
}


@dataclass
class TemplateContext:
    cve: CVEModel | None = None
    exploits: list[ExploitModel] = field(default_factory=list)
    module_type: str = "auto"
    author: str = "CVELI Research"
    explicit_edb: bool = False
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    @property
    def primary_exploit(self) -> ExploitModel | None:
        return self.exploits[0] if self.exploits else None

    @property
    def cve_id(self) -> str | None:
        if self.cve:
            return self.cve.id
        exploit = self.primary_exploit
        return exploit.cve_ids[0] if exploit and exploit.cve_ids else None

    @property
    def edb_id(self) -> int | None:
        return self.primary_exploit.edb_id if self.primary_exploit else None

    @property
    def record_id(self) -> str:
        if self.cve_id:
            return self.cve_id
        return f"EDB-{self.edb_id}" if self.edb_id else "UNKNOWN"

    @property
    def product(self) -> str:
        exploit = self.primary_exploit
        if exploit and exploit.affected_product and (self.explicit_edb or not self.cve):
            return exploit.affected_product
        if self.cve and self.cve.affected_products:
            first = self.cve.affected_products[0]
            return str(first.get("name", "")) if isinstance(first, dict) else str(first)
        if self.cve and self.cve.vendor:
            return self.cve.vendor
        if exploit and exploit.affected_product:
            return exploit.affected_product
        return "TODO: affected product"

    @property
    def versions(self) -> list[str]:
        exploit = self.primary_exploit
        if (
            exploit
            and exploit.affected_versions
            and (self.explicit_edb or not self.cve)
        ):
            return exploit.affected_versions
        if self.cve:
            return [
                str(p.get("version", ""))
                for p in self.cve.affected_products[:5]
                if isinstance(p, dict) and p.get("version")
            ]
        return []

    @property
    def disclosure_date(self) -> str:
        if self.cve and self.cve.published:
            return self.cve.published
        exploit = self.primary_exploit
        return exploit.date_published if exploit and exploit.date_published else ""

    @property
    def summary(self) -> str:
        if self.cve and self.cve.summary:
            return self.cve.summary
        exploit = self.primary_exploit
        return exploit.title if exploit else "No description available."

    @property
    def platform(self) -> str:
        exploit = self.primary_exploit
        return PLATFORM_MAP.get((exploit.platform if exploit else "").lower(), "multi")

    @property
    def port(self) -> int | None:
        exploit = self.primary_exploit
        return exploit.port if exploit else None


def comment_block(text: str, width: int = 76) -> str:
    import textwrap

    return "\n".join(
        f"# {line}" for line in textwrap.wrap(ruby_comment(text, 600), width)
    )


def choose_module_type(context: TemplateContext) -> tuple[str, str, list[str]]:
    """Return (module_type, superclass, mixins) for the context."""
    requested = context.module_type.lower()
    exploit = context.primary_exploit
    edb_type = (exploit.type if exploit else "").lower()
    if requested == "post":
        return "post", "Msf::Post", []
    if requested == "auxiliary" or (requested == "auto" and edb_type in ("dos", "")):
        mixins = ["Msf::Exploit::Remote::HttpClient"]
        if edb_type in ("dos", "remote") and context.port not in (None, 80, 443, 8080):
            mixins = ["Msf::Exploit::Remote::Tcp"]
        return "auxiliary", "Msf::Auxiliary", mixins
    if requested not in ("auto", "exploit"):
        raise ValueError(f"module type must be one of auto, {', '.join(MODULE_TYPES)}")
    if edb_type == "local":
        return "exploit", "Msf::Exploit::Local", []
    if edb_type == "remote" and context.port not in (None, 80, 443, 8080):
        return "exploit", "Msf::Exploit::Remote", ["Msf::Exploit::Remote::Tcp"]
    return "exploit", "Msf::Exploit::Remote", ["Msf::Exploit::Remote::HttpClient"]


def _references(context: TemplateContext) -> list[str]:
    refs: list[str] = []
    if context.cve_id:
        refs.append(f"['CVE', '{ruby_single(context.cve_id.removeprefix('CVE-'))}']")
    for exploit in context.exploits[:5]:
        refs.append(f"['EDB', '{exploit.edb_id}']")
    urls: list[str] = []
    if context.cve:
        urls.extend(context.cve.references[:8])
    for exploit in context.exploits[:5]:
        urls.extend([exploit.advisory_url, exploit.source_url])
    for url in dict.fromkeys(urls):
        safe = safe_reference_url(url)
        if safe:
            refs.append(f"['URL', '{ruby_single(safe, 300)}']")
    return refs


RUBY_TEMPLATE = Template(
    """\
##
# CVELI RESEARCH TEMPLATE — NOT A WORKING EXPLOIT
#
# Generated by CVELI ${version} on ${generated_at} for ${record_id}.
# Product:  ${product_comment}
# Versions: ${versions_comment}
#
# This scaffold contains NO payload, NO exploitation logic and NO network
# interaction. It exists to structure an *authorized* validation effort.
#
# MANDATORY PREFLIGHT CHECKLIST (complete every item before writing code):
${checklist_comments}
#
${disclaimer}
${attribution}
##

class MetasploitModule < ${superclass}
${rank_line}${mixin_lines}
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '${name}',
        'Description' => %q{
        RESEARCH TEMPLATE ONLY.
        Complete target validation, authorization checks, and safe testing
        steps before use in an authorized environment.

${description}
        },
        'Author' => [
          '${author}' # TODO: add researcher names / handles
        ],
        'License' => MSF_LICENSE,
        'References' => [
${references}
        ],
${disclosure_line}${platform_block}        'Notes' => {
          # TODO: fill after lab validation (e.g. CRASH_SAFE, REPEATABLE_SESSION)
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
${options_block}  end

  # Non-destructive version / fingerprint validation only.
  def check
    # TODO(target-validation): identify ${product_comment} and compare the
    # detected version against the affected range (${versions_comment}).
    # Return CheckCode::Appears / Safe / Detected only with real evidence.
    CheckCode::Unknown
  end

  def ${action_method}
    # TODO(authorization): verify written authorization and scope first.
    # TODO(authentication): document any credentials the engagement provides.
    # TODO(payload-selection): decide in the lab which approach is appropriate.
    # TODO(safe-testing): non-production target, backups and rollback ready.
    unless validate_target
      fail_with(Failure::NoTarget, 'Target validation and authorization are required.')
    end

    fail_with(Failure::NoTarget, 'Target validation and authorization are required.')
  end

  private

  def validate_target
    # TODO(target-validation): implement a read-only fingerprint of the target.
    false
  end
end
"""
)


def render_ruby(context: TemplateContext) -> tuple[str, str, str]:
    """Render the .rb scaffold. Returns (ruby_source, module_type, superclass)."""
    module_type, superclass, mixins = choose_module_type(context)
    action_method = "exploit" if module_type == "exploit" else "run"
    versions = ", ".join(context.versions) or "TODO: affected versions"
    rank_line = "  Rank = ManualRanking\n\n" if module_type == "exploit" else ""
    mixin_lines = "".join(f"  include {mixin}\n" for mixin in mixins)
    disclosure = context.disclosure_date
    disclosure_line = (
        f"        'DisclosureDate' => '{ruby_single(disclosure, 10)}',\n"
        if disclosure
        else "        # TODO: 'DisclosureDate' => 'YYYY-MM-DD',\n"
    )
    platform_block = ""
    if module_type == "exploit":
        session = (
            "        'SessionTypes' => ['shell', 'meterpreter'],\n"
            if superclass == "Msf::Exploit::Local"
            else ""
        )
        platform_block = (
            f"        'Platform' => ['{context.platform}'],\n"
            f"{session}"
            "        'Targets' => [\n"
            "          ['Automatic (TODO: define tested targets)', {}]\n"
            "        ],\n"
            "        'DefaultTarget' => 0,\n"
            "        'Privileged' => false,\n"
        )
    elif module_type == "post":
        platform_block = (
            f"        'Platform' => ['{context.platform}'],\n"
            "        'SessionTypes' => ['shell', 'meterpreter'],\n"
        )
    options_block = ""
    if "Msf::Exploit::Remote::HttpClient" in mixins:
        options_block = (
            "\n    register_options(\n      [\n"
            f"        Opt::RPORT({context.port or 80}),\n"
            "        OptString.new('TARGETURI', "
            "[true, 'Base path (TODO: confirm)', '/'])"
            "\n      ]\n    )\n"
        )
    elif "Msf::Exploit::Remote::Tcp" in mixins:
        options_block = (
            "\n    register_options(\n      [\n"
            f"        Opt::RPORT({context.port or 0})  # TODO: confirm service port"
            "\n      ]\n    )\n"
        )
    references = ",\n".join(f"          {ref}" for ref in _references(context))
    source = RUBY_TEMPLATE.substitute(
        version=__version__,
        generated_at=context.generated_at,
        record_id=ruby_comment(context.record_id),
        product_comment=ruby_comment(context.product, 90),
        versions_comment=ruby_comment(versions, 90),
        checklist_comments="\n".join(f"#   [ ] {item}" for item in PREFLIGHT_CHECKLIST),
        disclaimer=comment_block(AUTHORIZED_USE_DISCLAIMER),
        attribution=comment_block(
            EXPLOITDB_ATTRIBUTION
            if context.exploits
            else "Data: NVD / CVE.org / CISA KEV / FIRST EPSS via CVELI."
        ),
        superclass=superclass,
        rank_line=rank_line,
        mixin_lines=mixin_lines,
        name=ruby_single(f"CVELI Research Template: {context.record_id}", 120),
        description=ruby_q_block(context.summary),
        author=ruby_single(context.author, 80),
        references=references or "          # TODO: add references",
        disclosure_line=disclosure_line,
        platform_block=platform_block,
        options_block=options_block,
        action_method=action_method,
    )
    return source, module_type, superclass


def _md(text: str | None) -> str:
    from core.formatter import _md_escape

    return _md_escape(text or "N/A")


def render_markdown(context: TemplateContext, module_type: str, file_stem: str) -> str:
    from core.formatter import format_cvss, format_epss

    cve = context.cve
    lines = [
        f"# Research report: {_md(context.record_id)}",
        "",
        f"> **Research template only.** {AUTHORIZED_USE_DISCLAIMER}",
        "",
        "## Preflight checklist (mandatory)",
        "",
        *[f"- [ ] {item}" for item in PREFLIGHT_CHECKLIST],
        "",
        "## Vulnerability",
        "",
        f"- **CVE:** {_md(context.cve_id or 'N/A')}",
        f"- **Affected product:** {_md(context.product)}",
        f"- **Affected versions:** {_md(', '.join(context.versions) or 'N/A')}",
        f"- **Disclosure date:** {context.disclosure_date or 'N/A'}",
    ]
    if cve:
        lines += [
            f"- **Severity / CVSS:** {cve.severity or 'N/A'} / {format_cvss(cve.cvss)}",
            f"- **EPSS:** {format_epss(cve.epss)}",
            f"- **CISA KEV:** {'yes (' + cve.kev_date + ')' if cve.kev else 'no'}",
            f"- **CWE:** {_md(cve.cwe.name) if cve.cwe else 'N/A'}",
        ]
    lines += ["", "### Description", "", _md(context.summary), ""]
    if context.exploits:
        lines += ["## Public exploit references (Exploit-DB)", ""]
        for exploit in context.exploits:
            lines.append(
                f"- EDB-{exploit.edb_id}: {_md(exploit.title)} "
                f"({exploit.date_published or 'N/A'}, {_md(exploit.platform)}, "
                f"{_md(exploit.type)}, "
                f"{'verified' if exploit.verified else 'unverified'})"
                f" — <{exploit.source_url}>"
            )
            lines.append(f"  - Labels: {', '.join(exploit.safety_labels)}")
        lines += ["", f"_{EXPLOIT_NOTICE}_", "", f"_{EXPLOITDB_ATTRIBUTION}_", ""]
    refs = [safe_reference_url(url) for url in (cve.references[:15] if cve else [])]
    if any(refs):
        lines += ["## References", "", *[f"- <{url}>" for url in refs if url], ""]
    lines += [
        "## Template",
        "",
        f"- Module type: `{module_type}`",
        f"- Scaffold: `{file_stem}.rb` (placeholders only — `check` returns "
        "`CheckCode::Unknown`, the action method always stops with `fail_with`)",
        "",
        "## Safe testing plan (TODO)",
        "",
        "1. Reproduce the vulnerable version in an isolated lab.",
        "2. Implement a read-only fingerprint in `check`.",
        "3. Agree success criteria and stop conditions with the system owner.",
        "4. Record evidence; never test outside the written scope.",
        "",
        "## Responsible disclosure",
        "",
        "Report findings to the system owner and, where applicable, the vendor or "
        "CERT/CC. Do not publish details before a fix or agreed deadline.",
        "",
        f"_Generated by CVELI {__version__} on {context.generated_at}._",
        "",
    ]
    return "\n".join(lines)


def render_json(
    context: TemplateContext, module_type: str, superclass: str
) -> dict[str, Any]:
    return {
        "schema": "cveli.msf-template/1",
        "generator": f"cveli {__version__}",
        "generated_at": context.generated_at,
        "record_id": context.record_id,
        "module_type": module_type,
        "module_class": superclass,
        "module_name": f"CVELI Research Template: {context.record_id}",
        "cve_id": context.cve_id,
        "edb_ids": [exploit.edb_id for exploit in context.exploits],
        "affected_product": context.product,
        "affected_versions": context.versions,
        "disclosure_date": context.disclosure_date or None,
        "references": {
            "cve": context.cve_id,
            "edb": [exploit.edb_id for exploit in context.exploits],
            "urls": [
                url
                for url in dict.fromkeys(
                    (context.cve.references[:15] if context.cve else [])
                    + [e.source_url for e in context.exploits]
                )
                if safe_reference_url(url)
            ],
        },
        "author": context.author,
        "license": "MSF_LICENSE (BSD-3-Clause) for the scaffold",
        "preflight_checklist": PREFLIGHT_CHECKLIST,
        "safety": {
            "research_only": True,
            "contains_payload": False,
            "contains_network_io": False,
            "notice": EXPLOIT_NOTICE,
        },
        "notes": "Placeholders only. Complete the preflight checklist first.",
    }


def file_stem(context: TemplateContext) -> str:
    return module_slug("cveli_research", context.record_id)


def to_json_text(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, default=str)
