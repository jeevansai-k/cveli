"""
Google dork templates (data) and operator explanations.

Templates build *query strings only*. CVELI never sends them to Google; the
user previews, copies, or explicitly opens them in their own browser.
Credential/secret/dump/breach patterns are blocked by ``core.dork_policy``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.dork_policy import LOW, MEDIUM
from core.social_platforms import SOCIAL_PLATFORMS

SOCIAL_SITE_PRESETS: list[tuple[str, str]] = [
    (platform.label, platform.domain)
    for platform in SOCIAL_PLATFORMS
    if platform.domain not in {"github.com", "medium.com"}
]
DEVELOPER_SITE_PRESETS: list[tuple[str, str]] = [
    ("GitHub", "github.com"),
    ("GitLab", "gitlab.com"),
    ("Medium", "medium.com"),
    ("Stack Overflow", "stackoverflow.com"),
    ("Hacker News", "news.ycombinator.com"),
]
SITE_PRESETS: list[tuple[str, str]] = SOCIAL_SITE_PRESETS + DEVELOPER_SITE_PRESETS

CATEGORIES: dict[str, str] = {
    "profiles": "Public profiles",
    "social": "Social media accounts (all platforms)",
    "posts": "Public posts",
    "documents": "Public documents",
    "files": "Public files",
    "code": "Public code",
    "subdomains": "Subdomains",
    "login": "Login pages",
    "directories": "Public directories",
    "custom": "Custom query",
}
CATEGORY_RISK = {
    "subdomains": MEDIUM,
    "login": MEDIUM,
    "directories": MEDIUM,
}
NEEDS_USERNAME = {"profiles", "social", "posts", "documents", "files", "code"}
# Categories that search many platforms and therefore need no target site.
DOMAIN_OPTIONAL = {"social"}
FALSE_POSITIVE_EXCLUSIONS = ("-inurl:tag", "-inurl:search", "-inurl:hashtag")

OPERATOR_EXPLANATIONS: dict[str, str] = {
    "site": "Restricts results to {value} and its subdomains.",
    "-site": "Excludes results from {value}.",
    "inurl": "Only pages whose URL contains '{value}'.",
    "-inurl": "Excludes pages whose URL contains '{value}'.",
    "intitle": "Only pages whose title contains {value}.",
    "-intitle": "Excludes pages whose title contains {value}.",
    "filetype": "Only files of type .{value}.",
    "ext": "Only files with the .{value} extension.",
    "intext": "Only pages whose body text contains {value}.",
    "phrase": "Exact phrase match for {value}.",
    "-phrase": "Excludes pages containing the exact phrase {value}.",
    "OR": "Matches either side of OR (alternatives grouped in parentheses).",
}

_OPERATOR_RE = re.compile(
    r"(?P<neg>-)?(?P<op>site|inurl|intitle|filetype|ext|intext):"
    r'(?P<value>"[^"]*"|\([^)]*\)|\S+)'
)
_PHRASE_RE = re.compile(r'(?<![:\w])(?P<neg>-)?(?P<value>"[^"]+")')


def explain_operators(query: str) -> list[dict[str, str]]:
    """Human-readable explanation for every operator used in ``query``."""
    explained: list[dict[str, str]] = []
    consumed: list[tuple[int, int]] = []
    for match in _OPERATOR_RE.finditer(query):
        op = ("-" if match.group("neg") else "") + match.group("op")
        value = match.group("value")
        template = OPERATOR_EXPLANATIONS.get(op, "Search operator {value}.")
        if op == "site" and "/" in value:
            template = "Only pages under {value} (that profile URL and its sub-pages)."
        explained.append(
            {
                "op": f"{op}:",
                "value": value,
                "explanation": template.format(value=value.strip("\"'")),
            }
        )
        consumed.append(match.span())
    for match in _PHRASE_RE.finditer(query):
        if any(start <= match.start() < end for start, end in consumed):
            continue
        key = "-phrase" if match.group("neg") else "phrase"
        explained.append(
            {
                "op": '-""' if match.group("neg") else '""',
                "value": match.group("value"),
                "explanation": OPERATOR_EXPLANATIONS[key].format(
                    value=match.group("value")
                ),
            }
        )
    if re.search(r"\sOR\s", query):
        explained.append(
            {"op": "OR", "value": "", "explanation": OPERATOR_EXPLANATIONS["OR"]}
        )
    return explained


@dataclass(frozen=True)
class DorkTemplate:
    id: str
    label: str
    category: str
    pattern: str
    explanation: str
    risk_level: str = LOW
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def render(self, **values: str) -> str:
        return re.sub(r"\s+", " ", self.pattern.format(**values)).strip()


INFRA_WARNING = (
    "This query surfaces public infrastructure of the target domain. Use it only "
    "with written authorization from the domain owner (e.g. an agreed pentest "
    "or bug-bounty scope)."
)

TEMPLATES: list[DorkTemplate] = [
    DorkTemplate(
        "public_profile_domain",
        "Public profile mentions",
        "profiles",
        "site:{domain} {user}",
        "Finds pages on {domain} that mention the username.",
    ),
    DorkTemplate(
        "profile_title",
        "Profile page by title",
        "profiles",
        "site:{domain} intitle:{user}",
        "Finds pages on {domain} whose title contains the username.",
    ),
    DorkTemplate(
        "profile_url",
        "Profile URL path",
        "profiles",
        "site:{domain} inurl:{user_url}",
        "Finds pages on {domain} whose URL contains the username (typical profile "
        "paths).",
    ),
    DorkTemplate(
        "public_posts",
        "Public posts and comments",
        "posts",
        "site:{domain} {user} (inurl:post OR inurl:status OR inurl:comments)",
        "Finds public posts, statuses or comment pages on {domain} that mention "
        "the username.",
    ),
    DorkTemplate(
        "public_documents",
        "Public documents",
        "documents",
        "site:{domain} filetype:{filetype} {user}",
        "Finds publicly indexed {filetype} documents on {domain} mentioning the "
        "username.",
    ),
    DorkTemplate(
        "public_files",
        "Public office/text files",
        "files",
        "site:{domain} (filetype:docx OR filetype:pptx OR filetype:txt) {user}",
        "Finds publicly indexed office or text files on {domain} mentioning the "
        "username.",
    ),
    DorkTemplate(
        "code_github",
        "GitHub code mentions",
        "code",
        'site:github.com {user} "{domain}"',
        "Finds public GitHub pages mentioning both the username and {domain}.",
    ),
    DorkTemplate(
        "code_gitlab",
        "GitLab code mentions",
        "code",
        'site:gitlab.com {user} "{domain}"',
        "Finds public GitLab pages mentioning both the username and {domain}.",
    ),
    DorkTemplate(
        "subdomains",
        "Indexed subdomains",
        "subdomains",
        "site:*.{domain} -site:www.{domain}",
        "Lists publicly indexed subdomains of {domain} (excluding www).",
        MEDIUM,
        (INFRA_WARNING,),
    ),
    DorkTemplate(
        "login_pages",
        "Public login pages",
        "login",
        'site:{domain} (inurl:login OR inurl:signin OR intitle:"sign in")',
        "Finds publicly indexed sign-in pages on {domain}.",
        MEDIUM,
        (INFRA_WARNING,),
    ),
    DorkTemplate(
        "public_directories",
        "Public directory listings",
        "directories",
        'site:{domain} intitle:"index of"',
        "Finds publicly indexed directory listings on {domain}.",
        MEDIUM,
        (INFRA_WARNING,),
    ),
]

TEMPLATES_BY_ID = {template.id: template for template in TEMPLATES}


def templates_for(category: str) -> list[DorkTemplate]:
    return [template for template in TEMPLATES if template.category == category]
