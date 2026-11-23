"""
Social-media platform knowledge for the Dork Builder.

Why this exists: social networks publish each public profile at a predictable
URL (``instagram.com/<user>``, ``snapchat.com/add/<user>``,
``tiktok.com/@<user>``), and the username is often *not* in the page text that
Google indexes. Generic text queries such as ``site:instagram.com "alice"``
therefore miss profiles or drown them in unrelated posts.

The most reliable Google operators for finding a specific account are:

* ``site:instagram.com/alice`` — ``site:`` accepts a URL prefix, so this matches
  exactly the profile and its sub-pages;
* ``intitle:"@alice"`` — most networks put ``(@handle)`` in the page title;
* ``"instagram.com/alice" -site:instagram.com`` — other sites linking to the
  profile (link-in-bio pages, articles, other networks).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SocialPlatform:
    domain: str
    label: str
    # Profile URL paths relative to the domain; ``{u}`` is the handle.
    profile_paths: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    extra_domains: tuple[str, ...] = field(default_factory=tuple)
    # Characters allowed in a handle on this platform (lower-cased if ``lower``).
    handle_pattern: str = r"[A-Za-z0-9._-]+"
    lower: bool = True
    title_has_at: bool = True  # page titles contain "(@handle)"

    def sites(self) -> list[str]:
        return [self.domain, *self.extra_domains]


SOCIAL_PLATFORMS: tuple[SocialPlatform, ...] = (
    SocialPlatform(
        "instagram.com",
        "Instagram",
        ("{u}",),
        ("instagram", "insta", "ig"),
        handle_pattern=r"[a-z0-9._]+",
    ),
    SocialPlatform(
        "facebook.com",
        "Facebook",
        ("{u}",),
        ("facebook", "fb"),
        handle_pattern=r"[A-Za-z0-9.]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "x.com",
        "X / Twitter",
        ("{u}",),
        ("x", "twitter"),
        ("twitter.com",),
        handle_pattern=r"[A-Za-z0-9_]+",
        lower=False,
    ),
    SocialPlatform(
        "tiktok.com", "TikTok", ("@{u}",), ("tiktok",), handle_pattern=r"[a-z0-9._]+"
    ),
    SocialPlatform(
        "snapchat.com",
        "Snapchat",
        ("add/{u}", "@{u}"),
        ("snapchat", "snap"),
        handle_pattern=r"[a-z0-9._-]+",
    ),
    SocialPlatform(
        "linkedin.com",
        "LinkedIn",
        ("in/{u}",),
        ("linkedin",),
        handle_pattern=r"[a-z0-9-]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "reddit.com",
        "Reddit",
        ("user/{u}", "u/{u}"),
        ("reddit",),
        handle_pattern=r"[A-Za-z0-9_-]+",
        lower=False,
        title_has_at=False,
    ),
    SocialPlatform(
        "youtube.com",
        "YouTube",
        ("@{u}", "c/{u}", "user/{u}"),
        ("youtube", "yt"),
        handle_pattern=r"[A-Za-z0-9._-]+",
    ),
    SocialPlatform(
        "threads.net",
        "Threads",
        ("@{u}",),
        ("threads",),
        ("threads.com",),
        handle_pattern=r"[a-z0-9._]+",
    ),
    SocialPlatform(
        "pinterest.com",
        "Pinterest",
        ("{u}",),
        ("pinterest",),
        handle_pattern=r"[A-Za-z0-9_]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "tumblr.com",
        "Tumblr",
        ("{u}",),
        ("tumblr",),
        handle_pattern=r"[a-z0-9-]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "twitch.tv",
        "Twitch",
        ("{u}",),
        ("twitch",),
        handle_pattern=r"[a-z0-9_]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "t.me",
        "Telegram",
        ("{u}",),
        ("telegram", "tg"),
        handle_pattern=r"[A-Za-z0-9_]+",
        lower=False,
    ),
    SocialPlatform(
        "bsky.app",
        "Bluesky",
        ("profile/{u}",),
        ("bluesky", "bsky"),
        handle_pattern=r"[a-z0-9.-]+",
    ),
    SocialPlatform(
        "mastodon.social",
        "Mastodon",
        ("@{u}",),
        ("mastodon",),
        handle_pattern=r"[A-Za-z0-9_]+",
        lower=False,
    ),
    SocialPlatform(
        "vk.com",
        "VK",
        ("{u}",),
        ("vk", "vkontakte"),
        handle_pattern=r"[a-z0-9_.]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "github.com",
        "GitHub",
        ("{u}",),
        ("github",),
        handle_pattern=r"[A-Za-z0-9-]+",
        lower=False,
        title_has_at=False,
    ),
    SocialPlatform(
        "medium.com",
        "Medium",
        ("@{u}",),
        ("medium",),
        handle_pattern=r"[A-Za-z0-9._-]+",
        lower=False,
        title_has_at=False,
    ),
    SocialPlatform(
        "quora.com",
        "Quora",
        ("profile/{u}",),
        ("quora",),
        handle_pattern=r"[A-Za-z0-9-]+",
        lower=False,
        title_has_at=False,
    ),
    SocialPlatform(
        "linktr.ee",
        "Linktree",
        ("{u}",),
        ("linktree",),
        handle_pattern=r"[A-Za-z0-9._]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "soundcloud.com",
        "SoundCloud",
        ("{u}",),
        ("soundcloud",),
        handle_pattern=r"[a-z0-9_-]+",
        title_has_at=False,
    ),
    SocialPlatform(
        "flickr.com",
        "Flickr",
        ("people/{u}", "photos/{u}"),
        ("flickr",),
        handle_pattern=r"[A-Za-z0-9@_.-]+",
        lower=False,
        title_has_at=False,
    ),
)

PLATFORMS_BY_DOMAIN = {
    domain: platform for platform in SOCIAL_PLATFORMS for domain in platform.sites()
}
ALIASES = {
    alias: platform.domain
    for platform in SOCIAL_PLATFORMS
    for alias in platform.aliases
}
# Largest networks, used for the combined "social footprint" query (kept short
# so the query stays within Google's ~32-term limit).
FOOTPRINT_DOMAINS = (
    "instagram.com",
    "facebook.com",
    "x.com",
    "tiktok.com",
    "snapchat.com",
    "linkedin.com",
    "reddit.com",
    "youtube.com",
    "threads.net",
    "pinterest.com",
)


def platform_for(domain: str) -> SocialPlatform | None:
    return PLATFORMS_BY_DOMAIN.get(domain.lower().removeprefix("www."))


def resolve_alias(name: str) -> str | None:
    """Map a bare platform name (``snapchat``) to its domain."""
    return ALIASES.get(name.strip().lower())


def handle_for(platform: SocialPlatform, username: str) -> tuple[str, list[str]]:
    """Turn user input into a handle valid on ``platform`` (plus notes).

    Spaces and characters the platform never allows in handles are removed,
    so a display name such as "Cristiano Ronaldo" still yields a usable
    URL query ("cristianoronaldo") while text queries keep the full name.
    """
    notes: list[str] = []
    raw = username.strip().removeprefix("@")
    handle = re.sub(r"\s+", "", raw)
    if platform.lower:
        handle = handle.lower()
    allowed = re.compile(rf"^{platform.handle_pattern}$")
    if not allowed.match(handle):
        cleaned = "".join(ch for ch in handle if allowed.match(ch))
        if cleaned != handle:
            notes.append(
                f"{platform.label} handles can't contain some of the characters "
                f"you entered; profile-URL queries use '{cleaned}'."
            )
        handle = cleaned
    elif handle != raw:
        notes.append(f"{platform.label} profile-URL queries use the handle '{handle}'.")
    if platform.domain == "bsky.app" and handle and "." not in handle:
        handle = f"{handle}.bsky.social"
    return handle, notes


def _group(terms: list[str]) -> str:
    return terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"


def profile_url_query(platform: SocialPlatform, handle: str) -> str:
    """``site:<profile URL>`` — matches exactly the account's own pages."""
    urls = [
        f"{site}/{path.format(u=handle)}"
        for site in platform.sites()
        for path in platform.profile_paths
    ]
    return _group([f"site:{url}" for url in urls])


def profile_links(platform: SocialPlatform, handle: str) -> list[str]:
    return [
        f"{platform.domain}/{path.format(u=handle)}" for path in platform.profile_paths
    ]


def site_clause(platform: SocialPlatform) -> str:
    return _group([f"site:{site}" for site in platform.sites()])


def title_query(platform: SocialPlatform, handle: str) -> str:
    """Profile pages whose title carries the handle."""
    token = f"@{handle}" if platform.title_has_at else handle
    return f'{site_clause(platform)} intitle:"{token}"'


def mention_query(platform: SocialPlatform, handle: str) -> str:
    """Pages on the platform that mention ``@handle``."""
    return f'{site_clause(platform)} "@{handle}"'


def external_links_query(platform: SocialPlatform, handle: str) -> str:
    """Other websites that link to the profile URL."""
    links = [f'"{link}"' for link in profile_links(platform, handle)]
    excluded = " ".join(f"-site:{site}" for site in platform.sites())
    return f"{_group(links)} {excluded}"


# Backwards-compatible name used by earlier releases.
def profile_query(platform: SocialPlatform, username: str) -> str:
    handle, _ = handle_for(platform, username)
    return profile_url_query(platform, handle)
