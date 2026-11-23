"""
Social-media platform knowledge for the Dork Builder.

Most social networks expose a public profile at a predictable URL path
(e.g. ``snapchat.com/add/<user>``, ``tiktok.com/@<user>``), and the username
often does not appear in the page text Google indexes. A plain
``site:snapchat.com "alice"`` query therefore finds little; matching the
profile URL path with ``inurl:`` works much better.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SocialPlatform:
    domain: str
    label: str
    profile_paths: tuple[str, ...]  # URL path patterns, ``{u}`` = username
    aliases: tuple[str, ...] = ()
    extra_domains: tuple[str, ...] = field(default_factory=tuple)

    def sites(self) -> list[str]:
        return [self.domain, *self.extra_domains]


SOCIAL_PLATFORMS: tuple[SocialPlatform, ...] = (
    SocialPlatform(
        "instagram.com", "Instagram", ("{u}",), ("instagram", "insta", "ig")
    ),
    SocialPlatform("facebook.com", "Facebook", ("{u}",), ("facebook", "fb")),
    SocialPlatform(
        "x.com",
        "X / Twitter",
        ("{u}",),
        ("x", "twitter"),
        ("twitter.com",),
    ),
    SocialPlatform("tiktok.com", "TikTok", ("@{u}",), ("tiktok",)),
    SocialPlatform(
        "snapchat.com", "Snapchat", ("add/{u}", "@{u}"), ("snapchat", "snap")
    ),
    SocialPlatform("linkedin.com", "LinkedIn", ("in/{u}",), ("linkedin",)),
    SocialPlatform("reddit.com", "Reddit", ("user/{u}", "u/{u}"), ("reddit",)),
    SocialPlatform(
        "youtube.com", "YouTube", ("@{u}", "c/{u}", "user/{u}"), ("youtube", "yt")
    ),
    SocialPlatform("threads.net", "Threads", ("@{u}",), ("threads",)),
    SocialPlatform("pinterest.com", "Pinterest", ("{u}",), ("pinterest",)),
    SocialPlatform("tumblr.com", "Tumblr", ("{u}",), ("tumblr",)),
    SocialPlatform("twitch.tv", "Twitch", ("{u}",), ("twitch",)),
    SocialPlatform("t.me", "Telegram", ("{u}",), ("telegram", "tg")),
    SocialPlatform("bsky.app", "Bluesky", ("profile/{u}",), ("bluesky", "bsky")),
    SocialPlatform("mastodon.social", "Mastodon", ("@{u}",), ("mastodon",)),
    SocialPlatform("vk.com", "VK", ("{u}",), ("vk", "vkontakte")),
    SocialPlatform("github.com", "GitHub", ("{u}",), ("github",)),
    SocialPlatform("medium.com", "Medium", ("@{u}",), ("medium",)),
    SocialPlatform("quora.com", "Quora", ("profile/{u}",), ("quora",)),
    SocialPlatform("linktr.ee", "Linktree", ("{u}",), ("linktree",)),
    SocialPlatform("soundcloud.com", "SoundCloud", ("{u}",), ("soundcloud",)),
    SocialPlatform("flickr.com", "Flickr", ("people/{u}", "photos/{u}"), ("flickr",)),
)

PLATFORMS_BY_DOMAIN = {
    domain: platform for platform in SOCIAL_PLATFORMS for domain in platform.sites()
}
ALIASES = {
    alias: platform.domain
    for platform in SOCIAL_PLATFORMS
    for alias in platform.aliases
}
# Big networks used for the combined "social footprint" query (kept short so
# the query stays within Google's ~32-term limit).
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


def profile_query(platform: SocialPlatform, username: str) -> str:
    """``site:`` + ``inurl:`` query matching the platform's profile URL."""
    user = username.replace(" ", "")
    sites = platform.sites()
    site_clause = (
        f"site:{sites[0]}"
        if len(sites) == 1
        else "(" + " OR ".join(f"site:{site}" for site in sites) + ")"
    )
    paths = [f'inurl:"{path.format(u=user)}"' for path in platform.profile_paths]
    path_clause = paths[0] if len(paths) == 1 else "(" + " OR ".join(paths) + ")"
    return f"{site_clause} {path_clause}"
