"""
Derive a slim runtime-friendly bot-patterns.json from the canonical
well-known-bots.json (sourced from arcjet/well-known-bots, MIT licensed).

Mapping notes:
  - We collapse Arcjet's 22-tag taxonomy into our 6-category enum
    (SEARCH_ENGINE, SOCIAL, MONITORING, AI_CRAWLER, SCRAPER, AUTOMATED).
  - Known headless / browser-automation IDs override category to AUTOMATED.
  - Entries without a pattern.accepted are skipped.
  - Forbidden patterns are kept to avoid false positives (e.g., Googlebot
    forbidden from matching Google's mobile-friendly tool variant).

Run after upgrading well-known-bots.json:
  python packages/core/generate-bot-patterns.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
REPO = ROOT.parent.parent  # arcis repo root
SOURCE = ROOT / "well-known-bots.json"
DEST = ROOT / "bot-patterns.json"

# Per-SDK data directories. The slim JSON is duplicated here so each SDK
# can bundle its own copy without reaching outside its package boundary.
SDK_DESTS = [
    REPO / "packages" / "arcis-node" / "src" / "data" / "bot-patterns.json",
    REPO / "packages" / "arcis-python" / "arcis" / "data" / "bot_patterns.json",
    REPO / "packages" / "arcis-go" / "middleware" / "data" / "bot_patterns.json",
]

# Supplementary patterns not in arcjet/well-known-bots (browser automation
# frameworks, headless drivers, common fakes). Mirrors what was previously
# hardcoded in each SDK's bot-detection module so we don't regress on those.
SUPPLEMENTARY = [
    {"id": "puppeteer",         "category": "AUTOMATED", "name": "Puppeteer",         "patterns": ["[Pp]uppeteer"],         "forbidden": []},
    {"id": "playwright",        "category": "AUTOMATED", "name": "Playwright",        "patterns": ["[Pp]laywright"],        "forbidden": []},
    {"id": "selenium",          "category": "AUTOMATED", "name": "Selenium",          "patterns": ["[Ss]elenium"],          "forbidden": []},
    {"id": "cypress",           "category": "AUTOMATED", "name": "Cypress",           "patterns": ["[Cc]ypress"],           "forbidden": []},
    {"id": "webdriver",         "category": "AUTOMATED", "name": "WebDriver",         "patterns": ["[Ww]ebdriver"],         "forbidden": []},
    {"id": "fake-msie6",        "category": "AUTOMATED", "name": "Fake IE6",          "patterns": ["MSIE 6\\.0"],            "forbidden": []},
    {"id": "python-httpx",      "category": "SCRAPER",   "name": "python-httpx",      "patterns": ["^python-httpx\\/"],     "forbidden": []},
    {"id": "python-urllib",     "category": "SCRAPER",   "name": "Python-urllib",     "patterns": ["^Python-urllib"],        "forbidden": []},
    {"id": "python-aiohttp",    "category": "SCRAPER",   "name": "aiohttp",           "patterns": ["^aiohttp\\/"],           "forbidden": []},
    {"id": "java-stdlib",       "category": "SCRAPER",   "name": "Java HttpClient",   "patterns": ["^Java\\/"],              "forbidden": []},
    {"id": "got",               "category": "SCRAPER",   "name": "got",               "patterns": ["^got\\/"],              "forbidden": []},
    {"id": "ruby",              "category": "SCRAPER",   "name": "Ruby",              "patterns": ["^Ruby"],                "forbidden": []},
    {"id": "php-ua",            "category": "SCRAPER",   "name": "PHP",               "patterns": ["^PHP\\/"],              "forbidden": []},
    {"id": "insomnia",          "category": "SCRAPER",   "name": "Insomnia",          "patterns": ["^[iI]nsomnia"],         "forbidden": []},
    {"id": "httpie",            "category": "SCRAPER",   "name": "HTTPie",            "patterns": ["^HTTPie\\/"],           "forbidden": []},
    # AI crawler UAs Arcjet's `anthropic-crawler` (which matches Claude*) does
    # not catch — these match the literal token strings used by Anthropic and
    # Meta's external scrapers in the wild.
    # Loose YandexBot fallback. Arcjet's official `yandex\\.com\\/bots` only
    # matches when the UA includes the URL — minimal test UAs and some legit
    # variants (e.g. `YandexBot/3.0` without the URL) wouldn't match otherwise.
    {"id": "yandex-loose",        "category": "SEARCH_ENGINE", "name": "YandexBot",  "patterns": ["YandexBot"],         "forbidden": []},
    {"id": "anthropic-ai-token",  "category": "AI_CRAWLER", "name": "Anthropic",       "patterns": ["anthropic-ai"],          "forbidden": []},
    {"id": "meta-externalagent",  "category": "AI_CRAWLER", "name": "Meta AI",         "patterns": ["meta-externalagent"],    "forbidden": []},
    # Loose Postman fallback — Arcjet's `PostmanRuntime\\/` is correct for the
    # current product but doesn't catch UAs of the form `Postman Runtime/X.Y`
    # (with a space) that older clients still send.
    {"id": "postman-loose",       "category": "SCRAPER",    "name": "Postman",         "patterns": ["^Postman[ /]"],          "forbidden": []},
]

# IDs we explicitly treat as AUTOMATED (headless / testing / scraping frameworks).
AUTOMATED_IDS = {
    "headless-chrome",
    "javascript-phantom",
    "puppeteer",
    "playwright",
    "selenium",
    "cypress",
    "webdriver",
}

# Tag → our category. First match wins. SOCIAL / SEARCH / MONITOR / SCRAPER
# are checked BEFORE AI so multi-tag entries like Facebook (`['ai', 'meta',
# 'preview', 'social']`) and Scrapy (`['ai', 'programmatic']`) land in the
# more user-facing bucket. `ai` only wins for entries tagged ONLY as AI.
TAG_PRIORITY = [
    ("social", "SOCIAL"),
    ("preview", "SOCIAL"),
    ("slack", "SOCIAL"),
    ("vercel", "SOCIAL"),
    ("webhook", "SOCIAL"),
    ("monitor", "MONITORING"),
    ("search-engine", "SEARCH_ENGINE"),
    ("google", "SEARCH_ENGINE"),
    ("microsoft", "SEARCH_ENGINE"),
    ("yahoo", "SEARCH_ENGINE"),
    ("apple", "SEARCH_ENGINE"),
    ("amazon", "SEARCH_ENGINE"),
    ("meta", "SEARCH_ENGINE"),
    ("archive", "SEARCH_ENGINE"),
    ("feedfetcher", "SEARCH_ENGINE"),
    ("programmatic", "SCRAPER"),
    ("tool", "SCRAPER"),
    ("optimizer", "SCRAPER"),
    ("advertising", "SCRAPER"),
    ("academic", "SCRAPER"),
    ("ai", "AI_CRAWLER"),
]

# IDs whose category we override regardless of the upstream tags. Keeps the
# detection result aligned with our taxonomy when Arcjet's tags either omit
# the obvious classification or assign one we'd surface differently.
ID_CATEGORY_OVERRIDES = {
    "baidu-crawler": "SEARCH_ENGINE",
    # CCBot is Common Crawl. Arcjet tags it `archive` only, but the well-known
    # use case is that AI training pipelines pull from CC, so treat it as AI
    # for allow/deny ergonomics.
    "ccbot-crawler": "AI_CRAWLER",
}

# IDs whose user-facing name we prefer over Arcjet's first-alias choice. The
# overrides match conventional naming (most users say "Pingdom", not "Pingdom
# Bot"; "Googlebot", not "GoogleBot"). When an entry has no entry here AND no
# alias, we fall through to the raw id so single-token tools like `curl`,
# `wget`, and `axios` keep their canonical lowercase form.
NAME_OVERRIDES = {
    "google-crawler": "Googlebot",
    "google-crawler-image": "Googlebot-Image",
    "google-crawler-video": "Googlebot-Video",
    "google-crawler-news": "Googlebot-News",
    "bing-crawler": "Bingbot",
    "baidu-crawler": "Baiduspider",
    "twitter-crawler": "Twitterbot",
    "facebook-share-crawler": "Facebook",
    "slack-crawler": "Slackbot",
    "whatsapp-crawler": "WhatsApp",
    "discord-crawler": "Discordbot",
    "pingdom-crawler": "Pingdom",
    "datadog-monitor-synthetics": "Datadog",
    "openai-crawler": "GPTBot",
    "openai-user": "ChatGPT-User",
    "perplexity-crawler": "PerplexityBot",
    "ccbot-crawler": "CCBot",
    "bytedance-crawler": "Bytespider",
    "anthropic-crawler": "ClaudeBot",
    "javascript-phantom": "PhantomJS",
    "javascript-axios": "axios",
    "javascript-node-fetch": "node-fetch",
    "java-okhttp": "OkHttp",
    "java-apache-httpclient": "Apache HttpClient",
    "go-http": "Go-http-client",
    "python-requests": "python-requests",
    "python-scrapy": "Scrapy",
    "perl-libwww": "libwww-perl",
    "headless-chrome": "Headless Chrome",
    "postman": "Postman",
}


def map_category(entry: dict) -> str:
    if entry["id"] in AUTOMATED_IDS:
        return "AUTOMATED"
    if entry["id"] in ID_CATEGORY_OVERRIDES:
        return ID_CATEGORY_OVERRIDES[entry["id"]]
    cats = set(entry.get("categories", []))
    for tag, mapped in TAG_PRIORITY:
        if tag in cats:
            return mapped
    return "UNKNOWN"


def derive_name(entry: dict) -> str:
    if entry["id"] in NAME_OVERRIDES:
        return NAME_OVERRIDES[entry["id"]]
    aliases = entry.get("aliases") or []
    if aliases:
        return aliases[0]
    # No alias: keep the raw id (e.g. `curl`, `wget`, `httpie`). For
    # hyphenated ids, the hyphenated form usually IS the canonical name
    # (e.g. `python-httpx`, `node-fetch`).
    return entry["id"]


def main() -> None:
    with SOURCE.open() as f:
        source = json.load(f)

    out = []
    for entry in source:
        accepted = entry["pattern"].get("accepted") or []
        if not accepted:
            continue
        out.append({
            "id": entry["id"],
            "category": map_category(entry),
            "name": derive_name(entry),
            "patterns": accepted,
            "forbidden": entry["pattern"].get("forbidden") or [],
        })

    # Merge supplementary entries (browser automation tools etc) and dedupe by id.
    seen = {e["id"] for e in out}
    for extra in SUPPLEMENTARY:
        if extra["id"] not in seen:
            out.append(extra)
            seen.add(extra["id"])

    # Stable sort: by category then id, so diffs read cleanly
    out.sort(key=lambda e: (e["category"], e["id"]))

    serialized = json.dumps(out, indent=2)
    DEST.write_text(serialized)
    for sdk_dest in SDK_DESTS:
        sdk_dest.parent.mkdir(parents=True, exist_ok=True)
        sdk_dest.write_text(serialized)

    # Summary
    from collections import Counter
    cats = Counter(e["category"] for e in out)
    print(f"Wrote {len(out)} bot patterns to {DEST}")
    for sdk_dest in SDK_DESTS:
        print(f"  + {sdk_dest.relative_to(REPO)}")
    print()
    for c, n in cats.most_common():
        print(f"  {n:5d}  {c}")


if __name__ == "__main__":
    main()
