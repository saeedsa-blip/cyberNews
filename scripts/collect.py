"""Collects cyber news (RSS) and threat intel (AlienVault OTX) into data/*.json.

Runs daily from GitHub Actions. No third-party packages needed.
OTX key comes from the OTX_API_KEY environment variable (a GitHub Secret).
"""
import hashlib
import html
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
KEEP_DAYS = 365
UA = "CyberRadar/1.0 (+https://github.com)"
ATOM = "{http://www.w3.org/2005/Atom}"

with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as f:
    CFG = json.load(f)


def fetch(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read()


def load(name):
    try:
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"updated": None, "items": []}


def save(name, items):
    with open(os.path.join(DATA, name), "w", encoding="utf-8") as f:
        json.dump({"updated": now_iso(), "items": items}, f, ensure_ascii=False, separators=(",", ":"))


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(s, limit=220):
    s = html.unescape(re.sub(r"<[^>]+>", " ", s or ""))
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[:limit].rsplit(" ", 1)[0] + "…"
    return s


ARABIC = re.compile(r"[\u0600-\u06FF]")


def has(words, text):
    # Arabic words carry attached prefixes (ال، و، ب) so they match as substrings;
    # English words must match whole words ("oman" must not match "woman").
    return any((w in text) if ARABIC.search(w) else re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", text) for w in words)


def classify(title, summary):
    t = f"{title} {summary}".lower()
    scope = "local" if has(CFG["scope"]["local"], t) else "regional" if has(CFG["scope"]["regional"], t) else "global"
    sev = "low"
    for level in ("critical", "high", "medium"):
        if has(CFG["severity"][level], t):
            sev = level
            break
    tag = next((name for name, words in CFG["tags"].items() if has(words, t)), "")
    return scope, sev, tag


def parse_feed(raw, feed):
    root = ET.fromstring(raw)
    out = []
    nodes = root.findall(".//item") or root.findall(f".//{ATOM}entry")
    for n in nodes:
        def g(*tags):
            for t in tags:
                x = n.find(t)
                if x is not None:
                    return (x.text or x.get("href") or "").strip()
            return ""
        title = clean(g("title", f"{ATOM}title"), 300)
        link = g("link", f"{ATOM}link")
        summary = clean(g("description", f"{ATOM}summary", f"{ATOM}content"))
        date = parse_date(g("pubDate", f"{ATOM}published", f"{ATOM}updated"))
        source = feed["name"]
        if "news.google.com" in feed["url"]:
            src = n.find("source")
            if src is not None and src.text:
                source = src.text.strip()
                title = re.sub(r"\s+-\s+" + re.escape(source) + r"$", "", title)
            summary = ""  # Google News descriptions are just link lists
        if not (title and date and re.match(r"https?://", link or "")):
            continue
        scope, sev, tag = classify(title, summary)
        out.append({
            "id": hashlib.sha1(link.encode()).hexdigest()[:12],
            "title": title, "summary": summary, "link": link,
            "source": source, "date": date,
            "scope": scope, "severity": sev, "tag": tag,
        })
    return out


def collect_news():
    old = {i["id"]: i for i in load("news.json")["items"]}
    added = 0
    for feed in CFG["feeds"]:
        try:
            items = parse_feed(fetch(feed["url"]), feed)
            for it in items:
                if it["id"] not in old:
                    added += 1
                old[it["id"]] = it
            print(f"ok   {feed['name']}: {len(items)}")
        except Exception as e:  # one bad feed must not stop the rest
            print(f"FAIL {feed['name']}: {e}", file=sys.stderr)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    items = sorted((i for i in old.values() if i["date"] >= cutoff), key=lambda i: i["date"], reverse=True)
    save("news.json", items)
    print(f"news: {added} new, {len(items)} total")


def names(lst):
    return [(x.get("display_name") or x.get("name") or x.get("id") or "") if isinstance(x, dict) else str(x) for x in (lst or [])]


def collect_intel():
    key = os.environ.get("OTX_API_KEY")
    if not key:
        print("skip OTX: no OTX_API_KEY")
        return
    data = load("intel.json")
    old = {i["id"]: i for i in data["items"]}
    since = (datetime.now(timezone.utc) - timedelta(days=30 if not old else 3)).strftime("%Y-%m-%dT%H:%M:%S")
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since={since}"
    pages = 0
    while url and pages < 20:
        try:
            page = json.loads(fetch(url, {"X-OTX-API-KEY": key}))
        except Exception as e:
            print(f"FAIL OTX: {e}", file=sys.stderr)
            break
        for p in page.get("results", []):
            attacks = [a.get("id") if isinstance(a, dict) else str(a) for a in (p.get("attack_ids") or [])]
            old[p["id"]] = {
                "id": p["id"],
                "date": (p.get("created") or "")[:10],
                "name": p.get("name", "")[:160],
                "countries": p.get("targeted_countries") or [],
                "industries": p.get("industries") or [],
                "adversary": p.get("adversary") or "",
                "malware": names(p.get("malware_families"))[:3],
                "attacks": [a for a in attacks if a][:20],
                "tags": [t.lower() for t in (p.get("tags") or [])][:12],
            }
        url = page.get("next")
        pages += 1
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
    items = sorted((i for i in old.values() if i["date"] >= cutoff), key=lambda i: i["date"], reverse=True)
    save("intel.json", items)
    print(f"intel: {len(items)} reports")


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    collect_news()
    collect_intel()
