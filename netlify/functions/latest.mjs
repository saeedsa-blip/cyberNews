// Live fetch for the "refresh" button: pulls the RSS feeds right now and
// returns the newest items, classified with the same rules as collect.py.
import { createHash } from "node:crypto";
import config from "../../config.json";

const UA = "CyberRadar/1.0";
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const AR = /[\u0600-\u06FF]/;
const has = (words, t) => words.some((w) => AR.test(w) ? t.includes(w) : new RegExp(`(^|[^\\p{L}\\p{N}_])${esc(w)}($|[^\\p{L}\\p{N}_])`, "u").test(t));

const decode = (s) => s
  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
  .replace(/<[^>]+>/g, " ")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
  .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/&amp;/g, "&")
  .replace(/\s+/g, " ").trim();

const clip = (s, n = 220) => (s.length > n ? s.slice(0, n).replace(/\s+\S*$/, "") + "…" : s);

function classify(title, summary) {
  const t = `${title} ${summary}`.toLowerCase();
  const scope = has(config.scope.local, t) ? "local" : has(config.scope.regional, t) ? "regional" : "global";
  const severity = ["critical", "high", "medium"].find((l) => has(config.severity[l], t)) || "low";
  const tag = Object.entries(config.tags).find(([, w]) => has(w, t))?.[0] || "";
  return { scope, severity, tag };
}

function parse(xml, feed) {
  const blocks = xml.match(/<item[\s>][\s\S]*?<\/item>|<entry[\s>][\s\S]*?<\/entry>/g) || [];
  const get = (b, tag) => {
    const m = b.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`));
    return m ? m[1] : "";
  };
  return blocks.map((b) => {
    let title = clip(decode(get(b, "title")), 300);
    const link = decode(get(b, "link")) || (b.match(/<link[^>]*href="([^"]+)"/) || [])[1] || "";
    let summary = clip(decode(get(b, "description") || get(b, "summary") || get(b, "content")));
    const raw = decode(get(b, "pubDate") || get(b, "published") || get(b, "updated"));
    const d = new Date(raw);
    let source = feed.name;
    if (feed.url.includes("news.google.com")) {
      const s = decode(get(b, "source"));
      if (s) { source = s; title = title.replace(new RegExp(`\\s+-\\s+${esc(s)}$`), ""); }
      summary = "";
    }
    if (!title || !/^https?:\/\//i.test(link) || isNaN(d)) return null;
    return {
      id: createHash("sha1").update(link).digest("hex").slice(0, 12),
      title, summary, link, source,
      date: d.toISOString().replace(/\.\d{3}Z$/, "Z"),
      ...classify(title, summary),
    };
  }).filter(Boolean);
}

export default async () => {
  const results = await Promise.allSettled(config.feeds.map((f) =>
    fetch(f.url, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(7000) })
      .then((r) => r.text()).then((x) => parse(x, f))));
  const seen = new Map();
  for (const r of results) if (r.status === "fulfilled") for (const it of r.value) seen.set(it.id, it);
  const items = [...seen.values()].sort((a, b) => b.date.localeCompare(a.date));
  return Response.json(
    { updated: new Date().toISOString(), failed: results.filter((r) => r.status === "rejected").length, items },
    { headers: { "Cache-Control": "public, max-age=300" } },
  );
};
