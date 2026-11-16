/**
 * ニュース記事プロキシ(Cloudflare Workers)
 *
 *   https://<your-worker>.workers.dev/?url=<記事のURL(URLエンコード)>            … リーダー表示(既定)
 *   https://<your-worker>.workers.dev/?url=<記事のURL(URLエンコード)>&mode=raw   … 元ページをそのまま表示
 *
 * リーダー表示: 記事の本文だけを取り出し、ダーク配色の読みやすいページとして返します。
 * 元ページ表示: 埋め込み禁止のヘッダーを外し、スクリプトを除去して返します。
 *
 * 取得を許可するのは許可リストのドメインだけです。個人利用の範囲で使い、
 * 各社の利用規約を確認してください(転載・再配布はしないでください)。
 */

const ALLOWED_HOSTS = ["nhk.or.jp", "news.web.nhk", "news.yahoo.co.jp"];

// このプロキシのページを埋め込んでよいサイト(CSPのframe-ancestors)。
// 時計ページの置き場所が決まったら "https://your-clock.example.com" のように絞ってください。
const FRAME_ANCESTORS = "https://user-x45.github.io";

const MAX_REDIRECTS = 4;
const MAX_BYTES = 5 * 1024 * 1024;
const CACHE_SECONDS = 300;
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

function isAllowedHost(hostname) {
  const h = hostname.toLowerCase();
  return ALLOWED_HOSTS.some((d) => h === d || h.endsWith("." + d));
}

function parseTarget(raw, base) {
  try {
    const u = new URL(raw, base);
    if (u.protocol !== "https:") return null;
    if (u.username || u.password) return null;
    if (u.port && u.port !== "443") return null;
    if (!isAllowedHost(u.hostname)) return null;
    return u;
  } catch {
    return null;
  }
}

function text(status, body) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const baseHeaders = (type, extraCsp = []) =>
  new Headers({
    "Content-Type": type,
    "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": [
      "default-src 'none'",
      "img-src https: data:",
      ...extraCsp,
      "base-uri https:",
      "form-action 'none'",
      `frame-ancestors ${FRAME_ANCESTORS}`,
      "sandbox",
    ].join("; "),
  });

// リダイレクトは手動で追い、毎回ドメインを検証する(SSRF対策)
async function load(target) {
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    let res;
    try {
      res = await fetch(target.href, {
        redirect: "manual",
        headers: { "User-Agent": UA, "Accept": "text/html,application/xhtml+xml", "Accept-Language": "ja,en;q=0.8" },
        cf: { cacheTtl: CACHE_SECONDS, cacheEverything: true },
      });
    } catch {
      return { err: text(502, "取得に失敗しました") };
    }
    if (res.status >= 300 && res.status < 400 && res.headers.get("Location")) {
      const next = parseTarget(res.headers.get("Location"), target);
      if (!next) return { err: text(403, "許可されていないドメインへのリダイレクトです") };
      target = next;
      continue;
    }
    if (!res.ok) return { err: text(res.status, `取得先がエラーを返しました(${res.status})`) };
    const type = res.headers.get("Content-Type") || "";
    if (!/text\/html|application\/xhtml\+xml/i.test(type)) return { err: text(415, "HTML以外は対応していません") };
    if (Number(res.headers.get("Content-Length") || 0) > MAX_BYTES) return { err: text(413, "ページが大きすぎます") };
    return { res, target, type };
  }
  return { err: text(508, "リダイレクトが多すぎます") };
}

/* ---------------- リーダー表示 ---------------- */

const clean = (s) => s.replace(/\s+/g, " ").trim();
const SKIP = /^(©|Copyright|関連記事|関連ニュース|この記事を|広告)/i;

function collector() {
  const items = [];
  let cur = "";
  return {
    items,
    handler: {
      element(el) {
        cur = "";
        el.onEndTag(() => {
          const t = clean(cur);
          if (t.length >= 12 && !SKIP.test(t) && items[items.length - 1] !== t) items.push(t);
          cur = "";
        });
      },
      text(t) {
        cur += t.text;
      },
    },
  };
}

function fromJsonLd(raw) {
  const out = { body: "", headline: "", date: "", image: "" };
  const walk = (o) => {
    if (!o || typeof o !== "object") return;
    if (Array.isArray(o)) return o.forEach(walk);
    if (typeof o.articleBody === "string" && o.articleBody.length > out.body.length) out.body = o.articleBody;
    if (typeof o.headline === "string" && !out.headline) out.headline = o.headline;
    if (typeof o.datePublished === "string" && !out.date) out.date = o.datePublished;
    if (!out.image) {
      const im = Array.isArray(o.image) ? o.image[0] : o.image;
      if (typeof im === "string") out.image = im;
      else if (im && typeof im.url === "string") out.image = im.url;
    }
    if (o["@graph"]) walk(o["@graph"]);
  };
  for (const r of raw) {
    try {
      walk(JSON.parse(r));
    } catch {
      /* 無視 */
    }
  }
  return out;
}

function fmtDate(s) {
  const d = new Date(s);
  if (!s || isNaN(d)) return "";
  return d.toLocaleString("ja-JP", { timeZone: "Asia/Tokyo", year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function reader(res, finalUrl) {
  const meta = {};
  let title = "", h1 = "", titleBuf = "", h1Buf = "";
  const ld = [];
  let ldBuf = "";
  const pref = collector(), all = collector();

  const rw = new HTMLRewriter()
    .on("meta", {
      element(e) {
        const k = e.getAttribute("property") || e.getAttribute("name");
        const v = e.getAttribute("content");
        if (k && v && !meta[k]) meta[k] = v;
      },
    })
    .on("title", { text(t) { titleBuf += t.text; } })
    .on("h1", { element(e) { if (!h1) e.onEndTag(() => { h1 = clean(h1Buf); }); }, text(t) { if (!h1) h1Buf += t.text; } })
    .on('script[type="application/ld+json"]', {
      element(e) { ldBuf = ""; e.onEndTag(() => ld.push(ldBuf)); },
      text(t) { ldBuf += t.text; },
    })
    .on("article p, main p, [itemprop=articleBody] p, [class*=article] p, [class*=Article] p, [class*=body] p, [class*=content] p", pref.handler)
    .on("p", all.handler);

  await rw.transform(res).arrayBuffer(); // 解析のため読み切る
  title = clean(titleBuf);

  const j = fromJsonLd(ld);
  const heading = clean(meta["og:title"] || j.headline || h1 || title);
  const site = meta["og:site_name"] || "";
  const date = fmtDate(meta["article:published_time"] || j.date);
  const image = meta["og:image"] || j.image || "";

  const joined = (a) => a.join("");
  let paras = joined(pref.items).length >= 200 ? pref.items : all.items;
  const ldParas = j.body ? j.body.split(/\n+/).map(clean).filter((t) => t.length >= 12) : [];
  if (joined(ldParas).length > joined(paras).length) paras = ldParas;

  let body;
  if (joined(paras).length >= 80) {
    body = paras.map((p) => `<p>${esc(p)}</p>`).join("");
  } else {
    const desc = clean(meta["og:description"] || meta["description"] || "");
    body =
      (desc ? `<p>${esc(desc)}</p>` : "") +
      `<p class="note">本文を取り出せませんでした。右のQRコードから元の記事を開いてください。</p>`;
  }

  const imgOk = /^https:\/\//i.test(image);
  const html = `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark">
<title>${esc(heading)}</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
html{background:#14161a;color:#e8eaed}
body{margin:0;padding:3vh 4vw 6vh;font-family:"Hiragino Sans","Noto Sans JP","Yu Gothic",-apple-system,"Segoe UI",sans-serif;
 font-size:clamp(16px,2.6vw,26px);line-height:1.9;-webkit-text-size-adjust:100%}
main{max-width:42em;margin:0 auto}
h1{font-size:1.35em;line-height:1.5;margin:0 0 .5em;color:#fff;font-weight:600}
.meta{color:#9aa0a6;font-size:.7em;margin-bottom:1.2em}
img{display:block;max-width:100%;height:auto;border-radius:10px;margin:0 0 1.4em}
p{margin:0 0 1.2em}.note{color:#f6ad55;font-size:.85em}
</style></head><body><main>
<h1>${esc(heading)}</h1>
<div class="meta">${esc([site, date].filter(Boolean).join("  /  "))}</div>
${imgOk ? `<img src="${esc(image)}" alt="">` : ""}
${body}
</main></body></html>`;

  return new Response(html, { status: 200, headers: baseHeaders("text/html; charset=utf-8", ["style-src 'unsafe-inline'"]) });
}

/* ---------------- 元ページ表示(mode=raw) ---------------- */

function raw(res, type, finalUrl, selfOrigin, isHead) {
  const proxify = (href) => {
    if (!href || /^(javascript|mailto|tel|data):/i.test(href)) return null;
    let u;
    try {
      u = new URL(href, finalUrl);
    } catch {
      return null;
    }
    if (u.protocol !== "https:" || !isAllowedHost(u.hostname)) return null;
    return `${selfOrigin}/?url=${encodeURIComponent(u.origin + u.pathname + u.search)}&mode=raw${u.hash}`;
  };
  const rewriter = new HTMLRewriter()
    .on("script, noscript, iframe, frame, object, embed, applet, form", { element: (e) => e.remove() })
    .on("meta[http-equiv]", { element: (e) => e.remove() })
    .on("link[rel=preload], link[rel=modulepreload], link[rel=prefetch], link[rel=manifest]", { element: (e) => e.remove() })
    .on("head", { element: (e) => e.prepend(`<base href="${esc(finalUrl)}">`, { html: true }) })
    .on("a[href]", {
      element(e) {
        const next = proxify(e.getAttribute("href"));
        if (next) { e.setAttribute("href", next); e.removeAttribute("target"); } else e.removeAttribute("href");
      },
    })
    .on("img[data-src]", { element(e) { if (!e.getAttribute("src")) e.setAttribute("src", e.getAttribute("data-src")); } });
  const headers = baseHeaders(type, ["style-src https: 'unsafe-inline'", "font-src https: data:", "media-src https:"]);
  return rewriter.transform(new Response(isHead ? null : res.body, { status: 200, headers }));
}

/* ---------------- エントリポイント ---------------- */

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") return text(405, "GETのみ対応しています");
    const self = new URL(request.url);
    const rawUrl = self.searchParams.get("url");
    if (!rawUrl) return text(400, "url パラメータを指定してください");
    const target = parseTarget(rawUrl);
    if (!target) return text(403, "このURLは取得できません(許可されていないドメインです)");

    const r = await load(target);
    if (r.err) return r.err;

    if (self.searchParams.get("mode") === "raw") {
      return raw(r.res, r.type, r.target.href, self.origin, request.method === "HEAD");
    }
    return reader(r.res, r.target.href);
  },
};
