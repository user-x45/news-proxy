/**
 * ニュース記事プロキシ(Cloudflare Workers)
 *
 * 使い方:  https://<your-worker>.workers.dev/?url=<記事のURL(URLエンコード)>
 *
 * - 許可リストにあるドメインの記事だけを取得します(それ以外は403)
 * - 他サイトへの埋め込みを禁止するヘッダー(X-Frame-Options など)を外して返します
 * - スクリプト類は取り除き、CSPでも実行を禁止します(読み取り専用の表示)
 * - 記事内のリンクもこのプロキシ経由に書き換えます
 *
 * 個人利用の範囲で使ってください。各社の利用規約を確認し、転載・再配布はしないでください。
 */

// 取得を許可するドメイン(サブドメインも含む)
const ALLOWED_HOSTS = [
  "nhk.or.jp",
  "news.web.nhk",
  "news.yahoo.co.jp",
];

// このプロキシのページを埋め込んでよいサイト(CSPのframe-ancestors)。
// 時計ページの置き場所が決まったら "https://your-clock.example.com" のように絞ってください。
const FRAME_ANCESTORS = "https://user-x45.github.io";

const MAX_REDIRECTS = 4;
const MAX_BYTES = 5 * 1024 * 1024; // 5MBまで
const CACHE_SECONDS = 300;         // 5分キャッシュ

const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

function isAllowedHost(hostname) {
  const h = hostname.toLowerCase();
  return ALLOWED_HOSTS.some((d) => h === d || h.endsWith("." + d));
}

function parseTarget(raw, base) {
  try {
    const u = new URL(raw, base);
    if (u.protocol !== "https:") return null; // httpsのみ
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

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return text(405, "GETのみ対応しています");
    }

    const self = new URL(request.url);
    const raw = self.searchParams.get("url");
    if (!raw) return text(400, "url パラメータを指定してください");

    let target = parseTarget(raw);
    if (!target) return text(403, "このURLは取得できません(許可されていないドメインです)");

    // リダイレクトは手動で追い、毎回ドメインを検証する(SSRF対策)
    let res;
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      try {
        res = await fetch(target.href, {
          redirect: "manual",
          headers: {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "ja,en;q=0.8",
          },
          cf: { cacheTtl: CACHE_SECONDS, cacheEverything: true },
        });
      } catch {
        return text(502, "取得に失敗しました");
      }
      if (res.status >= 300 && res.status < 400 && res.headers.get("Location")) {
        const next = parseTarget(res.headers.get("Location"), target);
        if (!next) return text(403, "許可されていないドメインへのリダイレクトです");
        target = next;
        res = null;
        continue;
      }
      break;
    }
    if (!res) return text(508, "リダイレクトが多すぎます");
    if (!res.ok) return text(res.status, `取得先がエラーを返しました(${res.status})`);

    const type = res.headers.get("Content-Type") || "";
    if (!/text\/html|application\/xhtml\+xml/i.test(type)) {
      return text(415, "HTML以外は対応していません");
    }
    const len = Number(res.headers.get("Content-Length") || 0);
    if (len > MAX_BYTES) return text(413, "ページが大きすぎます");

    const finalUrl = target.href;
    const proxify = (href) => {
      if (!href || /^(javascript|mailto|tel|data):/i.test(href)) return null;
      let u;
      try {
        u = new URL(href, finalUrl);
      } catch {
        return null;
      }
      if (u.protocol !== "https:" || !isAllowedHost(u.hostname)) return null;
      return `${self.origin}/?url=${encodeURIComponent(u.origin + u.pathname + u.search)}${u.hash}`;
    };

    const rewriter = new HTMLRewriter()
      // 実行系・埋め込み系は取り除く
      .on("script, noscript, iframe, frame, object, embed, applet", { element: (e) => e.remove() })
      .on("meta[http-equiv]", { element: (e) => e.remove() })
      .on("link[rel=preload], link[rel=modulepreload], link[rel=prefetch], link[rel=manifest]", {
        element: (e) => e.remove(),
      })
      // 相対パスの画像・CSSを元サイトから読み込むため
      .on("head", { element: (e) => e.prepend(`<base href="${finalUrl}">`, { html: true }) })
      // リンクはプロキシ経由に。許可外のリンクは無効化
      .on("a[href]", {
        element(e) {
          const next = proxify(e.getAttribute("href"));
          if (next) {
            e.setAttribute("href", next);
            e.removeAttribute("target");
          } else {
            e.removeAttribute("href");
          }
        },
      })
      .on("form", { element: (e) => e.remove() })
      // 遅延読み込み画像
      .on("img[data-src]", {
        element(e) {
          if (!e.getAttribute("src")) e.setAttribute("src", e.getAttribute("data-src"));
        },
      });

    const headers = new Headers({
      "Content-Type": type,
      "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      // スクリプト禁止。画像・CSS・フォントは元サイトから読み込み可
      "Content-Security-Policy": [
        "default-src 'none'",
        "img-src https: data:",
        "style-src https: 'unsafe-inline'",
        "font-src https: data:",
        "media-src https:",
        "base-uri https:",
        "form-action 'none'",
        `frame-ancestors ${FRAME_ANCESTORS}`,
        "sandbox",
      ].join("; "),
    });
    // 元サイトの X-Frame-Options / CSP などはコピーしない(=埋め込み禁止の設定を外す)

    return rewriter.transform(new Response(request.method === "HEAD" ? null : res.body, { status: 200, headers }));
  },
};
