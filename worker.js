/**
 * ============================================================================
 *  ULTRAVIOLET EDGE — a single-file Ultraviolet rendition for the
 *  FREE Cloudflare Workers plan.
 * ============================================================================
 *
 *  This is an edge-native rendition of the Ultraviolet web proxy
 *  (https://github.com/titaniumnetwork-dev/Ultraviolet). The original splits
 *  work between a client bundle (service worker + JS hooks + rewriters) and
 *  an origin-side handler. This rendition collapses the whole system into
 *  ONE Cloudflare Worker file:
 *
 *    • Ultraviolet's URL codec      (src/rewrite/codecs.js)  -> base64url codec below
 *    • Ultraviolet's attribute table (src/rewrite/rewrite.html.js) -> URL_ATTRS /
 *      SRCSET_ATTRS / FORBIDDEN_ATTRS lists below (ported verbatim)
 *    • Ultraviolet's CSS regexes    (src/rewrite/css.js)    -> rewriteCSS() below
 *    • Ultraviolet's CSP strip list (src/uv.sw.js)          -> STRIP_RESPONSE_HEADERS
 *    • Ultraviolet's SW routing     (src/sw.js + uv.sw.js)  -> SW_SCRIPT string below
 *    • Ultraviolet's cookie rules   (src/rewrite/cookie.js) -> edge cookie jar below
 *
 *  Route map (everything is served by this one Worker):
 *    GET  /            -> hosted test page (iframe + SW registration)
 *    GET  /sw.js       -> the service worker (scope "/")
 *    ANY  /proxy?url=<base64url(target)> -> the proxy endpoint (query form)
 *    ANY  /proxy/<base64url(target)>      -> the proxy endpoint (path form —
 *         used for form actions, whose query string gets REPLACED by the
 *         browser when a <form method="get"> submits; the target must live
 *         in the path to survive: HTML spec, "Mutate action URL's query")
 *    GET  /ws?url=<base64url(target)>    -> WebSocket reverse proxy. Primary
 *         transport: cloudflare:sockets connect() — a raw TCP/TLS socket with
 *         a hand-rolled RFC 6455 handshake and frame codec, giving full
 *         control over Origin/Cookie/Sec-WebSocket-Protocol (headers the
 *         fetch()-upgrade path cannot guarantee, which is why wss:// broke
 *         in the field). Fallback transport: outbound fetch() with
 *         Upgrade: websocket. Capped at 6 concurrent tunnels per isolate.
 *
 *  Straggler recovery (Bug 1/2, worker half): any same-origin request that
 *  is NOT a decodable proxy URL but carries a proxy Referer — a GET form
 *  submission whose ?url= was clobbered by "Mutate action URL's query", a
 *  query-relative navigation, a runtime-built relative URL — is recovered
 *  from the Referer and redirected through the proxy (302 for GET/HEAD,
 *  307 for POST so the body replays). The service worker performs the
 *  equivalent rescue client-side; the worker half removes the dependency
 *  on the SW being active.
 *
 *  Free-plan budget: exactly ONE upstream connection per proxied request
 *  (fetch() subrequest, or one connect() socket for the WebSocket tunnel),
 *  zero storage bindings, native streaming HTMLRewriter (low CPU), script
 *  size ~95KB of the 64 MiB limit.
 */

/* ============================================================================
 * 1. CONFIGURATION
 * ==========================================================================*/

/** Proxy endpoint path. */
const PROXY_PATH = '/proxy';
/** Query parameter carrying the base64url-encoded target URL (query form). */
const PARAM = 'url';
/** WebSocket reverse-proxy endpoint (target carried in ?url=). */
const WS_PATH = '/ws';
/** Schemes accepted as WebSocket proxy targets (mapped for the connect). */
const WS_SCHEMES = new Set(['ws:', 'wss:', 'http:', 'https:']);
/**
 * External scripts larger than this stream through unrewritten. The JS
 * navigation rewriter is O(n) regex work; past ~4 MB the free-plan CPU
 * budget (10 ms) is better spent streaming than buffering.
 */
const JS_REWRITE_LIMIT = 4 * 1024 * 1024;
/** Prefix for edge-side cookie-jar cookies (per-host buckets). */
const COOKIE_PREFIX = '__uvedge_';
/** Supported schemes. */
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

/**
 * Real-browser header profile (Chrome 138 / Windows 10).
 * Used to fill any header the inbound request does not already supply and
 * to override context headers that would betray the proxy (e.g. an iframe
 * sec-fetch-dest) — ported from Ultraviolet's policy of forwarding
 * `navigator.userAgent` on every proxied request.
 */
const BROWSER_UA =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';
const BROWSER_SEC_CH_UA = '"Chromium";v="138", "Google Chrome";v="138", "Not=A?Brand";v="8"';
const BROWSER_ACCEPT_NAV =
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
const BROWSER_ACCEPT_LANG = 'en-US,en;q=0.9';

/**
 * Schemes that must never be re-encoded or fetched — ported from
 * Ultraviolet's `urlRegex = /^(#|about:|data:|mailto:)/` guard
 * (src/rewrite/index.js), extended with the remaining non-fetch schemes.
 */
const SKIP_URL = /^(#|about:|data:|blob:|mailto:|tel:|sms:|javascript:|ftp:|ws:|wss:|magnet:|irc:)/i;

/**
 * Response headers stripped from every proxied response.
 *
 * Base list is Ultraviolet's `cspHeaders` (src/uv.sw.js) which exists
 * precisely to allow seamless iframe rendering. On top of it we strip every
 * "escape-the-frame" header (Refresh, Clear-Site-Data, Content-Disposition
 * on documents, Link preload hints pointing at the origin, Permissions-
 * Policy, NEL/Report-To reporting noise). After this, the only way content
 * leaves the iframe is an explicit user-initiated open-in-new-window.
 */
const STRIP_RESPONSE_HEADERS = new Set([
    // --- Ultraviolet cspHeaders list (ported) ---
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'content-security-policy',
    'content-security-policy-report-only',
    'expect-ct',
    'feature-policy',
    'origin-isolation',
    'strict-transport-security',
    'upgrade-insecure-requests',
    'x-content-type-options',
    'x-download-options',
    'x-frame-options',
    'x-permitted-cross-domain-policies',
    'x-powered-by',
    'x-xss-protection',
    // --- escape-the-frame / open-in-new-tab suppression (this rendition) ---
    'refresh', // forces navigation out of the iframe
    'clear-site-data', // would wipe our SW registration + cookie jar
    'link', // preload/preconnect hints reference the bare origin
    'nel',
    'report-to',
    'reporting-endpoints',
    'permissions-policy',
    'timing-allow-origin',
    // --- hop-by-hop; never forwarded ---
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    // --- rewritten by the cookie jar, never passed through ---
    'set-cookie',
    'content-disposition', // re-added selectively (inline for documents)
]);

/**
 * Outbound request headers that are never forwarded upstream: hop-by-hop
 * headers, Cloudflare's injected edge headers, and forwarding telemetry.
 * (Spec: "use real browser headers ... and strip Cloudflare's own request
 * headers".)
 */
const STRIP_REQUEST_HEADERS = new Set([
    // hop-by-hop
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    // transport/identity — set by the runtime
    'host',
    'content-length',
    // Cloudflare edge headers (any cf-* is also dropped by prefix rule)
    'cdn-loop',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-forwarded-server',
    'x-real-ip',
    'true-client-ip',
    'forwarded',
    // ours alone — never leak the hosted page's cookies upstream
    'cookie',
]);

/** HTTP methods that must never carry a body (ported from uv.sw.js). */
const EMPTY_METHODS = new Set(['GET', 'HEAD']);

/** Upstream status codes handled as redirects (Location rewrite). */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Max concurrent WebSocket tunnels per isolate (spec: "connect api for wss
 * (max of 6 at a time)"). This mirrors the platform limit — each Worker
 * invocation may hold six simultaneous connections waiting for response
 * headers; a tunnel holds exactly one (the TCP socket / upgrade fetch).
 * Module-scope state is per-isolate: a hard GLOBAL cap would need Durable
 * Objects, which the free plan avoids by design here.
 */
const MAX_TUNNELS = 6;

/** Wall-clock budget for the outbound TCP connect (ms). */
const WS_CONNECT_TIMEOUT = 10000;
/** Wall-clock budget for reading the upstream 101 handshake (ms). */
const WS_HANDSHAKE_TIMEOUT = 15000;
/** Refuse WebSocket frames larger than 16 MiB (corruption guard). */
const MAX_WS_FRAME = 1 << 24;

/* ============================================================================
 * 2. BASE64URL CODEC (UTF-8 safe)
 * --------------------------------------------------------------------------
 * Port of Ultraviolet's `base64` codec (src/rewrite/codecs.js) hardened into
 * the URL-safe alphabet required by the spec. Works on any runtime that has
 * TextEncoder/TextDecoder/btoa/atob (Workers, Node >= 8, browsers).
 * ==========================================================================*/

/**
 * Encode a string as unpadded base64url.
 * Chunked String.fromCharCode avoids the argument-limit stack overflow on
 * long URLs.
 * @param {string} str
 * @returns {string}
 */
function b64urlEncode(str) {
    const bytes = new TextEncoder().encode(String(str));
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode base64url (padded or unpadded) back into a UTF-8 string.
 * Throws on invalid input — callers must catch.
 * @param {string} str
 * @returns {string}
 */
function b64urlDecode(str) {
    let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
}

/* ============================================================================
 * 3. URL REWRITING (port of Ultraviolet's rewriteUrl / sourceUrl pair)
 * ==========================================================================*/

/**
 * Resolve `raw` against `base` into an absolute http(s) URL, or null when the
 * value must be left untouched (fragments, data:/blob:/mailto:/javascript:,
 * non-HTTP(S) schemes, unresolvable, or values that already point at this
 * worker — the self-proxy guard that prevents rewrite loops).
 *
 * @param {string} raw    attribute/value as found in the document
 * @param {string} base   absolute base URL (target URL or captured <base>)
 * @param {string} [selfOrigin] this worker's origin, for the loop guard
 * @returns {URL|null}
 */
function resolveTarget(raw, base, selfOrigin) {
    let str;
    try {
        str = String(raw).trim();
    } catch {
        return null;
    }
    if (!str || SKIP_URL.test(str)) return null;
    // Idempotency guard: values that are already proxy URLs (either form)
    // must never be re-encoded — without this, @import url(...) is
    // double-encoded by the CSS rewriter and re-proxied pages nest encodings.
    if (str.startsWith(PROXY_PATH + '?') || str.startsWith(PROXY_PATH + '/')) return null;
    let abs;
    try {
        abs = new URL(str, base);
    } catch {
        return null;
    }
    if (!ALLOWED_PROTOCOLS.has(abs.protocol)) return null;
    if (selfOrigin && abs.origin === selfOrigin) return null; // loop guard
    return abs;
}

/**
 * Resolve `raw` against `base` and return a proxy URL (query form), or null
 * when the value must be left untouched.
 *
 * @param {string} raw    attribute/value as found in the document
 * @param {string} base   absolute base URL (target URL or captured <base>)
 * @param {string} [selfOrigin] this worker's origin, for the loop guard
 * @returns {string|null} e.g. "/proxy?url=aHR0cHM6Ly9leGFtcGxlLmNvbS8"
 */
function toProxyUrl(raw, base, selfOrigin) {
    const abs = resolveTarget(raw, base, selfOrigin);
    if (!abs) return null;
    try {
        return PROXY_PATH + '?' + PARAM + '=' + b64urlEncode(abs.href);
    } catch {
        return null;
    }
}

/**
 * Path-form proxy URL: "/proxy/<base64url>". Used exclusively for <form
 * action>/formaction rewriting: when a browser submits a
 * <form method="get">, the HTML standard REPLACES the action URL's query
 * string with the serialized form fields ("Mutate action URL's query"). A
 * query-form action "/proxy?url=<b64>" therefore degrades to
 * "/proxy?q=term" — a 400 "Missing url parameter" (Bug 1: searching on
 * Bing/YouTube). The path form survives the mutation, and handleProxy()
 * merges the surviving fields back into the target URL.
 *
 * @param {string} raw
 * @param {string} base
 * @param {string} [selfOrigin]
 * @returns {string|null} e.g. "/proxy/aHR0cHM6Ly9leGFtcGxlLmNvbS8"
 */
function toProxyUrlPath(raw, base, selfOrigin) {
    const abs = resolveTarget(raw, base, selfOrigin);
    if (!abs) return null;
    try {
        return PROXY_PATH + '/' + b64urlEncode(abs.href);
    } catch {
        return null;
    }
}

/**
 * True when the pathname is one of the two proxy routes.
 * @param {string} pathname
 */
function isProxyPathname(pathname) {
    return pathname === PROXY_PATH || pathname.startsWith(PROXY_PATH + '/');
}

/**
 * Extract the encoded target from a proxy URL string/URL (query or path
 * form), or null. Used to rebuild upstream Referer values and by the
 * service worker.
 * @param {string|URL} proxyUrl
 * @returns {string|null} absolute target URL
 */
function targetFromProxyUrl(proxyUrl) {
    try {
        const u = typeof proxyUrl === 'string' ? new URL(proxyUrl) : proxyUrl;
        if (!isProxyPathname(u.pathname)) return null;
        // Path form is authoritative when present: a query param named PARAM
        // riding along on a path-form URL is a form field the browser left
        // behind, not the target (handleProxy reads it the same way).
        let v = null;
        if (u.pathname.startsWith(PROXY_PATH + '/')) {
            v = u.pathname.slice(PROXY_PATH.length + 1);
        }
        if (!v) v = u.searchParams.get(PARAM);
        if (!v) return null;
        return b64urlDecode(v);
    } catch {
        return null;
    }
}

/**
 * Merge every inbound query parameter other than PARAM into the target URL
 * (Bug 1 fix, worker half). Surviving parameters are exactly what a
 * <form method="get"> submission left on the action URL after the browser
 * replaced its query: the site's own search fields. Appending (not setting)
 * preserves duplicates and keeps the target's own query intact — the same
 * result a browser produces for a form whose action already had a query.
 *
 * @param {URL} targetUrl        mutated in place
 * @param {URLSearchParams} searchParams inbound query parameters
 * @returns {boolean} true when anything was merged
 */
function mergeExtraParams(targetUrl, searchParams) {
    let touched = false;
    for (const [k, v] of searchParams) {
        if (k === PARAM) continue;
        try {
            targetUrl.searchParams.append(k, v);
            touched = true;
        } catch {
            /* skip pathological names */
        }
    }
    return touched;
}

/* ------------------------------------------------------------------------
 * STRAGGLER RECOVERY (Bug 1/2, worker half)
 * ----------------------------------------------------------------------*/

/**
 * Recover the intended upstream target of a same-origin request whose proxy
 * encoding was lost or never existed.
 *
 * Sources of stragglers, and the recovery rule for each:
 *  - /proxy (or /proxy/<garbage>) with a clobbered ?url=: a GET form
 *    submission against a query-form action, or a query-relative navigation
 *    ("?q=term"). HTML's "Mutate action URL's query" REPLACED the target's
 *    query with the surviving form fields, so the intended target is the
 *    referer's target with its query set to exactly those fields.
 *  - any other path ("/search?q=term", "/", "/favicon.ico", ...): a
 *    runtime-built document-relative URL; resolve path+query against the
 *    referer's target (what the page's JS meant, since the page believes it
 *    lives on the target origin).
 *
 * Returns null when no recovery is possible (no Referer, or the Referer is
 * not a proxy URL — e.g. the hosted landing page), in which case the worker
 * serves its own route (landing / 204 / 400 / 404).
 *
 * @param {string} pathname inbound request pathname
 * @param {string} search    inbound request query (with leading '?', or '')
 * @param {string|null} referer inbound Referer header
 * @returns {string|null} absolute upstream URL
 */
function recoverStragglerTarget(pathname, search, referer) {
    if (!referer) return null;
    let refUrl;
    try {
        refUrl = new URL(referer);
    } catch {
        return null;
    }
    const baseStr = targetFromProxyUrl(refUrl);
    if (!baseStr) return null;
    let base;
    try {
        base = new URL(baseStr);
    } catch {
        return null;
    }
    try {
        if (isProxyPathname(pathname)) {
            // query-mutation semantics: the incoming query IS the form's fields
            base.search = search || '';
            base.hash = '';
            return base.href;
        }
        return new URL(pathname + (search || ''), base).href;
    } catch {
        return null;
    }
}

/**
 * Redirect a recovered straggler through the proxy endpoint.
 * GET/HEAD get a 302 (a fresh GET); POST gets a 307 so the browser replays
 * the untouched request body against the recovered target.
 * @param {string} target absolute upstream URL
 * @param {string} method inbound method
 * @returns {Response}
 */
function redirectProxy(target, method) {
    let proxied;
    try {
        proxied = PROXY_PATH + '?' + PARAM + '=' + b64urlEncode(target);
    } catch {
        return errorResponse(400, 'Recovered target is not encodable');
    }
    const status = method === 'POST' ? 307 : 302;
    return new Response(null, { status, headers: { location: proxied } });
}

/* ============================================================================
 * 4. EDGE COOKIE JAR (stateless port of Ultraviolet's IDB cookie store)
 * --------------------------------------------------------------------------
 * Free plan forbids relying on storage bindings for correctness, so upstream
 * cookies are bounced into per-host browser cookies scoped to the worker
 * origin ("jar cookies") and rebuilt into a Cookie header on every outbound
 * request. Semantics follow src/rewrite/cookie.js: domain/path matching,
 * Secure-over-HTTP dropped, Max-Age=0 / past Expires delete.
 * ==========================================================================*/

/** 32-bit FNV-1a — stable, cheap bucket name hash. */
function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16).padStart(8, '0');
}

/** Jar cookie name for a host. */
function jarCookieName(host) {
    return COOKIE_PREFIX + fnv1a(String(host || '').toLowerCase());
}

/**
 * Fallback splitter for combined Set-Cookie strings (used only when
 * Headers.getSetCookie is unavailable). Heuristic port of
 * set-cookie-parser's splitCookiesString: a comma starts a new cookie only
 * when followed by `token=` and no `;` before the `=` (keeps `Expires=Wed,
 * 21 Oct ...` dates intact).
 * @param {string} str
 * @returns {string[]}
 */
function splitSetCookieString(str) {
    if (!str) return [];
    return String(str)
        .split(/,(?=\s*[^\s=;,]{1,64}=)/g)
        .map((s) => s.trim())
        .filter(Boolean);
}

/** All Set-Cookie strings of a response as an array. */
function getSetCookies(headers) {
    if (typeof headers.getSetCookie === 'function') {
        try {
            return headers.getSetCookie();
        } catch {
            /* fall through */
        }
    }
    const combined = headers.get('set-cookie');
    return combined ? splitSetCookieString(combined) : [];
}

/**
 * Parse one Set-Cookie string into { name, value, maxAge, expires }.
 * Mirrors Ultraviolet's use of set-cookie-parser with decodeValues:false.
 * @param {string} sc
 */
function parseSetCookie(sc) {
    const firstSemi = sc.indexOf(';');
    const pair = firstSemi === -1 ? sc : sc.slice(0, firstSemi);
    const attrs = firstSemi === -1 ? '' : sc.slice(firstSemi + 1);
    const eq = pair.indexOf('=');
    if (eq <= 0) return null;
    const out = {
        name: pair.slice(0, eq).trim(),
        value: pair.slice(eq + 1).trim(),
        maxAge: null,
        expires: null,
    };
    const ma = /max-age\s*=\s*(-?\d+)/i.exec(attrs);
    if (ma) out.maxAge = parseInt(ma[1], 10);
    const ex = /expires\s*=\s*(.+)/i.exec(attrs);
    if (ex) {
        const d = new Date(ex[1].trim());
        if (!isNaN(d.getTime())) out.expires = d.getTime();
    }
    return out;
}

/**
 * Merge upstream Set-Cookie strings into an existing pairs map.
 * Deletion (Max-Age<=0 or past Expires) removes the pair.
 * @param {Map<string,string>} pairs
 * @param {string[]} setCookies
 * @returns {number} the largest positive Max-Age seen (seconds), or 0
 */
function applySetCookies(pairs, setCookies) {
    let maxAge = 0;
    const now = Date.now();
    for (const sc of setCookies) {
        const c = parseSetCookie(sc);
        if (!c || !c.name) continue;
        let expired = false;
        if (c.maxAge !== null) expired = c.maxAge <= 0;
        else if (c.expires !== null) expired = c.expires <= now;
        if (expired) {
            pairs.delete(c.name);
            continue;
        }
        pairs.set(c.name, c.value);
        if (c.maxAge !== null && c.maxAge > maxAge) maxAge = c.maxAge;
        else if (c.expires !== null) {
            const secs = Math.floor((c.expires - now) / 1000);
            if (secs > maxAge) maxAge = secs;
        }
    }
    return maxAge;
}

/**
 * Read the jar bucket for `host` out of an inbound Cookie header string.
 * @param {string|null} cookieHeader
 * @param {string} host
 * @returns {Map<string,string>}
 */
function readJar(cookieHeader, host) {
    const pairs = new Map();
    if (!cookieHeader) return pairs;
    const want = jarCookieName(host);
    // Split on ';' AND ',' — a synthetic client's duplicate Cookie headers
    // get merged with ', ' by the Headers API, which would otherwise hide
    // the jar bucket. Jar values are encodeURIComponent'd, so neither
    // separator can appear inside them.
    for (const part of String(cookieHeader).split(/[;,]/)) {
        const p = part.trim();
        if (!p) continue;
        const eq = p.indexOf('=');
        if (eq === -1) continue;
        if (p.slice(0, eq) !== want) continue;
        try {
            const decoded = decodeURIComponent(p.slice(eq + 1));
            for (const kv of decoded.split(';')) {
                const e = kv.indexOf('=');
                if (e > 0) pairs.set(kv.slice(0, e).trim(), kv.slice(e + 1).trim());
            }
        } catch {
            /* ignore malformed jar */
        }
    }
    return pairs;
}

/**
 * Serialize a jar bucket into one Set-Cookie value for the client.
 * Empty pair maps expire the bucket.
 * @param {string} host
 * @param {Map<string,string>} pairs
 * @param {number} maxAge seconds (0 = session cookie)
 * @returns {string} full Set-Cookie line (without the header name)
 */
function buildJarCookie(host, pairs, maxAge) {
    const name = jarCookieName(host);
    if (!pairs.size) {
        return name + '=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax';
    }
    const joined = Array.from(pairs, ([k, v]) => k + '=' + v).join('; ');
    let sc =
        name + '=' + encodeURIComponent(joined) + '; Path=/; HttpOnly; SameSite=Lax';
    if (maxAge > 0) sc += '; Max-Age=' + maxAge;
    return sc;
}

/**
 * Cookie header the upstream request should carry (or null).
 * @param {Map<string,string>} pairs
 * @returns {string|null}
 */
function serializeJar(pairs) {
    if (!pairs.size) return null;
    return Array.from(pairs, ([k, v]) => k + '=' + v).join('; ');
}

/* ============================================================================
 * 5. OUTBOUND REQUEST BUILDER
 * --------------------------------------------------------------------------
 * Spec: "use real browser headers in your request and strip Cloudflare's
 * own request headers." The inbound header set is copied through an
 * allowlist (dropping cf- prefixed, hop-by-hop, and telemetry headers),
 * then the browser profile fills the gaps. Referer/Origin are translated
 * from proxy URLs to upstream URLs, and the edge cookie jar supplies the
 * Cookie header.
 * ==========================================================================*/

/**
 * True when the inbound request looks like a document/iframe navigation.
 * Detection: SW-visible mode, the browser's sec-fetch-dest hint, or an
 * HTML Accept header as a last resort.
 */
function isNavigationRequest(request) {
    if (request.mode === 'navigate') return true;
    const dest = (request.headers.get('sec-fetch-dest') || '').toLowerCase();
    if (dest === 'document' || dest === 'iframe') return true;
    const accept = request.headers.get('accept') || '';
    return accept.includes('text/html');
}

/**
 * Build the outbound (upstream) Request.
 * @param {Request} request inbound client request to /proxy
 * @param {URL} targetUrl decoded absolute target
 * @returns {Request}
 */
function buildOutgoingRequest(request, targetUrl) {
    const headers = new Headers();
    for (const [name, value] of request.headers.entries()) {
        const lower = name.toLowerCase();
        if (STRIP_REQUEST_HEADERS.has(lower)) continue;
        if (lower.startsWith('cf-')) continue; // Cloudflare-injected edge headers
        if (lower === 'referer' || lower === 'origin') continue; // translated below
        if (lower.startsWith('sec-')) continue; // re-synthesized below
        if (lower === 'user-agent') continue; // browser profile below
        if (lower === 'accept-language') continue; // normalized below
        if (lower === 'accept-encoding') continue; // runtime-managed
        headers.set(name, value);
    }

    const navigation = isNavigationRequest(request);

    // --- real-browser header profile -------------------------------------
    headers.set('user-agent', BROWSER_UA);
    const inboundAccept = headers.get('accept');
    if (navigation) {
        // A document load must present a document Accept — never */*.
        if (!inboundAccept || !inboundAccept.includes('text/html')) {
            headers.set('accept', BROWSER_ACCEPT_NAV);
        }
    } else if (!inboundAccept || inboundAccept === '*/*') {
        headers.set('accept', '*/*');
    }
    // An absent or placeholder ("*") Accept-Language from synthetic clients
    // must not shadow the browser profile.
    const inboundLang = request.headers.get('accept-language');
    headers.set(
        'accept-language',
        inboundLang && inboundLang !== '*' && inboundLang.trim() ? inboundLang : BROWSER_ACCEPT_LANG
    );
    headers.set('sec-ch-ua', BROWSER_SEC_CH_UA);
    headers.set('sec-ch-ua-mobile', '?0');
    headers.set('sec-ch-ua-platform', '"Windows"');

    if (navigation) {
        // Present as a top-level document load, not an embedded frame —
        // the browser's real values would advertise the iframe context.
        headers.set('sec-fetch-dest', 'document');
        headers.set('sec-fetch-mode', 'navigate');
        headers.set('sec-fetch-site', 'none');
        headers.set('sec-fetch-user', '?1');
        headers.set('upgrade-insecure-requests', '1');
    } else {
        // Subresource context from the browser is accurate once the page
        // itself is served from our origin (sec-fetch-site: same-origin).
        const dest = request.headers.get('sec-fetch-dest');
        const mode = request.headers.get('sec-fetch-mode');
        headers.set('sec-fetch-dest', dest || 'empty');
        headers.set('sec-fetch-mode', mode || 'cors');
        headers.set('sec-fetch-site', request.headers.get('sec-fetch-site') || 'same-origin');
    }

    // --- Referer translation (proxy URL -> upstream URL) -----------------
    const ref = request.headers.get('referer');
    if (ref) {
        const refTarget = targetFromProxyUrl(ref);
        if (refTarget) headers.set('referer', refTarget);
        // Referers that aren't proxy URLs (e.g. the hosted "/" page) are
        // dropped: never advertise the worker itself upstream.
    }

    // --- Origin translation (POST forms / XHR through the SW) ------------
    const origin = request.headers.get('origin');
    if (origin) headers.set('origin', targetUrl.origin);

    // --- Edge cookie jar ---------------------------------------------------
    const jar = readJar(request.headers.get('cookie'), targetUrl.hostname);
    const cookieHeader = serializeJar(jar);
    if (cookieHeader) headers.set('cookie', cookieHeader);

    const method = request.method.toUpperCase();
    const hasBody = !EMPTY_METHODS.has(method) && request.body != null;

    return new Request(targetUrl.href, {
        method,
        headers,
        body: hasBody ? request.body : undefined,
        redirect: 'manual', // we rewrite Location ourselves (see handleProxy)
    });
}

/* ============================================================================
 * 6. RESPONSE HEADER SANITIZER
 * ==========================================================================*/

/**
 * Copy upstream headers into a client-facing Headers object, dropping the
 * STRIP_RESPONSE_HEADERS set. Returns the new headers plus the jar work
 * product so the caller can attach Set-Cookie lines.
 *
 * @param {Response} upstream
 * @param {URL} targetUrl
 * @param {Request} request inbound request (for the existing jar bucket)
 * @returns {{ headers: Headers, jarCookie: string|null }}
 */
function sanitizeResponseHeaders(upstream, targetUrl, request) {
    const out = new Headers();
    for (const [name, value] of upstream.headers.entries()) {
        const lower = name.toLowerCase();
        if (STRIP_RESPONSE_HEADERS.has(lower)) continue;
        out.set(name, value);
    }

    // --- cookie jar ---------------------------------------------------------
    const setCookies = getSetCookies(upstream.headers);
    let jarCookie = null;
    if (setCookies.length) {
        const jar = readJar(request.headers.get('cookie'), targetUrl.hostname);
        const maxAge = applySetCookies(jar, setCookies);
        jarCookie = buildJarCookie(targetUrl.hostname, jar, maxAge);
    }

    return { headers: out, jarCookie };
}

/**
 * Content-Disposition policy: documents and styles render inline inside the
 * iframe (spec: strip open-in-new-tab/attachment behaviour); everything
 * else keeps the header so explicit file downloads still work.
 */
function applyDispositionPolicy(headers, contentType, upstreamDisposition) {
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('text/html') || ct.includes('text/css') || ct === '') {
        // already stripped by STRIP_RESPONSE_HEADERS
        return;
    }
    if (upstreamDisposition) headers.set('content-disposition', upstreamDisposition);
}

/**
 * Rewrite an upstream Location header value into a proxy URL.
 * Non-HTTP(S) or unresolvable locations pass through untouched.
 * @param {string} location
 * @param {URL} targetUrl
 * @returns {string}
 */
function rewriteLocationHeader(location, targetUrl) {
    try {
        const abs = new URL(location, targetUrl);
        if (!ALLOWED_PROTOCOLS.has(abs.protocol)) return location;
        const proxied = toProxyUrl(abs.href, targetUrl.href);
        return proxied || location;
    } catch {
        return location;
    }
}

/* ============================================================================
 * 7. CSS REWRITER (regex port of Ultraviolet src/rewrite/css.js)
 * --------------------------------------------------------------------------
 * UV's original patterns, plus guards: url() values that are data:/blob:/
 * fragments are skipped by toProxyUrl, and empty url() calls are left alone.
 * Works for both stylesheet bodies and inline style="" attributes.
 * ==========================================================================*/

/** uv: /url\(['"]?(.+?)['"]?\)/gm — refined to capture quotes symmetrically. */
const CSS_URL_RE = /url\(\s*(['"]?)([^'")]+?)\1\s*\)/gi;

/** @import in url(), quoted, or bare form (uv: Atruleregex). */
const CSS_IMPORT_RE =
    /@import\s+(?:url\(\s*(['"]?)([^'")]+?)\1\s*\)|(['"])([^'"]+)\3|([^'"\s;()]+))/gi;

/**
 * Rewrite every url() and @import reference in a CSS payload so it points
 * at the proxy endpoint, resolving against the stylesheet's own URL.
 * @param {string} css
 * @param {string} base absolute URL of the stylesheet
 * @returns {string}
 */
function rewriteCSS(css, base) {
    if (!css) return css;
    let out = String(css).replace(CSS_URL_RE, (match, quote, url) => {
        const proxied = toProxyUrl(url, base);
        return proxied ? 'url(' + quote + proxied + quote + ')' : match;
    });
    out = out.replace(CSS_IMPORT_RE, (match, q1, u1, q2, u2, bare) => {
        const url = u1 || u2 || bare;
        if (url == null) return match;
        const proxied = toProxyUrl(url, base);
        if (!proxied) return match;
        if (q1 !== undefined) return '@import url("' + proxied + '")';
        if (q2 !== undefined) return '@import "' + proxied + '"';
        return '@import ' + proxied;
    });
    return out;
}

/**
 * Rewrite a srcset/imagesrcset attribute value (port of UV's
 * wrapSrcset, with a data:-URI bail-out: commas inside data URIs make
 * comma-splitting unsafe, and unrewritten candidates are picked up by the
 * service worker's referer-based fallback anyway).
 * @param {string} str
 * @param {string} base
 * @returns {string}
 */
function rewriteSrcset(str, base) {
    if (!str) return str;
    if (/data:/i.test(str)) return str;
    return str.split(',').map((part) => {
        const lead = part.match(/^\s*/)[0];
        const rest = part.slice(lead.length);
        const sp = rest.search(/\s/);
        const url = sp === -1 ? rest : rest.slice(0, sp);
        const tail = sp === -1 ? '' : rest.slice(sp);
        if (!url) return part;
        const proxied = toProxyUrl(url, base);
        return lead + (proxied || url) + tail;
    }).join(',');
}

/**
 * Rewrite the URL inside a <meta http-equiv="refresh" content> value.
 * Plain delay values ("5") and javascript: targets are left untouched.
 * @param {string} content
 * @param {string} base
 * @returns {string}
 */
function rewriteMetaRefresh(content, base) {
    if (!content) return content;
    return String(content).replace(
        /(url\s*=\s*)(['"]?)([^'"]+)\2/i,
        (match, pre, quote, url) => {
            const proxied = toProxyUrl(url, base);
            return proxied ? pre + quote + proxied + quote : match;
        }
    );
}

/* ============================================================================
 * 7b. JS NAVIGATION REWRITER (Bug 2 fix)
 * --------------------------------------------------------------------------
 * The edge rewriter cannot hook `window.location` at runtime (it is an
 * unforgivable property), so absolute-URL navigations written as string
 * literals inside <script> bodies would navigate the iframe straight to the
 * cross-origin site — escaping the proxy ("urls not rewritten, open in a new
 * tab"). This conservative subset of Ultraviolet's JS rewriter
 * (src/rewrite/js.js rewrites the whole AST; we only touch unambiguous
 * navigation call sites) rewrites exactly three patterns:
 *
 *   location.href = "https://..."
 *   location.assign("https://...")
 *   location.replace("https://...")
 *
 * each optionally prefixed with `window.`/`document.`. String literals only —
 * dynamic values are covered by the runtime hooks in BOOTSTRAP_SCRIPT and by
 * the service-worker straggler path.
 * ==========================================================================*/

/** location.href = 'https://...' (assignment) */
const JS_LOCATION_SET_RE =
    /((?:document\s*\.\s*|window\s*\.\s*)?location\s*\.\s*href\s*=\s*)(['"])(https?:\/\/[^'"\s\\]*)\2/g;

/** location.assign('https://...') / location.replace('https://...') */
const JS_LOCATION_CALL_RE =
    /((?:document\s*\.\s*|window\s*\.\s*)?location\s*\.\s*(?:assign|replace)\s*\(\s*)(['"])(https?:\/\/[^'"\s\\]*)\2/g;

/** Script types whose text is JavaScript (others: JSON-LD, templates...). */
const JS_TYPE_RE = /(javascript|ecmascript|module)/i;

/**
 * Rewrite absolute http(s) navigation literals inside JavaScript source so
 * they route through the proxy. Fail-open: any URL that does not resolve is
 * left byte-identical.
 *
 * @param {string} js    script source
 * @param {string} base  document base URL for resolution
 * @returns {string}
 */
function rewriteNavigationJS(js, base) {
    if (!js) return js;
    const src = String(js);
    if (src.indexOf('http') === -1) return src; // fast bail for the common case
    const routeLiteral = (match, prefix, quote, raw) => {
        const proxied = toProxyUrl(raw, base);
        return proxied ? prefix + quote + proxied + quote : match;
    };
    return src
        .replace(JS_LOCATION_SET_RE, routeLiteral)
        .replace(JS_LOCATION_CALL_RE, routeLiteral);
}

/* ============================================================================
 * 8. HTML REWRITER (Cloudflare native, streaming)
 * --------------------------------------------------------------------------
 * Replaces Ultraviolet's client-side parse5 rewriter. The attribute tables
 * below are ported from UV's src/rewrite/rewrite.html.js:
 *   URL_ATTRS      <- isUrl()            (src, href, ping, movie, action,
 *                                          poster, profile, background, data)
 *   SRCSET_ATTRS   <- isSrcset()         (srcset, imagesrcset)
 *   FORBIDDEN_ATTRS<- isForbidden()      (integrity, crossorigin, nonce,
 *                                          sandbox, http-equiv*)
 * (*http-equiv is selectively handled here: CSP metas are removed outright,
 *  refresh metas get their URL rewritten — both are strictly stronger than
 *  UV's blanket rename.)
 * ==========================================================================*/

const URL_ATTRS = new Set([
    'src', 'href', 'ping', 'movie', 'action', 'poster', 'profile',
    'background', 'cite', 'formaction', 'manifest', 'longdesc', 'xlink:href',
    'data', // <object data="..."> — guarded by the object-tag check below
]);

const SRCSET_ATTRS = new Set(['srcset', 'imagesrcset']);

/**
 * Lazy-load / carousel data-* attributes carrying URLs (Bug 2: runtime
 * copies like `el.src = el.dataset.src` must land on an already-proxied
 * URL). Image/media conventions only — data-href/data-url are deliberately
 * left alone because SPAs template them ("/api/{{id}}") and string surgery
 * on them would corrupt the template.
 */
const DATA_URL_ATTRS = ['data-src', 'data-srcset', 'data-poster', 'data-background', 'data-thumb'];

const FORBIDDEN_ATTRS = ['integrity', 'crossorigin', 'nonce', 'sandbox'];

/**
 * Per-response rewrite context threaded through all HTMLRewriter handlers.
 * `base` starts as the target URL and is replaced by any <base href> seen
 * first (document order guarantees base is usually in <head>).
 */
function makeRewriteCtx(baseHref, selfOrigin) {
    return {
        base: baseHref,
        docUrl: baseHref,
        selfOrigin,
        injected: false,
        styleBuf: '',
        scriptBuf: '',
        scriptType: '',
    };
}

/**
 * Element handler for '*' — URL, srcset, data-attribute and style-attribute
 * rewriting plus forbidden-attribute stripping (SRI removal is a spec
 * requirement).
 *
 * Bug 2 hardening:
 *  - `target` attributes are stripped from a/area/form and `formtarget`
 *    from button/input (both open new tabs); tagName is compared
 *    lowercased so SVG anchors (serialized as lowercase 'a') are covered.
 *  - action/formaction attributes use the PATH-form proxy URL so GET form
 *    submissions cannot clobber the encoded target (Bug 1).
 *  - lazy-load data-* URL attributes are rewritten alongside src/srcset.
 */
function urlAttrsHandler(ctx) {
    return {
        element(el) {
            try {
                // SVG elements keep their serialized case ('a' vs 'A'); the
                // lowercase comparison covers both namespaces.
                const tag = el.tagName.toLowerCase();

                // SRI + friends (spec: strip integrity hashes)
                for (const bad of FORBIDDEN_ATTRS) {
                    if (el.hasAttribute(bad)) el.removeAttribute(bad);
                }

                // Open-in-new-tab suppression (Bug 2): links, image maps and
                // forms must never leave the iframe through a target attr.
                if (tag === 'a' || tag === 'area' || tag === 'form') {
                    if (el.hasAttribute('target')) el.removeAttribute('target');
                }
                // <button formtarget>/<input formtarget> submit into a new
                // tab even when the form itself has no target (Bug 2).
                if (tag === 'button' || tag === 'input') {
                    if (el.hasAttribute('formtarget')) el.removeAttribute('formtarget');
                }

                // <base> is handled by its own handler (capture + remove)
                if (tag !== 'base') {
                    for (const name of URL_ATTRS) {
                        if (!el.hasAttribute(name)) continue;
                        if (name === 'data' && tag !== 'object') continue;
                        const val = el.getAttribute(name);
                        if (val == null || val === '') continue;
                        if (name === 'action' || name === 'formaction') {
                            // Path form: the action URL's query is REPLACED by
                            // GET form fields on submit, so the encoded target
                            // must live in the path (Bug 1).
                            const proxied = toProxyUrlPath(val, ctx.base, ctx.selfOrigin);
                            if (proxied) el.setAttribute(name, proxied);
                            continue;
                        }
                        const proxied = toProxyUrl(val, ctx.base, ctx.selfOrigin);
                        if (proxied) el.setAttribute(name, proxied);
                    }
                    for (const name of SRCSET_ATTRS) {
                        if (!el.hasAttribute(name)) continue;
                        const val = el.getAttribute(name);
                        if (val == null || val === '') continue;
                        el.setAttribute(name, rewriteSrcset(val, ctx.base));
                    }
                    // Lazy-load data-* URLs (Bug 2)
                    for (const name of DATA_URL_ATTRS) {
                        if (!el.hasAttribute(name)) continue;
                        const val = el.getAttribute(name);
                        if (val == null || val === '') continue;
                        if (name === 'data-srcset') {
                            el.setAttribute(name, rewriteSrcset(val, ctx.base));
                            continue;
                        }
                        const proxied = toProxyUrl(val, ctx.base, ctx.selfOrigin);
                        if (proxied) el.setAttribute(name, proxied);
                    }
                    if (el.hasAttribute('style')) {
                        const style = el.getAttribute('style');
                        if (style) el.setAttribute('style', rewriteCSS(style, ctx.base));
                    }
                }
            } catch {
                /* fail-open: leave the element untouched */
            }
        },
    };
}

/**
 * <base> handler — capture the base URL for resolving every subsequent
 * relative reference, then remove the element (a rewritten query-param
 * proxy URL cannot act as a base for relative resolution, and an untouched
 * one would misresolve them). The element is removed even when it only
 * carries a `target` attribute: <base target="_blank"> is a blanket
 * open-in-new-tab directive and must not survive (Bug 2).
 */
function baseHandler(ctx) {
    return {
        element(el) {
            try {
                const href = el.getAttribute('href');
                if (href) {
                    try {
                        ctx.base = new URL(href, ctx.base).href;
                    } catch {
                        /* keep the document URL as base */
                    }
                }
                el.remove();
            } catch {
                /* ignore */
            }
        },
    };
}

/**
 * <form> handler (Bug 1 + Bug 2).
 *
 * 1. Strips `target` (a targeted form opens its result in a new tab).
 * 2. Injects a path-form default action for forms whose action is missing,
 *    empty, or "#". Such forms submit to the CURRENT document URL — and a
 *    GET submission REPLACES that URL's query ("Mutate action URL's query",
 *    HTML spec), wiping url=<b64> and producing the reported
 *    400 "Missing url parameter". With the injected action the submission
 *    goes to /proxy/<b64>?<fields>, and handleProxy() merges the fields into
 *    the target. The injected action mimics browser semantics: the document
 *    URL without its own query and fragment (a real browser drops the
 *    query on submit too).
 *
 * An action of "javascript:..." never navigates, so it is left alone.
 */
function formHandler(ctx) {
    return {
        element(el) {
            try {
                if (el.hasAttribute('target')) el.removeAttribute('target');
                const action = el.getAttribute('action');
                if (action != null) {
                    const trimmed = String(action).trim();
                    if (trimmed !== '' && trimmed !== '#') return;
                }
                let docUrl;
                try {
                    docUrl = new URL(ctx.docUrl);
                } catch {
                    return;
                }
                docUrl.search = '';
                docUrl.hash = '';
                try {
                    el.setAttribute('action', PROXY_PATH + '/' + b64urlEncode(docUrl.href));
                } catch {
                    /* ignore */
                }
            } catch {
                /* ignore */
            }
        },
    };
}

/**
 * <meta> handler — removes CSP metas (they re-impose frame restrictions
 * inside the document even after response headers are stripped) and
 * rewrites meta-refresh targets through the proxy.
 */
function metaHandler(ctx) {
    return {
        element(el) {
            try {
                const equiv = (el.getAttribute('http-equiv') || '').toLowerCase();
                if (!equiv) return;
                if (
                    equiv === 'content-security-policy' ||
                    equiv === 'content-security-policy-report-only'
                ) {
                    el.remove();
                    return;
                }
                if (equiv === 'refresh') {
                    const content = el.getAttribute('content');
                    if (content) el.setAttribute('content', rewriteMetaRefresh(content, ctx.base));
                }
            } catch {
                /* ignore */
            }
        },
    };
}

/**
 * <style> handler — rewrites inline stylesheet text. Text chunks are
 * buffered until `lastInTextNode`, then the whole block is replaced at once
 * (a url() split across chunk boundaries would corrupt per-chunk regexes).
 */
function styleHandler(ctx) {
    return {
        element() {
            ctx.styleBuf = '';
        },
        text(chunk) {
            try {
                ctx.styleBuf += chunk.text;
                if (chunk.lastInTextNode) {
                    const rewritten = rewriteCSS(ctx.styleBuf, ctx.base);
                    ctx.styleBuf = '';
                    chunk.replace(rewritten);
                } else {
                    chunk.replace('');
                }
            } catch {
                /* fail-open */
            }
        },
    };
}

/**
 * <script> handler (Bug 2 fix) — same buffering strategy as <style>, but
 * only for scripts whose type is JavaScript-ish. Non-JS script bodies
 * (JSON-LD `application/ld+json`, text templates) pass through untouched.
 * The buffered source is fed through rewriteNavigationJS, which only touches
 * unambiguous `location.href=`/`location.assign()`/`location.replace()`
 * absolute-URL literals — everything else is byte-identical, so a false
 * positive cannot corrupt unrelated code paths.
 */
function scriptHandler(ctx) {
    return {
        element(el) {
            ctx.scriptBuf = '';
            ctx.scriptType = el.getAttribute('type') || '';
        },
        text(chunk) {
            try {
                if (!JS_TYPE_RE.test(ctx.scriptType)) return; // pass through untouched
                ctx.scriptBuf += chunk.text;
                if (chunk.lastInTextNode) {
                    const rewritten = rewriteNavigationJS(ctx.scriptBuf, ctx.base);
                    ctx.scriptBuf = '';
                    chunk.replace(rewritten);
                } else {
                    chunk.replace('');
                }
            } catch {
                /* fail-open */
            }
        },
    };
}

/**
 * Bootstrap injector — prepends two scripts into <head> (or <body> as
 * fallback), in this order:
 *
 *   1. `self.__uvedge$base = <docUrl>` — the TRUE document URL, so the
 *      runtime hooks can resolve protocol-relative and relative values
 *      against the target instead of the worker origin.
 *   2. BOOTSTRAP_SCRIPT — the fetch/XHR/sendBeacon/window.open/history/
 *      form.submit/WebSocket/EventSource hooks + the click/auxclick/submit
 *      capture listeners that re-route runtime-set URLs at event time (the
 *      event-capture design replaces a MutationObserver: zero idle CPU and
 *      the same observable behaviour for anything a user can click or
 *      submit).
 *
 * HTMLRewriter insertions are emitted verbatim and are NOT re-processed by
 * any handler, so the injected scripts are never mangled.
 */
function injectHandler(ctx) {
    return {
        element(el) {
            try {
                if (ctx.injected) return;
                ctx.injected = true;
                el.prepend(BOOTSTRAP_SCRIPT, { html: true });
                el.prepend(
                    '<script>self.__uvedge$base=' + JSON.stringify(ctx.docUrl) + ';</script>',
                    { html: true }
                );
            } catch {
                /* ignore */
            }
        },
    };
}

/**
 * True when the Content-Type is HTML (the only type fed to HTMLRewriter).
 */
function isHtmlContentType(contentType) {
    return (contentType || '').toLowerCase().includes('text/html');
}

/* ============================================================================
 * 9. PROXY CORE
 * ==========================================================================*/

/**
 * Handle /proxy?url=<base64url target> AND /proxy/<base64url target> —
 * decode, merge surviving form fields, fetch, sanitize, rewrite.
 * Exactly one upstream subrequest per invocation.
 *
 * Bug 1: a <form method="get"> submission REPLACES the action URL's query
 * (HTML spec "Mutate action URL's query"), so the path form carries the
 * target in the path and whatever fields survive on the query are merged
 * back into the target URL before fetching.
 */
async function handleProxy(request) {
    const url = new URL(request.url);

    let encoded = null;
    if (url.pathname === PROXY_PATH) {
        encoded = url.searchParams.get(PARAM);
    } else if (url.pathname.startsWith(PROXY_PATH + '/')) {
        // Path form (form actions): /proxy/<base64url>
        encoded = url.pathname.slice(PROXY_PATH.length + 1);
        if (!encoded) encoded = url.searchParams.get(PARAM); // belt & braces
    }
    if (!encoded) {
        // Bug 1 recovery: the url parameter was clobbered (GET form submission
        // against a query-form action, or a query-relative navigation). The
        // Referer still identifies the document, so the intended target is
        // the referer's target with its query REPLACED by whatever survived.
        const rec = recoverStragglerTarget(url.pathname, url.search, request.headers.get('referer'));
        if (rec) return redirectProxy(rec, request.method);
        return errorResponse(400, 'Missing "' + PARAM + '" parameter');
    }
    let target;
    try {
        target = b64urlDecode(encoded);
    } catch {
        const rec = recoverStragglerTarget(url.pathname, url.search, request.headers.get('referer'));
        if (rec) return redirectProxy(rec, request.method);
        return errorResponse(400, 'Malformed base64url parameter');
    }
    let targetUrl;
    try {
        targetUrl = new URL(target);
    } catch {
        return errorResponse(400, 'Decoded value is not a valid absolute URL');
    }
    if (!ALLOWED_PROTOCOLS.has(targetUrl.protocol)) {
        return errorResponse(400, 'Only http and https targets are supported');
    }
    if (targetUrl.origin === url.origin) {
        // Self-proxy guard: a crafted url parameter pointing back at this
        // worker would burn subrequests recursively (and would let a
        // referer-recovery chain loop).
        return errorResponse(400, 'Refusing to proxy the proxy itself');
    }

    // --- Bug 1: merge surviving GET-form fields / appended params ----------
    mergeExtraParams(targetUrl, url.searchParams);

    const outRequest = buildOutgoingRequest(request, targetUrl);

    let upstream;
    try {
        upstream = await fetch(outRequest);
    } catch (err) {
        return errorResponse(502, 'Upstream fetch failed: ' + (err && err.message ? err.message : String(err)), target);
    }

    const { headers, jarCookie } = sanitizeResponseHeaders(upstream, targetUrl, request);
    const contentType = upstream.headers.get('content-type') || '';
    applyDispositionPolicy(headers, contentType, upstream.headers.get('content-disposition'));

    // --- redirects: keep the status, rewrite Location into a proxy URL ----
    if (REDIRECT_STATUSES.has(upstream.status)) {
        const location = upstream.headers.get('location');
        if (location) {
            headers.set('location', rewriteLocationHeader(location, targetUrl));
        }
        if (jarCookie) headers.append('set-cookie', jarCookie);
        return new Response(null, { status: upstream.status, headers });
    }

    // --- no-body responses --------------------------------------------------
    if (upstream.status === 204 || upstream.status === 304 || request.method === 'HEAD') {
        if (jarCookie) headers.append('set-cookie', jarCookie);
        return new Response(null, { status: upstream.status, headers });
    }

    if (jarCookie) headers.append('set-cookie', jarCookie);

    // --- HTML: stream through the native HTMLRewriter ----------------------
    if (isHtmlContentType(contentType) && typeof HTMLRewriter === 'function') {
        headers.delete('content-length'); // body length changes
        headers.delete('content-encoding');
        const ctx = makeRewriteCtx(targetUrl.href, url.origin);
        const transformed = new HTMLRewriter()
            .on('base', baseHandler(ctx))
            .on('meta', metaHandler(ctx))
            .on('form', formHandler(ctx))
            .on('style', styleHandler(ctx))
            .on('script', scriptHandler(ctx))
            .on('head', injectHandler(ctx))
            .on('body', injectHandler(ctx))
            .on('*', urlAttrsHandler(ctx))
            .transform(new Response(upstream.body, { status: upstream.status, headers }));
        return transformed;
    }

    // --- CSS: buffered regex rewrite (url()/@import must not be split) -----
    const ctLower = contentType.toLowerCase();
    if (ctLower.includes('text/css')) {
        let cssText;
        try {
            cssText = await upstream.text();
        } catch (err) {
            return errorResponse(502, 'Stylesheet read failed: ' + (err && err.message), target);
        }
        headers.delete('content-length');
        headers.delete('content-encoding');
        return new Response(rewriteCSS(cssText, targetUrl.href), {
            status: upstream.status,
            headers,
        });
    }

    // --- JavaScript: buffered navigation-literal rewrite (Bug 2) -----------
    // Only for scripts within the CPU-safe size budget; larger bundles
    // stream through untouched (fail-open for effectiveness of delivery).
    if (ctLower.includes('javascript') || ctLower.includes('ecmascript')) {
        const declaredLength = parseInt(upstream.headers.get('content-length') || '0', 10);
        if (!(declaredLength > JS_REWRITE_LIMIT)) {
            let jsText;
            try {
                jsText = await upstream.text();
            } catch (err) {
                return errorResponse(502, 'Script read failed: ' + (err && err.message), target);
            }
            headers.delete('content-length');
            headers.delete('content-encoding');
            return new Response(rewriteNavigationJS(jsText, targetUrl.href), {
                status: upstream.status,
                headers,
            });
        }
    }

    // --- everything else: pure streaming passthrough ------------------------
    // Images, video, fonts, JSON... the browser pools these connections
    // natively (spec) and the rewriter would only add latency.
    return new Response(upstream.body, { status: upstream.status, headers });
}

/* ============================================================================
 * 9b. WEBSOCKET REVERSE PROXY (Bug 3 fix)
 * --------------------------------------------------------------------------
 * Two transports, tried in order:
 *
 *   1. cloudflare:sockets connect() — a raw TCP (ws:) or TLS (wss:) socket
 *      plus a hand-rolled RFC 6455 handshake and frame codec. This gives
 *      full control over Origin / Cookie / Sec-WebSocket-Protocol / the
 *      request path, none of which the fetch()-upgrade path can guarantee —
 *      the field failure the spec calls a "HARD Cloudflare Workers
 *      limitation". connect() is GA on the free plan.
 *   2. fetch() + Upgrade: websocket — the runtime's convenience client,
 *      kept as an automatic fallback for environments where connect() is
 *      unavailable.
 *
 * The browser leg is a same-origin upgrade to /ws?url=<b64(target)> served
 * from a WebSocketPair; the bootstrap hook rewrites `new WebSocket(...)`
 * onto it (service workers never intercept WebSocket traffic, so /ws needs
 * no SW routing).
 *
 *   browser ── wss://<worker>/ws?url=<b64> ── Worker ── connect()/Upgrade ── target
 *
 * Concurrency: MAX_TUNNELS (= 6) per isolate, honouring the spec's "max of
 * 6 at a time" and the platform's six-simultaneous-connections budget. Each
 * tunnel holds exactly one outbound connection. A hard GLOBAL cap would
 * need Durable Objects; per-isolate is the free-plan-faithful reading.
 * ==========================================================================*/

/** Live tunnels in this isolate (see MAX_TUNNELS). */
let activeTunnels = 0;

/**
 * Acquire a tunnel slot. False when the isolate is at capacity. The
 * single-threaded runtime makes check-and-increment atomic; the cap is also
 * pre-checked before the WebSocketPair is created so overload answers fast.
 */
function acquireTunnelSlot() {
    if (activeTunnels >= MAX_TUNNELS) return false;
    activeTunnels++;
    return true;
}

/** Test hook: current tunnel accounting (used by the test suite only). */
function __tunnelState() {
    return { active: activeTunnels, max: MAX_TUNNELS };
}

/**
 * Lazily resolve cloudflare:sockets' connect(). A dynamic import keeps the
 * module loadable in plain Node (unit tests import worker.js directly) and
 * lets the test suite substitute the transport through
 * globalThis.__UVEDGE_CONNECT__. undefined = untried; null = unavailable.
 * @returns {Promise<Function|null>}
 */
let __connectFn;
async function getConnect() {
    if (typeof globalThis.__UVEDGE_CONNECT__ === 'function') {
        __connectFn = globalThis.__UVEDGE_CONNECT__;
        return __connectFn;
    }
    if (__connectFn !== undefined) return __connectFn || null;
    try {
        __connectFn = (await import('cloudflare:sockets')).connect;
    } catch {
        __connectFn = null;
    }
    return __connectFn || null;
}

/** Race a promise against a wall-clock deadline (timers are free CPU-wise). */
function withTimeout(promise, ms, label) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(label || 'timeout')), ms);
        promise.then(
            (v) => {
                clearTimeout(timer);
                resolve(v);
            },
            (e) => {
                clearTimeout(timer);
                reject(e);
            }
        );
    });
}

/** Concatenate Uint8Arrays into one fresh buffer. */
function concatBytes(chunks) {
    let total = 0;
    for (const c of chunks) total += c.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
        out.set(c, off);
        off += c.length;
    }
    return out;
}

/**
 * Encode one WebSocket frame (RFC 6455 §5). Client-to-server frames MUST be
 * masked (§5.3); server-to-client frames must not be. FIN is always set —
 * the relay sends only whole messages and control frames.
 * @param {number} opcode 0x1 text, 0x2 binary, 0x8 close, 0x9 ping, 0xA pong
 * @param {Uint8Array} payload
 * @param {boolean} mask
 * @returns {Uint8Array}
 */
function encodeWsFrame(opcode, payload, mask) {
    const len = payload.length;
    const headerLen = len < 126 ? 2 : len < 65536 ? 4 : 10;
    const maskLen = mask ? 4 : 0;
    const out = new Uint8Array(headerLen + maskLen + len);
    out[0] = 0x80 | (opcode & 0x0f); // FIN + opcode
    if (len < 126) {
        out[1] = (mask ? 0x80 : 0) | len;
    } else if (len < 65536) {
        out[1] = (mask ? 0x80 : 0) | 126;
        out[2] = (len >> 8) & 0xff;
        out[3] = len & 0xff;
    } else {
        out[1] = (mask ? 0x80 : 0) | 127;
        const dv = new DataView(out.buffer);
        dv.setUint32(2, Math.floor(len / 4294967296));
        dv.setUint32(6, len % 4294967296);
    }
    let off = headerLen;
    if (mask) {
        const key = crypto.getRandomValues(new Uint8Array(4));
        out.set(key, off);
        off += 4;
        for (let i = 0; i < len; i++) out[off + i] = payload[i] ^ key[i & 3];
    } else {
        out.set(payload, off);
    }
    return out;
}

/**
 * Try to parse ONE frame from the head of `buf`. Returns null when more
 * bytes are needed; throws on protocol-level garbage (oversized length) so
 * callers can fail the tunnel instead of buffering forever.
 * @param {Uint8Array} buf
 * @returns {{fin:boolean, opcode:number, payload:Uint8Array, consumed:number}|null}
 */
function tryParseFrame(buf) {
    if (buf.length < 2) return null;
    const b0 = buf[0];
    const b1 = buf[1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let off = 2;
    if (len === 126) {
        if (buf.length < 4) return null;
        len = (buf[2] << 8) | buf[3];
        off = 4;
    } else if (len === 127) {
        if (buf.length < 10) return null;
        const dv = new DataView(buf.buffer, buf.byteOffset + 2, 8);
        const hi = dv.getUint32(0);
        const lo = dv.getUint32(4);
        len = hi * 4294967296 + lo;
        off = 10;
    }
    if (len > MAX_WS_FRAME) {
        throw new Error('oversized WebSocket frame (' + len + ' bytes)');
    }
    let maskKey = null;
    if (masked) {
        if (buf.length < off + 4) return null;
        maskKey = buf.subarray(off, off + 4);
        off += 4;
    }
    if (buf.length < off + len) return null;
    let payload = buf.subarray(off, off + len);
    if (masked) {
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++) out[i] = payload[i] ^ maskKey[i & 3];
        payload = out;
    } else {
        payload = payload.slice(); // detach from the (reused) buffer
    }
    return { fin, opcode, payload, consumed: off + len };
}

/**
 * Incremental RFC 6455 stream decoder: feed() raw socket bytes, drain()
 * complete events — data messages (opcode 1/2, fragmentation reassembled)
 * and control frames (close/ping/pong). Pure logic, no I/O: unit-testable
 * in plain Node.
 */
class WsStreamDecoder {
    /**
     * @param {Uint8Array} [seed] bytes already read past the HTTP head
     */
    constructor(seed) {
        this.buf = seed && seed.length ? new Uint8Array(seed) : new Uint8Array(0);
        this.out = [];
        this.msgOpcode = 0;
        this.msgParts = null;
    }

    /** @param {Uint8Array} chunk */
    feed(chunk) {
        if (!chunk || !chunk.length) return;
        this.buf = this.buf.length ? concatBytes([this.buf, chunk]) : new Uint8Array(chunk);
        this.parse();
    }

    /**
     * @returns {Array<{control?:boolean, opcode:number, payload:Uint8Array, error?:string}>}
     */
    drain() {
        const out = this.out;
        this.out = [];
        return out;
    }

    fail(message) {
        this.out.push({ error: message });
        this.buf = new Uint8Array(0);
        this.msgParts = null;
    }

    parse() {
        for (;;) {
            let frame;
            try {
                frame = tryParseFrame(this.buf);
            } catch (err) {
                this.fail(err && err.message ? err.message : String(err));
                return;
            }
            if (!frame) return;
            this.buf = this.buf.subarray(frame.consumed);
            if (frame.opcode >= 0x8) {
                // control frames may interleave with fragments (§5.5)
                this.out.push({ control: true, opcode: frame.opcode, payload: frame.payload });
                continue;
            }
            if (frame.opcode !== 0) {
                this.msgOpcode = frame.opcode;
                this.msgParts = [frame.payload];
            } else if (this.msgParts) {
                this.msgParts.push(frame.payload);
            } else {
                this.fail('continuation frame without a start frame');
                return;
            }
            if (frame.fin && this.msgParts) {
                const payload =
                    this.msgParts.length === 1 ? this.msgParts[0] : concatBytes(this.msgParts);
                this.out.push({ opcode: this.msgOpcode, payload });
                this.msgParts = null;
            }
        }
    }
}

/**
 * Build the outbound HTTP Upgrade request for the TCP tunnel (RFC 6455 §4.1)
 * — full control over every header, which is precisely what the
 * fetch()-upgrade path cannot offer. Pure string builder: unit-testable.
 * @param {URL} targetUrl absolute ws/wss/http/https target
 * @param {{origin?:string, protocol?:string, cookie?:string}} [opts]
 * @returns {string} the complete request, CRLF-terminated
 */
function buildWsHandshake(targetUrl, opts) {
    const o = opts || {};
    let host = targetUrl.hostname;
    if (host.includes(':') && !host.startsWith('[')) host = '[' + host + ']'; // IPv6 literal
    const hostHeader = targetUrl.port ? host + ':' + targetUrl.port : host;
    const keyBytes = crypto.getRandomValues(new Uint8Array(16));
    let keyBin = '';
    for (let i = 0; i < keyBytes.length; i++) keyBin += String.fromCharCode(keyBytes[i]);
    const key = btoa(keyBin);
    let hs =
        'GET ' + (targetUrl.pathname || '/') + (targetUrl.search || '') + ' HTTP/1.1\r\n' +
        'Host: ' + hostHeader + '\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Key: ' + key + '\r\n' +
        'Sec-WebSocket-Version: 13\r\n' +
        'User-Agent: ' + BROWSER_UA + '\r\n' +
        'Accept-Language: ' + BROWSER_ACCEPT_LANG + '\r\n' +
        'Cache-Control: no-cache\r\n' +
        'Pragma: no-cache\r\n';
    if (o.origin) hs += 'Origin: ' + o.origin + '\r\n';
    if (o.protocol) hs += 'Sec-WebSocket-Protocol: ' + o.protocol + '\r\n';
    if (o.cookie) hs += 'Cookie: ' + o.cookie + '\r\n';
    return hs + '\r\n';
}

/** Index of the first \\r\\n\\r\\n in buf, or -1. */
function findHeaderEnd(buf) {
    for (let i = 0; i + 3 < buf.length; i++) {
        if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) return i;
    }
    return -1;
}

/**
 * Read from a socket reader until the end of the HTTP head. Returns the
 * status line, the header lines, and any bytes already past the head (the
 * first WebSocket frame often arrives glued to the 101).
 * @param {ReadableStreamDefaultReader} reader
 * @returns {Promise<{statusLine:string, headers:string[], rest:Uint8Array}>}
 */
async function readHttpHead(reader) {
    let buf = new Uint8Array(0);
    for (;;) {
        const idx = findHeaderEnd(buf);
        if (idx !== -1) {
            const headText = new TextDecoder().decode(buf.subarray(0, idx));
            const rest = buf.subarray(idx + 4);
            const lines = headText.split('\r\n');
            return { statusLine: lines[0] || '', headers: lines.slice(1), rest };
        }
        if (buf.length > 65536) throw new Error('handshake head exceeded 64 KiB');
        const { value, done } = await reader.read();
        if (done) throw new Error('socket closed during handshake');
        buf = buf.length ? concatBytes([buf, value]) : new Uint8Array(value);
    }
}

/** Case-insensitive header lookup over ["Name: value"] lines. */
function findHeaderValue(headerLines, name) {
    const lower = String(name).toLowerCase();
    for (const line of headerLines) {
        const idx = line.indexOf(':');
        if (idx <= 0) continue;
        if (line.slice(0, idx).trim().toLowerCase() === lower) {
            return line.slice(idx + 1).trim();
        }
    }
    return null;
}

/** All Set-Cookie values over ["Name: value"] lines. */
function collectSetCookieLines(headerLines) {
    const out = [];
    for (const line of headerLines) {
        const idx = line.indexOf(':');
        if (idx <= 0) continue;
        if (line.slice(0, idx).trim().toLowerCase() === 'set-cookie') {
            out.push(line.slice(idx + 1).trim());
        }
    }
    return out;
}

/**
 * Wire the relay loops between the browser-side socket and the TCP stream.
 * Browser->target frames are re-encoded MASKED (the browser-side socket of a
 * WebSocketPair delivers unmasked message events; the target requires
 * masked client frames). Target->browser frames are parsed, reassembled and
 * delivered as messages. Exactly one tunnel slot is released per call
 * (guarded finish()).
 *
 * @param {WebSocket} clientSock server side of our WebSocketPair (browser leg)
 * @param {object} socket cloudflare:sockets handle
 * @param {WritableStreamDefaultWriter} writer
 * @param {ReadableStreamDefaultReader} reader
 * @param {WsStreamDecoder} decoder pre-seeded with post-101 bytes
 */
function pumpTunnelFrames(clientSock, socket, writer, reader, decoder) {
    let finished = false; // socket torn down?
    let released = false; // tunnel slot returned?
    const release = () => {
        // The slot is returned the moment ANY terminal signal arrives — the
        // browser close event must not wait for the close-frame flush to
        // settle, or a rapid close/reopen cycle spuriously hits the cap.
        if (released) return;
        released = true;
        activeTunnels--;
    };
    const finish = () => {
        if (finished) return;
        finished = true;
        release();
        try { socket.close(); } catch { /* already closed */ }
    };
    const writeFrame = (opcode, payload) => {
        writer.write(encodeWsFrame(opcode, payload, true)).catch(() => finish());
    };
    /** Forward a close frame downstream (best effort), then tear down. */
    const closeDownstream = (code, reason) => {
        release(); // capacity returns immediately; the flush is politeness
        const payload = new Uint8Array([(code >> 8) & 0xff, code & 0xff]);
        let settled = false;
        const done = () => {
            if (!settled) {
                settled = true;
                finish();
            }
        };
        writer.write(encodeWsFrame(0x8, payload, true)).then(done, done);
        setTimeout(done, 1000); // bounded flush window
        try { clientSock.close(code, String(reason || '').slice(0, 100)); } catch { /* ignore */ }
    };

    // --- target -> browser -------------------------------------------------
    (async () => {
        try {
            for (;;) {
                const events = decoder.drain();
                for (const ev of events) {
                    if (ev.error) {
                        finish();
                        try { clientSock.close(1002, 'protocol error'); } catch { /* ignore */ }
                        return;
                    }
                    if (ev.control) {
                        if (ev.opcode === 0x9) {
                            writeFrame(0xA, ev.payload); // ping -> pong (masked)
                        } else if (ev.opcode === 0x8) {
                            // Echo the close frame (RFC 6455 §5.5.1) ...
                            writeFrame(0x8, ev.payload);
                            const code = ev.payload.length >= 2 ? ((ev.payload[0] << 8) | ev.payload[1]) : 1000;
                            const reason =
                                ev.payload.length > 2 ? new TextDecoder().decode(ev.payload.subarray(2)) : '';
                            // ... then propagate the code to the browser.
                            finish();
                            try { clientSock.close(code, String(reason).slice(0, 100)); } catch { /* ignore */ }
                            return;
                        }
                        // pong (0xA): nothing to do
                        continue;
                    }
                    try {
                        if (ev.opcode === 0x1) {
                            clientSock.send(new TextDecoder().decode(ev.payload));
                        } else {
                            clientSock.send(
                                ev.payload.buffer.slice(
                                    ev.payload.byteOffset,
                                    ev.payload.byteOffset + ev.payload.byteLength
                                )
                            );
                        }
                    } catch {
                        finish();
                        return;
                    }
                }
                const { value, done } = await reader.read();
                if (done) {
                    finish();
                    try { clientSock.close(1006, 'upstream closed'); } catch { /* ignore */ }
                    return;
                }
                decoder.feed(value);
            }
        } catch {
            finish();
            try { clientSock.close(1011, 'relay error'); } catch { /* ignore */ }
        }
    })();

    // --- browser -> target ---------------------------------------------------
    clientSock.addEventListener('message', (ev) => {
        if (finished) return;
        try {
            if (typeof ev.data === 'string') writeFrame(0x1, new TextEncoder().encode(ev.data));
            else writeFrame(0x2, new Uint8Array(ev.data));
        } catch {
            finish();
        }
    });
    clientSock.addEventListener('close', (ev) => {
        if (finished) return;
        closeDownstream(ev && typeof ev.code === 'number' ? ev.code : 1000, '');
    });
    clientSock.addEventListener('error', () => {
        if (finished) return;
        closeDownstream(1011, 'client error');
    });
}

/**
 * Primary transport: raw TCP/TLS socket + manual RFC 6455 handshake.
 * @param {URL} targetUrl
 * @param {Request} request inbound upgrade request (protocol/cookie context)
 * @param {WebSocket} clientSock server side of our WebSocketPair
 * @returns {Promise<{negotiated:string|null, setCookieLines:string[]}>}
 */
async function tunnelViaConnect(targetUrl, request, clientSock) {
    const connect = await getConnect();
    if (!connect) throw new Error('cloudflare:sockets connect() unavailable');
    const secure = targetUrl.protocol === 'wss:' || targetUrl.protocol === 'https:';
    const port = targetUrl.port ? Number(targetUrl.port) : secure ? 443 : 80;
    let host = targetUrl.hostname;
    if (host.includes(':') && !host.startsWith('[')) host = '[' + host + ']';
    const socket = connect(host + ':' + port, { secureTransport: secure ? 'on' : 'off' });
    let writer = null;
    let reader = null;
    try {
        await withTimeout(socket.opened, WS_CONNECT_TIMEOUT, 'TCP connect timeout');
        writer = socket.writable.getWriter();
        reader = socket.readable.getReader();
        const jar = readJar(request.headers.get('cookie'), targetUrl.hostname);
        const handshake = buildWsHandshake(targetUrl, {
            // A browser page on the target origin sends an http(s)-scheme
            // Origin on the WS handshake (ws/wss never appear in Origin).
            origin: wsFetchUrl(targetUrl) ? wsFetchUrl(targetUrl).origin : undefined,
            protocol: request.headers.get('sec-websocket-protocol') || undefined,
            cookie: serializeJar(jar) || undefined,
        });
        await writer.write(new TextEncoder().encode(handshake));
        const head = await withTimeout(
            readHttpHead(reader),
            WS_HANDSHAKE_TIMEOUT,
            'WebSocket handshake timeout'
        );
        if (!/^HTTP\/1\.[01]\s+101\b/.test(head.statusLine)) {
            throw new Error('upstream refused the upgrade: ' + head.statusLine.trim().slice(0, 80));
        }
        const negotiated = findHeaderValue(head.headers, 'sec-websocket-protocol');
        const setCookieLines = collectSetCookieLines(head.headers);
        if (!acquireTunnelSlot()) throw new Error('tunnel limit reached');
        pumpTunnelFrames(clientSock, socket, writer, reader, new WsStreamDecoder(head.rest));
        return { negotiated, setCookieLines };
    } catch (err) {
        try { socket.close(); } catch { /* ignore */ }
        throw err;
    }
}

/**
 * Map ws:/wss: targets onto the http(s) scheme fetch() needs for the
 * outbound upgrade.
 * @param {URL} targetUrl
 * @returns {URL|null}
 */
function wsFetchUrl(targetUrl) {
    try {
        if (targetUrl.protocol === 'wss:') return new URL('https:' + targetUrl.href.slice('wss:'.length));
        if (targetUrl.protocol === 'ws:') return new URL('http:' + targetUrl.href.slice('ws:'.length));
        return targetUrl; // http:/https: targets pass through
    } catch {
        return null;
    }
}

/**
 * Fallback transport: the runtime's fetch()-based WebSocket client
 * (response.webSocket). Kept because connect() can be unavailable in
 * restricted runtimes while fetch-upgrade still works for well-behaved
 * upstreams that do not require precise handshake headers.
 * @param {URL} targetUrl
 * @param {Request} request
 * @param {WebSocket} clientSock server side of our WebSocketPair
 * @returns {Promise<{negotiated:string|null, setCookieLines:string[]}>}
 */
async function tunnelViaFetchUpgrade(targetUrl, request, clientSock) {
    const fetchUrl = wsFetchUrl(targetUrl);
    if (!fetchUrl) throw new Error('invalid WebSocket target URL');
    const headers = new Headers();
    headers.set('Upgrade', 'websocket');
    headers.set('Connection', 'Upgrade');
    headers.set('User-Agent', BROWSER_UA);
    headers.set('Accept-Language', BROWSER_ACCEPT_LANG);
    headers.set('Origin', fetchUrl.origin); // spoofed, same policy as HTTP path
    headers.set('sec-ch-ua', BROWSER_SEC_CH_UA);
    headers.set('sec-ch-ua-mobile', '?0');
    headers.set('sec-ch-ua-platform', '"Windows"');
    const requestedProtocol = request.headers.get('sec-websocket-protocol');
    if (requestedProtocol) headers.set('Sec-WebSocket-Protocol', requestedProtocol);
    const jar = readJar(request.headers.get('cookie'), targetUrl.hostname);
    const cookieHeader = serializeJar(jar);
    if (cookieHeader) headers.set('Cookie', cookieHeader);

    let upstreamResp;
    try {
        upstreamResp = await fetch(fetchUrl.href, { headers });
    } catch (err) {
        throw new Error(
            'upstream connect failed: ' + (err && err.message ? err.message : String(err))
        );
    }
    const upstreamWs = upstreamResp.webSocket;
    if (!upstreamWs || upstreamResp.status !== 101) {
        try {
            if (upstreamResp.body) upstreamResp.body.cancel();
        } catch { /* ignore */ }
        throw new Error('upstream refused the upgrade (HTTP ' + upstreamResp.status + ')');
    }
    upstreamWs.accept();
    if (!acquireTunnelSlot()) {
        try { upstreamWs.close(1013, 'tunnel limit'); } catch { /* ignore */ }
        throw new Error('tunnel limit reached');
    }

    let finished = false;
    const finish = () => {
        if (finished) return;
        finished = true;
        activeTunnels--;
    };
    const hangup = (code, reason) => {
        try { upstreamWs.close(code, String(reason || '').slice(0, 100)); } catch { /* ignore */ }
        try { clientSock.close(code, String(reason || '').slice(0, 100)); } catch { /* ignore */ }
    };
    clientSock.addEventListener('message', (ev) => {
        if (finished) return;
        try { upstreamWs.send(ev.data); } catch { finish(); hangup(1011, 'upstream send failed'); }
    });
    upstreamWs.addEventListener('message', (ev) => {
        if (finished) return;
        try { clientSock.send(ev.data); } catch { finish(); hangup(1011, 'client send failed'); }
    });
    clientSock.addEventListener('close', (ev) => {
        if (finished) return;
        finish();
        try { upstreamWs.close(ev && typeof ev.code === 'number' ? ev.code : 1000, ''); } catch { /* ignore */ }
    });
    upstreamWs.addEventListener('close', (ev) => {
        if (finished) return;
        finish();
        try { clientSock.close(ev && typeof ev.code === 'number' ? ev.code : 1000, ''); } catch { /* ignore */ }
    });
    clientSock.addEventListener('error', () => { finish(); hangup(1011, 'client error'); });
    upstreamWs.addEventListener('error', () => { finish(); hangup(1011, 'upstream error'); });

    return {
        negotiated: upstreamResp.headers.get('sec-websocket-protocol') || null,
        setCookieLines: getSetCookies(upstreamResp.headers),
    };
}

/**
 * Handle /ws?url=<b64url target> — the WebSocket reverse proxy.
 * Validates, caps, pairs, then tries connect() with the fetch-upgrade
 * fallback. One outbound connection per tunnel; free-plan compatible.
 * @param {Request} request inbound upgrade request
 */
async function handleWebsocketProxy(request) {
    const url = new URL(request.url);
    const encoded = url.searchParams.get(PARAM);
    if (!encoded) return errorResponse(400, 'Missing "' + PARAM + '" parameter');
    let target;
    try {
        target = b64urlDecode(encoded);
    } catch {
        return errorResponse(400, 'Malformed base64url parameter');
    }
    let targetUrl;
    try {
        targetUrl = new URL(target);
    } catch {
        return errorResponse(400, 'Decoded value is not a valid absolute URL');
    }
    if (!WS_SCHEMES.has(targetUrl.protocol)) {
        return errorResponse(400, 'Only ws, wss, http and https targets are supported');
    }
    const upgrade = (request.headers.get('upgrade') || '').toLowerCase();
    if (upgrade !== 'websocket') {
        return errorResponse(426, 'Upgrade Required: this endpoint only speaks WebSocket');
    }
    // Fast pre-check before the pair is created (acquireTunnelSlot re-checks
    // after the await gaps inside each transport).
    if (activeTunnels >= MAX_TUNNELS) {
        return errorResponse(
            503,
            'WebSocket tunnel limit reached (' + MAX_TUNNELS + ' concurrent tunnels per isolate)'
        );
    }

    // --- client side: a fresh WebSocketPair ---------------------------------
    let pair;
    try {
        pair = Object.values(new WebSocketPair());
    } catch (err) {
        return errorResponse(
            500,
            'WebSocketPair failed: ' + (err && err.message ? err.message : String(err))
        );
    }
    const [client, serverSide] = pair;
    serverSide.accept();

    // --- transports: connect() first, fetch-upgrade as fallback --------------
    let tunnel = null;
    let lastError = null;
    try {
        tunnel = await tunnelViaConnect(targetUrl, request, serverSide);
    } catch (err) {
        lastError = err;
    }
    if (!tunnel) {
        try {
            tunnel = await tunnelViaFetchUpgrade(targetUrl, request, serverSide);
        } catch (err) {
            lastError = err;
        }
    }
    if (!tunnel) {
        try { serverSide.close(1011, 'tunnel failed'); } catch { /* ignore */ }
        return errorResponse(
            502,
            'WebSocket tunnel failed: ' +
                (lastError && lastError.message ? lastError.message : String(lastError)),
            target
        );
    }

    // --- 101 with the client socket ------------------------------------------
    const respHeaders = new Headers();
    if (tunnel.negotiated) {
        try { respHeaders.set('Sec-WebSocket-Protocol', tunnel.negotiated); } catch { /* ignore */ }
    }
    if (tunnel.setCookieLines && tunnel.setCookieLines.length) {
        // jar any cookies the upstream handshake set, same as the HTTP path
        const jar = readJar(request.headers.get('cookie'), targetUrl.hostname);
        applySetCookies(jar, tunnel.setCookieLines);
        try {
            respHeaders.append('Set-Cookie', buildJarCookie(targetUrl.hostname, jar, 0));
        } catch { /* ignore */ }
    }
    return new Response(null, { status: 101, webSocket: client, headers: respHeaders });
}

/* ============================================================================
 * 10. STATIC ASSETS + ROUTER
 * ==========================================================================*/

/** Minimal styled error page. */
function errorResponse(status, message, target) {
    const safeMsg = String(message).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const safeTarget = target ? String(target).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])) : '';
    const html =
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + status + ' — Ultraviolet Edge</title>' +
        '<style>body{font:14px system-ui,sans-serif;background:#0b0e14;color:#e6e9ef;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}' +
        '.card{background:#151a23;border:1px solid #2a3242;border-radius:12px;padding:32px 40px;max-width:520px}' +
        'h1{margin:0 0 8px;font-size:20px;color:#ff6b6b}p{margin:4px 0;color:#9aa4b2}code{color:#7dd3fc;word-break:break-all}</style></head>' +
        '<body><div class="card"><h1>' + status + '</h1><p>' + safeMsg + '</p>' +
        (safeTarget ? '<p>Target: <code>' + safeTarget + '</code></p>' : '') +
        '</div></body></html>';
    return new Response(html, {
        status,
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
}

/** GET / — hosted test page (HEAD returns headers only). */
function serveIndex(headOnly) {
    return new Response(headOnly ? null : INDEX_HTML, {
        status: 200,
        headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
        },
    });
}

/** GET /sw.js — the service worker (HEAD returns headers only). */
function serveServiceWorker(headOnly) {
    return new Response(headOnly ? null : SW_SCRIPT, {
        status: 200,
        headers: {
            'content-type': 'application/javascript; charset=utf-8',
            'cache-control': 'no-cache',
            'service-worker-allowed': '/',
        },
    });
}

/**
 * Worker entry point (ES modules format — a valid Cloudflare Worker).
 *
 * Routes: / (hosted page, or target-root recovery when a proxied page
 * navigates to it), /sw.js, /favicon.ico (or the target's favicon when a
 * proxied page requests it), /proxy (query form), /proxy/<b64> (path form —
 * form actions), /ws (WebSocket proxy). Everything else with a proxy
 * Referer is a recoverable straggler (Bug 1/2); without one it is a genuine
 * 404.
 */
export default {
    async fetch(request) {
        try {
            const url = new URL(request.url);
            const path = url.pathname;
            const method = request.method;
            const referer = request.headers.get('referer');
            if (path === '/') {
                // A proxied document navigating to '/' means the TARGET's
                // root (runtime-built root-relative URL — Bug 1/2); the
                // Referer carries the document context. Direct visits have
                // no proxy referer and get the hosted landing page.
                if (method === 'GET' || method === 'HEAD' || method === 'POST') {
                    const recRoot = recoverStragglerTarget(path, url.search, referer);
                    if (recRoot) return redirectProxy(recRoot, method);
                }
                if (method !== 'GET' && method !== 'HEAD') {
                    return errorResponse(405, 'Method not allowed');
                }
                return serveIndex(method === 'HEAD');
            }
            if (path === '/sw.js') {
                if (method !== 'GET' && method !== 'HEAD') {
                    return errorResponse(405, 'Method not allowed');
                }
                return serveServiceWorker(method === 'HEAD');
            }
            if (path === '/favicon.ico') {
                // Same recovery: a proxied page's favicon link is rewritten
                // by the edge rewriter, but the browser's automatic
                // /favicon.ico probe still resolves against our origin.
                if (method === 'GET' || method === 'HEAD') {
                    const recIcon = recoverStragglerTarget(path, url.search, referer);
                    if (recIcon) return redirectProxy(recIcon, method);
                }
                return new Response(null, { status: 204 });
            }
            if (isProxyPathname(path)) {
                return handleProxy(request);
            }
            if (path === WS_PATH) {
                return handleWebsocketProxy(request);
            }
            // Straggler rescue (Bug 1/2, worker half): a same-origin path
            // with a proxy Referer is a runtime-built document-relative URL
            // (fetch('/api/x'), location.href='/next', an unrewritten srcset
            // candidate, ...). Recover the intended target and redirect
            // through the proxy — 307 for POST so the body replays intact.
            if (method === 'GET' || method === 'HEAD' || method === 'POST') {
                const rec = recoverStragglerTarget(path, url.search, referer);
                if (rec) return redirectProxy(rec, method);
            }
            return errorResponse(
                404,
                'Not found. Use /proxy?' + PARAM + '=<base64url target> or /proxy/<base64url target>'
            );
        } catch (err) {
            return errorResponse(500, 'Worker error: ' + (err && err.message ? err.message : String(err)));
        }
    },
};

/* ============================================================================
 * 11. SERVICE WORKER (served at /sw.js, scope "/")
 * --------------------------------------------------------------------------
 * Port of Ultraviolet's routing layer (src/sw.js + src/uv.sw.js), reduced
 * to the jobs that still belong on the client when HTML/CSS rewriting
 * happens at the edge:
 *
 *   1. Route proxy traffic — but only when the target actually decodes.
 *      A /proxy URL whose ?url= was clobbered (GET form submission against
 *      a query-form action, query-relative navigation) is a STRAGGLER now,
 *      not passthrough traffic — passing it through is what produced the
 *      400 "Missing url parameter" on Bing/YouTube searches (Bug 1).
 *   2. Resolve stragglers: same-origin requests for anything the rewriter
 *      never saw (relative URLs built at runtime, unrewritten srcset
 *      candidates, clobbered proxy URLs). The target context comes from the
 *      request's referrer (a proxy URL) or a clientId -> target map kept
 *      for every proxied navigation; the request is re-encoded and fetched
 *      through the proxy. Clobbered proxy URLs apply form-mutation
 *      semantics: the referrer target's query is REPLACED by the surviving
 *      fields. '/' and '/favicon.ico' recover the same way when a proxy
 *      context exists; without one they fall through to the worker
 *      (landing page / 204), which performs the equivalent rescue for
 *      SW-less clients.
 * ==========================================================================*/

const SW_SCRIPT = `'use strict';
/*
 * ULTRAVIOLET EDGE — Service Worker
 * Routing layer ported from Ultraviolet's uv.sw.js / sw.js.
 */

var PROXY_PATH = ${JSON.stringify(PROXY_PATH)};
var PARAM = ${JSON.stringify(PARAM)};
var WS_PATH = ${JSON.stringify(WS_PATH)};

/* resultingClientId -> target URL of the document being loaded */
var docBases = new Map();

self.addEventListener('install', function (e) {
    self.skipWaiting();
});

self.addEventListener('activate', function (e) {
    e.waitUntil(self.clients.claim());
});

/* client-side copy of the edge base64url codec (UTF-8 safe) */
function enc(str) {
    try {
        var bytes = new TextEncoder().encode(String(str));
        var bin = '';
        for (var i = 0; i < bytes.length; i += 0x8000) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }
        return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    } catch (e) {
        return null;
    }
}

function dec(str) {
    try {
        var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var bin = atob(s);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new TextDecoder().decode(bytes);
    } catch (e) {
        return null;
    }
}

function isProxyUrl(u) {
    if (u.origin !== location.origin) return false;
    /* both forms: /proxy?url=<b64> and /proxy/<b64> (form actions) */
    return u.pathname === PROXY_PATH || u.pathname.indexOf(PROXY_PATH + '/') === 0;
}

function targetOf(u) {
    if (!isProxyUrl(u)) return null;
    /* Path form is authoritative (mirrors the worker's targetFromProxyUrl):
       a url param riding on a path-form URL is a leftover form field. */
    var v = null;
    if (u.pathname.indexOf(PROXY_PATH + '/') === 0) {
        v = u.pathname.slice(PROXY_PATH.length + 1);
    }
    if (!v) v = u.searchParams.get(PARAM);
    return v ? dec(v) : null;
}

function proxyUrl(href) {
    return PROXY_PATH + '?' + PARAM + '=' + enc(href);
}

self.addEventListener('fetch', function (event) {
    var req = event.request;
    var url;
    try {
        url = new URL(req.url);
    } catch (e) {
        return;
    }

    /* Cross-origin requests are never ours to touch. */
    if (url.origin !== location.origin) return;

    /* Proxy traffic passes through ONLY when the target actually decodes
       (Bug 1). A /proxy URL whose ?url= was clobbered — GET form submission
       against a query-form action, query-relative navigation — is handled
       by the straggler recovery below instead of being handed to the worker
       to 400. */
    if (isProxyUrl(url)) {
        var t = targetOf(url);
        if (t) {
            if (req.mode === 'navigate' && event.resultingClientId) {
                /* bound the map so long-lived sessions cannot leak entries */
                if (docBases.size > 500) docBases.delete(docBases.keys().next().value);
                docBases.set(event.resultingClientId, t);
            }
            return; // healthy proxy traffic -> straight to the worker
        }
    } else if (url.pathname === '/sw.js' || url.pathname === WS_PATH) {
        /* Worker-owned routes that are never stragglers (WS bypasses the SW
           fetch event entirely; listed so non-upgrade probes fall through). */
        return;
    }

    /*
     * Straggler: anything else same-origin — a runtime-built relative URL
     * (location.href='/next', fetch('/api/x'), unrewritten srcset entries)
     * or a clobbered proxy URL. '/' and '/favicon.ico' recover the same way
     * when a proxy context exists; without one they fall through to the
     * worker (landing page / silent 204).
     */
    var base = null;

    if (req.referrer) {
        try {
            var r = new URL(req.referrer);
            if (isProxyUrl(r)) base = targetOf(r);
        } catch (e) {}
    }
    if (!base && req.clientId && docBases.has(req.clientId)) {
        base = docBases.get(req.clientId);
    }
    if (!base) return; // no document context: the worker handles it

    /*
     * respondWith must be called synchronously, but the work inside may be
     * async: request bodies are buffered (rather than passed through as
     * streams) because fetch() with a ReadableStream body requires the
     * duplex:'half' option, which not every browser implements.
     */
    event.respondWith((async function () {
        try {
            var abs;
            if (isProxyUrl(url)) {
                /* clobbered proxy URL: form-mutation semantics — the
                   referrer target with its query REPLACED by the surviving
                   fields (exactly what the browser did to the action URL) */
                var b = new URL(base);
                b.search = url.search; /* '' when nothing survived */
                b.hash = '';
                abs = b.href;
            } else {
                abs = new URL(url.pathname + url.search, base).href;
            }
            var init = {
                method: req.method,
                headers: req.headers,
                credentials: 'include',
                redirect: 'follow',
            };
            if (req.method !== 'GET' && req.method !== 'HEAD') {
                init.body = await req.arrayBuffer();
            }
            return await fetch(proxyUrl(abs), init);
        } catch (e) {
            return new Response('Ultraviolet Edge: request routing failed', {
                status: 502,
                headers: { 'content-type': 'text/plain' },
            });
        }
    })());
});
`;

/* ============================================================================
 * 12. BOOTSTRAP SCRIPT (injected into every proxied HTML document)
 * --------------------------------------------------------------------------
 * The edge rewriter cannot see URLs constructed at runtime. This shim is a
 * port of Ultraviolet's client hook layer (src/client/requests/*,
 * src/client/dom/*), reduced to the hooks that compose safely without UV's
 * full window wrapping:
 *
 *  - route()/routeAny(): URL routing. route() handles absolute http(s);
 *    routeAny() ALSO resolves relative values against __uvedge$base (the
 *    target document URL) before routing — so fetch/XHR/beacon/open/
 *    EventSource calls work even without the service worker (Bug 2).
 *  - fetch / XHR / sendBeacon / window.open / pushState / replaceState hooks.
 *  - submit capture + form.submit(): rewrite actions to the PATH-form proxy
 *    URL at submission time — a GET submit REPLACES the action's query, so
 *    the encoded target must live in the path, and dynamically-changed
 *    actions get fixed just-in-time (Bug 1).
 *  - click/auxclick capture: rewrite hrefs of dynamically-built anchors and
 *    strip their target attribute at event time, so unrewritten links can
 *    never escape the iframe into a new tab (Bug 2).
 *  - WebSocket constructor: routes ws(s):// through the same-origin /ws
 *    tunnel (browser leg forced to wss on https pages) (Bug 3).
 *  - EventSource constructor: routes SSE through the proxy.
 *  - navigator.serviceWorker.register: blocked — a target site registering
 *    an SW at our origin would hijack the proxy's own worker.
 *
 * Deliberately NOT hooked: location.href (unforgeable own property — UV
 * needs its whole fake-window layer for that; the JS literal rewriter, the
 * SW and the worker's referer recovery cover the practical cases), and
 * HTMLAnchorElement.href property accessors (getter unrouting would feed
 * raw target URLs back into unhookable location assignments).
 * ==========================================================================*/

const BOOTSTRAP_SCRIPT = `<script>
(function () {
    if (window.__uvedge) return;
    window.__uvedge = 1;
    var ORIGIN = location.origin;
    var P = ${JSON.stringify(PROXY_PATH + '?' + PARAM + '=')};
    var PP = ${JSON.stringify(PROXY_PATH + '/')};
    var WSQ = ${JSON.stringify(WS_PATH + '?' + PARAM + '=')};
    var BASE = self.__uvedge$base || location.href;
    function enc(u) {
        try {
            var bytes = new TextEncoder().encode(String(u));
            var s = '';
            for (var i = 0; i < bytes.length; i += 0x8000) {
                s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
            }
            return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
        } catch (e) { return null; }
    }
    /* absolute http(s) -> query-form proxy URL */
    function route(u) {
        if (typeof u !== 'string' || !u) return u;
        if (!/^https?:/i.test(u)) return u;
        if (u.indexOf(ORIGIN + '/') === 0) return u;
        var e = enc(u);
        return e ? ORIGIN + P + e : u;
    }
    /*
     * Any URL value the page hands to fetch/XHR/beacon/open/EventSource.
     * Relative values are resolved against the TARGET document URL (what
     * the page's JS means), not the worker origin — this removes the
     * service worker from the critical path for runtime-built requests
     * and is the core of the Bug 2 "not rewritten correctly" fix.
     */
    function routeAny(u) {
        if (typeof u !== 'string' || u === '') return u;
        if (/^(data:|blob:|javascript:|mailto:|tel:|about:|wss?:)/i.test(u)) return u;
        if (u.indexOf(ORIGIN + P) === 0 || u.indexOf(ORIGIN + PP) === 0 || u.indexOf(ORIGIN + WSQ) === 0) return u;
        if (u.indexOf(P) === 0 || u.indexOf(PP) === 0 || u.indexOf(WSQ) === 0) return u;
        var abs;
        try { abs = /^https?:/i.test(u) ? u : new URL(u, BASE).href; } catch (e) { return u; }
        if (!/^https?:/i.test(abs)) return u;
        if (abs.indexOf(ORIGIN + '/') === 0) {
            /*
             * A same-origin ABSOLUTE url that is not one of our endpoints is
             * a Request the page built from a relative value: the browser
             * resolved it against the iframe's real (worker) URL, but the
             * page meant the TARGET. Re-resolve its path against BASE.
             */
            try {
                var pu = new URL(abs);
                var abs2 = new URL(pu.pathname + pu.search, BASE).href;
                if (abs2.indexOf(ORIGIN + '/') !== 0) {
                    var e2 = enc(abs2);
                    if (e2) return ORIGIN + P + e2;
                }
            } catch (er) {}
            return u;
        }
        var e = enc(abs);
        return e ? ORIGIN + P + e : u;
    }
    /*
     * ws/wss URL -> same-origin /ws tunnel URL. The browser leg is forced
     * to wss on https pages (mixed content); the TARGET's original scheme
     * survives inside the encoded parameter, and /ws dials TCP or TLS
     * accordingly (Bug 3).
     */
    function wsRoute(u) {
        if (typeof u !== 'string' || u === '') return u;
        if (u.indexOf(ORIGIN + WSQ) === 0 || u.indexOf(WSQ) === 0) return u;
        if (/^(data:|blob:)/i.test(u)) return u;
        var abs;
        try { abs = new URL(u, BASE).href; } catch (e) { return u; }
        var p = abs.protocol;
        if (p !== 'ws:' && p !== 'wss:' && p !== 'http:' && p !== 'https:') return u;
        var e = enc(abs);
        if (!e) return u;
        return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + WSQ + e;
    }
    /* form action -> PATH-form proxy URL: a GET submission REPLACES the
       action's query, so the target must live in the path (Bug 1) */
    function routePath(abs) {
        var e = enc(abs);
        return e ? ORIGIN + PP + e : abs;
    }
    function fixForm(f) {
        try {
            if (!f || f.tagName !== 'FORM') return;
            if (f.getAttribute('target')) f.removeAttribute('target');
            var a = f.getAttribute('action');
            var abs = null;
            if (a != null) {
                var t = String(a).trim();
                if (t === '' || t === '#') {
                    /* submits to the current document; mirror browser
                       semantics (the document URL, query dropped) */
                } else if (/^(javascript|data:|about:|mailto:|tel:)/i.test(t)) {
                    return;
                } else {
                    try { abs = new URL(t, BASE).href; } catch (e) { return; }
                }
            }
            if (!abs) {
                var d = new URL(BASE);
                d.search = '';
                d.hash = '';
                abs = d.href;
            }
            if (abs.indexOf(ORIGIN + P) === 0) {
                /* Query-form action (e.g. set at runtime from a rewritten
                   attribute): convert to path form so a GET submit cannot
                   clobber the encoded target (Bug 1). */
                try {
                    f.setAttribute('action', ORIGIN + PP + abs.slice((ORIGIN + P).length));
                } catch (er) {}
                return;
            }
            if (abs.indexOf(ORIGIN + '/') === 0) return; /* already ours (path form) */
            var r = routePath(abs);
            if (r !== abs) f.setAttribute('action', r);
        } catch (e) {}
    }
    function fixAnchor(a) {
        try {
            if (!a || !a.getAttribute) return;
            var raw = a.getAttribute('href');
            if (raw == null) return;
            var t = String(raw);
            if (t === '' || t.charAt(0) === '#') return;
            if (/^(javascript:|mailto:|tel:|data:|blob:|about:)/i.test(t)) return;
            var r = routeAny(t);
            if (r !== t) a.setAttribute('href', r);
            var tg = a.getAttribute('target');
            if (tg && tg !== '_self') a.removeAttribute('target');
        } catch (e) {}
    }
    /* --- fetch ------------------------------------------------------------- */
    try {
        var of = window.fetch;
        window.fetch = function (input, init) {
            var url = null;
            try {
                if (typeof input === 'string') url = input;
                else if (input && typeof input.url === 'string') url = input.url;
            } catch (e) {}
            if (!url) return of.call(window, input, init);
            var r = routeAny(url);
            if (r === url) return of.call(window, input, init);
            if (typeof input === 'string') return of.call(window, r, init);
            /*
             * Request object: rebuild it against the proxy. Body-bearing
             * requests are buffered first — passing a stream body through
             * Request-as-init needs duplex:'half', which is not universally
             * supported.
             */
            var method = (init && init.method) || input.method || 'GET';
            if (method === 'GET' || method === 'HEAD') {
                return of.call(window, new Request(r, input));
            }
            return input.clone().arrayBuffer().then(
                function (buf) {
                    return of.call(window, new Request(r, {
                        method: method,
                        headers: input.headers,
                        body: buf,
                        credentials: 'include',
                    }));
                },
                function () { return of.call(window, input); }
            );
        };
    } catch (e) {}
    /* --- XHR ----------------------------------------------------------------- */
    try {
        var oo = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (m, u) {
            arguments[1] = routeAny(u);
            return oo.apply(this, arguments);
        };
    } catch (e) {}
    /* --- sendBeacon ------------------------------------------------------------ */
    try {
        if (navigator.sendBeacon) {
            var ob = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function (u, d) { return ob(routeAny(String(u)), d); };
        }
    } catch (e) {}
    /* --- window.open (relative URLs resolve against the target; the opened
           window/tab stays on our origin, so it stays inside the proxy) ------- */
    try {
        var ow = window.open;
        window.open = function (u, n, f) { return ow.call(window, routeAny(u), n, f); };
    } catch (e) {}
    /* --- history: absolute literals only — relative pushState keeps the SPA's
           pathname semantics (documented trade-off, see REPORT) ---------------- */
    try {
        var hp = history.pushState, hr = history.replaceState;
        history.pushState = function (s, t, u) { return hp.call(history, s, t, route(u)); };
        history.replaceState = function (s, t, u) { return hr.call(history, s, t, route(u)); };
    } catch (e) {}
    /* --- form submission: native (capture) + programmatic ---------------------- */
    try {
        document.addEventListener('submit', function (e) { fixForm(e.target); }, true);
    } catch (e) {}
    try {
        var fs = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function () {
            try { fixForm(this); } catch (e) {}
            return fs.apply(this, arguments);
        };
    } catch (e) {}
    /* --- dynamically-built anchors: fix href/target at click time -------------- */
    try {
        var anchorFrom = function (e) {
            var n = e.target;
            return n && n.closest ? n.closest('a[href],area[href]') : null;
        };
        document.addEventListener('click', function (e) { fixAnchor(anchorFrom(e)); }, true);
        document.addEventListener('auxclick', function (e) { fixAnchor(anchorFrom(e)); }, true);
    } catch (e) {}
    /* --- WebSocket: route through the /ws tunnel (Bug 3) ------------------------ */
    try {
        var NativeWS = window.WebSocket;
        var WSProxy = function (url, protocols) {
            var r = wsRoute(url);
            if (r === url) return new NativeWS(url, protocols);
            return new NativeWS(r, protocols);
        };
        try { WSProxy.prototype = NativeWS.prototype; } catch (e2) {}
        try {
            WSProxy.CONNECTING = NativeWS.CONNECTING;
            WSProxy.OPEN = NativeWS.OPEN;
            WSProxy.CLOSING = NativeWS.CLOSING;
            WSProxy.CLOSED = NativeWS.CLOSED;
        } catch (e3) {}
        window.WebSocket = WSProxy;
    } catch (e) {}
    /* --- EventSource: route SSE through the proxy -------------------------------- */
    try {
        var NativeES = window.EventSource;
        if (NativeES) {
            var ESProxy = function (url, cfg) {
                var r = routeAny(typeof url === 'string' ? url : String(url));
                if (r === url) return new NativeES(url, cfg);
                return new NativeES(r, cfg);
            };
            try { ESProxy.prototype = NativeES.prototype; } catch (e2) {}
            try {
                ESProxy.CONNECTING = NativeES.CONNECTING;
                ESProxy.OPEN = NativeES.OPEN;
                ESProxy.CLOSED = NativeES.CLOSED;
            } catch (e3) {}
            window.EventSource = ESProxy;
        }
    } catch (e) {}
    /* --- block foreign SW registration on OUR origin ------------------------------ */
    try {
        if (navigator.serviceWorker && navigator.serviceWorker.register) {
            navigator.serviceWorker.register = function () {
                return Promise.reject(
                    new TypeError('ServiceWorker registration is disabled inside the proxy')
                );
            };
        }
    } catch (e) {}
})();
</script>`;

/* ============================================================================
 * 13. HOSTED TEST PAGE (GET /)
 * --------------------------------------------------------------------------
 * Simple HTML document with an iframe plus service-worker registration —
 * the spec's hosted entry point.
 * ==========================================================================*/

const INDEX_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ultraviolet Edge</title>
<style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    html, body { height: 100%; margin: 0; }
    body { font: 14px system-ui, -apple-system, sans-serif; background: #0b0e14; color: #e6e9ef; display: flex; flex-direction: column; }
    header { display: flex; gap: 8px; align-items: center; padding: 10px 12px; background: #10141d; border-bottom: 1px solid #232b3b; }
    header h1 { font-size: 14px; margin: 0 8px 0 0; color: #7dd3fc; white-space: nowrap; letter-spacing: .3px; }
    input { flex: 1; padding: 9px 12px; border-radius: 8px; border: 1px solid #2a3242; background: #0b0e14; color: #e6e9ef; font: inherit; outline: none; }
    input:focus { border-color: #38bdf8; }
    button { padding: 9px 14px; border-radius: 8px; border: 1px solid #2a3242; background: #1b2333; color: #e6e9ef; font: inherit; cursor: pointer; white-space: nowrap; }
    button:hover { background: #243044; }
    #status { font-size: 11px; padding: 3px 9px; border-radius: 999px; border: 1px solid #2a3242; color: #9aa4b2; white-space: nowrap; }
    #status.ok { color: #4ade80; border-color: #14532d; }
    #status.bad { color: #f87171; border-color: #7f1d1d; }
    main { flex: 1; position: relative; }
    iframe { position: absolute; inset: 0; width: 100%; height: 100%; border: 0; background: #fff; }
</style>
</head>
<body>
<header>
    <h1>ULTRAVIOLET&nbsp;EDGE</h1>
    <input id="urlbar" type="text" placeholder="https://example.com" spellcheck="false" autocomplete="off">
    <button id="go" title="Load in iframe">Go</button>
    <button id="win" title="Open the current proxied page in a new window">New&nbsp;window</button>
    <span id="status">booting…</span>
</header>
<main>
    <iframe id="frame" allow="fullscreen; autoplay; clipboard-write; encrypted-media" referrerpolicy="strict-origin-when-cross-origin"></iframe>
</main>
<script>
(function () {
    var P = ${JSON.stringify(PROXY_PATH + '?' + PARAM + '=')};
    var frame = document.getElementById('frame');
    var urlbar = document.getElementById('urlbar');
    var statusEl = document.getElementById('status');
    var current = null;

    function enc(u) {
        try {
            var bytes = new TextEncoder().encode(String(u));
            var s = '';
            for (var i = 0; i < bytes.length; i += 0x8000) {
                s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
            }
            return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
        } catch (e) { return null; }
    }

    function setStatus(text, cls) {
        statusEl.textContent = text;
        statusEl.className = cls || '';
    }

    function navigate() {
        var v = (urlbar.value || '').trim();
        if (!v) return;
        if (!/^[a-z][a-z0-9+.-]*:/i.test(v)) v = 'https://' + v;
        var u;
        try { u = new URL(v); } catch (e) { setStatus('invalid URL', 'bad'); return; }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            setStatus('http/https only', 'bad');
            return;
        }
        var e = enc(u.href);
        if (!e) { setStatus('encode failed', 'bad'); return; }
        current = P + e;
        frame.src = current;
        setStatus('loading ' + u.hostname + '…');
    }

    frame.addEventListener('load', function () {
        setStatus(current ? 'ready' : 'idle', 'ok');
    });

    document.getElementById('go').addEventListener('click', navigate);
    urlbar.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') navigate();
    });
    document.getElementById('win').addEventListener('click', function () {
        if (current) window.open(current, '_blank');
    });

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker
            .register('/sw.js', { scope: '/' })
            .then(function () {
                setStatus('service worker active', 'ok');
                urlbar.value = urlbar.value || 'https://example.com';
                navigate();
            })
            .catch(function (err) {
                setStatus('service worker failed', 'bad');
                urlbar.value = urlbar.value || 'https://example.com';
                navigate(); // proxy still works without the SW
            });
    } else {
        setStatus('no service worker', 'bad');
        urlbar.value = 'https://example.com';
        navigate();
    }
})();
</script>
</body>
</html>`;

/* ============================================================================
 * 14. TEST HOOKS (named export; ignored by wrangler, used by the test suite)
 * ==========================================================================*/

export const __internals = {
    // constants
    PROXY_PATH,
    PARAM,
    COOKIE_PREFIX,
    MAX_TUNNELS,
    STRIP_RESPONSE_HEADERS,
    STRIP_REQUEST_HEADERS,
    URL_ATTRS,
    SRCSET_ATTRS,
    DATA_URL_ATTRS,
    FORBIDDEN_ATTRS,
    // pure logic
    b64urlEncode,
    b64urlDecode,
    toProxyUrl,
    toProxyUrlPath,
    targetFromProxyUrl,
    mergeExtraParams,
    recoverStragglerTarget,
    redirectProxy,
    fnv1a,
    jarCookieName,
    splitSetCookieString,
    parseSetCookie,
    applySetCookies,
    readJar,
    buildJarCookie,
    serializeJar,
    rewriteCSS,
    rewriteSrcset,
    rewriteMetaRefresh,
    rewriteLocationHeader,
    buildOutgoingRequest,
    sanitizeResponseHeaders,
    isNavigationRequest,
    applyDispositionPolicy,
    // WebSocket tunnel machinery (pure parts)
    wsFetchUrl,
    buildWsHandshake,
    encodeWsFrame,
    tryParseFrame,
    WsStreamDecoder,
    findHeaderValue,
    collectSetCookieLines,
    concatBytes,
    __tunnelState,
    // embedded assets (syntax-checked by the test suite)
    SW_SCRIPT,
    BOOTSTRAP_SCRIPT,
    INDEX_HTML,
};
