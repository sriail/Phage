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
 *    GET  /proxy?url=<base64url(target)> -> the proxy endpoint (any method)
 *
 *  Free-plan budget: exactly ONE fetch() subrequest per proxied request,
 *  zero storage bindings, native streaming HTMLRewriter (low CPU), script
 *  size ~50KB of the 1MB limit.
 */

/* ============================================================================
 * 1. CONFIGURATION
 * ==========================================================================*/

/** Proxy endpoint path. */
const PROXY_PATH = '/proxy';
/** Query parameter carrying the base64url-encoded target URL. */
const PARAM = 'url';
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
 * Resolve `raw` against `base` and return a proxy URL, or null when the
 * value must be left untouched (fragments, data:/blob:/mailto:/javascript:,
 * non-HTTP(S) schemes, unresolvable, or URLs that already point at this
 * worker — the self-proxy guard that prevents rewrite loops).
 *
 * @param {string} raw    attribute/value as found in the document
 * @param {string} base   absolute base URL (target URL or captured <base>)
 * @param {string} [selfOrigin] this worker's origin, for the loop guard
 * @returns {string|null} e.g. "/proxy?url=aHR0cHM6Ly9leGFtcGxlLmNvbS8"
 */
function toProxyUrl(raw, base, selfOrigin) {
    let str;
    try {
        str = String(raw).trim();
    } catch {
        return null;
    }
    if (!str || SKIP_URL.test(str)) return null;
    // Idempotency guard: values that are already proxy URLs (or would
    // resolve to this worker's proxy route) must never be re-encoded —
    // without this, @import url(...) is double-encoded by the CSS rewriter
    // and re-proxied pages would nest encodings.
    if (str.startsWith(PROXY_PATH + '?')) return null;
    let abs;
    try {
        abs = new URL(str, base);
    } catch {
        return null;
    }
    if (!ALLOWED_PROTOCOLS.has(abs.protocol)) return null;
    if (selfOrigin && abs.origin === selfOrigin) return null; // loop guard
    try {
        return PROXY_PATH + '?' + PARAM + '=' + b64urlEncode(abs.href);
    } catch {
        return null;
    }
}

/**
 * Extract the encoded target from a proxy URL string/URL, or null.
 * Used to rebuild upstream Referer values and by the service worker.
 * @param {string|URL} proxyUrl
 * @returns {string|null} absolute target URL
 */
function targetFromProxyUrl(proxyUrl) {
    try {
        const u = typeof proxyUrl === 'string' ? new URL(proxyUrl) : proxyUrl;
        if (u.pathname !== PROXY_PATH) return null;
        const v = u.searchParams.get(PARAM);
        if (!v) return null;
        return b64urlDecode(v);
    } catch {
        return null;
    }
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

const FORBIDDEN_ATTRS = ['integrity', 'crossorigin', 'nonce', 'sandbox'];

/**
 * Per-response rewrite context threaded through all HTMLRewriter handlers.
 * `base` starts as the target URL and is replaced by any <base href> seen
 * first (document order guarantees base is usually in <head>).
 */
function makeRewriteCtx(baseHref, selfOrigin) {
    return { base: baseHref, selfOrigin, injected: false, styleBuf: '' };
}

/**
 * Element handler for '*' — URL/srcset/style-attribute rewriting plus
 * forbidden-attribute stripping (SRI removal is a spec requirement).
 */
function urlAttrsHandler(ctx) {
    return {
        element(el) {
            try {
                const tag = el.tagName;

                // SRI + friends (spec: strip integrity hashes)
                for (const bad of FORBIDDEN_ATTRS) {
                    if (el.hasAttribute(bad)) el.removeAttribute(bad);
                }

                // <base> is handled by its own handler (capture + remove)
                if (tag !== 'base') {
                    for (const name of URL_ATTRS) {
                        if (!el.hasAttribute(name)) continue;
                        if (name === 'data' && tag !== 'object') continue;
                        const val = el.getAttribute(name);
                        if (val == null || val === '') continue;
                        const proxied = toProxyUrl(val, ctx.base, ctx.selfOrigin);
                        if (proxied) el.setAttribute(name, proxied);
                    }
                    for (const name of SRCSET_ATTRS) {
                        if (!el.hasAttribute(name)) continue;
                        const val = el.getAttribute(name);
                        if (val == null || val === '') continue;
                        el.setAttribute(name, rewriteSrcset(val, ctx.base));
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
 * one would misresolve them).
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
                    el.remove();
                }
                // <base target="..."> without href stays — it only sets the
                // default link target, which does not break resolution.
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
 * Bootstrap injector — prepends the fetch/XHR/window.open/history hook
 * script into <head> (or <body> as fallback).
 */
function injectHandler(ctx) {
    return {
        element(el) {
            try {
                if (ctx.injected) return;
                ctx.injected = true;
                el.prepend(BOOTSTRAP_SCRIPT, { html: true });
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
 * Handle /proxy?url=<base64url target> — decode, fetch, sanitize, rewrite.
 * Exactly one upstream subrequest per invocation.
 */
async function handleProxy(request) {
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
    if (!ALLOWED_PROTOCOLS.has(targetUrl.protocol)) {
        return errorResponse(400, 'Only http and https targets are supported');
    }

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
            .on('style', styleHandler(ctx))
            .on('head', injectHandler(ctx))
            .on('body', injectHandler(ctx))
            .on('*', urlAttrsHandler(ctx))
            .transform(new Response(upstream.body, { status: upstream.status, headers }));
        return transformed;
    }

    // --- CSS: buffered regex rewrite (url()/@import must not be split) -----
    if ((contentType || '').toLowerCase().includes('text/css')) {
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

    // --- everything else: pure streaming passthrough ------------------------
    // Images, video, fonts, JSON... the browser pools these connections
    // natively (spec) and the rewriter would only add latency.
    return new Response(upstream.body, { status: upstream.status, headers });
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
 */
export default {
    async fetch(request) {
        try {
            const url = new URL(request.url);
            switch (url.pathname) {
                case '/':
                    if (request.method !== 'GET' && request.method !== 'HEAD') {
                        return errorResponse(405, 'Method not allowed');
                    }
                    return serveIndex(request.method === 'HEAD');
                case '/sw.js':
                    if (request.method !== 'GET' && request.method !== 'HEAD') {
                        return errorResponse(405, 'Method not allowed');
                    }
                    return serveServiceWorker(request.method === 'HEAD');
                case '/favicon.ico':
                    return new Response(null, { status: 204 });
                case PROXY_PATH:
                    return handleProxy(request);
                default:
                    return errorResponse(404, 'Not found. Use /proxy?' + PARAM + '=<base64url target>');
            }
        } catch (err) {
            return errorResponse(500, 'Worker error: ' + (err && err.message ? err.message : String(err)));
        }
    },
};

/* ============================================================================
 * 11. SERVICE WORKER (served at /sw.js, scope "/")
 * --------------------------------------------------------------------------
 * Port of Ultraviolet's routing layer (src/sw.js + src/uv.sw.js) reduced to
 * the two jobs that still belong on the client when HTML/CSS rewriting
 * happens at the edge:
 *
 *   1. Route proxy traffic: let /proxy requests through to the worker.
 *   2. Resolve "stragglers": same-origin requests for paths the server-side
 *      rewriter never saw (relative URLs built at runtime by JS, unrewritten
 *      srcset candidates, etc.). The target is recovered either from the
 *      request's referrer (a proxy URL) or from a clientId -> target map
 *      kept for every proxied navigation, then re-encoded and fetched
 *      through the proxy.
 * ==========================================================================*/

const SW_SCRIPT = `'use strict';
/*
 * ULTRAVIOLET EDGE — Service Worker
 * Routing layer ported from Ultraviolet's uv.sw.js / sw.js.
 */

var PROXY_PATH = ${JSON.stringify(PROXY_PATH)};
var PARAM = ${JSON.stringify(PARAM)};

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
    return u.origin === location.origin && u.pathname === PROXY_PATH;
}

function targetOf(u) {
    if (!isProxyUrl(u)) return null;
    var v = u.searchParams.get(PARAM);
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

    /* Proxy traffic and worker assets: pass through to the edge worker. */
    if (url.pathname === PROXY_PATH) {
        if (req.mode === 'navigate') {
            var t = targetOf(url);
            if (t && event.resultingClientId) docBases.set(event.resultingClientId, t);
        }
        return; // handled by the worker
    }
    if (url.pathname === '/' || url.pathname === '/sw.js' || url.pathname === '/favicon.ico') {
        return; // worker assets
    }

    /*
     * Straggler: a same-origin path that is neither a proxy URL nor a worker
     * asset. This is how runtime-built relative URLs (location.href='next',
     * fetch('/api/x'), unrewritten srcset entries, ...) reach the proxy.
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
    if (!base) return; // no context: let it 404 naturally

    /*
     * respondWith must be called synchronously, but the work inside may be
     * async: request bodies are buffered (rather than passed through as
     * streams) because fetch() with a ReadableStream body requires the
     * duplex:'half' option, which not every browser implements.
     */
    event.respondWith((async function () {
        try {
            var abs = new URL(url.pathname + url.search, base).href;
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
 * The edge rewriter cannot see URLs constructed at runtime inside scripts.
 * This tiny shim re-routes the absolute-URL producers (fetch, XHR,
 * sendBeacon, window.open, pushState/replaceState, form.submit) through the
 * proxy. Relative URLs need no hook: they hit the service worker, which
 * resolves them against the document's referrer.
 * ==========================================================================*/

const BOOTSTRAP_SCRIPT = `<script>
(function () {
    if (window.__uvedge) return;
    window.__uvedge = 1;
    var ORIGIN = location.origin;
    var P = ${JSON.stringify(PROXY_PATH + '?' + PARAM + '=')};
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
    function route(u) {
        if (typeof u !== 'string' || !u) return u;
        if (!/^https?:/i.test(u)) return u;
        if (u.indexOf(ORIGIN + '/') === 0) return u;
        var e = enc(u);
        return e ? ORIGIN + P + e : u;
    }
    try {
        var of = window.fetch;
        window.fetch = function (input, init) {
            var url = null;
            try {
                if (typeof input === 'string') url = input;
                else if (input && typeof input.url === 'string') url = input.url;
            } catch (e) {}
            if (!url) return of.call(window, input, init);
            var r = route(url);
            if (r === url) return of.call(window, input, init);
            if (typeof input === 'string') return of.call(window, r, init);
            /*
             * Request object with an absolute URL: rebuild it against the
             * proxy. Body-bearing requests are buffered first — passing a
             * stream body through Request-as-init needs duplex:'half',
             * which is not universally supported.
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
    try {
        var oo = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (m, u) {
            arguments[1] = route(u);
            return oo.apply(this, arguments);
        };
    } catch (e) {}
    try {
        if (navigator.sendBeacon) {
            var ob = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function (u, d) { return ob(route(String(u)), d); };
        }
    } catch (e) {}
    try {
        var ow = window.open;
        window.open = function (u, n, f) { return ow.call(window, route(u), n, f); };
    } catch (e) {}
    try {
        var hp = history.pushState, hr = history.replaceState;
        history.pushState = function (s, t, u) { return hp.call(history, s, t, route(u)); };
        history.replaceState = function (s, t, u) { return hr.call(history, s, t, route(u)); };
    } catch (e) {}
    try {
        var fs = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function () {
            try {
                var a = this.getAttribute('action');
                if (a) this.setAttribute('action', route(a));
            } catch (e) {}
            return fs.apply(this, arguments);
        };
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
    STRIP_RESPONSE_HEADERS,
    STRIP_REQUEST_HEADERS,
    URL_ATTRS,
    SRCSET_ATTRS,
    FORBIDDEN_ATTRS,
    // pure logic
    b64urlEncode,
    b64urlDecode,
    toProxyUrl,
    targetFromProxyUrl,
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
    // embedded assets (syntax-checked by the test suite)
    SW_SCRIPT,
    BOOTSTRAP_SCRIPT,
    INDEX_HTML,
};
