/**
 * EdgeFrame — a stateless, iframe-friendly web proxy that runs entirely at the
 * Cloudflare edge.
 *
 * Architecture (single file, zero external dependencies):
 *   GET  /                     -> shell HTML (address bar + iframe + SW registration)
 *   GET  /sw.js                -> service worker (fallback router for missed rewrites)
 *   GET  /favicon.ico          -> 204 (keeps the shell quiet)
 *   *   /proxy?u=<base64url>   -> proxy endpoint, query-parameter form (navigation)
 *   *   /p/<base64url>[?query] -> proxy endpoint, path form (form submissions; the
 *                                 query string is merged onto the target so GET
 *                                 forms survive the browser's query replacement)
 *
 * Behaviour:
 *   - The target URL is decoded inside the edge runtime and fetched natively;
 *     there is no origin server and no secondary network hop.
 *   - Restrictive framing/isolation headers (X-Frame-Options, CSP, COOP, COEP,
 *     CORP, Clear-Site-Data, Permissions-Policy) are dropped so the content
 *     renders inside an iframe and opened windows keep normal semantics.
 *   - HTML is piped through the native HTMLRewriter: hyperlinks, stylesheets,
 *     scripts, images, media, iframes, forms, meta-refresh and inline CSS are
 *     rewritten back to this worker with newly encoded parameters.
 *   - Subresource Integrity attributes are stripped from <link>/<script> so
 *     transformed resources never fail their (now meaningless) hash checks.
 *   - Non-HTML assets (images, video, fonts, JSON, ...) bypass the rewriter
 *     and stream straight through, letting the browser use its own native
 *     connection pooling for sub-resources.
 *   - Upstream requests are rebuilt from an allow-list of genuine browser
 *     headers (Chrome UA + client hints + the client's real Accept family);
 *     every Cloudflare-injected header (cf-*, x-forwarded-*, true-client-ip,
 *     cdn-loop, ...) is absent by construction.
 *   - A per-origin cookie jar is persisted in the CLIENT's cookie store using
 *     encoded names (p_<base64url(origin|name)>), so sessions and logins work
 *     without any server-side state.
 *
 * Entry point: `export default { fetch }` (valid module Worker).
 */

/* eslint-disable */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION = '1.0.0';

const ROUTES = {
  SHELL: '/',
  SW: '/sw.js',
  PROXY: '/proxy',
  PROXY_PATH: '/p/',
  FAVICON: '/favicon.ico',
};

const PARAM = 'u';
const MAX_TARGET_URL = 4096;
const MAX_REDIRECTS = 10;
const MAX_BODY_BYTES = 25 * 1024 * 1024;

// A real, current Chrome on Windows 10/11 — kept consistent with the
// sec-ch-ua client hints below so the fingerprint is internally coherent.
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const CLIENT_HINTS = {
  'sec-ch-ua': '"Chromium";v="131", "Not_A Brand";v="24"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
};

// Request headers we are willing to forward upstream. This is an ALLOWLIST:
// everything else (including every cf-* / x-forwarded-* / true-client-ip /
// cdn-loop header Cloudflare attaches to the inbound request) is never copied,
// so it is stripped by construction rather than by fragile blocklisting.
const FORWARD_REQUEST_HEADERS = [
  'accept',
  'range',
  'if-range',
  'if-none-match',
  'if-modified-since',
  'authorization', // lets HTTP Basic auth flows pass through the proxy
  'upgrade-insecure-requests',
  'save-data',
  'dnt',
  'sec-gpc',
  'sec-purpose',
  'sec-fetch-dest',
  'sec-fetch-mode', // runtime-stamped to "cors" by workerd; kept for forward-compat
  'sec-fetch-site',
  'sec-fetch-user',
];

// Response headers kept from the upstream. Everything else — CSP, XFO, COOP,
// COEP, CORP, Clear-Site-Data, Permissions-Policy, alt-svc (which could
// hijack the browser's connection routing for our origin!), report-to, nel,
// server, via, cf-*, content-encoding/length (rewritten bodies) — is dropped
// by the allowlist copy in finalize().
const KEEP_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'content-language',
  'etag',
  'last-modified',
  'expires',
  'accept-ranges',
  'content-range',
  'retry-after',
  'www-authenticate',
  'x-content-type-options',
];

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

// URL schemes that must never be routed through the proxy.
const NON_PROXY_SCHEME =
  /^(data|blob|javascript|mailto|tel|about|sms|ftp|ftps|magnet|ws|wss|intent|market|itms|itms-apps|itms-services|chrome|chrome-extension|moz-extension|file|indexeddb|webcal|feed|viber|whatsapp):/i;

const COOKIE_PREFIX = 'p_';

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function textResp(message, status) {
  return new Response(message + '\n', {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

/** UTF-8 safe, chunked base64url encode (spread limits are respected). */
function b64urlEncode(str) {
  const bytes = ENC.encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url decode; throws on invalid input (caller catches). */
function b64urlDecode(s) {
  if (typeof s !== 'string' || !s) return '';
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const binary = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return DEC.decode(bytes);
}

// ---------------------------------------------------------------------------
// URL -> proxy-URL conversion
// ---------------------------------------------------------------------------

/**
 * Convert a raw reference found in a document into a proxy URL.
 * Returns null when the value must be left untouched (fragments, javascript:,
 * mailto:, data:, already-relative-only anchors, unparseable values...).
 *
 * The fragment is deliberately kept OUTSIDE the encoded parameter so the
 * browser performs an in-document anchor scroll instead of reloading.
 */
function toProxyUrl(raw, base, opts) {
  if (raw == null) return null;
  const value = String(raw).trim();
  if (!value || value.startsWith('#')) return null;
  if (NON_PROXY_SCHEME.test(value)) return null;
  let abs;
  try {
    abs = new URL(value, base);
  } catch (e) {
    return null;
  }
  if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return null;
  if (abs.href.length > MAX_TARGET_URL) return null;
  const hash = abs.hash;
  if (hash) abs.hash = '';
  const encoded = b64urlEncode(abs.href);
  if (opts && opts.pathForm) return ROUTES.PROXY_PATH + encoded;
  return ROUTES.PROXY + '?' + PARAM + '=' + encoded + hash;
}

/** Extract the encoded target from one of our own proxy URLs (or null). */
function encodedTargetFromUrl(u) {
  if (!u) return null;
  try {
    if (u.pathname === ROUTES.PROXY) return u.searchParams.get(PARAM);
    if (u.pathname.startsWith(ROUTES.PROXY_PATH)) {
      return u.pathname.slice(ROUTES.PROXY_PATH.length) || null;
    }
  } catch (e) {
    /* fallthrough */
  }
  return null;
}

/**
 * Per-response proxifier with memoization. Real documents repeat references
 * (preload + stylesheet pairs, thumbnails, sprites), so the URL-parse and
 * base64-encode cost is paid once per unique value instead of once per
 * occurrence.
 */
function makeProxifier(base) {
  const cache = new Map();
  return function proxify(raw, opts) {
    const key = (opts && opts.pathForm ? 'p|' : 'q|') + raw;
    if (cache.has(key)) return cache.get(key);
    const value = toProxyUrl(raw, base, opts);
    cache.set(key, value);
    return value;
  };
}

/**
 * Rebuild a realistic Referer for the upstream request. The client's referer
 * is one of OUR proxy URLs; decoding it yields the target page URL a native
 * browser would have sent for an in-site navigation.
 */
function buildReferer(request) {
  const ref = request.headers.get('referer');
  if (!ref) return null;
  try {
    const r = new URL(ref);
    if (r.origin !== new URL(request.url).origin) return null;
    const encoded = encodedTargetFromUrl(r);
    if (!encoded) return null;
    return new URL(b64urlDecode(encoded)).href;
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// CSS rewriting
// ---------------------------------------------------------------------------

const CSS_URL_RE = /url\(\s*(['"]?)([^'")]+?)\1\s*\)/gi;
const CSS_IMPORT_RE = /@import\s+(['"])([^'"]+)\1/gi;

/** Rewrite every url(...) and @import "..." inside a CSS fragment. */
function rewriteCss(css, proxify) {
  if (css == null) return css;
  let out = css.replace(CSS_URL_RE, (full, quote, url) => {
    const proxied = proxify(url);
    return proxied !== null ? 'url(' + proxied + ')' : full;
  });
  out = out.replace(CSS_IMPORT_RE, (full, quote, url) => {
    const proxied = proxify(url);
    return proxied !== null ? '@import ' + quote + proxied + quote : full;
  });
  return out;
}

/** Rewrite a srcset attribute value (comma separated URL [descriptor] list). */
function rewriteSrcsetValue(value, proxify) {
  const parts = value.split(',');
  const out = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const trimmed = part.trim();
    if (!trimmed) {
      out.push(part);
      continue;
    }
    const sp = trimmed.search(/\s/);
    const url = sp === -1 ? trimmed : trimmed.slice(0, sp);
    const descriptor = sp === -1 ? '' : trimmed.slice(sp);
    const proxied = proxify(url);
    if (proxied !== null) out.push(proxied + descriptor);
    else out.push(part);
  }
  return out.join(', ');
}

/**
 * Find the index of an unterminated url( token in a CSS fragment, or -1.
 * Used by the <style> text handler to hold back a partial token that may be
 * completed by the next text chunk (HTMLRewriter splits text arbitrarily).
 */
function findUnclosedCssUrl(s) {
  const re = /url\(/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    let i = m.index + 4;
    let quote = null;
    while (i < s.length && (s[i] === ' ' || s[i] === '\t' || s[i] === '\n' || s[i] === '\r')) i++;
    if (i < s.length && (s[i] === "'" || s[i] === '"')) {
      quote = s[i];
      i++;
    }
    let closed = false;
    for (; i < s.length; i++) {
      if (quote) {
        if (s[i] === quote) quote = null;
      } else if (s[i] === ')') {
        closed = true;
        break;
      }
    }
    if (!closed) return m.index;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Cookie jar (client-side storage, per-origin scoping)
// ---------------------------------------------------------------------------

/** Parse one Set-Cookie header value into { name, value, attrs }. */
function parseSetCookie(raw) {
  if (typeof raw !== 'string' || !raw) return null;
  const firstSemi = raw.indexOf(';');
  const head = firstSemi === -1 ? raw : raw.slice(0, firstSemi);
  const rest = firstSemi === -1 ? '' : raw.slice(firstSemi + 1);
  const eq = head.indexOf('=');
  const name = eq === -1 ? head.trim() : head.slice(0, eq).trim();
  const value = eq === -1 ? '' : head.slice(eq + 1).trim();
  if (!name) return null;
  const attrs = {};
  for (const part of rest.split(';')) {
    if (!part.trim()) continue;
    const pe = part.indexOf('=');
    const key = (pe === -1 ? part : part.slice(0, pe)).trim().toLowerCase();
    const val = pe === -1 ? '' : part.slice(pe + 1).trim();
    attrs[key] = val;
  }
  return { name, value, attrs };
}

/**
 * Convert an upstream Set-Cookie into a cookie the BROWSER stores for our
 * worker origin, with an encoded name that embeds the target origin so the
 * jar can be re-scoped on later requests. SameSite is deliberately omitted
 * (every proxied request is same-origin from the browser's perspective, so
 * the default Lax policy still attaches) and Secure is omitted so local
 * http://localhost development works; production is HTTPS regardless.
 */
function transformSetCookie(parsed, origin) {
  const a = parsed.attrs;
  let out = COOKIE_PREFIX + b64urlEncode(origin + '|' + parsed.name) + '=' + b64urlEncode(parsed.value || '') + '; Path=/';
  if (a['max-age'] && /^\d+$/.test(a['max-age'])) out += '; Max-Age=' + a['max-age'];
  if (a.expires) out += '; Expires=' + a.expires;
  if ('httponly' in a) out += '; HttpOnly';
  return out;
}

/**
 * Collect the raw Set-Cookie header values from a response across runtimes:
 * standard getSetCookie() first, then the workerd getAll() extension, then a
 * lossy comma-split fallback (Expires dates contain commas, hence the guard).
 */
function getSetCookieList(headers) {
  try {
    if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  } catch (e) {
    /* fallthrough */
  }
  try {
    if (typeof headers.getAll === 'function') return headers.getAll('set-cookie');
  } catch (e) {
    /* fallthrough */
  }
  const joined = headers.get('set-cookie');
  if (!joined) return [];
  return joined.split(/,\s*(?=[^;,=\s]+=[^;]*)/g).filter(Boolean);
}

/**
 * A per-response cookie jar. Seeds from the client's cookie header (decoded
 * p_* cookies), absorbs Set-Cookie values during the redirect loop, and
 * produces both the upstream Cookie header per hop and the transformed
 * Set-Cookie list to re-apply on the final response.
 */
class CookieJar {
  constructor(request) {
    this.cookies = new Map(); // `${origin}|${name}` -> value
    this.clientCookies = []; // transformed Set-Cookie strings for the browser
    const raw = request.headers.get('cookie');
    if (raw) {
      for (const pair of raw.split(';')) {
        const eq = pair.indexOf('=');
        if (eq < 1) continue;
        const name = pair.slice(0, eq).trim();
        if (!name.startsWith(COOKIE_PREFIX)) continue;
        const value = pair.slice(eq + 1).trim();
        try {
          const decoded = b64urlDecode(name.slice(COOKIE_PREFIX.length));
          const bar = decoded.indexOf('|');
          if (bar < 1) continue;
          const origin = decoded.slice(0, bar);
          const origName = decoded.slice(bar + 1);
          if (!origName) continue;
          this.cookies.set(origin + '|' + origName, b64urlDecode(value));
        } catch (e) {
          /* malformed jar entry — ignore */
        }
      }
    }
  }

  /** Compose the upstream Cookie header for a given target origin. */
  header(origin) {
    const prefix = origin + '|';
    const parts = [];
    for (const entry of this.cookies) {
      if (entry[0].startsWith(prefix)) parts.push(entry[0].slice(prefix.length) + '=' + entry[1]);
    }
    return parts.join('; ');
  }

  /** Absorb Set-Cookie headers from one hop of the upstream exchange. */
  absorb(response, origin) {
    for (const raw of getSetCookieList(response.headers)) {
      const parsed = parseSetCookie(raw);
      if (!parsed) continue;
      this.cookies.set(origin + '|' + parsed.name, parsed.value);
      this.clientCookies.push(transformSetCookie(parsed, origin));
    }
  }
}

// ---------------------------------------------------------------------------
// Upstream request headers — "real browser headers, nothing of Cloudflare's"
// ---------------------------------------------------------------------------

const ACCEPT_BY_DEST = {
  document: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
  style: 'text/css,*/*;q=0.1',
  script: '*/*',
  image: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
  font: '*/*',
  video: '*/*',
  audio: '*/*',
};

function defaultAcceptFor(request) {
  const dest = (request.headers.get('sec-fetch-dest') || 'document').toLowerCase();
  return ACCEPT_BY_DEST[dest] || '*/*';
}

/**
 * Build a fresh, coherent Chrome header set for the upstream fetch.
 * Because the request is constructed from scratch, no Cloudflare-injected
 * header can ever reach the target origin.
 */
function buildUpstreamHeaders(request) {
  const h = new Headers();
  h.set('user-agent', USER_AGENT);
  for (const key of Object.keys(CLIENT_HINTS)) h.set(key, CLIENT_HINTS[key]);

  // Forward the client's genuine per-context headers when present.
  // NOTE: workerd stamps "Sec-Fetch-Mode: cors" on every outbound subrequest
  // and overrides whatever we set here; dest/site/user do pass through.
  for (const name of FORWARD_REQUEST_HEADERS) {
    const v = request.headers.get(name);
    if (v != null) h.set(name, v);
  }
  // A real browser never sends "Accept-Language: *"; treat the wildcard the
  // runtime injects for headerless subresource fetches as "unset".
  const al = request.headers.get('accept-language');
  if (al && al.trim() && al.trim() !== '*') h.set('accept-language', al.trim());
  if (!h.has('accept-language')) h.set('accept-language', 'en-US,en;q=0.9');
  if (!h.has('accept')) h.set('accept', defaultAcceptFor(request));

  // Synthesize a coherent Sec-Fetch family when the client omitted it.
  const dest = (request.headers.get('sec-fetch-dest') || '').toLowerCase();
  const referer = buildReferer(request);
  if (!h.has('sec-fetch-dest')) h.set('sec-fetch-dest', 'document');
  if (!h.has('sec-fetch-mode')) h.set('sec-fetch-mode', dest && dest !== 'document' ? 'no-cors' : 'navigate');
  if (!h.has('sec-fetch-site')) h.set('sec-fetch-site', dest && dest !== 'document' ? 'same-origin' : referer ? 'same-origin' : 'none');

  if (referer) h.set('referer', referer);
  h.set('accept-encoding', 'gzip, deflate, br');
  return h;
}

// ---------------------------------------------------------------------------
// SSRF guards
// ---------------------------------------------------------------------------

/** True when the host is private, reserved, loopback or otherwise unroutable. */
function isPrivateHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h === '::1' || h === '0.0.0.0' || h === '::' || h === 'unknown') return true;
  // IPv4 evasion forms: bare-integer (2130706433 = 127.0.0.1), hex (0x7f...),
  // and octal (0177.0.0.1) notations all resolve to private space in resolvers
  // that still accept them — reject anything that is not a strict dotted quad.
  if (/^(0x[0-9a-f]+|[0-9]+)$/i.test(h)) return true; // integer / hex forms
  if (/^[0-9.]+$/.test(h)) {
    const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!v4) return true; // e.g. "0177.0.0.1" or "127.0.0.1." style oddities
    const a = +v4[1];
    const b = +v4[2];
    if (+v4[3] > 255 || +v4[4] > 255) return true; // weird octets
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a > 255 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) || // link-local incl. cloud metadata
      a >= 224 // multicast + reserved
    );
  }
  if (h.includes(':')) {
    // IPv6 — reject unspecified, loopback, unique-local (fc00::/7) and link-local (fe80::/10)
    const first = parseInt((h.match(/^([0-9a-f]{1,4})/) || [])[1] || '0', 16);
    if (!isNaN(first)) {
      return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || first === 0;
    }
    return true;
  }
  return false;
}

/** Allow-list override used only by the local test harness (see wrangler.toml). */
function privateAllowed(env, host) {
  const v = env && env.ALLOW_PRIVATE;
  if (!v) return false;
  const s = String(v);
  if (s === '*' || s === '1' || s === 'true') return true;
  const list = s.toLowerCase().split(',').map((x) => x.trim());
  return list.includes(String(host).toLowerCase());
}

function isPubliclyRoutable(env, host) {
  if (!isPrivateHost(host)) return true;
  return privateAllowed(env, host);
}

// ---------------------------------------------------------------------------
// HTMLRewriter pipeline (single pass over the stream)
// ---------------------------------------------------------------------------

/** Handler for <style> element text: chunk-safe CSS rewriting with carry. */
function cssStyleHandler(proxify) {
  let carry = '';
  return {
    element() {
      carry = '';
    },
    text(chunk) {
      let s = carry + chunk.text;
      carry = '';
      let emit = s;
      let keep = '';
      const hold = findUnclosedCssUrl(s);
      if (hold !== -1 && !chunk.lastInTextNode) {
        emit = s.slice(0, hold);
        keep = s.slice(hold);
      }
      if (emit) {
        // html:true inserts verbatim — CSS must never be HTML-escaped.
        chunk.replace(rewriteCss(emit, proxify), { html: true });
      }
      carry = keep;
    },
  };
}

/**
 * Build the HTMLRewriter for one document. `base` is the FINAL upstream URL
 * (after redirects), so relative references resolve exactly like they would
 * in a native browser.
 */
function buildRewriter(base) {
  const rewriter = new HTMLRewriter();
  const proxify = makeProxifier(base);

  const rewriteAttr = (el, attr, opts) => {
    let raw = null;
    try {
      raw = el.getAttribute(attr);
    } catch (e) {
      return;
    }
    if (raw == null) return;
    const proxied = proxify(raw, opts);
    if (proxied !== null) el.setAttribute(attr, proxied);
  };

  const rewriteSrcset = (el, attr) => {
    let raw = null;
    try {
      raw = el.getAttribute(attr);
    } catch (e) {
      return;
    }
    if (raw == null || !raw.trim()) return;
    const next = rewriteSrcsetValue(raw, proxify);
    if (next !== raw) el.setAttribute(attr, next);
  };

  rewriter
    .on('a', {
      element(el) {
        rewriteAttr(el, 'href');
        // Breakouts become new windows instead of replacing the shell.
        const t = el.getAttribute('target');
        if (t) {
          const tl = t.toLowerCase();
          if (tl === '_top' || tl === '_parent') el.setAttribute('target', '_blank');
        }
      },
    })
    .on('link', {
      element(el) {
        el.removeAttribute('integrity'); // never let a hash check fail
        const rel = (el.getAttribute('rel') || '').toLowerCase();
        if (/(^|\s)(preconnect|dns-prefetch)(\s|$)/.test(rel)) {
          el.remove(); // pointless through a proxy
          return;
        }
        rewriteAttr(el, 'href');
        rewriteSrcset(el, 'imagesrcset');
      },
    })
    .on('script', {
      element(el) {
        el.removeAttribute('integrity'); // never let a hash check fail
        rewriteAttr(el, 'src');
      },
    })
    .on('img', {
      element(el) {
        rewriteAttr(el, 'src');
        rewriteAttr(el, 'data-src'); // lazy-loading
        rewriteSrcset(el, 'srcset');
        rewriteSrcset(el, 'data-srcset');
      },
    })
    .on('source', {
      element(el) {
        rewriteAttr(el, 'src');
        rewriteSrcset(el, 'srcset');
      },
    })
    .on('video', {
      element(el) {
        rewriteAttr(el, 'src');
        rewriteAttr(el, 'poster');
      },
    })
    .on('audio', {
      element(el) {
        rewriteAttr(el, 'src');
      },
    })
    .on('track', {
      element(el) {
        rewriteAttr(el, 'src');
      },
    })
    .on('embed', {
      element(el) {
        rewriteAttr(el, 'src');
      },
    })
    .on('object', {
      element(el) {
        rewriteAttr(el, 'data');
      },
    })
    .on('iframe', {
      element(el) {
        rewriteAttr(el, 'src'); // nested frames route through the same proxy
      },
    })
    .on('use', {
      element(el) {
        rewriteAttr(el, 'href'); // SVG2
        rewriteAttr(el, 'xlink:href'); // SVG 1.1
      },
    })
    .on('image', {
      element(el) {
        rewriteAttr(el, 'href');
        rewriteAttr(el, 'xlink:href');
      },
    })
    .on('input', {
      element(el) {
        if ((el.getAttribute('type') || '').toLowerCase() === 'image') rewriteAttr(el, 'src');
      },
    })
    .on('form', {
      element(el) {
        try {
          const method = (el.getAttribute('method') || 'GET').toLowerCase();
          const action = el.getAttribute('action');
          // Missing/empty action resolves to the current page URL, like a browser.
          const actionUrl = new URL(action == null ? '' : action.trim(), base);
          actionUrl.hash = '';
          // GET forms make the browser REPLACE the query string, so the target
          // query is dropped here and re-merged from the submitted fields.
          if (method === 'get') actionUrl.search = '';
          el.setAttribute('action', ROUTES.PROXY_PATH + b64urlEncode(actionUrl.href));
        } catch (e) {
          /* leave the form untouched */
        }
      },
    })
    .on('base', {
      // We resolve every reference against the true final URL server-side;
      // a <base> tag would fight that and break the SW fallback router.
      element(el) {
        el.remove();
      },
    })
    .on('meta', {
      element(el) {
        const he = (el.getAttribute('http-equiv') || '').toLowerCase();
        if (he === 'refresh') {
          const content = el.getAttribute('content') || '';
          const m = content.match(/^\s*(\d+)\s*[;,]?\s*(?:url\s*=\s*)?([\s\S]*)$/i);
          if (m) {
            let target = (m[2] || '').trim();
            let quote = '';
            if (
              (target.length > 1 && target.startsWith("'") && target.endsWith("'")) ||
              (target.length > 1 && target.startsWith('"') && target.endsWith('"'))
            ) {
              quote = target[0];
              target = target.slice(1, -1);
            }
            const proxied = target ? proxify(target) : null;
            if (proxied) el.setAttribute('content', m[1] + '; url=' + quote + proxied + quote);
          }
        } else if (he === 'content-type') {
          // HTMLRewriter emits UTF-8; keep the declaration consistent.
          el.setAttribute('content', 'text/html; charset=utf-8');
        }
        if (el.hasAttribute('charset')) el.setAttribute('charset', 'utf-8');
      },
    })
    .on('[style]', {
      element(el) {
        const style = el.getAttribute('style');
        // CSS keywords are case-insensitive: URL("x") is just as valid.
        if (style == null || style.toLowerCase().indexOf('url(') === -1) return;
        const next = rewriteCss(style, proxify);
        if (next !== style) el.setAttribute('style', next);
      },
    })
    .on('[background]', {
      element(el) {
        rewriteAttr(el, 'background');
      },
    })
    .on('style', cssStyleHandler(proxify));

  return rewriter;
}

// ---------------------------------------------------------------------------
// Response finalization
// ---------------------------------------------------------------------------

/**
 * Sanitize headers, apply the cookie jar and route the body through the right
 * path: HTMLRewriter for HTML, buffered regex rewrite for CSS, and a
 * zero-copy stream for everything else.
 */
async function finalize(res, finalUrl, jar) {
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  const isHtml = ct.includes('text/html') || ct.includes('application/xhtml');
  const isCss = !isHtml && ct.includes('text/css');

  // Allowlisted copy of upstream headers (mutable by construction).
  const out = new Headers();
  for (const name of KEEP_RESPONSE_HEADERS) {
    const v = res.headers.get(name);
    if (v != null) out.set(name, v);
  }
  out.set('x-ef-target', finalUrl.href);

  const hasCookies = jar.clientCookies.length > 0;
  for (const c of jar.clientCookies) out.append('set-cookie', c);

  // Never let a shared edge/browser cache serve personalized bytes.
  if (hasCookies || isHtml) {
    out.set('cache-control', 'private, no-store');
    out.delete('expires');
  } else if (!out.has('cache-control')) {
    out.set('cache-control', 'public, max-age=300');
  }

  let body = res.body;
  if (NULL_BODY_STATUSES.has(res.status) || body == null) body = null;

  if (isHtml) {
    out.set('content-type', ct.includes('application/xhtml') ? 'application/xhtml+xml; charset=utf-8' : 'text/html; charset=utf-8');
    const base = new Response(body, { status: res.status, headers: out });
    return buildRewriter(finalUrl).transform(base);
  }
  if (isCss) {
    const css = await res.text(); // CSS is small; buffering keeps url() integrity
    return new Response(rewriteCss(css, makeProxifier(finalUrl)), { status: res.status, headers: out });
  }
  // Everything else: pass the upstream stream straight through (zero copy).
  return new Response(body, { status: res.status, headers: out });
}

// ---------------------------------------------------------------------------
// Proxy core
// ---------------------------------------------------------------------------

async function proxyRequest(request, enc, extraQuery, env, fromPath) {
  let target;
  try {
    target = new URL(b64urlDecode(enc));
  } catch (e) {
    return textResp('Bad Request: invalid or missing encoded target URL.', 400);
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return textResp('Bad Request: only http and https targets are supported.', 400);
  }
  if (!isPubliclyRoutable(env, target.hostname)) {
    return textResp('Forbidden: private, reserved, or non-routable target host.', 403);
  }
  if (target.href.length > MAX_TARGET_URL) {
    return textResp('URI Too Long: encoded target exceeds 4096 characters.', 414);
  }

  // Path-form requests (form submissions): merge the submitted query onto the
  // target so GET form fields reach the origin intact.
  if (fromPath && extraQuery && extraQuery.length > 1) {
    const incoming = extraQuery.slice(1);
    const existing = target.search ? target.search.slice(1) : '';
    target.search = existing ? existing + '&' + incoming : incoming;
  }

  const jar = new CookieJar(request);
  const headers = buildUpstreamHeaders(request);

  let method = request.method.toUpperCase();
  let bodyBytes = null;
  if (method !== 'GET' && method !== 'HEAD') {
    const declared = Number(request.headers.get('content-length') || 0);
    if (declared > MAX_BODY_BYTES) {
      return textResp('Payload Too Large: proxied request bodies are capped at 25 MiB.', 413);
    }
    bodyBytes = new Uint8Array(await request.arrayBuffer());
    const type = request.headers.get('content-type');
    if (type) headers.set('content-type', type);
  }

  // Manual redirect loop: cookies set on 3xx hops are captured, relative
  // Locations are resolved, and the final URL becomes the rewriting base.
  let current = target;
  let res = null;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const cookieHeader = jar.header(current.origin);
    if (cookieHeader) headers.set('cookie', cookieHeader);
    else headers.delete('cookie');

    try {
      res = await fetch(current, {
        method,
        headers,
        redirect: 'manual',
        body: method === 'GET' || method === 'HEAD' ? undefined : bodyBytes,
      });
    } catch (e) {
      // Network-level failure (DNS, refused, TLS) — a clean 502, not a 500.
      return textResp('Bad Gateway: could not reach ' + current.origin + ' (' + (e && e.message ? e.message : 'network error') + ').', 502);
    }

    jar.absorb(res, current.origin);

    if (REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get('location');
      if (!location) break; // degenerate 3xx without Location — fall through
      let next;
      try {
        next = new URL(location, current);
      } catch (e) {
        break;
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') break;
      if (!isPubliclyRoutable(env, next.hostname)) {
        return textResp('Forbidden: redirect targeted a private or reserved host.', 403);
      }
      // Browser-faithful method downgrades.
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method !== 'GET' && method !== 'HEAD')) {
        method = 'GET';
        bodyBytes = null;
        headers.delete('content-type'); // a GET would never carry the form type
      }
      current = next;
      continue;
    }
    break;
  }

  if (res && REDIRECT_STATUSES.has(res.status) && res.headers.get('location')) {
    return textResp('Loop Detected: exceeded ' + MAX_REDIRECTS + ' upstream redirects.', 508);
  }
  if (!res) return textResp('Bad Gateway: no upstream response.', 502);
  return finalize(res, current, jar);
}

// ---------------------------------------------------------------------------
// Shell (HTML + iframe + service worker registration)
// ---------------------------------------------------------------------------

const SHELL_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EdgeFrame Proxy</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
html, body { height: 100%; }
body { margin: 0; font: 14px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; background: #0b0e14; color: #e6edf3; display: flex; flex-direction: column; }
header { display: flex; gap: 8px; padding: 10px 12px; background: #11151f; border-bottom: 1px solid #1f2633; }
input { flex: 1; min-width: 0; background: #0b0e14; border: 1px solid #2a3345; color: #e6edf3; border-radius: 8px; padding: 8px 12px; font: inherit; outline: none; }
input:focus { border-color: #4c8dff; }
button { background: #1f6feb; color: #fff; border: 0; border-radius: 8px; padding: 8px 14px; font: inherit; cursor: pointer; }
button:hover { background: #388bfd; }
button.ghost { background: #21293a; }
main { flex: 1; position: relative; }
iframe { position: absolute; inset: 0; width: 100%; height: 100%; border: 0; background: #fff; }
#status { position: absolute; bottom: 8px; right: 12px; font-size: 11px; color: #8b949e; user-select: none; }
</style>
</head>
<body>
<header>
<input id="addr" type="text" placeholder="Enter a URL and press Enter" spellcheck="false" autocomplete="off">
<button id="go" title="Load the URL in the frame">Go</button>
<button id="pop" class="ghost" title="Open the current frame URL in a new window">New Window</button>
</header>
<main>
<iframe id="view" title="Proxied content" allow="autoplay; fullscreen; encrypted-media; clipboard-write; picture-in-picture" referrerpolicy="no-referrer-when-downgrade"></iframe>
<div id="status"></div>
</main>
<script>
(function () {
  'use strict';
  var HOME = 'https://en.wikipedia.org/wiki/Main_Page';
  var frame = document.getElementById('view');
  var addr = document.getElementById('addr');
  var status = document.getElementById('status');

  function enc(value) {
    var bytes = new TextEncoder().encode(value);
    var binary = '';
    for (var i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  function dec(value) {
    if (!value) return '';
    var padded = value.length % 4 === 0 ? value : value + '='.repeat(4 - (value.length % 4));
    var binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  function normalize(value) {
    value = (value || '').trim();
    if (!value) return HOME;
    if (!/^[a-z][a-z0-9+.-]*:/i.test(value)) value = 'https://' + value;
    return value;
  }

  function navigate(url) { frame.src = '/proxy?u=' + enc(url); }

  document.getElementById('go').addEventListener('click', function () { navigate(normalize(addr.value)); });
  addr.addEventListener('keydown', function (e) { if (e.key === 'Enter') navigate(normalize(addr.value)); });
  document.getElementById('pop').addEventListener('click', function () { if (frame.src) window.open(frame.src, '_blank'); });

  // Keep the address bar in sync with in-frame navigations (same-origin, so
  // the iframe location is readable).
  frame.addEventListener('load', function () {
    try {
      var loc = frame.contentWindow.location;
      var encoded = new URL(loc.href).searchParams.get('u');
      if (encoded) addr.value = dec(encoded);
      status.textContent = 'proxied';
    } catch (e) {
      status.textContent = 'opaque';
    }
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').then(function () {
      status.textContent = 'sw active';
    }).catch(function () {
      status.textContent = 'sw unavailable';
    });
  }

  navigate(HOME);
})();
</script>
</body>
</html>`;

const SW_SCRIPT = `/* EdgeFrame service worker — fallback router.
 * Server-side rewriting covers every reference that exists in the delivered
 * markup. This worker catches the remainder: URLs constructed at runtime by
 * site JavaScript that resolve against the proxy origin. The referring
 * document's proxy URL (available via request.referrer) carries the base
 * needed to resolve them back onto the target origin.
 */
(function () {
  'use strict';

  var PROXY = '/proxy';
  var PROXY_PATH = '/p/';
  var PARAM = 'u';
  var APP_ROUTES = ['/', '/sw.js', '/favicon.ico'];

  function enc(value) {
    var bytes = new TextEncoder().encode(value);
    var binary = '';
    for (var i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  function dec(value) {
    if (!value) return '';
    var padded = value.length % 4 === 0 ? value : value + '='.repeat(4 - (value.length % 4));
    var binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  function encodedTarget(u) {
    try {
      if (u.pathname === PROXY) return u.searchParams.get(PARAM);
      if (u.pathname.indexOf(PROXY_PATH) === 0) return u.pathname.slice(PROXY_PATH.length) || null;
    } catch (e) {}
    return null;
  }

  self.addEventListener('install', function () { self.skipWaiting(); });
  self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });

  self.addEventListener('fetch', function (event) {
    var request = event.request;
    var url;
    try { url = new URL(request.url); } catch (e) { return; }
    if (url.origin !== self.location.origin) return;

    var path = url.pathname;
    if (APP_ROUTES.indexOf(path) !== -1) return; // shell assets -> network
    if (path === PROXY || path.indexOf(PROXY_PATH) === 0) return; // already proxied -> network

    // A same-origin request that is not one of our routes is a missed rewrite.
    var base = null;
    if (request.referrer) {
      try {
        var ref = new URL(request.referrer);
        if (ref.origin === self.location.origin) {
          var encoded = encodedTarget(ref);
          if (encoded) base = dec(encoded);
        }
      } catch (e) {}
    }
    if (!base) return; // no base to resolve against — let it 404 naturally

    var resolved;
    try { resolved = new URL(path + url.search + url.hash, base); } catch (e) { return; }
    var target = self.location.origin + PROXY + '?' + PARAM + '=' + enc(resolved.href);

    if (request.mode === 'navigate') {
      // New-window navigations get the clean proxy URL in the address bar.
      event.respondWith(Response.redirect(target, 302));
      return;
    }

    var init = { method: request.method, headers: request.headers, redirect: 'follow' };
    if (request.method !== 'GET' && request.method !== 'HEAD') init.body = request.body;
    event.respondWith(
      fetch(target, init).catch(function () { return Response.error(); })
    );
  });
})();`;

function shellResponse() {
  return new Response(SHELL_HTML, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-cache',
      'x-ef-version': VERSION,
    },
  });
}

function swResponse() {
  return new Response(SW_SCRIPT, {
    status: 200,
    headers: {
      'content-type': 'application/javascript; charset=utf-8',
      'cache-control': 'no-cache',
      'x-ef-version': VERSION,
    },
  });
}

// ---------------------------------------------------------------------------
// Router + entry point
// ---------------------------------------------------------------------------

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (path === ROUTES.SHELL) {
    if (method === 'GET' || method === 'HEAD') return shellResponse();
    return textResp('Method Not Allowed', 405);
  }
  if (path === ROUTES.SW) {
    if (method === 'GET' || method === 'HEAD') return swResponse();
    return textResp('Method Not Allowed', 405);
  }
  if (path === ROUTES.FAVICON) {
    return new Response(null, {
      status: 204,
      headers: { 'cache-control': 'public, max-age=86400' },
    });
  }
  if (path === ROUTES.PROXY) {
    if (method !== 'GET' && method !== 'HEAD' && method !== 'POST') {
      return textResp('Method Not Allowed: use GET, HEAD, or POST.', 405);
    }
    const enc = url.searchParams.get(PARAM);
    if (!enc) return textResp('Bad Request: missing ?u=<base64url target>.', 400);
    return proxyRequest(request, enc, '', env, false);
  }
  if (path.startsWith(ROUTES.PROXY_PATH)) {
    if (method !== 'GET' && method !== 'HEAD' && method !== 'POST') {
      return textResp('Method Not Allowed: use GET, HEAD, or POST.', 405);
    }
    const enc = path.slice(ROUTES.PROXY_PATH.length);
    if (!enc) return textResp('Bad Request: missing encoded target path segment.', 400);
    return proxyRequest(request, enc, url.search, env, true);
  }
  return textResp('Not Found', 404);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env);
    } catch (err) {
      const message = err && err.message ? err.message : String(err);
      return textResp('Worker Error: ' + message, 500);
    }
  },
};
