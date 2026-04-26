// Prova Pages middleware. Routes by hostname, applies global security
// headers, and handles cross-origin (CORS) preflights for the public
// API surface.
//
// - get.prova.network        -> install.sh (one-liner CLI installer)
// - everywhere else          -> falls through to static + functions,
//                               with CSP / HSTS / CORS / etc. layered
//                               on the response

interface Env {}

// CORS allow-list. Same-origin browsers don't need this; CLIs and
// SDKs explicitly do (so we can be hit with `Origin: null` from
// `file://` test pages). Subdomains of prova.network are explicitly
// excluded — if a future subdomain needs API access, list it here.
const CORS_ALLOWED_ORIGINS = new Set<string>([
  'https://prova.network',
  'https://www.prova.network',
  'https://docs.prova.network',
  'https://spec.prova.network',
]);

// Endpoints that consumers might legitimately call cross-origin (e.g.
// from an SDK in a third-party app). They get the wildcard treatment
// below. Auth endpoints are deliberately NOT on this list — their
// origin gate is enforced server-side per request and they require
// the production origin (see _shared/origin.ts).
const CORS_PUBLIC_API_PATHS: ReadonlyArray<RegExp> = [
  /^\/api\/abuse\/report$/,
  /^\/p\/[a-z0-9]+$/i,
];

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const url = new URL(ctx.request.url);
  const host = url.hostname;

  if (host === 'get.prova.network') {
    return serveInstaller(ctx.request);
  }

  // Handle CORS preflight before anything else — saves a downstream
  // call and keeps the OPTIONS surface predictable.
  if (ctx.request.method === 'OPTIONS' && url.pathname.startsWith('/api/')) {
    return handleCorsPreflight(ctx.request, url);
  }

  // Pass through to static / function handlers, then add headers
  const res = await ctx.next();
  return withSecurityHeaders(res, ctx.request, url);
};

/**
 * Compute the CORS Access-Control-Allow-Origin value for this request,
 * or `null` if the request isn't from an allowed origin. We deliberately
 * do not echo arbitrary `Origin` headers (no `*` either) because most
 * of our endpoints are credentialed with bearer tokens.
 */
function allowedCorsOrigin(req: Request): string | null {
  const origin = req.headers.get('origin');
  if (!origin) return null;
  if (CORS_ALLOWED_ORIGINS.has(origin)) return origin;
  return null;
}

/**
 * Decide if a path is a 'public API' that should accept any allowed
 * cross-origin caller. Auth endpoints are always strict-origin (handled
 * server-side per route).
 */
function isPublicApiPath(pathname: string): boolean {
  return CORS_PUBLIC_API_PATHS.some((rx) => rx.test(pathname));
}

function handleCorsPreflight(req: Request, url: URL): Response {
  const origin = allowedCorsOrigin(req);
  // Even non-public-API paths get a 204 preflight, but the actual
  // CORS-allow header is only set if origin + path are both OK.
  const headers = new Headers({
    'access-control-allow-methods': 'GET, HEAD, POST, OPTIONS',
    'access-control-allow-headers': 'authorization, content-type, x-filename, x-requested-with',
    'access-control-max-age': '86400',
    'vary': 'Origin',
  });
  if (origin && isPublicApiPath(url.pathname)) {
    headers.set('access-control-allow-origin', origin);
    headers.set('access-control-allow-credentials', 'true');
  }
  return new Response(null, { status: 204, headers });
}

function withSecurityHeaders(res: Response, req: Request, url: URL): Response {
  // Don't rewrite responses that already pinned their own CSP
  // (e.g. /p/{cid} retrievals where we want default-src 'none' sandbox).
  const r = new Response(res.body, res);

  if (!r.headers.has('content-security-policy')) {
    // Allowlist:
    //   - same-origin scripts
    //   - JSDelivr for marked.js (whitepaper page)
    //   - unpkg for three.js (Earth hero)
    //   - inline styles (we use them generously in <style> blocks)
    //   - blob: for upload progress (canvas/file readers)
    //   - https: images (for the Earth hero textures + brand assets)
    //   - api endpoints on same origin
    //
    // SECURITY NOTE (F-15 / NEW-5 in 2026-04-26 audit): `'unsafe-inline'`
    // for `script-src` is still permitted here because the static site
    // currently relies on inline `<script>` blocks for upload progress
    // and dashboard wiring. Removing it requires either (a) extracting
    // every inline script to a separate file (large refactor across
    // index.html, app/*.html, upload/*.html, specs.html, lab.js inline
    // bootstraps), or (b) injecting a per-request nonce via HTML
    // rewriting. Both are tracked as a follow-up. The mitigations that
    // ship in the meantime are:
    //   - /p/{cid} now serves application/octet-stream + sandbox CSP
    //     (NEW-7 fix), so user-uploaded HTML cannot run on this
    //     origin.
    //   - The auth flow no longer leaks the verify challenge into
    //     response bodies (NEW-4 fix), so a hypothetical inline-XSS
    //     can no longer mint tokens for arbitrary emails.
    //   - Subdomain takeover surface from `*.pages.dev` is closed for
    //     auth endpoints (NEW-8 fix).
    const csp = [
      "default-src 'self'",
      "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://prova.network https://p.prova.network",
      "worker-src 'self' blob:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
      "upgrade-insecure-requests",
    ].join('; ');
    r.headers.set('content-security-policy', csp);
  }

  if (!r.headers.has('x-content-type-options')) r.headers.set('x-content-type-options', 'nosniff');
  if (!r.headers.has('x-frame-options'))         r.headers.set('x-frame-options', 'DENY');
  if (!r.headers.has('referrer-policy'))         r.headers.set('referrer-policy', 'strict-origin-when-cross-origin');
  if (!r.headers.has('permissions-policy'))      r.headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  if (!r.headers.has('strict-transport-security')) r.headers.set('strict-transport-security', 'max-age=63072000; includeSubDomains; preload');
  if (!r.headers.has('cross-origin-opener-policy'))   r.headers.set('cross-origin-opener-policy', 'same-origin');
  if (!r.headers.has('cross-origin-resource-policy')) r.headers.set('cross-origin-resource-policy', 'same-site');

  // CORS (F-13 fix). Apply only on /api/ paths and only when origin is
  // in the allow-list. Same-origin browser requests don't need any of
  // this; cross-origin requests from CLIs / SDKs / 3rd-party apps do.
  if (url.pathname.startsWith('/api/')) {
    const origin = allowedCorsOrigin(req);
    if (origin && isPublicApiPath(url.pathname)) {
      r.headers.set('access-control-allow-origin', origin);
      r.headers.set('access-control-allow-credentials', 'true');
      // Always set Vary: Origin when echoing the request origin, so
      // CDN caches don't conflate responses for different origins.
      const existingVary = r.headers.get('vary');
      if (existingVary && !existingVary.toLowerCase().includes('origin')) {
        r.headers.set('vary', `${existingVary}, Origin`);
      } else if (!existingVary) {
        r.headers.set('vary', 'Origin');
      }
      // Expose the prova-* headers so SDK consumers can read them
      // from the response (otherwise the browser hides them).
      r.headers.set('access-control-expose-headers', 'x-prova-piece-cid, x-prova-source, x-prova-verified, x-prova-prover');
    }
  }

  return r;
}

function serveInstaller(req: Request): Response {
  const ua = (req.headers.get('user-agent') || '').toLowerCase();
  const accept = req.headers.get('accept') || '';
  const url = new URL(req.url);

  const isCli =
    ua.includes('curl/') ||
    ua.includes('wget/') ||
    ua.includes('fetch/') ||
    ua.includes('libcurl') ||
    !accept.includes('text/html');

  if (req.method === 'HEAD') {
    return new Response(null, {
      status: 200,
      headers: {
        'content-type': 'text/x-shellscript; charset=utf-8',
        'cache-control': 'public, max-age=300',
      },
    });
  }

  if (!isCli) {
    // Browser hit. Until docs are public, send them to the CLI page on the
    // marketing site rather than docs.prova.network.
    return Response.redirect('https://prova.network/#use', 302);
  }

  const wantPrerelease = url.searchParams.get('prerelease') === '1';
  // SECURITY (NEW-1 Critical, 2026-04-26 audit): the version string is
  // interpolated into a shell script that the user pipes to /bin/sh.
  // Any unvalidated query-string passes straight to the victim's shell
  // as command substitution. The allow-list below is exhaustive: the
  // 3 named tracks plus a strict semver-ish pattern. Anything else
  // collapses to 'latest' — no error message, no echo.
  const rawVersion = url.searchParams.get('version') || (wantPrerelease ? 'prerelease' : 'latest');
  const wantVersion = sanitizeInstallerVersion(rawVersion);

  return new Response(installerScript(wantVersion), {
    status: 200,
    headers: {
      'content-type': 'text/x-shellscript; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'x-prova-installer-version': wantVersion,
    },
  });
}

/**
 * Whitelist the version string that gets interpolated into the
 * generated shell script. Anything that doesn't match a known
 * track or a strict semver collapses to 'latest'. We never echo,
 * 400, or otherwise reflect the bad value to the requester — the
 * only safe behaviour is silently fall back.
 *
 * SECURITY: do not relax this without a fresh audit. The output is
 * piped to /bin/sh on the victim's machine.
 */
function sanitizeInstallerVersion(s: string | null | undefined): string {
  if (!s) return 'latest';
  if (s === 'latest' || s === 'prerelease' || s === 'next') return s;
  // semver, optional leading 'v', optional pre-release tag of [\w.-]+,
  // capped length so we can't swallow arbitrary blobs.
  if (s.length <= 32 && /^v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(s)) return s;
  return 'latest';
}

function installerScript(version: string): string {
  // Defense-in-depth: even though sanitizeInstallerVersion already
  // limits `version` to a known-safe alphabet, we shell-quote it on
  // the way out so any future relaxation of the regex doesn't hand
  // arbitrary substitution to the script.
  const escVer = shellSingleQuote(version);
  return [
    '#!/bin/sh',
    '# Prova CLI installer (https://get.prova.network)',
    '#',
    '# Usage:',
    '#   curl -fsSL https://get.prova.network | sh',
    '#',
    '# Options (env vars):',
    '#   PROVA_VERSION="latest"|"prerelease"|"0.1.0"',
    '#   PROVA_PREFIX="$HOME/.prova"',
    '#   PROVA_NO_PATH=1   skip PATH modification',
    '',
    'set -eu',
    '',
    `VERSION="\${PROVA_VERSION:-$(printf %s ${escVer})}"`,
    'PREFIX="${PROVA_PREFIX:-$HOME/.prova}"',
    'NO_PATH="${PROVA_NO_PATH:-0}"',
    'CLI_PKG="@prova-network/cli"',
    '',
    'red()   { printf "\\033[31m%s\\033[0m\\n" "$1"; }',
    'green() { printf "\\033[32m%s\\033[0m\\n" "$1"; }',
    'dim()   { printf "\\033[2m%s\\033[0m\\n"  "$1"; }',
    'bold()  { printf "\\033[1m%s\\033[0m\\n"  "$1"; }',
    '',
    'bold "Installing Prova CLI"',
    'dim  "  version : $VERSION"',
    'dim  "  prefix  : $PREFIX"',
    'echo',
    '',
    'if command -v npm >/dev/null 2>&1; then',
    '  if npm install -g "$CLI_PKG@$VERSION" 2>/dev/null; then',
    '    echo',
    '    green "✓ Installed via npm"',
    '    echo',
    '    bold "Next: prova auth"',
    '    exit 0',
    '  else',
    '    dim "npm install failed (probably not yet published). Falling back to direct download..."',
    '  fi',
    'fi',
    '',
    'mkdir -p "$PREFIX/bin"',
    'TMP="$(mktemp -d)"',
    'TARBALL="$TMP/prova-cli.tar.gz"',
    '',
    '# Distribution URL. Will switch to R2 once enabled.',
    'TAG="$VERSION"',
    '[ "$TAG" = "latest" ] && TAG="v0.1.0"',
    '[ "$TAG" = "prerelease" ] && TAG="v0.1.0"',
    'case "$TAG" in v*) ;; *) TAG="v$TAG" ;; esac',
    'URL="https://prova.network/cli/${TAG}/prova-cli.tar.gz"',
    '',
    'echo "Fetching $URL"',
    'if command -v curl >/dev/null 2>&1; then',
    '  curl -fsSL "$URL" -o "$TARBALL"',
    'elif command -v wget >/dev/null 2>&1; then',
    '  wget -qO "$TARBALL" "$URL"',
    'else',
    '  red "Need curl or wget to download. Install one and rerun."',
    '  exit 1',
    'fi',
    '',
    'mkdir -p "$PREFIX/lib/cli"',
    'tar -xzf "$TARBALL" -C "$PREFIX/lib/cli" --strip-components=1',
    'rm -rf "$TMP"',
    '',
    'if [ -f "$PREFIX/lib/cli/bin/prova.mjs" ]; then',
    '  ln -sf "$PREFIX/lib/cli/bin/prova.mjs" "$PREFIX/bin/prova"',
    '  chmod +x "$PREFIX/lib/cli/bin/prova.mjs"',
    'else',
    '  red "Tarball did not contain bin/prova.mjs"',
    '  exit 1',
    'fi',
    '',
    'if [ "$NO_PATH" != "1" ]; then',
    '  case ":$PATH:" in',
    '    *":$PREFIX/bin:"*) ;;',
    '    *)',
    '      dim "Add $PREFIX/bin to your PATH:"',
    '      dim "  echo \'export PATH=\\"\\$HOME/.prova/bin:\\$PATH\\"\' >> ~/.zshrc"',
    '      ;;',
    '  esac',
    'fi',
    '',
    'if ! command -v node >/dev/null 2>&1; then',
    '  echo',
    '  red "Prova CLI needs Node 18 or newer."',
    '  echo "  Install Node:  https://nodejs.org/"',
    '  exit 1',
    'fi',
    '',
    'echo',
    'green "✓ Installed at $PREFIX/bin/prova"',
    'echo',
    'bold "Next: prova auth"',
    '',
    `# Installer build: ${version}`,
  ].join('\n');
}

/**
 * POSIX shell single-quote a string so it survives interpolation into a
 * shell script verbatim, with no command substitution / variable
 * expansion / globbing performed by the eventual shell. The standard
 * trick: wrap in single quotes, and replace any embedded single quote
 * with the four-character sequence  '\''  which closes the current
 * quoted span, emits a literal quote, and reopens.
 *
 * Used as defense-in-depth against the version-injection bug
 * even though the regex in sanitizeInstallerVersion already
 * forbids any of the dangerous characters.
 */
function shellSingleQuote(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}
