// Cloudflare Pages Function: GET/HEAD /p/:cid
// Streams the stored piece bytes from R2.
//
// SECURITY (NEW-7 in 2026-04-26 audit): retrievals MUST NOT serve
// arbitrary user-uploaded HTML / SVG / JS as inline content on the
// `prova.network` origin. Doing so allows a malicious uploader to
// trick a victim into hitting `/p/<cid>` and have their browser
// execute the attacker's script in the prova.network origin context,
// stealing localStorage tokens.
//
// Therefore retrievals on the main origin always:
//   1. Force `content-type: application/octet-stream` (kills sniffing).
//   2. Force `content-disposition: attachment; filename="<cid>"` so
//      the browser downloads instead of rendering.
//   3. Set `x-content-type-options: nosniff` defensively.
//   4. Set a hard `content-security-policy: sandbox` so even if a
//      future browser bug ignored the disposition, no scripts can run.
//
// `.eth` website hosting (a stated v1 use case) needs a separate
// isolated origin (e.g. `prova-content.network`) where these protections
// are explicitly relaxed and where the origin itself does not co-host
// the dashboard or the magic-link flow. Until that origin exists,
// retrievals are download-only on the main domain.

interface Env {
  PROVA_PIECES?: R2Bucket;
  PROVA_STAGE_URL?: string;
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request: req, env, params } = ctx;
  const cid = params.cid as string;
  // Accept both new (baga…) and legacy (bafy…) CID formats here so old
  // retrieval URLs in the wild keep working. The /api/upload endpoint
  // is stricter and only accepts new-format CIDs going forward.
  if (!cid || !/^[a-z0-9]{8,80}$/i.test(cid)) {
    return new Response('Invalid cid', { status: 400 });
  }
  // R2 path
  if (env.PROVA_PIECES) {
    const obj = await env.PROVA_PIECES.get(`pieces/${cid}`);
    if (!obj) return new Response('Not found', { status: 404 });
    return serveR2(req, obj, cid);
  }

  // Hetzner stage fallback. Cloudflare Workers can't fetch raw-IP
  // hostnames (error 1003), so when PROVA_STAGE_URL points at one we
  // 302 the client there directly. Once we have a CF-routed hostname
  // we'll switch back to a transparent proxy.
  if (env.PROVA_STAGE_URL) {
    const base = env.PROVA_STAGE_URL.replace(/\/+$/, '');
    const target = `${base}/p/${encodeURIComponent(cid)}`;
    const looksLikeRawIp = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?/.test(base);
    if (looksLikeRawIp) {
      return Response.redirect(target, 302);
    }
    const upstream = await fetch(target, {
      method: req.method,
      headers: { 'user-agent': 'prova-pages-fn/1' },
    });
    if (!upstream.ok) {
      return new Response(await upstream.text().catch(() => 'Upstream error'), {
        status: upstream.status,
      });
    }
    // Build a hardened response. We deliberately do NOT propagate the
    // upstream `content-type` or `content-disposition` — those are
    // attacker-controlled (the attacker uploaded the file) and were the
    // exact pivot in NEW-7. We DO propagate content-length so range
    // streaming math stays accurate.
    const headers = new Headers();
    const upstreamLen = upstream.headers.get('content-length');
    if (upstreamLen) headers.set('content-length', upstreamLen);
    applyDownloadHeaders(headers, cid);
    headers.set('x-prova-source', 'stage');
    return new Response(upstream.body, { headers });
  }

  return new Response('Storage offline (provisioning)', { status: 503 });
};

function serveR2(req: Request, obj: R2ObjectBody, cid: string): Response {
  if (req.method === 'HEAD') {
    const h = new Headers();
    h.set('content-length', String(obj.size));
    applyDownloadHeaders(h, cid);
    h.set('x-prova-source', 'r2');
    return new Response(null, { headers: h });
  }
  const headers = new Headers();
  applyDownloadHeaders(headers, cid);
  headers.set('x-prova-source', 'r2');
  return new Response(obj.body, { headers });
}

/**
 * Apply the hardened retrieval headers that turn `/p/<cid>` into a
 * safe download surface, regardless of what bytes the prover stored.
 *
 * Order of operations:
 *   1. Force a non-sniffable, non-renderable content-type.
 *   2. Force attachment disposition so the browser downloads rather
 *      than rendering; the filename is the CID itself, which we
 *      validated against `[a-z0-9]{8,80}` above so it cannot inject
 *      header escapes or control characters.
 *   3. `x-content-type-options: nosniff` so even the misconfigured
 *      browsers that try to MIME-sniff get told no.
 *   4. `content-security-policy: sandbox` so even if a future browser
 *      bug honored neither the disposition nor the type, the served
 *      bytes execute in an opaque origin with no DOM, no scripts, no
 *      same-origin access.
 *   5. Cache-control `public, max-age=3600, immutable` because pieces
 *      are content-addressed: the bytes for a given CID never change.
 *
 * If the project later wants in-browser preview of e.g. images or
 * `.eth` static sites, that MUST happen on a separate origin
 * (`prova-content.network` is the planned hostname) where this header
 * suite is relaxed deliberately and the origin does not co-host any
 * authenticated dashboard. Do not relax these on the main origin.
 */
function applyDownloadHeaders(headers: Headers, cid: string): void {
  headers.set('content-type', 'application/octet-stream');
  headers.set('content-disposition', `attachment; filename="${cid}"`);
  headers.set('x-content-type-options', 'nosniff');
  headers.set('content-security-policy', "sandbox; default-src 'none'");
  headers.set('cache-control', 'public, max-age=3600, immutable');
  headers.set('x-prova-piece-cid', cid);
}
