// POST /api/auth/start  { email, label?, returnUrl? }
//
// Step 1 of magic-link auth. Generates a 6-digit code + a long-lived
// challenge token, stores them in KV with TTL, and emails the user a
// link they can click + a code they can paste into the CLI.
//
// Response is intentionally vague — we don't reveal whether the email
// was syntactically valid or whether the user already exists, beyond
// what's needed for the UI to give feedback. We DO 400 on garbage
// emails so the form can show a useful error.

import { sendMail, type MailEnv } from '../../_shared/email';
import { isProvaProductionOrigin, originRoot } from '../../_shared/origin';

interface Env extends MailEnv {
  PROVA_USERS?: KVNamespace;
  PROVA_RATE?: KVNamespace;
  PROVA_PUBLIC_BASE?: string; // e.g. https://prova.network
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request: req, env } = ctx;
  if (req.method !== 'POST') return j({ error: 'method_not_allowed' }, 405);

  // Origin / Referer check — production-only.
  //
  // SECURITY (NEW-8 in 2026-04-26 audit): we deliberately do NOT accept
  // `*.prova-network.pages.dev` here. Cloudflare Pages preview
  // deployments inherit the prod `PROVA_TOKEN_SECRET` binding, so a
  // PR-preview running untrusted code could otherwise call this
  // endpoint with a forged origin and mint tokens for arbitrary emails
  // signed with the production secret. Preview branches that need to
  // test the sign-in flow get their own deployment with a scoped
  // secret and a scoped origin allow-list.
  const origin = req.headers.get('origin') || '';
  const refer  = req.headers.get('referer') || '';
  const ok = isProvaProductionOrigin(origin) || isProvaProductionOrigin(refer);
  if (!ok) return j({ error: 'forbidden_origin' }, 403);

  let body: { email?: string; label?: string; returnUrl?: string };
  try { body = await req.json(); } catch { return j({ error: 'invalid_json' }, 400); }

  const email = (body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return j({ error: 'invalid_email' }, 400);

  const label = sanitizeLabel(body.label || 'web');
  const returnUrl = sanitizeReturnUrl(body.returnUrl || '');

  // Per-IP and per-email rate limit: 5 starts / 15 minutes
  //
  // Use a /64 bucket for IPv6 to avoid trivial bypass via the 2^64 host
  // suffix in a single delegation; for IPv4 we use the full address. We
  // also fall back to a stable token rather than '0.0.0.0' so that
  // requests with a missing cf-connecting-ip don't all collide into the
  // same bucket (the prior behaviour silently DoS'd legitimate users
  // when the header was stripped).
  const ip = clientIpBucket(req);
  if (env.PROVA_RATE) {
    const ipKey = `auth:ip:${ip}`;
    const emailKey = `auth:em:${await sha256Hex(email)}`;
    if (await overLimit(env.PROVA_RATE, ipKey, 5, 900)) {
      return j({ error: 'rate_limited', detail: 'Too many sign-in requests. Try again in 15 minutes.' }, 429);
    }
    // F-09 fix: per-email limiter result was previously discarded.
    if (await overLimit(env.PROVA_RATE, emailKey, 5, 900)) {
      return j({ error: 'rate_limited', detail: 'Too many sign-in requests for this email. Try again in 15 minutes.' }, 429);
    }
  }

  // 6-digit code (CLI paste) + 32-byte challenge (link click).
  //
  // SECURITY: The OTP MUST come from a CSPRNG. Math.random() is a non-
  // cryptographic PRNG whose internal state is observable from a few
  // outputs, which would allow an attacker who knows a victim's email to
  // predict their next OTP after observing one of their own.
  // Rejection-sampling out of a uint32 keeps the distribution uniform
  // across the 6-digit space (10^6 = 1_000_000).
  const code = secureSixDigitCode();
  const challenge = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

  // Store challenge → email mapping for 15 minutes
  if (env.PROVA_USERS) {
    const value = JSON.stringify({
      email, code, label, returnUrl,
      attempts: 0,
      createdAt: Math.floor(Date.now() / 1000),
    });
    await env.PROVA_USERS.put(`magic:${challenge}`, value, { expirationTtl: 900 });
    // Reverse lookup so the CLI can verify with code+email instead of needing the link
    await env.PROVA_USERS.put(`magic:e:${await sha256Hex(email)}:${code}`, challenge, { expirationTtl: 900 });
  }

  const base = env.PROVA_PUBLIC_BASE || originRoot(origin) || 'https://prova.network';
  const link = `${base}/auth/verify?challenge=${challenge}${returnUrl ? `&return=${encodeURIComponent(returnUrl)}` : ''}`;

  // From-address: prefers MAIL_FROM_EMAIL when configured (e.g.
  // hello@prova.network once Resend verifies the domain). Falls back
  // to Resend's shared onboarding sender so sign-in keeps working
  // before domain verification completes.
  const fromEmail = (env as { MAIL_FROM_EMAIL?: string }).MAIL_FROM_EMAIL || 'onboarding@resend.dev';
  const replyTo   = (env as { MAIL_REPLY_TO?: string }).MAIL_REPLY_TO || 'hello@prova.network';

  const mail = await sendMail({
    to: { email },
    from: { email: fromEmail, name: 'Prova' },
    replyTo: { email: replyTo },
    subject: `Your Prova sign-in code: ${code}`,
    content: [
      { type: 'text/plain', value: textBody(code, link) },
      { type: 'text/html',  value: htmlBody(code, link) },
    ],
  }, env);

  if (!mail.ok) {
    return j({
      error: 'mail_failed',
      detail: 'Could not deliver sign-in email. Try again in a moment.',
      ...((env as { DEBUG?: string }).DEBUG ? { upstream: mail } : {}),
    }, 502);
  }

  // SECURITY: We deliberately do NOT return `challenge` to the caller.
  // Returning it would let any same-origin script (XSS, malicious inline
  // dependency, browser extension on `prova.network`) call /api/auth/start
  // for an arbitrary email, read the verify secret from the response, and
  // mint a token without ever touching the inbox. The only legitimate
  // out-of-band proof of email ownership is delivery to the inbox itself.
  return j({
    sent: true,
    email,
    expiresIn: 900,
  });
};

function j(d: unknown, s = 200) {
  return new Response(JSON.stringify(d), {
    status: s,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function isValidEmail(s: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length < 256;
}

/**
 * Compute a stable rate-limit bucket id for a client.
 *
 * - IPv4: full address (a.b.c.d)
 * - IPv6: only the routing prefix (/64). Without this bucketing, an
 *   attacker on any non-trivial residential or datacenter IPv6
 *   allocation has at least 2^64 distinct source addresses available
 *   inside a single subscriber line and can bypass per-IP rate limits
 *   completely.
 * - Missing header: a fixed 'no-ip' bucket scoped per request method, so
 *   we don't either (a) collapse every IP-less caller into '0.0.0.0' (a
 *   shared-bucket DoS) or (b) silently drop the limit. CGNAT users may
 *   share the same /64 in practice; that's still much better than the
 *   previous behaviour of all sharing 0.0.0.0.
 */
function clientIpBucket(req: Request): string {
  const raw = req.headers.get('cf-connecting-ip') || '';
  if (!raw) return 'no-ip';
  if (raw.includes(':')) {
    // IPv6 — keep first four hextets (the /64 prefix). Cloudflare
    // already normalizes the header to a single address, so we just
    // split on ':' and re-join the first four groups. Empty groups in a
    // '::' compression are preserved on join, so `2001:db8::1` becomes
    // bucket `2001:db8:::` which is fine — it's still a stable key per
    // /64.
    return raw.toLowerCase().split(':').slice(0, 4).join(':') + '::/64';
  }
  return raw;
}

/**
 * Return a uniformly-random 6-digit numeric string (\"000000\" .. \"999999\").
 * Uses a CSPRNG. Rejection sampling avoids the modulo bias from a
 * straight `% 1_000_000` over uint32, which is small but non-zero.
 */
function secureSixDigitCode(): string {
  const buf = new Uint32Array(1);
  // The largest multiple of 1_000_000 that fits in uint32 is
  // 0xFFC00000 (4_293_000_000). Anything above that, retry. Rejection
  // probability is < 0.07%.
  const cutoff = Math.floor(0xFFFFFFFF / 1_000_000) * 1_000_000;
  for (let i = 0; i < 8; i++) {
    crypto.getRandomValues(buf);
    if (buf[0]! < cutoff) {
      return String(buf[0]! % 1_000_000).padStart(6, '0');
    }
  }
  // 8 consecutive rejections is astronomically unlikely (< 1e-26).
  // Fall through with the last sample biased; it's still a CSPRNG.
  return String(buf[0]! % 1_000_000).padStart(6, '0');
}

function sanitizeLabel(s: string) {
  return s.replace(/[^\w\-. ]/g, '').slice(0, 64) || 'web';
}

function sanitizeReturnUrl(s: string) {
  if (!s) return '';
  // Only allow same-origin paths, no protocol-relative / off-site
  if (s.startsWith('/') && !s.startsWith('//')) return s.slice(0, 200);
  return '';
}

// origin / production allow-list helpers moved to ../../_shared/origin.ts

function bytesToHex(b: Uint8Array) {
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(s: string) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return bytesToHex(new Uint8Array(h));
}

async function overLimit(kv: KVNamespace, key: string, limit: number, ttl: number) {
  const cur = parseInt((await kv.get(key)) || '0', 10);
  if (cur >= limit) return true;
  await kv.put(key, String(cur + 1), { expirationTtl: ttl });
  return false;
}

function textBody(code: string, link: string) {
  return [
    'Hello!',
    '',
    `Your Prova sign-in code is: ${code}`,
    '',
    'Or click this link to sign in:',
    link,
    '',
    'This code expires in 15 minutes.',
    "If you didn't request this, you can ignore this email.",
    '',
    '— Prova (https://prova.network)',
  ].join('\n');
}

function htmlBody(code: string, link: string) {
  // Inline styles only — no external CSS, MailChannels strips it anyway.
  // Keep brand identity in line with marketing site (teal gradient + Apple stack).
  return `<!doctype html><html><body style="margin:0;padding:0;background:#f6f8fa;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f6f8fa;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 1px 2px rgba(15,76,92,0.08);">
        <tr>
          <td style="padding:32px 32px 8px 32px;text-align:left;">
            <div style="font-size:13px;letter-spacing:0.08em;text-transform:uppercase;color:#0F4C5C;font-weight:600;">Prova</div>
            <h1 style="margin:8px 0 0;font-size:24px;line-height:1.2;color:#0F1419;font-weight:600;">Sign in to your account</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 32px 0 32px;">
            <p style="margin:16px 0;font-size:15px;line-height:1.55;color:#39424c;">Use this code to finish signing in:</p>
            <div style="background:linear-gradient(135deg,#5DC3E5 0%,#2EC4B6 55%,#0F4C5C 100%);padding:1px;border-radius:14px;">
              <div style="background:#ffffff;border-radius:13px;padding:18px 24px;text-align:center;">
                <div style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:32px;letter-spacing:0.18em;color:#0F4C5C;font-weight:600;">${escapeHtml(code)}</div>
              </div>
            </div>
            <p style="margin:24px 0 8px;font-size:15px;color:#39424c;line-height:1.55;">Or click the button to sign in directly:</p>
            <p style="margin:8px 0 24px;">
              <a href="${escapeAttr(link)}" style="display:inline-block;background:#0F4C5C;color:#ffffff;text-decoration:none;padding:12px 22px;border-radius:10px;font-size:15px;font-weight:500;">Sign in to Prova</a>
            </p>
            <p style="margin:20px 0 0;font-size:12px;color:#9aa4b1;line-height:1.6;">This code expires in 15 minutes. If you didn't request this, you can safely ignore this email.</p>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 32px 32px 32px;border-top:1px solid #e6eaef;">
            <p style="margin:0;font-size:12px;color:#9aa4b1;">Prova · <a href="https://prova.network" style="color:#9aa4b1;text-decoration:underline;">prova.network</a></p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  } as Record<string,string>)[c]);
}

function escapeAttr(s: string) {
  return escapeHtml(s);
}
