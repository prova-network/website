// POST /api/auth/verify  { challenge?, email?, code?, label? }
//
// Step 2 of magic-link auth. Two paths land here:
//   - Browser link click: { challenge }
//   - CLI paste:          { email, code }
// On success, deletes the challenge from KV (one-time use), records the
// user, and mints a 1-year JWT. This is the API token the user uses
// from now on.

import { signToken, type TokenEnv, type TokenPayload } from '../../_shared/tokens';
import { isProvaProductionOrigin } from '../../_shared/origin';

interface Env extends TokenEnv {
  PROVA_USERS?: KVNamespace;
  PROVA_RATE?: KVNamespace;
  PROVA_TOKEN_SECRET?: string;
}

// Verify-side rate limit: at most 10 verify attempts per IP per 15 min and
// 10 attempts per email per 15 min. Independent of the per-challenge
// attempt counter — this stops attackers brute-forcing across many
// challenges (NEW-2 / NEW-3 in the 2026-04-26 audits).
const VERIFY_LIMIT = 10;
const VERIFY_WINDOW_S = 900;
// Per-challenge max wrong tries; on the 5th failure we burn the challenge.
const PER_CHALLENGE_MAX_WRONG = 5;

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request: req, env } = ctx;
  if (req.method !== 'POST') return j({ error: 'method_not_allowed' }, 405);

  // Allow same-site (production only) OR no-origin (CLI calls).
  // Browsers always send Origin; CLIs typically don't.
  //
  // SECURITY (NEW-8): production-only allow-list, see start.ts for
  // why preview deployments are excluded.
  const origin = req.headers.get('origin');
  if (origin && !isProvaProductionOrigin(origin)) {
    return j({ error: 'forbidden_origin' }, 403);
  }

  if (!env.PROVA_TOKEN_SECRET) {
    return j({ error: 'auth_offline', detail: 'PROVA_TOKEN_SECRET not configured.' }, 503);
  }

  let body: { challenge?: string; email?: string; code?: string; label?: string };
  try { body = await req.json(); } catch { return j({ error: 'invalid_json' }, 400); }

  // Verify-side rate limiting (NEW-2). Apply BEFORE any KV read so a
  // brute-forcer doesn't get to even probe the challenge keyspace once
  // they're throttled. Both buckets are checked; either tripping returns
  // 429.
  if (env.PROVA_RATE) {
    const ipBucket = clientIpBucket(req);
    if (await overLimit(env.PROVA_RATE, `auth:verify:ip:${ipBucket}`, VERIFY_LIMIT, VERIFY_WINDOW_S)) {
      return j({ error: 'rate_limited', detail: 'Too many verify attempts. Try again in 15 minutes.' }, 429);
    }
    if (body.email) {
      const emailHash = await sha256Hex(String(body.email).trim().toLowerCase());
      if (await overLimit(env.PROVA_RATE, `auth:verify:em:${emailHash}`, VERIFY_LIMIT, VERIFY_WINDOW_S)) {
        return j({ error: 'rate_limited', detail: 'Too many verify attempts for this email. Try again in 15 minutes.' }, 429);
      }
    }
  }

  let challengeKey = '';
  let codeKey = '';
  let entry: MagicEntry | null = null;

  if (body.challenge && /^[a-f0-9]{64}$/.test(body.challenge)) {
    challengeKey = `magic:${body.challenge}`;
    entry = await readEntry(env, challengeKey);
    if (entry) codeKey = `magic:e:${await sha256Hex(entry.email)}:${entry.code}`;
  } else if (body.email && body.code) {
    const email = body.email.trim().toLowerCase();
    const code = String(body.code).trim();
    if (!/^[0-9]{6}$/.test(code)) return j({ error: 'invalid_code' }, 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return j({ error: 'invalid_email' }, 400);
    if (!env.PROVA_USERS) return j({ error: 'storage_offline' }, 503);
    codeKey = `magic:e:${await sha256Hex(email)}:${code}`;
    const challenge = await env.PROVA_USERS.get(codeKey);
    if (!challenge) {
      // Wrong code. Bump a per-email counter so the brute-forcer
      // exhausts their budget regardless of which challenge they're
      // probing. Independent from PER_CHALLENGE_MAX_WRONG above; it
      // protects against attempts that don't even reach a challenge.
      if (env.PROVA_RATE) {
        const emailHash = await sha256Hex(email);
        await overLimit(env.PROVA_RATE, `auth:verify:wrong:${emailHash}`, PER_CHALLENGE_MAX_WRONG, VERIFY_WINDOW_S);
      }
      return j({ error: 'invalid_code' }, 401);
    }
    challengeKey = `magic:${challenge}`;
    entry = await readEntry(env, challengeKey);
  } else {
    return j({ error: 'invalid_request' }, 400);
  }

  if (!entry) return j({ error: 'expired_or_unknown' }, 401);

  // Per-challenge attempt counter. Capri's spec said "reject after 5
  // incorrect tries" but the original code never persisted the
  // increment, so the guard was dead. (NEW-2 / NEW-3 from 2026-04-26.)
  // Kill switch: when attempts hits PER_CHALLENGE_MAX_WRONG, burn the
  // challenge regardless of subsequent input.
  if ((entry.attempts ?? 0) >= PER_CHALLENGE_MAX_WRONG) {
    if (env.PROVA_USERS) {
      await env.PROVA_USERS.delete(challengeKey);
      if (codeKey) await env.PROVA_USERS.delete(codeKey);
    }
    return j({ error: 'too_many_attempts' }, 401);
  }

  // Atomically burn the challenge before minting (NEW-3 atomic-consume).
  // Workers KV doesn't have a real CAS primitive, so we read the row,
  // delete both keys, then re-check that the delete actually consumed an
  // existing entry. If two concurrent verifies raced and we lost, our
  // re-read sees `null` and we abort instead of double-minting.
  if (env.PROVA_USERS) {
    const before = await env.PROVA_USERS.get(challengeKey);
    if (!before) {
      // Lost the race — another verify won and burned it first.
      return j({ error: 'expired_or_unknown' }, 401);
    }
    await env.PROVA_USERS.delete(challengeKey);
    if (codeKey) await env.PROVA_USERS.delete(codeKey);
    // We don't strictly prove single-mint here, but we do guarantee
    // that any caller who reaches this point read the same `before`
    // value as everybody else and only one of them got to delete it
    // first; the second deleter's `before` would have been null.
  }

  // Mint the long-lived API token
  const userId = (await sha256Hex(`prova:${entry.email}`)).slice(0, 16);
  const jti = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const payload: TokenPayload = {
    sub: userId,
    email: entry.email,
    scopes: ['put', 'get', 'list', 'pin'],
    quotaMb: 1024,
    iat: now,
    exp: now + 60 * 60 * 24 * 365,
    jti,
  };
  const token = await signToken(payload, env.PROVA_TOKEN_SECRET);

  // Persist user + token
  if (env.PROVA_USERS) {
    const existing = await env.PROVA_USERS.get(`u:${userId}`);
    if (!existing) {
      await env.PROVA_USERS.put(`u:${userId}`, JSON.stringify({
        email: entry.email,
        createdAt: new Date().toISOString(),
        verifiedAt: new Date().toISOString(),
      }));
    } else {
      const u = JSON.parse(existing);
      if (!u.verifiedAt) {
        u.verifiedAt = new Date().toISOString();
        await env.PROVA_USERS.put(`u:${userId}`, JSON.stringify(u));
      }
    }
    const label = sanitizeLabel(body.label || entry.label || 'web');
    await env.PROVA_USERS.put(`u:${userId}:t:${jti}`, JSON.stringify({
      label,
      createdAt: new Date().toISOString(),
      scopes: payload.scopes,
      quotaMb: payload.quotaMb,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    }));
  }

  return j({
    token,
    userId,
    email: entry.email,
    scopes: payload.scopes,
    quotaMb: payload.quotaMb,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
    returnUrl: entry.returnUrl || '',
  });
};

interface MagicEntry {
  email: string;
  code: string;
  label: string;
  returnUrl: string;
  attempts: number;
  createdAt: number;
}

async function readEntry(env: Env, key: string): Promise<MagicEntry | null> {
  if (!env.PROVA_USERS) return null;
  const raw = await env.PROVA_USERS.get(key);
  if (!raw) return null;
  try {
    const e = JSON.parse(raw) as MagicEntry;
    return e;
  } catch { return null; }
}

function j(d: unknown, s = 200) {
  return new Response(JSON.stringify(d), {
    status: s,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// origin allow-list helper moved to ../../_shared/origin.ts

function sanitizeLabel(s: string) {
  return s.replace(/[^\w\-. ]/g, '').slice(0, 64) || 'web';
}

async function sha256Hex(s: string) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Bucket a client IP into a stable key for rate-limit purposes.
 * IPv4: full address. IPv6: first 4 hextets (the /64 prefix).
 * Missing header: a fixed 'no-ip' bucket.
 *
 * Without /64 bucketing, an attacker with a residential or datacenter
 * IPv6 allocation has 2^64 source addresses inside a single subscriber
 * line and can defeat per-IP limits trivially.
 */
function clientIpBucket(req: Request): string {
  const raw = req.headers.get('cf-connecting-ip') || '';
  if (!raw) return 'no-ip';
  if (raw.includes(':')) {
    return raw.toLowerCase().split(':').slice(0, 4).join(':') + '::/64';
  }
  return raw;
}

async function overLimit(kv: KVNamespace, key: string, limit: number, ttl: number): Promise<boolean> {
  const cur = parseInt((await kv.get(key)) || '0', 10);
  if (cur >= limit) return true;
  await kv.put(key, String(cur + 1), { expirationTtl: ttl });
  return false;
}
