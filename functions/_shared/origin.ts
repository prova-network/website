// Origin allow-list helpers shared by auth-sensitive endpoints.
//
// SECURITY (NEW-8 in 2026-04-26 audit): the previous helper accepted
// any subdomain of `prova-network.pages.dev`, including PR-preview
// builds. Cloudflare Pages applies the same secret bindings (notably
// `PROVA_TOKEN_SECRET`) to preview deployments by default, so a
// contributor's WIP branch could call /auth/start with a forged
// origin header that matched `*.prova-network.pages.dev` and mint
// tokens for arbitrary emails using the production secret.
//
// We split the allow-list into two tiers:
//
//   isProvaProductionOrigin()
//     Only the canonical prod hosts. Use this for endpoints that
//     have access to long-lived auth state (sign-in flow, token
//     management). Preview deployments are NOT trusted for these.
//
//   isProvaAnyOrigin()
//     Production + Pages preview subdomains. Use this for endpoints
//     where preview-deployment access is acceptable (read-only /
//     non-state-mutating endpoints).
//
// If a preview deployment needs to test the auth flow, configure it
// with a separate `PROVA_TOKEN_SECRET` and a separate `PROVA_RATE` /
// `PROVA_USERS` KV namespace, then re-include its hostname here
// explicitly.

const PRODUCTION_HOSTS = new Set<string>([
  'prova.network',
  'www.prova.network',
]);

/**
 * Allow only the canonical production hosts. Use this for any
 * endpoint that touches `PROVA_TOKEN_SECRET` or mints/revokes
 * long-lived tokens.
 */
export function isProvaProductionOrigin(s: string | null | undefined): boolean {
  if (!s) return false;
  try {
    const u = new URL(s);
    return u.protocol === 'https:' && PRODUCTION_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
}

/**
 * Allow production hosts plus Cloudflare Pages preview subdomains.
 * Use this for endpoints where allowing preview-deployment access
 * is acceptable (read-only marketing pages, public retrieval, abuse
 * intake). Do NOT use this for auth flows.
 */
export function isProvaAnyOrigin(s: string | null | undefined): boolean {
  if (!s) return false;
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:') return false;
    if (PRODUCTION_HOSTS.has(u.hostname)) return true;
    // Cloudflare Pages preview pattern. We require the suffix to
    // include the org segment (`prova-network`) so an attacker can't
    // register `evil.pages.dev` and pass.
    return u.hostname.endsWith('.prova-network.pages.dev');
  } catch {
    return false;
  }
}

/**
 * Convenience: extract the URL `protocol://host` of a string, or
 * empty string if it's not a parseable URL.
 */
export function originRoot(s: string | null | undefined): string {
  if (!s) return '';
  try {
    const u = new URL(s);
    return `${u.protocol}//${u.host}`;
  } catch {
    return '';
  }
}
