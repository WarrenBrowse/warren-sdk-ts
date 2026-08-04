/**
 * Product anchors resolved for the release channel this build targets.
 *
 * `WARREN_PRODUCT_ENV` picks the channel (`prod` when unset). tsup replaces the
 * identifier with a string literal at build time, so a published bundle carries
 * its channel baked in; when the define is absent (source run through vitest,
 * an unbundled Node script) the same variable is read from the process
 * environment instead. An explicit `baseUrl`/`apiBase` passed by the caller
 * still wins over these defaults.
 */

declare const WARREN_PRODUCT_ENV: string | undefined;

export type ProductChannel = 'prod' | 'beta';

/**
 * API base of each channel. `api.beta` and `api.warrenbrowse.com` resolve to
 * the same box today, so a wrong binding stays invisible until production
 * splits off and silently steals the client.
 */
export const API_BASE_URL_BY_CHANNEL: Readonly<Record<ProductChannel, string>> = Object.freeze({
  prod: 'https://api.warrenbrowse.com',
  beta: 'https://api.beta.warrenbrowse.com',
});

/** Throws rather than falling back to prod: a typo must not ship as prod. */
export function resolveProductChannel(value: string | undefined | null): ProductChannel {
  const raw = (value ?? '').trim();
  if (raw === '' || raw === 'prod') return 'prod';
  if (raw === 'beta') return 'beta';
  throw new Error(`WARREN_PRODUCT_ENV must be prod or beta (or unset for prod), got: ${raw}`);
}

function selector(): string | undefined {
  if (typeof WARREN_PRODUCT_ENV === 'string') return WARREN_PRODUCT_ENV;
  return typeof process === 'undefined' ? undefined : process.env?.WARREN_PRODUCT_ENV;
}

/** The channel this build targets. */
export const productChannel: ProductChannel = resolveProductChannel(selector());

/** Compiled default API base URL, the one every consumer falls back to. */
export const apiBaseUrl: string = API_BASE_URL_BY_CHANNEL[productChannel];
