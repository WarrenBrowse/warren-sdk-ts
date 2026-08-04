import { describe, expect, it } from 'vitest';
import {
  API_BASE_URL_BY_CHANNEL,
  apiBaseUrl,
  productChannel,
  resolveProductChannel,
} from '../src/product.js';

describe('release channel anchors', () => {
  it('pins the API base of every channel', () => {
    expect(API_BASE_URL_BY_CHANNEL.prod).toBe('https://api.warrenbrowse.com');
    expect(API_BASE_URL_BY_CHANNEL.beta).toBe('https://api.beta.warrenbrowse.com');
  });

  it('never lets beta share the prod host', () => {
    // Both names resolve to the same box today, so a wrong binding would stay
    // invisible until production splits off.
    expect(API_BASE_URL_BY_CHANNEL.beta).not.toBe(API_BASE_URL_BY_CHANNEL.prod);
  });

  it('defaults to prod when the selector is unset or empty', () => {
    expect(resolveProductChannel(undefined)).toBe('prod');
    expect(resolveProductChannel(null)).toBe('prod');
    expect(resolveProductChannel('  ')).toBe('prod');
    expect(resolveProductChannel('prod')).toBe('prod');
  });

  it('selects beta only on an explicit beta selector', () => {
    expect(resolveProductChannel('beta')).toBe('beta');
  });

  it('rejects an unknown selector instead of falling back to prod', () => {
    expect(() => resolveProductChannel('staging')).toThrow(
      /WARREN_PRODUCT_ENV must be prod or beta/,
    );
  });

  it('exposes the compiled anchor of the selected channel', () => {
    expect(apiBaseUrl).toBe(API_BASE_URL_BY_CHANNEL[productChannel]);
    expect(productChannel).toBe(resolveProductChannel(process.env.WARREN_PRODUCT_ENV));
  });
});
