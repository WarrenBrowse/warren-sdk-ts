import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The fatal-cause vocabulary is written three times by hand: the addon's
 * `FatalCauseJs` enum, the curated `index.d.ts` (CI never regenerates it: the
 * addon is not built there), and the facade's `ProxyFatalCause`. A variant the
 * addon sends but the typings omit reaches a consumer's exhaustive switch as a
 * value it was told cannot exist, so the three lists must stay equal.
 */
function source(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
}

function rustEnumVariants(rust: string, name: string): string[] {
  const body = rust.match(new RegExp(`pub enum ${name} \\{([\\s\\S]*?)\\n\\}`))?.[1];
  if (body === undefined) throw new Error(`enum ${name} not found`);
  return body
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => !line.startsWith('//'))
    .flatMap((line) => line.match(/^([A-Z]\w*),$/)?.[1] ?? []);
}

function tsUnionMembers(ts: string, name: string): string[] {
  const body = ts.match(new RegExp(`export type ${name} =([\\s\\S]*?);`))?.[1];
  if (body === undefined) throw new Error(`type ${name} not found`);
  const withoutComments = body.replace(/\/\*[\s\S]*?\*\//g, '');
  return [...withoutComments.matchAll(/'(\w+)'/g)].map((m) => m[1] as string);
}

describe('the fatal-cause vocabulary across the addon boundary', () => {
  const addon = rustEnumVariants(source('../native/warren-napi/src/lib.rs'), 'FatalCauseJs');

  it('names a network that routes no entry relay on the addon side', () => {
    expect(addon).toContain('NoReachableEntry');
  });

  it('types every cause the addon sends in the curated binding typings', () => {
    expect(tsUnionMembers(source('../native/warren-napi/index.d.ts'), 'FatalCauseJs')).toEqual(
      addon,
    );
  });

  it('types every cause the addon sends on the facade', () => {
    expect(tsUnionMembers(source('../src/proxy/tunnel.ts'), 'ProxyFatalCause')).toEqual(addon);
  });
});
