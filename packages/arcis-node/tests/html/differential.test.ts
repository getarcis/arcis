/**
 * Differential tests: the sanitizer against the real DOMPurify on jsdom, at
 * test time. Covers every fixture input, then a fresh seeded fuzz set (a
 * different seed from the fixture generator) under several configurations.
 */
import { describe, expect, it } from 'vitest';
import { type HtmlSanitizerConfig, sanitizeHtmlDetailed } from '../../src/html';
import { FUZZ_CONFIGS, fuzzInputs, referenceSanitize, toConfig, vectors } from './helpers';

interface Mismatch {
  input: string;
  ours: unknown;
  reference: unknown;
}

function compare(inputs: readonly string[], config: HtmlSanitizerConfig): Mismatch[] {
  const mismatches: Mismatch[] = [];
  for (const input of inputs) {
    const reference = referenceSanitize(input, config);
    const ours = sanitizeHtmlDetailed(input, config);
    if (ours.html !== reference.html) {
      mismatches.push({ input, ours: ours.html, reference: reference.html });
    } else if (JSON.stringify(ours.removed) !== JSON.stringify(reference.removed)) {
      mismatches.push({ input, ours: ours.removed, reference: reference.removed });
    }
  }
  return mismatches;
}

describe('HTML sanitizer matches DOMPurify on jsdom', () => {
  it('on every fixture input and config', () => {
    const mismatches = vectors.cases.flatMap((fixture) =>
      compare([fixture.input], toConfig(fixture.config)).map((m) => ({ id: fixture.id, ...m })),
    );
    expect(mismatches).toEqual([]);
  });

  const fixtureInputs = new Set(vectors.cases.map((c) => c.input));
  const inputs = fuzzInputs(0x5eed2026, 400, fixtureInputs);

  it('generates a fresh fuzz set', () => {
    expect(inputs).toHaveLength(400);
    expect(inputs.filter((input) => fixtureInputs.has(input))).toEqual([]);
  });

  it.each(FUZZ_CONFIGS.map((config) => [JSON.stringify(config), config] as const))(
    'on seeded fuzz input with config %s',
    (_name, config) => {
      expect(compare(inputs, config).slice(0, 5)).toEqual([]);
    },
  );
});
