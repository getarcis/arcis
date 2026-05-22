/**
 * V34 — GraphQL alias bomb + fragment cycle (improvements.md §1.2).
 *
 * Mirrors `tests/sanitizers/test_v34_graphql_extensions.py` in the
 * Python SDK; both SDKs must accept the same base corpus per
 * Pattern 7 (cross-SDK parity contract).
 */
import { describe, it, expect } from 'vitest';
import { inspectGraphqlQuery } from '../../src/sanitizers/graphql';

describe('V34: GraphQL alias bomb', () => {
  it('returns alias count on clean queries', () => {
    const q = 'query { u1: user(id: 1) { name } u2: user(id: 2) { name } }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(false);
    expect(result.aliases).toBeGreaterThanOrEqual(2);
  });

  it('passes alias counts under the default cap', () => {
    const parts: string[] = [];
    for (let i = 0; i < 30; i++) parts.push(`u${i}: user(id: ${i}) { name }`);
    const q = 'query { ' + parts.join(' ') + ' }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(false);
    expect(result.aliases).toBeGreaterThanOrEqual(25);
    expect(result.aliases).toBeLessThanOrEqual(35);
  });

  it('blocks alias counts over the default cap', () => {
    const parts: string[] = [];
    for (let i = 0; i < 75; i++) parts.push(`u${i}: user(id: ${i}) { name }`);
    const q = 'query { ' + parts.join(' ') + ' }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe('aliases');
    expect(result.aliases).toBeGreaterThan(50);
  });

  it('alias cap can be relaxed via maxAliases option', () => {
    const parts: string[] = [];
    for (let i = 0; i < 75; i++) parts.push(`u${i}: user(id: ${i}) { name }`);
    const q = 'query { ' + parts.join(' ') + ' }';
    const result = inspectGraphqlQuery(q, { maxAliases: 200 });
    expect(result.blocked).toBe(false);
  });
});

describe('V34: GraphQL fragment cycle', () => {
  it('blocks direct self-referential fragment', () => {
    const q = 'fragment A on User { ...A name } query { me { ...A } }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe('fragment_cycle');
  });

  it('blocks indirect A→B→A cycle', () => {
    const q =
      'fragment A on User { ...B } ' +
      'fragment B on User { ...A } ' +
      'query { me { ...A } }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe('fragment_cycle');
  });

  it('passes acyclic fragments', () => {
    const q =
      'fragment A on User { ...B name } ' +
      'fragment B on User { email } ' +
      'query { me { ...A } }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(false);
  });

  it('cycle check can be disabled via blockFragmentCycles option', () => {
    const q = 'fragment A on User { ...A name } query { me { ...A } }';
    const result = inspectGraphqlQuery(q, { blockFragmentCycles: false });
    expect(
      result.blocked === false || result.reason !== 'fragment_cycle',
    ).toBe(true);
  });

  it('query with no fragments has no cycle', () => {
    const q = 'query { user(id: 1) { name email } }';
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(false);
  });
});

describe('V34: precedence (depth → introspection → aliases → fragment_cycle → length)', () => {
  it('depth beats aliases', () => {
    const deep = '{ ' + 'a: x { '.repeat(15) + '}'.repeat(15);
    const result = inspectGraphqlQuery(deep);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe('depth');
  });

  it('aliases beat length', () => {
    const parts: string[] = [];
    for (let i = 0; i < 100; i++) parts.push(`u${i}: x`);
    const q = '{ ' + parts.join(' ') + ' }';
    expect(q.length).toBeLessThan(10000);
    const result = inspectGraphqlQuery(q);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe('aliases');
  });
});
