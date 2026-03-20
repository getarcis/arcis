/**
 * NoSQL Injection Sanitizer Tests
 * Tests for src/sanitizers/nosql.ts
 */

import { describe, it, expect } from 'vitest';
import { isDangerousNoSqlKey, detectNoSqlInjection, getDangerousOperators } from '../../src/sanitizers/nosql';

describe('isDangerousNoSqlKey', () => {
  describe('Query Operators', () => {
    it('should detect $gt operator', () => {
      expect(isDangerousNoSqlKey('$gt')).toBe(true);
    });

    it('should detect $gte operator', () => {
      expect(isDangerousNoSqlKey('$gte')).toBe(true);
    });

    it('should detect $lt operator', () => {
      expect(isDangerousNoSqlKey('$lt')).toBe(true);
    });

    it('should detect $lte operator', () => {
      expect(isDangerousNoSqlKey('$lte')).toBe(true);
    });

    it('should detect $ne operator', () => {
      expect(isDangerousNoSqlKey('$ne')).toBe(true);
    });

    it('should detect $eq operator', () => {
      expect(isDangerousNoSqlKey('$eq')).toBe(true);
    });

    it('should detect $in operator', () => {
      expect(isDangerousNoSqlKey('$in')).toBe(true);
    });

    it('should detect $nin operator', () => {
      expect(isDangerousNoSqlKey('$nin')).toBe(true);
    });
  });

  describe('Logical Operators', () => {
    it('should detect $or operator', () => {
      expect(isDangerousNoSqlKey('$or')).toBe(true);
    });

    it('should detect $and operator', () => {
      expect(isDangerousNoSqlKey('$and')).toBe(true);
    });

    it('should detect $not operator', () => {
      expect(isDangerousNoSqlKey('$not')).toBe(true);
    });

    it('should detect $nor operator', () => {
      expect(isDangerousNoSqlKey('$nor')).toBe(true);
    });
  });

  describe('Evaluation Operators', () => {
    it('should detect $where operator', () => {
      expect(isDangerousNoSqlKey('$where')).toBe(true);
    });

    it('should detect $regex operator', () => {
      expect(isDangerousNoSqlKey('$regex')).toBe(true);
    });

    it('should detect $expr operator', () => {
      expect(isDangerousNoSqlKey('$expr')).toBe(true);
    });

    it('should detect $jsonSchema operator', () => {
      expect(isDangerousNoSqlKey('$jsonSchema')).toBe(true);
    });

    it('should detect $mod operator', () => {
      expect(isDangerousNoSqlKey('$mod')).toBe(true);
    });

    it('should detect $text operator', () => {
      expect(isDangerousNoSqlKey('$text')).toBe(true);
    });
  });

  describe('JS Execution Operators', () => {
    it('should detect $function operator', () => {
      expect(isDangerousNoSqlKey('$function')).toBe(true);
    });

    it('should detect $accumulator operator', () => {
      expect(isDangerousNoSqlKey('$accumulator')).toBe(true);
    });
  });

  describe('Array Operators', () => {
    it('should detect $elemMatch operator', () => {
      expect(isDangerousNoSqlKey('$elemMatch')).toBe(true);
    });

    it('should detect $all operator', () => {
      expect(isDangerousNoSqlKey('$all')).toBe(true);
    });

    it('should detect $size operator', () => {
      expect(isDangerousNoSqlKey('$size')).toBe(true);
    });
  });

  describe('Aggregation Pipeline Operators', () => {
    it('should detect $lookup operator', () => {
      expect(isDangerousNoSqlKey('$lookup')).toBe(true);
    });

    it('should detect $match operator', () => {
      expect(isDangerousNoSqlKey('$match')).toBe(true);
    });

    it('should detect $project operator', () => {
      expect(isDangerousNoSqlKey('$project')).toBe(true);
    });

    it('should detect $group operator', () => {
      expect(isDangerousNoSqlKey('$group')).toBe(true);
    });

    it('should detect $addFields operator', () => {
      expect(isDangerousNoSqlKey('$addFields')).toBe(true);
    });

    it('should detect $replaceRoot operator', () => {
      expect(isDangerousNoSqlKey('$replaceRoot')).toBe(true);
    });
  });

  describe('Safe Keys', () => {
    it('should allow normal field names', () => {
      expect(isDangerousNoSqlKey('name')).toBe(false);
    });

    it('should allow fields starting with underscore', () => {
      expect(isDangerousNoSqlKey('_id')).toBe(false);
    });

    it('should allow numeric strings', () => {
      expect(isDangerousNoSqlKey('123')).toBe(false);
    });

    it('should allow camelCase fields', () => {
      expect(isDangerousNoSqlKey('userName')).toBe(false);
    });
  });
});

describe('detectNoSqlInjection', () => {
  describe('Top-Level Detection', () => {
    it('should detect $gt at top level', () => {
      expect(detectNoSqlInjection({ $gt: '' })).toBe(true);
    });

    it('should detect $where at top level', () => {
      expect(detectNoSqlInjection({ $where: 'function() { return true; }' })).toBe(true);
    });

    it('should detect multiple operators', () => {
      expect(detectNoSqlInjection({ $ne: null, $or: [] })).toBe(true);
    });
  });

  describe('Nested Object Detection', () => {
    it('should detect operators in nested objects', () => {
      expect(detectNoSqlInjection({ user: { password: { $regex: '.*' } } })).toBe(true);
    });

    it('should detect operators deeply nested', () => {
      expect(detectNoSqlInjection({ 
        level1: { 
          level2: { 
            level3: { $gt: 0 } 
          } 
        } 
      })).toBe(true);
    });
  });

  describe('Array Detection', () => {
    it('should detect operators in arrays', () => {
      expect(detectNoSqlInjection([{ $gt: '' }])).toBe(true);
    });

    it('should detect operators in nested arrays', () => {
      expect(detectNoSqlInjection({ items: [{ price: { $gt: 0 } }] })).toBe(true);
    });
  });

  describe('Safe Objects', () => {
    it('should return false for safe objects', () => {
      expect(detectNoSqlInjection({ name: 'John', age: 30 })).toBe(false);
    });

    it('should return false for null', () => {
      expect(detectNoSqlInjection(null)).toBe(false);
    });

    it('should return false for primitives', () => {
      expect(detectNoSqlInjection('string')).toBe(false);
      expect(detectNoSqlInjection(123)).toBe(false);
      expect(detectNoSqlInjection(true)).toBe(false);
    });

    it('should return false for empty objects', () => {
      expect(detectNoSqlInjection({})).toBe(false);
    });
  });

  describe('Max Depth Protection', () => {
    it('should detect within default max depth', () => {
      // 9 levels of nesting, should be within default maxDepth of 10
      const deepObject = { a: { b: { c: { d: { e: { f: { g: { h: { $gt: '' } } } } } } } } };
      expect(detectNoSqlInjection(deepObject)).toBe(true);
    });

    it('should stop at max depth', () => {
      const deepObject = { a: { b: { c: { $gt: '' } } } };
      // With maxDepth of 2, should not detect at depth 3
      expect(detectNoSqlInjection(deepObject, 2)).toBe(false);
    });
  });
});

describe('getDangerousOperators', () => {
  it('should return an array', () => {
    const operators = getDangerousOperators();
    expect(Array.isArray(operators)).toBe(true);
  });

  it('should include common operators', () => {
    const operators = getDangerousOperators();
    expect(operators).toContain('$gt');
    expect(operators).toContain('$where');
    expect(operators).toContain('$regex');
  });

  it('should return strings starting with $', () => {
    const operators = getDangerousOperators();
    operators.forEach(op => {
      expect(op.startsWith('$')).toBe(true);
    });
  });
});
