/**
 * @module @arcis/node/validation/schema
 * Request validation middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { VALIDATION, ERRORS } from '../core/constants';
import type { ValidationSchema, FieldValidator } from '../core/types';
import { sanitizeString } from '../sanitizers';

/**
 * Create Express middleware for request validation.
 * Prevents mass assignment by only allowing fields defined in the schema.
 * 
 * @param schema - Validation schema defining expected fields
 * @param source - Request property to validate ('body', 'query', or 'params')
 * @returns Express middleware
 * 
 * @example
 * app.post('/users', validate({
 *   email: { type: 'email', required: true },
 *   name: { type: 'string', min: 2, max: 50 },
 *   age: { type: 'number', min: 0, max: 150 },
 *   role: { type: 'string', enum: ['user', 'admin'] }
 * }), handler);
 * 
 * @example
 * // Validate query params
 * app.get('/search', validate({
 *   q: { type: 'string', required: true, min: 1 },
 *   page: { type: 'number', min: 1 }
 * }, 'query'), handler);
 */
export function validate(
  schema: ValidationSchema,
  source: 'body' | 'query' | 'params' = 'body'
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const data = req[source] || {};
    const errors: string[] = [];
    const validated: Record<string, unknown> = {};

    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];
      const result = validateField(field, value, rules);
      
      if (result.errors.length > 0) {
        errors.push(...result.errors);
      } else if (result.value !== undefined) {
        validated[field] = result.value;
      }
    }

    if (errors.length > 0) {
      res.status(400).json({ errors });
      return;
    }

    // Replace with validated data (prevents mass assignment).
    // SECURITY: Express 5 makes req.body/query/params read-only. Use
    // defineProperty so this works on both Express 4 and 5; direct
    // assignment crashes Express 5 with TypeError.
    Object.defineProperty(req, source, {
      value: validated,
      writable: true,
      configurable: true,
      enumerable: true,
    });
    next();
  };
}

/**
 * Validate a single field against its rules.
 */
function validateField(
  field: string,
  value: unknown,
  rules: FieldValidator
): { value?: unknown; errors: string[] } {
  const errors: string[] = [];

  // Required check
  if (rules.required && (value === undefined || value === null || value === '')) {
    errors.push(ERRORS.VALIDATION.REQUIRED(field));
    return { errors };
  }

  // Skip optional empty fields
  if (value === undefined || value === null) {
    return { errors: [] };
  }

  let typedValue: unknown = value;
  let isValid = true;

  // Type validation and coercion
  switch (rules.type) {
    case 'string':
      if (typeof value !== 'string') {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, 'string'));
        isValid = false;
        break;
      }
      if (rules.min !== undefined && value.length < rules.min) {
        errors.push(ERRORS.VALIDATION.MIN_LENGTH(field, rules.min));
        isValid = false;
      }
      if (rules.max !== undefined && value.length > rules.max) {
        errors.push(ERRORS.VALIDATION.MAX_LENGTH(field, rules.max));
        isValid = false;
      }
      if (rules.pattern && !rules.pattern.test(value)) {
        errors.push(ERRORS.VALIDATION.INVALID_FORMAT(field));
        isValid = false;
      }
      // Enum check runs before sanitization so the raw value is compared.
      // Sanitizing first could silently modify the value and cause a mismatch
      // with enum entries that contain characters the sanitizer would strip.
      if (isValid && rules.enum && !rules.enum.includes(value)) {
        errors.push(ERRORS.VALIDATION.INVALID_ENUM(field, rules.enum));
        isValid = false;
      }
      if (isValid && rules.sanitize !== false) {
        typedValue = sanitizeString(value);
      }
      break;

    case 'number':
      typedValue = Number(value);
      if (isNaN(typedValue as number)) {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, 'number'));
        isValid = false;
        break;
      }
      if (rules.min !== undefined && (typedValue as number) < rules.min) {
        errors.push(ERRORS.VALIDATION.MIN_VALUE(field, rules.min));
        isValid = false;
      }
      if (rules.max !== undefined && (typedValue as number) > rules.max) {
        errors.push(ERRORS.VALIDATION.MAX_VALUE(field, rules.max));
        isValid = false;
      }
      break;

    case 'boolean':
      if (value === 'true' || value === true || value === 1 || value === '1') {
        typedValue = true;
      } else if (value === 'false' || value === false || value === 0 || value === '0') {
        typedValue = false;
      } else {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, 'boolean'));
        isValid = false;
      }
      break;

    case 'email':
      if (!VALIDATION.EMAIL.test(String(value))) {
        errors.push(ERRORS.VALIDATION.INVALID_EMAIL(field));
        isValid = false;
      }
      if (isValid) {
        typedValue = sanitizeString(String(value).toLowerCase().trim());
      }
      break;

    case 'url':
      if (!VALIDATION.URL.test(String(value))) {
        errors.push(ERRORS.VALIDATION.INVALID_URL(field));
        isValid = false;
      }
      if (isValid) {
        typedValue = sanitizeString(String(value));
      }
      break;

    case 'uuid':
      if (!VALIDATION.UUID.test(String(value))) {
        errors.push(ERRORS.VALIDATION.INVALID_UUID(field));
        isValid = false;
      }
      break;

    case 'array':
      if (!Array.isArray(value)) {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, 'array'));
        isValid = false;
        break;
      }
      if (rules.min !== undefined && value.length < rules.min) {
        errors.push(ERRORS.VALIDATION.MIN_ITEMS(field, rules.min));
        isValid = false;
      }
      if (rules.max !== undefined && value.length > rules.max) {
        errors.push(ERRORS.VALIDATION.MAX_ITEMS(field, rules.max));
        isValid = false;
      }
      break;

    case 'object':
      if (typeof value !== 'object' || Array.isArray(value) || value === null) {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, 'object'));
        isValid = false;
      }
      break;
  }

  // Enum validation for non-string types (strings check enum before sanitizing above).
  if (isValid && rules.enum && rules.type !== 'string' && !rules.enum.includes(typedValue)) {
    errors.push(ERRORS.VALIDATION.INVALID_ENUM(field, rules.enum));
    isValid = false;
  }

  // Custom validation
  if (isValid && rules.custom) {
    const customResult = rules.custom(typedValue);
    if (customResult === undefined) {
      throw new TypeError(
        `Custom validator for field "${field}" returned undefined. ` +
        'Return true to pass, false to fail, or a string error message.'
      );
    }
    if (customResult !== true) {
      errors.push(typeof customResult === 'string' && customResult.length > 0 ? customResult : `${field} is invalid`);
      isValid = false;
    }
  }

  return {
    value: isValid ? typedValue : undefined,
    errors,
  };
}

/**
 * Alias for validate
 * @see validate
 */
export const createValidator = validate;
