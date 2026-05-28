/**
 * @module @arcis/node/nestjs
 *
 * NestJS adapter for Arcis.
 *
 * Two ways to wire this up:
 *
 * 1. Global functional middleware (zero NestJS knowledge required):
 *    ```ts
 *    // main.ts
 *    import { NestFactory } from '@nestjs/core';
 *    import { arcis } from '@arcis/node';
 *    const app = await NestFactory.create(AppModule);
 *    app.use(arcis({ block: true }));
 *    ```
 *
 * 2. DI-aware module + class middleware (per-route control):
 *    ```ts
 *    // app.module.ts
 *    import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
 *    import { ArcisModule, ArcisMiddleware } from '@arcis/node/nestjs';
 *
 *    @Module({ imports: [ArcisModule.forRoot({ block: true })] })
 *    export class AppModule implements NestModule {
 *      configure(consumer: MiddlewareConsumer) {
 *        consumer.apply(ArcisMiddleware).forRoutes('*');
 *      }
 *    }
 *    ```
 *
 * No runtime dependency on `@nestjs/common`: the only NestJS reference is a
 * type-only import erased at compile time. NestJS users already have
 * `@nestjs/common` installed; non-NestJS users pay nothing.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { CanActivate, DynamicModule, ExecutionContext } from '@nestjs/common';
import { arcis } from './main';
import type { ArcisOptions, ArcisMiddlewareStack } from '../core/types';

/** Injection token for `ArcisOptions` consumed by `ArcisMiddleware`'s factory. */
export const ARCIS_OPTIONS = Symbol('ARCIS_OPTIONS');

/**
 * NestJS-compatible class middleware. Implements the structural shape NestJS
 * expects (`.use(req, res, next)`) without importing `NestMiddleware` at
 * runtime. Internally builds the same handler stack as `arcis()` and walks it
 * sequentially, propagating errors and short-circuit responses correctly.
 */
export class ArcisMiddleware {
  private readonly handlers: ArcisMiddlewareStack;

  constructor(options: ArcisOptions = {}) {
    this.handlers = arcis(options);
  }

  use(req: Request, res: Response, next: NextFunction): void {
    const handlers = this.handlers;
    let i = 0;
    const run = (err?: unknown): void => {
      if (err !== undefined) {
        next(err as Parameters<NextFunction>[0]);
        return;
      }
      const handler: RequestHandler | undefined = handlers[i++];
      if (!handler) {
        next();
        return;
      }
      try {
        handler(req, res, run);
      } catch (caught) {
        next(caught as Parameters<NextFunction>[0]);
      }
    };
    run();
  }

  /** Release rate-limiter intervals etc. Call from `OnApplicationShutdown`. */
  close(): void {
    this.handlers.close();
  }
}

/**
 * NestJS Guard implementation of the Arcis stack.
 *
 * Class-middleware applied via `MiddlewareConsumer.apply().forRoutes()` does
 * not reliably short-circuit NestJS's controller pipeline when an inner
 * handler writes `res.status(403).end()` without calling Express's `next`.
 * The controller resolution path runs anyway and the controller's return
 * value overwrites the deny response. CI surfaced this with 0-of-8 attacks
 * blocked on the NestJS example using the `MiddlewareConsumer` pattern.
 *
 * `CanActivate` runs in the correct NestJS lifecycle slot (after body-parse,
 * before controller resolution) and is designed to deny via `return false`
 * or by writing the response directly. When an Arcis handler writes a 403,
 * the guard sees `res.headersSent === true` after it runs and returns
 * `false`, which NestJS treats as a denial without re-running the
 * controller. Successful traversal (no threats found) returns `true` and
 * NestJS proceeds to the controller with the mutated (sanitized) req.
 *
 * Recommended over `ArcisMiddleware` for NestJS apps that want deny-on-
 * detect behavior. `ArcisMiddleware` is retained for backward compat but
 * is best suited for sanitize-only / observation-only usage.
 *
 * Register globally via the `APP_GUARD` token:
 *
 * ```ts
 * import { APP_GUARD } from '@nestjs/core';
 * import { ArcisGuard } from '@arcis/node/nestjs';
 *
 * @Module({
 *   providers: [
 *     {
 *       provide: APP_GUARD,
 *       useFactory: () => new ArcisGuard({ block: true }),
 *     },
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
export class ArcisGuard implements CanActivate {
  private readonly handlers: ArcisMiddlewareStack;

  constructor(options: ArcisOptions = {}) {
    this.handlers = arcis(options);
  }

  canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    return new Promise((resolve, reject) => {
      const handlers = this.handlers;
      let i = 0;
      const run = (err?: unknown): void => {
        if (err !== undefined) {
          reject(err as Error);
          return;
        }
        if (res.headersSent) {
          // A prior handler wrote a terminal response (the sanitizer's
          // 403 or the limiter's 429). NestJS sees headersSent === true
          // and lets the response pass through; returning false denies
          // controller resolution.
          resolve(false);
          return;
        }
        const handler: RequestHandler | undefined = handlers[i++];
        if (!handler) {
          resolve(!res.headersSent);
          return;
        }
        let advanced = false;
        const wrappedNext = (innerErr?: unknown): void => {
          advanced = true;
          run(innerErr);
        };
        try {
          handler(req, res, wrappedNext);
        } catch (caught) {
          reject(caught as Error);
          return;
        }
        // Synchronous-handler post-check: the sanitizer / rate limiter
        // write res.status(...).json(...) and return without calling
        // next. After handler() returns, if next wasn't called but the
        // response was already written, the chain ended right here and
        // we can resolve immediately. Async handlers (that haven't
        // resolved yet) leave `advanced` false and `headersSent` false,
        // and we wait for them to call wrappedNext on their own.
        if (!advanced && res.headersSent) {
          resolve(false);
        }
      };
      run();
    });
  }

  /** Release rate-limiter intervals etc. Call from `OnApplicationShutdown`. */
  close(): void {
    this.handlers.close();
  }
}

/**
 * NestJS dynamic module. `ArcisModule.forRoot(options)` is the entry point.
 * Returns a plain `DynamicModule` literal so `@Module({})` is unnecessary on
 * `ArcisModule` itself; this keeps `@nestjs/common` purely a type-only import.
 *
 * Exports both `ArcisMiddleware` (for legacy `MiddlewareConsumer` consumers)
 * and `ArcisGuard` (recommended — actually denies attacks on detect).
 */
export class ArcisModule {
  static forRoot(options: ArcisOptions = {}): DynamicModule {
    return {
      module: ArcisModule,
      providers: [
        { provide: ARCIS_OPTIONS, useValue: options },
        {
          provide: ArcisMiddleware,
          useFactory: (opts: ArcisOptions) => new ArcisMiddleware(opts),
          inject: [ARCIS_OPTIONS],
        },
        {
          provide: ArcisGuard,
          useFactory: (opts: ArcisOptions) => new ArcisGuard(opts),
          inject: [ARCIS_OPTIONS],
        },
      ],
      exports: [ArcisMiddleware, ArcisGuard],
    };
  }
}

export default ArcisModule;
