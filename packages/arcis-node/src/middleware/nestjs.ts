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
import type { DynamicModule } from '@nestjs/common';
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
 * NestJS dynamic module. `ArcisModule.forRoot(options)` is the entry point.
 * Returns a plain `DynamicModule` literal so `@Module({})` is unnecessary on
 * `ArcisModule` itself; this keeps `@nestjs/common` purely a type-only import.
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
      ],
      exports: [ArcisMiddleware],
    };
  }
}

export default ArcisModule;
