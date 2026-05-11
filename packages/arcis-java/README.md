# arcis-java

> Pre-alpha. Do not deploy.

This package is a skeleton for a future Java SDK of Arcis. It currently includes a single XSS sanitizer and configuration scaffold; framework adapters (Servlet filter, Spring Security, Jakarta middleware) are not yet implemented.

For production use today, pick one of the SDKs that ship full coverage:

- Node.js / TypeScript: [`@arcis/node`](https://www.npmjs.com/package/@arcis/node)
- Python: [`arcis`](https://pypi.org/project/arcis/)
- Go: [`github.com/GagancM/arcis`](https://pkg.go.dev/github.com/GagancM/arcis)

## What is here

- `Arcis.java` and `ArcisConfig.java`: builder-style config entry point.
- `XssSanitizer.java`: single sanitizer with remove-then-encode order.
- `SecurityThreatException.java`: exception type.
- One test file (`XssSanitizerTest.java`).

## What is not here

- No middleware / filter integrations.
- No CSRF, CORS, rate limit, headers, or input validation modules.
- No supply-chain audit or static-analysis CLI.
- No cross-SDK parity test coverage.

When this package gains a working middleware layer it will be re-evaluated against the same `spec/TEST_VECTORS.json` contract that Node, Python, and Go pass today. Until then, prefer the production-ready SDKs above.

## License

MIT.
