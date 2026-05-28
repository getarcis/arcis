# Third-party licenses

Arcis is MIT-licensed (see `LICENSE`). This file lists upstream code or data Arcis bundles or directly adapts, with the attribution each upstream license requires.

> **Attribution rule of thumb.** MIT, BSD-2, BSD-3, ISC, and Apache 2.0 all require preserving the upstream copyright notice and full license text in any distribution. "Free to use" does NOT mean "free to use without credit." Apache 2.0 additionally requires passing through any upstream `NOTICE` file unchanged.

## Current third-party content

### `packages/core/bot-patterns.json` + `packages/core/well-known-bots.json`

The 695-entry SDK-loaded bot corpus (`bot-patterns.json` + bundled copies in each SDK) is composed of three sources:

1. The standalone [arcjet/well-known-bots](https://github.com/arcjet/well-known-bots) corpus (~635 entries).
2. 15 Arcis-specific additions (Selenium, Puppeteer, Playwright, Cypress, WebDriver, headless browser fakes).
3. 45 net-new entries merged in from monperrus/crawler-user-agents (see next section).

#### Source A: arcjet/well-known-bots

- **Upstream license:** MIT
- **Upstream:** https://github.com/arcjet/well-known-bots
- **Use in Arcis:** entries copied + extended into both `packages/core/well-known-bots.json` (standalone passthrough corpus) and `packages/core/bot-patterns.json` (active SDK corpus).

```
Copyright (c) 2024 Arcjet, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

#### Source B: monperrus/crawler-user-agents

- **Upstream license:** MIT
- **Upstream:** https://github.com/monperrus/crawler-user-agents
- **Use in Arcis:** 45 net-new entries merged into `bot-patterns.json` from the crawler-user-agents corpus on 2026-05-27. 602 entries were duplicates against existing patterns. The mapping script normalized their schema (`pattern` + `tags`) to our schema (`id` + `name` + `category` + `patterns`); each merged entry's `id` is prefixed `ext-` to keep the provenance traceable in the data.

```
The MIT License (MIT)

Copyright (c) 2017 Martin Monperrus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### `packages/arcis-{node,python,go}/sanitizers/prompt_injection*`

The prompt-injection signature library carries six rule shapes that were modeled on patterns we examined in two upstream prompt-injection projects. The Arcis regexes were written independently against the documented LLM template syntax (ChatML, Llama 2, guidance/handlebars are all publicly specified by their respective vendors) — these are not byte-for-byte copies — but the *shape* of what to look for, and several of the keywords in our extended verb set, were informed by upstream work and deserve credit.

#### Source C: protectai/rebuff

- **Upstream license:** Apache-2.0
- **Upstream:** https://github.com/protectai/rebuff
- **Use in Arcis:** the extended verb list in the `ignore-previous-instructions` rule (`skip`, `neglect`, `overlook`, `omit`) and the multi-word verb shapes in `instruction-bypass-phrases` (`pay no attention to`, `do not follow`, `do not obey`) were informed by Rebuff's combinatorial injection-keyword generator in `python-sdk/rebuff/detect_pi_heuristics.py`.

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

Copyright (c) Protect AI, contributors to Rebuff

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Full text: https://www.apache.org/licenses/LICENSE-2.0

#### Source D: deadbits/vigil-llm

- **Upstream license:** Apache-2.0
- **Upstream:** https://github.com/deadbits/vigil-llm
- **Use in Arcis:** the four prompt-template marker rules — `chatml-template-marker`, `llama2-system-marker`, `guidance-template-marker`, `markdown-system-link-spoof` — were informed by the YARA rules in `data/yara/system_instructions.yar` and `data/yara/instruction_bypass.yar`. We re-wrote the regexes from the public LLM template specs (OpenAI ChatML, Meta Llama 2, Microsoft guidance/handlebars) rather than copying the YARA pattern bytes.

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

Copyright (c) Adam M. Swanda, contributors to vigil-llm

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Full text: https://www.apache.org/licenses/LICENSE-2.0

### `packages/arcis-node/src/_third_party/rate-limit/*`

The internal limiter primitives in `packages/arcis-node/src/_third_party/rate-limit/` (`abstract.ts`, `memory.ts`, `memory-storage.ts`, `record.ts`, `bursty.ts`, `types.ts`) are a TypeScript port of a subset of the upstream `rate-limiter-flexible` Node.js library. The port covers the in-memory storage backend, the abstract limiter base, and the bursty composition pattern; we did not port the Redis/Postgres/MongoDB/etc. backends. Public surface in Arcis is the `bruteForceProtection` middleware (`packages/arcis-node/src/middleware/brute-force.ts`), which wires the limiter primitives into Express.

#### Source E: animir/node-rate-limiter-flexible

- **Upstream license:** ISC
- **Upstream:** https://github.com/animir/node-rate-limiter-flexible
- **Use in Arcis:** TypeScript port of `lib/RateLimiterAbstract.js`, `lib/RateLimiterMemory.js`, `lib/RateLimiterRes.js`, `lib/BurstyRateLimiter.js`, `lib/component/MemoryStorage/MemoryStorage.js`, and `lib/component/MemoryStorage/Record.js`. Class names renamed (`RateLimiterMemory` → `MemoryLimiter`, `RateLimiterRes` → `LimiterResult`, etc.) to fit Arcis naming, but the algorithm and rejection semantics match the original.

```
ISC License (ISC)

Copyright 2019 Roman Voloboev

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## How to add a new entry

When adopting any upstream code or data:

1. Identify the upstream license (MIT, Apache 2.0, BSD, ISC — anything else needs a separate decision).
2. Add a section above with: upstream URL, license name, what was adopted, and the full license text.
3. For Apache 2.0 specifically, also vendor the upstream `NOTICE` file under `NOTICES/` and reference it from this section.
4. For any data file (JSON corpus, pattern list, etc.) that the SDK loads at runtime, add a comment at the top of the file referencing this entry.

## Licenses Arcis avoids

- **GPL-2.0, GPL-3.0** — copyleft, would force Arcis itself under GPL.
- **AGPL-3.0** — network-use trigger, even worse for a library that runs on servers.
- **LGPL-3.0** — borderline on vendored libraries; awkward for npm/PyPI packaging.
- **SSPL** — non-OSI, MongoDB-specific.

If a dependency under one of these turns up in a v1.7+ adoption shortlist, the decision is "skip" or "rewrite the relevant logic from spec without copying the code."
