# Third-party licenses

Arcis is MIT-licensed (see `LICENSE`). This file lists upstream code or data Arcis bundles or directly adapts, with the attribution each upstream license requires.

> **Attribution rule of thumb.** MIT, BSD-2, BSD-3, ISC, and Apache 2.0 all require preserving the upstream copyright notice and full license text in any distribution. "Free to use" does NOT mean "free to use without credit." Apache 2.0 additionally requires passing through any upstream `NOTICE` file unchanged.

## Current third-party content

### `packages/core/well-known-bots.json`

Originally derived from the [arcjet/well-known-bots](https://github.com/arcjet/well-known-bots) corpus.

- **Upstream license:** MIT
- **Upstream:** https://github.com/arcjet/well-known-bots
- **Use in Arcis:** entries copied + extended. The 15 Arcis-specific additions (Selenium, Puppeteer, Playwright, Cypress, WebDriver, headless browser fakes) are net-new; the remaining 635 entries are derived from the upstream corpus.

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
