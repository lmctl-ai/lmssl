# Third-party notices

lmssl is distributed as one statically linked executable. It contains the following third-party code.

## OpenSSL 4.0.3

- Source: <https://github.com/openssl/openssl> (tag `openssl-4.0.3`, pinned by commit in `openssl.lock`; fetched into
  `third_party/openssl` at build time, never modified).
- License: Apache License 2.0. The full text is the `LICENSE` file at the root of this repository (identical to OpenSSL's
  `LICENSE.txt`).
- Contained in the binary: `libcrypto`, `libssl`, and the `openssl` command line applications (`apps/`), plus OpenSSL's
  stock `apps/openssl.cnf`, embedded and used only when the system has no OpenSSL configuration file.
- Copyright (c) 1998-2026 The OpenSSL Project Authors; Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson.

## lmcode-cpp (`cpp/dslvm.hpp`)

- Source: <https://github.com/lmctl-ai/lmcode-cpp>, vendored verbatim and pinned by SHA-256 in `sdk.lock`.
- License: MIT.

```
MIT License

Copyright (c) 2026 Lattice Systems LLC

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
