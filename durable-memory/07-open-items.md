# 07 — Open items

- **musl build** for a fully static Linux binary with no NSS caveat (Alpine runner or `zig cc`). Today's Linux build is
  glibc-static: it resolves via `/etc/hosts` + DNS but warns at link time about `getaddrinfo`.
- **Windows**: the CI job builds with MinGW + MSYS perl; `ensure_config`, `Fs.write_private` (no chmod) and
  `system_roots` (Windows ROOT store) are written but only exercised where CI proves them (see 06).
- **Schema growth** (each is a new type plus a handful of methods): PKCS#12 export for browsers, CRL generation and
  `Cert.verify_chain(roots, intermediates)` using `X509_STORE_CTX` (today `verify_with` is a signature check only),
  OCSP request building, `Tls` session resumption/tickets, `EVP_PKEY` raw ECDH, X.509 name constraints.
- **`ssl.run(args)`**: run an OpenSSL CLI command from a script and capture its output. `lmssl_openssl_main` calls
  `exit()` on errors in several apps, so this needs a subprocess (re-exec of `argv[0]`) rather than a function call.
- **Connect timeout**: `Net.connect` uses the OS default (~2 min on Linux). A non-blocking connect with
  `BIO_socket_wait` would honour `net.timeout`.
- **Multiple bytecode files** per invocation (lmhtml accepts several): not needed for the examples.
- **Binary size**: 12.4 MB on Linux. `no-legacy`, `no-cmp`, `no-cms`... would trim it, at the price of CLI commands that
  make lmssl a worse `openssl`. Kept the default feature set.
