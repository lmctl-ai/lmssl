# 02 — Static OpenSSL build

## Pinning

`openssl.lock` holds `repo`, `tag` and `commit` (the peeled tag commit). `scripts/sync-openssl.sh` shallow-clones the tag
into `third_party/openssl` (git-ignored) and fails if `HEAD` differs from the lock; `--update TAG` re-pins. This mirrors
`sdk.lock`/`sync-sdk.sh` for the SDK header. CI and `test.sh` both verify the pin.

## Configure flags (scripts/build-openssl.sh)

```
perl Configure [mingw64 on Windows] no-shared no-dso no-tests no-docs no-module no-afalgeng enable-ssl-trace --libdir=lib [-static on Linux]
```

- `no-shared no-dso no-module`: static libraries only, providers (default, legacy) compiled in, nothing `dlopen`ed at run time.
- `enable-ssl-trace`: gives `SSL_trace`, which `TlsCtx.trace(true)` uses to record handshake messages.
- `no-tests no-docs`: faster, smaller tree. `no-afalgeng`: avoids the Linux AF_ALG engine (needs kernel headers).
- Build is out of tree in `build/openssl`; a first full build is ~35 s on 4 cores (Linux x64), ~12.4 MB final binary.

## Reusing apps/ without patching OpenSSL

OpenSSL builds the CLI from `apps/openssl.c` (which defines `main`), ~50 `apps/*.c` command implementations, the
generated `apps/progs.c` command table, and `apps/lib/*.c` helpers (`libapps.a`). lmssl needs all of it except `main`.

`scripts/build-openssl.sh`:
1. `make build_libs` and `make apps/openssl` (the stock link, which also proves the tree is healthy).
2. Deletes `apps/openssl-bin-openssl.o` and rebuilds only that object with `CPPFLAGS=-Dmain=lmssl_openssl_main` on the
   `make` command line. A command-line variable overrides the Makefile's empty `CPPFLAGS` for that one invocation.
3. Archives every `apps/openssl-bin-*.o` and `apps/lib/openssl-bin-*.o` into `liblmssl_cli.a`.

`cmake/openssl.cmake` runs the script as one `add_custom_command` (outputs: the four archives) and exposes an INTERFACE
target `lmssl_openssl_apps` linking `liblmssl_cli.a apps/libapps.a libssl.a libcrypto.a` plus platform libraries
(`ws2_32 crypt32 user32 advapi32 gdi32` on Windows, `Threads` + `dl` elsewhere). Link order matters: the CLI objects
reference `libapps`, which references `libssl`, which references `libcrypto`.

Why not `-Dmain=` for the whole OpenSSL build? It would also rewrite identifiers in libcrypto; renaming one object is
exact and keeps `apps/` byte-for-byte upstream.

## Static linking caveats

- **glibc.** `getaddrinfo`/`gethostbyname` in a fully static glibc binary print a linker warning (they load NSS shared
  libraries at run time for non-DNS sources). Name resolution via `/etc/hosts` and DNS works (the examples resolve
  `localhost` and `google.com`), but a machine with exotic NSS modules and a different glibc may fail to resolve. A musl
  build (Alpine) would remove the caveat; it is listed in 07.
- **macOS.** Apple does not support fully static executables; the binary links only the system libraries
  (`libSystem`, `libc++`) that every macOS install has, and no third-party library.
- **Windows.** MinGW-w64 with `-static -static-libgcc -static-libstdc++`; system DLLs only (`ws2_32`, `crypt32`, ...).

## Trust roots

A static OpenSSL has no `OPENSSLDIR/certs`. `TlsCtx.system_roots()` finds one bundle: `$SSL_CERT_FILE`, then
`/etc/ssl/certs/ca-certificates.crt` (Debian), `/etc/pki/tls/certs/ca-bundle.crt` (RHEL), `/etc/ssl/ca-bundle.pem`
(SUSE), `/etc/ssl/cert.pem` (macOS, Alpine, BSD), `/usr/local/share/certs/ca-root-nss.crt` (FreeBSD). On Windows it
enumerates the `ROOT` store with `CertEnumCertificatesInStore` and adds each to the `X509_STORE`. `client_ctx()` itself
starts with **no** trust anchors, so a script that forgets to choose a trust source fails closed (the
`tests/fail-trust.lms` case).

## OpenSSL 4.0 API notes hit while porting

- `X509_get_subject_name` / `X509_REQ_get_subject_name` return `const X509_NAME *`: build a name with `X509_NAME_new`
  and `X509_set_subject_name` instead of filling the returned pointer.
- `SSL_set1_host` and `X509_cmp_current_time` are deprecated: use `X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), ...)`
  and `ASN1_TIME_cmp_time_t`.
- Default TLS 1.3 key exchange is the hybrid `X25519MLKEM768`; it makes ClientHello ~1.5 KB, visible in the trace.
