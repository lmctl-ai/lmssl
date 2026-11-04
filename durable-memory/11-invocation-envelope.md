# Invocation envelope (0.2.1)

SDK origin/main 93bddf1; staging compiler 0.2.460. Use InvocationResults to validate
metadata, load every part first, select/run/complete, stop at first error and emit
one terminal SDK frame. Exit 0 success, 2 CLI/metadata, 3 load/run, 4 APP_FAIL/output.
Native OpenSSL commands remain unchanged; ensure_config is not called by lmcode
or introspection. Dry mode performs no key generation, file or socket callbacks.

Keep --lmcode FILE ARG... compatibility; repeat --lmcode FILE ARG... for more
parts, with separate ssl.args() vectors. --json remains accepted but all lmcode
invocations now frame stdout. Out.line/text and diagnostics use stderr. Examples
run directly via run_lmcode(p, {args: ARGV}); private inputs are captured only in
tests. No renderers are used. The optional public HTTPS smoke stays opt-in.

Tests retain cryptographic vectors, certificates/CSR/chain/hostname checks,
0600 key permissions, local TLS/redirect/mTLS, native OpenSSL interoperability,
refusals and static linkage. Added builders, load-before-effects, per-part argv and UTF-8 source/data,
application phase, dry occupied-socket negative control and direct-source smoke.
Recording shim is compiled on every platform; Windows compiler uses npm .cmd.
All Python test text boundaries explicitly use UTF-8; captured text uses replace.
