# Examples

Each `.lms` file is a normal lmscript file whose `_dsl_` block is compiled to bytecode and run by `lmssl --lmcode`.
The header comment of each file shows the equivalent `openssl` command line and the compile/run commands.

- `selfsigned-wildcard.lms` Generate a key and a self-signed wildcard certificate (`*.example.test`), print what ends up in it, and check which host names it covers. Equivalent of `openssl req -x509 -addext subjectAltName=...`.
- `ca-and-leaf.lms` A root CA, a server CSR with SANs, a leaf certificate signed by the CA, and the checks a verifier makes (including a look-alike CA that must not validate it).
- `crypto-basics.lms` Digests, HMAC, PBKDF2, AES-256-GCM / ChaCha20-Poly1305 and Ed25519 / ECDSA signatures, with published test vectors checked in the script.
- `https-steps.lms` One HTTPS request split into DNS, TCP, TLS handshake (with the handshake messages), certificate chain and verification, HTTP status and headers; follows redirects (`google.com` -> `www.google.com`).
- `serve-https.lms` A small HTTPS server with its own self-signed certificate, to see the other side of the handshake and to run `https-steps.lms` without a network.

Offline walk-through of the last two, in two terminals:

```sh
lmscript examples/serve-https.lms build/serve.dslb && lmscript examples/https-steps.lms build/steps.dslb
lmssl --lmcode build/serve.dslb 0 2 build/server              # prints the port, serves 2 requests
lmssl --lmcode build/steps.dslb localhost "$(cat build/server/port)" /old build/server/cert.pem
```

`./test.sh` compiles and runs all of them and cross-checks the output with the `openssl` half of the same binary
(`verify`, `x509`, `req -verify`, `s_client`).
