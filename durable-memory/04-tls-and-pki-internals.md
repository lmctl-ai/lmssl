# 04 — What each call does inside OpenSSL

A reading guide: DSL call -> libcrypto/libssl calls (all in `cpp/host.cpp`). Start here when you want to learn the
OpenSSL API from the examples.

## Keys

| DSL | OpenSSL |
| --- | --- |
| `ssl.gen_rsa(2048)` | `EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048)` |
| `ssl.gen_ec("P-256")` | `EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")`; `Key.curve()` reads `OSSL_PKEY_PARAM_GROUP_NAME` (prints `prime256v1`) |
| `ssl.gen_ed25519()` | `EVP_PKEY_Q_keygen(NULL, NULL, "ED25519")` |
| `key.pem()` / `save` | `PEM_write_bio_PrivateKey` (PKCS#8, unencrypted) into a memory `BIO`; `save` writes the file as mode 0600 |
| `key.save_encrypted(path, pass)` | `PEM_write_bio_PKCS8PrivateKey` with `EVP_aes_256_cbc()` |
| `ssl.load_key(path, pass)` | `PEM_read_bio_PrivateKey` with a password callback |
| `key.fingerprint()` | SHA-256 of `i2d_PUBKEY` (the SubjectPublicKeyInfo DER) |
| `key.sign("SHA256", data)` | `EVP_DigestSignInit` + one-shot `EVP_DigestSign`; for Ed25519 the digest is NULL |

## Certificates and CSRs

| DSL | OpenSSL |
| --- | --- |
| `ssl.new_cert(key, dn)` | `X509_new`, `X509_set_version(3)`, random serial, `X509_gmtime_adj` for validity, `X509_NAME_add_entry_by_txt` per DN part, `X509_set_pubkey` |
| `cert.san("DNS:a,IP:1.2.3.4")` / `ext(name, value)` | `X509V3_EXT_nconf_nid` (same syntax as `openssl.cnf` extension values) then `X509_add_ext`, replacing an existing extension of the same NID |
| `cert.ca(true)` | `basicConstraints = critical,CA:TRUE` and `keyUsage = critical,keyCertSign,cRLSign` |
| `cert.sign_self(key, "SHA256")` | `X509_set_issuer_name(subject)`, SKID `hash`, AKID `keyid:always`, `X509_sign` |
| `cert.sign_with(ca, cakey, d)` | issuer name from the CA certificate; `X509_check_private_key(ca, cakey)` first; AKID uses the CA's SKID |
| `ssl.new_csr` / `csr.san` / `csr.sign` | `X509_REQ_new`, `X509V3_EXT_conf_nid(subjectAltName)` into `X509_REQ_add_extensions`, `X509_REQ_sign` |
| `ssl.cert_from_csr(csr)` | `X509_REQ_verify`, copies subject, public key and `X509_REQ_get_extensions` (a real CA would filter these; the example CA adds its own `keyUsage`/`extendedKeyUsage`) |
| `cert.matches_host(h)` | `X509_check_host` / `X509_check_ip_asc`: wildcard `*` covers exactly one label, never the bare domain |
| `cert.verify_with(ca)` | `X509_verify(cert, X509_get0_pubkey(ca))`: a **signature check only**, no validity, name, or path logic |
| `cert.self_signed()` | `X509_self_signed(x, 1)` (also verifies the signature) |

## Sockets

`Net.connect` is `BIO_new_connect("host:port")` + `BIO_do_connect`. Using OpenSSL's BIO layer keeps the code identical on
POSIX and Windows (it initialises Winsock) and gives the same resolver the CLI uses. `Net.resolve` is `BIO_lookup_ex`;
`Net.listen` is `BIO_new_accept` with `BIO_BIND_REUSEADDR`, and `Listener.accept` is `BIO_do_accept` followed by `BIO_pop`
to detach the connected socket BIO. Timeouts are `SO_RCVTIMEO`/`SO_SNDTIMEO` on the descriptor; `BIO_read` then
returns -1 with `BIO_should_retry`, reported as "read timed out". Connect itself uses the OS default timeout.

## TLS

| DSL | OpenSSL |
| --- | --- |
| `ssl.client_ctx()` | `SSL_CTX_new(TLS_client_method())`, min version TLS 1.2, `SSL_VERIFY_PEER`, `SSL_OP_IGNORE_UNEXPECTED_EOF` (HTTP/1.0-style `Connection: close` servers send no `close_notify`) |
| `ctx.min_version("TLSv1.3")` | `SSL_CTX_set_min_proto_version` |
| `ctx.ciphers` / `suites` / `groups` | `SSL_CTX_set_cipher_list` (TLS 1.2 names) / `SSL_CTX_set_ciphersuites` (TLS 1.3 names) / `SSL_CTX_set1_groups_list` |
| `ctx.alpn("h2,http/1.1")` | client: `SSL_CTX_set_alpn_protos` (length-prefixed wire list); server: `SSL_CTX_set_alpn_select_cb` + `SSL_select_next_proto` |
| `ctx.ca_file(path)` / `add_ca(cert)` / `system_roots()` | `SSL_CTX_load_verify_locations` / `X509_STORE_add_cert(SSL_CTX_get_cert_store())` / see 02 |
| `ctx.trace(true)` | per `SSL`: `SSL_set_msg_callback(ssl, SSL_trace)` with a memory `BIO` as the callback argument; `Tls.trace()` returns its contents |
| `ctx.connect(conn, host)` | `SSL_new`, SNI via `SSL_set_tlsext_host_name` (not for IP literals), host check via `X509_VERIFY_PARAM_set1_host` or `set1_ip_asc`, `SSL_set_bio(ssl, bio, bio)` (the SSL now owns the BIO), `SSL_connect` |
| `ctx.accept(conn)` | same without SNI/host, `SSL_accept` |
| `tls.version()` / `cipher()` / `group()` / `peer_sigalg()` / `alpn()` | `SSL_get_version` / `SSL_CIPHER_get_name(SSL_get_current_cipher)` / `SSL_get0_group_name` / `SSL_get0_peer_signature_name` / `SSL_get0_alpn_selected` |
| `tls.peer()` / `chain_at(i)` | `SSL_get1_peer_certificate` / `SSL_get_peer_cert_chain` with `X509_up_ref` (client side: the chain the server *sent*, leaf first; not the chain OpenSSL built) |
| `tls.verified()` / `verify_result()` | `SSL_get_verify_result` / `X509_verify_cert_error_string` |

Handshake failure text is assembled from the OpenSSL error queue plus the X509 verify result, e.g.
`TLS handshake failed: error:0A000086:SSL routines::certificate verify failed (certificate verify: self-signed certificate)`.

### Reading the trace

`tls.trace()` is the output of `SSL_trace`: for each record `Sent Record` / `Received Record`, header, and a decoded
handshake message. `https-steps.lms` keeps only lines containing `, Length=` (non-empty), which are the handshake
message headings: `ClientHello`, `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`.
Encrypted handshake messages are decoded after the traffic secrets exist, which is why TLS 1.3 shows them even though
a wire capture would not.

## Symmetric primitives

`Ssl.seal/open` are `EVP_CIPHER_fetch` + `EVP_CIPHER_CTX_ctrl(AEAD_SET_IVLEN)` + AAD through a null-output
`EVP_EncryptUpdate`, ciphertext, `EVP_EncryptFinal_ex`, then `AEAD_GET_TAG`. `open` sets the expected tag before
`EVP_DecryptFinal_ex` and reports a failed final as "authentication failed" without returning any plaintext.
`pbkdf2` is `PKCS5_PBKDF2_HMAC`; `hmac` is `EVP_Q_mac(..., "HMAC", ...)`; `digest` is `EVP_Digest` with a fetched `EVP_MD`.
Unknown algorithm names are errors, not defaults.
