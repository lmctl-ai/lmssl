#include "host.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#endif

namespace lmssl {
namespace {

using dslvm::Args;
using dslvm::Value;
namespace fs = std::filesystem;

// ---------------------------------------------------------------- errors

// Drain OpenSSL's per-thread error queue into one readable string.
std::string ossl_errors() {
  std::string out;
  unsigned long e;
  char buf[256];
  while ((e = ERR_get_error()) != 0) {
    ERR_error_string_n(e, buf, sizeof buf);
    if (!out.empty()) out += "; ";
    out += buf;
  }
  return out;
}

[[noreturn]] void fail(const std::string &what) {
  std::string e = ossl_errors();
  throw std::runtime_error(e.empty() ? what : what + ": " + e);
}

// ---------------------------------------------------------------- RAII

template <class T, void (*F)(T *)> struct Free { void operator()(T *p) const { if (p) F(p); } };
using PKey = std::unique_ptr<EVP_PKEY, Free<EVP_PKEY, EVP_PKEY_free>>;
using X509p = std::unique_ptr<X509, Free<X509, X509_free>>;
using Reqp = std::unique_ptr<X509_REQ, Free<X509_REQ, X509_REQ_free>>;
using MdP = std::unique_ptr<EVP_MD, Free<EVP_MD, EVP_MD_free>>;
using CipherP = std::unique_ptr<EVP_CIPHER, Free<EVP_CIPHER, EVP_CIPHER_free>>;
struct BioFree { void operator()(BIO *b) const { if (b) BIO_free_all(b); } };
using Bio = std::unique_ptr<BIO, BioFree>;
struct CtxFree { void operator()(SSL_CTX *c) const { if (c) SSL_CTX_free(c); } };
using SslCtxP = std::unique_ptr<SSL_CTX, CtxFree>;
struct SslFree { void operator()(SSL *s) const { if (s) SSL_free(s); } };
using SslP = std::unique_ptr<SSL, SslFree>;

std::string bio_string(BIO *b) {
  char *p = nullptr;
  long n = BIO_get_mem_data(b, &p);
  return n > 0 ? std::string(p, static_cast<size_t>(n)) : std::string();
}

Bio mem_bio() {
  Bio b(BIO_new(BIO_s_mem()));
  if (!b) fail("BIO_new");
  return b;
}

// ---------------------------------------------------------------- helpers

std::string to_hex(const unsigned char *p, size_t n) {
  static const char d[] = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) { out += d[p[i] >> 4]; out += d[p[i] & 15]; }
  return out;
}
std::string to_hex(const std::string &s) { return to_hex(reinterpret_cast<const unsigned char *>(s.data()), s.size()); }

std::string from_hex(const std::string &h) {
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::string out;
  int hi = -1;
  for (char c : h) {
    if (c == ':' || c == ' ' || c == '\n') continue;
    int v = nib(c);
    if (v < 0) throw std::runtime_error("invalid hex digit");
    if (hi < 0) hi = v; else { out += static_cast<char>(hi * 16 + v); hi = -1; }
  }
  if (hi >= 0) throw std::runtime_error("odd number of hex digits");
  return out;
}

std::string colon_hex(const unsigned char *p, size_t n) {
  std::string out;
  static const char d[] = "0123456789ABCDEF";
  for (size_t i = 0; i < n; ++i) {
    if (i) out += ':';
    out += d[p[i] >> 4];
    out += d[p[i] & 15];
  }
  return out;
}

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64_encode(const std::string &in) {
  std::string out;
  size_t i = 0;
  while (i + 2 < in.size()) {
    unsigned v = (unsigned char)in[i] << 16 | (unsigned char)in[i + 1] << 8 | (unsigned char)in[i + 2];
    out += kB64[v >> 18]; out += kB64[(v >> 12) & 63]; out += kB64[(v >> 6) & 63]; out += kB64[v & 63];
    i += 3;
  }
  if (i + 1 == in.size()) {
    unsigned v = (unsigned char)in[i] << 16;
    out += kB64[v >> 18]; out += kB64[(v >> 12) & 63]; out += "==";
  } else if (i + 2 == in.size()) {
    unsigned v = (unsigned char)in[i] << 16 | (unsigned char)in[i + 1] << 8;
    out += kB64[v >> 18]; out += kB64[(v >> 12) & 63]; out += kB64[(v >> 6) & 63]; out += '=';
  }
  return out;
}
std::string b64_decode(const std::string &in) {
  std::string out;
  unsigned acc = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
    const char *p = c ? std::strchr(kB64, c) : nullptr;
    if (!p) throw std::runtime_error("invalid base64 character");
    acc = acc << 6 | static_cast<unsigned>(p - kB64);
    bits += 6;
    if (bits >= 8) { bits -= 8; out += static_cast<char>((acc >> bits) & 0xff); }
  }
  return out;
}

MdP fetch_md(const std::string &alg) {
  MdP md(EVP_MD_fetch(nullptr, alg.c_str(), nullptr));
  if (!md) fail("unknown digest '" + alg + "'");
  return md;
}

std::string iso_time(const ASN1_TIME *t) {
  std::tm tm{};
  if (!t || !ASN1_TIME_to_tm(t, &tm)) return "";
  char buf[32];
  std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

std::string name_string(const X509_NAME *n) {
  Bio b = mem_bio();
  X509_NAME_print_ex(b.get(), n, 0, ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_FN_SN);
  return bio_string(b.get());
}

// "CN=a,O=b" or "/CN=a/O=b" -> X509_NAME. A backslash escapes the next character.
void set_name(X509_NAME *name, const std::string &dn) {
  char sep = !dn.empty() && dn[0] == '/' ? '/' : ',';
  std::vector<std::string> parts(1);
  for (size_t i = (sep == '/' ? 1 : 0); i < dn.size(); ++i) {
    if (dn[i] == '\\' && i + 1 < dn.size()) parts.back() += dn[++i];
    else if (dn[i] == sep) parts.emplace_back();
    else parts.back() += dn[i];
  }
  for (auto &p : parts) {
    size_t eq = p.find('=');
    if (eq == std::string::npos || eq == 0) throw std::runtime_error("bad subject '" + dn + "': expected KEY=value pairs");
    std::string key = p.substr(0, eq), val = p.substr(eq + 1);
    while (!key.empty() && key.front() == ' ') key.erase(key.begin());
    while (!key.empty() && key.back() == ' ') key.pop_back();
    if (!X509_NAME_add_entry_by_txt(name, key.c_str(), MBSTRING_UTF8,
                                    reinterpret_cast<const unsigned char *>(val.c_str()), -1, -1, 0))
      fail("bad subject attribute '" + key + "'");
  }
}

// ---------------------------------------------------------------- object types

struct KeyObj { PKey key; };
struct CertObj { X509p x; };
struct CsrObj { Reqp req; std::vector<std::string> sans; };

// A byte stream with a read-ahead buffer; plain TCP and TLS share read_until/read_all.
struct Stream {
  std::string buf;
  bool eof = false;
  virtual ~Stream() = default;
  virtual int raw_read(char *p, int n) = 0;  // >0 bytes, 0 at end of stream; throws on error
  virtual int raw_write(const char *p, int n) = 0;

  void fill(size_t hint) {
    if (eof) return;
    char tmp[16384];
    int r = raw_read(tmp, static_cast<int>(std::min(hint, sizeof tmp)));
    if (r <= 0) eof = true; else buf.append(tmp, static_cast<size_t>(r));
  }
  std::string read(int64_t n) {
    if (n < 0) throw std::runtime_error("negative read size");
    if (buf.empty()) fill(static_cast<size_t>(n));
    size_t take = std::min<size_t>(static_cast<size_t>(n), buf.size());
    std::string out = buf.substr(0, take);
    buf.erase(0, take);
    return out;
  }
  // Returns up to and including `delim`; at end of stream returns whatever remains.
  std::string read_until(const std::string &delim, int64_t limit) {
    if (delim.empty()) throw std::runtime_error("empty delimiter");
    size_t from = 0;
    for (;;) {
      size_t at = buf.find(delim, from);
      if (at != std::string::npos) {
        std::string out = buf.substr(0, at + delim.size());
        buf.erase(0, at + delim.size());
        return out;
      }
      if (static_cast<int64_t>(buf.size()) > limit) throw std::runtime_error("delimiter not found within " + std::to_string(limit) + " bytes");
      from = buf.size() >= delim.size() ? buf.size() - delim.size() + 1 : 0;
      if (eof) { std::string out; out.swap(buf); return out; }
      fill(16384);
    }
  }
  std::string read_all(int64_t limit) {
    while (!eof) {
      if (static_cast<int64_t>(buf.size()) > limit) throw std::runtime_error("response larger than " + std::to_string(limit) + " bytes");
      fill(16384);
    }
    std::string out;
    out.swap(buf);
    return out;
  }
  int64_t write(const std::string &s) {
    size_t off = 0;
    while (off < s.size()) {
      int w = raw_write(s.data() + off, static_cast<int>(std::min<size_t>(s.size() - off, 1 << 20)));
      if (w <= 0) throw std::runtime_error("write failed");
      off += static_cast<size_t>(w);
    }
    return static_cast<int64_t>(s.size());
  }
};

std::string sock_name(int fd, bool peer) {
  sockaddr_storage ss{};
#ifdef _WIN32
  int len = sizeof ss;
  int rc = peer ? getpeername(static_cast<SOCKET>(fd), reinterpret_cast<sockaddr *>(&ss), &len)
                : getsockname(static_cast<SOCKET>(fd), reinterpret_cast<sockaddr *>(&ss), &len);
#else
  socklen_t len = sizeof ss;
  int rc = peer ? getpeername(fd, reinterpret_cast<sockaddr *>(&ss), &len)
                : getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &len);
#endif
  if (rc != 0) return "";
  char host[INET6_ADDRSTRLEN] = "";
  int port = 0;
  if (ss.ss_family == AF_INET) {
    auto *a = reinterpret_cast<sockaddr_in *>(&ss);
    inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
    port = ntohs(a->sin_port);
    return std::string(host) + ":" + std::to_string(port);
  }
  if (ss.ss_family == AF_INET6) {
    auto *a = reinterpret_cast<sockaddr_in6 *>(&ss);
    inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
    port = ntohs(a->sin6_port);
    return "[" + std::string(host) + "]:" + std::to_string(port);
  }
  return "";
}

void set_socket_timeout(int fd, int seconds) {
  if (seconds <= 0) return;
#ifdef _WIN32
  DWORD ms = static_cast<DWORD>(seconds) * 1000;
  setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof ms);
  setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&ms), sizeof ms);
#else
  timeval tv{seconds, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
}

struct ConnObj : Stream {
  Bio bio;
  bool upgraded = false;  // handed to TLS: the plain handle is no longer usable
  std::string peer_s, local_s;  // addresses captured at creation so they stay readable after the upgrade
  BIO *live() {
    if (upgraded) throw std::runtime_error("connection already belongs to a TLS session");
    if (!bio) throw std::runtime_error("connection is closed");
    return bio.get();
  }
  int fd() { return BIO_get_fd(live(), nullptr); }
  int raw_read(char *p, int n) override {
    int r = BIO_read(live(), p, n);
    if (r > 0) return r;
    if (r == 0) return 0;
    if (BIO_should_retry(bio.get())) throw std::runtime_error("read timed out");
    return 0;  // reset by peer: treat as end of stream
  }
  int raw_write(const char *p, int n) override {
    int r = BIO_write(live(), p, n);
    if (r <= 0) fail("write");
    return r;
  }
};

struct ListenerObj { Bio abio; int timeout = 30; };

struct TlsCtxObj {
  SslCtxP ctx;
  bool server = false;
  bool trace = false;
  std::string alpn_wire;  // length-prefixed protocol list (client offer / server preference)
};

struct TlsObj : Stream {
  SslP ssl;
  Bio trace_bio;
  int raw_read(char *p, int n) override {
    size_t got = 0;
    ERR_clear_error();
    if (SSL_read_ex(ssl.get(), p, static_cast<size_t>(n), &got) == 1) return static_cast<int>(got);
    int e = SSL_get_error(ssl.get(), 0);
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0 && errno == 0) return 0;
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) throw std::runtime_error("read timed out");
    fail("TLS read");
  }
  int raw_write(const char *p, int n) override {
    size_t put = 0;
    ERR_clear_error();
    if (SSL_write_ex(ssl.get(), p, static_cast<size_t>(n), &put) != 1) fail("TLS write");
    return static_cast<int>(put);
  }
};

// ---------------------------------------------------------------- registration plumbing

struct Reg {
  dslvm::Registry &r;
  Host &h;

  template <class T> Value wrap(const char *type, T *raw) {
    if (h.arena.size() >= 1u << 20) { delete raw; throw std::runtime_error("object limit exceeded"); }
    h.arena.push_back(std::shared_ptr<void>(raw, [](void *p) { delete static_cast<T *>(p); }));
    return Value::object(type, raw);
  }

  template <class T, class F>
  void method(const char *type, const char *name, std::vector<std::string> params, const char *ret, F f) {
    std::string label = std::string(type) + "." + name;
    r.method(type, name, std::move(params), ret, [f, label](void *self, Args &a) -> Value {
      if (!self) throw dslvm::Error(label + ": null handle");
      try {
        return f(*static_cast<T *>(self), a);
      } catch (const dslvm::Error &) {
        throw;
      } catch (const std::exception &e) {
        throw dslvm::Error(label + ": " + e.what());
      }
    });
  }
  template <class F>
  void function(const char *name, std::vector<std::string> params, const char *ret, F f) {
    std::string label = name;
    r.function(name, std::move(params), ret, [f, label](Args &a) -> Value {
      try {
        return f(a);
      } catch (const dslvm::Error &) {
        throw;
      } catch (const std::exception &e) {
        throw dslvm::Error(label + ": " + e.what());
      }
    });
  }
};

Value str(std::string s) { return Value::string(std::move(s)); }
Value none() { return Value::none(); }

struct StrList { std::vector<std::string> items; };

// ---------------------------------------------------------------- X509 building

int64_t random_serial() {
  uint64_t v = 0;
  do {
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&v), sizeof v) != 1) fail("RAND_bytes");
    v &= 0x7fffffffffffffffULL;
  } while (v == 0);
  return static_cast<int64_t>(v);
}

bool is_edwards(EVP_PKEY *k) {
  return EVP_PKEY_is_a(k, "ED25519") || EVP_PKEY_is_a(k, "ED448");
}

// Add (replacing any existing) extension `name`=`value`; `issuer` supplies keyid context.
void put_ext(X509 *x, X509 *issuer, const std::string &name, const std::string &value) {
  int nid = OBJ_txt2nid(name.c_str());
  if (nid == NID_undef) throw std::runtime_error("unknown extension '" + name + "'");
  X509V3_CTX c;
  X509V3_set_ctx_nodb(&c);
  X509V3_set_ctx(&c, issuer ? issuer : x, x, nullptr, nullptr, 0);
  X509_EXTENSION *e = X509V3_EXT_nconf_nid(nullptr, &c, nid, value.c_str());
  if (!e) fail("bad value for extension '" + name + "'");
  int at = X509_get_ext_by_NID(x, nid, -1);
  if (at >= 0) X509_EXTENSION_free(X509_delete_ext(x, at));
  int ok = X509_add_ext(x, e, -1);
  X509_EXTENSION_free(e);
  if (!ok) fail("add extension '" + name + "'");
}

bool has_ext(X509 *x, int nid) { return X509_get_ext_by_NID(x, nid, -1) >= 0; }

void finish_and_sign(X509 *x, X509 *issuer, EVP_PKEY *issuer_key, const std::string &alg) {
  if (!X509_check_private_key(issuer, issuer_key) && issuer != x)
    throw std::runtime_error("issuer key does not match issuer certificate");
  if (!X509_set_issuer_name(x, X509_get_subject_name(issuer))) fail("set issuer");
  if (!has_ext(x, NID_subject_key_identifier)) put_ext(x, nullptr, "subjectKeyIdentifier", "hash");
  if (!has_ext(x, NID_basic_constraints)) put_ext(x, nullptr, "basicConstraints", "CA:FALSE");
  if (!has_ext(x, NID_authority_key_identifier) &&
      (issuer == x || has_ext(issuer, NID_subject_key_identifier)))
    put_ext(x, issuer, "authorityKeyIdentifier", "keyid:always");
  MdP md;
  if (!is_edwards(issuer_key)) md = fetch_md(alg.empty() ? "SHA256" : alg);
  if (!X509_sign(x, issuer_key, md.get())) fail("X509_sign");
}

std::string pem_of(X509 *x) {
  Bio b = mem_bio();
  if (!PEM_write_bio_X509(b.get(), x)) fail("PEM_write_bio_X509");
  return bio_string(b.get());
}

std::string text_of(X509 *x) {
  Bio b = mem_bio();
  if (!X509_print(b.get(), x)) fail("X509_print");
  return bio_string(b.get());
}

std::string san_of(X509 *x) {
  std::string out;
  auto *names = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
  if (!names) return out;
  for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
    GENERAL_NAME *g = sk_GENERAL_NAME_value(names, i);
    std::string item;
    auto asn = [&](const char *tag, ASN1_STRING *s) {
      item = std::string(tag) + ":" + std::string(reinterpret_cast<const char *>(ASN1_STRING_get0_data(s)), static_cast<size_t>(ASN1_STRING_length(s)));
    };
    switch (g->type) {
      case GEN_DNS: asn("DNS", g->d.dNSName); break;
      case GEN_EMAIL: asn("email", g->d.rfc822Name); break;
      case GEN_URI: asn("URI", g->d.uniformResourceIdentifier); break;
      case GEN_IPADD: {
        const unsigned char *p = ASN1_STRING_get0_data(g->d.iPAddress);
        int n = ASN1_STRING_length(g->d.iPAddress);
        char buf[INET6_ADDRSTRLEN] = "";
        if (n == 4) inet_ntop(AF_INET, p, buf, sizeof buf);
        else if (n == 16) inet_ntop(AF_INET6, p, buf, sizeof buf);
        item = std::string("IP:") + buf;
        break;
      }
      default: item = "other"; break;
    }
    if (!out.empty()) out += ",";
    out += item;
  }
  GENERAL_NAMES_free(names);
  return out;
}

std::string key_desc(EVP_PKEY *k) {
  std::string t = EVP_PKEY_get0_type_name(k) ? EVP_PKEY_get0_type_name(k) : "?";
  if (EVP_PKEY_is_a(k, "RSA")) return t + " " + std::to_string(EVP_PKEY_get_bits(k));
  char curve[64];
  size_t n = 0;
  if (EVP_PKEY_is_a(k, "EC") && EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof curve, &n)) return t + " " + curve;
  return t;
}

// ISO "2026-01-02T03:04:05Z" -> "20260102030405Z" for ASN1_TIME_set_string_X509.
std::string compact_time(const std::string &s) {
  std::string out;
  for (char c : s) if (c != '-' && c != ':' && c != 'T' && c != ' ') out += c;
  if (out.size() == 8) out += "000000Z";
  else if (!out.empty() && out.back() != 'Z') out += 'Z';
  return out;
}

X509p read_cert_pem(const std::string &pem) {
  Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  X509p x(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
  if (!x) fail("not a PEM certificate");
  return x;
}

PKey read_key_pem(const std::string &pem, const std::string &pass, bool has_pass) {
  Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  std::string pw = pass;
  PKey k(PEM_read_bio_PrivateKey(
      b.get(), nullptr,
      [](char *buf, int size, int, void *u) -> int {
        auto *p = static_cast<std::string *>(u);
        if (p->size() > static_cast<size_t>(size)) return -1;
        std::memcpy(buf, p->data(), p->size());
        return static_cast<int>(p->size());
      },
      has_pass ? &pw : nullptr));
  if (!k) fail(has_pass ? "cannot read private key (wrong passphrase?)" : "cannot read private key (encrypted keys need a passphrase)");
  return k;
}

std::string slurp(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot read '" + path + "'");
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

void spit(const std::string &path, const std::string &data, bool priv) {
  fs::path p(path);
  if (p.has_parent_path() && !fs::exists(p.parent_path())) throw std::runtime_error("directory '" + p.parent_path().string() + "' does not exist");
#ifndef _WIN32
  if (priv) {
    // Create with 0600 before any secret byte is written.
    std::ofstream touch(path, std::ios::binary | std::ios::trunc);
    touch.close();
    chmod(path.c_str(), 0600);
  }
#endif
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) throw std::runtime_error("cannot write '" + path + "'");
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  if (!f) throw std::runtime_error("write to '" + path + "' failed");
}

// ---------------------------------------------------------------- TLS helpers

int proto_version(const std::string &v) {
  std::string s;
  for (char c : v) s += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (s == "tlsv1.3" || s == "1.3" || s == "tls1.3") return TLS1_3_VERSION;
  if (s == "tlsv1.2" || s == "1.2" || s == "tls1.2") return TLS1_2_VERSION;
  if (s == "tlsv1.1" || s == "1.1" || s == "tls1.1") return TLS1_1_VERSION;
  if (s == "tlsv1" || s == "tlsv1.0" || s == "1.0" || s == "tls1") return TLS1_VERSION;
  throw std::runtime_error("unknown TLS version '" + v + "' (use TLSv1.2 or TLSv1.3)");
}

std::string alpn_wire(const std::string &csv) {
  std::string wire, cur;
  auto flush = [&] {
    if (cur.empty()) return;
    if (cur.size() > 255) throw std::runtime_error("ALPN name too long");
    wire += static_cast<char>(cur.size());
    wire += cur;
    cur.clear();
  };
  for (char c : csv) { if (c == ',') flush(); else if (c != ' ') cur += c; }
  flush();
  return wire;
}

int server_alpn_cb(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
  auto *w = static_cast<std::string *>(arg);
  unsigned char *sel = nullptr;
  if (SSL_select_next_proto(&sel, outlen, reinterpret_cast<const unsigned char *>(w->data()), static_cast<unsigned>(w->size()), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

void load_system_roots(SSL_CTX *ctx) {
#ifdef _WIN32
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  HCERTSTORE h = CertOpenSystemStoreA(0, "ROOT");
  if (!h) throw std::runtime_error("cannot open the Windows ROOT store");
  PCCERT_CONTEXT c = nullptr;
  int n = 0;
  while ((c = CertEnumCertificatesInStore(h, c)) != nullptr) {
    const unsigned char *der = c->pbCertEncoded;
    X509p x(d2i_X509(nullptr, &der, static_cast<long>(c->cbCertEncoded)));
    if (x && X509_STORE_add_cert(store, x.get())) ++n;
  }
  CertCloseStore(h, 0);
  ERR_clear_error();
  if (n == 0) throw std::runtime_error("the Windows ROOT store has no usable certificates");
#else
  const char *candidates[] = {std::getenv("SSL_CERT_FILE"), "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                              "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem", "/usr/local/share/certs/ca-root-nss.crt"};
  for (const char *p : candidates) {
    if (!p || !*p) continue;
    if (fs::exists(p) && SSL_CTX_load_verify_locations(ctx, p, nullptr) == 1) return;
    ERR_clear_error();
  }
  throw std::runtime_error("no system CA bundle found; use ca_file(path) or set SSL_CERT_FILE");
#endif
}

bool looks_like_ip(const std::string &h) {
  unsigned char buf[16];
  return inet_pton(AF_INET, h.c_str(), buf) == 1 || inet_pton(AF_INET6, h.c_str(), buf) == 1;
}

std::string verify_text(SSL *ssl) {
  long v = SSL_get_verify_result(ssl);
  return v == X509_V_OK ? "ok" : std::string(X509_verify_cert_error_string(v));
}

[[noreturn]] void handshake_failed(SSL *ssl, const char *what) {
  std::string e = ossl_errors();
  std::string vr = verify_text(ssl);
  throw std::runtime_error(std::string(what) + " failed" + (e.empty() ? "" : ": " + e) + (vr != "ok" ? " (certificate verify: " + vr + ")" : ""));
}

Value make_tls(Reg &g, TlsCtxObj &c, ConnObj &conn, const std::string &host) {
  BIO *plain = conn.live();
  SslP ssl(SSL_new(c.ctx.get()));
  if (!ssl) fail("SSL_new");
  auto t = std::make_unique<TlsObj>();
  if (c.trace) {
    t->trace_bio = mem_bio();
    SSL_set_msg_callback(ssl.get(), SSL_trace);
    SSL_set_msg_callback_arg(ssl.get(), t->trace_bio.get());
  }
  if (!c.server) {
    if (!host.empty()) {
      if (looks_like_ip(host)) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), host.c_str())) fail("set IP to verify");
      } else {
        if (!SSL_set_tlsext_host_name(ssl.get(), host.c_str())) fail("set SNI");
        if (!X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl.get()), host.c_str(), 0)) fail("set host to verify");
      }
    }
  }
  SSL_set_bio(ssl.get(), plain, plain);  // ownership of the BIO moves into the SSL
  conn.bio.release();
  conn.upgraded = true;
  t->ssl = std::move(ssl);
  ERR_clear_error();
  int rc = c.server ? SSL_accept(t->ssl.get()) : SSL_connect(t->ssl.get());
  if (rc != 1) handshake_failed(t->ssl.get(), c.server ? "TLS accept" : "TLS handshake");
  TlsObj *raw = t.release();
  return g.wrap("Tls", raw);
}

}  // namespace

// ================================================================ the schema

void register_host(dslvm::Registry &reg, Host &host) {
  auto reg_holder = std::make_shared<Reg>(Reg{reg, host});  // captured by reference by every registered closure
  host.arena.push_back(reg_holder);
  Reg &g = *reg_holder;
  reg.context("ssl", "Ssl");
  reg.context("out", "Out");
  reg.context("fs", "Fs");
  reg.context("net", "Net");

#ifndef _WIN32
  std::signal(SIGPIPE, SIG_IGN);
#endif

  auto strlist = [&g](std::vector<std::string> v) { return g.wrap("StrList", new StrList{std::move(v)}); };

  // ---------------------------------------------------------------- free functions
  g.function("str_list", {}, "StrList", [strlist](Args &) { return strlist({}); });
  g.function("str_split", {"string", "string"}, "StrList", [strlist](Args &a) {
    std::vector<std::string> v;
    const std::string &s = a[0].s, &d = a[1].s;
    if (d.empty()) throw std::runtime_error("empty separator");
    size_t from = 0;
    for (;;) {
      size_t at = s.find(d, from);
      if (at == std::string::npos) { v.push_back(s.substr(from)); break; }
      v.push_back(s.substr(from, at - from));
      from = at + d.size();
    }
    return strlist(std::move(v));
  });
  g.function("str_len", {"string"}, "int", [](Args &a) { return Value::integer(static_cast<int64_t>(a[0].s.size())); });
  g.function("str_find", {"string", "string"}, "int", [](Args &a) {
    size_t at = a[0].s.find(a[1].s);
    return Value::integer(at == std::string::npos ? -1 : static_cast<int64_t>(at));
  });
  g.function("str_contains", {"string", "string"}, "bool", [](Args &a) { return Value::boolean(a[0].s.find(a[1].s) != std::string::npos); });
  g.function("str_starts_with", {"string", "string"}, "bool", [](Args &a) { return Value::boolean(a[0].s.compare(0, a[1].s.size(), a[1].s) == 0); });
  g.function("str_ends_with", {"string", "string"}, "bool", [](Args &a) {
    return Value::boolean(a[0].s.size() >= a[1].s.size() && a[0].s.compare(a[0].s.size() - a[1].s.size(), a[1].s.size(), a[1].s) == 0);
  });
  g.function("str_substr", {"string", "int", "int"}, "string", [](Args &a) {
    int64_t start = std::max<int64_t>(0, a[1].i), n = a[2].i;
    if (n <= 0 || start >= static_cast<int64_t>(a[0].s.size())) return str("");
    return str(a[0].s.substr(static_cast<size_t>(start), static_cast<size_t>(n)));
  });
  g.function("str_replace", {"string", "string", "string"}, "string", [](Args &a) {
    std::string out = a[0].s;
    if (a[1].s.empty()) return str(out);
    size_t at = 0;
    while ((at = out.find(a[1].s, at)) != std::string::npos) { out.replace(at, a[1].s.size(), a[2].s); at += a[2].s.size(); }
    return str(out);
  });
  g.function("str_trim", {"string"}, "string", [](Args &a) {
    const std::string &s = a[0].s;
    size_t b = 0, e = s.size();
    while (b < e && std::strchr(" \t\r\n\v\f", s[b])) ++b;
    while (e > b && std::strchr(" \t\r\n\v\f", s[e - 1])) --e;
    return str(s.substr(b, e - b));
  });
  g.function("str_lower", {"string"}, "string", [](Args &a) {
    std::string s = a[0].s;
    for (auto &c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return str(s);
  });
  g.function("str_to_int", {"string"}, "int", [](Args &a) {
    try { size_t used = 0; long long v = std::stoll(a[0].s, &used, 10); return Value::integer(used == a[0].s.size() ? v : 0); }
    catch (...) { return Value::integer(0); }
  });

  // ---------------------------------------------------------------- StrList
  g.method<StrList>("StrList", "len", {}, "int", [](StrList &l, Args &) { return Value::integer(static_cast<int64_t>(l.items.size())); });
  g.method<StrList>("StrList", "at", {"int"}, "string", [](StrList &l, Args &a) {
    if (a[0].i < 0 || a[0].i >= static_cast<int64_t>(l.items.size())) throw std::runtime_error("index " + std::to_string(a[0].i) + " out of range");
    return str(l.items[static_cast<size_t>(a[0].i)]);
  });
  g.method<StrList>("StrList", "add", {"string"}, "StrList", [](StrList &l, Args &a) { l.items.push_back(a[0].s); return Value::object("StrList", &l); });
  g.method<StrList>("StrList", "join", {"string"}, "string", [](StrList &l, Args &a) {
    std::string out;
    for (size_t i = 0; i < l.items.size(); ++i) { if (i) out += a[0].s; out += l.items[i]; }
    return str(out);
  });

  // ---------------------------------------------------------------- Out
  g.method<Host>("Out", "line", {"string"}, "void", [](Host &h, Args &a) { (h.json_mode ? std::cerr : std::cout) << a[0].s << "\n"; return none(); });
  g.method<Host>("Out", "text", {"string"}, "void", [](Host &h, Args &a) { (h.json_mode ? std::cerr : std::cout) << a[0].s; return none(); });
  g.method<Host>("Out", "warn", {"string"}, "void", [](Host &, Args &a) { std::cerr << a[0].s << "\n"; return none(); });
  g.method<Host>("Out", "fail", {"string"}, "void", [](Host &, Args &a) -> Value { throw dslvm::Error("APP_FAIL", a[0].s); });

  // ---------------------------------------------------------------- Fs
  g.method<Host>("Fs", "read", {"string"}, "string", [](Host &, Args &a) { return str(slurp(a[0].s)); });
  g.method<Host>("Fs", "write", {"string", "string"}, "void", [](Host &, Args &a) { spit(a[0].s, a[1].s, false); return none(); });
  g.method<Host>("Fs", "write_private", {"string", "string"}, "void", [](Host &, Args &a) { spit(a[0].s, a[1].s, true); return none(); });
  g.method<Host>("Fs", "exists", {"string"}, "bool", [](Host &, Args &a) { return Value::boolean(fs::exists(a[0].s)); });
  g.method<Host>("Fs", "mkdir", {"string"}, "void", [](Host &, Args &a) { fs::create_directories(a[0].s); return none(); });
  g.method<Host>("Fs", "remove", {"string"}, "void", [](Host &, Args &a) { fs::remove_all(a[0].s); return none(); });

  // ---------------------------------------------------------------- Key
  g.method<KeyObj>("Key", "type", {}, "string", [](KeyObj &k, Args &) { return str(EVP_PKEY_get0_type_name(k.key.get()) ? EVP_PKEY_get0_type_name(k.key.get()) : ""); });
  g.method<KeyObj>("Key", "bits", {}, "int", [](KeyObj &k, Args &) { return Value::integer(EVP_PKEY_get_bits(k.key.get())); });
  g.method<KeyObj>("Key", "curve", {}, "string", [](KeyObj &k, Args &) {
    char curve[64];
    size_t n = 0;
    if (EVP_PKEY_get_utf8_string_param(k.key.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof curve, &n)) return str(std::string(curve, n));
    ERR_clear_error();
    return str("");
  });
  g.method<KeyObj>("Key", "pem", {}, "string", [](KeyObj &k, Args &) {
    Bio b = mem_bio();
    if (!PEM_write_bio_PrivateKey(b.get(), k.key.get(), nullptr, nullptr, 0, nullptr, nullptr)) fail("PEM_write_bio_PrivateKey");
    return str(bio_string(b.get()));
  });
  g.method<KeyObj>("Key", "public_pem", {}, "string", [](KeyObj &k, Args &) {
    Bio b = mem_bio();
    if (!PEM_write_bio_PUBKEY(b.get(), k.key.get())) fail("PEM_write_bio_PUBKEY");
    return str(bio_string(b.get()));
  });
  g.method<KeyObj>("Key", "text", {}, "string", [](KeyObj &k, Args &) {
    Bio b = mem_bio();
    if (!EVP_PKEY_print_private(b.get(), k.key.get(), 0, nullptr)) fail("EVP_PKEY_print_private");
    return str(bio_string(b.get()));
  });
  g.method<KeyObj>("Key", "fingerprint", {}, "string", [](KeyObj &k, Args &) {
    unsigned char *der = nullptr;
    int n = i2d_PUBKEY(k.key.get(), &der);
    if (n <= 0) fail("i2d_PUBKEY");
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    int ok = EVP_Digest(der, static_cast<size_t>(n), md, &len, EVP_sha256(), nullptr);
    OPENSSL_free(der);
    if (!ok) fail("digest");
    return str(to_hex(md, len));
  });
  g.method<KeyObj>("Key", "save", {"string"}, "void", [](KeyObj &k, Args &a) {
    Bio b = mem_bio();
    if (!PEM_write_bio_PrivateKey(b.get(), k.key.get(), nullptr, nullptr, 0, nullptr, nullptr)) fail("PEM_write_bio_PrivateKey");
    spit(a[0].s, bio_string(b.get()), true);
    return none();
  });
  g.method<KeyObj>("Key", "save_encrypted", {"string", "string"}, "void", [](KeyObj &k, Args &a) {
    Bio b = mem_bio();
    if (a[1].s.empty()) throw std::runtime_error("empty passphrase");
    if (!PEM_write_bio_PKCS8PrivateKey(b.get(), k.key.get(), EVP_aes_256_cbc(), a[1].s.data(), static_cast<int>(a[1].s.size()), nullptr, nullptr)) fail("PEM_write_bio_PKCS8PrivateKey");
    spit(a[0].s, bio_string(b.get()), true);
    return none();
  });
  g.method<KeyObj>("Key", "sign", {"string", "string"}, "string", [](KeyObj &k, Args &a) {
    std::unique_ptr<EVP_MD_CTX, Free<EVP_MD_CTX, EVP_MD_CTX_free>> c(EVP_MD_CTX_new());
    MdP md;
    if (!is_edwards(k.key.get())) md = fetch_md(a[0].s);
    if (EVP_DigestSignInit(c.get(), nullptr, md.get(), nullptr, k.key.get()) != 1) fail("EVP_DigestSignInit");
    size_t n = 0;
    if (EVP_DigestSign(c.get(), nullptr, &n, reinterpret_cast<const unsigned char *>(a[1].s.data()), a[1].s.size()) != 1) fail("EVP_DigestSign");
    std::string sig(n, '\0');
    if (EVP_DigestSign(c.get(), reinterpret_cast<unsigned char *>(&sig[0]), &n, reinterpret_cast<const unsigned char *>(a[1].s.data()), a[1].s.size()) != 1) fail("EVP_DigestSign");
    return str(to_hex(reinterpret_cast<const unsigned char *>(sig.data()), n));
  });
  g.method<KeyObj>("Key", "verify", {"string", "string", "string"}, "bool", [](KeyObj &k, Args &a) {
    std::string sig = from_hex(a[2].s);
    std::unique_ptr<EVP_MD_CTX, Free<EVP_MD_CTX, EVP_MD_CTX_free>> c(EVP_MD_CTX_new());
    MdP md;
    if (!is_edwards(k.key.get())) md = fetch_md(a[0].s);
    if (EVP_DigestVerifyInit(c.get(), nullptr, md.get(), nullptr, k.key.get()) != 1) fail("EVP_DigestVerifyInit");
    int rc = EVP_DigestVerify(c.get(), reinterpret_cast<const unsigned char *>(sig.data()), sig.size(), reinterpret_cast<const unsigned char *>(a[1].s.data()), a[1].s.size());
    ERR_clear_error();
    return Value::boolean(rc == 1);
  });

  // ---------------------------------------------------------------- Csr
  g.method<CsrObj>("Csr", "san", {"string"}, "Csr", [](CsrObj &c, Args &a) { c.sans.push_back(a[0].s); return Value::object("Csr", &c); });
  g.method<CsrObj>("Csr", "sign", {"Key", "string"}, "Csr", [](CsrObj &c, Args &a) {
    auto *k = static_cast<KeyObj *>(a[0].obj);
    if (!c.sans.empty()) {
      std::string joined;
      for (auto &s : c.sans) { if (!joined.empty()) joined += ","; joined += s; }
      STACK_OF(X509_EXTENSION) *exts = nullptr;
      X509_EXTENSION *e = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, joined.c_str());
      if (!e) fail("bad subjectAltName '" + joined + "'");
      if (!X509v3_add_ext(&exts, e, -1)) { X509_EXTENSION_free(e); fail("add SAN"); }
      X509_EXTENSION_free(e);
      int ok = X509_REQ_add_extensions(c.req.get(), exts);
      sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
      if (!ok) fail("X509_REQ_add_extensions");
    }
    MdP md;
    if (!is_edwards(k->key.get())) md = fetch_md(a[1].s.empty() ? "SHA256" : a[1].s);
    if (!X509_REQ_sign(c.req.get(), k->key.get(), md.get())) fail("X509_REQ_sign");
    return Value::object("Csr", &c);
  });
  g.method<CsrObj>("Csr", "verify", {}, "bool", [](CsrObj &c, Args &) {
    EVP_PKEY *pk = X509_REQ_get0_pubkey(c.req.get());
    int rc = pk ? X509_REQ_verify(c.req.get(), pk) : 0;
    ERR_clear_error();
    return Value::boolean(rc == 1);
  });
  g.method<CsrObj>("Csr", "subject", {}, "string", [](CsrObj &c, Args &) { return str(name_string(X509_REQ_get_subject_name(c.req.get()))); });
  g.method<CsrObj>("Csr", "pem", {}, "string", [](CsrObj &c, Args &) {
    Bio b = mem_bio();
    if (!PEM_write_bio_X509_REQ(b.get(), c.req.get())) fail("PEM_write_bio_X509_REQ");
    return str(bio_string(b.get()));
  });
  g.method<CsrObj>("Csr", "text", {}, "string", [](CsrObj &c, Args &) {
    Bio b = mem_bio();
    if (!X509_REQ_print(b.get(), c.req.get())) fail("X509_REQ_print");
    return str(bio_string(b.get()));
  });
  g.method<CsrObj>("Csr", "save", {"string"}, "void", [](CsrObj &c, Args &a) {
    Bio b = mem_bio();
    if (!PEM_write_bio_X509_REQ(b.get(), c.req.get())) fail("PEM_write_bio_X509_REQ");
    spit(a[0].s, bio_string(b.get()), false);
    return none();
  });

  // ---------------------------------------------------------------- Cert
  auto self_cert = [](CertObj &c) { return Value::object("Cert", &c); };
  g.method<CertObj>("Cert", "serial", {"int"}, "Cert", [self_cert](CertObj &c, Args &a) {
    if (a[0].i <= 0) throw std::runtime_error("serial must be positive");
    if (!ASN1_INTEGER_set_int64(X509_get_serialNumber(c.x.get()), a[0].i)) fail("set serial");
    return self_cert(c);
  });
  g.method<CertObj>("Cert", "valid_days", {"int"}, "Cert", [self_cert](CertObj &c, Args &a) {
    if (a[0].i < 0) throw std::runtime_error("negative validity");
    if (!X509_gmtime_adj(X509_getm_notBefore(c.x.get()), 0) || !X509_gmtime_adj(X509_getm_notAfter(c.x.get()), 60L * 60 * 24 * a[0].i)) fail("set validity");
    return self_cert(c);
  });
  g.method<CertObj>("Cert", "valid_between", {"string", "string"}, "Cert", [self_cert](CertObj &c, Args &a) {
    if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(c.x.get()), compact_time(a[0].s).c_str())) fail("bad not-before '" + a[0].s + "'");
    if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(c.x.get()), compact_time(a[1].s).c_str())) fail("bad not-after '" + a[1].s + "'");
    return self_cert(c);
  });
  g.method<CertObj>("Cert", "san", {"string"}, "Cert", [self_cert](CertObj &c, Args &a) { put_ext(c.x.get(), nullptr, "subjectAltName", a[0].s); return self_cert(c); });
  g.method<CertObj>("Cert", "ca", {"bool"}, "Cert", [self_cert](CertObj &c, Args &a) {
    if (a[0].b) {
      put_ext(c.x.get(), nullptr, "basicConstraints", "critical,CA:TRUE");
      put_ext(c.x.get(), nullptr, "keyUsage", "critical,keyCertSign,cRLSign");
    } else {
      put_ext(c.x.get(), nullptr, "basicConstraints", "critical,CA:FALSE");
    }
    return self_cert(c);
  });
  g.method<CertObj>("Cert", "ext", {"string", "string"}, "Cert", [self_cert](CertObj &c, Args &a) { put_ext(c.x.get(), nullptr, a[0].s, a[1].s); return self_cert(c); });
  g.method<CertObj>("Cert", "sign_self", {"Key", "string"}, "Cert", [self_cert](CertObj &c, Args &a) {
    auto *k = static_cast<KeyObj *>(a[0].obj);
    if (!X509_check_private_key(c.x.get(), k->key.get())) fail("key does not match the certificate's public key");
    finish_and_sign(c.x.get(), c.x.get(), k->key.get(), a[1].s);
    return self_cert(c);
  });
  g.method<CertObj>("Cert", "sign_with", {"Cert", "Key", "string"}, "Cert", [self_cert](CertObj &c, Args &a) {
    auto *issuer = static_cast<CertObj *>(a[0].obj);
    auto *k = static_cast<KeyObj *>(a[1].obj);
    if (issuer == &c) throw std::runtime_error("use sign_self to sign a certificate with its own key");
    if (!X509_check_private_key(issuer->x.get(), k->key.get())) fail("issuer key does not match the issuer certificate");
    finish_and_sign(c.x.get(), issuer->x.get(), k->key.get(), a[2].s);
    return self_cert(c);
  });
  g.method<CertObj>("Cert", "subject", {}, "string", [](CertObj &c, Args &) { return str(name_string(X509_get_subject_name(c.x.get()))); });
  g.method<CertObj>("Cert", "issuer", {}, "string", [](CertObj &c, Args &) { return str(name_string(X509_get_issuer_name(c.x.get()))); });
  g.method<CertObj>("Cert", "serial_hex", {}, "string", [](CertObj &c, Args &) {
    Bio b = mem_bio();
    i2a_ASN1_INTEGER(b.get(), X509_get0_serialNumber(c.x.get()));
    return str(bio_string(b.get()));
  });
  g.method<CertObj>("Cert", "not_before", {}, "string", [](CertObj &c, Args &) { return str(iso_time(X509_get0_notBefore(c.x.get()))); });
  g.method<CertObj>("Cert", "not_after", {}, "string", [](CertObj &c, Args &) { return str(iso_time(X509_get0_notAfter(c.x.get()))); });
  g.method<CertObj>("Cert", "san_text", {}, "string", [](CertObj &c, Args &) { return str(san_of(c.x.get())); });
  g.method<CertObj>("Cert", "sig_alg", {}, "string", [](CertObj &c, Args &) { return str(OBJ_nid2ln(X509_get_signature_nid(c.x.get()))); });
  g.method<CertObj>("Cert", "key_type", {}, "string", [](CertObj &c, Args &) { return str(key_desc(X509_get0_pubkey(c.x.get()))); });
  g.method<CertObj>("Cert", "is_ca", {}, "bool", [](CertObj &c, Args &) { return Value::boolean(X509_check_ca(c.x.get()) == 1); });
  g.method<CertObj>("Cert", "self_signed", {}, "bool", [](CertObj &c, Args &) {
    int rc = X509_self_signed(c.x.get(), 1);
    ERR_clear_error();
    return Value::boolean(rc == 1);
  });
  g.method<CertObj>("Cert", "expired", {}, "bool", [](CertObj &c, Args &) { return Value::boolean(ASN1_TIME_cmp_time_t(X509_get0_notAfter(c.x.get()), std::time(nullptr)) < 0); });
  g.method<CertObj>("Cert", "matches_host", {"string"}, "bool", [](CertObj &c, Args &a) {
    int rc = looks_like_ip(a[0].s) ? X509_check_ip_asc(c.x.get(), a[0].s.c_str(), 0) : X509_check_host(c.x.get(), a[0].s.data(), a[0].s.size(), 0, nullptr);
    return Value::boolean(rc == 1);
  });
  g.method<CertObj>("Cert", "verify_with", {"Cert"}, "bool", [](CertObj &c, Args &a) {
    auto *ca = static_cast<CertObj *>(a[0].obj);
    int rc = X509_verify(c.x.get(), X509_get0_pubkey(ca->x.get()));
    ERR_clear_error();
    return Value::boolean(rc == 1);
  });
  g.method<CertObj>("Cert", "fingerprint", {"string"}, "string", [](CertObj &c, Args &a) {
    MdP md = fetch_md(a[0].s);
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned n = 0;
    if (!X509_digest(c.x.get(), md.get(), buf, &n)) fail("X509_digest");
    return str(colon_hex(buf, n));
  });
  g.method<CertObj>("Cert", "pem", {}, "string", [](CertObj &c, Args &) { return str(pem_of(c.x.get())); });
  g.method<CertObj>("Cert", "text", {}, "string", [](CertObj &c, Args &) { return str(text_of(c.x.get())); });
  g.method<CertObj>("Cert", "save", {"string"}, "void", [](CertObj &c, Args &a) { spit(a[0].s, pem_of(c.x.get()), false); return none(); });

  // ---------------------------------------------------------------- Net, Conn, Listener
  g.method<Host>("Net", "resolve", {"string"}, "StrList", [&g, strlist](Host &, Args &a) {
    BIO_ADDRINFO *res = nullptr;
    if (!BIO_lookup_ex(a[0].s.c_str(), nullptr, BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_STREAM, 0, &res)) fail("cannot resolve '" + a[0].s + "'");
    std::vector<std::string> out;
    for (const BIO_ADDRINFO *p = res; p; p = BIO_ADDRINFO_next(p)) {
      char *s = BIO_ADDR_hostname_string(BIO_ADDRINFO_address(p), 1);
      if (s) {
        if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
        OPENSSL_free(s);
      }
    }
    BIO_ADDRINFO_free(res);
    (void)g;
    return strlist(std::move(out));
  });
  g.method<Host>("Net", "connect", {"string", "int"}, "Conn", [&g](Host &h, Args &a) {
    if (a[1].i <= 0 || a[1].i > 65535) throw std::runtime_error("bad port");
    std::string target = (a[0].s.find(':') != std::string::npos ? "[" + a[0].s + "]" : a[0].s) + ":" + std::to_string(a[1].i);
    auto c = std::make_unique<ConnObj>();
    c->bio.reset(BIO_new_connect(target.c_str()));
    if (!c->bio) fail("BIO_new_connect");
    if (BIO_do_connect(c->bio.get()) <= 0) fail("cannot connect to " + target);
    set_socket_timeout(c->fd(), h.timeout_seconds);
    c->peer_s = sock_name(c->fd(), true);
    c->local_s = sock_name(c->fd(), false);
    return g.wrap("Conn", c.release());
  });
  g.method<Host>("Net", "listen", {"int"}, "Listener", [&g](Host &h, Args &a) {
    if (a[0].i < 0 || a[0].i > 65535) throw std::runtime_error("bad port");
    auto l = std::make_unique<ListenerObj>();
    l->timeout = h.timeout_seconds;
    l->abio.reset(BIO_new_accept(std::to_string(a[0].i).c_str()));
    if (!l->abio) fail("BIO_new_accept");
    BIO_set_bind_mode(l->abio.get(), BIO_BIND_REUSEADDR);
    if (BIO_do_accept(l->abio.get()) <= 0) fail("cannot listen on port " + std::to_string(a[0].i));
    return g.wrap("Listener", l.release());
  });
  g.method<Host>("Net", "timeout", {"int"}, "void", [](Host &h, Args &a) { h.timeout_seconds = static_cast<int>(std::max<int64_t>(0, a[0].i)); return none(); });

  g.method<ConnObj>("Conn", "peer", {}, "string", [](ConnObj &c, Args &) { return str(c.peer_s); });
  g.method<ConnObj>("Conn", "local", {}, "string", [](ConnObj &c, Args &) { return str(c.local_s); });
  g.method<ConnObj>("Conn", "write", {"string"}, "int", [](ConnObj &c, Args &a) { c.live(); return Value::integer(c.write(a[0].s)); });
  g.method<ConnObj>("Conn", "read", {"int"}, "string", [](ConnObj &c, Args &a) { c.live(); return str(c.read(a[0].i)); });
  g.method<ConnObj>("Conn", "read_until", {"string", "int"}, "string", [](ConnObj &c, Args &a) { c.live(); return str(c.read_until(a[0].s, a[1].i)); });
  g.method<ConnObj>("Conn", "close", {}, "void", [](ConnObj &c, Args &) { c.bio.reset(); return none(); });

  g.method<ListenerObj>("Listener", "port", {}, "int", [](ListenerObj &l, Args &) {
    const char *p = BIO_get_accept_port(l.abio.get());
    return Value::integer(p ? std::atoi(p) : 0);
  });
  g.method<ListenerObj>("Listener", "accept", {}, "Conn", [&g](ListenerObj &l, Args &) {
    if (!l.abio) throw std::runtime_error("listener is closed");
    if (BIO_do_accept(l.abio.get()) <= 0) fail("accept");
    auto c = std::make_unique<ConnObj>();
    c->bio.reset(BIO_pop(l.abio.get()));
    set_socket_timeout(c->fd(), l.timeout);
    c->peer_s = sock_name(c->fd(), true);
    c->local_s = sock_name(c->fd(), false);
    return g.wrap("Conn", c.release());
  });
  g.method<ListenerObj>("Listener", "close", {}, "void", [](ListenerObj &l, Args &) { l.abio.reset(); return none(); });

  // ---------------------------------------------------------------- TlsCtx
  auto self_ctx = [](TlsCtxObj &c) { return Value::object("TlsCtx", &c); };
  g.method<TlsCtxObj>("TlsCtx", "min_version", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (!SSL_CTX_set_min_proto_version(c.ctx.get(), proto_version(a[0].s))) fail("set min version");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "max_version", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (!SSL_CTX_set_max_proto_version(c.ctx.get(), proto_version(a[0].s))) fail("set max version");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "alpn", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    c.alpn_wire = alpn_wire(a[0].s);
    if (c.server) {
      SSL_CTX_set_alpn_select_cb(c.ctx.get(), server_alpn_cb, &c.alpn_wire);
    } else if (SSL_CTX_set_alpn_protos(c.ctx.get(), reinterpret_cast<const unsigned char *>(c.alpn_wire.data()), static_cast<unsigned>(c.alpn_wire.size())) != 0) {
      fail("set ALPN");
    }
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "ciphers", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (!SSL_CTX_set_cipher_list(c.ctx.get(), a[0].s.c_str())) fail("no usable TLS 1.2 cipher in '" + a[0].s + "'");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "suites", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (!SSL_CTX_set_ciphersuites(c.ctx.get(), a[0].s.c_str())) fail("no usable TLS 1.3 suite in '" + a[0].s + "'");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "groups", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (!SSL_CTX_set1_groups_list(c.ctx.get(), a[0].s.c_str())) fail("no usable group in '" + a[0].s + "'");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "verify", {"bool"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    SSL_CTX_set_verify(c.ctx.get(), a[0].b ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "require_client", {"bool"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    SSL_CTX_set_verify(c.ctx.get(), a[0].b ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE, nullptr);
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "ca_file", {"string"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (SSL_CTX_load_verify_locations(c.ctx.get(), a[0].s.c_str(), nullptr) != 1) fail("cannot load CA file '" + a[0].s + "'");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "add_ca", {"Cert"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (X509_STORE_add_cert(SSL_CTX_get_cert_store(c.ctx.get()), static_cast<CertObj *>(a[0].obj)->x.get()) != 1) fail("add CA certificate");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "system_roots", {}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &) { load_system_roots(c.ctx.get()); return self_ctx(c); });
  g.method<TlsCtxObj>("TlsCtx", "chain", {"Cert"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    X509 *x = static_cast<CertObj *>(a[0].obj)->x.get();
    X509_up_ref(x);
    if (!SSL_CTX_add_extra_chain_cert(c.ctx.get(), x)) { X509_free(x); fail("add chain certificate"); }
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "client_cert", {"Cert", "Key"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) {
    if (SSL_CTX_use_certificate(c.ctx.get(), static_cast<CertObj *>(a[0].obj)->x.get()) != 1) fail("use certificate");
    if (SSL_CTX_use_PrivateKey(c.ctx.get(), static_cast<KeyObj *>(a[1].obj)->key.get()) != 1) fail("use private key");
    if (SSL_CTX_check_private_key(c.ctx.get()) != 1) fail("certificate and key do not match");
    return self_ctx(c);
  });
  g.method<TlsCtxObj>("TlsCtx", "trace", {"bool"}, "TlsCtx", [self_ctx](TlsCtxObj &c, Args &a) { c.trace = a[0].b; return self_ctx(c); });
  g.method<TlsCtxObj>("TlsCtx", "connect", {"Conn", "string"}, "Tls", [&g](TlsCtxObj &c, Args &a) {
    if (c.server) throw std::runtime_error("this context is a server context; use accept");
    return make_tls(g, c, *static_cast<ConnObj *>(a[0].obj), a[1].s);
  });
  g.method<TlsCtxObj>("TlsCtx", "accept", {"Conn"}, "Tls", [&g](TlsCtxObj &c, Args &a) {
    if (!c.server) throw std::runtime_error("this context is a client context; use connect");
    return make_tls(g, c, *static_cast<ConnObj *>(a[0].obj), "");
  });

  // ---------------------------------------------------------------- Tls
  g.method<TlsObj>("Tls", "version", {}, "string", [](TlsObj &t, Args &) { return str(SSL_get_version(t.ssl.get())); });
  g.method<TlsObj>("Tls", "cipher", {}, "string", [](TlsObj &t, Args &) {
    const SSL_CIPHER *c = SSL_get_current_cipher(t.ssl.get());
    return str(c ? SSL_CIPHER_get_name(c) : "");
  });
  g.method<TlsObj>("Tls", "group", {}, "string", [](TlsObj &t, Args &) {
    const char *n = SSL_get0_group_name(t.ssl.get());
    return str(n ? n : "");
  });
  g.method<TlsObj>("Tls", "peer_sigalg", {}, "string", [](TlsObj &t, Args &) {
    const char *n = nullptr;
    if (SSL_get0_peer_signature_name(t.ssl.get(), &n) != 1 || !n) { ERR_clear_error(); return str(""); }
    return str(n);
  });
  g.method<TlsObj>("Tls", "alpn", {}, "string", [](TlsObj &t, Args &) {
    const unsigned char *p = nullptr;
    unsigned n = 0;
    SSL_get0_alpn_selected(t.ssl.get(), &p, &n);
    return str(p ? std::string(reinterpret_cast<const char *>(p), n) : std::string());
  });
  g.method<TlsObj>("Tls", "server_name", {}, "string", [](TlsObj &t, Args &) {
    const char *n = SSL_get_servername(t.ssl.get(), TLSEXT_NAMETYPE_host_name);
    return str(n ? n : "");
  });
  g.method<TlsObj>("Tls", "verified", {}, "bool", [](TlsObj &t, Args &) { return Value::boolean(SSL_get_verify_result(t.ssl.get()) == X509_V_OK); });
  g.method<TlsObj>("Tls", "verify_result", {}, "string", [](TlsObj &t, Args &) { return str(verify_text(t.ssl.get())); });
  g.method<TlsObj>("Tls", "peer", {}, "Cert", [&g](TlsObj &t, Args &) {
    X509 *x = SSL_get1_peer_certificate(t.ssl.get());
    if (!x) throw std::runtime_error("the peer sent no certificate");
    return g.wrap("Cert", new CertObj{X509p(x)});
  });
  g.method<TlsObj>("Tls", "chain_len", {}, "int", [](TlsObj &t, Args &) {
    STACK_OF(X509) *s = SSL_get_peer_cert_chain(t.ssl.get());
    return Value::integer(s ? sk_X509_num(s) : 0);
  });
  g.method<TlsObj>("Tls", "chain_at", {"int"}, "Cert", [&g](TlsObj &t, Args &a) {
    STACK_OF(X509) *s = SSL_get_peer_cert_chain(t.ssl.get());
    if (!s || a[0].i < 0 || a[0].i >= sk_X509_num(s)) throw std::runtime_error("chain index out of range");
    X509 *x = sk_X509_value(s, static_cast<int>(a[0].i));
    X509_up_ref(x);
    return g.wrap("Cert", new CertObj{X509p(x)});
  });
  g.method<TlsObj>("Tls", "trace", {}, "string", [](TlsObj &t, Args &) { return str(t.trace_bio ? bio_string(t.trace_bio.get()) : std::string()); });
  g.method<TlsObj>("Tls", "write", {"string"}, "int", [](TlsObj &t, Args &a) { return Value::integer(t.write(a[0].s)); });
  g.method<TlsObj>("Tls", "read", {"int"}, "string", [](TlsObj &t, Args &a) { return str(t.read(a[0].i)); });
  g.method<TlsObj>("Tls", "read_until", {"string", "int"}, "string", [](TlsObj &t, Args &a) { return str(t.read_until(a[0].s, a[1].i)); });
  g.method<TlsObj>("Tls", "read_all", {"int"}, "string", [](TlsObj &t, Args &a) { return str(t.read_all(a[0].i)); });
  g.method<TlsObj>("Tls", "shutdown", {}, "void", [](TlsObj &t, Args &) {
    SSL_shutdown(t.ssl.get());
    ERR_clear_error();
    return none();
  });

  // ---------------------------------------------------------------- Ssl
  g.method<Host>("Ssl", "version", {}, "string", [](Host &, Args &) { return str(OpenSSL_version(OPENSSL_VERSION)); });
  g.method<Host>("Ssl", "args", {}, "StrList", [strlist](Host &h, Args &) { return strlist(h.args); });
  g.method<Host>("Ssl", "now", {}, "string", [](Host &, Args &) {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return str(buf);
  });
  g.method<Host>("Ssl", "hex", {"string"}, "string", [](Host &, Args &a) { return str(to_hex(a[0].s)); });
  g.method<Host>("Ssl", "unhex", {"string"}, "string", [](Host &, Args &a) { return str(from_hex(a[0].s)); });
  g.method<Host>("Ssl", "b64", {"string"}, "string", [](Host &, Args &a) { return str(b64_encode(a[0].s)); });
  g.method<Host>("Ssl", "unb64", {"string"}, "string", [](Host &, Args &a) { return str(b64_decode(a[0].s)); });
  g.method<Host>("Ssl", "rand_bytes", {"int"}, "string", [](Host &, Args &a) {
    if (a[0].i < 0 || a[0].i > (1 << 24)) throw std::runtime_error("size out of range");
    std::string s(static_cast<size_t>(a[0].i), '\0');
    if (!s.empty() && RAND_bytes(reinterpret_cast<unsigned char *>(&s[0]), static_cast<int>(s.size())) != 1) fail("RAND_bytes");
    return str(s);
  });
  g.method<Host>("Ssl", "rand_hex", {"int"}, "string", [](Host &, Args &a) {
    if (a[0].i < 0 || a[0].i > (1 << 24)) throw std::runtime_error("size out of range");
    std::string s(static_cast<size_t>(a[0].i), '\0');
    if (!s.empty() && RAND_bytes(reinterpret_cast<unsigned char *>(&s[0]), static_cast<int>(s.size())) != 1) fail("RAND_bytes");
    return str(to_hex(s));
  });
  g.method<Host>("Ssl", "digest", {"string", "string"}, "string", [](Host &, Args &a) {
    MdP md = fetch_md(a[0].s);
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned n = 0;
    if (!EVP_Digest(a[1].s.data(), a[1].s.size(), buf, &n, md.get(), nullptr)) fail("digest");
    return str(to_hex(buf, n));
  });
  g.method<Host>("Ssl", "hmac", {"string", "string", "string"}, "string", [](Host &, Args &a) {
    unsigned char buf[EVP_MAX_MD_SIZE];
    size_t n = 0;
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, a[0].s.c_str(), nullptr, a[1].s.data(), a[1].s.size(),
                   reinterpret_cast<const unsigned char *>(a[2].s.data()), a[2].s.size(), buf, sizeof buf, &n))
      fail("HMAC with digest '" + a[0].s + "'");
    return str(to_hex(buf, n));
  });
  g.method<Host>("Ssl", "pbkdf2", {"string", "string", "int", "string", "int"}, "string", [](Host &, Args &a) {
    MdP md = fetch_md(a[3].s);
    if (a[2].i < 1 || a[4].i < 1 || a[4].i > 1024) throw std::runtime_error("iterations must be >= 1 and length in 1..1024");
    std::string out(static_cast<size_t>(a[4].i), '\0');
    if (!PKCS5_PBKDF2_HMAC(a[0].s.data(), static_cast<int>(a[0].s.size()), reinterpret_cast<const unsigned char *>(a[1].s.data()),
                           static_cast<int>(a[1].s.size()), static_cast<int>(a[2].i), md.get(), static_cast<int>(out.size()),
                           reinterpret_cast<unsigned char *>(&out[0])))
      fail("PBKDF2");
    return str(to_hex(out));
  });
  // seal(alg, key_hex, iv_hex, aad, plaintext) -> hex(ciphertext || 16-byte tag)
  g.method<Host>("Ssl", "seal", {"string", "string", "string", "string", "string"}, "string", [](Host &, Args &a) {
    CipherP ci(EVP_CIPHER_fetch(nullptr, a[0].s.c_str(), nullptr));
    if (!ci) fail("unknown cipher '" + a[0].s + "'");
    std::string key = from_hex(a[1].s), iv = from_hex(a[2].s);
    if (static_cast<int>(key.size()) != EVP_CIPHER_get_key_length(ci.get())) throw std::runtime_error("key must be " + std::to_string(EVP_CIPHER_get_key_length(ci.get())) + " bytes");
    std::unique_ptr<EVP_CIPHER_CTX, Free<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>> c(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(c.get(), ci.get(), nullptr, nullptr, nullptr) != 1) fail("cipher init");
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) fail("bad IV length " + std::to_string(iv.size()));
    if (EVP_EncryptInit_ex(c.get(), nullptr, nullptr, reinterpret_cast<const unsigned char *>(key.data()), reinterpret_cast<const unsigned char *>(iv.data())) != 1) fail("cipher key/iv");
    int n = 0;
    if (!a[3].s.empty() && EVP_EncryptUpdate(c.get(), nullptr, &n, reinterpret_cast<const unsigned char *>(a[3].s.data()), static_cast<int>(a[3].s.size())) != 1) fail("aad");
    std::string out(a[4].s.size() + 32, '\0');
    int len = 0, total = 0;
    if (EVP_EncryptUpdate(c.get(), reinterpret_cast<unsigned char *>(&out[0]), &len, reinterpret_cast<const unsigned char *>(a[4].s.data()), static_cast<int>(a[4].s.size())) != 1) fail("encrypt");
    total = len;
    if (EVP_EncryptFinal_ex(c.get(), reinterpret_cast<unsigned char *>(&out[0]) + total, &len) != 1) fail("encrypt final");
    total += len;
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) fail("get tag (is this an AEAD cipher?)");
    out.resize(static_cast<size_t>(total));
    out.append(reinterpret_cast<char *>(tag), 16);
    return str(to_hex(out));
  });
  g.method<Host>("Ssl", "open", {"string", "string", "string", "string", "string"}, "string", [](Host &, Args &a) {
    CipherP ci(EVP_CIPHER_fetch(nullptr, a[0].s.c_str(), nullptr));
    if (!ci) fail("unknown cipher '" + a[0].s + "'");
    std::string key = from_hex(a[1].s), iv = from_hex(a[2].s), sealed = from_hex(a[4].s);
    if (sealed.size() < 16) throw std::runtime_error("sealed data is shorter than the 16-byte tag");
    if (static_cast<int>(key.size()) != EVP_CIPHER_get_key_length(ci.get())) throw std::runtime_error("key must be " + std::to_string(EVP_CIPHER_get_key_length(ci.get())) + " bytes");
    std::string tag = sealed.substr(sealed.size() - 16);
    sealed.resize(sealed.size() - 16);
    std::unique_ptr<EVP_CIPHER_CTX, Free<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>> c(EVP_CIPHER_CTX_new());
    if (EVP_DecryptInit_ex(c.get(), ci.get(), nullptr, nullptr, nullptr) != 1) fail("cipher init");
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) fail("bad IV length " + std::to_string(iv.size()));
    if (EVP_DecryptInit_ex(c.get(), nullptr, nullptr, reinterpret_cast<const unsigned char *>(key.data()), reinterpret_cast<const unsigned char *>(iv.data())) != 1) fail("cipher key/iv");
    int n = 0;
    if (!a[3].s.empty() && EVP_DecryptUpdate(c.get(), nullptr, &n, reinterpret_cast<const unsigned char *>(a[3].s.data()), static_cast<int>(a[3].s.size())) != 1) fail("aad");
    std::string out(sealed.size() + 32, '\0');
    int len = 0, total = 0;
    if (EVP_DecryptUpdate(c.get(), reinterpret_cast<unsigned char *>(&out[0]), &len, reinterpret_cast<const unsigned char *>(sealed.data()), static_cast<int>(sealed.size())) != 1) fail("decrypt");
    total = len;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_TAG, 16, &tag[0]) != 1) fail("set tag");
    if (EVP_DecryptFinal_ex(c.get(), reinterpret_cast<unsigned char *>(&out[0]) + total, &len) != 1) {
      ERR_clear_error();
      throw std::runtime_error("authentication failed (wrong key, IV, AAD or tampered data)");
    }
    total += len;
    out.resize(static_cast<size_t>(total));
    return str(out);
  });
  g.method<Host>("Ssl", "gen_rsa", {"int"}, "Key", [&g](Host &, Args &a) {
    if (a[0].i < 512 || a[0].i > 16384) throw std::runtime_error("RSA size must be 512..16384 bits");
    PKey k(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(a[0].i)));
    if (!k) fail("RSA key generation");
    return g.wrap("Key", new KeyObj{std::move(k)});
  });
  g.method<Host>("Ssl", "gen_ec", {"string"}, "Key", [&g](Host &, Args &a) {
    PKey k(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", a[0].s.c_str()));
    if (!k) fail("EC key generation on curve '" + a[0].s + "'");
    return g.wrap("Key", new KeyObj{std::move(k)});
  });
  g.method<Host>("Ssl", "gen_ed25519", {}, "Key", [&g](Host &, Args &) {
    PKey k(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    if (!k) fail("Ed25519 key generation");
    return g.wrap("Key", new KeyObj{std::move(k)});
  });
  g.method<Host>("Ssl", "load_key", {"string"}, "Key", [&g](Host &, Args &a) { return g.wrap("Key", new KeyObj{read_key_pem(slurp(a[0].s), "", false)}); });
  g.method<Host>("Ssl", "load_key", {"string", "string"}, "Key", [&g](Host &, Args &a) { return g.wrap("Key", new KeyObj{read_key_pem(slurp(a[0].s), a[1].s, true)}); });
  g.method<Host>("Ssl", "parse_key", {"string"}, "Key", [&g](Host &, Args &a) { return g.wrap("Key", new KeyObj{read_key_pem(a[0].s, "", false)}); });
  g.method<Host>("Ssl", "new_cert", {"Key", "string"}, "Cert", [&g](Host &, Args &a) {
    auto *k = static_cast<KeyObj *>(a[0].obj);
    X509p x(X509_new());
    if (!x) fail("X509_new");
    X509_set_version(x.get(), X509_VERSION_3);
    ASN1_INTEGER_set_int64(X509_get_serialNumber(x.get()), random_serial());
    X509_gmtime_adj(X509_getm_notBefore(x.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 60L * 60 * 24 * 365);
    {
      std::unique_ptr<X509_NAME, Free<X509_NAME, X509_NAME_free>> name(X509_NAME_new());
      set_name(name.get(), a[1].s);
      if (!X509_set_subject_name(x.get(), name.get())) fail("set subject");
    }
    if (!X509_set_pubkey(x.get(), k->key.get())) fail("X509_set_pubkey");
    return g.wrap("Cert", new CertObj{std::move(x)});
  });
  g.method<Host>("Ssl", "cert_from_csr", {"Csr"}, "Cert", [&g](Host &, Args &a) {
    auto *c = static_cast<CsrObj *>(a[0].obj);
    EVP_PKEY *pk = X509_REQ_get0_pubkey(c->req.get());
    if (!pk || X509_REQ_verify(c->req.get(), pk) != 1) fail("the CSR signature is invalid or missing");
    X509p x(X509_new());
    X509_set_version(x.get(), X509_VERSION_3);
    ASN1_INTEGER_set_int64(X509_get_serialNumber(x.get()), random_serial());
    X509_gmtime_adj(X509_getm_notBefore(x.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 60L * 60 * 24 * 365);
    if (!X509_set_subject_name(x.get(), X509_REQ_get_subject_name(c->req.get())) || !X509_set_pubkey(x.get(), pk)) fail("copy CSR fields");
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(c->req.get());
    for (int i = 0; exts && i < sk_X509_EXTENSION_num(exts); ++i)
      if (!X509_add_ext(x.get(), sk_X509_EXTENSION_value(exts, i), -1)) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); fail("copy CSR extension"); }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return g.wrap("Cert", new CertObj{std::move(x)});
  });
  g.method<Host>("Ssl", "load_cert", {"string"}, "Cert", [&g](Host &, Args &a) { return g.wrap("Cert", new CertObj{read_cert_pem(slurp(a[0].s))}); });
  g.method<Host>("Ssl", "parse_cert", {"string"}, "Cert", [&g](Host &, Args &a) { return g.wrap("Cert", new CertObj{read_cert_pem(a[0].s)}); });
  g.method<Host>("Ssl", "new_csr", {"Key", "string"}, "Csr", [&g](Host &, Args &a) {
    auto *k = static_cast<KeyObj *>(a[0].obj);
    Reqp r(X509_REQ_new());
    if (!r) fail("X509_REQ_new");
    X509_REQ_set_version(r.get(), X509_REQ_VERSION_1);
    {
      std::unique_ptr<X509_NAME, Free<X509_NAME, X509_NAME_free>> name(X509_NAME_new());
      set_name(name.get(), a[1].s);
      if (!X509_REQ_set_subject_name(r.get(), name.get())) fail("set subject");
    }
    if (!X509_REQ_set_pubkey(r.get(), k->key.get())) fail("X509_REQ_set_pubkey");
    return g.wrap("Csr", new CsrObj{std::move(r), {}});
  });
  g.method<Host>("Ssl", "load_csr", {"string"}, "Csr", [&g](Host &, Args &a) {
    std::string pem = slurp(a[0].s);
    Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    Reqp r(PEM_read_bio_X509_REQ(b.get(), nullptr, nullptr, nullptr));
    if (!r) fail("not a PEM certificate request");
    return g.wrap("Csr", new CsrObj{std::move(r), {}});
  });
  auto new_ctx = [&g](bool server) {
    auto c = std::make_unique<TlsCtxObj>();
    c->server = server;
    c->ctx.reset(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()));
    if (!c->ctx) fail("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(c->ctx.get(), TLS1_2_VERSION);
    SSL_CTX_set_options(c->ctx.get(), SSL_OP_IGNORE_UNEXPECTED_EOF);  // HTTP/1.0-style servers close without close_notify
    if (!server) SSL_CTX_set_verify(c->ctx.get(), SSL_VERIFY_PEER, nullptr);
    return c;
  };
  g.method<Host>("Ssl", "client_ctx", {}, "TlsCtx", [&g, new_ctx](Host &, Args &) { return g.wrap("TlsCtx", new_ctx(false).release()); });
  g.method<Host>("Ssl", "server_ctx", {"Cert", "Key"}, "TlsCtx", [&g, new_ctx](Host &, Args &a) {
    auto c = new_ctx(true);
    if (SSL_CTX_use_certificate(c->ctx.get(), static_cast<CertObj *>(a[0].obj)->x.get()) != 1) fail("use certificate");
    if (SSL_CTX_use_PrivateKey(c->ctx.get(), static_cast<KeyObj *>(a[1].obj)->key.get()) != 1) fail("use private key");
    if (SSL_CTX_check_private_key(c->ctx.get()) != 1) fail("certificate and key do not match");
    return g.wrap("TlsCtx", c.release());
  });
}

}  // namespace lmssl
