// lmssl: the OpenSSL command line, statically linked, plus `--lmcode FILE`, which runs lmscript _dsl_ bytecode
// against the same libcrypto/libssl.
#include "dslvm.hpp"
#include "host.hpp"
#include "cnf_embedded.hpp"
#include "schema_embedded.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <iostream>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <string>

// apps/openssl.c compiled with -Dmain=lmssl_openssl_main (see CMakeLists.txt).
extern "C" int lmssl_openssl_main(int argc, char **argv);

namespace {
const char kUsage[] =
    "usage: lmssl --version | --lmcode-schema [--json] | --lmcode-signatures\n"
    "       lmssl [--json] --lmcode FILE.dslb [ARG ...]   run compiled _dsl_ bytecode; ARGs reach ssl.args()\n"
    "       lmssl COMMAND [ARG ...]                    anything else is the OpenSSL command line (try: lmssl help)\n";

void print_schema_summary(dslvm::Registry &reg) {
  std::string current;
  for (const auto &sig : reg.signatures()) {
    if (sig.rfind("context ", 0) == 0) { std::cout << "context " << sig.substr(8) << "\n"; continue; }
    if (sig.rfind("fn ", 0) == 0) { std::cout << "fn " << sig.substr(3) << "\n"; continue; }
    std::string body = sig.substr(7);
    std::string type = body.substr(0, body.find('.'));
    if (type != current) { current = type; std::cout << type << ":\n"; }
    std::cout << "  " << body << "\n";
  }
}

std::string g_temp_cnf;
void remove_temp_cnf() { if (!g_temp_cnf.empty()) { std::error_code ec; std::filesystem::remove(g_temp_cnf, ec); } }

// A static binary has no usable OPENSSLDIR. If the user did not name a config and the compiled-in default is
// absent, give the OpenSSL command line the stock openssl.cnf (embedded) through a temporary OPENSSL_CONF.
void ensure_config() {
  if (std::getenv("OPENSSL_CONF") && *std::getenv("OPENSSL_CONF")) return;
  std::error_code ec;
  if (std::filesystem::exists(std::string(X509_get_default_cert_area()) + "/openssl.cnf", ec)) return;
  std::random_device rd;
  auto path = std::filesystem::temp_directory_path(ec) / ("lmssl-" + std::to_string(rd()) + ".cnf");
  std::ofstream f(path, std::ios::binary);
  if (!f) return;
  f.write(reinterpret_cast<const char *>(lmssl::stock_cnf), static_cast<std::streamsize>(lmssl::stock_cnf_size));
  f.close();
  g_temp_cnf = path.string();
  std::atexit(remove_temp_cnf);
#ifdef _WIN32
  _putenv_s("OPENSSL_CONF", g_temp_cnf.c_str());
#else
  setenv("OPENSSL_CONF", g_temp_cnf.c_str(), 1);
#endif
}
}  // namespace

int main(int argc, char **argv) {
  const std::string first = argc > 1 ? argv[1] : "";
#ifdef _WIN32
  // Text mode would turn \n into \r\n: --lmcode-schema --json must stay byte-identical and the result line one line.
  _setmode(_fileno(stdout), _O_BINARY);
  _setmode(_fileno(stderr), _O_BINARY);
#endif
  const bool ours = first == "--version" || first == "--lmcode-schema" || first == "--lmcode-signatures" || first == "--lmcode" || first == "--json";
  if (!ours) {
    ensure_config();
    return lmssl_openssl_main(argc, argv);
  }

  lmssl::Host host;
  dslvm::Registry reg;
  lmssl::register_host(reg, host);

  if (argc == 2 && first == "--version") {
    // "lmssl X.Y.Z": lmscript install="github:...@latest" compares this with the release tag.
    std::cout << "lmssl " LMSSL_VERSION " (" << OpenSSL_version(OPENSSL_VERSION) << ")\n";
    return std::cout ? 0 : 4;
  }
  if (first == "--lmcode-schema") {
    if (argc == 2) { print_schema_summary(reg); return std::cout ? 0 : 4; }
    if (argc == 3 && std::string(argv[2]) == "--json") {
      std::cout.write(reinterpret_cast<const char *>(lmssl::embedded_schema), static_cast<std::streamsize>(lmssl::embedded_schema_size));
      return std::cout ? 0 : 4;
    }
    std::cerr << kUsage;
    return 2;
  }
  if (argc == 2 && first == "--lmcode-signatures") {
    for (const auto &s : reg.signatures()) std::cout << s << "\n";
    return 0;
  }

  int at = 1;
  if (first == "--json") { host.json_mode = true; at = 2; }
  if (argc < at + 2 || std::string(argv[at]) != "--lmcode") { std::cerr << kUsage; return 2; }
  const std::string file = argv[at + 1];
  for (int i = at + 2; i < argc; ++i) host.args.push_back(argv[i]);

  const std::string schema(reinterpret_cast<const char *>(lmssl::embedded_schema), lmssl::embedded_schema_size);
  dslvm::Context context;
  context.set("ssl", &host);
  context.set("out", &host);
  context.set("fs", &host);
  context.set("net", &host);

  auto report = [&](const char *phase, const dslvm::Error &e) {
    if (host.json_mode) return dslvm::report_error(e.code == "APP_FAIL" ? "app" : phase, e);
    std::cerr << "lmssl: " << (std::string(phase) == "load" ? "refused: " : e.code == "APP_FAIL" ? "" : "error: ") << e.what() << "\n";
    return e.code == "APP_FAIL" ? 4 : 3;
  };
  dslvm::Program program;
  try {
    program = dslvm::Program::load(dslvm::read_file(file), schema, reg);
  } catch (const dslvm::Error &e) {
    return report("load", e);
  } catch (const std::exception &e) {
    return report("load", dslvm::Error("LOAD_BAD_BYTECODE", e.what()));
  }
  try {
    program.run(context, reg);
  } catch (const dslvm::Error &e) {
    std::cout.flush();
    return report("run", e);
  }
  std::cout.flush();
  return host.json_mode ? dslvm::report_ok() : 0;
}
