// lmssl: the OpenSSL command line, statically linked, plus `--lmcode FILE`, which runs lmscript _lmcode_ bytecode
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
#include <optional>
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
    "       lmssl [--json] [--dry-run] --lmcode FILE [ARG ...] [--lmcode FILE ...]   run compiled _lmcode_ bytecode; ARGs reach ssl.args()\n"
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
  const bool ours = first == "--version" || first == "--lmcode-schema" || first == "--lmcode-signatures" || first == "--lmcode" || first == "--json" || first == "--dry-run";
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

  auto usage_error = [&]() {
    std::cerr << kUsage;
    return dslvm::failure_frame("cli", dslvm::Error("CLI_USAGE", "invalid lmcode arguments"));
  };
  int at = 1;
  bool dry = false;
  bool json = false; // Compatibility flag; all lmcode results now use frames.
  while (at < argc && (std::string(argv[at]) == "--json" || std::string(argv[at]) == "--dry-run")) {
    if (std::string(argv[at]) == "--json") { if (json) return usage_error(); json = true; }
    else { if (dry) return usage_error(); dry = true; }
    ++at;
  }
  std::vector<std::string> files;
  std::vector<std::vector<std::string>> arguments;
  // Repeat --lmcode FILE to add a part; other words retain their ssl.args() meaning.
  while (at < argc) {
    if (std::string(argv[at++]) != "--lmcode" || at >= argc) return usage_error();
    std::string file = argv[at++];
    if (file.empty() || file.rfind("--", 0) == 0) return usage_error();
    files.push_back(file);
    arguments.emplace_back();
    while (at < argc && std::string(argv[at]) != "--lmcode") arguments.back().push_back(argv[at++]);
  }
  if (files.empty()) return usage_error();
  std::optional<dslvm::InvocationResults> holder;
  try {
    if (dry && !std::getenv("LMCODE_INVOCATION_FILE")) holder.emplace(dslvm::InvocationResults::from_command(files, true));
    else holder.emplace(dslvm::InvocationResults::from_command(files));
  } catch (const dslvm::Error &e) { return dslvm::failure_frame("cli", e); }
  auto &results = *holder;
  if (dry && !results.dry()) return dslvm::failure_frame("cli", dslvm::Error("CLI_USAGE", "--dry-run contradicts real-mode metadata"));
  const std::string schema(reinterpret_cast<const char *>(lmssl::embedded_schema), lmssl::embedded_schema_size);
  dslvm::Context context;
  context.set("ssl", &host);
  context.set("out", &host);
  context.set("fs", &host);
  context.set("net", &host);
  dslvm::ResultContract contract;
  try { contract = dslvm::ResultContract::from_schema(schema); }
  catch (const dslvm::Error &e) { results.fail(std::nullopt, "load", e); return results.write_frame(std::cout); }
  std::vector<std::pair<size_t, dslvm::Program>> programs;
  for (const auto &part : results.registrations()) {
    try { programs.emplace_back(part.index, dslvm::Program::load(dslvm::read_file(part.file), schema, reg)); }
    catch (const dslvm::Error &e) { std::cerr << "lmssl: refused: " << e.what() << "\n"; results.fail(part.index, "load", e); return results.write_frame(std::cout); }
    catch (const std::exception &e) { std::cerr << e.what() << "\n"; results.fail(part.index, "load", dslvm::Error("LOAD_BAD_BYTECODE", e.what())); return results.write_frame(std::cout); }
  }
  for (auto &[index, program] : programs) {
    try {
      host.args = arguments[index];
      results.select(index, reg, contract);
      // Dry mode validates all programs without filesystem, socket, TLS or key-generation effects.
      if (!results.dry()) program.run(context, reg);
      results.complete(index);
    } catch (const dslvm::Error &e) {
      std::cerr << "lmssl: " << e.what() << "\n";
      results.fail(index, e.code == "APP_FAIL" ? "app" : "run", e); break;
    } catch (const std::exception &e) { std::cerr << e.what() << "\n"; results.fail(index, "run", dslvm::Error(e.what())); break; }
  }
  return results.write_frame(std::cout);
}
