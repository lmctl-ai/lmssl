// lmssl host: registers the lmssl.dsl.json schema (OpenSSL libcrypto/libssl facade) with a dslvm::Registry.
#pragma once
#include "dslvm.hpp"
#include "stdlib/collections.hpp"
#include <memory>
#include <string>
#include <vector>

namespace lmssl {

struct Host {
  std::vector<std::shared_ptr<void>> arena;  // every object a script has been handed lives until the run ends
  std::vector<std::string> args;             // ssl.args(): the words after the bytecode file name
  bool json_mode = false;                    // --json: script output goes to stderr, stdout carries the result line
  int timeout_seconds = 30;                  // net.timeout(): socket read/write timeout for new connections
};

// The four context objects of the schema all point at the host.
void register_host(dslvm::Registry &reg, Host &host);

}  // namespace lmssl
