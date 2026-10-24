#pragma once
// The complete built-in standard. Include dslvm.hpp normally; individual catalog
// headers also finish this aggregator after their own declarations are complete.
#define DSLVM_STD_BUILDING
#include "string.hpp"
#include "math.hpp"
#include "collections.hpp"
#include "testing.hpp"
#undef DSLVM_STD_BUILDING

namespace dslvm {
namespace stdlib {
struct StdRuntime {
  Collections collections;
  bool running = false;
};
} // namespace stdlib

inline Registry::Registry(StdMode mode) {
  if (mode == StdMode::Enabled) register_std(*this);
}

inline Registry& register_std(Registry& registry) {
  if (registry.has_std()) return registry;
  // Build transactionally: a conflicting host declaration leaves the original intact.
  Registry candidate(StdMode::Disabled);
  candidate = registry;
  candidate.std_runtime_ = std::make_shared<stdlib::StdRuntime>();
  const auto before = candidate.signatures();
  stdlib::register_string(candidate);
  stdlib::register_math(candidate);
  stdlib::register_collections(candidate, candidate.std_runtime_->collections);
  stdlib::register_testing(candidate);
  const auto after = candidate.signatures();
  std::set_difference(after.begin(), after.end(), before.begin(), before.end(), std::back_inserter(candidate.std_signatures_));
  candidate.std_initialized_ = true;
  registry = std::move(candidate);
  return registry;
}

inline stdlib::Collections& Registry::std_collections() const {
  if (!has_std()) throw Error("std: registry has standard library disabled");
  return std_runtime_->collections;
}
inline void Registry::set_std_output(std::ostream* sink) {
  if (!has_std()) throw Error("std: registry has standard library disabled");
  auto* output = sink ? sink : &std::cout;
  functions_.at("fn print(string) -> void").entry.fn = [output](Args& args) {
    stdlib::testing_print(*output, args[0].s); return Value::none();
  };
}
inline void Registry::begin_std_run() const {
  if (std_runtime_->running) throw Error("std: registry already has an active run");
  std_runtime_->collections.reset();
  std_runtime_->running = true;
}
inline void Registry::end_std_run() const noexcept {
  std_runtime_->collections.reset();
  std_runtime_->running = false;
}
} // namespace dslvm
