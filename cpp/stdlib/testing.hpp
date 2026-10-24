#pragma once
// Optional host-side testing helpers. Copy testing.schema-fragment.json into
// the host schema and call register_testing(registry).
//
// The sink pointer is captured by the registered callbacks; when supplied it
// must remain alive and writable for every call made through the registry. A
// null sink selects std::cout at registration time.
#include "dslvm.hpp"
#include <cmath>
#include <cstdio>
#include <iostream>
#include <ostream>
#include <string>

namespace dslvm::stdlib {

inline void testing_print(std::ostream& sink, const std::string& value) {
  sink.write(value.data(), static_cast<std::streamsize>(value.size()));
  sink.put('\n');
}

inline void testing_assert_close(double a, double b, double tolerance) {
  // Keep this deliberately as an explicit comparison: equal infinities
  // subtract to NaN and therefore fail, as do NaN operands and tolerances.
  if (std::fabs(a - b) <= tolerance) return;
  char message[160];
  std::snprintf(message, sizeof(message), "assert_close failed: %.15g vs %.15g (tol %.15g)", a, b, tolerance);
  throw Error(message);
}

inline Registry& register_testing(Registry& r, std::ostream* sink = nullptr) {
  std::ostream* output = sink ? sink : &std::cout;
  r.function("print", {"string"}, "void", [output](Args& a) {
    testing_print(*output, a[0].s);
    return Value::none();
  });
  r.function("assert_close", {"float", "float", "float"}, "void", [](Args& a) {
    testing_assert_close(a[0].f, a[1].f, a[2].f);
    return Value::none();
  });
  return r;
}

} // namespace dslvm::stdlib
