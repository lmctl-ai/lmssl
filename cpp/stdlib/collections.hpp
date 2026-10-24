#pragma once
#include "dslvm.hpp"
#include <algorithm>
#include <deque>
#include <utility>
#include <vector>

namespace dslvm::stdlib {
template<class T> struct CollectionList { std::vector<T> items; };
using StrList = CollectionList<std::string>;
using IntList = CollectionList<int64_t>;
using FloatList = CollectionList<double>;
struct StrMap { std::vector<std::pair<std::string, std::string>> items; };

// Stable addresses for the whole run. Keep this arena and its registry alive
// while any handle is in use. Reset only between runs, after all handles expire.
struct Collections {
  std::deque<StrList> str_lists;
  std::deque<IntList> int_lists;
  std::deque<FloatList> float_lists;
  std::deque<StrMap> str_maps;
  size_t size() const { return str_lists.size() + int_lists.size() + float_lists.size() + str_maps.size(); }
  void reset() { str_lists.clear(); int_lists.clear(); float_lists.clear(); str_maps.clear(); }
  void reserve_object(const char* type) const {
    if (size() >= 65536) throw Error(std::string(type) + " object limit exceeded (65536)");
  }
  StrList* make_str_list(std::vector<std::string> values = {}) { reserve_object("StrList"); str_lists.push_back({std::move(values)}); return &str_lists.back(); }
  IntList* make_int_list(std::vector<int64_t> values = {}) { reserve_object("IntList"); int_lists.push_back({std::move(values)}); return &int_lists.back(); }
  FloatList* make_float_list(std::vector<double> values = {}) { reserve_object("FloatList"); float_lists.push_back({std::move(values)}); return &float_lists.back(); }
  StrMap* make_str_map() { reserve_object("StrMap"); str_maps.emplace_back(); return &str_maps.back(); }
};

namespace detail {
inline size_t collection_index(int64_t i, size_t size, const std::string& method) {
  if (i < 0 || uint64_t(i) >= size) throw Error(method + ": index out of range: " + std::to_string(i));
  return size_t(i);
}
template<class T> struct CollectionValue;
template<> struct CollectionValue<std::string> {
  static const std::string& get(const Value& v) { return v.s; }
  static Value put(const std::string& v) { return Value::string(v); }
};
template<> struct CollectionValue<int64_t> {
  static int64_t get(const Value& v) { return v.i; }
  static Value put(int64_t v) { return Value::integer(v); }
};
template<> struct CollectionValue<double> {
  static double get(const Value& v) { return v.f; }
  static Value put(double v) { return Value::real(v); }
};
template<class T> inline void register_collection_list(Registry& r, const std::string& type, const std::string& element) {
  using List = CollectionList<T>; using Codec = CollectionValue<T>;
  r.method(type, "len", {}, "int", [](void* p, Args&) { return Value::integer(int64_t(static_cast<List*>(p)->items.size())); });
  r.method(type, "at", {"int"}, element, [type](void* p, Args& a) {
    auto& items = static_cast<List*>(p)->items;
    return Codec::put(items[collection_index(a[0].i, items.size(), type + ".at")]);
  });
  r.method(type, "add", {element}, type, [type](void* p, Args& a) {
    static_cast<List*>(p)->items.push_back(Codec::get(a[0])); return Value::object(type, p);
  });
  r.method(type, "set", {"int", element}, type, [type](void* p, Args& a) {
    auto& items = static_cast<List*>(p)->items;
    items[collection_index(a[0].i, items.size(), type + ".set")] = Codec::get(a[1]); return Value::object(type, p);
  });
  r.method(type, "contains", {element}, "bool", [](void* p, Args& a) {
    const auto& items = static_cast<List*>(p)->items;
    return Value::boolean(std::find(items.begin(), items.end(), Codec::get(a[0])) != items.end());
  });
  r.method(type, "index_of", {element}, "int", [](void* p, Args& a) {
    const auto& items = static_cast<List*>(p)->items; auto found = std::find(items.begin(), items.end(), Codec::get(a[0]));
    return Value::integer(found == items.end() ? -1 : int64_t(found - items.begin()));
  });
  r.method(type, "clear", {}, type, [type](void* p, Args&) { static_cast<List*>(p)->items.clear(); return Value::object(type, p); });
}
} // namespace detail

inline Registry& register_collections(Registry& r, Collections& arena) {
  detail::register_collection_list<std::string>(r, "StrList", "string");
  detail::register_collection_list<int64_t>(r, "IntList", "int");
  detail::register_collection_list<double>(r, "FloatList", "float");
  r.method("StrList", "join", {"string"}, "string", [](void* p, Args& a) {
    std::string out; bool first = true;
    for (const auto& item : static_cast<StrList*>(p)->items) { if (!first) out += a[0].s; out += item; first = false; }
    return Value::string(std::move(out));
  });
  r.function("str_list", {}, "StrList", [&arena](Args&) { return Value::object("StrList", arena.make_str_list()); });
  r.function("int_list", {}, "IntList", [&arena](Args&) { return Value::object("IntList", arena.make_int_list()); });
  r.function("float_list", {}, "FloatList", [&arena](Args&) { return Value::object("FloatList", arena.make_float_list()); });
  r.function("str_map", {}, "StrMap", [&arena](Args&) { return Value::object("StrMap", arena.make_str_map()); });
  r.function("str_split", {"string", "string"}, "StrList", [&arena](Args& a) {
    if (a[1].s.empty()) throw Error("str_split: separator must not be empty");
    arena.reserve_object("StrList");
    std::vector<std::string> items; size_t at = 0, found;
    while ((found = a[0].s.find(a[1].s, at)) != std::string::npos) { items.push_back(a[0].s.substr(at, found - at)); at = found + a[1].s.size(); }
    items.push_back(a[0].s.substr(at)); return Value::object("StrList", arena.make_str_list(std::move(items)));
  });
  r.method("StrMap", "len", {}, "int", [](void* p, Args&) { return Value::integer(int64_t(static_cast<StrMap*>(p)->items.size())); });
  r.method("StrMap", "has", {"string"}, "bool", [](void* p, Args& a) {
    const auto& items = static_cast<StrMap*>(p)->items;
    return Value::boolean(std::any_of(items.begin(), items.end(), [&](const auto& item) { return item.first == a[0].s; }));
  });
  r.method("StrMap", "get", {"string"}, "string", [](void* p, Args& a) {
    for (const auto& item : static_cast<StrMap*>(p)->items) if (item.first == a[0].s) return Value::string(item.second);
    throw Error("StrMap.get: missing key"); return Value::none();
  });
  r.method("StrMap", "get_or", {"string", "string"}, "string", [](void* p, Args& a) {
    for (const auto& item : static_cast<StrMap*>(p)->items) if (item.first == a[0].s) return Value::string(item.second);
    return Value::string(a[1].s);
  });
  r.method("StrMap", "set", {"string", "string"}, "StrMap", [](void* p, Args& a) {
    auto& items = static_cast<StrMap*>(p)->items;
    for (auto& item : items) if (item.first == a[0].s) { item.second = a[1].s; return Value::object("StrMap", p); }
    items.emplace_back(a[0].s, a[1].s); return Value::object("StrMap", p);
  });
  r.method("StrMap", "key_at", {"int"}, "string", [](void* p, Args& a) {
    const auto& items = static_cast<StrMap*>(p)->items;
    return Value::string(items[detail::collection_index(a[0].i, items.size(), "StrMap.key_at")].first);
  });
  r.method("StrMap", "remove", {"string"}, "bool", [](void* p, Args& a) {
    auto& items = static_cast<StrMap*>(p)->items;
    auto found = std::find_if(items.begin(), items.end(), [&](const auto& item) { return item.first == a[0].s; });
    if (found == items.end()) return Value::boolean(false);
    items.erase(found); return Value::boolean(true);
  });
  r.method("StrMap", "clear", {}, "StrMap", [](void* p, Args&) { static_cast<StrMap*>(p)->items.clear(); return Value::object("StrMap", p); });
  return r;
}
} // namespace dslvm::stdlib
