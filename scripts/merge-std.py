#!/usr/bin/env python3
"""Merge, strip, or normalize the compiler-compatible lmcode standard schema."""
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent

def read_text(path):
    return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()

def read_json(path):
    return json.loads(read_text(path).decode("utf-8"))

def write_text(path, data):
    if path == "-":
        sys.stdout.buffer.write(data.encode("utf-8"))
    else:
        Path(path).write_text(data, encoding="utf-8", newline="\n")

def std_path(explicit):
    if explicit:
        return Path(explicit)
    for candidate in (ROOT / "std/lmcode-std.schema.json", ROOT / "cpp/std/lmcode-std.schema.json"):
        if candidate.is_file():
            return candidate
    raise ValueError("cannot locate std/lmcode-std.schema.json; pass --std PATH")

def overloads(value):
    return value if isinstance(value, list) else [value]

def normalized_return(declaration, owner=None):
    value = declaration.get("returns")
    return owner if value == "self" else value

def same_signature(left, right, owner=None):
    return left.get("params") == right.get("params") and normalized_return(left, owner) == normalized_return(right, owner)

def merge_overloads(target, source, label, owner=None):
    for name, wanted in source.items():
        existing = target.setdefault(name, [])
        for declaration in overloads(wanted):
            matching = [item for item in existing if item.get("params") == declaration.get("params")]
            if matching and not any(same_signature(item, declaration, owner) for item in matching):
                raise ValueError(f"conflicting {label} {name}{tuple(declaration.get('params', []))}")
            if not matching:
                existing.append(copy.deepcopy(declaration))

def merge_schema(host, standard):
    if host.get("dsl.schema") != 2 or standard.get("dsl.schema") != 2:
        raise ValueError("host and std schemas must use dsl.schema 2")
    result = copy.deepcopy(host)
    merge_overloads(result.setdefault("functions", {}), standard.get("functions", {}), "function")
    types = result.setdefault("types", {})
    for name, definition in standard.get("types", {}).items():
        if name not in types:
            types[name] = copy.deepcopy(definition)
            continue
        current = types[name]
        for key, value in definition.items():
            if key == "methods":
                merge_overloads(current.setdefault("methods", {}), value, f"method {name}.", owner=name)
            elif key in current and current[key] != value:
                raise ValueError(f"conflicting type {name}.{key}")
            else:
                current[key] = copy.deepcopy(value)
    return result

def remove_standard(schema, standard):
    result = copy.deepcopy(schema)
    for name, wanted in standard.get("functions", {}).items():
        if name not in result.get("functions", {}):
            continue
        kept = [item for item in overloads(result["functions"][name]) if not any(same_signature(item, item2) for item2 in overloads(wanted))]
        if kept:
            result["functions"][name] = kept
        else:
            del result["functions"][name]
    for name, definition in standard.get("types", {}).items():
        current = result.get("types", {}).get(name)
        if not current:
            continue
        for method, wanted in definition.get("methods", {}).items():
            if method not in current.get("methods", {}):
                continue
            kept = [item for item in overloads(current["methods"][method]) if not any(same_signature(item, item2, name) for item2 in overloads(wanted))]
            if kept:
                current["methods"][method] = kept
            else:
                del current["methods"][method]
        if not current.get("methods") and not any(key != "methods" for key in current):
            del result["types"][name]
    return result

def signature_strings(schema):
    result = {f"context {name}: {owner}" for name, owner in schema.get("context", {}).items()}
    for name, declarations in schema.get("functions", {}).items():
        for declaration in overloads(declarations):
            result.add(f"fn {name}({', '.join(declaration.get('params', []))}) -> {declaration.get('returns')}")
    for owner, definition in schema.get("types", {}).items():
        for name, declarations in definition.get("methods", {}).items():
            for declaration in overloads(declarations):
                result.add(f"method {owner}.{name}({', '.join(declaration.get('params', []))}) -> {normalized_return(declaration, owner)}")
    return result

def canonical_signatures(standard):
    return signature_strings(standard)

def json_output(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"

def normalized_input(path):
    raw = read_text(path)
    try:
        value = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        lines = raw.split(b"\n")
        return {line[:-1].decode("utf-8") if line.endswith(b"\r") else line.decode("utf-8") for line in lines if line.rstrip(b"\r")}
    return signature_strings(value) if isinstance(value, dict) else {str(item) for item in value}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--std")
    parser.add_argument("--host-only", nargs=2, metavar=("INPUT", "OUTPUT"))
    parser.add_argument("--normalize-signatures", nargs=2, metavar=("INPUT", "OUTPUT"))
    args = parser.parse_args(argv)
    modes = [args.host_only, args.normalize_signatures]
    if sum(item is not None for item in modes) > 1 or ((args.host is None or args.output is None) != any(item is not None for item in modes)):
        parser.error("use HOST_SCHEMA OUTPUT, --host-only INPUT OUTPUT, or --normalize-signatures INPUT OUTPUT")
    try:
        standard = read_json(str(std_path(args.std)))
        if args.host_only:
            write_text(args.host_only[1], json_output(remove_standard(read_json(args.host_only[0]), standard)))
        elif args.normalize_signatures:
            signatures = normalized_input(args.normalize_signatures[0]) | canonical_signatures(standard)
            write_text(args.normalize_signatures[1], "".join(f"{item}\n" for item in sorted(signatures)))
        else:
            write_text(args.output, json_output(merge_schema(read_json(args.host), standard)))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        parser.exit(2, f"merge-std: {error}\n")

if __name__ == "__main__":
    main()
