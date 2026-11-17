# Standard `lmcode` REST Endpoints & Stateless CLI Interfaces

## Summary

`lmssl` upgrades its vendored `lmcode-cpp` SDK (`cpp/dslvm.hpp`, `cpp/stdlib/rest.hpp`, `cpp/stdlib/std.hpp`, `cpp/std/lmcode-std.schema.json`, `scripts/merge-std.py`, `sdk.lock`) to the 226-signature `lmcode_std_v3` standard catalog and `@lmctl-ai/lmctl@0.2.482`:
- Implicit `lmcode_std_v3` exposes the 10 standard REST/CLI interfaces (`RestGet`, `RestPost`, `RestPut`, `RestDelete`, `RestPatch`, `RestHead`, `RestOptions`, `RestHandler`, `CliCommand`, `CliOption`), `RestExchange` methods, and `rest_config` / `rest_route` / `rest_serve` / `rest_cli` while `schema/lmssl.dsl.json` remains host-only.
- Verified in `test.sh` with `std-rest-cli.lms`, exercising `CliOption`, `CliCommand`, `RestGet`, `rest_config`, and `rest_cli` driving `ssl.digest(...)`, `ssl.gen_ec(...)`, and `ssl.new_cert(...)`.
