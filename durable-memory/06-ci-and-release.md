# 06 — CI and release

`.github/workflows/ci.yml` (modelled on lmhtml's): five build jobs, each running `./test.sh` (build + all checks) and
uploading `lmssl-<name>[.exe]` plus `LICENSE` and `THIRD_PARTY_NOTICES.md`; a `release` job on `v*` tags attaches
them to a GitHub release together with `SHA256SUMS`.

| name | runner | toolchain | result |
| --- | --- | --- | --- |
| linux-x64 | ubuntu-24.04 | gcc, glibc, `-static` | 19 checks, fully static |
| linux-arm64 | ubuntu-24.04-arm | same | 19 checks |
| macos-arm64 | macos-15 | Apple clang, system libs only | 19 checks |
| macos-x64 | macos-15-intel | same | 19 checks |
| windows-x64 | windows-2022 | MSYS2 MINGW64 gcc, `-static` | 19 checks (13.0 MB `.exe`) |

Asset names `lmssl-linux-x64`, `-linux-arm64`, `-macos-x64`, `-macos-arm64`, `-windows-x64.exe` follow the lmscript
`install="github:OWNER/REPO@TAG"` convention (`HOST-OS-ARCH[.exe]`). The release job checks that
`lmssl --version` starts with `lmssl <tag without v>`; bump `project(lmssl VERSION ...)` in `CMakeLists.txt` before tagging.
Docs-only pushes (`durable-memory/**`, `*.md`) skip CI; tag pushes always build. `workflow_dispatch` takes an `only` input.

The lmscript compiler comes from `npm i -g @lmctl-ai/lmctl@0.2.347` (DSL v5); `scripts/select-compiler.sh` probes that
the emitted bytecode starts with `DSLB\0\5`.

## Platform bugs found (in the order CI showed them)

1. **macOS bash 3.2 and `set -u`.** `"${TARGET[@]}"` of an empty array is "unbound variable". Use
   `${TARGET[@]+"${TARGET[@]}"}`.
2. **Windows generator.** CMake picked the Visual Studio generator; the OpenSSL custom command then ran under MSBuild.
   `test.sh` passes `-G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++` on MINGW/MSYS.
3. **perl.** OpenSSL's `mingw64` target insists on a unix-like perl ("This perl implementation doesn't produce Unix like
   paths"), while Git-for-Windows' perl lacks core modules (`Locale::Maketext::Simple`) and Strawberry Perl is
   "native" and refused. Solution: run the whole Windows job inside MSYS2 (`C:\msys64\usr\bin\bash.exe -l` with
   `MSYSTEM=MINGW64`, `MSYS2_PATH_TYPE=inherit`, `CHERE_INVOKING=1`) after `pacman -S` of gcc, cmake, ninja, python,
   make, perl. Node (setup-node) stays a Windows tool found through the inherited PATH.
4. **Object suffix.** mingw OpenSSL builds `*.obj`, not `*.o`; `build-openssl.sh` uses `$O`.
5. **Text-mode stdout.** The msvcrt turned `\n` into `\r\n`, so `--dsl-schema --json` was not byte-identical. `main`
   sets `_O_BINARY` on stdout/stderr (as lmhtml does).
6. **MSYS path conversion.** bash rewrites arguments such as `/CN=x` or `/old` into `C:/msys64/...` when starting a
   native exe. The test sets `MSYS2_ARG_CONV_EXCL="*"` for exactly those two commands (setting it globally broke
   `lmscript`, which needs the conversion for its file arguments). Hosts running on Windows get plain strings; this is a
   shell artefact, not an lmssl bug.
7. **Native python.** `select-compiler.sh` passes `cygpath -m` paths to mingw python (it cannot read `/tmp/...`).
8. **Re-running `build-openssl.sh`** after a previous run left the renamed-main object made the stock link fail
   (`undefined reference to main`); the script now deletes it first.

Windows also confirmed: IPv6 (`localhost` resolved to `::1` first) and TLS 1.3 with `X25519MLKEM768` work end to end.
Windows time per run is ~6 min (OpenSSL build), Linux ~2 min.

## Releasing

```sh
# bump VERSION in CMakeLists.txt, commit, then:
git tag v0.1.0 && git push origin v0.1.0
```
The workflow builds all five, tests them, and publishes the assets. Re-running a tag's workflow overwrites the assets.
