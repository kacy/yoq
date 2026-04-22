# contributing to yoq

thanks for your interest in contributing. this document covers the basics.

## requirements

- Linux kernel 6.1+ (user namespace support required)
- Zig 0.16.0

## building

```bash
make build        # build the binary
make test         # run all tests
make fmt          # format source code
make bpf          # regenerate eBPF bytecode (only needed if you change bpf/ sources)
```

the binary is output to `zig-out/bin/yoq`. you can install it with:

```bash
make install      # copies to /usr/local/bin/yoq
```

## code style

- **clear over clever.** if something feels too smart, simplify it or add comments explaining why.
- **no panics.** yoq is built to be production-grade. handle errors explicitly. use `return error.*` instead of `@panic` or `unreachable` wherever possible.
- **explicit allocators.** follow Zig conventions — pass allocators through, use arenas where appropriate.
- **readable code.** this codebase will be read by many people. optimize for understanding, not brevity.

## testing

add tests for core functionality and edge cases. avoid tests for the sake of tests — if a test doesn't catch a real bug or protect important behavior, it's not worth writing.

run tests with:

```bash
make test
```

## pull requests

every PR should include:

1. **summary** — what changed and why
2. **what was tested** — how you verified it works
3. **design notes** (optional) — tradeoffs, alternatives considered

keep PRs focused. one feature or fix per PR. no massive changesets.

## eBPF programs

the eBPF programs in `bpf/` are pre-compiled to bytecode and checked into the repo as Zig source files under `src/network/bpf/`. if you modify a BPF C source, regenerate the bytecode with:

```bash
make bpf
```

this requires clang with BPF target support.

## questions?

open an issue. we're happy to help.
