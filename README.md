# emp-ag2pc

![build](https://github.com/emp-toolkit/emp-ag2pc/workflows/build/badge.svg)
[![CodeQL](https://github.com/emp-toolkit/emp-ag2pc/actions/workflows/codeql.yml/badge.svg)](https://github.com/emp-toolkit/emp-ag2pc/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

Maliciously-secure **two-party computation via authenticated garbling**, on top
of [emp-tool](https://github.com/emp-toolkit/emp-tool) and
[emp-ot](https://github.com/emp-toolkit/emp-ot). The whole API is one context,
`AG2PCCtx`: you authenticate inputs, build circuits over the emp-tool value layer
(`UInt_T` / `Int_T` / `Float_T` / `Bits_T` / `Bit_T`), and open results — exactly
like emp-sh2pc, but malicious-secure.

```cpp
#include <emp-ag2pc/emp-ag2pc.h>
using namespace emp;

NetIO *io; make_io2pc(party, port, io);
ThreadPool pool(4);
AG2PCCtx ctx(io, &pool, party);

using UInt32 = UInt_T<AG2PCCtx, 32>;
auto a = ctx.input<UInt32>(ALICE, party == ALICE ? x : 0);  // each party owns its input
auto b = ctx.input<UInt32>(BOB,   party == BOB   ? y : 0);
auto c = a + b;
uint32_t out = ctx.reveal(c, PUBLIC).value();               // std::optional<uint64_t>
```

`ctx.reveal(v, recipient)` returns `std::optional<clear_t>` — the value at the
recipient (or `PUBLIC`), `std::nullopt` at any other party.

> **Heads up — AI-assisted rewrite, not yet audited.** The development branch is
> under active refactoring and review; do not deploy it without your own audit.

## Values and circuits

Circuit values are emp-tool's context-bound types parameterized on `AG2PCCtx`:
`Bit_T<AG2PCCtx>`, `UInt_T<AG2PCCtx,N>`, `Int_T<AG2PCCtx,N>`,
`Float_T<AG2PCCtx,W>`, and `Bits_T<AG2PCCtx,N>` (a fixed-width bit vector for
crypto blocks). They support the usual operators (`+ - * / %`, comparisons,
bit ops, shifts/rotates, slice/concat). A reusable circuit is written once as a
pure body and compiled with the emp-tool frontend:

```cpp
auto adder = frontend::compile<rec::UInt<32>, rec::UInt<32>>(
    [](auto x, auto y) { return x + y; });   // record once, over RecordCtx
auto c = ctx.run(adder, a, b);               // replay on AG2PCCtx
```

The same compiled circuit runs on any context (plaintext, this protocol, ZK, …).
The context is always explicit — there is no global backend.

## Execution strategies

A circuit reaches the protocol three ways. All share the same passes and produce
the same per-gate cost; see [docs/execution_strategies.md](docs/execution_strategies.md).

| Strategy | How | When |
|---|---|---|
| **Direct / chunked** | operators (`a + b`) record gates into the current chunk; flushed at `reveal` / `checkpoint` | imperative, reactive programs; large chunked compositions |
| **Compiled replay** | `ctx.run(circuit, args...)` replays a stored `Circuit` standalone through the passes | fixed circuits, compile-once / replay-many |
| **Live body replay** | `ctx.run_body(body, args...)` replays a pure body live, once per pass, with no stored IR | one-off pure circuits; lowest memory |

`ctx.run` / `ctx.run_body` are standalone pass replays; their arguments must be
materialized (from `input` / a prior run / a `checkpoint`). A typed raw-program
escape hatch, `ctx.run_program<RetV>(program, args...)`, replays a hand-authored
or loaded `BooleanProgram` (e.g. an AES/SHA builtin) over `Bits_T` I/O.

## Inputs, reveal, and explicit liveness

- **`ctx.input<T>(owner, x)`** authenticates one input immediately (`PUBLIC` builds
  a public constant, no OT). **`ctx.input_batch()`** authenticates many inputs —
  across both owners — in a single phase:

  ```cpp
  auto batch = ctx.input_batch();
  auto a = batch.add<UInt32>(ALICE, x);
  auto b = batch.add<UInt32>(BOB, y);
  batch.finish();                          // one input phase for ALICE + BOB
  ```

- Wire liveness is **explicit** — there is no refcount or hidden "keep all live
  objects". `ctx.checkpoint(keep...)` runs the pending chunk and carries forward
  exactly the named values (bounding memory in long compositions);
  `ctx.checkpoint()` with no args drops all pending work and all carried state.
  `ctx.reveal(v, recipient, keep...)` flushes keeping `v` and the explicit
  `keep...`; any other still-pending value is dropped at the flush. A wire used
  after it is dropped is a hard error.

## Protocol

Authenticated garbling [WRK17] with the
[KRRW18](https://eprint.iacr.org/2018/578) optimizations: a **function-dependent**
half-gate leaky-AND (KRRW §5.2) that runs in place on each gate's own input masks,
a batched `F_eq` consistency check, then cyclic-shift bucketing to remove leakage.
Correlated OT comes from a single lifetime-open SoftSpoken⟨4⟩ session in emp-ot,
whose consistency check runs before every reveal so it gates output release.
Party 1 is the garbler, party 2 the evaluator.

## Requirements

- CMake ≥ 3.21
- A C++20 compiler (Clang ≥ 14, GCC ≥ 10, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- [emp-ot](https://github.com/emp-toolkit/emp-ot) ≥ 1.0
- OpenSSL ≥ 3.0
- pthreads

emp-ag2pc is **header-only**: the protocol lives entirely in headers
(`emp-ag2pc::emp-ag2pc` is an `INTERFACE` target); the compiled OT / crypto bodies
come from emp-ot and emp-tool.

## Build and install

emp-ag2pc consumes emp-tool and emp-ot through their installed CMake packages.
Install those two first, then build emp-ag2pc the same way:

```bash
# emp-tool
git clone https://github.com/emp-toolkit/emp-tool.git
cmake -S emp-tool -B emp-tool/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-tool/build -j
cmake --install emp-tool/build       # respects CMAKE_INSTALL_PREFIX

# emp-ot
git clone https://github.com/emp-toolkit/emp-ot.git
cmake -S emp-ot -B emp-ot/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-ot/build -j
cmake --install emp-ot/build

# emp-ag2pc
git clone https://github.com/emp-toolkit/emp-ag2pc.git
cmake -S emp-ag2pc -B emp-ag2pc/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-ag2pc/build -j
cmake --install emp-ag2pc/build
```

If you don't want to install the dependencies, point emp-ag2pc directly at their
build trees:

```bash
cmake -S emp-ag2pc -B emp-ag2pc/build \
    -DCMAKE_BUILD_TYPE=Release \
    -Demp-tool_DIR=/abs/path/to/emp-tool/build \
    -Demp-ot_DIR=/abs/path/to/emp-ot/build
```

### CMake options

| Option | Default | Effect |
|---|---|---|
| `EMP_AG2PC_BUILD_TESTS` | `ON` when top-level | Build the test suite under `test/`. |
| `EMP_AG2PC_BUILD_BENCHES` | `OFF` | Build manual benchmarks (not run by ctest). |
| `EMP_AG2PC_BUILD_EXAMPLES` | `ON` when top-level | Build the tutorial examples under `example/`. |

## Consuming from another CMake project

```cmake
find_package(emp-ag2pc CONFIG REQUIRED)
target_link_libraries(my-app PRIVATE emp-ag2pc::emp-ag2pc)
```

`emp-ag2pc::emp-ag2pc` pulls in `emp-tool::emp-tool` and `emp-ot::emp-ot`
transitively, so consumers don't need to find them separately.

## Examples

The [example](example/) folder is a gentle walkthrough rather than a test suite.
Start with `1_basics.cpp`, then move through reveal-and-continue, reusable
circuits, bit strings, checkpointed long computations, and finally a raw
`BooleanProgram` example.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DEMP_AG2PC_BUILD_EXAMPLES=ON
cmake --build build -j
./run ./build/bin/example_1_basics
```

## Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Each test launches both parties on localhost via the top-level `run` helper and
checks the secure output against a cleartext oracle. ALICE (party 1) reports the
verdict, so its exit code is the test's exit code.

| Test | What it exercises |
|---|---|
| `test_flush_plan` | single-process unit test of the direct-chunk planner: DCE, canonical compaction, stale-operand detection |
| `test_context_api` | typed `input` / `reveal`, arithmetic, comparison, signed `Int`, a `PUBLIC` constant, reveal-to-one-recipient |
| `test_direct_chunks` | multi-owner `input_batch`, `checkpoint` prune + carry, reveal keep-lists, no-arg `checkpoint` cleanup |
| `test_program_replay` | compiled `run`, hand-authored `run_program`, the fp32 builtin |
| `test_body_replay_equiv` | `run_body` vs compiled `run` produce a **byte-identical** transcript (the regression gate) |
| `test_aes_sha_builtin` | `aes128` + `sha256_256` builtins replayed over `Bits_T` vs a `ClearCtx` oracle |

Benchmarks are opt-in (`-DEMP_AG2PC_BUILD_BENCHES=ON`) and are not run by ctest.
`bench_100m` runs a repeated SHA-256 chain over a 32-byte all-zero string: the low
128 input bits are authenticated from ALICE, the high 128 from BOB, and ALICE
checks the final digest against OpenSSL. The default 100M-AND run is chunked at
404 SHA applications per protocol chunk, carrying only the 256-bit digest between
chunks.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DEMP_AG2PC_BUILD_BENCHES=ON
cmake --build build --target bench_100m -j

# default: at least 100,000,000 authenticated ANDs
BENCH_THREADS=4 ./run ./build/bin/bench_100m

# quick smoke run
SHA_ITERS=1 SHA_CHUNK_ITERS=1 ./run ./build/bin/bench_100m
```

## How it works

Three pieces; `AG2PCCtx` is the only public handle.

- **`AG2PCCtx`** (`frontend/ag2pc_ctx.h`) — the public context. It is a
  `BooleanContext` whose gate ops record into the current chunk, and it owns the
  protocol + executor and the typed I/O (`input` / `input_batch` / `reveal` /
  `checkpoint` / `run` / `run_body` / `run_program`). Wires are bare ids; liveness
  is explicit (no refcount, no global singleton).
- **`AG2PCExecutor`** (`backend/executor.h`) — runs a `BooleanProgram` or a live
  body source through the five protocol passes. The pass framework (`backend/passes.h`)
  expresses each garbling phase (liveness, slot/mask collection, garble/evaluate,
  c_γ correction) as a `BooleanContext` over one shared `LambdaState`, so the same
  gate stream drives every phase — hence the byte-identical transcript across
  strategies. Per-wire state uses a slot-reuse map, so memory is linear in #AND
  gates + live width, not #wires.
- **`AG2PCProtocol`** (`backend/protocol.h`) — the session crypto: `process_inputs`
  shares inputs (KRRW Fig. 3), `decode` opens outputs, and it owns the long-lived
  COT/Δ session. **`TriplePool`** (`backend/triple_pool.h`) is the correlated-OT
  mesh plus malicious authenticated AND-share generation (aShares `MAC = KEY ⊕ x·Δ`
  from emp-ot COT, the function-dependent leaky-AND, `F_eq`, and bucketing). The
  COT session is opened once and its consistency check runs before each reveal so
  it gates output release.

The two parties hold a **duplex pair** of `NetIO` channels (`send_io` / `recv_io`):
the two COT instances run one per socket, so parallel send/recv overlap without
head-of-line blocking.

### Profiling

Compile with `-DAG2PC_PROFILE` (the single flag for all instrumentation) to print,
at party 1, a per-step wall-time + communication + peak-RSS breakdown (`[ag2pc]`),
the leaky-AND sub-phase timers (`[ag2pc-tp]`), and a per-array memory census
(`[ag2pc-mem]`).

## [Acknowledgement, Reference, and Questions](https://github.com/emp-toolkit/emp-readme/blob/master/README.md#citation)

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
