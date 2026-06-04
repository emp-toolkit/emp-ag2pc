# emp-ag2pc

![build](https://github.com/emp-toolkit/emp-ag2pc/workflows/build/badge.svg)
[![CodeQL](https://github.com/emp-toolkit/emp-ag2pc/actions/workflows/codeql.yml/badge.svg)](https://github.com/emp-toolkit/emp-ag2pc/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

> **Which version do I want?**
>
> - **Existing projects pinned to a published release: stay on `0.3.0`** —
>   tag [`0.3.0`](https://github.com/emp-toolkit/emp-ag2pc/releases/tag/0.3.0)
>   or branch [`v0.3.x`](https://github.com/emp-toolkit/emp-ag2pc/tree/v0.3.x).
>   That is the long-standing BristolFormat-driven AG-2PC. Bug fixes are
>   backported to `v0.3.x`.
> - **New projects, or willing to migrate: track the development branch**
>   (this branch). It will become `1.0.0-alpha` after a polish pass and then
>   `1.0.0`. It is a ground-up rewrite: a native emp-tool Bit/Integer
>   frontend (no hand-written Bristol files), a slot-reused wire layout, and the
>   KRRW (eprint 2018/578) function-dependent leaky-AND (computed in place on
>   each AND gate's own input masks).
>   The API is not yet frozen and headers may move between alphas. Requires
>   emp-tool ≥ 1.0 and emp-ot ≥ 1.0.

Maliciously-secure **two-party computation via authenticated garbling**, on
top of [emp-tool](https://github.com/emp-toolkit/emp-tool) and
[emp-ot](https://github.com/emp-toolkit/emp-ot). You write circuits as ordinary
EMP code — `setup_ag2pc`, native objects (`Bit` / `UInt32` / `BitVec` / …),
normal operators, `.reveal<T>()`, `finalize_ag2pc` — exactly like emp-sh2pc. No
BristolFormat files to hand-write or ship.

```cpp
#include <emp-ag2pc/direct.h>
using namespace emp;

NetIO *io; make_io2pc(party, port, io);
ThreadPool pool(4);
setup_ag2pc(io, &pool, party);

UInt32 a(party == ALICE ? x : 0, ALICE);   // each party owns its input
UInt32 b(party == BOB   ? y : 0, BOB);
UInt32 c = a + b;
uint32_t out = c.reveal<uint32_t>(PUBLIC);  // open to both

finalize_ag2pc();
```

That is the whole public surface. You never touch the session object, the
execution engine, or share/wire internals — the direct backend records your gates
and runs them on the one shared engine behind the scenes.

The protocol is authenticated garbling [WRK17] with the
[KRRW18](https://eprint.iacr.org/2018/578) optimizations: a **function-dependent**
half-gate leaky-AND (KRRW §5.2) that runs in place on each gate's own input
masks, a batched `F_eq` consistency check, then cyclic-shift bucketing to remove
leakage. Correlated OT comes from a single lifetime-open SoftSpoken⟨4⟩ session in
emp-ot, whose consistency check is run before every reveal so it gates output.

> **Heads up — AI-assisted rewrite, not yet audited.** The development branch
> is under active refactoring and review; do not deploy it without your own
> audit.

## Choosing a mode

There are two ways to *author* a circuit. Both compile to the **same one protocol
executor** (`run_engine_`) — they differ only in how you write inputs, compute,
and outputs. Most code wants **direct mode**; reach for **function mode** when
you specifically need a pure reusable body, a compiled circuit, or the streaming
memory profile.

| | **Direct mode** | **Function mode** |
|---|---|---|
| Include | `<emp-ag2pc/direct.h>` | `<emp-ag2pc/function.h>` |
| Wire binding | `AG2PCWire` aliases | `LambdaWire` aliases |
| Inputs | `UInt32 a(x, party)` constructor | `process_inputs` / `AG2PCInputs` → `SecureWires` |
| Compute | imperative straight-line code | a *pure* wire-generic body (no I/O inside) |
| Outputs | object `c.reveal<T>(party)` | `AG2PCInputs` run returns a handle with `c.reveal<T>(party)`; other entries open `SecureWires` via `mpc.reveal`/`decode` |
| Extra powers | mid-stream reveal, reactive branch on a revealed value, RAII checkpoint | streaming (no gate-log materialized), compile-once/replay-many |
| Use it when | you want ordinary SH2PC-style code, reveal-and-branch, or huge compositions with checkpoints | you have a fixed circuit to compile and reuse, or want memory linear in live width |

The two binding alias sets (`AG2PCWire` vs `LambdaWire`) both define `Bit`/`UInt32`/…,
so they collide — **pick one mode header per translation unit**. The compatibility
header `<emp-ag2pc/emp-ag2pc.h>` is equivalent to `<emp-ag2pc/direct.h>`. Shared
circuit logic should live in wire-generic functions/templates in a neutral header;
then direct mode and function mode can both call it.

## Requirements

- CMake ≥ 3.21
- A C++17 compiler (Clang ≥ 12, GCC ≥ 9, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- [emp-ot](https://github.com/emp-toolkit/emp-ot) ≥ 1.0
- OpenSSL ≥ 3.0
- pthreads

emp-ag2pc is **header-only**: the protocol lives entirely in headers
(`emp-ag2pc::emp-ag2pc` is an `INTERFACE` target), and the compiled OT /
crypto bodies come from emp-ot and emp-tool.

## Build and install

emp-ag2pc consumes emp-tool and emp-ot through their installed CMake
packages. Install those two first, then build emp-ag2pc the same way:

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

If you don't want to install the dependencies, point emp-ag2pc directly at
their build trees:

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
| `EMP_AG2PC_BUILD_BENCHES` | `OFF` | Build `test/bench_modes.cpp` (manual; not run by ctest). |

## Consuming from another CMake project

```cmake
find_package(emp-ag2pc CONFIG REQUIRED)
target_link_libraries(my-app PRIVATE emp-ag2pc::emp-ag2pc)
```

`emp-ag2pc::emp-ag2pc` pulls in `emp-tool::emp-tool` and `emp-ot::emp-ot`
transitively, so consumers don't need to find them separately.

## Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Each test launches the two parties on localhost via the top-level `run` helper
and checks the secure output against a cleartext oracle. Tests are grouped by
SURFACE — the public API first, then the internal/expert engine:

| Test | Surface | What it exercises |
|---|---|---|
| `test_public_api`       | public | SH2PC-style `setup_ag2pc` + `UInt32`/`Bit` + operators + `reveal` + `finalize_ag2pc`. Includes ONLY `<emp-ag2pc/direct.h>` — the direct-mode self-sufficiency proof. |
| `test_direct_semantics` | public | direct-mode capabilities in plain EMP code: record→reveal (incl. constant-only), per-owner input batching, mid-stream checkpoint carry, reactive reveal/branch/new-input, RAII liveness |
| `test_direct_crypto`    | public | direct-mode AES-128 + SHA-256 vs clear oracle (`SHA_BLOCKS`, `SHA_CHECKPOINT`) |
| `test_engine_internal`  | internal | function mode directly: `run`/`run_compiled`/`run_program`/`run_circuit`, chaining, C++20 typed body, AES/SHA — uses `<emp-ag2pc/function.h>` |
| `test_wire_equiv`       | internal | transcript byte-equivalence of the streaming front-doors + semantic equivalence of the compiled path |

The direct backend (`AG2PCBackend`) is **not** a separate protocol path: it is an
imperative adapter that records your EMP objects, emits `BooleanProgram` chunks,
and runs them on the one shared engine via `run_program`.

Benchmarks (`test/bench_modes.cpp`) are opt-in: they build only with
`-DEMP_AG2PC_BUILD_BENCHES=ON` (OFF by default) and are **not** registered with
`ctest`. Build and run manually, e.g.:

```sh
cmake -S . -B build -DEMP_AG2PC_BUILD_BENCHES=ON
cmake --build build --target bench_modes
BENCH_MODE=direct-chunked SHA_BLOCKS=50 SHA_CHECKPOINT=10 ./run ./build/bin/bench_modes
```

Modes are `direct-chunked`, `frontend-compiled`, `frontend-live` — all on the
one shared engine; `direct-chunked` is the direct recorder, not a separate
crypto backend.

## Usage

Author circuits in emp-tool's native objects between `setup_ag2pc` and
`finalize_ag2pc`, and read results with `.reveal<T>()`. Every party runs the
same program; each constructs its own inputs (a dummy for the inputs it does not
own) and the owner tag (`ALICE` / `BOB`) selects whose value is real.

```cpp
#include <emp-ag2pc/direct.h>
using namespace emp;

NetIO *io; make_io2pc(party, port, io);     // or new NetIO(...) yourself
ThreadPool pool(4);
setup_ag2pc(io, &pool, party);

UInt32 a(party == ALICE ? x : 0, ALICE);
UInt32 b(party == BOB   ? y : 0, BOB);
UInt32 c = a + b;
uint32_t z   = c.reveal<uint32_t>(PUBLIC);  // open to both
uint32_t z1  = c.reveal<uint32_t>(ALICE);   // or open only to one party

finalize_ag2pc();
```

`Bit`, `UInt8…UInt64` / `Int8…Int64`, `UnsignedInt`/`SignedInt`, `BitVec`,
`Float`, and the AES / SHA calculators are all bound to AG2PC by `direct.h` —
the same objects you'd use in emp-sh2pc. Mid-stream reveals, reveal-to-a-party,
host branching on a revealed value, and `checkpoint_ag2pc_keep_all()` (to cap
memory on very large compositions) all work; see `test_direct_semantics.cpp`.

### Function Mode

Most users never need this. The one executor — `AG2PCEngine`
(`emp-ag2pc/backend/engine.h`) over the session-crypto object `AG2PCSession` — can
replay a circuit *source* directly: a pure wire-generic body (`run<Ins...>`), a
`frontend::compile`d circuit (`run_compiled<Ins...>`), or a raw
`frontend::BooleanProgram` (`run_program`), with inputs/outputs handled explicitly
via `AG2PCSession::process_inputs` / `decode` and `SecureWires`. These live behind
`emp-ag2pc/function.h`, which is **mutually exclusive with `direct.h`**
(its `LambdaWire` aliases collide with the direct `AG2PCWire` ones) — include ONE
mode header per translation unit. See `test_engine_internal.cpp`.

```cpp
#include <emp-ag2pc/function.h>             // AG2PCEngine + LambdaWire aliases
using namespace emp;
AG2PCSession mpc(io, &pool, party);
AG2PCEngine  runner(&mpc);
auto in  = mpc.process_inputs({1, 2}, { x_bits /*P1*/, y_bits /*P2*/ });
SecureWires out = runner.run<UInt32, UInt32>({in[0], in[1]},
                                             [](auto a, auto b){ return a + b; });
std::vector<bool> z = mpc.reveal(out, /*to=*/1);   // reveal() == decode()
```

Engine circuit sources: `run<Ins...>` (live body), `run_compiled<Ins...>` (a
`frontend::compile`d circuit, replayed), `run_program` (a raw `BooleanProgram`),
and `run_circuit` (the legacy flat `(in_bits,out_bits)` lambda). Inputs can also be
built with **EMP-object constructors** via `AG2PCInputs`, which keeps the engine's
pure-body model but lets you write `UInt32 a(x, party)` outside the lambda instead
of hand-rolling `process_inputs` (all constructed inputs go into one batched
`process_inputs` call, grouped by owner):

```cpp
AG2PCInputs inputs(&mpc);
UInt32 a(party == ALICE ? x : 0, ALICE);     // deferred; batched at run
UInt32 b(party == BOB   ? y : 0, BOB);
auto c = runner.run(inputs, [&]{ return a + b; });   // pure body captures a, b
uint32_t z = c.reveal<uint32_t>(/*to=*/1);           // object-style reveal on the result handle
```

So the `AG2PCInputs` flow is constructor-in / object-reveal-out on the engine. The
handle's `reveal<T>()` is a decode-and-fold convenience (scalar / `vector<bool>`
outputs; for composite returns use `reveal_bits()` and slice), and it still
converts to `SecureWires` for `mpc.reveal`/`decode`. The other engine entries
(`run<Ins...>` / `run_compiled` / `run_program` / `run_circuit`) return `SecureWires`
directly, opened with `mpc.reveal`/`decode`.

(`C2PC` and `LambdaRunner` remain as compatibility aliases for `AG2PCSession` and
`AG2PCEngine`.)

### Reveal patterns (direct mode)

The reveal semantics below are specific to the direct backend (the expert engine
path decodes once, at the end, outside the circuit).

A `reveal` call closes the chunk (running the c_γ + COT checks at chunk-end)
and then ships the opened bits to the recipient. The chunk-end checks fire
only when there's new work since the last reveal — back-to-back reveals with
no gates in between share a single check, so per-reveal you pay just the
one-way share send to the recipient.

This shape collapses across **same-recipient** reveals: ten sequential
`reveal<bool>(/*to=*/1)` calls cost roughly the same as one (one chunk-check,
then ten pipelined one-way sends). Same for `/*to=*/2`.

It does **not** collapse across `PUBLIC` reveals: a `PUBLIC` reveal routes
through the evaluator and waits on a broadcast back, so it inherently has a
round-trip per call. If you have many bits to open to both parties, do them
as two single-recipient reveals instead:

```cpp
// Slow: N PUBLIC reveals = N round-trips
for (auto& bit : bits) bit.reveal<bool>(PUBLIC);

// Fast: two pipelined batches, ~constant latency in N
for (auto& bit : bits) bit.reveal<bool>(/*to=*/1);  // P2 ships shares, P1 sees
for (auto& bit : bits) bit.reveal<bool>(/*to=*/2);  // P1 ships shares, P2 sees
```

Or batch at the API level by passing the wires together:

```cpp
std::vector<AG2PCWire> wires = ...;
std::vector<bool> out(wires.size());
backend->reveal(out.data(), /*to=*/1, wires.data(), wires.size());
```

— that collapses the N share sends into one wire message as well.

### Checkpointing for bounded memory

The backend records the whole circuit before the (single, terminal) reveal, so a
long or repeated composition — AES ×k, SHA-256 ×N, … — would otherwise hold the
entire gate list in memory. `checkpoint_ag2pc_keep_all()` cuts it into chunks:
it evaluates everything recorded so far, carries every wire still held by a
live `Bit` forward as authenticated state, and frees the rest. Wires whose
`Bit` has gone out of scope are dropped automatically, so brace-scoping a
stage's transient state is enough to bound memory.

```cpp
// C2 = AES(K2, AES(K1, P)), with a checkpoint between the two AES calls.
// Setup (assumed already fed at chunk-1 start):
AES_Calculator_T<AG2PCWire> aes;
Bit k1[128], k2[128], p[128];         // ... input-fed via Bit ctors ...

Bit c1[128];
{
  // Brace-scope the 1408-wire expanded round key so it dies BEFORE the
  // checkpoint — checkpoint_keep_all then drops it automatically. c1 stays in
  // outer scope, so it carries across; k1/k2/p are still alive too.
  Bit ek1[1408];
  aes.key_schedule(k1, ek1);
  aes.encrypt(p, ek1, c1);
}
checkpoint_ag2pc_keep_all();          // ek1 dropped; c1 + k1, k2, p carry

Bit c2[128];
{                                      // same pattern for AES #2
  Bit ek2[1408];
  aes.key_schedule(k2, ek2);
  aes.encrypt(c1, ek2, c2);
}

bool out[128];                         // reveal the full ciphertext to party 1
backend->reveal(out, /*to=*/1, c2, 128);
```

Feed each chunk's fresh inputs at its start (before recording its gates). The
common idiom is to wrap each stage's transient state (round keys, intermediate
arrays) in its own brace block so the wires die before the next
`checkpoint_ag2pc_keep_all()` — see the checkpoint-carry case in
`test_direct_recorder` (AES ×2) and `test_direct_crypto` (`SHA_CHECKPOINT=K`
checkpoints every K compressions, so a 100M-gate circuit fits a small box). The
RAII-liveness case in `test_direct_recorder` verifies the `{ Bit b; }`-style
drop actually happens.

Per-chunk peak memory scales as `≈ 400 · A + 40 · X` bytes (ignoring inputs)
where `A` and `X` are the per-chunk AND and XOR gate counts. The AND term
covers the triple-gen transient (~192 B/AND), the per-AND share bundles
(~128 B/AND), and the wire / label arrays (~80 B/AND); XORs are free-XOR, so
the XOR term is just the gate-log entry plus per-wire metadata. Picking `K`
to keep `400 · A_chunk + 40 · X_chunk` under your memory budget bounds the
whole run — a circuit's AND/XOR mix tells you which term dominates.

## How it works

The two user-facing mode headers are:

- **`direct.h`** — ordinary EMP object code over `AG2PCWire`.
- **`function.h`** — pure function / compiled-circuit code over `LambdaWire`.

The implementation is organized as **`frontend/`** (mode adapters) over
**`backend/`** (one engine + session crypto). Most users only need one of the two
mode headers; the rest is internal.

Frontend (`emp-ag2pc/frontend/`):

- **`ag2pc.h` + `direct_backend.h`** — the public API. `AG2PCBackend` is a
  `Backend` over a refcounted 4-byte `AG2PCWire`: it records imperative
  `Bit`/`Integer` code into a per-chunk gate log + per-wire metadata. At every
  reveal/checkpoint it dead-code-eliminates the chunk, emits it as a
  `frontend::BooleanProgram`, and runs it on the one shared engine via
  `run_program`. It is a buffering/chunking adapter, **not** a second
  garbler/evaluator — and it's the path that supports mid-stream reveals,
  `checkpoint_ag2pc_keep_all()`, and reactive host branching.
- **`circuit_types.h`** — binds emp-tool's objects (`Bit`/`UInt32`/`BitVec`/…) to
  AG2PC. **`run.h`** — the implementation header behind `function.h`
  (`run`/`run_compiled`/`run_program` + `LambdaWire` aliases); not pulled by
  `direct.h`.

Backend (`emp-ag2pc/backend/`, internal):

- **`AG2PCEngine`** (`engine.h`) — the one protocol executor. A circuit *source*
  (a pure body, a `frontend::compile`d circuit, a raw `BooleanProgram`, or the
  flat lambda) is replayed against per-phase backends: a liveness pass, a fused
  size/collect-masks pass, then garble/evaluate and the `c_γ` correction.
  Per-wire state uses a slot-reuse map, so memory is linear in #AND gates + live
  width, not #wires.
- **`AG2PCSession`** (`session.h`) — the session crypto: `process_inputs` shares
  inputs (KRRW Fig. 3), `decode` opens outputs, and it owns the long-lived
  COT/Δ session. (No circuit walk — that's the engine.)
- **`TriplePool`** (`triple_pool.h`) — the correlated-OT mesh plus malicious
  authenticated AND-share generation. aShares (`MAC = KEY ⊕ x·Δ`) are minted
  from emp-ot correlated OT with a bit-0/bit-1 Δ pinning that folds the share
  bit into the COT choice bit; each AND gate's `σ = λ_α∧λ_β` is then built by a
  function-dependent half-gate leaky-AND (KRRW §5.2) run in place on the gate's
  own input masks, a batched `F_eq` check, and cyclic-shift bucketing. The COT
  session is opened once and held for the object's lifetime, its consistency
  check run before each reveal so it gates output release.

`AG2PCSession` and `AG2PCEngine` were formerly `C2PC` and `LambdaRunner`; those
names remain as compatibility aliases, `<emp-ag2pc/emp-ag2pc.h>` remains a
compatibility alias for `direct.h`, and the old top-level header paths (`2pc.h`,
`lambda_runner.h`, `ag2pc_backend.h`, `share_bundle.h`, …) remain as thin
forwarders.

The two parties hold a **duplex pair** of `NetIO` channels (`send_io` /
`recv_io`): the two COT instances run one per socket, and parallel send/recv
overlap without head-of-line blocking.

### Profiling

Compile with `-DAG2PC_PROFILE` (the single flag for all instrumentation) to
print, at party 1, a per-step wall-time + communication + peak-RSS breakdown
(`[ag2pc]`), the leaky-AND sub-phase timers (`[ag2pc-tp]`), and a per-array
memory census (`[ag2pc-mem]`).

## [Acknowledgement, Reference, and Questions](https://github.com/emp-toolkit/emp-readme/blob/master/README.md#citation)

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
