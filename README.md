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
[emp-ot](https://github.com/emp-toolkit/emp-ot). Circuits are authored in
emp-tool's native `Bit` / `Integer` frontend and run through a recording
backend — no BristolFormat files to hand-write or ship.

The protocol is authenticated garbling [WRK17] with the
[KRRW18](https://eprint.iacr.org/2018/578) optimizations: a **function-dependent**
half-gate leaky-AND (KRRW §5.2) that runs in place on each gate's own input
masks, a batched `F_eq` consistency check, then cyclic-shift bucketing to remove
leakage. Correlated OT comes from a single lifetime-open SoftSpoken⟨4⟩ session in
emp-ot, whose consistency check is run before every reveal so it gates output.

> **Heads up — AI-assisted rewrite, not yet audited.** The development branch
> is under active refactoring and review; do not deploy it without your own
> audit.

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
| `EMP_AG2PC_DEBUG`       | `OFF`               | Compile in the internal MAC / correctness checks (`EMP_DEBUG_PHASE`). |

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

Each test launches the two parties on localhost via the top-level `run`
helper and checks the secure output against a cleartext oracle:

| Test | What it exercises |
|---|---|
| `test_aes`        | AES-128 in the native Bit frontend vs plaintext AES |
| `test_sha256`     | SHA-256 compression (`SHA_BLOCKS=N` for N back-to-back blocks) |
| `test_chain`      | AES ×2 with a mid-circuit `checkpoint_ag2pc_keep_all()` (bounded memory) |
| `test_keep_all`   | `{ Bit b; }`-scoped wires really do drop at the next checkpoint |
| `test_reactive`   | reveal-to-`PUBLIC` host branching |
| `test_recording`  | the record → `WireGraph` → `C2PC` path on a tiny circuit |
| `test_rounds`     | input batching (one `process_input` per owner) |
| `wire_graph_test` | the `WireGraph` IR end to end |

## Usage

Author the circuit once, in ordinary emp-tool frontend code; the backend
records it and runs the protocol at the (single, terminal) reveal. Every
party runs the same program, passing its own input and a dummy for inputs it
does not own.

```cpp
#include <emp-ag2pc/emp-ag2pc.h>
#include <emp-ag2pc/ag2pc_backend.h>
#include <emp-ag2pc/ag2pc_circuit_types.h>   // Bit / Integer / ... = *_T<AG2PCWire>
using namespace emp;

// One NetIO to the peer (party 1 server, party 2 client); the protocol spawns
// its own sibling channel internally (NetIO::make_sibling).
NetIO *io = (party == 1) ? new NetIO(nullptr, port)        // server
                         : new NetIO("127.0.0.1", port);   // client

ThreadPool pool(4);
setup_ag2pc(io, &pool, party);

Bit a(in_a, /*owner=*/1);           // party 1's secret input
Bit b(in_b, /*owner=*/2);           // party 2's secret input
Bit c = a & b;
bool out = c.reveal<bool>(/*to=*/1);

finalize_ag2pc();
```

`Integer`, `Float`, and the rest of emp-tool's frontend work the same way.
For host branching, `reveal<bool>(PUBLIC)` opens to both parties.

### Reveal patterns

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
`checkpoint_ag2pc_keep_all()` — see `test_chain` (AES ×2) and `test_sha256`
(`SHA_CHECKPOINT=K` checkpoints every K compressions, so a 100M-gate circuit
fits a small box). `test_keep_all` is the smoke test that verifies the
`{ Bit b; }`-style drop actually happens.

Per-chunk peak memory scales as `≈ 400 · A + 40 · X` bytes (ignoring inputs)
where `A` and `X` are the per-chunk AND and XOR gate counts. The AND term
covers the triple-gen transient (~192 B/AND), the per-AND share bundles
(~128 B/AND), and the wire / label arrays (~80 B/AND); XORs are free-XOR, so
the XOR term is just the gate-log entry plus per-wire metadata. Picking `K`
to keep `400 · A_chunk + 40 · X_chunk` under your memory budget bounds the
whole run — a circuit's AND/XOR mix tells you which term dominates.

## How it works

The stack is three header layers, each consuming the one below:

- **`AG2PCBackend`** (`ag2pc_backend.h`) — a recording `Backend` over a 4-byte
  wire carrier (`AG2PCWire`) that reference-counts each frontend `Bit`.
  Authenticated garbling is multi-pass, so it records the frontend into
  per-wire metadata arrays plus a per-chunk gate log, then runs the protocol
  per chunk. Wire slots released by dead `Bit`s are reused at the next chunk
  boundary. `checkpoint_ag2pc_keep_all()` flushes a long composition (e.g.
  AES ×k) — carries every wire still held by a live `Bit`, drops the rest —
  so per-chunk peak memory is bounded.
- **`C2PC`** (`2pc.h`) — the protocol: `process_input` shares inputs, `compute`
  garbles/evaluates the circuit with the half-gate construction and runs the
  malicious checks (the leaky-AND `F_eq` and the KRRW Fig. 3 `c_γ` check),
  `decode` opens outputs.
- **`TriplePool`** (`triple_pool.h`) — the correlated-OT mesh plus malicious
  authenticated AND-share generation. aShares (`MAC = KEY ⊕ x·Δ`) are minted
  from emp-ot correlated OT with a bit-0/bit-1 Δ pinning that folds the share
  bit into the COT choice bit; each AND gate's `σ = λ_α∧λ_β` is then built by a
  function-dependent half-gate leaky-AND (KRRW §5.2) run in place on the gate's
  own input masks, a batched `F_eq` check, and cyclic-shift bucketing. The COT
  session is opened once and held for the object's lifetime, its consistency
  check run before each reveal so it gates output release.

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
