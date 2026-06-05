# Programming modes — object mode vs stream mode

emp-ag2pc exposes **two front-ends** for writing a circuit. They compile to the
**same protocol engine** (`AG2PCEngine::run_engine_`) with identical security,
communication, and per-gate cost — they differ only in *how you express inputs,
computation, and outputs*, and in their memory/latency trade-offs.

- **Object mode** — imperative, SH2PC-style. You write ordinary EMP-object code
  and it executes as the statements run. Best for most code.
- **Stream mode** — a pure circuit *body* (or a compiled circuit) handed to the
  engine. Best for fixed circuits you compile once and replay, and for the leanest
  memory profile.

> **One mode header per translation unit.** Each mode header defines the friendly
> aliases `Bit` / `UInt32` / `BitVec` / … bound to a *different* wire type, so the
> two collide. Include **either** `<emp-ag2pc/emp-ag2pc.h>` **or**
> `<emp-ag2pc/stream.h>` in a given `.cpp`, never both. Put shared circuit logic in
> **wire-generic** functions/templates (`template <class W> … Bit_T<W> …`) in a
> neutral header; object mode and stream mode can both call it.

| | **Object mode** | **Stream mode** |
|---|---|---|
| Header | `<emp-ag2pc/emp-ag2pc.h>` | `<emp-ag2pc/stream.h>` |
| Wire binding | `AG2PCWire` aliases | `LambdaWire` aliases |
| Inputs | EMP constructors in the program (`UInt32 a(x, party)`) | `process_inputs` bundles, or `AG2PCInputs` EMP constructors before `run` |
| Compute | ordinary EMP-object statements | a pure body passed to `run(...)` / `run_compiled(...)` |
| Outputs | `c.reveal<T>(party)` on EMP objects | `mpc.reveal/decode` on `SecureWires`, or `c.reveal<T>(party)` on the `Opened` run handle |
| Control flow | reveal, branch on a revealed value, feed more inputs, checkpoint — all mid-program | reveal/branch *between* runs; no feed/reveal *inside* the pure body |
| Memory | engine chunk state + the recorder's gate log | engine chunk state only (live), or + the compiled program |
| Best for | SH2PC-style code, reactive programs, large chunked computations | fixed pure circuits, compile-once/replay-many, benchmarks |

---

## Object mode

Include `<emp-ag2pc/emp-ag2pc.h>`. `setup_ag2pc` installs `AG2PCBackend` as the
active emp-tool backend; you then write native EMP objects (bound to `AG2PCWire`)
and read results with `.reveal<T>()`; `finalize_ag2pc` tears down.

```cpp
#include <emp-ag2pc/emp-ag2pc.h>
using namespace emp;

NetIO *io; make_io2pc(party, port, io);
ThreadPool pool(2);
setup_ag2pc(io, &pool, party);

UInt32 a(party == ALICE ? x : 0, ALICE);   // each party owns its input
UInt32 b(party == BOB   ? y : 0, BOB);
UInt32 c = a + b;
uint32_t out = c.reveal<uint32_t>(PUBLIC);  // open to all (or ALICE / BOB)

finalize_ag2pc();
```

Surface: `setup_ag2pc(io, pool, party, ssp=40)`, `finalize_ag2pc()`, the EMP object
constructors / operators / `.reveal<T>(party)`, plus `checkpoint_ag2pc_keep_all()`
and `reveal_ag2pc(out, wires, n)`. The full circuit-type set (`Bit`, `UInt8…UInt64`,
`Int8…Int64`, `UnsignedInt`/`SignedInt`, `BitVec`, `Float`, AES/SHA calculators) is
bound to AG2PC by the umbrella.

**How it works.** `AG2PCBackend` *records* your gates into a per-chunk gate log
(over a refcounted 4-byte `AG2PCWire`). At every `reveal` / checkpoint it
dead-code-eliminates the chunk, emits it as a `emp::circuit::BooleanProgram`, and runs
that on the one engine. So object mode is a recording/chunking front-door — not a
second protocol.

**What object mode can do that a pure body cannot:**
- **Mid-stream reveal** and **host branching** on a revealed value (the program
  reacts to intermediate results).
- **Feeding new secret inputs mid-program.**
- **RAII checkpointing**: `checkpoint_ag2pc_keep_all()` evaluates the chunk so far;
  wires whose `Bit`/`Integer` handles have gone out of scope are dropped, so peak
  memory stays bounded on long compositions (no `keep[]` list to maintain).

**Cost.** The recording (building + DCE-ing the `BooleanProgram`) is real work
outside the protocol — at 100 M gates it adds tens of seconds vs stream mode, which
is the entire wall-clock gap between the two. Memory = engine chunk state + the
recorder's gate log.

---

## Stream mode

Include `<emp-ag2pc/stream.h>`. You drive the engine directly: an `AG2PCSession`
(session crypto) and an `AG2PCEngine` (the executor) over `LambdaWire`-bound
objects. The circuit is a **pure** wire-generic body — no `feed`/`reveal` inside it
(the engine replays the body several times per chunk, so I/O must stay outside).

```cpp
#include <emp-ag2pc/stream.h>
using namespace emp;

AG2PCSession mpc(io, &pool, party);
AG2PCEngine  runner(&mpc);

// Inputs OUTSIDE the body. x owned by P1, y by P2 (bit-vectors per owner).
auto in = mpc.process_inputs({1, 2}, { x_bits, y_bits });

SecureWires out = runner.run<UInt32, UInt32>({in[0], in[1]},
                                             [](auto a, auto b){ return a + b; });
std::vector<bool> z = mpc.reveal(out, /*to=*/1);   // reveal() == decode()
```

### Circuit sources (`AG2PCEngine`)

The engine replays a *source* per phase; four are available:

| Source | API | Notes |
|---|---|---|
| live body | `run<Ins...>(inputs, body)` | a pure wire-generic body, replayed per phase; nothing materialized |
| compiled circuit | `run_compiled<Ins...>(tc, inputs)` | replay a `frontend::compile`'d `TypedCircuit` (compile once, replay many) |
| raw program | `run_program(prog, inputs)` | replay a raw `emp::circuit::BooleanProgram` (lowest-level; result is the program's declared outputs) |
| flat lambda | `run_circuit(in_wires, n_out, lambda)` | legacy `(in_bits, out_bits)` lambda |

### Inputs — two ways

1. **Explicit bundles:** `mpc.process_inputs({owners}, {bits_per_owner})` returns
   one `SecureWires` per owner; pass them to `run<Ins...>` in argument order.
2. **EMP constructors (ergonomic), via `AG2PCInputs`:** construct inputs with the
   normal `(value, party)` constructor *outside* the body; the batch is shared with
   one `process_inputs` (grouped by owner) at run time. A nullary body captures the
   constructed objects:

   ```cpp
   AG2PCInputs inputs(&mpc);
   UInt32 a(party == ALICE ? x : 0, ALICE);
   UInt32 b(party == BOB   ? y : 0, BOB);
   auto c = runner.run(inputs, [&]{ return a + b; });   // returns an Opened handle
   uint32_t z = c.reveal<uint32_t>(PUBLIC);              // object-style output
   ```
   Only secret inputs may be constructed under `AG2PCInputs`; public constants,
   gates, and reveal belong inside the run body / after `run`. The batch freezes at
   the first `run` (feeding after is an error) and the frozen bundle is reusable
   across several `run` calls.

### Outputs — two ways

- **`SecureWires` + session open:** `mpc.reveal(out, party)` (an alias for
  `decode`), returning a `std::vector<bool>`.
- **`Opened` handle:** `runner.run(AG2PCInputs&, body)` returns an `Opened`
  wrapping the output, with `c.reveal<T>(party)` (decode + fold to `bool` / unsigned
  integer / `vector<bool>`); composite returns use `c.reveal_bits(party)`. It also
  converts implicitly to `SecureWires`. Note this is a *post-run* decode-and-fold
  convenience, not the live EMP object's `.reveal` — that one is object mode.

**Cost.** A live body adds ≈0 over the engine. `run_compiled` adds a one-time
compile and holds the compiled program resident (more memory). Compiling one small
unit and replaying it (the "reuse" pattern) is fastest and leanest. Memory is the
engine's per-chunk slot-reused state (+ the compiled program for `run_compiled`),
with no recorder gate log.

---

## Under the hood: the mechanics that make both modes work

Everything below lives in [backend/engine.h](../emp-ag2pc/backend/engine.h),
[frontend/direct_backend.h](../emp-ag2pc/frontend/direct_backend.h), and
[backend/session.h](../emp-ag2pc/backend/session.h). Understanding it explains *why*
the two modes have the shapes they do.

### 1. The engine is a multi-pass replay over a "circuit source"

`AG2PCEngine::run_engine_(in_wires, replay)` is the whole executor. `replay` is a
callback that, each time it's invoked, **emits the same circuit** by issuing
`and_gate`/`xor_gate`/`not_gate`/`public_label` calls against whatever `Backend` is
currently installed. The engine installs a *different* backend for each protocol
phase and calls `replay()` again:

| Phase | Installed backend | Work |
|---|---|---|
| 0. liveness | `LivenessBackend` | value-free walk: assign each wire an id; record `last_use` + `persist` (inputs / AND-outputs / circuit-outputs keep a slot to the end) |
| — load inputs | — | copy `in_wires` (`SecureWires`) into slots `[0, num_in)` |
| 1. fused | `FusedSizeCollectMasksBackend` | assign each wire a physical **slot** (recycling dead XOR/NOT scratch); draw fresh AND-output masks λ_γ; collect per-AND input masks |
| — triples | (no replay) | `TriplePool::compute_inplace` — the leaky-AND, builds σ = λ_α∧λ_β per gate |
| 2. garble / evaluate | `GarbleBackend` (P1) / `EvaluateBackend` (P2) | emit / consume the half-gate ciphertexts; the evaluator fuses the c_γ witness inline |
| 3. c_γ check | `PostRecvCheckBackend` (P1 only) | after receiving the evaluator's masked-output bits, recompute the garbler's c_γ witness |
| — flush / gather | — | run the deferred COT consistency check; read outputs from their slots |

So the **garbler replays the circuit 4 times** (liveness, fused, garble, c_γ) and
the **evaluator 3 times**. Wire ids are assigned purely by emission order (a counter
that starts at `num_in` and ++s per gate), so every replay yields the *same* ids —
which is what lets per-wire state arrays, grown on the first pass, be indexed by id
on every later pass.

**This multi-pass replay is the reason a stream body must be pure.** A `feed()` of a
secret input is a one-time network step (`process_inputs`); a `reveal()` is a
side-effecting open. Running either *inside* the body would execute it 3–4 times.
So stream mode forbids both inside the body (the phase backends `error()` on a
non-`PUBLIC` `feed` or any `reveal`) — inputs are supplied as `SecureWires` before
the run, outputs are opened after. (`public_label`, i.e. public constants, *is*
allowed inside: it's deterministic and emits a CONST wire each pass.)

### 2. Two wire carriers — the mechanical root of "one mode per TU"

A circuit object (`Bit_T<W>`, `UInt32_T<W>`, …) is templated on a wire carrier `W`,
and `EMP_USE_CIRCUIT_TYPES_ALL(W)` binds the friendly names `Bit`/`UInt32`/… to one
`W`. The two modes use *different* carriers:

- **`LambdaWire`** (stream) — a bare 4-byte `int id`, no hooks. Cheap, and replays
  identically pass to pass; that's all the engine needs.
- **`AG2PCWire`** (object) — a 4-byte `int id` **with refcount hooks**: its
  ctor/copy/dtor call `pin`/`unpin` on `AG2PCBackend::singleton_`. So the recorder
  always knows which wire ids are still held by a live `Bit`/`Integer` — the basis
  for RAII checkpoint liveness.

Both header sets call `EMP_USE_CIRCUIT_TYPES_ALL` with their own carrier, so `Bit`
etc. would be *defined twice* if both headers were included. Hence **one mode header
per translation unit**, and shared circuit logic written as `template <class W>`
over `Bit_T<W>` so either binding can instantiate it.

### 3. Object mode = a recording backend that feeds the engine

`AG2PCBackend` implements the global `Backend` interface. As your statements run, it
*records*: `and/xor/not` append to a per-chunk gate log; secret `feed` registers an
input; `public_label` records a CONST gate; the `AG2PCWire` refcounts track which
ids are still live. At each `reveal` / `checkpoint_ag2pc_keep_all()`,
`run_chunk_()`:

1. **DCE** — reachability from the still-live (pinned) wires; prune dead gates.
2. **remap** to compact wire ids and emit a `emp::circuit::BooleanProgram`.
3. **gather** the carried authenticated state for inputs that survived from a prior
   chunk, plus `process_inputs` for freshly-fed secrets (batched per owner).
4. **`AG2PCEngine::run_program(prog, input_bundle)`** — i.e. the same
   `run_engine_`, with a replay that walks the just-built `BooleanProgram`.
5. **stash** every still-live wire's fresh state into `carried_`, so it flows into
   the next chunk; reclaim dead slots.

That is the entire object/stream difference: object mode pays to *build and DCE a
`BooleanProgram` per chunk* (the "recording" cost, tens of seconds at 100 M gates),
in exchange for imperative ergonomics and a *persistent* backend — which is what
makes **mid-stream reveal** and **host branching on a revealed value** possible (the
recorder flushes a chunk, decodes, and keeps recording). A pure stream body can't do
that because it is replayed, not executed once.

### 4. Stream mode = drive the engine directly

- **Inputs.** `AG2PCSession::process_inputs(owners, bits)` runs KRRW Fig.3: one COT
  draw mints the authenticated λ-shares, a single batched message opens shares +
  folds in owner bits, and it returns `SecureWires` — per wire, the public mask Λ,
  the share bundle `(MAC, KEY)`, and the garbler/evaluator label. That bundle is what
  `run_engine_` loads into input slots.
- **`run<Ins...>`** assembles typed `LambdaWire` arguments over ids `[0, num_in)`,
  checks the body against the pure-circuit contract (`circuit_fn_traits` /
  `circuit_contract`: callable, returns a circuit value by value), and builds a
  replay that calls `frontend::run(body, args)` under each phase backend.
  **`run_compiled`** replays a `frontend::compile`'d program via `frontend::run(tc,
  args)` (same backend calls, no body re-invocation); **`run_program`** replays a raw
  `BooleanProgram` (the level object mode uses); **`run_circuit`** wraps a flat
  `(in_bits, out_bits)` lambda.
- **`AG2PCInputs`** is a tiny input-builder `Backend`: while installed, each EMP
  constructor's `feed` is **deferred** — it records `(owner, bits)` and hands back
  placeholder ids. `process()` (called by `run`) does **one** `process_inputs`
  grouped by owner and scatters the result back into placeholder-id order, then
  freezes. So you get constructor syntax with a single batched input round.
- **`Opened`** wraps the run's output `SecureWires`; `reveal<T>(party)` calls
  `AG2PCSession::decode` and folds the bits into `T` (it also converts implicitly to
  `SecureWires`). It's a post-run decode-and-fold, not the live object's `.reveal`.

### 5. Why memory is bounded — slot reuse + chunking

The fused pass gives each wire a **physical slot**; XOR/NOT "fabric" wires return
their slot to a freelist at their last read, while inputs, AND-outputs, and circuit
outputs persist. So the heavy per-wire arrays size to **(live width + #AND)**, not
total wires. On top of that, both modes **chunk**: object mode at each
`checkpoint_ag2pc_keep_all()`; stream mode by slicing the input bundle and calling
`run` per slice. Peak RSS scales ~linearly with the per-chunk gate count, so the
chunk size is the dial for fitting a memory budget — see
[performance_100m.md](performance_100m.md) for the measured numbers (a 100 M-gate
circuit fits 8 GB).

Same protocol (WRK17 + KRRW18), same bytes on the wire, same malicious-security
guarantee in both modes — the engine, `AG2PCSession`, and `TriplePool` are shared
verbatim.

## Compatibility aliases

`AG2PCSession` and `AG2PCEngine` were formerly `C2PC` and `LambdaRunner`; those
names remain as `using` aliases. The pre-split header paths (`2pc.h`,
`lambda_runner.h`, `ag2pc_backend.h`, …) remain as thin forwarders.
