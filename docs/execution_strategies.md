# Execution strategies

Every circuit in emp-ag2pc runs on one session, `AG2PCSession`, through the same
five protocol passes (`backend/pass_ctx.h`) with identical security, communication,
and per-gate cost. There are three ways to feed a circuit to those passes. They
differ only in *how the gate stream is produced* and in their memory/latency
trade-offs.

```cpp
AG2PCSession sess(io, &pool, party);
using Ctx = AG2PCSession::DirectCtx;
using UInt32 = UInt_T<Ctx, 32>;
auto a = sess.input<UInt32>(ALICE, x);
auto b = sess.input<UInt32>(BOB, y);
```

The session owns the I/O boundary and the crypto; `sess.direct_ctx()` is the gate context
(`AG2PCSession::DirectCtx`) the values are built over.

`DirectCtx` is **only** the direct/user operator-mode context — the recorder where
`a + b` and `frontend::run(sess.direct_ctx(), …)` emit gates. A session is multipass:
it owns several internal pass contexts that the engine drives, and a single canonical
"session ctx" for all phases does not exist. In compiled replay the circuit is recorded
over `RecordCtx` and replayed through those internal pass contexts; in live-body replay
the body is re-instantiated over each pass context per pass. A materialized direct
value is just wires/ids over `DirectCtx`; the pass contexts are not user-visible.

## 1. Direct / chunked

`sess.direct_ctx()` is a `BooleanContext`: operators on its values (`a + b`) record gates
into the current **chunk**. The chunk runs through the engine when you `reveal` or
`checkpoint`.

```cpp
auto z = a + b;                    // recorded, pending
auto out = sess.reveal(z, PUBLIC); // flush the chunk, then open z
```

emp-tool's generic `frontend::run(sess.direct_ctx(), circuit, args...)` and
`frontend::run(body, args...)` also drive the gate context's ops, so they too emit
**direct** gates into the current chunk — convenient, but not a standalone pass
replay. Prefer `sess.run(...)` (below) when you want a self-contained replay.

Best for imperative / reactive programs and large compositions chunked with
`checkpoint`.

## 2. Compiled replay

Compile a pure body once with the emp-tool frontend, then replay the stored
program standalone through all passes:

```cpp
auto c = frontend::compile<rec::UInt<32>, rec::UInt<32>>(
    [](auto x, auto y) { return x + y; });
auto z = sess.run(c, a, b);        // standalone pass replay
```

Best for fixed circuits compiled once and replayed many times.

## 3. Live body replay

Replay a pure body live, once per pass, with no stored IR. Argument value types
are deduced from the arguments:

```cpp
auto z = sess.run([](auto x, auto y) { return x + y; }, a, b);
```

`sess.run` is one overloaded call: hand it a compiled `Circuit` (strategy 2) or a
pure body (strategy 3) and the right one runs, selected at compile time on
`frontend::is_circuit_v`. Best for one-off pure circuits and the leanest memory
profile. A live body replay and the compiled replay of the *same* body produce a
**byte-identical** protocol transcript — both drive the same pass definitions over
the same gate stream. This is the regression gate `test_body_replay_equiv`.

## Materialized vs pending arguments

`sess.run(...)` is a standalone replay: its arguments must be **materialized** —
produced by `sess.input` / `sess.input_batch`, a prior `run`, or carried through a
`checkpoint`. A value that is still pending in the open direct chunk must be flushed
first (`sess.checkpoint(v)`); passing a pending value is a hard error. (Mixing a
direct-chunk value directly into a standalone run is a deferred feature.)

## Raw programs

For the genuinely-untyped case — a hand-authored or loaded `BooleanProgram` (e.g.
an AES/SHA `.empbc` builtin) that carries no typed signature (no `RetV`/`ArgVs`
value types), so it cannot be wrapped as a typed `frontend::Circuit` — the
advanced escape `sess.run_artifact<RetV>(program, args...)` replays it over
materialized typed arguments, returning a value of type `RetV`. Use `BitVec` (or the
raw `protocol()` bit path) for wide crypto I/O — never a `UInt` clear codec beyond
64 bits. Prefer wrapping a fixed program into a typed `frontend::Circuit` and calling
`sess.run(circuit, ...)`; reach for `run_artifact` only when the signature is truly
untyped.
