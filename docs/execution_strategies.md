# Execution strategies

Every circuit in emp-ag2pc runs on one context, `AG2PCCtx`, through the same five
protocol passes (`backend/passes.h`) with identical security, communication, and
per-gate cost. There are three ways to feed a circuit to those passes. They differ
only in *how the gate stream is produced* and in their memory/latency trade-offs.

```cpp
AG2PCCtx ctx(io, &pool, party);
using UInt32 = UInt_T<AG2PCCtx, 32>;
auto a = ctx.input<UInt32>(ALICE, x);
auto b = ctx.input<UInt32>(BOB, y);
```

## 1. Direct / chunked

`AG2PCCtx` is a `BooleanContext`: operators on its values (`a + b`) record gates
into the current **chunk**. The chunk runs through the executor when you `reveal`
or `checkpoint`.

```cpp
auto z = a + b;                  // recorded, pending
auto out = ctx.reveal(z, PUBLIC); // flush the chunk, then open z
```

emp-tool's generic `frontend::run(ctx, circuit, args...)` and
`frontend::run(body, args...)` also drive the context's gate ops, so they too emit
**direct** gates into the current chunk — convenient, but not a standalone pass
replay. Prefer `ctx.run(...)` / `ctx.run_body(...)` (below) when you want a
self-contained replay.

Best for imperative / reactive programs and large compositions chunked with
`checkpoint`.

## 2. Compiled replay

Compile a pure body once with the emp-tool frontend, then replay the stored
program standalone through all passes:

```cpp
auto c = frontend::compile<rec::UInt<32>, rec::UInt<32>>(
    [](auto x, auto y) { return x + y; });
auto z = ctx.run(c, a, b);       // standalone pass replay
```

Best for fixed circuits compiled once and replayed many times.

## 3. Live body replay

Replay a pure body live, once per pass, with no stored IR. Argument value types
are deduced from the arguments:

```cpp
auto z = ctx.run_body([](auto x, auto y) { return x + y; }, a, b);
```

Best for one-off pure circuits and the leanest memory profile. A live body replay
and the compiled replay of the *same* body produce a **byte-identical** protocol
transcript — both drive the same pass definitions over the same gate stream. This
is the regression gate `test_body_replay_equiv`.

## Materialized vs pending arguments

`ctx.run(...)` and `ctx.run_body(...)` are standalone replays: their arguments must
be **materialized** — produced by `ctx.input` / `ctx.input_batch`, a prior `run` /
`run_body`, or carried through a `checkpoint`. A value that is still pending in the
open direct chunk must be flushed first (`ctx.checkpoint(v)`); passing a pending
value is a hard error. (Mixing a direct-chunk value directly into a standalone run
is a deferred feature.)

## Raw programs

`ctx.run_program<RetV>(program, args...)` replays a hand-authored or loaded
`BooleanProgram` (e.g. an AES/SHA `.empbc` builtin) over materialized typed
arguments, returning a value of type `RetV`. Use `Bits_T` (or the raw
`protocol()` / `executor()` bit path) for wide crypto I/O — never a `UInt_T` clear
codec beyond 64 bits.
