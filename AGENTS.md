# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

A header-only C++20 implementation of WRK-style maliciously-secure two-party computation over authenticated garbled circuits, built on emp-tool's `BooleanContext` model. The entire API is one session, [emp-ag2pc/session/ag2pc_session.h](emp-ag2pc/session/ag2pc_session.h) `AG2PCSession`, surfaced through the single public header [emp-ag2pc/emp-ag2pc.h](emp-ag2pc/emp-ag2pc.h).

`AG2PCSession` owns the I/O boundary (`input` / `input_batch` / `reveal` / `checkpoint` / `run` / `run_artifact`), the crypto protocol, an internal engine, and the authenticated carried wire state — only the session can drive a crypto transition, so that invariant is structural. `sess.ctx()` returns `AG2PCSession::Ctx` (= `AG2PCCtx`), a **pure** `BooleanContext` gate recorder (`Wire = uint32_t`, a bare recorder id) holding no crypto and no carried state. Circuit values are emp-tool's context-bound types over that gate context (`AG2PCSession::Bit` / `UInt<N>` / `Int<N>` / `Float<W>` / `BitVec<N>`, i.e. `*_T<AG2PCCtx, …>`); reusable circuits are authored once with the emp-tool frontend (`frontend::compile<rec::…>`). Every emp protocol exposes a Session like this (the trivial `ClearSession` in emp-tool wraps a pure context); the public surface is always the Session.

**Three execution strategies, one pass engine** (see [docs/execution_strategies.md](docs/execution_strategies.md)):
- **Direct / chunked** — operators (`a + b`) record gates into the current chunk, flushed at `reveal` / `checkpoint`. (emp-tool's generic `frontend::run` on `sess.ctx()` also emits direct gates into the chunk; prefer `sess.run` for standalone replay.)
- **Compiled replay** — `sess.run(circuit, args...)` replays a stored `Circuit` standalone through all passes.
- **Live body replay** — `sess.run(body, args...)` replays a pure body live per pass; byte-identical transcript to compiled replay. (`run` is one overloaded call, SFINAE-split on `frontend::is_circuit_v`.)

`sess.run` requires **materialized** args (from `input` / a prior run / a `checkpoint`); a pending direct-chunk arg is a hard error (cross-mode mixing is deferred). Wire liveness is **explicit** — no refcount, no global singleton, no global `emp::Backend`. `checkpoint(keep...)` prunes carried state to the named values; `reveal(v, recipient, keep...)` flushes keeping `v` + `keep...`; stale wires error loudly. The gate recorder defers stale-detection to the session's flush (it has no view of carried state), so a stale-operand error still precedes any protocol execution. The genuinely-untyped raw-program case (a hand-authored / loaded `BooleanProgram` with wide `BitVec` I/O) uses the advanced escape `sess.run_artifact<RetV>(program, args...)`.

**Layout — `session/` over `backend/`:**
- `emp-ag2pc.h` → `emp-tool/emp-tool.h` + `emp-tool/frontend/frontend.h` (compile/run, `rec::`) + `session/ag2pc_session.h` (`AG2PCSession` + `AG2PCCtx`).
- `session/ag2pc_ctx.h` (`AG2PCCtx`, the gate recorder), `session/ag2pc_session.h` (`AG2PCSession`, the public I/O + crypto owner).
- `backend/protocol.h` (`AG2PCProtocol`), `backend/engine.h` (`AG2PCEngine` — internal — + `ag2pc_detail::{append_bundle,body_replay}`), `backend/pass_ctx.h` (the 5 `*Pass` contexts), `backend/run_state.h` (`AG2PCRunState`), `backend/canonical.h`, `backend/flush_plan.h` (`plan_flush`), `backend/secure_wires.h`, `backend/triple_pool.h`, `backend/profiling.h`, `backend/helper.h`.

emp-tool + emp-ot are external `find_package` dependencies (IKNP, NetIO, BlockVec, MITCCRH, the value layer all come from upstream). Local-dev pointer: `-Demp-tool_DIR=/path/to/emp-tool/build -Demp-ot_DIR=/path/to/emp-ot/build`.

**Do not reintroduce:** the public object/stream mode split, `Shape` / `SecureValue<Shape>`, an `AG2PCBackend` / `AG2PCWire` refcount carrier, `setup_ag2pc` / global `emp::Backend`, `EMP_CIRCUIT_TYPES_ALL` aliases, `LambdaWire` / `run_circuit` / `AG2PCInputs`. The value surface uses only `*_T<Ctx>` + `value_traits` + `rec::`/`compile`/`run`. (Note: the current `AG2PCSession` / `AG2PCEngine` are the sanctioned explicit-liveness design — the session owns `carried_` and the engine is an internal `SecureWires`-in/out runner — **not** the rejected refcount-carrier `AG2PCBackend`/`AG2PCWire` model.)

## Protocol

Authenticated garbling (WRK17) with the [KRRW18](https://eprint.iacr.org/2018/578) optimizations: a function-dependent half-gate leaky-AND (KRRW §5.2) run in place on each AND gate's own input masks, a batched `F_eq` check, and cyclic-shift bucketing. Correlated OT is a single lifetime-open SoftSpoken⟨4⟩ session from emp-ot, whose consistency check runs before every reveal so it gates output. Party 1 is the garbler, party 2 the evaluator. See the README **"How it works"** for the component map.

## Build / test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release      # out-of-source REQUIRED (in-source = fatal error)
cmake --build build -j
ctest --test-dir build --output-on-failure          # 2-party over localhost
```
- Dependencies: emp-tool + emp-ot via `find_package` (`-Demp-tool_DIR=… -Demp-ot_DIR=…`).
- Options: `EMP_AG2PC_BUILD_TESTS` (ON when top-level), `EMP_AG2PC_BUILD_BENCHES` (OFF; SHA benches await the Stage-5 context-generic SHA kernel and are not built yet).
- Profiling: configure with `-DCMAKE_CXX_FLAGS=-DAG2PC_PROFILE` for the per-phase `[ag2pc]` / `[ag2pc-tp]` markers ([backend/profiling.h](emp-ag2pc/backend/profiling.h)); zero-cost when off.

## Running a test

Each binary takes `<party> <port>`; use the top-level [run](run) helper (2-party over localhost, random port, ALICE's exit code is the verdict). Binary `test_<name>` is built from `test/test_<name>.cpp`:

```bash
./run ./build/bin/test_context_api
```
Transport: a primary `emp::NetIO` plus a sibling channel via `NetIO::make_sibling()` (the `send_io`/`recv_io` duplex), built in [test/net_setup.h](test/net_setup.h) by `make_io2pc`. Tests: `test_context_api`, `test_direct_chunks`, `test_program_replay`, `test_body_replay_equiv` (the byte-identical-transcript gate), `test_aes_sha_builtin`, `test_flush_plan` (single-process planner unit test), `test_session_concepts` (compile-time `CircuitSession`/`SessionIO`/`CheckpointingSession` + `run` accepts a checkpointed value). See the README test table.

## Architecture (bottom-up)

1. **`TriplePool`** ([backend/triple_pool.h](emp-ag2pc/backend/triple_pool.h)) — the COT/Δ session over emp-ot SoftSpoken⟨4⟩ plus authenticated AND-share generation: aShares (`MAC = KEY ⊕ x·Δ`) minted from COT with a bit-0/bit-1 Δ pinning, each AND gate's `σ = λ_α∧λ_β` built by the in-place function-dependent leaky-AND (KRRW §5.2), a batched `F_eq` check, and cyclic-shift bucketing. Opened once, held for the session; its check gates every reveal.
2. **`AG2PCProtocol`** ([backend/protocol.h](emp-ag2pc/backend/protocol.h)) — session crypto only: `process_inputs` (KRRW Fig.3 input authentication, batched across owners) and `decode`/`reveal` (output open). Owns the `TriplePool` (`fpre`) and the duplex `NetIO`. No circuit walk.
3. **`AG2PCEngine`** ([backend/engine.h](emp-ag2pc/backend/engine.h)) — internal (not public), `SecureWires`-in/out. Runs a `BooleanProgram` or a live body source through the five `*Pass` contexts ([backend/pass_ctx.h](emp-ag2pc/backend/pass_ctx.h)): `AG2PCLivenessPass` → `AG2PCSlotMaskPass` (fused size/collect-masks) → `AG2PCGarblePass`/`AG2PCEvaluatePass` → `AG2PCGammaCheckPass` (`c_γ`) → output, over a slot-reused per-wire layout (memory linear in #AND + live width, not #wires). Each pass is itself a `BooleanContext` over one shared `AG2PCRunState` ([backend/run_state.h](emp-ag2pc/backend/run_state.h)) constructed fresh as a stack local per run, so the same gate stream drives every phase — hence the byte-identical transcript across strategies. `total_ands` is the engine's lone durable field.
4. **`AG2PCCtx`** ([session/ag2pc_ctx.h](emp-ag2pc/session/ag2pc_ctx.h)) — the gate recorder (`AG2PCSession::Ctx`). Gate ops record `circuit::Gate`s into the current chunk as bare ids and insert them into `pending_`; it owns only `next_id_` / `chunk_gates_` / `pending_` / `const_wire_` — no crypto, no `carried_`. It does **no** carried/stale lookup in the gate path; an operand id that is neither pending nor allocated is the only thing it rejects.
5. **`AG2PCSession`** ([session/ag2pc_session.h](emp-ag2pc/session/ag2pc_session.h)) — the public session. Owns `AG2PCProtocol proto_`, the gate `ctx_`, the internal `engine_`, and `carried_` (materialized id → authenticated state). `flush_` plans the pending chunk ([backend/flush_plan.h](emp-ag2pc/backend/flush_plan.h) `plan_flush`: keep-list-driven DCE + RecordCtx-canonical compaction + deferred stale-operand detection over `carried_`), runs it through `engine_`, scatters outputs back into `carried_`, and drops the chunk. A value's ids are MATERIALIZED (state in `carried_`) or PENDING (in the open chunk); `reveal`/`run`/`checkpoint` validate and error on a stale id.
