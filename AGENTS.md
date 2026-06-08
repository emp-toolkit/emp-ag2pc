# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

A header-only C++20 implementation of WRK-style maliciously-secure two-party computation over authenticated garbled circuits, built on emp-tool's `BooleanContext` model. The entire API is one context, [emp-ag2pc/frontend/ag2pc_ctx.h](emp-ag2pc/frontend/ag2pc_ctx.h) `AG2PCCtx`, surfaced through the single public header [emp-ag2pc/emp-ag2pc.h](emp-ag2pc/emp-ag2pc.h).

`AG2PCCtx` IS a `BooleanContext` (`Wire = uint32_t`, a bare recorder id) and owns the crypto protocol + executor and the typed I/O: `input` / `input_batch` / `reveal` / `checkpoint` / `run` / `run_body` / `run_program`. Circuit values are emp-tool's context-bound types over `AG2PCCtx` (`Bit_T` / `UInt_T<N>` / `Int_T<N>` / `Float_T<W>` / `BitVec_T<N>`); reusable circuits are authored once with the emp-tool frontend (`frontend::compile<rec::…>`).

**Three execution strategies, one pass executor** (see [docs/execution_strategies.md](docs/execution_strategies.md)):
- **Direct / chunked** — operators (`a + b`) record gates into the current chunk, flushed at `reveal` / `checkpoint`. (emp-tool's generic `frontend::run` also emits direct gates into the chunk; prefer `ctx.run` for standalone replay.)
- **Compiled replay** — `ctx.run(circuit, args...)` replays a stored `Circuit` standalone through all passes.
- **Live body replay** — `ctx.run_body(body, args...)` replays a pure body live per pass; byte-identical transcript to compiled replay.

`ctx.run` / `ctx.run_body` require **materialized** args (from `input` / a prior run / a `checkpoint`); a pending direct-chunk arg is a hard error (cross-mode mixing is deferred). Wire liveness is **explicit** — no refcount, no global singleton, no global `emp::Backend`. `checkpoint(keep...)` prunes carried state to the named values; `reveal(v, recipient, keep...)` flushes keeping `v` + `keep...`; stale wires error loudly.

**Layout — `frontend/` over `backend/`:**
- `emp-ag2pc.h` → `emp-tool/emp-tool.h` + `emp-tool/frontend/frontend.h` (compile/run, `rec::`) + `frontend/ag2pc_ctx.h` (`AG2PCCtx`).
- `backend/protocol.h` (`AG2PCProtocol`), `backend/executor.h` (`AG2PCExecutor` + `ag2pc_detail::body_replay`), `backend/passes.h` (the 5 passes + `LambdaState`), `backend/secure_wires.h`, `backend/triple_pool.h`, `backend/profiling.h`, `backend/helper.h`.

emp-tool + emp-ot are external `find_package` dependencies (IKNP, NetIO, BlockVec, MITCCRH, the value layer all come from upstream). Local-dev pointer: `-Demp-tool_DIR=/path/to/emp-tool/build -Demp-ot_DIR=/path/to/emp-ot/build`.

**Do not reintroduce:** the public object/stream mode split, `Shape` / `SecureValue<Shape>`, `AG2PCSession` / `AG2PCEngine` / `AG2PCBackend` / `AG2PCWire` refcount carrier, `setup_ag2pc` / global `emp::Backend`, `EMP_CIRCUIT_TYPES_ALL` aliases, `LambdaWire` / `run_circuit` / `AG2PCInputs`. The value surface uses only `*_T<Ctx>` + `value_traits` + `rec::`/`compile`/`run`.

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
Transport: a primary `emp::NetIO` plus a sibling channel via `NetIO::make_sibling()` (the `send_io`/`recv_io` duplex), built in [test/net_setup.h](test/net_setup.h) by `make_io2pc`. Tests: `test_context_api`, `test_direct_chunks`, `test_program_replay`, `test_body_replay_equiv` (the byte-identical-transcript gate), `test_aes_sha_builtin`. See the README test table.

## Architecture (bottom-up)

1. **`TriplePool`** ([backend/triple_pool.h](emp-ag2pc/backend/triple_pool.h)) — the COT/Δ session over emp-ot SoftSpoken⟨4⟩ plus authenticated AND-share generation: aShares (`MAC = KEY ⊕ x·Δ`) minted from COT with a bit-0/bit-1 Δ pinning, each AND gate's `σ = λ_α∧λ_β` built by the in-place function-dependent leaky-AND (KRRW §5.2), a batched `F_eq` check, and cyclic-shift bucketing. Opened once, held for the session; its check gates every reveal.
2. **`AG2PCProtocol`** ([backend/protocol.h](emp-ag2pc/backend/protocol.h)) — session crypto only: `process_inputs` (KRRW Fig.3 input authentication, batched across owners) and `decode`/`reveal` (output open). Owns the `TriplePool` (`fpre`) and the duplex `NetIO`. No circuit walk.
3. **`AG2PCExecutor`** ([backend/executor.h](emp-ag2pc/backend/executor.h)) — runs a `BooleanProgram` or a live body source through the five passes ([backend/passes.h](emp-ag2pc/backend/passes.h)): liveness → fused size/collect-masks → garble/evaluate → `c_γ` check → output, over a slot-reused per-wire layout (memory linear in #AND + live width, not #wires). Each pass is itself a `BooleanContext` over one shared `LambdaState`, so the same gate stream drives every phase — hence the byte-identical transcript across strategies.
4. **`AG2PCCtx`** ([frontend/ag2pc_ctx.h](emp-ag2pc/frontend/ag2pc_ctx.h)) — the public context. Gate ops record `circuit::Gate`s into the current chunk; `flush_` does keep-list-driven DCE and compacts to a RecordCtx-canonical `BooleanProgram` for the executor. A value's ids are MATERIALIZED (authenticated state in `carried_`) or PENDING (in the open chunk); every lookup validates and errors on a stale id.
