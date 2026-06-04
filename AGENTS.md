# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

A header-only C++ implementation of WRK-style maliciously-secure two-party computation over authenticated garbled circuits. User code chooses one of two parallel mode headers: [emp-ag2pc/direct.h](emp-ag2pc/direct.h) or [emp-ag2pc/function.h](emp-ag2pc/function.h). The compatibility umbrella [emp-ag2pc/emp-ag2pc.h](emp-ag2pc/emp-ag2pc.h) forwards to direct mode.

**Direct mode first.** Users write ordinary EMP code: `setup_ag2pc` + native objects (`Bit`/`UInt32`/`BitVec`) + operators + `.reveal<T>()` + `finalize_ag2pc`, all from [emp-ag2pc/direct.h](emp-ag2pc/direct.h). Do not present `AG2PCSession` / `AG2PCEngine` / `SecureWires` / `process_inputs` / `decode` as the direct-mode surface.

**Two modes, one engine.** There are two intentional front-ends over the single executor (`run_engine_`): **direct mode** (`direct.h`: persistent backend, object I/O, mid-stream reveal / reactive / checkpoint) and **function mode** (`function.h`: `AG2PCEngine` `run<>`/`run_compiled`/`run_program`/`run_circuit`/`AG2PCInputs`, pure body, `SecureWires` I/O, streaming / compiled). They are disjoint at the wire-binding + I/O layer (`AG2PCWire` vs `LambdaWire`, one mode header per TU); see the README **"Choosing a mode"** table. Shared circuit logic should live in wire-generic functions/templates in neutral headers. Object-level `.reveal<T>()` on a live value is a direct-mode feature (persistent backend); function mode opens `SecureWires` via `AG2PCSession::reveal`/`decode`, except `run(AG2PCInputs&, body)` which returns an `Opened` handle exposing a post-run `c.reveal<T>(party)` (decode-and-fold) for constructor-in / object-reveal-out symmetry.

**Layout — `frontend/` over `backend/`:**
- `direct.h` is the public object API; it includes `frontend/ag2pc.h` (setup/finalize/reveal/checkpoint), `frontend/direct_backend.h` (`AG2PCBackend` + `AG2PCWire`), and `frontend/circuit_types.h` (AG2PCWire `Bit`/`Integer`/… aliases). `function.h` is the pure function / compiled API; it includes `frontend/run.h` (`run`/`run_compiled`/`run_program` + `LambdaWire` aliases). Never include both mode headers in one TU (alias collision).
- `backend/engine.h` (`AG2PCEngine`), `backend/session.h` (`AG2PCSession`), `backend/secure_wires.h`, `backend/triple_pool.h`, `backend/profiling.h`, `backend/helper.h`.

**One protocol executor:** exactly one engine — `AG2PCEngine::run_engine_` ([emp-ag2pc/backend/engine.h](emp-ag2pc/backend/engine.h)). It runs a *circuit source* (replay callback) per phase; inputs/outputs are handled via `AG2PCSession::process_inputs` / `decode`. Sources: a pure frontend body (`run<Ins...>`), a compiled `frontend::TypedCircuit` (`run_compiled<Ins...>`), a raw `frontend::BooleanProgram` (`run_program`), or the flat lambda (`run_circuit`). The direct backend `AG2PCBackend` ([emp-ag2pc/frontend/direct_backend.h](emp-ag2pc/frontend/direct_backend.h)) is **not** a separate path: it buffers each chunk into a `frontend::BooleanProgram` and replays it via `run_program` on the same engine — kept for what a pure body can't express (mid-stream reveal / checkpoint, reactive host branching, RAII liveness). `AG2PCSession` ([emp-ag2pc/backend/session.h](emp-ag2pc/backend/session.h)) is pure crypto: input authentication, output decode, the long-lived COT/Δ session — no circuit walk.

**Renames / compat:** `C2PC`→`AG2PCSession`, `LambdaRunner`→`AG2PCEngine` (old names kept as `using` aliases). `<emp-ag2pc/emp-ag2pc.h>` remains a compatibility forwarder to direct mode. Old header paths (`2pc.h`, `lambda_runner.h`, `ag2pc_backend.h`, `share_bundle.h`, `profiling.h`, `triple_pool.h`, `helper.h`, `ag2pc_circuit_types.h`, `lambda_circuit_types.h`) remain as thin forwarders. `WireGraph` and `C2PC::compute` no longer exist; do not reintroduce them. emp-tool + emp-ot are external `find_package` dependencies — IKNP, NetIO, BlockVec, default_init_allocator, MITCCRH all come from upstream via CMake `find_package`. Local-dev pointer: `-Demp-tool_DIR=/path/to/emp-tool/build -Demp-ot_DIR=/path/to/emp-ot/build`.

## Protocol

Authenticated garbling (WRK17) with the [KRRW18](https://eprint.iacr.org/2018/578) optimizations: a function-dependent half-gate leaky-AND (KRRW §5.2) run in place on each AND gate's own input masks, a batched `F_eq` check, and cyclic-shift bucketing. Correlated OT is a single lifetime-open SoftSpoken⟨4⟩ session from emp-ot, whose consistency check runs before every reveal so it gates output. See the README **"How it works"** for the component map. (Party 1 is the garbler, party 2 the evaluator.)

## Build / test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release      # out-of-source REQUIRED (in-source = fatal error)
cmake --build build -j
ctest --test-dir build --output-on-failure          # 2-party over localhost
```
- Dependencies: emp-tool + emp-ot via `find_package` (point at build trees with `-Demp-tool_DIR=… -Demp-ot_DIR=…`).
- Options: `EMP_AG2PC_BUILD_TESTS` (ON when top-level), `EMP_AG2PC_BUILD_BENCHES` (OFF; builds `test/bench_modes.cpp`, **not** registered with ctest).
- Profiling: configure with `-DCMAKE_CXX_FLAGS=-DAG2PC_PROFILE` to enable the per-phase `[ag2pc]` / `[ag2pc-tp]` markers ([backend/profiling.h](emp-ag2pc/backend/profiling.h)); zero-cost when off.

## Running a test

Each binary takes `<party> <port>`; use the top-level [run](run) helper (2-party — party 3 returns immediately). Binaries are double-prefixed `test_test_<name>`:

```bash
./run ./build/bin/test_test_public_api
```
Transport: a primary `emp::NetIO` plus a sibling channel spawned via `NetIO::make_sibling()` (the `send_io`/`recv_io` duplex), built in [test/net_setup.h](test/net_setup.h) by `make_io2pc`. Tests are grouped by surface — `test_public_api` / `test_direct_semantics` / `test_direct_crypto` (direct mode) and `test_engine_internal` / `test_wire_equiv` (function mode / internal). See README's test table.

## Architecture (bottom-up; one engine)

1. **`TriplePool`** ([backend/triple_pool.h](emp-ag2pc/backend/triple_pool.h)) — the COT/Δ session over emp-ot SoftSpoken⟨4⟩ plus authenticated AND-share generation: aShares (`MAC = KEY ⊕ x·Δ`) minted from COT with a bit-0/bit-1 Δ pinning, then each AND gate's `σ = λ_α∧λ_β` built by the in-place function-dependent leaky-AND (KRRW §5.2), a batched `F_eq` check, and cyclic-shift bucketing. Opened once and held for the session; its check gates every reveal.
2. **`AG2PCSession`** ([backend/session.h](emp-ag2pc/backend/session.h), was `C2PC`) — session crypto only: `process_inputs` (KRRW Fig.3 input authentication, batched across owners) and `decode`/`reveal` (output open). Owns the `TriplePool` (`fpre`) and the duplex `NetIO`. No circuit walk.
3. **`AG2PCEngine`** ([backend/engine.h](emp-ag2pc/backend/engine.h), was `LambdaRunner`) — the ONE executor (`run_engine_`): replays a circuit source per phase (liveness → fused size/collect-masks → garble/evaluate → `c_γ` check → output) over a slot-reused per-wire layout, so memory is linear in #AND + live width, not #wires. Sources listed above; `AG2PCInputs` provides constructor-style batched inputs and `run` returns an `Opened` result handle.
4. **`AG2PCBackend`** ([frontend/direct_backend.h](emp-ag2pc/frontend/direct_backend.h)) — the public direct adapter over a refcounted 4-byte `AG2PCWire`: records native `Bit`/`Integer` code, dead-code-eliminates + chunks it into a `frontend::BooleanProgram`, and runs it on `AG2PCEngine` via `run_program`. A recording/chunking front-door, **not** a second garbler/evaluator; supports mid-stream reveal, reactive branching, and `checkpoint_ag2pc_keep_all()`.

Gone — do not reintroduce: `WireGraph` / `C2PC::compute`, the `nP` / `NetIOMP` mesh, `AuthSharePool` / `cot.h` / `ot/`, BristolFormat circuits, and `doc/main.pdf`. (Earlier docs described that pre-rewrite `ref` stack; it is no longer this tree.)
