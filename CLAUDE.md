# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A header-only C++ implementation of WRK-style maliciously-secure multiparty computation over authenticated garbled circuits. The protocol logic lives in headers under [emp-ag2pc/](emp-ag2pc/) and is pulled in via [emp-ag2pc/emp-ag2pc.h](emp-ag2pc/emp-ag2pc.h). emp-tool + emp-ot are external `find_package` dependencies — IKNP, NetIO, BlockVec, default_init_allocator, MITCCRH all come from upstream emp-tool / emp-ot via CMake `find_package(emp-tool)` / `find_package(emp-ot)`. Local-dev pointer: `-Demp-tool_DIR=/path/to/emp-tool/build -Demp-ot_DIR=/path/to/emp-ot/build`.

### Known status (2026-05)

3 of 13 ctest targets currently fail at the LaAND alpha sum-check ([triple_pool.h:388](emp-ag2pc/triple_pool.h)): `triple`, `pr10_test`, `prof_triple`. The common pattern is "the very first MAC/KEY-consuming step is a *large* TriplePool::compute" — tests that warm IKNP with a small draw first (anything going through C2PC's process_input path) pass cleanly. Root cause not yet pinned; suspect a NetIO send_buf cross-thread race that the previous NetIOBuffered transport masked (cf. ref/'s own commit `f90a644` "AuthSharePool: flush abit1 NetIO directly to avoid cross-thread send_buf race" — that workaround targets the same class of bug, and NetIOBuffered itself has since been removed from emp-tool). three_party_iknp passes, so raw IKNP rcot is correct; the divergence is somewhere in the AuthSharePool→TriplePool path's cold-start.


## Design doc

The cryptographic protocol spec is at [doc/main.pdf](doc/main.pdf) — Figures 13 (Π_aShare, page 32), 15 (Π_aAND, page 34), and 16 (bucketing, page 48) there are the direct reference for [auth_share_pool.h](emp-ag2pc/auth_share_pool.h) and [triple_pool.h](emp-ag2pc/triple_pool.h). Read specific pages via the `pages` argument. Consult it before changing protocol structure, not just naming or locality refactors.

## Build / test

```bash
cmake .                       # configure (out-of-source also works; CMake writes into repo root by default)
make test_triple              # build a single test target; binary goes to ./bin/
cmake -DEMP_AG2PC_DEBUG=ON .  # turn on internal MAC / correctness checks (defines __debug)
cmake -DEMP_AG2PC_DEBUG=OFF . # turn them off (default)
ctest                         # run all tests (uses ./run)
```

Build flags: Release (`-O3`) is default; debug sets `-O0 -ggdb`. Arm builds use `-march=armv8-a+simd+crypto+crc` and the [sse2neon](emp-ag2pc/utils/sse2neon.h) shim; x86 uses `-march=native -maes -mrdseed`. OpenSSL is required (on macOS arm64 the build auto-points at `/opt/homebrew/opt/openssl`).

The `EMP_AG2PC_DEBUG` flag is the single switch for in-protocol correctness checks (`check_MAC`, `check_correctness`) and per-phase timing prints — it's surfaced via CMake rather than editing `c2pc_config.h`.

## Running a test

Each test binary in [test/](test/) takes `<party> <port>` and needs two or more processes talking over localhost. Use the [run](run) helper:

However, note that run script only works for nP=2

```bash
./run ./bin/test_triple          # launch both parties, party 2 foregrounded
./run -t1 ./bin/test_mpc         # /usr/bin/time on party 1
./run -p1 ./bin/test_mpc         # perf record on party 1
./run -m1 ./bin/test_mpc         # valgrind on party 1
```

The test binaries differ in party count (e.g. `test_triple` hardcodes `nP = 2`, `test_mpc` / `test_iknp_aes` / `test_pool` hardcode `nP = 3`); if you change `nP`, edit the test file.

This is now **2-party** (`nP = 2`): spawn exactly two processes, party ids 1 and 2. Tests build the transport with `make_io2pc(party, port, io1, io2)` ([test/net_setup.h](test/net_setup.h)) and feed `io1`/`io2` to the constructors.

The transport is a **duplex pair of `NetIO` channels** to the single peer: `io1` on `port` (party 1 server, party 2 client), `io2` on `port + 1` (the mirror). `io1` carries the 1→2 direction, `io2` the 2→1; the layers route by `sign(idx - party)` via the `io_send`/`io_recv`/`io_flush` free helpers in [helper.h](emp-ag2pc/helper.h), and `AuthSharePool` hands one channel to each of its two COT instances for parallel send/recv. (The old `nP × nP` `NetIOMP` mesh is gone.)

## Architecture

The protocol stack is strictly layered; upper layers instantiate and drive the layers below. Each layer is a template on `nP` (party count).

1. **`Cot` / `IKNP`** ([emp-ag2pc/cot.h](emp-ag2pc/cot.h), [emp-ag2pc/ot/](emp-ag2pc/ot/)) — correlated OT built on IKNP. Uses `MITCCRH<8>` (multi-instance tweakable CCRH, [emp-ag2pc/utils/mitccrh.h](emp-ag2pc/utils/mitccrh.h)) for the half-gate-style hashing. Each pair of parties holds symmetric `Cot` instances.

2. **`AuthSharePool` (Π_aShare, Figure 13)** ([emp-ag2pc/auth_share_pool.h](emp-ag2pc/auth_share_pool.h)) — authenticated bits + amortized pool. For each party's random bit `x^i` every peer holds a MAC under its own global key `Δ_j`: `MAC = KEY ⊕ x^i · Δ_j`. Correctness on the sacrificial csp-tail is checked by `check1` (gadget packing over GF(2^128)) and on the output by `check2` (universal hashing); both broadcasts go through `EchoBC` and are finalized together. `compute()` is the refill primitive (mints `length` aShares + 128 csp tail per call); `draw(n, ...)` and `preprocess(n)` consume from / fill an internal pool so per-call csp cost is amortized across many `process_input` calls.

   Critical invariant: `LSB(Δ_1) = nP mod 2`, `LSB(Δ_j) = 1` for `j ≠ 1`. This makes `LSB(⊕_p Δ_p) = 1`, which the half-gate Λ_γ recovery in `mpc.h` and the LaAND `d = LSB(⊕ s^p)` decoding in `triple_pool.h` both rely on. Forced in `AuthSharePool`'s ctor.

3. **`TriplePool` (Π_aAND, Figure 15 + Figure 16 bucketing)** ([emp-ag2pc/triple_pool.h](emp-ag2pc/triple_pool.h)) — generates authenticated AND triples + amortized pool, owns the inner `AuthSharePool` (`abit` member). Half-gate phi exchange uses `MITCCRH<8>` per peer pair, seeded with a deterministic public `start_point = makeBlock(min(party,peer), max(party,peer))` so both sides' `gid` advance in lockstep. Chunk width `1<<16` is divisible by the MITCCRH batch size of 8, and last batches are zero-padded identically on both sides to keep state aligned. The LAND→AND bucketing uses Figure 16's per-row circular shifts on a `bucket_size × length` matrix (not a Fisher-Yates permutation): row 0 is unshifted; rows `k = 1..B-1` get a random shift `r_k` derived from the shared seed `S`. Bucket `i`'s `k`-th slot is leaky triple `k*length + (i + r_k) mod length` — no `location[]` array, and each row is streamed once per bucket range (with one wraparound cut) for sequential reads. `compute()` is the refill primitive (bucket size 5/4/3 at 3.1K/280K thresholds); `draw(n, ...)` and `preprocess(n)` use a pool with `min_refill = 280000` so even small calls land at bucket-3 cost.

4. **`C2PC`** ([emp-ag2pc/2pc.h](emp-ag2pc/2pc.h)) — top-level WRK protocol. New API: `process_input(bits, n, owner) → SecureWires`, `compute(cf, inputs) → SecureWires`, `decode(wires, recipient) → vector<bool>`; `compute()` accepts a single bundle or a `vector<SecureWires>` of bundles laid out sequentially in the wire space. Both `process_input` and `compute` draw aShares/triples from the pools owned by the inner `TriplePool` (`fpre`) and `AuthSharePool` (`fpre->abit`); `C2PC::preprocess(num_triples, num_abits)` eagerly mints into both. Backward-compat wrappers (`function_independent`/`function_dependent`/`online`) cover the old workflow; `function_independent()` now pre-mints based on the cached circuit's AND count and input width. Takes a `BristolFormat` circuit ([emp-ag2pc/circuits/circuit_file.h](emp-ag2pc/circuits/circuit_file.h)). Circuits live under [emp-ag2pc/circuits/files/](emp-ag2pc/circuits/files/); the `EMP_CIRCUIT_PATH` macro (set via `add_definitions` in the root CMake) is how tests find them.

5. **Transport** — two raw `emp::NetIO` channels (`io1`, `io2`) held directly by each layer (no wrapper object); the duplex pair to the single peer. Created in tests by `make_io2pc` ([test/net_setup.h](test/net_setup.h)) and routed by the `io_send`/`io_recv`/`io_flush`/`io_count` free helpers in [helper.h](emp-ag2pc/helper.h). `AuthSharePool` runs its COT sender + receiver in parallel, one on each channel.

> NOTE: the rest of this Architecture section is inherited from the pre-modernization doc and is partly stale (e.g. `cot.h`, `BristolFormat`, `function_independent`); it needs a full rewrite to match the imported agmpc stack (native Bit frontend, `wrk_backend.h`, typed gate IR).

## Debug timing

When `__debug` is defined, [emp-ag2pc/helper.h](emp-ag2pc/helper.h) exposes `_phase(name, party)` with a single static clock. Non-empty `name` prints `"  name: elapsed us"` (only from party 1) and resets; empty `name` silently resets. The silent-reset form is how we drop internal debug checks from the timeline: after an internal `check_MAC`, call `_phase("", party)` and the elapsed interval doesn't land in the next phase's measurement. See the pattern at the end of `AuthSharePool::compute` — the aShare phase is printed there, not from `TriplePool`.

`TriplePool::compute` emits phase markers (prefixed `[triple]`) for `phi compute`, `half-gate exchange`, `combine s`, `LAND check`, `bucketing`, and `bucket d exchange`. The final `check_MAC` / `check_correctness` at the bottom of `TriplePool::compute` are intentionally outside all phase timers.
