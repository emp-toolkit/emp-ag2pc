#ifndef EMP_AG2PC_FRONTEND_AG2PC_H__
#define EMP_AG2PC_FRONTEND_AG2PC_H__

// Public AG2PC entry point — the SH2PC-style front door.
//
// Author circuits in emp-tool's native objects (Bit / Integer / UInt32 / BitVec,
// from frontend/circuit_types.h) between setup_ag2pc() and finalize_ag2pc(), and
// read results with `.reveal<T>()`. The direct recorder (frontend/direct_backend.h)
// records the gates and runs them on the shared engine behind the scenes — users
// never touch the session, the engine, or SecureWires.
//
//   setup_ag2pc(io, &pool, party);
//   Integer a(32, party == ALICE ? x : 0, ALICE);
//   Integer b(32, party == BOB   ? y : 0, BOB);
//   Integer c = a + b;
//   uint32_t out = c.reveal<uint32_t>(PUBLIC);
//   finalize_ag2pc();

#include "emp-ag2pc/frontend/direct_backend.h"   // AG2PCBackend (the direct adapter)

namespace emp {

// Install the AG2PC direct backend as the active emp-tool backend. Returns the
// backend (rarely needed directly). Pair with finalize_ag2pc().
inline AG2PCBackend *setup_ag2pc(NetIO *io, ThreadPool *pool, int party,
                                 int ssp = 40) {
  auto *b = new AG2PCBackend(io, pool, party, ssp);
  backend = b;
  return b;
}

// Reveal n wire carriers to ALL parties (returns the values, keeps all alive
// wires live, continues recording). A single Bit can also use
// `x.reveal<bool>(PUBLIC)` directly.
inline void reveal_ag2pc(bool *out, void *wires, int n) {
  backend->reveal(out, PUBLIC, wires, n);
}

// Force evaluation of the chunk recorded so far. Every wire still pinned by a
// live user-side Bit carries its authenticated state into the next chunk;
// wires whose Bit handles have gone out of scope are dropped (RAII-driven —
// no `keep[]` list to maintain). Caps gate-list and triple-gen transient
// memory for long compositions.
inline void checkpoint_ag2pc_keep_all() {
  static_cast<AG2PCBackend *>(backend)->checkpoint_keep_all();
}

inline void finalize_ag2pc() {
  if (backend == nullptr) return;
  backend->finalize();
  delete backend;
  backend = nullptr;
}

}  // namespace emp
#endif  // EMP_AG2PC_FRONTEND_AG2PC_H__
