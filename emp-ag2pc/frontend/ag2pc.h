#ifndef EMP_AG2PC_FRONTEND_AG2PC_H__
#define EMP_AG2PC_FRONTEND_AG2PC_H__

// Object-mode setup/finalize helpers.

#include "emp-ag2pc/frontend/direct_backend.h"

namespace emp {

// Install AG2PCBackend as the active emp-tool backend.
inline AG2PCBackend *setup_ag2pc(NetIO *io, ThreadPool *pool, int party,
                                 int ssp = 40) {
  auto *b = new AG2PCBackend(io, pool, party, ssp);
  backend = b;
  return b;
}

// Reveal n wire carriers to all parties.
inline void reveal_ag2pc(bool *out, void *wires, int n) {
  backend->reveal(out, PUBLIC, wires, n);
}

// Evaluate the current object-mode chunk and carry all live wires.
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
