#ifndef EMP_AG2PC_H__
#define EMP_AG2PC_H__

// emp-ag2pc — two-party authenticated garbling (malicious-secure 2PC) over the
// emp-tool BooleanContext model. The whole API is one session, AG2PCSession:
//
//   AG2PCSession sess(io, &pool, party);
//   using Ctx = AG2PCSession::DirectCtx;  // the direct gate context
//   using UInt32 = UInt_T<Ctx, 32>;
//   auto a = sess.input<UInt32>(ALICE, x);
//   auto b = sess.input<UInt32>(BOB, y);
//   auto z = a + b;                       // direct: recorded into a chunk
//   auto out = sess.reveal(z, PUBLIC);    // std::optional<uint64_t>
//
// The session owns the I/O boundary (input / reveal / checkpoint), the crypto
// protocol, and the authenticated carried state; sess.direct_ctx() is the gate
// context values are built over (the session names no value family). Circuits run three ways: direct/chunked (operators),
// compiled replay (sess.run(circuit, ...)), and live body replay
// (sess.run(body, ...)). Circuits are authored once with the emp-tool frontend
// (compile / rec:: value types) and run on any session. Everything is explicit —
// no global backend.

#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/frontend/frontend.h"      // compile / run, rec:: value aliases
#include "emp-ag2pc/session/ag2pc_session.h" // AG2PCSession (+ AG2PCCtx gate context)

#endif  // EMP_AG2PC_H__
