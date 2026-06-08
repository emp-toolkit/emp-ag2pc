#ifndef EMP_AG2PC_H__
#define EMP_AG2PC_H__

// emp-ag2pc — two-party authenticated garbling (malicious-secure 2PC) over the
// emp-tool BooleanContext model. The whole API is one context, AG2PCCtx:
//
//   AG2PCCtx ctx(io, &pool, party);
//   using UInt32 = UInt_T<AG2PCCtx, 32>;
//   auto a = ctx.input<UInt32>(ALICE, x);
//   auto b = ctx.input<UInt32>(BOB, y);
//   auto z = a + b;                       // direct: recorded into a chunk
//   auto out = ctx.reveal(z, PUBLIC);     // std::optional<uint64_t>
//
// Circuits run three ways on the context: direct/chunked (operators), compiled
// replay (ctx.run(circuit, ...)), and live body replay (ctx.run_body(body, ...)).
// Circuits are authored once with the emp-tool frontend (compile / rec:: value
// types) and run on any context. The context is explicit — no global backend.

#include "emp-tool/emp-tool.h"
#include "emp-tool/frontend/frontend.h"   // compile / run, rec:: value aliases
#include "emp-ag2pc/frontend/ag2pc_ctx.h" // AG2PCCtx

#endif  // EMP_AG2PC_H__
