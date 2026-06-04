#ifndef EMP_AG2PC_DIRECT_H__
#define EMP_AG2PC_DIRECT_H__

// Direct AG2PC mode: the SH2PC-style object API.
//
// Include this when you want to write ordinary EMP code:
//   setup_ag2pc(io, &pool, party);
//   UInt32 a(x, ALICE), b(y, BOB);
//   UInt32 c = a + b;
//   uint32_t z = c.reveal<uint32_t>(PUBLIC);
//   finalize_ag2pc();
//
// This header binds Bit / Integer / UInt32 / BitVec / ... to AG2PCWire. Do not
// include it in the same translation unit as <emp-ag2pc/function.h>, which binds
// those same names to LambdaWire for the pure function API.

#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/frontend/ag2pc.h"
#include "emp-ag2pc/frontend/circuit_types.h"

#endif  // EMP_AG2PC_DIRECT_H__
