#ifndef EMP_AG2PC_FUNCTION_H__
#define EMP_AG2PC_FUNCTION_H__

// Function AG2PC mode: the pure function / compiled-circuit API.
//
// Include this when you want to drive the shared engine explicitly:
//   AG2PCSession session(io, &pool, party);
//   AG2PCEngine engine(&session);
//   auto in = session.process_inputs(...);
//   SecureWires out = engine.run<UInt32, UInt32>({in[0], in[1]}, body);
//   auto opened = session.reveal(out, PUBLIC);
//
// This header binds Bit / Integer / UInt32 / BitVec / ... to LambdaWire. Do not
// include it in the same translation unit as <emp-ag2pc/direct.h>, which binds
// those same names to AG2PCWire for the direct object API.

#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/frontend/run.h"

#endif  // EMP_AG2PC_FUNCTION_H__
