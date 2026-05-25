#ifndef EMP_AGMPC_H__
#define EMP_AGMPC_H__
#include <thread>

// Pulls in everything from emp-tool: io / core / crypto / group / circuits
// (BristolFormat parser, Bit_T<block>) / execution (Backend, half_gate, ...).
#include "emp-tool/emp-tool.h"

// Upstream OT (IKNP, COT base) consumed by AuthSharePool.
#include "emp-ot/ot_extension/iknp.h"

// emp-agmpc layer (header-only).
#include "emp-agmpc/auth_share_pool.h"
#include "emp-agmpc/triple_pool.h"
#include "emp-agmpc/helper.h"
#include "emp-agmpc/secure_wires.h"
#include "emp-agmpc/circuit_layout.h"
#include "emp-agmpc/mpc.h"
#include "emp-agmpc/netmp.h"
#endif // EMP_AGMPC_H__
