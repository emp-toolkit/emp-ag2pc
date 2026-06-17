#ifndef AG2PC_TEST_COMMON_H__
#define AG2PC_TEST_COMMON_H__
// Shared helpers for the AG2PCSession tests.
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/context/context.h"   // ClearCtx, execute_program
#include "net_setup.h"
#include <cstdint>
#include <span>
#include <vector>

namespace ag2pc_test {

// Cleartext oracle: evaluate a BooleanProgram on the plaintext ClearCtx over the
// same input bits, returning the output bits. Used to check AG2PC replay results.
inline std::vector<uint8_t> clear_eval(const emp::circuit::BooleanProgram &p,
                                    const std::vector<uint8_t> &in) {
  emp::ClearCtx cx;
  std::vector<uint8_t> cin(in.size());
  for (size_t i = 0; i < in.size(); ++i) cin[i] = in[i] ? 1 : 0;
  std::vector<uint8_t> cow =
      emp::execute_program(cx, p, std::span<const uint8_t>(cin.data(), cin.size()));
  std::vector<uint8_t> out(cow.size());
  for (size_t i = 0; i < cow.size(); ++i) out[i] = (cow[i] & 1);
  return out;
}

}  // namespace ag2pc_test
#endif  // AG2PC_TEST_COMMON_H__
