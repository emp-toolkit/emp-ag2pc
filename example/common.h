#ifndef EMP_AG2PC_EXAMPLE_COMMON_H__
#define EMP_AG2PC_EXAMPLE_COMMON_H__

#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-tool/ir/context/context.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

namespace ag2pc_example {

inline bool is_alice(int party) {
  return party == emp::ALICE;
}

template <size_t N>
std::array<bool, N> bits_from_u64(uint64_t v) {
  static_assert(N <= 64);
  std::array<bool, N> bits{};
  for (int i = 0; i < N; ++i) bits[(size_t)i] = ((v >> i) & 1) != 0;
  return bits;
}

template <size_t N>
uint64_t u64_from_bits(const std::array<bool, N>& bits) {
  static_assert(N <= 64);
  uint64_t v = 0;
  for (int i = 0; i < N; ++i)
    if (bits[(size_t)i]) v |= uint64_t(1) << i;
  return v;
}

inline std::vector<uint8_t> clear_eval(const emp::circuit::BooleanProgram& program,
                                    const std::vector<uint8_t>& input) {
  emp::ClearCtx clear;
  std::vector<uint8_t> in(input.size());
  for (size_t i = 0; i < input.size(); ++i) in[i] = input[i] ? 1 : 0;
  std::vector<uint8_t> out =
      emp::execute_program(clear, program, std::span<const uint8_t>(in.data(), in.size()));
  std::vector<uint8_t> result(out.size());
  for (size_t i = 0; i < out.size(); ++i) result[i] = (out[i] & 1) != 0;
  return result;
}

}  // namespace ag2pc_example

#endif  // EMP_AG2PC_EXAMPLE_COMMON_H__
