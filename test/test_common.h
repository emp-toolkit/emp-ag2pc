#ifndef AG2PC_TEST_COMMON_H__
#define AG2PC_TEST_COMMON_H__
// Small, alias-neutral helpers shared by the AG2PC tests.
//
// IMPORTANT: this header is **mode-header-free** — it includes only emp-tool +
// net_setup, defines NO circuit-type alias set (`Bit`/`Integer`/...), and pulls
// in NO `emp-ag2pc/*` header. That lets it be shared by BOTH the public/direct
// tests (which include <emp-ag2pc/direct.h> for the AG2PCWire aliases) and the
// internal/expert tests (which include <emp-ag2pc/function.h> for the LambdaWire
// aliases) without an alias collision and without dragging either mode header
// into a file that uses engine internals. The helpers below are either plain value
// conversions or wire-generic templates (`Bit_T<Wire>`), so they work under any
// binding. (SecureWires-shaped helpers live with the internal tests that need them.)
#include "emp-tool/emp-tool.h"
#include "net_setup.h"
#include <cstdint>
#include <vector>

namespace ag2pc_test {

// Little-endian bit (de)composition for 32-bit test scalars.
inline std::vector<bool> bits_of(uint32_t v, int n = 32) {
  std::vector<bool> b(n);
  for (int i = 0; i < n; ++i) b[i] = (v >> i) & 1u;
  return b;
}
inline uint32_t u32_of(const std::vector<bool> &b) {
  uint32_t v = 0;
  for (size_t i = 0; i < b.size() && i < 32; ++i) if (b[i]) v |= (1u << i);
  return v;
}

// Fixed (arbitrary, deterministic) 128-bit AES key + plaintext, shared by every
// AES test so the same plaintext-oracle ciphertext applies everywhere.
inline void aes_test_bits(bool key_bits[128], bool pt_bits[128]) {
  for (int i = 0; i < 128; ++i) {
    key_bits[i] = ((i * 7 + 3) % 5) == 0;
    pt_bits[i]  = ((i * 3 + 1) % 4) == 0;
  }
}

// Plaintext AES-128 oracle: run emp-tool's AES_Calculator on the clear backend.
// Wire-generic (call with Wire=block); caller wraps it in setup_clear_backend("")
// / finalize_clear_backend().
template <typename Wire>
inline void aes_clear(const bool key_bits[128], const bool pt_bits[128], bool *ct_out) {
  using BW = emp::Bit_T<Wire>;
  BW key[128], pt[128], expanded[1408], ct[128];
  for (int i = 0; i < 128; ++i) key[i] = BW(key_bits[i], emp::PUBLIC);
  for (int i = 0; i < 128; ++i) pt[i]  = BW(pt_bits[i], emp::PUBLIC);
  emp::AES_Calculator_T<Wire> aes;
  aes.key_schedule(key, expanded);
  aes.encrypt(pt, expanded, ct);
  Wire buf[128];
  for (int i = 0; i < 128; ++i) buf[i] = ct[i].bit;
  emp::backend->reveal(ct_out, 1, buf, 128);
}

}  // namespace ag2pc_test
#endif  // AG2PC_TEST_COMMON_H__
