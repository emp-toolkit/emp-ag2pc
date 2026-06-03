#ifndef AG2PC_TEST_COMMON_H__
#define AG2PC_TEST_COMMON_H__
// Small, binding-neutral helpers shared by the AG2PC tests. Deliberately does
// NOT install any circuit-type aliases (no EMP_USE_CIRCUIT_TYPES_ALL / *_circuit
// _types.h) so each test TU can pick its own wire binding (block / LambdaWire /
// AG2PCWire); the helpers here are either plain value conversions or wire-generic
// templates (Bit_T<Wire>), so they work under any binding.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"   // SecureWires, C2PC, LambdaRunner
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

// Concatenate per-owner SecureWires bundles into one flat bundle, preserving
// order. Role-correct: garbler P1 carries label0, evaluator P2 carries
// eval_label; Lambda + wire_bundle always carry. Used to feed a multi-argument
// circuit whose engine binds inputs to wire ids [0, total) positionally.
inline emp::SecureWires concat(const std::vector<emp::SecureWires> &in, int party) {
  emp::SecureWires w;
  for (const auto &s : in) {
    w.Lambda.insert(w.Lambda.end(), s.Lambda.begin(), s.Lambda.end());
    w.wire_bundle.insert(w.wire_bundle.end(), s.wire_bundle.begin(), s.wire_bundle.end());
    if (party == 1) w.label0.insert(w.label0.end(), s.label0.begin(), s.label0.end());
    else            w.eval_label.insert(w.eval_label.end(), s.eval_label.begin(), s.eval_label.end());
  }
  return w;
}

// Fixed (arbitrary, deterministic) 128-bit AES key + plaintext, shared by every
// AES test so the same plaintext oracle ciphertext applies everywhere.
inline void aes_test_bits(bool key_bits[128], bool pt_bits[128]) {
  for (int i = 0; i < 128; ++i) {
    key_bits[i] = ((i * 7 + 3) % 5) == 0;
    pt_bits[i]  = ((i * 3 + 1) % 4) == 0;
  }
}

// Plaintext AES-128 oracle: run emp-tool's AES_Calculator on the clear backend.
// Wire-generic (call with Wire=block); the caller wraps it in
// setup_clear_backend("") / finalize_clear_backend().
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
