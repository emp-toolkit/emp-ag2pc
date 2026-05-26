#ifndef SHARE_BUNDLE_H__
#define SHARE_BUNDLE_H__
#include "emp-tool/core/block.h"
#include <vector>

namespace emp {

// AoS-by-wire packing of authenticated-share state for one wire.
// Layout (slot k indexes peers in increasing party-id order, skipping `self`):
//   km[2*k]     = mac for the k-th peer
//   km[2*k + 1] = key for the k-th peer
// With a single peer there is one slot: K = 1, N = 2 blocks (32B, half a
// cache line). The flat block layout lets per-slot loops compile into linear
// SSE/AVX XOR sequences.
struct AShareBundle {
  static constexpr int K = 1;
  static constexpr int N = 2;
  block km[N];

  block &mac(int slot) { return km[2 * slot]; }
  block &key(int slot) { return km[2 * slot + 1]; }
  const block &mac(int slot) const { return km[2 * slot]; }
  const block &key(int slot) const { return km[2 * slot + 1]; }
};

// Map peer party-id (1-based) to a slot index in [0, 1) within a bundle owned
// by `self`. Caller must ensure peer != self. With a single peer this is
// always 0.
inline int peer_slot(int self, int peer) {
  return (peer < self) ? (peer - 1) : (peer - 2);
}

// Skip zero/value-init for trivial bundles in resize / vector(N), matching
// the BlockVec convention.
using AShareBundleVec =
    std::vector<AShareBundle, default_init_allocator<AShareBundle>>;

// AoS-by-triple packing: three AShareBundles back-to-back, one per share-slot
// of an AND triple, laid out contiguously per triple so a consumer reading
// slot 2 / 1 / 0 of the same triple walks sequential memory (good for HW
// prefetch).
struct TripleBundle {
  AShareBundle b[3];
};

using TripleBundleVec =
    std::vector<TripleBundle, default_init_allocator<TripleBundle>>;

}  // namespace emp
#endif // SHARE_BUNDLE_H__
