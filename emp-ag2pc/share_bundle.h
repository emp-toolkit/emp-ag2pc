#ifndef SHARE_BUNDLE_H__
#define SHARE_BUNDLE_H__
#include "emp-tool/core/block.h"
#include <vector>

namespace emp {

// AoS-by-wire packing of authenticated-share state for one wire.
// Layout (slot k indexes peers in increasing party-id order, skipping `self`):
//   km[2*k]     = mac for the k-th peer
//   km[2*k + 1] = key for the k-th peer
// Bundle size = 2*(nP-1) blocks. At nP=3 this is 64B = 1 cache line; at nP=2
// it is 32B (half a line). The flat block layout lets per-slot loops compile
// into linear SSE/AVX XOR sequences.
template <int nP> struct AShareBundle {
  static constexpr int K = nP - 1;
  static constexpr int N = 2 * (nP - 1);
  block km[N];

  block &mac(int slot) { return km[2 * slot]; }
  block &key(int slot) { return km[2 * slot + 1]; }
  const block &mac(int slot) const { return km[2 * slot]; }
  const block &key(int slot) const { return km[2 * slot + 1]; }
};

// Map peer party-id (1-based) to a slot index in [0, nP-1) within a bundle
// owned by `self`. Caller must ensure peer != self.
inline int peer_slot(int self, int peer) {
  return (peer < self) ? (peer - 1) : (peer - 2);
}

// Skip zero/value-init for trivial bundles in resize / vector(N), matching
// the BlockVec convention.
template <int nP>
using AShareBundleVec =
    std::vector<AShareBundle<nP>, default_init_allocator<AShareBundle<nP>>>;

// AoS-by-triple packing: three AShareBundles back-to-back, one per share-slot
// of an AND triple. At nP=3 this is 3 * 64 = 192B = 3 cache lines, laid out
// contiguously per triple so a consumer reading slot 2 / 1 / 0 of the same
// triple walks sequential memory (good for HW prefetch).
template <int nP> struct TripleBundle {
  AShareBundle<nP> b[3];
};

template <int nP>
using TripleBundleVec =
    std::vector<TripleBundle<nP>, default_init_allocator<TripleBundle<nP>>>;

}  // namespace emp
#endif // SHARE_BUNDLE_H__
