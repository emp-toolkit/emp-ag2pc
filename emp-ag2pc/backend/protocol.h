#ifndef EMP_AG2PC_PROTOCOL_H__
#define EMP_AG2PC_PROTOCOL_H__
#include "emp-ag2pc/backend/triple_pool.h"
#include "emp-ag2pc/backend/profiling.h"
#include "emp-tool/runtime/io/net_io_channel.h"
#include "emp-ag2pc/backend/secure_wires.h"
#include <string>
#include <vector>
using namespace emp;

namespace emp {
// A SecureWires bundle is "n wires" iff Lambda has n entries; wire_bundle must
// match, and exactly the local party's label array (label0 at the garbler P1,
// eval_label at the evaluator P2) must match. An externally-supplied bundle that
// violates this would read out of bounds during input load / decode, so check it
// at the boundary (always on; O(1)).
inline void check_secure_wires(const SecureWires &w, int party, const char *where) {
  const size_t n = w.Lambda.size();
  if (w.wire_bundle.size() != n)
    error((std::string("AG2PC ") + where + ": SecureWires wire_bundle length != Lambda length").c_str());
  if (party == 1) {
    if (w.label0.size() != n)
      error((std::string("AG2PC ") + where + ": garbler SecureWires label0 length != Lambda length").c_str());
  } else {
    if (w.eval_label.size() != n)
      error((std::string("AG2PC ") + where + ": evaluator SecureWires eval_label length != Lambda length").c_str());
  }
}
}  // namespace emp

// Two-party authenticated garbling protocol Π_MPC of agc.tex
// (Figures P:MPC-1, P:MPC-2, P:MPC-3) specialized to two parties. Role
// convention in this codebase: **party 1 is the garbler, party 2 is the
// evaluator** (note this is the inverse of agc.tex's Pi convention, where P1 is
// the evaluator and Pi (i ≥ 2) are garblers; agc.tex superscripts in formulas
// below have been renumbered to this codebase's convention).
//
// The half-gate construction: the garbler P1 sends 2 ciphertexts G_{γ,0/1}^1
// (no cross-peer S terms with a single garbler) plus b_γ; the evaluator P2
// recovers Λ_γ = b_γ ⊕ LSB1(m_{γ,Λ_γ}^1). The bit-1 Δ convention is set in
// TriplePool::init_abit_: bit1(Δ_1) = 1 and bit1(Δ_2) = 0, so
// bit1(Δ_1 ⊕ Δ_2) = 1. Bit 0 is reserved for share-value encoding.
//
// API:
//   process_inputs(owners, bits_per_owner) → SecureWires[]  // KRRW Fig.3 inputs
//   decode(wires, recipient)               → vector<uint8_t>  // step 14
//
// AG2PCProtocol owns input authentication, output decode, the long-lived
// COT/Delta session, and the half-gate primitives the engine builds on. It is
// the crypto core under AG2PCSession — protocol math only, no typed-value layer.

class AG2PCProtocol {
public:
  // Long-lived setup: TriplePool (COT mesh + Δ). Constructed once per session and
  // reused across all process_inputs / compute / decode calls; it holds the COT
  // session open across compute() calls and runs the COT consistency check before
  // each reveal (decode) so the check gates output release.
  std::unique_ptr<TriplePool> fpre;
  // io = primary channel (sequential comm); sib = a second channel spawned from
  // it, owned here. send_io/recv_io alias (io, sib) by party for the duplex
  // beaver pass; everything sequential uses io directly.
  NetIO *io;
  std::unique_ptr<NetIO> sib_owned;
  NetIO *sib, *send_io, *recv_io;
  ThreadPool *pool;
  int party;
  block Delta;
  PRG prg;

  // Number of batched input phases executed (one per process_inputs call) — the
  // observable that proves input batching (surfaced via AG2PCSession::process_input_calls()).
  int process_input_calls = 0;

  // Takes a single NetIO; spawns and owns the sibling channel. ssp is the
  // statistical security parameter forwarded to TriplePool (bucket sizing).
  AG2PCProtocol(NetIO *io, ThreadPool *pool_, int party_, int ssp = 40)
      : io(io), sib_owned(io->make_sibling()), sib(sib_owned.get()),
        send_io(party_ == ALICE ? io : sib_owned.get()),
        recv_io(party_ == ALICE ? sib_owned.get() : io),
        pool(pool_), party(party_) {
    fpre = std::make_unique<TriplePool>(io, sib_owned.get(), pool_, party_, ssp);
    Delta = fpre->Delta;
  }
  // TriplePool borrows io / sib_owned; release it here (dtor body runs before
  // the member destructors) so it is gone before those channels are torn down.
  ~AG2PCProtocol() { fpre.reset(); }

  // Garbler = party 1 (ALICE); evaluator = party 2 (BOB).
  bool is_garbler()   const { return party == ALICE; }
  bool is_evaluator() const { return party != ALICE; }

  // Flush the deferred subspace-VOLE / COT consistency check (end of a run).
  void flush_cot_check() { fpre->maybe_flush_cot_check(); }

  // KRRW Fig.3 input phase, batched across both owners' input wires in a
  // single protocol call. owners[k] is the owner for bits_per_owner[k]
  // (length K, typically 1 or 2); returns K SecureWires bundles, one per
  // owner. Internally:
  //   - fpre->draw mints all n_total authenticated λ-shares (one COT batch)
  //   - the garbler samples m_{w, 0} for every wire
  //   - authenticated share open: each party ships (its λ^self bits + Hash of
  //     the matching MACs) plus, in the same message, the x_w bits for the
  //     wires it owns. Sent in parallel on the duplex pair so the whole
  //     exchange is one one-way latency. Hashes are verified before Γ is used.
  //   - the garbler ships m_{w,Γ_w} = label0 ⊕ Γ_w·Δ for all wires (one-way).
  // Net: 2 message rounds (~1 RTT) for the whole input phase, regardless of
  // owner count.
  std::vector<SecureWires> process_inputs(
      const std::vector<int> &owners,
      const std::vector<std::vector<uint8_t>> &bits_per_owner);

  // Step 14 (output decode): all Pi ≠ recipient send λ_w^p to recipient;
  // recipient computes y_w = Λ_w ⊕ λ_w. Returns the n cleartext bits at
  // `recipient`; empty vector at non-recipients.
  std::vector<uint8_t> decode(const SecureWires &wires, int recipient);

  // Alias for decode(): opens the output wires to `recipient`.
  std::vector<uint8_t> reveal(const SecureWires &wires, int recipient) {
    return decode(wires, recipient);
  }

  // Build the SecureWires for public constant wires (no OT, no communication).
  // Exact party-local encoding: authenticated share = 0, Lambda = the public
  // bit, garbler (P1) label0 = bit ? Delta : zero_block, evaluator (P2) eval
  // label = zero_block. All parties MUST pass the same public bits.
  SecureWires public_wires(const std::vector<uint8_t> &bits) {
    int n = (int)bits.size();
    SecureWires sw;
    sw.Lambda.resize(n);
    sw.wire_bundle.assign(n, AShareBundle{});
    if (party == 1) sw.label0.resize(n);
    else            sw.eval_label.resize(n);
    for (int i = 0; i < n; ++i) {
      sw.Lambda[i] = bits[i] ? 1 : 0;
      if (party == 1) sw.label0[i] = bits[i] ? Delta : zero_block;
      else            sw.eval_label[i] = zero_block;
    }
    return sw;
  }
};

// ==========================================================================
// Implementation
// ==========================================================================

std::vector<SecureWires> AG2PCProtocol::process_inputs(
    const std::vector<int> &owners,
    const std::vector<std::vector<uint8_t>> &bits_per_owner) {
  AG2PC_PHASE_BEGIN();
  ++process_input_calls;
  // Validate the request before any communication: a count mismatch or an owner
  // that is neither ALICE nor BOB would desync the two parties (each side waits
  // for peer-owned bits nobody sends → hang). PUBLIC inputs do not go through the
  // OT input phase — build them with public_wires() instead.
  if (owners.size() != bits_per_owner.size())
    error("process_inputs: owners.size() != bits_per_owner.size()");
  for (int o : owners)
    if (o != ALICE && o != BOB)
      error("process_inputs: owner must be ALICE or BOB (use public_wires for PUBLIC)");
  const int K = (int)owners.size();
  int n_total = 0;
  std::vector<int> off_per_owner(K);
  for (int k = 0; k < K; ++k) {
    off_per_owner[k] = n_total;
    n_total += (int)bits_per_owner[k].size();
  }
  if (n_total == 0) {
    AG2PC_PHASE("process_inputs");
    return std::vector<SecureWires>(K);
  }

  // Combined bundle for every input wire across all owners.
  SecureWires sw;
  sw.Lambda.resize(n_total);
  sw.wire_bundle.resize(n_total);
  if (party == 1) sw.label0.resize(n_total);          // garbler
  else            sw.eval_label.resize(n_total);      // evaluator

  // Step 3 (Π_aShare): n_total authenticated λ-shares from the open COT
  // session. One draw covers both owners.
  fpre->draw(n_total, sw.wire_bundle);

  // Step 3 (cont.): the garbler samples m_{w,0} for every wire.
  if (party == 1) prg.random_block(sw.label0.data(), n_total);

  // Per-wire metadata: which owner, and the x_w bit for wires this party owns
  // (zero for wires this party doesn't own — those x's are folded in by the
  // peer in their own message below).
  std::vector<int> owner_of_wire(n_total);
  std::vector<unsigned char> own_x_bits(n_total, 0);
  for (int k = 0; k < K; ++k) {
    int o = owners[k];
    bool i_own = (o == party);
    for (size_t i = 0; i < bits_per_owner[k].size(); ++i) {
      int idx = off_per_owner[k] + (int)i;
      owner_of_wire[idx] = o;
      if (i_own) own_x_bits[idx] = (unsigned char)bits_per_owner[k][i];
    }
  }

  // KRRW Fig.3 authenticated share open + (folded into the same message) the
  // owner's x_w bits, both directions in parallel on the duplex pair.
  //
  // Each party ships:
  //   (a) λ^self bits for ALL wires (n_total bytes) — the raw share open
  //   (b) Hash of the matching MACs (DIGEST_SIZE bytes) — authenticates (a);
  //       peer recomputes expected MAC = K_peer ⊕ bit · Δ_peer from its own
  //       wire_bundle.key + Delta, hashes those, compares — abort on mismatch.
  //   (c) own_x_bits packed for wires this party owns (n_owned bytes) — the
  //       unauthenticated owner contribution Γ_w := x_w ⊕ λ_w gets folded in
  //       by the recipient using (a) + own λ^self below. Γ_w itself is bound
  //       downstream by the c_γ check that runs at chunk end.
  std::vector<unsigned char> share_msg(n_total);
  BlockVec my_macs(n_total);
  for (int i = 0; i < n_total; ++i) {
    share_msg[i] = (unsigned char)LSB(sw.wire_bundle[i].mac);
    my_macs[i]   = sw.wire_bundle[i].mac;
  }
  char D_me[Hash::DIGEST_SIZE];
  Hash::hash_once(D_me, my_macs.data(), (size_t)n_total * sizeof(block));

  std::vector<unsigned char> own_x_packed;
  std::vector<int> peer_idx_list;             // wire indices peer owns
  for (int i = 0; i < n_total; ++i) {
    if (owner_of_wire[i] == party) own_x_packed.push_back(own_x_bits[i]);
    else                            peer_idx_list.push_back(i);
  }

  std::vector<unsigned char> peer_share(n_total);
  char D_peer[Hash::DIGEST_SIZE];
  std::vector<unsigned char> peer_x_packed(peer_idx_list.size());
  {
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([&]() {
      send_io->send_data(share_msg.data(), n_total);
      send_io->send_data(D_me, Hash::DIGEST_SIZE);
      if (!own_x_packed.empty())
        send_io->send_data(own_x_packed.data(), own_x_packed.size());
      send_io->flush();
    }));
    res.push_back(pool->enqueue([&]() {
      recv_io->recv_data(peer_share.data(), n_total);
      recv_io->recv_data(D_peer, Hash::DIGEST_SIZE);
      if (!peer_x_packed.empty())
        recv_io->recv_data(peer_x_packed.data(), peer_x_packed.size());
    }));
    joinNclean(res);
  }

  // Verify peer's MAC hash before using their share.
  BlockVec exp_macs(n_total);
  for (int i = 0; i < n_total; ++i)
    exp_macs[i] = sw.wire_bundle[i].key ^ (select_mask[peer_share[i]] & Delta);
  char D_exp[Hash::DIGEST_SIZE];
  Hash::hash_once(D_exp, exp_macs.data(), (size_t)n_total * sizeof(block));
  if (memcmp(D_exp, D_peer, Hash::DIGEST_SIZE) != 0)
    error("process_inputs: peer share-MAC hash mismatch");

  // Reconstruct Γ_w = λ_w ⊕ x_w = (λ^self ⊕ λ^peer) ⊕ x_w for every wire.
  // own_x_bits is 0 for peer-owned, so this folds in my own x only.
  for (int i = 0; i < n_total; ++i)
    sw.Lambda[i] = (unsigned char)(share_msg[i] ^ peer_share[i] ^ own_x_bits[i]);
  // Add peer's x bits for the wires they own.
  for (size_t i = 0; i < peer_idx_list.size(); ++i)
    sw.Lambda[peer_idx_list[i]] ^= peer_x_packed[i];

  // Garbler ships m_{w,Γ_w} for every input wire.
  if (party == 1) {
    BlockVec labels(n_total);
    for (int i = 0; i < n_total; ++i)
      labels[i] = sw.label0[i] ^ (select_mask[sw.Lambda[i]] & Delta);
    io->send_data(labels.data(), (size_t)n_total * sizeof(block));
    io->flush();
  } else {
    io->recv_data(sw.eval_label.data(), (size_t)n_total * sizeof(block));
  }
  AG2PC_PHASE("process_inputs");

  // Slice the combined bundle back into per-owner SecureWires.
  std::vector<SecureWires> result(K);
  for (int k = 0; k < K; ++k) {
    int off = off_per_owner[k];
    int n = (int)bits_per_owner[k].size();
    result[k] = sw.slice((size_t)off, (size_t)(off + n));
  }
  return result;
}

std::vector<uint8_t> AG2PCProtocol::decode(const SecureWires &wires,
                                        int recipient) {
  check_secure_wires(wires, party, "decode");   // reject malformed bundles before OOB access
  int n = (int)wires.size();
  AG2PC_PHASE_BEGIN();
  // Reveal to ALL parties: reconstruct at the evaluator (P2), then P2 broadcasts.
  // Needed for reactive host branching — every party must learn the same value.
  if (recipient == PUBLIC) {
    std::vector<uint8_t> v = decode(wires, 2);  // only P2 holds it after this
    std::vector<unsigned char> buf(n);
    if (party != 1) {
      for (int i = 0; i < n; ++i) buf[i] = v[i];
      io->send_data(buf.data(), n);
      io->flush();
      return v;
    }
    io->recv_data(buf.data(), n);
    std::vector<uint8_t> out(n);
    for (int i = 0; i < n; ++i) out[i] = (buf[i] & 1);
    return out;
  }
  std::vector<uint8_t> result;
  // Authenticated open of each party's λ-share to the recipient (KRRW Fig.3
  // open). The non-recipient ships (n share bits, Hash(n MACs)); the recipient
  // recomputes the expected MAC for each bit as KEY ⊕ bit·Δ — using its own
  // wire_bundle[i].key plus Delta — hashes those, and compares the digest to
  // the one shipped. A flipped bit forces a flipped MAC (by Δ_peer, which the
  // sender doesn't know), so the digest mismatch aborts here before the secret
  // is consumed. The chunk-level c_γ and COT-correlation checks (run in the
  // engine) gate this in turn: any tampered MAC structure has aborted
  // already, so the only thing the per-reveal hash needs to catch is a sender
  // flipping a bit at decode-time.
  std::vector<unsigned char> my_share(n);
  BlockVec my_macs(n);
  for (int i = 0; i < n; ++i) {
    my_share[i] = (unsigned char)LSB(wires.wire_bundle[i].mac);
    my_macs[i]  = wires.wire_bundle[i].mac;
  }
  if (party != recipient) {
    char D[Hash::DIGEST_SIZE];
    Hash::hash_once(D, my_macs.data(), (size_t)n * sizeof(block));
    io->send_data(my_share.data(), n);
    io->send_data(D, Hash::DIGEST_SIZE);
    io->flush();
  } else {
    result.resize(n);
    std::vector<unsigned char> tmp(n);
    char D_peer[Hash::DIGEST_SIZE];
    io->recv_data(tmp.data(), n);
    io->recv_data(D_peer, Hash::DIGEST_SIZE);
    BlockVec exp_macs(n);
    for (int i = 0; i < n; ++i)
      exp_macs[i] = wires.wire_bundle[i].key ^ (select_mask[tmp[i]] & Delta);
    char D_exp[Hash::DIGEST_SIZE];
    Hash::hash_once(D_exp, exp_macs.data(), (size_t)n * sizeof(block));
    if (memcmp(D_exp, D_peer, Hash::DIGEST_SIZE) != 0)
      error("decode: peer share-MAC hash mismatch");
    for (int i = 0; i < n; ++i) {
      unsigned char v = my_share[i] ^ wires.Lambda[i] ^ tmp[i];
      result[i] = (v & 1);
    }
  }
  AG2PC_PHASE("decode[step14]");
  return result;
}

#endif // EMP_AG2PC_PROTOCOL_H__
