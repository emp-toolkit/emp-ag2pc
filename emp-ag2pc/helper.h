#ifndef __HELPER
#define __HELPER
#include "emp-tool/io/net_io_channel.h"
#include "emp-tool/crypto/ro.h"
#include <future>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>
using namespace emp;
using std::cerr;
using std::cout;
using std::endl;
using std::flush;
using std::future;
using std::max;

// default_init_allocator + BlockVec live in emp-tool/core/block_vector.h
// (re-included here via the project's emp-tool dependency).

// Single-bit masks at positions 0 and 1. Used by protocols that pin the
// low bits of the global key Δ (e.g. WRK-style aShare encoding pins bit 0
// of K, half-gate Λ_γ recovery pins bit 1 of ⊕_p Δ_p).
inline constexpr block bit0_mask = makeBlock(0, 1);
inline constexpr block bit1_mask = makeBlock(0, 2);

// Two-party transport: parties {1, 2} hold a duplex pair of NetIO channels to
// the single peer. io1 carries the 1->2 direction, io2 the 2->1 direction
// (so party 1 sends on io1 / recvs on io2, party 2 the mirror); the OT layer
// uses both channels by index. These free routers replace the old NetIOMP
// object -- callers pass io1/io2/party directly. The dst/src == party guard
// is kept so the (formerly no-op) self-addressed calls stay no-ops.
inline void io_send(NetIO *io1, NetIO *io2, int party, int dst,
                    const void *data, size_t len) {
  if (dst != 0 && dst != party) (party < dst ? io1 : io2)->send_data(data, len);
}
inline void io_recv(NetIO *io1, NetIO *io2, int party, int src,
                    void *data, size_t len) {
  if (src != 0 && src != party) (src < party ? io1 : io2)->recv_data(data, len);
}
inline void io_flush(NetIO *io1, NetIO *io2, int party, int idx) {
  if (idx == 0) { io1->flush(); io2->flush(); }
  else if (idx != party) (party < idx ? io1 : io2)->flush();
}
inline int64_t io_count(NetIO *io1, NetIO *io2) {
  return io1->send_counter + io1->recv_counter +
         io2->send_counter + io2->recv_counter;
}


#ifdef EMP_DEBUG_PHASE
// Phase timer with a single static clock, shared across the protocol stack.
// Empty name silently resets (use it after an internal debugging check to
// drop that interval from the next phase's measurement). Non-empty name
// prints elapsed-since-last-call and resets. Prints only from party 1.
inline void _phase(const char *name, int party) {
  static auto _pt = clock_start();
  if (name && name[0] && party == 1)
    cerr << "  " << name << ": " << time_from(_pt) << " us" << endl;
  _pt = clock_start();
}
#endif

template <typename T> void joinNclean(vector<future<T>> &res) {
  for (auto &v : res)
    v.get();
  res.clear();
}

bool joinNcleanCheat(vector<future<bool>> &res) {
  bool cheat = false;
  for (auto &v : res)
    cheat = cheat or v.get();
  res.clear();
  return cheat;
}


template <int B>
void send_partial_block(NetIO *io, const block *data, int length) {
  for (int i = 0; i < length; ++i) {
    io->send_data(&(data[i]), B);
  }
}

template <int B> void recv_partial_block(NetIO *io, block *data, int length) {
  for (int i = 0; i < length; ++i) {
    io->recv_data(&(data[i]), B);
  }
}

inline uint8_t LSB(const block &b) { return _mm_extract_epi8(b, 0) & 0x1; }
// Bit 1 (second-lowest) of a block. Reserved for the half-gate Λ_γ recovery
// invariant LSB1(⊕_p Δ_p) = 1; bit 0 is reserved for share-value encoding
// (see share_bundle.h).
inline uint8_t LSB1(const block &b) { return (_mm_extract_epi8(b, 0) >> 1) & 0x1; }

// Π_FZero: shared-zero block-vector via pairwise seed-and-expand under
// the ICM assumption on the AES-based PRG. Each peer-pair shares a
// λ-bit seed (the larger-indexed party samples and sends to the
// smaller); both expand the seed via PRG into n blocks and XOR into
// `out`. Each seed contributes to exactly two parties so Σ_p out^p[k]
// = 0 for every k. Communication: λ bits for the single pair. Caller is
// responsible for zero-init — the contributions are XORed in so this composes
// with caller buffers that already have content (e.g. TriplePool loads z
// directly into phi).
void fzero_xor(NetIO *io1, NetIO *io2, PRG *prg, ThreadPool *pool, int party,
               block *out, int n) {
  block seed_by_peer[3];
  prg->random_block(&seed_by_peer[1], 2);

  // Single pair: the larger-indexed party samples + sends the shared seed,
  // the smaller receives it (only one direction happens per party).
  const int peer = 3 - party;
  if (peer < party) {
    io_send(io1, io2, party, peer, &seed_by_peer[peer], sizeof(block));
    io_flush(io1, io2, party, peer);
  } else {
    io_recv(io1, io2, party, peer, &seed_by_peer[peer], sizeof(block));
  }

  BlockVec contribution(n);
  PRG expand(&seed_by_peer[peer]);
  expand.random_block(contribution.data(), n);
  xorBlocks_arr(out, out, contribution.data(), n);
}

void check_MAC(NetIO *io1, NetIO *io2, block *MAC, block *KEY, bool *r,
               block Delta, int length, int party) {
  block *tmp = new block[length];
  block tD;
  // Single pair (1, 2): party 1 sends Δ + its KEY for the peer, party 2 verifies.
  if (party == 1) {
    io_send(io1, io2, party, 2, &Delta, sizeof(block));
    io_send(io1, io2, party, 2, KEY, sizeof(block) * length);
    io_flush(io1, io2, party, 2);
  } else {
    io_recv(io1, io2, party, 1, &tD, sizeof(block));
    io_recv(io1, io2, party, 1, tmp, sizeof(block) * length);
    for (int k = 0; k < length; ++k)
      if (r[k]) tmp[k] = tmp[k] ^ tD;
    if (!cmpBlock(MAC, tmp, length))
      error("check_MAC failed!");
  }
  delete[] tmp;
  if (party == 1)
    cerr << "check_MAC pass!\n" << flush;
}

void check_MAC(NetIO *io1, NetIO *io2, BlockVec &MAC,
               BlockVec &KEY, std::vector<unsigned char> &r, block Delta,
               int length, int party) {
  check_MAC(io1, io2, MAC.data(), KEY.data(), (bool *)r.data(), Delta,
                length, party);
}

// r-less overload: derive share bits from bit0(MAC[any peer]). Valid when
// the pool invariant holds (bit0(K)=0, bit0(Δ)=1 ⇒ bit0(M) = x consistently
// across peers).
void check_MAC(NetIO *io1, NetIO *io2, BlockVec &MAC,
               BlockVec &KEY, block Delta, int length, int party) {
  std::vector<unsigned char> r(length);
  for (int k = 0; k < length; ++k)
    r[k] = (unsigned char)LSB(MAC[k]);
  check_MAC(io1, io2, MAC, KEY, r, Delta, length, party);
}

void check_correctness(NetIO *io1, NetIO *io2, bool *r, int length, int party) {
  if (party == 1) {
    bool *tmp1 = new bool[length * 3];
    bool *tmp2 = new bool[length * 3];
    memcpy(tmp1, r, length * 3);
    io_recv(io1, io2, party, 2, tmp2, length * 3);
    for (int k = 0; k < length * 3; ++k)
      tmp1[k] = (tmp1[k] != tmp2[k]);
    for (int k = 0; k < length; ++k) {
      if ((tmp1[k] and tmp1[length + k]) != tmp1[2 * length + k])
        error("check_correctness failed!");
    }
    delete[] tmp1;
    delete[] tmp2;
    cerr << "check_correctness pass!\n" << flush;
  } else {
    io_send(io1, io2, party, 1, r, length * 3);
    io_flush(io1, io2, party, 1);
  }
}

void check_correctness(NetIO *io1, NetIO *io2, vector<unsigned char> &r, int length, int party) {
  check_correctness(io1, io2, (bool *)r.data(), length, party);
}

// r-less overload for AND-triple buffers: MAC[*] is sized 3*length (slot-major
// a/b/c), so r[k] = bit0(MAC[k]) reconstructs the full 3*length
// share vector before delegating to the bool* form.
void check_correctness(NetIO *io1, NetIO *io2, BlockVec &MAC, int length, int party) {
  std::vector<unsigned char> r(3 * length);
  for (int k = 0; k < 3 * length; ++k)
    r[k] = (unsigned char)LSB(MAC[k]);
  check_correctness(io1, io2, (bool *)r.data(), length, party);
}

inline const char *hex_char_to_bin(char c) {
  switch (toupper(c)) {
  case '0':
    return "0000";
  case '1':
    return "0001";
  case '2':
    return "0010";
  case '3':
    return "0011";
  case '4':
    return "0100";
  case '5':
    return "0101";
  case '6':
    return "0110";
  case '7':
    return "0111";
  case '8':
    return "1000";
  case '9':
    return "1001";
  case 'A':
    return "1010";
  case 'B':
    return "1011";
  case 'C':
    return "1100";
  case 'D':
    return "1101";
  case 'E':
    return "1110";
  case 'F':
    return "1111";
  default:
    return "0";
  }
}

inline std::string hex_to_binary(std::string hex) {
  std::string bin;
  for (unsigned i = 0; i != hex.length(); ++i)
    bin += hex_char_to_bin(hex[i]);
  return bin;
}

#endif // __HELPER
