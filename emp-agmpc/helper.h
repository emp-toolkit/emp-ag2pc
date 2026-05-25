#ifndef __HELPER
#define __HELPER
#include "emp-agmpc/netmp.h"
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

// Echo broadcast with deferred finalize. Each all_bcast does an insecure
// pairwise send (one round) and folds the received view into a rolling
// transcript hash in canonical order. finalize() exchanges transcript
// digests pairwise and aborts on any mismatch — one round suffices because
// honest parties compare received digests against their own. Any logical
// broadcast routed through all_bcast is protected against equivocation.
template <int nP>
class EchoBC {
public:
  Hash h;
  NetIOMP<nP> *io;
  ThreadPool *pool;
  int party;

  EchoBC(NetIOMP<nP> *io_in, ThreadPool *pool_in, int party_in)
      : io(io_in), pool(pool_in), party(party_in) {}

  // Broadcast `len` elements of type T per party. view[p] must point to a
  // buffer of at least `len` T's for every p; view[party] is populated from
  // my_v, and view[p] for p != party is filled from the wire. The full
  // view (nP * len * sizeof(T) bytes) is folded into the transcript hash
  // in party-index order.
  template <typename T>
  void all_bcast(const T *my_v, int len, T *view[nP + 1]) {
    memcpy(view[party], my_v, sizeof(T) * len);
    int bytes = (int)(sizeof(T) * len);
    vector<future<void>> res;
    for (int i = 1; i <= nP; ++i) for (int j = 1; j <= nP; ++j)
      if ((i < j) and (i == party or j == party)) {
        int p2 = i + j - party;
        res.push_back(pool->enqueue([this, my_v, bytes, p2]() {
          io->send_data(p2, my_v, bytes);
          io->flush(p2);
        }));
        res.push_back(pool->enqueue([this, &view, bytes, p2]() {
          io->recv_data(p2, view[p2], bytes);
        }));
      }
    joinNclean(res);
    for (int p = 1; p <= nP; ++p) h.put(view[p], bytes);
  }

  // Single-element convenience overload: view is a flat [nP+1] stack array.
  template <typename T>
  void all_bcast(const T &my_v, T view[nP + 1]) {
    T *ptrs[nP + 1];
    for (int p = 1; p <= nP; ++p) ptrs[p] = &view[p];
    all_bcast(&my_v, 1, ptrs);
  }

  void finalize() {
    char d_me[Hash::DIGEST_SIZE];
    h.digest(d_me);
    char recv[nP + 1][Hash::DIGEST_SIZE];
    vector<future<void>> res;
    for (int i = 1; i <= nP; ++i) for (int j = 1; j <= nP; ++j)
      if ((i < j) and (i == party or j == party)) {
        int p2 = i + j - party;
        res.push_back(pool->enqueue([this, &d_me, p2]() {
          io->send_data(p2, d_me, Hash::DIGEST_SIZE);
          io->flush(p2);
        }));
        res.push_back(pool->enqueue([this, &recv, p2]() {
          io->recv_data(p2, recv[p2], Hash::DIGEST_SIZE);
        }));
      }
    joinNclean(res);
    for (int p = 1; p <= nP; ++p) if (p != party)
      if (strncmp(d_me, recv[p], Hash::DIGEST_SIZE) != 0)
        error("EchoBC finalize: transcript divergence\n");
  }
};

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

template <int nP>
block sampleRandom(NetIOMP<nP> *io, PRG *prg, ThreadPool *pool, int party) {
  vector<future<void>> res;
  vector<future<bool>> res2;
  char(*dgst)[Hash::DIGEST_SIZE] = new char[nP + 1][Hash::DIGEST_SIZE];
  block *S = new block[nP + 1];
  prg->random_block(&S[party], 1);
  Hash::hash_once(dgst[party], &S[party], sizeof(block));

  for (int i = 1; i <= nP; ++i)
    for (int j = 1; j <= nP; ++j)
      if ((i < j) and (i == party or j == party)) {
        int party2 = i + j - party;
        res.push_back(pool->enqueue([dgst, io, party, party2]() {
          io->send_data(party2, dgst[party], Hash::DIGEST_SIZE);
          io->flush(party2);
          io->recv_data(party2, dgst[party2], Hash::DIGEST_SIZE);
        }));
      }
  joinNclean(res);
  for (int i = 1; i <= nP; ++i)
    for (int j = 1; j <= nP; ++j)
      if ((i < j) and (i == party or j == party)) {
        int party2 = i + j - party;
        res2.push_back(pool->enqueue([io, S, dgst, party, party2]() -> bool {
          io->send_data(party2, &S[party], sizeof(block));
          io->flush(party2);
          io->recv_data(party2, &S[party2], sizeof(block));
          char tmp[Hash::DIGEST_SIZE];
          Hash::hash_once(tmp, &S[party2], sizeof(block));
          return strncmp(tmp, dgst[party2], Hash::DIGEST_SIZE) != 0;
        }));
      }
  bool cheat = joinNcleanCheat(res2);
  if (cheat) {
    cout << "cheat in sampleRandom\n" << flush;
    exit(0);
  }
  for (int i = 2; i <= nP; ++i)
    S[1] = S[1] ^ S[i];
  block result = S[1];
  delete[] S;
  delete[] dgst;
  return result;
}

// Π_FZero: shared-zero block-vector via pairwise seed-and-expand under
// the ICM assumption on the AES-based PRG. Each peer-pair shares a
// λ-bit seed (the larger-indexed party samples and sends to the
// smaller); both expand the seed via PRG into n blocks and XOR into
// `out`. Each seed contributes to exactly two parties so Σ_p out^p[k]
// = 0 for every k. Communication: λ bits per pair (vs nP·λ for the
// straightforward zero-share). Caller is responsible for zero-init —
// the contributions are XORed in so this composes with caller buffers
// that already have content (e.g. TriplePool loads z directly into phi).
template <int nP>
void fzero_xor(NetIOMP<nP> *io, PRG *prg, ThreadPool *pool, int party,
               block *out, int n) {
  block seed_by_peer[nP + 1];
  prg->random_block(&seed_by_peer[1], nP);

  vector<future<void>> res;
  for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
    res.push_back(pool->enqueue([io, &seed_by_peer, peer, party]() {
      if (peer < party) {
        io->send_data(peer, &seed_by_peer[peer], sizeof(block));
        io->flush(peer);
      } else {
        io->recv_data(peer, &seed_by_peer[peer], sizeof(block));
      }
    }));
  }
  joinNclean(res);

  BlockVec contribution(n);
  for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
    PRG expand(&seed_by_peer[peer]);
    expand.random_block(contribution.data(), n);
    xorBlocks_arr(out, out, contribution.data(), n);
  }
}

template <int nP>
void check_MAC(NetIOMP<nP> *io, block *MAC[nP + 1], block *KEY[nP + 1], bool *r,
               block Delta, int length, int party) {
  block *tmp = new block[length];
  block tD;
  for (int i = 1; i <= nP; ++i)
    for (int j = 1; j <= nP; ++j)
      if (i < j) {
        if (party == i) {
          io->send_data(j, &Delta, sizeof(block));
          io->send_data(j, KEY[j], sizeof(block) * length);
          io->flush(j);
        } else if (party == j) {
          io->recv_data(i, &tD, sizeof(block));
          io->recv_data(i, tmp, sizeof(block) * length);
          for (int k = 0; k < length; ++k) {
            if (r[k])
              tmp[k] = tmp[k] ^ tD;
          }
          if (!cmpBlock(MAC[i], tmp, length))
            error("check_MAC failed!");
        }
      }
  delete[] tmp;
  if (party == 1)
    cerr << "check_MAC pass!\n" << flush;
}

template <int nP>
void check_MAC(NetIOMP<nP> *io, BlockVec MAC[nP + 1],
               BlockVec KEY[nP + 1], std::vector<unsigned char> &r, block Delta,
               int length, int party) {
  block *MAC_p[nP + 1], *KEY_p[nP + 1];
  for (int i = 1; i <= nP; ++i) if (i != party) {
    MAC_p[i] = MAC[i].data();
    KEY_p[i] = KEY[i].data();
  }
  check_MAC<nP>(io, MAC_p, KEY_p, (bool *)r.data(), Delta, length, party);
}

// r-less overload: derive share bits from bit0(MAC[any peer]). Valid when
// the pool invariant holds (bit0(K)=0, bit0(Δ)=1 ⇒ bit0(M) = x consistently
// across peers).
template <int nP>
void check_MAC(NetIOMP<nP> *io, BlockVec MAC[nP + 1],
               BlockVec KEY[nP + 1], block Delta, int length, int party) {
  int any_peer = (party == 1) ? 2 : 1;
  std::vector<unsigned char> r(length);
  for (int k = 0; k < length; ++k)
    r[k] = (unsigned char)LSB(MAC[any_peer][k]);
  check_MAC<nP>(io, MAC, KEY, r, Delta, length, party);
}

template <int nP>
void check_correctness(NetIOMP<nP> *io, bool *r, int length, int party) {
  if (party == 1) {
    bool *tmp1 = new bool[length * 3];
    bool *tmp2 = new bool[length * 3];
    memcpy(tmp1, r, length * 3);
    for (int i = 2; i <= nP; ++i) {
      io->recv_data(i, tmp2, length * 3);
      for (int k = 0; k < length * 3; ++k)
        tmp1[k] = (tmp1[k] != tmp2[k]);
    }
    for (int k = 0; k < length; ++k) {
      if ((tmp1[k] and tmp1[length + k]) != tmp1[2 * length + k])
        error("check_correctness failed!");
    }
    delete[] tmp1;
    delete[] tmp2;
    cerr << "check_correctness pass!\n" << flush;
  } else {
    io->send_data(1, r, length * 3);
    io->flush(1);
  }
}

template <int nP>
void check_correctness(NetIOMP<nP> *io, vector<unsigned char> &r, int length, int party) {
  check_correctness<nP>(io, (bool *)r.data(), length, party);
}

// r-less overload for AND-triple buffers: MAC[*] is sized 3*length (slot-major
// a/b/c), so r[k] = bit0(MAC[any peer][k]) reconstructs the full 3*length
// share vector before delegating to the bool* form.
template <int nP>
void check_correctness(NetIOMP<nP> *io, BlockVec MAC[nP + 1], int length, int party) {
  int any_peer = (party == 1) ? 2 : 1;
  std::vector<unsigned char> r(3 * length);
  for (int k = 0; k < 3 * length; ++k)
    r[k] = (unsigned char)LSB(MAC[any_peer][k]);
  check_correctness<nP>(io, (bool *)r.data(), length, party);
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
