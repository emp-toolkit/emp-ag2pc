#ifndef __HELPER
#define __HELPER
#include "emp-tool/runtime/io/net_io_channel.h"
#include "emp-tool/runtime/crypto/ro.h"
#include "emp-tool/runtime/crypto/prg.h"
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>
using namespace emp;
using std::future;

// default_init_allocator + BlockVec live in emp-tool/runtime/core/block_vector.h
// (re-included here via the project's emp-tool dependency).

// Single-bit masks at positions 0 and 1. Used by protocols that pin the
// low bits of the global key Δ (e.g. ag2pc-style aShare encoding pins bit 0
// of K, half-gate Λ_γ recovery pins bit 1 of ⊕_p Δ_p).
inline constexpr block bit0_mask = makeBlock(0, 1);
inline constexpr block bit1_mask = makeBlock(0, 2);

// Two-party transport: each party holds a duplex pair of NetIO channels to the
// single peer, named by role -- send_io for outgoing, recv_io for incoming.
// They are two distinct sockets (party 1's send_io == party 2's recv_io and
// vice versa), so a send task on send_io and a recv task on recv_io overlap
// without head-of-line blocking, and the two COT instances run one per socket.
// Code just uses send_io->send_data / recv_io->recv_data directly; there is no
// dst/src routing because the only peer is implicit.
//
// Total bytes across both channels (for the AG2PC_PROFILE phase counters).
inline int64_t io_count(NetIO *send_io, NetIO *recv_io) {
  return send_io->send_counter + send_io->recv_counter +
         recv_io->send_counter + recv_io->recv_counter;
}

// Bounded single-producer / single-consumer pipe of T values, used to overlap a
// blocking IO call with compute on the *same* socket: one thread runs the IO,
// the other runs compute, the pipe holds the chunks in flight. At depth N (the
// default 2 is enough for one-step lookahead) the producer can fill slot k+1
// while the consumer drains slot k.
//
// Producer side (one thread): producer_slot() blocks until a slot is free and
// returns it for filling; producer_publish() marks it full and wakes the
// consumer; producer_close() declares no more chunks will come. Consumer side
// (one thread): consumer_slot() blocks until a slot is full (or the producer
// has closed and the pipe is drained, in which case it returns nullptr);
// consumer_release() marks the consumed slot free and wakes the producer.
//
// Slots are pre-constructed once via the Init callback so a chunk's buffers can
// be sized to the per-call cap up front (no allocation in the hot path).
template <typename T>
class chunk_pipe {
public:
  template <typename Init>
  chunk_pipe(size_t depth, Init init) : slots_(depth) {
    for (auto &s : slots_) init(s);
  }

  T &producer_slot() {
    std::unique_lock<std::mutex> lk(mu_);
    cv_free_.wait(lk, [&] { return count_ < slots_.size(); });
    return slots_[(consumer_head_ + count_) % slots_.size()];
  }
  void producer_publish() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      ++count_;
    }
    cv_full_.notify_one();
  }
  void producer_close() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      closed_ = true;
    }
    cv_full_.notify_one();
  }

  T *consumer_slot() {
    std::unique_lock<std::mutex> lk(mu_);
    cv_full_.wait(lk, [&] { return count_ > 0 || closed_; });
    if (count_ == 0) return nullptr;            // drained + closed
    return &slots_[consumer_head_];
  }
  void consumer_release() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      consumer_head_ = (consumer_head_ + 1) % slots_.size();
      --count_;
    }
    cv_free_.notify_one();
  }

private:
  std::vector<T> slots_;
  size_t consumer_head_ = 0;
  size_t count_ = 0;
  bool closed_ = false;
  std::mutex mu_;
  std::condition_variable cv_full_, cv_free_;
};

template <typename T> void joinNclean(std::vector<future<T>> &res) {
  for (auto &v : res)
    v.get();
  res.clear();
}

inline uint8_t LSB(const block &b) { return _mm_extract_epi8(b, 0) & 0x1; }
// Bit 1 (second-lowest) of a block. Reserved for the half-gate Λ_γ recovery
// invariant LSB1(⊕_p Δ_p) = 1; bit 0 is reserved for share-value encoding
// (see share_bundle.h).
inline uint8_t LSB1(const block &b) { return (_mm_extract_epi8(b, 0) >> 1) & 0x1; }

// F_eq (eprint 2018/578): rush-safe equality test on a precomputed digest Dme.
// P1 commits H(Dme‖r) first, P2 replies with its Dme, then P1 opens (Dme, r) —
// the commit-before-open order is rush-safe and the nonce r keeps the commitment
// hiding. Aborts via error(fail_msg) when the two digests differ. Dme may be a
// digest over a whole batched vector, so one call (one round) checks many values.
inline void feq_check(NetIO *io, int party, const char *Dme,
                      const char *fail_msg) {
  char Dpeer[Hash::DIGEST_SIZE];
  if (party == 1) {
    block r; PRG().random_block(&r, 1);
    char com[Hash::DIGEST_SIZE];
    { Hash h; h.put(Dme, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(com); }
    io->send_data(com, Hash::DIGEST_SIZE);
    io->recv_data(Dpeer, Hash::DIGEST_SIZE);
    io->send_data(Dme, Hash::DIGEST_SIZE);
    io->send_data(&r, sizeof(block)); io->flush();
  } else {
    char com[Hash::DIGEST_SIZE], chk[Hash::DIGEST_SIZE];
    block r;
    io->recv_data(com, Hash::DIGEST_SIZE);
    io->send_data(Dme, Hash::DIGEST_SIZE);
    io->recv_data(Dpeer, Hash::DIGEST_SIZE);
    io->recv_data(&r, sizeof(block));
    { Hash h; h.put(Dpeer, Hash::DIGEST_SIZE); h.put(&r, sizeof(block)); h.digest(chk); }
    if (memcmp(chk, com, Hash::DIGEST_SIZE) != 0)
      error("F_eq: commit-open mismatch");
  }
  if (memcmp(Dme, Dpeer, Hash::DIGEST_SIZE) != 0)
    error(fail_msg);
}

#endif // __HELPER
