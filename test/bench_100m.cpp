// Final-state 100M-AND benchmark for AG2PCSession.
//
// Workload: start from a 32-byte all-zero string, with the low 128 input bits
// owned by ALICE and the high 128 input bits owned by BOB, then repeatedly apply
// the stored sha256_256 BooleanProgram in chunked live replay sources. ALICE
// checks the final digest against OpenSSL SHA256 iterated the same number of
// times.
//
// Environment:
//   SHA_ITERS=<n>     exact number of SHA-256 iterations
//   TARGET_ANDS=<n>   default 100000000; used only when SHA_ITERS is unset
//   SHA_CHUNK_ITERS=<n>
//                     SHA-256 iterations per protocol chunk, default 404
//   BENCH_THREADS=<n> ThreadPool workers, default 4

#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-tool/ir/builtins.h"
#include "net_setup.h"

#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <sys/resource.h>

using namespace emp;

namespace {

using B128 = BitVec_T<AG2PCSession::ctx_t, 128>;
using B256 = BitVec_T<AG2PCSession::ctx_t, 256>;

uint64_t env_u64(const char* name, uint64_t fallback) {
  const char* s = std::getenv(name);
  if (s == nullptr || *s == '\0') return fallback;
  char* end = nullptr;
  uint64_t v = std::strtoull(s, &end, 10);
  if (end == s || *end != '\0') {
    std::fprintf(stderr, "bench_100m: invalid %s=%s\n", name, s);
    std::exit(1);
  }
  return v;
}

int env_int(const char* name, int fallback) {
  uint64_t v = env_u64(name, (uint64_t)fallback);
  if (v == 0 || v > 1024) {
    std::fprintf(stderr, "bench_100m: invalid %s=%llu\n", name,
                 (unsigned long long)v);
    std::exit(1);
  }
  return (int)v;
}

uint64_t count_ands(const circuit::BooleanProgram& p) {
  uint64_t n = 0;
  for (const circuit::Gate& g : p.gates)
    if (g.op == circuit::Op::And) ++n;
  return n;
}

long peak_rss_kib() {
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
  return ru.ru_maxrss / 1024;
#else
  return ru.ru_maxrss;
#endif
}


std::array<uint8_t, 32> openssl_sha_chain(uint64_t iters) {
  std::array<uint8_t, 32> cur{};
  std::array<uint8_t, 32> next{};
  for (uint64_t i = 0; i < iters; ++i) {
    SHA256(cur.data(), cur.size(), next.data());
    cur = next;
  }
  return cur;
}

void print_hex(const char* label, const std::array<uint8_t, 32>& d) {
  std::printf("%s", label);
  for (uint8_t b : d) std::printf("%02x", b);
  std::printf("\n");
}

uint64_t io_bytes(AG2PCSession& sess) {
  NetIO* io = sess.protocol().io;
  NetIO* sib = sess.protocol().sib;
  return io->send_counter + io->recv_counter +
         sib->send_counter + sib->recv_counter;
}

template <class Ctx>
BitVec_T<Ctx, 256> replay_sha256_256(Ctx& c, const circuit::BooleanProgram& prog,
                                   const BitVec_T<Ctx, 256>& in,
                                   ProgramWorkspace<typename Ctx::Wire>& ws) {
  using W = typename Ctx::Wire;
  std::array<W, 256> iw{};
  in.pack_wires(iw.data());
  const std::vector<W>& ow =
      execute_program(c, prog, std::span<const W>(iw.data(), iw.size()), ws);
  return BitVec_T<Ctx, 256>::from_wires(c, ow.data());
}

}  // namespace

int main(int argc, char** argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  const circuit::BooleanProgram& sha = circuit::builtin_circuit("sha256_256");
  const uint64_t sha_ands = count_ands(sha);
  const uint64_t target_ands = env_u64("TARGET_ANDS", 100000000ULL);
  uint64_t iters = env_u64("SHA_ITERS", 0);
  if (iters == 0) iters = (target_ands + sha_ands - 1) / sha_ands;
  if (iters == 0) {
    std::fprintf(stderr, "bench_100m: SHA_ITERS/TARGET_ANDS produced zero iterations\n");
    return 1;
  }
  const uint64_t chunk_iters = env_u64("SHA_CHUNK_ITERS", 404);
  if (chunk_iters == 0) {
    std::fprintf(stderr, "bench_100m: SHA_CHUNK_ITERS must be positive\n");
    return 1;
  }
  const int threads = env_int("BENCH_THREADS", 4);

  NetIO* io;
  make_io2pc(party, port, io);
  ThreadPool pool(threads);
  AG2PCSession sess(io, &pool, party);
  io->flush();

  const uint64_t planned_ands = sha_ands * iters;
  const uint64_t planned_gates = (uint64_t)sha.gates.size() * iters;
  if (party == ALICE) {
    std::printf("bench_100m sha256_256 zero-string chain\n");
    std::printf("  iterations      %llu\n", (unsigned long long)iters);
    std::printf("  sha gates/iter  %zu\n", sha.gates.size());
    std::printf("  sha ANDs/iter   %llu\n", (unsigned long long)sha_ands);
    std::printf("  planned gates   %llu\n", (unsigned long long)planned_gates);
    std::printf("  planned ANDs    %llu\n", (unsigned long long)planned_ands);
    std::printf("  chunk iters     %llu\n", (unsigned long long)chunk_iters);
    std::printf("  threads         %d\n", threads);
    std::printf("  input           256 zero bits: [0,128) ALICE, [128,256) BOB\n");
  }

  auto t0 = std::chrono::steady_clock::now();

  std::array<bool, 128> zero_half{};
  auto batch = sess.input_batch();
  B128 alice_half = batch.add<B128>(ALICE, zero_half);
  B128 bob_half = batch.add<B128>(BOB, zero_half);
  batch.finish();
  B256 state = alice_half.concat(bob_half);

  auto t_input = std::chrono::steady_clock::now();

  uint64_t chunks = 0;
  for (uint64_t done = 0; done < iters; ) {
    const uint64_t n = std::min<uint64_t>(chunk_iters, iters - done);
    auto body = [&](auto& pass, auto x) {
      ProgramWorkspace<typename std::decay_t<decltype(pass)>::Wire> ws;
      for (uint64_t i = 0; i < n; ++i)
        x = replay_sha256_256(pass, sha, x, ws);
      return x;
    };
    state = sess.run(body, state);
    sess.checkpoint(state);   // carry only the digest into the next chunk
    done += n;
    ++chunks;
  }
  B256 digest = state;

  auto t_run = std::chrono::steady_clock::now();
  auto opened = sess.reveal(digest, ALICE);
  auto t_reveal = std::chrono::steady_clock::now();

  bool ok = true;
  if (party == ALICE) {
    if (!opened.has_value()) {
      std::printf("  result          missing reveal at ALICE\n");
      ok = false;
    } else {
      std::array<uint8_t, 32> got{};
      bools_to_bits(got.data(), opened.value().data(), 256);  // pack 256 bools -> 32 bytes
      std::array<uint8_t, 32> ref = openssl_sha_chain(iters);
      ok = std::memcmp(got.data(), ref.data(), got.size()) == 0;
      print_hex("  got             ", got);
      print_hex("  openssl         ", ref);
    }

    const double input_s =
        std::chrono::duration<double>(t_input - t0).count();
    const double run_s =
        std::chrono::duration<double>(t_run - t_input).count();
    const double reveal_s =
        std::chrono::duration<double>(t_reveal - t_run).count();
    const double total_s =
        std::chrono::duration<double>(t_reveal - t0).count();
    const uint64_t actual_ands = sess.num_and();
    const uint64_t comm = io_bytes(sess);

    std::printf("  input phases    %d\n", sess.process_input_calls());
    std::printf("  protocol chunks %llu\n", (unsigned long long)chunks);
    std::printf("  actual ANDs     %llu\n", (unsigned long long)actual_ands);
    std::printf("  wall input      %.3f s\n", input_s);
    std::printf("  wall run        %.3f s\n", run_s);
    std::printf("  wall reveal     %.3f s\n", reveal_s);
    std::printf("  wall total      %.3f s\n", total_s);
    std::printf("  throughput      %.3f MAND/s\n",
                total_s > 0 ? (double)actual_ands / total_s / 1.0e6 : 0.0);
    std::printf("  comm total      %.3f GiB\n",
                (double)comm / (1024.0 * 1024.0 * 1024.0));
    std::printf("  peak RSS        %.3f GiB\n",
                (double)peak_rss_kib() / (1024.0 * 1024.0));
    std::printf("bench_100m: %s\n", ok ? "GOOD!" : "BAD!");
  }

  return (party == ALICE && !ok) ? 1 : 0;
}
