// AG2PCCtx public surface: typed input/reveal over the value layer, arithmetic
// and comparison, signed Int, a PUBLIC constant, and reveal to a single recipient.
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include <cstdio>
#include <optional>
using namespace std;
using namespace emp;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCCtx ctx(io, &pool, party);
  io->flush();

  using UInt32 = UInt_T<AG2PCCtx, 32>;
  using Int32  = Int_T<AG2PCCtx, 32>;

  const uint32_t X = 1234567u, Y = 7654321u, K = 333u;
  bool ok = true;

  // a + b ; reveal does not prune, so a/b stay materialized for later use.
  auto a = ctx.input<UInt32>(ALICE, party == ALICE ? X : 0);
  auto b = ctx.input<UInt32>(BOB,   party == BOB   ? Y : 0);
  uint32_t got_sum = (uint32_t)ctx.reveal(a + b, PUBLIC).value_or(0);

  // (a + b) * 3 + K, with K a PUBLIC constant input (no OT).
  auto three = ctx.input<UInt32>(PUBLIC, 3);
  auto kpub  = ctx.input<UInt32>(PUBLIC, K);
  uint32_t got_expr = (uint32_t)ctx.reveal((a + b) * three + kpub, PUBLIC).value_or(0);

  // a < b, revealed to ALICE only (BOB gets nullopt).
  std::optional<bool> lt = ctx.reveal(a < b, ALICE);

  // Signed Int32: (-5) + 12 == 7.
  auto ia = ctx.input<Int32>(ALICE, party == ALICE ? (int64_t)-5 : 0);
  auto ib = ctx.input<Int32>(BOB,   party == BOB   ? (int64_t)12 : 0);
  int32_t got_signed = (int32_t)ctx.reveal(ia + ib, PUBLIC).value_or(0);

  if (party == BOB) ok &= !lt.has_value();   // BOB must NOT learn a<b

  if (party == ALICE) {
    uint32_t ref_sum = X + Y, ref_expr = (X + Y) * 3u + K;
    bool ref_lt = X < Y;
    ok &= (got_sum == ref_sum);
    ok &= (got_expr == ref_expr);
    ok &= (lt.has_value() && lt.value() == ref_lt);
    ok &= (got_signed == 7);
    printf("context_api: a+b=%u (exp %u), (a+b)*3+K=%u (exp %u), a<b=%d (exp %d), "
           "(-5)+12=%d (exp 7)  %s\n",
           got_sum, ref_sum, got_expr, ref_expr, (int)lt.value(), (int)ref_lt,
           got_signed, ok ? "GOOD!" : "BAD!");
  }
  return (party == ALICE && !ok) ? 1 : 0;
}
