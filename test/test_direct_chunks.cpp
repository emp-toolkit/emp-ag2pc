// Direct/chunked execution: multi-owner input batching, checkpoint prune+carry,
// reveal with an explicit keep list, and no-arg checkpoint cleanup. These are the
// behaviors of the explicit-keep-list wire model (no refcount, no hidden liveness).
//
// The stale-id guards fire as error() -> exit(1) by design (fail-fast): a wire used
// after a prune, or a reserved input_batch().add value still unmaterialized at the
// next flush, has no carried state and aborts. (A gate over a reserved batch id
// records fine; the stale error is deferred to that flush, and only if the value is
// reachable from a reveal/keep.) Such an abort would desync a live two-party run, so
// these are validated by construction here rather than death-tested.
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include <cstdio>
using namespace std;
using namespace emp;
using UInt32 = UInt_T<AG2PCSession::ctx_t, 32>;

// ALICE + BOB inputs authenticated in ONE process_inputs phase.
static bool batch_inputs(int party, int port) {
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();

  const uint32_t X = 11111u, Y = 22222u;
  auto batch = sess.input_batch();
  auto a = batch.add<UInt32>(ALICE, party == ALICE ? X : 0);
  auto b = batch.add<UInt32>(BOB,   party == BOB   ? Y : 0);
  batch.finish();                       // one phase across both owners
  auto out = sess.reveal(a + b, PUBLIC);
  int calls = sess.process_input_calls();
  if (party != ALICE) return true;
  bool ok = out.has_value() && out.value() == (uint64_t)(X + Y) && calls == 1;
  printf("  input_batch (ALICE+BOB, one phase): a+b=%u (exp %u) process_input_calls=%d  %s\n",
         (uint32_t)out.value_or(0), X + Y, calls, ok ? "GOOD! (batched)" : "BAD!");
  return ok;
}

// Long accumulator chain, checkpoint(acc) after each step: prunes the dropped
// per-step inputs, carries acc forward.
static bool checkpoint_chain(int party, int port) {
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();

  const int N = 8;
  uint32_t blk[N];
  for (int i = 0; i < N; ++i) blk[i] = 0x100u * (uint32_t)(i + 1);
  const uint32_t init = 1000u;

  auto acc = sess.input<UInt32>(ALICE, party == ALICE ? init : 0);
  uint32_t ref = init;
  for (int k = 0; k < N; ++k) {
    auto x = sess.input<UInt32>(BOB, party == BOB ? blk[k] : 0);
    acc = acc + x;
    sess.checkpoint(acc);                 // keep acc, prune everything else
    ref += blk[k];
  }
  auto out = sess.reveal(acc, PUBLIC);
  if (party != ALICE) return true;
  bool ok = out.has_value() && out.value() == (uint64_t)ref;
  printf("  checkpoint chain (%d adds, prune each step): acc=%u (exp %u)  %s\n",
         N, (uint32_t)out.value_or(0), ref, ok ? "GOOD!" : "BAD!");
  return ok;
}

// reveal(p, ..., keep q): q is pending and must survive the flush so a later
// reveal(q) still finds it.
static bool reveal_keep_list(int party, int port) {
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();

  const uint32_t X = 40u, Y = 15u;
  auto a = sess.input<UInt32>(ALICE, party == ALICE ? X : 0);
  auto b = sess.input<UInt32>(BOB,   party == BOB   ? Y : 0);
  auto p = a + b;                         // pending
  auto q = a - b;                         // pending (X > Y)
  auto rp = sess.reveal(p, PUBLIC, q);     // flush, keep q across it
  auto rq = sess.reveal(q, PUBLIC);        // q now materialized
  if (party != ALICE) return true;
  bool ok = rp.has_value() && rq.has_value() &&
            rp.value() == (uint64_t)(X + Y) && rq.value() == (uint64_t)(X - Y);
  printf("  reveal keep-list (q=a-b kept across reveal(a+b)): p=%u (exp %u) q=%u (exp %u)  %s\n",
         (uint32_t)rp.value_or(0), X + Y, (uint32_t)rq.value_or(0), X - Y,
         ok ? "GOOD!" : "BAD!");
  return ok;
}

// checkpoint() with no args drops all pending work and prunes all carried state;
// the context stays usable with fresh inputs afterward.
static bool checkpoint_cleanup(int party, int port) {
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  AG2PCSession sess(io, &pool, party);
  io->flush();

  auto a = sess.input<UInt32>(ALICE, party == ALICE ? 5 : 0);
  auto b = sess.input<UInt32>(BOB,   party == BOB   ? 7 : 0);
  (void)(a + b);                          // pending work, intentionally abandoned
  sess.checkpoint();                       // drop pending, prune all carried (a, b too)

  auto c = sess.input<UInt32>(ALICE, party == ALICE ? 100 : 0);
  auto d = sess.input<UInt32>(BOB,   party == BOB   ? 23 : 0);
  auto out = sess.reveal(c + d, PUBLIC);
  if (party != ALICE) return true;
  bool ok = out.has_value() && out.value() == 123u;
  printf("  checkpoint() no-arg cleanup, then fresh c+d=%u (exp 123)  %s\n",
         (uint32_t)out.value_or(0), ok ? "GOOD!" : "BAD!");
  return ok;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  bool ok = true;
  ok &= batch_inputs(party,      port + 0);
  ok &= checkpoint_chain(party,  port + 1);
  ok &= reveal_keep_list(party,  port + 2);
  ok &= checkpoint_cleanup(party, port + 3);

  if (party == ALICE)
    printf("test_direct_chunks: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == ALICE && !ok) ? 1 : 0;
}
