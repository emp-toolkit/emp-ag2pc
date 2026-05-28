// Smoke test for checkpoint_ag2pc_keep_all()'s RAII-driven liveness: build
// some wires in an inner scope, let them die at scope end, then checkpoint
// without listing anything. The dropped wires should NOT be carried, and the
// still-alive wire (`keep`) must continue to work across the checkpoint.
//
// Checks two things at party 1:
//   1. backend->live_wire_count() drops sharply at end of the inner scope.
//   2. the reveal of `keep & d` (computed AFTER the checkpoint) matches the
//      plaintext oracle — i.e., the kept wire's authenticated state survived
//      the checkpoint correctly while everything else was dropped.
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "emp-ag2pc/ag2pc_backend.h"
#include "emp-ag2pc/ag2pc_circuit_types.h"
#include "net_setup.h"
using namespace std;
using namespace emp;

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  auto *b = setup_ag2pc(io, &pool, party);
  io->flush();

  // The wire we WANT to survive across the checkpoint.
  Bit keep((party == 1), 1);

  size_t live_pre_inner = b->live_wire_count();

  // Inner scope: feed 1000 inputs + chain XOR them. Every one of these Bits
  // (and the XOR chain's intermediates) goes out of scope at the closing
  // brace, dropping their refcount to 0.
  size_t live_peak_inner = 0;
  {
    std::vector<Bit> noise;
    noise.reserve(1000);
    for (int i = 0; i < 1000; ++i)
      noise.emplace_back(party == 1, 1);
    Bit tmp = noise[0];
    for (int i = 1; i < 1000; ++i) tmp = tmp ^ noise[i];
    live_peak_inner = b->live_wire_count();   // sampled while noise[] still alive
  }
  size_t live_post_inner = b->live_wire_count();

  // Smart checkpoint: no keep[] list. The 1000 noise inputs + their XOR-chain
  // outputs are all dead (refcount 0) — they get pruned by DCE + dropped from
  // the carry. Only `keep` (and any not-yet-pinned wire from earlier) carries.
  checkpoint_ag2pc_keep_all();
  size_t live_post_ckpt = b->live_wire_count();

  // Use `keep` after the checkpoint to prove it survived intact.
  Bit d((party == 1), 1);
  Bit out = keep & d;
  bool result = out.reveal<bool>(1);

  finalize_ag2pc();

  if (party == 1) {
    // Plaintext oracle: keep = a = true, d = true → keep & d = true.
    bool expected = true;
    // The big drop check: post-inner live count must be FAR below the peak
    // (we dropped >900 wires when the inner scope ended).
    bool dropped = (live_peak_inner > live_post_inner + 500);
    // And after the checkpoint, only the kept wire's slot is live (plus
    // any chunk-local intermediate count from the keep feed — typically 1).
    bool ckpt_tight = (live_post_ckpt <= live_post_inner);
    bool ok = (result == expected) && dropped && ckpt_tight;
    cout << "test_keep_all: result=" << result << " expected=" << expected
         << " live(pre/peak/post-inner/post-ckpt)="
         << live_pre_inner << "/" << live_peak_inner << "/"
         << live_post_inner << "/" << live_post_ckpt
         << "  " << (ok ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
