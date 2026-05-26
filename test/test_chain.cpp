// Capability test: chain AES twice, C2 = AES(K2, AES(K1, P)), with a mid-stream
// checkpoint_ag2pc() between the two AES instances. The checkpoint forces the ag2pc
// protocol to evaluate the first AES, keeps the intermediate (C1) + the still-
// needed K2 live as authenticated wires, and discards the first AES's gate list
// — so peak gate-list memory is one AES, not two. Oracle: the same 2x chain in
// plaintext via setup_clear_backend (no checkpoint).
#include "emp-tool/emp-tool.h"
#include "emp-ag2pc/emp-ag2pc.h"
#include "net_setup.h"
#include "emp-ag2pc/ag2pc_backend.h"
using namespace std;
using namespace emp;


// C2 = AES(K2, AES(K1, P)). If do_ckpt, checkpoint between the two AES calls.
template <typename Wire>
static void aes2(const bool k1b[128], const bool k2b[128], const bool pb[128],
                 int k_owner, int p_owner, bool do_ckpt, bool *ct_out /*128*/) {
  using B = Bit_T<Wire>;
  B k1[128], k2[128], p[128];
  for (int i = 0; i < 128; ++i) k1[i] = B(k1b[i], k_owner);
  for (int i = 0; i < 128; ++i) k2[i] = B(k2b[i], k_owner);
  for (int i = 0; i < 128; ++i) p[i] = B(pb[i], p_owner);  // all inputs first

  AES_Calculator_T<Wire> aes;
  B ek1[1408], c1[128];
  aes.key_schedule(k1, ek1);
  aes.encrypt(p, ek1, c1);

  if (do_ckpt) {
    // Keep C1 and K2 (K2 is still needed by the second AES) across the chunk.
    B keep[256];
    for (int i = 0; i < 128; ++i) keep[i] = c1[i];
    for (int i = 0; i < 128; ++i) keep[128 + i] = k2[i];
    checkpoint_ag2pc(keep, 256);
    for (int i = 0; i < 128; ++i) c1[i] = keep[i];
    for (int i = 0; i < 128; ++i) k2[i] = keep[128 + i];
  }

  B ek2[1408], c2[128];
  aes.key_schedule(k2, ek2);
  aes.encrypt(c1, ek2, c2);

  block buf[128];
  for (int i = 0; i < 128; ++i) memcpy(&buf[i], &c2[i], sizeof(block));
  backend->reveal(ct_out, 1, buf, 128);
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  bool k1[128], k2[128], pt[128];
  for (int i = 0; i < 128; ++i) {
    k1[i] = ((i * 7 + 3) % 5) == 0;
    k2[i] = ((i * 5 + 2) % 3) == 0;
    pt[i] = ((i * 3 + 1) % 4) == 0;
  }

  NetIO *io1, *io2; make_io2pc(party, port, io1, io2);
  ThreadPool pool(4);
  setup_ag2pc(io1, io2, &pool, party);
  io1->flush(); io2->flush();
  bool k1a[128], k2a[128], pb[128];
  for (int i = 0; i < 128; ++i) {
    k1a[i] = (party == 1) ? k1[i] : false;
    k2a[i] = (party == 1) ? k2[i] : false;
    pb[i] = (party == 2) ? pt[i] : false;
  }
  bool ct_ag2pc[128];
  aes2<block>(k1a, k2a, pb, /*k_owner=*/1, /*p_owner=*/2, /*do_ckpt=*/true, ct_ag2pc);
  finalize_ag2pc();

  if (party == 1) {
    setup_clear_backend("");
    bool ct_ref[128];
    aes2<block>(k1, k2, pt, PUBLIC, PUBLIC, /*do_ckpt=*/false, ct_ref);
    finalize_clear_backend();
    bool ok = true;
    for (int i = 0; i < 128; ++i) if (ct_ag2pc[i] != ct_ref[i]) ok = false;
    cout << "test_chain (AES x2 with mid checkpoint) vs plaintext: "
         << (ok ? "GOOD!" : "BAD!") << endl;
  }
  return 0;
}
