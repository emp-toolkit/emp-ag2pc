// Object-mode controls: input batching, checkpoint carry, reactive reveal, and
// RAII liveness.
#include "emp-ag2pc/emp-ag2pc.h"
#include "test_common.h"
using namespace std;
using namespace emp;

// Inputs with the same owner are shared in one input phase.
static bool input_batching(int party, int port) {
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  auto *b = setup_ag2pc(io, &pool, party);
  io->flush();

  const int K = 32;
  Bit acc(false, PUBLIC);
  std::vector<Bit> xs;
  for (int i = 0; i <= K; ++i)
    xs.emplace_back((party == 1) ? ((i & 1) != 0) : false, 1);
  for (int i = 0; i < K; ++i) acc = acc ^ xs[i];
  Bit bit0b = acc & xs[K];
  bool bit0 = bit0b.reveal<bool>(1);

  int calls = b->process_input_calls;
  finalize_ag2pc();
  if (party != 1) return true;
  bool ok = (calls == 1);
  printf("  input batching: K=%d same-owner inputs -> process_input_calls=%d "
         "(out bit0=%d)  %s\n", K, calls, bit0,
         ok ? "GOOD! (batched)" : "BAD! (per-input)");
  return ok;
}

// C2 = AES(K2, AES(K1, P)).
template <typename Wire>
static void aes2(const bool k1b[128], const bool k2b[128], const bool pb[128],
                 int k_owner, int p_owner, bool do_ckpt, bool *ct_out) {
  using B = Bit_T<Wire>;
  B k1[128], k2[128], p[128];
  for (int i = 0; i < 128; ++i) k1[i] = B(k1b[i], k_owner);
  for (int i = 0; i < 128; ++i) k2[i] = B(k2b[i], k_owner);
  for (int i = 0; i < 128; ++i) p[i] = B(pb[i], p_owner);

  AES_Calculator_T<Wire> aes;
  B c1[128];
  {
    B ek1[1408];
    aes.key_schedule(k1, ek1);
    aes.encrypt(p, ek1, c1);
  }
  if (do_ckpt) checkpoint_ag2pc_keep_all();
  B ek2[1408], c2[128];
  aes.key_schedule(k2, ek2);
  aes.encrypt(c1, ek2, c2);

  Wire buf[128];
  for (int i = 0; i < 128; ++i) buf[i] = c2[i].bit;
  backend->reveal(ct_out, 1, buf, 128);
}

// Mid-stream checkpoint with carried authenticated state.
static bool checkpoint_carry(int party, int port) {
  bool k1[128], k2[128], pt[128];
  for (int i = 0; i < 128; ++i) {
    k1[i] = ((i * 7 + 3) % 5) == 0;
    k2[i] = ((i * 5 + 2) % 3) == 0;
    pt[i] = ((i * 3 + 1) % 4) == 0;
  }
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();
  bool k1a[128], k2a[128], pb[128];
  for (int i = 0; i < 128; ++i) {
    k1a[i] = (party == 1) ? k1[i] : false;
    k2a[i] = (party == 1) ? k2[i] : false;
    pb[i]  = (party == 2) ? pt[i] : false;
  }
  bool ct_ag2pc[128];
  aes2<AG2PCWire>(k1a, k2a, pb, /*k_owner=*/1, /*p_owner=*/2, /*do_ckpt=*/true, ct_ag2pc);
  finalize_ag2pc();
  if (party != 1) return true;

  setup_clear_backend("");
  bool ct_ref[128];
  aes2<block>(k1, k2, pt, PUBLIC, PUBLIC, /*do_ckpt=*/false, ct_ref);
  finalize_clear_backend();
  bool ok = true;
  for (int i = 0; i < 128; ++i) if (ct_ag2pc[i] != ct_ref[i]) ok = false;
  printf("  checkpoint carry (AES x2, mid checkpoint) vs plaintext  %s\n",
         ok ? "GOOD!" : "BAD!");
  return ok;
}

// Mid-circuit reveal, host branch, and a post-reveal input.
template <typename Wire>
static void reactive_body(bool a_in, bool b_in, bool d_in, bool *out3) {
  using B = Bit_T<Wire>;
  B a(a_in, 1), b(b_in, 2);
  B c = a & b;
  bool v = c.template reveal<bool>(PUBLIC);
  B result;
  if (v) {
    B d(d_in, 1);
    result = d ^ a;
  } else {
    result = a;
  }
  bool r = result.template reveal<bool>(PUBLIC);

  B x(a_in, 1);
  B t = x & x;
  B y(b_in, 2);
  B u = t ^ y;
  bool ru = u.template reveal<bool>(PUBLIC);

  out3[0] = v; out3[1] = r; out3[2] = ru;
}

// Reactive reveal + host branch + new input.
static bool reactive(int party, int port) {
  const bool A = true, Bv = true, D = true;             // logical values
  bool a_in = (party == 1) ? A : false;
  bool b_in = (party == 2) ? Bv : false;
  bool d_in = (party == 1) ? D : false;

  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  setup_ag2pc(io, &pool, party);
  io->flush();
  bool got[3];
  reactive_body<AG2PCWire>(a_in, b_in, d_in, got);
  finalize_ag2pc();
  if (party != 1) return true;

  setup_clear_backend("");
  bool ref[3];
  reactive_body<block>(A, Bv, D, ref);
  finalize_clear_backend();
  bool ok = got[0] == ref[0] && got[1] == ref[1] && got[2] == ref[2];
  printf("  reactive (mid reveal + branch + new input) vs plaintext  %s "
         "(v=%d r=%d ru=%d)\n", ok ? "GOOD!" : "BAD!", got[0], got[1], got[2]);
  return ok;
}

// Wires that go out of scope are not carried across checkpoint_keep_all().
static bool raii_liveness(int party, int port) {
  NetIO *io; make_io2pc(party, port, io);
  ThreadPool pool(4);
  auto *b = setup_ag2pc(io, &pool, party);
  io->flush();

  Bit keep((party == 1), 1);
  size_t live_pre_inner = b->live_wire_count();
  size_t live_peak_inner = 0;
  {
    std::vector<Bit> noise;
    noise.reserve(1000);
    for (int i = 0; i < 1000; ++i) noise.emplace_back(party == 1, 1);
    Bit tmp = noise[0];
    for (int i = 1; i < 1000; ++i) tmp = tmp ^ noise[i];
    live_peak_inner = b->live_wire_count();   // sampled while noise[] still alive
  }
  size_t live_post_inner = b->live_wire_count();

  checkpoint_ag2pc_keep_all();
  size_t live_post_ckpt = b->live_wire_count();

  Bit d((party == 1), 1);
  Bit out = keep & d;
  bool result = out.reveal<bool>(1);

  finalize_ag2pc();
  if (party != 1) return true;

  bool expected = true;
  bool dropped    = (live_peak_inner > live_post_inner + 500);
  bool ckpt_tight = (live_post_ckpt <= live_post_inner);
  bool ok = (result == expected) && dropped && ckpt_tight;
  printf("  RAII liveness: result=%d live(pre/peak/post-inner/post-ckpt)="
         "%zu/%zu/%zu/%zu  %s\n", result, live_pre_inner, live_peak_inner,
         live_post_inner, live_post_ckpt, ok ? "GOOD!" : "BAD!");
  return ok;
}

int main(int argc, char **argv) {
  int port, party;
  parse_party_and_port(argv, &party, &port);
  if (party > 2) return 0;

  bool ok = true;
  ok &= input_batching(party,   port + 0);
  ok &= checkpoint_carry(party, port + 1);
  ok &= reactive(party,         port + 2);
  ok &= raii_liveness(party,    port + 3);

  if (party == 1)
    printf("test_object_control: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
