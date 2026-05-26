#ifndef TRIPLE_POOL_CUTCHOOSE_H__
#define TRIPLE_POOL_CUTCHOOSE_H__
// Cut-and-choose (FKOS) leaky-AND path for TriplePool: the LeakyAnd::CutChoose
// alternative to the half-gate (OT multiply -> authenticated leaky triple ->
// cyclic-shift correctness sacrifice) plus its self-tests. Split out of
// triple_pool.h to keep that file focused on the half-gate method.
//
// This is a fragment of class TriplePool: it is textually #included INSIDE the
// class body from triple_pool.h (after the kLeakyAnd / leaky_abit_len seam and
// before compute()). It declares no includes of its own and must not be
// included anywhere other than that single site.
  // ===== Cut-and-choose (FKOS) Stage 1: OT multiplication =====
  // Lean variant (no 2κ key doubling, per design): reuse the a-aShare COT
  // correlation (aMAC/aKEY under Δ) as the correlation-robust hash input.
  // Produces UNAUTHENTICATED product bit-shares z with ⊕_p z^p = (⊕_p a^p) ∧
  // (⊕_p b^p). One communication round (each party ships an s vector per peer).
  //   a^me = bit0(aMAC[k]). For peer j:
  //     aMAC[k] = M_j[a^me] = K_j[a^me] ⊕ a^me·Δ_j   (me = OT receiver to j)
  //     aKEY[k] = K_me[a^j]                            (me = OT sender to j)
  //   send-role (a^j·b^me): s = H(K_me[a^j]) ⊕ H(K_me[a^j]⊕Δ_me) ⊕ b^me; keep v0=H(K_me[a^j])
  //   recv-role (a^me·b^j): n = H(M_j[a^me]) ⊕ a^me·s_recv = H(K_j[a^me]) ⊕ a^me·b^j
  //   z^me = a^me·b^me ⊕ ⊕_{j≠me} ( v0_send ⊕ n_recv )   (the ⊕H terms cancel in Σ_p)
  void multiply_unauth(BlockVec &aMAC, BlockVec &aKEY,
                       const std::vector<uint8_t> &b, int len,
                       std::vector<uint8_t> &z) {
    PRP prp;  // fixed public key → same correlation-robust H on all parties
    auto H = [&](block x) -> uint8_t {
      block y = x;
      prp.permute_block(&y, 1);
      return (uint8_t)(LSB(y ^ x));  // π(x)⊕x, low bit
    };
    int ap = (party == 1) ? 2 : 1;  // any peer slot carries a^me in bit0
    z.assign(len, 0);
    const int peer = 3 - party;
    std::vector<uint8_t> s_send(len), s_recv(len);
    for (int k = 0; k < len; ++k) z[k] = (uint8_t)(LSB(aMAC[k]) & b[k]);
    for (int k = 0; k < len; ++k) {
      uint8_t v0 = H(aKEY[k]);
      s_send[k] = (uint8_t)(v0 ^ H(aKEY[k] ^ Delta) ^ b[k]);
      z[k] ^= v0;
    }
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, &s_send, len, peer]() {
      send_io->send_bool((const bool *)s_send.data(), len);
      send_io->flush();
    }));
    res.push_back(pool->enqueue([this, &s_recv, len, peer]() {
      recv_io->recv_bool((bool *)s_recv.data(), len);
    }));
    joinNclean(res);
    for (int k = 0; k < len; ++k) {
      uint8_t ame = (uint8_t)LSB(aMAC[k]);
      z[k] ^= (uint8_t)(H(aMAC[k]) ^ (ame & s_recv[k]));
    }
  }

  // Self-test: gen random authenticated a, b; multiply; open a,b,z to P1 and
  // check ⊕z == (⊕a)∧(⊕b). Prints GOOD/BAD at party 1.
  void cutchoose_mult_selftest(int len) {
    BlockVec aMAC, aKEY, bMAC, bKEY;
    process_phase1(aMAC, aKEY, len);
    process_phase1(bMAC, bKEY, len);
    int ap = (party == 1) ? 2 : 1;
    std::vector<uint8_t> a(len), b(len), z;
    for (int k = 0; k < len; ++k) { a[k] = (uint8_t)LSB(aMAC[k]); b[k] = (uint8_t)LSB(bMAC[k]); }
    multiply_unauth(aMAC, aKEY, b, len, z);
    if (party != 1) {
      io->send_data(a.data(), len); io->send_data(b.data(), len);
      io->send_data(z.data(), len); io->flush();
    } else {
      bool ok = true;
      std::vector<uint8_t> A(a), B(b), Z(z);
      { const int p = 2;
        std::vector<uint8_t> ta(len), tb(len), tz(len);
        io->recv_data(ta.data(), len); io->recv_data(tb.data(), len);
        io->recv_data(tz.data(), len);
        for (int k = 0; k < len; ++k) { A[k] ^= ta[k]; B[k] ^= tb[k]; Z[k] ^= tz[k]; }
      }
      for (int k = 0; k < len; ++k) if (Z[k] != (uint8_t)(A[k] & B[k])) ok = false;
      printf("cutchoose_mult (len=%d): %s\n", len, ok ? "GOOD!" : "BAD!");
    }
  }

  // ===== Cut-and-choose Stage 2: authenticated leaky triple =====
  // From a/b/r aShares (a=[0,LB), b=[LB,2LB), r=[2LB,3LB) of tMAC/tKEY) produce
  // an authenticated AND triple (a, b, c=a∧b) with c overwriting the r-region.
  // Lean authentication (no doubling): c = r ⊕ d with d = (a∧b)⊕r opened public,
  // reusing the half-gate's r→c flip (d here comes from the OT multiplication).
  // Honest-correct; a malicious wrong product is caught by Stage 3's sacrifice.
  void make_leaky_triples_cutchoose(BlockVec &tMAC, BlockVec &tKEY,
                                    int LB) {
    int ap = (party == 1) ? 2 : 1;
    std::vector<uint8_t> b(LB), z;
    for (int k = 0; k < LB; ++k) b[k] = (uint8_t)LSB(tMAC[LB + k]);
    multiply_unauth(tMAC, tKEY, b, LB, z);  // a-region at offset 0; ⊕z = a∧b
    // d^me = z^me ⊕ r^me; open d = ⊕_p d^p (all-to-all XOR).
    std::vector<uint8_t> dme(LB);
    for (int k = 0; k < LB; ++k)
      dme[k] = (uint8_t)(z[k] ^ LSB(tMAC[2 * LB + k]));
    std::vector<uint8_t> dr(LB);
    const int peer = 3 - party;
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, &dme, LB, peer]() {
      send_io->send_bool((const bool *)dme.data(), LB);
      send_io->flush();
    }));
    res.push_back(pool->enqueue([this, &dr, LB, peer]() {
      recv_io->recv_bool((bool *)dr.data(), LB);
    }));
    joinNclean(res);
    std::vector<uint8_t> d(dme);
    for (int k = 0; k < LB; ++k) d[k] ^= dr[k];
    // c = r ⊕ d (public d) on the r-region: P1 flips bit0(MAC) by d; every other
    // party flips its key for peer 1 by Δ⊕e_0 to keep the MAC on c consistent.
    block dxor = Delta ^ bit0_mask;
    for (int k = 0; k < LB; ++k) {
      if (!d[k]) continue;
      if (party == 1) {
        tMAC[2 * LB + k] = tMAC[2 * LB + k] ^ bit0_mask;
      } else {
        tKEY[2 * LB + k] = tKEY[2 * LB + k] ^ dxor;
      }
    }
  }

  // Seam middle for LeakyAnd::CutChoose. tMAC/tKEY hold 3·T·LB aShares
  // (process_phase1 sized by leaky_abit_len): candidates a=[0,N) b=[N,2N) r=[2N,3N),
  // N=T·LB. Make N leaky triples, run the cyclic-shift correctness sacrifice
  // (abort on a bad triple), then COMPACT the LB row-0 heads into a=[0,LB)
  // b=[LB,2LB) c=[2LB,3LB) so the existing Π_Prep combine consumes them. tr is
  // rebuilt over [0,3LB) for the bucketing's b-region reads.
  void cutchoose_leaky(BlockVec &tMAC, BlockVec &tKEY,
                       std::vector<unsigned char> &tr, int LB) {
    const int T = cutchoose_T, N = T * LB;
    make_leaky_triples_cutchoose(tMAC, tKEY, N);  // c = a∧b → [2N,3N)
    int ap = (party == 1) ? 2 : 1;
    block S = RO("AG2PC RO", zero_block)
                  .absorb(io->get_digest())
                  .absorb(sib->get_digest())
                  .squeeze_block();
    std::vector<int> shift(T, 0);
    { PRG p2(&S); std::vector<uint32_t> raw(T); p2.random_data(raw.data(), T * sizeof(uint32_t));
      for (int r = 1; r < T; ++r) shift[r] = (int)(raw[r] % (uint32_t)LB); }
    auto bit = [&](int region, int g) { return (uint8_t)LSB(tMAC[region * N + g]); };
    int P = LB * (T - 1);
    std::vector<uint8_t> rho(P), sig(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB, e = i * (T - 1) + (r - 1);
        rho[e] = (uint8_t)(bit(0, i) ^ bit(0, g));
        sig[e] = (uint8_t)(bit(1, i) ^ bit(1, g));
      }
    std::vector<uint8_t> RHO = open_bits(rho, P), SIG = open_bits(sig, P), v(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB, e = i * (T - 1) + (r - 1);
        uint8_t V = (uint8_t)(bit(2, i) ^ bit(2, g) ^ (RHO[e] & bit(1, g)) ^ (SIG[e] & bit(0, g)));
        if (party == 1) V ^= (uint8_t)(RHO[e] & SIG[e]);
        v[e] = V;
      }
    std::vector<uint8_t> Vpub = open_bits(v, P);
    for (int e = 0; e < P; ++e)
      if (Vpub[e]) error("cut-and-choose sacrifice: incorrect AND triple");
    // Compact row-0 heads: a already at [0,LB); move b,c heads down.
    { const int j = 3 - party;
      memcpy(&tMAC[LB], &tMAC[N], LB * sizeof(block));
      memcpy(&tMAC[2 * LB], &tMAC[2 * N], LB * sizeof(block));
      memcpy(&tKEY[LB], &tKEY[N], LB * sizeof(block));
      memcpy(&tKEY[2 * LB], &tKEY[2 * N], LB * sizeof(block));
    }
    tr.resize(3 * LB);
    for (int k = 0; k < 3 * LB; ++k) tr[k] = (uint8_t)LSB(tMAC[k]);
  }

  // Self-test: gen 3·LB aShares (a,b,r); build the leaky triple; verify the
  // c-region MAC is valid (check_MAC aborts on tamper) and ⊕c == (⊕a)∧(⊕b).
  void cutchoose_triple_selftest(int LB) {
    BlockVec tMAC, tKEY;
    process_phase1(tMAC, tKEY, 3 * LB);
    int ap = (party == 1) ? 2 : 1;
    std::vector<uint8_t> a(LB), b(LB);
    for (int k = 0; k < LB; ++k) { a[k] = (uint8_t)LSB(tMAC[k]); b[k] = (uint8_t)LSB(tMAC[LB + k]); }
    make_leaky_triples_cutchoose(tMAC, tKEY, LB);
    std::vector<uint8_t> c(LB);
    for (int k = 0; k < LB; ++k) c[k] = (uint8_t)LSB(tMAC[2 * LB + k]);
    // Authentication check on the c-region (aborts via error() on bad MAC).
    BlockVec cMAC, cKEY;
    { const int j = 3 - party;
      cMAC.assign(tMAC.begin() + 2 * LB, tMAC.begin() + 3 * LB);
      cKEY.assign(tKEY.begin() + 2 * LB, tKEY.begin() + 3 * LB);
    }
    check_MAC(io, cMAC, cKEY, Delta, LB, party);
    if (party != 1) {
      io->send_data(a.data(), LB); io->send_data(b.data(), LB);
      io->send_data(c.data(), LB); io->flush();
    } else {
      bool ok = true;
      std::vector<uint8_t> A(a), B(b), C(c);
      { const int p = 2;
        std::vector<uint8_t> ta(LB), tb(LB), tc(LB);
        io->recv_data(ta.data(), LB); io->recv_data(tb.data(), LB);
        io->recv_data(tc.data(), LB);
        for (int k = 0; k < LB; ++k) { A[k] ^= ta[k]; B[k] ^= tb[k]; C[k] ^= tc[k]; }
      }
      for (int k = 0; k < LB; ++k) if (C[k] != (uint8_t)(A[k] & B[k])) ok = false;
      printf("cutchoose_triple (LB=%d): %s (MAC verified)\n", LB, ok ? "GOOD!" : "BAD!");
    }
  }

  // Open a per-party bit-share vector: returns the public ⊕_p share^p at every
  // party (all-to-all XOR). (Value-level open; MAC binding checked separately.)
  std::vector<uint8_t> open_bits(const std::vector<uint8_t> &share, int len) {
    std::vector<uint8_t> r(len);
    const int peer = 3 - party;
    std::vector<std::future<void>> res;
    res.push_back(pool->enqueue([this, &share, len, peer]() {
      send_io->send_bool((const bool *)share.data(), len);
      send_io->flush();
    }));
    res.push_back(pool->enqueue([this, &r, len, peer]() {
      recv_io->recv_bool((bool *)r.data(), len);
    }));
    joinNclean(res);
    std::vector<uint8_t> pub(share);
    for (int k = 0; k < len; ++k) pub[k] ^= r[k];
    return pub;
  }

  // ===== Cut-and-choose Stage 3: bucket-sacrifice (correctness) =====
  // Generate N = T·LB candidate triples, arrange as a T-by-LB matrix, CYCLIC-shift
  // rows 1..T-1 by shared random r_k (per design, not a random permutation), and
  // for each column (bucket) sacrifice the T-1 shifted partners against the row-0
  // head: open ρ=a0⊕a1, σ=b0⊕b1 and check V = c0⊕c1⊕ρ·b1⊕σ·a1⊕ρσ == 0. A wrong
  // triple in a bucket with a good head yields V=1 → abort. Heads are the output.
  //   `tamper`: if >=0, flip the VALUE of candidate `tamper`'s c (simulated cheat).
  //   NOTE: value-level check; the batch MAC-binding of V (malicious soundness)
  //   and Phase-I cut-and-choose are the remaining hardening (see plan ⚠).
  void cutchoose_sacrifice_selftest(int LB, int T, int tamper = -1) {
    int N = T * LB;
    BlockVec tMAC, tKEY;
    process_phase1(tMAC, tKEY, 3 * N);
    make_leaky_triples_cutchoose(tMAC, tKEY, N);  // a=[0,N) b=[N,2N) c=[2N,3N)
    int ap = (party == 1) ? 2 : 1;
    if (tamper >= 0 && party == 1)  // flip ⊕c by flipping bit0 of c-MAC on P1
      tMAC[2 * N + tamper] = tMAC[2 * N + tamper] ^ bit0_mask;

    // Cyclic shifts r_k for rows 1..T-1 from a shared seed.
    block S = RO("AG2PC RO", zero_block)
                  .absorb(io->get_digest())
                  .absorb(sib->get_digest())
                  .squeeze_block();
    std::vector<int> shift(T, 0);
    { PRG p2(&S); std::vector<uint32_t> raw(T); p2.random_data(raw.data(), T * sizeof(uint32_t));
      for (int r = 1; r < T; ++r) shift[r] = (int)(raw[r] % (uint32_t)LB); }

    auto bit = [&](int region, int g) { return (uint8_t)LSB(tMAC[region * N + g]); };
    int P = LB * (T - 1);  // number of sacrifice pairs
    std::vector<uint8_t> rho(P), sig(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB;   // partner global index
        int e = i * (T - 1) + (r - 1);
        rho[e] = (uint8_t)(bit(0, i) ^ bit(0, g));   // a0 ⊕ a1
        sig[e] = (uint8_t)(bit(1, i) ^ bit(1, g));   // b0 ⊕ b1
      }
    std::vector<uint8_t> RHO = open_bits(rho, P), SIG = open_bits(sig, P);
    std::vector<uint8_t> v(P);
    for (int i = 0; i < LB; ++i)
      for (int r = 1; r < T; ++r) {
        int g = r * LB + (i + shift[r]) % LB;
        int e = i * (T - 1) + (r - 1);
        // V^me = c0 ⊕ c1 ⊕ ρ·b1 ⊕ σ·a1 (⊕ ρσ at P1)
        uint8_t V = (uint8_t)(bit(2, i) ^ bit(2, g) ^ (RHO[e] & bit(1, g)) ^ (SIG[e] & bit(0, g)));
        if (party == 1) V ^= (uint8_t)(RHO[e] & SIG[e]);
        v[e] = V;
      }
    std::vector<uint8_t> Vpub = open_bits(v, P);
    int bad = 0;
    for (int e = 0; e < P; ++e) if (Vpub[e]) ++bad;
    if (party == 1)
      printf("cutchoose_sacrifice (LB=%d T=%d tamper=%d): %s (%d/%d sacrifice checks nonzero)\n",
             LB, T, tamper, bad == 0 ? "ALL PASS" : "CHEAT DETECTED", bad, P);
  }
#endif // TRIPLE_POOL_CUTCHOOSE_H__
