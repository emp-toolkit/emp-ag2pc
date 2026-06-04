#ifndef AG2PC_PROFILING_H__
#define AG2PC_PROFILING_H__

// ===========================================================================
// One opt-in profiling flag for the whole protocol.
//
// Compile with -DAG2PC_PROFILE (or #define before include) to turn on ALL
// instrumentation; build without it for a zero-cost release. Everything lives
// here so it can be enabled/disabled in one place:
//
//   * AG2PC_PHASE(name)        per-step wall time + this party's send+recv byte
//                              delta + peak RSS  (the [ag2pc] lines). Requires
//                              io_count / send_io / recv_io / party visible at
//                              the call site — the macro expands there.
//   * AG2PC_TP(name)           leaky-AND sub-phase wall timer (the [ag2pc-tp] lines).
//   * g_tp_* / g_ag2pc_*       sub-phase accumulators + COT/phi byte counters.
//   * ag2pc_peak_rss_kib()     monotonic peak RSS (KiB); the jump between two
//                              steps is that step's footprint contribution.
//   * ag2pc_mem_row()          one per-array byte-census row ([ag2pc-mem]).
// ===========================================================================

#ifdef AG2PC_PROFILE
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/resource.h>

// This party's send+recv bytes in the half-gate phi exchange and (separately)
// the COT extension.
inline uint64_t g_ag2pc_phi_bytes = 0;
inline uint64_t g_ag2pc_cot_bytes = 0;
// Sub-phase wall accumulators for the layered leaky-AND (reset per compute_*):
// cot = COT extend (gen_cot_shares); hg = half-gate join; sopen = s-open exchange;
// feq = F_eq; bkt = bucket_one_layer (incl. its d-open).
inline uint64_t g_tp_cot_ns = 0, g_tp_hg_ns = 0;
inline uint64_t g_tp_sopen_ns = 0, g_tp_feq_ns = 0, g_tp_bkt_ns = 0;
inline uint64_t tp_now_ns() {
  return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Peak resident set so far (KiB). Monotonic, so sampling at step boundaries
// localizes which step grows the footprint. macOS getrusage reports ru_maxrss in
// bytes, Linux in KiB.
inline long ag2pc_peak_rss_kib() {
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
  return ru.ru_maxrss / 1024;
#else
  return ru.ru_maxrss;
#endif
}
// One row of the per-array byte census: total MiB and bytes per AND gate.
inline void ag2pc_mem_row(const char *label, double bytes, double div) {
  printf("[ag2pc-mem]   %-18s %10.2f MiB  %9.1f B/AND\n", label,
         bytes / (1024.0 * 1024.0), div > 0 ? bytes / div : 0.0);
}

// Per-step time + comm + peak RSS. Expands at the call site, so it needs
// io_count(send_io, recv_io) and `party` visible there.
#define AG2PC_PHASE_BEGIN()                                                      \
  auto _ag2pc_t = std::chrono::steady_clock::now();                              \
  int64_t _ag2pc_c = io_count(send_io, recv_io)
#define AG2PC_PHASE(name)                                                        \
  do {                                                                           \
    auto _n = std::chrono::steady_clock::now();                                  \
    int64_t _c = io_count(send_io, recv_io);                                     \
    if (party == 1)                                                              \
      printf("[ag2pc] %-22s %9.3f ms  %12lld B  peakRSS %8ld KiB\n", (name),     \
             std::chrono::duration<double, std::milli>(_n - _ag2pc_t).count(),   \
             (long long)(_c - _ag2pc_c), ag2pc_peak_rss_kib());                  \
    _ag2pc_t = _n;                                                               \
    _ag2pc_c = _c;                                                               \
  } while (0)

// Leaky-AND sub-phase timer: elapsed since the last marker, printed at party 1.
#define AG2PC_TP_BEGIN() auto _tp_t = std::chrono::steady_clock::now()
#define AG2PC_TP(name)                                                           \
  do {                                                                           \
    auto _n = std::chrono::steady_clock::now();                                  \
    if (party == 1)                                                              \
      printf("[ag2pc-tp]   %-24s %9.3f ms\n", (name),                            \
             std::chrono::duration<double, std::milli>(_n - _tp_t).count());     \
    _tp_t = _n;                                                                  \
  } while (0)

#else  // !AG2PC_PROFILE
#define AG2PC_PHASE_BEGIN() ((void)0)
#define AG2PC_PHASE(name) ((void)0)
#define AG2PC_TP_BEGIN() ((void)0)
#define AG2PC_TP(name) ((void)0)
#endif

#endif  // AG2PC_PROFILING_H__
