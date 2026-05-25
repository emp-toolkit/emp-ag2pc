#ifndef NETIOMP_H__
#define NETIOMP_H__
#include "emp-tool/io/net_io_channel.h"
#include <atomic>
#include <thread>
#include <vector>

using namespace emp;

template <int nP> class NetIOMP {
public:
  NetIO *ios[nP + 1];
  NetIO *ios2[nP + 1];
  int party;
  bool sent[nP + 1];

  // Symmetric pairwise mesh. For each peer p != party we open two TCP
  // connections so each direction has its own duplex channel. Convention:
  // for pair (i, j) with i < j, the smaller party drives the `ios` slot's
  // connect; the larger party drives the `ios2` slot's connect.
  // Each endpoint listens on `port + party`. One connector thread per
  // peer; the main thread runs the matching accepts. `ip` supplies a per-party
  // address table (1-based; ip[p] for peer p); nullptr means loopback for all.
  NetIOMP(int party, int port, const char *const *ip = nullptr) {
    this->party = party;
    memset(sent, false, nP + 1);
    for (int i = 0; i <= nP; ++i) {
      ios[i] = nullptr;
      ios2[i] = nullptr;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("netiomp socket"); exit(1); }
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(port + party);
    if (bind(listen_fd, (sockaddr *)&serv, sizeof(serv)) < 0) { perror("netiomp bind"); exit(1); }
    if (listen(listen_fd, nP) < 0) { perror("netiomp listen"); exit(1); }

    auto connect_to = [&](int peer) -> int {
      int peer_port = port + peer;
      while (true) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(ip ? ip[peer] : "127.0.0.1");
        dest.sin_port = htons(peer_port);
        if (connect(sock, (sockaddr *)&dest, sizeof(dest)) == 0) {
          uint16_t hs = (uint16_t)party;
          if (write(sock, &hs, sizeof(hs)) != (ssize_t)sizeof(hs)) {
            fprintf(stderr, "netiomp handshake send failed\n"); exit(1);
          }
          return sock;
        }
        close(sock);
        usleep(1000);
      }
    };

    // One connector thread per peer. We connect on `ios[p]` if we're the
    // smaller party of the pair, otherwise on `ios2[p]`.
    std::vector<std::thread> connectors;
    connectors.reserve(nP - 1);
    for (int p = 1; p <= nP; ++p) if (p != party) {
      connectors.emplace_back([this, p, &connect_to] {
        int sock = connect_to(p);
        auto *netio = new NetIO(sock, true);
        if (this->party < p) ios[p]  = netio;
        else                 ios2[p] = netio;
      });
    }

    // Main thread accepts the matching (nP-1) connections. The handshake
    // tells us which peer connected; the slot is determined by sign(peer-party):
    // if peer < party, peer is the smaller party of the pair → its connect
    // landed on ios[peer]; if peer > party, peer drove ios2[peer].
    for (int k = 0; k < nP - 1; ++k) {
      sockaddr_in cli; socklen_t clilen = sizeof(cli);
      int fd = accept(listen_fd, (sockaddr *)&cli, &clilen);
      if (fd < 0) { perror("netiomp accept"); exit(1); }
      uint16_t peer;
      if (read(fd, &peer, sizeof(peer)) != (ssize_t)sizeof(peer)) {
        fprintf(stderr, "netiomp handshake recv failed\n"); exit(1);
      }
      auto *netio = new NetIO(fd, true);
      if ((int)peer < party) ios[(int)peer]  = netio;
      else                   ios2[(int)peer] = netio;
    }
    for (auto &t : connectors) t.join();

    close(listen_fd);
  }
  int64_t count() {
    int64_t res = 0;
    for (int i = 1; i <= nP; ++i)
      if (i != party) {
        res += ios[i]->send_counter + ios[i]->recv_counter;
        res += ios2[i]->send_counter + ios2[i]->recv_counter;
      }
    return res;
  }

  ~NetIOMP() {
    for (int i = 1; i <= nP; ++i)
      if (i != party) {
        delete ios[i];
        delete ios2[i];
      }
  }
  void send_data(int dst, const void *data, size_t len) {
    if (dst != 0 and dst != party) {
      if (party < dst)
        ios[dst]->send_data(data, len);
      else
        ios2[dst]->send_data(data, len);
      sent[dst] = true;
    }
  }
  void recv_data(int src, void *data, size_t len) {
    if (src != 0 and src != party) {
      // No auto-flush of the send stream here: callers already flush
      // before any round-trip, and acquiring flockfile() on the send
      // stream from a recv thread can deadlock against a pool thread
      // that's blocked in write() holding that same stdio lock.
      if (src < party)
        ios[src]->recv_data(data, len);
      else
        ios2[src]->recv_data(data, len);
    }
  }
  NetIO *&get(size_t idx, bool b = false) {
    if (b)
      return ios[idx];
    else
      return ios2[idx];
  }
  void flush(int idx = 0) {
    if (idx == 0) {
      for (int i = 1; i <= nP; ++i)
        if (i != party) {
          ios[i]->flush();
          ios2[i]->flush();
        }
    } else {
      if (party < idx)
        ios[idx]->flush();
      else
        ios2[idx]->flush();
    }
  }
  void sync() {
    for (int i = 1; i <= nP; ++i)
      for (int j = 1; j <= nP; ++j)
        if (i < j) {
          if (i == party) {
            ios[j]->sync();
            ios2[j]->sync();
          } else if (j == party) {
            ios[i]->sync();
            ios2[i]->sync();
          }
        }
  }
};
#endif // NETIOMP_H__
