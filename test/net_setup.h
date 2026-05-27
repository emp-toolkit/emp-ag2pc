#ifndef AG2PC_TEST_NET_SETUP_H__
#define AG2PC_TEST_NET_SETUP_H__
#include "emp-tool/io/net_io_channel.h"
#include <cstdlib>

// Two-party test transport: one NetIO to the peer (party 1 server, party 2
// client, both on `port`). The protocol spawns its own sibling channel
// internally (NetIO::make_sibling). Party 2 dials AG2PC_PEER if set (for
// cross-machine runs), else 127.0.0.1 (local).
inline void make_io2pc(int party, int port, emp::NetIO *&io) {
  using emp::NetIO;
  const char *peer = std::getenv("AG2PC_PEER");
  io = (party == 1) ? new emp::NetIO(nullptr, port)
                    : new emp::NetIO(peer ? peer : "127.0.0.1", port);
}
#endif  // AG2PC_TEST_NET_SETUP_H__
