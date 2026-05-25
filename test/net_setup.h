#ifndef AG2PC_TEST_NET_SETUP_H__
#define AG2PC_TEST_NET_SETUP_H__
#include "emp-tool/io/net_io_channel.h"

// Two-party test transport: create the duplex pair of NetIO channels (io1 on
// `port`, io2 on `port+1`) and hand them to the protocol constructors. Party 1
// is the server on io1 / client on io2; party 2 is the mirror, so io1/io2 name
// the same physical connection on both sides. Loopback only (tests run all
// parties locally).
inline void make_io2pc(int party, int port, emp::NetIO *&io1, emp::NetIO *&io2) {
  using emp::NetIO;
  if (party == 1) {
    io1 = new NetIO(nullptr, port);             // server
    io2 = new NetIO("127.0.0.1", port + 1);     // client
  } else {
    io1 = new NetIO("127.0.0.1", port);         // client
    io2 = new NetIO(nullptr, port + 1);         // server
  }
}
#endif  // AG2PC_TEST_NET_SETUP_H__
