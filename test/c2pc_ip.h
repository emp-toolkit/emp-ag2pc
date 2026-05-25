#ifndef C2PC_TEST_IP_H__
#define C2PC_TEST_IP_H__

// Per-party address table for multi-host test runs. 1-based: IP[p] is the
// address of party p. All loopback by default; pass to NetIOMP's `ip` argument
// (NetIOMP defaults to loopback when none is given, so loopback runs need not
// use this).
const static char *IP[] = {"",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
    "127.0.0.1"};

#endif // C2PC_TEST_IP_H__
