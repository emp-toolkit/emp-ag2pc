#ifndef __HELPER
#define __HELPER
#include <emp-tool/emp-tool.h>
#include "c2pc_config.h"
using std::future;
using std::cout;
using std::endl;
using std::flush;

namespace emp {

void send_bool(NetIO * io, const bool * data, int length) {
	if(lan_network) {
		io->send_data(data, length);
		return;
	}
	for(int i = 0; i < length;) {
		uint64_t tmp = 0;
		for(int j = 0; j < 64 and i < length; ++i,++j) {
			if(data[i])
				tmp|=(0x1ULL<<j);
		}
		io->send_data(&tmp, 8);
	}
}

void recv_bool(NetIO * io, bool * data, int length) {
	if(lan_network) {
		io->recv_data(data, length);
		return;
	}
	for(int i = 0; i < length;) {
		uint64_t tmp = 0;
		io->recv_data(&tmp, 8);
		for(int j = 63; j >= 0 and i < length; ++i,--j) {
			data[i] = (tmp&0x1) == 0x1;
			tmp>>=1;
		}
	}
}

template<int B>
void send_partial_block(NetIO * io, const block * data, int length) {
	for(int i = 0; i < length; ++i) {
		io->send_data(&(data[i]), B);
	}
}

template<int B>
void recv_partial_block(NetIO * io, block * data, int length) {
	for(int i = 0; i < length; ++i) {
		io->recv_data(&(data[i]), B);
	}
}
}
#endif// __HELPER