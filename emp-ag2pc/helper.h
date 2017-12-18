#ifndef __HELPER
#define __HELPER
#include <emp-tool/emp-tool.h>
#include "c2pc_config.h"
#include <immintrin.h>

using std::future;
using std::cout;
using std::endl;
using std::flush;
#undef align

namespace emp {

void send_bool_aligned(NetIO* io, const bool * data, int length) {
	unsigned long long * data64 = (unsigned long long * )data;
	int i = 0;
#if !defined(__BMI2__)
	unsigned long long mask;
#endif
	for(; i < length/8; ++i) {
		unsigned long long tmp;
#if defined(__BMI2__)
		tmp = _pext_u64(data64[i], 0x0101010101010101ULL);
#else
		// https://github.com/Forceflow/libmorton/issues/6
		tmp = 0;
		mask = 0x0101010101010101ULL;
		for (unsigned long long bb = 1; mask != 0; bb += bb) {
			if (data64[i] & mask & -mask) { tmp |= bb; }
			mask &= (mask - 1);
		}
#endif
		io->send_data(&tmp, 1);
	}
	if (8*i != length)
		io->send_data(data + 8*i, length - 8*i);
}
void recv_bool_aligned(NetIO* io, bool * data, int length) {
	unsigned long long * data64 = (unsigned long long *) data;
	int i = 0;
#if !defined(__BMI2__)
	unsigned long long mask;
#endif
	for(; i < length/8; ++i) {
		unsigned long long tmp = 0;
		io->recv_data(&tmp, 1);
#if defined(__BMI2__)
		data64[i] = _pdep_u64(tmp, (unsigned long long) 0x0101010101010101ULL);
#else
		data64[i] = 0;
		mask = 0x0101010101010101ULL;
                for (unsigned long long bb = 1; mask != 0; bb += bb) {
                        if (tmp & bb) {data64[i] |= mask & (-mask); }
                        mask &= (mask - 1);
                }
#endif
	}
	if (8*i != length)
		io->recv_data(data + 8*i, length - 8*i);
}
void send_bool(NetIO * io, bool * data, int length) {
	void * ptr = (void *)data;
	size_t space = length;
	void * aligned = std::align(alignof(uint64_t), sizeof(uint64_t), ptr, space);
	int diff = length - space;
	io->send_data(data, diff);
	send_bool_aligned(io, (const bool*)aligned, length - diff);
}

void recv_bool(NetIO * io, bool * data, int length) {
	void * ptr = (void *)data;
	size_t space = length;
	void * aligned = std::align(alignof(uint64_t), sizeof(uint64_t), ptr, space);
	int diff = length - space;
	io->recv_data(data, diff);
	recv_bool_aligned(io, (bool*)aligned, length - diff);
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
