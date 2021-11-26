#include "murmur3shim.h"
#include <MurmurHash3.h>

extern "C" {

uint32_t murmurhash3(const void* key, int len, uint32_t seed) //<<<
{
	uint32_t	out;
	MurmurHash3_x86_32(key, len, seed, &out);
	return out;
}

//>>>

}

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
