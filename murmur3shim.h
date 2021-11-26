#ifndef _MURMUR3SHIM_H
#define _MURMUR3SHIM_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
	uint32_t murmurhash3(const void* key, int len, uint32_t seed);
#ifdef __cplusplus
}
#endif

#endif
