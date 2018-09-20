#ifndef __RANGES_H_
#define __RANGES_H_
#include "config.h"
#include <stdint.h>

typedef union {
	__uint128_t v;
	struct {
		uint64_t hi;
		uint64_t lo;
	} ll;
	uint32_t longs[4];
	uint8_t  bytes[16];
} u128;

typedef struct range6 {
	u128 from;
	u128 till;
	int  asn;
} range6;

void add6(range6 *r6);
int lookup_asn6(void *);

typedef struct range4 {
	uint32_t from;
	uint32_t till;
	int      asn;
} range4;

void add4(range4 *r4);
int lookup_asn4(void *);

#endif
