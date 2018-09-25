#include "config.h"
#include "ranges.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

extern const range6 ranges6[];
extern const size_t ranges6_sz;
extern const range4 ranges4[];
extern const size_t ranges4_sz;

int keycmp4(const void *x, const void *y)
{
	const uint32_t *key = x;
	const range4   *r4 = y;

	return *key == r4->from ?  0
	     : *key  < r4->from ? -1
	     : *key  < r4->till ?  0 : 1;
}

int lookup_asn4(void *ipv4)
{
	uint32_t key = ntohl(*((uint32_t *)ipv4));
	range4   key_spc;
	range4  *res = bsearch( &key, ranges4
	                      , ranges4_sz, sizeof(range4), keycmp4);
	if (res)
		return res->asn;
	return 0;
}

static inline int cmp_u128(const u128 *x, const u128 *y)
{ return x->ll.hi > y->ll.hi ?  1
       : x->ll.hi < y->ll.hi ? -1
       : x->ll.lo > y->ll.lo ?  1
       : x->ll.lo < y->ll.lo ? -1 : 0; }

static inline int fprint_u128(FILE *f, const u128 *ip)
{ return fprintf(f, "%.16" PRIX64 ":%.16" PRIX64, ip->ll.hi, ip->ll.lo); }

int keycmp6(const void *x, const void *y)
{
	const u128   *key = x;
	const range6 *r6 = y;
	return cmp_u128(key, &r6->from) == 0 ?  0
	     : cmp_u128(key, &r6->from)  < 0 ? -1
	     : cmp_u128(key, &r6->till)  < 0 ?  0 : 1;
}

static const uint8_t ipv4_mapped_ipv6_prefix[] =
    "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\xFF\xFF";

int lookup_asn6(void *ipv6)
{
	u128 orig, key;
	range6 *res;

	if (memcmp(ipv6, ipv4_mapped_ipv6_prefix, 12) == 0)
		return lookup_asn4(((uint8_t *)ipv6) + 12);

	memcpy(orig.bytes, ipv6, 16);
	key.longs[0] = ntohl(orig.longs[1]);
	key.longs[1] = ntohl(orig.longs[0]);
	key.longs[2] = ntohl(orig.longs[3]);
	key.longs[3] = ntohl(orig.longs[2]);

	res = bsearch( &key, ranges6
	             , ranges6_sz, sizeof(range6), keycmp6);
	if (res)
		return res->asn;
	return 0;
}
