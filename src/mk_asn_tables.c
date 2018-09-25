#include "config.h"
#include "ranges.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

//#define DEBUG
#ifdef DEBUG
# define DEBUG_PRINTF printf
#else
# define DEBUG_PRINTF(...)
#endif

range6 table6[100000] = { 0 };
const size_t table6_sz = sizeof(table6);
size_t n6 = 0;

range4 table4[1000000] = { 0 };
const size_t table4_sz = sizeof(table4);
size_t n4 = 0;

static inline int fprint_u128(FILE *f, u128 *ip)
{ return fprintf(f, "%.16" PRIX64 ":%.16" PRIX64, ip->ll.hi, ip->ll.lo); }

static inline int fprint_r6(FILE *f, range6 *r6)
{ if (!r6) return fprintf(f, "nill")
; fprint_u128(f, &r6->from); fprintf(f, "-")
; fprint_u128(f, &r6->till); return fprintf(f, " %d", r6->asn); }

static inline int fprint_r4(FILE *f, range4 *r4)
{ if (!r4) return fprintf(f, "nill")
; return fprintf(f, "%.8" PRIX32 "-%.8" PRIX32 " %d", r4->from, r4->till, r4->asn); }

static inline int cmp_u128(u128 *x, u128 *y)
{ return x->ll.hi > y->ll.hi ?  1
       : x->ll.hi < y->ll.hi ? -1
       : x->ll.lo > y->ll.lo ?  1
       : x->ll.lo < y->ll.lo ? -1 : 0; }

static inline void
bsearch6(u128 *key, size_t *lo, size_t *hi)
{
	size_t swap;

	*lo = 0;
	*hi = n6 ? n6 - 1 : 0;
	while (*hi > *lo) {
		size_t i;
		int r;

		if (cmp_u128(key, &table6[*lo].from) <= 0) {
			*hi = *lo;
			return;
		}
		if (cmp_u128(key, &table6[*hi].from) >= 0) {
			*lo = *hi;
			return;
		}
		i = (*hi + *lo) / 2;
		r = cmp_u128(key, &table6[i].from);
		if (r == 0) {
			*hi = *lo = i;
			return;
		}
		if (r > 0) {
			if (*lo == i) break;
			*lo = i;
		} else {
			if (*hi == i) break;
			*hi = i;
		}
	}
	if (*hi < *lo) {
		swap = *hi;
		*hi  = *lo;
		*lo  = swap;
	}
}

static inline void insert6(range6 *r6, size_t pos)
{
	memmove(table6 + pos + 1, table6 + pos, sizeof(range6) * (n6 - pos));
	table6[pos] = *r6;
	n6 += 1;
	assert(n6 < table6_sz);
	DEBUG_PRINTF("insert @ %zu\n", pos);
}
static inline void left_shrink6(u128 *from, size_t pos)
{
	table6[pos].from = *from;
	DEBUG_PRINTF("left shrink @ %zu\n", pos);
}
static inline void right_extend6(u128 *till, size_t pos)
{
	table6[pos].till = *till;
	DEBUG_PRINTF("right extend @ %zu\n", pos);
}
static inline void right_shrink6(u128 *till, size_t pos)
{
	table6[pos].till = *till;
	DEBUG_PRINTF("right shrink @ %zu\n", pos);
}
static inline void replace6(range6 *r6, size_t pos)
{
	table6[pos] = *r6;
	DEBUG_PRINTF("replace @ %zu\n", pos);
}

void add6(range6 *r6)
{
	int r;
	size_t hi, lo;

	if (!n6) {
		table6[n6++] = *r6;
		return;
	}
#ifdef DEBUG
	DEBUG_PRINTF("add "); fprint_r6(stdout, r6); DEBUG_PRINTF("\n");
#endif
	bsearch6(&r6->from, &lo, &hi);
#ifdef DEBUG
	DEBUG_PRINTF("add "); fprint_r6(stdout, r6); DEBUG_PRINTF("\n");
	DEBUG_PRINTF("lo: %zu, ", lo); fprint_r6(stdout, table6 + lo); DEBUG_PRINTF("\n");
	DEBUG_PRINTF("hi: %zu, ", hi); fprint_r6(stdout, table6 + hi); DEBUG_PRINTF("\n");
#endif
	if (lo == hi) {
		int ffc, tfc, ftc, ttc;
		
		ffc = cmp_u128(&r6->from, &table6[lo].from);
		assert(ffc >= 0);
		if (ffc == 0) {
			ttc = cmp_u128(&r6->till, &table6[lo].till);
			if (ttc < 0) {
				/* situation 6 */
				DEBUG_PRINTF("situation 6.\n");
				if (r6->asn != table6[lo].asn) {
					left_shrink6(&r6->till, lo);
					insert6(r6, lo);
				}
				return;
			}	
			assert(ttc == 0);
			/* situation 7 */
			DEBUG_PRINTF("situation 7. \n");
			replace6(r6, lo);
			return;
		}
		ftc = cmp_u128(&r6->from, &table6[lo].till);
		if (ftc < 0) {
			ttc = cmp_u128(&r6->till, &table6[lo].till);
			if (ttc < 0) {
				/* situation 9 */
				DEBUG_PRINTF("situation 9.\n");
				if (r6->asn == table6[lo].asn)
					return;
				insert6(&table6[lo], lo + 1);
				right_shrink6(&r6->from, lo);
				left_shrink6(&r6->till, lo + 1);
				insert6(r6, lo + 1);
				return;
			}
			assert(ttc == 0);
			/* situation 10 */
			DEBUG_PRINTF("situation 10.\n");
			if (r6->asn != table6[lo].asn) {
				right_shrink6(&r6->from, lo);
				insert6(r6, lo + 1);
			}
			return;

		} else if (ftc == 0) {
			/* situation 12 */
			DEBUG_PRINTF("situation 12.\n");
			assert(lo == n6 - 1);
			if (r6->asn == table6[lo].asn)
				right_extend6(&r6->till, lo);
			else	insert6(r6, lo + 1);
			return;
		}
		/* situation 13 */
		DEBUG_PRINTF("situation 13.\n");
		assert(lo == n6 - 1);
		insert6(r6, lo + 1);
		return;
	}
	int tfc1 = cmp_u128(&table6[lo].till, &r6->from);
	int tfc2 = cmp_u128(&r6->till, &table6[hi].from);
	assert(tfc1 == 1);
	assert(tfc2 <= 0);
	int ttc = cmp_u128(&r6->till, &table6[lo].till);
	//DEBUG_PRINTF("situation 14. (%d, %d, %d)\n", tfc1, tfc2, ttc);
	if (ttc < 0) {
		/* situation 14.9 */
		DEBUG_PRINTF("situation 14.9.\n");
		if (r6->asn == table6[lo].asn)
			return;
		insert6(&table6[lo], lo + 1);
		right_shrink6(&r6->from, lo);
		left_shrink6(&r6->till, lo + 1);
		insert6(r6, lo + 1);
		return;
	}
	assert(ttc == 0);
	/* situation 14.10 */
	DEBUG_PRINTF("situation 14.10.\n");
	if (r6->asn != table6[lo].asn) {
		right_shrink6(&r6->from, lo);
		insert6(r6, lo + 1);
	}
}

static inline void
bsearch4(uint32_t key, size_t *lo, size_t *hi)
{
	size_t swap;

	*lo = 0;
	*hi = n4 ? n4 - 1 : 0;
	while (*hi > *lo) {
		size_t i;

		if (key <= table4[*lo].from) {
			*hi = *lo;
			return;
		}
		if (key >= table4[*hi].from) {
			*lo = *hi;
			return;
		}
		i = (*hi + *lo) / 2;
		if (key == table4[i].from) {
			*hi = *lo = i;
			return;
		}
		if (key > table4[i].from) {
			if (*lo == i) break;
			*lo = i;
		} else {
			if (*hi == i) break;
			*hi = i;
		}
	}
	if (*hi < *lo) {
		swap = *hi;
		*hi  = *lo;
		*lo  = swap;
	}
}

static inline void insert4(range4 *r4, size_t pos)
{
	memmove(table4 + pos + 1, table4 + pos, sizeof(range4) * (n4 - pos));
	table4[pos] = *r4;
	n4 += 1;
	assert(n4 < table4_sz);
	DEBUG_PRINTF("insert @ %zu\n", pos);
}
static inline void left_shrink4(uint32_t from, size_t pos)
{
	table4[pos].from = from;
	DEBUG_PRINTF("left shrink @ %zu\n", pos);
}
static inline void right_extend4(uint32_t till, size_t pos)
{
	table4[pos].till = till;
	DEBUG_PRINTF("right extend @ %zu\n", pos);
}
static inline void right_shrink4(uint32_t till, size_t pos)
{
	table4[pos].till = till;
	DEBUG_PRINTF("right shrink @ %zu\n", pos);
}
static inline void replace4(range4 *r4, size_t pos)
{
	table4[pos] = *r4;
	DEBUG_PRINTF("replace @ %zu\n", pos);
}
static inline int cmp_u32(uint32_t x, uint32_t y)
{ return x == y ? 0 : x > y ? 1 : -1; }

void add4(range4 *r4)
{
	int r;
	size_t hi, lo;

	if (!n4) {
		table4[n4++] = *r4;
		return;
	}
#ifdef DEBUG
	DEBUG_PRINTF("add "); fprint_r4(stdout, r4); DEBUG_PRINTF("\n");
#endif
	bsearch4(r4->from, &lo, &hi);
#ifdef DEBUG
	DEBUG_PRINTF("lo: %zu, ", lo); fprint_r4(stdout, table4 + lo); DEBUG_PRINTF("\n");
	DEBUG_PRINTF("hi: %zu, ", hi); fprint_r4(stdout, table4 + hi); DEBUG_PRINTF("\n");
#endif

	if (lo == hi) {
		int ffc, tfc, ftc, ttc;
		
		ffc = cmp_u32(r4->from, table4[lo].from);
		assert(ffc >= 0);
		if (ffc == 0) {
			ttc = cmp_u32(r4->till, table4[lo].till);
			if (ttc < 0) {
				/* situation 6 */
				DEBUG_PRINTF("situation 6.\n");
				if (r4->asn != table4[lo].asn) {
					left_shrink4(r4->till, lo);
					insert4(r4, lo);
				}
				return;
			}	
			assert(ttc == 0);
			/* situation 7 */
			DEBUG_PRINTF("situation 7. \n");
			replace4(r4, lo);
			return;
		}
		ftc = cmp_u32(r4->from, table4[lo].till);
		if (ftc < 0) {
			ttc = cmp_u32(r4->till, table4[lo].till);
			if (ttc < 0) {
				/* situation 9 */
				DEBUG_PRINTF("situation 9.\n");
				if (r4->asn == table4[lo].asn)
					return;
				insert4(&table4[lo], lo + 1);
				right_shrink4(r4->from, lo);
				left_shrink4(r4->till, lo + 1);
				insert4(r4, lo + 1);
				return;
			}
			assert(ttc == 0);
			/* situation 10 */
			DEBUG_PRINTF("situation 10.\n");
			if (r4->asn != table4[lo].asn) {
				right_shrink4(r4->from, lo);
				insert4(r4, lo + 1);
			}
			return;

		} else if (ftc == 0) {
			/* situation 12 */
			DEBUG_PRINTF("situation 12.\n");
			assert(lo == n4 - 1);
			if (r4->asn == table4[lo].asn)
				right_extend4(r4->till, lo);
			else	insert4(r4, lo + 1);
			return;
		}
		/* situation 13 */
		DEBUG_PRINTF("situation 13.\n");
		assert(lo == n4 - 1);
		insert4(r4, lo + 1);
		return;
	}
	int tfc1 = cmp_u32(table4[lo].till, r4->from);
	int tfc2 = cmp_u32(r4->till, table4[hi].from);
	assert(tfc1 == 1);
	assert(tfc2 <= 0);
	int ttc = cmp_u32(r4->till, table4[lo].till);
	//DEBUG_PRINTF("situation 14. (%d, %d, %d)\n", tfc1, tfc2, ttc);
	if (ttc < 0) {
		/* situation 14.9 */
		DEBUG_PRINTF("situation 14.9.\n");
		if (r4->asn == table4[lo].asn)
			return;
		insert4(&table4[lo], lo + 1);
		right_shrink4(r4->from, lo);
		left_shrink4(r4->till, lo + 1);
		insert4(r4, lo + 1);
		return;
	}
	assert(ttc == 0);
	/* situation 14.10 */
	DEBUG_PRINTF("situation 14.10.\n");
	if (r4->asn != table4[lo].asn) {
		right_shrink4(r4->from, lo);
		insert4(r4, lo + 1);
	}
}

int main(int argc, const char **argv)
{
	int          r = EXIT_FAILURE;
	int         fd = -1;
	char       *rv = NULL, *ln, *eor;
	struct stat st;

	if (argc != 2 && argc != 3)
		printf("usage: %s <routeviews file> [<test IP>]\n", argv[0]);

	else if ((fd = open(argv[1], O_RDONLY)) < 0)
		fprintf(stderr, "Could not open \"%s\"\n", argv[1]);

	else if (fstat(fd, &st) < 0)
		fprintf(stderr, "Could not fstat \"%s\"\n", argv[1]);

	else if ((rv = mmap( NULL, st.st_size
	                   , PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		fprintf(stderr, "Could not mmap \"%s\"\n", argv[1]);

	else for (ln = rv, eor = rv + st.st_size; ln < eor;) {
		char    *sep;
		int      af;
		range6   r6;
		range4   r4;
		uint32_t swap;
		uint8_t  mask;

		if (!(sep = memchr(ln, '\t', eor - ln)))
			break;
		*sep = '\0';
		switch ((af = strchr(ln, ':') ? AF_INET6 : AF_INET)) {
		case AF_INET6 :	if ((r = inet_pton(af, ln, (void *)&r6.from)) != 1)
					break;
				swap = ntohl(r6.from.longs[0]);
				r6.from.longs[0] = ntohl(r6.from.longs[1]);
				r6.from.longs[1] = swap;
				swap = ntohl(r6.from.longs[2]);
				r6.from.longs[2] = ntohl(r6.from.longs[3]);
				r6.from.longs[3] = swap;
				break;
		case AF_INET  :	if ((r = inet_pton(af, ln, (void *)&r4.from)) != 1)
					break;
				r4.from = ntohl(r4.from);
				break;
		}
		if (r != 1) {
			fprintf(stderr, "Unparsable address \"%s\"\n", ln);
			break;
		}
		if ((ln = sep + 1) >= eor)
			break;
		if (!(sep = memchr(ln, '\t', eor - ln)))
			break;
		*sep = '\0';
		mask = atoi(ln);
		switch (af) {
		case AF_INET6 :	r6.till = r6.from;
				if (mask > 64)
					r6.till.ll.lo += ((uint64_t)1 << (128 - mask));
				else	r6.till.ll.hi += ((uint64_t)1 << ( 64 - mask));
				break;
		case AF_INET  :	r4.till = r4.from + ((uint32_t)1 << (32 - mask));
				break;
		}
		if ((ln = sep + 1) >= eor)
			break;
		if (!(sep = memchr(ln, '\n', eor - ln)))
			break;
		*sep = '\0';
		switch (af) {
		case AF_INET6 :	r6.asn = atoi(ln); add6(&r6); break;
		case AF_INET  :	r4.asn = atoi(ln); add4(&r4); break;
		}
#ifdef DEBUG
		switch (af) {
		case AF_INET6 :	printf("%.16" PRIX64 ":%.16" PRIX64 "/%" PRIu8 "\n"
				       "%.16" PRIX64 ":%.16" PRIX64 ": %d\n"
				      , r6.from.ll.hi, r6.from.ll.lo, mask
				      , r6.till.ll.hi, r6.till.ll.lo, asn);
				break;
		case AF_INET  :	printf("%.8" PRIX32 "/%" PRIu8 "\n%.8" PRIX32 ": %d\n"
				      , r4.from, mask, r4.till, asn);
				break;
		}
#endif
		ln = sep + 1;
	}
	if (n4) {
		size_t i;

		for (i = 0; i < n4 ; i++) {
			printf("\t{ UINT32_C(0x%.8" PRIx32 "), UINT32_C(0x%.8" PRIx32 "), %6d },\n"
			     , table4[i].from, table4[i].till, table4[i].asn);
		}
	}
	if (n6) {
		size_t i;

		for (i = 0; i < n6 ; i++) {
			printf("\t{ .from = { .ll = { UINT64_C(0x%.16" PRIX64 ")\n"
			       "\t                  , UINT64_C(0x%.16" PRIX64 ") } }\n"
			     , table6[i].from.ll.hi, table6[i].from.ll.lo);
			printf("\t, .till = { .ll = { UINT64_C(0x%.16" PRIX64 ")\n"
			       "\t                  , UINT64_C(0x%.16" PRIX64 ") } }, "
			     , table6[i].till.ll.hi, table6[i].till.ll.lo);
			printf("%6d },\n", table6[i].asn);
		}
	}

	if (rv && rv != MAP_FAILED) {
		munmap(rv, st.st_size);
		r = ln >= eor ?  EXIT_SUCCESS : EXIT_FAILURE;
	}
	if (fd > 0)
		close(fd);
	return r;
}
