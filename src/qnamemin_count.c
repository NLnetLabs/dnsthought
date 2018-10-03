#include "config.h"
#include "dnst.h"
#include "rbtree.h"
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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const uint8_t ipv4_mapped_ipv6_prefix[] =
    "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\xFF\xFF";


typedef struct asn_count {
	size_t count;
	int asn;
} asn_count;

typedef struct asn_counter {
	rbnode_type byasn;
	rbnode_type bycount;

	asn_count ac;
} asn_counter;

static int asncmp(const void *x, const void *y)
{ return *(int *)x == *(int *)y ? 0 : *(int *)x < *(int *)y ? -1 : 1; };
static int countcmp(const void *x, const void *y)
{ return *(size_t *)x == *(size_t *)y ? 0 : *(size_t *)x > *(size_t *)y ? -1 : 1; };

static rbtree_type byasn = { RBTREE_NULL, 0, asncmp };
static rbtree_type bycount = { RBTREE_NULL, 0, countcmp };

void cap_top20_asn(cap_counter *cap)
{
	rbtree_type counts = { RBTREE_NULL, 0, countcmp };
	asn_counter *c;
	rbnode_type *n;
	size_t i;

	RBTREE_FOR(c, asn_counter *, &cap->auth_asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&counts, &c->bycount);
	}
	i = 0;
	RBTREE_FOR(n, rbnode_type *, &counts) {
		const asn_count *ac = n->key;
		printf("ASN %6d, count: %5zu\n", ac->asn, ac->count);
		if (i++ == 20)
			break;
	}
}

void cap_counter_init(cap_counter *cap)
{
	memset(cap, 0, sizeof(cap_counter));
	rbtree_init(&cap->auth_asns, asncmp);
}

void count_cap(cap_counter *cap, dnst_rec *rec, int incr_n_probes)
{
	size_t i;
	int asn = -1;
	asn_counter *c;

	cap->n_resolvers++;
	if (incr_n_probes)
		cap->n_probes++;

	for (i = 0; i < 12; i++)
		cap->res.dnskey_alg[i][rec->dnskey_alg[i]]++;
	for (i = 0; i < 2; i++)
		cap->res.ds_alg[i][rec->ds_alg[i]]++;
	cap->res.qnamemin[rec->qnamemin]++;
	cap->res.tcp_ipv4[rec->tcp_ipv4]++;
	cap->res.tcp_ipv6[rec->tcp_ipv6]++;
	cap->res.nxdomain[rec->nxdomain]++;

	cap->res.has_ta_19036[rec->has_ta_19036]++;
	cap->res.has_ta_20326[rec->has_ta_20326]++;

	if ((asn = lookup_asn4(rec->whoami_g)))
		; /* pass */
	else if (!(asn = lookup_asn4(rec->whoami_a)))
		asn = lookup_asn6(rec->whoami_6);
	
	if ((c = (void *)rbtree_search(&cap->auth_asns, &asn)))
		c->ac.count++;

	else if ((c = calloc(1, sizeof(asn_counter)))) {
		c->ac.asn = asn;
		c->ac.count = 1;
		c->byasn.key = &c->ac.asn;
		rbtree_insert(&cap->auth_asns, &c->byasn);
	}
}

static inline int back_one_day(struct tm *tm)
{ tm->tm_mday -= 1; mktime(tm); return 0; }

int main(int argc, const char **argv)
{
	const char *endptr;
	const char *datestr;
	struct tm   today;
	dnst_rec   *recs = NULL, *rec;
	size_t    n_recs;
	int         fd = -1;
	struct stat st;
	cap_counter cap, qnamemincap[4];
	uint32_t    prev_prb_id = 0xFFFFFFFF;
	size_t      res_by_prb[65536];
	size_t      qres_by_prb[sizeof(res_by_prb)];
	size_t      i;
	
	assert(sizeof(dnst_rec) == 104);

	cap_counter_init(&cap);
	for (i = 0; i < sizeof(qnamemincap) / sizeof(cap_counter); i++)
		cap_counter_init(&qnamemincap[i]);
	memset(&today, 0, sizeof(today));
	memset(&res_by_prb, 0, sizeof(res_by_prb));
	memset(&qres_by_prb, 0, sizeof(qres_by_prb));

	if (argc != 2)
		printf("usage: %s <resfile>\n", argv[0]);

	else if (!(endptr = strptime(
	    ((datestr = strrchr(argv[1], '/')) ? datestr + 1 : argv[1]),
	    "%Y-%m-%d.res", &today)) || *endptr)
		fprintf(stderr, "Could not filename \"%s\", should be of form \"%s\"\n"
		        , argv[1], "YYYY-MM-DD.res");

	else if (back_one_day(&today))
		; /* cannot happen */

	else if ((fd = open(argv[1], O_RDONLY)) < 0)
		fprintf(stderr, "Could not open \"%s\"\n", argv[1]);

	else if (fstat(fd, &st) < 0)
		fprintf(stderr, "Could not fstat \"%s\"\n", argv[1]);

	else if ((recs = mmap( NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0))
			== MAP_FAILED)
		fprintf(stderr, "Could not mmap \"%s\"\n", argv[1]);

	else for ( n_recs = st.st_size / sizeof(dnst_rec), rec = recs
	         ; n_recs > 0
		 ; n_recs--, rec++) {

		char addrstr[80];
		char timestr[80];
		struct tm tm;
		time_t t = rec->updated;
		int incr_probes = rec->key.prb_id != prev_prb_id;

		gmtime_r(&t, &tm);
		if (tm.tm_mday != today.tm_mday
		||  tm.tm_mon  != today.tm_mon
		||  tm.tm_year != today.tm_year)
			continue;

		assert(rec->key.prb_id < sizeof(res_by_prb));
		res_by_prb[rec->key.prb_id]++;
		if (rec->qnamemin == CAP_DOES)
			qres_by_prb[rec->key.prb_id]++;

		count_cap(&cap, rec, incr_probes);
		count_cap(qnamemincap + rec->qnamemin, rec, incr_probes);

		if (rec->key.prb_id != prev_prb_id)
			prev_prb_id = rec->key.prb_id;

		/*
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M.%S", &tm);
		if (memcmp(rec->key.addr, ipv4_mapped_ipv6_prefix, 12) == 0)
			inet_ntop(AF_INET, &rec->key.addr[12], addrstr, sizeof(addrstr));
		else
			inet_ntop(AF_INET6, rec->key.addr    , addrstr, sizeof(addrstr));

		printf("[%s] %" PRIu32 " %s\n", timestr, rec->key.prb_id, addrstr); 
		*/
	}
	size_t n_res_per_qprb = 0, n_qres_per_qprb = 0, n_qnamemin_only = 0, n_res_qnamemin_only = 0;
	for (i = 0; i < sizeof(res_by_prb); i++) {
		if (qres_by_prb[i]) {
			n_qres_per_qprb += qres_by_prb[i];
			n_res_per_qprb += res_by_prb[i];
			if (qres_by_prb[i] == res_by_prb[i]) {
				n_qnamemin_only++;
				n_res_qnamemin_only += res_by_prb[i];
			}
		}
	}
	printf("%.4d-%.2d-%.2d,%zu,%zu,%zu,%zu,%f,%zu,%zu\n"
	      , (int)today.tm_year + 1900, (int)today.tm_mon + 1, (int)today.tm_mday
	      , qnamemincap[1].n_resolvers+ qnamemincap[2].n_resolvers
	      , qnamemincap[1].n_probes   + qnamemincap[2].n_probes
	      , qnamemincap[1].n_resolvers, qnamemincap[1].n_probes
	      , (float)n_qres_per_qprb / (float)n_res_per_qprb
	      , n_res_qnamemin_only, n_qnamemin_only
	      );
	cap_top20_asn(&cap);
	cap_top20_asn(&qnamemincap[1]);

	if (recs && recs != MAP_FAILED)
		munmap(recs, st.st_size);
	if (fd > 0)
		close(fd);
	return 0;
}
