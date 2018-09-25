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

typedef struct ecs_mask_count {
	size_t count;
	uint8_t ecs_mask;
} ecs_mask_count;

typedef struct ecs_mask_counter {
	rbnode_type byecs_mask;
	rbnode_type bycount;

	ecs_mask_count ec;
} ecs_mask_counter;

static int ecs_maskcmp(const void *x, const void *y)
{ return *(uint8_t *)x == *(uint8_t *)y ? 0 : *(uint8_t *)x < *(uint8_t *)y ? -1 : 1; };

void cap_top20_asn(cap_counter *cap)
{
	rbtree_type counts = { RBTREE_NULL, 0, countcmp };
	asn_counter *c;
	rbnode_type *n;
	size_t i;

	RBTREE_FOR(c, asn_counter *, &cap->asns) {
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
	rbtree_init(&cap->asns, asncmp);
	rbtree_init(&cap->ecs_masks, ecs_maskcmp);
}

static uint8_t const * const zeros =
    (uint8_t const * const) "\x00\x00\x00\x00\x00\x00\x00\x00"
                            "\x00\x00\x00\x00\x00\x00\x00\x00";

static const cap_descr caps[] = {
	{ 2, { "can_ipv6"     } },
	{ 2, { "can_tcp"      } },
	{ 2, { "can_tcp6"     } },
	{ 2, { "does_ecs"     } },
	//{ 3, { "internal"     , "external"        } },
	{ 3, { "does_qnamemin", "doesnt_qnamemin" } },
	{ 3, { "does_nxdomain", "doesnt_nxdomain" } },
	{ 3, { "has_ta_19036" , "hasnt_ta_19036"  } },
	{ 3, { "has_ta_20326" , "hasnt_ta_20326"  } },
	{ 4, { "can_rsamd5"   , "cannot_rsamd5"   , "broken_rsamd5"    } },
	{ 4, { "can_dsa"      , "cannot_dsa"      , "broken_dsa"       } },
	{ 4, { "can_rsasha1"  , "cannot_rsasha1"  , "broken_rsasha1"   } },
	{ 4, { "can_dsansec3" , "cannot_dsansec3" , "broken_dsansec3"  } },
	{ 4, { "can_rsansec3" , "cannot_rsansec3" , "broken_rsannsec3" } },
	{ 4, { "can_rsasha256", "cannot_rsasha256", "broken_rsasha256" } },
	{ 4, { "can_rsasha512", "cannot_rsasha512", "broken_rsasha512" } },
	{ 4, { "can_eccgost"  , "cannot_eccgost"  , "broken_ecchost"   } },
	{ 4, { "can_ecdsa256" , "cannot_ecdsa256" , "broken_ecdsa256"  } },
	{ 4, { "can_ecdsa384" , "cannot_ecdsa384" , "broken_ecdsa384"  } },
	{ 4, { "can_ed25519"  , "cannot_ed25519"  , "broken_ed25519"   } },
	{ 4, { "can_ed448"    , "cannot_ed448"    , "broken_ed448"     } },
	{ 4, { "can_gost"     , "cannot_gost"     , "broken_gost"      } },
	{ 4, { "can_sha384"   , "cannot_sha384"   , "broken_sha384"    } }
};
static const size_t n_caps = sizeof(caps) / sizeof(cap_descr);

void count_cap(cap_counter *cap, dnst_rec *rec, int incr_n_probes)
{
	size_t i;
	int asn = -1, has_ipv6 = 0;
	asn_counter *c;
	ecs_mask_counter *e;

	cap->n_resolvers++;
	if (incr_n_probes)
		cap->n_probes++;

	for (i = 0; i < 12; i++)
		cap->dnskey_alg[i][rec->dnskey_alg[i]]++;
	for (i = 0; i < 2; i++)
		cap->ds_alg[i][rec->ds_alg[i]]++;
	cap->qnamemin[rec->qnamemin]++;
	cap->tcp_ipv4[rec->tcp_ipv4]++;
	cap->tcp_ipv6[rec->tcp_ipv6]++;
	cap->nxdomain[rec->nxdomain]++;

	cap->has_ta_19036[rec->has_ta_19036]++;
	cap->has_ta_20326[rec->has_ta_20326]++;

	if (memcmp(rec->whoami_6, zeros, 16))
		has_ipv6 = CAP_CAN;
	cap->has_ipv6[has_ipv6]++;

	if (rec->ecs_mask != 0)
		cap->does_ecs[CAP_DOES]++;

	if (memcmp(rec->whoami_g, zeros, 4) != 0
	&& (asn = lookup_asn4(rec->whoami_g)))
		; /* pass */
	else if (memcmp(rec->whoami_a, zeros, 4) != 0
	&& (asn = lookup_asn4(rec->whoami_a)))
		; /* pass */
	else if (has_ipv6)
		asn = lookup_asn6(rec->whoami_6);
#if 0
	if (asn > 0) {
		int probe_asn = lookup_asn4(rec->key.addr);
		if (probe_asn > 0) {
			if (asn == probe_asn)
				cap->int_ext[CAP_INTERN]++;
			else	cap->int_ext[CAP_EXTERN]++;
		}
	}
#endif
	if (asn > 0) {
		if ((c = (void *)rbtree_search(&cap->asns, &asn)))
			c->ac.count++;

		else if ((c = calloc(1, sizeof(asn_counter)))) {
			c->ac.asn = asn;
			c->ac.count = 1;
			c->byasn.key = &c->ac.asn;
			rbtree_insert(&cap->asns, &c->byasn);
		}
	}
	if (rec->ecs_mask) {
		if ((e = (void *)rbtree_search(&cap->ecs_masks, &rec->ecs_mask)))
			e->ec.count++;

		else if ((e = calloc(1, sizeof(ecs_mask_counter)))) {
			e->ec.ecs_mask = rec->ecs_mask;
			e->ec.count = 1;
			e->byecs_mask.key = &e->ec.ecs_mask;
			rbtree_insert(&cap->ecs_masks, &e->byecs_mask);
		}
	}
}

static const size_t n_asns = 10;
static const size_t n_ecs_masks = 10;

void cap_log(FILE *f, cap_counter *cap)
{
	size_t *counter = counter_values(cap);
	rbtree_type counts = { RBTREE_NULL, 0, countcmp };
	asn_counter *c;
	ecs_mask_counter *e;
	rbnode_type *n;
	size_t i, remain;

	fprintf(f, ",%zu,%zu", cap->n_resolvers, cap->n_probes);
	for (i = 0; i < n_caps; i++) {
		const cap_descr *d = caps + i;
		uint8_t j;
		for (j = 1; j < d->n_vals; j++)
			//fprintf(f,",%s: %zu", d->val_names[j-1], counter[j]);
			fprintf(f, ",%zu", counter[j]);
		counter += 4;
	}

	RBTREE_FOR(c, asn_counter *, &cap->asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&counts, &c->bycount);
	}
	i = 0;
	remain = 0;
	RBTREE_FOR(n, rbnode_type *, &counts) {
		const asn_count *ac = n->key;
		if (i++ < n_asns)
			fprintf(f,",%d,%zu", ac->asn, ac->count);
		else	remain += ac->count;
	}
	while (i < n_asns) {
		fprintf(f,",0,0");
		i++;
	}
	fprintf(f,",%zu",remain);

	rbtree_init(&counts, countcmp);
	RBTREE_FOR(e, ecs_mask_counter *, &cap->ecs_masks) {
		e->bycount.key = &e->ec.count;
		rbtree_insert(&counts, &e->bycount);
	}
	i = 0;
	remain = 0;
	RBTREE_FOR(n, rbnode_type *, &counts) {
		const ecs_mask_count *ec = n->key;
		if (i++ < n_ecs_masks)
			fprintf(f,",%" PRIu8 ",%zu", ec->ecs_mask, ec->count);
		else	remain += ec->count;
	}
	while (i < n_ecs_masks) {
		fprintf(f,",0,0");
		i++;
	}
	fprintf(f,",%zu\n",remain);
}
void cap_hdr(FILE *f)
{
	size_t i;

	fprintf(f,"\"datetime\",\"# resolvers\",\"# probes\"");
	for (i = 0; i < n_caps; i++) {
		const cap_descr *d = caps + i;
		uint8_t j;
		for (j = 1; j < d->n_vals; j++)
			fprintf(f, ",\"%s\"", d->val_names[j-1]);
	}
	for (i = 0; i < n_asns; i++) {
		fprintf(f,",\"ASN #%zu\",\"ASN #%zu count\"", (i+1), (i+1));
	}
	fprintf(f,"\"Remaining ASNs count\"");
	for (i = 0; i < n_ecs_masks; i++) {
		fprintf(f,",\"ECS mask #%zu\",\"ECS mask #%zu count\"", (i+1), (i+1));
	}
	fprintf(f,"\"Remaining ECS mask count\"\n");
}

#if 0
static void
count_recs(dnst_rec *rec, size_t n_recs, struct tm &day)
{
	for (; n_recs--; rec++) {
		struct tm tm;
		time_t t = rec->updated;
		int incr_probes = rec->key.prb_id != prev_prb_id;

		gmtime_r(&t, &tm);
		if (tm.tm_mday != today.tm_mday
		||  tm.tm_mon  != today.tm_mon
		||  tm.tm_year != today.tm_year)
			continue; /* Only records updated on this day */

		assert(rec->key.prb_id < sizeof(res_by_prb));
		res_by_prb[rec->key.prb_id]++;
		if (rec->qnamemin == CAP_DOES)
			qres_by_prb[rec->key.prb_id]++;

		count_cap(&cap, rec, incr_probes);
		count_cap(qnamemincap + rec->qnamemin, rec, incr_probes);

		if (rec->key.prb_id != prev_prb_id)
			prev_prb_id = rec->key.prb_id;
	}
}

#endif

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

		struct tm tm;
		time_t t = rec->updated;
		int incr_probes = rec->key.prb_id != prev_prb_id;

		gmtime_r(&t, &tm);
		if (tm.tm_mday != today.tm_mday
		||  tm.tm_mon  != today.tm_mon
		||  tm.tm_year != today.tm_year)
			continue; /* Only records updated on this day */

		assert(rec->key.prb_id < sizeof(res_by_prb));
		res_by_prb[rec->key.prb_id]++;
		if (rec->qnamemin == CAP_DOES)
			qres_by_prb[rec->key.prb_id]++;

		count_cap(&cap, rec, incr_probes);
		count_cap(qnamemincap + rec->qnamemin, rec, incr_probes);

		if (rec->key.prb_id != prev_prb_id)
			prev_prb_id = rec->key.prb_id;
	}
	cap_hdr(stdout);
	cap_log(stdout, &cap);

	if (recs && recs != MAP_FAILED)
		munmap(recs, st.st_size);
	if (fd > 0)
		close(fd);
	return 0;
}
