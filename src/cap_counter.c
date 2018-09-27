#include "config.h"
#include "dnst.h"
#include "probes.h"
#include "rbtree.h"
#include "ranges.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
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

static const size_t n_ecs_masks = 10;
static const size_t n_asns = 100;
static const size_t print_n_ASNs = 20;


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
static int asn_countcmp(const void *x, const void *y)
{ return *(size_t *)x > *(size_t *)y ? -1
       : *(size_t *)x < *(size_t *)y ?  1
       : ((asn_count *)x)->asn > ((asn_count *)y)->asn ?  1
       : ((asn_count *)x)->asn < ((asn_count *)y)->asn ? -1 : 0;
};

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
static int ecs_countcmp(const void *x, const void *y)
{ return *(size_t *)x > *(size_t *)y ? -1
       : *(size_t *)x < *(size_t *)y ?  1
       : ((ecs_mask_count *)x)->ecs_mask > ((ecs_mask_count *)y)->ecs_mask ?  1
       : ((ecs_mask_count *)x)->ecs_mask < ((ecs_mask_count *)y)->ecs_mask ? -1 : 0;
};

void cap_counter_init(cap_counter *cap)
{
	memset(cap, 0, sizeof(cap_counter));
	rbtree_init(&cap->asns, asncmp);
	rbtree_init(&cap->asn_counts, asn_countcmp);
	rbtree_init(&cap->ecs_masks, ecs_maskcmp);
	rbtree_init(&cap->ecs_counts, ecs_countcmp);
}

static void rbnode_free(rbnode_type *node, void *ignore)
{ free(node); }

void reset_cap_counter(cap_counter *cap)
{
	traverse_postorder(&cap->asns, rbnode_free, NULL);
	traverse_postorder(&cap->ecs_masks, rbnode_free, NULL);
	cap_counter_init(cap);
}

static uint8_t const * const zeros =
    (uint8_t const * const) "\x00\x00\x00\x00\x00\x00\x00\x00"
                            "\x00\x00\x00\x00\x00\x00\x00\x00";

static uint8_t cd_get_ipv6(dnst_rec *rec)
{ return memcmp(rec->whoami_6, zeros, 16) ? CAP_CAN : CAP_UNKNOWN; }
static uint8_t cd_get_tcp(dnst_rec *rec)          { return rec->tcp_ipv4; }
static uint8_t cd_get_tcp6(dnst_rec *rec)         { return rec->tcp_ipv6; }
static uint8_t cd_get_ecs(dnst_rec *rec)
{ return rec->ecs_mask ? CAP_DOES : CAP_UNKNOWN; }
static uint8_t cd_get_qnamemin(dnst_rec *rec)     { return rec->qnamemin; }
static uint8_t cd_get_nxdomain(dnst_rec *rec)     { return rec->nxdomain; }
static uint8_t cd_get_has_ta_19036(dnst_rec *rec) { return rec->has_ta_19036; }
static uint8_t cd_get_has_ta_20326(dnst_rec *rec) { return rec->has_ta_20326; }
static uint8_t cd_get_rsamd5(dnst_rec *rec)       { return rec->dnskey_alg[ 0]; }
static uint8_t cd_get_dsa(dnst_rec *rec)          { return rec->dnskey_alg[ 1]; }
static uint8_t cd_get_rsasha1(dnst_rec *rec)      { return rec->dnskey_alg[ 2]; }
static uint8_t cd_get_dsansec3(dnst_rec *rec)     { return rec->dnskey_alg[ 3]; }
static uint8_t cd_get_rsansec3(dnst_rec *rec)     { return rec->dnskey_alg[ 4]; }
static uint8_t cd_get_rsasha256(dnst_rec *rec)    { return rec->dnskey_alg[ 5]; }
static uint8_t cd_get_rsasha512(dnst_rec *rec)    { return rec->dnskey_alg[ 6]; }
static uint8_t cd_get_eccgost(dnst_rec *rec)      { return rec->dnskey_alg[ 7]; }
static uint8_t cd_get_ecdsa256(dnst_rec *rec)     { return rec->dnskey_alg[ 8]; }
static uint8_t cd_get_ecdsa384(dnst_rec *rec)     { return rec->dnskey_alg[ 9]; }
static uint8_t cd_get_ed25519(dnst_rec *rec)      { return rec->dnskey_alg[10]; }
static uint8_t cd_get_ed448(dnst_rec *rec)        { return rec->dnskey_alg[11]; }
static uint8_t cd_get_gost(dnst_rec *rec)         { return rec->ds_alg[0]; }
static uint8_t cd_get_sha384(dnst_rec *rec)       { return rec->ds_alg[1]; }

static const cap_descr caps[] = {
    { 2, { "can_ipv6"     } , cd_get_ipv6       },
    { 2, { "can_tcp"      } , cd_get_tcp        },
    { 2, { "can_tcp6"     } , cd_get_tcp6       },
    { 2, { "does_ecs"     } , cd_get_ecs        },
    //{ 3, { "internal"     , "external"        } },
    { 3, { "does_qnamemin", "doesnt_qnamemin" } , cd_get_qnamemin     },
    { 3, { "does_nxdomain", "doesnt_nxdomain" } , cd_get_nxdomain     },
    { 3, { "has_ta_19036" , "hasnt_ta_19036"  } , cd_get_has_ta_19036 },
    { 3, { "has_ta_20326" , "hasnt_ta_20326"  } , cd_get_has_ta_20326 },
    { 4, { "can_rsamd5"   , "cannot_rsamd5"   , "broken_rsamd5"    }, cd_get_rsamd5    },
    { 4, { "can_dsa"      , "cannot_dsa"      , "broken_dsa"       }, cd_get_dsa       },
    { 4, { "can_rsasha1"  , "cannot_rsasha1"  , "broken_rsasha1"   }, cd_get_rsasha1   },
    { 4, { "can_dsansec3" , "cannot_dsansec3" , "broken_dsansec3"  }, cd_get_dsansec3  },
    { 4, { "can_rsansec3" , "cannot_rsansec3" , "broken_rsannsec3" }, cd_get_rsansec3  },
    { 4, { "can_rsasha256", "cannot_rsasha256", "broken_rsasha256" }, cd_get_rsasha256 },
    { 4, { "can_rsasha512", "cannot_rsasha512", "broken_rsasha512" }, cd_get_rsasha512 },
    { 4, { "can_eccgost"  , "cannot_eccgost"  , "broken_eccgost"   }, cd_get_eccgost   },
    { 4, { "can_ecdsa256" , "cannot_ecdsa256" , "broken_ecdsa256"  }, cd_get_ecdsa256  },
    { 4, { "can_ecdsa384" , "cannot_ecdsa384" , "broken_ecdsa384"  }, cd_get_ecdsa384  },
    { 4, { "can_ed25519"  , "cannot_ed25519"  , "broken_ed25519"   }, cd_get_ed25519   },
    { 4, { "can_ed448"    , "cannot_ed448"    , "broken_ed448"     }, cd_get_ed448     },
    { 4, { "can_gost"     , "cannot_gost"     , "broken_gost"      }, cd_get_gost      },
    { 4, { "can_sha384"   , "cannot_sha384"   , "broken_sha384"    }, cd_get_sha384    }
};
static cap_descr const * const end_of_caps
    = caps + (sizeof(caps) / sizeof(cap_descr));
static const size_t n_caps = sizeof(caps) / sizeof(cap_descr);

typedef struct cap_sel  cap_sel;

struct cap_sel {
	cap_sel    *parent;
	cap_counter counts;
	uint8_t     sel[sizeof(caps) / sizeof(cap_descr)];
	size_t    n_children;
	cap_sel    *children[];
};

static void print_cap_sel(FILE *f, cap_sel *s)
{
	char val[n_caps * 2];
	size_t i;

	for (i = 0; i < n_caps; i++) {
		val[i * 2]     =  '0' + s->sel[i];
		val[i * 2 + 1] =  ',';
	}
	val[n_caps * 2 - 1] = '\x00';
	fprintf(f, "%s\n", val);
}

static cap_sel *new_cap_sel_(cap_sel *parent, size_t n_cap, size_t cap_val, size_t depth)
{
	const cap_descr *cd;
	size_t n_children = 0, i, j;
	cap_sel *r;

	//fprintf(stderr, "new_cap_sel_(%p, %zu, %zu, %zu)\n", parent, n_cap, cap_val, depth);
	if (depth) for (cd = caps + n_cap + 1; cd < end_of_caps; cd++)
		n_children += cd->n_vals - 1;

	if (!(r = calloc(1, sizeof(cap_sel) + n_children * sizeof(cap_sel *))))
		return NULL;
	cap_counter_init(&r->counts);
	r->n_children = n_children;
	memcpy(r->sel, parent->sel, n_caps);
	r->sel[n_cap] = cap_val;

	// print_cap_sel(stderr, r);

	if (n_children) for (i = 0, cd = caps + n_cap + 1; cd < end_of_caps; cd++)
		for (j = 1; j < cd->n_vals; j++)
			r->children[i++] = new_cap_sel_(r, (cd - caps), j, depth - 1);
	return r;
}

static cap_sel *new_cap_sel(size_t depth)
{ 
	size_t n_children = 0, i, j;
	const cap_descr *cd;
	cap_sel *r;

	if (depth) for (cd = caps; cd < end_of_caps; cd++)
		n_children += cd->n_vals - 1;

	if (!(r = calloc(1, sizeof(cap_sel) + n_children * sizeof(cap_sel *))))
		return NULL;
	cap_counter_init(&r->counts);
	r->n_children = n_children;

	for (i = 0, cd = caps; cd < end_of_caps; cd++)
		for (j = 1; j < cd->n_vals; j++)
			r->children[i++] = new_cap_sel_(r, (cd - caps), j, depth - 1);
	return r;
}

static void destroy_cap_sel(cap_sel *sel)
{
	size_t i;

	for (i = 0; i < sel->n_children; i++)
		destroy_cap_sel(sel->children[i]);
	reset_cap_counter(&sel->counts);
	free(sel);
}

static void reset_cap_sel(cap_sel *sel)
{
	size_t i;

	for (i = 0; i < sel->n_children; i++)
		reset_cap_sel(sel->children[i]);
	reset_cap_counter(&sel->counts);
}

void count_cap(cap_counter *cap, dnst_rec *rec)
{
	size_t i;
	int asn = -1, has_ipv6 = 0;
	asn_counter *c;
	ecs_mask_counter *e;

	cap->n_resolvers++;
	if (rec->key.prb_id != cap->prev_prb_id) {
		cap->prev_prb_id += 1;
		cap->n_probes++;
	}
	if (rec->updated > cap->updated)
		cap->updated = rec->updated;

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

	if (!cap->asns.cmp)
		return;

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
	if ((c = (void *)rbtree_search(&cap->asns, &asn)))
		c->ac.count++;

	else if ((c = calloc(1, sizeof(asn_counter)))) {
		c->ac.asn = asn;
		c->ac.count = 1;
		c->byasn.key = &c->ac.asn;
		rbtree_insert(&cap->asns, &c->byasn);
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

void count_cap_sel(cap_sel *sel, dnst_rec *rec)
{
	size_t i;

	for (i = 0; i < n_caps; i++) {
		if (sel->sel[i] && caps[i].get_val(rec) != sel->sel[i])
			return;
	}
	count_cap(&sel->counts, rec);
	for (int i = 0; i < sel->n_children; i++)
		count_cap_sel(sel->children[i], rec);
}

static void cap_log(FILE *f, cap_counter *cap)
{
	size_t *counter = counter_values(cap);
	asn_counter *c;
	ecs_mask_counter *e;
	rbnode_type *n;
	size_t i, remain;
	char timestr[80];
	struct tm tm;
	time_t t = cap->updated;
	char ASNs[32768];
	size_t l;
	size_t prev_count;
	int prev_asn;
	size_t asn_total;
	size_t n_ASNs;

	gmtime_r(&t, &tm);
	
	fprintf( f, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ,%zu,%zu"
	       , tm.tm_year + 1900 , tm.tm_mon + 1 , tm.tm_mday
	       , tm.tm_hour, tm.tm_min, tm.tm_sec
	       , cap->n_resolvers, cap->n_probes);
	for (i = 0; i < n_caps; i++) {
		const cap_descr *d = caps + i;
		uint8_t j;
		for (j = 1; j < d->n_vals; j++)
			//fprintf(f,",%s: %zu", d->val_names[j-1], counter[j]);
			fprintf(f, ",%zu", counter[j]);
		counter += 4;
	}
	RBTREE_FOR(e, ecs_mask_counter *, &cap->ecs_masks) {
		e->bycount.key = &e->ec.count;
		rbtree_insert(&cap->ecs_counts, &e->bycount);
	}
	i = 0;
	remain = 0;
	RBTREE_FOR(n, rbnode_type *, &cap->ecs_counts) {
		const ecs_mask_count *ec = n->key;
		if (i++ < n_ecs_masks)
			fprintf(f,",%" PRIu8 ",%zu", ec->ecs_mask, ec->count);
		else	remain += ec->count;
	}
	while (i < n_ecs_masks) {
		fprintf(f,",0,0");
		i++;
	}
	fprintf(f,",%zu",remain);

	RBTREE_FOR(c, asn_counter *, &cap->asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&cap->asn_counts, &c->bycount);
	}
	i = 0;
	remain = 0;
	prev_count = 0;
	RBTREE_FOR(n, rbnode_type *, &cap->asn_counts) {
		const asn_count *ac = n->key;
		if (i >= n_asns)
			remain += ac->count;

		else if (ac->count != prev_count) {
			if (prev_count != 0) {
				if (n_ASNs > print_n_ASNs)
					fprintf( f,",%zu,\"in %zu ASNs (%zu)\"", asn_total
					       , n_ASNs, ac->count);
				else
					fprintf(f,",%zu,\"%s\"", asn_total, ASNs);
				if (i++ >= n_asns)
					continue;
			}
			l = snprintf(ASNs, sizeof(ASNs), "AS%d", ac->asn);
			prev_asn = ac->asn;
			prev_count = asn_total = ac->count;
			n_ASNs = 1;

		} else if (prev_asn != ac->asn) {
			l += snprintf(ASNs + l, sizeof(ASNs) - l, ",AS%d", ac->asn);
			assert(l < sizeof(ASNs));
			asn_total += ac->count;
			n_ASNs += 1;
		} else
			asn_total += ac->count;
	}
	if (i < n_asns) {
		if (n_ASNs > print_n_ASNs)
			fprintf( f,",%zu,\"in %zu ASNs\"", asn_total, n_ASNs);
		else	fprintf(f,",%zu,\"%s\"", asn_total, ASNs);
		while (++i < n_asns)
			fprintf(f,",0,\"\"");
	}
	fprintf(f,",%zu",remain);
	fprintf(f,"\n");
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
	for (i = 0; i < n_ecs_masks; i++) {
		fprintf(f,",\"ECS mask #%zu\",\"ECS mask #%zu count\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining ECS mask count\"");
	for (i = 0; i < n_asns; i++) {
		fprintf(f,",\"band #%zu total\",\"band #%zu ASNs\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining ASNs count\"");
	fprintf(f,"\n");
}

static const char *cap_sel_fn(cap_sel *sel, char *path, size_t path_sz,
    const char *base_dir, const char *fn)
{
	int r;
	size_t i, l;

	if (!*base_dir || (l = strlcpy(path, base_dir, path_sz) >= path_sz))
		return NULL;

	if (path[l - 1] == '/') path[l - 1] = '\0';
	if (mkdir(path, 0755) == -1 && errno != EEXIST) {
		fprintf( stderr, "Could mkdir(\"%s\", 0755): %s\n"
		       , path, strerror(errno));
		return NULL;
	}
	for (i = 0; i < n_caps; i++) {
		if (!sel->sel[i]) continue;
		if (strlcat(path, "/", path_sz) >= path_sz
		||  strlcat(path, caps[i].val_names[sel->sel[i]-1], path_sz) >= path_sz)
			return NULL;
		if (mkdir(path, 0755) == -1 && errno != EEXIST) {
			fprintf( stderr, "Could mkdir(\"%s\", 0755): %s\n"
			       , path, strerror(errno));
			return NULL;
		}
	}
	if (!fn)return path;
	if (strlcat(path, "/", path_sz) >= path_sz
	||  strlcat(path, fn, path_sz) >= path_sz)
		return NULL;
	else	return path;
}

static void report_cap_sel(cap_sel *sel, const char *report_dir)
{
	char path[4096];
	size_t i;
	FILE *f;

	if (!(cap_sel_fn(sel, path, sizeof(path), report_dir, "report.csv")))
		return;
	else if ((f = fopen(path, "wx")))
		cap_hdr(f);
	else if (!(f = fopen(path, "a")))
		return;
	cap_log(f, &sel->counts);
	for (i = 0; i < sel->n_children; i++)
		report_cap_sel(sel->children[i], report_dir);
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
	cap_sel    *sel = NULL;
	struct tm   tm;
	time_t      t;
	
	assert(sizeof(dnst_rec) == 104);

	memset(&today, 0, sizeof(today));

	if (argc != 3)
		printf("usage: %s <resfile> <output_dir>\n", argv[0]);

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

	else if (!(sel = new_cap_sel(2)))
		fprintf(stderr, "Could not create counters\n");

	else for ( n_recs = st.st_size / sizeof(dnst_rec), rec = recs
	         ; n_recs > 0
		 ; n_recs--, rec++) {

		t = rec->updated;

		gmtime_r(&t, &tm);
		if (tm.tm_mday != today.tm_mday
		||  tm.tm_mon  != today.tm_mon
		||  tm.tm_year != today.tm_year)
			continue; /* Only records updated on this day */

		count_cap_sel(sel, rec);
	}
	if (sel) {
		struct { int asn; size_t count; cap_sel *sel; } asn_sels[50];
		const size_t n_asn_sels = sizeof(asn_sels) / sizeof(asn_sels[0]);
		rbnode_type *n;
		size_t i;

		report_cap_sel(sel, argv[2]);

		fprintf(stderr, "asns: %zu\n", sel->counts.asns.count);
		fprintf(stderr, "asns: %zu\n", sel->counts.asn_counts.count);
		i = 0;
		RBTREE_FOR(n, rbnode_type *, &sel->counts.asn_counts) {
			const asn_count *ac = n->key;

			asn_sels[i].asn   = ac->asn;
			asn_sels[i].count = ac->count;
			asn_sels[i].sel   = new_cap_sel(1);
			if (i++ >= n_asn_sels)
				break;
		}
		for ( n_recs = st.st_size / sizeof(dnst_rec), rec = recs
			 ; n_recs > 0
			 ; n_recs--, rec++) {

			int asn = -1;
			t = rec->updated;


			gmtime_r(&t, &tm);
			if (tm.tm_mday != today.tm_mday
			||  tm.tm_mon  != today.tm_mon
			||  tm.tm_year != today.tm_year)
				continue; /* Only records updated on this day */

			if (memcmp(rec->whoami_g, zeros, 4) != 0
			&& (asn = lookup_asn4(rec->whoami_g)))
				; /* pass */
			else if (memcmp(rec->whoami_a, zeros, 4) != 0
			&& (asn = lookup_asn4(rec->whoami_a)))
				; /* pass */
			else if (memcmp(rec->whoami_6, zeros, 16) != 0) {
				asn = lookup_asn6(rec->whoami_6);
			}
			for (i = 0; i < n_asn_sels; i++)
				if (asn == asn_sels[i].asn) {
					count_cap_sel(asn_sels[i].sel, rec);
					break;
				}
		}
		for (i = 0; i < n_asn_sels; i++) {
			char path[4096];
			size_t l, l2;

			l = strlcpy(path, argv[2], sizeof(path));
			assert(l > 0 && l < sizeof(path));

			if (path[l - 1] == '/') l -= 1;
			l2 = snprintf( path + l, sizeof(path) - l
			             , "/AS%d", asn_sels[i].asn);
			assert(l + l2 < sizeof(path));
			report_cap_sel(asn_sels[i].sel, path);
			destroy_cap_sel(asn_sels[i].sel);
		}
		destroy_cap_sel(sel);
	}
	if (recs && recs != MAP_FAILED)
		munmap(recs, st.st_size);
	if (fd > 0)
		close(fd);
	return 0;
}
