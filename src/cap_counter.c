/* Copyright (c) 2018, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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
static const size_t n_asn_sels = 100;

static int dont_report = 0;

#define DEBUG_fprintf(...)

typedef struct asn_info_rec {
	int registered;
	int prb_4;
	int prb_6;
	int res;
	int auth_g;
	int auth_a;
	int auth_6;
	int nxhj;
} asn_info_rec;

static asn_info_rec *asn_info = NULL;

static int prb_id_cmp(const void *x, const void *y)
{ return *(uint32_t *)x == *(uint32_t *)y ? 0
       : *(uint32_t *)x >  *(uint32_t *)y ? 1 : -1; }

static rbtree_type probes = { RBTREE_NULL, 0, prb_id_cmp };

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
	rbtree_init(&cap->prb_asns, asncmp);
	rbtree_init(&cap->prb_asn_counts, asn_countcmp);
	rbtree_init(&cap->res_asns, asncmp);
	rbtree_init(&cap->res_asn_counts, asn_countcmp);
	rbtree_init(&cap->auth_asns, asncmp);
	rbtree_init(&cap->auth_asn_counts, asn_countcmp);
	rbtree_init(&cap->nxhj_asns, asncmp);
	rbtree_init(&cap->nxhj_asn_counts, asn_countcmp);
	rbtree_init(&cap->ecs_masks, ecs_maskcmp);
	rbtree_init(&cap->ecs_counts, ecs_countcmp);
	rbtree_init(&cap->ecs6_masks, ecs_maskcmp);
	rbtree_init(&cap->ecs6_counts, ecs_countcmp);
}

static void rbnode_free(rbnode_type *node, void *ignore)
{ free(node); }

void reset_cap_counter(cap_counter *cap)
{
	traverse_postorder(&cap->prb_asns, rbnode_free, NULL);
	traverse_postorder(&cap->res_asns, rbnode_free, NULL);
	traverse_postorder(&cap->auth_asns, rbnode_free, NULL);
	traverse_postorder(&cap->nxhj_asns, rbnode_free, NULL);
	traverse_postorder(&cap->ecs_masks, rbnode_free, NULL);
	traverse_postorder(&cap->ecs6_masks, rbnode_free, NULL);
	free(cap->prb_ids);
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
{ return (rec->ecs_mask || rec->ecs_mask6) ? CAP_DOES : CAP_UNKNOWN; }
static uint8_t cd_get_internal(dnst_rec *rec)
{
	int Z_asn1 = -1, Z_asn2 = -1, Z_asn6 = -1;

	assert(asn_info[rec->asn_info].registered);
	Z_asn1 = asn_info[rec->asn_info].auth_g;
	Z_asn2 = asn_info[rec->asn_info].auth_a;
	Z_asn6 = asn_info[rec->asn_info].auth_6;
	if (Z_asn1 > 0 || Z_asn2 > 0 || Z_asn6 > 0) {
		/* X = configured ASN of probe
		 * Y = configured resolver ASN (private address space etc.)
		 * Z = ASN seen at authoritative
		 * for  X Y Z
		 *      a - a : internal
		 *      a a c : forwarding
		 *      a b c : forwarding
		 *      a c c : external
		 */
		int X_asn_v4 = asn_info[rec->asn_info].prb_4;
		int X_asn_v6 = asn_info[rec->asn_info].prb_6;
		int Y_asn = asn_info[rec->asn_info].res;

		if ((Z_asn1 > 0 && X_asn_v4 == Z_asn1)
		||  (Z_asn1 > 0 && X_asn_v6 == Z_asn1)
		||  (Z_asn2 > 0 && X_asn_v4 == Z_asn2)
		||  (Z_asn2 > 0 && X_asn_v6 == Z_asn2)
		||  (Z_asn6 > 0 && X_asn_v4 == Z_asn6)
		||  (Z_asn6 > 0 && X_asn_v6 == Z_asn6))

			return CAP_INTERN;
			
		else if ((Z_asn1 > 0 && Y_asn == Z_asn1)
		     ||  (Z_asn2 > 0 && Y_asn == Z_asn2)
		     ||  (Z_asn6 > 0 && Y_asn == Z_asn6))

			return CAP_EXTERN;
		else
			return CAP_FORWARD;
	}
	return CAP_UNKNOWN;
}
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
    { 3, { "does_qnamemin", "doesnt_qnamemin" } , cd_get_qnamemin     },
    { 3, { "does_nxdomain", "doesnt_nxdomain" } , cd_get_nxdomain     },
    { 3, { "has_ta_19036" , "hasnt_ta_19036"  } , cd_get_has_ta_19036 },
    { 3, { "has_ta_20326" , "hasnt_ta_20326"  } , cd_get_has_ta_20326 },
    { 4, { "can_rsamd5"   , "cannot_rsamd5"   , "broken_rsamd5"    }, cd_get_rsamd5    },
    { 4, { "can_dsa"      , "cannot_dsa"      , "broken_dsa"       }, cd_get_dsa       },
    { 4, { "can_rsasha1"  , "cannot_rsasha1"  , "broken_rsasha1"   }, cd_get_rsasha1   },
    { 4, { "can_dsansec3" , "cannot_dsansec3" , "broken_dsansec3"  }, cd_get_dsansec3  },
    { 4, { "can_rsansec3" , "cannot_rsansec3" , "broken_rsansec3"  }, cd_get_rsansec3  },
    { 4, { "can_rsasha256", "cannot_rsasha256", "broken_rsasha256" }, cd_get_rsasha256 },
    { 4, { "can_rsasha512", "cannot_rsasha512", "broken_rsasha512" }, cd_get_rsasha512 },
    { 4, { "can_eccgost"  , "cannot_eccgost"  , "broken_eccgost"   }, cd_get_eccgost   },
    { 4, { "can_ecdsa256" , "cannot_ecdsa256" , "broken_ecdsa256"  }, cd_get_ecdsa256  },
    { 4, { "can_ecdsa384" , "cannot_ecdsa384" , "broken_ecdsa384"  }, cd_get_ecdsa384  },
    { 4, { "can_ed25519"  , "cannot_ed25519"  , "broken_ed25519"   }, cd_get_ed25519   },
    { 4, { "can_ed448"    , "cannot_ed448"    , "broken_ed448"     }, cd_get_ed448     },
    { 4, { "can_gost"     , "cannot_gost"     , "broken_gost"      }, cd_get_gost      },
    { 4, { "can_sha384"   , "cannot_sha384"   , "broken_sha384"    }, cd_get_sha384    },
    { 4, { "is_internal"  , "is_forwarding"   , "is_external"      }, cd_get_internal     }
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

static cap_sel *new_cap_sel_(cap_sel *parent, size_t n_cap, size_t cap_val, size_t depth)
{
	const cap_descr *cd;
	size_t n_children = 0, i, j;
	cap_sel *r;

	if (depth) for (cd = caps + n_cap + 1; cd < end_of_caps; cd++)
		n_children += cd->n_vals - 1;

	if (!(r = calloc(1, sizeof(cap_sel) + n_children * sizeof(cap_sel *))))
		return NULL;
	cap_counter_init(&r->counts);
	r->n_children = n_children;
	memcpy(r->sel, parent->sel, n_caps);
	r->sel[n_cap] = cap_val;

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

void cap_probe_count(cap_counter *cap)
{
	size_t i;
	probe_counter *pc = (void *)rbtree_search(&probes, &cap->prev_prb_id);

	if (!cap->prb_ids_sz) {
		cap->prb_ids_sz = 100;
		cap->prb_ids = malloc(sizeof(uint32_t) * cap->prb_ids_sz);
		assert(cap->prb_ids);

	} else if  (cap->n_probes >= cap->prb_ids_sz) {
		cap->prb_ids_sz *= 2;
		cap->prb_ids = realloc( cap->prb_ids
		                      , sizeof(uint32_t) * cap->prb_ids_sz);
		assert(cap->prb_ids);
	}
	cap->prb_ids[cap->n_probes] = cap->prev_prb_id;
	if (pc) {
		size_t *src = counter_values(&pc->counts);
		size_t *dst = probe_counter_values(cap);
		for (i = 0; i < n_caps * 4 ; i++)
			*dst++ += *src++;

	} else if (cap->prev_prb_id != 0)
		fprintf(stderr, "%" PRIu32 " not found\n"
			      , cap->prev_prb_id);
}

void cap_res_count(cap_counter *cap, dnst_rec *rec)
{
	if (!cap->reses_sz) {
		cap->reses_sz = 200;
		cap->reses = malloc(sizeof(dnst_rec *) * cap->reses_sz);
		assert(cap->reses);

	} else if  (cap->n_resolvers >= cap->reses_sz) {
		cap->reses_sz *= 2;
		cap->reses = realloc( cap->reses
		                    , sizeof(dnst_rec *) * cap->reses_sz);
		assert(cap->reses);
	}
	cap->reses[cap->n_resolvers] = rec;
}

void count_cap(cap_counter *cap, dnst_rec *rec)
{
	size_t i;
	int Z_asn1 = -1, Z_asn2 = -1, Z_asn6 = -1, asn = -1, has_ipv6 = 0;
	asn_counter *c;
	ecs_mask_counter *e;
	probe *X = NULL;
	int X_asn = -1, X_asn_v4 = -1, X_asn_v6 = -1;
	int Y_asn = -1;
	int nxhj_asn = -1;
	
	cap_res_count(cap, rec);
	cap->n_resolvers++;
	if (rec->key.prb_id != cap->prev_prb_id) {
		/* Now update cap->prbs counter with values from cap->prev_prb_id
		 */
		cap_probe_count(cap);
		cap->prev_prb_id = rec->key.prb_id;
		cap->n_probes++;
	}
	if (rec->updated > cap->updated)
		cap->updated = rec->updated;

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

	if (memcmp(rec->whoami_6, zeros, 16))
		has_ipv6 = CAP_CAN;
	cap->res.has_ipv6[has_ipv6]++;

	if ((rec->ecs_mask || rec->ecs_mask6))
		cap->res.does_ecs[CAP_DOES]++;

	if (!cap->auth_asns.cmp)
		return;

	if (!asn_info[rec->asn_info].registered) {
		if (memcmp(rec->whoami_g, zeros, 4) != 0)
			Z_asn1 = lookup_asn4(rec->whoami_g);
		asn_info[rec->asn_info].auth_g = Z_asn1;
		if (memcmp(rec->whoami_a, zeros, 4) != 0)
			Z_asn2 = lookup_asn4(rec->whoami_a);
		asn_info[rec->asn_info].auth_a = Z_asn2;
		if (has_ipv6)
			Z_asn6 = lookup_asn6(rec->whoami_6);
		asn_info[rec->asn_info].auth_6 = Z_asn6;
		X = lookup_probe(rec->key.prb_id);
		X_asn_v4 = X ? X->asn_v4 : -1;
		X_asn_v6 = X ? X->asn_v6 : -1;
		asn_info[rec->asn_info].prb_4 = X_asn_v4;
		asn_info[rec->asn_info].prb_6 = X_asn_v6;
		Y_asn = lookup_asn6(rec->key.addr);
		asn_info[rec->asn_info].res = Y_asn;
		if (memcmp(rec->hijacked[0], zeros, 4) != 0)
			nxhj_asn = lookup_asn4(rec->hijacked[0]);
		asn_info[rec->asn_info].nxhj = nxhj_asn;
		asn_info[rec->asn_info].registered = 1;
	} else {
		Z_asn1   = asn_info[rec->asn_info].auth_g;
		Z_asn2   = asn_info[rec->asn_info].auth_a;
		Z_asn6   = asn_info[rec->asn_info].auth_6;
		X_asn_v4 = asn_info[rec->asn_info].prb_4;
		X_asn_v6 = asn_info[rec->asn_info].prb_6;
		Y_asn    = asn_info[rec->asn_info].res;
		nxhj_asn = asn_info[rec->asn_info].nxhj;
	}
	X_asn = X_asn_v4 > 0 ? X_asn_v4
	      : X_asn_v6 > 0 ? X_asn_v6 : -1;
	if (Y_asn == 0)
		Y_asn = X_asn;

	if (Z_asn1 > 0)
		asn = Z_asn1;
	else if (Z_asn2 > 0)
		asn = Z_asn2;
	else if (Z_asn6 > 0)
		asn = Z_asn6;
	else if (Z_asn1 == 0 || Z_asn2 == 0 || Z_asn6 == 0)
		asn = 0;

	if (asn > 0) {
		/* X = configured ASN of probe
		 * Y = configured resolver ASN (private address space etc.)
		 * Z = ASN seen at authoritative
		 * for  X Y Z
		 *      a - a : internal
		 *      a a c : forwarding
		 *      a b c : forwarding
		 *      a c c : external
		 */

		if (Z_asn1 > 0 && X_asn_v4 == Z_asn1) {
			cap->res.int_ext[CAP_INTERN]++;
			asn = Z_asn1;
			X_asn = X_asn_v4;

		} else if  (Z_asn1 > 0 && X_asn_v6 == Z_asn1) {
			cap->res.int_ext[CAP_INTERN]++;
			asn = Z_asn1;
			X_asn = X_asn_v6;

		} else if (Z_asn2 > 0 && X_asn_v4 == Z_asn2) {
			cap->res.int_ext[CAP_INTERN]++;
			asn = Z_asn2;
			X_asn = X_asn_v4;

		} else if (Z_asn2 > 0 && X_asn_v6 == Z_asn2) {
			cap->res.int_ext[CAP_INTERN]++;
			asn = Z_asn2;
			X_asn = X_asn_v6;

		} else if (Z_asn6 > 0 && X_asn_v4 == Z_asn6) {
			cap->res.int_ext[CAP_INTERN]++;
			asn = Z_asn6;
			X_asn = X_asn_v4;

		} else if (Z_asn6 > 0 && X_asn_v6 == Z_asn6) {
			cap->res.int_ext[CAP_INTERN]++;
			asn = Z_asn6;
			X_asn = X_asn_v6;

		} else if (Z_asn1 > 0 && Y_asn == Z_asn1) {
			cap->res.int_ext[CAP_EXTERN]++;
			asn = Z_asn1;

		} else if (Z_asn2 > 0 && Y_asn == Z_asn2) {
			cap->res.int_ext[CAP_EXTERN]++;
			asn = Z_asn2;

		} else if (Z_asn6 > 0 && Y_asn == Z_asn6) {
			cap->res.int_ext[CAP_EXTERN]++;
			asn = Z_asn6;
		} else {
			if ((X_asn_v4 == Y_asn || X_asn_v6 == Y_asn))
				X_asn = Y_asn;
			cap->res.int_ext[CAP_FORWARD]++;
		}
	}
	if ((c = (void *)rbtree_search(&cap->prb_asns, &X_asn)))
		c->ac.count++;

	else if ((c = calloc(1, sizeof(asn_counter)))) {
		c->ac.asn = X_asn;
		c->ac.count = 1;
		c->byasn.key = &c->ac.asn;
		rbtree_insert(&cap->prb_asns, &c->byasn);
	}
	if ((c = (void *)rbtree_search(&cap->res_asns, &Y_asn)))
		c->ac.count++;

	else if ((c = calloc(1, sizeof(asn_counter)))) {
		c->ac.asn = Y_asn;
		c->ac.count = 1;
		c->byasn.key = &c->ac.asn;
		rbtree_insert(&cap->res_asns, &c->byasn);
	}
	if ((c = (void *)rbtree_search(&cap->auth_asns, &asn)))
		c->ac.count++;

	else if ((c = calloc(1, sizeof(asn_counter)))) {
		c->ac.asn = asn;
		c->ac.count = 1;
		c->byasn.key = &c->ac.asn;
		rbtree_insert(&cap->auth_asns, &c->byasn);
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
	if (rec->ecs_mask6) {
		if ((e = (void *)rbtree_search(&cap->ecs6_masks, &rec->ecs_mask6)))
			e->ec.count++;

		else if ((e = calloc(1, sizeof(ecs_mask_counter)))) {
			e->ec.ecs_mask = rec->ecs_mask6;
			e->ec.count = 1;
			e->byecs_mask.key = &e->ec.ecs_mask;
			rbtree_insert(&cap->ecs6_masks, &e->byecs_mask);
		}
	}
	if (nxhj_asn <= 0) 
		; /* pass */

	else if ((c = (void *)rbtree_search(&cap->nxhj_asns, &nxhj_asn)))
		c->ac.count++;

	else if ((c = calloc(1, sizeof(asn_counter)))) {
		c->ac.asn = nxhj_asn;
		c->ac.count = 1;
		c->byasn.key = &c->ac.asn;
		rbtree_insert(&cap->nxhj_asns, &c->byasn);
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

static void log_asns(FILE *f, rbtree_type *asn_tree)
{
	rbnode_type *n;
	size_t i = 0, remain = 0, l = 0;
	char   ASNs[32768] = "";
	size_t prev_count  = 0;
	int    prev_asn    = -1;
	size_t asn_total   = 0;
	size_t n_ASNs      = 0;

	if (!f)
		return;

	RBTREE_FOR(n, rbnode_type *, asn_tree) {
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
}

static void cap_log(FILE *f, cap_counter *cap)
{
	size_t *counter = counter_values(cap);
	size_t *prb_counter = probe_counter_values(cap);
	rbnode_type *n;
	asn_counter *c;
	ecs_mask_counter *e;
	size_t i, remain;
	char timestr[80];
	struct tm tm;
	time_t t = cap->updated;

	gmtime_r(&t, &tm);

	if (cap->updated == 0)
		return;
	
	if (f) fprintf( f, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ,%zu,%zu"
		       , tm.tm_year + 1900 , tm.tm_mon + 1 , tm.tm_mday
		       , tm.tm_hour, tm.tm_min, tm.tm_sec
		       , cap->n_probes, cap->n_resolvers);
	if (f) for (i = 0; i < n_caps; i++) {
		const cap_descr *d = caps + i;
		uint8_t j;
		for (j = 1; j < d->n_vals; j++)
			//fprintf(f,",%s: %zu", d->val_names[j-1], counter[j]);
			fprintf(f, ",%zu", counter[j]);
		for (j = 1; j < d->n_vals; j++)
			//fprintf(f,",%s: %zu", d->val_names[j-1], counter[j]);
			fprintf(f, ",%zu", prb_counter[j]);
		counter += 4;
		prb_counter += 4;
	}
	RBTREE_FOR(e, ecs_mask_counter *, &cap->ecs_masks) {
		e->bycount.key = &e->ec.count;
		rbtree_insert(&cap->ecs_counts, &e->bycount);
	}
	if (f) {
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
	}
	RBTREE_FOR(e, ecs_mask_counter *, &cap->ecs6_masks) {
		e->bycount.key = &e->ec.count;
		rbtree_insert(&cap->ecs6_counts, &e->bycount);
	}
	if (f) {
		i = 0;
		remain = 0;
		RBTREE_FOR(n, rbnode_type *, &cap->ecs6_counts) {
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
	}

	RBTREE_FOR(c, asn_counter *, &cap->prb_asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&cap->prb_asn_counts, &c->bycount);
	}
	log_asns(f, &cap->prb_asn_counts);
	RBTREE_FOR(c, asn_counter *, &cap->res_asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&cap->res_asn_counts, &c->bycount);
	}
	log_asns(f, &cap->res_asn_counts);
	RBTREE_FOR(c, asn_counter *, &cap->auth_asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&cap->auth_asn_counts, &c->bycount);
	}
	log_asns(f, &cap->auth_asn_counts);
	RBTREE_FOR(c, asn_counter *, &cap->nxhj_asns) {
		c->bycount.key = &c->ac.count;
		rbtree_insert(&cap->nxhj_asn_counts, &c->bycount);
	}
	log_asns(f, &cap->nxhj_asn_counts);
	if (f)
		fprintf(f,"\n");
}
void cap_hdr(FILE *f)
{
	size_t i;

	fprintf(f,"\"datetime\",\"# probes\",\"# resolvers\"");
	for (i = 0; i < n_caps; i++) {
		const cap_descr *d = caps + i;
		uint8_t j;
		for (j = 1; j < d->n_vals; j++)
			fprintf(f, ",\"%s\"", d->val_names[j-1]);
		for (j = 1; j < d->n_vals; j++)
			fprintf(f, ",\"%s_prbs\"", d->val_names[j-1]);
	}
	for (i = 0; i < n_ecs_masks; i++) {
		fprintf(f,",\"ECS mask #%zu\",\"ECS mask #%zu count\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining ECS mask count\"");
	for (i = 0; i < n_ecs_masks; i++) {
		fprintf(f,",\"ECS mask6 #%zu\",\"ECS mask6 #%zu count\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining ECS mask6 count\"");
	for (i = 0; i < n_asns; i++) {
		fprintf(f,",\"probe #%zu total\",\"probe #%zu ASNs\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining probe ASNs count\"");
	for (i = 0; i < n_asns; i++) {
		fprintf(f,",\"resolver #%zu total\",\"resolver #%zu ASNs\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining resolver ASNs count\"");
	for (i = 0; i < n_asns; i++) {
		fprintf(f,",\"auth #%zu total\",\"auth #%zu ASNs\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining auth ASNs count\"");
	for (i = 0; i < n_asns; i++) {
		fprintf(f,",\"nxhj #%zu total\",\"nxhj #%zu ASNs\"", (i+1), (i+1));
	}
	fprintf(f,",\"Remaining nxhj ASNs count\"");
	fprintf(f,"\n");
}

static const char *cap_sel_fn(cap_sel *sel, char *path, size_t path_sz,
    const char *base_dir, const char *fn)
{
	int r;
	size_t i, l;

	if (!*base_dir || (l = strlcpy(path, base_dir, path_sz)) >= path_sz)
		return NULL;

	if (path[l - 1] == '/') path[l - 1] = '\0';
	if (mkdir(path, 0755) == -1 && errno != EEXIST) {
		fprintf( stderr, "Could mkdir(\"%s\", 0755): %s\n"
		       , path, strerror(errno));
		return NULL;
	}
	if (sel) for (i = 0; i < n_caps; i++) {
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

	if (dont_report)
		f = NULL;

	else if (!(cap_sel_fn(sel, path, sizeof(path), report_dir, "report.csv")))
		return;
	else if ((f = fopen(path, "wx")))
		cap_hdr(f);
	else if (!(f = fopen(path, "a")))
		return;
	cap_probe_count(&sel->counts);
	cap_log(f, &sel->counts);
	if (f)
		fclose(f);

	if (!sel->counts.prb_ids)
		; /* pass */
	else if (!(cap_sel_fn(sel, path, sizeof(path), report_dir, "probes.py")))
		; /* pass */
	else if ((f = fopen(path, "w"))) {
		fprintf(f, "set([");
		for (i = 0; i < sel->counts.n_probes; i++) {
			fprintf(f, "%s%" PRIu32, (i > 0 ? "," : "")
			       , sel->counts.prb_ids[i]);
		}
		fprintf(f, "])");
		fclose(f);
	}
#if 1
	if (!sel->counts.reses)
		; /* pass */
	else if (!sel->counts.updated)
		; /* pass */
	else if (!(cap_sel_fn(sel, path, sizeof(path), report_dir, "resolvers.py")))
		; /* pass */
	else if ((f = fopen(path, "a"))) {
		struct tm tm;
		time_t t = sel->counts.updated;
		char addrstr[80];

		gmtime_r(&t, &tm);

		fprintf( f, "('%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ,["
		       , tm.tm_year + 1900 , tm.tm_mon + 1 , tm.tm_mday
		       , tm.tm_hour, tm.tm_min, tm.tm_sec);

		for (i = 0; i < sel->counts.n_resolvers; i++) {
			dnst_rec_key *key = &sel->counts.reses[i]->key;
			if (memcmp(key->addr, ipv4_mapped_ipv6_prefix, 12) == 0)
				inet_ntop( AF_INET, &key->addr[12]
				         , addrstr, sizeof(addrstr));
			else
				inet_ntop( AF_INET6, key->addr
				         , addrstr, sizeof(addrstr));

			fprintf(f, "%s(%" PRIu32 ",'%s')", (i > 0 ? "," : "")
			       , key->prb_id, addrstr);
		}
		fprintf(f, "])\n");
		fclose(f);
	}
#endif

	for (i = 0; i < sel->n_children; i++)
		report_cap_sel(sel->children[i], report_dir);
}

static void log_probe(probe_counter *pc, const char *base_dir)
{
	char path[4096], fn_spc[3096];
	const char *fn = NULL;
	size_t l, l2;
	FILE *f;

	l = strlcpy(path, base_dir, sizeof(path));
	assert(l > 0 && l < sizeof(path));

	if (path[l - 1] == '/') l -= 1;
	l2 = snprintf( path + l, sizeof(path) - l
		     , "/ID_%" PRIu32, pc->recs->key.prb_id);
	assert(l + l2 < sizeof(path));
	if (dont_report)
		f = NULL;

	else if (!(fn = cap_sel_fn(NULL, fn_spc, sizeof(fn_spc), path, "report.csv"))) {
		fprintf(stderr, "No fn for %s\n", path);
		return;
	}
	else if ((f = fopen(fn, "wx")))
		cap_hdr(f);
	else if (!(f = fopen(fn, "a"))) {
		fprintf(stderr, "No fn for %s\n", path);
		return;
	}
	cap_log(f, &pc->counts);
	if (f)
		fclose(f);
}

void report_asns(rbtree_type *asns, const char *prefix,
    dnst_rec *rec, size_t n_recs, const char *base_dir, struct tm *today)
{
	struct {
		int    asn;
		size_t count;
		cap_sel *sel;
	}            asn_sels[n_asn_sels];
	rbnode_type *n;
	size_t       i;
	time_t       t;
	struct tm    tm;
	const asn_count *ac;
	int          asn;
	int          asn_g, asn_a, asn_6, asn_4;
	size_t       n_diff_asns, asns_counted;
	int          X_asn_v4, X_asn_v6;
	char         path[4096];
	size_t       l, l2;

	i = 0;
	memset(asn_sels, 0, sizeof(asn_sels));
	RBTREE_FOR(n, rbnode_type *, asns) {
		ac = n->key;
		asn_sels[i].asn   = ac->asn;
		asn_sels[i].count = ac->count;
		asn_sels[i].sel   = new_cap_sel(1);
		if (++i >= n_asn_sels)
			break;
	}
	for (; n_recs > 0; n_recs--, rec++) {
		asn = -1;
		t = rec->updated;

		gmtime_r(&t, &tm);
		if (tm.tm_mday != today->tm_mday
		||  tm.tm_mon  != today->tm_mon
		||  tm.tm_year != today->tm_year)
			continue; /* Only records updated on this day */

		switch (*prefix) {
		case 'p': X_asn_v4 = asn_info[rec->asn_info].prb_4;
			  X_asn_v6 = asn_info[rec->asn_info].prb_6;
			  n_diff_asns = X_asn_v4 > 0 ? 1 : 0;
			  if (X_asn_v6 > 0 && X_asn_v6 != X_asn_v4)
				  n_diff_asns += 1;
			  if (n_diff_asns == 0)
				  break;
			  asns_counted = 0;
			  for (i = 0; i < n_asn_sels && asn_sels[i].sel; i++) {
				  if (X_asn_v4 > 0 && X_asn_v4 == asn_sels[i].asn) {
					  count_cap_sel(asn_sels[i].sel, rec);
					  asns_counted += 1;
				  } else if (X_asn_v6 > 0 && X_asn_v6 == asn_sels[i].asn) {
					  count_cap_sel(asn_sels[i].sel, rec);
					  asns_counted += 1;
				  }
				  if (asns_counted >= n_diff_asns)
					  break;
			  }
			  break;

		case 'r': asn = asn_info[rec->asn_info].res;
			  for (i = 0; i < n_asn_sels && asn_sels[i].sel; i++) {
				  if (asn == asn_sels[i].asn) {
					  count_cap_sel(asn_sels[i].sel, rec);
					  break;
				  }
			  }
			  break;

		case 'a': asn_g = asn_info[rec->asn_info].auth_g;
			  asn_a = asn_info[rec->asn_info].auth_a;
			  asn_6 = asn_info[rec->asn_info].auth_6;
			  n_diff_asns = asn_g != 0 ? 1 : 0;
			  if (asn_a != 0 && asn_a != asn_g)
				  n_diff_asns += 1;
			  if (asn_6 != 0 && asn_6 != asn_g && asn_6 != asn_a)
				  n_diff_asns += 1;
			  if (n_diff_asns == 0)
				  break;
			  asns_counted = 0;
			  for (i = 0; i < n_asn_sels && asn_sels[i].sel; i++) {
				  if (asn_g == asn_sels[i].asn) {
					  count_cap_sel(asn_sels[i].sel, rec);
					  asns_counted += 1;
				  } else if (asn_a == asn_sels[i].asn) {
					  count_cap_sel(asn_sels[i].sel, rec);
					  asns_counted += 1;
				  } else if (asn_6 == asn_sels[i].asn) {
					  count_cap_sel(asn_sels[i].sel, rec);
					  asns_counted += 1;
				  }
				  if (asns_counted >= n_diff_asns)
					  break;
			  }
			  break;
		}
	}
	for (i = 0; i < n_asn_sels && asn_sels[i].sel; i++) {
		l = strlcpy(path, base_dir, sizeof(path));
		assert(l > 0 && l < sizeof(path));

		if (path[l - 1] == '/') l -= 1;
		l2 = snprintf( path + l, sizeof(path) - l
			     , "/%s_AS%d", prefix, asn_sels[i].asn);
		assert(l + l2 < sizeof(path));
		report_cap_sel(asn_sels[i].sel, path);
		destroy_cap_sel(asn_sels[i].sel);
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
	cap_sel    *sel = NULL;
	struct tm   tm;
	time_t      t;
	probe_counter *prb_recs, *prb_rec = NULL;
	dnst_rec      *prev_prb_rec;
	size_t         i;
	const char *me;
	
	static const dnst_rec_node node; /* Just for size assertion */
	assert(sizeof(dnst_rec) == sizeof(dnst_rec_node) -
            ((uint8_t *)&node.rec - (uint8_t *)&node));
#if 0
        fprintf(stderr, "sizeof(dnst_rec)        = %zu\n", sizeof(dnst_rec));
        fprintf(stderr, "sizeof(dnst_rec_node)   = %zu\n", sizeof(dnst_rec_node));
        fprintf(stderr, "offset dnst_rec in node = %zu\n",
            ((uint8_t *)&node.rec - (uint8_t *)&node));
#endif
	memset(&today, 0, sizeof(today));

	me = argv[0];
	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'q' && !argv[1][2]) {
		dont_report = 1;
		argc--;
		argv++;
	}
	if (argc != 3)
		printf("usage: %s [ -q ] <resfile> <output_dir>\n", me);

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

	else if ((recs = mmap( NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0))
			== MAP_FAILED)
		fprintf(stderr, "Could not mmap \"%s\"\n", argv[1]);

	else if (!(prb_recs = calloc(st.st_size/sizeof(dnst_rec), sizeof(probe_counter))))
		fprintf(stderr, "Could not allocate mem for prb_recs\n");

	else if (!(sel = new_cap_sel(2)))
		fprintf(stderr, "Could not create counters\n");
	else {
		prb_rec = prb_recs;
		prb_rec->recs = prev_prb_rec = recs;
		prb_rec->node.key = &prb_rec->recs->key.prb_id;
		cap_counter_init(&prb_rec->counts);
 		n_recs = st.st_size / sizeof(dnst_rec);
		if (!(asn_info = calloc(n_recs, sizeof(asn_info_rec))))
			fprintf(stderr, "Could not allocate ASN cache\n");
	}
	if (sel) for (rec = recs, i = 0
	         ; n_recs > 0
		 ; n_recs--, rec++, i++) {

		t = rec->updated;
		rec->asn_info = i;

		gmtime_r(&t, &tm);
		if (tm.tm_mday != today.tm_mday
		||  tm.tm_mon  != today.tm_mon
		||  tm.tm_year != today.tm_year)
			continue; /* Only records updated on this day */

		if (rec->key.prb_id != prev_prb_rec->key.prb_id) {
			prb_rec->n_recs = rec - prb_rec->recs;
			rbtree_insert(&probes, &prb_rec->node);

			prb_rec += 1;
			prb_rec->recs = prev_prb_rec = rec;
			prb_rec->node.key = &prb_rec->recs->key.prb_id;
			cap_counter_init(&prb_rec->counts);
		} 
		count_cap(&prb_rec->counts, rec);
	}
	if (prb_rec) {
		prb_rec->n_recs = rec - prb_rec->recs;
		rbtree_insert(&probes, &prb_rec->node);
	}
	if (sel) RBTREE_FOR(prb_rec, probe_counter *, &probes) {
		/* Reset counter values to zeros and ones. 
		 * (i.e. has this probe a resolver with the capability)
		 *
		 * These will be used to do probe counts for capabilities.
		 * Per probe results should already have been logged.
		 */
		//fprintf(stderr, "%" PRIu32 " in tree\n", prb_rec->recs->key.prb_id);
		size_t *counter = counter_values(&prb_rec->counts);

		if (prb_rec->counts.n_resolvers)
			log_probe(prb_rec, argv[2]);
		for (i = 0; i < (n_caps * 4); i++, counter++) {
			*counter = *counter ? 1 : 0;
		}
	}
	if (sel) for ( n_recs = st.st_size / sizeof(dnst_rec), rec = recs
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
		report_cap_sel(sel, argv[2]);

		n_recs = st.st_size / sizeof(dnst_rec);
		report_asns(&sel->counts.prb_asn_counts, "prb", recs, n_recs, argv[2], &today);
		report_asns(&sel->counts.res_asn_counts, "res", recs, n_recs, argv[2], &today);
		report_asns(&sel->counts.auth_asn_counts, "auth", recs, n_recs, argv[2], &today);
		destroy_cap_sel(sel);
	}
	if (recs && recs != MAP_FAILED)
		munmap(recs, st.st_size);
	if (fd > 0)
		close(fd);
	return 0;
}
