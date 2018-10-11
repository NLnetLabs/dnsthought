#ifndef __DNST_H_
#define __DNST_H_
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include "rbtree.h"

typedef struct dnst {
	uint32_t time;
	float    rt;
	uint32_t prb_id;
	uint8_t  af;    /* AF_INET || AF_INET6 */
	uint8_t  error; /* 0 == packet, 1 == error message */
	uint16_t len;
	union {
		struct {
			uint8_t addr[4];
			uint8_t msg[];
		} ipv4;
		struct {
			uint8_t addr[16];
			uint8_t msg[];
		} ipv6;
	} afu;
} dnst;

static inline size_t dnst_sz(dnst *d)
{ if (d->af == AF_INET6) return sizeof(dnst) + (((d->len + 3) >> 2) << 2)
; else return sizeof(dnst) + (((d->len + 3) >> 2) << 2) - 12; }

static inline uint8_t *dnst_addr(dnst *d)
{ return d->af == AF_INET6 ? d->afu.ipv6.addr : d->afu.ipv4.addr; }

static inline uint8_t *dnst_msg(dnst *d)
{ return d->af == AF_INET6 ? d->afu.ipv6.msg : d->afu.ipv4.msg; }

static inline dnst *dnst_next(dnst *d)
{ return (dnst *)&((uint8_t *)d)[dnst_sz(d)]; }

static inline int dnst_fits(dnst *d, uint8_t *pos)
{ return &((uint8_t *)d)[dnst_sz(d)] <= pos; }

typedef struct dnst_iter {
	struct tm    start;
	struct tm    stop;
	char         msm_dir[4096];
	unsigned int msm_id;
	int          fd;
	uint8_t     *buf;
	uint8_t     *end_of_buf;
	dnst        *cur;
} dnst_iter;

#define CAP_UNKNOWN 0
#define CAP_CAN     1
#define CAP_CANNOT  2
#define CAP_BROKEN  3
#define CAP_DOES    1
#define CAP_DOESNT  2
#define CAP_INTERN  1
#define CAP_FORWARD 2
#define CAP_EXTERN  3

typedef struct dnst_rec_key {
	uint32_t prb_id;   /* key */
	uint8_t  addr[16]; /*******/
} dnst_rec_key;

typedef struct dnst_rec {
	dnst_rec_key key;

	uint32_t updated; /* Discard if difference with previous update
	                   * is more than 1 hour back in time? */
	uint32_t logged;  /* Track time since last update */

	uint8_t         whoami_g[ 4]; /*      8310237 */
	uint8_t         whoami_a[ 4]; /*      8310245 */
	uint8_t         whoami_6[16]; /*      8310366 */
	uint8_t         hijacked[ 4][4]; /*   8311777 */

	uint8_t     secure_reply[12]; /*   1: 8926853,  3: 8926855,  5: 8926857,
	                               *   6: 8926859,  7: 8926861,  8: 8926863,
	                               *  10: 8926865, 12: 8926867, 13: 8926869,
	                               *  14: 8926871, 15: 8926873, 16: 8926875, 
                                       */
	uint8_t      bogus_reply[12]; /*   1: 8926854,  3: 8926856,  5: 8926858,
	                               *   6: 8926860,  7: 8926862,  8: 8926864,
	                               *  10: 8926866, 12: 8926868, 13: 8926870,
	                               *  14: 8926872, 15: 8926874, 16: 8926876, 
                                       */
	uint8_t       dnskey_alg[12]; /*     inferred */

	uint8_t  ds_secure_reply[ 2]; /*  38: 8926887, 48: 8926911 */
	uint8_t   ds_bogus_reply[ 2]; /*  38: 8926888, 48: 8926912 */
	uint8_t            ds_alg[2]; /*     inferred */

	uint8_t         ecs_mask    ; /*     inferred */

	unsigned     qnamemin: 2;     /*      8310250 */
	unsigned     tcp_ipv4: 2;     /*      8310360 */
	unsigned     tcp_ipv6: 2;     /*      8310364 */
	unsigned     nxdomain: 2;     /*      8311777 */

	unsigned not_ta_19036: 2;     /*     15283670 */
	unsigned not_ta_20326: 2;     /*     15283671 */

	unsigned has_ta_19036: 2;     /*     inferred */
	unsigned has_ta_20326: 2;     /*     inferred */

	unsigned  is_ta_20326: 2;     /*     16430285 */

	uint8_t         ecs_mask6   ; /*     inferred */

	uint32_t asn_info;
} dnst_rec;

typedef struct dnst_rec_node {
	struct rbnode_type node;
	dnst_rec rec;
} dnst_rec_node;

typedef struct cap_counters {
	size_t has_ipv6[4];
	size_t tcp_ipv4[4];
	size_t tcp_ipv6[4];
	size_t does_ecs[4];
	size_t qnamemin[4];
	size_t nxdomain[4];
	size_t has_ta_19036[4];
	size_t has_ta_20326[4];
	size_t dnskey_alg[12][4];
	size_t ds_alg[2][4];
	size_t int_ext[4];
} cap_counters;

typedef struct cap_counter {
	uint32_t prev_prb_id;
	uint32_t updated;

	size_t n_resolvers;
	size_t n_probes;

	rbtree_type prb_asns;
	rbtree_type prb_asn_counts;
	rbtree_type res_asns;
	rbtree_type res_asn_counts;
	rbtree_type auth_asns;
	rbtree_type auth_asn_counts;
	rbtree_type nxhj_asns;;
	rbtree_type nxhj_asn_counts;
	rbtree_type ecs_masks;
	rbtree_type ecs_counts;
	rbtree_type ecs6_masks;
	rbtree_type ecs6_counts;

	cap_counters res;
	cap_counters prbs;

	size_t       prb_ids_sz;
	uint32_t    *prb_ids;

	size_t       reses_sz;
	dnst_rec**   reses;
} cap_counter;

typedef struct probe_counter {
	rbnode_type node;
	dnst_rec   *recs;
	size_t    n_recs;
	cap_counter counts;
} probe_counter;

static inline size_t *counter_values(cap_counter *cc)
{ return cc->res.has_ipv6; }
static inline size_t *probe_counter_values(cap_counter *cc)
{ return cc->prbs.has_ipv6; }

typedef struct cap_descr {
	uint8_t   n_vals;
	const char *val_names[4];
	uint8_t (*get_val)(dnst_rec *rec);
} cap_descr;

#endif
