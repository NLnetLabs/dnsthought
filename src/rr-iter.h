/**
 *
 * /brief RR iterator over wireformat DNS packet
 */
/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RR_ITER_H_
#define RR_ITER_H_
#include <stdint.h>

#define RRTYPE_A	 1
#define RRTYPE_CNAME	 5
#define RRTYPE_TXT	16
#define RRTYPE_AAAA	28
#define RRTYPE_RRSIG	46

#define DNS_HEADER_SIZE	12

/* Second octet of flags */
#define RCODE_MASK	0x0fU
#define RCODE_WIRE(W)	(*((W)+3) & RCODE_MASK)
#define RCODE_SET(W, R)	(*((W)+3) = ((*((W)+3)) & ~RCODE_MASK) | (R))

#define RCODE_NOERROR	 0
#define RCODE_FORMERR	 1
#define RCODE_SERVFAIL	 2
#define RCODE_NXDOMAIN	 3

static inline uint16_t READ_U16(const void *src)
{ const uint8_t *p = src; return ((uint16_t)p[0]<<8)|(uint16_t)p[1]; }

/* Counter of the question section */
#define DNS_MSG_QDCOUNT_OFF               4
#define DNS_MSG_QDCOUNT(wirebuf)          (READ_U16(wirebuf+DNS_MSG_QDCOUNT_OFF))

/* Counter of the answer section */
#define DNS_MSG_ANCOUNT_OFF               6
#define DNS_MSG_ANCOUNT(wirebuf)          (READ_U16(wirebuf+DNS_MSG_ANCOUNT_OFF))

/* Counter of the authority section */
#define DNS_MSG_NSCOUNT_OFF               8
#define DNS_MSG_NSCOUNT(wirebuf)          (READ_U16(wirebuf+DNS_MSG_NSCOUNT_OFF))

/* Counter of the additional section */
#define DNS_MSG_ARCOUNT_OFF               10
#define DNS_MSG_ARCOUNT(wirebuf)          (READ_U16(wirebuf+DNS_MSG_ARCOUNT_OFF))


typedef enum section {
	SECTION_QUESTION      =  1,
	SECTION_ANSWER        =  2,
	SECTION_AUTHORITY     =  4,
	SECTION_ADDITIONAL    =  8,
	SECTION_ANY           = 15,
	SECTION_NO_QUESTION   = 14,
	SECTION_NO_ADDITIONAL =  6
} section;

int dname_equal(const uint8_t *s1, const uint8_t *s2);

typedef struct rr_iter {
	const uint8_t *pkt;
	const uint8_t *pkt_end;

	/* Which RR are we currently at */
	size_t   n;

	/* pos points to start of the owner name the RR.
	 * Or is NULL when there are no RR's left.
	 */
	const uint8_t *pos;

	/* rr_type will point to the rr_type right after the RR's owner name.
	 * rr_type is guaranteed to have a value when pos has a value
	 */
	const uint8_t *rr_type;

	/* nxt point to the owner name of the next RR or to pkt_end */
	const uint8_t *nxt;

} rr_iter;

rr_iter *rr_iter_init(rr_iter *i,
    const uint8_t *pkt, const size_t pkt_len);

rr_iter *single_rr_iter_init(rr_iter *i,
    const uint8_t *wire, const size_t wire_len);

static inline rr_iter *rr_iter_rewind(rr_iter *i)
{ return i ? rr_iter_init(i, i->pkt, i->pkt_end - i->pkt) : NULL; }

rr_iter *rr_iter_next(rr_iter *i);

const uint8_t *owner_if_or_as_decompressed(
    rr_iter *i, uint8_t *ff_bytes, size_t *len);

static inline section 
rr_iter_section(rr_iter *i)
{
	return ! i->pkt ? (i->nxt - i->rr_type == 4   ? SECTION_QUESTION
	                                              : SECTION_ANSWER  )
             : i->n < (size_t)DNS_MSG_QDCOUNT(i->pkt) ? SECTION_QUESTION
	     : i->n < (size_t)DNS_MSG_QDCOUNT(i->pkt)
	                    + DNS_MSG_ANCOUNT(i->pkt) ? SECTION_ANSWER
	     : i->n < (size_t)DNS_MSG_QDCOUNT(i->pkt)
	                    + DNS_MSG_ANCOUNT(i->pkt)
	                    + DNS_MSG_NSCOUNT(i->pkt) ? SECTION_AUTHORITY
	     : i->n < (size_t)DNS_MSG_QDCOUNT(i->pkt)
	                    + DNS_MSG_ANCOUNT(i->pkt)
	                    + DNS_MSG_NSCOUNT(i->pkt)
	                    + DNS_MSG_ARCOUNT(i->pkt) ? SECTION_ADDITIONAL
	                                              : SECTION_ANY;
}

/* Utility functions to read rr_type and rr_class from a rr iterator */
static inline uint16_t rr_iter_type(rr_iter *rr)
{ return rr->rr_type + 2 <= rr->nxt ? READ_U16(rr->rr_type) : 0; }

static inline uint16_t rr_iter_class(rr_iter *rr)
{ return rr->rr_type + 4 <= rr->nxt ? READ_U16(rr->rr_type + 2) : 0; }

typedef struct rrset {
	const uint8_t  *name;
	uint16_t        rr_class;
	uint16_t        rr_type;
	const uint8_t  *pkt;
	size_t          pkt_len;
	section sections;
} rrset;

typedef struct rrset_spc {
	rrset rrset;
	uint8_t       name_spc[256];
	size_t        name_len;
} rrset_spc;

rrset *rrset_answer(
    rrset_spc *rrset2init, const uint8_t *pkt, size_t pkt_len);

rrset *initialized_rrset_answer(
    rrset_spc *query_rrset);

typedef struct rrtype_iter {
	rr_iter  rr_i;
	rrset   *rrset;
} rrtype_iter;

rrtype_iter *rrtype_iter_init(
    rrtype_iter *i, rrset *rrset);
rrtype_iter *rrtype_iter_next(rrtype_iter *i);

static inline int rrset_has_rrs(rrset *rrset)
{
	rrtype_iter rr_spc;
	return rrtype_iter_init(&rr_spc, rrset) != NULL;
}

typedef struct rrsig_iter {
	rr_iter  rr_i;
	rrset   *rrset;
} rrsig_iter;

rrsig_iter *rrsig_iter_init(
    rrsig_iter *i, rrset *rrset);
rrsig_iter *rrsig_iter_next(rrsig_iter *i);


static inline int rrset_has_rrsigs(rrset *rrset)
{
	rrsig_iter rrsig;
	return rrsig_iter_init(&rrsig, rrset) != NULL;
}

/* The rrset_iter manifests an iterator of a wireformat packet that
 * will return all unique rrsets within that packet in turn.
 */
typedef struct rrset_iter {
	rrset   rrset;
	uint8_t name_spc[256];
	size_t  name_len;
	rr_iter rr_i;
} rrset_iter;


rrset_iter *rrset_iter_init(rrset_iter *i,
    const uint8_t *pkt, size_t pkt_len, section sections);
rrset_iter *rrset_iter_next(rrset_iter *i);

static inline rrset *rrset_iter_value(rrset_iter *i)
{ return i && i->rr_i.pos ? &i->rrset : NULL; }

static inline rrset_iter *rrset_iter_rewind(rrset_iter *i)
{ return i ? rrset_iter_init(i, i->rrset.pkt, i->rrset.pkt_len, i->rrset.sections) : NULL; }

# if 0
typedef struct rdf_iter {
	const uint8_t           *pkt;
	const uint8_t           *pkt_end;
	const rdata_def *rdd_pos;
	const rdata_def *rdd_end;
	const rdata_def *rdd_repeat;
	const uint8_t           *pos;
	const uint8_t           *end;
	const uint8_t           *nxt;
} rdf_iter;

rdf_iter *rdf_iter_init(rdf_iter *i,
    rr_iter *rr);

rdf_iter *rdf_iter_next(rdf_iter *i);

rdf_iter *rdf_iter_init_at(rdf_iter *i,
    rr_iter *rr, size_t pos);

const uint8_t *rdf_if_or_as_decompressed(
    rdf_iter *i, uint8_t *ff_bytes, size_t *len);
# endif

#endif
