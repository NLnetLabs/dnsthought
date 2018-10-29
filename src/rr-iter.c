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

#include "config.h"
#include "rr-iter.h"
#include <ctype.h>
#include <assert.h>

#define MAX_CNAME_REFERRALS	256
#define MAX_DNAME_POINTERS	256	

int
dname_equal(const uint8_t *s1, const uint8_t *s2)
{
	uint8_t i;
	for (;;) {
		if (*s1 != *s2)
			return 0;
		else if (!*s1)
			return 1;
		for (i = *s1++, s2++; i > 0; i--, s1++, s2++)
			if (*s1 != *s2 && tolower((unsigned char)*s1)
			               != tolower((unsigned char)*s2))
				return 0;
	}
}

static void
rr_iter_find_nxt(rr_iter *i)
{
	assert(i);
	assert(i->rr_type);

	i->nxt = i->pkt && i->n < DNS_MSG_QDCOUNT(i->pkt)
	       ? i->rr_type + 4
	       : i->rr_type + 10 > i->pkt_end
	       ? i->pkt_end
	       : i->rr_type + 10 + READ_U16(i->rr_type + 8) > i->pkt_end
	       ? i->pkt_end
	       : i->rr_type + 10 + READ_U16(i->rr_type + 8);
}

static rr_iter *
find_rrtype(rr_iter *i)
{
	const uint8_t *pos;

	assert(i);
	assert(i->pos);

	/* Past the last RR in the pkt */
	if (i->pkt &&
	    (size_t)DNS_MSG_QDCOUNT(i->pkt) + DNS_MSG_ANCOUNT(i->pkt) +
	            DNS_MSG_NSCOUNT(i->pkt) + DNS_MSG_ARCOUNT(i->pkt) <= i->n)
		goto done;

	for (pos = i->pos; pos + 4 < i->pkt_end; pos += *pos + 1)
		if (!*pos) {
			i->rr_type = pos + 1;
			rr_iter_find_nxt(i);
			return i;

		} else if ((*pos & 0xC0) == 0xC0) {
			if ( pos + 6 > i->pkt_end)
				break; /* No space for class */

			i->rr_type = pos + 2;
			rr_iter_find_nxt(i);
			return i;

		} else if (*pos & 0xC0)
			break; /* Unknown label type */
done:
	i->pos = NULL;
	return NULL;
}

rr_iter *
rr_iter_init(rr_iter *i, const uint8_t *pkt, const size_t pkt_len)
{
	assert(i);

	if (!pkt || pkt_len < DNS_HEADER_SIZE + 5) {
		i->pos = NULL;
		return NULL;
	}
	i->pkt     = pkt;
	i->pkt_end = pkt + pkt_len;
	i->n       = 0;
	i->pos     = pkt + DNS_HEADER_SIZE;

	return find_rrtype(i);
}

rr_iter *
single_rr_iter_init(
    rr_iter *i, const uint8_t *wire, const size_t wire_len)
{
	assert(i);

	if (!wire || wire_len < 5 /* name + type + class */) {
		i->pos = NULL;
		return NULL;
	}
	i->pkt     = NULL;
	i->pos     = wire;
	i->pkt_end = wire + wire_len;
	i->n       = 0;

	return find_rrtype(i);
}

rr_iter *
rr_iter_next(rr_iter *i)
{
	assert(i);

	/* Already done */
	if (!i->pos)
		return NULL;

	i->n  += 1;
	i->pos = i->nxt;
	return find_rrtype(i);
}

static const uint8_t *
dname_if_or_as_decompressed(const uint8_t *pkt, const uint8_t *pkt_end,
    const uint8_t *pos, uint8_t *buf, size_t *len, size_t refs)
{
	uint16_t offset;
	const uint8_t *start;
	uint8_t *dst;

	assert(pkt_end);
	assert(pos);
	assert(buf);
	assert(len);

	if (refs > MAX_DNAME_POINTERS)
		goto error;

	if ((*pos & 0xC0) == 0xC0) {
		if (!pkt || pos + 1 >= pkt_end)
			goto error;
		offset = READ_U16(pos) & 0x3FFF;
		if (pkt + offset >= pkt_end)
			goto error;
		return dname_if_or_as_decompressed(pkt, pkt_end, pkt + offset,
		    buf, len, refs + 1);
	}
	if (*pos & 0xC0)
		goto error;

	start = pos;
	*len  = 0;
	while (*pos) {
		if ((*pos & 0xC0) == 0xC0)
			break;

		else if (*pos & 0xC0)
			goto error;

		*len += *pos + 1;
		pos += *pos + 1;
	}
	if (!*pos) {
		*len += 1;
		return start;
	}
	dst = buf;
	for (;;) {
		if (pos > start) {
			if (dst + (pos - start) > buf + 255)
				goto error;
			(void) memcpy(dst, start, pos - start);
			dst += (pos - start);
			start = pos;
		}
		if ((*pos & 0xC0) == 0xC0) {
			if (!pkt || pos + 1 >= pkt_end)
				goto error;
			offset = READ_U16(pos) & 0x3FFF;
			if (pkt + offset >= pkt_end)
				goto error;

			start = pos = pkt + offset;
			if (++refs > 256)
				goto error;
		}
		if ((*pos & 0xC0) == 0xC0)
			continue;

		else if (*pos & 0xC0)
			goto error;

		else if (!*pos) {
			*len += 1;
			*dst = 0;
			return buf;
		}
		*len += *pos + 1;
		pos += *pos + 1;
	}
error:
	*len = 0;
	return NULL;
}

const uint8_t *
owner_if_or_as_decompressed(rr_iter *i,
    uint8_t *ff_bytes, size_t *len)
{
	return dname_if_or_as_decompressed(i->pkt, i->pkt_end, i->pos,
	    ff_bytes, len, 0);
}

rrset *
initialized_rrset_answer(rrset_spc *query_rrset)
{
	rrset *rrset = &query_rrset->rrset;
	uint16_t qtype = rrset->rr_type;
	size_t cname_loop_protection;

	assert(query_rrset);

	/* Follow CNAMEs */
	rrset->rr_type = RRTYPE_CNAME;
	for ( cname_loop_protection = MAX_CNAME_REFERRALS
	    ; cname_loop_protection > 0
	    ; cname_loop_protection-- ) {
		rrtype_iter rr_spc, *rr;

		if (!(rr = rrtype_iter_init(&rr_spc, rrset)))
			break;
		if (!rr->rr_i.pos /* A rr */
		||   rr->rr_i.rr_type + 11 > rr->rr_i.pkt_end /* space for rdata */
		||   rr->rr_i.rr_type + 10 + READ_U16(rr->rr_i.rr_type + 8)
		                           > rr->rr_i.pkt_end /* space for rdata */ )
			break;
		query_rrset->name_len = sizeof(query_rrset->name_spc);
		rrset->name = dname_if_or_as_decompressed(
		    rr->rr_i.pkt, rr->rr_i.pkt_end,
		    rr->rr_i.rr_type + 10,
		    query_rrset->name_spc, &query_rrset->name_len, 0);
	}
	rrset->rr_type = qtype;
	if (qtype == RRTYPE_CNAME &&
	    cname_loop_protection < MAX_CNAME_REFERRALS)
		return rrset; /* The CNAME was the answer */

	return rrset_has_rrs(rrset) ? rrset : NULL;
}

rrset *
rrset_answer(rrset_spc *spc, const uint8_t *pkt, size_t len)
{
	rr_iter rr_spc, *rr;

	assert(spc);

	spc->rrset.name = NULL;
	spc->name_len = sizeof(spc->name_spc);
	if (   !(rr = rr_iter_init(&rr_spc, pkt, len))
	    || rr_iter_section(rr) != SECTION_QUESTION
	    || !(spc->rrset.name = owner_if_or_as_decompressed(
			    rr, spc->name_spc, &spc->name_len))
	    || rr->nxt < rr->rr_type + 4)
		return NULL;

	spc->rrset.rr_class = rr_iter_class(rr);
	spc->rrset.rr_type = rr_iter_type(rr);
	spc->rrset.pkt = pkt;
	spc->rrset.pkt_len = len;
	spc->rrset.sections = SECTION_ANSWER;
	return initialized_rrset_answer(spc);
}

/* Utility function to compare owner name of rr with name */
static int rr_owner_equal(rr_iter *rr, const uint8_t *name)
{
	uint8_t owner_spc[256];
	const uint8_t *owner;
	size_t  owner_len = sizeof(owner_spc);

	return (owner = owner_if_or_as_decompressed(rr, owner_spc
	                                                      ,&owner_len))
	    && name && dname_equal(owner, name);
}

/* First a few filter functions that filter a RR iterator to point only
 * to RRs with certain constraints (and moves on otherwise).
 */

/* Filter that only iterates over the sections */
static inline rr_iter *rr_iter_section_filter(
    rr_iter *rr, section sections)
{
	while (rr && rr->pos && !(sections & rr_iter_section(rr)))
		rr = rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

/* Filter that only iterates over RRs with a certain name/class/type */
static rr_iter *rr_iter_name_class_type(rr_iter *rr,
    const uint8_t *name, uint16_t rr_class, uint16_t rr_type,
    section sections)
{
	while (rr_iter_section_filter(rr, sections) && !(
	    rr_iter_type(rr)  == rr_type  &&
	    rr_iter_class(rr) == rr_class &&
	    rr_owner_equal(rr, name)))

		rr = rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

/* Filter that only iterates over RRs that do not have a name/class/type */
static rr_iter *rr_iter_not_name_class_type(rr_iter *rr,
    const uint8_t *name, uint16_t rr_class, uint16_t rr_type,
    section sections)
{
	while (rr_iter_section_filter(rr, sections) && (
	    rr_iter_type(rr)  == RRTYPE_RRSIG || (
	    rr_iter_type(rr)  == rr_type  &&
	    rr_iter_class(rr) == rr_class &&
	    rr_owner_equal(rr, name))))

		rr = rr_iter_next(rr);
	
	return rr && rr->pos ? rr : NULL;
}

/* Filter that only iterates over RRs that are of type RRSIG, that cover
 * a RRset with a certain name/class/type
 */
static rr_iter *rr_iter_rrsig_covering(rr_iter *rr,
    const uint8_t *name, uint16_t rr_class, uint16_t rr_type,
    section sections)
{
	while (rr_iter_section_filter(rr, sections) && !(
	    rr_iter_type(rr)  == RRTYPE_RRSIG &&
	    rr_iter_class(rr) == rr_class &&
	    rr->rr_type + 12 <= rr->nxt &&
	    READ_U16(rr->rr_type + 10) == rr_type && 
	    rr_owner_equal(rr, name)))

		rr = rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

rrtype_iter *
rrtype_iter_next(rrtype_iter *i)
{
	return (rrtype_iter *) rr_iter_name_class_type(
	    rr_iter_next(&i->rr_i),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type,
	    i->rrset->sections);
}

rrtype_iter *
rrtype_iter_init(rrtype_iter *i, rrset *rrset)
{
	i->rrset = rrset;
	return (rrtype_iter *) rr_iter_name_class_type(
	    rr_iter_init(&i->rr_i, rrset->pkt, rrset->pkt_len ),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type,
	    i->rrset->sections);
}

rrsig_iter *
rrsig_iter_next(rrsig_iter *i)
{
	return (rrsig_iter *) rr_iter_rrsig_covering(
	    rr_iter_next(&i->rr_i),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type,
	    i->rrset->sections);
}

rrsig_iter *
rrsig_iter_init(rrsig_iter *i, rrset *rrset)
{
	i->rrset = rrset;
	return (rrsig_iter *) rr_iter_rrsig_covering(
	    rr_iter_init(&i->rr_i, rrset->pkt, rrset->pkt_len),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type,
	    i->rrset->sections);
}

rrset_iter *
rrset_iter_init(rrset_iter *i,
    const uint8_t *pkt, size_t pkt_len, section sections)
{
	rr_iter *rr;

	i->rrset.name = i->name_spc;
	i->rrset.pkt = pkt;
	i->rrset.pkt_len = pkt_len;
	i->rrset.sections = sections;
	i->name_len = 0;

	for ( rr = rr_iter_init(&i->rr_i, pkt, pkt_len)
	    ;(rr = rr_iter_section_filter(rr, sections))
	    ; rr = rr_iter_next(rr)) {

		if ((i->rrset.rr_type = rr_iter_type(rr))
		    == RRTYPE_RRSIG)
			continue;

		i->rrset.rr_class = rr_iter_class(rr);

		if (!(i->rrset.name = owner_if_or_as_decompressed(
		    rr, i->name_spc, &i->name_len)))
			continue;

		return i;
	}
	return NULL;
}

rrset_iter *rrset_iter_next(rrset_iter *i)
{
	rr_iter *rr;

	if (!(rr = i && i->rr_i.pos ? &i->rr_i : NULL))
		return NULL;

	if (!(rr = rr_iter_not_name_class_type(rr,
	    i->rrset.name, i->rrset.rr_class, i->rrset.rr_type,
	    i->rrset.sections)))
		return NULL;

	i->rrset.rr_type  = rr_iter_type(rr);
	i->rrset.rr_class = rr_iter_class(rr);
	if (!(i->rrset.name = owner_if_or_as_decompressed(
		    rr, i->name_spc, &i->name_len)))

		/* This is safe, because rr_iter_not_name_class_type will shift
		 * the iterator forward because at least name does not match.
		 * Goal is to skip broken compression pointer issues but keep
		 * processing the packet.
		 */
		return rrset_iter_next(i);

	return i;
}


