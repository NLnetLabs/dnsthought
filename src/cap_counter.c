#include "config.h"
#include "dnst.h"
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

static int quiet = 0;

static const uint8_t ipv4_mapped_ipv6_prefix[] =
    "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\xFF\xFF";

static void
rec_debug(FILE *f, const char *msg, unsigned int msm_id, uint32_t time, dnst_rec *rec)
{
	char addrstr[80];
	char timestr[80];
	struct tm tm;
	time_t t = time;

	gmtime_r(&t, &tm);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M.%S", &tm);

	if (memcmp(rec->key.addr, ipv4_mapped_ipv6_prefix, 12) == 0)
		inet_ntop(AF_INET, &rec->key.addr[12], addrstr, sizeof(addrstr));
	else
		inet_ntop(AF_INET6, rec->key.addr    , addrstr, sizeof(addrstr));

	if (msg)
		fprintf(f, "%s ", msg);
	if (msm_id)
		fprintf(f, "%5u ", msm_id);
	fprintf( f, "%s %5" PRIu32 "_%s\n"
	       , timestr, rec->key.prb_id, addrstr);
}

static void
log_rec(FILE *out, dnst_rec *rec)
{
	size_t i;
	char addrstr[80];
	char timestr[80];
	struct tm tm;
	time_t t;

	if (!out)
		return;

	t = rec->updated;
	gmtime_r(&t, &tm);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S+00", &tm);

	if (memcmp(rec->key.addr, ipv4_mapped_ipv6_prefix, 12) == 0)
		inet_ntop(AF_INET, &rec->key.addr[12], addrstr, sizeof(addrstr));
	else
		inet_ntop(AF_INET6, rec->key.addr    , addrstr, sizeof(addrstr));

	fprintf(out, "%s,%" PRIu32 ",%s"
	       , timestr, rec->key.prb_id, addrstr);
	if (memcmp(rec->whoami_g, "\x00\x00\x00\x00", 4) == 0)
		fprintf(out, ",NULL");
	else	fprintf(out, ",%s", inet_ntop( AF_INET, rec->whoami_g
		                               , addrstr, sizeof(addrstr)));

	if (memcmp(rec->whoami_a, "\x00\x00\x00\x00", 4) == 0)
		fprintf(out, ",NULL");
	else	fprintf(out, ",%s", inet_ntop( AF_INET, rec->whoami_a
		                               , addrstr, sizeof(addrstr)));
	if (memcmp(rec->whoami_6, "\x00\x00\x00\x00\x00\x00\x00\x00"
	                          "\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0)
		fprintf(out, ",NULL");
	else	fprintf(out, ",%s", inet_ntop( AF_INET6, rec->whoami_6
		                               , addrstr , sizeof(addrstr)));

	for (i = 0; i < 12; i++)
		fprintf(out, ",%" PRIu8, rec->dnskey_alg[i]);
	for (i = 0; i < 2; i++)
		fprintf(out, ",%" PRIu8, rec->ds_alg[i]);
	fprintf(out, ",%" PRIu8, rec->ecs_mask);
	fprintf(out, ",%d", (int)rec->qnamemin);
	fprintf(out, ",%d", (int)rec->tcp_ipv4);
	fprintf(out, ",%d", (int)rec->tcp_ipv6);
	fprintf(out, ",%d", (int)rec->nxdomain);
	fprintf(out, ",%d", (int)rec->has_ta_19036);
	fprintf(out, ",%d", (int)rec->has_ta_20326);
	fprintf(out, "\n");
}

void count_cap(cap_counter *cap, dnst_rec *rec, int incr_n_probes)
{
	size_t i;

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
	
	assert(sizeof(dnst_rec) == 104);

	memset(&cap, 0, sizeof(cap));
	memset(&qnamemincap, 0, sizeof(qnamemincap));
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
	size_t i, n_res_per_qprb = 0, n_qres_per_qprb = 0, n_qnamemin_only = 0, n_res_qnamemin_only = 0;
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

	if (recs && recs != MAP_FAILED)
		munmap(recs, st.st_size);
	if (fd > 0)
		close(fd);
	return 0;
}
