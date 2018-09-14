#include "config.h"
#include "dnst.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <getdns/getdns_extra.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const int quiet = 1;

void dnst_iter_done(dnst_iter *i)
{
	if (i->buf)
		munmap(i->buf, i->end_of_buf - i->buf);
	i->buf = NULL;
	if (i->fd >= 0)
		close(i->fd);
	i->fd = -1;
	i->cur = NULL;
}

dnst *dnst_iter_open(dnst_iter *i)
{
	char fn[4096 + 32 ];
	int r;
	struct stat st;

	r = snprintf( fn, sizeof(fn), "%s/%.4d-%.2d-%.2d.dnst"
	            , i->msm_dir
	            , i->start.tm_year + 1900
	            , i->start.tm_mon  + 1
	            , i->start.tm_mday);

	if (r < 0 || r > sizeof(fn) - 1)
		fprintf(stderr, "Filename parse error\n");

	else if ((i->fd = open(fn, O_RDONLY)) < 0)
		; /* fprintf(stderr, "Could not open \"%s\" (should pass silently)\n", fn); */

	else if (fstat(i->fd, &st) < 0)
		fprintf(stderr, "Could not fstat \"%s\"\n", fn);

	else if (st.st_size < 16)
		fprintf(stderr, "\"%s\" too small\n", fn);
	
	else if ((i->buf = mmap( NULL, st.st_size
	                       , PROT_READ, MAP_PRIVATE, i->fd, 0)) == MAP_FAILED)
		fprintf(stderr, "Could not mmap \"%s\"\n", fn);
	else {
		i->end_of_buf = i->buf + st.st_size;
		return (i->cur = (void *)i->buf);
	}
	if (i->buf)
		munmap(i->buf, i->end_of_buf - i->buf);
	if (i->fd >= 0)
		close(i->fd);

	i->start.tm_mday += 1;
	return (i->cur = NULL);
}

void dnst_iter_next(dnst_iter *i)
{
	i->cur = dnst_next(i->cur);
	if ((uint8_t *)i->cur + 16 < i->end_of_buf)
		return;
	dnst_iter_done(i);
	i->start.tm_mday += 1;
	while (!i->cur && mktime(&i->start) < mktime(&i->stop))
		dnst_iter_open(i);
}

void dnst_iter_init(dnst_iter *i, struct tm *start, struct tm *stop, const char *path)
{
	const char *slash;
	if (mktime(start) >= mktime(stop))
		return;

	i->fd = -1;
	i->start = *start;
	i->stop  = *stop;
	if (!(slash = strrchr(path, '/')))
		i->msm_id = atoi(path);
	else	i->msm_id = atoi(slash + 1);
	(void)strlcpy(i->msm_dir, path, sizeof(i->msm_dir));
	while (!i->cur && mktime(&i->start) < mktime(stop))
		dnst_iter_open(i);
}

static int dnst_cmp(const void *x, const void *y)
{
	return memcmp(x, y, sizeof(dnst_rec_key));
}


static const uint8_t ipv4_mapped_ipv6_prefix[] =
    "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\x00\x00" "\xFF\xFF";

void rec_debug(FILE *f, const char *msg, unsigned int msm_id, uint32_t time, dnst_rec *rec)
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

void log_rec(dnst_rec *rec)
{
	size_t i;

	if (quiet)
		return;

	rec_debug( stdout, 0, 0, rec->updated, rec);
	for (i = 0; i < 12; i++)
		printf(",%" PRIu8, rec->dnskey_alg[i]);
	printf("\n");
	
}

#define PROCESS_DNSKEY_ALG_SECURE(ALG) \
	process_secure( msg \
	              , &rec->secure_reply[(ALG)] \
	              , &rec->bogus_reply[(ALG)] \
	              , &rec->dnskey_alg[(ALG)] )

#define PROCESS_DNSKEY_ALG_BOGUS(ALG) \
	process_bogus( msg \
	             , &rec->bogus_reply[(ALG)] \
	             , &rec->secure_reply[(ALG)] \
	             , &rec->dnskey_alg[(ALG)] )

void process_secure(getdns_dict *msg, uint8_t *secure, uint8_t *bogus, uint8_t *result)
{
	getdns_list *answer;

	if (!getdns_dict_get_list(msg, "answer", &answer)) {
		size_t i = 0;
		getdns_dict *rr;

		for (i = 0; !getdns_list_get_dict(answer, i, &rr); i++) {
			getdns_bindata *ipv4;

			if (getdns_dict_get_bindata(rr, "/rdata/ipv4_address", &ipv4))
				continue;
			if (ipv4->data[0] == 145 && ipv4->data[1] == 97
			&&  ipv4->data[2] ==  20 && ipv4->data[3] == 17) {
				*secure = CAP_DOES;
				if (*bogus == CAP_DOESNT)
					*result  = CAP_DOES;
				else if (*bogus == CAP_DOES)
					*result  = CAP_DOESNT;
				return;
			}
		}
	}
	*secure = CAP_DOESNT;
	if (*bogus != CAP_UNKNOWN)
		*result = CAP_BROKEN;
}

void process_bogus(getdns_dict *msg, uint8_t *bogus, uint8_t *secure, uint8_t *result)
{
	getdns_list *answer;

	if (!getdns_dict_get_list(msg, "answer", &answer)) {
		size_t i = 0;
		getdns_dict *rr;

		for (i = 0; !getdns_list_get_dict(answer, i, &rr); i++) {
			getdns_bindata *ipv4;

			if (getdns_dict_get_bindata(rr, "/rdata/ipv4_address", &ipv4))
				continue;
			if (ipv4->data[0] == 145 && ipv4->data[1] == 97
			&&  ipv4->data[2] ==  20 && ipv4->data[3] == 17) {
				*bogus = CAP_DOES;
				if (*secure == CAP_DOES)
					*result = CAP_DOESNT;
				return;
			}
		}
	}
	*bogus = CAP_DOESNT;
	if (*secure == CAP_DOES)
		*result = CAP_DOES;
}

void process_dnst(dnst *d, unsigned int msm_id)
{
	static rbtree_type recs = { RBTREE_NULL, 0, dnst_cmp };
	dnst_rec_key k;
	dnst_rec *rec;
	getdns_return_t r;
	getdns_dict *msg = NULL;

	k.prb_id = d->prb_id;
	if (d->af == AF_INET6)
		memcpy(k.addr, dnst_addr(d), 16);
	else if (d->af == AF_INET) {
		memcpy( k.addr    , ipv4_mapped_ipv6_prefix, 12);
		memcpy(&k.addr[12], dnst_addr(d), 4);
	} else
		return;

	if (!(rec = (dnst_rec *)rbtree_search(&recs, &k))) {
		rec = calloc(1, sizeof(dnst_rec));
		rec->key = k;
		rec->node.key = &rec->key;
		(void)rbtree_insert(&recs, &rec->node);
	}
	if (d->error || (r = getdns_wire2msg_dict(dnst_msg(d), d->len, &msg))) {
		/* TODO: log error; */
	} else switch (msm_id) {
	case  8310237: /* o-o.myaddr.l.google.com TXT */
	case  8310245: /* whoami.akamai.net A */
	case  8310366: /* <prb_id>.<time>.ripe-hackathon6.nlnetlabs.nl AAAA (ipv6 cap) */
		break;
	case  8926853: /*  secure.d2a1n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 0); break;
	case  8926855: /*  secure.d2a3n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 1); break;
	case  8926857: /*  secure.d2a5n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 2); break;
	case  8926859: /*  secure.d2a6n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 3); break;
	case  8926861: /*  secure.d2a7n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 4); break;
	case  8926863: /*  secure.d2a8n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 5); break;
	case  8926865: /* secure.d2a10n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 6); break;
	case  8926867: /* secure.d2a12n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 7); break;
	case  8926869: /* secure.d2a13n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 8); break;
	case  8926871: /* secure.d2a14n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE( 9); break;
	case  8926873: /* secure.d2a15n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE(10); break;
	case  8926875: /* secure.d2a16n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_SECURE(11); break;
	case  8926854: /*   bogus.d2a1n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 0); break;
	case  8926856: /*   bogus.d2a3n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 1); break;
	case  8926858: /*   bogus.d2a5n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 2); break;
	case  8926860: /*   bogus.d2a6n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 3); break;
	case  8926862: /*   bogus.d2a7n1.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 4); break;
	case  8926864: /*   bogus.d2a8n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 5); break;
	case  8926866: /*  bogus.d2a10n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 6); break;
	case  8926868: /*  bogus.d2a12n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 7); break;
	case  8926870: /*  bogus.d2a13n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 8); break;
	case  8926872: /*  bogus.d2a14n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS( 9); break;
	case  8926874: /*  bogus.d2a15n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS(10); break;
	case  8926876: /*  bogus.d2a16n3.rootcanary.net A */
		PROCESS_DNSKEY_ALG_BOGUS(11); break;
	case  8926887: /*  secure.d3a8n3.rootcanary.net A */
		process_secure( msg
		              , &rec->ds_secure_reply[0]
			      , &rec->ds_bogus_reply[0]
			      , &rec->ds_alg[0]
			      );
		break;
	case  8926911: /*  secure.d4a8n3.rootcanary.net A */
		process_secure( msg
		              , &rec->ds_secure_reply[1]
			      , &rec->ds_bogus_reply[1]
			      , &rec->ds_alg[1]
			      );
		break;
	case  8926888: /*   bogus.d3a8n3.rootcanary.net A */
		process_bogus( msg
			     , &rec->ds_bogus_reply[0]
		             , &rec->ds_secure_reply[0]
			     , &rec->ds_alg[0]
			     );
		break;
	case  8926912: /*   bogus.d4a8n3.rootcanary.net A */
		process_bogus( msg
			     , &rec->ds_bogus_reply[0]
		             , &rec->ds_secure_reply[0]
			     , &rec->ds_alg[0]
			     );
		break;
	case  8310250: /* qnamemintest.internet.nl TXT */
	case  8310360: /* <prb_id>.<time>.tc.ripe-hackathon4.nlnetlabs.nl A    (tcp4 cap) */
	case  8310364: /* <prb_id>.<time>.tc.ripe-hackathon6.nlnetlabs.nl AAAA (tcp6 cap) */
	case  8311777: /* nxdomain.ripe-hackathon2.nlnetlabs.nl A */
	case 15283670: /* root-key-sentinel-not-ta-19036.d2a8n3.rootcanary.net A */
	case 15283671: /* root-key-sentinel-not-ta-20326.d2a8n3.rootcanary.net A */
		break;
	default:
		fprintf(stderr, "Unknown msm_id: %u\n", msm_id);
		return;
	}
	if (rec->updated == 0) {
		rec->updated = d->time;
		rec->logged = d->time;

	} else if (d->time < rec->updated && rec->updated - d->time > 3600) {
		rec_debug( stderr, "Discard > 1 hour back leap", msm_id, d->time, rec);
		return;

	} else if (d->time > rec->updated)
		rec->updated = d->time;

	if (rec->updated - rec->logged > 3600) {
		log_rec(rec);
		rec->logged = d->time;
	}
	if (msg)
		getdns_dict_destroy(msg);
}

int main(int argc, const char **argv)
{
	const char *endptr;
	struct tm   start;
	struct tm   stop;
	dnst_iter  *iters;
	size_t    n_iters, i;

	memset((void *)&start, 0, sizeof(struct tm));
	memset((void *)&stop, 0, sizeof(struct tm));
	if (argc < 4)
		printf("usage: %s <start-date> <stop-date> <msm_dir> [ ... ]\n", argv[0]);

	else if (!(endptr = strptime(argv[1], "%Y-%m-%d", &start)) || *endptr)
		fprintf(stderr, "Could not parse <start-date>\n");

	else if (!(endptr = strptime(argv[2], "%Y-%m-%d", &stop)) || *endptr)
		fprintf(stderr, "Could not parse <stop-date>\n");

	else if (mktime(&start) >= mktime(&stop)) 
		fprintf(stderr, "<start-date> should be < <stop-date> (%d >= %d)\n"
		       , (int)mktime(&start), (int)mktime(&stop));

	else if (!(iters = calloc((n_iters = argc - 3), sizeof(dnst_iter))))
		fprintf(stderr, "Could not allocate dnst_iterators\n");

	else {
		uint32_t prev_t;
		int diff_t = 0;
		dnst_iter *first;

		for (i = 0; i < n_iters; i++)
			dnst_iter_init(&iters[i], &start, &stop, argv[i+3]);

		do {
			first = NULL;
			for (i = 0; i < n_iters; i++) {
				if (iters[i].cur
				&& (!first || iters[i].cur->time < first->cur->time))
					first = &iters[i];
			}
			if (first) {
				process_dnst(first->cur, first->msm_id);
				dnst_iter_next(first);
			}
		} while (first);
		for (i = 0; i < n_iters; i++)
			dnst_iter_done(&iters[i]);
	}
	return 1;
}
