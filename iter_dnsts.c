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
#include "dnst.h"

void error_dnst(int msm_id, dnst *d, int prb_id, const char *ip, const char *ts, float rt,
    int len, const char *error)
{
	printf("%s, rt: %7.2fms, %5d_%s\n\terror: \"%.*s\""
	      , ts, rt, prb_id, ip, len, error);
}

void process_dnst(int msm_id, dnst *d, int prb_id, const char *ip, const char *ts, float rt,
    getdns_dict *msg)
{
	char *msg_str;
	getdns_return_t r;

	if ((r = getdns_msg_dict2str(msg, &msg_str))) {
		const char *err_msg = getdns_get_errorstr_by_id(r);
		error_dnst(msm_id, d, prb_id, ip, ts, rt, strlen(err_msg), err_msg);
		return;
	}
	printf("%s, rt: %7.2fms, %5d_%s\n%s\n", ts, rt, prb_id, ip, msg_str);
	free(msg_str);
}

int parse_dnsts(uint8_t *buf, size_t sz, int msm_id)
{
	uint8_t *eob = buf + sz;
	dnst *d = (void *)buf;

	for ( d = (void *)buf
	    ; ((uint8_t *)d) + 16 < eob
	    ; d = dnst_next(d)) {

		char time_str[20];
		size_t time_str_sz;
		time_t ts = d->time;
		struct tm tm_buf, *tm;
		char addr_str[64];
		getdns_dict *msg;
		getdns_return_t r;
		
		tm = localtime_r(&ts, &tm_buf);
		assert(tm);

		time_str_sz = strftime(time_str, sizeof(time_str)
		                      , "%Y-%m-%d %H:%M.%S", tm);
		assert(time_str_sz < sizeof(time_str));

		if (!inet_ntop(d->af, dnst_addr(d), addr_str, sizeof(addr_str)))
			continue;

		if (d->error)
			error_dnst(msm_id, d, d->prb_id, addr_str, time_str, d->rt
			                    , d->len, (char *)dnst_msg(d));

		else if ((r = getdns_wire2msg_dict(dnst_msg(d), d->len, &msg))) {
			const char *err_msg = getdns_get_errorstr_by_id(r);
			error_dnst(msm_id, d, d->prb_id, addr_str, time_str, d->rt
			                    , strlen(err_msg), err_msg);
		} else {
			process_dnst(msm_id, d, d->prb_id, addr_str, time_str, d->rt, msg);
			getdns_dict_destroy(msg);
		}
		if (!dnst_fits(d, eob))
			break;
	}
	printf("%p %p\n", buf, eob);
	return 0;
}

void dnst_iter_done(dnst_iter *d)
{
	if (d->buf)
		munmap(d->buf, d->end_of_buf - d->buf);
	d->buf = NULL;
	if (d->fd >= 0)
		close(d->fd);
	d->fd = -1;
	d->cur = NULL;
}

dnst *dnst_iter_open(dnst_iter *d)
{
	char fn[4096 + 32 ];
	int r;
	struct stat st;

	r = snprintf( fn, sizeof(fn), "%s/%.4d-%.2d-%.2d.dnst"
	            , d->msm_dir
	            , d->start.tm_year + 1900
	            , d->start.tm_mon  + 1
	            , d->start.tm_mday);

	if (r < 0 || r > sizeof(fn) - 1)
		fprintf(stderr, "Filename parse error\n");

	else if ((d->fd = open(fn, O_RDONLY)) < 0)
		/* TODO: replace with silent pass */
		fprintf(stderr, "Could not open \"%s\" (should pass silently)\n", fn);

	else if (fstat(d->fd, &st) < 0)
		fprintf(stderr, "Could not fstat \"%s\"\n", fn);

	else if (st.st_size < 16)
		fprintf(stderr, "\"%s\" too small\n", fn);
	
	else if ((d->buf = mmap( NULL, st.st_size
	                       , PROT_READ, MAP_PRIVATE, d->fd, 0)) == MAP_FAILED)
		fprintf(stderr, "Could not mmap \"%s\"\n", fn);
	else {
		d->end_of_buf = d->buf + st.st_size;
		return (d->cur = (void *)d->buf);
	}
	if (d->buf)
		munmap(d->buf, d->end_of_buf - d->buf);
	if (d->fd >= 0)
		close(d->fd);

	d->start.tm_mday += 1;
	return (d->cur = NULL);
}

void dnst_iter_next(dnst_iter *d)
{
	d->cur = dnst_next(d->cur);
	if ((uint8_t *)d->cur + 16 < d->end_of_buf)
		return;
	dnst_iter_done(d);
	d->start.tm_mday += 1;
	while (!d->cur && mktime(&d->start) < mktime(&d->stop))
		dnst_iter_open(d);
}

void dnst_iter_init(dnst_iter *d, struct tm *start, struct tm *stop, const char *path)
{
	if (mktime(start) >= mktime(stop))
		return;

	d->fd = -1;
	d->start = *start;
	d->stop  = *stop;
	(void)strlcpy(d->msm_dir, path, sizeof(d->msm_dir));
	while (!d->cur && mktime(&d->start) < mktime(stop))
		dnst_iter_open(d);
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
				printf("%" PRIu32 "\n", first->cur->time);
				dnst_iter_next(first);
			}
		} while (first);
		for (i = 0; i < n_iters; i++)
			dnst_iter_done(&iters[i]);
	}

	/*
	else while (mktime(&start) < mktime(&stop)) {

		printf("%.4d-%.2d-%.2d\n"
		      , start.tm_year+1900, start.tm_mon+1, start.tm_mday);
		start.tm_mday += 1;
	}

	else if ((fd = open(argv[1], O_RDONLY)) < 0)
		perror("Could not open input file");

	else if (fstat(fd, &st) < 0)
		perror("Could not stat input file");

	else if ((buf = mmap( NULL, st.st_size
	                     , PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		perror("Could not mmap input file");
	else
		return parse_dnsts(buf, st.st_size, argc == 3 ? atoi(argv[3]): 0);

	if (buf)
		munmap(buf, st.st_size);
	if (fd >= 0)
		close(fd);
	*/

	return 1;
}
