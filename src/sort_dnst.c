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
#include "dnst.h"

void error_dnst(int msm_id, dnst *d, int prb_id, const char *ip, const char *ts, float rt,
    int len, const char *error)
{
	printf("%s, rt: %7.2fms, %5d_%s\n\terror: \"%.*s\""
	      , ts, rt, prb_id, ip, len, error);
}

void process_dnst(int msm_id, dnst *d, int prb_id, const char *ip, const char *ts, float rt)
{
	printf("%s, rt: %7.2fms, %5d_%s\n", ts, rt, prb_id, ip);
}

int dnst_time_cmp(const void *x, const void *y)
{ return (*(dnst **)x)->time == (*(dnst **)y)->time ? 0
       : (*(dnst **)x)->time >  (*(dnst **)y)->time ? 1 : -1; }

int sort_dnsts(uint8_t *buf, size_t sz, const char *fn, int dodel)
{
	uint8_t *eob = buf + sz;
	dnst *d = (void *)buf, **refs;
	size_t i, j;
	uint32_t prev_time, min_time, max_time;
	int sorted = 1;
	int fd = -1;
	char min_timestr[40], max_timestr[40];
	struct tm min_tm, max_tm;
	time_t min_t, max_t;
	uint8_t *wr_buf;

	min_time = 0xFFFFFFFF;
	max_time = 0;
	for ( d = (void *)buf, i = 0, prev_time = 0
	    ; ((uint8_t *)d) + 16 < eob
	    ; d = dnst_next(d), i++) {

		if (d->time < prev_time)
			sorted = 0;
		if (d->time < min_time)
			min_time = d->time;
		if (d->time > max_time)
			max_time = d->time;
		prev_time = d->time;

		if (!dnst_fits(d, eob))
			break;
	}
	fprintf(stderr, "%" PRIu32 " ... %" PRIu32 "\n", min_time, max_time);
	min_t = min_time;
	gmtime_r(&min_t, &min_tm);
	strftime(min_timestr, sizeof(min_timestr), "%Y-%m-%dT%H:%M:%SZ", &min_tm);
	max_t = max_time;
	gmtime_r(&max_t, &max_tm);
	strftime(max_timestr, sizeof(max_timestr), "%Y-%m-%dT%H:%M:%SZ", &max_tm);
	fprintf(stderr, "%s ... %s\n", min_timestr, max_timestr);
	min_tm.tm_mday += 1;
	min_tm.tm_hour = 0;
	min_tm.tm_min  = 0;
	min_tm.tm_sec  = 0;
	min_t = timegm(&min_tm);

	if ((min_t > max_t && min_t - max_t > 300)
	||  (max_t > min_t && max_t - min_t > 300)) {
		strftime(min_timestr, sizeof(min_timestr), "%Y-%m-%dT%H:%M:%SZ", &min_tm);
		fprintf(stderr, "end to far from %s\n", min_timestr);
		if (dodel)
			return fn ? -666 : 1;
	}
	if (sorted) {
		fprintf(stderr, "File was already sorted\n");
		return 1;
	}
	if (!(refs = malloc(i * sizeof(dnst *))))
		return -1;
	for ( d = (void *)buf, i = 0
	    ; ((uint8_t *)d) + 16 < eob
	    ; d = dnst_next(d), i++) {

		refs[i] = d;
		if (!dnst_fits(d, eob))
			break;
	}
	qsort(refs, i, sizeof(dnst *), dnst_time_cmp);
	for (j = 0, prev_time = 0; j < i; j++) {
		if (refs[j]->time < prev_time)
			printf("Jump back of %" PRIu32 "\n", (prev_time - refs[j]->time));
		prev_time = refs[j]->time;
	}
	if (!fn)
		return 0;
#if 0
	if ((fd = open(fn, O_RDWR|O_CREAT, 0644)) < 0) {
		fprintf(stderr, "Could not open \"%s\": %s\n", fn, strerror(errno));
	}

	for (j = 0; j < i; j++) {
		write(fd, refs[j], dnst_sz(refs[j]));
	}
	close(fd);
#else
	if (!(wr_buf = malloc(sz)))
		perror("Could not malloc output file");
	d = (void *)wr_buf;
	for (j = 0; j < i; j++) {
		memcpy(d, refs[j], dnst_sz(refs[j]));
		d = (dnst *)(((uint8_t *)d) + dnst_sz(refs[j]));
	}
	if ((fd = open(fn, O_WRONLY|O_CREAT, 0644)) < 0) {
		fprintf(stderr, "Could not open \"%s\": %s\n", fn, strerror(errno));
	}
	write(fd, wr_buf, sz);
	close(fd);
	free(wr_buf);

#endif
	return 0;
}

int main(int argc, const char **argv)
{
	int fd = -1;
	struct stat st;
	uint8_t *buf = NULL;
	int r = 1;
	int dodel = 1;

	if (argc >= 2 && strcmp(argv[1], "-d") == 0) {
		dodel = 0;
		argc--;
		argv++;
	}
	if (argc != 2 && argc != 3)
		printf("usage: %s [ -d ] <file.dnst> [ <file.sdnst> ]\n", argv[0]);

	else if ((fd = open(argv[1], O_RDONLY)) < 0)
		perror("Could not open input file");

	else if (fstat(fd, &st) < 0)
		perror("Could not stat input file");

	else if ((buf = mmap( NULL, st.st_size
	                     , PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		perror("Could not mmap input file");
	else {
		r = sort_dnsts(buf, st.st_size, (argc == 3 ? argv[2] : 0), dodel);
	}

	if (buf)
		munmap(buf, st.st_size);
	if (fd >= 0)
		close(fd);
	if (r == -666) {
		if (dodel) {
			fprintf(stderr, "Removing \"%s\"\n", argv[1]);
			unlink(argv[1]);
		} else
			return 0;
	}
	return r;
}
