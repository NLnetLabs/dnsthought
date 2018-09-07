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
			                    , d->len, dnst_msg(d));

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

int main(int argc, char **argv)
{
	int fd = -1;
	struct stat st;
	uint8_t *buf = NULL;

	if (argc != 2 && argc != 3)
		printf("usage: %s <file.dnst> [ <msm_id> ]\n", argv[0]);

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

	return 1;
}
