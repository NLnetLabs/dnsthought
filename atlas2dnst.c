/* #define WITHOUT_MMAP 1 */
#include "jsmn.h"
#include "rbtree.h"
#include "dnst.h"
#include <arpa/inet.h>
#include <assert.h>
#ifdef __linux__
#include <bsd/string.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WITHOUT_MMAP
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

int b64_pton(char const *src, size_t srcsize, uint8_t *target, size_t targsize)
{
	const uint8_t pad64 = 64; /* is 64th in the b64 array */
	const char* s = src;
	uint8_t in[4];
	size_t o = 0, incount = 0;

	while(s < src + srcsize) {
		/* skip any character that is not base64 */
		/* conceptually we do:
		const char* b64 =      pad'=' is appended to array
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		const char* d = strchr(b64, *s++);
		and use d-b64;
		*/
		char d = *s++;
		if(d <= 'Z' && d >= 'A')
			d -= 'A';
		else if(d <= 'z' && d >= 'a')
			d = d - 'a' + 26;
		else if(d <= '9' && d >= '0')
			d = d - '0' + 52;
		else if(d == '+')
			d = 62;
		else if(d == '/')
			d = 63;
		else if(d == '=')
			d = 64;
		else	continue;
		in[incount++] = (uint8_t)d;
		if(incount != 4)
			continue;
		/* process whole block of 4 characters into 3 output bytes */
		incount = 0;
		if(in[3] == pad64 && in[2] == pad64) { /* A B = = */
			if(o+1 > targsize)
				return -1;
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			o += 1;
			break; /* we are done */
		} else if(in[3] == pad64) { /* A B C = */
			if(o+2 > targsize)
				return -1;
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
			o += 2;
			break; /* we are done */
		} else {
			if(o+3 > targsize)
				return -1;
			/* write xxxxxxyy yyyyzzzz zzwwwwww */
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
			target[o+2]= ((in[2]&0x03)<<6) | in[3];
			o += 3;
		}
	}
	switch (incount) {
	case 0: break;
	case 1: assert(incount != 1);
		break;
	case 2: if(o+1 > targsize)
			return -1;
		target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
		o += 1;
		break;
	case 3: if(o+2 > targsize)
			return -1;
		target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
		target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
		o += 2;
		break;
	default:
		assert(incount < 4);
		break;
	}
	return (int)o;
}

static const char *j;
static int32_t prb_id;
static uint8_t resultset_spc[65536];
static uint8_t *resultset = resultset_spc;
static size_t resultset_sz = sizeof(resultset_spc);
static dnst *d1st;
static dnst *dcur;
static const char *msg_start;
static size_t msg_len;
static FILE *out_fh;


size_t skip_array(jsmntok_t *t, size_t count);
size_t skip_object(jsmntok_t *t, size_t count) {
	size_t i = 0;

	for (i = 0; count > 0; i++, count--) {
		assert(t[i].type == JSMN_STRING);
		if (t[i].size == 0)
			; /* key without value */
		else switch(t[++i].type) {
		case JSMN_OBJECT: i += skip_object(&t[i+1], t[i].size);
		                  break;
		case JSMN_ARRAY : i += skip_array(&t[i+1], t[i].size);
		                  break;
		default         : assert(  t[i].type == JSMN_OBJECT
		                        || t[i].type == JSMN_ARRAY );
		}
	}
	return i;
};


size_t skip_array(jsmntok_t *t, size_t count) {
	size_t i = 0;

	for (i = 0; count > 0; i++, count--) {
		switch (t[i].type) {
		case JSMN_OBJECT: i += skip_object(&t[i+1], t[i].size);
		                  break;
		case JSMN_ARRAY : i += skip_array(&t[i+1], t[i].size);
		                  break;
		default         : assert(  t[i].type == JSMN_OBJECT
		                        || t[i].type == JSMN_ARRAY );
		}
	}
	return i;
};


size_t parse_result(jsmntok_t *t, size_t count) {
	size_t i = 0;

	for (i = 0; count > 0; i++, count--) {
		assert(t[i].type == JSMN_STRING);
		if (t[i].size == 0)
			; /* key without value */

		else if (t[i].end - t[i].start == 2 &&
		    strncmp(j + t[i].start, "rt", 2) == 0) {
			char *endptr;

			i += 1;
			assert(t[i].type == JSMN_PRIMITIVE);
			dcur->rt = strtof(j + t[i].start, &endptr);
			assert(j + t[i].end == endptr);

		} else if (t[i].end - t[i].start == 4 &&
		    strncmp(j + t[i].start, "abuf", 4) == 0) {
			i += 1;
			assert(t[i].type == JSMN_STRING);
			dcur->error = 0;
			msg_start = j + t[i].start;
			msg_len = t[i].end - t[i].start;
			if (msg_len > 1 && j[t[i].end - 1] == '=') {
				msg_len -= 1;
				if (msg_len > 1 && j[t[i].end - 2] == '=')
					msg_len -= 1;
			}

		} else switch(t[++i].type) {
		case JSMN_OBJECT: i += skip_object(&t[i+1], t[i].size);
		                  break;
		case JSMN_ARRAY : i += skip_array(&t[i+1], t[i].size);
		                  break;
		default         : assert(  t[i].type == JSMN_OBJECT
		                        || t[i].type == JSMN_ARRAY );
		}
	}
	return i;
};


size_t parse_resultset(jsmntok_t *t, size_t count) {
	size_t i = 0;

	dcur->time = 0;
	dcur->rt = -1;
	dcur->prb_id = prb_id;
	dcur->af = 0;
	dcur->error = 2;
	dcur->len = 0;
	msg_start = NULL;
	msg_len = 0;

	for (i = 0; count > 0; i++, count--) {
		assert(t[i].type == JSMN_STRING);
		if (t[i].size == 0)
			; /* key without value */

		else if (t[i].end - t[i].start == 4 &&
		    strncmp(j + t[i].start, "time", 4) == 0) {
			char *endptr;

			i += 1;
			assert(t[i].type == JSMN_PRIMITIVE);
			dcur->time = strtoul(j + t[i].start, &endptr, 10);
			assert(j + t[i].end == endptr);

		} else if (t[i].end - t[i].start == 8 &&
		    strncmp(j + t[i].start, "dst_addr", 8) == 0) {
			char buf[48];

			i += 1;
			assert(t[i].type == JSMN_STRING);
			dcur->af =
			    memchr(j + t[i].start, ':', t[i].end - t[i].start)
			  ? AF_INET6 : AF_INET;

			assert(t[i].end - t[i].start < sizeof(buf) - 1);
			memcpy(buf, j + t[i].start, t[i].end - t[i].start);
			buf[t[i].end - t[i].start] = '\0';
			
			int r = inet_pton(dcur->af, buf, dcur->afu.ipv6.addr);
			assert(r == 1);

		} else if (t[i].end - t[i].start == 8 &&
		    strncmp(j + t[i].start, "dst_name", 8) == 0) {
			char buf[48];

			i += 1;
			assert(t[i].type == JSMN_STRING);
			if (dcur->af != 0)
				continue;

			dcur->af =
			    memchr(j + t[i].start, ':', t[i].end - t[i].start)
			  ? AF_INET6 : AF_INET;
			if (t[i].end - t[i].start >= sizeof(buf) - 1) {
				dcur->af = 0;
				continue;
			}
			memcpy(buf, j + t[i].start, t[i].end - t[i].start);
			buf[t[i].end - t[i].start] = '\0';
			if (inet_pton(dcur->af, buf, dcur->afu.ipv6.addr) != 1)
				dcur->af = 0;

		} else if (t[i].end - t[i].start == 5 &&
		    strncmp(j + t[i].start, "error", 5) == 0) {
			i += 1;
			assert(t[i].type == JSMN_OBJECT);
			dcur->error = 1;
			msg_start = j + t[i].start;
			msg_len = t[i].end - t[i].start;
			i += skip_object(&t[i+1], t[i].size);

		} else if (t[i].end - t[i].start == 6 &&
		    strncmp(j + t[i].start, "result", 6) == 0) {
			i += 1;
			assert(t[i].type == JSMN_OBJECT);
			i += parse_result(&t[i+1], t[i].size);

		} else switch(t[++i].type) {
		case JSMN_OBJECT: i += skip_object(&t[i+1], t[i].size);
		                  break;
		case JSMN_ARRAY : i += skip_array(&t[i+1], t[i].size);
		                  break;
		default         : assert(  t[i].type == JSMN_OBJECT
		                        || t[i].type == JSMN_ARRAY );
		}
	}
	dcur->len = dcur->error == 0 ? msg_len * 3 / 4
	          : dcur->error == 1 ? msg_len
		  : 0;
	/* TODO allocate more space when needed */
	size_t dcur_sz  = dnst_sz(dcur);
	int b64_len;
	assert(&((uint8_t *)dcur)[dcur_sz] - resultset < resultset_sz);
	switch (dcur->error) {
	case 0:	b64_len = b64_pton( msg_start, msg_len, dnst_msg(dcur)
		                  , dnst_msg(dcur) - (resultset+resultset_sz));
		assert(b64_len > 0);
		if (b64_len != dcur->len) {
			dcur->len = b64_len;
			dcur_sz = dnst_sz(dcur);
		}
		break;
	case 1: (void) memcpy(dnst_msg(dcur), msg_start, msg_len);
		break;
	}
	size_t dcur_pad = dcur_sz - (sizeof(dnst) - 12) - dcur->len;
	if (dcur->af == AF_INET6)
		dcur_pad -= 12;
	while (dcur_pad) {
		dnst_msg(dcur)[msg_len + dcur_pad] = '=';
		dcur_pad--;
	}
	return i;
};


void handle_msm(const char *json, jsmntok_t *t, size_t r)
{
	size_t i;

	j = json;
	prb_id = -1;
	dcur = d1st = (void *)resultset;

	assert(t[0].type == JSMN_OBJECT);
	for (i = 1; i < r; i++) {
		assert(t[i].type == JSMN_STRING);
		if (t[i].size == 0)
			; /* key without value */

		else if (t[i].end - t[i].start == 6 &&
		    strncmp(j + t[i].start, "prb_id", 6) == 0) {
			char *endptr;

			i += 1;
			assert(t[i].type == JSMN_PRIMITIVE);
			prb_id = strtol(j + t[i].start, &endptr, 10);
			assert(j + t[i].end == endptr);
			if (dcur > d1st) {
				uint8_t *d = (void *)d1st;
				while ((void *)d < (void *)dcur) {
					((dnst *)d)->prb_id = prb_id;
					d += dnst_sz((dnst *)d);
				}
				assert((void *)d == (void *)dcur);
			}

		} else if (t[i].end - t[i].start == 9 &&
		    strncmp(j + t[i].start, "resultset", 9) == 0) {
			size_t count;

			i += 1;
			assert(t[i].type == JSMN_ARRAY);
			for (count = t[i].size; count > 0; count--) {
				i += 1;
				assert(t[i].type == JSMN_OBJECT);
				i += parse_resultset(&t[i+1], t[i].size);
				if (dcur->af == 0 || dcur->error == 2)
					continue;

				uint8_t *dcur_p = (uint8_t *)dcur;
				size_t dcur_sz = dnst_sz(dcur);

				assert(dcur_p + dcur_sz + sizeof(dnst)
				              - resultset < resultset_sz);
				dcur = (dnst *)(dcur_p + dcur_sz);
			}

		} else switch (t[++i].type) {
		case JSMN_OBJECT: i += skip_object(&t[i+1], t[i].size);
		                  break;
		case JSMN_ARRAY : i += skip_array(&t[i+1], t[i].size);
		                  break;
		default         : assert(  t[i].type == JSMN_OBJECT
		                        || t[i].type == JSMN_ARRAY );
		}
	}
	if (prb_id >= 0 && dcur > d1st) {
		if (!fwrite(d1st,
		    ((uint8_t *)dcur) - ((uint8_t *)d1st), 1, out_fh)) {
			fprintf( stderr, "Could not write resultset: %s\n"
			       , strerror(errno));
		}
	}
}


int parse_json(const char *json, const char *end)
{
	jsmn_parser p;
	jsmntok_t tok_spc[1024], *tok = tok_spc;
	size_t tokcount = sizeof(tok_spc);
	int r = 3;
	size_t i = 0;
	const char *next;

	assert((end - 1) >= (json + 1));
	json += 1;
	end -= 1;
	next = strnstr(json, "},{", (end - json));
	next = next ? next + 1 : end;
	while (next > json) {
		jsmn_init(&p);
		r = jsmn_parse(&p, json, next - json, tok, tokcount);
		if (r == JSMN_ERROR_PART) {
			next = strnstr(next, "},{", (end - next));
			next = next ? next + 1 : end;

		} else if (r == JSMN_ERROR_NOMEM) {
			jsmntok_t *new_tok =
			    malloc(sizeof(*tok) * (tokcount *= 2));

			if (!new_tok)
				break;
			if (tok != tok_spc)
				free(tok);
			tok = new_tok;

		} else if (r < 0) {
			fprintf( stderr
			       , "Error %d occured parsing '%.*s'\n"
			       , r, (int)(next - json), json);
			break;
		} else {
			handle_msm(json, tok, r);
			json = next + 1;
			next = strnstr(json, "},{", end - json);
			next = next ? next + 1 : end;
		}
	}
	if (tok != tok_spc)
		free(tok);
	return r;
}


int main(int argc, const char **argv)
{
	char out_fn[1024];
	int r = 1;
#ifndef WITHOUT_MMAP
	int f = -1;
	struct stat statbuf;
#else
	FILE *f = NULL;
	long f_sz;
#endif
	char *json = NULL;

	if (argc != 2)
		fprintf(stderr, "usage: %s <atlas msm result json>\n", argv[0]);

	else if (strlen(argv[1]) + 6 > sizeof(out_fn))
		fprintf(stderr, "File name too large!\n");

	else if (!(out_fh = fopen(strcat(strcpy(out_fn, argv[1]), ".dnst"), "wb")))
		fprintf(stderr, "Could not open \"%s\" for writing: %s\n"
		              , out_fn, strerror(errno));

#ifndef WITHOUT_MMAP
	else if ((f = open(argv[1], O_RDONLY)) < 0)
		fprintf(stderr, "Could not open \"%s\": %s\n"
		              , argv[1], strerror(errno));

	else if (fstat(f, &statbuf) < 0)
		fprintf(stderr, "Could not fstat \"%s\": %s\n"
		              , argv[1], strerror(errno));

	else if ((json = mmap( NULL, statbuf.st_size, PROT_READ
	                     , MAP_PRIVATE, f, 0)) == MAP_FAILED)
		fprintf(stderr, "Could not mmap \"%s\": %s\n"
		              , argv[1], strerror(errno));
	else
		r = parse_json(json, json + statbuf.st_size);
#else
	else if (!(f = fopen(argv[1], "rb")))
		fprintf(stderr, "Could not open \"%s\": %s\n"
		              , argv[1], strerror(errno));

	else if (fseek(f, 0, SEEK_END) < 0)
		fprintf(stderr, "Could not seek to EOF: %s\n", strerror(errno));

	else if (!(f_sz = ftell(f)))
		fprintf(stderr, "File \"%s\" had no content\n", argv[1]);

	else if (fseek(f, 0, SEEK_SET) < 0)
		fprintf(stderr, "Could not rewind: %s\n", strerror(errno));

	else if (!(json = malloc(f_sz+1)))
		fprintf(stderr, "Could allocate %ld bytes of memory\n", f_sz+1);

	else if (fread(json, f_sz, 1, f) != 1)
		fprintf(stderr, "Could not read content of \"%s\"\n", argv[1]);
	else
		r = parse_json(json, json + f_sz);
#endif

#ifndef WITHOUT_MMAP
	if (json && json != MAP_FAILED)
		munmap(json, statbuf.st_size);
	if (f >= 0)
		close(f);
#else
	if (json)
		free(json);
	if (f)
		fclose(f);
#endif
	if (out_fh)
		fclose(out_fh);
	return r;
}
