#ifndef __DNST_H_
#define __DNST_H_
#include <stdint.h>
#include <sys/socket.h>

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

#endif
