#ifndef __PROBES_H_
#define __PROBES_H_
#include "config.h"
#include <stdint.h>

typedef struct probe {
	uint32_t prb_id;
	uint32_t asn_v4;
	uint32_t asn_v6;
	float    latitude;
	float    longitude;
	char     cc_0;
	char     cc_1;
} probe;

probe *lookup_probe(uint32_t prb_id);

#endif
