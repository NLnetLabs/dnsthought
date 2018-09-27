#!/usr/bin/env python

import bz2, json
from ftplib import FTP

ftp = FTP('ftp.ripe.net')
ftp.login()
ftp.cwd('ripe/atlas/probes/archive')
data = ''
def append_to_data(x):
	global data
	data += x
ftp.retrbinary('RETR meta-latest', append_to_data)
objects = sorted([(o['id'], o) for o in json.loads(bz2.decompress(data))['objects']])

with open('src/probes.c', 'w') as f:
	f.write("""#include "config.h"
#include "probes.h"
#include <stdlib.h>

const probe probes[] = {
""")
	for prb_id, o in objects:
		asn_v4    = o['asn_v4']    if o['asn_v4']    else -1
		asn_v6    = o['asn_v6']    if o['asn_v6']    else -1
		latitude  = o['latitude']  if o['latitude']  else 666
		longitude = o['longitude'] if o['longitude'] else 666
		cc_0      = o['country_code'][0] if o['country_code'] else '\\x00'
		cc_1      = o['country_code'][1] if o['country_code'] else '\\x00'
		if asn_v4 == -1 and asn_v6 == -1 \
		and latitude == 666 and longitude == 666 \
		and cc_0 == '\\x00' and cc_1 == '\\x00':
			continue

		f.write( '\t{ %5d, %6d, %6d, %9.4f, %9.4f, \'%s\', \'%s\' },\n'
		      % ( prb_id, asn_v4, asn_v6, latitude, longitude, cc_0, cc_1))
	f.write("""};
const size_t probes_sz = sizeof(probes) / sizeof(probe);

static int uint32_cmp(const void *x, const void *y)
{ return *(uint32_t *)x == *(uint32_t *)y ? 0
       : *(uint32_t *)x >  *(uint32_t *)y ? 1 : -1; }

probe *lookup_probe(uint32_t prb_id)
{ return bsearch(&prb_id, probes, probes_sz, sizeof(probe), uint32_cmp); }
""")
