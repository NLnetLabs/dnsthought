#!/usr/bin/env python
#
## Copyright (c) 2018, NLnet Labs. All rights reserved.
##
## This software is open source.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
##
## Redistributions of source code must retain the above copyright notice,
## this list of conditions and the following disclaimer.
##
## Redistributions in binary form must reproduce the above copyright notice,
## this list of conditions and the following disclaimer in the documentation
## and/or other materials provided with the distribution.
##
## Neither the name of the NLNET LABS nor the names of its contributors may
## be used to endorse or promote products derived from this software without
## specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
## "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
## LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
## A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
## HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
## TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
## PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
## LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
## NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
## SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


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
