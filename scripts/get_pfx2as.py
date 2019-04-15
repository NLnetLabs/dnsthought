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


import requests
from subprocess import call, check_output

def get_pfx2as(rv_dir):
	r = requests.get(rv_dir + 'pfx2as-creation.log')
	assert r.status_code == 200
	last = r.content.strip().split('\n')[-1].split()[-1]
	fn = last.split('/')[-1]
	r = requests.get(rv_dir + last, stream = True)
	assert r.status_code == 200
	with open(fn, 'wb') as f:
		for chunk in r.iter_content(chunk_size = 16384): 
			if chunk:
				f.write(chunk)
	call(('gunzip', '-f', fn))
	return fn.rstrip('.gz')


fn6 = get_pfx2as('http://data.caida.org/datasets/routing/routeviews6-prefix2as/')
with open('src/table6.c', 'wb') as f:
	f.write('#include "config.h"\n#include "ranges.h"\n'
	        'const range6 ranges6[] = {\n')
	f.write(check_output(('src/mk_asn_tables', fn6)).rstrip(',\n'))
	f.write('};\nconst size_t ranges6_sz = sizeof(ranges6) / sizeof(range6);\n')

fn4 = get_pfx2as('http://data.caida.org/datasets/routing/routeviews-prefix2as/')
with open('src/table4.c', 'wb') as f:
	f.write('#include "config.h"\n#include "ranges.h"\n'
	        'const range4 ranges4[] = {\n')
	f.write(check_output(('src/mk_asn_tables', fn4)).rstrip(',\n'))
	f.write('};\nconst size_t ranges4_sz = sizeof(ranges4) / sizeof(range4);\n')

