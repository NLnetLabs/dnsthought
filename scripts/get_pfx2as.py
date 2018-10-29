#!/usr/bin/env python

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

