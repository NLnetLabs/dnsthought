#!/usr/bin/env python

import requests
import cPickle

asns = dict()
for page in ( 'list-of-autonomous-system-numbers'
            , 'list-of-autonomous-system-numbers-2'
	    , '4-byte-asn-names-list' ):
	r = requests.get('http://www.bgplookingglass.com/' + page)
	if r.status_code != 200:
		print('Could not fetch %s' % page)
		sys.exit(1)
	asns.update(dict([ (lambda x: (x[0], (x[1], ' '.join(x[2:]).lstrip('- '))))(x.split())
	                   for x in r.content.split('<pre>')[1]
	                                     .split('</pre>')[0]
	                                     .split('<br />')]))

with file('asns.cPickle', 'w') as f:
	cPickle.dump(asns, f)

