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
import cPickle
import sys

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

with file(('/'.join(sys.argv[0].split('/')[:-1] + ['']) if '/' in sys.argv[0] else '')
         + 'asns.cPickle', 'w') as f:
	cPickle.dump(asns, f)
