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


from datetime import datetime, timedelta
from dateutil.tz import *
from sys import argv, exit
import os.path
import certifi
import urllib3
import threadpool

def fetch_msm_results(msm_id):
	global http
	global results

	if not os.path.isdir(msm_id):
		os.mkdir(msm_id)

	utc_start_of_day = datetime.now(tzlocal()).astimezone(tzutc()).replace(
	    hour = 0, minute = 0, second = 0, microsecond = 0)
	start_dt = utc_start_of_day - timedelta(days = 1)
	while True:
		fn = '%s/%s' % (msm_id, start_dt.strftime('%Y-%m-%d'))
		if not os.path.exists(fn) and not os.path.exists(fn + '.dnst'):
			break
		start_dt -= timedelta(days = 1)

	start = int(start_dt.astimezone(tzlocal()).strftime("%s"))
	stop  = start + 24 * 60 * 60
	#print start, stop

	url  = 'https://atlas.ripe.net/api/v2/measurements/'
	url += '%s/results/?start=%d&stop=%d' % (msm_id, start, stop)
	#print 'fetching', fn
	r = http.request('GET', url)
	results[msm_id] = r.status
	if r.status == 200:
		print 'writing ', fn
		with open(fn, 'wb') as fh:
			fh.write(r.data)

if __name__ == '__main__':
	http = urllib3.PoolManager( cert_reqs='CERT_REQUIRED'
	                          , ca_certs=certifi.where())
	results = dict()

	pool = threadpool.ThreadPool(len(argv) - 1)
	for req in threadpool.makeRequests(fetch_msm_results, argv[1:]):
		pool.putRequest(req)
	pool.wait()
	if 200 not in results.values():
		exit(1)
