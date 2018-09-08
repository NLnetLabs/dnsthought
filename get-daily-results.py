#!/usr/bin/env python

from datetime import datetime, timedelta
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

	utcnow   = datetime.utcnow()
	start_dt = datetime(utcnow.year, utcnow.month, utcnow.day) - day
	while True:
		fn = '%s/%s' % (msm_id, start_dt.strftime('%Y-%m-%d'))
		if not os.path.exists(fn) and not os.path.exists(fn + '.dnst'):
			break
		start_dt -= day

	start = int(start_dt.strftime("%s"))
	stop  = start + 24 * 60 * 60

	url  = 'https://atlas.ripe.net/api/v2/measurements/'
	url += '%s/results/?start=%d&stop=%d' % (msm_id, start, stop)
	print 'fetching', fn
	r = http.request('GET', url)
	results[msm_id] = r.status
	if r.status == 200:
		print 'writing ', fn
		with open(fn, 'wb') as fh:
			fh.write(r.data)

if __name__ == '__main__':
	day = timedelta(days = 1)
	http = urllib3.PoolManager( cert_reqs='CERT_REQUIRED'
	                          , ca_certs=certifi.where())
	results = dict()

	pool = threadpool.ThreadPool(len(argv) - 1)
	for req in threadpool.makeRequests(fetch_msm_results, argv[1:]):
		pool.putRequest(req)
	pool.wait()
	if 200 not in results.values():
		exit(1)
