#!/usr/bin/env python

import csv
import datetime
import subprocess
import sys
import cPickle

asns_by_ip       = dict()
hijacks_by_probe = dict()
hj_res_by_asn    = dict()
hj_ips_by_asn    = dict()

def process_hijack(dt_str, prb_id, res_ip, hjs):
	global hijacks

	dt = datetime.datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%SZ')

	for hj in hjs:
		asn = asns_by_ip.get(hj, None)
		if asn is None:
			asn = asns_by_ip[hj] = int(subprocess.check_output(
			    ['/home/hackathon/bin/lookup_asn', hj]))
		if asn == 0:
			continue

		if prb_id not in hijacks_by_probe:
			hijacks_by_probe[prb_id] = dict()
		if res_ip not in hijacks_by_probe[prb_id]:
			hijacks_by_probe[prb_id][res_ip] = dict()
		hijacks_by_probe[prb_id][res_ip][asn] = dt

		if asn not in hj_res_by_asn:
			hj_res_by_asn[asn] = dict()
			hj_ips_by_asn[asn] = dict()
		hj_res_by_asn[asn][(prb_id, res_ip)] = dt
		hj_ips_by_asn[asn][hj] = dt

def process_csv(reader):
	header = reader.next()
	hj_i = header.index('hijacked #0')
	for row in reader:
		hj = row[hj_i]
		if hj != 'NULL':
			process_hijack( row[0], row[1], row[2]
			              , tuple(sorted([r for r in row[hj_i:hj_i+4]
				                         if r != 'NULL' ])))

if __name__ == '__main__':
	one_day = datetime.timedelta(days = 1)
	if len(sys.argv) == 2:
		now = datetime.datetime.strptime(sys.argv[1], '%Y-%m-%d').date()
	else:
		now = datetime.datetime.utcnow().date()
	
	pcl_fn = (now - one_day).strftime('%Y-%m-%d.pcl')
	try:
		with open(pcl_fn, 'rb') as f:
			hijacks_by_probe, hj_res_by_asn, hj_ips_by_asn \
			    = cPickle.load(f)
			print( 'hijacking info for %d probes and %d asns loaded'
			     % (len(hijacks_by_probe), len(hj_res_by_asn)))
	except IOError:
		print('Could not open "%s"' % pcl_fn)
		pass
	while True:
		csv_fn = now.strftime('%Y-%m-%d.csv')
		try:
			with open(csv_fn, 'rb') as f:
				print 'processing', now
				process_csv(csv.reader(f))
		except IOError:
			break

		# Cleanup old date
		#
		now_dt = datetime.datetime(now.year, now.month, now.day)
		rm_before = now_dt - datetime.timedelta(days = 10)

		to_rm = [ (asn, res_ip, prb_id)
		          for prb_id, res_d in hijacks_by_probe.items()
		          for res_ip, asn_d in res_d.items()
		          for asn, dt in asn_d.items()
		           if dt < rm_before ]
		for asn, res_ip, prb_id in to_rm:
			del(hijacks_by_probe[prb_id][res_ip][asn])

		to_rm = [ (asn, res_ip, prb_id)
		          for asn, res_d in hj_res_by_asn.items()
		          for (prb_id, res_ip), dt in res_d.items()
		           if dt < rm_before ]
		for asn, res_ip, prb_id in to_rm:
			del(hj_res_by_asn[asn][(prb_id, res_ip)])

		to_rm = [ (asn, hj_ip)
		          for asn, ips_d in hj_res_by_asn.items()
		          for hj_ip, dt in ips_d.items()
		           if dt < rm_before ]
		for asn, hj_ip in to_rm:
			del(hj_ips_by_asn[asn][hj_ip])

		pcl_fn = now.strftime('%Y-%m-%d.pcl')
		with open(pcl_fn, 'wb') as f:
			cPickle.dump(( hijacks_by_probe
			             , hj_res_by_asn
				     , hj_ips_by_asn ), f)
		print( 'saved hijacking info for %d probes and %d asns'
		     % (len(hijacks_by_probe), len(hj_res_by_asn)))

		now += one_day

