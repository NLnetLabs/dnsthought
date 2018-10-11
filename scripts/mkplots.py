#!/usr/bin/env python

import os.path
import time
from datetime import datetime, date, timedelta
import matplotlib
import sys
matplotlib.use('Agg')
import matplotlib.pyplot as pyplot
import matplotlib.pyplot as pp
import matplotlib.patches as mpatches
import matplotlib.dates as mpd
import pandas as pd
import cPickle

def darken(color):
	return '#%.2X%.2X%.2X' % ( int(color[1:3], 16) / 1.25
	                         , int(color[3:5], 16) / 1.25
	                         , int(color[5:7], 16) / 1.25
	                         )

best_colors = [ ('#7293cb', '#396ab1')
              , ('#e1974c', '#da7c30')
	      , ('#84ba5b', '#3e9651')
	      , ('#d35e60', '#cc2529')
	      , ('#808585', '#535154')
	      , ('#9067a7', '#6b4c9a')
	      , ('#ab6857', '#922428')
	      , ('#ccc210', '#948b3d') ]
best_line_colors = [ x[1] for x in best_colors ]
best_bar_colors = [ x[0] for x in best_colors ] + best_line_colors
color_tables = dict()

def lookup_color(table, label, prev_color):
	global color_tables

	if label == 'Remaining':
		return '#999999'

	if table not in color_tables:
		color_tables[table] = dict()

	if label in color_tables[table]:
		return color_tables[table][label]

	if not prev_color:
		prev_color = color_tables[table].get('last', '')

	if prev_color:
		try:
			i = best_bar_colors.index(prev_color)
			if i + 1 == len(best_bar_colors):
				new_color = best_bar_colors[0]
			else:
			 	new_color = best_bar_colors[i + 1]
		except ValueError:
			new_color = best_bar_colors[0]
	else:
		new_color = best_bar_colors[0]

	color_tables[table][label] = new_color
	color_tables[table]['last'] = new_color
	return new_color

cap_names = \
	{ 'can_ipv6'       : ( 1, 'can reach IPv6 only nameservers')
	, 'can_tcp'        : ( 2, 'can return over TCP')
	, 'can_tcp6'       : ( 3, 'can return over TCP (to an IPv6 only nameserver)')
	, 'does_ecs'       : ( 4, 'send an EDNS Client Subnet option')
	, 'does_qnamemin'  : ( 5, 'do QNAME Minimization')
	, 'doesnt_qnamemin': ( 5, 'do <b>not</b> do QNAME Minimization')
	, 'does_nxdomain'  : ( 6, 'do NXDOMAIN Rewriting')
	, 'doesnt_nxdomain': ( 6, 'do <b>not</b> do NXDOMAIN Rewriting')
	, 'has_ta_19036'   : ( 7, 'have root KSK 19036 (and root KSK sentinel support)')
	, 'hasnt_ta_19036' : ( 7, 'do <b>not</b> have root KSK 19036 (but <b>do</b> have root KSK sentinel support)')
	, 'has_ta_20326'   : ( 8, 'have root KSK 20326 (and root KSK sentinel support)')
	, 'hasnt_ta_20326' : ( 8, 'do <b>not</b> have root KSK 20326 (but <b>do</b> have root KSK sentinel support)')
	, 'can_rsamd5'     : (20, 'validate DNSKEY algorithm RSAMD5')
	, 'cannot_rsamd5'  : (20, 'do <b>not</b> validate DNSKEY algorithm RSAMD5')
	, 'broken_rsamd5'  : (20, 'Hhve broken DNSKEY algorithm RSAMD5 validation support')
	, 'can_dsa'        : (21, 'validate DNSKEY algorithm DSA')
	, 'cannot_dsa'     : (21, 'do <b>not</b> validate DNSKEY algorithm DSA')
	, 'broken_dsa'     : (21, 'have broken DNSKEY algorithm DSA validation support')
	, 'can_rsasha1'    : (22, 'validate DNSKEY algorithm RSA-SHA1')
	, 'cannot_rsasha1' : (22, 'do <b>not</b> validate DNSKEY algorithm RSA-SHA1')
	, 'broken_rsasha1' : (22, 'have broken DNSKEY algorithm RSA-SHA1 validation support')
	, 'can_dsansec3'   : (23, 'validates DNSKEY algorithm DSA-NSEC3')
	, 'cannot_dsansec3': (23, 'do <b>not</b> validate DNSKEY algorithm DSA-NSEC3')
	, 'broken_dsansec3': (23, 'have broken DNSKEY algorithm DSA-NSEC3 validation support')

	, 'can_rsansec3'   : (24, 'validate DNSKEY algorithm RSA-NSEC3')
	, 'cannot_rsansec3': (24, 'do <b>not</b> validate DNSKEY algorithm RSA-NSEC3')
	, 'broken_rsansec3': (24, 'have broken DNSKEY algorithm RSA-NSEC3 validation support')
	, 'can_rsasha256'   : (25, 'validate DNSKEY algorithm RSA-SHA256')
	, 'cannot_rsasha256': (25, 'do <b>not</b> validate DNSKEY algorithm RSA-SHA256')
	, 'broken_rsasha256': (25, 'have broken DNSKEY algorithm RSA-SHA256 validation support')
	, 'can_rsasha512'   : (26, 'validate DNSKEY algorithm RSA-SHA512')
	, 'cannot_rsasha512': (26, 'do <b>not</b> validate DNSKEY algorithm RSA-SHA512')
	, 'broken_rsasha512': (26, 'have broken DNSKEY algorithm RSA-SHA512 validation support')
	, 'can_eccgost'    : (27, 'validate DNSKEY algorithm ECC-GOST')
	, 'cannot_eccgost' : (27, 'do <b>not</b> validate DNSKEY algorithm ECC-GOST')
	, 'broken_eccgost' : (27, 'have broken DNSKEY algorithm ECC-GOST validation support')

	, 'can_ecdsa256'   : (28, 'validate DNSKEY algorithm ECDSA256')
	, 'cannot_ecdsa256': (28, 'do <b>not</b> validate DNSKEY algorithm ECDSA256')
	, 'broken_ecdsa256': (28, 'have broken DNSKEY algorithm ECDSA256 validation support')
	, 'can_ecdsa384'   : (29, 'validate DNSKEY algorithm ECDSA384')
	, 'cannot_ecdsa384': (29, 'do <b>not</b> validate DNSKEY algorithm ECDSA384')
	, 'broken_ecdsa384': (29, 'have broken DNSKEY algorithm ECDSA384 validation support')
	, 'can_ed25519'    : (30, 'validate DNSKEY algorithm ED25519')
	, 'cannot_ed25519' : (30, 'do <b>not</b> validate DNSKEY algorithm ED25519')
	, 'broken_ed25519' : (30, 'have broken DNSKEY algorithm ED25519 validation support')
	, 'can_ed448'      : (31, 'validate DNSKEY algorithm ED448')
	, 'cannot_ed448'   : (31, 'do <b>not</b> validate DNSKEY algorithm ED448')
	, 'broken_ed448'   : (31, 'have broken DNSKEY algorithm ED448 validation support')

	, 'can_gost'       : (40, 'validate DS algorithm GOST')
	, 'cannot_gost'    : (40, 'do <b>not</b> validate DS algorithm GOST')
	, 'broken_gost'    : (40, 'have broken DS algorithm GOST validation support')
	, 'can_sha384'     : (41, 'validate DS algorithm SHA384')
	, 'cannot_sha384'  : (41, 'do <b>not</b> validate DS algorithm SHA384')
	, 'broken_sha384'  : (41, 'have broken DS algorithm SHA384 validation support')
	, 'is_internal'    : (60, 'have the same ASN as the probe (internal)')
	, 'is_forwarding'  : (60, 'are forwarding to a resolver with a different ASN (forwarding)')
	, 'is_external'    : (60, 'have a ASN different from the probe ASN (external)')
}

def mkpath(path_es):
	return '/' + '/'.join([e[2] for e in path_es])

def get_nav_e(e):
	if e.startswith('prb_AS'):
		return (0, 'from probes within ' + e[4:])
	elif e.startswith('res_AS'):
		return (0, 'within ' + e[4:])
	elif e.startswith('auth_AS'):
		return (0, 'coming from ' + e[5:])
	elif e.startswith('ID_'):
		return (0, 'from probe ' + e[3:])
	else:
		return cap_names.get(e, None)

class Nav(object):
	def __init__(self, path):
		es = path.split('/')
		self.path = path
		self.nav = list()
		i = 0
		for e in es[::-1]:
			nav_e = get_nav_e(e)
			if nav_e is None:
				break
			i += 1
			nav_e = (nav_e[0], nav_e[1], e)
			self.nav.append(nav_e)
		self.nav.sort()
		self.base = '/'.join(es[:-i])

	def title(self):
		if len(self.nav) == 0:
			return ''
		elif len(self.nav) == 1:
			return ( 'that ' if 'AS' not in self.nav[0][2] else '') \
			       + self.nav[0][1]
		elif len(self.nav) == 2:
			return self.nav[0][1] + ' that ' + self.nav[1][1]
		else:
			raise(Exception())

	def print_clear_links(self, f):
		f.write('<ul>')
		for e in self.nav:
			new_nav = list(self.nav)
			new_nav.remove(e)
			href = os.path.relpath(mkpath(new_nav), mkpath(self.nav))
			f.write( '<li><a href="%s"><b>Clear</b> %s</a></li>'
			       % ( href, e[1] ))
			for name, (value, descr) in cap_names.items():
				if value != e[0] or name == e[2]:
					continue
				href = os.path.relpath(
				    mkpath(sorted(new_nav + [(value, descr, name)])),
				    mkpath(self.nav))
				f.write( '<li><a href="%s">%s</a></li>'
				       % ( href, descr ))

		f.write('</ul>')
	
	def rm_link(self, nav_e):
		new_nav = list(self.nav)
		new_nav.remove(nav_e)
		href = os.path.relpath(mkpath(new_nav), mkpath(self.nav))
		descr = '<b>Clear</b> %s' % nav_e[1]
		return href, descr

	def add_link(self, nav_e):
		if True: # Single layer nav switch
			new_nav = list()
		elif nav_e[0] == 0:
			new_nav = [e for e in self.nav if e[0] != 0]
		else:
			new_nav = [e for e in self.nav if e[0] == 0]

		new_nav.append(nav_e)
		new_nav.sort()
		href = os.path.relpath(mkpath(new_nav), mkpath(self.nav))
		return href, nav_e[1]

	def make_prop_links(self, props):
		links = list()
		for prop, label in props:
			if prop.startswith('nxhj_'):
				return []
			nav_e = get_nav_e(prop)
			nav_e = (nav_e[0], nav_e[1], prop)
			if nav_e in self.nav:
				links.append(self.rm_link(nav_e))
			else:
				links.append(self.add_link(nav_e))
		return links


	def print_prop_links(self, f, props):
		links = self.make_prop_links(props)
		if links:
			f.write('<br />Resolvers')
			if 'AS' not in props[0][0]:
				f.write(' that')
			f.write('<ul>')
			for href, descr in links:
				f.write( '<li><a href="%s">%s</a></li>'
				       % ( href, descr ))
			f.write('</ul>')

class Index(object):
	def __init__(self, path, title):
		self.path  = path
		self.title = title
		self.plots = []

	def add_plots(self, title, anchor, plots, prop = None):
		self.plots.append((title, anchor, plots, prop))

	def save_to_f(self, f):
		global ts_series, n_probes, n_resolvers

		if len(ts_series) == 0:
			return

		n_res = n_resolvers[-1]
		n_prb = n_probes[-1]
		dt = ts_series[-1]

		quick_jump = '<ul class="main">'
		for title, anchor, plots, prop in self.plots:
			quick_jump += '<li><a href="#%s">%s</a></li>' \
			            % (anchor, title)
		quick_jump += '</ul>'

		nav = Nav(self.path)
		title = nav.title()
		f.write('<html><head><style>img, table { display: inline-block; vertical-align: top; }\ntd { text-align: center; }\nul.main li { display: inline-block; margin-right: 1em; padding-right: 1em; border-right: 1px solid black; }</style><link rel="stylesheet" type="text/css" href="/dnsthought.css"><title>%s%s%s</title></head><body>\n'
		       % ( self.title, (' - Resolvers ' if title else ''), title))
		f.write('<h1>Report from %s for %d resolver at %d probes%s%s</h1>'
		       % ( dt.strftime('%Y-%m-%d %H:%M')
		         , n_res, n_prb, '<br />' if title else '', title))
		nav.print_clear_links(f)
		f.write(quick_jump)
		first = True
		for title, anchor, plots, prop in self.plots:
			if first:
				first = False
			else:
				f.write('<hr />\n')
			f.write( '<a name="%s"></a><h2>%s</h2>\n\n'
			       % (anchor, title))
			if plots:
				f.write('<img style="margin-top: 10ex;" src="%s">' % plots[0])
			if len(plots) > 2:
				f.write('<table><tr><th colspan="2">on %s</th></tr>'
				       % dt.strftime('%Y-%m-%d %H:%M'))
				f.write('<tr><td>with %d resolvers</td><td>with %d probes</td></tr>' % (n_res, n_prb))
				f.write('<tr><td><img src="%s"></td><td><img src="%s">' % (plots[1], plots[2]))
				if len(plots) > 3:
					f.write('<br /><img src="%s">' % plots[3])
				if len(plots) > 4:
					f.write(''.join(['<img src="%s">' % pfn for pfn in plots[4:]]))
				f.write('</table>')
			elif len(plots) > 1:
				f.write('<table><tr><th>on %s</th></tr>'
				       % dt.strftime('%Y-%m-%d %H:%M'))
				f.write('<tr><td>with %d resolvers</td></tr>'
				       % n_res)
				f.write('<tr><td><img src="%s"></td></tr>'
				       % plots[1] )
				f.write('</table>')
			
			if prop is not None:
				prop.save(f)
			nav.print_prop_links(f, zip(prop.cols(), prop.labs()))

	def save(self):
		with file(self.path + '/index.html', 'w') as f:
			self.save_to_f(f)

class Prop(object):
	def __init__(self, title, col_name, lab_name, size = 3):
		self.title    = title
		self.col_name = col_name
		self.lab_name = lab_name
		self.size     = size
		self.plot_fns = []
	
	def save(self, f):
		pass

	def cols(self):
		if self.col_name:
			return [p + '_' + self.col_name for p, l in self.prop][:self.size]
		else:
			return [p for p, l in self.prop][:self.size]
	def labs(self):
		return [l + ' ' + self.lab_name for p, l in self.prop][:self.size]
	def pie_labs(self):
		return self.labs()
	def colors(self):
		return ['#7DB874', '#E39C37', '#D92120'][:self.size]
	def pie_colors(self):
		return self.colors()
	
	def register_plot(self, fn):
		self.plot_fns.append(fn)
	
	def register_with_index(self, ind, no_data = False):
		xtra = ''
		if no_data:
			xtra = 'No data<br />'

		elif self.dt_ts[0] == self.dt_ts[-1]:
			xtra = 'Data from %s<br />' % self.dt_ts[0].ctime()

		ind.add_plots( self.title
		             , self.col_name
			     , [fn.split('/')[-1] for fn in self.plot_fns]
#, xtra + ''.join([ '<img src="%s" />' % fn.split('/')[-1]
#		                         for fn in self.plot_fns ])
			     , self
			     )

	def plot_more(self, ax):
		pass;

	def do_prb_plots(self, fn, data, n_probes_now, labs = None, colors = None, cols = None):
		fn_split = fn.split('.')
		if labs is None:
			labs = self.labs()
		if colors is None:
			colors = self.colors()
		if cols is None:
			cols = self.cols()
		for col, number, color, label in zip(cols, data, colors, labs):
			print col, number, n_probes_now, n_probes_now - number, color, label
			fig, ax = pp.subplots(1, 1, figsize=(2.25, 2.25))
			ax.pie( [number, n_probes_now - number]
			      , colors = [color, '#CCCCCC']
			      , shadow = False )
			ax.axis('equal')
			patch = mpatches.Patch(color = color)
			if label.startswith('do not'):
				lab_txt = ' '.join(label.split()[:3])
			elif label.startswith('do') or label.startswith('have'):
				lab_txt = label.split()[0]
			else:
			 	lab_txt = label.split()[-1]
			pct_label = '%s (%1.1f%%)' \
			          % ( lab_txt
			            , number * 100.0 / n_probes_now)
			ax.legend([patch], [pct_label], ncol = 1
				 , loc='lower right')
			fn_ext   = fn_split[-1]
			fn_base  = '.'.join(fn_split[:-1])
			pie_fn = fn_base + '_' + col  + '_pie.' + fn_ext
			pp.savefig(pie_fn, transparent = True, bbox_inches='tight')
			pp.close()
			self.register_plot(pie_fn)

	def do_pie_plot(self, fn, data, unknown = None, labels = None, colors = None):
		fig, ax = pp.subplots(1, 1, figsize=(4.5, 4.5))
		if unknown:
			data += [unknown]
			ax.pie(data, colors = self.colors() + ['#CCCCCC'], shadow = False)
		else:
			ax.pie(data, colors = self.colors(), shadow = False)
		ax.axis('equal')

		plot_patches = []
		if not labels:
			labels = self.pie_labs()
		if not colors:
			colors = self.pie_colors()
		if unknown:
			#labels += ['unknown']
			colors += ['#CCCCCC']
		i = 0
		for label in labels:
			plot_patches.append(mpatches.Patch(color = colors[i]))
			i += 1

		pct_labels = ['%s (%1.1f%%)' % (label, pct) for label, pct in zip(labels, [float(100*n) / float(sum(data)) for n in data])]

		ax.legend(plot_patches[::-1], pct_labels[::-1]
		         , ncol=(2 if len(pct_labels) > 3 else 1)
			 , loc='lower right')

		fn_split = fn.split('.')
		fn_ext   = fn_split[-1]
		fn_base  = '.'.join(fn_split[:-1])
		pie_fn = fn_base + '_pie.' + fn_ext
		pp.savefig(pie_fn, transparent = True, bbox_inches='tight')
		pp.close()
		self.register_plot(pie_fn)

	def do_plot(self, dt_ts, data_ts, fn, data_ts_prbs = None):
		global n_resolvers

		unknown_ts = [ row[0] - sum(row[1:]) 
		               for row in zip(n_resolvers[len(n_resolvers)-len(dt_ts):], *data_ts)]
		if dt_ts[0] == dt_ts[-1]:
			self.dt_ts = dt_ts
			self.do_pie_plot(fn, [v[-1] for v in data_ts], unknown_ts[-1])
			return

		fig, ax = pp.subplots(figsize=(8, 4.5))

		if len(dt_ts) > 270:
			ticks = []
			prev_month = dt_ts[0].month
			for day in dt_ts:
				if day.month != prev_month:
					ticks.append(day)
				prev_month = day.month

			ax.xaxis.set_ticks(ticks)
			ax.xaxis.set_major_formatter(mpd.DateFormatter('%Y-%m-%d'))
		elif len > 120:
			ax.xaxis.set_major_formatter(mpd.DateFormatter('%Y-%m-%d'))

		ax.stackplot(dt_ts, data_ts + [unknown_ts], colors = self.colors() + ['#CCCCCC'])
		ax.set_xlim(dt_ts[0], dt_ts[-1])

		self.dt_ts = dt_ts
		self.plot_more(ax)
		
		colors = [ mpatches.Patch(color = c) for c in self.colors()]
		labels = self.labs()
		if data_ts_prbs:
			i = 0
			for col_prbs in data_ts_prbs:
				color = darken(self.colors()[i])
				colors.append(mpatches.Patch(color = color))
				label = 'probes that ' + labels[i]
				labels.append(label)
				ax.plot(dt_ts, col_prbs, color = color)
				i += 1
		ax.legend( colors[::-1]
			 , [label.decode('utf-8') for label in labels[::-1]]
			 , ncol=1, loc='upper left')
		ax.set_ylabel('Probe/resolver pairs')
		
		fig.autofmt_xdate(rotation=45)
		pp.savefig(fn, transparent = True, bbox_inches='tight')
		pp.close()
		self.register_plot(fn)
		self.do_pie_plot(fn, [v[-1] for v in data_ts], unknown_ts[-1])
		if data_ts_prbs:
			self.do_prb_plots(fn, [v[-1] for v in data_ts_prbs], n_probes[-1])

	def plot(self, dt_ts, csv, ind):
		data_ts = [csv[col].values for col in self.cols()]
		for offset in range(len(dt_ts)):
			if sum([ts[offset] for ts in data_ts]) > 0:
				break;
		try:
			offset
		except NameError:
			self.register_with_index(ind, no_data = True)
			return

		data_ts_prbs = [csv[col + '_prbs'].values[offset:] for col in self.cols()]

		self.csv    = csv
		self.do_plot( dt_ts[offset:]
		            , [ts[offset:] for ts in data_ts]
			    , ind.path + '/' + self.col_name + '.svg'
		            , data_ts_prbs )
		self.register_with_index(ind)

class DoesProp(Prop):
	prop = [('does', 'do'), ('doesnt', 'do not do')]

class HasProp(Prop):
	prop = [('has', 'have'), ('hasnt', 'do not have ')]
	def colors(self):
		return ['#7DB874', '#D92120'][:self.size]

class CanProp(Prop):
	prop = [('can', 'can do'), ('cannot', 'cannot do'), ('broken', 'broken')]

class DNSSECProp(CanProp):
	prop = [('can', 'can do'), ('cannot', 'cannot do'), ('broken', 'has broken')]
	def labs(self):
		return [ self.lab_name + ' secure', self.lab_name + ' insecure'
		       , self.lab_name + ' failing' ]

class DNSKEYProp(DNSSECProp):
	def __init__(self, col_name, lab_name):
		super(DNSKEYProp, self).__init__(
		    'DNSKEY Algorithm %s support' % lab_name, col_name, lab_name)

class DSProp(DNSSECProp):
	def __init__(self, col_name, lab_name):
		super(DSProp, self).__init__(
		    'DS Algorithm %s support' % lab_name, col_name, lab_name)

class IntProp(Prop):
	def __init__(self):
		super(IntProp, self).__init__(
		    'Internal, Forwarding & External',
		    'int_fwd_ext', 'Internal/Forwarding/External')
	def cols(self):
		return ['is_internal', 'is_forwarding', 'is_external']
	def labs(self):
		return ['internal', 'forwarding', 'external']
	def colors(self):
		return ['#CC66CC', '#66CCCC', '#CCCC66']

def asn_label(asn):
	return asns.get(asn, (asn, asn))[1]

#DoesProp  ('Non existant domain hijacking', 'nxdomain' , 'NX hijacking', 2)
class TopASNs(Prop):
	def __init__(self, asn_type):
		self.asn_type = asn_type
		self.asn_small_type = 'prb' if asn_type == 'probe' else \
				      'res' if asn_type == 'resolver' else asn_type
		self.labels = None
		size = 10
		super(TopASNs, self).__init__(
		    ( 'Top %d %sASNs'
		    % ( size
		      , 'Probe ' if asn_type == 'probe' else
		        'Resolver ' if asn_type == 'resolver' else
		        'Authoritative ' if asn_type == 'auth' else 
		        'NX domain rewriting' if asn_type == 'nxhj' else '' )),
		    'top_%s_asns' % asn_type, 'Top ASNs')
		self.size = 10

	def labs(self):
		return self.labels
	def pie_labs(self):
		return self.pie_labels
	def colors(self):
		if self.labels:
			colors = list()
			prev_color = ''
			for label in self.labels:
				color = lookup_color('asn', label, prev_color)
				colors.append(color)
				prev_color = color
			return colors
		else:
			return (best_bar_colors + best_bar_colors)
		return [ '#CC9966', '#CC6699', '#99CC66', '#9966CC', '#66CC99', '#6699CC'
		       , '#33CC99', '#3399CC', '#CC3399'#, '#CC9933', '#9933CC', '#99CC33'
		       , '#999999'][:(len(self.labels)
		                       if self.labels is not None else 999999)]
	def plot(self, dt_ts, csv, ind):
		offset = -1
		n_resolvers = csv['# resolvers'].values
		for i in range(len(n_resolvers)):
			if n_resolvers[i] != 0:
				offset = i
				break
		if offset < 0:
			return '';

		asn_totals = dict()
		bands = [ zip( csv['%s #%d total' % (self.asn_type, band)].values[offset:]
		             , csv['%s #%d ASNs' % (self.asn_type, band)].values[offset:])
		          for band in range(1,100) ]
		rem   = csv['Remaining %s ASNs count' % self.asn_type].values[offset:]
		bands += [zip(rem, ['rem'] * len(rem))]
		for band in bands:
			i = 0
			for total, ASNs in band:
				if n_resolvers[offset + i] == 0:
					i += 1
					continue
				if type(ASNs) is not str or not ASNs.startswith('AS'):
					i ++ 1
					continue
				ASNs = ASNs.split(',')
				for asn in ASNs:
					if asn not in asn_totals:
						asn_totals[asn] = 0
					asn_totals[asn] += total / len(ASNs)
				i += 1

		top = sorted( [(tot, asn) for asn, tot in asn_totals.items()]
		            , reverse = True)

		size = self.size
		self.labels = [asn for tot, asn in top][:size-1]
		self.labels += ['Remaining']
		self.prop = [ (('%s_%s' % (self.asn_small_type, asn)), None)
		              for tot, asn in top][:size-1]
		data_ts = list()
		i = 0
		for row in zip(*bands):
			if n_resolvers[offset + i] == 0:
				i += 1
				data_ts.append([0] * size)
				continue
			asn_dict = {}
			top_row = list()
			rem = 0
			for total, ASNs in row:
				if type(ASNs) is not str:
					continue
				if not ASNs.startswith('AS'):
					rem += total
					continue
				ASNs = ASNs.split(',')
				for asn in ASNs:
					asn_dict[asn] = total / len(ASNs)
			for j in range(len(self.labels)-1):
				asn = self.labels[j]
				top_row.append(asn_dict.get(asn, 0))
				asn_dict[asn] = 0
			top_row.append(sum(asn_dict.values()) + rem)
			data_ts.append(top_row)
			i += 1

		data_ts = [list(ts) for ts in zip(*data_ts)]
		self.pie_labels = [asn for asn in self.labels]
		self.labels = [asn_label(asn) for asn in self.labels]
		self.do_plot( dt_ts[offset:], data_ts
			    , ind.path + '/' + self.col_name + '.svg' )

		if self.asn_type == 'nxhj':
			does_nxdomain = csv['does_nxdomain_prbs'].values[-1]
			doesnt_nxdomain = csv['doesnt_nxdomain_prbs'].values[-1]
			self.do_prb_plots(ind.path + '/' + self.col_name + '.svg', [does_nxdomain, doesnt_nxdomain], n_probes[-1], labs = ['do rewriting', 'do not do rewriting'], colors = ['#D92120', '#7DB874'], cols = ['doesn_nxdomain', 'doesnt_nxdomain'])
		self.register_with_index(ind)
		self.col_name = ''
		if self.asn_type == 'nxhj':
			self.prop = [ ('does_nxdomain', None)
			            , ('doesnt_nxdomain', None) ]

	

class TopECSMasks(Prop):
	def __init__(self, af = ''):
		self.af = af = str(af)
		if af == '4': self.af = ''
		self.labels = None
		super(TopECSMasks, self).__init__(
		    ('Top %sEDNS Client Subnet masks' % ('6' if af == 'IPv6 ' else '')),
		    'ecs_masks'+af, 'ECS Masks'+af)

	def labs(self):
		return self.labels
	def colors(self):
		return best_bar_colors[:(len(self.labels)
		                       if self.labels is not None else 999999)]
	def plot(self, dt_ts, csv, ind):
		offset = -1
		n_resolvers = csv['# resolvers'].values
		for i in range(len(n_resolvers)):
			if n_resolvers[i] != 0:
				offset = i
				break
		if offset < 0:
			return '';

		ecs_totals = dict()
		masks = [ zip( csv['ECS mask%s #%d'       % (self.af,mask)].values[offset:]
		             , csv['ECS mask%s #%d count' % (self.af,mask)].values[offset:])
		          for mask in range(1,10) ]
		rem   = csv['Remaining ECS mask%s count' % self.af].values[offset:]
		if self.af == '':
			masks6 = [ zip( csv['ECS mask6 #%d' % mask].values[offset:]
			              , csv['ECS mask6 #%d count' % mask].values[offset:])
			 	  for mask in range(1,10) ]
			rem6   = csv['Remaining ECS mask6 count'].values[offset:]
			masks += masks6
			rem    = [ r4 + r6 for r4, r6 in zip(rem, rem6) ]
			
		masks+= [zip([-1] * len(rem), rem)]
		for mask_counts in masks:
			i = 0
			for mask, count in mask_counts:
				if n_resolvers[offset + i] == 0:
					i += 1
					continue
				if mask not in ecs_totals:
					ecs_totals[mask] = 0
				ecs_totals[mask] += count
				i += 1

		top = sorted( [ (tot, ecs) for ecs, tot in ecs_totals.items()
		                           if  ecs > 0 and tot > 0 ]
		            , reverse = True)
		size = len(self.colors())
		if len(top) < size:
			self.size = size = len(top)
			self.labels = [ecs for tot, ecs in top][:size]
		else:
			self.labels = [ecs for tot, ecs in top][:size-1]
			self.labels += ['Remaining']
		data_ts = list()
		i = 0
		for row in zip(*masks):
			if n_resolvers[offset + i] == 0:
				i += 1
				data_ts.append([0] * size)
				continue
			ecs_dict = dict(row)
			top_row = list()
			rem = 0
			for j in range(len(self.labels)-1):
				mask = self.labels[j]
				top_row.append(ecs_dict.get(mask, 0))
				ecs_dict[mask] = 0
			top_row.append(sum(ecs_dict.values()) + rem)
			data_ts.append(top_row)
			i += 1

		data_ts = [list(ts) for ts in zip(*data_ts)]
		self.labels = [ '/' + str(l) if type(l) is not str else l
		                for l in self.labels]
		self.do_plot( dt_ts[offset:], data_ts
			    , ind.path + '/' + self.col_name + '.svg' )

		try:
			self.do_prb_plots(ind.path + '/' + self.col_name + '.svg', [self.does_ecs_prbs], n_probes[-1], labs = ['sends ECS'], colors = ['#E39C37'], cols = ['does_ecs'])
		except AttributeError:
			does_ecs = csv['does_ecs_prbs'].values
			self.does_ecs_prbs = does_ecs[-1]
			self.do_prb_plots(ind.path + '/' + self.col_name + '.svg', [self.does_ecs_prbs], n_probes[-1], labs = ['sends ECS'], colors = ['#E39C37'], cols = ['does_ecs'])

		self.register_with_index(ind)
		self.col_name = ''
		self.prop = [('does_ecs', '')]

	def plot_more(self, ax):
		global csv
		does_ecs = csv['does_ecs_prbs'].values
		self.does_ecs_prbs = does_ecs[-1]
		if len(does_ecs) > len(self.dt_ts):
			does_ecs = does_ecs[(len(does_ecs) - len(self.dt_ts)):]
		ax.plot(self.dt_ts, does_ecs, color = '#009900')

class TAProp(HasProp):
	def __init__(self):
		return super(TAProp, self).__init__(
		    'Root Key Trust Anchor Sentinel for DNSSEC',
		    'ta_20326' , '. KSK 20326')
	
	def colors(self):
		return super(TAProp, self).colors()
	def labs(self):
		return super(TAProp, self).labs()

	def plot(self, dt_ts, csv, ind):
		super(TAProp, self).plot(dt_ts, csv, ind)
		self.col_name = ''
		self.prop = [ ('has_ta_19036', '')
		            , ('has_ta_20326', ''), ('hasnt_ta_20326', '')]

	def plot_more(self, ax):
		has_19036 = self.csv['has_ta_19036'].values
		if len(has_19036) > len(self.dt_ts):
			has_19036 = has_19036[(len(has_19036) - len(self.dt_ts)):]
		ax.plot(self.dt_ts, has_19036, color = '#000000')

def create_plots(fn):
	global  csv, n_probes, n_resolvers, ts_series, p_t, t_t
	props = [ IntProp()
		, TopASNs   ('auth')
		, TopASNs   ('resolver')
		, TopASNs   ('probe')
		, DoesProp  ('Qname Minimization', 'qnamemin' , 'qnamemin'   , 2)
#, DoesProp  ('ENDS Client Subnet', 'ecs'      , 'EDNS Client Subnet', 1)
		, TopECSMasks()
#, TopECSMasks(6)
		, TopASNs   ('nxhj')
	        , TAProp()
		, DNSKEYProp('ed448'    , 'ED448')
		, DNSKEYProp('ed25519'  , 'ED25519')
		, DNSKEYProp('ecdsa384' , 'ECDSA-P384-SHA384')
		, DNSKEYProp('ecdsa256' , 'ECDSA-P256-SHA256')
		, DNSKEYProp('eccgost'  , 'ECC-GOST')
		, DNSKEYProp('rsasha512', 'RSA-SHA512')
		, DNSKEYProp('rsasha256', 'RSA-SHA256')
		, DNSKEYProp('rsansec3' , 'RSA-SHA1-NSEC3')
		, DNSKEYProp('dsansec3' , 'DSA-NSEC3')
		, DNSKEYProp('rsasha1'  , 'RSA-SHA1')
		, DNSKEYProp('dsa'      , 'DSA')
		, DNSKEYProp('rsamd5'   , 'RSA-MD5')
		, DSProp    ('gost'     , 'GOST DS')
		, DSProp    ('sha384'   , 'SHA-384 DS')
		, CanProp   ('IPv6', 'ipv6'     , 'IPv6'       , 1)
		, CanProp   ('TCP' , 'tcp'      , 'TCP'        , 1)
		, CanProp   ('TCP6', 'tcp6'     , 'TCP6'       , 1)
		]

	csv         = pd.read_csv(fn)
	n_probes    = csv['# probes'].values
	n_resolvers = csv['# resolvers'].values

	ts_series   = [ datetime.strptime(iso_dt, '%Y-%m-%dT%H:%M:%SZ')
		        for iso_dt in csv['datetime'].values ]

	path = '/'.join(fn.split('/')[:-1])
	path = path if path else '.'
	page = Index(path, 'DNSThought')
	for prop in props:
#for prop in [TopASNs   ('auth') , TopASNs   ('resolver') , TopASNs   ('probe')]:
		prop.plot(ts_series, csv, page)
		t = time.time()
		t_t += (t - p_t)
		print('t: %7.4f %7.4f' % (t - p_t, t_t))
		p_t = t
	page.save()

if __name__ == '__main__':
	global p_t, t_t, asns, hijacks_by_probe, hj_res_by_asn, hj_ips_by_asn
	t_t = 0
	p_t = time.time()
	if len(sys.argv) != 2:
		print('usage: %s <report.csv>' % sys.argv[0])
		sys.exit(1)
	
	with open('/'.join(sys.argv[0].split('/')[:-1] + ['asns.cPickle'])) as o:
		asns = cPickle.load(o)
	with open('/'.join(sys.argv[0].split('/')[:-1] + ['hijacks.pcl'])) as o:
		hijacks_by_probe, hj_res_by_asn, hj_ips_by_asn = cPickle.load(o)

	create_plots(sys.argv[1])

