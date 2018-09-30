#!/usr/bin/env python

from datetime import *
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as pp
import matplotlib.patches as mpatches
import matplotlib.dates as mpd
import pandas as pd

report_csv = pd.read_csv('/home/hackathon/dnsthought/daily2/report.csv')
ts_series = [ datetime.strptime(iso_dt, '%Y-%m-%dT%H:%M:%SZ')
              for iso_dt in report_csv['datetime'].values ]
n_resolvers      = report_csv['# resolvers']
does_qnamemin    = report_csv['does_qnamemin'].values
doesnt_qnamemin  = report_csv['doesnt_qnamemin'].values
unknown_qnamemin = [ n_resolvers[i] - does_qnamemin[i] - doesnt_qnamemin[i]
                     for i in range(len(n_resolvers)) ]
#data_ts          = [ unknown_qnamemin, does_qnamemin, doesnt_qnamemin ]
#plot_labels      = [ 'unknown', 'does qnamemin', 'doesn\'t qnamemin' ]
#plot_colors      = [ '#B8B8B8', '#7DB874', '#E39C37' ] # Failing: '#D92120'

data_ts          = [ does_qnamemin, doesnt_qnamemin ]
plot_labels      = [ 'does qnamemin', 'doesn\'t qnamemin' ]
plot_colors      = [ '#7DB874', '#E39C37' ] # Failing: '#D92120'

plot_patches     = [ mpatches.Patch(color = c) for c in plot_colors ]

fig,ax = pp.subplots(figsize=(8,4.5))
ticks = []
prev_month = ts_series[0].month
for day in ts_series:
	if day.month != prev_month:
		ticks.append(day)
		prev_month = day.month
ax.xaxis.set_ticks(ticks)
ax.xaxis.set_major_formatter(mpd.DateFormatter('%b %Y'))
ax.stackplot(ts_series, data_ts, colors = plot_colors)

plot_patches.reverse()
plot_labels.reverse()
ax.legend(plot_patches, plot_labels, ncol=1, loc='upper right')
ax.set_ylabel('Probe/resolver pairs')
ax.set_xlim(ts_series[0], ts_series[-1])
fig.autofmt_xdate(rotation=45)
pp.savefig('qnamemin.svg')
