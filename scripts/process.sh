#!/bin/sh

export TZ=UTC
now_t=`date +%s`
yesterday_t=`expr $now_t - 86400`
yesterday=`date -r $yesterday_t +%Y-%m-%d`
today=`date +%Y-%m-%d`

start_t=`date -j 201704200000 +%s`
#start_t=`date -j 201807190000 +%s`
start=`date -r $start_t +%Y-%m-%d`
next_t=`expr $start_t + 86400`
next=`date -r $next_t +%Y-%m-%d`

if [ "$start" = "$yesterday" ]
then
	exit 1
fi
while [ -f ${next}.res ]
do
	next_d=`date -r $next_t +%Y%m%d`
	start_t=`date -j ${next_d}0000 +%s`
	start=`date -r $start_t +%Y-%m-%d`
	next_t=`expr $start_t + 86400`
	next=`date -r $next_t +%Y-%m-%d`
	if [ "$start" = "$today" ]
	then
		exit 1
	fi
done
echo $start $next
time $HOME/dnsthought/dnst-processing/src/iter_dnsts $start $next ../atlas/[0-9]*
time $HOME/dnsthought/dnst-processing/src/cap_counter ${next}.res ../daily8
for c in *.csv
do
	if [ ! -e ../daily8/raw/$c ]
	then
		ln -s ../../processed7/$c ../daily8/raw
	fi
done

