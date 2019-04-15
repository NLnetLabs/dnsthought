#!/bin/sh
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

