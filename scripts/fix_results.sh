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


DNSTHOUGHT_HOME=/home/hackathon/dnsthought
#SCRIPTS_DIR=${DNSTHOUGHT_HOME}/dnst-processing/scripts
#BIN_DIR=${DNSTHOUGHT_HOME}/dnst-processing/src
SCRIPTS_DIR=/home/hackathon/bin
BIN_DIR=/home/hackathon/bin
GET_DAILY_RESULTS=${SCRIPTS_DIR}/get-daily-results.py
ATLAS2DNST=${BIN_DIR}/atlas2dnst
SORT_DNST=${BIN_DIR}/sort_dnst

check_mtime() {
	eval `/usr/bin/stat -s $1`
	D=`echo $1 | /usr/bin/sed -e 's/^.*\///g' -e 's/\.dnst//g' -e 's/-//g'`
	D=`TZ=UTC /bin/date -j ${D}0000 +%s`
	if [ $st_mtime != $D ]
	then
		echo touch -d `TZ=UTC date -r $D +%Y-%m-%dT%H:%M:%SZ` $1
		/usr/bin/touch -d `TZ=UTC date -r $D +%Y-%m-%dT%H:%M:%SZ` $1
	fi
}

for d in atlas
do
	cd ${DNSTHOUGHT_HOME}/$d
	(
		TO_MAKE=""
		for f in `/usr/bin/find . -type f -name 201[78]-[0-9][0-9]-[0-9][0-9]`
		do
			rm -f ${f}.dnst
			TO_RM=${f%/*}
			DAY=${f#${TO_RM}/}
			cat << EOM
${f}.dnst:
	(  ${ATLAS2DNST} ${f} \\
	&& ${SORT_DNST} ${f}.dnst ${f}.sdnst \\
	&& /bin/mv -v ${f}.sdnst ${f}.dnst \\
	&& TZ=UTC /usr/bin/touch -d "${DAY}T00:00:00Z" ${f}.dnst \\
	&& /bin/rm -v ${f} \\
	)  || rm -f ${f}.dnst ${f}.sdnst
EOM
			TO_MAKE="$TO_MAKE ${f}.dnst"
		done
		echo "all:${TO_MAKE}"
	) > Makefile && make -j 6 all
done
exit 0

for d in atlas
do
	for f in `/usr/bin/find . -type f -name 201[78]-[0-9][0-9]-[0-9][0-9].dnst`
	do
		check_mtime $f
	done
done
