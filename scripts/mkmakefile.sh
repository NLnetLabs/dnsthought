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


TMPDIR=`/usr/bin/mktemp -d`

cat > $TMPDIR/head << EOM
MKPLOTS = /home/hackathon/dnsthought/dnst-processing/scripts/mkplots.py
EOM

makefile_entries() {
	PREFIX="$1"
	TARGET="$2"
	MK_E_TO_MAKE=""
	for r in ${PREFIX}report.csv ${PREFIX}can_*/report.csv ${PREFIX}cannot_*/report.csv ${PREFIX}broken_*/report.csv ${PREFIX}does_*/report.csv ${PREFIX}doesnt_*/report.csv ${PREFIX}has_*/report.csv ${PREFIX}hasnt_*/report.csv ${PREFIX}is_*/report.csv
	do
		cat >> "${TMPDIR}/${TARGET}" << EOM
${r%report.csv}index.html: ${r}
	\$(MKPLOTS) ${r}
EOM
		MK_E_TO_MAKE="${MK_E_TO_MAKE} ${r%report.csv}index.html"
	done
	echo "${MK_E_TO_MAKE}"
}

MAIN_ENTRIES=`makefile_entries "" main`
for ASN_prefix in prb res auth
do
	TO_MAKE=""
	ASN_DETAILS=""
	for r in ${ASN_prefix}_AS*/report.csv
	do
#		cat >> "${TMPDIR}/${ASN_prefix}" << EOM
#${r%report.csv}index.html: ${r}
#	\$(MKPLOTS) ${r}
#EOM
		DETAILS=`makefile_entries ${r%report.csv} ${r%/report.csv}_indexes`
		echo "${r%/report.csv}_details:${DETAILS}" > "${TMPDIR}/${r%/report.csv}_details"
		TO_MAKE="${TO_MAKE} ${r%report.csv}index.html"
	done
	case $ASN_prefix in
	prb)  prb_ASNs="${TO_MAKE}" ;;
	res)  res_ASNs="${TO_MAKE}" ;;
	auth) auth_ASNs="${TO_MAKE}" ;;
	esac
done

(
 	cat ${TMPDIR}/head
	echo "all: main ASNs"
	echo "main:$MAIN_ENTRIES"
	echo "ASNs: prb_ASNs res_ASNs auth_ASNs"
	echo "prb_ASNs:${prb_ASNs}"
	echo "res_ASNs:${res_ASNs}"
	echo "auth_ASNs:${auth_ASNs}"
	echo "prb_ASN_details: `(cd ${TMPDIR}; echo prb_*_details)`"
	echo "res_ASN_details: `(cd ${TMPDIR}; echo res_*_details)`"
	echo "auth_ASN_details: `(cd ${TMPDIR}; echo auth_*_details)`"
	cat ${TMPDIR}/main
	cat ${TMPDIR}/*_details
	cat ${TMPDIR}/*_indexes
#	cat ${TMPDIR}/prb
#	cat ${TMPDIR}/res
#	cat ${TMPDIR}/auth
) > Makefile
rm -r ${TMPDIR}
