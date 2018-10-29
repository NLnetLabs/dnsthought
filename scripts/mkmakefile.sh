#!/bin/sh

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
