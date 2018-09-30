#!/bin/sh

DNSTHOUGHT_HOME=/home/hackathon/dnsthought
SCRIPTS_DIR=${DNSTHOUGHT_HOME}/dnst-processing/scripts
BIN_DIR=${DNSTHOUGHT_HOME}/dnst-processing/src
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
	PREV_TIME=`/bin/date +%s`
	while ${GET_DAILY_RESULTS} [0-9]*
	do
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
	&& ${SORT_DNST} -d ${f}.dnst ${f}.sdnst \\
	&& /bin/mv -v ${f}.sdnst ${f}.dnst \\
	&& TZ=UTC /usr/bin/touch -d "${DAY}T00:00:00Z" ${f}.dnst \\
	&& /bin/rm -v ${f} \\
	)  || rm -f ${f}.dnst ${f}.sdnst
EOM
				TO_MAKE="$TO_MAKE ${f}.dnst"
			done
			echo "all:${TO_MAKE}"

		) > Makefile && make -j 6 all
		CUR_TIME=`/bin/date +%s`
		echo "One day took `expr $CUR_TIME - $PREV_TIME` seconds"
		PREV_TIME=$CUR_TIME
	done
done
