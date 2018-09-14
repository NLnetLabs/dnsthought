#!/bin/sh

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

for d in atlas-results rootcanary-results rootcanary-dss
do
	cd /home/hackathon/dnsthought/$d
	for f in `/usr/bin/find . -type f -name 201[78]-[0-9][0-9]-[0-9][0-9]`
	do
		if [ ! -e ${f}.dnst ]
		then
			echo converting $f
			/home/hackathon/bin/atlas2dnst $f || /bin/rm -f ${f}.dnst
			
			if [ -e ${f}.dnst ]
			then
				echo ${f}.dnst exists, removing $f
				/bin/rm $f
				check_mtime ${f}.dnst
			fi
		else
			echo ${f}.dnst exists, removing $f
			/bin/rm -v $f
			check_mtime ${f}.dnst
		fi
	done
	for f in `/usr/bin/find . -type f -name 201[78]-[0-9][0-9]-[0-9][0-9].dnst`
	do
		check_mtime $f
	done
done
