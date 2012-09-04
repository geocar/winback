#!/bin/sh

# this backup tool requires bourne-shell, find, xargs, and ln
# it doesn't require the GNU versions of these, but will work fine with busybox
# which makes it work on a terastation pro
#
# the theory of operation follows:
#
#	1. run rotatedir.sh dir/ on your nas for each "root" twice as often as
#          your backup tool
#
#	2. run the backup tool on the server to upload to the nas with /K
#          (or -k) to dir/backup.0
#


count=3
if [ "X$1" = "X" ]; then
	echo "Usage: $0 basedir ..." >&2
	exit 1
fi
n=`expr "$2" - 1 2>/dev/null`
if [ "X$2" = "X" ]; then
	true
elif [ "X$n" = "X" ]; then
	echo "Can't parse number $2; using default count=$count" >&2
elif echo "$n" | grep '[^0-9]' 2>/dev/null; then
	echo "Must keep at least one rotation (count=$n not allowed)" >&2
	exit 1
elif [ "$n" -lt 1 ]; then
	echo "Must keep at least one rotation (count=$n not allowed)" >&2
	exit 1
fi

for dest in $@; do
(cd "$dest" || exit 1

if [ -d backup.0 ]; then
	if [ -f backup.0/checkpoint.txt ]; then
		true
	else
		exit 0
	fi
fi

rm -f backup.[1-9]/checkpoint.txt backup.[1-9]*/checkpoint.txt 
rm -rf "backup.$count"

pcount="$count"
count=`expr "$pcount" - 1`
while [ "$count" -gt "0" ]; do
	[ -d backup.$count ] && set -e && mv backup.$count backup.$pcount
	set +e
	pcount="$count"
	count=`expr "$pcount" - 1`
done

rm -rf backup.tmp
if [ -d backup.0 ]; then
	if cp --version >/dev/null 2>&1; then
		# assume GNU cp which supports -al, which is a LOT faster
		cp -al backup.0 backup.tmp || exit 1
	else
		# busybox can do this, but it's a bit slower
		set -e
		(cd backup.0 && find . -type d -print0) | (mkdir -p backup.tmp; cd backup.tmp && xargs -0 mkdir -p)
		(cd backup.0 && find . \! -type l -type f -print0) | xargs -0 -i ln -- backup.0/{} backup.tmp/{}
	fi
	rm -f backup.tmp/checkpoint.txt
	mv backup.tmp backup.1
else
	mkdir -p backup.0
fi

rm -f backup.0/checkpoint.txt
); done
# at this point, it's safe to upload to dir/backup.0
