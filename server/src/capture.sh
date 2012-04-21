#!/bin/bash

SNAPLEN=100
ERR=0

# cd to this dir
if ! cd "${0%/*}"; then
	echo "Changing directory failed" >&2
	ERR=1
fi

# check root
if [ "$UID" != "0" ]; then
	echo "You need to be root" >&2
	ERR=1
fi

# get ID
ID=`ip r get 173.194.65.106 2>/dev/null | head -1`
ID="`hostname`-${ID##* src }"
ID="${ID// /}"
PREFIX=../out/current/$ID-`date "+%d.%m.%Y-%H_%M_%S"`

mkdir -p ../out/{current,archive,upload}

# check tcpdump
if ! tcpdump -h 2>&1 | grep -q 'tcpdump version'; then
	echo "You need tcpdump program installed" >&2
	ERR=1
fi

[[ $ERR -eq 1 ]] && exit 1

if [[ "`./httpd check 2>/dev/null`" != "works" ]]; then
	# check gcc
	if ! gcc -v 2>&1 | grep -q 'gcc version'; then
		echo "You need gcc compiler installed" >&2
		exit 1
	fi

	# build httpd server
	if ! make -B; then
		echo "Building httpd failed" >&2
		exit 1
	fi
fi

########################

# on exit terminate subprocesses
function doexit()
{
	kill $PID_TCPDUMP $PID_HTTPD 2>/dev/null
}
trap doexit EXIT

# start tcpdump
(tcpdump -qn -i any -s $SNAPLEN -w $PREFIX.pcap \
	'(udp and port 53) or (tcp and (port 80 or port 443))' >/dev/null) &
PID_TCPDUMP=$!

# start httpd
( ./httpd > $PREFIX.txt ) &
PID_HTTPD=$!

# check
sleep 1
if [[ ! -d /proc/$PID_TCPDUMP ]]; then
	echo "Starting tcpdump failed" >&2
	exit 1
elif [[ ! -d /proc/$PID_HTTPD ]]; then
	echo "Starting httpd failed" >&2
	exit 1
fi

echo "Dumping web traffic to $PREFIX"
wait $PID_HTTPD 2>/dev/null
