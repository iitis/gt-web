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

# get IP address
IP="`ip r get 173.194.65.106 2>/dev/null | sed -re '/src /!d; s/.* src ([^ ]+).*/\1/'`"
if [[ ! $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	IP="`hostname -I | sed -re 's;[^0-9.:a-fA-F];_;g'`"
	if [[ $? -ne 0 || -z "$IP" ]]; then
		echo "Could not get local IP address"
		ERR=1
	fi
fi

# make storage place
if [[ ! -d ./out ]]; then
	echo "No storage space"
	ERR=1
fi

PREFIX=./out/$IP-`date "+%d.%m.%Y-%H_%M_%S"`

# check tcpdump
if ! tcpdump -h 2>&1 | grep -q 'tcpdump version'; then
	echo "You need tcpdump program installed" >&2
	ERR=1
fi

# check gcc
if ! gcc -v 2>&1 | grep -q 'gcc version'; then
	echo "You need gcc compiler installed" >&2
	ERR=1
fi

if [[ $ERR -eq 1 ]]; then
	exit 1
fi

# build httpd server
if ! make -C src -s; then
	echo "Building httpd failed" >&2
	exit 1
fi

# start tcpdump
(
tcpdump -q \
	-n -i any -s $SNAPLEN -w $PREFIX.pcap \
	'(udp and port 53) or (tcp and (port 80 or port 443))' >/dev/null 2>&1
) &
PID=$!

sleep 0.2 2>/dev/null
if [[ ! -d /proc/$PID ]]; then
	echo "Starting tcpdump failed" >&2
	exit 1
fi

# start httpd
echo "Dumping web traffic to $PREFIX - stop with Ctrl+C"
./src/httpd > $PREFIX.txt
kill $PID
