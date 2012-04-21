#!/bin/bash

# cd to this dir
if ! cd "${0%/*}/../out/upload"; then
	echo "Changing directory failed" >&2
	exit 0
fi

if [[ -z "`ls`" ]]; then
	echo "Nothing to upload"
	exit 1
fi

echo "Connecting to server..."
echo "put * pisa2012/" \
	| sftp -b - -C \
	-o IdentityFile=../../src/iitis \
	-o UserKnownHostsFile=../../src/known_hosts \
	-o ConnectTimeout=30 \
	-o ServerAliveInterval=3 \
	-o ServerAliveCountMax=20 \
	pjf-upload@leming.iitis.pl

if [[ $? -eq 0 ]]; then
	mv -f ./* ../archive/
	echo "Success!"
else
	echo "Upload failed"
	exit 1
fi
