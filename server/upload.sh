#!/bin/bash

# cd to this dir
if ! cd "${0%/*}/out"; then
	echo "Changing directory failed" >&2
	exit 0
fi

if [[ -z "`ls`" ]]; then
	echo "Nothing to upload"
	exit 1
fi

echo "Connecting to server..."
echo "put * pisa2012/" \
	| sftp -i ../src/iitis -b - -o UserKnownHostsFile=../src/known_hosts \
	pjf-upload@leming.iitis.pl

if [[ $? -eq 0 ]]; then
	echo "Success!"
	rm -f ./*
else
	echo "Upload failed"
	exit 1
fi
