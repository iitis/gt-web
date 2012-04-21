#!/bin/bash

# cd to this dir
if ! cd "${0%/*}"; then
	echo "Changing directory failed" >&2
	exit 1
fi

function doexit()
{
	kill $PID 2>/dev/null

	echo "Exiting - please wait while all the data is uploaded..."
	mv ./out/current/* ./out/upload/
	./src/upload.sh
}

function now()
{
	date +%s
}

while true; do
	./src/capture.sh &
	PID=$!

	sleep 2
	trap - EXIT
	if [[ ! -d /proc/$PID ]]; then
		echo "Starting the tracker failed" >&2
		exit 1
	fi
	trap doexit EXIT

	ts_timeout=$((`now` + 86400))
	while true; do
		sleep 1
		ts_now=`now`
		if [[ $ts_now -ge $ts_timeout ]]; then
			break
		fi
	done

	kill $PID
	sleep 1

	mv ./out/current/* ./out/upload/
	./src/upload.sh &
done
