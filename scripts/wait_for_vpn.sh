#!/bin/bash
TIME_IN_SECONDS=$1
NOW=$(date +%s)
END_TIME=$((NOW + TIME_IN_SECONDS))

while ! ip route | grep -q "dev tun0 scope link"; do
	NOW=$(date +%s)
	if [[ $NOW -ge $END_TIME ]]; then
		exit 1
	fi
	sleep 0.01
done
exit 0
