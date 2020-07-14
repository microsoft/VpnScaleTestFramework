#!/bin/bash

CONTROLLER_ENDPOINT_BASE_URI=$1
VPN_SERVER_CERT_THUMBPRINT=$2
VPN_SERVER_HOST=$3
SPREAD=$4
CONNECT_TIMEOUT=$5
TUNNEL_SCRIPT=$6

if [[ SPREAD -ne 0 ]]; then
    sleep $((RANDOM%SPREAD))
fi

start=$(date +"%D %T.%N")
./$TUNNEL_SCRIPT $CONTROLLER_ENDPOINT_BASE_URI $VPN_SERVER_CERT_THUMBPRINT $VPN_SERVER_HOST $SPREAD <&- >./connect.log 2>&1 &

./wait_for_vpn.sh $CONNECT_TIMEOUT
WAIT_FOR_VPN=$?
if [[ WAIT_FOR_VPN -ne 0 ]]; then
    echo "Tunnel failed to open within $CONNECT_TIMEOUT seconds"
    echo "LOGS:"
    cat ./connect.log
    exit $WAIT_FOR_VPN
fi

end=$(date +"%D %T.%N")
echo "Tunnel open with IP Address: $(ip address show dev tun0 | grep inet | awk '{print $2}')"
echo "TunnelOpen,$start,$end"
exit 0