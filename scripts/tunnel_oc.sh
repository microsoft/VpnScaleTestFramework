#!/bin/bash
CONTROLLER_ENDPOINT_BASE_URI=$1
VPN_SERVER_CERT_THUMBPRINT=$2
VPN_SERVER_HOST=$3
SPREAD=30
ldconfig

while [[ 1 ]]
do
    openconnect --token-mode=oidc --token-secret="$(wget $CONTROLLER_ENDPOINT_BASE_URI/oidc/token -O - 2>/dev/null)" --http-auth=Bearer --servercert $VPN_SERVER_CERT_THUMBPRINT $VPN_SERVER_HOST
    sleep $((RANDOM%30))
done

