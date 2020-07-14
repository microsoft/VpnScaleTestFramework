FROM ubuntu:18.04 

# Dependencies
ENV RUN_DEPS \
iputils-ping \
iperf3 \
wget \
libcurl3-gnutls \
vpnc-scripts \
openconnect

# Setup runtime dependencies
RUN apt update && apt install -y ${RUN_DEPS} && apt autoremove && apt clean

COPY fetch_script.sh /usr/local/bin
COPY TestClient /usr/local/bin