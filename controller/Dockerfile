FROM ubuntu:18.04

ENV RUN_DEPS \
wget \
libicu60 \
dotnet-runtime-3.1 \
aspnetcore-runtime-3.1 

RUN \
apt-get update && \
apt install -y wget software-properties-common

RUN \
wget https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
dpkg -i packages-microsoft-prod.deb && \
apt-get update && \
apt-get install apt-transport-https && \
add-apt-repository universe && \
apt-get update

# Install the runtime dependencies
RUN apt update && apt install -y ${RUN_DEPS} && apt autoremove && apt clean

COPY helpers/bin/ /usr/local/bin
COPY bin/Debug/netcoreapp3.1/linux-x64/publish/ /usr/local/bin

WORKDIR /usr/local/bin

ENTRYPOINT ["MobileAccessTestController"]

EXPOSE 8080/tcp