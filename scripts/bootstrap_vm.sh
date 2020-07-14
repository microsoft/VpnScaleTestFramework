#!/bin/bash
TEST_CONTROLLER=$1
IMAGE_SOURCE=$2
IMAGE_FILE=$3
IMAGE_ID=$4

vpntestcount=$(docker ps -a | grep vpntest | wc |  awk {'print $1'})
if [ $vpntestcount -gt 0 ]; then 
    docker rm -f $(docker ps -a | grep vpntest | awk {'print $1'})
    if [ $? -ne 0 ]; then
        echo "Failed to cleanup old containers"
        exit 1
    fi
fi
docker image prune -f -a
if [ $? -ne 0 ]; then
  echo "Failed to cleanup old images"
  exit 
fi

rm -f $IMAGE_FILE
wget -q $IMAGE_SOURCE/$IMAGE_FILE

docker load -i $IMAGE_FILE 
if [ $? -ne 0 ]; then
  echo "Failed to load image $IMAGE_SOURCE/$IMAGE_FILE"
  exit 1
fi
rm $IMAGE_FILE

for i in $(seq 1 125); do
    docker create --restart always --name vpntest_$i --cap-add NET_ADMIN --device /dev/net/tun $IMAGE_ID bash -c "TestClient $TEST_CONTROLLER/testdata /test-controller-cert.pem >/tmp/agent.log 2>&1"
    docker cp test-controller-cert.pem vpntest_$i:/test-controller-cert.pem
    docker start vpntest_$i
done
