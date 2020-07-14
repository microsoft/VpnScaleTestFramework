#!/bin/bash
IMAGE_SOURCE=$1
IMAGE_FILE=$2
IMAGE_HASH=$3

rm -f $IMAGE_SOURCE/$IMAGE_FILE && wget -q $IMAGE_SOURCE/$IMAGE_FILE
if [ $? -ne 0 ]; then
  echo "Failed to download $IMAGE_SOURCE/$IMAGE_FILE"
  exit 1
fi

echo $IMAGE_HASH  $IMAGE_FILE | sha512sum -c
if [ $? -ne 0 ]; then
  echo "Failed to verify hash $IMAGE_SOURCE/$IMAGE_FILE"
  echo "Expected hash $IMAGE_HASH"
  echo "Actual hash" $(sha512sum $IMAGE_FILE)
  rm -f $IMAGE_FILE
  exit 1
fi

tar xvfz $IMAGE_FILE

chmod +x *.sh