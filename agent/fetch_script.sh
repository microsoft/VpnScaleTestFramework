#!/bin/bash
SOURCE_PATH=$1
NAME=$2
HASH=$3
rm -f ./$NAME && wget -q "$SOURCE_PATH/$NAME"
if [ $? -ne 0 ]; then
  echo Failed to fetch script from "$SOURCE_PATH/$NAME"
  exit 1
fi

if [ -n "$HASH" ]; then
  echo $HASH $NAME | sha512sum -c
  if [ $? -ne 0 ]; then
    rm -f ./$NAME
    exit 1
  fi
else
  echo WARNING: Hash not verified
fi

chmod +x ./$NAME 
if [ $? -ne 0 ]; then
  echo chmod failed
  rm -f ./$NAME
  exit 1
fi
