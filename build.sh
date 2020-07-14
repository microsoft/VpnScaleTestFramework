#!/bin/bash

# Save current working directory
PWD=`pwd`
pushd $PWD

cd agent
make
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to make agent."
    popd
    exit $EX
fi

cd ../controller

cd helpers
make
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to make helpers."
    popd
    exit $EX
fi

cd ..
dotnet restore
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to restore controller."
    popd
    exit $EX
fi
dotnet build 
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to build controller."
    popd
    exit $EX
fi
dotnet publish
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to publish controller."
    popd
    exit $EX
fi

docker build -t vpnscaletest_agent:latest .
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to make agent container."
    popd
    exit $EX
fi

docker build -t vpnscaletest_controller:latest .
EX=$?
if [ "$EX" -ne "0" ]; then
    echo "Failed to make agent container."
    popd
    exit $EX
fi
popd



