#!/bin/bash -e

if [ "$NAME" == "" ]
then
    NAME=ds
fi

docker stop $NAME > /dev/null
docker rm $NAME > /dev/null

echo "DS container has been removed"
