#!/bin/bash -e

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-remove.sh <name>"
    exit 1
fi

echo "Stopping DS container"

docker stop $NAME > /dev/null

echo "Removing DS container"

docker rm $NAME > /dev/null

if [ "$DATA" == "" ]
then
    echo "Removing DS volume"
    DATA=$NAME-data
    docker volume rm $DATA > /dev/null
fi

echo "DS container has been removed"
