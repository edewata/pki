#!/bin/bash

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

if [ "$NAME" == "" ]
then
    NAME=ds
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

max_wait=60 # seconds

echo "Creating DS container"
start_time=$(date +%s)

docker run \
    --detach \
    --name=$NAME \
    --hostname=$HOSTNAME \
    -e DS_DM_PASSWORD=$PASSWORD \
    quay.io/389ds/dirsrv > /dev/null

if [ $? -ne 0 ]
then
    exit 1
fi

while :
do
    sleep 1

    docker exec -i $NAME \
        ldapsearch \
        -H ldap://$HOSTNAME:3389 \
        -D "cn=Directory Manager" \
        -w $PASSWORD \
        -x \
        -b "" \
        -s base > /dev/null 2> /dev/null

    if [ $? -eq 0 ]
    then
        echo "DS container is running"
        break
    fi

    stop_time=$(date +%s)
    counter=$(expr $stop_time - $start_time)

    if [ $counter -ge $max_wait ]
    then
        echo "DS container did not start after ${max_wait}s"
        exit 1
    fi

    echo "Waiting for DS container to start (${counter}s)"
done

docker exec -i $NAME \
    dsconf localhost backend create \
        --suffix dc=example,dc=com \
        --be-name userRoot > /dev/null

docker exec -i $NAME \
    ldapadd \
    -H ldap://$HOSTNAME:3389 \
    -D "cn=Directory Manager" \
    -w $PASSWORD \
    -x > /dev/null << EOF
dn: dc=example,dc=com
objectClass: domain
dc: example

dn: dc=pki,dc=example,dc=com
objectClass: domain
dc: pki
EOF
