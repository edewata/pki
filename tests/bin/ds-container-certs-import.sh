#!/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-certs-import.sh <name> <input>"
    exit 1
fi

INPUT=$2

if [ "$INPUT" == "" ]
then
    echo "Usage: ds-container-certs-import.sh <name> <input>"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

import_certs_into_server() {

    echo "Importing DS certs into server"

    docker cp $INPUT $NAME:certs.p12
    docker exec $NAME pwd
    docker exec $NAME ls -la

    docker exec $NAME pk12util \
        -d /etc/dirsrv/slapd-localhost \
        -k /etc/dirsrv/slapd-localhost/pwdfile.txt \
        -i certs.p12 \
        -W Secret.123

    echo "Configuring trust flags"

    docker exec $NAME certutil -M \
        -d /etc/dirsrv/slapd-localhost \
        -f /etc/dirsrv/slapd-localhost/pwdfile.txt \
        -n Self-Signed-CA \
        -t CT,C,C

    echo "Enabling SSL connection"

    docker exec $NAME dsconf localhost config replace nsslapd-security=on
}

import_certs_into_container() {

    echo "Importing DS certs into container"

    ls -laR $DATA

    echo "Exporting server cert into $DATA/tls/server.crt"

    openssl pkcs12 \
        -in $INPUT \
        -passin pass:$PASSWORD \
        -out $DATA/tls/server.crt \
        -clcerts \
        -nokeys

    echo "Exporting server key into $DATA/tls/server.key"

    openssl pkcs12 \
        -in $INPUT \
        -passin pass:$PASSWORD \
        -out $DATA/tls/server.key \
        -nodes \
        -nocerts

    echo "Exporting CA cert into $DATA/tls/ca/ca.crt"

    openssl pkcs12 \
        -in $INPUT \
        -passin pass:$PASSWORD \
        -out $DATA/tls/ca/ca.crt \
        -cacerts \
        -nokeys
}

if [ "$IMAGE" == "pki-runner" ]
then
    import_certs_into_server
else
    import_certs_into_container
fi

echo "DS certs imported"
