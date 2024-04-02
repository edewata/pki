#!/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name> <input>"
    echo
    echo "Options:"
    echo "    --image=<image>        Container image (default: pki-runner)"
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
}

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        image=?*)
            IMAGE="$LONG_OPTARG"
            ;;
        verbose)
            VERBOSE=true
            ;;
        debug)
            VERBOSE=true
            DEBUG=true
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        image*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

import_certs_into_server() {

    echo "Importing $INPUT into $NAME"

    docker cp $INPUT $NAME:certs.p12

    echo "Importing certs into NSS database in $NAME"

    docker exec $NAME pk12util \
        -d /etc/dirsrv/slapd-localhost \
        -k /etc/dirsrv/slapd-localhost/pwdfile.txt \
        -i certs.p12 \
        -W $PASSWORD

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

    docker cp $INPUT $NAME:/tmp/certs.p12

    echo "Fixing file ownership"

    docker exec -u 0 $NAME chown dirsrv.dirsrv /tmp/certs.p12

    echo "Exporting server cert into /data/tls/server.crt"

    docker exec $NAME openssl pkcs12 \
        -in /tmp/certs.p12 \
        -passin pass:$PASSWORD \
        -out /data/tls/server.crt \
        -clcerts \
        -nokeys

    echo "Exporting server key into /data/tls/server.key"

    docker exec $NAME openssl pkcs12 \
        -in /tmp/certs.p12 \
        -passin pass:$PASSWORD \
        -out /data/tls/server.key \
        -nodes \
        -nocerts

    echo "Exporting CA cert into /data/tls/ca/ca.crt"

    docker exec $NAME openssl pkcs12 \
        -in /tmp/certs.p12 \
        -passin pass:$PASSWORD \
        -out /data/tls/ca/ca.crt \
        -cacerts \
        -nokeys
}

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1
INPUT=$2

if [ "$NAME" == "" ]
then
    echo "ERROR: Missing container name"
    exit 1
fi

if [ "$INPUT" == "" ]
then
    echo "ERROR: Missing input file"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

if [ "$IMAGE" = "" ]
then
    IMAGE=pki-runner
fi

if [ "$IMAGE" == "pki-runner" ]
then
    import_certs_into_server
else
    import_certs_into_container
fi

echo "DS certs imported"
