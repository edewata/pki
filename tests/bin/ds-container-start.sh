#!/bin/bash

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

LDAP_PORT=3389
LDAPS_PORT=

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name>"
    echo
    echo "Options:"
    echo "    --ldap-port=<port>     LDAP port (default: $LDAP_PORT)"
    echo "    --ldaps-port=<port>    LDAPS port"
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
        ldap-port=?*)
            LDAP_PORT="$LONG_OPTARG"
            ;;
        ldaps-port=?*)
            LDAPS_PORT="$LONG_OPTARG"
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
        ldap-port* | ldaps-port*)
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

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-start.sh <name>"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

if [ "$MAX_WAIT" == "" ]
then
    MAX_WAIT=60 # seconds
fi

echo "Starting DS container"
start_time=$(date +%s)

if [ "$IMAGE" == "" ]
then
    docker exec $NAME dsctl localhost start
else
    docker start $NAME > /dev/null
fi

if [ $? -ne 0 ]
then
    exit 1
fi

HOSTNAME=$(docker exec $NAME uname -n)

if [ "$LDAPS_PORT" == "" ]
then
    LDAP_URL=ldap://$HOSTNAME:$LDAP_PORT
else
    LDAP_URL=ldaps://$HOSTNAME:$LDAPS_PORT
fi

while :
do
    sleep 1

    docker exec $NAME \
        ldapsearch \
        -H $LDAP_URL \
        -D "cn=Directory Manager" \
        -w $PASSWORD \
        -x \
        -b "" \
        -s base > /dev/null 2> /dev/null

    if [ $? -eq 0 ]
    then
        break
    fi

    current_time=$(date +%s)
    elapsed_time=$(expr $current_time - $start_time)

    if [ $elapsed_time -ge $MAX_WAIT ]
    then
        echo "DS container did not start after ${MAX_WAIT}s"
        exit 1
    fi

    echo "Waiting for DS container to start (${elapsed_time}s)"
done

echo "DS container is started"
