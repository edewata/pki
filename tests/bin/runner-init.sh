#!/bin/bash -e
#
# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name>"
    echo
    echo "Options:"
    echo "    --image=<image>          Container image (default: pki-runner)"
    echo "    --hostname=<hostname>    Container hostname"
    echo "    --network=<network>      Container network"
    echo "    --network-alias=<alias>  Container network alias"
    echo "    --env=<variable>         Environment variable"
    echo "    --run-dir=<path>         Run directory"
    echo " -v,--verbose                Run in verbose mode."
    echo "    --debug                  Run in debug mode."
    echo "    --help                   Show help message."
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
        hostname=?*)
            HOSTNAME="$LONG_OPTARG"
            ;;
        network=?*)
            NETWORK="$LONG_OPTARG"
            ;;
        network-alias=?*)
            ALIASES+=("$LONG_OPTARG")
            ;;
        env=?*)
            ENVS+=("$LONG_OPTARG")
            ;;
        run-dir=?*)
            RUN_DIR+=("$LONG_OPTARG")
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
        image* | hostname* | network* | network-alias* | env*)
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

if [ "$NAME" = "" ]
then
    echo "ERROR: Missing container name"
    exit 1
fi

if [ "$IMAGE" = "" ]
then
    IMAGE=pki-runner
fi

if [ "$DEBUG" = true ] ; then
    echo "NAME: $NAME"
    echo "IMAGE: $IMAGE"
    echo "HOSTNAME: $HOSTNAME"
    echo "NETWORK: $NETWORK"
    echo "ALIASES: ${$ALIASES[@]}"
fi

mkdir -p run

OPTIONS=()
OPTIONS+=(--name $NAME)
OPTIONS+=(--hostname $HOSTNAME)
OPTIONS+=(--tmpfs /tmp)

if [ "$RUN_DIR" = "" ]
then
    OPTIONS+=(--tmpfs /run)
fi

OPTIONS+=(-v $GITHUB_WORKSPACE:$SHARED)

# required to run Podman in container
OPTIONS+=(-v /var/lib/containers:/var/lib/containers)

if [ "$RUN_DIR" != "" ]
then
    OPTIONS+=(-v $RUN_DIR:/run)
fi

OPTIONS+=(-e BUILDUSER_UID=$(id -u))
OPTIONS+=(-e BUILDUSER_GID=$(id -g))
OPTIONS+=(-e SHARED=$SHARED)
OPTIONS+=(-e BUILDUSER=builduser)
OPTIONS+=(-e GITHUB_ACTIONS=$GITHUB_ACTIONS)
OPTIONS+=(-e GITHUB_RUN_NUMBER=$GITHUB_RUN_NUMBER)
OPTIONS+=(-e container=docker)

for ENV in "${ENVS[@]}"
do
    OPTIONS+=(--env $ENV)
done

OPTIONS+=(--expose 22)
OPTIONS+=(--expose 389)
OPTIONS+=(--expose 8080)
OPTIONS+=(--expose 8443)
OPTIONS+=(--detach)
OPTIONS+=(--privileged)
OPTIONS+=(--cap-add AUDIT_WRITE)
OPTIONS+=(-i)

if [ "$NETWORK" != "" ]
then
    OPTIONS+=(--network $NETWORK)
fi

for ALIAS in "${ALIASES[@]}"
do
    OPTIONS+=(--network-alias $ALIAS)
done

docker run "${OPTIONS[@]}" $IMAGE "/usr/sbin/init"

# Pause 5 seconds to let the container start up.
# The container uses /usr/sbin/init as its entrypoint which requires few seconds
# to startup. This avoids the following error:
# [Errno 2] No such file or directory: '/var/cache/dnf/metadata_lock.pid'
sleep 5
