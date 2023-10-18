#!/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

LDAP_PORT=3389
LDAPS_PORT=3636

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name>"
    echo
    echo "Options:"
    echo "    --ldap-port=<port>     LDAP port (default: $LDAP_PORT)"
    echo "    --ldaps-port=<port>    LDAPS port (default: $LDAPS_PORT)"
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
    echo "Usage: ds-container-create.sh <name>"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    echo "Missing Directory Manager password"
    exit 1
fi

if [ "$IMAGE" == "" ]
then
    IMAGE=quay.io/389ds/dirsrv
fi

create_server() {

    echo "Creating DS server"

    $SCRIPT_DIR/runner-init.sh $NAME

    docker exec $NAME dnf install -y 389-ds-base

    docker exec $NAME dscreate create-template ds.inf

    docker exec $NAME sed -i \
        -e "s/;instance_name = .*/instance_name = localhost/g" \
        -e "s/;port = .*/port = $LDAP_PORT/g" \
        -e "s/;secure_port = .*/secure_port = $LDAPS_PORT/g" \
        -e "s/;root_password = .*/root_password = Secret.123/g" \
        -e "s/;suffix = .*/suffix = dc=example,dc=com/g" \
        -e "s/;self_sign_cert = .*/self_sign_cert = False/g" \
        ds.inf

    docker exec $NAME dscreate from-file ds.inf
}

create_container() {

    echo "Creating DS volume"

    docker volume create $NAME-data > /dev/null

    echo "Creating DS container"

    docker create \
        --name=$NAME \
        --hostname=$HOSTNAME \
        -v $NAME-data:/data \
        -v $GITHUB_WORKSPACE:$SHARED \
        -e DS_DM_PASSWORD=$PASSWORD \
        -p $LDAP_PORT \
        -p $LDAPS_PORT \
        $IMAGE > /dev/null

    $SCRIPT_DIR/ds-container-start.sh $NAME

    echo "Creating certs folder"

    docker exec $NAME mkdir -p /data/tls/ca

    echo "Creating database backend"

    docker exec $NAME dsconf localhost backend create \
        --suffix dc=example,dc=com \
        --be-name userRoot > /dev/null

    docker exec $NAME dsconf localhost backend suffix list
}

add_base_entries() {

    echo "Adding base entries"

    docker exec -i $NAME ldapadd \
        -H ldap://$HOSTNAME:$LDAP_PORT \
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
}

if [ "$IMAGE" == "pki-runner" ]
then
    create_server
else
    create_container
fi

add_base_entries

docker exec $NAME ldapsearch \
    -H ldap://$HOSTNAME:$LDAP_PORT \
    -D "cn=Directory Manager" \
    -w $PASSWORD \
    -x \
    -b "dc=example,dc=com"

echo "DS container is ready"
