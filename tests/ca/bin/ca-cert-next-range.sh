#!/bin/bash -e

NAME=$1

docker exec $NAME ldapsearch \
    -H ldap://$NAME.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=certs2,ou=ranges,dc=ca,dc=pki,dc=example,dc=com \
    -s base \
    -o ldif_wrap=no \
    -LLL \
    | grep nextRange:
