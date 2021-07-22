#!/bin/bash -ex

SCRIPT_PATH=`readlink -f "$0"`
SCRIPT_NAME=`basename "$SCRIPT_PATH"`

BIN_DIR=`dirname "$SCRIPT_PATH"`
TOOLS_DIR=`dirname "$BIN_DIR"`
SRC_DIR=`dirname "$TOOLS_DIR"`

SPEC_TEMPLATE="$SRC_DIR/pki.spec"

PACKAGES="$(rpmspec -P "$SPEC_TEMPLATE" | grep "^Requires:" | awk '{print $2;}')"

echo microdnf install -y $PACKAGES
microdnf install -y $PACKAGES
