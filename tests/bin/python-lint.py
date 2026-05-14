#! /bin/bash -e

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")

BIN_DIR=$(dirname "$SCRIPT_PATH")
TESTS_DIR=$(dirname "$BIN_DIR")
SRC_DIR=$(dirname "$TESTS_DIR")

RC_FILE="$TESTS_DIR/pylintrc"

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS]"
    echo
    echo "Options:"
    echo "    --rcfile=<path>        pylint configuration (default: $RC_FILE)"
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
}

while getopts v-: arg ; do
    case $arg in
    v)
        set -x
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        rcfile=?*)
            RC_FILE="$LONG_OPTARG"
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        rcfile*)
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

SOURCES=$(find $SRC_DIR/base/common/python/pki -name "*.py")
SOURCES="$SOURCES $(find $SRC_DIR/base/common/upgrade -name "*.py")"
SOURCES="$SOURCES $(find $SRC_DIR/base/server/python/pki/server -name "*.py")"
SOURCES="$SOURCES $(find $SRC_DIR/base/server/upgrade -name "*.py")"

pylint-3 \
    --rcfile=${RC_FILE} \
    $SOURCES
