#!/bin/bash
#
# $Id$
#
# List the protocols (dissectors) used in capture file(s)
#
# This script extracts the protocol names contained in a given capture file.
# This is useful for generating a "database" (flat file :-)) of in what file
# a given protocol can be found.
#
# Output consists of the file name followed by the protocols, for example:
# /path/to/the/file.pcap eth ip sctp

# Directory containing binaries.  Default current directory.
BIN_DIR=_build

# Tweak the following to your liking.  Editcap must support "-E".
TSHARK="$BIN_DIR/tshark"
CAPINFOS="$BIN_DIR/capinfos"

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=
fi

NOTFOUND=0
for i in "$TSHARK" "$CAPINFOS"
do
    if [ ! -x $i ]
    then
        echo "Couldn't find $i"
        NOTFOUND=1
    fi
done
if [ $NOTFOUND -eq 1 ]
then
    exit 1
fi

# Make sure we have at least one file
FOUND=0
for CF in "$@"
do
    if [ "$OSTYPE" == "cygwin" ]
    then
        CF=`cygpath --windows "$CF"`
    fi
    "$CAPINFOS" "$CF" > /dev/null 2>&1 && FOUND=1
    if [ $FOUND -eq 1 ]
    then
	break
    fi
done

if [ $FOUND -eq 0 ] ; then
    cat <<FIN
Error: No valid capture files found.

Usage: `basename $0` capture file 1 [capture file 2]...
FIN
    exit 1
fi

for CF in "$@" ; do
    "$CAPINFOS" "$CF" > /dev/null
    if [ "$OSTYPE" == "cygwin" ] ; then
	CF=`cygpath --windows "$CF"`
    fi
    printf "$CF "

    # Extract the protocol names.
    $TSHARK -T fields -eframe.protocols -nr "$CF" 2>/dev/null | sed 's/:/\n/g' \
	| sort -u | tr '\n' ' '

    printf "\n"
done

