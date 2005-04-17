#!/bin/bash
#
# $Id$

# Fuzz-testing script for Tethereal
#
# This script uses Editcap to add random errors ("fuzz") to a set of
# capture files specified on the command line.  It runs Tethereal on
# each fuzzed file and checks for errors.  The files are processed
# repeatedly until an error is found.

# This needs to point to a 'date' that supports %s.
DATE=/bin/date

# Where our temp files are saved (editcap.out and stderr.out)
TMP_DIR=/tmp

TETHEREAL_ARGS="-nVxr"

# These may be set to your liking
MAX_CPU_TIME=900
ERR_PROB=0.02

ulimit -S -t $MAX_CPU_TIME

# Make sure we have a valid test set
FOUND=0
for CF in "$@" ; do
    ./capinfos $CF > /dev/null 2>&1 && FOUND=1
done

if [ $FOUND -eq 0 ] ; then
    cat <<FIN
Error: No valid capture files found.

Usage: `basename $0` capture file 1 [capture file 2]...
FIN
    exit 1
fi

echo "Running tethereal with args:" $TETHEREAL_ARGS
echo ""

# Iterate over our capture files.
PASS=0
while [ 1 ] ; do
    PASS=`expr $PASS + 1`
    echo "Pass $PASS:"

    for CF in "$@" ; do
	echo -n "    $CF: "

	./capinfos $CF > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	    echo "Not a valid capture file"
	    continue
	fi

	DISSECTOR_BUG=0

	./editcap -E $ERR_PROB "$CF" $TMP_DIR/editcap.out > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	    echo "Invalid format for editcap"
	    continue
	fi

	./tethereal -nxVr $TMP_DIR/editcap.out \
		> /dev/null 2> $TMP_DIR/stderr.out
	RETVAL=$?
	grep -i "dissector bug" $TMP_DIR/stderr.out \
	    > /dev/null 2>&1 && DISSECTOR_BUG=1
	if [ $RETVAL -ne 0 -o $DISSECTOR_BUG -ne 0 ] ; then
	    SUF=`$DATE +%s`
	    echo " ERROR"
	    echo -e "Processing failed.  Capture info follows:\n"
	    mv $TMP_DIR/editcap.out $TMP_DIR/editcap.out.$SUF
	    echo "  Output file: $TMP_DIR/editcap.out.$SUF"
	    if [ $DISSECTOR_BUG -ne 0 ] ; then
		echo -e "stderr follows:\n"
		cat $TMP_DIR/stderr.out
	    fi
	    exit 1
	fi
	echo " OK"
    done
done

