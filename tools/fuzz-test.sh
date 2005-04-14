#!/bin/bash
#
# $Id$

# This needs to point to a 'date' that supports %s.
DATE=/bin/date

# Where our temp files are saved (editcap.out and stderr.out)
TMP_DIR=/tmp

TETHEREAL_ARGS="-nVxr"

# These may be set to your liking
MAX_CPU_TIME=900
ERR_PROB=0.02

ulimit -S -t $MAX_CPU_TIME

echo "Running tethereal with args:" $TETHEREAL_ARGS
echo ""

# Iterate over our capture files.
PASS=0
while [ 1 ] ; do
    PASS=`expr $PASS + 1`
    echo "Pass $PASS:"

    for CF in "$@" ; do
	echo -n "    $CF: "
	DISSECTOR_BUG=0
	./editcap -E $ERR_PROB "$CF" $TMP_DIR/editcap.out
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

