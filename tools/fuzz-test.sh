#!/bin/bash
#
# $Id$

# Fuzz-testing script for Tethereal
#
# This script uses Editcap to add random errors ("fuzz") to a set of
# capture files specified on the command line.  It runs Tethereal on
# each fuzzed file and checks for errors.  The files are processed
# repeatedly until an error is found.

# Tweak the following to your liking.  Editcap must support "-E".
TETHEREAL=./tethereal
EDITCAP=./editcap
CAPINFOS=./capinfos

# This needs to point to a 'date' that supports %s.
DATE=/bin/date

# Temporary file directory and names.
# (had problems with this on cygwin, tried TMP_DIR=./ which worked)
TMP_DIR=/tmp
TMP_FILE=fuzz-test.pcap
ERR_FILE=fuzz-err.txt

# These may be set to your liking
# Stop the child process, if it's running longer than x seconds
MAX_CPU_TIME=900
# Stop the child process, if it's using more than y * 1024 bytes
MAX_VMEM=500000
# Insert z times an error into the capture file (0.02 seems to be a good value to find errors)
ERR_PROB=0.02
# Trigger an abort if a dissector finds a bug.
# Uncomment to disable
ETHEREAL_ABORT_ON_DISSECTOR_BUG="True"

# set some limits to the child processes, e.g. stop it if it's running longer then MAX_CPU_TIME seconds
# (ulimit is not supported well on cygwin and probably other platforms, e.g. cygwin shows some warnings)
ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM
ulimit -c unlimited

### usually you won't have to change anything below this line ###

# Tethereal arguments (you won't have to change these)
# n Disable network object name resolution
# V Print a view of the details of the packet rather than a one-line summary of the packet
# x Cause Tethereal to print a hex and ASCII dump of the packet data after printing the summary or details
# r Read packet data from the following infile
TETHEREAL_ARGS="-nVxr"

NOTFOUND=0
for i in "$TETHEREAL" "$EDITCAP" "$CAPINFOS" "$DATE" "$TMP_DIR" ; do
	if [ ! -x $i ]; then
		echo "Couldn't find $i"
		NOTFOUND=1
	fi
done 
if [ $NOTFOUND -eq 1 ]; then
	exit 1
fi

# Make sure we have a valid test set
FOUND=0
for CF in "$@" ; do
    "$CAPINFOS" "$CF" > /dev/null 2>&1 && FOUND=1
    if [ $FOUND -eq 1 ] ; then break ; fi
done

if [ $FOUND -eq 0 ] ; then
    cat <<FIN
Error: No valid capture files found.

Usage: `basename $0` capture file 1 [capture file 2]...
FIN
    exit 1
fi

echo "Running $TETHEREAL with args: $TETHEREAL_ARGS"
echo ""

# Not yet - properly handle empty filenames
#trap "rm $TMP_DIR/$TMP_FILE $TMP_DIR/$FUZZ_FILE; exit 1" 1 2 15

# Iterate over our capture files.
PASS=0
while [ 1 ] ; do
    PASS=`expr $PASS + 1`
    echo "Pass $PASS:"

    for CF in "$@" ; do
	echo -n "    $CF: "

	"$CAPINFOS" "$CF" > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	    echo "Not a valid capture file"
	    continue
	fi

	DISSECTOR_BUG=0

	"$EDITCAP" -E $ERR_PROB "$CF" $TMP_DIR/$TMP_FILE > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	    "$EDITCAP" -E $ERR_PROB -T ether "$CF" $TMP_DIR/$TMP_FILE \
		> /dev/null 2>&1
	    if [ $? -ne 0 ] ; then
		echo "Invalid format for editcap"
		continue
	    fi
	fi

	"$TETHEREAL" $TETHEREAL_ARGS $TMP_DIR/$TMP_FILE \
		> /dev/null 2> $TMP_DIR/$ERR_FILE
	RETVAL=$?
	grep -i "dissector bug" $TMP_DIR/$ERR_FILE \
	    > /dev/null 2>&1 && DISSECTOR_BUG=1
	if [ $RETVAL -ne 0 -o $DISSECTOR_BUG -ne 0 ] ; then
	    FUZZ_FILE="fuzz-`$DATE +%Y-%m-%d`-$$.pcap"
	    echo " ERROR"
	    echo -e "Processing failed.  Capture info follows:\n"
	    mv $TMP_DIR/$TMP_FILE $TMP_DIR/$FUZZ_FILE
	    echo "  Output file: $TMP_DIR/$FUZZ_FILE"
	    if [ $DISSECTOR_BUG -ne 0 ] ; then
		echo -e "stderr follows:\n"
		cat $TMP_DIR/$ERR_FILE
	    fi
	    exit 1
	fi
	echo " OK"
    done
done

