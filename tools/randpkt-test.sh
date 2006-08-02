#!/bin/bash
#
# $Id: randpkt-test.sh 18577 2006-06-26 19:49:27Z gerald $

# Randpkt testing script for TShark
#
# This script uses Randpkt to generate capture files with randomized
# content.  It runs TShark on each generated file and checks for errors.
# The files are processed repeatedly until an error is found.

# Tweak the following to your liking.
TSHARK=./tshark
RANDPKT=./randpkt

# This needs to point to a 'date' that supports %s.
DATE=/bin/date
BASE_NAME=rand-`$DATE +%Y-%m-%d`-$$

# Temporary file directory and names.
# (had problems with this on cygwin, tried TMP_DIR=./ which worked)
TMP_DIR=/tmp
TMP_FILE=$BASE_NAME.pcap
ERR_FILE=$BASE_NAME.err

# Loop this many times (< 1 loops forever)
MAX_PASSES=0

# These may be set to your liking
# Stop the child process, if it's running longer than x seconds
MAX_CPU_TIME=900
# Stop the child process, if it's using more than y * 1024 bytes
MAX_VMEM=500000
# Trigger an abort if a dissector finds a bug.
# Uncomment to disable
WIRESHARK_ABORT_ON_DISSECTOR_BUG="True"

PKT_TYPES=`$RANDPKT -h | awk '/^\t/ {print $1}'`

# To do: add options for file names and limits
while getopts ":d:p:t:" OPTCHAR ; do
    case $OPTCHAR in
        d) TMP_DIR=$OPTARG ;;
        p) MAX_PASSES=$OPTARG ;;
        t) PKT_TYPES=$OPTARG ;;
    esac
done
shift $(($OPTIND - 1))

# set some limits to the child processes, e.g. stop it if it's running longer then MAX_CPU_TIME seconds
# (ulimit is not supported well on cygwin and probably other platforms, e.g. cygwin shows some warnings)
ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM
ulimit -c unlimited

### usually you won't have to change anything below this line ###

# TShark arguments (you won't have to change these)
# n Disable network object name resolution
# V Print a view of the details of the packet rather than a one-line summary of the packet
# x Cause TShark to print a hex and ASCII dump of the packet data after printing the summary or details
# r Read packet data from the following infile
TSHARK_ARGS="-nVxr"
RANDPKT_ARGS="-b 2000 -c 5000"

NOTFOUND=0
for i in "$TSHARK" "$RANDPKT" "$DATE" "$TMP_DIR" ; do
    if [ ! -x $i ]; then
        echo "Couldn't find $i"
        NOTFOUND=1
    fi
done
if [ $NOTFOUND -eq 1 ]; then
    exit 1
fi

HOWMANY="forever"
if [ $MAX_PASSES -gt 0 ]; then
    HOWMANY="$MAX_PASSES passes"
fi
echo "Running $TSHARK with args: $TSHARK_ARGS ($HOWMANY)"
echo "Running $RANDPKT with args: $RANDPKT_ARGS"
echo ""

# Not yet - properly handle empty filenames
#trap "rm $TMP_DIR/$TMP_FILE $TMP_DIR/$RAND_FILE; exit 1" 1 2 15

# Iterate over our capture files.
PASS=0
while [ $PASS -lt $MAX_PASSES -o $MAX_PASSES -lt 1 ] ; do
    PASS=`expr $PASS + 1`
    echo "Pass $PASS:"

    for PKT_TYPE in $PKT_TYPES ; do
	echo -n "    $PKT_TYPE: "

	DISSECTOR_BUG=0

	"$RANDPKT" $RANDPKT_ARGS -t $PKT_TYPE $TMP_DIR/$TMP_FILE \
            > /dev/null 2>&1

	"$TSHARK" $TSHARK_ARGS $TMP_DIR/$TMP_FILE \
		> /dev/null 2> $TMP_DIR/$ERR_FILE
	RETVAL=$?
	grep -i "dissector bug" $TMP_DIR/$ERR_FILE \
	    > /dev/null 2>&1 && DISSECTOR_BUG=1
	if [ $RETVAL -ne 0 -o $DISSECTOR_BUG -ne 0 ] ; then
	    RAND_FILE="rand-`$DATE +%Y-%m-%d`-$$.pcap"
            echo ""
	    echo " ERROR"
	    echo -e "Processing failed.  Capture info follows:\n"
	    mv $TMP_DIR/$TMP_FILE $TMP_DIR/$RAND_FILE
	    echo "  Output file: $TMP_DIR/$RAND_FILE"
	    if [ $DISSECTOR_BUG -ne 0 ] ; then
		echo -e "stderr follows:\n"
		cat $TMP_DIR/$ERR_FILE
	    fi
	    exit 1
	fi
	echo " OK"
        rm -f $TMP_DIR/$TMP_FILE $TMP_DIR/$ERR_FILE
    done
done
