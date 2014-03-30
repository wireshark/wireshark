#!/bin/bash

# Randpkt testing script for TShark
#
# This script uses Randpkt to generate capture files with randomized
# content.  It runs TShark on each generated file and checks for errors.
# The files are processed repeatedly until an error is found.

TEST_TYPE="randpkt"
. `dirname $0`/test-common.sh || exit 1

# Trigger an abort if a dissector finds a bug.
# Uncomment to disable
WIRESHARK_ABORT_ON_DISSECTOR_BUG="True"

# To do: add options for file names and limits
while getopts ":b:d:p:t:" OPTCHAR ; do
    case $OPTCHAR in
        b) BIN_DIR=$OPTARG ;;
        d) TMP_DIR=$OPTARG ;;
        p) MAX_PASSES=$OPTARG ;;
        t) PKT_TYPES=$OPTARG ;;
    esac
done
shift $(($OPTIND - 1))

### usually you won't have to change anything below this line ###

ws_bind_exec_paths
ws_check_exec "$TSHARK" "$RANDPKT" "$DATE" "$TMP_DIR"

[[ -z "$PKT_TYPES" ]] && PKT_TYPES=$($RANDPKT -h | awk '/^\t/ {print $1}')

# TShark arguments (you won't have to change these)
# n Disable network object name resolution
# V Print a view of the details of the packet rather than a one-line summary of the packet
# x Cause TShark to print a hex and ASCII dump of the packet data after printing the summary or details
# r Read packet data from the following infile
declare -a TSHARK_ARGS=("-nVxr" "-nr")
RANDPKT_ARGS="-b 2000 -c 5000"

HOWMANY="forever"
if [ $MAX_PASSES -gt 0 ]; then
    HOWMANY="$MAX_PASSES passes"
fi
echo -n "Running $TSHARK with args: "
printf "\"%s\" " "${TSHARK_ARGS[@]}"
echo "($HOWMANY)"
echo "Running $RANDPKT with args: $RANDPKT_ARGS"
echo ""

trap "MAX_PASSES=1; echo 'Caught signal'" HUP INT TERM


# Iterate over our capture files.
PASS=0
while [ $PASS -lt $MAX_PASSES -o $MAX_PASSES -lt 1 ] ; do
    let PASS=$PASS+1
    echo "Pass $PASS:"

    for PKT_TYPE in $PKT_TYPES ; do
        if [ $PASS -gt $MAX_PASSES -a $MAX_PASSES -ge 1 ] ; then
            break # We caught a signal
        fi
        echo -n "    $PKT_TYPE: "

        DISSECTOR_BUG=0

        "$RANDPKT" $RANDPKT_ARGS -t $PKT_TYPE $TMP_DIR/$TMP_FILE \
            > /dev/null 2>&1

	for ARGS in "${TSHARK_ARGS[@]}" ; do
            echo -n "($ARGS) "
	    echo -e "Command and args: $TSHARK $ARGS\n" > $TMP_DIR/$ERR_FILE

            # Run in a child process with limits, e.g. stop it if it's running
            # longer then MAX_CPU_TIME seconds. (ulimit may not be supported
            # well on some platforms, particularly cygwin.)
            (
                ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM -s $MAX_STACK
                ulimit -c unlimited
                "$TSHARK" $ARGS $TMP_DIR/$TMP_FILE \
                    > /dev/null 2>> $TMP_DIR/$ERR_FILE
            )
            RETVAL=$?
	    if [ $RETVAL -ne 0 ] ; then break ; fi
        done
        grep -i "dissector bug" $TMP_DIR/$ERR_FILE \
            > /dev/null 2>&1 && DISSECTOR_BUG=1

        if [ $RETVAL -ne 0 -o $DISSECTOR_BUG -ne 0 ] ; then

            ws_exit_error
        fi
        echo " OK"
        rm -f $TMP_DIR/$TMP_FILE $TMP_DIR/$ERR_FILE
    done
done
