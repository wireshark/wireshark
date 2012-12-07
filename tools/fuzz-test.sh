#!/bin/bash
#
# $Id$

# Fuzz-testing script for TShark
#
# This script uses Editcap to add random errors ("fuzz") to a set of
# capture files specified on the command line.  It runs TShark on
# each fuzzed file and checks for errors.  The files are processed
# repeatedly until an error is found.

TEST_TYPE="fuzz"
. `dirname $0`/test-common.sh

# Directory containing binaries.  Default current directory.
BIN_DIR=.

# Sanity check to make sure we can find our plugins. Zero or less disables.
MIN_PLUGINS=0

# Did we catch a signal?
DONE=0

# Perform a two pass analysis on the capture file?
TWO_PASS=

# Specific config profile ?
CONFIG_PROFILE=

# Run under valgrind ?
VALGRIND=0


# To do: add options for file names and limits
while getopts ":2b:C:d:e:gp:P:" OPTCHAR ; do
    case $OPTCHAR in
        2) TWO_PASS="-2 " ;;
        b) BIN_DIR=$OPTARG ;;
        C) CONFIG_PROFILE="-C $OPTARG " ;;
        d) TMP_DIR=$OPTARG ;;
        e) ERR_PROB=$OPTARG ;;
        g) VALGRIND=1 ;;
        p) MAX_PASSES=$OPTARG ;;
        P) MIN_PLUGINS=$OPTARG ;;
    esac
done
shift $(($OPTIND - 1))

### usually you won't have to change anything below this line ###

if [ $VALGRIND -eq 1 ]; then
    RUNNER="$BIN_DIR/tools/valgrind-wireshark.sh"
    declare -a RUNNER_ARGS=("${CONFIG_PROFILE}${TWO_PASS}")
else
    # Not using valgrind, use regular tshark.
    # TShark arguments (you won't have to change these)
    # n Disable network object name resolution
    # V Print a view of the details of the packet rather than a one-line summary of the packet
    # x Cause TShark to print a hex and ASCII dump of the packet data after printing the summary or details
    # r Read packet data from the following infile
    RUNNER="$TSHARK"
    declare -a RUNNER_ARGS=("${CONFIG_PROFILE}${TWO_PASS}-nVxr" "${CONFIG_PROFILE}${TWO_PASS}-nr")
fi


NOTFOUND=0
for i in "$TSHARK" "$EDITCAP" "$CAPINFOS" "$DATE" "$TMP_DIR" ; do
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
    if [ "$OSTYPE" == "cygwin" ] ; then
        CF=`cygpath --windows "$CF"`
    fi
    "$CAPINFOS" "$CF" > /dev/null 2>&1 && FOUND=1
    if [ $FOUND -eq 1 ] ; then break ; fi
done

if [ $FOUND -eq 0 ] ; then
    cat <<FIN
Error: No valid capture files found.

Usage: `basename $0` [-2] [-b bin_dir] [-C config_profile] [-d work_dir] [-e error probability] [-g] [-p passes] capture file 1 [capture file 2]...
FIN
    exit 1
fi

PLUGIN_COUNT=`$TSHARK -G plugins | grep dissector | wc -l`
if [ $MIN_PLUGINS -gt 0 -a $PLUGIN_COUNT -lt $MIN_PLUGINS ] ; then
    echo "Warning: Found fewer plugins than expected ($PLUGIN_COUNT vs $MIN_PLUGINS)."
    exit 1
fi

HOWMANY="forever"
if [ $MAX_PASSES -gt 0 ]; then
        HOWMANY="$MAX_PASSES passes"
fi
echo -n "Running $RUNNER with args: "
printf "\"%s\" " "${RUNNER_ARGS[@]}"
echo "($HOWMANY)"
echo ""

# Clean up on <ctrl>C, etc
trap "DONE=1; echo 'Caught signal'" HUP INT TERM


# Iterate over our capture files.
PASS=0
while [ \( $PASS -lt $MAX_PASSES -o $MAX_PASSES -lt 1 \) -a $DONE -ne 1 ] ; do
    let PASS=$PASS+1
    echo "Starting pass $PASS:"
    RUN=0

    for CF in "$@" ; do
	if [ $DONE -eq 1 ]; then
	    break # We caught a signal
	fi
        RUN=$(( $RUN + 1 ))
        if [ $(( $RUN % 50 )) -eq 0 ] ; then
            echo "    [Pass $PASS]"
        fi
        if [ "$OSTYPE" == "cygwin" ] ; then
            CF=`cygpath --windows "$CF"`
        fi
	echo -n "    $CF: "

	"$CAPINFOS" "$CF" > /dev/null 2> $TMP_DIR/$ERR_FILE
	RETVAL=$?
	if [ $RETVAL -eq 1 ] ; then
	    echo "Not a valid capture file"
	    rm -f $TMP_DIR/$ERR_FILE
	    continue
	elif [ $RETVAL -ne 0 -a $DONE -ne 1 ] ; then
	    # Some other error
	    exit_error
	fi

	DISSECTOR_BUG=0
	VG_ERR_CNT=0

	"$EDITCAP" -E $ERR_PROB "$CF" $TMP_DIR/$TMP_FILE > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	    "$EDITCAP" -E $ERR_PROB -T ether "$CF" $TMP_DIR/$TMP_FILE \
	    > /dev/null 2>&1
	    if [ $? -ne 0 ] ; then
	    echo "Invalid format for editcap"
	    continue
	    fi
	fi

	for ARGS in "${RUNNER_ARGS[@]}" ; do
	    echo -n "($ARGS) "
	    echo -e "Command and args: $RUNNER $ARGS\n" > $TMP_DIR/$ERR_FILE
	    "$RUNNER" $ARGS $TMP_DIR/$TMP_FILE \
		> /dev/null 2>> $TMP_DIR/$ERR_FILE
	    RETVAL=$?
	    if [ $RETVAL -ne 0 ] ; then break ; fi
	done

	# Uncomment the next two lines to enable dissector bug
	# checking.
	#grep -i "dissector bug" $TMP_DIR/$ERR_FILE \
	#    > /dev/null 2>&1 && DISSECTOR_BUG=1

	if [ $VALGRIND -eq 1 ]; then
	    VG_ERR_CNT="`grep "ERROR SUMMARY:" $TMP_DIR/$ERR_FILE | cut -f4 -d' '`"
	    if grep -q "Valgrind cannot continue" $TMP_DIR/$ERR_FILE; then
		    VG_ERR_CNT=-1
	    fi
	fi

	if [ \( $RETVAL -ne 0 -o $DISSECTOR_BUG -ne 0 -o $VG_ERR_CNT -ne 0 \) \
	    -a $DONE -ne 1 ] ; then

	    exit_error
	fi

	echo " OK"
	rm -f $TMP_DIR/$TMP_FILE $TMP_DIR/$ERR_FILE
    done
done
