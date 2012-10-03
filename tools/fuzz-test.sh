#!/bin/bash
#
# $Id$

# Fuzz-testing script for TShark
#
# This script uses Editcap to add random errors ("fuzz") to a set of
# capture files specified on the command line.  It runs TShark on
# each fuzzed file and checks for errors.  The files are processed
# repeatedly until an error is found.

# This needs to point to a 'date' that supports %s.
DATE=/bin/date
BASE_NAME=fuzz-`$DATE +%Y-%m-%d`-$$

# Directory containing binaries.  Default current directory.
BIN_DIR=.

# Temporary file directory and names.
# (had problems with this on cygwin, tried TMP_DIR=./ which worked)
TMP_DIR=/tmp
if [ "$OSTYPE" == "cygwin" ] ; then
        TMP_DIR=`cygpath --windows "$TMP_DIR"`
fi
TMP_FILE=$BASE_NAME.pcap
ERR_FILE=$BASE_NAME.err

# Loop this many times (< 1 loops forever)
MAX_PASSES=0

# Did we catch a signal?
DONE=0

# Perform a two pass analysis on the capture file?
TWO_PASS=

# Specific config profile ?
CONFIG_PROFILE=

# Run under valgrind ?
VALGRIND=0

# These may be set to your liking
# Stop the child process if it's running longer than x seconds
MAX_CPU_TIME=900
# Stop the child process if it's using more than y * 1024 bytes
MAX_VMEM=500000
# Stop the child process if its stack is larger than than z * 1024 bytes
# Windows XP:   2033
# Windows 7:    2034
# OS X 10.6:    8192
# Linux 2.6.24: 8192
# Solaris 10:   8192
MAX_STACK=2033
# Insert z times an error into the capture file (0.02 seems to be a good value to find errors)
ERR_PROB=0.02
# Trigger an abort if a dissector finds a bug.
# Uncomment to enable
# Note that if ABORT is enabled there will be no info
#  output to stderr about the DISSECTOR_BUG.
#  (There'll just be a core-dump).
###export WIRESHARK_ABORT_ON_DISSECTOR_BUG="True"


# To do: add options for file names and limits
while getopts ":2b:d:e:gC:p:" OPTCHAR ; do
    case $OPTCHAR in
        2) TWO_PASS="-2 " ;;
        b) BIN_DIR=$OPTARG ;;
        C) CONFIG_PROFILE="-C $OPTARG " ;;
        d) TMP_DIR=$OPTARG ;;
        e) ERR_PROB=$OPTARG ;;
        g) VALGRIND=1 ;;
        p) MAX_PASSES=$OPTARG ;;
    esac
done
shift $(($OPTIND - 1))

# Tweak the following to your liking.  Editcap must support "-E".
TSHARK="$BIN_DIR/tshark"
EDITCAP="$BIN_DIR/editcap"
CAPINFOS="$BIN_DIR/capinfos"

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
fi

# set some limits to the child processes, e.g. stop it if it's running longer then MAX_CPU_TIME seconds
# (ulimit is not supported well on cygwin and probably other platforms, e.g. cygwin shows some warnings)
ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM -s $MAX_STACK
ulimit -c unlimited

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

DISSECTOR_PLUGINS=`$TSHARK -G plugins | grep dissector | wc -l`
# 10 is an arbritary value.
if [ $DISSECTOR_PLUGINS -lt 10 ] ; then
    echo "Error: Found fewer plugins than expected."
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


##############################################################################
### Set up environment variables for fuzz testing			   ###
##############################################################################
# Initialize (ep_ and se_) allocated memory to 0xBADDCAFE and freed memory
# to 0xDEADBEEF
export WIRESHARK_DEBUG_SCRUB_MEMORY=
# Use canaries in se_ allocations (off by default due to the memory usage)
export WIRESHARK_DEBUG_SE_USE_CANARY=
# Verify that ep_ and se_ allocated memory is not passed to certain routines
# which need the memory to be persistent.
export WIRESHARK_EP_VERIFY_POINTERS=
export WIRESHARK_SE_VERIFY_POINTERS=

# Turn on GLib memory debugging (since 2.13)
export G_SLICE=debug-blocks
# Cause glibc (Linux) to abort() if some memory errors are found
export MALLOC_CHECK_=3
# Cause FreeBSD (and other BSDs) to abort() on allocator warnings and
# initialize allocated memory (to 0xa5) and freed memory (to 0x5a).  see:
# http://www.freebsd.org/cgi/man.cgi?query=malloc&apropos=0&sektion=0&manpath=FreeBSD+8.2-RELEASE&format=html
export MALLOC_OPTIONS=AJ

# MacOS options; see http://developer.apple.com/library/mac/releasenotes/DeveloperTools/RN-MallocOptions/_index.html
# Initialize allocated memory to 0xAA and freed memory to 0x55
export MallocPreScribble=1
export MallocScribble=1
# Add guard pages before and after large allocations
export MallocGuardEdges=1
# Call abort() if heap corruption is detected.  Heap is checked every 1000
# allocations (may need to be tuned!)
export MallocCheckHeapStart=1000
export MallocCheckHeapEach=1000
export MallocCheckHeapAbort=1
# Call abort() if an illegal free() call is made
export MallocBadFreeAbort=1

function exit_error() {
    echo -e "\n ERROR"
    echo -e "Processing failed. Capture info follows:\n"
    echo "  Input file: $CF"

    if [ -d .svn ] ; then
        echo -e "\nSubversion revision" >> $TMP_DIR/$ERR_FILE
        svn log -l 1 >> $TMP_DIR/$ERR_FILE
    elif [ -d .git ] ; then
        echo -e "\nGit commit" >> $TMP_DIR/$ERR_FILE
        git log -1 >> $TMP_DIR/$ERR_FILE
    fi

    echo -e "stderr follows:\n"
    cat $TMP_DIR/$ERR_FILE

    exit 1
}

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
