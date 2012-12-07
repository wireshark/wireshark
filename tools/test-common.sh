#!/bin/bash
#
# $Id$

# Common variables and functions for fuzz and randpkt tests.

# This needs to point to a 'date' that supports %s.
if [ -z "$TEST_TYPE" ] ; then
    echo "TEST_TYPE must be defined by the sourcing script."
    exit 1
fi

DATE=/bin/date
BASE_NAME=$TEST_TYPE-`$DATE +%Y-%m-%d`-$$

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

# Tweak the following to your liking.  Editcap must support "-E".
TSHARK="$BIN_DIR/tshark"
EDITCAP="$BIN_DIR/editcap"
CAPINFOS="$BIN_DIR/capinfos"
RANDPKT="$BIN_DIR/randpkt"

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
fi

# set some limits to the child processes, e.g. stop it if it's running longer then MAX_CPU_TIME seconds
# (ulimit is not supported well on cygwin and probably other platforms, e.g. cygwin shows some warnings)
ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM -s $MAX_STACK
ulimit -c unlimited


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

# Create an error report
function exit_error() {
    echo -e "\n ERROR"
    echo -e "Processing failed. Capture info follows:\n"
    echo "  Input file: $CF"

    # Fill in build information
    echo -e "Input file: $CF\n" > $TMP_DIR/${ERR_FILE}.header
    echo -e "Build host information:" >> $TMP_DIR/${ERR_FILE}.header
    uname -a >> $TMP_DIR/${ERR_FILE}.header
    lsb_release -a >> $TMP_DIR/${ERR_FILE}.header 2> /dev/null

    if [ -n "$BUILDBOT_BUILDERNAME" ] ; then
        echo -e "\nBuildbot information:" >> $TMP_DIR/${ERR_FILE}.header
        env | grep "^BUILDBOT_" >> $TMP_DIR/${ERR_FILE}.header
    fi

    echo -e "\n" >> $TMP_DIR/${ERR_FILE}.header

    if [ -d .svn ] ; then
        echo -e "\nSubversion revision" >> $TMP_DIR/${ERR_FILE}.header
        svn log -l 1 >> $TMP_DIR/${ERR_FILE}.header
    elif [ -d .git ] ; then
        echo -e "\nGit commit" >> $TMP_DIR/${ERR_FILE}.header
        git log -1 >> $TMP_DIR/${ERR_FILE}.header
    fi

    echo -e "\n" >> $TMP_DIR/${ERR_FILE}.header

    # Trim the stderr output if needed
    ERR_SIZE=$(du -sk $TMP_DIR/$ERR_FILE | awk '{ print $1 }')
    if [ $ERR_SIZE -ge 5000 ] ; then
        mv $TMP_DIR/$ERR_FILE $TMP_DIR/${ERR_FILE}.full
        head -n 2000 $TMP_DIR/${ERR_FILE}.full > $TMP_DIR/$ERR_FILE
        echo -e "\n\n[ Output removed ]\n\n" >> $TMP_DIR/$ERR_FILE
        tail -n 2000 $TMP_DIR/${ERR_FILE}.full >> $TMP_DIR/$ERR_FILE
        rm -f $TMP_DIR/${ERR_FILE}.full
    fi

    cat $TMP_DIR/${ERR_FILE} >> $TMP_DIR/${ERR_FILE}.header
    mv $TMP_DIR/${ERR_FILE}.header $TMP_DIR/${ERR_FILE}

    echo -e "stderr follows:\n"
    cat $TMP_DIR/$ERR_FILE

    exit 1
}
