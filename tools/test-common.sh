#!/bin/bash
#
# Copyright 2013 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
MAX_CPU_TIME=300
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

# Call *after* any changes to BIN_DIR (e.g., via command-line options)
function ws_bind_exec_paths() {
# Tweak the following to your liking.  Editcap must support "-E".
TSHARK="$BIN_DIR/tshark"
EDITCAP="$BIN_DIR/editcap"
CAPINFOS="$BIN_DIR/capinfos"
RANDPKT="$BIN_DIR/randpkt"

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
fi
}

function ws_check_exec() {
NOTFOUND=0
for i in "$@" ; do
    if [ ! -x "$i" ]; then
        echo "Couldn't find \"$i\""
        NOTFOUND=1
    fi
done
if [ $NOTFOUND -eq 1 ]; then
    exit 1
fi
}

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
# Use the Wmem strict allocator which does canaries and scrubbing etc.
export WIRESHARK_DEBUG_WMEM_OVERRIDE=strict
# Abort if a dissector adds too many items to the tree
export WIRESHARK_ABORT_ON_TOO_MANY_ITEMS=

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
function ws_exit_error() {
    echo -e "\n ERROR"
    echo -e "Processing failed. Capture info follows:\n"
    echo "  Input file: $CF"
    echo "  Output file: $TMP_DIR/$TMP_FILE"
    echo

    # Fill in build information
    echo -e "Input file: $CF\n" > $TMP_DIR/${ERR_FILE}.header
    echo -e "Build host information:" >> $TMP_DIR/${ERR_FILE}.header
    uname -a >> $TMP_DIR/${ERR_FILE}.header
    lsb_release -a >> $TMP_DIR/${ERR_FILE}.header 2> /dev/null

    if [ -n "$BUILDBOT_BUILDERNAME" ] ; then
        echo -e "\nBuildbot information:" >> $TMP_DIR/${ERR_FILE}.header
        env | grep "^BUILDBOT_" >> $TMP_DIR/${ERR_FILE}.header
    fi

    echo -e "\nReturn value: " $RETVAL >> $TMP_DIR/${ERR_FILE}.header
    echo -e "\nDissector bug: " $DISSECTOR_BUG >> $TMP_DIR/${ERR_FILE}.header
    echo -e "\nValgrind error count: " $VG_ERR_CNT >> $TMP_DIR/${ERR_FILE}.header

    echo -e "\n" >> $TMP_DIR/${ERR_FILE}.header

    if [ -d ${GIT_DIR:-.git} ] ; then
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

    exit 255
}
