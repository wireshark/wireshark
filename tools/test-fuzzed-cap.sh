#!/bin/bash
#
# $Id$

# A little script to run tshark on a capture file that failed fuzz testing.
# Useful because it sets up ulimits for you.  (I'm writing this after having
# my machine hang up for like 15 minutes because I wasn't paying attention
# while tshark was running on a fuzzed capture and it used all my RAM +
# swap--which was pretty painful.)

if [ $# -ne 1 ]
then
	printf "Usage: $0 /path/to/file.pcap\n"
	exit 1
fi

# Directory containing tshark.  Default current directory.
BIN_DIR=.

# These may be set to your liking
# Stop the child process, if it's running longer than x seconds
MAX_CPU_TIME=900
# Stop the child process, if it's using more than y * 1024 bytes
MAX_VMEM=500000

# set some limits to the child processes, e.g. stop it if it's running longer then MAX_CPU_TIME seconds
# (ulimit is not supported well on cygwin and probably other platforms, e.g. cygwin shows some warnings)
ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM
# Allow core files to be generated
ulimit -c unlimited

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=
fi

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

# abort instead of giving a nice error message
export WIRESHARK_ABORT_ON_OUT_OF_MEMORY=

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
# Call abort() on dissector bugs to make it easier to get a stack trace
export WIRESHARK_ABORT_ON_DISSECTOR_BUG=

$BIN_DIR/tshark -nVxr $1 > /dev/null
