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

./tshark -nVxr $1 > /dev/null
