#!/bin/bash

# A little script to run tshark on capture file[s] (potentially ones that
# failed fuzz testing). Useful because it sets up ulimits and other environment
# variables for you to ensure things like misused ephemeral memory are caught.
# (I'm writing this after having my machine hang up for like 15 minutes because
# I wasn't paying attention while tshark was running on a fuzzed capture and
# it used all my RAM + swap--which was pretty painful.)
#
# Copyright 2012 Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

TEST_TYPE="manual"
# shellcheck source=tools/test-common.sh
. "$( dirname "$0" )"/test-common.sh || exit 1

# Run under AddressSanitizer ?
ASAN=$CONFIGURED_WITH_ASAN

while getopts "ab:" OPTCHAR ; do
    case $OPTCHAR in
        a) ASAN=1 ;;
        b) WIRESHARK_BIN_DIR=$OPTARG ;;
        *) printf "Unknown option: %s\\n" "$OPTARG"
    esac
done
shift $(( OPTIND - 1 ))

if [ $# -lt 1 ]
then
	printf "Usage: %s [-b bin_dir] /path/to/file[s].pcap\\n" "$( basename "$0" )"
	exit 1
fi

ws_bind_exec_paths
ws_check_exec "$TSHARK"

# Set some limits to the child processes, e.g. stop it if it's running
# longer than MAX_CPU_TIME seconds. (ulimit is not supported well on
# cygwin - it shows some warnings - and the features we use may not all
# be supported on some UN*X platforms.)
ulimit -S -t $MAX_CPU_TIME

# Allow core files to be generated
ulimit -c unlimited

# Don't enable ulimit -v when using ASAN. See
# https://github.com/google/sanitizers/wiki/AddressSanitizer#ulimit--v
if [ $ASAN -eq 0 ]; then
	ulimit -S -v $MAX_VMEM
fi

for file in "$@"
do
	echo "Testing file $file..."
	echo -n " - with tree... "
	if $TSHARK -nVxr "$file" > /dev/null
	then
		echo "OK"
		echo -n " - without tree... "
		if "$WIRESHARK_BIN_DIR/tshark" -nr "$file" > /dev/null
		then
			echo "OK"
			echo -n " - without tree but with a read filter... "
			if "$WIRESHARK_BIN_DIR/tshark" -Yframe -nr "$file" > /dev/null
			then
				echo "OK"
			else
				echo "Failed"
				exit 1
			fi
		else
			echo "Failed"
			exit 1
		fi
	else
		echo "Failed"
		exit 1
	fi
done
