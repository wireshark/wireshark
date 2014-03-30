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

TEST_TYPE="manual"
. `dirname $0`/test-common.sh || exit 1

while getopts ":b:" OPTCHAR ; do
    case $OPTCHAR in
        b) BIN_DIR=$OPTARG ;;
    esac
done
shift $(($OPTIND - 1))

if [ $# -lt 1 ]
then
	printf "Usage: $(basename $0) [-b bin_dir] /path/to/file[s].pcap\n"
	exit 1
fi

ws_bind_exec_paths
ws_check_exec "$TSHARK"

# set some limits to the child processes, e.g. stop it if it's running longer then MAX_CPU_TIME seconds
# (ulimit is not supported well on cygwin and probably other platforms, e.g. cygwin shows some warnings)
ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM
# Allow core files to be generated
ulimit -c unlimited

for file in "$@"
do
	echo "Testing file $file..."
	echo -n " - with tree... "
	if $TSHARK -nVxr $file > /dev/null
	then
		echo "OK"
		echo -n " - without tree... "
		if $BIN_DIR/tshark -nr $file > /dev/null
		then
			echo "OK"
			echo -n " - without tree but with a read filter... "
			if $BIN_DIR/tshark -Yframe -nr $file > /dev/null
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
