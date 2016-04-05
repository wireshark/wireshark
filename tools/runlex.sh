#!/bin/sh

#
# runlex.sh
# Script to run Flex.
# First argument is the (quoted) name of the command; if it's null, that
# means that Flex wasn't found, so we report an error and quit.
# Second arg is the sed executable
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2007 Gerald Combs
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

#
# Get the name of the command to run, and then shift to get the arguments.
#
if [ $# -lt 2 ]
then
	echo "Usage: runlex <Flex command to run> <path to sed> [ arguments ]" 1>&2
	exit 1
fi

case "$OS" in

Windows*)
	PATH=$PATH:/bin
	LEX=`cygpath --unix $1`
	echo "$1 -> $LEX"
	;;

*)
	LEX="$1"
	;;
esac

shift
#
# Check whether we have Flex.
#
if [ -z "${LEX}" ]
then
	echo "Flex was not found" 1>&2
	exit 1
fi

SED="$1"
shift
#
# Check whether we have sed.
#
if [ -z "${SED}" ]
then
	echo "Sed was not found" 1>&2
	exit 1
fi

#
# Process the flags.  We don't use getopt because we don't want to
# embed complete knowledge of what options are supported by Flex.
#
flags=""
outfile=lex.yy.c
while [ $# -ne 0 ]
do
	case "$1" in

	-o*)
		#
		# Set the output file name.
		#
		outfile=`echo "$1" | ${SED} 's/-o\(.*\)/\1/'`
		;;

	-*)
		#
		# Add this to the list of flags.
		#
		flags="$flags $1"
		;;

	--|*)
		#
		# End of flags.
		#
		break
		;;
	esac
	shift
done

#
# We make Flex generate a header file declaring the relevant functions
# defined by the .c file, using the --header-file= flag; if the .c file
# is .../foo.c, the header file will be .../foo_lex.h.
#
#echo "Getting header file name"
header_file=`dirname "$outfile"`/`basename "$outfile" .c`_lex.h

#
# OK, run Flex.
#
#echo "Running ${LEX} -o\"$outfile\" --header-file=\"$header_file\" $flags \"$@\""
${LEX} -o"$outfile" --header-file="$header_file" $flags "$@"

#
# Did it succeed?
#
exitstatus=$?
if [ $exitstatus -ne 0 ]
then
	#
	# No.  Exit with the failing exit status.
	#
	echo "${LEX} failed: exit status $exitstatus"
	exit $exitstatus
fi

#
# Flex has the annoying habit of stripping all but the last component of
# the "-o" flag argument and using that as the place to put the output.
# This gets in the way of building in a directory different from the
# source directory.  Try to work around this.
#
# XXX - where is this an issue?
#
#
# Is the outfile where we think it is?
#
outfile_base=`basename "$outfile"`
if [ "$outfile_base" != "$outfile" -a \( ! -r "$outfile" \) -a -r "$outfile_base" ]
then
	#
	# No, it's not, but it is in the current directory.  Put it
	# where it's supposed to be.
	#
echo "Moving $outfile_base to $outfile"
	mv "$outfile_base" "$outfile"
	if [ $? -ne 0 ]
	then
		echo $?
	fi
fi

#
# Is the header file where we think it is?
#
header_file_base=`basename "$header_file"`
if [ "$header_file_base" != "$header_file" -a \( ! -r "$header_file" \) -a -r "$header_file_base" ]
then
	#
	# No, it's not, but it is in the current directory.  Put it
	# where it's supposed to be.
	#
echo "Moving $header_file_base to $header_file"
	mv "$header_file_base" "$header_file"
	if [ $? -ne 0 ]
	then
		echo $?
	fi
fi

echo "Wrote $outfile and $header_file"
