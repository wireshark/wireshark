#!/bin/bash
#
# Compare ABIs of two Wireshark working copies
#
# Copyright 2013 Balint Reczey <balint at balintreczey.hu>
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

# Tested with abi-compliance-checker 1.96.1

function acc () {
	LIBNAME=$1
	DIR=$2
	# compare only dumped ABI descriptions first, then fall back to full comparison
	# if no difference is found
	if abi-compliance-checker -l $LIBNAME \
		-d1 $V1_PATH/$DIR/$REL_DUMP_PATH/$LIBNAME.abi.tar.gz \
		-d2 $V2_PATH/$DIR/$REL_DUMP_PATH/$LIBNAME.abi.tar.gz ; then
		abi-compliance-checker -l $LIBNAME \
			-d1 $V1_PATH/$DIR/abi-descriptor.xml -relpath1 $V1_PATH/$DIR \
			-v1 `ls  $V1_PATH/$DIR/$REL_LIB_PATH/$LIBNAME.so.?.*.*|sed 's/.*\.so\.//'` \
			-d2 $V2_PATH/$DIR/abi-descriptor.xml -relpath2 $V2_PATH/$DIR \
			-v2 `ls  $V2_PATH/$DIR/$REL_LIB_PATH/$LIBNAME.so.?.*.*|sed 's/.*\.so\.//'` \
			-check-implementation
	fi
}

V1_PATH=$1
V2_PATH=$2

# both working copies have to be built first with autotools or with cmake
# make -C $V1_PATH all dumpabi
# make -C $V2_PATH all dumpabi

if test -d $V1_PATH/lib; then
	REL_LIB_PATH=../lib
	REL_DUMP_PATH=.
else
	REL_LIB_PATH=.libs
	REL_DUMP_PATH=.libs
fi

acc libwiretap wiretap $V1_PATH $V2_PATH
RET=$?
acc libwsutil wsutil $V1_PATH $V2_PATH
RET=$(($RET + $?))
acc libwireshark epan $V1_PATH $V2_PATH
exit $(($RET + $?))

