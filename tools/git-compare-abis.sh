#!/bin/bash

# $Id$

# check if Wireshark's ABI has been changes since last release (tag)
set -e

if test -z "$1"; then
	echo "Usage:"
	echo "$0 \"<build commands>\""
	echo "e.g. $0 \"./autogen.sh && ./configure && make -j3 && make dumpabi\""
	exit 1
fi

# build current version
bash -c "$1"

cd `git rev-parse --show-toplevel`
# we are at top level
LAST_TAG=`git describe --tags --abbrev=0`
rm -rf $LAST_TAG
mkdir $LAST_TAG
git archive $LAST_TAG | tar -x -C $LAST_TAG

# build latest tag
(cd $LAST_TAG && bash -c "$1")

exec tools/compare-abis.sh `pwd`/$LAST_TAG `pwd`

