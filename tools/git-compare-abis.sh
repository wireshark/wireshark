#!/bin/bash

# $Id$

# check if Wireshark's ABI has been changes since last release (tag)
set -e

CORE_COUNT=4
if [ -r /proc/cpuinfo ] ; then
	CORE_COUNT=`grep -c ^processor /proc/cpuinfo`
elif sysctl hw.ncpu > /dev/null 2>&1 ; then
        CORE_COUNT=`sysctl -n hw.ncpu`
fi

BUILD_COMMAND="$1"

if [ -z "$BUILD_COMMAND" ]; then
	BUILD_COMMAND="./autogen.sh && ./configure && make -j$CORE_COUNT && make dumpabi"
	echo "No build command provided. Using"
	echo "    $BUILD_COMMAND"
fi

# build current version
bash -c "$1"

cd `git rev-parse --show-toplevel`
# we are at top level

# Stable branches with releases
LAST_TAG=`git describe --tags --abbrev=0`
LAST_TAG_DIR=$LAST_TAG

# Unstable branches, e.g. master don't have usable tags. Use a commit instead.
# git rev-list --first-parent --max-count=1 master-1.10
#LAST_TAG=75d3bda29c72f9673fa08dcc53159833b95a7dcc
#LAST_TAG_DIR=master-1.10

rm -rf $LAST_TAG_DIR
mkdir $LAST_TAG_DIR
git archive $LAST_TAG | tar -x -C $LAST_TAG_DIR

# build latest tag
(cd $LAST_TAG_DIR && bash -c "$BUILD_COMMAND")

exec tools/compare-abis.sh `pwd`/$LAST_TAG_DIR `pwd`
