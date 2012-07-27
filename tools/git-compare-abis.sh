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

# Stable branches with releases
#LAST_TAG=`git describe --tags --abbrev=0`
#LAST_TAG_DIR=$LAST_TAG

# Use latest commit
LAST_TAG=HEAD
LAST_TAG_DIR=master

rm -rf $LAST_TAG_DIR
mkdir $LAST_TAG_DIR
git archive $LAST_TAG | tar -x -C $LAST_TAG_DIR

# build latest tag
(cd $LAST_TAG_DIR && bash -c "$1")

exec tools/compare-abis.sh `pwd`/$LAST_TAG_DIR `pwd`

