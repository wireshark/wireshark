#!/bin/bash
#
# $Id$

# 32-bit wrapper for win-setup.sh.

export DOWNLOAD_TAG="2012-09-13"
export WIRESHARK_TARGET_PLATFORM="win32"

WIN_SETUP=`echo $0 | sed -e s/win32/win/`

exec $WIN_SETUP $@
