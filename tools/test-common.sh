#!/bin/bash
#
# Copyright 2013 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common variables and functions for fuzz and randpkt tests.

# This needs to point to a 'date' that supports %s.
if [ -z "$TEST_TYPE" ] ; then
    echo "TEST_TYPE must be defined by the sourcing script."
    exit 1
fi

DATE=/bin/date
BASE_NAME=$TEST_TYPE-$($DATE +%Y-%m-%d)-$$

# Directory containing binaries.  Default: cmake run directory.
if [ -z "$WIRESHARK_BIN_DIR" ]; then
    WIRESHARK_BIN_DIR=run
fi

# Temporary file directory and names.
# (had problems with this on cygwin, tried TMP_DIR=./ which worked)
TMP_DIR=/tmp
if [ "$OSTYPE" == "cygwin" ] ; then
        TMP_DIR=$(cygpath --windows "$TMP_DIR")
fi
TMP_FILE=$BASE_NAME.pcap
ERR_FILE=$BASE_NAME.err

# Loop this many times (< 1 loops forever)
MAX_PASSES=0

# These may be set to your liking
# Stop the child process if it's running longer than x seconds
MAX_CPU_TIME=600
# Stop the child process if it's using more than y * 1024 bytes
MAX_VMEM=1000000
# Stop the child process if its stack is larger than z * 1024 bytes
# Windows XP:    2033
# Windows 7:     2034
# Mac OS X 10.6: 8192
# Linux 2.6.24:  8192
# Solaris 10:    8192
MAX_STACK=2033
# Insert z times an error into the capture file (0.02 seems to be a good value to find errors)
ERR_PROB=0.02
# Maximum number of packets to fuzz
MAX_FUZZ_PACKETS=50000

# Call *after* any changes to WIRESHARK_BIN_DIR (e.g., via command-line options)
function ws_bind_exec_paths() {
# Tweak the following to your liking.  Editcap must support "-E".
TSHARK="$WIRESHARK_BIN_DIR/tshark"
EDITCAP="$WIRESHARK_BIN_DIR/editcap"
CAPINFOS="$WIRESHARK_BIN_DIR/capinfos"
RANDPKT="$WIRESHARK_BIN_DIR/randpkt"

if [ "$WIRESHARK_BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
fi
}

function ws_check_exec() {
NOTFOUND=0
for i in "$@" ; do
    if [ ! -x "$i" ]; then
        echo "Couldn't find \"$i\""
        NOTFOUND=1
    fi
done
if [ $NOTFOUND -eq 1 ]; then
    exit 1
fi
}

source "$(dirname "$0")"/debug-alloc.env

# Address Sanitizer options
export ASAN_OPTIONS=detect_leaks=0

# See if we were configured with gcc or clang's AddressSanitizer.
CONFIGURED_WITH_ASAN=0
# If tshark is built with ASAN this will generate an error. We could
# also pass help=1 and look for help text.
ASAN_OPTIONS=Invalid_Option_Flag $TSHARK -h > /dev/null 2>&1
if [ $? -ne 0 ] ; then
    CONFIGURED_WITH_ASAN=1
fi
export CONFIGURED_WITH_ASAN

# Create an error report
function ws_exit_error() {
    echo -e "\n ERROR"
    echo -e "Processing failed. Capture info follows:\n"
    echo "  Input file: $CF"
    echo "  Output file: $TMP_DIR/$TMP_FILE"
    echo "  Pass: $PASS"
    echo

    # Fill in build information
    {
        if [ -n "$CI_COMMIT_BRANCH" ] ; then
            printf "Branch: %s\\n" "$CI_COMMIT_BRANCH"
        else
            printf "Branch: %s\\n" "$(git rev-parse --abbrev-ref HEAD)"
        fi

        printf "Input file: %s\\n" "$CF"

        if [ -n "$CI_JOB_NAME" ] ; then
            printf "CI job name: %s, ID: %s\\n" "$CI_JOB_NAME" "$CI_JOB_ID"
            printf "CI job URL: %s\\n" "$CI_JOB_URL"
        fi

        printf "Return value: %s\\n" "$RETVAL"
        printf "Dissector bug: %s\\n" "$DISSECTOR_BUG"
        if [ "$VALGRIND" -eq 1 ] ; then
            printf "Valgrind error count: %s\\n" "$VG_ERR_CNT"
        fi

        printf "Date and time: %s\\n" "$( date --utc )"

        SINCE_HOURS=48
        if [ -d "${GIT_DIR:-.git}" ] ; then
                printf "\\nCommits in the last %s hours:\\n" $SINCE_HOURS
                git --no-pager log --oneline --no-decorate --since=${SINCE_HOURS}hours
                printf "\\n"
        fi

        printf "Build host information:\\n"
        uname -srvm
        lsb_release -a 2> /dev/null
        printf "\\n"

    } > "$TMP_DIR/${ERR_FILE}.header"

    # Trim the stderr output if needed
    ERR_SIZE=$(du -sk $TMP_DIR/$ERR_FILE | awk '{ print $1 }')
    if [ $ERR_SIZE -ge 5000 ] ; then
        mv $TMP_DIR/$ERR_FILE $TMP_DIR/${ERR_FILE}.full
        head -n 2000 $TMP_DIR/${ERR_FILE}.full > $TMP_DIR/$ERR_FILE
        echo -e "\n\n[ Output removed ]\n\n" >> $TMP_DIR/$ERR_FILE
        tail -n 2000 $TMP_DIR/${ERR_FILE}.full >> $TMP_DIR/$ERR_FILE
        rm -f $TMP_DIR/${ERR_FILE}.full
    fi

    cat $TMP_DIR/${ERR_FILE} >> $TMP_DIR/${ERR_FILE}.header
    mv $TMP_DIR/${ERR_FILE}.header $TMP_DIR/${ERR_FILE}

    echo -e "stderr follows:\n"
    cat $TMP_DIR/$ERR_FILE

    exit 255
}
