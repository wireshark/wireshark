#!/bin/bash
#
# Fuzz-testing script for TShark
#
# This script uses Editcap to add random errors ("fuzz") to a set of
# capture files specified on the command line.  It runs TShark on
# each fuzzed file and checks for errors.  The files are processed
# repeatedly until an error is found.
#
# Copyright 2013 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

TEST_TYPE="fuzz"
# shellcheck source=tools/test-common.sh
. "$( dirname "$0" )"/test-common.sh || exit 1

# Sanity check to make sure we can find our plugins. Zero or less disables.
MIN_PLUGINS=0

# Did we catch a signal or time out?
DONE=false

# Currently running children
RUNNER_PIDS=

# Perform a two-pass analysis on the capture file?
TWO_PASS=

# Specific config profile ?
CONFIG_PROFILE=

# Run under valgrind ?
VALGRIND=0

# Run under AddressSanitizer ?
ASAN=$CONFIGURED_WITH_ASAN

# Don't skip any byte from being changed
CHANGE_OFFSET=0

# The maximum permitted amount of memory leaked. Eventually this should be
# worked down to zero, but right now that would fail on every single capture.
# Only has effect when running under valgrind.
MAX_LEAK=$(( 1024 * 100 ))

# Our maximum run time.
RUN_START_SECONDS=$SECONDS
RUN_MAX_SECONDS=$(( RUN_START_SECONDS + 86400 ))

# To do: add options for file names and limits
while getopts "2b:C:d:e:agp:P:o:t:" OPTCHAR ; do
    case $OPTCHAR in
        a) ASAN=1 ;;
        2) TWO_PASS="-2 " ;;
        b) WIRESHARK_BIN_DIR=$OPTARG ;;
        C) CONFIG_PROFILE="-C $OPTARG " ;;
        d) TMP_DIR=$OPTARG ;;
        e) ERR_PROB=$OPTARG ;;
        g) VALGRIND=1 ;;
        p) MAX_PASSES=$OPTARG ;;
        P) MIN_PLUGINS=$OPTARG ;;
        o) CHANGE_OFFSET=$OPTARG ;;
        t) RUN_MAX_SECONDS=$(( RUN_START_SECONDS + OPTARG )) ;;
        *) printf "Unknown option %s" "$OPTCHAR"
    esac
done
shift $((OPTIND - 1))

### usually you won't have to change anything below this line ###

ws_bind_exec_paths
ws_check_exec "$TSHARK" "$EDITCAP" "$CAPINFOS" "$DATE" "$TMP_DIR"

COMMON_ARGS="${CONFIG_PROFILE}${TWO_PASS}"
KEEP=
PACKET_RANGE=
if [ $VALGRIND -eq 1 ]; then
    RUNNER=$( dirname "$0" )"/valgrind-wireshark.sh"
    COMMON_ARGS="-b $WIRESHARK_BIN_DIR $COMMON_ARGS"
    declare -a RUNNER_ARGS=("" "-T")
    # Valgrind requires more resources, so permit 1.5x memory and 3x time
    # (1.5x time is too small for a few large captures in the menagerie)
    MAX_CPU_TIME=$(( 3 * MAX_CPU_TIME ))
    MAX_VMEM=$(( 3 * MAX_VMEM / 2 ))
    # Valgrind is slow. Trim captures to the first 10k packets so that
    # we don't time out.
    KEEP=-r
    PACKET_RANGE=1-10000
else
    # Not using valgrind, use regular tshark.
    # TShark arguments (you won't have to change these)
    # n Disable network object name resolution
    # V Print a view of the details of the packet rather than a one-line summary of the packet
    # x Cause TShark to print a hex and ASCII dump of the packet data after printing the summary or details
    # r Read packet data from the following infile
    RUNNER="$TSHARK"
    declare -a RUNNER_ARGS=("-nVxr" "-nr")
    # Running with a read filter but without generating the tree exposes some
    # "More than 100000 items in tree" bugs.
    # Not sure if we want to add even more cycles to the fuzz bot's work load...
    #declare -a RUNNER_ARGS=("${CONFIG_PROFILE}${TWO_PASS}-nVxr" "${CONFIG_PROFILE}${TWO_PASS}-nr" "-Yframe ${CONFIG_PROFILE}${TWO_PASS}-nr")
fi


# Make sure we have a valid test set
FOUND=0
for CF in "$@" ; do
    if [ "$OSTYPE" == "cygwin" ] ; then
        CF=$( cygpath --windows "$CF" )
    fi
    "$CAPINFOS" "$CF" > /dev/null 2>&1 && FOUND=1
    if [ $FOUND -eq 1 ] ; then break ; fi
done

if [ $FOUND -eq 0 ] ; then
    cat <<FIN
Error: No valid capture files found.

Usage: $( basename "$0" ) [-2] [-b bin_dir] [-C config_profile] [-d work_dir] [-e error probability] [-o changes offset] [-g] [-a] [-p passes] capture file 1 [capture file 2]...
FIN
    exit 1
fi

PLUGIN_COUNT=$( $TSHARK -G plugins | grep -c dissector )
if [ "$MIN_PLUGINS" -gt 0 ] && [ "$PLUGIN_COUNT" -lt "$MIN_PLUGINS" ] ; then
    echo "Warning: Found fewer plugins than expected ($PLUGIN_COUNT vs $MIN_PLUGINS)."
    exit 1
fi

if [ $ASAN -ne 0 ]; then
    echo -n "ASan enabled. Virtual memory limit is "
    ulimit -v
else
    echo "ASan disabled. Virtual memory limit is $MAX_VMEM"
fi

HOWMANY="forever"
if [ "$MAX_PASSES" -gt 0 ]; then
    HOWMANY="$MAX_PASSES passes"
fi
echo -n "Running $RUNNER $COMMON_ARGS with args: "
printf "\"%s\" " "${RUNNER_ARGS[@]}"
echo "($HOWMANY)"
echo ""

# Clean up on <ctrl>C, etc
trap_all() {
    printf '\n\nCaught signal. Exiting.\n'
    rm -f "$TMP_DIR/$TMP_FILE" "$TMP_DIR/$ERR_FILE"*
    exit 0
}

trap_abrt() {
    for RUNNER_PID in $RUNNER_PIDS ; do
        kill -ABRT "$RUNNER_PID"
    done
    trap_all
}

trap trap_all HUP INT TERM
trap trap_abrt ABRT

# Iterate over our capture files.
PASS=0
while { [ $PASS -lt "$MAX_PASSES" ] || [ "$MAX_PASSES" -lt 1 ]; } && ! $DONE ; do
    PASS=$(( PASS+1 ))
    echo "Pass $PASS:"
    RUN=0

    for CF in "$@" ; do
        if $DONE; then
            break # We caught a signal or timed out
        fi
        RUN=$(( RUN + 1 ))
        if [ $(( RUN % 50 )) -eq 0 ] ; then
            echo "    [Pass $PASS]"
        fi
        if [ "$OSTYPE" == "cygwin" ] ; then
            CF=$( cygpath --windows "$CF" )
        fi
        printf "    %s: " "$( basename "$CF" )"

        "$CAPINFOS" "$CF" > /dev/null 2> "$TMP_DIR/$ERR_FILE"
        RETVAL=$?
        if [ $RETVAL -eq 1 ] || [ $RETVAL -eq 2 ] ; then
            echo "Not a valid capture file"
            rm -f "$TMP_DIR/$ERR_FILE"
            continue
        elif [ $RETVAL -ne 0 ] && ! $DONE ; then
            # Some other error
            ws_exit_error
        fi

        DISSECTOR_BUG=0
        VG_ERR_CNT=0

        "$EDITCAP" -E "$ERR_PROB" -o "$CHANGE_OFFSET" $KEEP "$CF" "$TMP_DIR/$TMP_FILE" $PACKET_RANGE > /dev/null 2>&1
        RETVAL=$?
        if [ $RETVAL -ne 0 ] ; then
            "$EDITCAP" -E "$ERR_PROB" -o "$CHANGE_OFFSET" $KEEP -T ether "$CF" "$TMP_DIR/$TMP_FILE" $PACKET_RANGE \
                > /dev/null 2>&1
            RETVAL=$?
            if [ $RETVAL -ne 0 ] ; then
                echo "Invalid format for editcap"
                continue
            fi
        fi

        FILE_START_SECONDS=$SECONDS
        RUNNER_PIDS=
        RUNNER_ERR_FILES=
        for ARGS in "${RUNNER_ARGS[@]}" ; do
            if $DONE; then
                break # We caught a signal
            fi
            echo -n "($ARGS) "

            # Run in a child process with limits.
            (
                # Set some limits to the child processes, e.g. stop it if
                # it's running longer than MAX_CPU_TIME seconds. (ulimit
                # is not supported well on cygwin - it shows some warnings -
                # and the features we use may not all be supported on some
                # UN*X platforms.)
                ulimit -S -t "$MAX_CPU_TIME" -s "$MAX_STACK"

                # Allow core files to be generated
                ulimit -c unlimited

                # Don't enable ulimit -v when using ASAN. See
                # https://github.com/google/sanitizers/wiki/AddressSanitizer#ulimit--v
                if [ $ASAN -eq 0 ]; then
                    ulimit -S -v "$MAX_VMEM"
                fi

                # shellcheck disable=SC2016
                SUBSHELL_PID=$($SHELL -c 'echo $PPID')

                printf 'Command and args: %s %s %s\n' "$RUNNER" "$COMMON_ARGS" "$ARGS" > "$TMP_DIR/$ERR_FILE.$SUBSHELL_PID"
                # shellcheck disable=SC2086
                "$RUNNER" $COMMON_ARGS $ARGS "$TMP_DIR/$TMP_FILE" \
                    > /dev/null 2>> "$TMP_DIR/$ERR_FILE.$SUBSHELL_PID"
            ) &
            RUNNER_PID=$!
            RUNNER_PIDS="$RUNNER_PIDS $RUNNER_PID"
            RUNNER_ERR_FILES="$RUNNER_ERR_FILES $TMP_DIR/$ERR_FILE.$RUNNER_PID"

            if [ $SECONDS -ge $RUN_MAX_SECONDS ] ; then
                printf "\nStopping after %d seconds.\n" $(( SECONDS - RUN_START_SECONDS ))
                DONE=true
            fi
        done

        for RUNNER_PID in $RUNNER_PIDS ; do
            wait "$RUNNER_PID"
            RUNNER_RETVAL=$?
            mv "$TMP_DIR/$ERR_FILE.$RUNNER_PID" "$TMP_DIR/$ERR_FILE"

            # Uncomment the next two lines to enable dissector bug
            # checking.
            #grep -i "dissector bug" $TMP_DIR/$ERR_FILE \
                #    > /dev/null 2>&1 && DISSECTOR_BUG=1

            if [ $VALGRIND -eq 1 ] && ! $DONE; then
                VG_ERR_CNT=$( grep "ERROR SUMMARY:" "$TMP_DIR/$ERR_FILE" | cut -f4 -d' ' )
                VG_DEF_LEAKED=$( grep "definitely lost:" "$TMP_DIR/$ERR_FILE" | cut -f7 -d' ' | tr -d , )
                VG_IND_LEAKED=$( grep "indirectly lost:" "$TMP_DIR/$ERR_FILE" | cut -f7 -d' ' | tr -d , )
                VG_TOTAL_LEAKED=$(( VG_DEF_LEAKED + VG_IND_LEAKED ))
                if [ $RUNNER_RETVAL -ne 0 ] ; then
                    echo "General Valgrind failure."
                    VG_ERR_CNT=1
                elif [ "$VG_TOTAL_LEAKED" -gt "$MAX_LEAK" ] ; then
                    echo "Definitely + indirectly ($VG_DEF_LEAKED + $VG_IND_LEAKED) exceeds max ($MAX_LEAK)."
                    echo "Definitely + indirectly ($VG_DEF_LEAKED + $VG_IND_LEAKED) exceeds max ($MAX_LEAK)." >> "$TMP_DIR/$ERR_FILE"
                    VG_ERR_CNT=1
                fi
                if grep -q "Valgrind cannot continue" "$TMP_DIR/$ERR_FILE" ; then
                    echo "Valgrind unable to continue."
                    VG_ERR_CNT=-1
                fi
            fi

            if ! $DONE && { [ $RUNNER_RETVAL -ne 0 ] || [ $DISSECTOR_BUG -ne 0 ] || [ $VG_ERR_CNT -ne 0 ]; } ; then
                # shellcheck disable=SC2086
                rm -f $RUNNER_ERR_FILES
                ws_exit_error
            fi
        done

        printf " OK (%s seconds)\\n" $(( SECONDS - FILE_START_SECONDS ))
        rm -f "$TMP_DIR/$TMP_FILE" "$TMP_DIR/$ERR_FILE"
    done
done
