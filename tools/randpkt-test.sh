#!/bin/bash

# Randpkt testing script for TShark
#
# This script uses Randpkt to generate capture files with randomized
# content.  It runs TShark on each generated file and checks for errors.
# The files are processed repeatedly until an error is found.

TEST_TYPE="randpkt"
# shellcheck source=tools/test-common.sh
. "$( dirname "$0" )"/test-common.sh || exit 1

# Run under valgrind ?
VALGRIND=0

# Run under AddressSanitizer ?
ASAN=$CONFIGURED_WITH_ASAN

# Trigger an abort if a dissector finds a bug.
# Uncomment to disable
export WIRESHARK_ABORT_ON_DISSECTOR_BUG="True"

# The maximum permitted amount of memory leaked. Eventually this should be
# worked down to zero, but right now that would fail on every single capture.
# Only has effect when running under valgrind.
MAX_LEAK=$(( 1024 * 100 ))

# To do: add options for file names and limits
while getopts "ab:d:gp:t:" OPTCHAR ; do
    case $OPTCHAR in
        a) ASAN=1 ;;
        b) WIRESHARK_BIN_DIR=$OPTARG ;;
        d) TMP_DIR=$OPTARG ;;
        g) VALGRIND=1 ;;
        p) MAX_PASSES=$OPTARG ;;
        t) PKT_TYPES=$OPTARG ;;
        *) printf "Unknown option: %s\\n" "$OPTARG"
    esac
done
shift $(( OPTIND - 1 ))

### usually you won't have to change anything below this line ###

ws_bind_exec_paths
ws_check_exec "$TSHARK" "$RANDPKT" "$DATE" "$TMP_DIR"

[[ -z "$PKT_TYPES" ]] && PKT_TYPES=$($RANDPKT -h | awk '/^\t/ {print $1}')

if [ $VALGRIND -eq 1 ]; then
    RUNNER="$( dirname "$0" )/valgrind-wireshark.sh"
    COMMON_ARGS="-b $WIRESHARK_BIN_DIR $COMMON_ARGS"
    declare -a RUNNER_ARGS=("" "-T")
    # Valgrind requires more resources, so permit 1.5x memory and 3x time
    # (1.5x time is too small for a few large captures in the menagerie)
    MAX_CPU_TIME=$(( 3 * "$MAX_CPU_TIME" ))
    MAX_VMEM=$(( 3 * "$MAX_VMEM" / 2 ))
else
    # Not using valgrind, use regular tshark.
    # TShark arguments (you won't have to change these)
    # n Disable network object name resolution
    # V Print a view of the details of the packet rather than a one-line summary of the packet
    # x Cause TShark to print a hex and ASCII dump of the packet data after printing the summary or details
    # r Read packet data from the following infile
    RUNNER="$TSHARK"
    declare -a RUNNER_ARGS=("-nVxr" "-nr")
fi
RANDPKT_ARGS="-b 2000 -c 5000"

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
echo -n "Running $RUNNER with args: "
printf "\"%s\" " "${RUNNER_ARGS[@]}"
echo "($HOWMANY)"
echo "Running $RANDPKT with args: $RANDPKT_ARGS"
echo ""

trap "MAX_PASSES=1; echo 'Caught signal'" HUP INT TERM


# Iterate over our capture files.
PASS=0
while [ $PASS -lt "$MAX_PASSES" ] || [ "$MAX_PASSES" -lt 1 ] ; do
    PASS=$(( PASS + 1 ))
    echo "Pass $PASS:"

    for PKT_TYPE in $PKT_TYPES ; do
        if [ $PASS -gt "$MAX_PASSES" ] && [ "$MAX_PASSES" -ge 1 ] ; then
            break # We caught a signal
        fi
        echo -n "    $PKT_TYPE: "

        DISSECTOR_BUG=0
        VG_ERR_CNT=0

        # shellcheck disable=SC2086
        "$RANDPKT" $RANDPKT_ARGS -t "$PKT_TYPE" "$TMP_DIR/$TMP_FILE" \
            > /dev/null 2>&1

        for ARGS in "${RUNNER_ARGS[@]}" ; do
            echo -n "($ARGS) "
               echo -e "Command and args: $RUNNER $ARGS\\n" > "$TMP_DIR/$ERR_FILE"

            # Run in a child process with limits.
            (
                # Set some limits to the child processes, e.g. stop it if
                # it's running longer than MAX_CPU_TIME seconds. (ulimit
                # is not supported well on cygwin - it shows some warnings -
                # and the features we use may not all be supported on some
                # UN*X platforms.)
                ulimit -S -t $MAX_CPU_TIME -s $MAX_STACK

                # Allow core files to be generated
                ulimit -c unlimited

                # Don't enable ulimit -v when using ASAN. See
                # https://github.com/google/sanitizers/wiki/AddressSanitizer#ulimit--v
                if [ $ASAN -eq 0 ]; then
                    ulimit -S -v $MAX_VMEM
                fi

                # shellcheck disable=SC2086
                "$RUNNER" $ARGS "$TMP_DIR/$TMP_FILE" \
                    > /dev/null 2>> "$TMP_DIR/$ERR_FILE"
            )
            RETVAL=$?

            if [ $VALGRIND -eq 1 ]; then
                VG_ERR_CNT=$( grep "ERROR SUMMARY:" "$TMP_DIR/$ERR_FILE" | cut -f4 -d' ' )
                VG_DEF_LEAKED=$( grep "definitely lost:" "$TMP_DIR/$ERR_FILE" | cut -f7 -d' ' | tr -d , )
                VG_IND_LEAKED=$( grep "indirectly lost:" "$TMP_DIR/$ERR_FILE" | cut -f7 -d' ' | tr -d , )
                VG_TOTAL_LEAKED=$(( "$VG_DEF_LEAKED" + "$VG_IND_LEAKED" ))
                if [ $RETVAL -ne 0 ] ; then
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
	    if [ $RETVAL -ne 0 ] ; then break ; fi
        done
        grep -i "dissector bug" "$TMP_DIR/$ERR_FILE" \
            > /dev/null 2>&1 && DISSECTOR_BUG=1

        if [ $RETVAL -ne 0 ] || [ $DISSECTOR_BUG -ne 0 ] || [ $VG_ERR_CNT -ne 0 ] ; then
            ws_exit_error
        fi
        echo " OK"
        rm -f "$TMP_DIR/$TMP_FILE" "$TMP_DIR/$ERR_FILE"
    done
done
