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

TEST_TYPE="fuzz"
. `dirname $0`/test-common.sh || exit 1

# Sanity check to make sure we can find our plugins. Zero or less disables.
MIN_PLUGINS=0

# Did we catch a signal?
DONE=0

# Perform a two pass analysis on the capture file?
TWO_PASS=

# Specific config profile ?
CONFIG_PROFILE=

# Run under valgrind ?
VALGRIND=0

# The maximum permitted amount of memory leaked. Eventually this should be
# worked down to zero, but right now that would fail on every single capture.
# Only has effect when running under valgrind.
MAX_LEAK=`expr 1024 \* 500`

# To do: add options for file names and limits
while getopts ":2b:C:d:e:gp:P:" OPTCHAR ; do
    case $OPTCHAR in
        2) TWO_PASS="-2 " ;;
        b) BIN_DIR=$OPTARG ;;
        C) CONFIG_PROFILE="-C $OPTARG " ;;
        d) TMP_DIR=$OPTARG ;;
        e) ERR_PROB=$OPTARG ;;
        g) VALGRIND=1 ;;
        p) MAX_PASSES=$OPTARG ;;
        P) MIN_PLUGINS=$OPTARG ;;
    esac
done
shift $(($OPTIND - 1))

### usually you won't have to change anything below this line ###

ws_bind_exec_paths
ws_check_exec "$TSHARK" "$EDITCAP" "$CAPINFOS" "$DATE" "$TMP_DIR"

COMMON_ARGS="${CONFIG_PROFILE}${TWO_PASS}"
if [ $VALGRIND -eq 1 ]; then
    RUNNER="`dirname $0`/valgrind-wireshark.sh"
    COMMON_ARGS="-b $BIN_DIR $COMMON_ARGS"
    declare -a RUNNER_ARGS=("" "-T")
    # Valgrind requires more resources, so permit 1.5x memory and 2.5x time
    # (1.5x time is too small for a few large captures in the menagerie)
    MAX_CPU_TIME=`expr 5 \* $MAX_CPU_TIME / 2`
    MAX_VMEM=`expr 3 \* $MAX_VMEM / 2`
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
        CF=`cygpath --windows "$CF"`
    fi
    "$CAPINFOS" "$CF" > /dev/null 2>&1 && FOUND=1
    if [ $FOUND -eq 1 ] ; then break ; fi
done

if [ $FOUND -eq 0 ] ; then
    cat <<FIN
Error: No valid capture files found.

Usage: `basename $0` [-2] [-b bin_dir] [-C config_profile] [-d work_dir] [-e error probability] [-g] [-p passes] capture file 1 [capture file 2]...
FIN
    exit 1
fi

PLUGIN_COUNT=`$TSHARK -G plugins | grep dissector | wc -l`
if [ $MIN_PLUGINS -gt 0 -a $PLUGIN_COUNT -lt $MIN_PLUGINS ] ; then
    echo "Warning: Found fewer plugins than expected ($PLUGIN_COUNT vs $MIN_PLUGINS)."
    exit 1
fi

HOWMANY="forever"
if [ $MAX_PASSES -gt 0 ]; then
    HOWMANY="$MAX_PASSES passes"
fi
echo -n "Running $RUNNER $COMMON_ARGS with args: "
printf "\"%s\" " "${RUNNER_ARGS[@]}"
echo "($HOWMANY)"
echo ""

# Clean up on <ctrl>C, etc
trap "DONE=1; echo 'Caught signal'" HUP INT TERM


# Iterate over our capture files.
PASS=0
while [ \( $PASS -lt $MAX_PASSES -o $MAX_PASSES -lt 1 \) -a $DONE -ne 1 ] ; do
    let PASS=$PASS+1
    echo "Starting pass $PASS:"
    RUN=0

    for CF in "$@" ; do
        if [ $DONE -eq 1 ]; then
            break # We caught a signal
        fi
        RUN=$(( $RUN + 1 ))
        if [ $(( $RUN % 50 )) -eq 0 ] ; then
            echo "    [Pass $PASS]"
        fi
        if [ "$OSTYPE" == "cygwin" ] ; then
            CF=`cygpath --windows "$CF"`
        fi
        echo -n "    $CF: "

        "$CAPINFOS" "$CF" > /dev/null 2> $TMP_DIR/$ERR_FILE
        RETVAL=$?
        if [ $RETVAL -eq 1 ] ; then
            echo "Not a valid capture file"
            rm -f $TMP_DIR/$ERR_FILE
            continue
        elif [ $RETVAL -ne 0 -a $DONE -ne 1 ] ; then
            # Some other error
            ws_exit_error
        fi

        DISSECTOR_BUG=0
        VG_ERR_CNT=0

        "$EDITCAP" -E $ERR_PROB "$CF" $TMP_DIR/$TMP_FILE > /dev/null 2>&1
        if [ $? -ne 0 ] ; then
            "$EDITCAP" -E $ERR_PROB -T ether "$CF" $TMP_DIR/$TMP_FILE \
                > /dev/null 2>&1
            if [ $? -ne 0 ] ; then
                echo "Invalid format for editcap"
                continue
            fi
        fi

        for ARGS in "${RUNNER_ARGS[@]}" ; do
            if [ $DONE -eq 1 ]; then
                break # We caught a signal
            fi
            echo -n "($ARGS) "
            echo -e "Command and args: $RUNNER $ARGS\n" > $TMP_DIR/$ERR_FILE

            # Run in a child process with limits, e.g. stop it if it's running
            # longer then MAX_CPU_TIME seconds. (ulimit may not be supported
            # well on some platforms, particularly cygwin.)
            (
                ulimit -S -t $MAX_CPU_TIME -v $MAX_VMEM -s $MAX_STACK
                ulimit -c unlimited

                "$RUNNER" $COMMON_ARGS $ARGS $TMP_DIR/$TMP_FILE \
                    > /dev/null 2>> $TMP_DIR/$ERR_FILE
            )
            RETVAL=$?

            # Uncomment the next two lines to enable dissector bug
            # checking.
            #grep -i "dissector bug" $TMP_DIR/$ERR_FILE \
                #    > /dev/null 2>&1 && DISSECTOR_BUG=1

            if [ $VALGRIND -eq 1 -a $DONE -ne 1 ]; then
                VG_ERR_CNT=`grep "ERROR SUMMARY:" $TMP_DIR/$ERR_FILE | cut -f4 -d' '`
                VG_DEF_LEAKED=`grep "definitely lost:" $TMP_DIR/$ERR_FILE | cut -f7 -d' ' | tr -d ,`
                VG_IND_LEAKED=`grep "indirectly lost:" $TMP_DIR/$ERR_FILE | cut -f7 -d' ' | tr -d ,`
                VG_TOTAL_LEAKED=`expr $VG_DEF_LEAKED + $VG_IND_LEAKED`
                if [ $? -ne 0 ] ; then
                    VG_ERR_CNT=1
                elif [ "$VG_TOTAL_LEAKED" -gt "$MAX_LEAK" ] ; then
                    VG_ERR_CNT=1
                fi
                if grep -q "Valgrind cannot continue" $TMP_DIR/$ERR_FILE; then
                    VG_ERR_CNT=-1
                fi
            fi

            if [ $DONE -ne 1 -a \( $RETVAL -ne 0 -o $DISSECTOR_BUG -ne 0 -o $VG_ERR_CNT -ne 0 \) ] ; then
                ws_exit_error
            fi
        done

        echo " OK"
        rm -f $TMP_DIR/$TMP_FILE $TMP_DIR/$ERR_FILE
    done
done
