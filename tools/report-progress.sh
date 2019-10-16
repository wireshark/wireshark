#!/bin/bash
# Reads stdin and periodically report the most recently seen output.
#
# Copyright (C) 2019 Peter Wu <peter@lekensteyn.nl>
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Like "travis_wait", it prevents a build timeout due to lack of progress.
# Additionally:
# - During execution it reports the most recent line instead of some fixed text.
# - It does not write the full output at the end of execution.
# - It does not impose a command timeout.

set -eu

# Default to a 60 seconds interval between printing messages.
PERIOD=${1:-60}

nexttime=$PERIOD
msg=
count=0

# Reset timer (SECONDS is a special Bash variable).
SECONDS=0

while true; do
    # Periodically report the last read line.
    timeleft=$((nexttime-SECONDS))
    while [ $timeleft -le 0 ]; do
        ((nexttime+=PERIOD))
        ((timeleft+=PERIOD))
        printf "[progress] %3d %s\n" $SECONDS "${msg:-(no output)}"
        msg=
    done

    if read -r -t $timeleft line; then
        # Save line for later.
        ((count+=1))
        msg="Line $count: $line"
        continue
    elif [ $? -le 128 ]; then
        # EOF (as opposed to a timeout)
        [ -z "$msg" ] || printf "[progress] %3d %s\n" $SECONDS "$msg"
        printf "[progress] %3d done (read %d lines).\n" $SECONDS $count
        break
    fi
done
