#!/bin/sh
#
# Author: Aaron Voisine <aaron@voisine.org>

if [ "$DISPLAY"x == "x" ]; then
    echo :0 > /tmp/display.$UID
else
    echo $DISPLAY > /tmp/display.$UID
fi
