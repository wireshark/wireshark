#!/bin/sh

#
# Install the XQuartz fixer job, and run it, so that if the system
# currently has an XQuartz installation missing its /usr/X11 -> /opt/X11
# symlink, courtesy of the Yosemite installer removing it on an upgrade,
# we put it back.  (It has to run as root, so it can write to /usr.)
#
XQUARTZFIXER="/Library/LaunchDaemons/org.wireshark.XQuartzFixer.plist"

cp "/Library/Application Support/Wireshark/XQuartzFixer/org.wireshark.XQuartzFixer.plist" \
    "$XQUARTZFIXER"
chmod 755 "$XQUARTZFIXER"
chown root:wheel "$XQUARTZFIXER"

rm -rf /Library/StartupItems/XQuartzFixer

launchctl load "$XQUARTZFIXER"
