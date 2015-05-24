#!/bin/sh

#
# After an upgrade, get rid of leftover plugins that were converted
# to built-in dissectors, so that we won't have problems trying to load
# them (wrong instruction set, collisions with the built-ins, etc.).
#
# XXX - apparently, there's no longer a "postinstall" vs. "postupgrade"
# difference, but if you've never installed Wireshark before, this
# will just silently and harmlessly fail to remove files that aren't
# there in the first place.
#
PLUGINS="coseventcomm cosnaming interlink parlay sercosiii tango"

PLUGINS_PATH="$2/Wireshark.app/Contents/Resources/lib/wireshark/plugins"

for plugin in $PLUGINS
do
	rm -f "$PLUGINS_PATH"/$plugin.so "$PLUGINS_PATH"/$plugin.la
done

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
