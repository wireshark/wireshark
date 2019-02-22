#!/bin/sh

# Setting PATH
# if /etc/paths.d/Wireshark already exists we overwrite it.
#
WSPATH="$2/Wireshark.app/Contents/MacOS"

if [ ! -d /etc/paths.d ]
then
	mkdir -m u=rwx,g=rx,o=rx /etc/paths.d
fi
echo $WSPATH > /etc/paths.d/Wireshark

# Setting MANPATH
# if /etc/manpaths.d/Wireshark already exists we overwrite it.
#
WSMANPATH="$2/Wireshark.app/Contents/Resources/share/man"

if [ ! -d /etc/manpaths.d ]
then
	mkdir -m u=rwx,g=rx,o=rx /etc/manpaths.d
fi
echo $WSMANPATH > /etc/manpaths.d/Wireshark

#
# If we still have the old XQuartz fixer, get rid of it; we don't use
# X11, and haven't used it since Wireshark 2.0, so we don't need it.
#
XQUARTZ_FIXER_PLIST="/Library/LaunchDaemons/org.wireshark.XQuartzFixer.plist"
if [ -e "$XQUARTZ_FIXER_PLIST" ]
then
	launchctl unload "$XQUARTZ_FIXER_PLIST"
	rm -rf "/Library/Application Support/Wireshark/XQuartzFixer"
	rm -f "$XQUARTZ_FIXER_PLIST"
fi

#
# And get rid of the *really* old XQuartz fixer while we're at it.
#
rm -rf /Library/StartupItems/XQuartzFixer
