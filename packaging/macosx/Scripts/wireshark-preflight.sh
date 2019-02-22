#!/bin/sh

#
# If we're upgrading, remove the old Wireshark.app before installing
# the new one so that we don't try to load old, incompatible libraries,
# plugins, codes, or other code.
#

OLD_APP="$2/Wireshark.app"

if [ -d "$OLD_APP" ] ; then
	rm -rf "$OLD_APP"
fi
