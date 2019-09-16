#!/bin/sh

#
# If we're upgrading, remove the old Wireshark.app before installing
# the new one so that we don't try to load old, incompatible libraries,
# plugins, codes, or other code.
#

OLD_APP="$2/Wireshark.app"

# This is the wrong way to go about ensuring that our installation is
# deterministic.
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16050
#if [ -d "$OLD_APP" ] ; then
#	rm -rf "$OLD_APP"
#fi
