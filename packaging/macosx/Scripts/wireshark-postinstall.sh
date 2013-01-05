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
