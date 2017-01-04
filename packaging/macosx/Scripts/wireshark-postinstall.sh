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

BIN_PATH="$2/Wireshark.app/Contents/Resources/bin"
#
# For some reason, packagemaker isn't including Contents/Resources/bin
# in the app bundle, so let's just construct it ourselves.
#
if [ ! -d "$BIN_PATH" ]
then
	mkdir -m u=rwx,g=rx,o=rx "$BIN_PATH"
fi
for i in capinfos dftest dumpcap editcap mergecap randpkt rawshark \
    tshark text2pcap      
do
	ln -s "$BIN_PATH/$i" ../../MacOS/"$i"
done
ln -s "$BIN_PATH/wireshark" ../../MacOS/Wireshark

# Setting PATH
# if /etc/paths.d/Wireshark already exists we overwrite it.
#
WSPATH="$BIN_PATH"

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
