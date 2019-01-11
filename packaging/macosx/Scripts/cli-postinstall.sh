#!/bin/sh

CLI_PATH="$2"
BINARIES="
    capinfos
    captype
    dftest
    dumpcap
    editcap
    mergecap
    mmdbresolve
    randpkt
    rawshark
    reordercap
    text2pcap
    tshark
"

cd "$CLI_PATH"

chmod 755 wireshark
chown root:wheel wireshark

for BIN in $BINARIES ; do
    rm -f ./"$BIN"
    ln -sn ./wireshark "$BIN"
done
