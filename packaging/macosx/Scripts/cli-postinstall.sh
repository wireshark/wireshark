#!/bin/sh

CLI_PATH="$2"
BINARIES="
    capinfos
    dftest
    dumpcap
    editcap
    idl2wrs
    mergecap
    randpkt
    rawshark
    text2pcap
    tshark
"

cd "$CLI_PATH"

rm -f ./wireshark
mv utility-launcher wireshark
chmod 755 wireshark

for BIN in $BINARIES ; do
    rm -f ./"$BIN"
    ln -sn ./wireshark "$BIN"
done
