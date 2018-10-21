#!/bin/sh

CHMOD_BPF_PLIST="/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"
BPF_GROUP="access_bpf"
BPF_GROUP_NAME="BPF device access ACL"

dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1 || \
    dseditgroup -q -o create "$BPF_GROUP"
dseditgroup -q -o edit -a "$USER" -t user "$BPF_GROUP"

cp "/Library/Application Support/Wireshark/ChmodBPF/org.wireshark.ChmodBPF.plist" \
    "$CHMOD_BPF_PLIST"
chmod u=rw,g=r,o=r "$CHMOD_BPF_PLIST"
chown root:wheel "$CHMOD_BPF_PLIST"

rm -rf /Library/StartupItems/ChmodBPF

launchctl load "$CHMOD_BPF_PLIST"
