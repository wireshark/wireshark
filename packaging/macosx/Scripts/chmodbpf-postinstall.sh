#!/bin/sh

CHMOD_BPF="/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"
BPF_GROUP="access_bpf"
BPF_GROUP_NAME="BPF device access ACL"

dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1 || \
    dseditgroup -q -o create "$BPF_GROUP"
dseditgroup -q -o edit -a "$USER" -t user "$BPF_GROUP"

cp "/Library/Application Support/Wireshark/ChmodBPF/org.wireshark.ChmodBPF.plist" \
    "$CHMOD_BPF"
chmod 755 "$CHMOD_BPF"
chown root:wheel "$CHMOD_BPF"

rm -rf /Library/StartupItems/ChmodBPF

launchctl load "$CHMOD_BPF"
