#!/bin/sh

CHMOD_BPF_DIR="/Library/StartupItems/ChmodBPF"
CHMOD_BPF="$CHMOD_BPF_DIR/ChmodBPF"
BPF_GROUP="access_bpf"
BPF_GROUP_NAME="BPF device access ACL"

dscl . -read /Groups/"$BPF_GROUP" > /dev/null 2>&1 || \
    dseditgroup -q -o create "$BPF_GROUP"
dseditgroup -q -o edit -a "$USER" -t user "$BPF_GROUP"

chmod -R go-w "$CHMOD_BPF_DIR"

sh "$CHMOD_BPF" start
