#!/bin/sh

CHMOD_BPF="/Library/StartupItems/ChmodBPF/ChmodBPF"
BPF_GROUP="access_bpf"
BPF_GROUP_NAME="BPF device access ACL"

dseditgroup -q -o read "$BPF_GROUP" > /dev/null 2>&1 || \
    dseditgroup -q -o create "$BPF_GROUP"
dseditgroup -q -o edit -a "$USER" -t user "$BPF_GROUP"

sh "$CHMOD_BPF" start
