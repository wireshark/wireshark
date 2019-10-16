#!/bin/bash
# Publishes artifacts from a Travis CI build.
#
# Copyright (C) 2019 Peter Wu <peter@lekensteyn.nl>
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Currently it dumps a base64-encoded xz-compressed tarball as Travis CI
# does not have a nice way to publish artifacts (like Gitlab does).
#

shopt -s nullglob
files=(*screenshot.png)

if [ ${#files[@]} -eq 0 ]; then
    echo "No artifacts found"
    exit
fi

output=travis.tar.xz
tar -cJvf "$output" "${files[@]}"

# Print some details for an integrity check.
ls -l "$output"
openssl dgst -sha256 "$output"

# Upload to other services just in case the log output is corrupted.
curl -F 'f:1=<-' ix.io < "$output"

# Dump the contents to the log (note: Travis has a 4MiB limit)
cat <<EOF
base64 -d > $output <<ARTIFACTS_BASE64
$(base64 < "$output" | tr -d '\n' | fold -w200)
ARTIFACTS_BASE64
EOF
