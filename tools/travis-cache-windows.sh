#!/bin/bash
# Packs and unpacks files for Travis CI cache.
#
# Copyright (C) 2019 Peter Wu <peter@lekensteyn.nl>
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Travis CI currently has a bug that prevents absolute paths from being cached.
# See https://github.com/travis-ci/casher/pull/38
# As a workaround, manually pack directories into an uncompressed tarball
# (which will be bzip2-compressed by casher). An additional advantage is that
# casher has to check fewer files to determine whether it is out of date.

pre_restore() {
    restored_files=()
    echo "Contents of ${cachedir}:"
    ls -la "$cachedir"
    echo
}

do_restore() {
    local tarball="$cachedir/$1" path="$2"
    if [ -e "$tarball" ]; then
        echo "Restoring ${path}..."
        time tar -xPf "$tarball" "$path"
        restored_files+=("$1")
    fi
}

post_restore() {
    # Remove old cache entries if any.
    mkdir "${cachedir}.new"
    for file in "${restored_files[@]}"; do
        mv "$cachedir/$file" "${cachedir}.new/"
    done
    if oldfiles=$(ls -lA "$cachedir" | grep -v ^total); then
        echo "Removed stale cache entries:"
        echo "$oldfiles"
        echo
    fi
    rm -rf "$cachedir"
    mv "${cachedir}.new" "$cachedir"
}

pre_save() { :;}

do_save() {
    local tarball="$cachedir/$1" path="$2"
    if [ ! -e "$path" ]; then
        echo "Cannot cache $path as it is missing."
        return
    fi
    if [ -e "$tarball" ]; then
        if ! [ "$path" -nt "$tarball" ]; then
            echo "No changes detected in ${path}."
            return
        fi
        echo "Saving new version of ${path}..."
    else
        echo "Saving $path for the first time..."
    fi
    time tar -cPf "$tarball" "$path"
}

post_save() {
    echo "New contents of ${cachedir}:"
    ls -la "$cachedir"
    echo
}

main() {
    # Cache directories are relative to this path.
    cd "$TRAVIS_BUILD_DIR"
    pwd
    cachedir=travis-cache
    mkdir -p "$cachedir"

    "pre_$1"

    "do_$1" wireshark-libs.tar              "$WIRESHARK_BASE_DIR"
    "do_$1" Qt.tar                          "$QT5_BASE_DIR"

    "post_$1"
}

# Merge stderr to stdout to prevent stderr from ending up in future output.
main "$1" 2>&1
