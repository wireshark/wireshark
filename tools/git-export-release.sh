#!/bin/bash
#
# creates a release tarball directly from git
#
# Copyright 2011 Balint Reczey <balint@balintreczey.hu>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# First paremeter, if set, is a git commit, like v1.12.0-rc1 or 54819e5699f
# By default HEAD is used.
# Note, that filtering takes place base on the _exported_ version's
# .gitattributes files thus archives generated from older commits will contain
# the whole tree.
COMMIT="HEAD"
if test -n "$1"; then
  COMMIT="$1"
fi

if [ ! -e "${GIT_DIR:-.git}" ] ; then
    echo "Must be run from the top-level repository directory."
    exit 1
fi

# --abbrev=<n> and --match should match make-version.pl.
DESCRIPTION=$(git describe --abbrev=8 --match "v[1-9]*" ${COMMIT})
VERSION=${DESCRIPTION#v}
STASH_POP=False

if [ "$COMMIT" == "HEAD" ] ; then
    echo "Adding description $DESCRIPTION"
    echo "git_description=$DESCRIPTION" >> version.conf
    git add version.conf
    git stash --keep-index
    COMMIT="stash@{0}"
    STASH_POP=True
else
    echo "Not archiving HEAD. Skipping description."
fi

echo "Creating wireshark-$VERSION.tar.xz"

git archive --prefix=wireshark-${VERSION}/ ${COMMIT}  | xz > wireshark-${VERSION}.tar.xz

if [ "$STASH_POP" == "True" ] ; then
    git stash pop
fi
