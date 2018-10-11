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

set -e

DESTDIR=.

while getopts "d:" OPTCHAR ; do
    case $OPTCHAR in
        d) DESTDIR=$OPTARG ;;
        *) printf "Unknown option %s" "$OPTCHAR"
    esac
done
shift $(( OPTIND - 1 ))

# The remaining parameter, if set, is a git commit, like v1.12.0-rc1 or 54819e5699f
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
DESCRIPTION=$(git describe --abbrev=8 --match "v[1-9]*" "${COMMIT}")
VERSION=${DESCRIPTION#v}
STASH_POP=False
XZ_OPTS=

# We might be able to avoid stashing by doing one of the following:
#
# For official releases, update our build process such that we don't
# need to modify version.conf.
#
# Use tar to append a new or updated version.conf to the archive.
# This would require detecting our local tar flavor (GNU or BSD) and
# constructing a compatible command. BSD tar appears to support inline
# inline filtering via `-a @- -s /^/wireshark-${VERSION} version.conf`
# or something similar. GNU tar appears to require that we write to
# a file and append to it. I'm not sure if we can add a path prefix.
#
# Use the 'export-subst' gitattribute along with
# 'git_description=$Format:...$' in version.conf. export-subst uses
# 'git log' formatting. I'm not sure if we can build $DESCRIPTION
# from that.
#
# Rewrite this script in Python and use the built-in tarfile module
# to replace version.conf.

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

echo . | xz --threads=0 > /dev/null 2>&1 && XZ_OPTS=--threads=0

git archive --prefix="wireshark-${VERSION}/" ${COMMIT} | xz $XZ_OPTS > "${DESTDIR}/wireshark-${VERSION}.tar.xz"

if [ "$STASH_POP" == "True" ] ; then
    git stash pop
fi
