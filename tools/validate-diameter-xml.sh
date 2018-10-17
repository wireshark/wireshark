#!/bin/bash

# A small script to run xmllint on the Diameter XML files (after doing some
# fixups to those files).
#
# Copyright 2016 Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
# SPDX-License-Identifier: GPL-2.0-or-later

if ! type -p sed > /dev/null
then
	echo "'sed' is needed to run $0." 1>&2
	# Exit cleanly because we don't want pre-commit to fail just because
	# someone doesn't have the tools...
	exit 0
fi
if ! type -p xmllint > /dev/null
then
	echo "'xmllint' is needed to run $0." 1>&2
	# Exit cleanly because we don't want pre-commit to fail just because
	# someone doesn't have the tools...
	exit 0
fi

# Ideally this would work regardless of our cwd
if [ ! -r diameter/dictionary.xml ]
then
	echo "Couldn't find diameter/dictionary.xml" 1>&2
	exit 1
fi
if [ ! -r diameter/dictionary.dtd ]
then
	echo "Couldn't find diameter/dictionary.dtd" 1>&2
	exit 1
fi

if ! tmpdir=$(mktemp -d); then
	echo "Could not create temporary directory" >&2
	exit 1
fi
trap 'rm -rf "$tmpdir"' EXIT

# First edit all the AVP names that start with "3GPP" to indicate "TGPP".
# XML doesn't allow ID's to start with a digit but:
#   1) We don't *really* care if it's valid XML
#   2) (but) we do want to use xmllint to find problems
#   3) (and) users see the AVP names.  Showing them "TGPP" instead of "3GPP"
#      is annoying enough to warrant this extra work.
cp diameter/dictionary.dtd "$tmpdir" || exit 1
for f in diameter/*.xml
do
	sed 's/name="3GPP/name="TGPP/g' "$f" > "$tmpdir/${f##*/}" || exit 1
done

xmllint --noout --noent --postvalid "$tmpdir/dictionary.xml" &&
	echo "Diameter dictionary is (mostly) valid XML."

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
