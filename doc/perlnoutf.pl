#!/usr/bin/perl -w
# Call another Perl script, passing our caller's arguments, with
# environment variables unset so perl doesn't interpret bytes as UTF-8
# characters.
#
# Copyright 2004 Graeme Hewson <ghewson@wormhole.me.uk>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

use strict;

delete $ENV{LANG};
delete $ENV{LANGUAGE};
delete $ENV{LC_ALL};
delete $ENV{LC_CTYPE};

system("$^X -w @ARGV");
