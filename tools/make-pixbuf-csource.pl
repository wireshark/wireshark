#!/usr/bin/env perl

# Simple script to create extern pixbuf csource. Receives list of
# tuples (varname, path) separated with spaces.

# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

use strict;

my $target = shift;

open(my $fout, ">", $target . ".c");
open(my $fin, "-|", "gdk-pixbuf-csource", "--extern", "--raw", "--build-list", @ARGV);
select($fout);

print << "HEADER";
/* This file was automatically generated. DO NOT EDIT. */

#include <glib.h>
HEADER

while (<$fin>) {
    s/ *$//;
    print "\n" if (/^\/\*/);
    print if ($_ ne "\n");
}

close($fout);
close($fin);

open(my $fout, ">", $target . ".h");
select($fout);

print << "HEADER";
/* This file was automatically generated. DO NOT EDIT. */

#ifndef __PIXBUF_CSOURCE_HEADER__
#define __PIXBUF_CSOURCE_HEADER__

#include <glib.h>

HEADER

while (my $var = shift @ARGV) {
    print "extern const guint8 ${var}[];\n";
    shift @ARGV;
}

print << "TRAILER";

#endif /*__PIXBUF_CSOURCE_HEADER__*/
TRAILER

close($fout);
