#!/usr/bin/env perl

# Simple script to create extern pixbuf csource. Receives list of
# tuples (varname, path) separated with spaces.

# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
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
