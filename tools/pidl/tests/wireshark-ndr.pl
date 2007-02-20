#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
# test parsing wireshark conformance files
use strict;
use warnings;

use Test::More tests => 3;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Wireshark::NDR qw(field2name %res PrintIdl);

is("Access Mask", field2name("access_mask"));
is("Accessmask", field2name("AccessMask"));

$res{code} = "";
PrintIdl("foo\nbar\n");
is("/* IDL: foo */
/* IDL: bar */

", $res{code});
