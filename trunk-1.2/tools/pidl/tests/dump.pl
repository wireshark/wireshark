#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 1;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Dump qw(DumpStruct);

is (DumpStruct({ NAME => "foo", ELEMENTS => []}), 
	"struct foo {\n}");

