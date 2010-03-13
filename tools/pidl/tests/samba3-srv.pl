#!/usr/bin/perl
# (C) 2008 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 1;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper has_property);
use Parse::Pidl::Samba3::ServerNDR qw(DeclLevel);

my $l = { TYPE => "DATA", DATA_TYPE => "uint32" }; 
my $e = { FILE => "foo", LINE => 0, PROPERTIES => { }, TYPE => "uint32",
          LEVELS => [ $l ] };

is("uint32_t", DeclLevel($e, 0));
