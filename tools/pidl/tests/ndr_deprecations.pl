#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 1;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::NDR qw(ValidElement);

# Case 1

my $e = {
	'FILE' => 'foo.idl',
	'NAME' => 'v',
	'PROPERTIES' => {"subcontext" => 1},
	'POINTERS' => 0,
	'TYPE' => 'uint8',
	'PARENT' => { TYPE => 'STRUCT' },
	'LINE' => 42 };

test_warnings("foo.idl:42: subcontext() is deprecated. Use represent_as() or transmit_as() instead\n", 
	sub { ValidElement($e); });
