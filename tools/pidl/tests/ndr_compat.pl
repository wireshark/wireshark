#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 2;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util; 
use Parse::Pidl;
use Parse::Pidl::IDL;

sub parse_idl($) 
{
	my $idl = shift;
	my $pidl = Parse::Pidl::IDL::parse_string("interface echo { $idl }; ", "nofile");
	Parse::Pidl::NDR::Parse($pidl);
}

test_warnings("", sub {parse_idl("void x();"); });
test_warnings("nofile:0: top-level [out] pointer `x' is not a [ref] pointer\n", sub {parse_idl("void x([out,unique] int *x);"); });
