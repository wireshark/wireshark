#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::More tests => 3;
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

test_warnings("nofile:0: pointer_default_top() is a pidl extension and should not be used\n", sub {
	my $pidl = Parse::Pidl::IDL::parse_string("[pointer_default_top(unique)] interface echo { void x(); }; ", "nofile");
	Parse::Pidl::NDR::Parse($pidl);
});

