#!/usr/bin/perl
# Shared helper for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Dump the whole Pidl NDR tree of an IDL file as JSON (see pidljson.py).
# Usage: ndrdump.pl <file.idl> <incdir>... > out.json
use strict;
# Pidl from tools/pidl of this source tree.
BEGIN {
  require File::Spec; require File::Basename;
  unshift @INC, File::Spec->catdir(File::Basename::dirname(File::Spec->rel2abs(__FILE__)),
                                   '..', '..', '..', '..', 'tools', 'pidl', 'lib');
}
use File::Basename;
use Parse::Pidl::IDL;
use Parse::Pidl::ODL;
use Parse::Pidl::Typelist;
use Parse::Pidl::NDR;
use JSON::PP;
my ($idl, @inc) = @ARGV;
my $pidl = Parse::Pidl::IDL::parse_file($idl, \@inc);
Parse::Pidl::Typelist::LoadIdl($pidl, basename($idl, '.idl'));
$pidl = Parse::Pidl::ODL::ODL2IDL($pidl, dirname($idl), \@inc);
my $ndr = Parse::Pidl::NDR::Parse($pidl);
# drop back references (ORIGINAL etc.) that make cycles
sub strip { my $x = shift; my $d = shift; return undef if $d > 40;
  if (ref $x eq 'HASH') { my %h; for (keys %$x) { next if $_ eq 'ORIGINAL' || $_ eq 'PARENT'; $h{$_} = strip($x->{$_}, $d+1) } return \%h }
  if (ref $x eq 'ARRAY') { return [ map { strip($_, $d+1) } @$x ] }
  return $x }
print JSON::PP->new->canonical->pretty->encode(strip($ndr, 0));
