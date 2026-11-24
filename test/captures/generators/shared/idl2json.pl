#!/usr/bin/perl
# Shared helper for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Dump the Pidl NDR tree of an IDL file (and the files it imports) as JSON
# for the DCE/RPC generators (see pidljson.py).
# Usage: idl2json.pl <file.idl> <incdir> > out.json
use strict; use warnings;
# Pidl from tools/pidl of this source tree.
BEGIN {
  require File::Spec; require File::Basename;
  unshift @INC, File::Spec->catdir(File::Basename::dirname(File::Spec->rel2abs(__FILE__)),
                                   '..', '..', '..', '..', 'tools', 'pidl', 'lib');
}
use Parse::Pidl::IDL; use Parse::Pidl::Typelist; use Parse::Pidl::NDR; use Parse::Pidl::ODL;
use JSON::PP; use File::Basename;
my ($file, $inc) = @ARGV;
my %types; my @funcs; my $iface;
sub lv { my $l = shift; my %h = %$l; return \%h; }
sub el {
  my $e = shift;
  return { NAME => $e->{NAME}, TYPE => $e->{TYPE}, PROPERTIES => $e->{PROPERTIES} // {},
           LEVELS => [ map { lv($_) } @{$e->{LEVELS} // []} ],
           ALIGN => $e->{ALIGN}, DIRECTION => $e->{DIRECTION}, CASE => $e->{CASE} };
}
sub data {
  my $d = shift;
  my %o = (TYPE => $d->{TYPE}, NAME => $d->{NAME}, ALIGN => $d->{ALIGN}, PROPERTIES => $d->{PROPERTIES} // {});
  if ($d->{TYPE} eq 'STRUCT' or $d->{TYPE} eq 'UNION') {
    $o{ELEMENTS} = [ map { $_->{TYPE} eq 'EMPTY' ? {TYPE=>'EMPTY', CASE=>$_->{CASE}} : el($_) } @{$d->{ELEMENTS} // []} ];
    $o{SURROUNDING} = $d->{SURROUNDING_ELEMENT} ? $d->{SURROUNDING_ELEMENT}->{NAME} : undef;
    $o{SWITCH_TYPE} = $d->{SWITCH_TYPE}; $o{HAS_DEFAULT} = $d->{HAS_DEFAULT};
  } elsif ($d->{TYPE} eq 'ENUM' or $d->{TYPE} eq 'BITMAP') {
    $o{BASE_TYPE} = $d->{BASE_TYPE}; $o{ELEMENTS} = $d->{ELEMENTS};
  }
  return \%o;
}
my %seen;
sub doit {
  my ($f, $main) = @_;
  return if $seen{$f}++;
  my $pidl = Parse::Pidl::IDL::parse_file($f, [$inc]) or die "parse $f";
  Parse::Pidl::Typelist::LoadIdl($pidl, basename($f, '.idl'));
  $pidl = Parse::Pidl::ODL::ODL2IDL($pidl, dirname($f), [$inc]);
  for my $x (@$pidl) {
    if ($x->{TYPE} eq 'IMPORT') { for my $p (@{$x->{PATHS}}) { $p =~ s/"//g; my $fp = (-f "$inc/$p") ? "$inc/$p" : (glob("$inc/*/$p"))[0]; doit($fp, 0) if $fp; } }
  }
  my $ndr = Parse::Pidl::NDR::Parse($pidl);
  for my $i (@$ndr) {
    next unless $i->{TYPE} eq 'INTERFACE';
    for my $t (@{$i->{TYPES}}) {
      next unless $t->{TYPE} eq 'TYPEDEF' or $t->{TYPE} eq 'STRUCT' or $t->{TYPE} eq 'UNION' or $t->{TYPE} eq 'ENUM' or $t->{TYPE} eq 'BITMAP';
      my $d = $t->{TYPE} eq 'TYPEDEF' ? $t->{DATA} : $t;
      next unless ref $d eq 'HASH';
      my $o = data($d); $o->{NAME} = $t->{NAME};
      $types{$t->{NAME}} = $o;
    }
    if ($main) {
      $iface = { NAME => $i->{NAME}, UUID => $i->{UUID}, VERSION => $i->{VERSION} };
      for my $fn (@{$i->{FUNCTIONS}}) {
        push @funcs, { NAME => $fn->{NAME}, OPNUM => $fn->{OPNUM}, RETURN_TYPE => $fn->{RETURN_TYPE},
                       ELEMENTS => [ map { el($_) } @{$fn->{ELEMENTS}} ] };
      }
    }
  }
}
doit($file, 1);
print JSON::PP->new->canonical->pretty->encode({ iface => $iface, types => \%types, functions => \@funcs });
