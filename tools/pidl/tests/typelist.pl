#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 33;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Typelist qw(hasType getType mapTypeName expandAlias
	mapScalarType addType typeIs is_scalar scalar_is_reference
	enum_type_fn bitmap_type_fn mapType);

is("foo", expandAlias("foo"));
is("uint32", expandAlias("DWORD"));
is("int32", expandAlias("int"));
is("", expandAlias(""));
is("int32", expandAlias("int32"));

is("uint32_t", mapScalarType("uint32"));
is("void", mapScalarType("void"));
is("uint64_t", mapScalarType("hyper"));

my $x = { TYPE => "ENUM", NAME => "foo" };
addType($x);
is($x, getType("foo"));
is(undef, getType("bloebla"));

is(0, typeIs("someUnknownType", "ENUM"));

is(1, hasType("foo"));
is(0, hasType("nonexistant"));

is(1, is_scalar("uint32"));
is(0, is_scalar("nonexistant"));

is(1, scalar_is_reference("string"));
is(0, scalar_is_reference("uint32"));

is("uint8", enum_type_fn({TYPE => "ENUM", PARENT=>{PROPERTIES => {enum8bit => 1}}}));
is("uint32", enum_type_fn({TYPE => "ENUM", PARENT=>{PROPERTIES => {v1_enum => 1}}}));
is("uint16", enum_type_fn({TYPE => "ENUM", PARENT=>{PROPERTIES => {}}}));

is("uint8", bitmap_type_fn({TYPE => "BITMAP", PROPERTIES => {bitmap8bit => 1}}));
is("uint16", bitmap_type_fn({TYPE => "BITMAP", PROPERTIES => {bitmap16bit => 1}}));
is("hyper", bitmap_type_fn({TYPE => "BITMAP", PROPERTIES => {bitmap64bit => 1}}));
is("uint32", bitmap_type_fn({TYPE => "BITMAP", PROPERTIES => {}}));

is("enum foo", mapType({TYPE => "ENUM"}, "foo"));
is("union foo", mapType({TYPE => "UNION"}, "foo"));
is("struct foo", mapType({TYPE => "STRUCT"}, "foo"));
is("uint8_t", mapType({TYPE => "BITMAP", PROPERTIES => {bitmap8bit => 1}}, "foo"));
is("uint8_t", mapType({TYPE => "SCALAR"}, "uint8"));
is("uint32_t", mapType({TYPE => "TYPEDEF", DATA => {TYPE => "SCALAR"}}, "uint32"));

is("void", mapTypeName(undef));
is("uint32_t", mapTypeName("uint32"));
is("int32_t", mapTypeName("int"));
