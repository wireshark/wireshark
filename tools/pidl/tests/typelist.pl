#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 56;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Typelist qw(hasType typeHasBody getType mapTypeName expandAlias
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
is("double", mapScalarType("double"));

my $x = { TYPE => "ENUM", NAME => "foo", EXTRADATA => 1 };
addType($x);
is_deeply($x, getType("foo"));
is(undef, getType("bloebla"));
is_deeply(getType({ TYPE => "STRUCT" }), { TYPE => "STRUCT" });
is_deeply(getType({ TYPE => "ENUM", NAME => "foo" }), $x);
is_deeply(getType("uint16"), {
		NAME => "uint16",
		BASEFILE => "<builtin>",
		TYPE => "TYPEDEF",
		DATA => { NAME => "uint16", TYPE => "SCALAR" }});

is_deeply(getType("double"), {
		NAME => "double",
		BASEFILE => "<builtin>",
		TYPE => "TYPEDEF",
		DATA => { NAME => "double", TYPE => "SCALAR" }});

is(0, typeIs("someUnknownType", "ENUM"));
is(0, typeIs("foo", "ENUM"));
addType({NAME => "mytypedef", TYPE => "TYPEDEF", DATA => { TYPE => "ENUM" }});
is(1, typeIs("mytypedef", "ENUM"));
is(0, typeIs("mytypedef", "BITMAP"));
is(1, typeIs({ TYPE => "ENUM"}, "ENUM"));
is(0, typeIs({ TYPE => "BITMAP"}, "ENUM"));
is(1, typeIs("uint32", "SCALAR"));
is(0, typeIs("uint32", "ENUM"));

is(1, hasType("foo"));
is(0, hasType("nonexistant"));
is(0, hasType({TYPE => "ENUM", NAME => "someUnknownType"}));
is(1, hasType({TYPE => "ENUM", NAME => "foo"}));
is(1, hasType({TYPE => "ENUM"}));
is(1, hasType({TYPE => "STRUCT"}));

is(1, is_scalar("uint32"));
is(0, is_scalar("nonexistant"));
is(1, is_scalar({TYPE => "ENUM"}));
is(0, is_scalar({TYPE => "STRUCT"}));
is(1, is_scalar({TYPE => "TYPEDEF", DATA => {TYPE => "ENUM" }}));
is(1, is_scalar("mytypedef"));

is(1, scalar_is_reference("string"));
is(0, scalar_is_reference("uint32"));
is(0, scalar_is_reference({TYPE => "STRUCT", NAME => "echo_foobar"}));

is("uint8", enum_type_fn({TYPE => "ENUM", PARENT=>{PROPERTIES => {enum8bit => 1}}}));
is("uint32", enum_type_fn({TYPE => "ENUM", PARENT=>{PROPERTIES => {v1_enum => 1}}}));
is("uint1632", enum_type_fn({TYPE => "ENUM", PARENT=>{PROPERTIES => {}}}));

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

ok(not typeHasBody({TYPE => "TYPEDEF", DATA => { TYPE => "STRUCT" }}));
ok(typeHasBody({TYPE => "TYPEDEF", DATA => { TYPE => "STRUCT", ELEMENTS => [] }}));
