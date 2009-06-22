#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 72;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl qw(error);
use Parse::Pidl::Util;

# has_property()
is(undef, has_property({}, "foo"));
is(undef, has_property({PROPERTIES => {}}, "foo"));
is("data", has_property({PROPERTIES => {foo => "data"}}, "foo"));
is(undef, has_property({PROPERTIES => {foo => undef}}, "foo"));

# is_constant()
ok(is_constant("2"));
ok(is_constant("256"));
ok(is_constant("0x400"));
ok(is_constant("0x4BC"));
ok(not is_constant("0x4BGC"));
ok(not is_constant("str"));
ok(not is_constant("2 * expr"));

# make_str()
is("\"bla\"", make_str("bla"));
is("\"bla\"", make_str("\"bla\""));
is("\"\"bla\"\"", make_str("\"\"bla\"\""));
is("\"bla\"\"", make_str("bla\""));
is("\"foo\"bar\"", make_str("foo\"bar"));

is("bla", unmake_str("\"bla\""));
is("\"bla\"", unmake_str("\"\"bla\"\""));

# print_uuid()
is(undef, print_uuid("invalid"));
is("{0x12345778,0x1234,0xabcd,{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xac}}", 
   print_uuid("12345778-1234-abcd-ef00-0123456789ac"));
is("{0x12345778,0x1234,0xabcd,{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xac}}", 
   print_uuid("\"12345778-1234-abcd-ef00-0123456789ac\""));

# property_matches()
# missing property
ok(not property_matches({PROPERTIES => {}}, "x", "data"));
# data not matching
ok(not property_matches({PROPERTIES => {x => "bar"}}, "x", "data"));
# data matching exactly
ok(property_matches({PROPERTIES => {x => "data"}}, "x", "data"));
# regex matching
ok(property_matches({PROPERTIES => {x => "data"}}, "x", "^([dat]+)\$"));

# ParseExpr()
is(undef, ParseExpr("", {}, undef));
is("a", ParseExpr("a", {"b" => "2"}, undef));
is("2", ParseExpr("a", {"a" => "2"}, undef));
is("2 * 2", ParseExpr("a*a", {"a" => "2"}, undef));
is("r->length + r->length", 
   ParseExpr("length+length", {"length" => "r->length"}, undef));
is("2 / 2 * (r->length)", 
	ParseExpr("constant/constant*(len)", {"constant" => "2", 
			                              "len" => "r->length"}, undef));
is("2 + 2 - r->length", 
	ParseExpr("constant+constant-len", {"constant" => "2", 
			                              "len" => "r->length"}, undef));
is("*r->length", ParseExpr("*len", { "len" => "r->length"}, undef));
is("**r->length", ParseExpr("**len", { "len" => "r->length"}, undef));
is("r->length & 2", ParseExpr("len&2", { "len" => "r->length"}, undef));
is("&r->length", ParseExpr("&len", { "len" => "r->length"}, undef));
is("calc()", ParseExpr("calc()", { "foo" => "2"}, undef));
is("calc(2 * 2)", ParseExpr("calc(foo * 2)", { "foo" => "2"}, undef));
is("strlen(\"data\")", ParseExpr("strlen(foo)", { "foo" => "\"data\""}, undef));
is("strlen(\"data\", 4)", ParseExpr("strlen(foo, 4)", { "foo" => "\"data\""}, undef));
is("foo / bar", ParseExpr("foo / bar", { "bla" => "\"data\""}, undef));
is("r->length % 2", ParseExpr("len%2", { "len" => "r->length"}, undef));
is("r->length == 2", ParseExpr("len==2", { "len" => "r->length"}, undef));
is("r->length != 2", ParseExpr("len!=2", { "len" => "r->length"}, undef));
is("pr->length", ParseExpr("pr->length", { "p" => "r"}, undef));
is("r->length", ParseExpr("p->length", { "p" => "r"}, undef));
is("_foo / bla32", ParseExpr("_foo / bla32", { "bla" => "\"data\""}, undef));
is("foo.bar.blah", ParseExpr("foo.blah", { "foo" => "foo.bar"}, undef));
is("\"bla\"", ParseExpr("\"bla\"", {}, undef));
is("1 << 2", ParseExpr("1 << 2", {}, undef));
is("1 >> 2", ParseExpr("1 >> 2", {}, undef));
is("0x200", ParseExpr("0x200", {}, undef));
is("2?3:0", ParseExpr("2?3:0", {}, undef));
is("~0", ParseExpr("~0", {}, undef));
is("b->a->a", ParseExpr("a->a->a", {"a" => "b"}, undef));
is("b.a.a", ParseExpr("a.a.a", {"a" => "b"}, undef));

test_errors("nofile:0: Parse error in `~' near `~'\n", sub {
	is(undef, ParseExpr("~", {}, {FILE => "nofile", LINE => 0})); });

test_errors("nofile:0: Got pointer, expected integer\n", sub {
		is(undef, ParseExprExt("foo", {}, {FILE => "nofile", LINE => 0},
				         undef, sub { my $x = shift; 
							 error({FILE => "nofile", LINE => 0}, 
									 "Got pointer, expected integer");
							 return undef; }))});

is("b.a.a", ParseExpr("b.a.a", {"a" => "b"}, undef));
is("((rr_type) == NBT_QTYPE_NETBIOS)", ParseExpr("((rr_type)==NBT_QTYPE_NETBIOS)", {}, undef));
is("talloc_check_name", ParseExpr("talloc_check_name", {}, undef));
is("talloc_check_name()", ParseExpr("talloc_check_name()", {}, undef));
is("talloc_check_name(ndr)", ParseExpr("talloc_check_name(ndr)", {}, undef));
is("talloc_check_name(ndr, 1)", ParseExpr("talloc_check_name(ndr,1)", {}, undef));
is("talloc_check_name(ndr, \"struct ndr_push\")", ParseExpr("talloc_check_name(ndr,\"struct ndr_push\")", {}, undef));
is("((rr_type) == NBT_QTYPE_NETBIOS) && talloc_check_name(ndr, \"struct ndr_push\")", ParseExpr("((rr_type)==NBT_QTYPE_NETBIOS)&&talloc_check_name(ndr,\"struct ndr_push\")", {}, undef));
is("(rdata).data.length", ParseExpr("(rdata).data.length", {}, undef));
is("((rdata).data.length == 2)", ParseExpr("((rdata).data.length==2)", {}, undef));
is("((rdata).data.length == 2)?0:rr_type", ParseExpr("((rdata).data.length==2)?0:rr_type", {}, undef));
is("((((rr_type) == NBT_QTYPE_NETBIOS) && talloc_check_name(ndr, \"struct ndr_push\") && ((rdata).data.length == 2))?0:rr_type)", ParseExpr("((((rr_type)==NBT_QTYPE_NETBIOS)&&talloc_check_name(ndr,\"struct ndr_push\")&&((rdata).data.length==2))?0:rr_type)", {}, undef));
