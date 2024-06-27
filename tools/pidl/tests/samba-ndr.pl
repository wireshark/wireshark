#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 31;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Samba4::NDR::Parser qw(check_null_pointer 
	NeededFunction NeededElement NeededType
	NeededInterface TypeFunctionName ParseElementPrint); 

my $output;
sub print_fn($) { my $x = shift; $output.=$x; }

# Test case 1: Simple unique pointer dereference

$output = "";
my $fn = check_null_pointer({ 
	PARENT => {
		ELEMENTS => [
			{ 
				NAME => "bla",
				LEVELS => [
					{ TYPE => "POINTER",
					  POINTER_INDEX => 0,
					  POINTER_TYPE => "unique" },
					{ TYPE => "DATA" }
				],
			},
		]
	}
}, { bla => "r->in.bla" }, \&print_fn, "return;"); 


test_warnings("", sub { $fn->("r->in.bla"); });

is($output, "if (r->in.bla == NULL) return;");

# Test case 2: Simple ref pointer dereference

$output = "";
$fn = check_null_pointer({ 
	PARENT => {
		ELEMENTS => [
			{ 
				NAME => "bla",
				LEVELS => [
					{ TYPE => "POINTER",
					  POINTER_INDEX => 0,
					  POINTER_TYPE => "ref" },
					{ TYPE => "DATA" }
				],
			},
		]
	}
}, { bla => "r->in.bla" }, \&print_fn, undef); 

test_warnings("", sub { $fn->("r->in.bla"); });

is($output, "");

# Test case 3: Illegal dereference

$output = "";
$fn = check_null_pointer({ 
	FILE => "nofile",
	LINE => 1,
	PARENT => {
		ELEMENTS => [
			{ 
				NAME => "bla",
				LEVELS => [
					{ TYPE => "DATA" }
				],
			},
		]
	}
}, { bla => "r->in.bla" }, \&print_fn, undef); 

test_warnings("nofile:1: too much dereferences for `bla'\n", 
	          sub { $fn->("r->in.bla"); });

is($output, "");

# Test case 4: Double pointer dereference

$output = "";
$fn = check_null_pointer({ 
	PARENT => {
		ELEMENTS => [
			{ 
				NAME => "bla",
				LEVELS => [
					{ TYPE => "POINTER",
					  POINTER_INDEX => 0,
					  POINTER_TYPE => "unique" },
					{ TYPE => "POINTER",
					  POINTER_INDEX => 1,
					  POINTER_TYPE => "unique" },
					{ TYPE => "DATA" }
				],
			},
		]
	}
}, { bla => "r->in.bla" }, \&print_fn, "return;"); 

test_warnings("",
	          sub { $fn->("*r->in.bla"); });

is($output, "if (*r->in.bla == NULL) return;");

# Test case 5: Unknown variable

$output = "";
$fn = check_null_pointer({ 
	FILE => "nofile",
	LINE => 2,
	PARENT => {
		ELEMENTS => [
			{ 
				NAME => "bla",
				LEVELS => [
					{ TYPE => "DATA" }
				],
			},
		]
	}
}, { }, \&print_fn, "return;"); 

test_warnings("nofile:2: unknown dereferenced expression `r->in.bla'\n",
	          sub { $fn->("r->in.bla"); });

is($output, "if (r->in.bla == NULL) return;");

my $needed = {};
NeededElement({ TYPE => "foo", REPRESENTATION_TYPE => "foo" }, "pull", $needed); 
is_deeply($needed, { ndr_pull_foo => 1 });

# old settings should be kept
$needed = { ndr_pull_foo => 0 };
NeededElement({ TYPE => "foo", REPRESENTATION_TYPE => "foo" }, "pull", $needed); 
is_deeply($needed, { ndr_pull_foo => 0 });

# print/pull/push are independent of each other
$needed = { ndr_pull_foo => 0 };
NeededElement({ TYPE => "foo", REPRESENTATION_TYPE => "foo" }, "print", $needed); 
is_deeply($needed, { ndr_pull_foo => 0, ndr_print_foo => 1 });

$needed = { };
NeededFunction({ NAME => "foo", ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] }, $needed); 
is_deeply($needed, { ndr_pull_foo => 1, ndr_print_foo => 1, ndr_push_foo => 1,
	                 ndr_pull_bar => 1, ndr_print_bar => 1, ndr_push_bar => 1});

# push/pull/print are always set for functions
$needed = { ndr_pull_foo => 0 };
NeededFunction({ NAME => "foo", ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] }, $needed); 
is_deeply($needed, { ndr_pull_foo => 1, ndr_print_foo => 1, ndr_push_foo => 1,
	                 ndr_pull_bar => 1, ndr_push_bar => 1, ndr_print_bar => 1});

# public structs are always needed
$needed = {};
NeededType({ NAME => "bla", TYPE => "TYPEDEF",
		DATA => { TYPE => "STRUCT", ELEMENTS => [] } },
			  $needed, "pull");
is_deeply($needed, { });

$needed = {};
NeededInterface({ TYPES => [ { PROPERTIES => { public => 1 }, NAME => "bla", 
				TYPE => "TYPEDEF",
	            DATA => { TYPE => "STRUCT", ELEMENTS => [] } } ] },
			  $needed);
is_deeply($needed, { ndr_pull_bla => 1, ndr_push_bla => 1, ndr_print_bla => 1 });

# make sure types for elements are set too
$needed = {};
NeededInterface({ TYPES => [ { PROPERTIES => { public => 1 }, NAME => "bla", 
				TYPE => "TYPEDEF",
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] } } ] },
			  $needed);
is_deeply($needed, { ndr_pull_bla => 1, ndr_pull_bar => 1, ndr_push_bla => 1, ndr_push_bar => 1,
					 ndr_print_bla => 1, ndr_print_bar => 1});

$needed = {};
NeededInterface({ TYPES => [ { PROPERTIES => { gensize => 1}, NAME => "bla", 
				TYPE => "TYPEDEF",
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] } } ] },
			  $needed);
is_deeply($needed, { ndr_size_bla => 1 });
	                 
# make sure types for elements are set too
$needed = { ndr_pull_bla => 1 };
NeededType({ NAME => "bla", 
				TYPE => "TYPEDEF",
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] } },
			  $needed, "pull");
is_deeply($needed, { ndr_pull_bla => 1, ndr_pull_bar => 1 });

$needed = {};
NeededInterface({ TYPES => [ { PROPERTIES => { public => 1}, 
				NAME => "bla", 
				TYPE => "TYPEDEF",
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "rep" } ] } } ] }, $needed);
is_deeply($needed, { ndr_pull_bla => 1, ndr_push_bla => 1, ndr_print_bla => 1, 
					 ndr_print_rep => 1,
	                 ndr_pull_bar => 1, ndr_push_bar => 1, 
				     ndr_bar_to_rep => 1, ndr_rep_to_bar => 1});
	
my $generator = new Parse::Pidl::Samba4::NDR::Parser();
$generator->ParseStructPush({
			NAME => "mystruct",
			TYPE => "STRUCT",
			PROPERTIES => {},
			ALIGN => 4,
			ELEMENTS => [ ]}, "ndr", "x");
is($generator->{res}, "NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
if (ndr_flags & NDR_SCALARS) {
	NDR_CHECK(ndr_push_align(ndr, 4));
	NDR_CHECK(ndr_push_trailer_align(ndr, 4));
}
if (ndr_flags & NDR_BUFFERS) {
}
");

$generator = new Parse::Pidl::Samba4::NDR::Parser();
my $e = { 
	NAME => "el1", 
	TYPE => "mytype",
	REPRESENTATION_TYPE => "mytype",
	PROPERTIES => {},
	LEVELS => [ 
		{ LEVEL_INDEX => 0, TYPE => "DATA", DATA_TYPE => "mytype" } 
] };
$generator->ParseStructPush({
			NAME => "mystruct",
			TYPE => "STRUCT",
			PROPERTIES => {},
			ALIGN => 4,
			SURROUNDING_ELEMENT => $e,
			ELEMENTS => [ $e ]}, "ndr", "x");
is($generator->{res}, "NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
if (ndr_flags & NDR_SCALARS) {
	NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_string_array_size(ndr, x->el1)));
	NDR_CHECK(ndr_push_align(ndr, 4));
	NDR_CHECK(ndr_push_mytype(ndr, NDR_SCALARS, &x->el1));
	NDR_CHECK(ndr_push_trailer_align(ndr, 4));
}
if (ndr_flags & NDR_BUFFERS) {
}
");

is(TypeFunctionName("ndr_pull", "uint32"), "ndr_pull_uint32");
is(TypeFunctionName("ndr_pull", {TYPE => "ENUM", NAME => "bar"}), "ndr_pull_ENUM_bar");
is(TypeFunctionName("ndr_pull", {TYPE => "TYPEDEF", NAME => "bar", DATA => undef}), "ndr_pull_bar");
is(TypeFunctionName("ndr_push", {TYPE => "STRUCT", NAME => "bar"}), "ndr_push_STRUCT_bar");

# check noprint works
$generator = new Parse::Pidl::Samba4::NDR::Parser();
$generator->ParseElementPrint({ NAME => "x", TYPE => "rt", REPRESENTATION_TYPE => "rt", 
				    PROPERTIES => { noprint => 1},
				    LEVELS => [ { TYPE => "DATA", DATA_TYPE => "rt"} ]},
				    "ndr", "var", { "x" => "r->foobar" } );
is($generator->{res}, "");

$generator = new Parse::Pidl::Samba4::NDR::Parser();
$generator->ParseElementPrint({ NAME => "x", TYPE => "rt", REPRESENTATION_TYPE => "rt", 
				    PROPERTIES => {},
				    LEVELS => [ { TYPE => "DATA", DATA_TYPE => "rt" }]},
				    "ndr", "var", { "x" => "r->foobar" } );
is($generator->{res}, "ndr_print_rt(ndr, \"x\", &var);\n");

# make sure that a print function for an element with value() set works
$generator = new Parse::Pidl::Samba4::NDR::Parser();
$generator->ParseElementPrint({ NAME => "x", TYPE => "uint32", REPRESENTATION_TYPE => "uint32", 
				    PROPERTIES => { value => "23" },
				    LEVELS => [ { TYPE => "DATA", DATA_TYPE => "uint32"} ]},
				    "ndr", "var", { "x" => "r->foobar" } );
is($generator->{res}, "ndr_print_uint32(ndr, \"x\", (ndr->flags & LIBNDR_PRINT_SET_VALUES)?23:var);\n");

$generator = new Parse::Pidl::Samba4::NDR::Parser();
$generator->AuthServiceStruct("bridge", "\"rot13\",\"onetimepad\"");
is($generator->{res}, "static const char * const bridge_authservice_strings[] = {
	\"rot13\", 
	\"onetimepad\", 
};

static const struct ndr_interface_string_array bridge_authservices = {
	.count	= 2,
	.names	= bridge_authservice_strings
};

");
