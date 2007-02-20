#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 34;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Samba4::NDR::Parser qw(check_null_pointer 
	GenerateFunctionInEnv GenerateFunctionOutEnv GenerateStructEnv 
	EnvSubstituteValue NeededFunction NeededElement NeededType $res); 

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

# Make sure GenerateFunctionInEnv and GenerateFunctionOutEnv work
$fn = { ELEMENTS => [ { DIRECTION => ["in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r->in.foo" }, GenerateFunctionInEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["out"], NAME => "foo" } ] };
is_deeply({ "foo" => "r->out.foo" }, GenerateFunctionOutEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["out", "in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r->in.foo" }, GenerateFunctionInEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["out", "in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r->out.foo" }, GenerateFunctionOutEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r->in.foo" }, GenerateFunctionOutEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["out"], NAME => "foo" } ] };
is_deeply({ }, GenerateFunctionInEnv($fn));

$fn = { ELEMENTS => [ { NAME => "foo" }, { NAME => "bar" } ] };
is_deeply({ foo => "r->foo", bar => "r->bar", this => "r" }, 
		GenerateStructEnv($fn, "r"));

$fn = { ELEMENTS => [ { NAME => "foo" }, { NAME => "bar" } ] };
is_deeply({ foo => "some->complex.variable->foo", 
		    bar => "some->complex.variable->bar", 
			this => "some->complex.variable" }, 
		GenerateStructEnv($fn, "some->complex.variable"));

$fn = { ELEMENTS => [ { NAME => "foo", PROPERTIES => { value => 3 }} ] };

my $env = GenerateStructEnv($fn, "r");
EnvSubstituteValue($env, $fn);
is_deeply($env, { foo => 3, this => "r" });

$fn = { ELEMENTS => [ { NAME => "foo" }, { NAME => "bar" } ] };
$env = GenerateStructEnv($fn, "r");
EnvSubstituteValue($env, $fn);
is_deeply($env, { foo => 'r->foo', bar => 'r->bar', this => "r" });

$fn = { ELEMENTS => [ { NAME => "foo", PROPERTIES => { value => 0 }} ] };

$env = GenerateStructEnv($fn, "r");
EnvSubstituteValue($env, $fn);
is_deeply($env, { foo => 0, this => "r" });

my $needed = {};
NeededElement({ TYPE => "foo", REPRESENTATION_TYPE => "foo" }, "pull", $needed); 
is_deeply($needed, { pull_foo => 1 });

# old settings should be kept
$needed = { pull_foo => 0 };
NeededElement({ TYPE => "foo", REPRESENTATION_TYPE => "foo" }, "pull", $needed); 
is_deeply($needed, { pull_foo => 0 });

# print/pull/push are independent of each other
$needed = { pull_foo => 0 };
NeededElement({ TYPE => "foo", REPRESENTATION_TYPE => "foo" }, "print", $needed); 
is_deeply($needed, { pull_foo => 0, print_foo => 1 });

$needed = { };
NeededFunction({ NAME => "foo", ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] }, $needed); 
is_deeply($needed, { pull_foo => 1, print_foo => 1, push_foo => 1,
	                 pull_bar => 1, print_bar => 1, push_bar => 1});

# push/pull/print are always set for functions
$needed = { pull_foo => 0 };
NeededFunction({ NAME => "foo", ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] }, $needed); 
is_deeply($needed, { pull_foo => 1, print_foo => 1, push_foo => 1,
	                 pull_bar => 1, push_bar => 1, print_bar => 1});

# public structs are always needed
$needed = {};
NeededType({ NAME => "bla", DATA => { TYPE => "STRUCT", ELEMENTS => [] } },
			  $needed);
is_deeply($needed, { });

$needed = {};
NeededType({ PROPERTIES => { public => 1 }, NAME => "bla", 
	            DATA => { TYPE => "STRUCT", ELEMENTS => [] } },
			  $needed);
is_deeply($needed, { pull_bla => 1, print_bla => 1, push_bla => 1 });

# make sure types for elements are set too
$needed = {};
NeededType({ PROPERTIES => { public => 1 }, NAME => "bla", 
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] } },
			  $needed);
is_deeply($needed, { pull_bla => 1, print_bla => 1, push_bla => 1,
	                 pull_bar => 1, print_bar => 1, push_bar => 1});

$needed = {};
NeededType({ PROPERTIES => { gensize => 1}, NAME => "bla", 
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] } },
			  $needed);
is_deeply($needed, { ndr_size_bla => 1 });
	                 
# make sure types for elements are set too
$needed = { pull_bla => 1 };
NeededType({ NAME => "bla", 
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "bar" } ] } },
			  $needed);
is_deeply($needed, { pull_bla => 1, pull_bar => 1 });

$needed = {};
NeededType({ PROPERTIES => { public => 1}, 
				NAME => "bla", 
	            DATA => { TYPE => "STRUCT", 
						  ELEMENTS => [ { TYPE => "bar", REPRESENTATION_TYPE => "rep" } ] } },
			  $needed);
is_deeply($needed, { pull_bla => 1, push_bla => 1, print_bla => 1, print_rep => 1,
	                 pull_bar => 1, push_bar => 1, 
				     ndr_bar_to_rep => 1, ndr_rep_to_bar => 1});
	
$res = "";
Parse::Pidl::Samba4::NDR::Parser::ParseStructPush({
			NAME => "mystruct",
			TYPE => "STRUCT",
			PROPERTIES => {},
			ALIGN => 4,
			ELEMENTS => [ ]}, "x");
is($res, "if (ndr_flags & NDR_SCALARS) {
	NDR_CHECK(ndr_push_align(ndr, 4));
}
if (ndr_flags & NDR_BUFFERS) {
}
");

$res = "";
my $e = { 
	NAME => "el1", 
	TYPE => "mytype",
	REPRESENTATION_TYPE => "mytype",
	PROPERTIES => {},
	LEVELS => [ 
		{ LEVEL_INDEX => 0, TYPE => "DATA", DATA_TYPE => "mytype" } 
] };
Parse::Pidl::Samba4::NDR::Parser::ParseStructPush({
			NAME => "mystruct",
			TYPE => "STRUCT",
			PROPERTIES => {},
			ALIGN => 4,
			SURROUNDING_ELEMENT => $e,
			ELEMENTS => [ $e ]}, "x");
is($res, "if (ndr_flags & NDR_SCALARS) {
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_string_array_size(ndr, x->el1)));
	NDR_CHECK(ndr_push_align(ndr, 4));
	NDR_CHECK(ndr_push_mytype(ndr, NDR_SCALARS, &x->el1));
}
if (ndr_flags & NDR_BUFFERS) {
}
");
