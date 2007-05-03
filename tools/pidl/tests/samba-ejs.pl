#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 17;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Samba4::EJS qw(get_pointer_to get_value_of check_null_pointer
        fn_declare TypeFunctionName);

is("&foo", get_pointer_to("foo"));
is("&(&foo)", get_pointer_to(get_pointer_to("foo")));
is("*foo", get_pointer_to("**foo"));
is("foo", get_pointer_to("*foo"));

is("foo", get_value_of("&foo"));
is("*foo", get_value_of("foo"));
is("**foo", get_value_of("*foo"));

my $ejs = new Parse::Pidl::Samba4::EJS();

$ejs->check_null_pointer("bla");
is($ejs->{res}, "");

$ejs = new Parse::Pidl::Samba4::EJS();
$ejs->check_null_pointer("*bla");
is($ejs->{res}, "if (bla == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;\n");

$ejs = new Parse::Pidl::Samba4::EJS();
$ejs->fn_declare({ PROPERTIES => { public => 1 } }, "myproto(int x)");
is($ejs->{res}, "_PUBLIC_ myproto(int x)\n");
is($ejs->{res_hdr}, "myproto(int x);\n");

$ejs = new Parse::Pidl::Samba4::EJS();
$ejs->fn_declare({ PROPERTIES => {} }, "mybla(int foo)");
is($ejs->{res}, "static mybla(int foo)\n");
is($ejs->{res_hdr}, "");

is(TypeFunctionName("ejs_pull", "uint32"), "ejs_pull_uint32");
is(TypeFunctionName("ejs_pull", {TYPE => "ENUM", NAME => "bar"}), "ejs_pull_ENUM_bar");
is(TypeFunctionName("ejs_pull", {TYPE => "TYPEDEF", NAME => "bar", DATA => undef}), "ejs_pull_bar");
is(TypeFunctionName("ejs_push", {TYPE => "STRUCT", NAME => "bar"}), "ejs_push_STRUCT_bar");
