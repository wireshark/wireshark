#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 9;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Samba3::ClientNDR qw(ParseFunction ParseOutputArgument);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv);

# Make sure GenerateFunctionInEnv and GenerateFunctionOutEnv work
my $fn = { ELEMENTS => [ { DIRECTION => ["in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionInEnv($fn, "r."));
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionOutEnv($fn, "r."));

$fn = { ELEMENTS => [ { DIRECTION => ["out", "in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionInEnv($fn, "r."));
is_deeply({ "foo" => "r.out.foo" }, GenerateFunctionOutEnv($fn, "r."));

$fn = { ELEMENTS => [ { DIRECTION => ["out"], NAME => "foo" } ] };
is_deeply({ }, GenerateFunctionInEnv($fn, "r."));
is_deeply({ "foo" => "r.out.foo" }, GenerateFunctionOutEnv($fn, "r."));

my $x = new Parse::Pidl::Samba3::ClientNDR();

$fn = { NAME => "bar", ELEMENTS => [ ] };
$x->ParseFunction("foo", $fn);
is($x->{res}, 
"NTSTATUS rpccli_bar(struct rpc_pipe_client *cli,
		    TALLOC_CTX *mem_ctx)
{
\tstruct bar r;
\tNTSTATUS status;

\t/* In parameters */

\tif (DEBUGLEVEL >= 10) {
\t\tNDR_PRINT_IN_DEBUG(bar, &r);
\t}

	status = cli->dispatch(cli,
				mem_ctx,
				&ndr_table_foo,
				NDR_BAR,
				&r);

\tif (!NT_STATUS_IS_OK(status)) {
\t\treturn status;
\t}

\tif (DEBUGLEVEL >= 10) {
\t\tNDR_PRINT_OUT_DEBUG(bar, &r);
\t}

\tif (NT_STATUS_IS_ERR(status)) {
\t\treturn status;
\t}

\t/* Return variables */

\t/* Return result */
\treturn NT_STATUS_OK;
}

");

$x = new Parse::Pidl::Samba3::ClientNDR();

$fn = { NAME => "bar", ELEMENTS => [ ], RETURN_TYPE => "WERROR" };
$x->ParseFunction("foo", $fn);
is($x->{res}, 
"NTSTATUS rpccli_bar(struct rpc_pipe_client *cli,
		    TALLOC_CTX *mem_ctx,
		    WERROR *werror)
{
\tstruct bar r;
\tNTSTATUS status;

\t/* In parameters */

\tif (DEBUGLEVEL >= 10) {
\t\tNDR_PRINT_IN_DEBUG(bar, &r);
\t}

	status = cli->dispatch(cli,
				mem_ctx,
				&ndr_table_foo,
				NDR_BAR,
				&r);

\tif (!NT_STATUS_IS_OK(status)) {
\t\treturn status;
\t}

\tif (DEBUGLEVEL >= 10) {
\t\tNDR_PRINT_OUT_DEBUG(bar, &r);
\t}

\tif (NT_STATUS_IS_ERR(status)) {
\t\treturn status;
\t}

\t/* Return variables */

\t/* Return result */
\tif (werror) {
\t\t*werror = r.out.result;
\t}

\treturn werror_to_ntstatus(r.out.result);
}

");

$x = new Parse::Pidl::Samba3::ClientNDR();

$fn = { NAME => "bar", ELEMENTS => [ ], RETURN_TYPE => "WERROR" };
my $e = { NAME => "foo", ORIGINAL => { FILE => "f", LINE => -1 },
          LEVELS => [ { TYPE => "ARRAY", SIZE_IS => "mysize" }, { TYPE => "DATA", DATA_TYPE => "int" } ]};

$x->ParseOutputArgument($fn, $e);
is($x->{res}, "memcpy(foo, r.out.foo, mysize * sizeof(*foo));\n");
