#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 4;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Samba3::ClientNDR qw(GenerateFunctionInEnv ParseFunction $res 
    $res_hdr);

# Make sure GenerateFunctionInEnv and GenerateFunctionOutEnv work
my $fn = { ELEMENTS => [ { DIRECTION => ["in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionInEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["out", "in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionInEnv($fn));

$fn = { ELEMENTS => [ { DIRECTION => ["out"], NAME => "foo" } ] };
is_deeply({ }, GenerateFunctionInEnv($fn));

$fn = { NAME => "bar", ELEMENTS => [ ] };
ParseFunction("foo", $fn);
is($res, "NTSTATUS rpccli_bar(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx)
{
\tstruct bar r;
\tNTSTATUS status;
\t
\t/* In parameters */
\t
\tif (DEBUGLEVEL >= 10)
\t\tNDR_PRINT_IN_DEBUG(bar, &r);
\t
\tstatus = cli_do_rpc_ndr(cli, mem_ctx, PI_foo, DCERPC_BAR, &r, (ndr_pull_flags_fn_t)ndr_pull_bar, (ndr_push_flags_fn_t)ndr_push_bar);
\t
\tif (!NT_STATUS_IS_OK(status)) {
\t\treturn status;
\t}
\t
\tif (DEBUGLEVEL >= 10)
\t\tNDR_PRINT_OUT_DEBUG(bar, &r);
\t
\tif (NT_STATUS_IS_ERR(status)) {
\t\treturn status;
\t}
\t
\t/* Return variables */
\t
\t/* Return result */
\treturn NT_STATUS_OK;
}

");
