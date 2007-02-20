#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 6;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Samba4::TDR qw($ret $ret_hdr ParserType);

ParserType({TYPE => "STRUCT", NAME => "foo", PROPERTIES => {public => 1}}, "pull");
is($ret, "NTSTATUS tdr_pull_foo (struct tdr_pull *tdr, TALLOC_CTX *mem_ctx, struct foo *v)
{
	return NT_STATUS_OK;
}

");
is($ret_hdr, "NTSTATUS tdr_pull_foo (struct tdr_pull *tdr, TALLOC_CTX *mem_ctx, struct foo *v);\n");

$ret = ""; $ret_hdr = "";

ParserType({TYPE => "UNION", NAME => "bar", PROPERTIES => {public => 1}}, "pull");
is($ret, "NTSTATUS tdr_pull_bar(struct tdr_pull *tdr, TALLOC_CTX *mem_ctx, int level, union bar *v)
{
	switch (level) {
	}
	return NT_STATUS_OK;

}

");
is($ret_hdr, "NTSTATUS tdr_pull_bar(struct tdr_pull *tdr, TALLOC_CTX *mem_ctx, int level, union bar *v);\n");

$ret = ""; $ret_hdr = "";

ParserType({TYPE => "UNION", NAME => "bar", PROPERTIES => {}}, "pull");
is($ret, "static NTSTATUS tdr_pull_bar(struct tdr_pull *tdr, TALLOC_CTX *mem_ctx, int level, union bar *v)
{
	switch (level) {
	}
	return NT_STATUS_OK;

}

"); 
is($ret_hdr, "");
