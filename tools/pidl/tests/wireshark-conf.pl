#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
# test parsing wireshark conformance files
use strict;
use warnings;

use Test::More tests => 20;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Wireshark::Conformance qw(ReadConformanceFH);

sub parse_conf($)
{
	my $str = shift;
    open(TMP, "+>", undef) or die("unable to open temp file");
	print TMP $str;
	seek(TMP, 0, 0);
	my $data = {};
	ReadConformanceFH(*TMP, $data, "nofile") or return undef;
	close(TMP);
	return $data;
}

ok(parse_conf("\n"), undef);
ok(parse_conf(" \n"), undef);
ok(parse_conf("CODE START\nCODE END\n"));
test_warnings("nofile:1: Expecting CODE END\n", sub { is(parse_conf("CODE START\n"), undef); });
ok(parse_conf("#foobar\n"), undef);
test_warnings("nofile:1: Unknown command `foobar'\n",
	sub { ok(parse_conf("foobar\n"), undef); });

test_warnings("nofile:1: incomplete HF_RENAME command\n",
	sub { parse_conf("HF_RENAME\n"); });


is_deeply(parse_conf("HF_RENAME foo bar\n")->{hf_renames}->{foo}, 
	{ OLDNAME => "foo", NEWNAME => "bar", POS => {FILE => "nofile", LINE => 1}, USED => 0});

is_deeply(parse_conf("NOEMIT\n"), { "noemit_dissector" => 1 });
is_deeply(parse_conf("NOEMIT foo\n"), { "noemit" => { "foo" => 1 } });

test_warnings("nofile:1: incomplete MANUAL command\n",
	sub { parse_conf("MANUAL\n"); } );

is_deeply(parse_conf("MANUAL foo\n"), { manual => {foo => 1}});

test_warnings("nofile:1: incomplete FIELD_DESCRIPTION command\n",
	sub { parse_conf("FIELD_DESCRIPTION foo\n"); });

is_deeply(parse_conf("FIELD_DESCRIPTION foo \"my description\"\n"),
	{ fielddescription => { foo => { DESCRIPTION => "\"my description\"", POS => { FILE => "nofile", LINE => 1}, USED => 0 }}});

is_deeply(parse_conf("FIELD_DESCRIPTION foo my description\n"),
	{ fielddescription => { foo => { DESCRIPTION => "my", POS => { FILE => "nofile", LINE => 1}, USED => 0 }}});

is_deeply(parse_conf("CODE START\ndata\nCODE END\n"), { override => "data\n" });
is_deeply(parse_conf("CODE START\ndata\nmore data\nCODE END\n"), { override => "data\nmore data\n" });
test_warnings("nofile:1: Unknown command `CODE'\n",
	sub { parse_conf("CODE END\n"); } );
