#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
# test parsing wireshark conformance files
use strict;
use warnings;

use Test::More tests => 49;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Wireshark::Conformance qw(ReadConformanceFH valid_ft_type valid_base_type);

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

test_errors("nofile:1: incomplete INCLUDE command\n",
	sub { parse_conf("INCLUDE\n"); } );

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

is_deeply(parse_conf("TYPE winreg_String dissect_myminregstring(); FT_STRING BASE_DEC 0 0 2\n"), { types => { winreg_String => { 
				NAME => "winreg_String",
				POS => { FILE => "nofile", LINE => 1 },
				USED => 0,
				DISSECTOR_NAME => "dissect_myminregstring();",
				FT_TYPE => "FT_STRING",
				BASE_TYPE => "BASE_DEC",
				MASK => 0,
				VALSSTRING => 0,
				ALIGNMENT => 2}}});

ok(valid_ft_type("FT_UINT32"));
ok(not valid_ft_type("BLA"));
ok(not valid_ft_type("ft_uint32"));
ok(valid_ft_type("FT_BLA"));

ok(valid_base_type("BASE_DEC"));
ok(valid_base_type("BASE_HEX"));
ok(not valid_base_type("base_dec"));
ok(not valid_base_type("BLA"));
ok(not valid_base_type("BASEDEC"));

test_errors("nofile:1: incomplete TYPE command\n",
	sub { parse_conf("TYPE mytype dissector\n"); });

test_warnings("nofile:1: dissector name does not contain `dissect'\n",
	sub { parse_conf("TYPE winreg_String myminregstring; FT_STRING BASE_DEC 0 0 2\n"); });

test_warnings("nofile:1: invalid FT_TYPE `BLA'\n",
	sub { parse_conf("TYPE winreg_String dissect_myminregstring; BLA BASE_DEC 0 0 2\n"); });

test_warnings("nofile:1: invalid BASE_TYPE `BLOE'\n",
	sub { parse_conf("TYPE winreg_String dissect_myminregstring; FT_UINT32 BLOE 0 0 2\n"); });

is_deeply(parse_conf("TFS hf_bla \"True string\" \"False String\"\n"),
		{ tfs => { hf_bla => {
					TRUE_STRING => "\"True string\"",
				   FALSE_STRING => "\"False String\"" } } });

test_errors("nofile:1: incomplete TFS command\n",
	sub { parse_conf("TFS hf_bla \"Trues\""); } );

test_errors("nofile:1: incomplete PARAM_VALUE command\n",
	sub { parse_conf("PARAM_VALUE\n"); });

is_deeply(parse_conf("PARAM_VALUE Life 42\n"),
	{ dissectorparams => {
			Life => {
				DISSECTOR => "Life",
				POS => { FILE => "nofile", LINE => 1 },
				PARAM => 42,
				USED => 0
			}
		}
	});

is_deeply(parse_conf("STRIP_PREFIX bla_\n"),
	{ strip_prefixes => [ "bla_" ] });

is_deeply(parse_conf("STRIP_PREFIX bla_\nSTRIP_PREFIX bloe\n"),
	{ strip_prefixes => [ "bla_", "bloe" ] });

is_deeply(parse_conf("PROTOCOL atsvc \"Scheduling jobs on remote machines\" \"at\" \"atsvc\"\n"), 
	{ protocols => {
			atsvc => {
				LONGNAME => "\"Scheduling jobs on remote machines\"",
				SHORTNAME => "\"at\"",
				FILTERNAME => "\"atsvc\""
			}
		}
	}
);

is_deeply(parse_conf("IMPORT bla\n"), {
		imports => {
			bla => {
				NAME => "bla",
				DATA => "",
				USED => 0,
				POS => { FILE => "nofile", LINE => 1 }
			}
		}
	}
);

is_deeply(parse_conf("IMPORT bla fn1 fn2 fn3\n"), {
		imports => {
			bla => {
				NAME => "bla",
				DATA => "fn1 fn2 fn3",
				USED => 0,
				POS => { FILE => "nofile", LINE => 1 }
			}
		}
	}
);

test_errors("nofile:1: no dissectorname specified\n",
	sub { parse_conf("IMPORT\n"); } );

test_errors("nofile:1: incomplete HF_FIELD command\n",
	sub { parse_conf("HF_FIELD hf_idx\n"); });

test_errors("nofile:1: incomplete ETT_FIELD command\n",
	sub { parse_conf("ETT_FIELD\n"); });

is_deeply(parse_conf("TYPE winreg_String dissect_myminregstring(); FT_STRING BASE_DEC 0 0 0 2\n"), {
		types => {
			winreg_String => {
				NAME => "winreg_String",
				POS => { FILE => "nofile", LINE => 1 },
				USED => 0,
				DISSECTOR_NAME => "dissect_myminregstring();",
				FT_TYPE => "FT_STRING",
				BASE_TYPE => "BASE_DEC",
				MASK => 0,
				VALSSTRING => 0,
				ALIGNMENT => 0
			}
		}
	}
);


is_deeply(parse_conf("TYPE winreg_String \"offset = dissect_myminregstring(\@HF\@);\" FT_STRING BASE_DEC 0 0 0 2\n"), {
		types => {
			winreg_String => {
				NAME => "winreg_String",
				POS => { FILE => "nofile", LINE => 1 },
				USED => 0,
				DISSECTOR_NAME => "offset = dissect_myminregstring(\@HF\@);",
				FT_TYPE => "FT_STRING",
				BASE_TYPE => "BASE_DEC",
				MASK => 0,
				VALSSTRING => 0,
				ALIGNMENT => 0
			}
		}
	}
);
