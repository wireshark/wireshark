#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
# test parsing wireshark conformance files
use strict;
use warnings;

use Test::More tests => 40;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use strict;
use Parse::Pidl::Wireshark::NDR qw(field2name %res PrintIdl StripPrefixes RegisterInterfaceHandoff register_hf_field ProcessImport ProcessInclude find_type DumpEttList DumpEttDeclaration DumpHfList DumpHfDeclaration DumpFunctionTable register_type register_ett);

is("Access Mask", field2name("access_mask"));
is("AccessMask", field2name("AccessMask"));

my $x = new Parse::Pidl::Wireshark::NDR();
$x->PrintIdl("foo\nbar\n");
is("/* IDL: foo */
/* IDL: bar */

", $x->{res}->{code});

is("bla_foo", StripPrefixes("bla_foo", []));
is("foo", StripPrefixes("bla_foo", ["bla"]));
is("foo_bla", StripPrefixes("foo_bla", ["bla"]));

$x = new Parse::Pidl::Wireshark::NDR();
$x->RegisterInterfaceHandoff({});
is($x->{res}->{code}, "");
ok(not defined($x->{hf_used}->{hf_bla_opnum}));

$x = new Parse::Pidl::Wireshark::NDR();
$x->{res}->{code} = "";
$x->RegisterInterfaceHandoff({UUID => "uuid", NAME => "bla"});
is($x->{res}->{code}, 'void proto_reg_handoff_dcerpc_bla(void)
{
	dcerpc_init_uuid(proto_dcerpc_bla, ett_dcerpc_bla,
		&uuid_dcerpc_bla, ver_dcerpc_bla,
		bla_dissectors, hf_bla_opnum);
}
');
is($x->{hf_used}->{hf_bla_opnum}, 1);

$x->{conformance} = {};
is("hf_bla_idx", 
	$x->register_hf_field("hf_bla_idx", "bla", "my.filter", "FT_UINT32", "BASE_HEX", "NULL", 0xF, undef));
is_deeply($x->{conformance}, {
		header_fields => {
			"hf_bla_idx" => {
				INDEX => "hf_bla_idx",
				NAME => "bla",
				FILTER => "my.filter",
				BASE_TYPE => "BASE_HEX",
				FT_TYPE => "FT_UINT32",
				VALSSTRING => "NULL",
				BLURB => undef,
				MASK => 0xF
			}
		},
		hf_renames => {},
		fielddescription => {}
});

$x->{conformance} = { fielddescription => { hf_bla_idx => { DESCRIPTION => "Some Description" }}};
is("hf_bla_idx",
	$x->register_hf_field("hf_bla_idx", "bla", "my.filter", "FT_UINT32", "BASE_HEX", "NULL", 0xF, undef));
is_deeply($x->{conformance}, {
		fielddescription => { 
			hf_bla_idx => {
				DESCRIPTION => "Some Description",
				USED => 1
			}
		},
		header_fields => {
			"hf_bla_idx" => {
				INDEX => "hf_bla_idx",
				NAME => "bla",
				FILTER => "my.filter",
				BASE_TYPE => "BASE_HEX",
				FT_TYPE => "FT_UINT32",
				VALSSTRING => "NULL",
				BLURB => "Some Description",
				MASK => 0xF
			}
		},
		hf_renames => {},
});

$x->{conformance} = { fielddescription => { hf_bla_idx => { DESCRIPTION => "Some Description" }}};
is("hf_bla_idx",
	$x->register_hf_field("hf_bla_idx", "bla", "my.filter", "FT_UINT32", "BASE_HEX", "NULL", 0xF, 
		"Actual Description"));
is_deeply($x->{conformance}, {
		fielddescription => { 
			hf_bla_idx => { DESCRIPTION => "Some Description" }
		},
		header_fields => {
			"hf_bla_idx" => {
				INDEX => "hf_bla_idx",
				NAME => "bla",
				FILTER => "my.filter",
				BASE_TYPE => "BASE_HEX",
				FT_TYPE => "FT_UINT32",
				VALSSTRING => "NULL",
				BLURB => "Actual Description",
				MASK => 0xF
			}
		},
		hf_renames => {},
});



$x->{conformance} = { hf_renames => { "hf_bla_idx" => { NEWNAME => "hf_bloe_idx" } } };
$x->register_hf_field("hf_bla_idx", "bla", "my.filter", "FT_UINT32", "BASE_HEX", "NULL", 0xF, undef);
is_deeply($x->{conformance}, {
		hf_renames => { hf_bla_idx => { USED => 1, NEWNAME => "hf_bloe_idx" } } });

$x->{hf_used} = { hf_bla => 1 };
test_warnings("", sub { 
		$x->CheckUsed({ header_fields => { foo => { INDEX => "hf_bla" }}})});

$x->{hf_used} = { };
test_warnings("hf field `hf_bla' not used\n", sub { 
		$x->CheckUsed({ header_fields => { foo => { INDEX => "hf_bla" }}})});

test_warnings("hf field `hf_id' not used\n", 
	sub { $x->CheckUsed({
	hf_renames => {
		hf_id => {
			OLDNAME => "hf_id",
			NEWNAME => "hf_newid",
			USED => 0
		}
	}
}); } );

test_warnings("dissector param never used\n",
	sub { $x->CheckUsed({
	dissectorparams => {
		dissect_foo => {
			PARAM => 42,
			USED => 0
		}
	}
}); } );

test_warnings("description never used\n",
	sub { $x->CheckUsed({
	fielddescription => {
		hf_bla => {
			USED => 0
		}
	}
}); } );

test_warnings("import never used\n",
	sub { $x->CheckUsed({
	imports => {
		bla => {
			USED => 0
		}
	}
}); } );

test_warnings("nofile:1: type never used\n",
	sub { $x->CheckUsed({
	types => {
		bla => {
			USED => 0,
			POS => { FILE => "nofile", LINE => 1 } 
		}
	}
}); } );

test_warnings("True/False description never used\n",
	sub { $x->CheckUsed({
	tfs => {
		hf_bloe => {
			USED => 0
		}
	}
}); } );

$x = new Parse::Pidl::Wireshark::NDR();
$x->ProcessImport("security", "bla");
is($x->{res}->{hdr}, "#include \"packet-dcerpc-bla.h\"\n\n");

$x = new Parse::Pidl::Wireshark::NDR();
$x->ProcessImport("\"bla.idl\"", "\"foo.idl\"");
is($x->{res}->{hdr}, "#include \"packet-dcerpc-bla.h\"\n" . 
              "#include \"packet-dcerpc-foo.h\"\n\n");

$x = new Parse::Pidl::Wireshark::NDR();
$x->ProcessInclude("foo.h", "bla.h", "bar.h");
is($x->{res}->{hdr}, "#include \"foo.h\"\n" . 
	          "#include \"bla.h\"\n" . 
			  "#include \"bar.h\"\n\n");
	
$x->{conformance} = {types => { bla => "brainslug" } };
is("brainslug", $x->find_type("bla"));

is(DumpEttList(["ett_t1", "ett_bla"]), 
	"\tstatic gint *ett[] = {\n" . 
	"\t\t&ett_t1,\n" .
	"\t\t&ett_bla,\n" .
	"\t};\n");

is(DumpEttList(), "\tstatic gint *ett[] = {\n\t};\n");
is(DumpEttList(["bla"]), "\tstatic gint *ett[] = {\n\t\t&bla,\n\t};\n");

is(DumpEttDeclaration(["void", "zoid"]), 
	"\n/* Ett declarations */\n" . 
	"static gint void = -1;\n" .
	"static gint zoid = -1;\n" .
	"\n");

is(DumpEttDeclaration(), "\n/* Ett declarations */\n\n");

$x->{conformance} = {
	header_fields => {
		hf_bla => { INDEX => "hf_bla", NAME => "Bla", FILTER => "bla.field", FT_TYPE => "FT_UINT32", BASE_TYPE => "BASE_DEC", VALSSTRING => "NULL", MASK => 0xFF, BLURB => "NULL" } 
	} 
};

is($x->DumpHfList(), "\tstatic hf_register_info hf[] = {
	{ &hf_bla,
	  { \"Bla\", \"bla.field\", FT_UINT32, BASE_DEC, NULL, 255, \"NULL\", HFILL }},
	};
");

is($x->DumpHfDeclaration(), "
/* Header field declarations */
static gint hf_bla = -1;

");

is(DumpFunctionTable({
			NAME => "someif",
			FUNCTIONS => [ { NAME => "fn1", OPNUM => 3 }, { NAME => "someif_fn2", OPNUM => 2 } ] }),
'static dcerpc_sub_dissector someif_dissectors[] = {
	{ 3, "fn1",
	   someif_dissect_fn1_request, someif_dissect_fn1_response},
	{ 2, "fn2",
	   someif_dissect_fn2_request, someif_dissect_fn2_response},
	{ 0, NULL, NULL, NULL }
};
');

$x->{conformance} = {};
$x->register_type("bla_type", "dissect_bla", "FT_UINT32", "BASE_HEX", 0xFF, "NULL", 4);
is_deeply($x->{conformance}, {
		types => {
			bla_type => {
				NAME => "bla_type",
				DISSECTOR_NAME => "dissect_bla",
				FT_TYPE => "FT_UINT32",
				BASE_TYPE => "BASE_HEX",
				MASK => 255,
				VALSSTRING => "NULL",
				ALIGNMENT => 4
			}
		}
	}
);

$x->{ett} = [];
$x->register_ett("name");
is_deeply($x->{ett}, ["name"]);
$x->register_ett("leela");
is_deeply($x->{ett}, ["name", "leela"]);
