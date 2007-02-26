#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
# test parsing wireshark conformance files
use strict;
use warnings;

use Test::More tests => 11;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Wireshark::NDR qw(field2name %res PrintIdl StripPrefixes %hf_used RegisterInterfaceHandoff $conformance register_hf_field CheckUsed);

is("Access Mask", field2name("access_mask"));
is("Accessmask", field2name("AccessMask"));

$res{code} = "";
PrintIdl("foo\nbar\n");
is("/* IDL: foo */
/* IDL: bar */

", $res{code});

is("bla_foo", StripPrefixes("bla_foo", []));
is("foo", StripPrefixes("bla_foo", ["bla"]));
is("foo_bla", StripPrefixes("foo_bla", ["bla"]));

%hf_used = ();
$res{code} = "";
RegisterInterfaceHandoff({});
is($res{code}, "");
ok(not defined($hf_used{hf_bla_opnum}));

%hf_used = ();
$res{code} = "";
RegisterInterfaceHandoff({UUID => "uuid", NAME => "bla"});
is($res{code}, 'void proto_reg_handoff_dcerpc_bla(void)
{
	dcerpc_init_uuid(proto_dcerpc_bla, ett_dcerpc_bla,
		&uuid_dcerpc_bla, ver_dcerpc_bla,
		bla_dissectors, hf_bla_opnum);
}
');
is($hf_used{hf_bla_opnum}, 1);

$conformance = {};
register_hf_field("hf_bla_idx", "bla", "my.filter", "FT_UINT32", "BASE_HEX", "NULL", 0xF, undef);
is_deeply($conformance, {
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

%hf_used = ( hf_bla => 1 );
test_warnings("", sub { 
		CheckUsed({ header_fields => { INDEX => "hf_bla" }})});

%hf_used = ( );
test_warnings("nofile:0: hf field `hf_bla' not used\n", sub { 
		CheckUsed({ header_fields => { INDEX => "hf_bla" }})});
