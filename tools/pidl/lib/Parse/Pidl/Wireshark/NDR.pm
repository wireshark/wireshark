##################################################
# Wireshark NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001,2005
# Copyright jelmer@samba.org 2004-2007
# Portions based on idl2eth.c by Ronnie Sahlberg
# released under the GNU GPL

=pod

=head1 NAME

Parse::Pidl::Wireshark::NDR - Parser generator for Wireshark

=cut

package Parse::Pidl::Wireshark::NDR;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(field2name %res PrintIdl StripPrefixes RegisterInterfaceHandoff register_hf_field CheckUsed ProcessImport ProcessInclude find_type DumpEttList DumpEttDeclaration DumpHfList DumpHfDeclaration DumpFunctionTable register_type register_ett);

use strict;
use Parse::Pidl qw(error warning);
use Parse::Pidl::Typelist qw(getType);
use Parse::Pidl::Util qw(has_property property_matches make_str);
use Parse::Pidl::NDR qw(ContainsString GetNextLevel);
use Parse::Pidl::Dump qw(DumpType DumpFunction);
use Parse::Pidl::Wireshark::Conformance qw(ReadConformance);
use File::Basename;

use vars qw($VERSION);
$VERSION = '0.01';

my %return_types = ();
my %dissector_used = ();

my %ptrtype_mappings = (
	"unique" => "NDR_POINTER_UNIQUE",
	"ref" => "NDR_POINTER_REF",
	"ptr" => "NDR_POINTER_PTR"
);

sub StripPrefixes($$)
{
	my ($s, $prefixes) = @_;

	foreach (@$prefixes) {
		$s =~ s/^$_\_//g;
	}

	return $s;
}

# Convert a IDL structure field name (e.g access_mask) to a prettier
# string like 'Access Mask'.

sub field2name($)
{
	my($field) = shift;

	$field =~ s/^(_)*//g;		# Remove any starting underscores
	$field =~ s/_/ /g;		# Replace underscores with spaces
	$field =~ s/(\w+)/\u\L$1/g;	# Capitalise each word

	return $field;
}

sub new($)
{
	my ($class) = @_;
	my $self = {res => {hdr => "", def => "", code => ""}, tabs => "", cur_fn => undef,
		hf_used => {}, ett => [], conformance => undef

	};
	bless($self, $class);
}

sub pidl_fn_start($$)
{
	my ($self, $fn) = @_;
	$self->{cur_fn} = $fn;
}
sub pidl_fn_end($$)
{
	my ($self, $fn) = @_;
	die("Inconsistent state: $fn != $self->{cur_fn}") if ($fn ne $self->{cur_fn});
	$self->{cur_fn} = undef;
}

sub pidl_code($$)
{
	my ($self, $d) = @_;
	return if (defined($self->{cur_fn}) and defined($self->{conformance}->{manual}->{$self->{cur_fn}}));

	if ($d) {
		$self->{res}->{code} .= $self->{tabs};
		$self->{res}->{code} .= $d;
	}
	$self->{res}->{code} .="\n";
}

sub pidl_hdr($$) { my ($self,$x) = @_; $self->{res}->{hdr} .= "$x\n"; }
sub pidl_def($$) { my ($self,$x) = @_; $self->{res}->{def} .= "$x\n"; }

sub indent($)
{
	my ($self) = @_;
	$self->{tabs} .= "\t";
}

sub deindent($)
{
	my ($self) = @_;
	$self->{tabs} = substr($self->{tabs}, 0, -1);
}

sub PrintIdl($$)
{
	my ($self, $idl) = @_;

	foreach (split /\n/, $idl) {
		$self->pidl_code("/* IDL: $_ */");
	}

	$self->pidl_code("");
}

#####################################################################
# parse the interface definitions
sub Interface($$)
{
	my($self, $interface) = @_;
	$self->Const($_,$interface->{NAME}) foreach (@{$interface->{CONSTS}});
	$self->Type($_, $_->{NAME}, $interface->{NAME}) foreach (@{$interface->{TYPES}});
	$self->Function($_,$interface->{NAME}) foreach (@{$interface->{FUNCTIONS}});
}

sub Enum($$$$)
{
	my ($self, $e,$name,$ifname) = @_;
	my $valsstring = "$ifname\_$name\_vals";
	my $dissectorname = "$ifname\_dissect\_enum\_".StripPrefixes($name, $self->{conformance}->{strip_prefixes});

	return if (defined($self->{conformance}->{noemit}->{StripPrefixes($name, $self->{conformance}->{strip_prefixes})}));

	foreach (@{$e->{ELEMENTS}}) {
		if (/([^=]*)=(.*)/) {
			$self->pidl_hdr("#define $1 ($2)");
		}
	}

	$self->pidl_hdr("extern const value_string $valsstring\[];");
	$self->pidl_hdr("int $dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, g$e->{BASE_TYPE} *param _U_);");

	$self->pidl_def("const value_string ".$valsstring."[] = {");
	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^=]*)=(.*)/);
		$self->pidl_def("\t{ $1, \"$1\" },");
	}

	$self->pidl_def("{ 0, NULL }");
	$self->pidl_def("};");

	$self->pidl_fn_start($dissectorname);
	$self->pidl_code("int");
	$self->pidl_code("$dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, g$e->{BASE_TYPE} *param _U_)");
	$self->pidl_code("{");
	$self->indent;
	$self->pidl_code("g$e->{BASE_TYPE} parameter=0;");
	$self->pidl_code("if (param) {");
	$self->indent;
	$self->pidl_code("parameter = *param;");
	$self->deindent;
	$self->pidl_code("}");
	$self->pidl_code("offset = dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);");
	$self->pidl_code("if (param) {");
	$self->indent;
	$self->pidl_code("*param = parameter;");
	$self->deindent;
	$self->pidl_code("}");
	$self->pidl_code("return offset;");
	$self->deindent;
	$self->pidl_code("}\n");
	$self->pidl_fn_end($dissectorname);

	my $enum_size = $e->{BASE_TYPE};
	$enum_size =~ s/uint//g;
	$self->register_type($name, "offset = $dissectorname(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);", "FT_UINT$enum_size", "BASE_DEC", "0", "VALS($valsstring)", $enum_size / 8);
}

sub Pipe($$$$)
{
	my ($self,$e,$name,$ifname) = @_;
	error($e->{ORIGINAL}, "Pipe not yet supported");
	return;
}

sub Bitmap($$$$)
{
	my ($self,$e,$name,$ifname) = @_;
	my $dissectorname = "$ifname\_dissect\_bitmap\_".StripPrefixes($name, $self->{conformance}->{strip_prefixes});
	my $element_count = 0;
	my $total_ev = 0;

	$self->register_ett("ett_$ifname\_$name");

	$self->pidl_hdr("int $dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);");

	$self->pidl_fn_start($dissectorname);
	$self->pidl_code("int");
	$self->pidl_code("$dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)");
	$self->pidl_code("{");
	$self->indent;
	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^ ]*) (.*)/);
		$element_count++;
	}
	if ($element_count > 0) {
		$self->pidl_code("proto_item *item;");
		$self->pidl_code("static const int * $ifname\_$name\_fields[] = {");
		$self->indent;
		foreach (@{$e->{ELEMENTS}}) {
			next unless (/([^ ]*) (.*)/);
			my ($en,$ev) = ($1,$2);
			my $hf_bitname = "hf_$ifname\_$name\_$1";

			$ev =~ s/[()\s]//g;
			if (hex($ev) != 0) {
				$total_ev += hex($ev);
				$self->pidl_code("&$hf_bitname,");
			}
		}
		$self->pidl_code("NULL");
		$self->deindent;
		$self->pidl_code("};");
	}

	$self->pidl_code("g$e->{BASE_TYPE} flags;");
	if ($e->{ALIGN} > 1) {
		$self->pidl_code("ALIGN_TO_$e->{ALIGN}_BYTES;");
	}

	$self->pidl_code("");

	if ($element_count > 0) {
		$self->pidl_code("item = proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_index,");
		$self->pidl_code("\t\t\tett_$ifname\_$name, $ifname\_$name\_fields, DREP_ENC_INTEGER(drep), BMT_NO_FALSE);");
		$self->pidl_code("");

		$self->pidl_code("offset = dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, parent_tree, di, drep, -1, &flags);");
		$self->pidl_code("");

		$self->pidl_code("if (!flags)");
		$self->pidl_code("\tproto_item_append_text(item, \": (No values set)\");\n");
	} else {
		$self->pidl_code("proto_tree_add_item(parent_tree, hf_index, tvb, offset, $e->{ALIGN}, DREP_ENC_INTEGER(drep));");
		$self->pidl_code("");

		$self->pidl_code("offset = dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, parent_tree, di, drep, -1, &flags);");
		$self->pidl_code("");
	}

	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^ ]*) (.*)/);
		my ($en,$ev) = ($1,$2);
		my $hf_bitname = "hf_$ifname\_$name\_$en";
		my $filtername = "$ifname\.$name\.$en";

		$self->{hf_used}->{$hf_bitname} = 1;

		$ev =~ s/[()\s]//g;
		if (hex($ev) != 0) {
			$self->register_hf_field($hf_bitname, field2name($en), $filtername, "FT_BOOLEAN", $e->{ALIGN} * 8, "TFS(&$name\_$en\_tfs)", "( $ev )", "");

			$self->pidl_def("static const true_false_string $name\_$en\_tfs = {");
			if (defined($self->{conformance}->{tfs}->{$hf_bitname})) {
				$self->pidl_def("   $self->{conformance}->{tfs}->{$hf_bitname}->{TRUE_STRING},");
				$self->pidl_def("   $self->{conformance}->{tfs}->{$hf_bitname}->{FALSE_STRING},");
				$self->{conformance}->{tfs}->{$hf_bitname}->{USED} = 1;
			} else {
				$self->pidl_def("   \"$en is SET\",");
				$self->pidl_def("   \"$en is NOT SET\",");
			}
			$self->pidl_def("};");
		}
	}

	if ($element_count > 0) {
		my $total_ev_hex = sprintf("0x%08x", $total_ev);
		$self->pidl_code("if (flags & (~$total_ev_hex)) {");
		$self->pidl_code("\tflags &= (~$total_ev_hex);");
		$self->pidl_code("\tproto_item_append_text(item, \"Unknown bitmap value 0x%x\", flags);");
		$self->pidl_code("}\n");
	}
	$self->pidl_code("return offset;");
	$self->deindent;
	$self->pidl_code("}\n");
	$self->pidl_fn_end($dissectorname);

	my $size = $e->{BASE_TYPE};
	$size =~ s/uint//g;
	$self->register_type($name, "offset = $dissectorname(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);", "FT_UINT$size", "BASE_HEX", "0", "NULL", $size/8);
}

sub ElementLevel($$$$$$$$)
{
	my ($self,$e,$l,$hf,$myname,$pn,$ifname,$param) = @_;

	if (defined($self->{conformance}->{dissectorparams}->{$myname})) {
		$param = $self->{conformance}->{dissectorparams}->{$myname}->{PARAM};
	}

	if ($l->{TYPE} eq "POINTER") {
		my $type;
		if ($l->{LEVEL} eq "TOP") {
			$type = "toplevel";
		} elsif ($l->{LEVEL} eq "EMBEDDED") {
			$type = "embedded";
		}
		$self->pidl_code("offset = dissect_ndr_$type\_pointer(tvb, offset, pinfo, tree, di, drep, $myname\_, $ptrtype_mappings{$l->{POINTER_TYPE}}, \"Pointer to ".field2name(StripPrefixes($e->{NAME}, $self->{conformance}->{strip_prefixes})) . " ($e->{TYPE})\",$hf);");
	} elsif ($l->{TYPE} eq "ARRAY") {
		if ($l->{IS_INLINE}) {
			error($e->{ORIGINAL}, "Inline arrays not supported");
		} elsif ($l->{IS_FIXED}) {
			$self->pidl_code("int i;");
			$self->pidl_code("for (i = 0; i < $l->{SIZE_IS}; i++)");
			$self->pidl_code("\toffset = $myname\_(tvb, offset, pinfo, tree, di, drep);");
		} else {
			my $type = "";
			$type .= "c" if ($l->{IS_CONFORMANT});
			$type .= "v" if ($l->{IS_VARYING});

			unless ($l->{IS_ZERO_TERMINATED}) {
				$self->pidl_code("offset = dissect_ndr_u" . $type . "array(tvb, offset, pinfo, tree, di, drep, $myname\_);");
			} else {
				my $nl = GetNextLevel($e,$l);
				$self->pidl_code("char *data;");
				$self->pidl_code("");
				$self->pidl_code("offset = dissect_ndr_$type" . "string(tvb, offset, pinfo, tree, di, drep, sizeof(g$nl->{DATA_TYPE}), $hf, FALSE, &data);");
				$self->pidl_code("proto_item_append_text(tree, \": %s\", data);");
			}
		}
	} elsif ($l->{TYPE} eq "DATA") {
		if ($l->{DATA_TYPE} eq "string") {
			my $bs = 2; # Byte size defaults to that of UCS2


			($bs = 1) if (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_ASCII.*"));

			if (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_SIZE4.*") and property_matches($e, "flag", ".*LIBNDR_FLAG_STR_LEN4.*")) {
				$self->pidl_code("char *data;\n");
				$self->pidl_code("offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, $bs, $hf, FALSE, &data);");
				$self->pidl_code("proto_item_append_text(tree, \": %s\", data);");
			} elsif (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_SIZE4.*")) {
				$self->pidl_code("offset = dissect_ndr_vstring(tvb, offset, pinfo, tree, di, drep, $bs, $hf, FALSE, NULL);");
			} elsif (property_matches($e, "flag", ".*STR_NULLTERM.*")) {
				if ($bs == 2) {
					$self->pidl_code("offset = dissect_null_term_wstring(tvb, offset, pinfo, tree, drep, $hf , 0);")
				} else {
					$self->pidl_code("offset = dissect_null_term_string(tvb, offset, pinfo, tree, drep, $hf , 0);")
				}
			} else {
				warn("Unable to handle string with flags $e->{PROPERTIES}->{flag}");
			}
		} elsif ($l->{DATA_TYPE} eq "DATA_BLOB") {
			my $remain = 0;
			$remain = 1 if (property_matches($e->{ORIGINAL}, "flag", ".*LIBNDR_FLAG_REMAINING.*"));
			$self->pidl_code("offset = dissect_ndr_datablob(tvb, offset, pinfo, tree, di, drep, $hf, $remain);");
		} else {
			my $call;

			if ($self->{conformance}->{imports}->{$l->{DATA_TYPE}}) {
				$call = $self->{conformance}->{imports}->{$l->{DATA_TYPE}}->{DATA};
				$self->{conformance}->{imports}->{$l->{DATA_TYPE}}->{USED} = 1;
			} elsif (defined($self->{conformance}->{imports}->{"$pn.$e->{NAME}"})) {
				$call = $self->{conformance}->{imports}->{"$pn.$e->{NAME}"}->{DATA};
				$self->{conformance}->{imports}->{"$pn.$e->{NAME}"}->{USED} = 1;
			} elsif (defined($self->{conformance}->{types}->{$l->{DATA_TYPE}})) {
				$call= $self->{conformance}->{types}->{$l->{DATA_TYPE}}->{DISSECTOR_NAME};
				$self->{conformance}->{types}->{$l->{DATA_TYPE}}->{USED} = 1;
			} else {
				my $t;
				if (ref($l->{DATA_TYPE}) eq "HASH" ) {
					$t = "$l->{DATA_TYPE}->{TYPE}_$l->{DATA_TYPE}->{NAME}";
				} else {
					$t = $l->{DATA_TYPE};
				}

				$self->pidl_code("offset = $ifname\_dissect_struct_" . $t . "(tvb,offset,pinfo,tree,di,drep,$hf,$param);");

				return;
			}

			$call =~ s/\@HF\@/$hf/g;
			$call =~ s/\@PARAM\@/$param/g;
			$self->pidl_code($call);
		}
	} elsif ($_->{TYPE} eq "SUBCONTEXT") {
		my $varswitch;
		if (has_property($e, "switch_is")) {
			$varswitch = $e->{PROPERTIES}->{switch_is};
		}
		my $num_bits = ($l->{HEADER_SIZE}*8);
		my $hf2 = $self->register_hf_field($hf."_", "Subcontext length", "$ifname.$pn.$_->{NAME}subcontext", "FT_UINT$num_bits", "BASE_HEX", "NULL", 0, "");
		$num_bits = 3264 if ($num_bits == 32);
		$self->{hf_used}->{$hf2} = 1;
		$self->pidl_code("guint$num_bits size;");
		$self->pidl_code("int conformant = di->conformant_run;");
		$self->pidl_code("tvbuff_t *subtvb;");
		$self->pidl_code("");
		# We need to be able to dissect the length of the context in every case
		# and conformant run skips the dissections of scalars ...
		$self->pidl_code("if (!conformant) {");
		$self->indent;
		$self->pidl_code("guint32 saved_flags = di->call_data->flags;");
		$self->pidl_code("offset = dissect_ndr_uint$num_bits(tvb, offset, pinfo, tree, di, drep, $hf2, &size);");
		# This is a subcontext, there is normally no such thing as
		# 64 bit NDR is subcontext so we clear the flag so that we can
		# continue to dissect handmarshalled stuff with pidl
		$self->pidl_code("di->call_data->flags &= ~DCERPC_IS_NDR64;");

		$self->pidl_code("subtvb = tvb_new_subset(tvb, offset, (const gint)size, -1);");
		if ($param ne 0) {
			$self->pidl_code("$myname\_(subtvb, 0, pinfo, tree, di, drep, $param);");
		} else {
			$self->pidl_code("$myname\_(subtvb, 0, pinfo, tree, di, drep);");
		}
		$self->pidl_code("offset += (int)size;");
		$self->pidl_code("di->call_data->flags = saved_flags;");
		$self->deindent;
		$self->pidl_code("}");
	} elsif ($_->{TYPE} eq "PIPE") {
		error($e->{ORIGINAL}, "Type PIPE not yet supported");
	} else {
		die("Unknown type `$_->{TYPE}'");
	}
}

sub SwitchType($$;$)
{
	my ($e, $type, $nodiscriminant) = @_;

	my $switch_dt =  getType($type);
	my $switch_type = undef;
	if ($switch_dt->{DATA}->{TYPE} eq "ENUM") {
		$switch_type = Parse::Pidl::Typelist::enum_type_fn($switch_dt->{DATA});
	} elsif ($switch_dt->{DATA}->{TYPE} eq "BITMAP") {
		$switch_type = Parse::Pidl::Typelist::bitmap_type_fn($switch_dt->{DATA});
	} elsif ($switch_dt->{DATA}->{TYPE} eq "SCALAR") {
		if (defined $e->{SWITCH_TYPE}) {
			$switch_type = "$e->{SWITCH_TYPE}";
		} else {
			$switch_type = "$switch_dt->{DATA}->{NAME}";
		}
	} elsif (not defined $e->{SWITCH_TYPE}) {
		$switch_type = $nodiscriminant;
	}

	return $switch_type
}

sub Element($$$$$$)
{
	my ($self,$e,$pn,$ifname,$isoruseswitch,%switchvars) = @_;

	my $dissectorname = "$ifname\_dissect\_element\_".StripPrefixes($pn, $self->{conformance}->{strip_prefixes})."\_".StripPrefixes($e->{NAME}, $self->{conformance}->{strip_prefixes});

	my ($call_code, $moreparam);
	my $param = 0;
	if (defined $isoruseswitch) {
		my $type = $isoruseswitch->[0];
		my $name = $isoruseswitch->[1];

		my $switch_dt =  getType($type);
		my $switch_raw_type = SwitchType($e, $type, "uint32");
		if (not defined($switch_raw_type)) {
			die("Unknown type[$type]\n");
		}
		my $switch_type = "g${switch_raw_type}";

		if ($name ne "") {
			$moreparam = ", $switch_type *".$name;
		} else {
			$moreparam = "";
		}
		if (($e->{PROPERTIES}->{switch_is} eq "") && ($switchvars{$name}) &&
			#not a "native" type
			(!($type =~ /^uint(8|16|1632|32|3264|64)/))) {
			$param = $name;
		} elsif ( $switch_dt->{DATA}->{TYPE} eq "ENUM") {
			$param = $name;
		} elsif ($name ne "") {
			$param = "*".$name;
		}

		if ($name ne "") {
			$call_code = "offset = $dissectorname(tvb, offset, pinfo, tree, di, drep, &$name);";
		} else {
			$call_code = "offset = $dissectorname(tvb, offset, pinfo, tree, di, drep);";
		}
	} else {
		$moreparam = "";
		$call_code = "offset = $dissectorname(tvb, offset, pinfo, tree, di, drep);";
	}


	my $type = $self->find_type($e->{TYPE});

	if (not defined($type)) {
		# default settings
		$type = {
			MASK => 0,
			VALSSTRING => "NULL",
			FT_TYPE => "FT_NONE",
			BASE_TYPE => "BASE_NONE"
		};
	}

	if (ContainsString($e)) {
		$type = {
			MASK => 0,
			VALSSTRING => "NULL",
			FT_TYPE => "FT_STRING",
			BASE_TYPE => "BASE_NONE"
		};
	}
	if (property_matches($e, "flag", ".*LIBNDR_FLAG_ALIGN.*")) {
		my $align_flag = $e->{PROPERTIES}->{flag};
		if ($align_flag =~ m/LIBNDR_FLAG_ALIGN(\d+)/) {
			$call_code = "ALIGN_TO_$1_BYTES; ".$call_code;
		}
	}

	my $hf = $self->register_hf_field("hf_$ifname\_$pn\_$e->{NAME}", field2name($e->{NAME}), "$ifname.$pn.$e->{NAME}", $type->{FT_TYPE}, $type->{BASE_TYPE}, $type->{VALSSTRING}, $type->{MASK}, "");
	$self->{hf_used}->{$hf} = 1;

	my $eltname = StripPrefixes($pn, $self->{conformance}->{strip_prefixes}) . ".$e->{NAME}";
	if (defined($self->{conformance}->{noemit}->{$eltname})) {
		return $call_code;
	}

	my $add = "";

	my $oldparam = undef;
	foreach (@{$e->{LEVELS}}) {
		if (defined $_->{SWITCH_IS}) {
			$oldparam = $param;
			if (($param ne "0") && (!($param =~ /\*/))) {
				$param = "*$param";
			}
		}
		next if ($_->{TYPE} eq "SWITCH");
		next if (defined($self->{conformance}->{noemit}->{"$dissectorname$add"}));
		$self->pidl_def("static int $dissectorname$add(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_$moreparam);");
		$self->pidl_fn_start("$dissectorname$add");
		$self->pidl_code("static int");
		$self->pidl_code("$dissectorname$add(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_$moreparam)");
		$self->pidl_code("{");
		$self->indent;

		$self->ElementLevel($e,$_,$hf,$dissectorname.$add,$pn,$ifname,$param);
		if (defined $oldparam) {
			$param = $oldparam;
		}

		$self->pidl_code("");
		$self->pidl_code("return offset;");
		$self->deindent;
		$self->pidl_code("}\n");
		$self->pidl_fn_end("$dissectorname$add");
		$add.="_";
		last if ($_->{TYPE} eq "ARRAY" and $_->{IS_ZERO_TERMINATED});
	}

	return $call_code;
}

sub Function($$$)
{
	my ($self, $fn,$ifname) = @_;

	my %dissectornames;

	foreach (@{$fn->{ELEMENTS}}) {
	    $dissectornames{$_->{NAME}} = $self->Element($_, $fn->{NAME}, $ifname, undef, undef) if not defined($dissectornames{$_->{NAME}});
	}

	my $fn_name = $_->{NAME};
	$fn_name =~ s/^${ifname}_//;

	$self->PrintIdl(DumpFunction($fn->{ORIGINAL}));
	$self->pidl_fn_start("$ifname\_dissect\_$fn_name\_response");
	$self->pidl_code("static int");
	$self->pidl_code("$ifname\_dissect\_${fn_name}_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)");
	$self->pidl_code("{");
	$self->indent;
	if ( not defined($fn->{RETURN_TYPE})) {
	} elsif ($fn->{RETURN_TYPE} eq "NTSTATUS" or $fn->{RETURN_TYPE} eq "WERROR")
	{
		$self->pidl_code("guint32 status;\n");
	} elsif (my $type = getType($fn->{RETURN_TYPE})) {
		if ($type->{DATA}->{TYPE} eq "ENUM") {
			$self->pidl_code("g".Parse::Pidl::Typelist::enum_type_fn($type->{DATA}) . " status;\n");
		} elsif ($type->{DATA}->{TYPE} eq "SCALAR") {
			$self->pidl_code("g$fn->{RETURN_TYPE} status;\n");
		} else {
			error($fn, "return type `$fn->{RETURN_TYPE}' not yet supported");
		}
	} else {
		error($fn, "unknown return type `$fn->{RETURN_TYPE}'");
	}

	$self->pidl_code("di->dcerpc_procedure_name=\"${fn_name}\";");
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$_->{DIRECTION}})) {
			$self->pidl_code("$dissectornames{$_->{NAME}}");
			$self->pidl_code("offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);");
			$self->pidl_code("");
		}
	}

	if (not defined($fn->{RETURN_TYPE})) {
	} elsif ($fn->{RETURN_TYPE} eq "NTSTATUS") {
		$self->pidl_code("offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf\_$ifname\_status, &status);\n");
		$self->pidl_code("if (status != 0)");
		$self->pidl_code("\tcol_append_fstr(pinfo->cinfo, COL_INFO, \", Error: %s\", val_to_str(status, NT_errors, \"Unknown NT status 0x%08x\"));\n");
		$return_types{$ifname}->{"status"} = ["NTSTATUS", "NT Error"];
	} elsif ($fn->{RETURN_TYPE} eq "WERROR") {
		$self->pidl_code("offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf\_$ifname\_werror, &status);\n");
		$self->pidl_code("if (status != 0)");
		$self->pidl_code("\tcol_append_fstr(pinfo->cinfo, COL_INFO, \", Error: %s\", val_to_str(status, WERR_errors, \"Unknown DOS error 0x%08x\"));\n");

		$return_types{$ifname}->{"werror"} = ["WERROR", "Windows Error"];
	} elsif (my $type = getType($fn->{RETURN_TYPE})) {
		if ($type->{DATA}->{TYPE} eq "ENUM") {
			my $return_type = "g".Parse::Pidl::Typelist::enum_type_fn($type->{DATA});
			my $return_dissect = "dissect_ndr_" .Parse::Pidl::Typelist::enum_type_fn($type->{DATA});

			$self->pidl_code("offset = $return_dissect(tvb, offset, pinfo, tree, di, drep, hf\_$ifname\_$fn->{RETURN_TYPE}_status, &status);");
			$self->pidl_code("if (status != 0)");
			$self->pidl_code("\tcol_append_fstr(pinfo->cinfo, COL_INFO, \", Status: %s\", val_to_str(status, $ifname\_$fn->{RETURN_TYPE}\_vals, \"Unknown " . $fn->{RETURN_TYPE} . " error 0x%08x\"));\n");
			$return_types{$ifname}->{$fn->{RETURN_TYPE}."_status"} = [$fn->{RETURN_TYPE}, $fn->{RETURN_TYPE}];
		} elsif ($type->{DATA}->{TYPE} eq "SCALAR") {
			$self->pidl_code("offset = dissect_ndr_$fn->{RETURN_TYPE}(tvb, offset, pinfo, tree, di, drep, hf\_$ifname\_$fn->{RETURN_TYPE}_status, &status);");
			$self->pidl_code("if (status != 0)");
			$self->pidl_code("\tcol_append_fstr(pinfo->cinfo, COL_INFO, \", Status: %d\", status);\n");
			$return_types{$ifname}->{$fn->{RETURN_TYPE}."_status"} = [$fn->{RETURN_TYPE}, $fn->{RETURN_TYPE}];
		}
	}

	$self->pidl_code("return offset;");
	$self->deindent;
	$self->pidl_code("}\n");
	$self->pidl_fn_end("$ifname\_dissect\_$fn_name\_response");

	$self->pidl_fn_start("$ifname\_dissect\_$fn_name\_request");
	$self->pidl_code("static int");
	$self->pidl_code("$ifname\_dissect\_${fn_name}_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)");
	$self->pidl_code("{");
	$self->indent;
	$self->pidl_code("di->dcerpc_procedure_name=\"${fn_name}\";");
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$_->{DIRECTION}})) {
			$self->pidl_code("$dissectornames{$_->{NAME}}");
			$self->pidl_code("offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);");
		}

	}

	$self->pidl_code("return offset;");
	$self->deindent;
	$self->pidl_code("}\n");
	$self->pidl_fn_end("$ifname\_dissect\_$fn_name\_request");
}

sub Struct($$$$)
{
	my ($self,$e,$name,$ifname) = @_;
	my $dissectorname = "$ifname\_dissect\_struct\_".StripPrefixes($name, $self->{conformance}->{strip_prefixes});

	return if (defined($self->{conformance}->{noemit}->{StripPrefixes($name, $self->{conformance}->{strip_prefixes})}));

	$self->register_ett("ett_$ifname\_$name");

	my $res = "";
	my $varswitchs = {};
	# will contain the switch var declaration;
	my $vars = [];
	my %switch_hash;
	foreach (@{$e->{ELEMENTS}}) {
		if (has_property($_, "switch_is")) {
			$varswitchs->{$_->{PROPERTIES}->{switch_is}} = [];
			$switch_hash{ $_->{PROPERTIES}->{switch_is}} =  $_->{PROPERTIES}->{switch_is};
		}
	}
	foreach (@{$e->{ELEMENTS}}) {
		my $switch_info = undef;

		my $v = $_->{NAME};
		if (scalar(grep {/^$v$/} keys(%$varswitchs)) == 1) {
			# This element is one of the switch attribute
			my $switch_raw_type = SwitchType($e, $_->{TYPE}, "uint32");
			if (not defined($switch_raw_type)) {
				die("Unknown type[$_->{TYPE}]\n");
			}
			my $switch_type = "g${switch_raw_type}";

			if ($switch_type ne "") {
				push @$vars, "$switch_type $v = 0;";
			}
			$switch_info = [ $_->{TYPE}, $v ];
			$varswitchs->{$v} = $switch_info;
		}

		if (has_property($_, "switch_is")) {
			my $varswitch = $_->{PROPERTIES}->{switch_is};
			$switch_info = $varswitchs->{$varswitch};
		}

		$res.="\t".$self->Element($_, $name, $ifname, $switch_info, %switch_hash)."\n\n";
	}

	my $doalign = undef;
	if ($e->{ALIGN} > 1 and not property_matches($e, "flag", ".*LIBNDR_FLAG_NOALIGN.*")) {
		$doalign = 1;
	} elsif (property_matches($e, "flag", ".*LIBNDR_FLAG_NOALIGN.*")) {
		$doalign = 0;
	}

	$self->pidl_hdr("int $dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);");

	$self->pidl_fn_start($dissectorname);
	$self->pidl_code("int");
	$self->pidl_code("$dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)");
	$self->pidl_code("{");
	$self->indent;
	$self->pidl_code($_) foreach (@$vars);
	$self->pidl_code("proto_item *item = NULL;");
	if($res) {
		$self->pidl_code("proto_tree *tree = NULL;");
	}
	if (defined($doalign) and $doalign == 0) {
		$self->pidl_code("gboolean oldalign = di->no_align;");
	}
	$self->pidl_code("int old_offset;");
	$self->pidl_code("");

	if (defined($doalign)) {
		if ($doalign == 1) {
			$self->pidl_code("ALIGN_TO_$e->{ALIGN}_BYTES;");
		}
		if ($doalign == 0) {
			$self->pidl_code("di->no_align = TRUE;");
		}
		$self->pidl_code("");
	}

	$self->pidl_code("old_offset = offset;");
	$self->pidl_code("");
	$self->pidl_code("if (parent_tree) {");
	$self->indent;
	$self->pidl_code("item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);");
	if($res) {
		$self->pidl_code("tree = proto_item_add_subtree(item, ett_$ifname\_$name);");
	}
	$self->deindent;
	$self->pidl_code("}");
	$self->pidl_code("");

	$self->deindent;
	$self->pidl_code("$res");
	$self->indent;

	$self->pidl_code("proto_item_set_len(item, offset-old_offset);\n");
	if (defined($doalign) and $doalign == 1) {
		$self->pidl_code("");
		$self->pidl_code("if (di->call_data->flags & DCERPC_IS_NDR64) {");
		$self->indent;
		$self->pidl_code("ALIGN_TO_$e->{ALIGN}_BYTES;");
		$self->deindent;
		$self->pidl_code("}");
	}
	if (defined($doalign) and $doalign == 0) {
		$self->pidl_code("");
		$self->pidl_code("di->no_align = oldalign;");
	}
	$self->pidl_code("");
	$self->pidl_code("return offset;");
	$self->deindent;
	$self->pidl_code("}\n");
	$self->pidl_fn_end($dissectorname);

	$self->register_type($name, "offset = $dissectorname(tvb,offset,pinfo,tree,di,drep,\@HF\@,\@PARAM\@);", "FT_NONE", "BASE_NONE", 0, "NULL", 0);
}

sub Union($$$$)
{
	my ($self,$e,$name,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect_".StripPrefixes($name, $self->{conformance}->{strip_prefixes});

	return if (defined($self->{conformance}->{noemit}->{StripPrefixes($name, $self->{conformance}->{strip_prefixes})}));

	$self->register_ett("ett_$ifname\_$name");

	my $res = "";
	foreach (@{$e->{ELEMENTS}}) {
		$res.="\n\t\t$_->{CASE}:\n";
		if ($_->{TYPE} ne "EMPTY") {
			$res.="\t\t\t".$self->Element($_, $name, $ifname, undef, undef)."\n";
		}
		$res.="\t\tbreak;\n";
	}

	my $switch_type = undef;
	my $switch_dissect = undef;
	my $switch_raw_type = SwitchType($e, $e->{SWITCH_TYPE});
	if (defined($switch_raw_type)) {
		$switch_type = "g${switch_raw_type}";
		$switch_dissect = "dissect_ndr_${switch_raw_type}";
	}

	$self->pidl_fn_start($dissectorname);
	$self->pidl_code("static int");
	$self->pidl_code("$dissectorname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)");
	$self->pidl_code("{");
	$self->indent;
	$self->pidl_code("proto_item *item = NULL;");
	$self->pidl_code("proto_tree *tree = NULL;");
	$self->pidl_code("int old_offset;");
	if (!defined $switch_type) {
		$self->pidl_code("guint32 level = param;");
	} else {
		$self->pidl_code("$switch_type level;");
	}
	$self->pidl_code("");

	$self->pidl_code("old_offset = offset;");
	$self->pidl_code("if (parent_tree) {");
	$self->indent;
	$self->pidl_code("tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_$ifname\_$name, &item, \"$name\");");
	$self->deindent;
	$self->pidl_code("}");

	$self->pidl_code("");

	if (defined $switch_type) {
		$self->pidl_code("offset = $switch_dissect(tvb, offset, pinfo, tree, di, drep, hf_index, &level);");

		if ($e->{ALIGN} > 1) {
			$self->pidl_code("ALIGN_TO_$e->{ALIGN}_BYTES;");
			$self->pidl_code("");
		}
	}


	$self->pidl_code("switch(level) {$res\t}");
	$self->pidl_code("proto_item_set_len(item, offset-old_offset);\n");
	$self->pidl_code("");

	$self->pidl_code("return offset;");
	$self->deindent;
	$self->pidl_code("}");
	$self->pidl_fn_end($dissectorname);

	$self->register_type($name, "offset = $dissectorname(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);", "FT_NONE", "BASE_NONE", 0, "NULL", 0);
}

sub Const($$$)
{
	my ($self,$const,$ifname) = @_;

	if (!defined($const->{ARRAY_LEN}[0])) {
		$self->pidl_hdr("#define $const->{NAME}\t( $const->{VALUE} )\n");
	} else {
		$self->pidl_hdr("#define $const->{NAME}\t $const->{VALUE}\n");
	}
}

sub Typedef($$$$)
{
	my ($self,$e,$name,$ifname) = @_;

	$self->Type($e->{DATA}, $name, $ifname);
}

sub Type($$$$)
{
	my ($self, $e, $name, $ifname) = @_;

	$self->PrintIdl(DumpType($e->{ORIGINAL}));
	{
		ENUM => \&Enum,
		STRUCT => \&Struct,
		UNION => \&Union,
		BITMAP => \&Bitmap,
		TYPEDEF => \&Typedef,
		PIPE    => \&Pipe
	}->{$e->{TYPE}}->($self, $e, $name, $ifname);
}

sub RegisterInterface($$)
{
	my ($self, $x) = @_;

	$self->pidl_fn_start("proto_register_dcerpc_$x->{NAME}");
	$self->pidl_code("void proto_register_dcerpc_$x->{NAME}(void)");
	$self->pidl_code("{");
	$self->indent;

	$self->{res}->{headers} .= "void proto_register_dcerpc_$x->{NAME}(void);\n";

	$self->{res}->{code}.=$self->DumpHfList()."\n";
	$self->{res}->{code}.="\n".DumpEttList($self->{ett})."\n";

	if (defined($x->{UUID})) {
		# These can be changed to non-pidl_code names if the old
		# dissectors in epan/dissectors are deleted.

		my $name = uc($x->{NAME}) . " (pidl)";
		my $short_name = uc($x->{NAME});
		my $filter_name = $x->{NAME};

		if (has_property($x, "helpstring")) {
			$name = $x->{PROPERTIES}->{helpstring};
		}

		if (defined($self->{conformance}->{protocols}->{$x->{NAME}})) {
		$short_name = $self->{conformance}->{protocols}->{$x->{NAME}}->{SHORTNAME};
		$name = $self->{conformance}->{protocols}->{$x->{NAME}}->{LONGNAME};
		$filter_name = $self->{conformance}->{protocols}->{$x->{NAME}}->{FILTERNAME};
		}

		$self->pidl_code("proto_dcerpc_$x->{NAME} = proto_register_protocol(".make_str($name).", ".make_str($short_name).", ".make_str($filter_name).");");

		$self->pidl_code("proto_register_field_array(proto_dcerpc_$x->{NAME}, hf, array_length (hf));");
		$self->pidl_code("proto_register_subtree_array(ett, array_length(ett));");
	} else {
		$self->pidl_code("proto_dcerpc = proto_get_id_by_filter_name(\"dcerpc\");");
		$self->pidl_code("proto_register_field_array(proto_dcerpc, hf, array_length(hf));");
		$self->pidl_code("proto_register_subtree_array(ett, array_length(ett));");
	}

	$self->deindent;
	$self->pidl_code("}\n");
	$self->pidl_fn_end("proto_register_dcerpc_$x->{NAME}");
}

sub RegisterInterfaceHandoff($$)
{
	my ($self,$x) = @_;

	if (defined($x->{UUID})) {
		$self->pidl_fn_start("proto_reg_handoff_dcerpc_$x->{NAME}");
		$self->pidl_code("void proto_reg_handoff_dcerpc_$x->{NAME}(void)");
		$self->pidl_code("{");
		$self->indent;
		$self->pidl_code("dcerpc_init_uuid(proto_dcerpc_$x->{NAME}, ett_dcerpc_$x->{NAME},");
		$self->pidl_code("\t&uuid_dcerpc_$x->{NAME}, ver_dcerpc_$x->{NAME},");
		$self->pidl_code("\t$x->{NAME}_dissectors, hf_$x->{NAME}_opnum);");
		$self->deindent;
		$self->pidl_code("}");
		$self->pidl_fn_end("proto_reg_handoff_dcerpc_$x->{NAME}");

		$self->{res}->{headers} .= "void proto_reg_handoff_dcerpc_$x->{NAME}(void);\n";

		$self->{hf_used}->{"hf_$x->{NAME}_opnum"} = 1;
	}
}

sub ProcessInclude
{
	my $self = shift;
	my @includes = @_;
	foreach (@includes) {
		$self->pidl_hdr("#include \"$_\"");
	}
	$self->pidl_hdr("");
}

sub ProcessImport
{
	my $self = shift;
	my @imports = @_;
	foreach (@imports) {
		next if($_ eq "security");
		s/^\"//;
		s/\.idl"?$//;
		s/^.*\///;
		$self->pidl_hdr("#include \"packet-dcerpc-$_\.h\"");
	}
	$self->pidl_hdr("");
}

sub ProcessInterface($$)
{
	my ($self, $x) = @_;

	push(@{$self->{conformance}->{strip_prefixes}}, $x->{NAME});

	my $define = "__PACKET_DCERPC_" . uc($_->{NAME}) . "_H";
	$self->pidl_hdr("#ifndef $define");
	$self->pidl_hdr("#define $define");
	$self->pidl_hdr("");

	$self->pidl_def("static gint proto_dcerpc_$x->{NAME} = -1;");
	$self->register_ett("ett_dcerpc_$x->{NAME}");
	$self->register_hf_field("hf_$x->{NAME}_opnum", "Operation", "$x->{NAME}.opnum", "FT_UINT16", "BASE_DEC", "NULL", 0, "");

	if (defined($x->{UUID})) {
		my $if_uuid = $x->{UUID};

		$self->pidl_def("/* Version information */\n\n");

		$self->pidl_def("static e_guid_t uuid_dcerpc_$x->{NAME} = {");
		$self->pidl_def("\t0x" . substr($if_uuid, 1, 8)
		. ", 0x" . substr($if_uuid, 10, 4)
		. ", 0x" . substr($if_uuid, 15, 4) . ",");
		$self->pidl_def("\t{ 0x" . substr($if_uuid, 20, 2)
		. ", 0x" . substr($if_uuid, 22, 2)
		. ", 0x" . substr($if_uuid, 25, 2)
		. ", 0x" . substr($if_uuid, 27, 2)
		. ", 0x" . substr($if_uuid, 29, 2)
		. ", 0x" . substr($if_uuid, 31, 2)
		. ", 0x" . substr($if_uuid, 33, 2)
		. ", 0x" . substr($if_uuid, 35, 2) . " }");
		$self->pidl_def("};");

		my $maj = 0x0000FFFF & $x->{VERSION};
		$maj =~ s/\.(.*)$//g;
		$self->pidl_def("static guint16 ver_dcerpc_$x->{NAME} = $maj;");
		$self->pidl_def("");
	}

	$return_types{$x->{NAME}} = {};

	$self->Interface($x);
	$self->pidl_code("\n".DumpFunctionTable($x));

	foreach (sort(keys %{$return_types{$x->{NAME}}})) {
		my ($type, $desc) = @{$return_types{$x->{NAME}}->{$_}};
		my $dt = $self->find_type($type);
		$dt or die("Unable to find information about return type `$type'");
		$self->register_hf_field("hf_$x->{NAME}_$_", $desc, "$x->{NAME}.$_", $dt->{FT_TYPE}, "BASE_HEX", $dt->{VALSSTRING}, 0, "");
		$self->{hf_used}->{"hf_$x->{NAME}_$_"} = 1;
	}

	$self->RegisterInterface($x);
	$self->RegisterInterfaceHandoff($x);

	if (exists ($self->{conformance}->{header})) {
		$self->pidl_hdr($self->{conformance}->{header});
	}

	$self->pidl_hdr("#endif /* $define */");
}

sub find_type($$)
{
	my ($self, $n) = @_;

	return $self->{conformance}->{types}->{$n};
}

sub register_type($$$$$$$$)
{
	my ($self, $type,$call,$ft,$base,$mask,$vals,$length) = @_;

	return if (defined($self->{conformance}->{types}->{$type}));

	$self->{conformance}->{types}->{$type} = {
		NAME => $type,
		DISSECTOR_NAME => $call,
		FT_TYPE => $ft,
		BASE_TYPE => $base,
		MASK => $mask,
		VALSSTRING => $vals,
		ALIGNMENT => $length
	};
}

# Loads the default types
sub Initialize($$)
{
	my ($self, $cnf_file) = @_;

	$self->{conformance} = {
		imports => {},
		header_fields=> {}
	};

	ReadConformance($cnf_file, $self->{conformance}) or print STDERR "warning: No conformance file `$cnf_file'\n";

	foreach my $bytes (qw(1 2 4 8)) {
		my $bits = $bytes * 8;
		$self->register_type("uint$bits", "offset = PIDL_dissect_uint$bits(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);", "FT_UINT$bits", "BASE_DEC", 0, "NULL", $bytes);
		$self->register_type("int$bits", "offset = PIDL_dissect_uint$bits(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);", "FT_INT$bits", "BASE_DEC", 0, "NULL", $bytes);
	}

	$self->register_type("uint3264", "offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep, \@HF\@, NULL);", "FT_UINT32", "BASE_DEC", 0, "NULL", 8);
	$self->register_type("hyper", "offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, di, drep, \@HF\@, NULL);", "FT_UINT64", "BASE_DEC", 0, "NULL", 8);
	$self->register_type("udlong", "offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, di, drep, \@HF\@, NULL);", "FT_UINT64", "BASE_DEC", 0, "NULL", 4);
	$self->register_type("bool8", "offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);","FT_INT8", "BASE_DEC", 0, "NULL", 1);
	$self->register_type("char", "offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);","FT_INT8", "BASE_DEC", 0, "NULL", 1);
	$self->register_type("long", "offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);","FT_INT32", "BASE_DEC", 0, "NULL", 4);
	$self->register_type("dlong", "offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, di, drep, \@HF\@, NULL);","FT_INT64", "BASE_DEC", 0, "NULL", 8);
	$self->register_type("GUID", "offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, \@HF\@, NULL);","FT_GUID", "BASE_NONE", 0, "NULL", 4);
	$self->register_type("policy_handle", "offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);","FT_BYTES", "BASE_NONE", 0, "NULL", 4);
	$self->register_type("NTTIME", "offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, \@HF\@);","FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", 0, "NULL", 4);
	$self->register_type("NTTIME_hyper", "offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, \@HF\@);","FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", 0, "NULL", 4);
	$self->register_type("time_t", "offset = dissect_ndr_time_t(tvb, offset, pinfo,tree, di, drep, \@HF\@, NULL);","FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", 0, "NULL", 4);
	$self->register_type("NTTIME_1sec", "offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, \@HF\@);", "FT_ABSOLUTE_TIME", "ABSOLUTE_TIME_LOCAL", 0, "NULL", 4);
	$self->register_type("dom_sid28", "
		di->hf_index = \@HF\@;

		offset = dissect_ndr_nt_SID28(tvb, offset, pinfo, tree, di, drep);
	", "FT_STRING", "BASE_NONE", 0, "NULL", 4);
	$self->register_type("SID", "
		di->hf_index = \@HF\@;

		offset = dissect_ndr_nt_SID_with_options(tvb, offset, pinfo, tree, di, drep, param);
	","FT_STRING", "BASE_NONE", 0, "NULL", 4);
	$self->register_type("WERROR",
		"offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);","FT_UINT32", "BASE_DEC", 0, "VALS(WERR_errors)", 4);
	$self->register_type("NTSTATUS",
		"offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, \@HF\@, \@PARAM\@);","FT_UINT32", "BASE_DEC", 0, "VALS(NT_errors)", 4);
	$self->register_type("ipv6address", "proto_tree_add_item(tree, \@HF\@, tvb, offset, 16, ENC_NA); offset += 16;", "FT_IPv6", "BASE_NONE", 0, "NULL", 16);
	$self->register_type("ipv4address", "proto_tree_add_item(tree, \@HF\@, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;", "FT_IPv4", "BASE_NONE", 0, "NULL", 4);

}

#####################################################################
# Generate Wireshark parser and header code
sub Parse($$$$$)
{
	my($self,$ndr,$idl_file,$h_filename,$cnf_file) = @_;

	$self->Initialize($cnf_file);

	return (undef, undef) if defined($self->{conformance}->{noemit_dissector});

	my $notice =
"/* DO NOT EDIT
	This file was automatically generated by Pidl
	from $idl_file and $cnf_file.

	Pidl is a perl based IDL compiler for DCE/RPC idl files.
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be
	found at https://wiki.wireshark.org/Pidl
*/

";

	$self->{res}->{headers} = "\n";
	$self->{res}->{headers} .= "#include \"config.h\"\n";

	$self->{res}->{headers} .= "#include <glib.h>\n";
	$self->{res}->{headers} .= "#include <string.h>\n";
	$self->{res}->{headers} .= "#include <epan/packet.h>\n\n";

	$self->{res}->{headers} .= "#include \"packet-dcerpc.h\"\n";
	$self->{res}->{headers} .= "#include \"packet-dcerpc-nt.h\"\n";
	$self->{res}->{headers} .= "#include \"packet-windows-common.h\"\n";

	my $h_basename = basename($h_filename);

	$self->{res}->{headers} .= "#include \"$h_basename\"\n";
	$self->pidl_code("");

	if (defined($self->{conformance}->{ett})) {
		register_ett($self,$_) foreach(@{$self->{conformance}->{ett}})
	}

	# Wireshark protocol registration

	foreach (@$ndr) {
		$self->ProcessInterface($_) if ($_->{TYPE} eq "INTERFACE");
		$self->ProcessImport(@{$_->{PATHS}}) if ($_->{TYPE} eq "IMPORT");
		$self->ProcessInclude(@{$_->{PATHS}}) if ($_->{TYPE} eq "INCLUDE");
	}

	$self->{res}->{ett} = DumpEttDeclaration($self->{ett});
	$self->{res}->{hf} = $self->DumpHfDeclaration();

	my $parser = $notice;
	$parser.= $self->{res}->{headers};
	$parser.=$self->{res}->{ett};
	$parser.=$self->{res}->{hf};
	$parser.=$self->{res}->{def};
	if (exists ($self->{conformance}->{override})) {
		$parser.=$self->{conformance}->{override};
	}
	$parser.=$self->{res}->{code};

	my $header = $notice;
	$header.=$self->{res}->{hdr};

	$self->CheckUsed($self->{conformance});

	return ($parser,$header);
}

###############################################################################
# ETT
###############################################################################

sub register_ett($$)
{
	my ($self, $name) = @_;

	push (@{$self->{ett}}, $name);
}

sub DumpEttList
{
	my ($ett) = @_;
	my $res = "\tstatic gint *ett[] = {\n";
	foreach (@$ett) {
		$res .= "\t\t&$_,\n";
	}

	return "$res\t};\n";
}

sub DumpEttDeclaration
{
	my ($ett) = @_;
	my $res = "\n/* Ett declarations */\n";
	foreach (@$ett) {
		$res .= "static gint $_ = -1;\n";
	}

	return "$res\n";
}

###############################################################################
# HF
###############################################################################

sub register_hf_field($$$$$$$$$)
{
	my ($self,$index,$name,$filter_name,$ft_type,$base_type,$valsstring,$mask,$blurb) = @_;

	if (defined ($self->{conformance}->{hf_renames}->{$index})) {
		$self->{conformance}->{hf_renames}->{$index}->{USED} = 1;
		return $self->{conformance}->{hf_renames}->{$index}->{NEWNAME};
	}

	$self->{conformance}->{header_fields}->{$index} = {
		INDEX => $index,
		NAME => $name,
		FILTER => $filter_name,
		FT_TYPE => $ft_type,
		BASE_TYPE => $base_type,
		VALSSTRING => $valsstring,
		MASK => $mask,
		BLURB => $blurb
	};

	if ((not defined($blurb) or $blurb eq "") and
			defined($self->{conformance}->{fielddescription}->{$index})) {
		$self->{conformance}->{header_fields}->{$index}->{BLURB} =
			$self->{conformance}->{fielddescription}->{$index}->{DESCRIPTION};
		$self->{conformance}->{fielddescription}->{$index}->{USED} = 1;
	}

	return $index;
}

sub change_hf_field_type($$$$)
{
	my ($self,$index,$ft_type,$base_type) = @_;
	if (defined ($self->{conformance}->{hf_renames}->{$index})) {
		print "Field $index has been renamed to ".$self->{conformance}->{hf_renames}->{$index}->{NEWNAME}." you can't change it's type";
		return 0;
	}

	if (!defined ($self->{conformance}->{header_fields}->{$index})) {
		print "Field $index doesn't exists";
		return 0;
	}
	$self->{conformance}->{header_fields}->{$index}->{FT_TYPE} = $ft_type;
	$self->{conformance}->{header_fields}->{$index}->{BASE_TYPE} = $base_type;
	return 1;
}

sub DumpHfDeclaration($)
{
	my ($self) = @_;
	my $res = "";

	$res = "\n/* Header field declarations */\n";

	foreach (sort(keys %{$self->{conformance}->{header_fields}}))
	{
		$res .= "static gint $_ = -1;\n";
	}

	return "$res\n";
}

sub make_str_or_null($)
{
	my $str = shift;
	if (substr($str, 0, 1) eq "\"") {
		$str = substr($str, 1, length($str)-2);
	}
	$str =~ s/^\s*//;
	$str =~ s/\s*$//;
	if ($str eq "") {
		return "NULL";
	}
	return make_str($str);
}

sub DumpHfList($)
{
	my ($self) = @_;
	my $res = "\tstatic hf_register_info hf[] = {\n";

	foreach (sort {$a->{INDEX} cmp $b->{INDEX}} values %{$self->{conformance}->{header_fields}})
	{
		$res .= "\t{ &$_->{INDEX},
		{ ".make_str($_->{NAME}).", ".make_str($_->{FILTER}).", $_->{FT_TYPE}, $_->{BASE_TYPE}, $_->{VALSSTRING}, $_->{MASK}, ".make_str_or_null($_->{BLURB}).", HFILL }},
";
	}

	return $res."\t};\n";
}


###############################################################################
# Function table
###############################################################################

sub DumpFunctionTable($)
{
	my $if = shift;

	my $res = "static dcerpc_sub_dissector $if->{NAME}\_dissectors[] = {\n";
	foreach (@{$if->{FUNCTIONS}}) {
		my $fn_name = $_->{NAME};
		$fn_name =~ s/^$if->{NAME}_//;
		$res.= "\t{ $_->{OPNUM}, \"$fn_name\",\n";
		$res.= "\t   $if->{NAME}_dissect_${fn_name}_request, $if->{NAME}_dissect_${fn_name}_response},\n";
	}

	$res .= "\t{ 0, NULL, NULL, NULL }\n";

	return "$res};\n";
}

sub CheckUsed($$)
{
	my ($self, $conformance) = @_;
	foreach (values %{$conformance->{header_fields}}) {
		if (not defined($self->{hf_used}->{$_->{INDEX}})) {
			warning($_->{POS}, "hf field `$_->{INDEX}' not used");
		}
	}

	foreach (values %{$conformance->{hf_renames}}) {
		if (not $_->{USED}) {
			warning($_->{POS}, "hf field `$_->{OLDNAME}' not used");
		}
	}

	foreach (values %{$conformance->{dissectorparams}}) {
		if (not $_->{USED}) {
			warning($_->{POS}, "dissector param never used");
		}
	}

	foreach (values %{$conformance->{imports}}) {
		if (not $_->{USED}) {
			warning($_->{POS}, "import never used");
		}
	}

	foreach (values %{$conformance->{types}}) {
		if (not $_->{USED} and defined($_->{POS})) {
			warning($_->{POS}, "type never used");
		}
	}

	foreach (values %{$conformance->{fielddescription}}) {
		if (not $_->{USED}) {
			warning($_->{POS}, "description never used");
		}
	}

	foreach (values %{$conformance->{tfs}}) {
		if (not $_->{USED}) {
			warning($_->{POS}, "True/False description never used");
		}
	}
}

1;
