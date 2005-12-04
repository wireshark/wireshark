##################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001,2005
# Copyright jelmer@samba.org 2004-2005
# Portions based on idl2eth.c by Ronnie Sahlberg
# released under the GNU GPL

=pod

=head1 NAME

Parse::Pidl::Ethereal::NDR - Parser generator for Ethereal

=cut

package Parse::Pidl::Ethereal::NDR;

use strict;
use Parse::Pidl::Typelist qw(getType);
use Parse::Pidl::Util qw(has_property ParseExpr property_matches make_str);
use Parse::Pidl::NDR qw(ContainsString GetNextLevel);
use Parse::Pidl::Dump qw(DumpTypedef DumpFunction);
use Parse::Pidl::Ethereal::Conformance qw(ReadConformance);

use vars qw($VERSION);
$VERSION = '0.01';

sub error($$)
{
	my ($e,$t) = @_;
	print "$e->{FILE}:$e->{LINE}: $t\n";
}

my @ett;

my %hf_used = ();
my %dissector_used = ();

my $conformance = undef;

my %ptrtype_mappings = (
	"unique" => "NDR_POINTER_UNIQUE",
	"ref" => "NDR_POINTER_REF",
	"ptr" => "NDR_POINTER_PTR"
);

sub StripPrefixes($)
{
	my ($s) = @_;

	foreach (@{$conformance->{strip_prefixes}}) {
		$s =~ s/^$_\_//g;
	}

	return $s;
}

# Convert a IDL structure field name (e.g access_mask) to a prettier
# string like 'Access Mask'.

sub field2name($)
{
    my($field) = shift;

    $field =~ s/_/ /g;		# Replace underscores with spaces
    $field =~ s/(\w+)/\u\L$1/g;	# Capitalise each word
    
    return $field;
}

my %res = ();
my $tabs = "";
sub pidl_code($)
{
	my $d = shift;
	if ($d) {
		$res{code} .= $tabs;
		$res{code} .= $d;
	}
	$res{code} .="\n";
}

sub pidl_hdr($) { my $x = shift; $res{hdr} .= "$x\n"; }
sub pidl_def($) { my $x = shift; $res{def} .= "$x\n"; }

sub indent()
{
	$tabs .= "\t";
}

sub deindent()
{
	$tabs = substr($tabs, 0, -1);
}

sub PrintIdl($)
{
	my $idl = shift;

	foreach (split /\n/, $idl) {
		pidl_code "/* IDL: $_ */";
	}

	pidl_code "";
}

#####################################################################
# parse the interface definitions
sub Interface($)
{
	my($interface) = @_;
	Const($_,$interface->{NAME}) foreach (@{$interface->{CONSTS}});
	Typedef($_,$interface->{NAME}) foreach (@{$interface->{TYPEDEFS}});
	Function($_,$interface->{NAME}) foreach (@{$interface->{FUNCTIONS}});
}

sub Enum($$$)
{
	my ($e,$name,$ifname) = @_;
	my $valsstring = "$ifname\_$name\_vals";
	my $dissectorname = "$ifname\_dissect\_enum\_".StripPrefixes($name);

	return if (defined($conformance->{noemit}->{StripPrefixes($name)}));

    	foreach (@{$e->{ELEMENTS}}) {
		if (/([^=]*)=(.*)/) {
			pidl_hdr "#define $1 ($2)";
		}
	}
	
	pidl_hdr "extern const value_string $valsstring\[];";
	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param);";

	pidl_def "const value_string ".$valsstring."[] = {";
    	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^=]*)=(.*)/);
		pidl_def "\t{ $1, \"$1\" },";
	}

	pidl_def "{ 0, NULL }";
	pidl_def "};";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "offset = dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, tree, drep, hf_index, NULL);";
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	my $enum_size = $e->{BASE_TYPE};
	$enum_size =~ s/uint//g;
	register_type($name, "offset = $dissectorname(tvb, offset, pinfo, tree, drep, \@HF\@, \@PARAM\@);", "FT_UINT$enum_size", "BASE_DEC", "0", "VALS($valsstring)", $enum_size / 8);
}

sub Bitmap($$$)
{
	my ($e,$name,$ifname) = @_;
	my $dissectorname = "$ifname\_dissect\_bitmap\_".StripPrefixes($name);

	register_ett("ett_$ifname\_$name");

	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param);";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item = NULL;";
	pidl_code "proto_tree *tree = NULL;";
	pidl_code "";
		
	pidl_code "g$e->{BASE_TYPE} flags;";
	if ($e->{ALIGN} > 1) {
		pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
	}

	pidl_code "";

	pidl_code "if(parent_tree) {";
	indent;
	pidl_code "item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, $e->{ALIGN}, TRUE);";
	pidl_code "tree = proto_item_add_subtree(item,ett_$ifname\_$name);";
	deindent;
	pidl_code "}\n";

	pidl_code "offset = dissect_ndr_$e->{BASE_TYPE}(tvb, offset, pinfo, NULL, drep, -1, &flags);";

	pidl_code "proto_item_append_text(item, \": \");\n";
	pidl_code "if (!flags)";
	pidl_code "\tproto_item_append_text(item, \"(No values set)\");\n";

	foreach (@{$e->{ELEMENTS}}) {
		next unless (/([^ ]*) (.*)/);
		my ($en,$ev) = ($1,$2);
		my $hf_bitname = "hf_$ifname\_$name\_$en";
		my $filtername = "$ifname\.$name\.$en";

		$hf_used{$hf_bitname} = 1;
		
		register_hf_field($hf_bitname, field2name($en), $filtername, "FT_BOOLEAN", $e->{ALIGN} * 8, "TFS(&$name\_$en\_tfs)", $ev, "");

		pidl_def "static const true_false_string $name\_$en\_tfs = {";
		pidl_def "   \"$en is SET\",";
		pidl_def "   \"$en is NOT SET\",";
		pidl_def "};";
		
		pidl_code "proto_tree_add_boolean(tree, $hf_bitname, tvb, offset-$e->{ALIGN}, $e->{ALIGN}, flags);";
		pidl_code "if (flags&$ev){";
		pidl_code "\tproto_item_append_text(item, \"$en\");";
		pidl_code "\tif (flags & (~$ev))";
		pidl_code "\t\tproto_item_append_text(item, \", \");";
		pidl_code "}";
		pidl_code "flags&=(~$ev);";
		pidl_code "";
	}

	pidl_code "if(flags){";
	pidl_code "\tproto_item_append_text(item, \"Unknown bitmap value 0x%x\", flags);";
	pidl_code "}\n";
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	my $size = $e->{BASE_TYPE};
	$size =~ s/uint//g;
	register_type($name, "offset = $dissectorname(tvb, offset, pinfo, tree, drep, \@HF\@, \@PARAM\@);", "FT_UINT$size", "BASE_DEC", "0", "NULL", $size/8);
}

sub ElementLevel($$$$$)
{
	my ($e,$l,$hf,$myname,$pn) = @_;

	my $param = 0;

	if (defined($conformance->{dissectorparams}->{$myname})) {
		$conformance->{dissectorparams}->{$myname}->{PARAM} = 1;
		$param = $conformance->{dissectorparams}->{$myname}->{PARAM};
	}

	if ($l->{TYPE} eq "POINTER") {
		my $type;
		if ($l->{LEVEL} eq "TOP") {
			$type = "toplevel";
		} elsif ($l->{LEVEL} eq "EMBEDDED") {
			$type = "embedded";
		}
		pidl_code "offset = dissect_ndr_$type\_pointer(tvb, offset, pinfo, tree, drep, $myname\_, $ptrtype_mappings{$l->{POINTER_TYPE}}, \"Pointer to ".field2name(StripPrefixes($e->{NAME})) . " ($e->{TYPE})\",$hf);";
	} elsif ($l->{TYPE} eq "ARRAY") {
		if ($l->{IS_INLINE}) {
			error($e->{ORIGINAL}, "Inline arrays not supported");
		} elsif ($l->{IS_FIXED}) {
			pidl_code "int i;";
			pidl_code "for (i = 0; i < $l->{SIZE_IS}; i++)";
			pidl_code "\toffset = $myname\_(tvb, offset, pinfo, tree, drep);";
		} else {
			my $type = "";
			$type .= "c" if ($l->{IS_CONFORMANT});
			$type .= "v" if ($l->{IS_VARYING});

			unless ($l->{IS_ZERO_TERMINATED}) {
				pidl_code "offset = dissect_ndr_u" . $type . "array(tvb, offset, pinfo, tree, drep, $myname\_);";
			} else {
				my $nl = GetNextLevel($e,$l);
				pidl_code "char *data;";
				pidl_code "";
				pidl_code "offset = dissect_ndr_$type" . "string(tvb, offset, pinfo, tree, drep, sizeof(g$nl->{DATA_TYPE}), $hf, FALSE, &data);";
				pidl_code "proto_item_append_text(tree, \": %s\", data);";
			}
		}
	} elsif ($l->{TYPE} eq "DATA") {
		if ($l->{DATA_TYPE} eq "string") {
			my $bs = 2; # Byte size defaults to that of UCS2


			($bs = 1) if (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_ASCII.*"));
			
			if (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_SIZE4.*") and property_matches($e, "flag", ".*LIBNDR_FLAG_STR_LEN4.*")) {
			        pidl_code "char *data;\n";
				pidl_code "offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, $bs, $hf, FALSE, &data);";
				pidl_code "proto_item_append_text(tree, \": %s\", data);";
			} elsif (property_matches($e, "flag", ".*LIBNDR_FLAG_STR_SIZE4.*")) {
				pidl_code "offset = dissect_ndr_vstring(tvb, offset, pinfo, tree, drep, $bs, $hf, FALSE, NULL);";
			} else {
				warn("Unable to handle string with flags $e->{PROPERTIES}->{flag}");
			}
		} else {
			my $call;

			if ($conformance->{imports}->{$l->{DATA_TYPE}}) {
				$call = $conformance->{imports}->{$l->{DATA_TYPE}}->{DATA};	
				$conformance->{imports}->{$l->{DATA_TYPE}}->{USED} = 1;
 		        } elsif (defined($conformance->{imports}->{"$pn.$e->{NAME}"})) {
 			        $call = $conformance->{imports}->{"$pn.$e->{NAME}"}->{DATA};
				$conformance->{imports}->{"$pn.$e->{NAME}"}->{USED} = 1;
			    
			} elsif (defined($conformance->{types}->{$l->{DATA_TYPE}})) {
				$call= $conformance->{types}->{$l->{DATA_TYPE}}->{DISSECTOR_NAME};
				$conformance->{types}->{$l->{DATA_TYPE}}->{USED} = 1;
			} else {
				if ($l->{DATA_TYPE} =~ /^([a-z]+)\_(.*)$/)
				{
					pidl_code "offset = $1_dissect_struct_$2(tvb,offset,pinfo,tree,drep,$hf,$param);";
				}

				return;
			}

			$call =~ s/\@HF\@/$hf/g;
			$call =~ s/\@PARAM\@/$param/g;
			pidl_code "$call";
		}
	} elsif ($_->{TYPE} eq "SUBCONTEXT") {
		my $num_bits = ($l->{HEADER_SIZE}*8);
		pidl_code "guint$num_bits size;";
		pidl_code "int start_offset = offset;";
		pidl_code "tvbuff_t *subtvb;";
		pidl_code "offset = dissect_ndr_uint$num_bits(tvb, offset, pinfo, tree, drep, $hf, &size);";
		pidl_code "proto_tree_add_text(tree, tvb, start_offset, offset - start_offset + size, \"Subcontext size\");";

		pidl_code "subtvb = tvb_new_subset(tvb, offset, size, -1);";
		pidl_code "$myname\_(subtvb, 0, pinfo, tree, drep);";
	} else {
		die("Unknown type `$_->{TYPE}'");
	}
}

sub Element($$$)
{
	my ($e,$pn,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect\_element\_".StripPrefixes($pn)."\_".StripPrefixes($e->{NAME});

	my $call_code = "offset = $dissectorname(tvb, offset, pinfo, tree, drep);";

	my $type = find_type($e->{TYPE});

	if (not defined($type)) {
		# default settings
		$type = {
			MASK => 0,
			VALSSTRING => "NULL",
			FT_TYPE => "FT_NONE",
			BASE_TYPE => "BASE_HEX"
		};
	}

	if (ContainsString($e)) {
		$type = {
			MASK => 0,
			VALSSTRING => "NULL",
			FT_TYPE => "FT_STRING",
			BASE_TYPE => "BASE_DEC"
		};
	}

	my $hf = register_hf_field("hf_$ifname\_$pn\_$e->{NAME}", field2name($e->{NAME}), "$ifname.$pn.$e->{NAME}", $type->{FT_TYPE}, $type->{BASE_TYPE}, $type->{VALSSTRING}, $type->{MASK}, "");
	$hf_used{$hf} = 1;

	my $eltname = StripPrefixes($pn) . ".$e->{NAME}";
	if (defined($conformance->{noemit}->{$eltname})) {
		return $call_code;
	}

	my $add = "";

	foreach (@{$e->{LEVELS}}) {
		next if ($_->{TYPE} eq "SWITCH");
		pidl_def "static int $dissectorname$add(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);";
		pidl_code "static int";
		pidl_code "$dissectorname$add(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)";
		pidl_code "{";
		indent;

		ElementLevel($e,$_,$hf,$dissectorname.$add,$pn);

		pidl_code "";
		pidl_code "return offset;";
		deindent;
		pidl_code "}\n";
		$add.="_";
		last if ($_->{TYPE} eq "ARRAY" and $_->{IS_ZERO_TERMINATED});
	}

	return $call_code;
}

sub Function($$$)
{
	my ($fn,$ifname) = @_;

	my %dissectornames;

	foreach (@{$fn->{ELEMENTS}}) {
	    $dissectornames{$_->{NAME}} = Element($_, $fn->{NAME}, $ifname) if not defined($dissectornames{$_->{NAME}});
	}
	
	my $fn_name = $_->{NAME};
	$fn_name =~ s/^${ifname}_//;

	PrintIdl DumpFunction($fn->{ORIGINAL});
	pidl_code "static int";
	pidl_code "$ifname\_dissect\_${fn_name}_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)";
	pidl_code "{";
	indent;
	pidl_code "guint32 status;\n";
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$_->{DIRECTION}})) {
			pidl_code "$dissectornames{$_->{NAME}}";
			pidl_code "offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);";
			pidl_code "";
		}
	}

	if (not defined($fn->{RETURN_TYPE})) {
	} elsif ($fn->{RETURN_TYPE} eq "NTSTATUS") {
		pidl_code "offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf\_$ifname\_status, &status);\n";
		pidl_code "if (status != 0 && check_col(pinfo->cinfo, COL_INFO))";
		pidl_code "\tcol_append_fstr(pinfo->cinfo, COL_INFO, \", Error: %s\", val_to_str(status, NT_errors, \"Unknown NT status 0x%08x\"));\n";
		$hf_used{"hf\_$ifname\_status"} = 1;
	} elsif ($fn->{RETURN_TYPE} eq "WERROR") {
		pidl_code "offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf\_$ifname\_werror, &status);\n";
		pidl_code "if (status != 0 && check_col(pinfo->cinfo, COL_INFO))";
		pidl_code "\tcol_append_fstr(pinfo->cinfo, COL_INFO, \", Error: %s\", val_to_str(status, DOS_errors, \"Unknown DOS error 0x%08x\"));\n";
		
		$hf_used{"hf\_$ifname\_werror"} = 1;
	} else {
		print "$fn->{FILE}:$fn->{LINE}: error: return type `$fn->{RETURN_TYPE}' not yet supported\n";
	}
		

	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	pidl_code "static int";
	pidl_code "$ifname\_dissect\_${fn_name}_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)";
	pidl_code "{";
	indent;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$_->{DIRECTION}})) {
			pidl_code "$dissectornames{$_->{NAME}}";
			pidl_code "offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);";
		}

	}

	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";
}

sub Struct($$$)
{
	my ($e,$name,$ifname) = @_;
	my $dissectorname = "$ifname\_dissect\_struct\_".StripPrefixes($name);

	return if (defined($conformance->{noemit}->{StripPrefixes($name)}));

	register_ett("ett_$ifname\_$name");

	my $res = "";
	($res.="\t".Element($_, $name, $ifname)."\n\n") foreach (@{$e->{ELEMENTS}});

	pidl_hdr "int $dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_);";

	pidl_code "int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item = NULL;";
	pidl_code "proto_tree *tree = NULL;";
	pidl_code "int old_offset;";
	pidl_code "";

	if ($e->{ALIGN} > 1) {
		pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
	}
	pidl_code "";

	pidl_code "old_offset = offset;";
	pidl_code "";
	pidl_code "if(parent_tree){";
	indent;
	pidl_code "item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);";
	pidl_code "tree = proto_item_add_subtree(item, ett_$ifname\_$name);";
	deindent;
	pidl_code "}";

	pidl_code "\n$res";

	pidl_code "proto_item_set_len(item, offset-old_offset);\n";
	pidl_code "return offset;";
	deindent;
	pidl_code "}\n";

	register_type($name, "offset = $dissectorname(tvb,offset,pinfo,tree,drep,\@HF\@,\@PARAM\@);", "FT_NONE", "BASE_NONE", 0, "NULL", 0);
}

sub Union($$$)
{
	my ($e,$name,$ifname) = @_;

	my $dissectorname = "$ifname\_dissect_".StripPrefixes($name);

	return if (defined($conformance->{noemit}->{StripPrefixes($name)}));
	
	register_ett("ett_$ifname\_$name");

	my $res = "";
	foreach (@{$e->{ELEMENTS}}) {
		$res.="\n\t\t$_->{CASE}:\n";
		if ($_->{TYPE} ne "EMPTY") {
			$res.="\t\t\t".Element($_, $name, $ifname)."\n";
		}
		$res.="\t\tbreak;\n";
	}

	my $switch_type;
	my $switch_dissect;
	my $switch_dt = getType($e->{SWITCH_TYPE});
	if ($switch_dt->{DATA}->{TYPE} eq "ENUM") {
		$switch_type = "g".Parse::Pidl::Typelist::enum_type_fn($switch_dt);
		$switch_dissect = "dissect_ndr_" .Parse::Pidl::Typelist::enum_type_fn($switch_dt);
	} elsif ($switch_dt->{DATA}->{TYPE} eq "SCALAR") {
		$switch_type = "g$e->{SWITCH_TYPE}";
		$switch_dissect = "dissect_ndr_$e->{SWITCH_TYPE}";
	}

	pidl_code "static int";
	pidl_code "$dissectorname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)";
	pidl_code "{";
	indent;
	pidl_code "proto_item *item = NULL;";
	pidl_code "proto_tree *tree = NULL;";
	pidl_code "int old_offset;";
	pidl_code "$switch_type level;";
	pidl_code "";

	if ($e->{ALIGN} > 1) {
		pidl_code "ALIGN_TO_$e->{ALIGN}_BYTES;";
	}

	pidl_code "";

	pidl_code "old_offset = offset;";
	pidl_code "if(parent_tree){";
	indent;
	pidl_code "item = proto_tree_add_text(parent_tree, tvb, offset, -1, \"$name\");";
	pidl_code "tree = proto_item_add_subtree(item, ett_$ifname\_$name);";
	deindent;
	pidl_code "}";

	pidl_code "";

	pidl_code "offset = $switch_dissect(tvb, offset, pinfo, tree, drep, hf_index, &level);";

	pidl_code "switch(level) {$res\t}";
	pidl_code "proto_item_set_len(item, offset-old_offset);\n";
	pidl_code "return offset;";
	deindent;
	pidl_code "}";

	register_type($name, "offset = $dissectorname(tvb, offset, pinfo, tree, drep, \@HF\@, \@PARAM\@);", "FT_NONE", "BASE_NONE", 0, "NULL", 0);
}

sub Const($$)
{
	my ($const,$ifname) = @_;
	
	if (!defined($const->{ARRAY_LEN}[0])) {
    		pidl_hdr "#define $const->{NAME}\t( $const->{VALUE} )\n";
    	} else {
    		pidl_hdr "#define $const->{NAME}\t $const->{VALUE}\n";
    	}
}

sub Typedef($$)
{
	my ($e,$ifname) = @_;

	PrintIdl DumpTypedef($e->{ORIGINAL});

	{
		ENUM => \&Enum,
		STRUCT => \&Struct,
		UNION => \&Union,
		BITMAP => \&Bitmap
	}->{$e->{DATA}->{TYPE}}->($e->{DATA}, $e->{NAME}, $ifname);
}

sub RegisterInterface($)
{
	my ($x) = @_;

	pidl_code "void proto_register_dcerpc_$x->{NAME}(void)";
	pidl_code "{";
	indent;

	$res{code}.=DumpHfList()."\n";
	$res{code}.="\n".DumpEttList()."\n";
	
	if (defined($x->{UUID})) {
	    # These can be changed to non-pidl_code names if the old dissectors
	    # in epan/dissctors are deleted.
    
	    my $name = uc($x->{NAME}) . " (pidl)";
	    my $short_name = uc($x->{NAME});
	    my $filter_name = $x->{NAME};

	    if (has_property($x, "helpstring")) {
	    	$name = $x->{PROPERTIES}->{helpstring};
	    }

	    if (defined($conformance->{protocols}->{$x->{NAME}})) {
		$short_name = $conformance->{protocols}->{$x->{NAME}}->{SHORTNAME};
		$name = $conformance->{protocols}->{$x->{NAME}}->{LONGNAME};
		$filter_name = $conformance->{protocols}->{$x->{NAME}}->{FILTERNAME};
	    }

	    pidl_code "proto_dcerpc_$x->{NAME} = proto_register_protocol(".make_str($name).", ".make_str($short_name).", ".make_str($filter_name).");";
	    
	    pidl_code "proto_register_field_array(proto_dcerpc_$x->{NAME}, hf, array_length (hf));";
	    pidl_code "proto_register_subtree_array(ett, array_length(ett));";
	} else {
	    pidl_code "proto_dcerpc = proto_get_id_by_filter_name(\"dcerpc\");";
	    pidl_code "proto_register_field_array(proto_dcerpc, hf, array_length(hf));";
	    pidl_code "proto_register_subtree_array(ett, array_length(ett));";
	}
	    
	deindent;
	pidl_code "}\n";
}

sub RegisterInterfaceHandoff($)
{
	my $x = shift;

	if (defined($x->{UUID})) {
	    pidl_code "void proto_reg_handoff_dcerpc_$x->{NAME}(void)";
	    pidl_code "{";
	    indent;
	    pidl_code "dcerpc_init_uuid(proto_dcerpc_$x->{NAME}, ett_dcerpc_$x->{NAME},";
	    pidl_code "\t&uuid_dcerpc_$x->{NAME}, ver_dcerpc_$x->{NAME},";
	    pidl_code "\t$x->{NAME}_dissectors, hf_$x->{NAME}_opnum);";
	    deindent;
	    pidl_code "}";

		$hf_used{"hf_$x->{NAME}_opnum"} = 1;
	}
}

sub ProcessInterface($)
{
	my ($x) = @_;

	push(@{$conformance->{strip_prefixes}}, $x->{NAME});

	my $define = "__PACKET_DCERPC_" . uc($_->{NAME}) . "_H";
	pidl_hdr "#ifndef $define";
	pidl_hdr "#define $define";
	pidl_hdr "";

	if (defined $x->{PROPERTIES}->{depends}) {
		foreach (split / /, $x->{PROPERTIES}->{depends}) {
			next if($_ eq "security");
			pidl_hdr "#include \"packet-dcerpc-$_\.h\"\n";
		}
	}

	pidl_def "static gint proto_dcerpc_$x->{NAME} = -1;";
	register_ett("ett_dcerpc_$x->{NAME}");
	register_hf_field("hf_$x->{NAME}_opnum", "Operation", "$x->{NAME}.opnum", "FT_UINT16", "BASE_DEC", "NULL", 0, "");

	if (defined($x->{UUID})) {
		my $if_uuid = $x->{UUID};

	    pidl_def "/* Version information */\n\n";
	    
	    pidl_def "static e_uuid_t uuid_dcerpc_$x->{NAME} = {";
	    pidl_def "\t0x" . substr($if_uuid, 1, 8) 
  		. ", 0x" . substr($if_uuid, 10, 4)
	    . ", 0x" . substr($if_uuid, 15, 4) . ",";
	    pidl_def "\t{ 0x" . substr($if_uuid, 20, 2) 
		. ", 0x" . substr($if_uuid, 22, 2)
	    . ", 0x" . substr($if_uuid, 25, 2)
	    . ", 0x" . substr($if_uuid, 27, 2)
	    . ", 0x" . substr($if_uuid, 29, 2)
	    . ", 0x" . substr($if_uuid, 31, 2)
	    . ", 0x" . substr($if_uuid, 33, 2)
	    . ", 0x" . substr($if_uuid, 35, 2) . " }";
	    pidl_def "};";
	
	    my $maj = $x->{VERSION};
	    $maj =~ s/\.(.*)$//g;
	    pidl_def "static guint16 ver_dcerpc_$x->{NAME} = $maj;";
	    pidl_def "";
	}

	Interface($x);

	pidl_code "\n".DumpFunctionTable($x);

	# Only register these two return types if they were actually used
	if (defined($hf_used{"hf_$x->{NAME}_status"})) {
		register_hf_field("hf_$x->{NAME}_status", "Status", "$x->{NAME}.status", "FT_UINT32", "BASE_HEX", "VALS(NT_errors)", 0, "");
	}

	if (defined($hf_used{"hf_$x->{NAME}_werror"})) {
		register_hf_field("hf_$x->{NAME}_werror", "Windows Error", "$x->{NAME}.werror", "FT_UINT32", "BASE_HEX", "VALS(DOS_errors)", 0, "");
	}

	RegisterInterface($x);
	RegisterInterfaceHandoff($x);

	pidl_hdr "#endif /* $define */";
}

sub find_type($)
{
	my $n = shift;

	return $conformance->{types}->{$n};
}

sub register_type($$$$$$$)
{
	my ($type,$call,$ft,$base,$mask,$vals,$length) = @_;

	$conformance->{types}->{$type} = {
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
sub Initialize($)
{
	my $cnf_file = shift;

	$conformance = {
		imports => {},
		header_fields=> {} 
	};

	ReadConformance($cnf_file, $conformance) or print "Warning: No conformance file `$cnf_file'\n";
	
	foreach my $bytes (qw(1 2 4 8)) {
		my $bits = $bytes * 8;
		register_type("uint$bits", "offset = dissect_ndr_uint$bits(tvb, offset, pinfo, tree, drep, \@HF\@,NULL);", "FT_UINT$bits", "BASE_DEC", 0, "NULL", $bytes);
		register_type("int$bits", "offset = dissect_ndr_uint$bits(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);", "FT_INT$bits", "BASE_DEC", 0, "NULL", $bytes);
	}
		
	register_type("udlong", "offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);", "FT_UINT64", "BASE_DEC", 0, "NULL", 4);
	register_type("bool8", "offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);","FT_INT8", "BASE_DEC", 0, "NULL", 1);
	register_type("char", "offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);","FT_INT8", "BASE_DEC", 0, "NULL", 1);
	register_type("long", "offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);","FT_INT32", "BASE_DEC", 0, "NULL", 4);
	register_type("dlong", "offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);","FT_INT64", "BASE_DEC", 0, "NULL", 8);
	register_type("GUID", "offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);","FT_GUID", "BASE_NONE", 0, "NULL", 4);
	register_type("policy_handle", "offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, \@HF\@, NULL, NULL, \@PARAM\@&0x01, \@PARAM\@&0x02);","FT_BYTES", "BASE_NONE", 0, "NULL", 4);
	register_type("NTTIME", "offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, \@HF\@);","FT_ABSOLUTE_TIME", "BASE_NONE", 0, "NULL", 4);
	register_type("NTTIME_hyper", "offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, \@HF\@);","FT_ABSOLUTE_TIME", "BASE_NONE", 0, "NULL", 4);
	register_type("time_t", "offset = dissect_ndr_time_t(tvb, offset, pinfo,tree, drep, \@HF\@, NULL);","FT_ABSOLUTE_TIME", "BASE_DEC", 0, "NULL", 4);
	register_type("NTTIME_1sec", "offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, \@HF\@);", "FT_ABSOLUTE_TIME", "BASE_NONE", 0, "NULL", 4);
	register_type("SID", "
		dcerpc_info *di = (dcerpc_info *)pinfo->private_data;

		di->hf_index = \@HF\@;

		offset = dissect_ndr_nt_SID_with_options(tvb, offset, pinfo, tree, drep, param);
	","FT_STRING", "BASE_DEC", 0, "NULL", 4);
	register_type("WERROR", 
		"offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, \@HF\@, NULL);","FT_UINT32", "BASE_DEC", 0, "VALS(NT_errors)", 4);

}

#####################################################################
# Generate ethereal parser and header code
sub Parse($$$$)
{
	my($ndr,$idl_file,$h_filename,$cnf_file) = @_;
	Initialize($cnf_file);

	return (undef, undef) if defined($conformance->{noemit_dissector});

	$tabs = "";

	%res = (code=>"",def=>"",hdr=>"");
	@ett = ();

	my $notice = 
"/* DO NOT EDIT
	This filter was automatically generated
	from $idl_file and $cnf_file.
	
	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Ethereal team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.ethereal.com/Pidl
*/

";

	pidl_hdr $notice;

	$res{headers} = "\n";
	$res{headers} .= "#ifdef HAVE_CONFIG_H\n";
	$res{headers} .= "#include \"config.h\"\n";
	$res{headers} .= "#endif\n\n";
	$res{headers} .= "#include <glib.h>\n";
	$res{headers} .= "#include <string.h>\n";
	$res{headers} .= "#include <epan/packet.h>\n\n";

	$res{headers} .= "#include \"packet-dcerpc.h\"\n";
	$res{headers} .= "#include \"packet-dcerpc-nt.h\"\n";
	$res{headers} .= "#include \"packet-windows-common.h\"\n";

	use File::Basename;	
	my $h_basename = basename($h_filename);

	$res{headers} .= "#include \"$h_basename\"\n";
	pidl_code "";

	# Ethereal protocol registration

	ProcessInterface($_) foreach (@$ndr);

	$res{ett} = DumpEttDeclaration();
	$res{hf} = DumpHfDeclaration();

	my $parser = $notice;
	$parser.= $res{headers};
	$parser.=$res{ett};
	$parser.=$res{hf};
	$parser.=$res{def};
	$parser.=$conformance->{override};
	$parser.=$res{code};

	my $header = "/* autogenerated by pidl */\n\n";
	$header.=$res{hdr};

	CheckUsed($conformance);
    
	return ($parser,$header);
}

###############################################################################
# ETT
###############################################################################

sub register_ett($)
{
	my $name = shift;

	push (@ett, $name);	
}

sub DumpEttList()
{
	my $res = "\tstatic gint *ett[] = {\n";
	foreach (@ett) {
		$res .= "\t\t&$_,\n";
	}

	return "$res\t};\n";
}

sub DumpEttDeclaration()
{
	my $res = "\n/* Ett declarations */\n";
	foreach (@ett) {
		$res .= "static gint $_ = -1;\n";
	}

	return "$res\n";
}

###############################################################################
# HF
###############################################################################

sub register_hf_field($$$$$$$$) 
{
	my ($index,$name,$filter_name,$ft_type,$base_type,$valsstring,$mask,$blurb) = @_;

	if (defined ($conformance->{hf_renames}->{$index})) {
		$conformance->{hf_renames}->{$index}->{USED} = 1;
		return $conformance->{hf_renames}->{$index}->{NEWNAME};
	}

	$conformance->{header_fields}->{$index} = {
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
			defined($conformance->{fielddescription}->{$index})) {
		$conformance->{header_fields}->{$index}->{BLURB} = 
			$conformance->{fielddescription}->{$index}->{DESCRIPTION};
		$conformance->{fielddescription}->{$index}->{USED} = 1;
	}

	return $index;
}

sub DumpHfDeclaration()
{
	my $res = "";

	$res = "\n/* Header field declarations */\n";

	foreach (keys %{$conformance->{header_fields}}) 
	{
		$res .= "static gint $_ = -1;\n";
	}

	return "$res\n";
}

sub DumpHfList()
{
	my $res = "\tstatic hf_register_info hf[] = {\n";

	foreach (values %{$conformance->{header_fields}}) 
	{
		$res .= "\t{ &$_->{INDEX}, 
	  { ".make_str($_->{NAME}).", ".make_str($_->{FILTER}).", $_->{FT_TYPE}, $_->{BASE_TYPE}, $_->{VALSSTRING}, $_->{MASK}, ".make_str($_->{BLURB}).", HFILL }},
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

sub CheckUsed($)
{
	my $conformance = shift;
	foreach (values %{$conformance->{header_fields}}) {
		if (not defined($hf_used{$_->{INDEX}})) {
			print "$_->{POS}: warning: hf field `$_->{INDEX}' not used\n";
		}
	}

	foreach (values %{$conformance->{hf_renames}}) {
		if (not $_->{USED}) {
			print "$_->{POS}: warning: hf field `$_->{OLDNAME}' not used\n";
		}
	}

	foreach (values %{$conformance->{dissectorparams}}) {
		if (not $_->{USED}) {
			print "$_->{POS}: warning: dissector param never used\n";
		}
	}

	foreach (values %{$conformance->{imports}}) {
		if (not $_->{USED}) {
			print "$_->{POS}: warning: import never used\n";
		}
	}

	foreach (values %{$conformance->{types}}) {
		if (not $_->{USED} and defined($_->{POS})) {
			print "$_->{POS}: warning: type never used\n";
		}
	}

	foreach (values %{$conformance->{fielddescription}}) {
		if (not $_->{USED}) {
			print "$_->{POS}: warning: description never used\n";
		}
	}
}

1;
