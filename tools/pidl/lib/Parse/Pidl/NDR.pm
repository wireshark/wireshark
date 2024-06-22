###################################################
# Samba4 NDR info tree generator
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2006
# released under the GNU GPL

=pod

=head1 NAME

Parse::Pidl::NDR - NDR parsing information generator

=head1 DESCRIPTION

Return a table describing the order in which the parts of an element
should be parsed
Possible level types:
 - POINTER
 - ARRAY
 - SUBCONTEXT
 - SWITCH
 - DATA

=head1 AUTHOR

Jelmer Vernooij <jelmer@samba.org>

=cut

package Parse::Pidl::NDR;

require Exporter;
use vars qw($VERSION);
$VERSION = '0.01';
@ISA = qw(Exporter);
@EXPORT = qw(GetPrevLevel GetNextLevel ContainsDeferred ContainsPipe ContainsString);
@EXPORT_OK = qw(GetElementLevelTable ParseElement ReturnTypeElement ValidElement align_type mapToScalar ParseType can_contain_deferred is_charset_array);

use strict;
use warnings;
use Parse::Pidl qw(warning fatal);
use Parse::Pidl::Typelist qw(hasType getType typeIs expandAlias mapScalarType is_fixed_size_scalar);
use Parse::Pidl::Util qw(has_property property_matches);

# Alignment of the built-in scalar types
my $scalar_alignment = {
	'void' => 0,
	'char' => 1,
	'int8' => 1,
	'uint8' => 1,
	'int16' => 2,
	'uint16' => 2,
	'int1632' => 3,
	'uint1632' => 3,
	'int32' => 4,
	'uint32' => 4,
	'int3264' => 5,
	'uint3264' => 5,
	'hyper' => 8,
	'double' => 8,
	'pointer' => 8,
	'dlong' => 4,
	'udlong' => 4,
	'udlongr' => 4,
	'DATA_BLOB' => 4,
	'string' => 4,
	'string_array' => 4, #???
	'time_t' => 4,
	'uid_t' => 8,
	'gid_t' => 8,
	'NTTIME' => 4,
	'NTTIME_1sec' => 4,
	'NTTIME_hyper' => 8,
	'WERROR' => 4,
	'NTSTATUS' => 4,
	'COMRESULT' => 4,
	'dns_string' => 4,
	'nbt_string' => 4,
	'wrepl_nbt_name' => 4,
	'ipv4address' => 4,
	'ipv6address' => 4, #16?
	'dnsp_name' => 1,
	'dnsp_string' => 1,
	'HRESULT' => 4,
};

sub GetElementLevelTable($$$)
{
	my ($e, $pointer_default, $ms_union) = @_;

	my $order = [];
	my $is_deferred = 0;
	my @bracket_array = ();
	my @length_is = ();
	my @size_is = ();
	my $pointer_idx = 0;

	if (has_property($e, "size_is")) {
		@size_is = split /,/, has_property($e, "size_is");
	}

	if (has_property($e, "length_is")) {
		@length_is = split /,/, has_property($e, "length_is");
	}

	if (defined($e->{ARRAY_LEN})) {
		@bracket_array = @{$e->{ARRAY_LEN}};
	}

	if (has_property($e, "out")) {
		my $needptrs = 1;

		if (has_property($e, "string") and not has_property($e, "in")) { $needptrs++; }
		if ($#bracket_array >= 0) { $needptrs = 0; }

		warning($e, "[out] argument `$e->{NAME}' not a pointer") if ($needptrs > $e->{POINTERS});
	}

	my $allow_pipe = (($e->{PARENT}->{TYPE} // '') eq "FUNCTION");
	my $is_pipe = typeIs($e->{TYPE}, "PIPE");

	if ($is_pipe) {
		if (not $allow_pipe) {
			fatal($e, "argument `$e->{NAME}' is a pipe and not allowed on $e->{PARENT}->{TYPE}");
		}

		if ($e->{POINTERS} > 1) {
			fatal($e, "$e->{POINTERS} are not allowed on pipe element $e->{NAME}");
		}

		if ($e->{POINTERS} < 0) {
			fatal($e, "pipe element $e->{NAME} needs pointer");
		}

		if ($e->{POINTERS} == 1 and pointer_type($e) ne "ref") {
			fatal($e, "pointer should be 'ref' on pipe element $e->{NAME}");
		}

		if (scalar(@size_is) > 0) {
			fatal($e, "size_is() on pipe element");
		}

		if (scalar(@length_is) > 0) {
			fatal($e, "length_is() on pipe element");
		}

		if (scalar(@bracket_array) > 0) {
			fatal($e, "brackets on pipe element");
		}

		if (defined(has_property($e, "subcontext"))) {
			fatal($e, "subcontext on pipe element");
		}

		if (has_property($e, "switch_is")) {
			fatal($e, "switch_is on pipe element");
		}

		if (can_contain_deferred($e->{TYPE})) {
			fatal($e, "$e->{TYPE} can_contain_deferred - not allowed on pipe element");
		}
	}

	# Parse the [][][][] style array stuff
	for my $i (0 .. $#bracket_array) {
		my $d = $bracket_array[$#bracket_array - $i];
		my $size = $d;
		my $length = $d;
		my $is_surrounding = 0;
		my $is_varying = 0;
		my $is_conformant = 0;
		my $is_string = 0;
		my $is_fixed = 0;
		my $is_inline = 0;
		my $is_to_null = 0;

		if ($d eq "*") {
			$is_conformant = 1;
			if ($size = shift @size_is) {
				if ($e->{POINTERS} < 1 and has_property($e, "string")) {
					$is_string = 1;
					delete($e->{PROPERTIES}->{string});
				}
			} elsif ((scalar(@size_is) == 0) and has_property($e, "string")) {
				$is_string = 1;
				delete($e->{PROPERTIES}->{string});
			} else {
				fatal($e, "Must specify size_is() for conformant array!")
			}

			if (($length = shift @length_is) or $is_string) {
				$is_varying = 1;
			} else {
				$length = $size;
			}

			if ($e == $e->{PARENT}->{ELEMENTS}[-1] 
				and $e->{PARENT}->{TYPE} ne "FUNCTION") {
				$is_surrounding = 1;
			}
		}

		$is_fixed = 1 if (not $is_conformant and Parse::Pidl::Util::is_constant($size));
		$is_inline = 1 if (not $is_conformant and not Parse::Pidl::Util::is_constant($size));

		if ($i == 0 and $is_fixed and has_property($e, "string")) {
			$is_fixed = 0;
			$is_varying = 1;
			$is_string = 1;
			delete($e->{PROPERTIES}->{string});
		}

		if (has_property($e, "to_null")) {
			$is_to_null = 1;
		}

		push (@$order, {
			TYPE => "ARRAY",
			SIZE_IS => $size,
			LENGTH_IS => $length,
			IS_DEFERRED => $is_deferred,
			IS_SURROUNDING => $is_surrounding,
			IS_ZERO_TERMINATED => $is_string,
			IS_VARYING => $is_varying,
			IS_CONFORMANT => $is_conformant,
			IS_FIXED => $is_fixed,
			IS_INLINE => $is_inline,
			IS_TO_NULL => $is_to_null
		});
	}

	# Next, all the pointers
	foreach my $i (1..$e->{POINTERS}) {
		my $level = "EMBEDDED";
		# Top level "ref" pointers do not have a referrent identifier
		$level = "TOP" if ($i == 1 and $e->{PARENT}->{TYPE} eq "FUNCTION");

		my $pt;
		#
		# Only the first level gets the pointer type from the
		# pointer property, the others get them from
		# the pointer_default() interface property
		#
		# see http://msdn2.microsoft.com/en-us/library/aa378984(VS.85).aspx
		# (Here they talk about the rightmost pointer, but testing shows
		#  they mean the leftmost pointer.)
		#
		# --metze
		#
		$pt = pointer_type($e);
		if ($i > 1) {
			$is_deferred = 1 if ($pt ne "ref" and $e->{PARENT}->{TYPE} eq "FUNCTION");
			$pt = $pointer_default;
		}

		push (@$order, { 
			TYPE => "POINTER",
			POINTER_TYPE => $pt,
			POINTER_INDEX => $pointer_idx,
			IS_DEFERRED => "$is_deferred",
			LEVEL => $level
		});

		warning($e, "top-level \[out\] pointer `$e->{NAME}' is not a \[ref\] pointer") 
			if ($i == 1 and $pt ne "ref" and
				$e->{PARENT}->{TYPE} eq "FUNCTION" and 
				not has_property($e, "in"));

		$pointer_idx++;
		
		# everything that follows will be deferred
		$is_deferred = 1 if ($level ne "TOP");

		my $array_size = shift @size_is;
		my $array_length;
		my $is_varying;
		my $is_conformant;
		my $is_string = 0;
		if ($array_size) {
			$is_conformant = 1;
			if ($array_length = shift @length_is) {
				$is_varying = 1;
			} else {
				$array_length = $array_size;
				$is_varying =0;
			}
		} 
		
		if (scalar(@size_is) == 0 and has_property($e, "string") and 
		    $i == $e->{POINTERS}) {
			$is_string = 1;
			$is_varying = $is_conformant = has_property($e, "noheader")?0:1;
			delete($e->{PROPERTIES}->{string});
		}

		if ($array_size or $is_string) {
			push (@$order, {
				TYPE => "ARRAY",
				SIZE_IS => $array_size,
				LENGTH_IS => $array_length,
				IS_DEFERRED => $is_deferred,
				IS_SURROUNDING => 0,
				IS_ZERO_TERMINATED => $is_string,
				IS_VARYING => $is_varying,
				IS_CONFORMANT => $is_conformant,
				IS_FIXED => 0,
				IS_INLINE => 0
			});

			$is_deferred = 0;
		} 
	}

	if ($is_pipe) {
		push (@$order, {
			TYPE => "PIPE",
			IS_DEFERRED => 0,
			CONTAINS_DEFERRED => 0,
		});

		my $i = 0;
		foreach (@$order) { $_->{LEVEL_INDEX} = $i; $i+=1; }

		return $order;
	}

	if (defined(has_property($e, "subcontext"))) {
		my $hdr_size = has_property($e, "subcontext");
		my $subsize = has_property($e, "subcontext_size");
		if (not defined($subsize)) { 
			$subsize = -1; 
		}
		
		push (@$order, {
			TYPE => "SUBCONTEXT",
			HEADER_SIZE => $hdr_size,
			SUBCONTEXT_SIZE => $subsize,
			IS_DEFERRED => $is_deferred,
			COMPRESSION => has_property($e, "compression"),
		});
	}

	if (my $switch = has_property($e, "switch_is")) {
		push (@$order, {
			TYPE => "SWITCH", 
			SWITCH_IS => $switch,
			IS_DEFERRED => $is_deferred
		});
	}

	if (scalar(@size_is) > 0) {
		fatal($e, "size_is() on non-array element");
	}

	if (scalar(@length_is) > 0) {
		fatal($e, "length_is() on non-array element");
	}

	if (has_property($e, "string")) {
		fatal($e, "string() attribute on non-array element");
	}

	push (@$order, {
		TYPE => "DATA",
		DATA_TYPE => $e->{TYPE},
		IS_DEFERRED => $is_deferred,
		CONTAINS_DEFERRED => can_contain_deferred($e->{TYPE}),
		IS_SURROUNDING => 0 #FIXME
	});

	my $i = 0;
	foreach (@$order) { $_->{LEVEL_INDEX} = $i; $i+=1; }

	return $order;
}

sub GetTypedefLevelTable($$$$)
{
	my ($e, $data, $pointer_default, $ms_union) = @_;

	my $order = [];

	push (@$order, {
		TYPE => "TYPEDEF"
	});

	my $i = 0;
	foreach (@$order) { $_->{LEVEL_INDEX} = $i; $i+=1; }

	return $order;
}

#####################################################################
# see if a type contains any deferred data 
sub can_contain_deferred($)
{
	sub can_contain_deferred($);
	my ($type) = @_;

	return 1 unless (hasType($type)); # assume the worst

	$type = getType($type);

	return 0 if (Parse::Pidl::Typelist::is_scalar($type));

	return can_contain_deferred($type->{DATA}) if ($type->{TYPE} eq "TYPEDEF");

	return 0 unless defined($type->{ELEMENTS});

	foreach (@{$type->{ELEMENTS}}) {
		return 1 if ($_->{POINTERS});
		return 1 if (can_contain_deferred ($_->{TYPE}));
	}
	
	return 0;
}

sub pointer_type($)
{
	my $e = shift;

	return undef unless $e->{POINTERS};
	
	return "ref" if (has_property($e, "ref"));
	return "full" if (has_property($e, "ptr"));
	return "sptr" if (has_property($e, "sptr"));
	return "unique" if (has_property($e, "unique"));
	return "relative" if (has_property($e, "relative"));
	return "relative_short" if (has_property($e, "relative_short"));
	return "ignore" if (has_property($e, "ignore"));

	return undef;
}

#####################################################################
# work out the correct alignment for a structure or union
sub find_largest_alignment($)
{
	my $s = shift;

	my $align = 1;
	for my $e (@{$s->{ELEMENTS}}) {
		my $a = 1;

		if ($e->{POINTERS}) {
			# this is a hack for NDR64
			# the NDR layer translates this into
			# an alignment of 4 for NDR and 8 for NDR64
			$a = 5;
		} elsif (has_property($e, "subcontext")) { 
			$a = 1;
		} elsif (has_property($e, "transmit_as")) {
			$a = align_type($e->{PROPERTIES}->{transmit_as});
		} else {
			$a = align_type($e->{TYPE}); 
		}

		$align = $a if ($align < $a);
	}

	return $align;
}

#####################################################################
# align a type
sub align_type($)
{
	sub align_type($);
	my ($e) = @_;

	if (ref($e) eq "HASH" and $e->{TYPE} eq "SCALAR") {
		my $ret = $scalar_alignment->{$e->{NAME}};
		if (not defined $ret) {
			warning($e, "no scalar alignment for $e->{NAME}!");
			return 0;
		}
		return $ret;
	}

	return 0 if ($e eq "EMPTY");

	unless (hasType($e)) {
	    # it must be an external type - all we can do is guess 
		# warning($e, "assuming alignment of unknown type '$e' is 4");
	    return 4;
	}

	my $dt = getType($e);

	if ($dt->{TYPE} eq "TYPEDEF") {
		return align_type($dt->{DATA});
	} elsif ($dt->{TYPE} eq "CONFORMANCE") {
		return $dt->{DATA}->{ALIGN};
	} elsif ($dt->{TYPE} eq "ENUM") {
		return align_type(Parse::Pidl::Typelist::enum_type_fn($dt));
	} elsif ($dt->{TYPE} eq "BITMAP") {
		return align_type(Parse::Pidl::Typelist::bitmap_type_fn($dt));
	} elsif (($dt->{TYPE} eq "STRUCT") or ($dt->{TYPE} eq "UNION")) {
		# Struct/union without body: assume 4
		return 4 unless (defined($dt->{ELEMENTS}));
		return find_largest_alignment($dt);
	} elsif (($dt->{TYPE} eq "PIPE")) {
		return 5;
	}

	die("Unknown data type type $dt->{TYPE}");
}

sub ParseElement($$$)
{
	my ($e, $pointer_default, $ms_union) = @_;

	$e->{TYPE} = expandAlias($e->{TYPE});

	if (ref($e->{TYPE}) eq "HASH") {
		$e->{TYPE} = ParseType($e->{TYPE}, $pointer_default, $ms_union);
	}

	return {
		NAME => $e->{NAME},
		TYPE => $e->{TYPE},
		PROPERTIES => $e->{PROPERTIES},
		LEVELS => GetElementLevelTable($e, $pointer_default, $ms_union),
		REPRESENTATION_TYPE => ($e->{PROPERTIES}->{represent_as} or $e->{TYPE}),
		ALIGN => align_type($e->{TYPE}),
		ORIGINAL => $e
	};
}

sub ParseStruct($$$)
{
	my ($struct, $pointer_default, $ms_union) = @_;
	my @elements = ();
	my $surrounding = undef;

	return {
		TYPE => "STRUCT",
		NAME => $struct->{NAME},
		SURROUNDING_ELEMENT => undef,
		ELEMENTS => undef,
		PROPERTIES => $struct->{PROPERTIES},
		ORIGINAL => $struct,
		ALIGN => undef
	} unless defined($struct->{ELEMENTS});

	CheckPointerTypes($struct, $pointer_default);

	foreach my $x (@{$struct->{ELEMENTS}}) 
	{
		my $e = ParseElement($x, $pointer_default, $ms_union);
		if ($x != $struct->{ELEMENTS}[-1] and 
			$e->{LEVELS}[0]->{IS_SURROUNDING}) {
			fatal($x, "conformant member not at end of struct");
		}
		push @elements, $e;
	}

	my $e = $elements[-1];
	if (defined($e) and defined($e->{LEVELS}[0]->{IS_SURROUNDING}) and
		$e->{LEVELS}[0]->{IS_SURROUNDING}) {
		$surrounding = $e;
	}

	if (defined $e->{TYPE} && $e->{TYPE} eq "string"
	    &&  property_matches($e, "flag", ".*LIBNDR_FLAG_STR_CONFORMANT.*")) {
		$surrounding = $struct->{ELEMENTS}[-1];
	}

	my $align = undef;
	if ($struct->{NAME}) {
		$align = align_type($struct->{NAME});
	}
		
	return {
		TYPE => "STRUCT",
		NAME => $struct->{NAME},
		SURROUNDING_ELEMENT => $surrounding,
		ELEMENTS => \@elements,
		PROPERTIES => $struct->{PROPERTIES},
		ORIGINAL => $struct,
		ALIGN => $align
	};
}

sub ParseUnion($$)
{
	my ($e, $pointer_default, $ms_union) = @_;
	my @elements = ();
	my $is_ms_union = $ms_union;
	$is_ms_union = 1 if has_property($e, "ms_union");
	my $hasdefault = 0;
	my $switch_type = has_property($e, "switch_type");
	unless (defined($switch_type)) { $switch_type = "uint32"; }
	if (has_property($e, "nodiscriminant")) { $switch_type = undef; }

	return {
		TYPE => "UNION",
		NAME => $e->{NAME},
		SWITCH_TYPE => $switch_type,
		ELEMENTS => undef,
		PROPERTIES => $e->{PROPERTIES},
		HAS_DEFAULT => $hasdefault,
		IS_MS_UNION => $is_ms_union,
		ORIGINAL => $e,
		ALIGN => undef
	} unless defined($e->{ELEMENTS});

	CheckPointerTypes($e, $pointer_default);

	foreach my $x (@{$e->{ELEMENTS}}) 
	{
		my $t;
		if ($x->{TYPE} eq "EMPTY") {
			$t = { TYPE => "EMPTY" };
		} else {
			$t = ParseElement($x, $pointer_default, $ms_union);
		}
		if (has_property($x, "default")) {
			$t->{CASE} = "default";
			$hasdefault = 1;
		} elsif (defined($x->{PROPERTIES}->{case})) {
			$t->{CASE} = "case $x->{PROPERTIES}->{case}";
		} else {
			die("Union element $x->{NAME} has neither default nor case property");
		}
		push @elements, $t;
	}

	my $align = undef;
	if ($e->{NAME}) {
		$align = align_type($e->{NAME});
	}

	return {
		TYPE => "UNION",
		NAME => $e->{NAME},
		SWITCH_TYPE => $switch_type,
		ELEMENTS => \@elements,
		PROPERTIES => $e->{PROPERTIES},
		HAS_DEFAULT => $hasdefault,
		IS_MS_UNION => $is_ms_union,
		ORIGINAL => $e,
		ALIGN => $align
	};
}

sub ParseEnum($$)
{
	my ($e, $pointer_default, $ms_union) = @_;

	return {
		TYPE => "ENUM",
		NAME => $e->{NAME},
		BASE_TYPE => Parse::Pidl::Typelist::enum_type_fn($e),
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES},
		ORIGINAL => $e
	};
}

sub ParseBitmap($$$)
{
	my ($e, $pointer_default, $ms_union) = @_;

	return {
		TYPE => "BITMAP",
		NAME => $e->{NAME},
		BASE_TYPE => Parse::Pidl::Typelist::bitmap_type_fn($e),
		ELEMENTS => $e->{ELEMENTS},
		PROPERTIES => $e->{PROPERTIES},
		ORIGINAL => $e
	};
}

sub ParsePipe($$$)
{
	my ($pipe, $pointer_default, $ms_union) = @_;

	my $pname = $pipe->{NAME};
	$pname = $pipe->{PARENT}->{NAME} unless defined $pname;

	if (not defined($pipe->{PROPERTIES})
	    and defined($pipe->{PARENT}->{PROPERTIES})) {
		$pipe->{PROPERTIES} = $pipe->{PARENT}->{PROPERTIES};
	}

	if (ref($pipe->{DATA}) eq "HASH") {
		if (not defined($pipe->{DATA}->{PROPERTIES})
		    and defined($pipe->{PROPERTIES})) {
			$pipe->{DATA}->{PROPERTIES} = $pipe->{PROPERTIES};
		}
	}

	my $struct = ParseStruct($pipe->{DATA}, $pointer_default, $ms_union);
	$struct->{ALIGN} = 5;
	$struct->{NAME} = "$pname\_chunk";

	# 'count' is element [0] and 'array' [1]
	my $e = $struct->{ELEMENTS}[1];
	# level [0] is of type "ARRAY"
	my $l = $e->{LEVELS}[1];

	# here we check that pipe elements have a fixed size type
	while (defined($l)) {
		my $cl = $l;
		$l = GetNextLevel($e, $cl);
		if ($cl->{TYPE} ne "DATA") {
			fatal($pipe, el_name($pipe) . ": pipe contains non DATA level");
		}

		# for now we only support scalars
		next if is_fixed_size_scalar($cl->{DATA_TYPE});

		fatal($pipe, el_name($pipe) . ": pipe contains non fixed size type[$cl->{DATA_TYPE}]");
	}

	return {
		TYPE => "PIPE",
		NAME => $pipe->{NAME},
		DATA => $struct,
		PROPERTIES => $pipe->{PROPERTIES},
		ORIGINAL => $pipe,
	};
}

sub ParseType($$$)
{
	my ($d, $pointer_default, $ms_union) = @_;

	my $data = {
		STRUCT => \&ParseStruct,
		UNION => \&ParseUnion,
		ENUM => \&ParseEnum,
		BITMAP => \&ParseBitmap,
		TYPEDEF => \&ParseTypedef,
		PIPE => \&ParsePipe,
	}->{$d->{TYPE}}->($d, $pointer_default, $ms_union);

	return $data;
}

sub ParseTypedef($$)
{
	my ($d, $pointer_default, $ms_union) = @_;

	my $data;

	if (ref($d->{DATA}) eq "HASH") {
		if (defined($d->{DATA}->{PROPERTIES})
		    and not defined($d->{PROPERTIES})) {
			$d->{PROPERTIES} = $d->{DATA}->{PROPERTIES};
		}

		$data = ParseType($d->{DATA}, $pointer_default, $ms_union);
		$data->{ALIGN} = align_type($d->{NAME});
	} else {
		$data = getType($d->{DATA});
	}

	return {
		NAME => $d->{NAME},
		TYPE => $d->{TYPE},
		PROPERTIES => $d->{PROPERTIES},
		LEVELS => GetTypedefLevelTable($d, $data, $pointer_default, $ms_union),
		DATA => $data,
		ORIGINAL => $d
	};
}

sub ParseConst($$)
{
	my ($ndr,$d) = @_;

	return $d;
}

sub ParseFunction($$$$)
{
	my ($ndr,$d,$opnum,$ms_union) = @_;
	my @elements = ();
	my $rettype = undef;
	my $thisopnum = undef;

	CheckPointerTypes($d, "ref");

	if (not defined($d->{PROPERTIES}{noopnum})) {
		$thisopnum = ${$opnum};
		${$opnum}++;
	}

	foreach my $x (@{$d->{ELEMENTS}}) {
		my $e = ParseElement($x, $ndr->{PROPERTIES}->{pointer_default}, $ms_union);
		push (@{$e->{DIRECTION}}, "in") if (has_property($x, "in"));
		push (@{$e->{DIRECTION}}, "out") if (has_property($x, "out"));

		push (@elements, $e);
	}

	if ($d->{RETURN_TYPE} ne "void") {
		$rettype = expandAlias($d->{RETURN_TYPE});
	}
	
	return {
			NAME => $d->{NAME},
			TYPE => "FUNCTION",
			OPNUM => $thisopnum,
			RETURN_TYPE => $rettype,
			PROPERTIES => $d->{PROPERTIES},
			ELEMENTS => \@elements,
			ORIGINAL => $d
		};
}

sub ReturnTypeElement($)
{
	my ($fn) = @_;

	return undef unless defined($fn->{RETURN_TYPE});

	my $e = {
		"NAME" => "result",
		"TYPE" => $fn->{RETURN_TYPE},
		"PROPERTIES" => undef,
		"POINTERS" => 0,
		"ARRAY_LEN" => [],
		"FILE" => $fn->{FILE},
		"LINE" => $fn->{LINE},
	};

	return ParseElement($e, 0, 0);
}

sub CheckPointerTypes($$)
{
	my ($s,$default) = @_;

	return unless defined($s->{ELEMENTS});

	foreach my $e (@{$s->{ELEMENTS}}) {
		if ($e->{POINTERS} and not defined(pointer_type($e))) {
			$e->{PROPERTIES}->{$default} = '1';
		}
	}
}

sub FindNestedTypes($$)
{
	sub FindNestedTypes($$);
	my ($l, $t) = @_;

	return unless defined($t->{ELEMENTS});
	return if ($t->{TYPE} eq "ENUM");
	return if ($t->{TYPE} eq "BITMAP");

	foreach (@{$t->{ELEMENTS}}) {
		if (ref($_->{TYPE}) eq "HASH") {
			push (@$l, $_->{TYPE}) if (defined($_->{TYPE}->{NAME}));
			FindNestedTypes($l, $_->{TYPE});
		}
	}
}

sub ParseInterface($)
{
	my $idl = shift;
	my @types = ();
	my @consts = ();
	my @functions = ();
	my @endpoints;
	my $opnum = 0;
	my $version;
	my $ms_union = 0;
	$ms_union = 1 if has_property($idl, "ms_union");

	if (not has_property($idl, "pointer_default")) {
		# MIDL defaults to "ptr" in DCE compatible mode (/osf)
		# and "unique" in Microsoft Extensions mode (default)
		$idl->{PROPERTIES}->{pointer_default} = "unique";
	}

	foreach my $d (@{$idl->{DATA}}) {
		if ($d->{TYPE} eq "FUNCTION") {
			push (@functions, ParseFunction($idl, $d, \$opnum, $ms_union));
		} elsif ($d->{TYPE} eq "CONST") {
			push (@consts, ParseConst($idl, $d));
		} else {
			push (@types, ParseType($d, $idl->{PROPERTIES}->{pointer_default}, $ms_union));
			FindNestedTypes(\@types, $d);
		}
	}

	$version = "0.0";

	if(defined $idl->{PROPERTIES}->{version}) { 
		my @if_version = split(/\./, $idl->{PROPERTIES}->{version});
		if ($if_version[0] == $idl->{PROPERTIES}->{version}) {
				$version = $idl->{PROPERTIES}->{version};
		} else {
				$version = $if_version[1] << 16 | $if_version[0];
		}
	}

	# If no endpoint is set, default to the interface name as a named pipe
	if (!defined $idl->{PROPERTIES}->{endpoint}) {
		push @endpoints, "\"ncacn_np:[\\\\pipe\\\\" . $idl->{NAME} . "]\"";
	} else {
		@endpoints = split /,/, $idl->{PROPERTIES}->{endpoint};
	}

	return { 
		NAME => $idl->{NAME},
		UUID => lc(has_property($idl, "uuid") // ''),
		VERSION => $version,
		TYPE => "INTERFACE",
		PROPERTIES => $idl->{PROPERTIES},
		FUNCTIONS => \@functions,
		CONSTS => \@consts,
		TYPES => \@types,
		ENDPOINTS => \@endpoints,
		ORIGINAL => $idl
	};
}

# Convert a IDL tree to a NDR tree
# Gives a result tree describing all that's necessary for easily generating
# NDR parsers / generators
sub Parse($)
{
	my $idl = shift;

	return undef unless (defined($idl));

	Parse::Pidl::NDR::Validate($idl);
	
	my @ndr = ();

	foreach (@{$idl}) {
		($_->{TYPE} eq "CPP_QUOTE") && push(@ndr, $_);
		($_->{TYPE} eq "INTERFACE") && push(@ndr, ParseInterface($_));
		($_->{TYPE} eq "IMPORT") && push(@ndr, $_);
	}

	return \@ndr;
}

sub GetNextLevel($$)
{
	my $e = shift;
	my $fl = shift;

	my $seen = 0;

	foreach my $l (@{$e->{LEVELS}}) {
		return $l if ($seen);
		($seen = 1) if ($l == $fl);
	}

	return undef;
}

sub GetPrevLevel($$)
{
	my ($e,$fl) = @_;
	my $prev = undef;

	foreach my $l (@{$e->{LEVELS}}) {
		(return $prev) if ($l == $fl);
		$prev = $l;
	}

	return undef;
}

sub ContainsString($)
{
	my ($e) = @_;

	if (property_matches($e, "flag", ".*STR_NULLTERM.*")) {
		return 1;
	}
	if (exists($e->{LEVELS}) and $e->{LEVELS}->[0]->{TYPE} eq "ARRAY" and
		($e->{LEVELS}->[0]->{IS_FIXED} or $e->{LEVELS}->[0]->{IS_INLINE}) and
		has_property($e, "charset"))
	{
		return 1;
	}

	foreach my $l (@{$e->{LEVELS}}) {
		return 1 if ($l->{TYPE} eq "ARRAY" and $l->{IS_ZERO_TERMINATED});
	}
	if (property_matches($e, "charset", ".*DOS.*")) {
		return 1;
	}

	return 0;
}

sub ContainsDeferred($$)
{
	my ($e,$l) = @_;

	return 1 if ($l->{CONTAINS_DEFERRED});

	while ($l = GetNextLevel($e,$l))
	{
		return 1 if ($l->{IS_DEFERRED}); 
		return 1 if ($l->{CONTAINS_DEFERRED});
	} 
	
	return 0;
}

sub ContainsPipe($$)
{
	my ($e,$l) = @_;

	return 1 if ($l->{TYPE} eq "PIPE");

	while ($l = GetNextLevel($e,$l))
	{
		return 1 if ($l->{TYPE} eq "PIPE");
	}

	return 0;
}

sub el_name($)
{
	my $e = shift;
	my $name = "<ANONYMOUS>";

	$name = $e->{NAME} if defined($e->{NAME});

	if (defined($e->{PARENT}) and defined($e->{PARENT}->{NAME})) {
		return "$e->{PARENT}->{NAME}.$name";
	}

	if (defined($e->{PARENT}) and
	    defined($e->{PARENT}->{PARENT}) and
	    defined($e->{PARENT}->{PARENT}->{NAME})) {
		return "$e->{PARENT}->{PARENT}->{NAME}.$name";
	}

	return $name;
}

###################################
# find a sibling var in a structure
sub find_sibling($$)
{
	my($e,$name) = @_;
	my($fn) = $e->{PARENT};

	if ($name =~ /\*(.*)/) {
		$name = $1;
	}

	for my $e2 (@{$fn->{ELEMENTS}}) {
		return $e2 if ($e2->{NAME} eq $name);
	}

	return undef;
}

my %property_list = (
	# interface
	"helpstring"		=> ["INTERFACE", "FUNCTION"],
	"version"		=> ["INTERFACE"],
	"uuid"			=> ["INTERFACE"],
	"endpoint"		=> ["INTERFACE"],
	"pointer_default"	=> ["INTERFACE"],
	"helper"		=> ["INTERFACE"],
	"pyhelper"		=> ["INTERFACE"],
	"authservice"		=> ["INTERFACE"],
	"restricted"	        => ["INTERFACE"],
        "no_srv_register"       => ["INTERFACE"],

	# dcom
	"object"		=> ["INTERFACE"],
	"local"			=> ["INTERFACE", "FUNCTION"],
	"iid_is"		=> ["ELEMENT"],
	"call_as"		=> ["FUNCTION"],
	"idempotent"		=> ["FUNCTION"],

	# function
	"noopnum"		=> ["FUNCTION"],
	"in"			=> ["ELEMENT"],
	"out"			=> ["ELEMENT"],

	# pointer
	"ref"			=> ["ELEMENT", "TYPEDEF"],
	"ptr"			=> ["ELEMENT", "TYPEDEF"],
	"unique"		=> ["ELEMENT", "TYPEDEF"],
	"ignore"		=> ["ELEMENT"],
	"relative"		=> ["ELEMENT", "TYPEDEF"],
	"relative_short"	=> ["ELEMENT", "TYPEDEF"],
	"null_is_ffffffff"	=> ["ELEMENT"],
	"relative_base"		=> ["TYPEDEF", "STRUCT", "UNION"],

	"gensize"		=> ["TYPEDEF", "STRUCT", "UNION"],
	"value"			=> ["ELEMENT"],
	"flag"			=> ["ELEMENT", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP", "PIPE"],
	"max_recursion"		=> ["ELEMENT"],

	# generic
	"public"		=> ["FUNCTION", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP", "PIPE"],
	"nopush"		=> ["FUNCTION", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP", "PIPE"],
	"nopull"		=> ["FUNCTION", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP", "PIPE"],
	"nosize"		=> ["FUNCTION", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP"],
	"noprint"		=> ["FUNCTION", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP", "ELEMENT", "PIPE"],
	"nopython"		=> ["FUNCTION", "TYPEDEF", "STRUCT", "UNION", "ENUM", "BITMAP"],
	"todo"			=> ["FUNCTION"],
	"skip"			=> ["ELEMENT"],
	"skip_noinit"		=> ["ELEMENT"],

	# union
	"switch_is"		=> ["ELEMENT"],
	"switch_type"		=> ["ELEMENT", "UNION"],
	"nodiscriminant"	=> ["UNION"],
	"ms_union"		=> ["INTERFACE", "UNION"],
	"case"			=> ["ELEMENT"],
	"default"		=> ["ELEMENT"],

	"represent_as"		=> ["ELEMENT"],
	"transmit_as"		=> ["ELEMENT"],

	# subcontext
	"subcontext"		=> ["ELEMENT"],
	"subcontext_size"	=> ["ELEMENT"],
	"compression"		=> ["ELEMENT"],

	# enum
	"enum8bit"		=> ["ENUM"],
	"enum16bit"		=> ["ENUM"],
	"v1_enum"		=> ["ENUM"],

	# bitmap
	"bitmap8bit"		=> ["BITMAP"],
	"bitmap16bit"		=> ["BITMAP"],
	"bitmap32bit"		=> ["BITMAP"],
	"bitmap64bit"		=> ["BITMAP"],

	# array
	"range"			=> ["ELEMENT", "PIPE"],
	"size_is"		=> ["ELEMENT"],
	"string"		=> ["ELEMENT"],
	"noheader"		=> ["ELEMENT"],
	"charset"		=> ["ELEMENT"],
	"length_is"		=> ["ELEMENT"],
	"to_null"		=> ["ELEMENT"],
);

#####################################################################
# check for unknown properties
sub ValidProperties($$)
{
	my ($e,$t) = @_;

	return unless defined $e->{PROPERTIES};

	foreach my $key (keys %{$e->{PROPERTIES}}) {
		warning($e, el_name($e) . ": unknown property '$key'")
			unless defined($property_list{$key});

   		fatal($e, el_name($e) . ": property '$key' not allowed on '$t'")
			unless grep(/^$t$/, @{$property_list{$key}});
	}
}

sub mapToScalar($)
{
	sub mapToScalar($);
	my $t = shift;
	return $t->{NAME} if (ref($t) eq "HASH" and $t->{TYPE} eq "SCALAR");
	my $ti = getType($t);

	if (not defined ($ti)) {
		return undef;
	} elsif ($ti->{TYPE} eq "TYPEDEF") {
		return mapToScalar($ti->{DATA});
	} elsif ($ti->{TYPE} eq "ENUM") {
		return Parse::Pidl::Typelist::enum_type_fn($ti);
	} elsif ($ti->{TYPE} eq "BITMAP") {
		return Parse::Pidl::Typelist::bitmap_type_fn($ti);
	}

	return undef;
}

#####################################################################
# validate an element
sub ValidElement($)
{
	my $e = shift;

	ValidProperties($e,"ELEMENT");

	# Check whether switches are used correctly.
	if (my $switch = has_property($e, "switch_is")) {
		my $e2 = find_sibling($e, $switch);
		my $type = getType($e->{TYPE});

		if (defined($type) and $type->{DATA}->{TYPE} ne "UNION") {
			fatal($e, el_name($e) . ": switch_is() used on non-union type $e->{TYPE} which is a $type->{DATA}->{TYPE}");
		}

		if (not has_property($type->{DATA}, "nodiscriminant") and defined($e2)) {
			my $discriminator_type = has_property($type->{DATA}, "switch_type");
			$discriminator_type = "uint32" unless defined ($discriminator_type);

			my $t1 = mapScalarType(mapToScalar($discriminator_type));

			if (not defined($t1)) {
				fatal($e, el_name($e) . ": unable to map discriminator type '$discriminator_type' to scalar");
			}

			my $t2 = mapScalarType(mapToScalar($e2->{TYPE}));
			if (not defined($t2)) {
				fatal($e, el_name($e) . ": unable to map variable used for switch_is() to scalar");
			}

			if ($t1 ne $t2) {
				warning($e, el_name($e) . ": switch_is() is of type $e2->{TYPE} ($t2), while discriminator type for union $type->{NAME} is $discriminator_type ($t1)");
			}
		}
	}

	if (has_property($e, "subcontext") and has_property($e, "represent_as")) {
		fatal($e, el_name($e) . " : subcontext() and represent_as() can not be used on the same element");
	}

	if (has_property($e, "subcontext") and has_property($e, "transmit_as")) {
		fatal($e, el_name($e) . " : subcontext() and transmit_as() can not be used on the same element");
	}

	if (has_property($e, "represent_as") and has_property($e, "transmit_as")) {
		fatal($e, el_name($e) . " : represent_as() and transmit_as() can not be used on the same element");
	}

	if (has_property($e, "represent_as") and has_property($e, "value")) {
		fatal($e, el_name($e) . " : represent_as() and value() can not be used on the same element");
	}

	if (has_property($e, "subcontext")) {
		warning($e, "subcontext() is deprecated. Use represent_as() or transmit_as() instead");
	}

	if (defined (has_property($e, "subcontext_size")) and not defined(has_property($e, "subcontext"))) {
		fatal($e, el_name($e) . " : subcontext_size() on non-subcontext element");
	}

	if (defined (has_property($e, "compression")) and not defined(has_property($e, "subcontext"))) {
		fatal($e, el_name($e) . " : compression() on non-subcontext element");
	}

	if (!$e->{POINTERS} && (
		has_property($e, "ptr") or
		has_property($e, "unique") or
		has_property($e, "relative") or
		has_property($e, "relative_short") or
		has_property($e, "ref"))) {
		fatal($e, el_name($e) . " : pointer properties on non-pointer element\n");	
	}
}

#####################################################################
# validate an enum
sub ValidEnum($)
{
	my ($enum) = @_;

	ValidProperties($enum, "ENUM");
}

#####################################################################
# validate a bitmap
sub ValidBitmap($)
{
	my ($bitmap) = @_;

	ValidProperties($bitmap, "BITMAP");
}

#####################################################################
# validate a struct
sub ValidStruct($)
{
	my($struct) = shift;

	ValidProperties($struct, "STRUCT");

	return unless defined($struct->{ELEMENTS});

	foreach my $e (@{$struct->{ELEMENTS}}) {
		$e->{PARENT} = $struct;
		ValidElement($e);
	}
}

#####################################################################
# parse a union
sub ValidUnion($)
{
	my($union) = shift;

	ValidProperties($union,"UNION");

	if (has_property($union->{PARENT}, "nodiscriminant") and 
		has_property($union->{PARENT}, "switch_type")) {
		fatal($union->{PARENT}, $union->{PARENT}->{NAME} . ": switch_type(" . $union->{PARENT}->{PROPERTIES}->{switch_type} . ") on union without discriminant");
	}

	return unless defined($union->{ELEMENTS});

	foreach my $e (@{$union->{ELEMENTS}}) {
		$e->{PARENT} = $union;

		if (defined($e->{PROPERTIES}->{default}) and 
			defined($e->{PROPERTIES}->{case})) {
			fatal($e, "Union member $e->{NAME} can not have both default and case properties!");
		}
		
		unless (defined ($e->{PROPERTIES}->{default}) or 
				defined ($e->{PROPERTIES}->{case})) {
			fatal($e, "Union member $e->{NAME} must have default or case property");
		}

		if (has_property($e, "ref")) {
			fatal($e, el_name($e) . ": embedded ref pointers are not supported yet\n");
		}


		ValidElement($e);
	}
}

#####################################################################
# validate a pipe
sub ValidPipe($)
{
	my ($pipe) = @_;
	my $struct = $pipe->{DATA};

	ValidProperties($pipe, "PIPE");

	$struct->{PARENT} = $pipe;

	$struct->{FILE} = $pipe->{FILE} unless defined($struct->{FILE});
	$struct->{LINE} = $pipe->{LINE} unless defined($struct->{LINE});

	ValidType($struct);
}

#####################################################################
# parse a typedef
sub ValidTypedef($)
{
	my($typedef) = shift;
	my $data = $typedef->{DATA};

	ValidProperties($typedef, "TYPEDEF");

	return unless (ref($data) eq "HASH");

	$data->{PARENT} = $typedef;

	$data->{FILE} = $typedef->{FILE} unless defined($data->{FILE});
	$data->{LINE} = $typedef->{LINE} unless defined($data->{LINE});

	ValidType($data);
}

#####################################################################
# validate a function
sub ValidFunction($)
{
	my($fn) = shift;

	ValidProperties($fn,"FUNCTION");

	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		if (has_property($e, "ref") && !$e->{POINTERS}) {
			fatal($e, "[ref] variables must be pointers ($fn->{NAME}/$e->{NAME})");
		}
		ValidElement($e);
	}
}

#####################################################################
# validate a type
sub ValidType($)
{
	my ($t) = @_;

	{ 
		TYPEDEF => \&ValidTypedef,
		STRUCT => \&ValidStruct,
		UNION => \&ValidUnion,
		ENUM => \&ValidEnum,
		BITMAP => \&ValidBitmap,
		PIPE => \&ValidPipe
	}->{$t->{TYPE}}->($t);
}

#####################################################################
# parse the interface definitions
sub ValidInterface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};

	if (has_property($interface, "helper")) {
		warning($interface, "helper() is pidl-specific and deprecated. Use `include' instead");
	}

	ValidProperties($interface,"INTERFACE");

	if (has_property($interface, "pointer_default")) {
		if (not grep (/$interface->{PROPERTIES}->{pointer_default}/, 
					("ref", "unique", "ptr"))) {
			fatal($interface, "Unknown default pointer type `$interface->{PROPERTIES}->{pointer_default}'");
		}
	}

	if (has_property($interface, "object")) {
     		if (has_property($interface, "version") && 
			$interface->{PROPERTIES}->{version} != 0) {
			fatal($interface, "Object interfaces must have version 0.0 ($interface->{NAME})");
		}

		if (!defined($interface->{BASE}) && 
			not ($interface->{NAME} eq "IUnknown")) {
			fatal($interface, "Object interfaces must all derive from IUnknown ($interface->{NAME})");
		}
	}
		
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "FUNCTION") && ValidFunction($d);
		($d->{TYPE} eq "TYPEDEF" or 
		 $d->{TYPE} eq "STRUCT" or
	 	 $d->{TYPE} eq "UNION" or 
	 	 $d->{TYPE} eq "ENUM" or
		 $d->{TYPE} eq "BITMAP" or
		 $d->{TYPE} eq "PIPE") && ValidType($d);
	}

}

#####################################################################
# Validate an IDL structure
sub Validate($)
{
	my($idl) = shift;

	foreach my $x (@{$idl}) {
		($x->{TYPE} eq "INTERFACE") && 
		    ValidInterface($x);
		($x->{TYPE} eq "IMPORTLIB") &&
			fatal($x, "importlib() not supported");
	}
}

sub is_charset_array($$)
{
	my ($e,$l) = @_;

	return 0 if ($l->{TYPE} ne "ARRAY");

	my $nl = GetNextLevel($e,$l);

	return 0 unless ($nl->{TYPE} eq "DATA");

	return has_property($e, "charset");
}



1;
