###################################################
# Samba4 parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Typelist;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(hasType getType resolveType mapTypeName scalar_is_reference expandAlias
	mapScalarType addType typeIs is_signed is_scalar enum_type_fn
	bitmap_type_fn mapType typeHasBody is_fixed_size_scalar
);
use vars qw($VERSION);
$VERSION = '0.01';

use Parse::Pidl::Util qw(has_property);
use strict;

my %types = ();

my @reference_scalars = (
	"string", "string_array", "nbt_string", "dns_string",
	"wrepl_nbt_name", "dnsp_name", "dnsp_string",
	"ipv4address", "ipv6address"
);

my @non_fixed_size_scalars = (
	"string", "string_array", "nbt_string", "dns_string",
	"wrepl_nbt_name", "dnsp_name", "dnsp_string"
);

# a list of known scalar types
my %scalars = (
	"void"		=> "void",
	"char"		=> "char",
	"int8"		=> "int8_t",
	"uint8"		=> "uint8_t",
	"int16"		=> "int16_t",
	"uint16"	=> "uint16_t",
	"int1632"	=> "int16_t",
	"uint1632"	=> "uint16_t",
	"int32"		=> "int32_t",
	"uint32"	=> "uint32_t",
	"int3264"	=> "int32_t",
	"uint3264"	=> "uint32_t",
	"hyper"		=> "uint64_t",
	"dlong"		=> "int64_t",
	"udlong"	=> "uint64_t",
	"udlongr"	=> "uint64_t",
	"double"	=> "double",
	"pointer"	=> "void*",
	"DATA_BLOB"	=> "DATA_BLOB",
	"string"	=> "const char *",
	"string_array"	=> "const char **",
	"time_t"	=> "time_t",
	"uid_t"	        => "uid_t",
	"gid_t"	        => "gid_t",
	"NTTIME"	=> "NTTIME",
	"NTTIME_1sec"	=> "NTTIME",
	"NTTIME_hyper"	=> "NTTIME",
	"WERROR"	=> "WERROR",
	"NTSTATUS"	=> "NTSTATUS",
	"COMRESULT" => "COMRESULT",
	"dns_string"	=> "const char *",
	"nbt_string"	=> "const char *",
	"wrepl_nbt_name"=> "struct nbt_name *",
	"ipv4address"	=> "const char *",
	"ipv6address"   => "const char *",
	"dnsp_name"	=> "const char *",
	"dnsp_string"	=> "const char *",
);

my %aliases = (
	"error_status_t" => "uint32",
	"boolean8" => "uint8",
	"boolean32" => "uint32",
	"DWORD" => "uint32",
	"uint" => "uint32",
	"int" => "int32",
	"WORD" => "uint16",
	"char" => "uint8",
	"long" => "int32",
	"short" => "int16",
	"HYPER_T" => "hyper",
	"HRESULT" => "COMRESULT",
        "mode_t"        => "uint32",
);

sub expandAlias($)
{
	my $name = shift;

	return $aliases{$name} if defined($aliases{$name});

	return $name;
}

# map from a IDL type to a C header type
sub mapScalarType($)
{
	my $name = shift;

	# it's a bug when a type is not in the list
	# of known scalars or has no mapping
	return $scalars{$name} if defined($scalars{$name});

	die("Unknown scalar type $name");
}

sub addType($)
{
	my $t = shift;
	$types{$t->{NAME}} = $t;
}

sub resolveType($)
{
	my ($ctype) = @_;

	if (not hasType($ctype)) {
		# assume struct typedef
		return { TYPE => "TYPEDEF", NAME => $ctype, DATA => { TYPE => "STRUCT" } };
	} else {
		return getType($ctype);
	}

	return $ctype;
}

sub getType($)
{
	my $t = shift;
	return ($t) if (ref($t) eq "HASH" and not defined($t->{NAME}));
	return undef if not hasType($t);
	return $types{$t->{NAME}} if (ref($t) eq "HASH");
	return $types{$t};
}

sub typeIs($$);
sub typeIs($$)
{
	my ($t,$tt) = @_;

	if (ref($t) eq "HASH") {
		return 1 if ($t->{TYPE} eq "TYPEDEF" and $t->{DATA}->{TYPE} eq $tt);
		return 1 if ($t->{TYPE} eq $tt);
		return 0;
	}
	if (hasType($t) and getType($t)->{TYPE} eq "TYPEDEF") {
		return typeIs(getType($t)->{DATA}, $tt);
	 }
	return 0;
}

sub hasType($)
{
	my $t = shift;
	if (ref($t) eq "HASH") {
		return 1 if (not defined($t->{NAME}));
		return 1 if (defined($types{$t->{NAME}}) and 
			$types{$t->{NAME}}->{TYPE} eq $t->{TYPE});
		return 0;
	}
	return 1 if defined($types{$t});
	return 0;
}

sub is_signed($)
{
    my $t = shift;

    return ($t eq "int8"
	    or $t eq "int16"
	    or $t eq "int32"
	    or $t eq "dlong"
	    or $t eq "int"
	    or $t eq "long"
	    or $t eq "short");
}

sub is_scalar($)
{
	sub is_scalar($);
	my $type = shift;

	return 1 if (ref($type) eq "HASH" and 
		($type->{TYPE} eq "SCALAR" or $type->{TYPE} eq "ENUM" or 
		 $type->{TYPE} eq "BITMAP"));

	if (my $dt = getType($type)) {
		return is_scalar($dt->{DATA}) if ($dt->{TYPE} eq "TYPEDEF");
		return 1 if ($dt->{TYPE} eq "SCALAR" or $dt->{TYPE} eq "ENUM" or 
			         $dt->{TYPE} eq "BITMAP");
	}

	return 0;
}

sub is_fixed_size_scalar($)
{
	my $name = shift;

	return 0 unless is_scalar($name);
	return 0 if (grep(/^$name$/, @non_fixed_size_scalars));
	return 1;
}

sub scalar_is_reference($)
{
	my $name = shift;

	return 1 if (grep(/^$name$/, @reference_scalars));
	return 0;
}

sub RegisterScalars()
{
	foreach (keys %scalars) {
		addType({
			NAME => $_,
			TYPE => "TYPEDEF",
			BASEFILE => "<builtin>",
			DATA => {
				TYPE => "SCALAR",
				NAME => $_
			}
		}
		);
	}
}

sub enum_type_fn($)
{
	my $enum = shift;
	$enum->{TYPE} eq "ENUM" or die("not an enum");

	# for typedef enum { } we need to check $enum->{PARENT}
	if (has_property($enum, "enum8bit")) {
		return "uint8";
	} elsif (has_property($enum, "enum16bit")) {
		return "uint16";
	} elsif (has_property($enum, "v1_enum")) {
		return "uint32";
	} elsif (has_property($enum->{PARENT}, "enum8bit")) {
		return "uint8";
	} elsif (has_property($enum->{PARENT}, "enum16bit")) {
		return "uint16";
	} elsif (has_property($enum->{PARENT}, "v1_enum")) {
		return "uint32";
	}
	return "uint1632";
}

sub bitmap_type_fn($)
{
	my $bitmap = shift;

	$bitmap->{TYPE} eq "BITMAP" or die("not a bitmap");

	if (has_property($bitmap, "bitmap8bit")) {
		return "uint8";
	} elsif (has_property($bitmap, "bitmap16bit")) {
		return "uint16";
	} elsif (has_property($bitmap, "bitmap64bit")) {
		return "hyper";
	}
	return "uint32";
}

sub typeHasBody($)
{
	sub typeHasBody($);
	my ($e) = @_;

	if ($e->{TYPE} eq "TYPEDEF") {
		return 0 unless(defined($e->{DATA}));
		return typeHasBody($e->{DATA});
	}

	return defined($e->{ELEMENTS});
}

sub mapType($$)
{
	sub mapType($$);
	my ($t, $n) = @_;

	return mapType($t->{DATA}, $n) if ($t->{TYPE} eq "TYPEDEF");
	return mapScalarType($n) if ($t->{TYPE} eq "SCALAR");
	return "enum $n" if ($t->{TYPE} eq "ENUM");
	return "struct $n" if ($t->{TYPE} eq "STRUCT" or $t->{TYPE} eq "INTERFACE");
	return "union $n" if ($t->{TYPE} eq "UNION");
	return mapScalarType(bitmap_type_fn($t)) if ($t->{TYPE} eq "BITMAP");
	return "struct $n" if ($t->{TYPE} eq "PIPE");
	die("Unknown type $t->{TYPE}");
}

sub mapTypeName($)
{
	my $t = shift;
	return "void" unless defined($t);
	my $dt;
	$t = expandAlias($t);

	if ($dt = getType($t)) {
		return mapType($dt, $dt->{NAME});
	} elsif (ref($t) eq "HASH" and defined($t->{NAME})) {
		return mapType($t, $t->{NAME});
	} else {
		# Best guess
		return "struct $t";
	}

}

sub LoadIdl($;$)
{
	my $idl = shift;
	my $basename = shift;

	foreach my $x (@{$idl}) {
		next if $x->{TYPE} ne "INTERFACE";

		# DCOM interfaces can be types as well
		addType({
			NAME => $x->{NAME},
			TYPE => "TYPEDEF",
			DATA => $x,
			BASEFILE => $basename,
			}) if (has_property($x, "object"));

		foreach my $y (@{$x->{DATA}}) {
			if ($y->{TYPE} eq "TYPEDEF"
			    or $y->{TYPE} eq "UNION"
			    or $y->{TYPE} eq "STRUCT"
			    or $y->{TYPE} eq "ENUM"
			    or $y->{TYPE} eq "BITMAP"
			    or $y->{TYPE} eq "PIPE") {
				$y->{BASEFILE} = $basename;
				addType($y);
			}
		}
	}
}

sub GenerateTypeLib()
{
	return Parse::Pidl::Util::MyDumper(\%types);
}

RegisterScalars();

1;
