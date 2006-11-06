###################################################
# Samba4 parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Typelist;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(hasType getType mapType scalar_is_reference expandAlias);
use vars qw($VERSION);
$VERSION = '0.01';

use Parse::Pidl::Util qw(has_property);
use strict;

my %typedefs = ();

my @reference_scalars = (
	"string", "string_array", "nbt_string", 
	"wrepl_nbt_name", "ipv4address"
);

# a list of known scalar types
my %scalars = (
	"void"		=> "void",
	"char"		=> "char",
	"int8"		=> "int8_t",
	"uint8"		=> "uint8_t",
	"int16"		=> "int16_t",
	"uint16"	=> "uint16_t",
	"int32"		=> "int32_t",
	"uint32"	=> "uint32_t",
	"hyper"		=> "uint64_t",
	"dlong"		=> "int64_t",
	"udlong"	=> "uint64_t",
	"udlongr"	=> "uint64_t",
	"pointer"	=> "void*",
	"DATA_BLOB"	=> "DATA_BLOB",
	"string"	=> "const char *",
	"string_array"	=> "const char **",
	"time_t"	=> "time_t",
	"NTTIME"	=> "NTTIME",
	"NTTIME_1sec"	=> "NTTIME",
	"NTTIME_hyper"	=> "NTTIME",
	"WERROR"	=> "WERROR",
	"NTSTATUS"	=> "NTSTATUS",
	"COMRESULT" => "COMRESULT",
	"nbt_string"	=> "const char *",
	"wrepl_nbt_name"=> "struct nbt_name *",
	"ipv4address"	=> "const char *",
);

my %aliases = (
	"error_status_t" => "uint32",
	"boolean8" => "uint8",
	"boolean32" => "uint32",
	"DWORD" => "uint32",
	"int" => "int32",
	"WORD" => "uint16",
	"char" => "uint8",
	"long" => "int32",
	"short" => "int16",
	"HYPER_T" => "hyper",
	"HRESULT" => "COMRESULT",
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
	$typedefs{$t->{NAME}} = $t;
}

sub getType($)
{
	my $t = shift;
	return undef if not hasType($t);
	return $typedefs{$t};
}

sub typeIs($$)
{
	my ($t,$tt) = @_;

	return 1 if (hasType($t) and getType($t)->{DATA}->{TYPE} eq $tt);
	return 0;
}

sub hasType($)
{
	my $t = shift;
	return 1 if defined($typedefs{$t});
	return 0;
}

sub is_scalar($)
{
	my $type = shift;

	return 0 unless(hasType($type));

	if (my $dt = getType($type)->{DATA}->{TYPE}) {
		return 1 if ($dt eq "SCALAR" or $dt eq "ENUM" or $dt eq "BITMAP");
	}

	return 0;
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
	if (has_property($enum->{PARENT}, "enum8bit")) {
		return "uint8";
	} elsif (has_property($enum->{PARENT}, "v1_enum")) {
		return "uint32";
	}
	return "uint16";
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

sub mapType($)
{
	my $t = shift;
	return "void" unless defined($t);
	my $dt;
	$t = expandAlias($t);

	unless ($dt or ($dt = getType($t))) {
		# Best guess
		return "struct $t";
	}
	return mapScalarType($t) if ($dt->{DATA}->{TYPE} eq "SCALAR");
	return "enum $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "ENUM");
	return "struct $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "STRUCT");
	return "struct $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "INTERFACE");
	return "union $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "UNION");

	if ($dt->{DATA}->{TYPE} eq "BITMAP") {
		return mapScalarType(bitmap_type_fn($dt->{DATA}));
	}

	die("Unknown type $dt->{DATA}->{TYPE}");
}

sub LoadIdl($)
{
	my $idl = shift;

	foreach my $x (@{$idl}) {
		next if $x->{TYPE} ne "INTERFACE";

		# DCOM interfaces can be types as well
		addType({
			NAME => $x->{NAME},
			TYPE => "TYPEDEF",
			DATA => $x
			}) if (has_property($x, "object"));

		foreach my $y (@{$x->{DATA}}) {
			addType($y) if (
				$y->{TYPE} eq "TYPEDEF" 
			     or $y->{TYPE} eq "DECLARE");
		}
	}
}

RegisterScalars();

1;
