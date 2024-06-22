###################################################
# create C header files for an IDL structure
# Copyright tridge@samba.org 2000
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba4::Header;
require Exporter;

@ISA = qw(Exporter);
@EXPORT_OK = qw(GenerateFunctionInEnv GenerateFunctionOutEnv EnvSubstituteValue GenerateStructEnv);

use strict;
use warnings;
use Parse::Pidl qw(fatal);
use Parse::Pidl::Typelist qw(mapTypeName scalar_is_reference);
use Parse::Pidl::Util qw(has_property is_constant unmake_str ParseExpr);
use Parse::Pidl::Samba4 qw(is_intree ElementStars ArrayBrackets choose_header);

use vars qw($VERSION);
$VERSION = '0.01';

my($res);
my($tab_depth);

sub pidl($) { $res .= shift; }

sub tabs()
{
	my $res = "";
	$res .="\t" foreach (1..$tab_depth);
	return $res;
}

#####################################################################
# parse a properties list
sub HeaderProperties($$)
{
	my($props,$ignores) = @_;
	my $ret = "";

	foreach my $d (sort(keys %{$props})) {
		next if (grep(/^$d$/, @$ignores));
		if($props->{$d} ne "1") {
			$ret.= "$d($props->{$d}),";
		} else {
			$ret.="$d,";
		}
	}

	if ($ret) {
		pidl "/* [" . substr($ret, 0, -1) . "] */";
	}
}

#####################################################################
# parse a structure element
sub HeaderElement($)
{
	my($element) = shift;

	pidl tabs();
	if (has_property($element, "represent_as")) {
		pidl mapTypeName($element->{PROPERTIES}->{represent_as})." ";
	} else {
		if (ref($element->{TYPE}) eq "HASH") {
			HeaderType($element, $element->{TYPE}, $element->{TYPE}->{NAME});
		} else {
			HeaderType($element, $element->{TYPE}, "");
		}
		pidl " ".ElementStars($element);
	}
	pidl $element->{NAME};
	pidl ArrayBrackets($element);

	pidl ";";
	if (defined $element->{PROPERTIES}) {
		HeaderProperties($element->{PROPERTIES}, ["in", "out"]);
	}
	pidl "\n";
}

#####################################################################
# parse a struct
sub HeaderStruct($$;$)
{
	my($struct,$name,$tail) = @_;
	pidl "struct $name";
	pidl $tail if defined($tail) and not defined($struct->{ELEMENTS});
	return if (not defined($struct->{ELEMENTS}));
	pidl " {\n";
	$tab_depth++;
	my $el_count=0;
	foreach (@{$struct->{ELEMENTS}}) {
		HeaderElement($_);
		$el_count++;
	}
	if ($el_count == 0) {
		# some compilers can't handle empty structures
		pidl tabs()."char _empty_;\n";
	}
	$tab_depth--;
	pidl tabs()."}";
	if (defined $struct->{PROPERTIES}) {
		HeaderProperties($struct->{PROPERTIES}, []);
	}
	pidl $tail if defined($tail);
}

#####################################################################
# parse a enum
sub HeaderEnum($$;$)
{
	my($enum,$name,$tail) = @_;
	my $first = 1;

	pidl "enum $name";
	if (defined($enum->{ELEMENTS})) {
		pidl "\n#ifndef USE_UINT_ENUMS\n";
		pidl " {\n";
		$tab_depth++;
		foreach my $e (@{$enum->{ELEMENTS}}) {
			my @enum_els = ();
			unless ($first) { pidl ",\n"; }
			$first = 0;
			pidl tabs();
			@enum_els = split(/=/, $e);
			if (@enum_els == 2) {
				pidl $enum_els[0];
				pidl "=(int)";
				pidl "(";
				pidl $enum_els[1];
				pidl ")";
			} else {
				pidl $e;
			}
		}
		pidl "\n";
		$tab_depth--;
		pidl "}";
		pidl "\n";
		pidl "#else\n";
		my $count = 0;
		my $with_val = 0;
		my $without_val = 0;
		pidl " { __do_not_use_enum_$name=0x7FFFFFFF}\n";
		foreach my $e (@{$enum->{ELEMENTS}}) {
			my $t = "$e";
			my $name;
			my $value;
			if ($t =~ /(.*)=(.*)/) {
				$name = $1;
				$value = $2;
				$with_val = 1;
				fatal($e->{ORIGINAL}, "you can't mix enum member with values and without values!")
					unless ($without_val == 0);
			} else {
				$name = $t;
				$value = $count++;
				$without_val = 1;
				fatal($e->{ORIGINAL}, "you can't mix enum member with values and without values!")
					unless ($with_val == 0);
			}
			pidl "#define $name ( $value )\n";
		}
		pidl "#endif\n";
	}
	pidl $tail if defined($tail);
}

#####################################################################
# parse a bitmap
sub HeaderBitmap($$)
{
	my($bitmap,$name) = @_;

	return unless defined($bitmap->{ELEMENTS});

	pidl "/* bitmap $name */\n";
	pidl "#define $_\n" foreach (@{$bitmap->{ELEMENTS}});
	pidl "\n";
}

#####################################################################
# parse a union
sub HeaderUnion($$;$)
{
	my($union,$name,$tail) = @_;
	my %done = ();

	pidl "union $name";
	pidl $tail if defined($tail) and not defined($union->{ELEMENTS});
	return if (not defined($union->{ELEMENTS}));
	pidl " {\n";
	$tab_depth++;
	my $needed = 0;
	foreach my $e (@{$union->{ELEMENTS}}) {
		if ($e->{TYPE} ne "EMPTY") {
			if (! defined $done{$e->{NAME}}) {
				HeaderElement($e);
			}
			$done{$e->{NAME}} = 1;
			$needed++;
		}
	}
	if (!$needed) {
		# sigh - some compilers don't like empty structures
		pidl tabs()."int _dummy_element;\n";
	}
	$tab_depth--;
	pidl "}";

	if (defined $union->{PROPERTIES}) {
		HeaderProperties($union->{PROPERTIES}, []);
	}
	pidl $tail if defined($tail);
}

#####################################################################
# parse a pipe
sub HeaderPipe($$;$)
{
	my($pipe,$name,$tail) = @_;

	my $struct = $pipe->{DATA};
	my $e = $struct->{ELEMENTS}[1];

	pidl "struct $name;\n";
	pidl "struct $struct->{NAME} {\n";
	$tab_depth++;
	pidl tabs()."uint32_t count;\n";
	pidl tabs().mapTypeName($e->{TYPE})." *array;\n";
	$tab_depth--;
	pidl "}";

	if (defined $struct->{PROPERTIES}) {
		HeaderProperties($struct->{PROPERTIES}, []);
	}

	pidl $tail if defined($tail);
}

#####################################################################
# parse a type
sub HeaderType($$$;$)
{
	my($e,$data,$name,$tail) = @_;
	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "ENUM") && HeaderEnum($data, $name, $tail);
		($data->{TYPE} eq "BITMAP") && HeaderBitmap($data, $name);
		($data->{TYPE} eq "STRUCT") && HeaderStruct($data, $name, $tail);
		($data->{TYPE} eq "UNION") && HeaderUnion($data, $name, $tail);
		($data->{TYPE} eq "PIPE") && HeaderPipe($data, $name, $tail);
		return;
	}

	if (has_property($e, "charset")) {
		pidl "const char";
	} else {
		pidl mapTypeName($e->{TYPE});
	}
	pidl $tail if defined($tail);
}

#####################################################################
# parse a typedef
sub HeaderTypedef($;$)
{
	my($typedef,$tail) = @_;
	# Don't print empty "enum foo;", since some compilers don't like it.
	return if ($typedef->{DATA}->{TYPE} eq "ENUM" and not defined($typedef->{DATA}->{ELEMENTS}));
	HeaderType($typedef, $typedef->{DATA}, $typedef->{NAME}, $tail) if defined ($typedef->{DATA});
}

#####################################################################
# parse a const
sub HeaderConst($)
{
	my($const) = shift;
	if (!defined($const->{ARRAY_LEN}[0])) {
		pidl "#define $const->{NAME}\t( $const->{VALUE} )\n";
	} else {
		pidl "#define $const->{NAME}\t $const->{VALUE}\n";
	}
}

sub ElementDirection($)
{
	my ($e) = @_;

	return "inout" if (has_property($e, "in") and has_property($e, "out"));
	return "in" if (has_property($e, "in"));
	return "out" if (has_property($e, "out"));
	return "inout";
}

#####################################################################
# parse a function
sub HeaderFunctionInOut($$)
{
	my($fn,$prop) = @_;

	return unless defined($fn->{ELEMENTS});

	foreach my $e (@{$fn->{ELEMENTS}}) {
		HeaderElement($e) if (ElementDirection($e) eq $prop);
	}
}

#####################################################################
# determine if we need an "in" or "out" section
sub HeaderFunctionInOut_needed($$)
{
	my($fn,$prop) = @_;

	return 1 if ($prop eq "out" && defined($fn->{RETURN_TYPE}));

	return undef unless defined($fn->{ELEMENTS});

	foreach my $e (@{$fn->{ELEMENTS}}) {
		return 1 if (ElementDirection($e) eq $prop);
	}

	return undef;
}

my %headerstructs;

#####################################################################
# parse a function
sub HeaderFunction($)
{
	my($fn) = shift;

	return if ($headerstructs{$fn->{NAME}});

	$headerstructs{$fn->{NAME}} = 1;

	pidl "\nstruct $fn->{NAME} {\n";
	$tab_depth++;
	my $needed = 0;

	if (HeaderFunctionInOut_needed($fn, "in") or
	    HeaderFunctionInOut_needed($fn, "inout")) {
		pidl tabs()."struct {\n";
		$tab_depth++;
		HeaderFunctionInOut($fn, "in");
		HeaderFunctionInOut($fn, "inout");
		$tab_depth--;
		pidl tabs()."} in;\n\n";
		$needed++;
	}

	if (HeaderFunctionInOut_needed($fn, "out") or
	    HeaderFunctionInOut_needed($fn, "inout")) {
		pidl tabs()."struct {\n";
		$tab_depth++;
		HeaderFunctionInOut($fn, "out");
		HeaderFunctionInOut($fn, "inout");
		if (defined($fn->{RETURN_TYPE})) {
			pidl tabs().mapTypeName($fn->{RETURN_TYPE}) . " result;\n";
		}
		$tab_depth--;
		pidl tabs()."} out;\n\n";
		$needed++;
	}

	if (!$needed) {
		# sigh - some compilers don't like empty structures
		pidl tabs()."int _dummy_element;\n";
	}

	$tab_depth--;
	pidl "};\n\n";
}

sub HeaderImport
{
	my @imports = @_;
	foreach my $import (@imports) {
		$import = unmake_str($import);
		$import =~ s/\.idl$//;
		pidl choose_header("librpc/gen_ndr/$import\.h", "gen_ndr/$import.h") . "\n";
	}
}

sub HeaderInclude
{
	my @includes = @_;
	foreach (@includes) {
		pidl "#include $_\n";
	}
}

#####################################################################
# parse the interface definitions
sub HeaderInterface($)
{
	my($interface) = shift;

	pidl "#ifndef _HEADER_$interface->{NAME}\n";
	pidl "#define _HEADER_$interface->{NAME}\n\n";

	foreach my $c (@{$interface->{CONSTS}}) {
		HeaderConst($c);
	}

	foreach my $t (@{$interface->{TYPES}}) {
		HeaderTypedef($t, ";\n\n") if ($t->{TYPE} eq "TYPEDEF");
		HeaderStruct($t, $t->{NAME}, ";\n\n") if ($t->{TYPE} eq "STRUCT");
		HeaderUnion($t, $t->{NAME}, ";\n\n") if ($t->{TYPE} eq "UNION");
		HeaderEnum($t, $t->{NAME}, ";\n\n") if ($t->{TYPE} eq "ENUM");
		HeaderBitmap($t, $t->{NAME}) if ($t->{TYPE} eq "BITMAP");
		HeaderPipe($t, $t->{NAME}, "\n\n") if ($t->{TYPE} eq "PIPE");
	}

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		HeaderFunction($fn);
	}

	pidl "#endif /* _HEADER_$interface->{NAME} */\n";
}

sub HeaderQuote($)
{
	my($quote) = shift;

	pidl unmake_str($quote->{DATA}) . "\n";
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($)
{
	my($ndr) = shift;
	$tab_depth = 0;

	$res = "";
	%headerstructs = ();
	pidl "/* header auto-generated by pidl */\n\n";

	my $ifacename = "";

	# work out a unique interface name
	foreach (@{$ndr}) {
		if ($_->{TYPE} eq "INTERFACE") {
			$ifacename = $_->{NAME};
			last;
		}
	}

	pidl "#ifndef _PIDL_HEADER_$ifacename\n";
	pidl "#define _PIDL_HEADER_$ifacename\n\n";

	if (!is_intree()) {
		pidl "#include <util/data_blob.h>\n";
	}
	pidl "#include <stdint.h>\n";
	pidl "\n";
	# FIXME: Include this only if NTSTATUS was actually used
	pidl choose_header("libcli/util/ntstatus.h", "core/ntstatus.h") . "\n";
	pidl "\n";

	foreach (@{$ndr}) {
		($_->{TYPE} eq "CPP_QUOTE") && HeaderQuote($_);
		($_->{TYPE} eq "INTERFACE") && HeaderInterface($_);
		($_->{TYPE} eq "IMPORT") && HeaderImport(@{$_->{PATHS}});
		($_->{TYPE} eq "INCLUDE") && HeaderInclude(@{$_->{PATHS}});
	}

	pidl "#endif /* _PIDL_HEADER_$ifacename */\n";

	return $res;
}

sub GenerateStructEnv($$)
{
	my ($x, $v) = @_;
	my %env;

	foreach my $e (@{$x->{ELEMENTS}}) {
		$env{$e->{NAME}} = "$v->$e->{NAME}";
	}

	$env{"this"} = $v;

	return \%env;
}

sub EnvSubstituteValue($$)
{
	my ($env,$s) = @_;

	# Substitute the value() values in the env
	foreach my $e (@{$s->{ELEMENTS}}) {
		next unless (defined(my $v = has_property($e, "value")));
		
		$env->{$e->{NAME}} = ParseExpr($v, $env, $e);
	}

	return $env;
}

sub GenerateFunctionInEnv($;$)
{
	my ($fn, $base) = @_;
	my %env;

	$base = "r->" unless defined($base);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = $base."in.$e->{NAME}";
		}
	}

	return \%env;
}

sub GenerateFunctionOutEnv($;$)
{
	my ($fn, $base) = @_;
	my %env;

	$base = "r->" unless defined($base);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/out/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = $base."out.$e->{NAME}";
		} elsif (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = $base."in.$e->{NAME}";
		}
	}

	return \%env;
}

1;
