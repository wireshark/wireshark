###################################################
# create C header files for an IDL structure
# Copyright tridge@samba.org 2000
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba4::Header;

use strict;
use Parse::Pidl::Typelist qw(mapType);
use Parse::Pidl::Util qw(has_property is_constant);
use Parse::Pidl::NDR qw(GetNextLevel GetPrevLevel);

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

    foreach my $d (keys %{$props}) {
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
	HeaderType($element, $element->{TYPE}, "");
	pidl " ";
	my $numstar = $element->{POINTERS};
	if ($numstar >= 1) {
		$numstar-- if Parse::Pidl::Typelist::scalar_is_reference($element->{TYPE});
	}
	foreach (@{$element->{ARRAY_LEN}})
	{
		next if is_constant($_) and 
			not has_property($element, "charset");
		$numstar++;
	}
	pidl "*" foreach (1..$numstar);
	pidl $element->{NAME};
	foreach (@{$element->{ARRAY_LEN}}) {
		next unless (is_constant($_) and 
			not has_property($element, "charset"));
		pidl "[$_]";
	}

	pidl ";";
	if (defined $element->{PROPERTIES}) {
		HeaderProperties($element->{PROPERTIES}, ["in", "out"]);
	}
	pidl "\n";
}

#####################################################################
# parse a struct
sub HeaderStruct($$)
{
    my($struct,$name) = @_;
	pidl "struct $name {\n";
    $tab_depth++;
    my $el_count=0;
    if (defined $struct->{ELEMENTS}) {
		foreach my $e (@{$struct->{ELEMENTS}}) {
		    HeaderElement($e);
		    $el_count++;
		}
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
}

#####################################################################
# parse a enum
sub HeaderEnum($$)
{
    my($enum,$name) = @_;
    my $first = 1;

    if (not Parse::Pidl::Util::useUintEnums()) {
    	pidl "enum $name {\n";
	$tab_depth++;
	foreach my $e (@{$enum->{ELEMENTS}}) {
 	    unless ($first) { pidl ",\n"; }
	    $first = 0;
	    pidl tabs();
	    pidl $e;
	}
	pidl "\n";
	$tab_depth--;
	pidl "}";
    } else {
        my $count = 0;
	pidl "enum $name { __donnot_use_enum_$name=0x7FFFFFFF};\n";
	my $with_val = 0;
	my $without_val = 0;
	foreach my $e (@{$enum->{ELEMENTS}}) {
	    my $t = "$e";
	    my $name;
	    my $value;
	    if ($t =~ /(.*)=(.*)/) {
	    	$name = $1;
	    	$value = $2;
		$with_val = 1;
		die ("you can't mix enum member with values and without values when using --uint-enums!")
			unless ($without_val == 0);
	    } else {
	    	$name = $t;
	    	$value = $count++;
		$without_val = 1;
		die ("you can't mix enum member with values and without values when using --uint-enums!")
			unless ($with_val == 0);
	    }
	    pidl "#define $name ( $value )\n";
	}
	pidl "\n";
    }
}

#####################################################################
# parse a bitmap
sub HeaderBitmap($$)
{
    my($bitmap,$name) = @_;

    pidl "/* bitmap $name */\n";
    pidl "#define $_\n" foreach (@{$bitmap->{ELEMENTS}});
    pidl "\n";
}

#####################################################################
# parse a union
sub HeaderUnion($$)
{
	my($union,$name) = @_;
	my %done = ();

	pidl "union $name {\n";
	$tab_depth++;
	foreach my $e (@{$union->{ELEMENTS}}) {
		if ($e->{TYPE} ne "EMPTY") {
			if (! defined $done{$e->{NAME}}) {
				HeaderElement($e);
			}
			$done{$e->{NAME}} = 1;
		}
	}
	$tab_depth--;
	pidl "}";

	if (defined $union->{PROPERTIES}) {
		HeaderProperties($union->{PROPERTIES}, []);
	}
}

#####################################################################
# parse a type
sub HeaderType($$$)
{
	my($e,$data,$name) = @_;
	if (ref($data) eq "HASH") {
		($data->{TYPE} eq "ENUM") && HeaderEnum($data, $name);
		($data->{TYPE} eq "BITMAP") && HeaderBitmap($data, $name);
		($data->{TYPE} eq "STRUCT") && HeaderStruct($data, $name);
		($data->{TYPE} eq "UNION") && HeaderUnion($data, $name);
		return;
	}

	if (has_property($e, "charset")) {
		pidl "const char";
	} else {
		pidl mapType($e->{TYPE});
	}
}

#####################################################################
# parse a typedef
sub HeaderTypedef($)
{
    my($typedef) = shift;
    HeaderType($typedef, $typedef->{DATA}, $typedef->{NAME});
    pidl ";\n\n" unless ($typedef->{DATA}->{TYPE} eq "BITMAP");
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

#####################################################################
# parse a function
sub HeaderFunctionInOut($$)
{
    my($fn,$prop) = @_;

    foreach my $e (@{$fn->{ELEMENTS}}) {
	    if (has_property($e, $prop)) {
		    HeaderElement($e);
	    }
    }
}

#####################################################################
# determine if we need an "in" or "out" section
sub HeaderFunctionInOut_needed($$)
{
    my($fn,$prop) = @_;

    return 1 if ($prop eq "out" && $fn->{RETURN_TYPE} ne "void");

    foreach (@{$fn->{ELEMENTS}}) {
	    return 1 if (has_property($_, $prop));
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

    if (HeaderFunctionInOut_needed($fn, "in")) {
	    pidl tabs()."struct {\n";
	    $tab_depth++;
	    HeaderFunctionInOut($fn, "in");
	    $tab_depth--;
	    pidl tabs()."} in;\n\n";
	    $needed++;
    }

    if (HeaderFunctionInOut_needed($fn, "out")) {
	    pidl tabs()."struct {\n";
	    $tab_depth++;
	    HeaderFunctionInOut($fn, "out");
	    if ($fn->{RETURN_TYPE} ne "void") {
		    pidl tabs().mapType($fn->{RETURN_TYPE}) . " result;\n";
	    }
	    $tab_depth--;
	    pidl tabs()."} out;\n\n";
	    $needed++;
    }

    if (! $needed) {
	    # sigh - some compilers don't like empty structures
	    pidl tabs()."int _dummy_element;\n";
    }

    $tab_depth--;
    pidl "};\n\n";
}

#####################################################################
# parse the interface definitions
sub HeaderInterface($)
{
	my($interface) = shift;

	pidl "#ifndef _HEADER_$interface->{NAME}\n";
	pidl "#define _HEADER_$interface->{NAME}\n\n";

	if (defined $interface->{PROPERTIES}->{depends}) {
		my @d = split / /, $interface->{PROPERTIES}->{depends};
		foreach my $i (@d) {
			pidl "#include \"librpc/gen_ndr/$i\.h\"\n";
		}
	}

	foreach my $d (@{$interface->{DATA}}) {
		next if ($d->{TYPE} ne "CONST");
		HeaderConst($d);
	}

	foreach my $d (@{$interface->{DATA}}) {
		next if ($d->{TYPE} ne "TYPEDEF");
		HeaderTypedef($d);
	}

	foreach my $d (@{$interface->{DATA}}) {
		next if ($d->{TYPE} ne "FUNCTION");

		HeaderFunction($d);
	}

	pidl "#endif /* _HEADER_$interface->{NAME} */\n";
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($)
{
    my($idl) = shift;
    $tab_depth = 0;

	$res = "";
	%headerstructs = ();
    pidl "/* header auto-generated by pidl */\n\n";
    foreach (@{$idl}) {
	    ($_->{TYPE} eq "INTERFACE") && HeaderInterface($_);
    }
    return $res;
}

1;
