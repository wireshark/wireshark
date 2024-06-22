###################################################
# dump function for IDL structures
# Copyright tridge@samba.org 2000
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

=pod

=head1 NAME

Parse::Pidl::Dump - Dump support

=head1 DESCRIPTION

This module provides functions that can generate IDL code from 
internal pidl data structures.

=cut

package Parse::Pidl::Dump;

use Exporter;

use vars qw($VERSION);
$VERSION = '0.01';
@ISA = qw(Exporter);
@EXPORT_OK = qw(DumpType DumpTypedef DumpStruct DumpEnum DumpBitmap DumpUnion DumpFunction);

use strict;
use warnings;
use Parse::Pidl::Util qw(has_property);

my($res);

#####################################################################
# dump a properties list
sub DumpProperties($)
{
    my($props) = shift;
    my $res = "";

    foreach my $d ($props) {
	foreach my $k (sort(keys %{$d})) {
	    if ($k eq "in") {
		$res .= "[in] ";
		next;
	    }
	    if ($k eq "out") {
		$res .= "[out] ";
		next;
	    }
	    if ($k eq "ref") {
		$res .= "[ref] ";
		next;
	    }
	    $res .= "[$k($d->{$k})] ";
	}
    }
    return $res;
}

#####################################################################
# dump a structure element
sub DumpElement($)
{
    my($element) = shift;
    my $res = "";

    (defined $element->{PROPERTIES}) && 
	($res .= DumpProperties($element->{PROPERTIES}));
    $res .= DumpType($element->{TYPE});
    $res .= " ";
	for my $i (1..$element->{POINTERS}) {
	    $res .= "*";
    }
    $res .= "$element->{NAME}";
	foreach (@{$element->{ARRAY_LEN}}) {
		$res .= "[$_]";
	}

    return $res;
}

#####################################################################
# dump a struct
sub DumpStruct($)
{
    my($struct) = shift;
    my($res);

    $res .= "struct ";
	if ($struct->{NAME}) {
		$res.="$struct->{NAME} ";
	}
	
	$res.="{\n";
    if (defined $struct->{ELEMENTS}) {
		foreach (@{$struct->{ELEMENTS}}) {
		    $res .= "\t" . DumpElement($_) . ";\n";
		}
    }
    $res .= "}";
    
    return $res;
}


#####################################################################
# dump a struct
sub DumpEnum($)
{
    my($enum) = shift;
    my($res);

    $res .= "enum {\n";

    foreach (@{$enum->{ELEMENTS}}) {
    	if (/^([A-Za-z0-9_]+)[ \t]*\((.*)\)$/) {
		$res .= "\t$1 = $2,\n";
	} else {
		$res .= "\t$_,\n";
	}
    }

    $res.= "}";
    
    return $res;
}

#####################################################################
# dump a struct
sub DumpBitmap($)
{
    my($bitmap) = shift;
    my($res);

    $res .= "bitmap {\n";

    foreach (@{$bitmap->{ELEMENTS}}) {
    	if (/^([A-Za-z0-9_]+)[ \t]*\((.*)\)$/) {
		$res .= "\t$1 = $2,\n";
	} else {
		die ("Bitmap $bitmap->{NAME} has field $_ without proper value");
	}
    }

    $res.= "}";
    
    return $res;
}


#####################################################################
# dump a union element
sub DumpUnionElement($)
{
    my($element) = shift;
    my($res);

    if (has_property($element, "default")) {
	$res .= "[default] ;\n";
    } else {
	$res .= "[case($element->{PROPERTIES}->{case})] ";
	$res .= DumpElement($element), if defined($element);
	$res .= ";\n";
    }

    return $res;
}

#####################################################################
# dump a union
sub DumpUnion($)
{
    my($union) = shift;
    my($res);

    (defined $union->{PROPERTIES}) && 
	($res .= DumpProperties($union->{PROPERTIES}));
    $res .= "union {\n";
    foreach my $e (@{$union->{ELEMENTS}}) {
	$res .= DumpUnionElement($e);
    }
    $res .= "}";

    return $res;
}

#####################################################################
# dump a type
sub DumpType($)
{
    my($data) = shift;

    if (ref($data) eq "HASH") {
		return DumpStruct($data) if ($data->{TYPE} eq "STRUCT");
		return DumpUnion($data) if ($data->{TYPE} eq "UNION");
		return DumpEnum($data) if ($data->{TYPE} eq "ENUM");
		return DumpBitmap($data) if ($data->{TYPE} eq "BITMAP");
    } else {
		return $data;
    }
}

#####################################################################
# dump a typedef
sub DumpTypedef($)
{
    my($typedef) = shift;
    my($res);

    $res .= "typedef ";
    $res .= DumpType($typedef->{DATA});
    $res .= " $typedef->{NAME};\n\n";

    return $res;
}

#####################################################################
# dump a typedef
sub DumpFunction($)
{
    my($function) = shift;
    my($first) = 1;
    my($res);

    $res .= DumpType($function->{RETURN_TYPE});
    $res .= " $function->{NAME}(\n";
    for my $d (@{$function->{ELEMENTS}}) {
		unless ($first) { $res .= ",\n"; } $first = 0;
		$res .= DumpElement($d);
    }
    $res .= "\n);\n\n";

    return $res;
}

#####################################################################
# dump a module header
sub DumpInterfaceProperties($)
{
    my($header) = shift;
    my($data) = $header->{DATA};
    my($first) = 1;
    my($res);

    $res .= "[\n";
    foreach my $k (sort(keys %{$data})) {
	    $first || ($res .= ",\n"); $first = 0;
	    $res .= "$k($data->{$k})";
    }
    $res .= "\n]\n";

    return $res;
}

#####################################################################
# dump the interface definitions
sub DumpInterface($)
{
    my($interface) = shift;
    my($data) = $interface->{DATA};
    my($res);

	$res .= DumpInterfaceProperties($interface->{PROPERTIES});

    $res .= "interface $interface->{NAME}\n{\n";
    foreach my $d (@{$data}) {
	($d->{TYPE} eq "TYPEDEF") &&
	    ($res .= DumpTypedef($d));
	($d->{TYPE} eq "FUNCTION") &&
	    ($res .= DumpFunction($d));
    }
    $res .= "}\n";

    return $res;
}


#####################################################################
# dump a parsed IDL structure back into an IDL file
sub Dump($)
{
    my($idl) = shift;
    my($res);

    $res = "/* Dumped by pidl */\n\n";
    foreach my $x (@{$idl}) {
	($x->{TYPE} eq "INTERFACE") && 
	    ($res .= DumpInterface($x));
    }
    return $res;
}

1;
