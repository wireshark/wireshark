#!/usr/bin/perl
#
# Script to convert xcbproto and mesa protocol files for
# X11 dissector. Creates header files containing code to
# dissect X11 extensions.
#
# Copyright 2008, 2009 Open Text Corporation <pharris[AT]opentext.com>
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

#TODO
# - look ahead to see if values are ever used again before creating an "int" in the output
# - support constructs that are legal in XCB, but don't appear to be used

use 5.010;

use warnings;
use strict;

use IO::File;
use XML::Twig;

use File::Spec;

my @reslist = grep {!/xproto\.xml$/} glob File::Spec->catfile('xcbproto', 'src', '*.xml');
my @register;

my %basictype = (
    char =>   { size => 1, type => 'FT_STRING', base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
    void =>   { size => 1, type => 'FT_BYTES',  base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
    BYTE =>   { size => 1, type => 'FT_BYTES',  base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
    CARD8 =>  { size => 1, type => 'FT_UINT8',  base => 'BASE_HEX_DEC', get => 'VALUE8',  list => 'listOfByte', },
    CARD16 => { size => 2, type => 'FT_UINT16', base => 'BASE_HEX_DEC', get => 'VALUE16', list => 'listOfCard16', },
    CARD32 => { size => 4, type => 'FT_UINT32', base => 'BASE_HEX_DEC', get => 'VALUE32', list => 'listOfCard32', },
    INT8 =>   { size => 1, type => 'FT_INT8',   base => 'BASE_DEC',     get => 'VALUE8',  list => 'listOfByte', },
    INT16 =>  { size => 2, type => 'FT_INT16',  base => 'BASE_DEC',     get => 'VALUE16', list => 'listOfInt16', },
    INT32 =>  { size => 4, type => 'FT_INT32',  base => 'BASE_DEC',     get => 'VALUE32', list => 'listOfInt32', },
    float =>  { size => 4, type => 'FT_FLOAT',  base => 'BASE_NONE',    get => 'FLOAT',   list => 'listOfFloat', },
    double => { size => 8, type => 'FT_DOUBLE', base => 'BASE_NONE',    get => 'DOUBLE',  list => 'listOfDouble', },
    BOOL =>   { size => 1, type => 'FT_BOOLEAN',base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
);

my %simpletype;  # Reset at the beginning of each extension
my %gltype;  # No need to reset, since it's only used once

my %struct =  # Not reset; contains structures already defined.
	      # Also contains this black-list of structures never used by any
	      # extension (to avoid generating useless code).
(
    # structures defined by xproto, but not used by any extension
    CHAR2B => 1,
    ARC => 1,
    FORMAT => 1,
    VISUALTYPE => 1,
    DEPTH => 1,
    SCREEN => 1,
    SetupRequest => 1,
    SetupFailed => 1,
    SetupAuthenticate => 1,
    Setup => 1,
    TIMECOORD => 1,
    FONTPROP => 1,
    CHARINFO => 1,
    SEGMENT => 1,
    COLORITEM => 1,
    RGB => 1,
    HOST => 1,

    # structures defined by xinput, but never used (except by each other)(bug in xcb?)
    InputInfo => 1,
    KeyInfo => 1,
    ButtonInfo => 1,
    AxisInfo => 1,
    ValuatorInfo => 1,
    DeviceTimeCoord => 1,
    FeedbackState => 1,
    KbdFeedbackState => 1,
    PtrFeedbackState => 1,
    IntegerFeedbackState => 1,
    StringFeedbackState => 1,
    BellFeedbackState => 1,
    LedFeedbackState => 1,
    FeedbackCtl => 1,
    KbdFeedbackCtl => 1,
    PtrFeedbackCtl => 1,
    IntegerFeedbackCtl => 1,
    StringFeedbackCtl => 1,
    BellFeedbackCtl => 1,
    LedFeedbackCtl => 1,
    InputState => 1,
    KeyState => 1,
    ButtonState => 1,
    ValuatorState => 1,
    DeviceState => 1,
    DeviceResolutionState => 1,
    DeviceAbsCalibState => 1,
    DeviceAbsAreaState => 1,
    DeviceCoreState => 1,
    DeviceEnableState => 1,
    DeviceCtl => 1,
    DeviceResolutionCtl => 1,
    DeviceAbsCalibCtl => 1,
    DeviceAbsAreaCtrl => 1,
    DeviceCoreCtrl => 1,
    DeviceEnableCtrl => 1,

    # structures defined by xv, but never used (bug in xcb?)
    Image => 1,
    
    # structures defined by xkb, but never used (bug in xcb?)
    CountedString8 => 1,
);
my %enum;  # Not reset; contains enums already defined.
my %enum_name;
my $header;
my $extname;
my @incname;
my %request;
my %event;
my %reply;

# Output files
my $impl;
my $reg;
my $decl;
my $error;

# glRender sub-op output files
my $enum;

# Mesa API definitions keep moving
my @mesas = ('mesa/src/mapi/glapi/gen',  # 2010-04-26
	     'mesa/src/mesa/glapi/gen',  # 2010-02-22
	     'mesa/src/mesa/glapi');     # 2004-05-18
my $mesadir = (grep { -d } @mesas)[0];

sub mesa_category_start {
    my ($t, $elt) = @_;
    my $name = $elt->att('name');
    my $comment;
    if ($name =~ /^\d\.\d$/) {
	$comment = "version $name";
    } else {
	$comment = "extension $name";
    }

    print $enum "/* OpenGL $comment */\n";
    print(" - $comment\n");
}

sub mesa_category {
    my ($t, $elt) = @_;
    $t->purge;
}

sub mesa_enum {
    my ($t, $elt) = @_;
    my $name = $elt->att('name');
    my $value = $elt->att('value');

    print $enum "  { $value, \"$name\" },\n" if (length($value) > 3 && length($value) < 10);
    $t->purge;
}

sub mesa_type {
    my ($t, $elt) = @_;

    my $name = $elt->att('name');
    my $size = $elt->att('size');
    my $float = $elt->att('float');
    my $unsigned = $elt->att('unsigned');
    my $base;

    $t->purge;

    if($name eq 'enum') {
	# enum does not have a direct X equivalent
	$gltype{'GLenum'} = { size => 4, type => 'FT_UINT32', base => 'BASE_HEX',
			      get => 'VALUE32', list => 'listOfCard32',
			      val => 'VALS(mesa_enum)', };
	return;
    }

    $name = 'GL'.$name;
    if (defined($float) && $float eq 'true') {
	$base = 'float';
	$base = 'double' if ($size == 8);
    } else {
	$base = 'INT';
	if (defined($unsigned) && $unsigned eq 'true') {
	    $base = 'CARD';
	}
	$base .= ($size * 8);

	$base = 'BOOL' if ($name eq 'bool');
	$base = 'BYTE' if ($name eq 'void');
    }

    $gltype{$name} = $basictype{$base};
}

sub registered_name($$)
{
    my $name = shift;
    my $field = shift;

    return "hf_x11_$header"."_$name"."_$field";
}

sub mesa_function {
    my ($t, $elt) = @_;
    # rop == glRender sub-op
    # sop == GLX minor opcode
    my $glx = $elt->first_child('glx');
    unless(defined $glx) { $t->purge; return; }

    my $rop = $glx->att('rop');
    unless (defined $rop) { $t->purge; return; }

    # Ideally, we want the main name, not the alias name.
    # Practically, we'd have to scan the file twice to find
    # the functions that we want to skip.
    my $alias = $elt->att('alias');
    if (defined $alias) { $t->purge; return; }

    my $name = $elt->att('name');
    $request{$rop} = $name;

    my $image;

    my $length = 0;
    my @elements = $elt->children('param');

    # Wireshark defines _U_ to mean "Unused" (compiler specific define)
    if (!@elements) {
	print $impl <<eot
static void mesa_$name(tvbuff_t *tvb _U_, int *offsetp _U_, proto_tree *t _U_, int little_endian _U_, int length _U_)
{
eot
;
    } else {
	print $impl <<eot
static void mesa_$name(tvbuff_t *tvb, int *offsetp, proto_tree *t, int little_endian, int length _U_)
{
eot
;
    }

    foreach my $e (@elements) {
	# Register field with wireshark

	my $type = $e->att('type');
	$type =~ s/^const //;
	my $list;
	$list = 1 if ($type =~ /\*$/);
	$type =~ s/ \*$//;

	my $fieldname = $e->att('name');
	my $regname = registered_name($name, $fieldname);

	my $info = $gltype{$type};
	my $ft = $info->{'type'};
	my $base = $info->{'base'};
	my $val = $info->{'val'} // 'NULL';

	print $decl "static int $regname = -1;\n";
	if ($list and $info->{'size'} > 1) {
	    print $reg "{ &$regname, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";
	    $regname .= '_item';
	    print $decl "static int $regname = -1;\n";
	}
	print $reg "{ &$regname, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", $ft, $base, $val, 0, NULL, HFILL }},\n";

	if ($e->att('counter')) {
	    print $impl "    int $fieldname;\n";
	}

	if ($list) {
	    if ($e->att('img_format')) {
		$image = 1;
		foreach my $wholename (('swap bytes', 'lsb first')) {
		    # Boolean values
		    my $varname = $wholename;
		    $varname =~ s/\s//g;
		    my $regname = registered_name($name, $varname);
		    print $decl "static int $regname = -1;\n";
		    print $reg "{ &$regname, { \"$wholename\", \"x11.glx.render.$name.$varname\", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }},\n";
		}
		foreach my $wholename (('row length', 'skip rows', 'skip pixels', 'alignment')) {
		    # Integer values
		    my $varname = $wholename;
		    $varname =~ s/\s//g;
		    my $regname = registered_name($name, $varname);
		    print $decl "static int $regname = -1;\n";
		    print $reg "{ &$regname, { \"$wholename\", \"x11.glx.render.$name.$varname\", FT_UINT32, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},\n";
		}
	    }
	}
    }

    # The image requests have a few implicit elements first:
    if ($image) {
	foreach my $wholename (('swap bytes', 'lsb first')) {
	    # Boolean values
	    my $varname = $wholename;
	    $varname =~ s/\s//g;
	    my $regname = registered_name($name, $varname);
	    print $impl "    proto_tree_add_item(t, $regname, tvb, *offsetp, 1, little_endian);\n";
	    print $impl "    *offsetp += 1;\n";
	    $length += 1;
	}
	print $impl "    UNUSED(2);\n";
	$length += 2;
	foreach my $wholename (('row length', 'skip rows', 'skip pixels', 'alignment')) {
	    # Integer values
	    my $varname = $wholename;
	    $varname =~ s/\s//g;
	    my $regname = registered_name($name, $varname);
	    print $impl "    proto_tree_add_item(t, $regname, tvb, *offsetp, 4, little_endian);\n";
	    print $impl "    *offsetp += 4;\n";
	    $length += 4;
	}
    }

    foreach my $e (@elements) {
	my $type = $e->att('type');
	$type =~ s/^const //;
	my $list;
	$list = 1 if ($type =~ /\*$/);
	$type =~ s/ \*$//;

	my $fieldname = $e->att('name');
	my $regname = registered_name($name, $fieldname);

	my $info = $gltype{$type};
	my $ft = $info->{'type'};
	my $base = $info->{'base'};

        if (!$list) {
	    my $size = $info->{'size'};
	    my $get = $info->{'get'};

	    if ($e->att('counter')) {
		print $impl "    $fieldname = $get(tvb, *offsetp);\n";
	    }
	    print $impl "    proto_tree_add_item(t, $regname, tvb, *offsetp, $size, little_endian);\n";
	    print $impl "    *offsetp += $size;\n";
	    $length += $size;
        } else {	# list
	    # TODO: variable_param
	    my $list = $info->{'list'};
	    my $count = $e->att('count');
	    my $variable_param = $e->att('variable_param');

	    $regname .= ", $regname".'_item' if ($info->{'size'} > 1);
	    if (defined($count) && !defined($variable_param)) {
		print $impl "    $list(tvb, offsetp, t, $regname, $count, little_endian);\n";
	    } else {
		print $impl "    $list(tvb, offsetp, t, $regname, (length - $length) / $gltype{$type}{'size'}, little_endian);\n";
	    }
	}
    }

    print $impl "}\n\n";
    $t->purge;
}

sub get_op($;$);
sub get_unop($;$);

sub get_ref($$)
{
    my $elt = shift;
    my $refref = shift;
    my $rv;

    given($elt->name()) {
	when ('fieldref') {
	    $rv = $elt->text();
	    $refref->{$rv} = 1;
	    $rv = 'f_'.$rv;
	}
	when ('value') { $rv = $elt->text(); }
	when ('op') { $rv = get_op($elt, $refref); }
	when (['unop','popcount']) { $rv = get_unop($elt, $refref); }
	default { die "Invalid op fragment: $_" }
    }
    return $rv;
}

sub get_op($;$) {
    my $op = shift;
    my $refref = shift // {};

    my @elements = $op->children(qr/fieldref|value|op|unop|popcount/);
    (@elements == 2) or die ("Wrong number of children for 'op'\n");
    my $left;
    my $right;

    $left = get_ref($elements[0], $refref);
    $right = get_ref($elements[1], $refref);

    return "($left " . $op->att('op') . " $right)";
}

sub get_unop($;$) {
    my $op = shift;
    my $refref = shift // {};

    my @elements = $op->children(qr/fieldref|value|op|unop|popcount/);
    (@elements == 1) or die ("Wrong number of children for 'unop'\n");
    my $left;

    $left = get_ref($elements[0], $refref);

    given ($op->name()) {
	when ('unop') {
	    return '(' . $op->att('op') . "$left)";
	}
	when ('popcount') {
	    return "popcount($left)";
	}
	default { die "Invalid unop element $op->name()\n"; }
    }
}

sub dump_enum_values($)
{
    my $e = shift;

    defined($enum{$e}) or die("Enum $e not found");

    my $enumname = "x11_enum_$e";
    return $enumname if (defined $enum{$e}{done});

    say $enum 'static const value_string '.$enumname.'[] = {';

    my $value = $enum{$e}{value};
    for my $val (sort { $a <=> $b } keys %$value) {
	say $enum sprintf("\t{ %3d, \"%s\" },", $val, $$value{$val});
    }
    say $enum sprintf("\t{ %3d, NULL },", 0);
    say $enum '};';
    say $enum '';

    $enum{$e}{done} = 1;
    return $enumname;
}

sub register_element($$$;$);

sub register_element($$$;$)
{
    my $e = shift;
    my $varpat = shift;
    my $humanpat = shift;
    my $indent = shift // ' ' x 4;

    given ($e->name()) {
	when ('pad') { return; }     # Pad has no variables
	when ('switch') { return; }  # Switch defines varaibles in a tighter scope to avoid collisions
    }

    # Register field with wireshark

    my $fieldname = $e->att('name');
    my $type = $e->att('type') or die ("Field $fieldname does not have a valid type\n");
    $type =~ s/^.*://;

    my $regname = 'hf_x11_'.sprintf ($varpat, $fieldname);
    my $humanname = 'x11.'.sprintf ($humanpat, $fieldname);

    my $info = $basictype{$type} // $simpletype{$type} // $struct{$type};
    my $ft = $info->{'type'} // 'FT_NONE';
    my $base = $info->{'base'} // 'BASE_NONE';
    my $vals = 'NULL';
    
    my $enum = $e->att('enum') // $e->att('altenum');
    if (defined $enum) {
	my $enumname = dump_enum_values($enum_name{$enum});
	$vals = "VALS($enumname)";

	# Wireshark does not allow FT_BYTES or BASE_NONE to have an enum
	$ft =~ s/FT_BYTES/FT_UINT8/;
	$base =~ s/BASE_NONE/BASE_DEC/;
    }

    $enum = $e->att('mask');
    if (defined $enum) {
	# Create subtree items:
	defined($enum{$enum_name{$enum}}) or die("Enum $enum not found");

	# Wireshark does not allow FT_BYTES or BASE_NONE to have an enum
	$ft =~ s/FT_BYTES/FT_UINT8/;
	$base =~ s/BASE_NONE/BASE_DEC/;

	my $bitsize = $info->{'size'} * 8;

	my $bit = $enum{$enum_name{$enum}}{bit};
	for my $val (sort { $a <=> $b } keys %$bit) {
	    my $itemname = $$bit{$val};
	    my $item = $regname . '_mask_' . $itemname;
	    my $itemhuman = $humanname . '.' . $itemname;
	    my $bitshift = "1 << $val";

	    say $decl "static int $item = -1;";
	    say $reg "{ &$item, { \"$itemname\", \"$itemhuman\", FT_BOOLEAN, $bitsize, NULL, $bitshift, NULL, HFILL }},";
	}
    }

    print $decl "static int $regname = -1;\n";
    if ($e->name() eq 'list' and $info->{'size'} > 1) {
	print $reg "{ &$regname, { \"$fieldname\", \"$humanname\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";
	$regname .= '_item';
	print $decl "static int $regname = -1;\n";
    }
    print $reg "{ &$regname, { \"$fieldname\", \"$humanname\", $ft, $base, $vals, 0, NULL, HFILL }},\n";

    if ($e->name() eq 'field') {
	if ($basictype{$type} or $simpletype{$type}) {
	    # Pre-declare variable
	    if ($ft eq 'FT_FLOAT') {
		print $impl $indent."gfloat f_$fieldname;\n";
	    } elsif ($ft eq 'FT_DOUBLE') {
		print $impl $indent."gdouble f_$fieldname;\n";
	    } else {
		print $impl $indent."int f_$fieldname;\n";
	    }
	}
    }
}

sub dissect_element($$$$;$$);

sub dissect_element($$$$;$$)
{
    my $e = shift;
    my $varpat = shift;
    my $humanpat = shift;
    my $length = shift;
    my $adjustlength = shift;
    my $indent = shift // ' ' x 4;

    given ($e->name()) {
	when ('pad') {
	    my $bytes = $e->att('bytes');
	    print $impl $indent."UNUSED($bytes);\n";
	    $length += $bytes;
	}
	when ('field') {
	    my $fieldname = $e->att('name');
	    my $regname = 'hf_x11_'.sprintf ($varpat, $fieldname);
	    my $type = $e->att('type');
	    $type =~ s/^.*://;

	    if ($basictype{$type} or $simpletype{$type}) {
		my $info = $basictype{$type} // $simpletype{$type};
		my $size = $info->{'size'};
		my $get = $info->{'get'};

		if ($e->att('enum') // $e->att('altenum')) {
		    my $fieldsize = $size * 8;
		    say $impl $indent."f_$fieldname = field$fieldsize(tvb, offsetp, t, $regname, little_endian);";
		} elsif ($e->att('mask')) {
		    say $impl $indent."f_$fieldname = $get(tvb, *offsetp);";
		    say $impl $indent."{";
		    say $impl $indent."    proto_item *ti = proto_tree_add_item(t, $regname, tvb, *offsetp, $size, little_endian);";
		    say $impl $indent."    proto_tree *bitmask_tree = proto_item_add_subtree(ti, ett_x11_rectangle);";

		    my $bytesize = $info->{'size'};
		    my $bit = $enum{$enum_name{$e->att('mask')}}{bit};
		    for my $val (sort { $a <=> $b } keys %$bit) {
			my $item = $regname . '_mask_' . $$bit{$val};

			say $impl "$indent    proto_tree_add_item(bitmask_tree, $item, tvb, *offsetp, $bytesize, little_endian);";
		    }

		    say $impl $indent."}";
		    say $impl $indent."*offsetp += $size;";
		} else {
		    print $impl $indent."f_$fieldname = $get(tvb, *offsetp);\n";
		    print $impl $indent."proto_tree_add_item(t, $regname, tvb, *offsetp, $size, little_endian);\n";
		    print $impl $indent."*offsetp += $size;\n";
		}
		$length += $size;
	    } elsif ($struct{$type}) {
		# TODO: variable-lengths (when $info->{'size'} == 0 )
		my $info = $struct{$type};
		$length += $info->{'size'};
		print $impl $indent."struct_$info->{'name'}(tvb, offsetp, t, little_endian, 1);\n";
	    } else {
		die ("Unrecognized type: $type\n");
	    }
	}
	when ('list') {
	    my $fieldname = $e->att('name');
	    my $regname = 'hf_x11_'.sprintf ($varpat, $fieldname);
	    my $type = $e->att('type');
	    $type =~ s/^.*://;

	    my $info = $basictype{$type} // $simpletype{$type} // $struct{$type};
	    my $lencalc = "(length - $length) / $info->{'size'}";
	    my $lentype = $e->first_child();
	    if (defined $lentype) {
		given ($lentype->name()) {
		    when ('value') { $lencalc = $lentype->text(); }
		    when ('fieldref') { $lencalc = 'f_'.$lentype->text(); }
		    when ('op') { $lencalc = get_op($lentype); }
		    when (['unop','popcount']) { $lencalc = get_unop($lentype); }
		}
	    }

	    if ($basictype{$type} or $simpletype{$type}) {
		my $list = $info->{'list'};
		$regname .= ", $regname".'_item' if ($info->{'size'} > 1);
		print $impl $indent."$list(tvb, offsetp, t, $regname, $lencalc, little_endian);\n";
	    } elsif ($struct{$type}) {
		print $impl $indent."struct_$info->{'name'}(tvb, offsetp, t, little_endian, $lencalc);\n";
	    } else {
		die ("Unrecognized type: $type\n");
	    }

	    if ($adjustlength && defined($lentype)) {
	      # Some requests end with a list of unspecified length
	      # Adjust the length field here so that the next $lencalc will be accurate
	      say $impl $indent."length -= $lencalc * $info->{'size'};";
	    }
	}
	when ('switch') {
	    my $switchtype = $e->first_child() or die("Switch element not defined");

	    my $switchon = get_ref($switchtype, {});
	    my @elements = $e->children('bitcase');
	    for my $case (@elements) {
		my $ref = $case->first_child('enumref');
		my $enum_ref = $ref->att('ref');
		my $field = $ref->text();
		my $bit = $enum{$enum_name{$enum_ref}}{rbit}{$field};
		if (! defined($bit)) {
		    for my $foo (keys %{$enum{$enum_name{$enum_ref}}{rbit}}) { say "'$foo'"; }
		    die ("Field '$field' not found in '$enum_ref'");
		}
		$bit = "(1 << $bit)";
		say $impl $indent."if (($switchon & $bit) != 0) {";

		my $vp = $varpat;
		my $hp = $humanpat;

		$vp =~ s/%s/${field}_%s/;
		$hp =~ s/%s/${field}.%s/;

		my @sub_elements = $case->children(qr/pad|field|list|switch/);
		foreach my $sub_e (@sub_elements) {
		    register_element($sub_e, $vp, $hp, $indent . '    ');
		}
		foreach my $sub_e (@sub_elements) {
		    $length = dissect_element($sub_e, $vp, $hp, $length, $adjustlength, $indent . '    ');
		}

		say $impl $indent."}";
	    }
	}
	default { die "Unknown field type: $_\n"; }
    }
    return $length;
}

sub struct {
    my ($t, $elt) = @_;
    my $name = $elt->att('name');

    if (defined $struct{$name}) {
	$t->purge;
	return;
    }

    my @elements = $elt->children(qr/pad|field|list|switch/);

    print(" - Struct $name\n");

    my %refs;
    my $size = 0;
    my $dynamic = 0;
    my $needi = 0;
    # Find struct size
    foreach my $e (@elements) {
	my $count;
	$count = 1;
	given ($e->name()) {
	    when ('pad') {
		my $bytes = $e->att('bytes');
		$size += $bytes;
		next;
	    }
	    when ('list') {
		my $type = $e->att('type');
		my $info = $basictype{$type} // $simpletype{$type} // $struct{$type};
		my $count;

		$needi = 1 if ($info->{'size'} == 0);

		my $value = $e->first_child();
		given($value->name()) {
		    when ('fieldref') {
			$refs{$value->text()} = 1;
			$count = 0;
			$dynamic = 1;
		    }
		    when ('op') {
			get_op($value, \%refs);
			$count = 0;
			$dynamic = 1;
		    }
		    when (['unop','popcount']) {
			get_unop($value, \%refs);
			$count = 0;
			$dynamic = 1;
		    }
		    when ('value') {
			$count = $value->text();
		    }
		    default { die("Invalid list size $_\n"); }
		}
	    }
	    when ('field') { }
	    default { die("unrecognized field $_\n"); }
	}

	my $type = $e->att('type');
	my $info = $basictype{$type} // $simpletype{$type} // $struct{$type};

	$size += $info->{'size'} * $count;
    }

    if ($dynamic) {
	$size = 0;
	print $impl <<eot

static int struct_size_$name(tvbuff_t *tvb, int *offsetp, int little_endian _U_)
{
    int size = 0;
eot
;
	say $impl '    int i, off;' if ($needi);

	foreach my $ref (keys %refs) {
	    say $impl "    int f_$ref;";
	}

	foreach my $e (@elements) {
	    my $count;
	    $count = 1;

	    my $type = $e->att('type') // '';
	    my $info = $basictype{$type} // $simpletype{$type} // $struct{$type};

	    given ($e->name()) {
		when ('pad') {
		    my $bytes = $e->att('bytes');
		    $size += $bytes;
		}
		when ('list') {
		    my $len = $e->first_child();
		    my $infosize = $info->{'size'};
		    my $sizemul;

		    given ($len->name()) {
			when ('op') { $sizemul = get_op($len, \%refs); }
			when (['unop','popcount']) { $sizemul = get_unop($len, \%refs); }
			when ('fieldref') { $sizemul = 'f_'.$len->text(); }
			when ('value') {
			    if ($infosize) {
				$size += $infosize * $len->text();
			    } else {
				$sizemul = $len->text();
			    }
			}
			default { die "Invalid list size: $_\n"; }
		    }
		    if (defined $sizemul) {
			if ($infosize) {
			    say $impl "    size += $sizemul * $infosize;";
			} else {
			    say $impl "    for (i = 0; i < $sizemul; i++) {";
			    say $impl "        off = (*offsetp) + size + $size;";
			    say $impl "        size += struct_size_$type(tvb, &off, little_endian);";
			    say $impl '    }';
			}
		    }
		}
		when ('field') {
		    my $fname = $e->att('name');
		    if (defined($refs{$fname})) {
			say $impl "    f_$fname = $info->{'get'}(tvb, *offsetp + size + $size);";
		    }
		    $size += $info->{'size'};
		}
	    }
	}
	say $impl "    return size + $size;";
	say $impl '}';
	$size = 0; # 0 means "dynamic calcuation required"
    }

    print $decl "static int hf_x11_struct_$name = -1;\n";
    print $reg "{ &hf_x11_struct_$name, { \"$name\", \"x11.struct.$name\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";

    print $impl <<eot

static void struct_$name(tvbuff_t *tvb, int *offsetp, proto_tree *root, int little_endian, int count)
{
    int i;
    for (i = 0; i < count; i++) {
	proto_item *item;
	proto_tree *t;
eot
;

    my $varpat = 'struct_'.$name.'_%s';
    my $humanpat = "struct.$name.%s";

    foreach my $e (@elements) {
	register_element($e, $varpat, $humanpat, "\t");
    }

    my $sizecalc = $size;
    $size or $sizecalc = "struct_size_$name(tvb, offsetp, little_endian)";

    print $impl <<eot

	item = proto_tree_add_item(root, hf_x11_struct_$name, tvb, *offsetp, $sizecalc, little_endian);
	t = proto_item_add_subtree(item, ett_x11_rectangle);
eot
;
    my $length = 0;
    foreach my $e (@elements) {
	$length = dissect_element($e, $varpat, $humanpat, $length, 0, "\t");
    }

    print $impl "    }\n}\n";
    $struct{$name} = { size => $size, name => $name };
    $t->purge;
}

sub union {
    # TODO proper dissection
    #
    # Right now, the only extension to use a union is randr.
    # for now, punt.
    my ($t, $elt) = @_;
    my $name = $elt->att('name');

    if (defined $struct{$name}) {
	$t->purge;
	return;
    }

    my @elements = $elt->children(qr/field/);
    my @sizes;

    print(" - Union $name\n");

    # Find union size
    foreach my $e (@elements) {
	my $type = $e->att('type');
	my $info = $basictype{$type} // $simpletype{$type} // $struct{$type};

	$info->{'size'} > 0 or die ("Error: Union containing variable sized struct $type\n");
	push @sizes, $info->{'size'};
    }
    @sizes = sort {$b <=> $a} @sizes;
    my $size = $sizes[0];

    print $decl "static int hf_x11_union_$name = -1;\n";
    print $reg "{ &hf_x11_union_$name, { \"$name\", \"x11.union.$name\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";

    print $impl <<eot

static void struct_$name(tvbuff_t *tvb, int *offsetp, proto_tree *root, int little_endian, int count)
{
    int i;
    int base = *offsetp;
    for (i = 0; i < count; i++) {
	proto_item *item;
	proto_tree *t;
eot
;

    my $varpat = 'union_'.$name.'_%s';
    my $humanpat = "union.$name.%s";

    foreach my $e (@elements) {
	register_element($e, $varpat, $humanpat, "\t");
    }

    print $impl <<eot
	item = proto_tree_add_item(root, hf_x11_union_$name, tvb, base, $size, little_endian);
	t = proto_item_add_subtree(item, ett_x11_rectangle);

eot
;

    foreach my $e (@elements) {
	say $impl '        *offsetp = base;';
	dissect_element($e, $varpat, $humanpat, 0, 0, "\t");
    }
    say $impl "        base += $size;";
    say $impl '    }';
    say $impl '    *offsetp = base;';
    say $impl '}';

    $struct{$name} = { size => $size, name => $name };
    $t->purge;
}

sub enum {
    my ($t, $elt) = @_;
    my $name = $elt->att('name');
    my $fullname = $incname[0].'_'.$name;

    $enum_name{$name} = $fullname;
    $enum_name{$incname[0].':'.$name} = $fullname;

    if (defined $enum{$fullname}) {
	$t->purge;
	return;
    }

    my @elements = $elt->children('item');

    print(" - Enum $name\n");

    my $value = {};
    my $bit = {};
    my $rbit = {};
    $enum{$fullname} = { value => $value, bit => $bit, rbit => $rbit };

    my $nextvalue = 0;

    foreach my $e (@elements) {
	my $n = $e->att('name');
	my $valtype = $e->first_child(qr/value|bit/);
	if (defined $valtype) {
	    my $val = int($valtype->text());
	    given ($valtype->name()) {
		when ('value') {
		    $$value{$val} = $n;
		    $nextvalue = $val + 1;
		}
		when ('bit') {
		    $$bit{$val} = $n;
		    $$rbit{$n} = $val;
		}
	    }
	} else {
	    $$value{$nextvalue} = $n;
	    $nextvalue++;
	}
    }

    $t->purge;
}

sub request {
    my ($t, $elt) = @_;
    my $name = $elt->att('name');

    print(" - Request $name\n");
    $request{$elt->att('opcode')} = $name;

    my $length = 4;
    my @elements = $elt->children(qr/pad|field|list|switch/);

    # Wireshark defines _U_ to mean "Unused" (compiler specific define)
    if (!@elements) {
	print $impl <<eot

static void $header$name(tvbuff_t *tvb _U_, packet_info *pinfo _U_, int *offsetp _U_, proto_tree *t _U_, int little_endian _U_, int length _U_)
{
eot
;
    } else {
	print $impl <<eot

static void $header$name(tvbuff_t *tvb, packet_info *pinfo _U_, int *offsetp, proto_tree *t, int little_endian, int length _U_)
{
eot
;
    }
    my $varpat = $header.'_'.$name.'_%s';
    my $humanpat = "$header.$name.%s";

    foreach my $e (@elements) {
	register_element($e, $varpat, $humanpat);
    }

    foreach my $e (@elements) {
	if ($e->name() eq 'list' && $name eq 'Render' && $e->att('name') eq 'data' && -e "$mesadir/gl_API.xml") {
	    # Special case: Use mesa-generated dissector for 'data'
	    print $impl "    dispatch_glx_render(tvb, pinfo, offsetp, t, little_endian, (length - $length));\n";
	} else {
	    $length = dissect_element($e, $varpat, $humanpat, $length, 1);
	}
    }

    say $impl '}';

    my $reply = $elt->first_child('reply');
    if ($reply) {
	$reply{$elt->att('opcode')} = $name;

	$varpat = $header.'_'.$name.'_reply_%s';
	$humanpat = "$header.$name.reply.%s";

	@elements = $reply->children(qr/pad|field|list|switch/);

	# Wireshark defines _U_ to mean "Unused" (compiler specific define)
	if (!@elements) {
	    say $impl "static void $header$name"."_Reply(tvbuff_t *tvb _U_, packet_info *pinfo, int *offsetp _U_, proto_tree *t _U_, int little_endian _U_)\n{";
	} else {
	    say $impl "static void $header$name"."_Reply(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, int little_endian)\n{";
	}
	say $impl '    int f_length, length, sequence_number;' if (@elements);

	foreach my $e (@elements) {
	    register_element($e, $varpat, $humanpat);
	}

	say $impl '';
	say $impl '    col_append_fstr(pinfo->cinfo, COL_INFO, "-'.$name.'");';
	say $impl '';
	say $impl '    REPLY(reply);';

	my $first = 1;
	my $length = 1;
	foreach my $e (@elements) {
	    $length = dissect_element($e, $varpat, $humanpat, $length);
	    if ($first) {
		$first = 0;
		say $impl '    sequence_number = VALUE16(tvb, *offsetp);';
		say $impl '    proto_tree_add_uint_format(t, hf_x11_reply_sequencenumber, tvb, *offsetp, 2, sequence_number,';
		say $impl '            "sequencenumber: %d ('.$header.'-'.$name.')", sequence_number);';
		say $impl '    *offsetp += 2;';

		say $impl '    f_length = VALUE32(tvb, *offsetp);';
		say $impl '    length = f_length * 4 + 32;';
		say $impl '    proto_tree_add_item(t, hf_x11_replylength, tvb, *offsetp, 4, little_endian);';
		say $impl '    *offsetp += 4;';

		$length += 6;
	    }
	}

	say $impl '}';
    }
    $t->purge;
}

sub defxid(@) {
    my $name;
    while ($name = shift) {
	$simpletype{$name} = { size => 4, type => 'FT_UINT32',  base => 'BASE_HEX',  get => 'VALUE32', list => 'listOfCard32', };
    }
}

sub xidtype {
    my ($t, $elt) = @_;
    my $name = $elt->att('name');

    defxid($name);

    $t->purge;
}

sub typedef {
    my ($t, $elt) = @_;
    my $oldname = $elt->att('oldname');
    my $newname = $elt->att('newname');

    # Duplicate the type
    my $info = $basictype{$oldname} // $simpletype{$oldname};
    if ($info) {
	$simpletype{$newname} = $info;
    } elsif ($struct{$oldname}) {
	$struct{$newname} = $struct{$oldname};
    } else {
	die ("$oldname not found while attempting to typedef $newname\n");
    }

    $t->purge;
}

sub error {
    my ($t, $elt) = @_;

    my $number = $elt->att('number');
    if ($number >= 0) {
	my $name = $elt->att('name');
	print $error "  \"$header-$name\",\n";
    }

    $t->purge;
}

sub event {
    my ($t, $elt) = @_;

    my $number = $elt->att('number');
    my $name = $elt->att('name');

    $event{$elt->att('number')} = $name;

    my $length = 1;
    my @elements = $elt->children(qr/pad|field|list|switch/);

    # Wireshark defines _U_ to mean "Unused" (compiler specific define)
    if (!@elements) {
	print $impl <<eot

static void $header$name(tvbuff_t *tvb _U_, int *offsetp _U_, proto_tree *t _U_, int little_endian _U_)
{
eot
;
    } else {
	print $impl <<eot

static void $header$name(tvbuff_t *tvb, int *offsetp, proto_tree *t, int little_endian)
{
eot
;
    }

    my $varpat = $header.'_'.$name.'_%s';
    my $humanpat = "$header.$name.%s";

    foreach my $e (@elements) {
	register_element($e, $varpat, $humanpat);
    }

    my $first = 1;
    foreach my $e (@elements) {
	$length = dissect_element($e, $varpat, $humanpat, $length);
	if ($first) {
	    $first = 0;
	    say $impl "    CARD16(event_sequencenumber);";
	}
    }

    print $impl "}\n";

    $t->purge;
}

sub include_start {
    my ($t, $elt) = @_;
    my $header = $elt->att('header');
    unshift @incname, $header;
}

sub include_end {
    shift @incname;
}

sub include
{
    my ($t, $elt) = @_;
    my $include = $elt->text();

    print " - Import $include\n";
    my $xml = XML::Twig->new(
		start_tag_handlers => {
		    'xcb' => \&include_start,
		},
		twig_roots => {
		    'import' => \&include,
		    'struct' => \&struct,
		    'xidtype' => \&xidtype,
		    'xidunion' => \&xidtype,
		    'typedef' => \&typedef,
		    'enum' => \&enum,
		},
		end_tag_handlers => {
		    'xcb' => \&include_end,
		});
    $xml->parsefile("xcbproto/src/$include.xml") or die ("Cannot open $include.xml\n");

    $t->purge;
}


sub xcb_start {
    my ($t, $elt) = @_;
    $header = $elt->att('header');
    $extname = ($elt->att('extension-name') or $header);
    unshift @incname, $header;

    print("Extension $extname\n");

    undef %request;
    undef %event;
    undef %reply;

    %simpletype = ();
    %enum_name = ();

    print $error "const char *$header"."_errors[] = {\n";
}

sub xcb {
    my ($t, $elt) = @_;

    my $xextname = $elt->att('extension-xname');
    my $lookup_name = $header . "_extension_minor";
    my $error_name = $header . "_errors";
    my $event_name = $header . "_events";
    my $reply_name = $header . "_replies";

    print $decl "static int hf_x11_$lookup_name = -1;\n\n";

    print $impl "static const value_string $lookup_name"."[] = {\n";
    foreach my $req (sort {$a <=> $b} keys %request) {
	print $impl "    { $req, \"$request{$req}\" },\n";
    }
    print $impl "    { 0, NULL }\n";
    print $impl "};\n";

    say $impl "const x11_event_info $event_name".'[] = {';
    foreach my $e (sort {$a <=> $b} keys %event) {
	say $impl "    { \"$header-$event{$e}\", $header$event{$e} },";
    }
    say $impl '    { NULL, NULL }';
    say $impl '};';

    print $impl "static x11_reply_info $reply_name"."[] = {\n";
    foreach my $e (sort {$a <=> $b} keys %reply) {
	print $impl "    { $e, $header$reply{$e}_Reply },\n";
    }
    print $impl "    { 0, NULL }\n";
    print $impl "};\n";

    print $reg "{ &hf_x11_$lookup_name, { \"extension-minor\", \"x11.extension-minor\", FT_UINT8, BASE_DEC, VALS($lookup_name), 0, \"minor opcode\", HFILL }},\n\n";

    print $impl <<eot

static void dispatch_$header(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, int little_endian)
{
    int minor, length;
    minor = CARD8($lookup_name);
    length = REQUEST_LENGTH();

    col_append_fstr(pinfo->cinfo, COL_INFO, "-%s",
			  val_to_str(minor, $lookup_name,
				     "<Unknown opcode %d>"));
    switch (minor) {
eot
    ;

    foreach my $req (sort {$a <=> $b} keys %request) {
	print $impl "    case $req:\n";
	print $impl "\t$header$request{$req}(tvb, pinfo, offsetp, t, little_endian, length);\n";
	print $impl "\tbreak;\n";
    }
    say $impl "    /* No need for a default case here, since Unknown is printed above,";
    say $impl "       and UNDECODED() is taken care of by dissect_x11_request */";
    print $impl "    }\n}\n";
    print $impl <<eot

static void register_$header(void)
{
    set_handler("$xextname", dispatch_$header, $error_name, $event_name, $reply_name);
}
eot
    ;

    print $error "  NULL\n};\n\n";

    push @register, $header;
}

sub find_version {
    #my $git = `which git`;
    #chomp($git);
    #-x $git or return 'unknown';

    my $lib = shift;
    # this will generate an error on stderr if git isn't in our $PATH
    # but that's OK.  The version is still set to 'unknown' in that case
    # and at least the operator could see it.
    my $ver = `git --git-dir=$lib/.git describe --tags`;
    $ver //= 'unknown';
    chomp $ver;
    return $ver;
}

sub add_generated_header {
    my ($out, $using) = @_;
    my $ver = find_version($using);

    print $out <<eot
/* Do not modify this file. */
/* It was automatically generated by $0
   using $using version $ver */
eot
    ;
    # Since this file is checked in, add its SVN revision
    print $out "/* \$"."Id"."\$ */\n\n";

    # Add license text
    print $out <<eot
/*
 * Copyright 2008, 2009 Open Text Corporation <pharris[AT]opentext.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

eot
    ;
}

# initialize core X11 protocol
# Do this in the Makefile now
#system('./process-x11-fields.pl < x11-fields');

# Extension implementation
$impl = new IO::File '> x11-extension-implementation.h'
	    or die ("Cannot open x11-extension-implementation.h for writing\n");
$error = new IO::File '> x11-extension-errors.h'
	    or die ("Cannot open x11-extension-errors.h for writing\n");

add_generated_header($impl, 'xcbproto');
add_generated_header($error, 'xcbproto');

# Open the files generated by process-x11-fields.pl for appending
$reg = new IO::File '>> x11-register-info.h'
	    or die ("Cannot open x11-register-info.h for appending\n");
$decl = new IO::File '>> x11-declarations.h'
	    or die ("Cannot open x11-declarations.h for appending\n");

print $reg "\n/* Generated by $0 below this line */\n";
print $decl "\n/* Generated by $0 below this line */\n";

# Mesa for glRender
if (-e "$mesadir/gl_API.xml") {
    $enum = new IO::File '> x11-glx-render-enum.h'
	    or die ("Cannot open x11-glx-render-enum.h for writing\n");
    add_generated_header($enum, 'mesa');
    print $enum "static const value_string mesa_enum[] = {\n";
    print $impl '#include "x11-glx-render-enum.h"'."\n\n";

    print("Mesa glRender:\n");
    $header = "glx_render";

    my $xml = XML::Twig->new(
		start_tag_handlers => {
		    'category' => \&mesa_category_start,
		},
		twig_roots => {
		    'category' => \&mesa_category,
		    'enum' => \&mesa_enum,
		    'type' => \&mesa_type,
		    'function' => \&mesa_function,
		});
    $xml->parsefile("$mesadir/gl_API.xml") or die ("Cannot open gl_API\n");

    print $enum "    { 0, NULL }\n";
    print $enum "};\n";
    $enum->close();

    print $decl "static int hf_x11_glx_render_op_name = -1;\n\n";

    print $impl "static const value_string glx_render_op_name"."[] = {\n";
    foreach my $req (sort {$a <=> $b} keys %request) {
	print $impl "    { $req, \"gl$request{$req}\" },\n";
    }
    print $impl "    { 0, NULL }\n";
    print $impl "};\n";

    print $reg "{ &hf_x11_glx_render_op_name, { \"render op\", \"x11.glx.render.op\", FT_UINT16, BASE_DEC, VALS(glx_render_op_name), 0, NULL, HFILL }},\n\n";

# Uses ett_x11_list_of_rectangle, since I am unable to see how the subtree type matters.
    print $impl <<eot

static void dispatch_glx_render(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, int little_endian, int length)
{
    while (length >= 4) {
	guint32 op, len;
	int next;
	proto_item *ti;
	proto_tree *tt;

	len = VALUE16(tvb, *offsetp);

	op = VALUE16(tvb, *offsetp + 2);
	ti = proto_tree_add_uint(t, hf_x11_glx_render_op_name, tvb, *offsetp, len, op);

	tt = proto_item_add_subtree(ti, ett_x11_list_of_rectangle);

	ti = proto_tree_add_item(tt, hf_x11_request_length, tvb, *offsetp, 2, little_endian);
	*offsetp += 2;
	proto_tree_add_item(tt, hf_x11_glx_render_op_name, tvb, *offsetp, 2, little_endian);
	*offsetp += 2;

	if (len < 4) {
	    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Invalid Length");
	    /* Eat the rest of the packet, mark it undecoded */
	    len = length;
	    op = -1;
	}
	len -= 4;

	next = *offsetp + len;

	switch (op) {
eot
    ;
    foreach my $req (sort {$a <=> $b} keys %request) {
	print $impl "\tcase $req:\n";
	print $impl "\t    mesa_$request{$req}(tvb, offsetp, tt, little_endian, len);\n";
	print $impl "\t    break;\n";
    }
    print $impl "\tdefault:\n";
    print $impl "\t    proto_tree_add_item(tt, hf_x11_undecoded, tvb, *offsetp, len, little_endian);\n";
    print $impl "\t    *offsetp += len;\n";

    print $impl "\t}\n";
    print $impl "\tif (*offsetp < next) {\n";
    print $impl "\t    proto_tree_add_item(tt, hf_x11_unused, tvb, *offsetp, next - *offsetp, little_endian);\n";
    print $impl "\t    *offsetp = next;\n";
    print $impl "\t}\n";
    print $impl "\tlength -= (len + 4);\n";
    print $impl "    }\n}\n";
}

$enum = new IO::File '> x11-enum.h'
	or die ("Cannot open x11-enum.h for writing\n");
add_generated_header($enum, 'xcbproto');
print $impl '#include "x11-enum.h"'."\n\n";

# XCB
foreach my $ext (@reslist) {
    my $xml = XML::Twig->new(
		start_tag_handlers => {
		    'xcb' => \&xcb_start,
		},
		twig_roots => {
		    'xcb' => \&xcb,
		    'import' => \&include,
		    'request' => \&request,
		    'struct' => \&struct,
		    'union' => \&union,
		    'xidtype' => \&xidtype,
		    'xidunion' => \&xidtype,
		    'typedef' => \&typedef,
		    'error' => \&error,
		    'errorcopy' => \&error,
		    'event' => \&event,
		    'enum' => \&enum,
		});
    $xml->parsefile($ext) or die ("Cannot open $ext\n");
}

print $impl "static void register_x11_extensions(void)\n{\n";
foreach my $reg (@register) {
    print $impl "    register_$reg();\n";
}
print $impl "}\n";
