#!/usr/bin/perl
#
# Script to convert xcbproto and mesa protocol files for
# X11 dissector. Creates header files containing code to
# dissect X11 extensions.
#
# Instructions for using this script are in epan/dissectors/README.X11
#
# Copyright 2008, 2009, 2013, 2014 Open Text Corporation <pharris[AT]opentext.com>
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

#TODO
# - support constructs that are legal in XCB, but don't appear to be used

use 5.010;

use warnings;
use strict;

# given/when is going to be removed (and/or dramatically altered)
# in 5.20. Patches welcome.
# Patches even more welcome if they rewrite this whole thing in a
# language with a proper compatibility document, such as
# http://golang.org/doc/go1compat
no if $] >= 5.018, warnings => "experimental::smartmatch";

use IO::File;
use XML::Twig;

use File::Spec;

my $srcdir = shift;
die "'$srcdir' is not a directory" unless -d $srcdir;

my @reslist = grep {!/xproto\.xml$/} glob File::Spec->catfile($srcdir, 'xcbproto', 'src', '*.xml');
my @register;

my $script_name = File::Spec->abs2rel ($0,  $srcdir);

my %basictype = (
    char =>   { size => 1, encoding => 'ENC_ASCII|ENC_NA', type => 'FT_STRING', base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
    void =>   { size => 1, encoding => 'ENC_NA',           type => 'FT_BYTES',  base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
    BYTE =>   { size => 1, encoding => 'ENC_NA',           type => 'FT_BYTES',  base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
    CARD8 =>  { size => 1, encoding => 'byte_order',       type => 'FT_UINT8',  base => 'BASE_HEX_DEC', get => 'VALUE8',  list => 'listOfByte', },
    CARD16 => { size => 2, encoding => 'byte_order',       type => 'FT_UINT16', base => 'BASE_HEX_DEC', get => 'VALUE16', list => 'listOfCard16', },
    CARD32 => { size => 4, encoding => 'byte_order',       type => 'FT_UINT32', base => 'BASE_HEX_DEC', get => 'VALUE32', list => 'listOfCard32', },
    CARD64 => { size => 8, encoding => 'byte_order',       type => 'FT_UINT64', base => 'BASE_HEX_DEC', get => 'VALUE64', list => 'listOfCard64', },
    INT8 =>   { size => 1, encoding => 'byte_order',       type => 'FT_INT8',   base => 'BASE_DEC',     get => 'VALUE8',  list => 'listOfByte', },
    INT16 =>  { size => 2, encoding => 'byte_order',       type => 'FT_INT16',  base => 'BASE_DEC',     get => 'VALUE16', list => 'listOfInt16', },
    INT32 =>  { size => 4, encoding => 'byte_order',       type => 'FT_INT32',  base => 'BASE_DEC',     get => 'VALUE32', list => 'listOfInt32', },
    INT64 =>  { size => 8, encoding => 'byte_order',       type => 'FT_INT64',  base => 'BASE_DEC',     get => 'VALUE64', list => 'listOfInt64', },
    float =>  { size => 4, encoding => 'byte_order',       type => 'FT_FLOAT',  base => 'BASE_NONE',    get => 'FLOAT',   list => 'listOfFloat', },
    double => { size => 8, encoding => 'byte_order',       type => 'FT_DOUBLE', base => 'BASE_NONE',    get => 'DOUBLE',  list => 'listOfDouble', },
    BOOL =>   { size => 1, encoding => 'byte_order',       type => 'FT_BOOLEAN',base => 'BASE_NONE',    get => 'VALUE8',  list => 'listOfByte', },
);

my %simpletype;  # Reset at the beginning of each extension
my %gltype;  # No need to reset, since it's only used once

my %struct =  # Not reset; contains structures already defined.
              # Also contains this black-list of structures never used by any
              # extension (to avoid generating useless code).
(
    # structures defined by xproto, but not used by any extension
    'xproto:CHAR2B' => 1,
    'xproto:ARC' => 1,
    'xproto:FORMAT' => 1,
    'xproto:VISUALTYPE' => 1,
    'xproto:DEPTH' => 1,
    'xproto:SCREEN' => 1,
    'xproto:SetupRequest' => 1,
    'xproto:SetupFailed' => 1,
    'xproto:SetupAuthenticate' => 1,
    'xproto:Setup' => 1,
    'xproto:TIMECOORD' => 1,
    'xproto:FONTPROP' => 1,
    'xproto:CHARINFO' => 1,
    'xproto:SEGMENT' => 1,
    'xproto:COLORITEM' => 1,
    'xproto:RGB' => 1,
    'xproto:HOST' => 1,
    'xproto:POINT' => 1,

    # structures defined by xinput, but never used (except by each other)(bug in xcb?)
    'xinput:KeyInfo' => 1,
    'xinput:ButtonInfo' => 1,
    'xinput:ValuatorInfo' => 1,
    'xinput:KbdFeedbackState' => 1,
    'xinput:PtrFeedbackState' => 1,
    'xinput:IntegerFeedbackState' => 1,
    'xinput:StringFeedbackState' => 1,
    'xinput:BellFeedbackState' => 1,
    'xinput:LedFeedbackState' => 1,
    'xinput:KbdFeedbackCtl' => 1,
    'xinput:PtrFeedbackCtl' => 1,
    'xinput:IntegerFeedbackCtl' => 1,
    'xinput:StringFeedbackCtl' => 1,
    'xinput:BellFeedbackCtl' => 1,
    'xinput:LedFeedbackCtl' => 1,
    'xinput:KeyState' => 1,
    'xinput:ButtonState' => 1,
    'xinput:ValuatorState' => 1,
    'xinput:DeviceResolutionState' => 1,
    'xinput:DeviceAbsCalibState' => 1,
    'xinput:DeviceAbsAreaState' => 1,
    'xinput:DeviceCoreState' => 1,
    'xinput:DeviceEnableState' => 1,
    'xinput:DeviceResolutionCtl' => 1,
    'xinput:DeviceAbsCalibCtl' => 1,
    'xinput:DeviceAbsAreaCtrl' => 1,
    'xinput:DeviceCoreCtrl' => 1,
    'xinput:DeviceEnableCtrl' => 1,
    'xinput:DeviceName' => 1,
    'xinput:AddMaster' => 1,
    'xinput:RemoveMaster' => 1,
    'xinput:AttachSlave' => 1,
    'xinput:DetachSlave' => 1,
    'xinput:ButtonClass' => 1,
    'xinput:KeyClass' => 1,
    'xinput:ScrollClass' => 1,
    'xinput:TouchClass' => 1,
    'xinput:ValuatorClass' => 1,

    # structures defined by xv, but never used (bug in xcb?)
    'xv:Image' => 1,

    # structures defined by xkb, but never used (except by each other)(bug in xcb?)
    'xkb:Key' => 1,
    'xkb:Outline' => 1,
    'xkb:Overlay' => 1,
    'xkb:OverlayKey' => 1,
    'xkb:OverlayRow' => 1,
    'xkb:Row' => 1,
    'xkb:Shape' => 1,
);
my %enum;  # Not reset; contains enums already defined.
my %enum_name;
my %type_name;
my $header;
my $extname;
my @incname;
my %request;
my %genericevent;
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
my @mesas = ($srcdir . '/mesa/src/mapi/glapi/gen',  # 2010-04-26
             $srcdir . '/mesa/src/mesa/glapi/gen',  # 2010-02-22
             $srcdir . '/mesa/src/mesa/glapi');     # 2004-05-18
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
        $gltype{'GLenum'} = { size => 4, encoding => 'byte_order', type => 'FT_UINT32', base => 'BASE_HEX',
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
static void mesa_$name(tvbuff_t *tvb _U_, int *offsetp _U_, proto_tree *t _U_, guint byte_order _U_, int length _U_)
{
eot
;
    } else {
        print $impl <<eot
static void mesa_$name(tvbuff_t *tvb, int *offsetp, proto_tree *t, guint byte_order, int length _U_)
{
eot
;
    }

    my %type_param;
    foreach my $e (@elements) {
        # Detect count && variable_param
        my $count = $e->att('count');
        my $variable_param = $e->att('variable_param');
        if (defined $count and defined $variable_param) {
            $type_param{$variable_param} = 1;
        }
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
        my $count = $e->att('count');
        my $variable_param = $e->att('variable_param');

        if ($list and $count and $variable_param) {
            print $decl "static int ${regname} = -1;\n";
            print $reg "{ &$regname, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_signed = -1;\n";
            print $reg "{ &${regname}_signed, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_unsigned = -1;\n";
            print $reg "{ &${regname}_unsigned, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_item_card16 = -1;\n";
            print $reg "{ &${regname}_item_card16, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_item_int16 = -1;\n";
            print $reg "{ &${regname}_item_int16, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_item_card32 = -1;\n";
            print $reg "{ &${regname}_item_card32, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_item_int32 = -1;\n";
            print $reg "{ &${regname}_item_int32, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},\n";
            print $decl "static int ${regname}_item_float = -1;\n";
            print $reg "{ &${regname}_item_float, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }},\n";
        } else {
            print $decl "static int $regname = -1;\n";
            if ($list and $info->{'size'} > 1) {
                print $reg "{ &$regname, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";
                $regname .= '_item';
                print $decl "static int $regname = -1;\n";
            }
            print $reg "{ &$regname, { \"$fieldname\", \"x11.glx.render.$name.$fieldname\", $ft, $base, $val, 0, NULL, HFILL }},\n";

            if ($e->att('counter') or $type_param{$fieldname}) {
                print $impl "    int $fieldname;\n";
            }
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
            print $impl "    proto_tree_add_item(t, $regname, tvb, *offsetp, 1, byte_order);\n";
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
            print $impl "    proto_tree_add_item(t, $regname, tvb, *offsetp, 4, byte_order);\n";
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
            my $encoding = $info->{'encoding'};
            my $get = $info->{'get'};

            if ($e->att('counter') or $type_param{$fieldname}) {
                print $impl "    $fieldname = $get(tvb, *offsetp);\n";
            }
            print $impl "    proto_tree_add_item(t, $regname, tvb, *offsetp, $size, $encoding);\n";
            print $impl "    *offsetp += $size;\n";
            $length += $size;
        } else {        # list
            my $list = $info->{'list'};
            my $count = $e->att('count');
            my $variable_param = $e->att('variable_param');

            if (defined($count) && !defined($variable_param)) {
                $regname .= ", $regname".'_item' if ($info->{'size'} > 1);
                print $impl "    $list(tvb, offsetp, t, $regname, $count, byte_order);\n";
            } else {
                if (defined($count)) {
                    # Currently, only CallLists has both a count and a variable_param
                    # The XML contains a size description of all the possibilities
                    # for CallLists, but not a type description. Implement by hand,
                    # with the caveat that more types may need to be added in the
                    # future.
                    say $impl "    switch($variable_param) {";
                    say $impl "    case 0x1400: /* BYTE */";
                    say $impl "        listOfByte(tvb, offsetp, t, ${regname}_signed, $count, byte_order);";
                    say $impl "        UNUSED(length - $length - $count);";
                    say $impl "        break;";
                    say $impl "    case 0x1401: /* UNSIGNED_BYTE */";
                    say $impl "        listOfByte(tvb, offsetp, t, ${regname}_unsigned, $count, byte_order);";
                    say $impl "        UNUSED(length - $length - $count);";
                    say $impl "        break;";
                    say $impl "    case 0x1402: /* SHORT */";
                    say $impl "        listOfInt16(tvb, offsetp, t, $regname, ${regname}_item_int16, $count, byte_order);";
                    say $impl "        UNUSED(length - $length - 2 * $count);";
                    say $impl "        break;";
                    say $impl "    case 0x1403: /* UNSIGNED_SHORT */";
                    say $impl "        listOfCard16(tvb, offsetp, t, $regname, ${regname}_item_card16, $count, byte_order);";
                    say $impl "        UNUSED(length - $length - 2 * $count);";
                    say $impl "        break;";
                    say $impl "    case 0x1404: /* INT */";
                    say $impl "        listOfInt32(tvb, offsetp, t, $regname, ${regname}_item_int32, $count, byte_order);";
                    say $impl "        break;";
                    say $impl "    case 0x1405: /* UNSIGNED_INT */";
                    say $impl "        listOfCard32(tvb, offsetp, t, $regname, ${regname}_item_card32, $count, byte_order);";
                    say $impl "        break;";
                    say $impl "    case 0x1406: /* FLOAT */";
                    say $impl "        listOfFloat(tvb, offsetp, t, $regname, ${regname}_item_float, $count, byte_order);";
                    say $impl "        break;";
                    say $impl "    case 0x1407: /* 2_BYTES */";
                    say $impl "        listOfCard16(tvb, offsetp, t, $regname, ${regname}_item_card16, $count, ENC_BIG_ENDIAN);";
                    say $impl "        UNUSED(length - $length - 2 * $count);";
                    say $impl "        break;";
                    say $impl "    case 0x1408: /* 3_BYTES */";
                    say $impl "        UNDECODED(3 * $count);";
                    say $impl "        UNUSED(length - $length - 3 * $count);";
                    say $impl "        break;";
                    say $impl "    case 0x1409: /* 4_BYTES */";
                    say $impl "        listOfCard32(tvb, offsetp, t, $regname, ${regname}_item_card32, $count, ENC_BIG_ENDIAN);";
                    say $impl "        break;";
                    say $impl "    case 0x140B: /* HALF_FLOAT */";
                    say $impl "        UNDECODED(2 * $count);";
                    say $impl "        UNUSED(length - $length - 2 * $count);";
                    say $impl "        break;";
                    say $impl "    default:     /* Unknown */";
                    say $impl "        UNDECODED(length - $length);";
                    say $impl "        break;";
                    say $impl "    }";
                } else {
                    $regname .= ", $regname".'_item' if ($info->{'size'} > 1);
                    print $impl "    $list(tvb, offsetp, t, $regname, (length - $length) / $gltype{$type}{'size'}, byte_order);\n";
                }
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

sub qualname {
    my $name = shift;
    $name = $incname[0].':'.$name unless $name =~ /:/;
    return $name
}

sub get_simple_info {
    my $name = shift;
    my $info = $basictype{$name};
    return $info if (defined $info);
    $info = $simpletype{$name};
    return $info if (defined $info);
    if (defined($type_name{$name})) {
        return $simpletype{$type_name{$name}};
    }
    return undef
}

sub get_struct_info {
    my $name = shift;
    my $info = $struct{$name};
    return $info if (defined $info);
    if (defined($type_name{$name})) {
        return $struct{$type_name{$name}};
    }
    return undef
}

sub getinfo {
    my $name = shift;
    my $info = get_simple_info($name) // get_struct_info($name);
    # If the script fails here search for $name in this script and remove it from the black list
    die "$name is defined to be unused in process-x11-xcb.pl but is actually used!" if (defined($info) && $info == "1");
    return $info;
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
        say $enum sprintf("    { %3d, \"%s\" },", $val, $$value{$val});
    }
    say $enum sprintf("    { %3d, NULL },", 0);
    say $enum '};';
    say $enum '';

    $enum{$e}{done} = 1;
    return $enumname;
}

# Find all references, so we can declare only the minimum necessary
sub reference_elements($$);

sub reference_elements($$)
{
    my $e = shift;
    my $refref = shift;

    given ($e->name()) {
        when ('switch') {
            my $lentype = $e->first_child();
            if (defined $lentype) {
                given ($lentype->name()) {
                    when ('fieldref') { $refref->{field}{$lentype->text()} = 1; }
                    when ('op') { get_op($lentype, $refref->{field}); }
                }
            }

            my @elements = $e->children(qr/(bit)?case/);
            for my $case (@elements) {
                my @sub_elements = $case->children(qr/list|switch/);

                foreach my $sub_e (@sub_elements) {
                    reference_elements($sub_e, $refref);
                }
            }
        }
        when ('list') {
            my $type = $e->att('type');
            my $info = getinfo($type);
            if (defined $info->{paramref}) {
                for my $pref (keys %{$info->{paramref}}) {
                    $refref->{field}{$pref} = 1;
                }
            }

            my $lentype = $e->first_child();
            if (defined $lentype) {
                given ($lentype->name()) {
                    when ('fieldref') { $refref->{field}{$lentype->text()} = 1; }
                    when ('op') { get_op($lentype, $refref->{field}); }
                    when (['unop','popcount']) { get_unop($lentype, $refref->{field}); }
                    when ('sumof') { $refref->{sumof}{$lentype->att('ref')} = 1; }
                }
            } else {
                $refref->{field}{'length'} = 1;
                $refref->{'length'} = 1;
            }
        }
    }
}

sub register_element($$$$;$)
{
    my $e = shift;
    my $varpat = shift;
    my $humanpat = shift;
    my $refref = shift;
    my $indent = shift // ' ' x 4;

    given ($e->name()) {
        when ('pad') { return; }     # Pad has no variables
        when ('switch') { return; }  # Switch defines varaibles in a tighter scope to avoid collisions
    }

    # Register field with wireshark

    my $fieldname = $e->att('name');
    my $type = $e->att('type') or die ("Field $fieldname does not have a valid type\n");

    my $regname = 'hf_x11_'.sprintf ($varpat, $fieldname);
    my $humanname = 'x11.'.sprintf ($humanpat, $fieldname);

    my $info = getinfo($type);
    my $ft = $info->{'type'} // 'FT_NONE';
    my $base = $info->{'base'} // 'BASE_NONE';
    my $vals = 'NULL';

    my $enum = $e->att('enum') // $e->att('altenum');
    if (defined $enum) {
        my $enumname = dump_enum_values($enum_name{$enum});
        $vals = "VALS($enumname)";

        # Wireshark does not allow FT_BYTES, FT_BOOLEAN, or BASE_NONE to have an enum
        $ft =~ s/FT_BYTES/FT_UINT8/;
        $ft =~ s/FT_BOOLEAN/FT_UINT8/;
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
            my $bitshift = "1U << $val";

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

    if ($refref->{sumof}{$fieldname}) {
        print $impl $indent."int sumof_$fieldname = 0;\n";
    }

    if ($e->name() eq 'field') {
        if ($refref->{field}{$fieldname} and get_simple_info($type)) {
            # Pre-declare variable
            if ($ft eq 'FT_FLOAT') {
                print $impl $indent."gfloat f_$fieldname;\n";
            } elsif ($ft eq 'FT_DOUBLE') {
                print $impl $indent."gdouble f_$fieldname;\n";
            } elsif ($ft eq 'FT_INT64' or $ft eq 'FT_UINT64') {
                print $impl $indent."gint64 f_$fieldname;\n";
            } else {
                print $impl $indent."int f_$fieldname;\n";
            }
        }
    }
}

sub dissect_element($$$$$;$$);

sub dissect_element($$$$$;$$)
{
    my $e = shift;
    my $varpat = shift;
    my $humanpat = shift;
    my $length = shift;
    my $refref = shift;
    my $adjustlength = shift;
    my $indent = shift // ' ' x 4;

    given ($e->name()) {
        when ('pad') {
            my $bytes = $e->att('bytes');
            my $align = $e->att('align');
            if (defined $bytes) {
                print $impl $indent."UNUSED($bytes);\n";
                $length += $bytes;
            } else {
                say $impl $indent.'if (*offsetp % '.$align.') {';
                say $impl $indent."    UNUSED($align - *offsetp % $align);";
                say $impl $indent."}";
                if ($length % $align != 0) {
                    $length += $align - $length % $align;
                }
                if ($adjustlength) {
                    say $impl $indent.'length = ((length + '.($align-1).') & ~'.($align-1).');';
                }
            }
        }
        when ('field') {
            my $fieldname = $e->att('name');
            my $regname = 'hf_x11_'.sprintf ($varpat, $fieldname);
            my $type = $e->att('type');

            if (get_simple_info($type)) {
                my $info = get_simple_info($type);
                my $size = $info->{'size'};
                my $encoding = $info->{'encoding'};
                my $get = $info->{'get'};

                if ($e->att('enum') // $e->att('altenum')) {
                    my $fieldsize = $size * 8;
                    print $impl $indent;
                    if ($refref->{field}{$fieldname}) {
                        print $impl "f_$fieldname = ";
                    }
                    say $impl "field$fieldsize(tvb, offsetp, t, $regname, byte_order);";
                } elsif ($e->att('mask')) {
                    if ($refref->{field}{$fieldname}) {
                        say $impl $indent."f_$fieldname = $get(tvb, *offsetp);";
                    }
                    say $impl $indent."{";
                    say $impl $indent."    proto_item *ti = proto_tree_add_item(t, $regname, tvb, *offsetp, $size, $encoding);";
                    say $impl $indent."    proto_tree *bitmask_tree = proto_item_add_subtree(ti, ett_x11_rectangle);";

                    my $bytesize = $info->{'size'};
                    my $byteencoding = $info->{'encoding'};
                    my $bit = $enum{$enum_name{$e->att('mask')}}{bit};
                    for my $val (sort { $a <=> $b } keys %$bit) {
                        my $item = $regname . '_mask_' . $$bit{$val};

                        say $impl "$indent    proto_tree_add_item(bitmask_tree, $item, tvb, *offsetp, $bytesize, $byteencoding);";
                    }

                    say $impl $indent."}";
                    say $impl $indent."*offsetp += $size;";
                } else {
                    if ($refref->{field}{$fieldname}) {
                        say $impl $indent."f_$fieldname = $get(tvb, *offsetp);";
                    }
                    print $impl $indent."proto_tree_add_item(t, $regname, tvb, *offsetp, $size, $encoding);\n";
                    print $impl $indent."*offsetp += $size;\n";
                }
                $length += $size;
            } elsif (get_struct_info($type)) {
                # TODO: variable-lengths (when $info->{'size'} == 0 )
                my $info = get_struct_info($type);
                $length += $info->{'size'};
                print $impl $indent."struct_$info->{'name'}(tvb, offsetp, t, byte_order, 1);\n";
            } else {
                die ("Unrecognized type: $type\n");
            }
        }
        when ('list') {
            my $fieldname = $e->att('name');
            my $regname = 'hf_x11_'.sprintf ($varpat, $fieldname);
            my $type = $e->att('type');

            my $info = getinfo($type);
            my $lencalc = "(length - $length) / $info->{'size'}";
            my $lentype = $e->first_child();
            if (defined $lentype) {
                given ($lentype->name()) {
                    when ('value') { $lencalc = $lentype->text(); }
                    when ('fieldref') { $lencalc = 'f_'.$lentype->text(); }
                    when ('paramref') { $lencalc = 'p_'.$lentype->text(); }
                    when ('op') { $lencalc = get_op($lentype); }
                    when (['unop','popcount']) { $lencalc = get_unop($lentype); }
                    when ('sumof') { $lencalc = 'sumof_'.$lentype->att('ref'); }
                }
            }

            if (get_simple_info($type)) {
                my $list = $info->{'list'};
                my $size = $info->{'size'};
                $regname .= ", $regname".'_item' if ($size > 1);

                if ($refref->{sumof}{$fieldname}) {
                    my $get = $info->{'get'};
                    say $impl $indent."{";
                    say $impl $indent."    int i;";
                    say $impl $indent."    for (i = 0; i < $lencalc; i++) {";
                    say $impl $indent."        sumof_$fieldname += $get(tvb, *offsetp + i * $size);";
                    say $impl $indent."    }";
                    say $impl $indent."}";
                }

                print $impl $indent."$list(tvb, offsetp, t, $regname, $lencalc, byte_order);\n";
            } elsif (get_struct_info($type)) {
                my $si = get_struct_info($type);
                my $prefs = "";
                foreach my $pref (sort keys %{$si->{paramref}}) {
                    $prefs .= ", f_$pref";
                }

                print $impl $indent."struct_$info->{'name'}(tvb, offsetp, t, byte_order, $lencalc$prefs);\n";
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
            my @elements = $e->children(qr/(bit)?case/);
            for my $case (@elements) {
                my @refs = $case->children('enumref');
                my @test;
                my $fieldname;
                foreach my $ref (@refs) {
                    my $enum_ref = $ref->att('ref');
                    my $field = $ref->text();
                    $fieldname //= $field; # Use first named field
                    if ($case->name() eq 'bitcase') {
                        my $bit = $enum{$enum_name{$enum_ref}}{rbit}{$field};
                        if (! defined($bit)) {
                            for my $foo (keys %{$enum{$enum_name{$enum_ref}}{rbit}}) { say "'$foo'"; }
                            die ("Field '$field' not found in '$enum_ref'");
                        }
                        push @test , "$switchon & (1U << $bit)";
                    } else {
                        my $val = $enum{$enum_name{$enum_ref}}{rvalue}{$field};
                        if (! defined($val)) {
                            for my $foo (keys %{$enum{$enum_name{$enum_ref}}{rvalue}}) { say "'$foo'"; }
                            die ("Field '$field' not found in '$enum_ref'");
                        }
                        push @test , "$switchon == $val";
                    }
                }

                if (@test > 1) {
                    # We have more than one conditional, add parentheses to them.
                    # We don't add parentheses to all the conditionals because
                    # clang complains about the extra parens if you do "if ((x == y))".
                    my @tests_with_parens;
                    foreach my $conditional (@test) {
                        push @tests_with_parens, "($conditional)";
                    }

                    @test = @tests_with_parens;
                }

                my $list = join ' || ', @test;
                say $impl $indent."if ($list) {";

                my $vp = $varpat;
                my $hp = $humanpat;

                $vp =~ s/%s/${fieldname}_%s/;
                $hp =~ s/%s/${fieldname}.%s/;

                my @sub_elements = $case->children(qr/pad|field|list|switch/);

                my $subref = { field => {}, sumof => {} };
                foreach my $sub_e (@sub_elements) {
                    reference_elements($sub_e, $subref);
                }
                foreach my $sub_e (@sub_elements) {
                    register_element($sub_e, $vp, $hp, $subref, $indent . '    ');
                }
                foreach my $sub_e (@sub_elements) {
                    $length = dissect_element($sub_e, $vp, $hp, $length, $subref, $adjustlength, $indent . '    ');
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
    my $qualname = qualname($name);
    $type_name{$name} = $qualname;

    if (defined $struct{$qualname}) {
        $t->purge;
        return;
    }

    my @elements = $elt->children(qr/pad|field|list|switch/);

    print(" - Struct $name\n");

    $name = $qualname;
    $name =~ s/:/_/;

    my %refs;
    my %paramrefs;
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
                my $align = $e->att('align');
                if (defined $bytes) {
                    $size += $bytes;
                    next;
                }
                if (!$dynamic) {
                    if ($size % $align) {
                        $size += $align - $size % $align;
                    }
                }
                next;
            }
            when ('list') {
                my $type = $e->att('type');
                my $info = getinfo($type);

                $needi = 1 if ($info->{'size'} == 0);

                my $value = $e->first_child();
                given($value->name()) {
                    when ('fieldref') {
                        $refs{$value->text()} = 1;
                        $count = 0;
                        $dynamic = 1;
                    }
                    when ('paramref') {
                        $paramrefs{$value->text()} = $value->att('type');
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
            when ('switch') {
                $dynamic = 1;
                next;
            }
            default { die("unrecognized field: $_\n"); }
        }

        my $type = $e->att('type');
        my $info = getinfo($type);

        $size += $info->{'size'} * $count;
    }

    my $prefs = "";

    if ($dynamic) {
        $size = 0;

        foreach my $pref (sort keys %paramrefs) {
            $prefs .= ", int p_$pref";
        }

        print $impl <<eot

static int struct_size_$name(tvbuff_t *tvb _U_, int *offsetp _U_, guint byte_order _U_$prefs)
{
    int size = 0;
eot
;
        say $impl '    int i, off;' if ($needi);

        foreach my $ref (sort keys %refs) {
            say $impl "    int f_$ref;";
        }

        foreach my $e (@elements) {
            my $count;
            $count = 1;

            my $type = $e->att('type') // '';
            my $info = getinfo($type);

            given ($e->name()) {
                when ('pad') {
                    my $bytes = $e->att('bytes');
                    my $align = $e->att('align');
                    if (defined $bytes) {
                        $size += $bytes;
                    } else {
                        say $impl '    size = (size + '.($align-1).') & ~'.($align-1).';';
                    }
                }
                when ('list') {
                    my $len = $e->first_child();
                    my $infosize = $info->{'size'};
                    my $sizemul;

                    given ($len->name()) {
                        when ('op') { $sizemul = get_op($len, \%refs); }
                        when (['unop','popcount']) { $sizemul = get_unop($len, \%refs); }
                        when ('fieldref') { $sizemul = 'f_'.$len->text(); }
                        when ('paramref') { $sizemul = 'p_'.$len->text(); }
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
                            say $impl "        size += struct_size_$info->{name}(tvb, &off, byte_order);";
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

static void struct_$name(tvbuff_t *tvb, int *offsetp, proto_tree *root, guint byte_order _U_, int count$prefs)
{
    int i;
    for (i = 0; i < count; i++) {
        proto_item *item;
        proto_tree *t;
eot
;

    my $varpat = 'struct_'.$name.'_%s';
    my $humanpat = "struct.$name.%s";
    my $refs = { field => {}, sumof => {} };

    foreach my $e (@elements) {
        reference_elements($e, $refs);
    }
    foreach my $e (@elements) {
        register_element($e, $varpat, $humanpat, $refs, "        ");
    }

    $prefs = "";
    foreach my $pref (sort keys %paramrefs) {
        $prefs .= ", p_$pref";
    }

    my $sizecalc = $size;
    $size or $sizecalc = "struct_size_$name(tvb, offsetp, byte_order$prefs)";

    print $impl <<eot

        item = proto_tree_add_item(root, hf_x11_struct_$name, tvb, *offsetp, $sizecalc, ENC_NA);
        t = proto_item_add_subtree(item, ett_x11_rectangle);
eot
;
    my $length = 0;
    foreach my $e (@elements) {
        $length = dissect_element($e, $varpat, $humanpat, $length, $refs, 0, "        ");
    }

    print $impl "    }\n}\n";
    $struct{$qualname} = { size => $size, name => $name, paramref => \%paramrefs };
    $t->purge;
}

sub union {
    # TODO proper dissection
    #
    # Right now, the only extension to use a union is randr.
    # for now, punt.
    my ($t, $elt) = @_;
    my $name = $elt->att('name');
    my $qualname = qualname($name);
    $type_name{$name} = $qualname;

    if (defined $struct{$qualname}) {
        $t->purge;
        return;
    }

    my @elements = $elt->children(qr/field/);
    my @sizes;

    print(" - Union $name\n");

    $name = $qualname;
    $name =~ s/:/_/;

    # Find union size
    foreach my $e (@elements) {
        my $type = $e->att('type');
        my $info = getinfo($type);

        $info->{'size'} > 0 or die ("Error: Union containing variable sized struct $type\n");
        push @sizes, $info->{'size'};
    }
    @sizes = sort {$b <=> $a} @sizes;
    my $size = $sizes[0];

    print $decl "static int hf_x11_union_$name = -1;\n";
    print $reg "{ &hf_x11_union_$name, { \"$name\", \"x11.union.$name\", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},\n";

    print $impl <<eot

static void struct_$name(tvbuff_t *tvb, int *offsetp, proto_tree *root, guint byte_order, int count)
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
    my $refs = { field => {}, sumof => {} };

    foreach my $e (@elements) {
        reference_elements($e, $refs);
    }
    foreach my $e (@elements) {
        register_element($e, $varpat, $humanpat, $refs, "        ");
    }

    print $impl <<eot
        item = proto_tree_add_item(root, hf_x11_union_$name, tvb, base, $size, ENC_NA);
        t = proto_item_add_subtree(item, ett_x11_rectangle);

eot
;

    foreach my $e (@elements) {
        say $impl '        *offsetp = base;';
        dissect_element($e, $varpat, $humanpat, 0, $refs, 0, "        ");
    }
    say $impl "        base += $size;";
    say $impl '    }';
    say $impl '    *offsetp = base;';
    say $impl '}';

    $struct{$qualname} = { size => $size, name => $name };
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
    my $rvalue = {};
    my $rbit = {};
    $enum{$fullname} = { value => $value, bit => $bit, rbit => $rbit, rvalue => $rvalue };

    my $nextvalue = 0;

    foreach my $e (@elements) {
        my $n = $e->att('name');
        my $valtype = $e->first_child(qr/value|bit/);
        if (defined $valtype) {
            my $val = int($valtype->text());
            given ($valtype->name()) {
                when ('value') {
                    $$value{$val} = $n;
                    $$rvalue{$n} = $val;
                    $nextvalue = $val + 1;

                    # Ugly hack to support (temporary, hopefully) ugly
                    # hack in xinput:ChangeDeviceProperty
                    # Register certain values as bits also
                    given ($val) {
                        when (8) {
                            $$bit{'3'} = $n;
                            $$rbit{$n} = 3;
                        }
                        when (16) {
                            $$bit{'4'} = $n;
                            $$rbit{$n} = 4;
                        }
                        when (32) {
                            $$bit{'5'} = $n;
                            $$rbit{$n} = 5;
                        }
                    }
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

static void $header$name(tvbuff_t *tvb _U_, packet_info *pinfo _U_, int *offsetp _U_, proto_tree *t _U_, guint byte_order _U_, int length _U_)
{
eot
;
    } else {
        print $impl <<eot

static void $header$name(tvbuff_t *tvb, packet_info *pinfo _U_, int *offsetp, proto_tree *t, guint byte_order, int length _U_)
{
eot
;
    }
    my $varpat = $header.'_'.$name.'_%s';
    my $humanpat = "$header.$name.%s";
    my $refs = { field => {}, sumof => {} };

    foreach my $e (@elements) {
        reference_elements($e, $refs);
    }
    foreach my $e (@elements) {
        register_element($e, $varpat, $humanpat, $refs);
    }

    foreach my $e (@elements) {
        if ($e->name() eq 'list' && $name eq 'Render' && $e->att('name') eq 'data' && -e "$mesadir/gl_API.xml") {
            # Special case: Use mesa-generated dissector for 'data'
            print $impl "    dispatch_glx_render(tvb, pinfo, offsetp, t, byte_order, (length - $length));\n";
        } else {
            $length = dissect_element($e, $varpat, $humanpat, $length, $refs, 1);
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
            say $impl "static void $header$name"."_Reply(tvbuff_t *tvb _U_, packet_info *pinfo, int *offsetp _U_, proto_tree *t _U_, guint byte_order _U_)\n{";
        } else {
            say $impl "static void $header$name"."_Reply(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order)\n{";
        }
        say $impl '    int sequence_number;' if (@elements);

        my $refs = { field => {}, sumof => {} };
        foreach my $e (@elements) {
            reference_elements($e, $refs);
        }

        say $impl '    int f_length;'        if ($refs->{field}{'length'});
        say $impl '    int length;'          if ($refs->{length});
        foreach my $e (@elements) {
            register_element($e, $varpat, $humanpat, $refs);
        }

        say $impl '';
        say $impl '    col_append_fstr(pinfo->cinfo, COL_INFO, "-'.$name.'");';
        say $impl '';
        say $impl '    REPLY(reply);';

        my $first = 1;
        my $length = 1;
        foreach my $e (@elements) {
            $length = dissect_element($e, $varpat, $humanpat, $length, $refs);
            if ($first) {
                $first = 0;
                say $impl '    sequence_number = VALUE16(tvb, *offsetp);';
                say $impl '    proto_tree_add_uint_format(t, hf_x11_reply_sequencenumber, tvb, *offsetp, 2, sequence_number,';
                say $impl '            "sequencenumber: %d ('.$header.'-'.$name.')", sequence_number);';
                say $impl '    *offsetp += 2;';

                if ($refs->{field}{length}) {
                    say $impl '    f_length = VALUE32(tvb, *offsetp);';
                }
                if ($refs->{length}) {
                    say $impl '    length = f_length * 4 + 32;';
                }
                say $impl '    proto_tree_add_item(t, hf_x11_replylength, tvb, *offsetp, 4, byte_order);';
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
        my $qualname = qualname($name);
        $simpletype{$qualname} = { size => 4, encoding => 'byte_order', type => 'FT_UINT32',  base => 'BASE_HEX',  get => 'VALUE32', list => 'listOfCard32', };
        $type_name{$name} = $qualname;
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
    my $qualname = qualname($newname);

    # Duplicate the type
    my $info = get_simple_info($oldname);
    if ($info) {
        $simpletype{$qualname} = $info;
    } elsif ($info = get_struct_info($oldname)) {
        $struct{$qualname} = $info;
    } else {
        die ("$oldname not found while attempting to typedef $newname\n");
    }
    $type_name{$newname} = $qualname;

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
    $number or return;

    my $name = $elt->att('name');
    my $xge = $elt->att('xge');

    if ($xge) {
        $genericevent{$number} = $name;
    } else {
        $event{$number} = $name;
    }

    my $length = 1;
    my @elements = $elt->children(qr/pad|field|list|switch/);

    # Wireshark defines _U_ to mean "Unused" (compiler specific define)
    if (!@elements) {
        if ($xge) {
            print $impl <<eot

static void $header$name(tvbuff_t *tvb _U_, int length _U_, int *offsetp _U_, proto_tree *t _U_, guint byte_order _U_)
{
        } else {
            print $impl <<eot

static void $header$name(tvbuff_t *tvb _U_, int *offsetp _U_, proto_tree *t _U_, guint byte_order _U_)
{
eot
;
        }
    } else {
        if ($xge) {
            $length = 10;
            print $impl <<eot

static void $header$name(tvbuff_t *tvb, int length _U_, int *offsetp, proto_tree *t, guint byte_order)
{
eot
;
        } else {
            print $impl <<eot

static void $header$name(tvbuff_t *tvb, int *offsetp, proto_tree *t, guint byte_order)
{
eot
;
        }
    }

    my $varpat = $header.'_'.$name.'_%s';
    my $humanpat = "$header.$name.%s";
    my $refs = { field => {}, sumof => {} };

    foreach my $e (@elements) {
        reference_elements($e, $refs);
    }
    foreach my $e (@elements) {
        register_element($e, $varpat, $humanpat, $refs);
    }

    if ($xge) {
        say $impl "    proto_tree_add_uint_format(t, hf_x11_minor_opcode, tvb, *offsetp, 2, $number,";
        say $impl "                               \"opcode: $name ($number)\");";
        foreach my $e (@elements) {
            $length = dissect_element($e, $varpat, $humanpat, $length, $refs);
        }
    } else {
        my $first = 1;
        foreach my $e (@elements) {
            $length = dissect_element($e, $varpat, $humanpat, $length, $refs);
            if ($first) {
                $first = 0;
                say $impl "    CARD16(event_sequencenumber);";
            }
        }
    }

    say $impl "}\n";

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
    $xml->parsefile("$srcdir/xcbproto/src/$include.xml") or die ("Cannot open $include.xml\n");

    $t->purge;
}


sub xcb_start {
    my ($t, $elt) = @_;
    $header = $elt->att('header');
    $extname = ($elt->att('extension-name') or $header);
    unshift @incname, $header;

    print("Extension $extname\n");

    undef %request;
    undef %genericevent;
    undef %event;
    undef %reply;

    %simpletype = ();
    %enum_name = ();
    %type_name = ();

    print $error "const char *$header"."_errors[] = {\n";
}

sub xcb {
    my ($t, $elt) = @_;

    my $xextname = $elt->att('extension-xname');
    my $lookup_name = $header . "_extension_minor";
    my $error_name = $header . "_errors";
    my $event_name = $header . "_events";
    my $genevent_name = 'NULL';
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

    if (%genericevent) {
        $genevent_name = $header.'_generic_events';
        say $impl 'static const x11_generic_event_info '.$genevent_name.'[] = {';

        for my $val (sort { $a <=> $b } keys %genericevent) {
            say $impl sprintf("        { %3d, %s },", $val, $header.$genericevent{$val});
        }
        say $impl sprintf("        { %3d, NULL },", 0);
        say $impl '};';
        say $impl '';
    }

    print $impl "static x11_reply_info $reply_name"."[] = {\n";
    foreach my $e (sort {$a <=> $b} keys %reply) {
        print $impl "    { $e, $header$reply{$e}_Reply },\n";
    }
    print $impl "    { 0, NULL }\n";
    print $impl "};\n";

    print $reg "{ &hf_x11_$lookup_name, { \"extension-minor\", \"x11.extension-minor\", FT_UINT8, BASE_DEC, VALS($lookup_name), 0, \"minor opcode\", HFILL }},\n\n";

    print $impl <<eot

static void dispatch_$header(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order)
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
        print $impl "        $header$request{$req}(tvb, pinfo, offsetp, t, byte_order, length);\n";
        print $impl "        break;\n";
    }
    say $impl "    /* No need for a default case here, since Unknown is printed above,";
    say $impl "       and UNDECODED() is taken care of by dissect_x11_request */";
    print $impl "    }\n}\n";
    print $impl <<eot

static void register_$header(void)
{
    set_handler("$xextname", dispatch_$header, $error_name, $event_name, $genevent_name, $reply_name);
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

    $using = File::Spec->abs2rel ($using,  $srcdir);

    print $out <<eot
/* Do not modify this file. */
/* It was automatically generated by $script_name
   using $using version $ver */
eot
    ;

    # Add license text
    print $out <<eot
/*
 * Copyright 2008, 2009, 2013, 2014 Open Text Corporation <pharris[AT]opentext.com>
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
$impl = new IO::File "> $srcdir/x11-extension-implementation.h"
            or die ("Cannot open $srcdir/x11-extension-implementation.h for writing\n");
$error = new IO::File "> $srcdir/x11-extension-errors.h"
            or die ("Cannot open $srcdir/x11-extension-errors.h for writing\n");

add_generated_header($impl, $srcdir . '/xcbproto');
add_generated_header($error, $srcdir . '/xcbproto');

# Open the files generated by process-x11-fields.pl for appending
$reg = new IO::File ">> $srcdir/x11-register-info.h"
            or die ("Cannot open $srcdir/x11-register-info.h for appending\n");
$decl = new IO::File ">> $srcdir/x11-declarations.h"
            or die ("Cannot open $srcdir/x11-declarations.h for appending\n");

print $reg "\n/* Generated by $script_name below this line */\n";
print $decl "\n/* Generated by $script_name below this line */\n";

# Mesa for glRender
if (-e "$mesadir/gl_API.xml") {
    $enum = new IO::File "> $srcdir/x11-glx-render-enum.h"
            or die ("Cannot open $srcdir/x11-glx-render-enum.h for writing\n");
    add_generated_header($enum, $srcdir . '/mesa');
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

static void dispatch_glx_render(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order, int length)
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

        ti = proto_tree_add_item(tt, hf_x11_request_length, tvb, *offsetp, 2, byte_order);
        *offsetp += 2;
        proto_tree_add_item(tt, hf_x11_glx_render_op_name, tvb, *offsetp, 2, byte_order);
        *offsetp += 2;

        if (len < 4) {
            expert_add_info(pinfo, ti, &ei_x11_request_length);
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
        print $impl "        case $req:\n";
        print $impl "            mesa_$request{$req}(tvb, offsetp, tt, byte_order, len);\n";
        print $impl "            break;\n";
    }
    print $impl "        default:\n";
    print $impl "            proto_tree_add_item(tt, hf_x11_undecoded, tvb, *offsetp, len, ENC_NA);\n";
    print $impl "            *offsetp += len;\n";

    print $impl "        }\n";
    print $impl "        if (*offsetp < next) {\n";
    print $impl "            proto_tree_add_item(tt, hf_x11_unused, tvb, *offsetp, next - *offsetp, ENC_NA);\n";
    print $impl "            *offsetp = next;\n";
    print $impl "        }\n";
    print $impl "        length -= (len + 4);\n";
    print $impl "    }\n}\n";
}

$enum = new IO::File "> $srcdir/x11-enum.h"
        or die ("Cannot open $srcdir/x11-enum.h for writing\n");
add_generated_header($enum, $srcdir . '/xcbproto');
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

#
#  Editor modelines
#
#  Local Variables:
#  c-basic-offset: 4
#  tab-width: 8
#  indent-tabs-mode: nil
#  End:
#
#  ex: set shiftwidth=4 tabstop=8 expandtab:
#  :indentSize=4:tabSize=8:noTabs=true:
#
