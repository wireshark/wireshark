#!/usr/bin/perl

open(DECL, ">x11-declarations.h") || die;
open(REG, ">x11-register-info.h") || die;

$prefix = '';
$subfieldStringLength = 0;

while(<>) {
    s/#.*$//go;
    next if /^\s*$/o;
    s/^(\s*)//o;
    $subfield = $1;

    if (length $subfield != $subfieldStringLength) {
	if (!length $subfield) {
	    $prefix = '';
	} elsif (length $subfield > $subfieldStringLength) {
	    $prefix .= "$lastAbbrev.";
	} else {
	    $prefix =~ s/^(.*)\.[^\.]+\.$/$1./o;
	}
	$subfieldStringLength = length $subfield;
    }

    @fields = split /\s+/o ;
    $abbrev = shift @fields;
    $type = shift @fields;
    $lastAbbrev = $abbrev;

    $field = $prefix.$abbrev;

    if ($fields[0] =~ /^\d+$/o) {
	#
	# This is presumably a Boolean bitfield, and this is the number
	# of bits in the parent field.
	#
	$fieldDisplay = shift @fields;
    } else {
	#
	# The next token is the base for the field.
	#
	$fieldDisplay = "BASE_".shift @fields;
    }

    if ($fields[0] eq 'VALS') {
	#
	# It's an enumerated field, with the value_string table having a
	# name based on the field's name.
	#
	shift @fields;
	$fieldStrings = "VALS(${abbrev}_vals)";
	$fieldStrings =~ s/-/_/go;
    } elsif ($fields[0] =~ /^VALS\(/o) {
	#
	# It's an enumerated field, with a specified name for the
	# value_string table.
	#
	$fieldStrings = shift @fields;
	$fieldStrings =~ s/\)/_vals\)/o;
    } else {
	#
	# It's not an enumerated field.
	#
	$fieldStrings = 'NULL';
    }

    if ($fields[0] =~ /^0x/) {
	#
	# The next token looks like a bitmask for a bitfield.
	#
	$mask = shift @fields;
    } else {
	$mask = 0;
    }

    $rest = join(' ', @fields);
    $longName = uc $name;
    $longName = $rest if ($rest);

    $variable = $field;
    $variable =~ s/-/_/go;
    $variable =~ s/\./_/go;

    print DECL "static int hf_x11_$variable = -1;\n";

    print REG <<END;
{ &hf_x11_$variable, { "$abbrev", "x11.$field", FT_$type, $fieldDisplay, $fieldStrings, $mask, "$longName" } },
END
}
