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

    ($abbrev, $type, $presentation, $field4) = split /\s+/o;
    $lastAbbrev = $abbrev;

    $field = $prefix.$abbrev;

    if ($presentation =~ /^VALS/) {
	$fieldBase = 'BASE_NONE';
    } elsif ($presentation =~ /^\d+$/o) {
	$fieldBase = $presentation;
    } else {
	$fieldBase = "BASE_$presentation";
    }

    if ($presentation eq 'VALS') {
	$fieldConvert = "VALS(${abbrev}_vals)";
	$fieldConvert =~ s/-/_/go;
    } elsif ($presentation =~ /^VALS\(/o) {
	$fieldConvert = $presentation;
	$fieldConvert =~ s/\)/_vals\)/o;
    } else {
	$fieldConvert = 'NULL';
    }

    $mask = 0;
    $mask = $field4 if $subfield;
    $mask = 0 unless $mask =~ /\d+/o;

    $longName = uc $name;
    $longName = $field4 if ($field4 && !$subfield);

    $variable = $field;
    $variable =~ s/-/_/go;
    $variable =~ s/\./_/go;

    print DECL "static int hf_x11_$variable = -1;\n";

    print REG <<END;
{ &hf_x11_$variable, { "$abbrev", "x11.$field", FT_$type, $fieldBase, $fieldConvert, $mask, "$longName" } },
END
}
