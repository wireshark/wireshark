#!/usr/bin/perl -w
# 
# USB PTP Dissector
#    Extracts PTP response codes from libgphoto2
#  This is then hand-merged into packet-usb-ptp.h
# 
# (c)2013 Max Baker <max@warped.org>
# 
# SPDX-License-Identifier: GPL-2.0-or-later

$file = shift @ARGV || 'ptp.h';
$outfile = 'epan/dissectors/packet-usb-ptp.h';

%tables = (
'PTP_AC' => 'StorageInfo Access Capability',
'PTP_AT' => 'Association Types',
'PTP_DPC' => 'Device Properties Codes',
'PTP_DPFF' => 'Device Property Form Flag',
'PTP_DPGS' => 'Device Property GetSet type',
'PTP_DTC' => 'Data Type Codes',
'PTP_EC' => 'Event Codes',
'PTP_FST' => 'FilesystemType Values',
'PTP_GOH' => 'GetObjectHandles',
'PTP_OC' => 'Operation Codes',
'PTP_OFC' => 'Object Format Codes',
'PTP_OPC' => 'MTP Object Properties',
'PTP_OPFF' => 'MTP Device Property Codes',
'PTP_PS' => 'Protection Status',
'PTP_RC' => 'Response Codes',
'PTP_ST' => 'Storage Types',
'PTP_VENDOR' => 'Vendor IDs',
);

%manual_entries = (
    'PTP_OC' => [
        "USB_PTP_FLAVOR_NIKON     , 0xfc01, \"ServiceModeStart\"",
        "USB_PTP_FLAVOR_NIKON     , 0xfc02, \"ServiceModeStop\"",
    ]
);

%Flavors = qw/
ANDROID     USB_PTP_FLAVOR_ANDROID
CANON       USB_PTP_FLAVOR_CANON
CANON_EOS   USB_PTP_FLAVOR_CANON
CASIO       USB_PTP_FLAVOR_CASIO
EK          USB_PTP_FLAVOR_KODAK
FUJI        USB_PTP_FLAVOR_FUJI
LEICA       USB_PTP_FLAVOR_LEICA
MTP         USB_PTP_FLAVOR_MTP
NIKON       USB_PTP_FLAVOR_NIKON
OLYMPUS     USB_PTP_FLAVOR_OLYMPUS
OLYMPUS_OMD USB_PTP_FLAVOR_OLYMPUS
PARROT      USB_PTP_FLAVOR_PARROT
PANASONIC   USB_PTP_FLAVOR_PANASONIC
SONY        USB_PTP_FLAVOR_SONY
SONY_QX     USB_PTP_FLAVOR_SONY
/;

$re_hex = '0x[0-9a-f]+';

open (H,"<$file") or die "Can't find gphoto2 header '$file'";
while (<H>) {
    chomp;

    next unless /^\s*#define\s+(\S+)\s+(.*)$/;
    
    my ($define,$val) = ($1,$2);
    # strip c-style comment
    $val =~ s,/\*.*\*/,,;
    $val =~ s,//.*,,;
    $val =~ s/^\s*//g;
    $val =~ s/\s*$//g;

    #print "$define=$val\n";
    $D{$define}=$val;
}

close H;

sub output_unmasked_table {
    my ($table,$desc, $FH) = @_;

    my $id = lc($table);
    $id =~ s/^PTP_//i;
    print $FH "/* $table $desc */\n";
    print $FH "static const value_string usb_ptp_${id}_vals\[\] = {\n";
    my @vals;
    DEFINE:
    foreach my $define (sort sort_D keys %D) {
        next unless $define =~ /^${table}_(.*)/i;
        my $subdefine = $1;
        my $value = $D{$define};

        push @vals, sprintf("    {%s, \"%s\"}",$value,$subdefine);
    }

    # now add manual entries
    if (exists $manual_entries{$table}) {
        for $i (0 .. $#{ $manual_entries{$table}}) {
            push @vals, sprintf("    {%s}", $manual_entries{$table}[$i]);
        }
    }

    # Add a null entry to mark the end
    push @vals, "    {0, NULL}";
    print $FH join(",\n",@vals),"\n";
    print $FH "};\n";

}

sub output_table {
    my ($table,$desc, $FH) = @_;
    my $is_masked = ($table ne "PTP_VENDOR");

    return output_unmasked_table($table,$desc,$FH) unless $is_masked;

    my $id = lc($table);
    $id =~ s/^PTP_//i;
    print $FH "/* $table $desc */\n";
    print $FH "static const usb_ptp_value_string_masked_t usb_ptp_${id}_mvals\[\] = {\n";
    my @vals;
    DEFINE:
    foreach my $define (sort sort_D keys %D) {
        next unless $define =~ /^${table}_(.*)/i;
        next if $define =~ /^.*_MASK/i;
        my $subdefine = $1;

        my $type = 'USB_PTP_FLAVOR_ALL';
        foreach my $flavor (sort {length($b) <=> length($a)} keys %Flavors) {
            next unless $subdefine =~ s/^${flavor}_//i;
            $type = $Flavors{$flavor}
        }

        my $value = $D{$define};
        if ($value =~ /^0x[0-9A-F]+|\d+$/i) {
            # number or (lowercase) hex
            $value = lc($value);
        } elsif ($value =~ /^\(\s*([A-Z_][A-Z0-9_]*)\s*\|\s([A-Z_][A-Z0-9_]*)\s*\)$/i) {
            # handle simple case of (A | B) where no recursive expansion
            $value = sprintf("(%s | %s)", $D{$1}, $D{$2})
        } else {
            die "unrecognized value $value for $subdefine"
        }

        # Ok, not a subflavor
        push @vals, sprintf("    {%-25s, %s, \"%s\"}",$type,$value,$subdefine);
    }

    # now add manual entries
    if (exists $manual_entries{$table}) {
        for $i (0 .. $#{ $manual_entries{$table}}) {
            push @vals, sprintf("    {%s}", $manual_entries{$table}[$i]);
        }
    }

    # Add a null entry to mark the end
    push @vals, sprintf("    {%-25s, 0, NULL}","USB_PTP_FLAVOR_NONE");
    print $FH join(",\n",@vals),"\n";
    print $FH "};\n";
}


sub sort_D {
    my $aa = $D{$a};
    $aa = hex($aa) if $aa=~/^${re_hex}$/i;
    $bb = $D{$b} || $b;
    $bb = hex($bb) if $bb=~/^${re_hex}$/i;

    if ($aa eq $bb) {
        return $a cmp $b;
    }
    if ($aa =~ /^\d+$/ and $bb=~/^\d+$/) {
        return $aa <=> $bb;
    }
    return $aa cmp $bb;
}

open (OUT,">$outfile.tmp") or die;
open (SRC,"<$outfile") or die;
$in_autogen = 0;
while (<SRC>) {
    my $line = $_;
    if ($line =~ /(?:START|END) AUTOGENERATED CODE/) {
        print OUT $line;
        if ($line =~ /START/) {
            $in_autogen = 1;
            # Output tables
            foreach my $table (sort keys %tables) {
                output_table($table, $tables{$table}, OUT);
            }
        } else {
            $in_autogen = 0;
        }
        next;
    }
    print OUT $_ unless $in_autogen;
}
close SRC;
close OUT;
rename("$outfile.tmp", $outfile) or die;