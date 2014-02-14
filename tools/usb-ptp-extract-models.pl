#!/usr/bin/perl -w
# 
# USAGE: $0 </path/to/libgphoto2/camlibs/ptp2>
#
# USB PTP Dissector
#    Extracts USB devices from libgphoto2
#  This is then parsed by make-usb.py to make epan/dissectors/usb.c
# 
# (c)2013 Max Baker <max@warped.org>
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

my $path = shift @ARGV || '.';

$re_hex = '0x[0-9a-f]+';

parse_file("$path/library.c",1);
parse_file("$path/music-players.h",0);

open (O,"> tools/usb-ptp-extract-models.txt") or die $!;

foreach my $vendor (sort {hex($a) <=> hex($b)} keys %devices) {
    my $p = $devices{$vendor};
    foreach my $product (sort {hex($a) <=> hex($b)} keys %$p) {
        my $pd = $product; $pd =~ s/^0x//i;
        my $v = $vendor; $v =~ s/^0x//i;
        # { 0xeb1ae355, "KWorld DVB-T 355U Digital TV Dongle" },
        #printf "    { 0x%s%s, \"%s\" },\n",$v, $pd, $p->{$product};

        printf O "%s%s %s\n", $v, $pd, $p->{$product};
    }
}

close O or die $!;

exit;

sub parse_file {
    my $file = shift;
    my $detect = shift;

    my $start = !$detect;

    open (H,"<$file") or die "Could not find $file. $!";
    while (<H>) {
        chomp;

        # Look for models[] line as start
        if (/\bmodels\[\]/) {
            $start = 1;
            next;
        }

        # Look for }; as the end
        $start = 0 if /^\s*};/;

        next unless $start;
        # Skip comment lines

        # Remove comments
        s,/\*.*\*/,,g;

        s,^\s*,,;
        s,\s*$,,;

        # Skip blank lines
        next if /^$/;
        next if m,^\s*/?\*,;

        my $line = $_;

        my ($model, $vendor, $product, $manif);

        # {"Nikon:DSC D90 (PTP mode)",  0x04b0, 0x0421, PTP_CAP|PTP_CAP_PREVIEW},
        if($line =~ m/^\{
            "([^"]+)",\s*
            ($re_hex),\s*
            ($re_hex),\s*
            /xi) {

            ($model, $vendor, $product) = ($1,$2,$3);
            $model =~ s/:/ /;
            $model =~ s/\(.*\)//;
        }
        # { "Creative", 0x041e, "ZEN X-Fi 3", 0x4169,
        # { "TrekStor", 0x0402, "i.Beat Sweez FM", 0x0611,
        if($line=~ m/^\{\s*
            "([^"]+)",\s*
            ($re_hex),\s*
            "([^"]+)",\s*
            ($re_hex),\s*
            /xi) {
            ($manif, $vendor, $model, $product) = ($1,$2,$3,$4);
            $model = "$manif $model";
        }
        
        next unless defined $vendor;

        $model =~ s/\s+/ /g;
        $model =~ s/\s*$//;

        #print "$vendor $product $model\n";
        $devices{$vendor}->{$product}=$model;
    }
}
