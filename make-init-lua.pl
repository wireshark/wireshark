#!/usr/bin/perl
# create the init.lua file based on a template (stdin) 
#
# $Id: $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
# Copyright 2004 Gerald Combs
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

use strict;

my $wtap_encaps_table = '';
my $ft_types_table = '';


my %replacements = %{{
    WTAP_ENCAPS => \$wtap_encaps_table,
    FT_TYPES => \$ft_types_table,
}};


#
# load template
#
my $template = '';
$template .= $_ while(<>);


#
# make wiretap encapusulation table 
#

$wtap_encaps_table = "-- Wiretap encapsulations\nwtap = {\n";

open WTAP_H, "< wiretap/wtap.h";

while(<WTAP_H>) {
    if ( /^#define WTAP_ENCAP_([A-Z0-9_]+)\s+(\d+)/ ) {
        $wtap_encaps_table .= "\t[\"$1\"] = $2,\n";
    }
}

$wtap_encaps_table =~ s/,\n$/\n}\n/msi;

#
# enum fttype
#

$ft_types_table = " -- Field Types\nftypes = {\n";

my $ftype_num = 0;

open FTYPES_H, "< ./epan/ftypes/ftypes.h";
while(<FTYPES_H>) {
    if ( /^\s+(FT_[A-Z0-9a-z_]+)\s*,/ ) {
        $ft_types_table .= "\t[\"$1\"] = $ftype_num,\n";
        $ftype_num++;
    }
}
close FTYPES_H;

$ft_types_table =~ s/,\n$/\n}\n/msi;



#
# 
#


#
# replace macros
#

for my $key (keys %replacements) {
    $template =~ s/%$key%/${$replacements{$key}}/msig;
}


print $template;
