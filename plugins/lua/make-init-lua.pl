#!/usr/bin/perl
# create the init.lua file based on a template (stdin) 
#
# $Id$
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
my $bases_table = '';
my $expert_pi = '';

my %replacements = %{{
    WTAP_ENCAPS => \$wtap_encaps_table,
    FT_TYPES => \$ft_types_table,
	BASES => \$bases_table,
	EXPERT => \$expert_pi,
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

open WTAP_H, "< ../../wiretap/wtap.h";

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

open FTYPES_H, "< ../../epan/ftypes/ftypes.h";
while(<FTYPES_H>) {
    if ( /^\s+FT_([A-Z0-9a-z_]+)\s*,/ ) {
        $ft_types_table .= "\t[\"$1\"] = $ftype_num,\n";
        $ftype_num++;
    }
}
close FTYPES_H;

$ft_types_table =~ s/,\n$/\n}\n/msi;



#
# enum base
#

$bases_table = "-- Display Bases\n base = {\n";
$expert_pi = "-- Expert flags and facilities\n";

my $base_num = 0;

open PROTO_H, "< ../../epan/proto.h";
while(<PROTO_H>) {
	if (/^\s+BASE_([A-Z_]+),/ ) {
		$bases_table .= "\t[\"$1\"] = $base_num,\n";
		$base_num++;
	}
	
	if ( /^.define\s+(PI_[A-Z_]+)\s+((0x)?[0-9A-Fa-f]+)/ ) {
		my ($name, $value) = ($1, hex($2));
		$expert_pi .= "$name = $value\n";
	}
}
close PROTO_H;

$bases_table .= "}\n\n";
$expert_pi .= "\n\n";


#
# replace macros
#

for my $key (keys %replacements) {
    $template =~ s/%$key%/${$replacements{$key}}/msig;
}


print $template;
