#!/usr/bin/perl
#
# make-init-lua.pl
#
# create the init.lua file based on a template (stdin) 
#
# (c) 2006, Luis E. Garcia Onatnon <luis.ontanon@gmail.com>
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
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

my $WSROOT = "../..";

my $wtap_encaps_table = '';
my $ft_types_table = '';
my $bases_table = '';
my $expert_pi = '';
my $menu_groups = '';

my %replacements = %{{
    WTAP_ENCAPS => \$wtap_encaps_table,
    FT_TYPES => \$ft_types_table,
	BASES => \$bases_table,
	EXPERT => \$expert_pi,
	MENU_GROUPS => \$menu_groups,
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

open WTAP_H, "< $WSROOT/wiretap/wtap.h";

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

open FTYPES_H, "< $WSROOT/epan/ftypes/ftypes.h";
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

open PROTO_H, "< $WSROOT/epan/proto.h";
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

# register_stat_group_t


$menu_groups .= "-- menu groups for register_menu \n";
my $menu_i = 0;

open STAT_MENU, "< $WSROOT/stat_menu.h";
while(<STAT_MENU>) {
	if (/REGISTER_([A-Z]+)_GROUP_([A-Z]+)/) {
		$menu_groups .= "MENU_$1_$2 = $menu_i\n";
		$menu_groups =~ s/_NONE//;
		$menu_i++;
	}
}
close STAT_MENU;


$bases_table .= "}\n\n";
$expert_pi .= "\n\n";

for my $key (keys %replacements) {
    $template =~ s/%$key%/${$replacements{$key}}/msig;
}


print $template;
