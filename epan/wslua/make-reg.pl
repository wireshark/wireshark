#!/usr/bin/perl
#
# make-reg.pl
# Registration Macros Generator
#
# (c) 2006, Luis E. Garcia Onatnon <luis.ontanon@gmail.com>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

use strict;

my @classes = ();
my @functions = ();

while (<>) {
	push @classes, $1 if /WSLUA_CLASS_DEFINE\050\s*([A-Za-z]+)/;
	push @functions, $1 if  /WSLUA_FUNCTION\s+wslua_([a-z_]+)/;
}

print "/* This file is automatically genrated by elua_makereg.pl do not edit */\n\n";

print "#define WSLUA_DECLARE_CLASSES() \\\n"; 
for (@classes) {
	print "\tWSLUA_CLASS_DECLARE($_);\\\n"
}
print "\n\n";

print "#define WSLUA_REGISTER_CLASSES() { \\\n"; 
for (@classes) {
	print "\t${_}_register(L);\\\n"
}
print "}\n\n";

print "#define WSLUA_DECLARE_FUNCTIONS() \\\n"; 
for (@functions) {
	print "\tWSLUA_FUNCTION wslua_$_(lua_State* L);\\\n"
}
print "\n\n";

print "#define WSLUA_REGISTER_FUNCTIONS() {\\\n"; 
for (@functions) {
	print "\t	WSLUA_REGISTER_FUNCTION($_); \\\n"
}
print "}\n\n";
