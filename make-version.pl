#!/usr/bin/perl -w
#
# Copyright 2004 Jörg Mayer (see AUTHORS file)
#
# $Id: make-version.pl,v 1.2 2004/01/17 13:09:00 jmayer Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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

# usage:  ./make-version.pl

use strict;

my ($d1,$d2,$d3,$date,$drest);
my ($wdayascii, $monthascii, $day, $time, $year);

my %asctonum = ( "Jan" => "01", "Feb" => "02", "Mar" => "03", "Apr" => "04",
		"May" => "05", "Jun" => "06", "Jul" => "07", "Aug" => "08",
		"Sep" => "09", "Oct" => "10", "Nov" => "11", "Dec" => "12" );

my $current;
my $last = "";


sub findentries {
	my $currentdir = shift;

	opendir(DIR, "$currentdir") || print STDERR "Opendir $currentdir failed ($!)\n" && next;
	grep { (-d "$currentdir/$_" && $_ !~ /^\.(|.)$/ && &findentries("$currentdir/$_")) ||
	       (-f "$currentdir/$_" && $_ =~ /^Entries$/ && &lastentry("$currentdir/$_")) } readdir(DIR);
	closedir DIR;
}

sub lastentry {
	my $file = shift;

	open(FILE, "<$file") || print STDERR "Open $file for reading failed ($!)\n" && return 1;
	while (<FILE>) {
		chomp;
		# Regular lines look like this: /ethereal_be.py/1.6/Fri Aug  2 22:55:19 2002//
		next if (/^D/);
		($d1,$d2,$d2,$date,$drest) = split(/\//, $_, 5);
		next if ($date !~ /\d:\d\d:\d\d/);
		($wdayascii, $monthascii, $day, $time, $year) = split(/\s+/, $date);
		$day = substr("0".$day, -2, 2);
		$time =~ s/://g;
		$current = "$year$asctonum{$monthascii}$day$time";
		if ($current gt $last) {
			$last = $current;
		}
	}
	close FILE;
	return 1;
}

&findentries(".");

if ($last eq "" && -f "cvsversion") {
	$last = `cat cvsversion`;
}
if ( $last ne "" ) {
	$last = "#define CVSVERSION \"cvs$last\"\n";
} else {
	$last = "#define CVSVERSION \"\"\n";
}

my $needsupdate=0;

if (! open(OLDVER, "<cvsversion.h")) {
	$needsupdate = 1;
} else {
	if (<OLDVER> ne $last) {
		$needsupdate = 1;
	}
	close OLDVER;
}

if ($needsupdate == 1) {
	open(VER, ">cvsversion.h") || die ("Cannot write to cvsversion.h ($!)\n");
	print VER "$last";
	close VER;
}

__END__


