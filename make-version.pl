#!/usr/bin/perl -w
#
# Copyright 2004 Jörg Mayer (see AUTHORS file)
#
# $Id: make-version.pl,v 1.5 2004/02/01 11:32:23 obiot Exp $
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

my $version_file = 'cvsversion.h';
my %asctonum = ( "Jan" => "01", "Feb" => "02", "Mar" => "03", "Apr" => "04",
		"May" => "05", "Jun" => "06", "Jul" => "07", "Aug" => "08",
		"Sep" => "09", "Oct" => "10", "Nov" => "11", "Dec" => "12" );
my $last = "";
my $last_modified = 0;
my $last_file = undef;


# Recursively find all CVS Entries files starting from the given directory,
# and compute the modification time of the most recently modified Entries file.
sub find_last_CVS_Entries {
	my $dir = shift;
	my $d;

	opendir(DIR, "$dir") || print STDERR "Can't open directory $dir ($!)\n" && next;
	foreach $d (readdir(DIR)) {
		if (-d "$dir/$d" && $d !~ /^\.(|.)$/) {
			if ($d =~ /^CVS$/) {
				my @stat = stat("$dir/CVS/Entries");

				if (@stat) {
					if ($last_modified < $stat[9]) {
						$last_modified = $stat[9];
						$last_file = "$dir/CVS/Entries"
					}
				}
			} else { # Recurse in directory
				&find_last_CVS_Entries("$dir/$d");
			}
		}
	}
	closedir DIR;
}


# Check all entries in $file. In case they are newer, update $last accordingly
# Args: Entries file
sub lastentry {
	my $date;
	my ($wdayascii, $monthascii, $day, $time, $year);
	my $file = shift;
	my $current;

	open(FILE, "<$file") || print STDERR "Open $file for reading failed ($!)\n" && return 1;

	while (<FILE>) {
		chomp;
		# Regular lines look like this: /ethereal_be.py/1.6/Fri Aug  2 22:55:19 2002//
		next if (/^D/);
		$date = (split(/\//, $_, 5))[3];
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


# Print the CVS version to $version_file.
# Don't change the file if it is not needed.
sub print_cvs_version
{
	my $cvs_version;
	my $needs_update = 1;

	if ($last ne "") {
		$cvs_version = "#define CVSVERSION \"$last\"\n";
	} else {
		$cvs_version = "/* #define CVSVERSION \"\" */\n";
	}
	if (open(OLDVER, "<$version_file")) {
		if (<OLDVER> eq $cvs_version) {
			print "$version_file is up-to-date.\n";
			$needs_update = 0;
		}
		close OLDVER;
	}

	if ($needs_update == 1) {
		# print "Updating $version_file so it contains:\n$cvs_version";
		open(VER, ">$version_file") || die ("Cannot write to $version_file ($!)\n");
		print VER "$cvs_version";
		close VER;
		print "$version_file has been updated.\n";
	}
}

##
## Start of code
##

if (-d "./CVS") {
	print "This is a build from CVS (or a CVS snapshot), "
	. "CVS version tag will be computed.\n";
	&find_last_CVS_Entries(".");
} else {
	print "This is not a CVS build.\n";
}

# Now $last_modified and $last_file are set if we found one CVS/Entries file.
# We need to invoke lastentry on the most recent entries file.

if (defined $last_file) {
	my @version_stat = stat($version_file);
	my $version_mtime = 0;
	if (@version_stat) {
		$version_mtime = $version_stat[9];
	}
	&lastentry($last_file);
	# print "Last: $last_file\t($last)\n";
}

# Now that we've computed everything, print the CVS version to $version_file
&print_cvs_version;

__END__
