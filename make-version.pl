#!/usr/bin/perl -w
#
# Copyright 2004 Jörg Mayer (see AUTHORS file)
#
# $Id: make-version.pl,v 1.7 2004/03/04 16:19:40 jmayer Exp $
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
#
# If "version.conf" is present, it is parsed for configuration values.  
# Possible values are:
#
#   enable - Enable or disable versioning.  Zero (0) disables, nonzero
#            enables.
#   format - A strftime() formatted string to use as a template for the
#            version string.
#
# Default configuration:
#
# enable: 1
# format: CVS %Y%m%d%H%M%S

use strict;

use Time::Local;
use POSIX qw(strftime);

my $version_file = 'cvsversion.h';
my $vconf_file = 'version.conf';
my %monthnum = ( "Jan" => "0", "Feb" => "1", "Mar" => "2", "Apr" => "3",
		"May" => "4", "Jun" => "5", "Jul" => "6", "Aug" => "7",
		"Sep" => "8", "Oct" => "9", "Nov" => "10", "Dec" => "11" );
my $last = 0;
my $last_file = undef;
my %version_pref = ("enable" => 1, "format" => "CVS %Y%m%d%H%M%S");


# Recursively find all CVS Entries files starting from the given directory,
# and compute the modification time of the most recently modified Entries file.
sub find_last_CVS_Entries {
	my $dir = shift;
	my $d;

	opendir(DIR, "$dir") || print STDERR "Can't open directory $dir ($!)\n" && next;
	foreach $d (readdir(DIR)) {
		if (-d "$dir/$d" && $d !~ /^\.(|.)$/) {
			if ($d =~ /^CVS$/) {
				if (-f "$dir/CVS/Entries") {
					&lastentry("$dir/CVS/Entries");
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
		#                        Month   Day   Hour   Minute Second Year
		next if ($date !~ /\w{3} (\w{3}) (.\d) (\d\d):(\d\d):(\d\d) (\d{4})/);
		$current = timegm($5, $4, $3, $2, $monthnum{$1}, $6);

		if ($current > $last) {
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

	if ($last) {
		$cvs_version = "#define CVSVERSION \"" . 
			strftime($version_pref{"format"}, gmtime($last)) .
			"\"\n";
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

# Read values from the configuration file, if it exists.
sub get_config {
	open(FILE, "<$vconf_file") || print STDERR "Version configuration file $vconf_file not found.  Using defaults.\n" && return 1;

	while (<FILE>) {
		chomp;
		next if (/^#/);
		next unless (/^(\w+):\s+(\S.*)/);
		$version_pref{$1} = $2;
	}
	close FILE;
	return 1;
}

##
## Start of code
##

&get_config();

if ($version_pref{"enable"} == 0) {
	print "Version tag disabled in $vconf_file.\n";
} elsif (-d "./CVS") {
	print "This is a build from CVS (or a CVS snapshot), "
	. "CVS version tag will be computed.\n";
	&find_last_CVS_Entries(".");
} else {
	print "This is not a CVS build.\n";
}

# Now that we've computed everything, print the CVS version to $version_file
&print_cvs_version;

__END__
