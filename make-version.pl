#!/usr/bin/perl -w
#
# Copyright 2004 Jörg Mayer (see AUTHORS file)
#
# $Id$
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
# format: SVN %Y%m%d%H%M%S

use strict;

use Time::Local;
use POSIX qw(strftime);

my $version_file = 'svnversion.h';
my $vconf_file = 'version.conf';
my $last = 0;
my %version_pref = ("enable" => 1, "format" => "SVN %Y%m%d%H%M%S");


# Recursively find all SVN Entries files starting from the given directory,
# and compute the modification time of the most recently modified Entries file.
sub read_svn_info {
	my $line;

	open(SVNINFO, "svn info |") || return;
	while ($line = <SVNINFO>) {
		if ($line =~ /^Last Changed Date: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
			$last = timegm($6, $5, $4, $3, $2 - 1, $1);
		}
	}
	close SVNINFO;
}


# Print the SVN version to $version_file.
# Don't change the file if it is not needed.
sub print_svn_version
{
	my $svn_version;
	my $needs_update = 1;

	if ($last) {
		$svn_version = "#define SVNVERSION \"" . 
			strftime($version_pref{"format"}, gmtime($last)) .
			"\"\n";
	} else {
		$svn_version = "/* #define SVNVERSION \"\" */\n";
	}
	if (open(OLDVER, "<$version_file")) {
		if (<OLDVER> eq $svn_version) {
			print "$version_file is up-to-date.\n";
			$needs_update = 0;
		}
		close OLDVER;
	}

	if ($needs_update == 1) {
		# print "Updating $version_file so it contains:\n$svn_version";
		open(VER, ">$version_file") || die ("Cannot write to $version_file ($!)\n");
		print VER "$svn_version";
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
} elsif (-d "./.svn") {
	print "This is a build from SVN (or a SVN snapshot), "
	. "SVN version tag will be computed.\n";
	&read_svn_info(".");
} else {
	print "This is not a SVN build.\n";
}

# Now that we've computed everything, print the SVN version to $version_file
&print_svn_version;

__END__
