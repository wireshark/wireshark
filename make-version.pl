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

# usage:  ./make-version.pl [-p] [--package-version]
#
# If "version.conf" is present, it is parsed for configuration values.  
# Possible values are:
#
#   enable     - Enable or disable versioning.  Zero (0) disables, nonzero
#                enables.
#   format     - A strftime() formatted string to use as a template for
#                the version string.  The sequence "%#" will substitute
#                the SVN revision number.
#   pkg_format - Like "format", but used for the package version.
#
# If run with the "-p" or "--package-version" argument, the
# AM_INIT_AUTOMAKE macro in configure.in and the VERSION macro in
# config.nmake will have the pkg_format template appended to the 
# version number.  svnversion.h will _not_ be generated if either
# argument is present.
#
# Default configuration:
#
# enable: 1
# format: SVN %Y%m%d%H%M%S
# pkg_format: -SVN-%#
# am_init: 0

# XXX - We're pretty dumb about the "%#" substitution, and about having
# spaces in the package format.

use strict;

use Time::Local;
use POSIX qw(strftime);

my $version_file = 'svnversion.h';
my $version_string = "";
my $package_string = "";
my $vconf_file = 'version.conf';
my $last = 0;
my $revision = 0;
my $pkg_version = 0;
my %version_pref = (
	"enable"     => 1,
	"format"     => "SVN %Y%m%d%H%M%S",
	"pkg_format" => "-SVN-%#",
	);


# Run "svn info".  Parse out the most recent modification time and the
# revision number.
sub read_svn_info {
	my $line;

	open(SVNINFO, "svn info |") || die("Unable to get SVN info!");
	while ($line = <SVNINFO>) {
		if ($line =~ /^Last Changed Date: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
			$last = timegm($6, $5, $4, $3, $2 - 1, $1);
		}
		if ($line =~ /^Revision: (\d+)/) {
			$revision = $1;
		}
	}
	close SVNINFO;

	if ($last && $revision) {
		$version_string = strftime($version_pref{"format"}, gmtime($last));
		$version_string =~ s/%#/$revision/;

		$package_string = strftime($version_pref{"pkg_format"}, gmtime($last));
		$package_string =~ s/%#/$revision/;
	}
}


# Read configure.in, then write it back out with an updated 
# "AM_INIT_AUTOMAKE" line.
sub update_configure_in
{
	my $line;
	my $contents = "";
	my $version = "";
	
	return if ($package_string eq "");
	
	open(CFGIN, "< configure.in") || die "Can't read configure.in!";
	while ($line = <CFGIN>) {
		if ($line =~ /^AM_INIT_AUTOMAKE\(ethereal, (\d+)\.(\d+).(\d+)/) {
			$line = "AM_INIT_AUTOMAKE\(ethereal, $1.$2.$3$package_string)\n";
		}
		$contents .= $line
	}
	
	open(CFGIN, "> configure.in") || die "Can't write configure.in!";
	print(CFGIN $contents);
	close(CFGIN);
	print "configure.in has been updated.\n";
}

# Read config.nmake, then write it back out with an updated 
# "VERSION" line.
sub update_config_nmake
{
	my $line;
	my $contents = "";
	my $version = "";
	
	return if ($package_string eq "");
	
	open(CFGIN, "< config.nmake") || die "Can't read config.nmake!";
	while ($line = <CFGIN>) {
		if ($line =~ /^VERSION=(\d+)\.(\d+).(\d+)/) {
			$line = "VERSION=$1.$2.$3$package_string\n";
		}
		$contents .= $line
	}
	
	open(CFGIN, "> config.nmake") || die "Can't write config.nmake!";
	print(CFGIN $contents);
	close(CFGIN);
	print "config.nmake has been updated.\n";
}



# Print the SVN version to $version_file.
# Don't change the file if it is not needed.
sub print_svn_version
{
	my $svn_version;
	my $needs_update = 1;

	if ($last && $revision) {
		$svn_version = "#define SVNVERSION \"" . 
			$version_string . "\"\n";
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
	my $arg;

	# Get our command-line args
	foreach $arg (@ARGV) {
		if ($arg eq "-p" || $arg eq "--package-version") {
			$pkg_version = 1;
		}
	}


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

if (-d "./.svn") {
	print "This is a build from SVN (or a SVN snapshot).\n";
	&read_svn_info(".");
	if ($pkg_version) {
		print "Generating package version.  Ignoring $vconf_file.\n";
		&update_configure_in;
		&update_config_nmake;
	} elsif ($version_pref{"enable"} == 0) {
		print "Version tag disabled in $vconf_file.\n";
	} else {
		print "SVN version tag will be computed.\n";
		&print_svn_version;
	}
} else {
	print "This is not a SVN build.\n";
}

__END__
