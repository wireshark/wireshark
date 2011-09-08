#!/usr/bin/perl -w
#
# Copyright 2004 Jörg Mayer (see AUTHORS file)
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# usage:  ./make-version.pl [-p|--package-version]
#
# If "version.conf" is present, it is parsed for configuration values.  
# Possible values are:
#
#   enable     - Enable or disable versioning.  Zero (0) disables, nonzero
#		 enables.
#   svn_client - Use svn client i.s.o. ugly internal SVN file hack
#   format     - A strftime() formatted string to use as a template for
#		 the version string.  The sequence "%#" will substitute
#		 the SVN revision number.
#   pkg_enable - Enable or disable package versioning.
#   pkg_format - Like "format", but used for the package version.
#   is_release - Specifies that we're building from a release tarball;
#		 svnversion.h is not updated.  This should be added only
#		 to the *released* version.conf, not the one used to build
#		 the release (IOW it should be added by automake's dist-hook).
#
# If run with the "-p" or "--package-version" argument, the
# AC_INIT macro in configure.in and the VERSION macro in
# config.nmake will have the pkg_format template appended to the 
# version number.  svnversion.h will _not_ be generated if either
# argument is present (it will also not be generated if 'is_release' is set
# in version.conf).
#
# Default configuration:
#
# enable: 1
# svn_client: 1
# format: SVN %Y%m%d%H%M%S
# pkg_enable: 1
# pkg_format: -SVN-%#

# XXX - We're pretty dumb about the "%#" substitution, and about having
# spaces in the package format.

use strict;

use Time::Local;
use POSIX qw(strftime);
use Getopt::Long;

my $version_file = 'svnversion.h';
my $package_string = "";
my $vconf_file = 'version.conf';
my $last_change = 0;
my $revision = 0;
my $repo_path = "unknown";
my $pkg_version = 0;
my %version_pref = (
	"enable"     => 1,
	"svn_client" => 1,
	"format"     => "SVN %Y%m%d%H%M%S",
	"is_release" => 0,

	# Normal development builds
	"pkg_enable" => 1,
	"pkg_format" => "-SVN-%#",

	# Development releases
	#"pkg_enable" => 0,
	#"pkg_format" => "",
	);
my $srcdir = ".";
my $svn_info_cmd = "";

$ENV{LANG} = "C";  # Ensure we run with correct locale

# Run "svn info".  Parse out the most recent modification time and the
# revision number.
sub read_svn_info {
	my $line;
	my $version_format = $version_pref{"format"};
	my $package_format = "";
	my $in_entries = 0;
	my $svn_name;
	my $repo_version;
	my $repo_root = undef;
	my $repo_url = undef;
	my $do_hack = 1;

	if ($version_pref{"pkg_enable"}) {
		$package_format = $version_pref{"pkg_format"};
	}

	if ($version_pref{"svn_client"}) {
		eval {
			use warnings "all";
			no warnings "all";
			$line = qx{$svn_info_cmd};
			if (defined($line)) {
				if ($line =~ /Last Changed Date: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
					$last_change = timegm($6, $5, $4, $3, $2 - 1, $1);
				}
				if ($line =~ /Last Changed Rev: (\d+)/) {
					$revision = $1;
				}
				if ($line =~ /URL: (\S+)/) {
					$repo_url = $1;
				}
				if ($line =~ /Repository Root: (\S+)/) {
					$repo_root = $1;
				}
			}
			1;
		};

		if ($last_change && $revision && $repo_url && $repo_root) {
			$do_hack = 0;
		}
	}

	# 'svn info' failed or the user really wants us to dig around in .svn/entries
	if ($do_hack) {
		# Start of ugly internal SVN file hack
		if (! open (ENTRIES, "< $srcdir/.svn/entries")) {
			print ("Unable to open $srcdir/.svn/entries\n");
		} else {
			# We need to find out whether our parser can handle the entries file
			$line = <ENTRIES>;
			chomp $line;
			if ($line eq '<?xml version="1.0" encoding="utf-8"?>') {
				$repo_version = "pre1.4";
			} elsif ($line =~ /^8$/) {
				$repo_version = "1.4";
			} else {
				$repo_version = "unknown";
			}

			if ($repo_version eq "pre1.4") {
				# The entries schema is flat, so we can use regexes to parse its contents.
				while ($line = <ENTRIES>) {
					if ($line =~ /<entry$/ || $line =~ /<entry\s/) {
						$in_entries = 1;
						$svn_name = "";
					}
					if ($in_entries) {
						if ($line =~ /name="(.*)"/) { $svn_name = $1; }
						if ($line =~ /committed-date="(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)/) {
							$last_change = timegm($6, $5, $4, $3, $2 - 1, $1);
						}
						if ($line =~ /revision="(\d+)"/) { $revision = $1; }
					}
					if ($line =~ /\/>/) {
						if (($svn_name eq "" || $svn_name eq "svn:this_dir") &&
								$last_change && $revision) {
							$in_entries = 0;
							last;
						}
					}
					# XXX - Fetch the repository root & URL
				}
			}
			close ENTRIES;
		}
	}

	# If we picked up the revision and modification time, 
	# generate our strings.
	if ($revision && $last_change) {
		$version_format =~ s/%#/$revision/;
		$package_format =~ s/%#/$revision/;
		$package_string = strftime($package_format, gmtime($last_change));
	}
	
	if ($repo_url && $repo_root && index($repo_url, $repo_root) == 0) {
		$repo_path = substr($repo_url, length($repo_root));
	}
}


# Read configure.in, then write it back out with an updated 
# "AC_INIT" line.
sub update_configure_in
{
	my $line;
	my $contents = "";
	my $version = "";
	
	return if ($package_string eq "");
	
	open(CFGIN, "< configure.in") || die "Can't read configure.in!";
	while ($line = <CFGIN>) {
		if ($line =~ /^AC_INIT\(wireshark, (\d+)\.(\d+).(\d+)/) {
			$line = "AC_INIT\(wireshark, $1.$2.$3$package_string)\n";
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
	my $update_ve = 0;
	
	if ($package_string ne "") { $update_ve = 1; };
	
	open(CFGIN, "< config.nmake") || die "Can't read config.nmake!";
	while ($line = <CFGIN>) {
		if ($update_ve && $line =~ /^VERSION_EXTRA=/) {
			$line = "VERSION_EXTRA=$package_string\n";
		}
		if ($line =~ /^VERSION_BUILD=/ && int($revision) > 0) {
			$line = "VERSION_BUILD=$revision\n";
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

	if ($pkg_version || $version_pref{"is_release"} == 1) { return; }

	if ($last_change && $revision) {
		$svn_version = "#define SVNVERSION \"SVN Rev " . 
			$revision . "\"\n" .
			"#define SVNPATH \"" . $repo_path . "\"\n";
	} else {
		$svn_version = "#define SVNVERSION \"SVN Rev Unknown\"\n" .
			"#define SVNPATH \"unknown\"\n";
	}
	if (open(OLDVER, "<$version_file")) {
		my $old_svn_version = <OLDVER> . <OLDVER>;
		if ($old_svn_version eq $svn_version) {
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
	} else {
		print "$version_file is up-to-date.\n";
	}
}

# Read values from the configuration file, if it exists.
sub get_config {
	my $arg;

	# Get our command-line args
	GetOptions("package-version", \$pkg_version);

	if ($#ARGV >= 0) {
		$srcdir = $ARGV[0]
	}

	if (! open(FILE, "<$vconf_file")) {
		print STDERR "Version configuration file $vconf_file not "
		. "found.  Using defaults.\n";
		return 1;
	}

	while (<FILE>) {
		chomp;
		next if (/^#/);
		next unless (/^(\w+)(:|=)\s*(\S.*)/);
		$version_pref{$1} = $3;
	}
	close FILE;
	return 1;
}

##
## Start of code
##

&get_config();

if (-d "$srcdir/.svn") {
	$svn_info_cmd = "svn info $srcdir";
} elsif (-d "$srcdir/.git/svn") {
	$svn_info_cmd = "(cd $srcdir; git svn info)";
}

if ($svn_info_cmd) {
	print "This is a build from SVN (or a SVN snapshot).\n";
	&read_svn_info();
	if ($pkg_version) {
		print "Generating package version.  Ignoring $version_file\n";
		&update_configure_in;
		&update_config_nmake;
	} elsif ($version_pref{"enable"} == 0) {
		print "Version tag disabled in $vconf_file.\n";
		$last_change = 0;
		$revision = 0;
	} else {
		print "SVN version tag will be computed.\n";
	}
} else {
	print "This is not a SVN build.\n";
}

&print_svn_version;

__END__
