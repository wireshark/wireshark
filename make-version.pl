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

# See below for usage
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
use Pod::Usage;
use IO::Handle;
use English;

my $version_file = 'svnversion.h';
my $package_string = "";
my $vconf_file = 'version.conf';
my $tortoise_file = "tortoise_template";
my $last_change = 0;
my $revision = 0;
my $repo_path = "unknown";
my $get_svn = 0;
my $set_version = 0;
my $set_release = 0;
my %version_pref = (
	"version_major" => 1,
	"version_minor" => 7,
	"version_micro" => 1,
	"version_build" => 0,

	"enable"        => 1,
	"svn_client"    => 1,
	"tortoise_svn"  => 0,
	"format"        => "SVN %Y%m%d%H%M%S",
	"is_release"    => 0,

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
	my $info_source = "Unknown";

	if ($version_pref{"pkg_enable"}) {
		$package_format = $version_pref{"pkg_format"};
	}

	if (-d "$srcdir/.svn") {
		$info_source = "Command line (svn info)";
		$svn_info_cmd = "svn info $srcdir";
	} elsif (-d "$srcdir/.git/svn") {
		$info_source = "Command line (git-svn)";
		$svn_info_cmd = "(cd $srcdir; git svn info)";
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
	} elsif ($version_pref{"tortoise_svn"}) {
		# Dynamically generic template file needed by TortoiseSVN
		open(TORTOISE, ">$tortoise_file");
		print TORTOISE "#define SVNVERSION \"\$WCREV\$\"\r\n";
		print TORTOISE "#define SVNPATH \"\$WCURL\$\"\r\n";
		close(TORTOISE);

		$info_source = "Command line (SubWCRev)";
		$svn_info_cmd = "SubWCRev $srcdir $tortoise_file $version_file";
		my $tortoise = system($svn_info_cmd);
		if ($tortoise == 0) {
			$do_hack = 0;
		}

		#clean up the template file
		unlink($tortoise_file);
	}

	if ($revision == 0) {
		# Fall back to config.nmake
		$info_source = "Prodding config.nmake";
		my $filepath = "config.nmake";
		open(CFGNMAKE, "< $filepath") || die "Can't read $filepath!";
		while ($line = <CFGNMAKE>) {
			if ($line =~ /^SVN_REVISION=(\d+)/) {
				$revision = $1;
				$do_hack = 0;
				last;
			}
		}
		close (CFGNMAKE);
	}

	# 'svn info' failed or the user really wants us to dig around in .svn/entries
	if ($do_hack) {
		# Start of ugly internal SVN file hack
		if (! open (ENTRIES, "< $srcdir/.svn/entries")) {
			print ("Unable to open $srcdir/.svn/entries\n");
		} else {
			$info_source = "Prodding .svn";
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

	if ($get_svn) {
		print <<"Fin";
SVN revision    : $revision
Revision source : $info_source
Release stamp   : $package_string
Fin
	}
}


# Read configure.in, then write it back out with an updated
# "AC_INIT" line.
sub update_configure_in
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "configure.in";

	return if (!$set_version && $package_string eq "");

	open(CFGIN, "< $filepath") || die "Can't read $filepath!";
	while ($line = <CFGIN>) {
		if ($line =~ /^AC_INIT\(wireshark, (\d+)\.(\d+).(\d+)/) {
			$line = sprintf("AC_INIT\(wireshark, %d.%d.%d%s)\n",
					$set_version ? $version_pref{"version_major"} : $1,
					$set_version ? $version_pref{"version_minor"} : $2,
					$set_version ? $version_pref{"version_micro"} : $3,
					$set_release ? $package_string : ""
				       );

		}
		$contents .= $line
	}

	open(CFGIN, "> $filepath") || die "Can't write $filepath!";
	print(CFGIN $contents);
	close(CFGIN);
	print "$filepath has been updated.\n";
}

# Read config.nmake, then write it back out with an updated
# "VERSION" line.
sub update_config_nmake
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "config.nmake";

	open(CFGNMAKE, "< $filepath") || die "Can't read $filepath!";
	while ($line = <CFGNMAKE>) {
		if ($line =~ /^SVN_REVISION=/) {
			$line = sprintf("SVN_REVISION=%d\n", $revision);
		} elsif ($set_version && $line =~ /^VERSION_MAJOR=/) {
			$line = sprintf("VERSION_MAJOR=%d\n", $version_pref{"version_major"});
		} elsif ($set_version && $line =~ /^VERSION_MINOR=/) {
			$line = sprintf("VERSION_MINOR=%d\n", $version_pref{"version_minor"});
		} elsif ($set_version && $line =~ /^VERSION_MICRO=/) {
			$line = sprintf("VERSION_MICRO=%d\n", $version_pref{"version_micro"});
		} elsif ($line =~ /^VERSION_EXTRA=/) {
			$line = "VERSION_EXTRA=$package_string\n";
		}
		$contents .= $line
	}

	open(CFGNMAKE, "> $filepath") || die "Can't write $filepath!";
	print(CFGNMAKE $contents);
	close(CFGNMAKE);
	print "$filepath has been updated.\n";
}

# Read docbook/release_notes.xml, then write it back out with an updated
# "WiresharkCurrentVersion" line.
sub update_release_notes
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "docbook/release-notes.xml";

	return if (!$set_version);

	open(RELNOTES, "< $filepath") || die "Can't read $filepath!";
	while ($line = <RELNOTES>) {
		#   <!ENTITY WiresharkCurrentVersion "1.7.1">

		if ($line =~ /<\!ENTITY\s+WiresharkCurrentVersion\s+/) {
			$line = sprintf("<!ENTITY WiresharkCurrentVersion \"%d.%d.%d\"\n",
					$version_pref{"version_major"},
					$version_pref{"version_minor"},
					$version_pref{"version_micro"},
				       );
		}
		$contents .= $line
	}

	open(RELNOTES, "> $filepath") || die "Can't write $filepath!";
	print(RELNOTES $contents);
	close(RELNOTES);
	print "$filepath has been updated.\n";
}

# Read debian/changelog, then write back out an updated version.
sub update_debian_changelog
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "debian/changelog";

	return if ($set_version == 0);

	open(CHANGELOG, "< $filepath") || die "Can't read $filepath!";
	while ($line = <CHANGELOG>) {
		if ($set_version && CHANGELOG->input_line_number() == 1) {
			$line = sprintf("wireshark (%d.%d.%d) unstable; urgency=low\n",
					$version_pref{"version_major"},
					$version_pref{"version_minor"},
					$version_pref{"version_micro"},
				       );
		}
		$contents .= $line
	}

	open(CHANGELOG, "> $filepath") || die "Can't write $filepath!";
	print(CHANGELOG $contents);
	close(CHANGELOG);
	print "$filepath has been updated.\n";
}

# Update distributed files that contain any version information
sub update_versioned_files
{
	&update_configure_in;
	&update_config_nmake;
	&update_release_notes;
	&update_debian_changelog;
}

# Print the SVN version to $version_file.
# Don't change the file if it is not needed.
sub print_svn_revision
{
	my $svn_revision;
	my $needs_update = 1;

	if ($last_change && $revision) {
		$svn_revision = "#define SVNVERSION \"SVN Rev " .
			$revision . "\"\n" .
			"#define SVNPATH \"" . $repo_path . "\"\n";
	} else {
		$svn_revision = "#define SVNVERSION \"SVN Rev Unknown\"\n" .
			"#define SVNPATH \"unknown\"\n";
	}
	if (open(OLDREV, "<$version_file")) {
		my $old_svn_revision = <OLDREV> . <OLDREV>;
		if ($old_svn_revision eq $svn_revision) {
			$needs_update = 0;
		}
		close OLDREV;
	}

	if (! $set_version && ! $set_release) { return; }

	if ($needs_update) {
		# print "Updating $version_file so it contains:\n$svn_revision";
		open(VER, ">$version_file") || die ("Cannot write to $version_file ($!)\n");
		print VER "$svn_revision";
		close VER;
		print "$version_file has been updated.\n";
	} else {
		print "$version_file unchanged.\n";
	}
}

# Read values from the configuration file, if it exists.
sub get_config {
	my $arg;
	my $show_help = 0;

	# Get our command-line args
	GetOptions(
		   "help|h", \$show_help,
		   "get-svn|g", \$get_svn,
		   "set-version|v", \$set_version,
		   "set-release|r|package-version|p", \$set_release
		   ) || pod2usage(2);

	if ($show_help) { pod2usage(1); }

	if ( !( $show_help || $get_svn || $set_release ) ) {
		$set_version = 1;
	}

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

&read_svn_info();

&print_svn_revision;

if ($set_version || $set_release) {
	if ($set_version) {
		print "Generating version information\n";
	}

	if ($version_pref{"enable"} == 0) {
		print "Release information disabled in $vconf_file.\n";
		$set_release = 0;
	}

	if ($set_release) {
		print "Generating release information\n";
	}

	&update_versioned_files;
}

__END__

=head1 NAM

make-version.pl - Get and set build-time version information for Wireshark

=head1 SYNOPSIS

make-version.pl [options] [source directory]

  Options:

    --help, -h                 This help message
    --get-svn, -g              Print the SVN revision and source.
    --set-version, -v          Set the major, minor, and micro versions.
                               Resets the release information when used by
			       itself.
    --set-release, -r          Set the release information.
    --package-version, -p      Deprecated. Same as --set-release.

Options can be used in any combination. If none are specified B<--set-version>
is assumed.
