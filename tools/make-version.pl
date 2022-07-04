#!/usr/bin/perl -w
#
# Copyright 2004 Jörg Mayer (see AUTHORS file)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# See below for usage.
#
# If run with the "-r" or "--set-release" argument the VERSION macro in
# CMakeLists.txt will have the version_extra template appended to the
# version number. vcs_version.h will _not_ be generated if either argument is
# present.
#
# make-version.pl is called during the build to update vcs_version.h in the build
# directory. To set a fixed version, use something like:
#
#   cmake -DVCSVERSION_OVERRIDE="Git v3.1.0 packaged as 3.1.0-1"
#

# XXX - We're pretty dumb about the "{vcsinfo}" substitution, and about having
# spaces in the package format.

use strict;

use Time::Local;
use File::Basename;
use File::Spec;
use POSIX qw(strftime);
use Getopt::Long;
use Pod::Usage;
use IO::Handle;
use English;

my $version_major = undef;
my $version_minor = undef;
my $version_micro = undef;
my $tagged_version_extra = "";
my $untagged_version_extra = "-{vcsinfo}";
my $force_extra = undef;
my $package_string = "";
my $version_file = 'vcs_version.h';
my $vcs_name = "Git";
my $last_change = 0;
my $num_commits = 0;
my $commit_id = '';
my $git_description = undef;
my $get_vcs = 0;
my $set_vcs = 0;
my $print_vcs = 0;
my $set_version = undef;
my $set_release = 0;
my $is_tagged = 0;
my $git_client = 0;
my $svn_client = 0;
my $git_svn = 0;
my $script_dir = dirname(__FILE__);
my $src_dir = "$script_dir/..";
my $verbose = 0;
my $devnull = File::Spec->devnull();
my $enable_vcsversion = 1;

# Ensure we run with correct locale
$ENV{LANG} = "C";
$ENV{LC_ALL} = "C";
$ENV{GIT_PAGER} = "";

sub print_diag {
	print STDERR @_ if $verbose;
}

# Attempt to get revision information from the repository.
sub read_repo_info {
	return if ($set_version);

	my $line;
	my $release_candidate = "";
	my $in_entries = 0;
	my $svn_name;
	my $repo_version;
	my $info_source = "Unknown";
	my $is_git_repo = 0;
	my $git_abbrev_length = 12;
	my $git_cdir;
	my $vcs_tag;
	my $repo_branch = "unknown";
	my $info_cmd = "";

	# Tarball produced by 'git archive' will have the $Format string
	# substituted due to the use of 'export-subst' in .gitattributes.
	my $git_archive_commit = '$Format:%H$';
	my @git_refs = split(/, /, '$Format:%D$');
	if (substr($git_archive_commit, 0, 1) eq '$') {
		# If $Format is still present, then this is not a git archive.
		$git_archive_commit = undef;
	} else {
		foreach my $git_ref (@git_refs) {
			if ($git_ref =~ /^tag: (v[1-9].+)/) {
				$vcs_tag = $1;
				$is_tagged = 1;
			}
		}
	}

	$package_string = $untagged_version_extra;

	# For tarball releases, do not invoke git at all and instead rely on
	# versioning information that was provided at tarball creation time.
	if ($git_archive_commit) {
		$info_source = "git archive";
	} elsif (-e "$src_dir/.git" && ! -d "$src_dir/.git/svn") {
		$info_source = "Command line (git)";
		$git_client = 1;
		$is_git_repo = 1;
	} elsif (-d "$src_dir/.svn" or -d "$src_dir/../.svn") {
		$info_source = "Command line (svn info)";
		$info_cmd = "cd $src_dir; svn info";
		$svn_client = 1;
	} elsif (-d "$src_dir/.git/svn") {
		$info_source = "Command line (git-svn)";
		$info_cmd = "(cd $src_dir; git svn info)";
		$is_git_repo = 1;
		$git_svn = 1;
	}

	# Make sure git is available.
	if ($is_git_repo && !`git --version`) {
		print STDERR "Git unavailable. Git revision will be missing from version string.\n";
		return;
	}

	# Check whether to include VCS version information in vcs_version.h
	if ($is_git_repo) {
		chomp($git_cdir = qx{git --git-dir="$src_dir/.git" rev-parse --git-common-dir 2> $devnull});
		if ($git_cdir && -f "$git_cdir/wireshark-disable-versioning") {
			print_diag "Header versioning disabled using git override.\n";
			$enable_vcsversion = 0;
		}
	}

	#Git can give us:
	#
	# A big ugly hash: git rev-parse HEAD
	# efd7cb38e67cbfd3333a8c2fd4bc47aaec4ba83c
	#
	# A small ugly hash: git rev-parse --short HEAD
	# efd7cb38e6
	#
	# The upstream branch path: git rev-parse --abbrev-ref --symbolic-full-name @{upstream}
	# origin/master
	#
	# A version description: git describe --tags --dirty
	# v3.3.0rc0-1829-gefd7cb38e6
	#
	# Number of commits in this branch: git rev-list --count HEAD
	# 78451
	#
	# Number of commits since v3.3.0rc0: git rev-list --count beb1fee6586725bd37651b8a73a1ef51888e99be..HEAD
	# 1829
	#   Where git show-ref --tags -d | grep v3.3.0 | grep '{}'
	#   beb1fee6586725bd37651b8a73a1ef51888e99be refs/tags/v3.3.0rc0^{}
	#
	# Refs: git ls-remote https://gitlab.com/wireshark/wireshark.git | head -n1
	# efd7cb38e67cbfd3333a8c2fd4bc47aaec4ba83c	HEAD

	if ($git_archive_commit) {
		# Assume a full commit hash, abbreviate it.
		$commit_id = substr($git_archive_commit, 0, $git_abbrev_length);
	} elsif ($git_client) {
		eval {
			use warnings "all";
			no warnings "all";

			chomp($line = qx{git --git-dir="$src_dir"/.git log -1 --pretty=format:%at});
			if ($? == 0 && length($line) > 1) {
				$last_change = $line;
			}

			# Commits since last annotated tag.
			chomp($line = qx{git --git-dir="$src_dir"/.git describe --abbrev=$git_abbrev_length --long --always --match "v[1-9]*"});
			if ($? == 0 && length($line) > 1) {
				my @parts = split(/-/, $line);
				$git_description = $line;
				$num_commits = $parts[-2] ? $parts[-2] : "0";
				$commit_id = $parts[-1];

				if ($line =~ /v\d+\.\d+\.\d+(rc\d+)-/) {
					$release_candidate = $1;
				}

				chomp($vcs_tag = qx{git --git-dir="$src_dir"/.git describe --exact-match --match "v[1-9]*" 2> $devnull});
				$is_tagged = ! ($? >> 8);
			}

			# This will break in some cases. Hopefully not during
			# official package builds.
			chomp($line = qx{git --git-dir="$src_dir"/.git rev-parse --abbrev-ref --symbolic-full-name \@\{upstream\} 2> $devnull});
			if ($? == 0 && length($line) > 1) {
				$repo_branch = basename($line);
			}

			1;
		};
	} elsif ($svn_client || $git_svn) {
		my $repo_root = undef;
		my $repo_url = undef;
		eval {
			use warnings "all";
			no warnings "all";
			$line = qx{$info_cmd};
			if (defined($line)) {
				if ($line =~ /Last Changed Date: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
					$last_change = timegm($6, $5, $4, $3, $2 - 1, $1);
				}
				if ($line =~ /Last Changed Rev: (\d+)/) {
					$num_commits = $1;
				}
				if ($line =~ /URL: (\S+)/) {
					$repo_url = $1;
				}
				if ($line =~ /Repository Root: (\S+)/) {
					$repo_root = $1;
				}
				$vcs_name = "SVN";
			}
			1;
		};

		if ($repo_url && $repo_root && index($repo_url, $repo_root) == 0) {
			$repo_branch = substr($repo_url, length($repo_root));
		}
	}

	if (defined $num_commits and $num_commits == 0 and -e "$src_dir/.git") {

		# Try git...
		eval {
			use warnings "all";
			no warnings "all";
			# If someone had properly tagged 1.9.0 we could also use
			# "git describe --abbrev=1 --tags HEAD"

			$info_cmd = "(cd $src_dir; git log --format='%b' -n 1)";
			$line = qx{$info_cmd};
			if (defined($line)) {
				if ($line =~ /svn path=.*; revision=(\d+)/) {
					$num_commits = $1;
				}
			}
			$info_cmd = "(cd $src_dir; git log --format='%ad' -n 1 --date=iso)";
			$line = qx{$info_cmd};
			if (defined($line)) {
				if ($line =~ /(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
					$last_change = timegm($6, $5, $4, $3, $2 - 1, $1);
				}
			}
			$info_cmd = "(cd $src_dir; git branch)";
			$line = qx{$info_cmd};
			if (defined($line)) {
				if ($line =~ /\* (\S+)/) {
					$repo_branch = $1;
				}
			}
			1;
			};
	}

	if ($force_extra) {
		if ($force_extra eq "tagged") {
			$is_tagged = 1;
		} elsif ($force_extra eq "untagged") {
			$is_tagged = 0;
		}
	}

	if ($is_tagged) {
		print "We are on tag $vcs_tag.\n";
		$package_string = $tagged_version_extra;
	} else {
		print "We are not tagged.\n";
	}

	# If we picked up the revision and modification time,
	# generate our strings.
	if ($package_string) {
		if(defined $num_commits){
			if($commit_id){
				$package_string =~ s/{vcsinfo}/$num_commits-$commit_id/;
			}else{
				$package_string =~ s/{vcsinfo}/$num_commits/;
			}
		}
		else{
			if($commit_id){
				$package_string =~ s/{vcsinfo}/-$commit_id/;
			}else{
				$package_string =~ s/{vcsinfo}//;
			}
		}
	}
	$package_string = $release_candidate . $package_string;

	if ($get_vcs) {
		print <<"Fin";
Commit distance : $num_commits
Commit ID       : $commit_id
Revision source : $info_source
Release stamp   : $package_string
Fin
	} elsif ($print_vcs) {
		print new_version_h();
	}
}


# Read CMakeLists.txt, then write it back out with updated "set(PROJECT_..._VERSION ...)
# lines
# set(GIT_REVISION 999)
# set(PROJECT_MAJOR_VERSION 1)
# set(PROJECT_MINOR_VERSION 99)
# set(PROJECT_PATCH_VERSION 0)
# set(PROJECT_VERSION_EXTENSION "-rc5")
sub update_cmakelists_txt
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "$src_dir/CMakeLists.txt";

	return if (!$set_version && $package_string eq "");

	open(CFGIN, "< $filepath") || die "Can't read $filepath!";
	while ($line = <CFGIN>) {
		if ($line =~ /^set *\( *GIT_REVISION .*?([\r\n]+)$/) {
			$line = sprintf("set(GIT_REVISION %d)$1", $num_commits);
		} elsif ($line =~ /^set *\( *PROJECT_MAJOR_VERSION .*?([\r\n]+)$/) {
			$line = sprintf("set(PROJECT_MAJOR_VERSION %d)$1", $version_major);
		} elsif ($line =~ /^set *\( *PROJECT_MINOR_VERSION .*?([\r\n]+)$/) {
			$line = sprintf("set(PROJECT_MINOR_VERSION %d)$1", $version_minor);
		} elsif ($line =~ /^set *\( *PROJECT_PATCH_VERSION .*?([\r\n]+)$/) {
			$line = sprintf("set(PROJECT_PATCH_VERSION %d)$1", $version_micro);
		} elsif ($line =~ /^set *\( *PROJECT_VERSION_EXTENSION .*?([\r\n]+)$/) {
			$line = sprintf("set(PROJECT_VERSION_EXTENSION \"%s\")$1", $package_string);
		}
		$contents .= $line
	}

	open(CFGIN, "> $filepath") || die "Can't write $filepath!";
	print(CFGIN $contents);
	close(CFGIN);
	print "$filepath has been updated.\n";
}

# Read docbook/attributes.adoc, then write it back out with an updated
# wireshark-version replacement line.
sub update_attributes_asciidoc
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "$src_dir/docbook/attributes.adoc";

	open(ADOC_CONF, "< $filepath") || die "Can't read $filepath!";
	while ($line = <ADOC_CONF>) {
		# :wireshark-version: 2.3.1

		if ($line =~ /^:wireshark-version:.*?([\r\n]+)$/) {
			$line = sprintf(":wireshark-version: %d.%d.%d$1",
					$version_major,
					$version_minor,
					$version_micro,
					);
		}
		$contents .= $line
	}

	open(ADOC_CONF, "> $filepath") || die "Can't write $filepath!";
	print(ADOC_CONF $contents);
	close(ADOC_CONF);
	print "$filepath has been updated.\n";
}

sub update_docinfo_asciidoc
{
	my $line;
	my @paths = ("$src_dir/docbook/developer-guide-docinfo.xml",
			"$src_dir/docbook/user-guide-docinfo.xml");

	foreach my $filepath (@paths) {
		my $contents = "";
		open(DOCINFO_XML, "< $filepath") || die "Can't read $filepath!";
		while ($line = <DOCINFO_XML>) {
			if ($line =~ /^<subtitle>For Wireshark \d.\d+<\/subtitle>([\r\n]+)$/) {
				$line = sprintf("<subtitle>For Wireshark %d.%d</subtitle>$1",
						$version_major,
						$version_minor,
						);
			}
			$contents .= $line
		}

		open(DOCINFO_XML, "> $filepath") || die "Can't write $filepath!";
		print(DOCINFO_XML $contents);
		close(DOCINFO_XML);
		print "$filepath has been updated.\n";
	}
}

# Read packaging/debian/changelog, then write back out an updated version.
sub update_debian_changelog
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filepath = "$src_dir/packaging/debian/changelog";

	open(CHANGELOG, "< $filepath") || die "Can't read $filepath!";
	while ($line = <CHANGELOG>) {
		if (CHANGELOG->input_line_number() == 1) {
			$line =~ /^.*?([\r\n]+)$/;
			$line = sprintf("wireshark (%d.%d.%d%s) unstable; urgency=low$1",
					$version_major,
					$version_minor,
					$version_micro,
					$package_string,
					);
		}
		$contents .= $line
	}

	open(CHANGELOG, "> $filepath") || die "Can't write $filepath!";
	print(CHANGELOG $contents);
	close(CHANGELOG);
	print "$filepath has been updated.\n";
}

# Read CMakeLists.txt for each library, then write back out an updated version.
sub update_cmake_lib_releases
{
	my $line;
	my $contents = "";
	my $version = "";
	my $filedir;
	my $filepath;

	for $filedir ("$src_dir/epan", "$src_dir/wiretap") {	# "$src_dir/wsutil"
		$contents = "";
		$filepath = $filedir . "/CMakeLists.txt";
		open(CMAKELISTS_TXT, "< $filepath") || die "Can't read $filepath!";
		while ($line = <CMAKELISTS_TXT>) {
			#	VERSION "0.0.0" SOVERSION 0

			if ($line =~ /^(\s*VERSION\s+"\d+\.\d+\.)\d+(".*[\r\n]+)$/) {
				$line = sprintf("$1%d$2", $version_micro);
			}
			$contents .= $line
		}

		open(CMAKELISTS_TXT, "> $filepath") || die "Can't write $filepath!";
		print(CMAKELISTS_TXT $contents);
		close(CMAKELISTS_TXT);
		print "$filepath has been updated.\n";
	}
}

# Update distributed files that contain any version information
sub update_versioned_files
{
	# Matches CMakeLists.txt
	printf "GR: %d, MaV: %d, MiV: %d, PL: %d, EV: %s\n",
		$num_commits, $version_major,
		$version_minor, $version_micro,
		$package_string;
	&update_cmakelists_txt;
	&update_debian_changelog;
	if ($set_version) {
		&update_attributes_asciidoc;
		&update_docinfo_asciidoc;
		&update_cmake_lib_releases;
	}
}

sub new_version_h
{
	my $line;
	if (!$enable_vcsversion) {
		return "/* #undef VCSVERSION */\n";
	}

	if ($git_description) {
		# Do not bother adding the git branch, the git describe output
		# normally contains the base tag and commit ID which is more
		# than sufficient to determine the actual source tree.
		return "#define VCSVERSION \"$git_description\"\n";
	}

	if ($last_change && $num_commits) {
		$line = sprintf("v%d.%d.%d",
			$version_major,
			$version_minor,
			$version_micro,
			);
		return "#define VCSVERSION \"$line-$vcs_name-$num_commits\"\n";
	}

	if ($commit_id) {
		return "#define VCSVERSION \"$vcs_name commit $commit_id\"\n";
	}

	return "#define VCSVERSION \"$vcs_name Rev Unknown from unknown\"\n";
}

# Print the version control system's version to $version_file.
# Don't change the file if it is not needed.
#
# XXX - We might want to add VCSVERSION to CMakeLists.txt so that it can
# generate vcs_version.h independently.
sub print_VCS_REVISION
{
	my $VCS_REVISION;
	my $needs_update = 1;

	$VCS_REVISION = new_version_h();
	if (open(OLDREV, "<$version_file")) {
		my $old_VCS_REVISION = <OLDREV>;
		if ($old_VCS_REVISION eq $VCS_REVISION) {
			$needs_update = 0;
		}
		close OLDREV;
	}

	if (! $set_vcs) { return; }

	if ($needs_update) {
		# print "Updating $version_file so it contains:\n$VCS_REVISION";
		open(VER, ">$version_file") || die ("Cannot write to $version_file ($!)\n");
		print VER "$VCS_REVISION";
		close VER;
		print "$version_file has been updated.\n";
	} elsif (!$enable_vcsversion) {
		print "$version_file disabled.\n";
	} else {
		print "$version_file unchanged.\n";
	}
}

# Read our major, minor, and micro version from CMakeLists.txt.
sub get_version
{
	my $line;
	my $filepath = "$src_dir/CMakeLists.txt";

	open(CFGIN, "< $filepath") || die "Can't read $filepath!";
	while ($line = <CFGIN>) {
		$line =~ s/^\s+|\s+$//g;
		if ($line =~ /^set *\( *PROJECT_MAJOR_VERSION *(\d+) *\)$/) {
			$version_major = $1;
		} elsif ($line =~ /^set *\( *PROJECT_MINOR_VERSION *(\d+) *\)$/) {
			$version_minor = $1;
		} elsif ($line =~ /^set *\( *PROJECT_PATCH_VERSION *(\d+) *\)$/) {
			$version_micro = $1;
		}
	}

	close(CFGIN);

	die "Couldn't get major version" if (!defined($version_major));
	die "Couldn't get minor version" if (!defined($version_minor));
	die "Couldn't get micro version" if (!defined($version_micro));
}

# Read values from the configuration file, if it exists.
sub get_config {
	my $arg;
	my $show_help = 0;

	# Get our command-line args
	# XXX - Do we need an option to undo --set-release?
	GetOptions(
		   "help|h", \$show_help,
		   "tagged-version-extra|t=s", \$tagged_version_extra,
		   "untagged-version-extra|u=s", \$untagged_version_extra,
		   "force-extra|f=s", \$force_extra,
		   "get-vcs|g", \$get_vcs,
		   "set-vcs|s", \$set_vcs,
		   "print-vcs", \$print_vcs,
		   "set-version|v=s", \$set_version,
		   "set-release|r", \$set_release,
		   "verbose", \$verbose
		   ) || pod2usage(2);

	if ($show_help) { pod2usage(1); }

	if ( !( $show_help || $get_vcs || $set_vcs || $print_vcs || $set_version || $set_release ) ) {
		$set_vcs = 1;
	}

	if ($force_extra && !($force_extra eq "tagged" || $force_extra eq "untagged")) {
		die "force-extra must be one of \"tagged\" or \"untagged\".\n";
	}

	if ($set_version) {
		if ($set_version =~ /^(\d+)\.(\d+)\.(\d+)/) {
			$version_major = $1;
			$version_minor = $2;
			$version_micro = $3;
		} else {
			die "\"$set_version\" isn't a version.\n";
		}
	}

	if ($#ARGV >= 0) {
		$src_dir = $ARGV[0]
	}

	return 1;
}

##
## Start of code
##

&get_version();

&get_config();

if (! $set_version) {
	&read_repo_info();
}

&print_VCS_REVISION;

if ($set_version || $set_release) {
	if ($set_version) {
		print "Generating version information.\n";
	}

	&update_versioned_files;
}

__END__

=head1 NAM

make-version.pl - Get and set build-time version information for Wireshark

=head1 SYNOPSIS

make-version.pl [options] [source directory]

=head1 OPTIONS

=over 4

=item --help, -h

Show this help message.

=item --tagged-version-extra=<format>, -t <format>

Extra version information format to use when a tag is found. No format
(an empty string) is used by default.

=item --untagged-version-extra, -u <format>

Extra version information format to use when no tag is found. The format
"-{vcsinfo}" (the number of commits and commit ID) is used by default.

=item --force-extra=<tagged,untagged>, -f <tagged,untagged>

Force either the tagged or untagged format to be used.

=item --get-vcs, -g

Print the VCS revision and source.

=item --print-vcs

Print the vcs version to standard output

=item --set-version=<x.y.z>, -v <x.y.z>

Set the major, minor, and micro versions in the top-level
CMakeLists.txt, configure.ac, docbook/attributes.adoc,
packaging/debian/changelog, and the CMakeLists.txt for all libraries
to the provided version number.

=item --set-release, -r

Set the extra release information in the top-level CMakeLists.txt
based on either default or command-line specified options.

=item --verbose

Print diagnostic messages to STDERR.

=back

=cut

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
#
