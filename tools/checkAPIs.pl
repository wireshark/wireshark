#!/usr/bin/env perl

#
# Copyright 2006, Jeff Morriss <jeff.morriss[AT]ulticom.com>
#
# A simple tool to check source code for function calls that should not
# be called by Wireshark code.
#
# Usage:
# checkAPIs.pl [-g group1] [-g group2] file1 file2 ...
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

use strict;
use Getopt::Long;

my %APIs = (
	# API groups.
	# # Group name, e.g. 'prohibited'
	# '<name>' => {
	#   # 1 if these are errors, 0 if warnings
	#   'count_errors' => 1,
	#   # Function list
	#   'functions' => [ 'f1', f2', ... ] },

	# APIs that MUST NOT be used in Wireshark
	'prohibited' => { 'count_errors' => 1, 'functions' => [
		# Memory-unsafe APIs
		# Use something that won't overwrite the end of your buffer instead
		# of these:
		'gets',
		'sprintf',
		'vsprintf',
		'strcpy',
		'strncpy',
		'strcat',
		'strncat',
		'cftime',
		'ascftime',
		### non-portable APIs
		# use glib (g_*) versions instead of these:
		'ntohl',
		'ntohs',
		'htonl',
		'htons',
		'strdup',
		'strndup',
		### non-ANSI C
		# use memset, memcpy, memcmp instead of these:
		'bzero',
		'bcopy',
		'bcmp',
		# use ep_*, se_*, or g_* functions instead of these:
		# (One thing to be aware of is that space allocated with malloc()
		# may not be freeable--at least on Windows--with g_free() and
		# vice-versa.)
		'malloc',
		'free',
		# Locale-unsafe APIs
		# These may have unexpected behaviors in some locales (e.g.,
		# "I" isn't always the upper-case form of "i", and "i" isn't
		# always the lower-case form of "I").  Use the g_ascii_* version
		# instead.
		'strcasecmp',
		'strncasecmp',
		'g_strcasecmp',
		'g_strncasecmp',
		'g_strup',
		'g_strdown',
		'g_string_up',
		'g_string_down',
		# Use the ws_* version of these:
		# (Necessary because on Windows we use UTF8 for throughout the code
		# so we must tweak that to UTF16 before operating on the file.  Code
		# using these functions will work unless the file/path name contains
		# non-ASCII chars.)
		'open',
		'rename',
		'mkdir',
		'stat',
		'unlink',
		'remove',
		'fopen',
		'freopen',
		# Misc
		'tmpnam'            # use mkstemp
	]},

	# APIs that SHOULD NOT be used in Wireshark (any more)
	'deprecated' => { 'count_errors' => 0, 'functions' => [
		### Depreciated glib functions
		# use g_string_printf() instead of:
		'g_string_sprintf',
		# use g_string_append_printf instead of:
		'g_string_sprintfa',
		'g_tree_traverse',
		'g_basename',
		'g_dirname',
		'g_hash_table_freeze',
		'g_hash_table_thaw',
		'G_HAVE_GINT64',
		'g_io_channel_close',
		'g_io_channel_read',
		'g_io_channel_seek',
		'g_io_channel_write',
		'g_main_new',
		'g_main_destroy',
		'g_main_run',
		'g_main_set_poll_func',
		'g_scanner_add_symbol',
		'g_scanner_remove_symbol',
		'g_scanner_foreach_symbol',
		'g_scanner_freeze_symbol_table',
		'g_scanner_thaw_symbol_table',
		# Wireshark should not write to stdout (?)
		# (Of course tshark should!)
		'printf',
		'perror',
		# Use PROTO_ITEM_SET_HIDDEN instead of these:
		'proto_tree_add_item_hidden',
		'proto_tree_add_bytes_hidden',
		'proto_tree_add_time_hidden',
		'proto_tree_add_ipxnet_hidden',
		'proto_tree_add_ipv4_hidden',
		'proto_tree_add_ipv6_hidden',
		'proto_tree_add_ether_hidden',
		'proto_tree_add_guid_hidden',
		'proto_tree_add_oid_hidden',
		'proto_tree_add_string_hidden',
		'proto_tree_add_boolean_hidden',
		'proto_tree_add_float_hidden',
		'proto_tree_add_double_hidden',
		'proto_tree_add_uint_hidden',
		'proto_tree_add_int_hidden',
		]},

	# APIs that make the program exit. Dissectors shouldn't call these
	'abort' => { 'count_errors' => 1, 'functions' => [
		'abort',
		'exit',
		'g_assert',
		'g_error',
		]},

);


# Given a list of APIs and the contents of a file, see if the API appears
# in the file.  If so, push the API onto the provided list.
sub findAPIinList($$$)
{
    my ($apiList, $fileContentsRef, $foundAPIsRef)=@_;

    for my $api (@{$apiList})
    {
        if ($$fileContentsRef =~ m/\W$api\W*\(/)
        {
            push @{$foundAPIsRef},$api;
        }
    }
}

# The below Regexp are based on those from:
# http://aspn.activestate.com/ASPN/Cookbook/Rx/Recipe/59811
# They are in the public domain.

# 1. A complicated regex which matches C-style comments.
my $CComment = qr{/\*[^*]*\*+([^/*][^*]*\*+)*/};

# 1.a A regex that matches C++-style comments.
#my $CppComment = qr{//(.*?)\n};

# 2. A regex which matches double-quoted strings.
my $DoubleQuotedStr = qr{(?:\"(?:\\.|[^\"\\])*\")};

# 3. A regex which matches single-quoted strings.
my $SingleQuotedStr = qr{(?:\'(?:\\.|[^\'\\])*\')};

# 4. Now combine 1 through 3 to produce a regex which
#    matches _either_ double or single quoted strings
#    OR comments. We surround the comment-matching
#    regex in capturing parenthesis to store the contents
#    of the comment in $1.
#    my $commentAndStringRegex = qr{(?:$DoubleQuotedStr|$SingleQuotedStr)|($CComment)|($CppComment)};

# 4. Wireshark is strictly a C program so don't take out C++ style comments
#    since they shouldn't be there anyway...
my $commentAndStringRegex = qr{(?:$DoubleQuotedStr|$SingleQuotedStr)|($CComment)};

#
# MAIN
#
my $errorCount = 0;
# The default list, which can be expanded.
my @apiGroups = qw(prohibited deprecated);

GetOptions('g=s' => \@apiGroups);
while ($_ = $ARGV[0])
{
	shift;
	my $filename = $_;
	my $fileContents = '';
	my @foundAPIs = ();

	die "No such file: \"$filename\"" if (! -e $filename);

	# delete leading './'
	$filename =~ s@^\./@@;

	# Read in the file (ouch, but it's easier that way)
	open(FC, $filename) || die("Couldn't open $filename");
	while (<FC>) { $fileContents .= $_; }
	close(FC);

	if ($fileContents =~ m{[\x80-\xFF]})
	{
		print STDERR "Warning: Found non-ASCII characters in " .$filename."\n";
#		Treat as warning
#		$errorCount++;
	}

	if ($fileContents =~ m{%ll})
	{
		# use G_GINT64_MODIFIER instead of ll
		print STDERR "Error: Found %ll in " .$filename."\n";
		$errorCount++;
	}

	if (! ($fileContents =~ m{\$Id.*\$}))
	{
		print STDERR "Warning: ".$filename." does not have an SVN Id tag.\n";
	}

	# Remove all the C-comments and strings
	$fileContents =~ s {$commentAndStringRegex} []g;

        if ($fileContents =~ m{//})
        {
		print STDERR "Error: Found C++ style comments in " .$filename."\n";
		$errorCount++;
        }

	for my $apiName (@apiGroups) {
		my $pfx = "Warning";
		@foundAPIs = ();

		findAPIinList($APIs{$apiName}->{functions}, \$fileContents, \@foundAPIs);

		if ($APIs{$apiName}->{count_errors}) {
			# the use of "prohibited" APIs is an error, increment the error count
			$errorCount += @foundAPIs;
			$pfx = "Error";
		}

		print STDERR $pfx . ": Found " . $apiName . " APIs in ".$filename.": ".join(',', @foundAPIs)."\n" if @foundAPIs;
	}

}

exit($errorCount);
