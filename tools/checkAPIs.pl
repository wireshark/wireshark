#!/usr/bin/env perl

#
# Copyright 2006, Jeff Morriss <jeff.morriss[AT]ulticom.com>
#
# A simple tool to check source code for function calls that should not
# be called by Wireshark code and to perform certain other checks.
#
# Usage:
# checkAPIs.pl [-g group1] [-g group2] [--nocheck-value-string-array-null-termination] file1 file2 ...
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
		#'gtk_clist_new', 
		# GtkCList has been deprecated since GTK+ 2.0 and should not be used
		# in newly written code. Use GtkTreeView instead. 
		'gtk_file_selection_new',
		# Use gtk_file_chooser_dialog_new() instead
		'gtk_combo_new',
		# GtkCombo has been deprecated since version 2.4 and should not be used in newly-written code. Use GtkComboBox instead.
		'gtk_entry_append_text',
		'gtk_label_set',
		# Aliases gtk_label_set_text(). Probably used for backward compatibility with GTK+ 1.0.x. 
		'gtk_menu_append',
		'gtk_menu_prepend',
		#gtk_menu_append is deprecated and should not be used in newly-written code. Use gtk_menu_shell_append() instead.
		#'gtk_progress_bar_update',
		# gtk_progress_bar_set_fraction ?
		# gtk_progress_bar_update is deprecated and should not be used in newly-written code.
		# This function is deprecated. Please use gtk_progress_set_value() or gtk_progress_set_percentage() instead.
		'gtk_widget_draw',
		# in general gtk_widget_queue_draw_area() is a better choice if you want to draw a region of a widget.
		'gtk_window_position',
		# Use strerror() and report messages in whatever
		# fashion is appropriate for the code in question.
		'perror',
		]},

	# APIs that make the program exit. Dissectors shouldn't call these
	'abort' => { 'count_errors' => 1, 'functions' => [
		'abort',
		'exit',
		'g_assert',
		'g_error',
		]},

	# APIs that print to the terminal. Dissectors shouldn't call these
	'termoutput' => { 'count_errors' => 0, 'functions' => [
		'printf',
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
#    ?s added so that strings containing a 'line continuation' 
#    ( \ followed by a new-line) will match.
my $DoubleQuotedStr = qr{(?:\"(?s:\\.|[^\"\\])*\")};

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
#    Also: capturing the comment isn't necessary.
my $commentAndStringRegex = qr{(?:$DoubleQuotedStr|$SingleQuotedStr|$CComment)};

#### Regex for use when searching for value-string definitions
my $StaticRegex = qr{static\s+};
my $ConstRegex  = qr{const\s+};
my $Static_andor_ConstRegex = qr{(?:$StaticRegex$ConstRegex|$StaticRegex|$ConstRegex)};
#
# MAIN
#
my $errorCount = 0;
# The default list, which can be expanded.
my @apiGroups = qw(prohibited deprecated);
my $check_value_string_array_null_termination = 1; # default: enabled
my $debug_flag = 0;

my $result = GetOptions(
                        'g=s' => \@apiGroups, 
                        'check-value-string-array-null-termination!' => \$check_value_string_array_null_termination,
                        'debug' => \$debug_flag
                       );
if (!$result) {
    print "Usage: checkAPIs.pl [-g group1] [-g group2] [--nocheck-value-string-array-null-termination] file1 file2 ..\n";
    exit(1);
}

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

	# Brute force check for value_string arrays which are not NULL terminated
	if ($check_value_string_array_null_termination) {
		#  Assumption: definition is of form (pseudo-Regex):
		#    " (static const|static|const) value_string .+ = { .+ ;" (possibly over multiple lines) 
		while ($fileContents =~ /( $Static_andor_ConstRegex value_string [^;*]+ = [^;]+ \{ [^;]+ ; )/xsg) {
			# value_string array definition found; check if NULL terminated
			my $vs = my $vsx = $1;
			if ($debug_flag) {
				$vsx =~ /(.+ value_string [^=]+ ) = /x;
				printf STDERR "==> %-35.35s: %s\n", $filename, $1;
				printf STDERR "%s\n", $vs;
			}
			$vs =~ s/\s//g;
			# README.developer says 
			#  "Don't put a comma after the last tuple of an initializer of an array"
			# However: since this usage is present in some number of cases, we'll allow for now
			if ($vs !~ / , NULL \} ,? \} ; $/x) {
				$vsx =~ /( value_string [^=]+ ) = /x;
				printf STDERR "Error: %-35.35s: Not terminated: %s\n", $filename, $1;
				$errorCount++;
			}
		}
	}

	# Check APIs
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
