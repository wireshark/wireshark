# Remove tasks from individual author entries from AUTHORS file
# for use in the about dialog.
#
# Copyright 2004 Ulf Lamping <ulf.lamping@web.de>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

use strict;
use open qw(:std :utf8);

my $subinfo=0;
my $nextline;

$_ = <>;
s/\xef\xbb\xbf//;		# Skip UTF-8 byte order mark
print unless /^\n/;

while (<>) {
	if (/(.*?)\s*\{/) {
		$subinfo = 1;
		print "$1\n";
	} elsif (/\}/) {
		$subinfo = 0;
		if (($nextline = <>) !~ /^[\s]*$/) {
			print STDERR "No blank line after '}', found: $nextline"
				if $nextline =~ m/\{/;
			print $nextline;
		}
	} elsif ($subinfo == 1) {
		next;
	} else {
		print;
	}
}
