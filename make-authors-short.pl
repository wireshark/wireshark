#!/usr/bin/perl -w

# $Id: make-authors-short.pl,v 1.2 2004/05/21 21:08:41 jmayer Exp $

# Remove tasks from individual author entries from AUTHORS file
# for use in the about dialog.

use strict;

my $subinfo=0;
my $nextline;

while (<>) {
	if (/(.*){/) {
		$subinfo = 1;
		print "$1\n";
	} elsif (/}/) {
		$subinfo = 0;
		if (($nextline = <>) !~ /^$/) {
			print $nextline;
		}
	} elsif ($subinfo == 1) {
		next;
	} else {
		print;
	}
}
