#!/usr/bin/perl -w

# $Id: make-authors-short.pl,v 1.3 2004/05/22 14:05:33 jmayer Exp $

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
		if (($nextline = <>) !~ /^[\s\r]*$/) {
			print $nextline;
		}
	} elsif ($subinfo == 1) {
		next;
	} else {
		print;
	}
}
