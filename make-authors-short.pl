#!/usr/bin/perl -w

# Remove tasks from individual author entries from AUTHORS file
# for use in the about dialog.

use strict;

my $subinfo=0;

while (<>) {
	if (/(.*){/) {
		$subinfo = 1;
		print "$1\n";
	} elsif (/}/) {
		$subinfo = 0;
	} elsif ($subinfo == 1) {
		next;
	} else {
		print;
	}
}
