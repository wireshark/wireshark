#!/usr/bin/perl -w

# $Id$

# Remove tasks from individual author entries from AUTHORS file
# for use in the about dialog.

use strict;

my $subinfo=0;
my $nextline;

print "=for html <pre>\n\n";
print "=for man .nf\n\n";

$_ = <>;
s/\xef\xbb\xbf//;		# Skip UTF-8 byte order mark
print unless /^\n/;

while (<>) {
	if (/(.*){/) {
		$subinfo = 1;
		print "$1\n";
	} elsif (/}/) {
		$subinfo = 0;
		if (($nextline = <>) !~ /^[\s]*$/) {
			print $nextline;
		}
	} elsif ($subinfo == 1) {
		next;
	} else {
		print;
	}
}

print "\n=for html </pre>\n";
print "\n=for man .fi\n";
