# $Id$

# Remove tasks from individual author entries from AUTHORS file
# for use in the about dialog.
#
# Must be called via perlnoutf.

use strict;

my $subinfo=0;
my $nextline;

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
