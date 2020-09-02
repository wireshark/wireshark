# Convert AUTHORS-SHORT file for use in man page and HTML documentation
# after processing through pod2man and pod2html.
#
# Copyright 2004 Graeme Hewson <ghewson@wormhole.me.uk>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

use strict;
use open qw(:std :utf8);

# This might not be necessary.
print "=for html <style>div#authors pre, div#authors pre code { white-space: pre-wrap; }</style>\n\n";
print "=for html <div id=authors>\n\n";

print "=for man .nf\n\n";

while (<>) {
	printline();
}

print "\n=for html </div>\n";
print "\n=for man .fi\n";

sub printline {
	my $line = shift || $_;

	if ($line =~ /^=/) {
		#
		# Convert Asciidoctor-style headings to Pod.
		#
		$line =~ s/^= /=head2 /;
		$line =~ s/\s*=+$//;
		print $line;
		return;
	}

	if ($line =~ /<\S+\[AT\]\S+>$/i or $line =~ /address removed.*\)/) {
		# Make the author lists verbatim paragraphs.
		$line = "    " . $line;
	}

	if ($line =~ /^and by:/) {
		# This needs to be a regular paragraph.
		$line = "\n" . $line;
	}

	print $line;
}
