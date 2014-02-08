# Convert AUTHORS-SHORT file for use in man page and HTML documentation
# after processing through pod2man and pod2html.
#
# Must be called via perlnoutf.
#
# Copyright 2004 Graeme Hewson <ghewson@wormhole.me.uk>
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use strict;

print "=for html <pre>\n\n";
print "=for man .nf\n\n";

while (<>) {
	printline();
}

print "\n=for html </pre>\n";
print "\n=for man .fi\n";

sub printline {
	my $line = shift || $_;
#
# Translate UTF-8 characters to the E<> escapes handled by Pod::Man
# (and only those, since they're a subset of HTML entities)
#
	$line =~ s/\xc3\x80/E<Agrave>/g;
	$line =~ s/\xc3\x81/E<Aacute>/g;
	$line =~ s/\xc3\x82/E<Acirc>/g;
	$line =~ s/\xc3\x83/E<Atilde>/g;
	$line =~ s/\xc3\x84/E<Auml>/g;
	$line =~ s/\xc3\x85/E<Aring>/g;
	$line =~ s/\xc3\x86/E<AElig>/g;
	$line =~ s/\xc3\x87/E<Ccedil>/g;
	$line =~ s/\xc3\x88/E<Egrave>/g;
	$line =~ s/\xc3\x89/E<Eacute>/g;
	$line =~ s/\xc3\x8a/E<Ecirc>/g;
	$line =~ s/\xc3\x8b/E<Euml>/g;
	$line =~ s/\xc3\x8c/E<Igrave>/g;
	$line =~ s/\xc3\x8d/E<Iacute>/g;
	$line =~ s/\xc3\x8e/E<Icirc>/g;
	$line =~ s/\xc3\x8f/E<Iuml>/g;
	$line =~ s/\xc3\x90/E<ETH>/g;
	$line =~ s/\xc3\x91/E<Ntilde>/g;
	$line =~ s/\xc3\x92/E<Ograve>/g;
	$line =~ s/\xc3\x93/E<Oacute>/g;
	$line =~ s/\xc3\x94/E<Ocirc>/g;
	$line =~ s/\xc3\x95/E<Otilde>/g;
	$line =~ s/\xc3\x96/E<Ouml>/g;
	$line =~ s/\xc3\x98/E<Oslash>/g;
	$line =~ s/\xc3\x99/E<Ugrave>/g;
	$line =~ s/\xc3\x9a/E<Uacute>/g;
	$line =~ s/\xc3\x9b/E<Ucirc>/g;
	$line =~ s/\xc3\x9c/E<Uuml>/g;
	$line =~ s/\xc3\x9d/E<Yacute>/g;
	$line =~ s/\xc3\x9e/E<THORN>/g;
	$line =~ s/\xc3\x9f/E<szlig>/g;
	$line =~ s/\xc3\xa0/E<agrave>/g;
	$line =~ s/\xc3\xa1/E<aacute>/g;
	$line =~ s/\xc3\xa2/E<acirc>/g;
	$line =~ s/\xc3\xa3/E<atilde>/g;
	$line =~ s/\xc3\xa4/E<auml>/g;
	$line =~ s/\xc3\xa5/E<aring>/g;
	$line =~ s/\xc3\xa6/E<aelig>/g;
	$line =~ s/\xc3\xa7/E<ccedil>/g;
	$line =~ s/\xc3\xa8/E<egrave>/g;
	$line =~ s/\xc3\xa9/E<eacute>/g;
	$line =~ s/\xc3\xaa/E<ecirc>/g;
	$line =~ s/\xc3\xab/E<euml>/g;
	$line =~ s/\xc3\xac/E<igrave>/g;
	$line =~ s/\xc3\xad/E<iacute>/g;
	$line =~ s/\xc3\xae/E<icirc>/g;
	$line =~ s/\xc3\xaf/E<iuml>/g;
	$line =~ s/\xc3\xb0/E<eth>/g;
	$line =~ s/\xc3\xb1/E<ntilde>/g;
	$line =~ s/\xc3\xb2/E<ograve>/g;
	$line =~ s/\xc3\xb3/E<oacute>/g;
	$line =~ s/\xc3\xb4/E<ocirc>/g;
	$line =~ s/\xc3\xb5/E<otilde>/g;
	$line =~ s/\xc3\xb6/E<ouml>/g;
	$line =~ s/\xc3\xb8/E<oslash>/g;
	$line =~ s/\xc3\xb9/E<ugrave>/g;
	$line =~ s/\xc3\xba/E<uacute>/g;
	$line =~ s/\xc3\xbb/E<ucirc>/g;
	$line =~ s/\xc3\xbc/E<uuml>/g;
	$line =~ s/\xc3\xbd/E<yacute>/g;
	$line =~ s/\xc3\xbe/E<thorn>/g;
	$line =~ s/\xc3\xbf/E<yuml>/g;
	print $line;
}
