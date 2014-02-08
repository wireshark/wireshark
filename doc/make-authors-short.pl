# Remove tasks from individual author entries from AUTHORS file
# for use in the about dialog.
#
# Must be called via perlnoutf.
#
# Copyright 2004 Ulf Lamping <ulf.lamping@web.de>
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
