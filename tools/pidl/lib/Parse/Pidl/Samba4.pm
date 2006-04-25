###################################################
# Common Samba4 functions
# Copyright jelmer@samba.org 2006
# released under the GNU GPL

package Parse::Pidl::Samba4;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(is_intree choose_header);

use Parse::Pidl::Util qw(has_property);
use strict;

use vars qw($VERSION);
$VERSION = '0.01';

sub is_intree()
{
	return -f "include/smb.h";
}

# Return an #include line depending on whether this build is an in-tree
# build or not.
sub choose_header($$)
{
	my ($in,$out) = @_;
	return "#include \"$in\"" if (is_intree());
	return "#include <$out>";
}

1;
