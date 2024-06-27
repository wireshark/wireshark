###################################################
# C utility functions for pidl
# Copyright jelmer@samba.org 2005-2007
# released under the GNU GPL
package Parse::Pidl::CUtil;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(get_pointer_to get_value_of get_array_element);
use vars qw($VERSION);
$VERSION = '0.01';

use strict;
use warnings;

sub get_pointer_to($)
{
	my $var_name = shift;
	
	if ($var_name =~ /^\*(.*)$/) {
		return $1;
	} elsif ($var_name =~ /^\&(.*)$/) {
		return "&($var_name)";
	} else {
		return "&$var_name";
	}
}

sub get_value_of($)
{
	my $var_name = shift;

	if ($var_name =~ /^\&(.*)$/) {
		return $1;
	} else {
		return "*$var_name";
	}
}

sub get_array_element($$)
{
	my ($var_name, $idx) = @_;

	if ($var_name =~ /^\*.*$/) {
		$var_name = "($var_name)";
	} elsif ($var_name =~ /^\&.*$/) {
		$var_name = "($var_name)";
	}

	return "$var_name"."[$idx]";
}

1;
