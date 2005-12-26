###################################################
# utility functions to support pidl
# Copyright tridge@samba.org 2000
# released under the GNU GPL
package Parse::Pidl::Util;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(has_property property_matches ParseExpr is_constant make_str);
use vars qw($VERSION);
$VERSION = '0.01';

use strict;

#####################################################################
# a dumper wrapper to prevent dependence on the Data::Dumper module
# unless we actually need it
sub MyDumper($)
{
	require Data::Dumper;
	my $s = shift;
	return Data::Dumper::Dumper($s);
}

#####################################################################
# see if a pidl property list contains a given property
sub has_property($$)
{
	my($e) = shift;
	my($p) = shift;

	if (!defined $e->{PROPERTIES}) {
		return undef;
	}

	return $e->{PROPERTIES}->{$p};
}

#####################################################################
# see if a pidl property matches a value
sub property_matches($$$)
{
	my($e) = shift;
	my($p) = shift;
	my($v) = shift;

	if (!defined has_property($e, $p)) {
		return undef;
	}

	if ($e->{PROPERTIES}->{$p} =~ /$v/) {
		return 1;
	}

	return undef;
}

# return 1 if the string is a C constant
sub is_constant($)
{
	my $s = shift;
	if (defined $s && $s =~ /^\d/) {
		return 1;
	}
	return 0;
}

# return a "" quoted string, unless already quoted
sub make_str($)
{
	my $str = shift;
	if (substr($str, 0, 1) eq "\"") {
		return $str;
	}
	return "\"" . $str . "\"";
}

# a hack to build on platforms that don't like negative enum values
my $useUintEnums = 0;
sub setUseUintEnums($)
{
	$useUintEnums = shift;
}
sub useUintEnums()
{
	return $useUintEnums;
}

sub ParseExpr($$)
{
	my($expr,$varlist) = @_;

	die("Undefined value in ParseExpr") if not defined($expr);

	my @tokens = split /((?:[A-Za-z_])(?:(?:(?:[A-Za-z0-9_.])|(?:->))+))/, $expr;
	my $ret = "";

	foreach my $t (@tokens) {
		if (defined($varlist->{$t})) {
			$ret .= $varlist->{$t};
		} else {
			$ret .= $t;
		}
	}

	return $ret;
}

1;
