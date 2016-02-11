###################################################
# utility functions to support pidl
# Copyright tridge@samba.org 2000
# released under the GNU GPL
package Parse::Pidl::Util;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(has_property property_matches ParseExpr ParseExprExt is_constant make_str unmake_str print_uuid MyDumper genpad);
use vars qw($VERSION);
$VERSION = '0.01';

use strict;

use Parse::Pidl::Expr;
use Parse::Pidl qw(error);

=head1 NAME

Parse::Pidl::Util - Generic utility functions for pidl

=head1 SYNOPSIS

use Parse::Pidl::Util;

=head1 DESCRIPTION

Simple module that contains a couple of trivial helper functions 
used throughout the various pidl modules.

=head1 FUNCTIONS

=over 4

=cut

=item B<MyDumper>
a dumper wrapper to prevent dependence on the Data::Dumper module
unless we actually need it

=cut

sub MyDumper($)
{
	require Data::Dumper;
	$Data::Dumper::Sortkeys = 1;
	my $s = shift;
	return Data::Dumper::Dumper($s);
}

=item B<has_property>
see if a pidl property list contains a given property

=cut
sub has_property($$)
{
	my($e, $p) = @_;

	return undef if (not defined($e->{PROPERTIES}));

	return $e->{PROPERTIES}->{$p};
}

=item B<property_matches>
see if a pidl property matches a value

=cut
sub property_matches($$$)
{
	my($e,$p,$v) = @_;

	if (!defined has_property($e, $p)) {
		return undef;
	}

	if ($e->{PROPERTIES}->{$p} =~ /$v/) {
		return 1;
	}

	return undef;
}

=item B<is_constant>
return 1 if the string is a C constant

=cut
sub is_constant($)
{
	my $s = shift;
	return 1 if ($s =~ /^\d+$/);
	return 1 if ($s =~ /^0x[0-9A-Fa-f]+$/);
	return 0;
}

=item B<make_str>
return a "" quoted string, unless already quoted

=cut
sub make_str($)
{
	my $str = shift;
	if (substr($str, 0, 1) eq "\"") {
		return $str;
	}
	return "\"$str\"";
}

=item B<unmake_str>
unquote a "" quoted string

=cut
sub unmake_str($)
{
	my $str = shift;
	
	$str =~ s/^\"(.*)\"$/$1/;

	return $str;
}

=item B<print_uuid>
Print C representation of a UUID.

=cut
sub print_uuid($)
{
	my ($uuid) = @_;
	$uuid =~ s/"//g;
	my ($time_low,$time_mid,$time_hi,$clock_seq,$node) = split /-/, $uuid;
	return undef if not defined($node);

	my @clock_seq = $clock_seq =~ /(..)/g;
	my @node = $node =~ /(..)/g;

	return "{0x$time_low,0x$time_mid,0x$time_hi," .
		"{".join(',', map {"0x$_"} @clock_seq)."}," .
		"{".join(',', map {"0x$_"} @node)."}}";
}

=item B<ParseExpr>
Interpret an IDL expression, substituting particular variables.

=cut
sub ParseExpr($$$)
{
	my($expr, $varlist, $e) = @_;

	my $x = new Parse::Pidl::Expr();
	
	return $x->Run($expr, sub { my $x = shift; error($e, $x); },
		# Lookup fn 
		sub { my $x = shift; 
			  return($varlist->{$x}) if (defined($varlist->{$x})); 
			  return $x;
		  },
		undef, undef);
}

=item B<ParseExprExt>
Interpret an IDL expression, substituting particular variables. Can call 
callbacks when pointers are being dereferenced or variables are being used.

=cut
sub ParseExprExt($$$$$)
{
	my($expr, $varlist, $e, $deref, $use) = @_;

	my $x = new Parse::Pidl::Expr();
	
	return $x->Run($expr, sub { my $x = shift; error($e, $x); },
		# Lookup fn 
		sub { my $x = shift; 
			  return($varlist->{$x}) if (defined($varlist->{$x})); 
			  return $x;
		  },
		$deref, $use);
}

=item B<genpad>
return an empty string consisting of tabs and spaces suitable for proper indent
of C-functions.

=cut
sub genpad($)
{
	my ($s) = @_;
	my $nt = int((length($s)+1)/8);
	my $lt = ($nt*8)-1;
	my $ns = (length($s)-$lt);
	return "\t"x($nt)." "x($ns);
}

=back

=cut

1;
