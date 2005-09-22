##########################################
# Converts ODL stuctures to IDL structures
# (C) 2004-2005 Jelmer Vernooij <jelmer@samba.org>

package Parse::Pidl::ODL;

use Parse::Pidl::Util qw(has_property);
use Parse::Pidl::Typelist qw(hasType getType);
use strict;

use vars qw($VERSION);
$VERSION = '0.01';

#####################################################################
# find an interface in an array of interfaces
sub get_interface($$)
{
	my($if) = shift;
	my($n) = shift;

	foreach(@{$if}) {
		if($_->{NAME} eq $n) { return $_; }
	}
	
	return 0;
}

sub FunctionAddObjArgs($)
{
	my $e = shift;
	
	unshift(@{$e->{ELEMENTS}}, {
		'NAME' => 'ORPCthis',
		'POINTERS' => 0,
		'PROPERTIES' => { 'in' => '1' },
		'TYPE' => 'ORPCTHIS'
	});
	unshift(@{$e->{ELEMENTS}}, {
		'NAME' => 'ORPCthat',
		'POINTERS' => 0,
		'PROPERTIES' => { 'out' => '1' },
		'TYPE' => 'ORPCTHAT'
	});
}

sub ReplaceInterfacePointers($)
{
	my $e = shift;

	foreach my $x (@{$e->{ELEMENTS}}) {
		next unless (hasType($x->{TYPE}));
		next unless getType($x->{TYPE})->{DATA}->{TYPE} eq "INTERFACE";
		
		$x->{TYPE} = "MInterfacePointer";
	}
}

# Add ORPC specific bits to an interface.
sub ODL2IDL($)
{
	my $odl = shift;
	
	foreach my $x (@{$odl}) {
		# Add [in] ORPCTHIS *this, [out] ORPCTHAT *that
		# and replace interfacepointers with MInterfacePointer
		# for 'object' interfaces
		if (has_property($x, "object")) {
			foreach my $e (@{$x->{DATA}}) {
				($e->{TYPE} eq "FUNCTION") && FunctionAddObjArgs($e);
				ReplaceInterfacePointers($e);
			}
			# Object interfaces use ORPC
			my @depends = ();
			if(has_property($x, "depends")) {
				@depends = split /,/, $x->{PROPERTIES}->{depends};
			}
			push @depends, "orpc";
			$x->{PROPERTIES}->{depends} = join(',',@depends);
		}

		if ($x->{BASE}) {
			my $base = get_interface($odl, $x->{BASE});

			foreach my $fn (reverse @{$base->{DATA}}) {
				next unless ($fn->{TYPE} eq "FUNCTION");
				unshift (@{$x->{DATA}}, $fn);
				push (@{$x->{INHERITED_FUNCTIONS}}, $fn->{NAME});
			}
		}
	}

	return $odl;
}

1;
