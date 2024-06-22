##########################################
# Converts ODL stuctures to IDL structures
# (C) 2004-2005, 2008 Jelmer Vernooij <jelmer@samba.org>

package Parse::Pidl::ODL;

use Parse::Pidl qw(error);
use Parse::Pidl::IDL;
use Parse::Pidl::Util qw(has_property unmake_str);
use Parse::Pidl::Typelist qw(hasType getType);
use File::Basename;
use strict;
use warnings;

use vars qw($VERSION);
$VERSION = '0.01';

sub FunctionAddObjArgs($)
{
	my $e = shift;
	
	unshift(@{$e->{ELEMENTS}}, {
		'NAME' => 'ORPCthis',
		'POINTERS' => 0,
		'PROPERTIES' => { 'in' => '1' },
		'TYPE' => 'ORPCTHIS',
		'FILE' => $e->{FILE},
		'LINE' => $e->{LINE}
	});
	unshift(@{$e->{ELEMENTS}}, {
		'NAME' => 'ORPCthat',
		'POINTERS' => 1,
		'PROPERTIES' => { 'out' => '1', 'ref' => '1' },
		'TYPE' => 'ORPCTHAT',
		'FILE' => $e->{FILE},
		'LINE' => $e->{LINE}
	});
}

sub ReplaceInterfacePointers($)
{
	my ($e) = @_;
	foreach my $x (@{$e->{ELEMENTS}}) {
		next unless (hasType($x->{TYPE}));
		next unless getType($x->{TYPE})->{DATA}->{TYPE} eq "INTERFACE";
		
		$x->{TYPE} = "MInterfacePointer";
	}
}

# Add ORPC specific bits to an interface.
sub ODL2IDL
{
	my ($odl, $basedir, $opt_incdirs) = (@_);
	my $addedorpc = 0;
	my $interfaces = {};

	foreach my $x (@$odl) {
		if ($x->{TYPE} eq "IMPORT") {
			foreach my $idl_file (@{$x->{PATHS}}) {
				$idl_file = unmake_str($idl_file);
				my $idl_path = undef;
				foreach ($basedir, @$opt_incdirs) {
					if (-f "$_/$idl_file") {
						$idl_path = "$_/$idl_file";
						last;
					}
				}
				unless ($idl_path) {
					error($x, "Unable to open include file `$idl_file'");
					next;
				}
				my $podl = Parse::Pidl::IDL::parse_file($idl_path, $opt_incdirs);
				if (defined($podl)) {
					require Parse::Pidl::Typelist;
					my $basename = basename($idl_path, ".idl");

					Parse::Pidl::Typelist::LoadIdl($podl, $basename);
					my $pidl = ODL2IDL($podl, $basedir, $opt_incdirs);

					foreach my $y (@$pidl) {
						if ($y->{TYPE} eq "INTERFACE") {
							$interfaces->{$y->{NAME}} = $y;
						}
					}
				} else {
					error($x, "Failed to parse $idl_path");
				}
			}
		}

		if ($x->{TYPE} eq "INTERFACE") {
			$interfaces->{$x->{NAME}} = $x;
			# Add [in] ORPCTHIS *this, [out] ORPCTHAT *that
			# and replace interfacepointers with MInterfacePointer
			# for 'object' interfaces
			if (has_property($x, "object")) {
				foreach my $e (@{$x->{DATA}}) {
					($e->{TYPE} eq "FUNCTION") && FunctionAddObjArgs($e);
					ReplaceInterfacePointers($e);
				}
				$addedorpc = 1;
			}

			if ($x->{BASE}) {
				my $base = $interfaces->{$x->{BASE}};

				unless (defined($base)) {
					error($x, "Undefined base interface `$x->{BASE}'");
				} else {
					foreach my $fn (reverse @{$base->{DATA}}) {
						next unless ($fn->{TYPE} eq "FUNCTION");
						push (@{$x->{INHERITED_FUNCTIONS}}, $fn);
					}
				}
			}
		}
	}

	unshift (@$odl, {
		TYPE => "IMPORT", 
		PATHS => [ "\"orpc.idl\"" ],
		FILE => undef,
		LINE => undef
	}) if ($addedorpc);


	return $odl;
}

1;
