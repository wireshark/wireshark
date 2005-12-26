###################################################
# Samba3 type-specific declarations / initialization / marshalling
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba3::Types;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(DeclShort DeclLong InitType DissectType AddType StringType);

use strict;
use Parse::Pidl::Util qw(has_property ParseExpr property_matches);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred ContainsString);

use vars qw($VERSION);
$VERSION = '0.01';

# TODO: Find external types somehow?

sub warning($$) { my ($e,$s) = @_; print STDERR "$e->{FILE}:$e->{LINE}: $s\n"; }

sub init_scalar($$$$)
{
	my ($e,$l,$n,$v) = @_;

	return "$n = $v;";
}

sub dissect_scalar($$$$$)
{
	my ($e,$l,$n,$w,$a) = @_;

	my $t = lc($e->{TYPE});
	
	return "prs_$t(\"$e->{NAME}\", ps, depth, &$n)";
}

sub decl_string($)
{
	my $e = shift;

	my $is_conformant = property_matches($e, "flag", ".*STR_SIZE4.*");
	my $is_varying = property_matches($e, "flag", ".*STR_LEN4.*");
	my $is_ascii = property_matches($e, "flag", ".*STR_ASCII.*");

	return "STRING2" if ($is_conformant and $is_varying and $is_ascii);

	return "UNISTR2" if ($is_conformant and $is_varying);
	return "UNISTR3" if ($is_varying);
	# We don't do UNISTR4, as we have lsa_String for that in Samba4's IDL

	die("Don't know what string type to use");
}

sub contains_pointer($)
{
	my $e = shift;
	
	foreach my $l (@{$e->{LEVELS}}) { 
		return 1 if ($l->{TYPE} eq "POINTER");
	}

	return 0;
}

sub ext_decl_string($)
{
	my $e = shift;

	# One pointer is sufficient..
	return "const char" if (contains_pointer($e));
	return "const char *";
}

sub init_string($$$$)
{
	my ($e,$l,$n,$v) = @_;

	my $t = lc(decl_string($e));

	my $flags;
	if (property_matches($e, "flag", ".*STR_NULLTERM.*")) {
		$flags = "UNI_STR_TERMINATE";
	} elsif (property_matches($e, "flag", ".*STR_NOTERM.*")) {
		$flags = "UNI_STR_NOTERM";
	} else {
		$flags = "UNI_FLAGS_NONE";
	}

	# One pointer is sufficient
	if (substr($v, 0, 1) eq "*") { $v = substr($v, 1); }
	
	return "init_$t(&$n, $v, $flags);";
}

sub dissect_string($$$$$)
{
	my ($e,$l,$n,$w,$a) = @_;

	my $t = lc(decl_string($e));

	$$a = 1;
	return "smb_io_$t(\"$e->{NAME}\", &$n, 1, ps, depth)";
}

sub StringType($$)
{
	my ($e,$l) = @_;
	my $nl = GetNextLevel($e,$l);

	if ($l->{IS_VARYING} and $l->{IS_CONFORMANT} and $nl->{DATA_TYPE} eq "uint16") {
		return ("unistr2", "UNI_FLAGS_NONE");
	} elsif ($l->{IS_CONFORMANT} and $l->{IS_VARYING} and $nl->{DATA_TYPE} eq "uint8") {
		return ("string2", 0);
	} else {
		fatal($e, "[string] non-varying string not supported for Samba3 yet");
	}
}

my $known_types = 
{
	uint8 => 
	{
		DECL => "uint8",
		INIT => \&init_scalar,
		DISSECT_P => \&dissect_scalar,
	},
	uint16 => 
	{
		DECL => "uint16",
		INIT => \&init_scalar,
		DISSECT_P => \&dissect_scalar,
	},
	uint32 => 
	{
		DECL => "uint32",
		INIT => \&init_scalar,
		DISSECT_P => \&dissect_scalar,
	},
	uint64 => 
	{
		DECL => "uint64",
		INIT => \&init_scalar,
		DISSECT_P => \&dissect_scalar,
	},
	string => 
	{
		DECL => \&decl_string,
		EXT_DECL => \&ext_decl_string,
		INIT => \&init_string,
		DISSECT_P => \&dissect_string,
	},
	NTSTATUS => 
	{
		DECL => "NTSTATUS",
		INIT => \&init_scalar,
		DISSECT_P => \&dissect_scalar,
	},
	WERROR => 
	{
		DECL => "WERROR",
		INIT => \&init_scalar,
		DISSECT_P => \&dissect_scalar,
	},
	GUID => 
	{
		DECL => "struct uuid",
		INIT => "",
		DISSECT_P => sub { 
			my ($e,$l,$n) = @_; 
			return "smb_io_uuid(\"$e->{NAME}\", &$n, ps, depth)";
		}
	},
	NTTIME => 
	{
		DECL => "NTTIME",
		INIT => "",
		DISSECT_P => sub { 
			my ($e,$l,$n,$w,$a) = @_; 
			return "smb_io_nttime(\"$e->{NAME}\", &n, ps, depth)"; 
		}
	},
	dom_sid => 
	{
		DECL => "DOM_SID",
		INIT => "",
		DISSECT_P => sub {
			my ($e,$l,$n,$w,$a) = @_;
			return "smb_io_dom_sid(\"$e->{NAME}\", &n, ps, depth)";
		}
	},
	policy_handle =>
	{
		DECL => "POLICY_HND",
		INIT => "",
		DISSECT_P => sub {
			my ($e,$l,$n,$w,$a) = @_;
			return "smb_io_pol_hnd(\"$e->{NAME}\", &n, ps, depth)";
		}
	},
	hyper => 
	{
		DECL => "uint64",
		INIT => "",
		DISSECT_P => sub {
			my ($e,$l,$n,$w,$a) = @_;
			return "prs_uint64(\"$e->{NAME}\", ps, depth, &$n)";
		}
	},
};

sub AddType($$)
{
	my ($t,$d) = @_;

	warn("Reregistering type $t") if (defined($known_types->{$t}));

	$known_types->{$t} = $d;
}

# Return type without special stuff, as used in 
# declarations for internal structs
sub DeclShort($)
{
	my $e = shift;

	my $t = $known_types->{$e->{TYPE}};

	if (not $t) {
		warning($e, "Can't declare unknown type $e->{TYPE}");
		return undef;
	}

	my $p;

	# DECL can be a function
	if (ref($t->{DECL}) eq "CODE") {
		$p = $t->{DECL}->($e);
	} else {
		$p = $t->{DECL};
	}

	my $prefixes = "";
	my $suffixes = "";
	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "ARRAY" and not $l->{IS_FIXED}) {
			$prefixes = "*$prefixes";
		} elsif ($l->{TYPE} eq "ARRAY" and $l->{IS_FIXED}) {
			$suffixes.="[$l->{SIZE_IS}]";
		}
	}
	
	return "$p $prefixes$e->{NAME}$suffixes";
}

# Return type including special stuff (pointers, etc).
sub DeclLong($)
{
	my $e = shift;

	my $t = $known_types->{$e->{TYPE}};

	if (not $t) {
		warning($e, "Can't declare unknown type $e->{TYPE}");
		return undef;
	}

	my $p;

	if (defined($t->{EXT_DECL})) {
		$p = $t->{EXT_DECL}
	} else {
		$p = $t->{DECL};
	}

	if (ref($p) eq "CODE") {
		$p = $p->($e);
	}

	my $prefixes = "";
	my $suffixes = "";

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "ARRAY" and $l->{IS_ZERO_TERMINATED}) {
			$p = "const char";
			last;
		} elsif ($l->{TYPE} eq "ARRAY" and not $l->{IS_FIXED}) {
			$prefixes = "*$prefixes";
		} elsif ($l->{TYPE} eq "ARRAY" and $l->{IS_FIXED}) {
			$suffixes.="[$l->{SIZE_IS}]";
		} elsif ($l->{TYPE} eq "POINTER") {
			$prefixes = "*$prefixes";
		}
	}
	
	return "$p $prefixes$e->{NAME}$suffixes";
}

sub InitType($$$$)
{
	my ($e, $l, $varname, $value) = @_;

	my $t = $known_types->{$l->{DATA_TYPE}};

	if (not $t) {
		warning($e, "Don't know how to initialize type $l->{DATA_TYPE}");
		return undef;
	}

	# INIT can be a function
	if (ref($t->{INIT}) eq "CODE") {
		return $t->{INIT}->($e, $l, $varname, $value);
	} else {
		return $t->{INIT};
	}
}

sub DissectType($$$$$)
{
	my ($e,$l,$varname,$what,$align) = @_;

	my $t = $known_types->{$l->{DATA_TYPE}};

	if (not $t) {
		warning($e, "Don't know how to dissect type $l->{DATA_TYPE}");
		return undef;
	}

	my $dissect;
	if ($what == 1) { #primitives
		$dissect = $t->{DISSECT_P};
	} elsif ($what == 2) {
		$dissect = $t->{DISSECT_D};
	}

	return "" if not defined($dissect);

	# DISSECT can be a function
	if (ref($dissect) eq "CODE") {
		return $dissect->($e,$l,$varname,$what,$align);
	} else {
		return $dissect;
	}
}

sub LoadTypes($)
{
	my $ndr = shift;
	foreach my $if (@{$ndr}) {
		next unless ($if->{TYPE} eq "INTERFACE");

		foreach my $td (@{$if->{TYPES}}) {
			my $decl = uc("$if->{NAME}_$td->{NAME}");

			my $init = sub {
					my ($e,$l,$n,$v) = @_;
					return "$n = $v;";
			};
			
			my $dissect_d;
			my $dissect_p;
			if ($td->{DATA}->{TYPE} eq "UNION") {
				$decl.="_CTR";
			} 

			 $dissect_p = sub {
				my ($e,$l,$n,$w,$a) = @_;

				return "$if->{NAME}_io_$td->{NAME}_p(\"$e->{NAME}\", &$n, ps, depth)";
			};
		 	$dissect_d = sub {
				my ($e,$l,$n,$w,$a) = @_;

				return "$if->{NAME}_io_$td->{NAME}_d(\"$e->{NAME}\", &$n, ps, depth)";
			};

			AddType($td->{NAME}, {
				DECL => $decl,
				INIT => $init,
				DISSECT_D => $dissect_d,
				DISSECT_P => $dissect_p
			});
		}
	}
}

1;
