###################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package Parse::Pidl::Samba::NDR::Parser;

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapType);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);

# list of known types
my %typefamily;

sub get_typefamily($)
{
	my $n = shift;
	return $typefamily{$n};
}

sub append_prefix($$)
{
	my ($e, $var_name) = @_;
	my $pointers = 0;

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER") {
			$pointers++;
		} elsif ($l->{TYPE} eq "ARRAY") {
			if (($pointers == 0) and 
			    (not $l->{IS_FIXED}) and
			    (not $l->{IS_INLINE})) {
				return get_value_of($var_name); 
			}
		} elsif ($l->{TYPE} eq "DATA") {
			if (Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
				return get_value_of($var_name) unless ($pointers);
			}
		}
	}
	
	return $var_name;
}

sub has_fast_array($$)
{
	my ($e,$l) = @_;

	return 0 if ($l->{TYPE} ne "ARRAY");

	my $nl = GetNextLevel($e,$l);
	return 0 unless ($nl->{TYPE} eq "DATA");
	return 0 unless (hasType($nl->{DATA_TYPE}));

	my $t = getType($nl->{DATA_TYPE});

	# Only uint8 and string have fast array functions at the moment
	return ($t->{NAME} eq "uint8") or ($t->{NAME} eq "string");
}

sub is_charset_array($$)
{
	my ($e,$l) = @_;

	return 0 if ($l->{TYPE} ne "ARRAY");

	my $nl = GetNextLevel($e,$l);

	return 0 unless ($nl->{TYPE} eq "DATA");

	return has_property($e, "charset");
}

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

my $res = "";
my $deferred = "";
my $tabs = "";

####################################
# pidl() is our basic output routine
sub pidl($)
{
	my $d = shift;
	if ($d) {
		$res .= $tabs;
		$res .= $d;
	}
	$res .="\n";
}

####################################
# defer() is like pidl(), but adds to 
# a deferred buffer which is then added to the 
# output buffer at the end of the structure/union/function
# This is needed to cope with code that must be pushed back
# to the end of a block of elements
sub defer($)
{
	my $d = shift;
	if ($d) {
		$deferred .= $tabs;
		$deferred .= $d;
	}
	$deferred .="\n";
}

########################################
# add the deferred content to the current
# output
sub add_deferred()
{
	$res .= $deferred;
	$deferred = "";
}

sub indent()
{
	$tabs .= "\t";
}

sub deindent()
{
	$tabs = substr($tabs, 0, -1);
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
sub check_null_pointer($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;";
	}
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer, 
# putting the check at the end of the structure/function
sub check_null_pointer_deferred($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		defer "if ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;";
	}
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
# void return varient
sub check_null_pointer_void($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return;";
	}
}

#####################################################################
# work out is a parse function should be declared static or not
sub fn_prefix($)
{
	my $fn = shift;

	return "" if (has_property($fn, "public"));
	return "static ";
}

###################################################################
# setup any special flags for an element or structure
sub start_flags($)
{
	my $e = shift;
	my $flags = has_property($e, "flag");
	if (defined $flags) {
		pidl "{";
		indent;
		pidl "uint32_t _flags_save_$e->{TYPE} = ndr->flags;";
		pidl "ndr_set_flags(&ndr->flags, $flags);";
	}
}

###################################################################
# end any special flags for an element or structure
sub end_flags($)
{
	my $e = shift;
	my $flags = has_property($e, "flag");
	if (defined $flags) {
		pidl "ndr->flags = _flags_save_$e->{TYPE};";
		deindent;
		pidl "}";
	}
}

sub GenerateStructEnv($)
{
	my $x = shift;
	my %env;

	foreach my $e (@{$x->{ELEMENTS}}) {
		$env{$e->{NAME}} = "r->$e->{NAME}";
	}

	$env{"this"} = "r";

	return \%env;
}

sub EnvSubstituteValue($$)
{
	my ($env,$s) = @_;

	# Substitute the value() values in the env
	foreach my $e (@{$s->{ELEMENTS}}) {
		next unless (my $v = has_property($e, "value"));
		
		$env->{$e->{NAME}} = ParseExpr($v, $env);
	}

	return $env;
}

sub GenerateFunctionInEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
}

sub GenerateFunctionOutEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/out/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->out.$e->{NAME}";
		} elsif (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
}

#####################################################################
# parse the data of an array - push side
sub ParseArrayPushHeader($$$$$)
{
	my ($e,$l,$ndr,$var_name,$env) = @_;

	my $size;
	my $length;

	if ($l->{IS_ZERO_TERMINATED}) {
		$size = $length = "ndr_string_length($var_name, sizeof(*$var_name))";
	} else {
		$size = ParseExpr($l->{SIZE_IS}, $env);
		$length = ParseExpr($l->{LENGTH_IS}, $env);
	}

	if ((!$l->{IS_SURROUNDING}) and $l->{IS_CONFORMANT}) {
		pidl "NDR_CHECK(ndr_push_uint32($ndr, NDR_SCALARS, $size));";
	}
	
	if ($l->{IS_VARYING}) {
		pidl "NDR_CHECK(ndr_push_uint32($ndr, NDR_SCALARS, 0));";  # array offset
		pidl "NDR_CHECK(ndr_push_uint32($ndr, NDR_SCALARS, $length));";
	} 

	return $length;
}

#####################################################################
# parse an array - pull side
sub ParseArrayPullHeader($$$$$)
{
	my ($e,$l,$ndr,$var_name,$env) = @_;

	my $length;
	my $size;

	if ($l->{IS_CONFORMANT}) {
		$length = $size = "ndr_get_array_size($ndr, " . get_pointer_to($var_name) . ")";
	} elsif ($l->{IS_ZERO_TERMINATED}) { # Noheader arrays
		$length = $size = "ndr_get_string_size($ndr, sizeof(*$var_name))";
	} else {
		$length = $size = ParseExpr($l->{SIZE_IS}, $env);
	}

	if ((!$l->{IS_SURROUNDING}) and $l->{IS_CONFORMANT}) {
		pidl "NDR_CHECK(ndr_pull_array_size(ndr, " . get_pointer_to($var_name) . "));";
	}


	if ($l->{IS_VARYING}) {
		pidl "NDR_CHECK(ndr_pull_array_length($ndr, " . get_pointer_to($var_name) . "));";
		$length = "ndr_get_array_length($ndr, " . get_pointer_to($var_name) .")";
	}

	check_null_pointer($length);

	if ($length ne $size) {
		pidl "if ($length > $size) {";
		indent;
		pidl "return ndr_pull_error($ndr, NDR_ERR_ARRAY_SIZE, \"Bad array size %u should exceed array length %u\", $size, $length);";
		deindent;
		pidl "}";
	}

	if ($l->{IS_CONFORMANT} and not $l->{IS_ZERO_TERMINATED}) {
		my $size = ParseExpr($l->{SIZE_IS}, $env);
		defer "if ($var_name) {";
		check_null_pointer_deferred($size);
		defer "NDR_CHECK(ndr_check_array_size(ndr, (void*)" . get_pointer_to($var_name) . ", $size));";
		defer "}";
	}

	if ($l->{IS_VARYING} and not $l->{IS_ZERO_TERMINATED}) {
		my $length = ParseExpr($l->{LENGTH_IS}, $env);
		defer "if ($var_name) {";
		check_null_pointer_deferred($length);
		defer "NDR_CHECK(ndr_check_array_length(ndr, (void*)" . get_pointer_to($var_name) . ", $length));";
		defer "}"
	}

	if (not $l->{IS_FIXED} and not is_charset_array($e, $l)) {
		AllocateArrayLevel($e,$l,$ndr,$env,$size);
	}

	return $length;
}

sub compression_alg($$)
{
	my ($e,$l) = @_;
	my $compression = $l->{COMPRESSION};
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return $alg;
}

sub compression_clen($$$)
{
	my ($e,$l,$env) = @_;
	my $compression = $l->{COMPRESSION};
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return ParseExpr($clen, $env);
}

sub compression_dlen($$$)
{
	my ($e,$l,$env) = @_;
	my $compression = $l->{COMPRESSION};
	my ($alg, $clen, $dlen) = split(/ /, $compression);

	return ParseExpr($dlen, $env);
}

sub ParseCompressionPushStart($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	pidl "{";
	indent;
	pidl "struct ndr_push *$comndr;";
	pidl "NDR_CHECK(ndr_push_compression_start($ndr, &$comndr, $alg, $dlen));";

	return $comndr;
}

sub ParseCompressionPushEnd($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	pidl "NDR_CHECK(ndr_push_compression_end($ndr, $comndr, $alg, $dlen));";
	deindent;
	pidl "}";
}

sub ParseCompressionPullStart($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	pidl "{";
	indent;
	pidl "struct ndr_pull *$comndr;";
	pidl "NDR_CHECK(ndr_pull_compression_start($ndr, &$comndr, $alg, $dlen));";

	return $comndr;
}

sub ParseCompressionPullEnd($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	pidl "NDR_CHECK(ndr_pull_compression_end($ndr, $comndr, $alg, $dlen));";
	deindent;
	pidl "}";
}

sub ParseObfuscationPushStart($$)
{
	my ($e,$ndr) = @_;
	my $obfuscation = has_property($e, "obfuscation");

	pidl "NDR_CHECK(ndr_push_obfuscation_start($ndr, $obfuscation));";

	return $ndr;
}

sub ParseObfuscationPushEnd($$)
{
	my ($e,$ndr) = @_;
	my $obfuscation = has_property($e, "obfuscation");

	pidl "NDR_CHECK(ndr_push_obfuscation_end($ndr, $obfuscation));";
}

sub ParseObfuscationPullStart($$)
{
	my ($e,$ndr) = @_;
	my $obfuscation = has_property($e, "obfuscation");

	pidl "NDR_CHECK(ndr_pull_obfuscation_start($ndr, $obfuscation));";

	return $ndr;
}

sub ParseObfuscationPullEnd($$)
{
	my ($e,$ndr) = @_;
	my $obfuscation = has_property($e, "obfuscation");

	pidl "NDR_CHECK(ndr_pull_obfuscation_end($ndr, $obfuscation));";
}

sub ParseSubcontextPushStart($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE},$env);

	pidl "{";
	indent;
	pidl "struct ndr_push *$subndr;";
	pidl "NDR_CHECK(ndr_push_subcontext_start($ndr, &$subndr, $l->{HEADER_SIZE}, $subcontext_size));";

	if (defined $l->{COMPRESSION}) {
		$subndr = ParseCompressionPushStart($e, $l, $subndr, $env);
	}

	if (defined $l->{OBFUSCATION}) {
		$subndr = ParseObfuscationPushStart($e, $subndr);
	}

	return $subndr;
}

sub ParseSubcontextPushEnd($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE},$env);

	if (defined $l->{COMPRESSION}) {
		ParseCompressionPushEnd($e, $l, $subndr, $env);
	}

	if (defined $l->{OBFUSCATION}) {
		ParseObfuscationPushEnd($e, $subndr);
	}

	pidl "NDR_CHECK(ndr_push_subcontext_end($ndr, $subndr, $l->{HEADER_SIZE}, $subcontext_size));";
	deindent;
	pidl "}";
}

sub ParseSubcontextPullStart($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE},$env);

	pidl "{";
	indent;
	pidl "struct ndr_pull *$subndr;";
	pidl "NDR_CHECK(ndr_pull_subcontext_start($ndr, &$subndr, $l->{HEADER_SIZE}, $subcontext_size));";

	if (defined $l->{COMPRESSION}) {
		$subndr = ParseCompressionPullStart($e, $l, $subndr, $env);
	}

	if (defined $l->{OBFUSCATION}) {
		$subndr = ParseObfuscationPullStart($e, $subndr);
	}
	
	return $subndr;
}

sub ParseSubcontextPullEnd($$$$)
{
	my ($e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE},$env);

	if (defined $l->{COMPRESSION}) {
		ParseCompressionPullEnd($e, $l, $subndr, $env);
	}

	if (defined $l->{OBFUSCATION}) {
		ParseObfuscationPullEnd($e, $subndr);
	}

	pidl "NDR_CHECK(ndr_pull_subcontext_end($ndr, $subndr, $l->{HEADER_SIZE}, $subcontext_size));";
	deindent;
	pidl "}";
}

sub ParseElementPushLevel
{
	my ($e,$l,$ndr,$var_name,$env,$primitives,$deferred) = @_;

	my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);

	if ($l->{TYPE} eq "ARRAY" and ($l->{IS_CONFORMANT} or $l->{IS_VARYING} 
		or is_charset_array($e, $l))) {
		$var_name = get_pointer_to($var_name);
	}

	if (defined($ndr_flags)) {
		if ($l->{TYPE} eq "SUBCONTEXT") {
			my $subndr = ParseSubcontextPushStart($e, $l, $ndr, $env);
			ParseElementPushLevel($e, GetNextLevel($e, $l), $subndr, $var_name, $env, 1, 1);
			ParseSubcontextPushEnd($e, $l, $ndr, $env);
		} elsif ($l->{TYPE} eq "POINTER") {
			ParsePtrPush($e, $l, $var_name);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length = ParseArrayPushHeader($e, $l, $ndr, $var_name, $env); 

			my $nl = GetNextLevel($e, $l);

			# Allow speedups for arrays of scalar types
			if (is_charset_array($e,$l)) {
				pidl "NDR_CHECK(ndr_push_charset($ndr, $ndr_flags, $var_name, $length, sizeof(" . mapType($nl->{DATA_TYPE}) . "), CH_$e->{PROPERTIES}->{charset}));";
				return;
			} elsif (has_fast_array($e,$l)) {
				pidl "NDR_CHECK(ndr_push_array_$nl->{DATA_TYPE}($ndr, $ndr_flags, $var_name, $length));";
				return;
			} 
		} elsif ($l->{TYPE} eq "SWITCH") {
			ParseSwitchPush($e, $l, $ndr, $var_name, $ndr_flags, $env);
		} elsif ($l->{TYPE} eq "DATA") {
			ParseDataPush($e, $l, $ndr, $var_name, $ndr_flags);
		}
	}

	if ($l->{TYPE} eq "POINTER" and $deferred) {
		if ($l->{POINTER_TYPE} ne "ref") {
			pidl "if ($var_name) {";
			indent;
			if ($l->{POINTER_TYPE} eq "relative") {
				pidl "NDR_CHECK(ndr_push_relative_ptr2(ndr, $var_name));";
			}
		}
		$var_name = get_value_of($var_name);
		ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, 1, 1);

		if ($l->{POINTER_TYPE} ne "ref") {
			deindent;
			pidl "}";
		}
	} elsif ($l->{TYPE} eq "ARRAY" and not has_fast_array($e,$l) and
		not is_charset_array($e, $l)) {
		my $length = ParseExpr($l->{LENGTH_IS}, $env);
		my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";

		$var_name = $var_name . "[$counter]";

		if (($primitives and not $l->{IS_DEFERRED}) or ($deferred and $l->{IS_DEFERRED})) {
			pidl "for ($counter = 0; $counter < $length; $counter++) {";
			indent;
			ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, 1, 0);
			deindent;
			pidl "}";
		}

		if ($deferred and ContainsDeferred($e, $l)) {
			pidl "for ($counter = 0; $counter < $length; $counter++) {";
			indent;
			ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, 0, 1);
			deindent;
			pidl "}";
		}	
	} elsif ($l->{TYPE} eq "SWITCH") {
		ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, $primitives, $deferred);
	}
}

#####################################################################
# parse scalars in a structure element
sub ParseElementPush($$$$$$)
{
	my ($e,$ndr,$var_prefix,$env,$primitives,$deferred) = @_;
	my $subndr = undef;

	my $var_name = $var_prefix.$e->{NAME};

	$var_name = append_prefix($e, $var_name);

	return unless $primitives or ($deferred and ContainsDeferred($e, $e->{LEVELS}[0]));

	start_flags($e);

	if (my $value = has_property($e, "value")) {
		$var_name = ParseExpr($value, $env);
	}

	ParseElementPushLevel($e, $e->{LEVELS}[0], $ndr, $var_name, $env, $primitives, $deferred);

	end_flags($e);
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtrPush($$$)
{
	my ($e,$l,$var_name) = @_;

	if ($l->{POINTER_TYPE} eq "ref") {
		if ($l->{LEVEL} eq "EMBEDDED") {
			pidl "NDR_CHECK(ndr_push_ref_ptr(ndr, $var_name));";
		} else {
			check_null_pointer(get_value_of($var_name));
		}
	} elsif ($l->{POINTER_TYPE} eq "relative") {
		pidl "NDR_CHECK(ndr_push_relative_ptr1(ndr, $var_name));";
	} elsif ($l->{POINTER_TYPE} eq "unique") {
		pidl "NDR_CHECK(ndr_push_unique_ptr(ndr, $var_name));";
	} elsif ($l->{POINTER_TYPE} eq "sptr") {
		pidl "NDR_CHECK(ndr_push_sptr_ptr(ndr, $var_name));";
	} else {
		die("Unhandled pointer type $l->{POINTER_TYPE}");
	}
}

#####################################################################
# print scalars in a structure element
sub ParseElementPrint($$$)
{
	my($e,$var_name,$env) = @_;

	$var_name = append_prefix($e, $var_name);
	return if (has_property($e, "noprint"));

	if (my $value = has_property($e, "value")) {
		$var_name = "(ndr->flags & LIBNDR_PRINT_SET_VALUES)?" . ParseExpr($value,$env) . ":$var_name";
	}

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER") {
			pidl "ndr_print_ptr(ndr, \"$e->{NAME}\", $var_name);";
			pidl "ndr->depth++;";
			if ($l->{POINTER_TYPE} ne "ref") {
				pidl "if ($var_name) {";
				indent;
			}
			$var_name = get_value_of($var_name);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length;

			if ($l->{IS_CONFORMANT} or $l->{IS_VARYING} or 
				is_charset_array($e,$l)) { 
				$var_name = get_pointer_to($var_name); 
			}
			
			if ($l->{IS_ZERO_TERMINATED}) {
				$length = "ndr_string_length($var_name, sizeof(*$var_name))";
			} else {
				$length = ParseExpr($l->{LENGTH_IS}, $env);
			}

			if (is_charset_array($e,$l)) {
				pidl "ndr_print_string(ndr, \"$e->{NAME}\", $var_name);";
				last;
			} elsif (has_fast_array($e, $l)) {
				my $nl = GetNextLevel($e, $l);
				pidl "ndr_print_array_$nl->{DATA_TYPE}(ndr, \"$e->{NAME}\", $var_name, $length);";
				last;
			} else {
				my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";

				pidl "ndr->print(ndr, \"\%s: ARRAY(\%d)\", \"$e->{NAME}\", $length);";
				pidl 'ndr->depth++;';
				pidl "for ($counter=0;$counter<$length;$counter++) {";
				indent;
				pidl "char *idx_$l->{LEVEL_INDEX}=NULL;";
				pidl "asprintf(&idx_$l->{LEVEL_INDEX}, \"[\%d]\", $counter);";
				pidl "if (idx_$l->{LEVEL_INDEX}) {";
				indent;

				$var_name = $var_name . "[$counter]";
			}
		} elsif ($l->{TYPE} eq "DATA") {
			if (not Parse::Pidl::Typelist::is_scalar($l->{DATA_TYPE}) or Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
				$var_name = get_pointer_to($var_name);
			}
			pidl "ndr_print_$l->{DATA_TYPE}(ndr, \"$e->{NAME}\", $var_name);";
		} elsif ($l->{TYPE} eq "SWITCH") {
			my $switch_var = ParseExpr($l->{SWITCH_IS}, $env);
			check_null_pointer_void($switch_var);
			pidl "ndr_print_set_switch_value(ndr, " . get_pointer_to($var_name) . ", $switch_var);";
		} 
	}

	foreach my $l (reverse @{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER") {
			if ($l->{POINTER_TYPE} ne "ref") {
				deindent;
				pidl "}";
			}
			pidl "ndr->depth--;";
		} elsif (($l->{TYPE} eq "ARRAY")
			and not is_charset_array($e,$l)
			and not has_fast_array($e,$l)) {
			pidl "free(idx_$l->{LEVEL_INDEX});";
			deindent;
			pidl "}";
			deindent;
			pidl "}";
			pidl "ndr->depth--;";
		}
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseSwitchPull($$$$$$)
{
	my($e,$l,$ndr,$var_name,$ndr_flags,$env) = @_;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env);

	check_null_pointer($switch_var);

	$var_name = get_pointer_to($var_name);
	pidl "NDR_CHECK(ndr_pull_set_switch_value($ndr, $var_name, $switch_var));";
}

#####################################################################
# push switch element
sub ParseSwitchPush($$$$$$)
{
	my($e,$l,$ndr,$var_name,$ndr_flags,$env) = @_;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env);

	check_null_pointer($switch_var);
	$var_name = get_pointer_to($var_name);
	pidl "NDR_CHECK(ndr_push_set_switch_value($ndr, $var_name, $switch_var));";
}

sub ParseDataPull($$$$$)
{
	my ($e,$l,$ndr,$var_name,$ndr_flags) = @_;

	if (Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
		$var_name = get_pointer_to($var_name);
	}

	$var_name = get_pointer_to($var_name);

	pidl "NDR_CHECK(ndr_pull_$l->{DATA_TYPE}($ndr, $ndr_flags, $var_name));";

	if (my $range = has_property($e, "range")) {
		$var_name = get_value_of($var_name);
		my ($low, $high) = split(/ /, $range, 2);
		pidl "if ($var_name < $low || $var_name > $high) {";
		pidl "\treturn ndr_pull_error($ndr, NDR_ERR_RANGE, \"value out of range\");";
		pidl "}";
	}
}

sub ParseDataPush($$$$$)
{
	my ($e,$l,$ndr,$var_name,$ndr_flags) = @_;

	# strings are passed by value rather then reference
	if (not Parse::Pidl::Typelist::is_scalar($l->{DATA_TYPE}) or Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
		$var_name = get_pointer_to($var_name);
	}

	pidl "NDR_CHECK(ndr_push_$l->{DATA_TYPE}($ndr, $ndr_flags, $var_name));";
}

sub CalcNdrFlags($$$)
{
	my ($l,$primitives,$deferred) = @_;

	my $scalars = 0;
	my $buffers = 0;

	# Add NDR_SCALARS if this one is deferred 
	# and deferreds may be pushed
	$scalars = 1 if ($l->{IS_DEFERRED} and $deferred);

	# Add NDR_SCALARS if this one is not deferred and 
	# primitives may be pushed
	$scalars = 1 if (!$l->{IS_DEFERRED} and $primitives);
	
	# Add NDR_BUFFERS if this one contains deferred stuff
	# and deferreds may be pushed
	$buffers = 1 if ($l->{CONTAINS_DEFERRED} and $deferred);

	return "NDR_SCALARS|NDR_BUFFERS" if ($scalars and $buffers);
	return "NDR_SCALARS" if ($scalars);
	return "NDR_BUFFERS" if ($buffers);
	return undef;
}

sub ParseMemCtxPullStart($$$)
{
	my $e = shift;
	my $l = shift;
	my $ptr_name = shift;

	my $mem_r_ctx = "_mem_save_$e->{NAME}_$l->{LEVEL_INDEX}";
	my $mem_c_ctx = $ptr_name;
	my $mem_c_flags = "0";

	return if ($l->{TYPE} eq "ARRAY" and $l->{IS_FIXED});

	if (($l->{TYPE} eq "POINTER") and ($l->{POINTER_TYPE} eq "ref")) {
		my $nl = GetNextLevel($e, $l);
		my $next_is_array = ($nl->{TYPE} eq "ARRAY");
		my $next_is_string = (($nl->{TYPE} eq "DATA") and 
					($nl->{DATA_TYPE} eq "string"));
		if ($next_is_array or $next_is_string) {
			return;
		} else {
			$mem_c_flags = "LIBNDR_FLAG_REF_ALLOC";
		}
	}

	pidl "$mem_r_ctx = NDR_PULL_GET_MEM_CTX(ndr);";
	pidl "NDR_PULL_SET_MEM_CTX(ndr, $mem_c_ctx, $mem_c_flags);";
}

sub ParseMemCtxPullEnd($$)
{
	my $e = shift;
	my $l = shift;

	my $mem_r_ctx = "_mem_save_$e->{NAME}_$l->{LEVEL_INDEX}";
	my $mem_r_flags = "0";

	return if ($l->{TYPE} eq "ARRAY" and $l->{IS_FIXED});

	if (($l->{TYPE} eq "POINTER") and ($l->{POINTER_TYPE} eq "ref")) {
		my $nl = GetNextLevel($e, $l);
		my $next_is_array = ($nl->{TYPE} eq "ARRAY");
		my $next_is_string = (($nl->{TYPE} eq "DATA") and 
					($nl->{DATA_TYPE} eq "string"));
		if ($next_is_array or $next_is_string) {
			return;
		} else {
			$mem_r_flags = "LIBNDR_FLAG_REF_ALLOC";
		}
	}

	pidl "NDR_PULL_SET_MEM_CTX(ndr, $mem_r_ctx, $mem_r_flags);";
}

sub ParseElementPullLevel
{
	my($e,$l,$ndr,$var_name,$env,$primitives,$deferred) = @_;

	my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);

	if ($l->{TYPE} eq "ARRAY" and ($l->{IS_VARYING} or $l->{IS_CONFORMANT} 
		or is_charset_array($e,$l))) {
		$var_name = get_pointer_to($var_name);
	}

	# Only pull something if there's actually something to be pulled
	if (defined($ndr_flags)) {
		if ($l->{TYPE} eq "SUBCONTEXT") {
			my $subndr = ParseSubcontextPullStart($e, $l, $ndr, $env);
			ParseElementPullLevel($e, GetNextLevel($e,$l), $subndr, $var_name, $env, 1, 1);
			ParseSubcontextPullEnd($e, $l, $ndr, $env);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length = ParseArrayPullHeader($e, $l, $ndr, $var_name, $env);

			my $nl = GetNextLevel($e, $l);

			if (is_charset_array($e,$l)) {
				pidl "NDR_CHECK(ndr_pull_charset($ndr, $ndr_flags, ".get_pointer_to($var_name).", $length, sizeof(" . mapType($nl->{DATA_TYPE}) . "), CH_$e->{PROPERTIES}->{charset}));";
				return;
			} elsif (has_fast_array($e, $l)) {
				pidl "NDR_CHECK(ndr_pull_array_$nl->{DATA_TYPE}($ndr, $ndr_flags, $var_name, $length));";
				if ($l->{IS_ZERO_TERMINATED}) {
					# Make sure last element is zero!
					pidl "NDR_CHECK(ndr_check_string_terminator($ndr, $var_name, $length, sizeof(*$var_name)));";
				}
				return;
			}
		} elsif ($l->{TYPE} eq "POINTER") {
			ParsePtrPull($e, $l, $ndr, $var_name);
		} elsif ($l->{TYPE} eq "SWITCH") {
			ParseSwitchPull($e, $l, $ndr, $var_name, $ndr_flags, $env);
		} elsif ($l->{TYPE} eq "DATA") {
			ParseDataPull($e, $l, $ndr, $var_name, $ndr_flags);
		}
	}

	# add additional constructions
	if ($l->{TYPE} eq "POINTER" and $deferred) {
		if ($l->{POINTER_TYPE} ne "ref") {
			pidl "if ($var_name) {";
			indent;

			if ($l->{POINTER_TYPE} eq "relative") {
				pidl "struct ndr_pull_save _relative_save;";
				pidl "ndr_pull_save(ndr, &_relative_save);";
				pidl "NDR_CHECK(ndr_pull_relative_ptr2(ndr, $var_name));";
			}
		}

		ParseMemCtxPullStart($e,$l, $var_name);

		$var_name = get_value_of($var_name);
		ParseElementPullLevel($e,GetNextLevel($e,$l), $ndr, $var_name, $env, 1, 1);

		ParseMemCtxPullEnd($e,$l);

		if ($l->{POINTER_TYPE} ne "ref") {
    			if ($l->{POINTER_TYPE} eq "relative") {
				pidl "ndr_pull_restore(ndr, &_relative_save);";
			}
			deindent;
			pidl "}";
		}
	} elsif ($l->{TYPE} eq "ARRAY" and 
			not has_fast_array($e,$l) and not is_charset_array($e, $l)) {
		my $length = ParseExpr($l->{LENGTH_IS}, $env);
		my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";
		my $array_name = $var_name;

		$var_name = $var_name . "[$counter]";

		ParseMemCtxPullStart($e,$l, $array_name);

		if (($primitives and not $l->{IS_DEFERRED}) or ($deferred and $l->{IS_DEFERRED})) {
			pidl "for ($counter = 0; $counter < $length; $counter++) {";
			indent;
			ParseElementPullLevel($e,GetNextLevel($e,$l), $ndr, $var_name, $env, 1, 0);
			deindent;
			pidl "}";

			if ($l->{IS_ZERO_TERMINATED}) {
				# Make sure last element is zero!
				pidl "NDR_CHECK(ndr_check_string_terminator($ndr, $var_name, $length, sizeof(*$var_name)));";
			}
		}

		if ($deferred and ContainsDeferred($e, $l)) {
			pidl "for ($counter = 0; $counter < $length; $counter++) {";
			indent;
			ParseElementPullLevel($e,GetNextLevel($e,$l), $ndr, $var_name, $env, 0, 1);
			deindent;
			pidl "}";
		}

		ParseMemCtxPullEnd($e,$l);

	} elsif ($l->{TYPE} eq "SWITCH") {
		ParseElementPullLevel($e,GetNextLevel($e,$l), $ndr, $var_name, $env, $primitives, $deferred);
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPull($$$$$$)
{
	my($e,$ndr,$var_prefix,$env,$primitives,$deferred) = @_;

	my $var_name = $var_prefix.$e->{NAME};

	$var_name = append_prefix($e, $var_name);

	return unless $primitives or ($deferred and ContainsDeferred($e, $e->{LEVELS}[0]));

	start_flags($e);

	ParseElementPullLevel($e,$e->{LEVELS}[0],$ndr,$var_name,$env,$primitives,$deferred);

	end_flags($e);
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtrPull($$$$)
{
	my($e,$l,$ndr,$var_name) = @_;

	my $nl = GetNextLevel($e, $l);
	my $next_is_array = ($nl->{TYPE} eq "ARRAY");
	my $next_is_string = (($nl->{TYPE} eq "DATA") and 
						 ($nl->{DATA_TYPE} eq "string"));

	if ($l->{POINTER_TYPE} eq "ref") {
		unless ($l->{LEVEL} eq "TOP") {
			pidl "NDR_CHECK(ndr_pull_ref_ptr($ndr, &_ptr_$e->{NAME}));";
		}

		unless ($next_is_array or $next_is_string) {
			pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
			pidl "\tNDR_PULL_ALLOC($ndr, $var_name);"; 
			pidl "}";
		}
		
		return;
	} elsif (($l->{POINTER_TYPE} eq "unique") or 
		 ($l->{POINTER_TYPE} eq "relative") or
		 ($l->{POINTER_TYPE} eq "sptr")) {
		pidl "NDR_CHECK(ndr_pull_generic_ptr($ndr, &_ptr_$e->{NAME}));";
		pidl "if (_ptr_$e->{NAME}) {";
		indent;
	} else {
		die("Unhandled pointer type $l->{POINTER_TYPE}");
	}

	# Don't do this for arrays, they're allocated at the actual level 
	# of the array
	unless ($next_is_array or $next_is_string) { 
		pidl "NDR_PULL_ALLOC($ndr, $var_name);"; 
	} else {
		# FIXME: Yes, this is nasty.
		# We allocate an array twice
		# - once just to indicate that it's there,
		# - then the real allocation...
		pidl "NDR_PULL_ALLOC_SIZE($ndr, $var_name, 1);";
	}

	#pidl "memset($var_name, 0, sizeof($var_name));";
	if ($l->{POINTER_TYPE} eq "relative") {
		pidl "NDR_CHECK(ndr_pull_relative_ptr1($ndr, $var_name, _ptr_$e->{NAME}));";
	}
	deindent;
	pidl "} else {";
	pidl "\t$var_name = NULL;";
	pidl "}";
}

#####################################################################
# parse a struct
sub ParseStructPush($$)
{
	my($struct,$name) = @_;
	
	return unless defined($struct->{ELEMENTS});

	my $env = GenerateStructEnv($struct);

	EnvSubstituteValue($env, $struct);

	# save the old relative_base_offset
	pidl "uint32_t _save_relative_base_offset = ndr_push_get_relative_base_offset(ndr);" if defined($struct->{PROPERTIES}{relative_base});

	foreach my $e (@{$struct->{ELEMENTS}}) { 
		DeclareArrayVariables($e);
	}

	start_flags($struct);

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to push the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	my $e = $struct->{ELEMENTS}[-1];
	if (defined($struct->{SURROUNDING_ELEMENT})) {
		my $e = $struct->{SURROUNDING_ELEMENT};

		if (defined($e->{LEVELS}[0]) and 
			$e->{LEVELS}[0]->{TYPE} eq "ARRAY") {
			my $size = ParseExpr($e->{LEVELS}[0]->{SIZE_IS}, $env);

			pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, $size));";
		} else {
			pidl "NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_string_array_size(ndr, r->$e->{NAME})));";
		}
	}

	pidl "if (ndr_flags & NDR_SCALARS) {";
	indent;

	pidl "NDR_CHECK(ndr_push_align(ndr, $struct->{ALIGN}));";

	if (defined($struct->{PROPERTIES}{relative_base})) {
		# set the current offset as base for relative pointers
		# and store it based on the toplevel struct/union
		pidl "NDR_CHECK(ndr_push_setup_relative_base_offset1(ndr, r, ndr->offset));";
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPush($e, "ndr", "r->", $env, 1, 0);
	}	

	deindent;
	pidl "}";

	pidl "if (ndr_flags & NDR_BUFFERS) {";
	indent;
	if (defined($struct->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		pidl "NDR_CHECK(ndr_push_setup_relative_base_offset2(ndr, r));";
	}
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPush($e, "ndr", "r->", $env, 0, 1);
	}

	deindent;
	pidl "}";

	end_flags($struct);
	# restore the old relative_base_offset
	pidl "ndr_push_restore_relative_base_offset(ndr, _save_relative_base_offset);" if defined($struct->{PROPERTIES}{relative_base});
}

#####################################################################
# generate a push function for an enum
sub ParseEnumPush($$)
{
	my($enum,$name) = @_;
	my($type_fn) = $enum->{BASE_TYPE};

	start_flags($enum);
	pidl "NDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));";
	end_flags($enum);
}

#####################################################################
# generate a pull function for an enum
sub ParseEnumPull($$)
{
	my($enum,$name) = @_;
	my($type_fn) = $enum->{BASE_TYPE};
	my($type_v_decl) = mapType($type_fn);

	pidl "$type_v_decl v;";
	start_flags($enum);
	pidl "NDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));";
	pidl "*r = v;";

	end_flags($enum);
}

#####################################################################
# generate a print function for an enum
sub ParseEnumPrint($$)
{
	my($enum,$name) = @_;

	pidl "const char *val = NULL;";
	pidl "";

	start_flags($enum);

	pidl "switch (r) {";
	indent;
	my $els = \@{$enum->{ELEMENTS}};
	foreach my $i (0 .. $#{$els}) {
		my $e = ${$els}[$i];
		chomp $e;
		if ($e =~ /^(.*)=/) {
			$e = $1;
		}
		pidl "case $e: val = \"$e\"; break;";
	}

	deindent;
	pidl "}";
	
	pidl "ndr_print_enum(ndr, name, \"$enum->{TYPE}\", val, r);";

	end_flags($enum);
}

sub DeclEnum($)
{
	my ($e,$t) = @_;
	return "enum $e->{NAME} " . 
		($t eq "pull"?"*":"") . "r";
}

$typefamily{ENUM} = {
	DECL => \&DeclEnum,
	PUSH_FN_BODY => \&ParseEnumPush,
	PULL_FN_BODY => \&ParseEnumPull,
	PRINT_FN_BODY => \&ParseEnumPrint,
};

#####################################################################
# generate a push function for a bitmap
sub ParseBitmapPush($$)
{
	my($bitmap,$name) = @_;
	my($type_fn) = $bitmap->{BASE_TYPE};

	start_flags($bitmap);

	pidl "NDR_CHECK(ndr_push_$type_fn(ndr, NDR_SCALARS, r));";

	end_flags($bitmap);
}

#####################################################################
# generate a pull function for an bitmap
sub ParseBitmapPull($$)
{
	my($bitmap,$name) = @_;
	my $type_fn = $bitmap->{BASE_TYPE};
	my($type_decl) = mapType($bitmap->{BASE_TYPE});

	pidl "$type_decl v;";
	start_flags($bitmap);
	pidl "NDR_CHECK(ndr_pull_$type_fn(ndr, NDR_SCALARS, &v));";
	pidl "*r = v;";

	end_flags($bitmap);
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrintElement($$$)
{
	my($e,$bitmap,$name) = @_;
	my($type_decl) = mapType($bitmap->{BASE_TYPE});
	my($type_fn) = $bitmap->{BASE_TYPE};
	my($flag);

	if ($e =~ /^(\w+) .*$/) {
		$flag = "$1";
	} else {
		die "Bitmap: \"$name\" invalid Flag: \"$e\"";
	}

	pidl "ndr_print_bitmap_flag(ndr, sizeof($type_decl), \"$flag\", $flag, r);";
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrint($$)
{
	my($bitmap,$name) = @_;
	my($type_decl) = mapType($bitmap->{TYPE});
	my($type_fn) = $bitmap->{BASE_TYPE};

	start_flags($bitmap);

	pidl "ndr_print_$type_fn(ndr, name, r);";

	pidl "ndr->depth++;";
	foreach my $e (@{$bitmap->{ELEMENTS}}) {
		ParseBitmapPrintElement($e, $bitmap, $name);
	}
	pidl "ndr->depth--;";

	end_flags($bitmap);
}

sub DeclBitmap($$)
{
	my ($e,$t) = @_;
	return mapType(Parse::Pidl::Typelist::bitmap_type_fn($e->{DATA})) . 
		($t eq "pull"?" *":" ") . "r";
}

$typefamily{BITMAP} = {
	DECL => \&DeclBitmap,
	PUSH_FN_BODY => \&ParseBitmapPush,
	PULL_FN_BODY => \&ParseBitmapPull,
	PRINT_FN_BODY => \&ParseBitmapPrint,
};

#####################################################################
# generate a struct print function
sub ParseStructPrint($$)
{
	my($struct,$name) = @_;

	return unless defined $struct->{ELEMENTS};

	my $env = GenerateStructEnv($struct);

	EnvSubstituteValue($env, $struct);

	foreach my $e (@{$struct->{ELEMENTS}}) {
		DeclareArrayVariables($e);
	}

	pidl "ndr_print_struct(ndr, name, \"$name\");";

	start_flags($struct);

	pidl "ndr->depth++;";
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPrint($e, "r->$e->{NAME}", $env);
	}
	pidl "ndr->depth--;";

	end_flags($struct);
}

sub DeclarePtrVariables($)
{
	my $e = shift;
	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER" and 
			not ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP")) {
			pidl "uint32_t _ptr_$e->{NAME};";
			last;
		}
	}
}

sub DeclareArrayVariables($)
{
	my $e = shift;

	foreach my $l (@{$e->{LEVELS}}) {
		next if has_fast_array($e,$l);
		next if is_charset_array($e,$l);
		if ($l->{TYPE} eq "ARRAY") {
			pidl "uint32_t cntr_$e->{NAME}_$l->{LEVEL_INDEX};";
		}
	}
}

sub need_decl_mem_ctx($$)
{
	my $e = shift;
	my $l = shift;

	return 0 if has_fast_array($e,$l);
	return 0 if is_charset_array($e,$l);
	return 1 if (($l->{TYPE} eq "ARRAY") and not $l->{IS_FIXED});

	if (($l->{TYPE} eq "POINTER") and ($l->{POINTER_TYPE} eq "ref")) {
		my $nl = GetNextLevel($e, $l);
		my $next_is_array = ($nl->{TYPE} eq "ARRAY");
		my $next_is_string = (($nl->{TYPE} eq "DATA") and 
					($nl->{DATA_TYPE} eq "string"));
		return 0 if ($next_is_array or $next_is_string);
	}
	return 1 if ($l->{TYPE} eq "POINTER");

	return 0;
}

sub DeclareMemCtxVariables($)
{
	my $e = shift;
	foreach my $l (@{$e->{LEVELS}}) {
		if (need_decl_mem_ctx($e, $l)) {
			pidl "TALLOC_CTX *_mem_save_$e->{NAME}_$l->{LEVEL_INDEX};";
		}
	}
}

#####################################################################
# parse a struct - pull side
sub ParseStructPull($$)
{
	my($struct,$name) = @_;

	return unless defined $struct->{ELEMENTS};

	my $env = GenerateStructEnv($struct);

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		DeclarePtrVariables($e);
		DeclareArrayVariables($e);
		DeclareMemCtxVariables($e);
	}

	# save the old relative_base_offset
	pidl "uint32_t _save_relative_base_offset = ndr_pull_get_relative_base_offset(ndr);" if defined($struct->{PROPERTIES}{relative_base});

	start_flags($struct);

	pidl "if (ndr_flags & NDR_SCALARS) {";
	indent;

	if (defined $struct->{SURROUNDING_ELEMENT}) {
		pidl "NDR_CHECK(ndr_pull_array_size(ndr, &r->$struct->{SURROUNDING_ELEMENT}->{NAME}));";
	}

	pidl "NDR_CHECK(ndr_pull_align(ndr, $struct->{ALIGN}));";

	if (defined($struct->{PROPERTIES}{relative_base})) {
		# set the current offset as base for relative pointers
		# and store it based on the toplevel struct/union
		pidl "NDR_CHECK(ndr_pull_setup_relative_base_offset1(ndr, r, ndr->offset));";
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPull($e, "ndr", "r->", $env, 1, 0);
	}	

	add_deferred();

	deindent;
	pidl "}";
	pidl "if (ndr_flags & NDR_BUFFERS) {";
	indent;
	if (defined($struct->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		pidl "NDR_CHECK(ndr_pull_setup_relative_base_offset2(ndr, r));";
	}
	foreach my $e (@{$struct->{ELEMENTS}}) {
		ParseElementPull($e, "ndr", "r->", $env, 0, 1);
	}

	add_deferred();

	deindent;
	pidl "}";

	end_flags($struct);
	# restore the old relative_base_offset
	pidl "ndr_pull_restore_relative_base_offset(ndr, _save_relative_base_offset);" if defined($struct->{PROPERTIES}{relative_base});
}

#####################################################################
# calculate size of ndr struct
sub ParseStructNdrSize($)
{
	my $t = shift;
	my $sizevar;

	if (my $flags = has_property($t, "flag")) {
		pidl "flags |= $flags;";
	}
	pidl "return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_$t->{NAME});";
}

sub DeclStruct($)
{
	my ($e,$t) = @_;
	return ($t ne "pull"?"const ":"") . "struct $e->{NAME} *r";
}

sub ArgsStructNdrSize($)
{
	my $d = shift;
	return "const struct $d->{NAME} *r, int flags";
}

$typefamily{STRUCT} = {
	PUSH_FN_BODY => \&ParseStructPush,
	DECL => \&DeclStruct,
	PULL_FN_BODY => \&ParseStructPull,
	PRINT_FN_BODY => \&ParseStructPrint,
	SIZE_FN_BODY => \&ParseStructNdrSize,
	SIZE_FN_ARGS => \&ArgsStructNdrSize,
};

#####################################################################
# calculate size of ndr struct
sub ParseUnionNdrSize($)
{
	my $t = shift;
	my $sizevar;

	if (my $flags = has_property($t, "flag")) {
		pidl "flags |= $flags;";
	}

	pidl "return ndr_size_union(r, flags, level, (ndr_push_flags_fn_t)ndr_push_$t->{NAME});";
}

#####################################################################
# parse a union - push side
sub ParseUnionPush($$)
{
	my ($e,$name) = @_;
	my $have_default = 0;

	# save the old relative_base_offset
	pidl "uint32_t _save_relative_base_offset = ndr_push_get_relative_base_offset(ndr);" if defined($e->{PROPERTIES}{relative_base});
	pidl "int level;";

	start_flags($e);

	pidl "level = ndr_push_get_switch_value(ndr, r);";

	pidl "if (ndr_flags & NDR_SCALARS) {";
	indent;

	if (defined($e->{SWITCH_TYPE})) {
		pidl "NDR_CHECK(ndr_push_$e->{SWITCH_TYPE}(ndr, NDR_SCALARS, level));";
	}

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		}
		pidl "$el->{CASE}:";

		if ($el->{TYPE} ne "EMPTY") {
			indent;
			if (defined($e->{PROPERTIES}{relative_base})) {
				pidl "NDR_CHECK(ndr_push_align(ndr, $el->{ALIGN}));";
				# set the current offset as base for relative pointers
				# and store it based on the toplevel struct/union
				pidl "NDR_CHECK(ndr_push_setup_relative_base_offset1(ndr, r, ndr->offset));";
			}
			DeclareArrayVariables($el);
			ParseElementPush($el, "ndr", "r->", {}, 1, 0);
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	deindent;
	pidl "}";
	pidl "if (ndr_flags & NDR_BUFFERS) {";
	indent;
	if (defined($e->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		pidl "NDR_CHECK(ndr_push_setup_relative_base_offset2(ndr, r));";
	}
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		pidl "$el->{CASE}:";
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPush($el, "ndr", "r->", {}, 0, 1);
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";

	deindent;
	pidl "}";
	end_flags($e);
	# restore the old relative_base_offset
	pidl "ndr_push_restore_relative_base_offset(ndr, _save_relative_base_offset);" if defined($e->{PROPERTIES}{relative_base});
}

#####################################################################
# print a union
sub ParseUnionPrint($$)
{
	my ($e,$name) = @_;
	my $have_default = 0;

	pidl "int level = ndr_print_get_switch_value(ndr, r);";

	foreach my $el (@{$e->{ELEMENTS}}) {
		DeclareArrayVariables($el);
	}

	pidl "ndr_print_union(ndr, name, level, \"$name\");";
	start_flags($e);

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		}
		pidl "$el->{CASE}:";
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPrint($el, "r->$el->{NAME}", {});
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\tndr_print_bad_level(ndr, name, level);";
	}
	deindent;
	pidl "}";

	end_flags($e);
}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($$)
{
	my ($e,$name) = @_;
	my $have_default = 0;
	my $switch_type = $e->{SWITCH_TYPE};

	# save the old relative_base_offset
	pidl "uint32_t _save_relative_base_offset = ndr_pull_get_relative_base_offset(ndr);" if defined($e->{PROPERTIES}{relative_base});
	pidl "int level;";
	if (defined($switch_type)) {
		if (Parse::Pidl::Typelist::typeIs($switch_type, "ENUM")) {
			$switch_type = Parse::Pidl::Typelist::enum_type_fn(getType($switch_type));
		}
		pidl mapType($switch_type) . " _level;";
	}

	my %double_cases = ();
	foreach my $el (@{$e->{ELEMENTS}}) {
		next if ($el->{TYPE} eq "EMPTY");
		next if ($double_cases{"$el->{NAME}"});
		DeclareMemCtxVariables($el);
		$double_cases{"$el->{NAME}"} = 1;
	}

	start_flags($e);

	pidl "level = ndr_pull_get_switch_value(ndr, r);";

	pidl "if (ndr_flags & NDR_SCALARS) {";
	indent;

	if (defined($switch_type)) {
		pidl "NDR_CHECK(ndr_pull_$switch_type(ndr, NDR_SCALARS, &_level));";
		pidl "if (_level != level) {"; 
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u for $name\", _level);";
		pidl "}";
	}

	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		} 
		pidl "$el->{CASE}: {";

		if ($el->{TYPE} ne "EMPTY") {
			indent;
			DeclarePtrVariables($el);
			DeclareArrayVariables($el);
			if (defined($e->{PROPERTIES}{relative_base})) {
				pidl "NDR_CHECK(ndr_pull_align(ndr, $el->{ALIGN}));";
				# set the current offset as base for relative pointers
				# and store it based on the toplevel struct/union
				pidl "NDR_CHECK(ndr_pull_setup_relative_base_offset1(ndr, r, ndr->offset));";
			}
			ParseElementPull($el, "ndr", "r->", {}, 1, 0);
			deindent;
		}
		pidl "break; }";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";
	deindent;
	pidl "}";
	pidl "if (ndr_flags & NDR_BUFFERS) {";
	indent;
	if (defined($e->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		pidl "NDR_CHECK(ndr_pull_setup_relative_base_offset2(ndr, r));";
	}
	pidl "switch (level) {";
	indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		pidl "$el->{CASE}:";
		if ($el->{TYPE} ne "EMPTY") {
			indent;
			ParseElementPull($el, "ndr", "r->", {}, 0, 1);
			deindent;
		}
		pidl "break;";
		pidl "";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);";
	}
	deindent;
	pidl "}";

	deindent;
	pidl "}";

	add_deferred();

	end_flags($e);
	# restore the old relative_base_offset
	pidl "ndr_pull_restore_relative_base_offset(ndr, _save_relative_base_offset);" if defined($e->{PROPERTIES}{relative_base});
}

sub DeclUnion($$)
{
	my ($e,$t) = @_;
	return ($t ne "pull"?"const ":"") . "union $e->{NAME} *r";
}

sub ArgsUnionNdrSize($)
{
	my $d = shift;
	return "const union $d->{NAME} *r, uint32_t level, int flags";
}

$typefamily{UNION} = {
	PUSH_FN_BODY => \&ParseUnionPush,
	DECL => \&DeclUnion,
	PULL_FN_BODY => \&ParseUnionPull,
	PRINT_FN_BODY => \&ParseUnionPrint,
	SIZE_FN_ARGS => \&ArgsUnionNdrSize,
	SIZE_FN_BODY => \&ParseUnionNdrSize,
};
	
#####################################################################
# parse a typedef - push side
sub ParseTypedefPush($)
{
	my($e) = shift;

	my $args = $typefamily{$e->{DATA}->{TYPE}}->{DECL}->($e,"push");
	pidl fn_prefix($e) . "NTSTATUS ndr_push_$e->{NAME}(struct ndr_push *ndr, int ndr_flags, $args)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PUSH_FN_BODY}->($e->{DATA}, $e->{NAME});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";;
}

#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($)
{
	my($e) = shift;

	my $args = $typefamily{$e->{DATA}->{TYPE}}->{DECL}->($e,"pull");

	pidl fn_prefix($e) . "NTSTATUS ndr_pull_$e->{NAME}(struct ndr_pull *ndr, int ndr_flags, $args)";

	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PULL_FN_BODY}->($e->{DATA}, $e->{NAME});
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a typedef - print side
sub ParseTypedefPrint($)
{
	my($e) = shift;

	my $args = $typefamily{$e->{DATA}->{TYPE}}->{DECL}->($e,"print");

	pidl "void ndr_print_$e->{NAME}(struct ndr_print *ndr, const char *name, $args)";
	pidl "{";
	indent;
	$typefamily{$e->{DATA}->{TYPE}}->{PRINT_FN_BODY}->($e->{DATA}, $e->{NAME});
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
## calculate the size of a structure
sub ParseTypedefNdrSize($)
{
	my($t) = shift;

	my $tf = $typefamily{$t->{DATA}->{TYPE}};
	my $args = $tf->{SIZE_FN_ARGS}->($t);

	pidl "size_t ndr_size_$t->{NAME}($args)";
	pidl "{";
	indent;
	$typefamily{$t->{DATA}->{TYPE}}->{SIZE_FN_BODY}->($t);
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function - print side
sub ParseFunctionPrint($)
{
	my($fn) = shift;

	return if has_property($fn, "noprint");

	pidl "void ndr_print_$fn->{NAME}(struct ndr_print *ndr, const char *name, int flags, const struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		DeclareArrayVariables($e);
	}

	pidl "ndr_print_struct(ndr, name, \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	pidl "if (flags & NDR_SET_VALUES) {";
	pidl "\tndr->flags |= LIBNDR_PRINT_SET_VALUES;";
	pidl "}";

	pidl "if (flags & NDR_IN) {";
	indent;
	pidl "ndr_print_struct(ndr, \"in\", \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	my $env = GenerateFunctionInEnv($fn);
	EnvSubstituteValue($env, $fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			ParseElementPrint($e, "r->in.$e->{NAME}", $env);
		}
	}
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	
	pidl "if (flags & NDR_OUT) {";
	indent;
	pidl "ndr_print_struct(ndr, \"out\", \"$fn->{NAME}\");";
	pidl "ndr->depth++;";

	$env = GenerateFunctionOutEnv($fn);
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			ParseElementPrint($e, "r->out.$e->{NAME}", $env);
		}
	}
	if ($fn->{RETURN_TYPE}) {
		pidl "ndr_print_$fn->{RETURN_TYPE}(ndr, \"result\", r->out.result);";
	}
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	
	pidl "ndr->depth--;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a function
sub ParseFunctionPush($)
{ 
	my($fn) = shift;

	return if has_property($fn, "nopush");

	pidl fn_prefix($fn) . "NTSTATUS ndr_push_$fn->{NAME}(struct ndr_push *ndr, int flags, const struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	foreach my $e (@{$fn->{ELEMENTS}}) { 
		DeclareArrayVariables($e);
	}

	pidl "if (flags & NDR_IN) {";
	indent;

	my $env = GenerateFunctionInEnv($fn);

	EnvSubstituteValue($env, $fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			ParseElementPush($e, "ndr", "r->in.", $env, 1, 1);
		}
	}

	deindent;
	pidl "}";

	pidl "if (flags & NDR_OUT) {";
	indent;

	$env = GenerateFunctionOutEnv($fn);
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			ParseElementPush($e, "ndr", "r->out.", $env, 1, 1);
		}
	}

	if ($fn->{RETURN_TYPE}) {
		pidl "NDR_CHECK(ndr_push_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, r->out.result));";
	}
    
	deindent;
	pidl "}";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

sub AllocateArrayLevel($$$$$)
{
	my ($e,$l,$ndr,$env,$size) = @_;

	my $var = ParseExpr($e->{NAME}, $env);

	check_null_pointer($size);
	my $pl = GetPrevLevel($e, $l);
	if (defined($pl) and 
	    $pl->{TYPE} eq "POINTER" and 
	    $pl->{POINTER_TYPE} eq "ref"
	    and not $l->{IS_ZERO_TERMINATED}) {
		pidl "if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {";
		pidl "\tNDR_PULL_ALLOC_N($ndr, $var, $size);";
		pidl "}";
	} else {
		pidl "NDR_PULL_ALLOC_N($ndr, $var, $size);";
	}

	if (grep(/in/,@{$e->{DIRECTION}}) and
	    grep(/out/,@{$e->{DIRECTION}}) and
	    $pl->{POINTER_TYPE} eq "ref") {
		pidl "memcpy(r->out.$e->{NAME},r->in.$e->{NAME},$size * sizeof(*r->in.$e->{NAME}));";
	}
}

#####################################################################
# parse a function
sub ParseFunctionPull($)
{ 
	my($fn) = shift;

	return if has_property($fn, "nopull");

	# pull function args
	pidl fn_prefix($fn) . "NTSTATUS ndr_pull_$fn->{NAME}(struct ndr_pull *ndr, int flags, struct $fn->{NAME} *r)";
	pidl "{";
	indent;

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) { 
		DeclarePtrVariables($e);
		DeclareArrayVariables($e);
	}

	my %double_cases = ();
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next if ($e->{TYPE} eq "EMPTY");
		next if ($double_cases{"$e->{NAME}"});
		DeclareMemCtxVariables($e);
		$double_cases{"$e->{NAME}"} = 1;
	}

	pidl "if (flags & NDR_IN) {";
	indent;

	# auto-init the out section of a structure. I originally argued that
	# this was a bad idea as it hides bugs, but coping correctly
	# with initialisation and not wiping ref vars is turning
	# out to be too tricky (tridge)
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});
		pidl "ZERO_STRUCT(r->out);";
		pidl "";
		last;
	}

	my $env = GenerateFunctionInEnv($fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		ParseElementPull($e, "ndr", "r->in.", $env, 1, 1);
	}

	# allocate the "simple" out ref variables. FIXME: Shouldn't this have it's
	# own flag rather then be in NDR_IN ?

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));
		next unless ($e->{LEVELS}[0]->{TYPE} eq "POINTER" and 
		             $e->{LEVELS}[0]->{POINTER_TYPE} eq "ref");
		next if (($e->{LEVELS}[1]->{TYPE} eq "DATA") and 
				 ($e->{LEVELS}[1]->{DATA_TYPE} eq "string"));
		next if (($e->{LEVELS}[1]->{TYPE} eq "ARRAY") 
			and   $e->{LEVELS}[1]->{IS_ZERO_TERMINATED});

		if ($e->{LEVELS}[1]->{TYPE} eq "ARRAY") {
			my $size = ParseExpr($e->{LEVELS}[1]->{SIZE_IS}, $env);
			check_null_pointer($size);
			
			pidl "NDR_PULL_ALLOC_N(ndr, r->out.$e->{NAME}, $size);";

			if (grep(/in/, @{$e->{DIRECTION}})) {
				pidl "memcpy(r->out.$e->{NAME}, r->in.$e->{NAME}, $size * sizeof(*r->in.$e->{NAME}));";
			} else {
				pidl "memset(r->out.$e->{NAME}, 0, $size * sizeof(*r->out.$e->{NAME}));";
			}
		} else {
			pidl "NDR_PULL_ALLOC(ndr, r->out.$e->{NAME});";
		
			if (grep(/in/, @{$e->{DIRECTION}})) {
				pidl "*r->out.$e->{NAME} = *r->in.$e->{NAME};";
			} else {
				pidl "ZERO_STRUCTP(r->out.$e->{NAME});";
			}
		}
	}

	add_deferred();
	deindent;
	pidl "}";
	
	pidl "if (flags & NDR_OUT) {";
	indent;

	$env = GenerateFunctionOutEnv($fn);
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});
		ParseElementPull($e, "ndr", "r->out.", $env, 1, 1);
	}

	if ($fn->{RETURN_TYPE}) {
		pidl "NDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}(ndr, NDR_SCALARS, &r->out.result));";
	}

	add_deferred();
	deindent;
	pidl "}";

	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# produce a function call table
sub FunctionTable($)
{
	my($interface) = shift;
	my $count = 0;
	my $uname = uc $interface->{NAME};

	$count = $#{$interface->{FUNCTIONS}}+1;

	return if ($count == 0);

	pidl "static const struct dcerpc_interface_call $interface->{NAME}\_calls[] = {";
	$count = 0;
	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		pidl "\t{";
		pidl "\t\t\"$d->{NAME}\",";
		pidl "\t\tsizeof(struct $d->{NAME}),";
		pidl "\t\t(ndr_push_flags_fn_t) ndr_push_$d->{NAME},";
		pidl "\t\t(ndr_pull_flags_fn_t) ndr_pull_$d->{NAME},";
		pidl "\t\t(ndr_print_function_t) ndr_print_$d->{NAME}";
		pidl "\t},";
		$count++;
	}
	pidl "\t{ NULL, 0, NULL, NULL, NULL }";
	pidl "};";
	pidl "";

	pidl "static const char * const $interface->{NAME}\_endpoint_strings[] = {";
	foreach my $ep (@{$interface->{ENDPOINTS}}) {
		pidl "\t$ep, ";
	}
	my $endpoint_count = $#{$interface->{ENDPOINTS}}+1;
	
	pidl "};";
	pidl "";

	pidl "static const struct dcerpc_endpoint_list $interface->{NAME}\_endpoints = {";
	pidl "\t.count\t= $endpoint_count,";
	pidl "\t.names\t= $interface->{NAME}\_endpoint_strings";
	pidl "};";
	pidl "";

	if (! defined $interface->{PROPERTIES}->{authservice}) {
		$interface->{PROPERTIES}->{authservice} = "\"host\"";
	}

	my @a = split / /, $interface->{PROPERTIES}->{authservice};
	my $authservice_count = $#a + 1;

	pidl "static const char * const $interface->{NAME}\_authservice_strings[] = {";
	foreach my $ap (@a) {
		pidl "\t$ap, ";
	}
	pidl "};";
	pidl "";

	pidl "static const struct dcerpc_authservice_list $interface->{NAME}\_authservices = {";
	pidl "\t.count\t= $endpoint_count,";
	pidl "\t.names\t= $interface->{NAME}\_authservice_strings";
	pidl "};";
	pidl "";

	pidl "\nconst struct dcerpc_interface_table dcerpc_table_$interface->{NAME} = {";
	pidl "\t.name\t\t= \"$interface->{NAME}\",";
	pidl "\t.uuid\t\t= DCERPC_$uname\_UUID,";
	pidl "\t.if_version\t= DCERPC_$uname\_VERSION,";
	pidl "\t.helpstring\t= DCERPC_$uname\_HELPSTRING,";
	pidl "\t.num_calls\t= $count,";
	pidl "\t.calls\t\t= $interface->{NAME}\_calls,";
	pidl "\t.endpoints\t= &$interface->{NAME}\_endpoints,";
	pidl "\t.authservices\t= &$interface->{NAME}\_authservices";
	pidl "};";
	pidl "";

	pidl "static NTSTATUS dcerpc_ndr_$interface->{NAME}_init(void)";
	pidl "{";
	pidl "\treturn librpc_register_interface(&dcerpc_table_$interface->{NAME});";
	pidl "}";
	pidl "";
}

#####################################################################
# parse the interface definitions
sub ParseInterface($$)
{
	my($interface,$needed) = @_;

	# Typedefs
	foreach my $d (@{$interface->{TYPEDEFS}}) {
		($needed->{"push_$d->{NAME}"}) && ParseTypedefPush($d);
		($needed->{"pull_$d->{NAME}"}) && ParseTypedefPull($d);
		($needed->{"print_$d->{NAME}"}) && ParseTypedefPrint($d);

		# Make sure we don't generate a function twice...
		$needed->{"push_$d->{NAME}"} = $needed->{"pull_$d->{NAME}"} = 
			$needed->{"print_$d->{NAME}"} = 0;

		($needed->{"ndr_size_$d->{NAME}"}) && ParseTypedefNdrSize($d);
	}

	# Functions
	foreach my $d (@{$interface->{FUNCTIONS}}) {
		($needed->{"push_$d->{NAME}"}) && ParseFunctionPush($d);
		($needed->{"pull_$d->{NAME}"}) && ParseFunctionPull($d);
		($needed->{"print_$d->{NAME}"}) && ParseFunctionPrint($d);

		# Make sure we don't generate a function twice...
		$needed->{"push_$d->{NAME}"} = $needed->{"pull_$d->{NAME}"} = 
			$needed->{"print_$d->{NAME}"} = 0;
	}

	FunctionTable($interface);
}

sub RegistrationFunction($$)
{
	my ($idl,$filename) = @_;

	$filename =~ /.*\/ndr_(.*).c/;
	my $basename = $1;
	pidl "NTSTATUS dcerpc_$basename\_init(void)";
	pidl "{";
	indent;
	pidl "NTSTATUS status = NT_STATUS_OK;";
	foreach my $interface (@{$idl}) {
		next if $interface->{TYPE} ne "INTERFACE";

		my $count = ($#{$interface->{FUNCTIONS}}+1);

		next if ($count == 0);

		pidl "status = dcerpc_ndr_$interface->{NAME}_init();";
		pidl "if (NT_STATUS_IS_ERR(status)) {";
		pidl "\treturn status;";
		pidl "}";
		pidl "";
	}
	pidl "return status;";
	deindent;
	pidl "}";
	pidl "";
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$)
{
	my($ndr,$filename) = @_;

	$tabs = "";
	my $h_filename = $filename;
	$res = "";

	if ($h_filename =~ /(.*)\.c/) {
		$h_filename = "$1.h";
	}

	pidl "/* parser auto-generated by pidl */";
	pidl "";
	pidl "#include \"includes.h\"";
	pidl "#include \"librpc/gen_ndr/ndr_misc.h\"";
	pidl "#include \"librpc/gen_ndr/ndr_dcerpc.h\"";
	pidl "#include \"$h_filename\"";
	pidl "";

	my %needed = ();

	foreach my $x (@{$ndr}) {
		($x->{TYPE} eq "INTERFACE") && NeededInterface($x, \%needed);
	}

	foreach my $x (@{$ndr}) {
		($x->{TYPE} eq "INTERFACE") && ParseInterface($x, \%needed);
	}

	RegistrationFunction($ndr, $filename);

	return $res;
}

sub NeededFunction($$)
{
	my ($fn,$needed) = @_;
	$needed->{"pull_$fn->{NAME}"} = 1;
	$needed->{"push_$fn->{NAME}"} = 1;
	$needed->{"print_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		unless(defined($needed->{"pull_$e->{TYPE}"})) {
			$needed->{"pull_$e->{TYPE}"} = 1;
		}
		unless(defined($needed->{"push_$e->{TYPE}"})) {
			$needed->{"push_$e->{TYPE}"} = 1;
		}
		unless(defined($needed->{"print_$e->{TYPE}"})) {
			$needed->{"print_$e->{TYPE}"} = 1;
		}
	}
}

sub NeededTypedef($$)
{
	my ($t,$needed) = @_;
	if (has_property($t, "public")) {
		$needed->{"pull_$t->{NAME}"} = not has_property($t, "nopull");
		$needed->{"push_$t->{NAME}"} = not has_property($t, "nopush");
		$needed->{"print_$t->{NAME}"} = not has_property($t, "noprint");
	}

	if ($t->{DATA}->{TYPE} eq "STRUCT" or $t->{DATA}->{TYPE} eq "UNION") {
		if (has_property($t, "gensize")) {
			$needed->{"ndr_size_$t->{NAME}"} = 1;
		}

		for my $e (@{$t->{DATA}->{ELEMENTS}}) {
			$e->{PARENT} = $t->{DATA};
			if ($needed->{"pull_$t->{NAME}"} and
				not defined($needed->{"pull_$e->{TYPE}"})) {
				$needed->{"pull_$e->{TYPE}"} = 1;
			}
			if ($needed->{"push_$t->{NAME}"} and
				not defined($needed->{"push_$e->{TYPE}"})) {
				$needed->{"push_$e->{TYPE}"} = 1;
			}
			if ($needed->{"print_$t->{NAME}"} and 
				not defined($needed->{"print_$e->{TYPE}"})) {
				$needed->{"print_$e->{TYPE}"} = 1;
			}
		}
	}
}

#####################################################################
# work out what parse functions are needed
sub NeededInterface($$)
{
	my ($interface,$needed) = @_;
	foreach my $d (@{$interface->{FUNCTIONS}}) {
	    NeededFunction($d, $needed);
	}
	foreach my $d (reverse @{$interface->{TYPEDEFS}}) {
	    NeededTypedef($d, $needed);
	}
}

1;
