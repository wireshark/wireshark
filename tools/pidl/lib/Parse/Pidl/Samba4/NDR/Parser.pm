###################################################
# Samba4 NDR parser generator for IDL structures
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2006
# released under the GNU GPL

package Parse::Pidl::Samba4::NDR::Parser;
use parent Parse::Pidl::Base;

require Exporter;
push @ISA, qw(Exporter);
@EXPORT_OK = qw(check_null_pointer NeededFunction NeededElement NeededType $res NeededInterface TypeFunctionName ParseElementPrint);

use strict;
use warnings;
use Parse::Pidl::Typelist qw(hasType getType mapTypeName typeHasBody);
use Parse::Pidl::Util qw(has_property
			 ParseExpr
			 ParseExprExt
			 print_uuid
			 unmake_str
			 parse_int
			 parse_range);
use Parse::Pidl::CUtil qw(get_pointer_to get_value_of get_array_element);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred ContainsPipe is_charset_array);
use Parse::Pidl::Samba4 qw(is_intree choose_header ArrayDynamicallyAllocated);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv EnvSubstituteValue GenerateStructEnv);
use Parse::Pidl qw(warning);

use vars qw($VERSION);
$VERSION = '0.01';

# list of known types
my %typefamily;

sub new($$) {
	my ($class) = @_;
	my $self = { res => "", res_hdr => "", deferred => [], tabs => "", defer_tabs => "" };
	bless($self, $class);
}

sub get_typefamily($)
{
	my $n = shift;
	return $typefamily{$n};
}

sub append_prefix($$)
{
	my ($e, $var_name) = @_;
	my $pointers = 0;
	my $arrays = 0;

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER") {
			$pointers++;
		} elsif ($l->{TYPE} eq "ARRAY") {
			$arrays++;
			if (($pointers == 0) and 
			    (not $l->{IS_FIXED}) and
			    (not $l->{IS_INLINE})) {
				return get_value_of($var_name);
			}
		} elsif ($l->{TYPE} eq "DATA") {
			if (Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
				return get_value_of($var_name) unless ($pointers or $arrays);
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

	# Only uint8 has a fast array function at the moment
	return ($t->{NAME} eq "uint8");
}

sub is_public_struct
{
	my ($d) = @_;
	if (!has_property($d, "public")) {
		return 0;
	}
	my $t = $d;
	if ($d->{TYPE} eq "TYPEDEF") {
		$t = $d->{DATA};
	}
	return $t->{TYPE} eq "STRUCT";
}

####################################
# defer() is like pidl(), but adds to 
# a deferred buffer which is then added to the 
# output buffer at the end of the structure/union/function
# This is needed to cope with code that must be pushed back
# to the end of a block of elements
sub defer_indent($) { my ($self) = @_; $self->{defer_tabs}.="\t"; }
sub defer_deindent($) { my ($self) = @_; $self->{defer_tabs}=substr($self->{defer_tabs}, 0, -1); }

sub defer($$)
{
	my ($self, $d) = @_;
	if ($d) {
		push(@{$self->{deferred}}, $self->{defer_tabs}.$d);
	}
}

########################################
# add the deferred content to the current
# output
sub add_deferred($)
{
	my ($self) = @_;
	$self->pidl($_) foreach (@{$self->{deferred}});
	$self->{deferred} = [];
	$self->{defer_tabs} = "";
}

#####################################################################
# declare a function public or static, depending on its attributes
sub fn_declare($$$$)
{
	my ($self,$type,$fn,$decl) = @_;

	if (has_property($fn, "no$type")) {
		$self->pidl_hdr("$decl;");
		return 0;
	}

	if (has_property($fn, "public")) {
		$self->pidl_hdr("$decl;");
		$self->pidl("_PUBLIC_ $decl");
	} else {
		$self->pidl("static $decl");
	}

	return 1;
}

###################################################################
# setup any special flags for an element or structure
sub start_flags($$$)
{
	my ($self, $e, $ndr) = @_;
	my $flags = has_property($e, "flag");
	if (defined $flags) {
		$self->pidl("{");
		$self->indent;
		$self->pidl("uint32_t _flags_save_$e->{TYPE} = $ndr->flags;");
		$self->pidl("ndr_set_flags(&$ndr->flags, $flags);");
	}
}

###################################################################
# end any special flags for an element or structure
sub end_flags($$$)
{
	my ($self, $e, $ndr) = @_;
	my $flags = has_property($e, "flag");
	if (defined $flags) {
		$self->pidl("$ndr->flags = _flags_save_$e->{TYPE};");
		$self->deindent;
		$self->pidl("}");
	}
}

#####################################################################
# parse the data of an array - push side
sub ParseArrayPushHeader($$$$$$)
{
	my ($self,$e,$l,$ndr,$var_name,$env) = @_;

	my $size;
	my $length;

	if ($l->{IS_ZERO_TERMINATED}) {
		if (has_property($e, "charset")) {
			$size = $length = "ndr_charset_length($var_name, CH_$e->{PROPERTIES}->{charset})";
		} else {
			$size = $length = "ndr_string_length($var_name, sizeof(*$var_name))";
		}
		if (defined($l->{SIZE_IS})) {
			$size = ParseExpr($l->{SIZE_IS}, $env, $e);
		}
		if (defined($l->{LENGTH_IS})) {
			$length = ParseExpr($l->{LENGTH_IS}, $env, $e);
		}
	} else {
		$size = ParseExpr($l->{SIZE_IS}, $env, $e);
		$length = ParseExpr($l->{LENGTH_IS}, $env, $e);
	}

	if ((!$l->{IS_SURROUNDING}) and $l->{IS_CONFORMANT}) {
		$self->pidl("NDR_CHECK(ndr_push_uint3264($ndr, NDR_SCALARS, $size));");
	}

	if ($l->{IS_VARYING}) {
		$self->pidl("NDR_CHECK(ndr_push_uint3264($ndr, NDR_SCALARS, 0));");  # array offset
		$self->pidl("NDR_CHECK(ndr_push_uint3264($ndr, NDR_SCALARS, $length));");
	}

	return $length;
}

sub check_fully_dereferenced($$)
{
	my ($element, $env) = @_;

	return sub ($) {
		my $origvar = shift;
		my $check = 0;

		# Figure out the number of pointers in $ptr
		my $expandedvar = $origvar;
		$expandedvar =~ s/^(\**)//;
		my $ptr = $1;

		my $var = undef;
		foreach (keys %$env) {
			if ($env->{$_} eq $expandedvar) {
				$var = $_;
				last;
			}
		}
		
		return($origvar) unless (defined($var));
		my $e;
		foreach (@{$element->{PARENT}->{ELEMENTS}}) {
			if ($_->{NAME} eq $var) {
				$e = $_;
				last;
			}
		}

		$e or die("Environment doesn't match siblings");

		# See if pointer at pointer level $level
		# needs to be checked.
		my $nump = 0;
		foreach (@{$e->{LEVELS}}) {
			if ($_->{TYPE} eq "POINTER") {
				$nump = $_->{POINTER_INDEX}+1;
			}
		}
		warning($element->{ORIGINAL}, "Got pointer for `$e->{NAME}', expected fully dereferenced variable") if ($nump > length($ptr));
		return ($origvar);
	}
}	

sub check_null_pointer($$$$)
{
	my ($element, $env, $print_fn, $return) = @_;

	return sub ($) {
		my $expandedvar = shift;
		my $check = 0;

		# Figure out the number of pointers in $ptr
		$expandedvar =~ s/^(\**)//;
		my $ptr = $1;

		my $var = undef;
		foreach (keys %$env) {
			if ($env->{$_} eq $expandedvar) {
				$var = $_;
				last;
			}
		}
		
		if (defined($var)) {
			my $e;
			# lookup ptr in $e
			foreach (@{$element->{PARENT}->{ELEMENTS}}) {
				if ($_->{NAME} eq $var) {
					$e = $_;
					last;
				}
			}

			$e or die("Environment doesn't match siblings");

			# See if pointer at pointer level $level
			# needs to be checked.
			foreach my $l (@{$e->{LEVELS}}) {
				if ($l->{TYPE} eq "POINTER" and 
					$l->{POINTER_INDEX} == length($ptr)) {
					# No need to check ref pointers
					$check = ($l->{POINTER_TYPE} ne "ref");
					last;
				}

				if ($l->{TYPE} eq "DATA") {
					warning($element, "too much dereferences for `$var'");
				}
			}
		} else {
			warning($element, "unknown dereferenced expression `$expandedvar'");
			$check = 1;
		}
		
		$print_fn->("if ($ptr$expandedvar == NULL) $return") if $check;
	}
}

sub is_deferred_switch_non_empty($)
{
	# 1 if there needs to be a deferred branch in an ndr_pull/push,
	# 0 otherwise.
	my ($e) = @_;
	my $have_default = 0;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		}
		if ($el->{TYPE} ne "EMPTY") {
			if (ContainsDeferred($el, $el->{LEVELS}[0])) {
				return 1;
			}
		}
	}
	return ! $have_default;
}

sub ParseArrayPullGetSize($$$$$$)
{
	my ($self,$e,$l,$ndr,$var_name,$env) = @_;

	my $size;

	if ($l->{IS_CONFORMANT}) {
		$size = "ndr_get_array_size($ndr, " . get_pointer_to($var_name) . ")";
	} elsif ($l->{IS_ZERO_TERMINATED} and $l->{SIZE_IS} == 0 and $l->{LENGTH_IS} == 0) { # Noheader arrays
		$size = "ndr_get_string_size($ndr, sizeof(*$var_name))";
	} else {
		$size = ParseExprExt($l->{SIZE_IS}, $env, $e->{ORIGINAL},
			check_null_pointer($e, $env, sub { $self->pidl(shift); },
					   "return ndr_pull_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL Pointer for size_is()\");"),
			check_fully_dereferenced($e, $env));
	}

	$self->pidl("size_$e->{NAME}_$l->{LEVEL_INDEX} = $size;");
	my $array_size = "size_$e->{NAME}_$l->{LEVEL_INDEX}";

	if (my $range = has_property($e, "range")) {
		my ($low, $high) = parse_range($range);
		if ($low < 0) {
			warning(0, "$low is invalid for the range of an array size");
		}
		if ($low == 0) {
			$self->pidl("if ($array_size > $high) {");
		} else {
			$self->pidl("if ($array_size < $low || $array_size > $high) {");
		}
		$self->pidl("\treturn ndr_pull_error($ndr, NDR_ERR_RANGE, \"value out of range\");");
		$self->pidl("}");
	}

	return $array_size;
}

#####################################################################
# parse an array - pull side
sub ParseArrayPullGetLength($$$$$$;$)
{
	my ($self,$e,$l,$ndr,$var_name,$env,$array_size) = @_;

	if (not defined($array_size)) {
		$array_size = $self->ParseArrayPullGetSize($e, $l, $ndr, $var_name, $env);
	}

	if (not $l->{IS_VARYING}) {
		return $array_size;
	}

	my $length = "ndr_get_array_length($ndr, " . get_pointer_to($var_name) .")";
	$self->pidl("length_$e->{NAME}_$l->{LEVEL_INDEX} = $length;");
	my $array_length = "length_$e->{NAME}_$l->{LEVEL_INDEX}";

	if (my $range = has_property($e, "range")) {
		my ($low, $high) = parse_range($range);
		if ($low < 0) {
			warning(0, "$low is invalid for the range of an array size");
		}
		if ($low == 0) {
			$self->pidl("if ($array_length > $high) {");
		} else {
			$self->pidl("if ($array_length < $low || $array_length > $high) {");
		}
		$self->pidl("\treturn ndr_pull_error($ndr, NDR_ERR_RANGE, \"value out of range\");");
		$self->pidl("}");
	}

	return $array_length;
}

#####################################################################
# parse an array - pull side
sub ParseArrayPullHeader($$$$$$)
{
	my ($self,$e,$l,$ndr,$var_name,$env) = @_;

	if ((!$l->{IS_SURROUNDING}) and $l->{IS_CONFORMANT}) {
		$self->pidl("NDR_CHECK(ndr_pull_array_size($ndr, " . get_pointer_to($var_name) . "));");
	}

	if ($l->{IS_VARYING}) {
		$self->pidl("NDR_CHECK(ndr_pull_array_length($ndr, " . get_pointer_to($var_name) . "));");
	}

	my $array_size = $self->ParseArrayPullGetSize($e, $l, $ndr, $var_name, $env);
	my $array_length = $self->ParseArrayPullGetLength($e, $l, $ndr, $var_name, $env, $array_size);

	if ($array_length ne $array_size) {
		$self->pidl("if ($array_length > $array_size) {");
		$self->indent;
		$self->pidl("return ndr_pull_error($ndr, NDR_ERR_ARRAY_SIZE, \"Bad array size %u should exceed array length %u\", $array_size, $array_length);");
		$self->deindent;
		$self->pidl("}");
	}

	if ($l->{IS_CONFORMANT} and (defined($l->{SIZE_IS}) or not $l->{IS_ZERO_TERMINATED})) {
		$self->defer("if ($var_name) {");
		$self->defer_indent;
		my $size = ParseExprExt($l->{SIZE_IS}, $env, $e->{ORIGINAL},
			check_null_pointer($e, $env, sub { $self->defer(shift); },
					   "return ndr_pull_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL Pointer for size_is()\");"),
			check_fully_dereferenced($e, $env));
		$self->defer("NDR_CHECK(ndr_check_array_size($ndr, (void*)" . get_pointer_to($var_name) . ", $size));");
		$self->defer_deindent;
		$self->defer("}");
	}

	if ($l->{IS_VARYING} and (defined($l->{LENGTH_IS}) or not $l->{IS_ZERO_TERMINATED})) {
		$self->defer("if ($var_name) {");
		$self->defer_indent;
		my $length = ParseExprExt($l->{LENGTH_IS}, $env, $e->{ORIGINAL}, 
			check_null_pointer($e, $env, sub { $self->defer(shift); },
					   "return ndr_pull_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL Pointer for length_is()\");"),
			check_fully_dereferenced($e, $env));
		$self->defer("NDR_CHECK(ndr_check_array_length($ndr, (void*)" . get_pointer_to($var_name) . ", $length));");
		$self->defer_deindent;
		$self->defer("}");
	}

	if (ArrayDynamicallyAllocated($e,$l) and not is_charset_array($e,$l)) {
		$self->AllocateArrayLevel($e,$l,$ndr,$var_name,$array_size);
	}

	return $array_length;
}

sub compression_alg($$)
{
	my ($e, $l) = @_;
	my ($alg, $clen, $dlen) = split(/,/, $l->{COMPRESSION});

	return $alg;
}

sub compression_clen($$$)
{
	my ($e, $l, $env) = @_;
	my ($alg, $clen, $dlen) = split(/,/, $l->{COMPRESSION});

	return ParseExpr($clen, $env, $e->{ORIGINAL});
}

sub compression_dlen($$$)
{
	my ($e,$l,$env) = @_;
	my ($alg, $clen, $dlen) = split(/,/, $l->{COMPRESSION});

	return ParseExpr($dlen, $env, $e->{ORIGINAL});
}

sub ParseCompressionPushStart($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	$self->pidl("{");
	$self->indent;
	$self->pidl("struct ndr_push *$comndr;");
	$self->pidl("NDR_CHECK(ndr_push_compression_start($ndr, &$comndr, $alg, $dlen));");

	return $comndr;
}

sub ParseCompressionPushEnd($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	$self->pidl("NDR_CHECK(ndr_push_compression_end($ndr, $comndr, $alg, $dlen));");
	$self->deindent;
	$self->pidl("}");
}

sub ParseCompressionPullStart($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);
	my $clen = compression_clen($e, $l, $env);

	$self->pidl("{");
	$self->indent;
	$self->pidl("struct ndr_pull *$comndr;");
	$self->pidl("NDR_CHECK(ndr_pull_compression_start($ndr, &$comndr, $alg, $dlen, $clen));");

	return $comndr;
}

sub ParseCompressionPullEnd($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $comndr = "$ndr\_compressed";
	my $alg = compression_alg($e, $l);
	my $dlen = compression_dlen($e, $l, $env);

	$self->pidl("NDR_CHECK(ndr_pull_compression_end($ndr, $comndr, $alg, $dlen));");
	$self->deindent;
	$self->pidl("}");
}

sub ParseSubcontextPushStart($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE}, $env, $e->{ORIGINAL});

	$self->pidl("{");
	$self->indent;
	$self->pidl("struct ndr_push *$subndr;");
	$self->pidl("NDR_CHECK(ndr_push_subcontext_start($ndr, &$subndr, $l->{HEADER_SIZE}, $subcontext_size));");

	if (defined $l->{COMPRESSION}) {
		$subndr = $self->ParseCompressionPushStart($e, $l, $subndr, $env);
	}

	return $subndr;
}

sub ParseSubcontextPushEnd($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE}, $env, $e->{ORIGINAL});

	if (defined $l->{COMPRESSION}) {
		$self->ParseCompressionPushEnd($e, $l, $subndr, $env);
	}

	$self->pidl("NDR_CHECK(ndr_push_subcontext_end($ndr, $subndr, $l->{HEADER_SIZE}, $subcontext_size));");
	$self->deindent;
	$self->pidl("}");
}

sub ParseSubcontextPullStart($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE}, $env, $e->{ORIGINAL});

	$self->pidl("{");
	$self->indent;
	$self->pidl("struct ndr_pull *$subndr;");
	$self->pidl("NDR_CHECK(ndr_pull_subcontext_start($ndr, &$subndr, $l->{HEADER_SIZE}, $subcontext_size));");

	if (defined $l->{COMPRESSION}) {
		$subndr = $self->ParseCompressionPullStart($e, $l, $subndr, $env);
	}

	return $subndr;
}

sub ParseSubcontextPullEnd($$$$$)
{
	my ($self,$e,$l,$ndr,$env) = @_;
	my $subndr = "_ndr_$e->{NAME}";
	my $subcontext_size = ParseExpr($l->{SUBCONTEXT_SIZE}, $env, $e->{ORIGINAL});

	if (defined $l->{COMPRESSION}) {
		$self->ParseCompressionPullEnd($e, $l, $subndr, $env);
	}

	$self->pidl("NDR_CHECK(ndr_pull_subcontext_end($ndr, $subndr, $l->{HEADER_SIZE}, $subcontext_size));");
	$self->deindent;
	$self->pidl("}");
}

sub ParseElementPushLevel
{
	my ($self,$e,$l,$ndr,$var_name,$env,$primitives,$deferred) = @_;

	my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);

	if ($l->{TYPE} eq "ARRAY" and ($l->{IS_CONFORMANT} or $l->{IS_VARYING})) {
		$var_name = get_pointer_to($var_name);
	}

	if (defined($ndr_flags)) {
		if ($l->{TYPE} eq "SUBCONTEXT") {
			my $subndr = $self->ParseSubcontextPushStart($e, $l, $ndr, $env);
			$self->ParseElementPushLevel($e, GetNextLevel($e, $l), $subndr, $var_name, $env, 1, 1);
			$self->ParseSubcontextPushEnd($e, $l, $ndr, $env);
		} elsif ($l->{TYPE} eq "POINTER") {
			$self->ParsePtrPush($e, $l, $ndr, $var_name);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length = $self->ParseArrayPushHeader($e, $l, $ndr, $var_name, $env); 

			my $nl = GetNextLevel($e, $l);

			# Allow speedups for arrays of scalar types
			if (is_charset_array($e,$l)) {
				if ($l->{IS_TO_NULL}) {
					$self->pidl("NDR_CHECK(ndr_push_charset_to_null($ndr, $ndr_flags, $var_name, $length, sizeof(" . mapTypeName($nl->{DATA_TYPE}) . "), CH_$e->{PROPERTIES}->{charset}));");
				} else {
					$self->pidl("NDR_CHECK(ndr_push_charset($ndr, $ndr_flags, $var_name, $length, sizeof(" . mapTypeName($nl->{DATA_TYPE}) . "), CH_$e->{PROPERTIES}->{charset}));");
				}
				return;
			} elsif (has_fast_array($e,$l)) {
				$self->pidl("NDR_CHECK(ndr_push_array_$nl->{DATA_TYPE}($ndr, $ndr_flags, $var_name, $length));");
				return;
			} 
		} elsif ($l->{TYPE} eq "DATA") {
			$self->ParseDataPush($e, $l, $ndr, $var_name, $primitives, $deferred);
		} elsif ($l->{TYPE} eq "TYPEDEF") {
			$typefamily{$e->{DATA}->{TYPE}}->{PUSH_FN_BODY}->($self, $e->{DATA}, $ndr, $var_name);
		}
	}

	if ($l->{TYPE} eq "POINTER" and $l->{POINTER_TYPE} eq "ignore") {
		$self->pidl("/* [ignore] '$e->{NAME}' */");
	} elsif ($l->{TYPE} eq "POINTER" and $deferred) {
		my $rel_var_name = $var_name;
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($var_name) {");
			$self->indent;
			if ($l->{POINTER_TYPE} eq "relative") {
				$self->pidl("NDR_CHECK(ndr_push_relative_ptr2_start($ndr, $rel_var_name));");
			}
			if ($l->{POINTER_TYPE} eq "relative_short") {
				$self->pidl("NDR_CHECK(ndr_push_short_relative_ptr2($ndr, $var_name));");
			}
		}
		$var_name = get_value_of($var_name);
		$self->ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, 1, 1);

		if ($l->{POINTER_TYPE} ne "ref") {
			if ($l->{POINTER_TYPE} eq "relative") {
				$self->pidl("NDR_CHECK(ndr_push_relative_ptr2_end($ndr, $rel_var_name));");
			}
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "ARRAY" and not has_fast_array($e,$l) and
		not is_charset_array($e, $l)) {
		my $length = ParseExpr($l->{LENGTH_IS}, $env, $e->{ORIGINAL});
		my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";

		my $array_pointless = ($length eq "0");

		if ($array_pointless) {
			warning($e->{ORIGINAL}, "pointless array `$e->{NAME}' will always have size 0");
		}

		$var_name = get_array_element($var_name, $counter);

		if ((($primitives and not $l->{IS_DEFERRED}) or ($deferred and $l->{IS_DEFERRED})) and not $array_pointless) {
			$self->pidl("for ($counter = 0; $counter < ($length); $counter++) {");
			$self->indent;
			$self->ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, 1, 0);
			$self->deindent;
			$self->pidl("}");
		}

		if ($deferred and ContainsDeferred($e, $l) and not $array_pointless) {
			$self->pidl("for ($counter = 0; $counter < ($length); $counter++) {");
			$self->indent;
			$self->ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, 0, 1);
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "SWITCH") {
		my $nl = GetNextLevel($e,$l);
		my $needs_deferred_switch = is_deferred_switch_non_empty($nl);

		# Avoid setting a switch value if it will not be
		# consumed again in the NDR_BUFFERS pull
		if ($needs_deferred_switch or !$deferred) {
			$self->ParseSwitchPush($e, $l, $ndr, $var_name, $env);
		}
		$self->ParseElementPushLevel($e, GetNextLevel($e, $l), $ndr, $var_name, $env, $primitives, $deferred);
	}
}

#####################################################################
# parse scalars in a structure element
sub ParseElementPush($$$$$$)
{
	my ($self,$e,$ndr,$env,$primitives,$deferred) = @_;
	my $subndr = undef;

	my $var_name = $env->{$e->{NAME}};

	if (has_property($e, "skip") or has_property($e, "skip_noinit")) {
		$self->pidl("/* [skip] '$var_name' */");
		return;
	}

	return if ContainsPipe($e, $e->{LEVELS}[0]);

	return unless $primitives or ($deferred and ContainsDeferred($e, $e->{LEVELS}[0]));

	# Representation type is different from transmit_as
	if ($e->{REPRESENTATION_TYPE} ne $e->{TYPE}) {
		$self->pidl("{");
		$self->indent;
		my $transmit_name = "_transmit_$e->{NAME}";
		$self->pidl(mapTypeName($e->{TYPE}) ." $transmit_name;");
		$self->pidl("NDR_CHECK(ndr_$e->{REPRESENTATION_TYPE}_to_$e->{TYPE}($var_name, " . get_pointer_to($transmit_name) . "));");
		$var_name = $transmit_name;
	}

	$var_name = append_prefix($e, $var_name);

	$self->start_flags($e, $ndr);

	if (defined(my $value = has_property($e, "value"))) {
		$var_name = ParseExpr($value, $env, $e->{ORIGINAL});
	}

	$self->ParseElementPushLevel($e, $e->{LEVELS}[0], $ndr, $var_name, $env, $primitives, $deferred);

	$self->end_flags($e, $ndr);

	if ($e->{REPRESENTATION_TYPE} ne $e->{TYPE}) {
		$self->deindent;
		$self->pidl("}");
	}
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtrPush($$$$$)
{
	my ($self,$e,$l,$ndr,$var_name) = @_;

	if ($l->{POINTER_TYPE} eq "ref") {
		if ($l->{LEVEL_INDEX} > 0) {
			$self->pidl("if ($var_name == NULL) {");
			$self->indent;
			$self->pidl("return ndr_push_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL [ref] pointer\");");
			$self->deindent;
			$self->pidl("}");
		}
		if ($l->{LEVEL} eq "EMBEDDED") {
			$self->pidl("NDR_CHECK(ndr_push_ref_ptr(ndr)); /* $var_name */");
		}
	} elsif ($l->{POINTER_TYPE} eq "relative") {
		$self->pidl("NDR_CHECK(ndr_push_relative_ptr1($ndr, $var_name));");
	} elsif ($l->{POINTER_TYPE} eq "relative_short") {
		$self->pidl("NDR_CHECK(ndr_push_short_relative_ptr1($ndr, $var_name));");
	} elsif ($l->{POINTER_TYPE} eq "unique") {
		$self->pidl("NDR_CHECK(ndr_push_unique_ptr($ndr, $var_name));");
	} elsif ($l->{POINTER_TYPE} eq "full") {
		$self->pidl("NDR_CHECK(ndr_push_full_ptr($ndr, $var_name));");
	} elsif ($l->{POINTER_TYPE} eq "ignore") {
	        # We don't want this pointer to appear on the wire at all
		$self->pidl("NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));");
	} else {
		die("Unhandled pointer type $l->{POINTER_TYPE}");
	}
}

sub need_pointer_to($$$)
{
	my ($e, $l, $scalar_only) = @_;

	my $t;
	if (ref($l->{DATA_TYPE})) {
		$t = "$l->{DATA_TYPE}->{TYPE}_$l->{DATA_TYPE}->{NAME}";
	} else {
		$t = $l->{DATA_TYPE};
	}

	if (not Parse::Pidl::Typelist::is_scalar($t)) {
		return 1 if $scalar_only;
	}

	my $arrays = 0;

	foreach my $tl (@{$e->{LEVELS}}) {
		last if $l == $tl;
		if ($tl->{TYPE} eq "ARRAY") {
			$arrays++;
		}
	}

	if (Parse::Pidl::Typelist::scalar_is_reference($t)) {
		return 1 unless $arrays;
	}

	return 0;
}

sub ParseDataPrint($$$$$)
{
	my ($self, $e, $l, $ndr, $var_name) = @_;

	if (not ref($l->{DATA_TYPE}) or defined($l->{DATA_TYPE}->{NAME})) {

		if (need_pointer_to($e, $l, 1)) {
			$var_name = get_pointer_to($var_name);
		}

		$self->pidl(TypeFunctionName("ndr_print", $l->{DATA_TYPE})."($ndr, \"$e->{NAME}\", $var_name);");
	} else {
		$self->ParseTypePrint($l->{DATA_TYPE}, $ndr, $var_name);
	}
}

#####################################################################
# print scalars in a structure element
sub ParseElementPrint($$$$$)
{
	my($self, $e, $ndr, $var_name, $env) = @_;

	return if (has_property($e, "noprint"));
	my $cur_depth = 0;
	my $ignore_depth = 0xFFFF;

	$self->start_flags($e, $ndr);
	if ($e->{REPRESENTATION_TYPE} ne $e->{TYPE}) {
		$self->pidl("ndr_print_$e->{REPRESENTATION_TYPE}($ndr, \"$e->{NAME}\", $var_name);");
		$self->end_flags($e, $ndr);
		return;
	}

	$var_name = append_prefix($e, $var_name);

	if (defined(my $value = has_property($e, "value"))) {
		$var_name = "($ndr->flags & LIBNDR_PRINT_SET_VALUES)?" . ParseExpr($value,$env, $e->{ORIGINAL}) . ":$var_name";
	}

	foreach my $l (@{$e->{LEVELS}}) {
		$cur_depth += 1;

		if ($cur_depth > $ignore_depth) {
			next;
		}

		if ($l->{TYPE} eq "POINTER") {
			$self->pidl("ndr_print_ptr($ndr, \"$e->{NAME}\", $var_name);");
			if ($l->{POINTER_TYPE} eq "ignore") {
				$self->pidl("/* [ignore] '$e->{NAME}' */");
				$ignore_depth = $cur_depth;
				last;
			}
			$self->pidl("$ndr->depth++;");
			if ($l->{POINTER_TYPE} ne "ref") {
				$self->pidl("if ($var_name) {");
				$self->indent;
			}
			$var_name = get_value_of($var_name);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length;

			if ($l->{IS_CONFORMANT} or $l->{IS_VARYING}) {
				$var_name = get_pointer_to($var_name); 
			}
			
			if ($l->{IS_ZERO_TERMINATED} and not defined($l->{LENGTH_IS})) {
				$length = "ndr_string_length($var_name, sizeof(*$var_name))";
			} else {
				$length = ParseExprExt($l->{LENGTH_IS}, $env, $e->{ORIGINAL}, 
							check_null_pointer($e, $env, sub { $self->pidl(shift); }, "return;"), check_fully_dereferenced($e, $env));
			}

			if (is_charset_array($e,$l)) {
				$self->pidl("ndr_print_string($ndr, \"$e->{NAME}\", $var_name);");
				last;
			} elsif (has_fast_array($e, $l)) {
				my $nl = GetNextLevel($e, $l);
				$self->pidl("ndr_print_array_$nl->{DATA_TYPE}($ndr, \"$e->{NAME}\", $var_name, $length);");
				last;
			} else {
				my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";

				$self->pidl("$ndr->print($ndr, \"\%s: ARRAY(\%d)\", \"$e->{NAME}\", (int)$length);");
				$self->pidl("$ndr->depth++;");
				$self->pidl("for ($counter = 0; $counter < ($length); $counter++) {");
				$self->indent;

				$var_name = get_array_element($var_name, $counter);
			}
		} elsif ($l->{TYPE} eq "DATA") {
			$self->ParseDataPrint($e, $l, $ndr, $var_name);
		} elsif ($l->{TYPE} eq "SWITCH") {
			my $switch_var = ParseExprExt($l->{SWITCH_IS}, $env, $e->{ORIGINAL}, 
						check_null_pointer($e, $env, sub { $self->pidl(shift); }, "return;"), check_fully_dereferenced($e, $env));
			$self->pidl("ndr_print_set_switch_value($ndr, " . get_pointer_to($var_name) . ", $switch_var);");
		} 
	}

	foreach my $l (reverse @{$e->{LEVELS}}) {
		$cur_depth -= 1;

		if ($cur_depth > $ignore_depth) {
			next;
		}

		if ($l->{TYPE} eq "POINTER") {
			if ($l->{POINTER_TYPE} eq "ignore") {
				next;
			}

			if ($l->{POINTER_TYPE} ne "ref") {
				$self->deindent;
				$self->pidl("}");
			}
			$self->pidl("$ndr->depth--;");
		} elsif (($l->{TYPE} eq "ARRAY")
			and not is_charset_array($e,$l)
			and not has_fast_array($e,$l)) {
			$self->deindent;
			$self->pidl("}");
			$self->pidl("$ndr->depth--;");
		}
	}

	$self->end_flags($e, $ndr);
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseSwitchPull($$$$$$)
{
	my($self,$e,$l,$ndr,$var_name,$env) = @_;
	my $switch_var = ParseExprExt($l->{SWITCH_IS}, $env, $e->{ORIGINAL}, 
		check_null_pointer($e, $env, sub { $self->pidl(shift); },
				   "return ndr_pull_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL Pointer for switch_is()\");"),
		check_fully_dereferenced($e, $env));

	$var_name = get_pointer_to($var_name);
	$self->pidl("NDR_CHECK(ndr_pull_set_switch_value($ndr, $var_name, $switch_var));");
}

#####################################################################
# push switch element
sub ParseSwitchPush($$$$$$)
{
	my($self,$e,$l,$ndr,$var_name,$env) = @_;
	my $switch_var = ParseExprExt($l->{SWITCH_IS}, $env, $e->{ORIGINAL}, 
		check_null_pointer($e, $env, sub { $self->pidl(shift); },
				   "return ndr_push_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL Pointer for switch_is()\");"),
		check_fully_dereferenced($e, $env));

	$var_name = get_pointer_to($var_name);
	$self->pidl("NDR_CHECK(ndr_push_set_switch_value($ndr, $var_name, $switch_var));");
}

sub ParseDataPull($$$$$$$)
{
	my ($self,$e,$l,$ndr,$var_name,$primitives,$deferred) = @_;

	if (not ref($l->{DATA_TYPE}) or defined($l->{DATA_TYPE}->{NAME})) {

		my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);

		if (need_pointer_to($e, $l, 0)) {
			$var_name = get_pointer_to($var_name);
		}

		$var_name = get_pointer_to($var_name);

		if (my $depth = has_property($e, "max_recursion")) {
			my $d = parse_int($depth);
			$self->pidl("NDR_RECURSION_CHECK($ndr, $d);");
		}
		$self->pidl("NDR_CHECK(".TypeFunctionName("ndr_pull", $l->{DATA_TYPE})."($ndr, $ndr_flags, $var_name));");
		if (has_property($e, "max_recursion")) {
			$self->pidl("NDR_RECURSION_UNWIND($ndr);");
		}

		my $pl = GetPrevLevel($e, $l);

		my $range = has_property($e, "range");
		if ($range and (not $pl or $pl->{TYPE} ne "ARRAY")) {
			$var_name = get_value_of($var_name);
			my $signed = Parse::Pidl::Typelist::is_signed($l->{DATA_TYPE});
			my ($low, $high) = parse_range($range);
			if ($low < 0 and not $signed) {
				warning(0, "$low is invalid for the range of an unsigned type");
			}
			if ($low == 0 and not $signed) {
				$self->pidl("if ($var_name > $high) {");
			} else {
				$self->pidl("if ($var_name < $low || $var_name > $high) {");
			}
			$self->pidl("\treturn ndr_pull_error($ndr, NDR_ERR_RANGE, \"value out of range\");");
			$self->pidl("}");
		}
	} else {
		$self->ParseTypePull($l->{DATA_TYPE}, $ndr, $var_name, $primitives, $deferred);
	}
}

sub ParseDataPush($$$$$$$)
{
	my ($self,$e,$l,$ndr,$var_name,$primitives,$deferred) = @_;

	if (not ref($l->{DATA_TYPE}) or defined($l->{DATA_TYPE}->{NAME})) {

		my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);

		# strings are passed by value rather than reference
		if (need_pointer_to($e, $l, 1)) {
			$var_name = get_pointer_to($var_name);
		}

		$self->pidl("NDR_CHECK(".TypeFunctionName("ndr_push", $l->{DATA_TYPE})."($ndr, $ndr_flags, $var_name));");
	} else {
		$self->ParseTypePush($l->{DATA_TYPE}, $ndr, $var_name, $primitives, $deferred);
	}
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

sub ParseMemCtxPullFlags($$$$)
{
	my ($self, $e, $l) = @_;

	return undef unless ($l->{TYPE} eq "POINTER" or $l->{TYPE} eq "ARRAY");
	return undef if (($l->{TYPE} eq "POINTER") and ($l->{POINTER_TYPE} eq "ignore"));

	return undef unless ($l->{TYPE} ne "ARRAY" or ArrayDynamicallyAllocated($e,$l));
	return undef if has_fast_array($e, $l);
	return undef if is_charset_array($e, $l);

	my $mem_flags = "0";

	if (($l->{TYPE} eq "POINTER") and ($l->{POINTER_TYPE} eq "ref")) {
		my $nl = GetNextLevel($e, $l);
		return undef if ($nl->{TYPE} eq "PIPE");
		return undef if ($nl->{TYPE} eq "ARRAY");
		return undef if (($nl->{TYPE} eq "DATA") and ($nl->{DATA_TYPE} eq "string"));

		if ($l->{LEVEL} eq "TOP") {
			$mem_flags = "LIBNDR_FLAG_REF_ALLOC";
		}
	}

	return $mem_flags;
}

sub ParseMemCtxPullStart($$$$$)
{
	my ($self, $e, $l, $ndr, $ptr_name) = @_;

	my $mem_r_ctx = "_mem_save_$e->{NAME}_$l->{LEVEL_INDEX}";
	my $mem_c_ctx = $ptr_name;
	my $mem_c_flags = $self->ParseMemCtxPullFlags($e, $l);

	return unless defined($mem_c_flags);

	$self->pidl("$mem_r_ctx = NDR_PULL_GET_MEM_CTX($ndr);");
	$self->pidl("NDR_PULL_SET_MEM_CTX($ndr, $mem_c_ctx, $mem_c_flags);");
}

sub ParseMemCtxPullEnd($$$$)
{
	my ($self, $e, $l, $ndr) = @_;

	my $mem_r_ctx = "_mem_save_$e->{NAME}_$l->{LEVEL_INDEX}";
	my $mem_r_flags = $self->ParseMemCtxPullFlags($e, $l);

	return unless defined($mem_r_flags);

	$self->pidl("NDR_PULL_SET_MEM_CTX($ndr, $mem_r_ctx, $mem_r_flags);");
}

sub CheckStringTerminator($$$$$)
{
	my ($self,$ndr,$e,$l,$length) = @_;
	my $nl = GetNextLevel($e, $l);

	# Make sure last element is zero!
	$self->pidl("NDR_CHECK(ndr_check_string_terminator($ndr, $length, sizeof($nl->{DATA_TYPE}_t)));");
}

sub ParseElementPullLevel
{
	my($self,$e,$l,$ndr,$var_name,$env,$primitives,$deferred) = @_;

	my $ndr_flags = CalcNdrFlags($l, $primitives, $deferred);
	my $array_length = undef;

	if (has_property($e, "skip") or has_property($e, "skip_noinit")) {
		$self->pidl("/* [skip] '$var_name' */");
		if (not has_property($e, "skip_noinit")) {
			$self->pidl("NDR_ZERO_STRUCT($var_name);");
		}
		return;
	}

	if ($l->{TYPE} eq "ARRAY" and ($l->{IS_VARYING} or $l->{IS_CONFORMANT})) {
		$var_name = get_pointer_to($var_name);
	}

	# Only pull something if there's actually something to be pulled
	if (defined($ndr_flags)) {
		if ($l->{TYPE} eq "SUBCONTEXT") {
			my $subndr = $self->ParseSubcontextPullStart($e, $l, $ndr, $env);
			$self->ParseElementPullLevel($e, GetNextLevel($e,$l), $subndr, $var_name, $env, 1, 1);
			$self->ParseSubcontextPullEnd($e, $l, $ndr, $env);
		} elsif ($l->{TYPE} eq "ARRAY") {
			my $length = $self->ParseArrayPullHeader($e, $l, $ndr, $var_name, $env);
			$array_length = $length;

			my $nl = GetNextLevel($e, $l);

			if (is_charset_array($e,$l)) {
				if ($l->{IS_ZERO_TERMINATED}) {
					$self->CheckStringTerminator($ndr, $e, $l, $length);
				}
				if ($l->{IS_TO_NULL}) {
					$self->pidl("NDR_CHECK(ndr_pull_charset_to_null($ndr, $ndr_flags, ".get_pointer_to($var_name).", $length, sizeof(" . mapTypeName($nl->{DATA_TYPE}) . "), CH_$e->{PROPERTIES}->{charset}));");
				} else {
					$self->pidl("NDR_CHECK(ndr_pull_charset($ndr, $ndr_flags, ".get_pointer_to($var_name).", $length, sizeof(" . mapTypeName($nl->{DATA_TYPE}) . "), CH_$e->{PROPERTIES}->{charset}));");
				}
				return;
			} elsif (has_fast_array($e, $l)) {
				if ($l->{IS_ZERO_TERMINATED}) {
					$self->CheckStringTerminator($ndr,$e,$l,$length);
				}
				$self->pidl("NDR_CHECK(ndr_pull_array_$nl->{DATA_TYPE}($ndr, $ndr_flags, $var_name, $length));");
				return;
			}
		} elsif ($l->{TYPE} eq "POINTER") {
			$self->ParsePtrPull($e, $l, $ndr, $var_name);
		} elsif ($l->{TYPE} eq "DATA") {
			$self->ParseDataPull($e, $l, $ndr, $var_name, $primitives, $deferred);
		} elsif ($l->{TYPE} eq "TYPEDEF") {
			$typefamily{$e->{DATA}->{TYPE}}->{PULL_FN_BODY}->($self, $e->{DATA}, $ndr, $var_name);
		}
	}

	# add additional constructions
	if ($l->{TYPE} eq "POINTER" and $l->{POINTER_TYPE} eq "ignore") {
		$self->pidl("/* [ignore] '$e->{NAME}' */");
	} elsif ($l->{TYPE} eq "POINTER" and $deferred) {
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($var_name) {");
			$self->indent;

			if ($l->{POINTER_TYPE} eq "relative" or $l->{POINTER_TYPE} eq "relative_short") {
				$self->pidl("uint32_t _relative_save_offset;");
				$self->pidl("_relative_save_offset = $ndr->offset;");
				$self->pidl("NDR_CHECK(ndr_pull_relative_ptr2($ndr, $var_name));");
			}
		}

		$self->ParseMemCtxPullStart($e, $l, $ndr, $var_name);

		$var_name = get_value_of($var_name);
		$self->ParseElementPullLevel($e, GetNextLevel($e,$l), $ndr, $var_name, $env, 1, 1);

		$self->ParseMemCtxPullEnd($e, $l, $ndr);

		if ($l->{POINTER_TYPE} ne "ref") {
			if ($l->{POINTER_TYPE} eq "relative" or $l->{POINTER_TYPE} eq "relative_short") {
				$self->pidl("if ($ndr->offset > $ndr->relative_highest_offset) {");
				$self->indent;
				$self->pidl("$ndr->relative_highest_offset = $ndr->offset;");
				$self->deindent;
				$self->pidl("}");
				$self->pidl("$ndr->offset = _relative_save_offset;");
			}
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "ARRAY" and 
			not has_fast_array($e,$l) and not is_charset_array($e, $l)) {
		my $length = $array_length;
		my $counter = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";
		my $array_name = $var_name;

		if (not defined($length)) {
			$length = $self->ParseArrayPullGetLength($e, $l, $ndr, $var_name, $env);
		}

		$var_name = get_array_element($var_name, $counter);

		$self->ParseMemCtxPullStart($e, $l, $ndr, $array_name);

		if (($primitives and not $l->{IS_DEFERRED}) or ($deferred and $l->{IS_DEFERRED})) {
			my $nl = GetNextLevel($e,$l);

			if ($l->{IS_ZERO_TERMINATED}) {
				$self->CheckStringTerminator($ndr,$e,$l,$length);
			}

			$self->pidl("for ($counter = 0; $counter < ($length); $counter++) {");
			$self->indent;
			$self->ParseElementPullLevel($e, $nl, $ndr, $var_name, $env, 1, 0);
			$self->deindent;
			$self->pidl("}");
		}

		if ($deferred and ContainsDeferred($e, $l)) {
			$self->pidl("for ($counter = 0; $counter < ($length); $counter++) {");
			$self->defer("for ($counter = 0; $counter < ($length); $counter++) {");
			$self->defer_indent;
			$self->indent;
			$self->ParseElementPullLevel($e,GetNextLevel($e,$l), $ndr, $var_name, $env, 0, 1);
			$self->deindent;
			$self->defer_deindent;
			$self->pidl("}");
			$self->defer("}");
		}

		$self->ParseMemCtxPullEnd($e, $l, $ndr);

	} elsif ($l->{TYPE} eq "SWITCH") {
		my $nl = GetNextLevel($e,$l);
		my $needs_deferred_switch = is_deferred_switch_non_empty($nl);

		# Avoid setting a switch value if it will not be
		# consumed again in the NDR_BUFFERS pull
		if ($needs_deferred_switch or !$deferred) {
			$self->ParseSwitchPull($e, $l, $ndr, $var_name, $env);
		}
		$self->ParseElementPullLevel($e, $nl, $ndr, $var_name, $env, $primitives, $deferred);
	}
}

#####################################################################
# parse scalars in a structure element - pull size
sub ParseElementPull($$$$$$)
{
	my($self,$e,$ndr,$env,$primitives,$deferred) = @_;

	my $var_name = $env->{$e->{NAME}};
	my $represent_name;
	my $transmit_name;

	return if ContainsPipe($e, $e->{LEVELS}[0]);

	return unless $primitives or ($deferred and ContainsDeferred($e, $e->{LEVELS}[0]));

	if ($e->{REPRESENTATION_TYPE} ne $e->{TYPE}) {
		$self->pidl("{");
		$self->indent;
		$represent_name = $var_name;
		$transmit_name = "_transmit_$e->{NAME}";
		$var_name = $transmit_name;
		$self->pidl(mapTypeName($e->{TYPE})." $var_name;");
	}

	$var_name = append_prefix($e, $var_name);

	$self->start_flags($e, $ndr);

	$self->ParseElementPullLevel($e,$e->{LEVELS}[0],$ndr,$var_name,$env,$primitives,$deferred);

	$self->end_flags($e, $ndr);

	# Representation type is different from transmit_as
	if ($e->{REPRESENTATION_TYPE} ne $e->{TYPE}) {
		$self->pidl("NDR_CHECK(ndr_$e->{TYPE}_to_$e->{REPRESENTATION_TYPE}($transmit_name, ".get_pointer_to($represent_name)."));");
		$self->deindent;
		$self->pidl("}");
	}
}

#####################################################################
# parse a pointer in a struct element or function
sub ParsePtrPull($$$$$)
{
	my($self, $e,$l,$ndr,$var_name) = @_;

	my $nl = GetNextLevel($e, $l);
	my $next_is_array = ($nl->{TYPE} eq "ARRAY");
	my $next_is_string = (($nl->{TYPE} eq "DATA") and 
						 ($nl->{DATA_TYPE} eq "string"));

	if ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP") {

		if (!$next_is_array and !$next_is_string) {
			$self->pidl("if ($ndr->flags & LIBNDR_FLAG_REF_ALLOC) {");
			$self->pidl("\tNDR_PULL_ALLOC($ndr, $var_name);"); 
			$self->pidl("}");
		}

		return;
	} elsif ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "EMBEDDED") {
		$self->pidl("NDR_CHECK(ndr_pull_ref_ptr($ndr, &_ptr_$e->{NAME}));");
	} elsif (($l->{POINTER_TYPE} eq "unique") or 
		 ($l->{POINTER_TYPE} eq "relative") or
		 ($l->{POINTER_TYPE} eq "full")) {
		$self->pidl("NDR_CHECK(ndr_pull_generic_ptr($ndr, &_ptr_$e->{NAME}));");
	} elsif ($l->{POINTER_TYPE} eq "relative_short") {
		$self->pidl("NDR_CHECK(ndr_pull_relative_ptr_short($ndr, &_ptr_$e->{NAME}));");
	} elsif ($l->{POINTER_TYPE} eq "ignore") {
                #We want to consume the pointer bytes, but ignore the pointer value
	        $self->pidl("NDR_CHECK(ndr_pull_uint3264(ndr, NDR_SCALARS, &_ptr_$e->{NAME}));");
		$self->pidl("_ptr_$e->{NAME} = 0;");
	} else {
		die("Unhandled pointer type $l->{POINTER_TYPE}");
	}

	$self->pidl("if (_ptr_$e->{NAME}) {");
	$self->indent;

	if ($l->{POINTER_TYPE} eq "ignore") {
	        # Don't do anything, we don't want to do the
	        # allocation, as we forced it to NULL just above, and
	        # we may not know the declared type anyway.
	} else {
	        # Don't do this for arrays, they're allocated at the actual level 
	        # of the array
	        unless ($next_is_array or $next_is_string) { 
		       $self->pidl("NDR_PULL_ALLOC($ndr, $var_name);"); 
		} else {
		       # FIXME: Yes, this is nasty.
		       # We allocate an array twice
		       # - once just to indicate that it's there,
		       # - then the real allocation...
		       $self->pidl("NDR_PULL_ALLOC($ndr, $var_name);");
		}
	}

	#$self->pidl("memset($var_name, 0, sizeof($var_name));");
	if ($l->{POINTER_TYPE} eq "relative" or $l->{POINTER_TYPE} eq "relative_short") {
		$self->pidl("NDR_CHECK(ndr_pull_relative_ptr1($ndr, $var_name, _ptr_$e->{NAME}));");
	}
	$self->deindent;
	$self->pidl("} else {");
	$self->pidl("\t$var_name = NULL;");
	$self->pidl("}");
}

sub CheckRefPtrs($$$$)
{
	my ($self,$e,$ndr,$env) = @_;

	return if ContainsPipe($e, $e->{LEVELS}[0]);
	return if ($e->{LEVELS}[0]->{TYPE} ne "POINTER");
	return if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref");

	my $var_name = $env->{$e->{NAME}};
	$var_name = append_prefix($e, $var_name);

	$self->pidl("if ($var_name == NULL) {");
	$self->indent;
	$self->pidl("return ndr_push_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL [ref] pointer\");");
	$self->deindent;
	$self->pidl("}");
}

sub ParseStructPushPrimitives($$$$$)
{
	my ($self, $struct, $ndr, $varname, $env) = @_;

	$self->CheckRefPtrs($_, $ndr, $env) foreach (@{$struct->{ELEMENTS}});

	# see if the structure contains a conformant array. If it
	# does, then it must be the last element of the structure, and
	# we need to push the conformant length early, as it fits on
	# the wire before the structure (and even before the structure
	# alignment)
	if (defined($struct->{SURROUNDING_ELEMENT})) {
		my $e = $struct->{SURROUNDING_ELEMENT};

		if (defined($e->{LEVELS}[0]) and 
			$e->{LEVELS}[0]->{TYPE} eq "ARRAY") {
			my $size;
			
			if ($e->{LEVELS}[0]->{IS_ZERO_TERMINATED}) {
				if (has_property($e, "charset")) {
					$size = "ndr_charset_length($varname->$e->{NAME}, CH_$e->{PROPERTIES}->{charset})";
				} else {
					$size = "ndr_string_length($varname->$e->{NAME}, sizeof(*$varname->$e->{NAME}))";
				}
				if (defined($e->{LEVELS}[0]->{SIZE_IS})) {
					$size = ParseExpr($e->{LEVELS}[0]->{SIZE_IS}, $env, $e->{ORIGINAL});
				}
			} else {
				$size = ParseExpr($e->{LEVELS}[0]->{SIZE_IS}, $env, $e->{ORIGINAL});
			}

			$self->pidl("NDR_CHECK(ndr_push_uint3264($ndr, NDR_SCALARS, $size));");
		} else {
			$self->pidl("NDR_CHECK(ndr_push_uint3264($ndr, NDR_SCALARS, ndr_string_array_size($ndr, $varname->$e->{NAME})));");
		}
	}

	$self->pidl("NDR_CHECK(ndr_push_align($ndr, $struct->{ALIGN}));");

	if (defined($struct->{PROPERTIES}{relative_base})) {
		# set the current offset as base for relative pointers
		# and store it based on the toplevel struct/union
		$self->pidl("NDR_CHECK(ndr_push_setup_relative_base_offset1($ndr, $varname, $ndr->offset));");
	}

	$self->ParseElementPush($_, $ndr, $env, 1, 0) foreach (@{$struct->{ELEMENTS}});

	$self->pidl("NDR_CHECK(ndr_push_trailer_align($ndr, $struct->{ALIGN}));");
}

sub ParseStructPushDeferred($$$$)
{
	my ($self, $struct, $ndr, $varname, $env) = @_;
	if (defined($struct->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		$self->pidl("NDR_CHECK(ndr_push_setup_relative_base_offset2($ndr, $varname));");
	}
	$self->ParseElementPush($_, $ndr, $env, 0, 1) foreach (@{$struct->{ELEMENTS}});
}

#####################################################################
# parse a struct
sub ParseStructPush($$$$)
{
	my ($self, $struct, $ndr, $varname) = @_;
	
	return unless defined($struct->{ELEMENTS});

	my $env = GenerateStructEnv($struct, $varname);

	EnvSubstituteValue($env, $struct);

	$self->DeclareArrayVariablesNoZero($_, $env) foreach (@{$struct->{ELEMENTS}});

	$self->start_flags($struct, $ndr);

	$self->pidl("NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);");
	$self->pidl("if (ndr_flags & NDR_SCALARS) {");
	$self->indent;
	$self->ParseStructPushPrimitives($struct, $ndr, $varname, $env);
	$self->deindent;
	$self->pidl("}");

	$self->pidl("if (ndr_flags & NDR_BUFFERS) {");
	$self->indent;
	$self->ParseStructPushDeferred($struct, $ndr, $varname, $env);
	$self->deindent;
	$self->pidl("}");

	$self->end_flags($struct, $ndr);
}

#####################################################################
# generate a push function for an enum
sub ParseEnumPush($$$$)
{
	my($self,$enum,$ndr,$varname) = @_;
	my($type_fn) = $enum->{BASE_TYPE};

	$self->start_flags($enum, $ndr);
	$self->pidl("NDR_CHECK(ndr_push_enum_$type_fn($ndr, NDR_SCALARS, $varname));");
	$self->end_flags($enum, $ndr);
}

#####################################################################
# generate a pull function for an enum
sub ParseEnumPull($$$$)
{
	my($self,$enum,$ndr,$varname) = @_;
	my($type_fn) = $enum->{BASE_TYPE};
	my($type_v_decl) = mapTypeName($type_fn);

	$self->pidl("$type_v_decl v;");
	$self->start_flags($enum, $ndr);
	$self->pidl("NDR_CHECK(ndr_pull_enum_$type_fn($ndr, NDR_SCALARS, &v));");
	$self->pidl("*$varname = v;");

	$self->end_flags($enum, $ndr);
}

#####################################################################
# generate a print function for an enum
sub ParseEnumPrint($$$$$)
{
	my($self,$enum,$ndr,$name,$varname) = @_;

	$self->pidl("const char *val = NULL;");
	$self->pidl("");

	$self->start_flags($enum, $ndr);

	$self->pidl("switch ($varname) {");
	$self->indent;
	my $els = \@{$enum->{ELEMENTS}};
	foreach my $i (0 .. $#{$els}) {
		my $e = ${$els}[$i];
		chomp $e;
		if ($e =~ /^(.*)=/) {
			$e = $1;
		}
		$self->pidl("case $e: val = \"$e\"; break;");
	}

	$self->deindent;
	$self->pidl("}");
	
	$self->pidl("ndr_print_enum($ndr, name, \"$enum->{TYPE}\", val, $varname);");

	$self->end_flags($enum, $ndr);
}

sub DeclEnum($$$$)
{
	my ($e,$t,$name,$varname) = @_;
	return "enum $name " . 
		($t eq "pull"?"*":"") . $varname;
}

$typefamily{ENUM} = {
	DECL => \&DeclEnum,
	PUSH_FN_BODY => \&ParseEnumPush,
	PULL_FN_BODY => \&ParseEnumPull,
	PRINT_FN_BODY => \&ParseEnumPrint,
};

#####################################################################
# generate a push function for a bitmap
sub ParseBitmapPush($$$$)
{
	my($self,$bitmap,$ndr,$varname) = @_;
	my($type_fn) = $bitmap->{BASE_TYPE};

	$self->start_flags($bitmap, $ndr);

	$self->pidl("NDR_CHECK(ndr_push_$type_fn($ndr, NDR_SCALARS, $varname));");

	$self->end_flags($bitmap, $ndr);
}

#####################################################################
# generate a pull function for an bitmap
sub ParseBitmapPull($$$$)
{
	my($self,$bitmap,$ndr,$varname) = @_;
	my $type_fn = $bitmap->{BASE_TYPE};
	my($type_decl) = mapTypeName($bitmap->{BASE_TYPE});

	$self->pidl("$type_decl v;");
	$self->start_flags($bitmap, $ndr);
	$self->pidl("NDR_CHECK(ndr_pull_$type_fn($ndr, NDR_SCALARS, &v));");
	$self->pidl("*$varname = v;");

	$self->end_flags($bitmap, $ndr);
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrintElement($$$$$$)
{
	my($self,$e,$bitmap,$ndr,$name,$varname) = @_;
	my($type_decl) = mapTypeName($bitmap->{BASE_TYPE});
	my($type_fn) = $bitmap->{BASE_TYPE};
	my($flag);

	if ($e =~ /^(\w+) .*$/) {
		$flag = "$1";
	} else {
		die "Bitmap: \"$name\" invalid Flag: \"$e\"";
	}

	$self->pidl("ndr_print_bitmap_flag($ndr, sizeof($type_decl), \"$flag\", $flag, $varname);");
}

#####################################################################
# generate a print function for an bitmap
sub ParseBitmapPrint($$$$$)
{
	my($self,$bitmap,$ndr,$name,$varname) = @_;
	my($type_decl) = mapTypeName($bitmap->{TYPE});
	my($type_fn) = $bitmap->{BASE_TYPE};

	$self->start_flags($bitmap, $ndr);

	$self->pidl("ndr_print_$type_fn($ndr, name, $varname);");

	$self->pidl("$ndr->depth++;");
	foreach my $e (@{$bitmap->{ELEMENTS}}) {
		$self->ParseBitmapPrintElement($e, $bitmap, $ndr, $name, $varname);
	}
	$self->pidl("$ndr->depth--;");

	$self->end_flags($bitmap, $ndr);
}

sub DeclBitmap($$$$)
{
	my ($e,$t,$name,$varname) = @_;
	return mapTypeName(Parse::Pidl::Typelist::bitmap_type_fn($e)) . 
		($t eq "pull"?" *":" ") . $varname;
}

$typefamily{BITMAP} = {
	DECL => \&DeclBitmap,
	PUSH_FN_BODY => \&ParseBitmapPush,
	PULL_FN_BODY => \&ParseBitmapPull,
	PRINT_FN_BODY => \&ParseBitmapPrint,
};

#####################################################################
# generate a struct print function
sub ParseStructPrint($$$$$)
{
	my($self,$struct,$ndr,$name,$varname) = @_;

	return unless defined $struct->{ELEMENTS};

	my $env = GenerateStructEnv($struct, $varname);

	$self->DeclareArrayVariables($_) foreach (@{$struct->{ELEMENTS}});

	$self->pidl("ndr_print_struct($ndr, name, \"$name\");");
	$self->pidl("if (r == NULL) { ndr_print_null($ndr); return; }");

	$self->start_flags($struct, $ndr);

	$self->pidl("$ndr->depth++;");
	
	$self->ParseElementPrint($_, $ndr, $env->{$_->{NAME}}, $env)
		foreach (@{$struct->{ELEMENTS}});
	$self->pidl("$ndr->depth--;");

	$self->end_flags($struct, $ndr);
}

sub DeclarePtrVariables($$)
{
	my ($self,$e) = @_;

	if (has_property($e, "skip") or has_property($e, "skip_noinit")) {
		return;
	}

	foreach my $l (@{$e->{LEVELS}}) {
		my $size = 32;
		if ($l->{TYPE} eq "POINTER" and 
			not ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP")) {
			if ($l->{POINTER_TYPE} eq "relative_short") {
				$size = 16;
			}
			$self->pidl("uint${size}_t _ptr_$e->{NAME};");
			last;
		}
	}
}

sub DeclareArrayVariables($$;$)
{
	my ($self,$e,$pull) = @_;

	if (has_property($e, "skip") or has_property($e, "skip_noinit")) {
		return;
	}

	foreach my $l (@{$e->{LEVELS}}) {
		next if ($l->{TYPE} ne "ARRAY");
		if (defined($pull)) {
			$self->pidl("uint32_t size_$e->{NAME}_$l->{LEVEL_INDEX} = 0;");
			if ($l->{IS_VARYING}) {
				$self->pidl("uint32_t length_$e->{NAME}_$l->{LEVEL_INDEX} = 0;");
			}
		}
		next if has_fast_array($e,$l);
		next if is_charset_array($e,$l);
		$self->pidl("uint32_t cntr_$e->{NAME}_$l->{LEVEL_INDEX};");
	}
}

sub DeclareArrayVariablesNoZero($$$)
{
	my ($self,$e,$env) = @_;

	if (has_property($e, "skip") or has_property($e, "skip_noinit")) {
		return;
	}

	foreach my $l (@{$e->{LEVELS}}) {
		next if ($l->{TYPE} ne "ARRAY");
		next if has_fast_array($e,$l);
		next if is_charset_array($e,$l);
		my $length = ParseExpr($l->{LENGTH_IS}, $env, $e->{ORIGINAL});
		if ($length eq "0") {
			warning($e->{ORIGINAL}, "pointless array cntr: 'cntr_$e->{NAME}_$l->{LEVEL_INDEX}': length=$length");
		} else {
			$self->pidl("uint32_t cntr_$e->{NAME}_$l->{LEVEL_INDEX};");
		}
	}
}

sub DeclareMemCtxVariables($$)
{
	my ($self,$e) = @_;

	if (has_property($e, "skip") or has_property($e, "skip_noinit")) {
		return;
	}

	foreach my $l (@{$e->{LEVELS}}) {
		my $mem_flags = $self->ParseMemCtxPullFlags($e, $l);

		if (($l->{TYPE} eq "POINTER") and ($l->{POINTER_TYPE} eq "ignore")) {
			last;
		}

		if (defined($mem_flags)) {
			$self->pidl("TALLOC_CTX *_mem_save_$e->{NAME}_$l->{LEVEL_INDEX} = NULL;");
		}
	}
}

sub ParseStructPullPrimitives($$$$$)
{
	my($self,$struct,$ndr,$varname,$env) = @_;

	if (defined $struct->{SURROUNDING_ELEMENT}) {
		$self->pidl("NDR_CHECK(ndr_pull_array_size($ndr, &$varname->$struct->{SURROUNDING_ELEMENT}->{NAME}));");
	}

	$self->pidl("NDR_CHECK(ndr_pull_align($ndr, $struct->{ALIGN}));");

	if (defined($struct->{PROPERTIES}{relative_base})) {
		# set the current offset as base for relative pointers
		# and store it based on the toplevel struct/union
		$self->pidl("NDR_CHECK(ndr_pull_setup_relative_base_offset1($ndr, $varname, $ndr->offset));");
	}

	$self->ParseElementPull($_, $ndr, $env, 1, 0) foreach (@{$struct->{ELEMENTS}});

	$self->add_deferred();

	$self->pidl("NDR_CHECK(ndr_pull_trailer_align($ndr, $struct->{ALIGN}));");
}

sub ParseStructPullDeferred($$$$$)
{
	my ($self,$struct,$ndr,$varname,$env) = @_;

	if (defined($struct->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		$self->pidl("NDR_CHECK(ndr_pull_setup_relative_base_offset2($ndr, $varname));");
	}
	foreach my $e (@{$struct->{ELEMENTS}}) {
		$self->ParseElementPull($e, $ndr, $env, 0, 1);
	}

	$self->add_deferred();
}

#####################################################################
# parse a struct - pull side
sub ParseStructPull($$$$)
{
	my($self,$struct,$ndr,$varname) = @_;

	return unless defined $struct->{ELEMENTS};

	# declare any internal pointers we need
	foreach my $e (@{$struct->{ELEMENTS}}) {
		$self->DeclarePtrVariables($e);
		$self->DeclareArrayVariables($e, "pull");
		$self->DeclareMemCtxVariables($e);
	}

	$self->start_flags($struct, $ndr);

	my $env = GenerateStructEnv($struct, $varname);

	$self->pidl("NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);");
	$self->pidl("if (ndr_flags & NDR_SCALARS) {");
	$self->indent;
	$self->ParseStructPullPrimitives($struct,$ndr,$varname,$env);
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (ndr_flags & NDR_BUFFERS) {");
	$self->indent;
	$self->ParseStructPullDeferred($struct,$ndr,$varname,$env);
	$self->deindent;
	$self->pidl("}");

	$self->end_flags($struct, $ndr);
}

#####################################################################
# calculate size of ndr struct
sub ParseStructNdrSize($$$$)
{
	my ($self,$t, $name, $varname) = @_;
	my $sizevar;

	if (my $flags = has_property($t, "flag")) {
		$self->pidl("flags |= $flags;");
	}
	$self->pidl("return ndr_size_struct($varname, flags, (ndr_push_flags_fn_t)ndr_push_$name);");
}

sub DeclStruct($$$$)
{
	my ($e,$t,$name,$varname) = @_;
	if ($t eq "base") {
	        return "struct $name $varname";
	}
	return ($t ne "pull"?"const ":"") . "struct $name *$varname";
}

sub ArgsStructNdrSize($$$)
{
	my ($d, $name, $varname) = @_;
	return "const struct $name *$varname, int flags";
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
sub ParseUnionNdrSize($$$)
{
	my ($self, $t, $name, $varname) = @_;
	my $sizevar;

	if (my $flags = has_property($t, "flag")) {
		$self->pidl("flags |= $flags;");
	}

	$self->pidl("return ndr_size_union($varname, flags, level, (ndr_push_flags_fn_t)ndr_push_$name);");
}

sub ParseUnionPushPrimitives($$$$)
{
	my ($self, $e, $ndr ,$varname) = @_;

	my $have_default = 0;

	if (defined($e->{SWITCH_TYPE})) {
		if (defined($e->{ALIGN})) {
			$self->pidl("NDR_CHECK(ndr_push_union_align($ndr, $e->{ALIGN}));");
		}

		$self->pidl("NDR_CHECK(ndr_push_$e->{SWITCH_TYPE}($ndr, NDR_SCALARS, level));");
	}

	if (defined($e->{ALIGN})) {
		if ($e->{IS_MS_UNION}) {
			$self->pidl("/* ms_union is always aligned to the largest union arm*/");
			$self->pidl("NDR_CHECK(ndr_push_align($ndr, $e->{ALIGN}));");
		} else {
			$self->pidl("NDR_CHECK(ndr_push_union_align($ndr, $e->{ALIGN}));");
		}
	}

	$self->pidl("switch (level) {");
	$self->indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		}
		$self->pidl("$el->{CASE}: {");

		if ($el->{TYPE} ne "EMPTY") {
			$self->indent;
			if (defined($e->{PROPERTIES}{relative_base})) {
				$self->pidl("NDR_CHECK(ndr_push_align($ndr, $el->{ALIGN}));");
				# set the current offset as base for relative pointers
				# and store it based on the toplevel struct/union
				$self->pidl("NDR_CHECK(ndr_push_setup_relative_base_offset1($ndr, $varname, $ndr->offset));");
			}
			$self->DeclareArrayVariables($el);
			my $el_env = {$el->{NAME} => "$varname->$el->{NAME}"};
			$self->CheckRefPtrs($el, $ndr, $el_env);
			$self->ParseElementPush($el, $ndr, $el_env, 1, 0);
			$self->deindent;
		}
		$self->pidl("break; }");
		$self->pidl("");
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->pidl("\treturn ndr_push_error($ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);");
	}
	$self->deindent;
	$self->pidl("}");
}

sub ParseUnionPushDeferred($$$$)
{
	my ($self,$e,$ndr,$varname) = @_;

	my $have_default = 0;

	if (defined($e->{PROPERTIES}{relative_base})) {
		# retrieve the current offset as base for relative pointers
		# based on the toplevel struct/union
		$self->pidl("NDR_CHECK(ndr_push_setup_relative_base_offset2($ndr, $varname));");
	}
	$self->pidl("switch (level) {");
	$self->indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		}

		$self->pidl("$el->{CASE}:");
		if ($el->{TYPE} ne "EMPTY") {
			$self->indent;
			$self->ParseElementPush($el, $ndr, {$el->{NAME} => "$varname->$el->{NAME}"}, 0, 1);
			$self->deindent;
		}
		$self->pidl("break;");
		$self->pidl("");
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->pidl("\treturn ndr_push_error($ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u\", level);");
	}
	$self->deindent;
	$self->pidl("}");
}

#####################################################################
# parse a union - push side
sub ParseUnionPush($$$$)
{
	my ($self,$e,$ndr,$varname) = @_;
	my $have_default = 0;

	$self->pidl("uint32_t level;");
	$self->start_flags($e, $ndr);

	$self->pidl("NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);");
	$self->pidl("if (ndr_flags & NDR_SCALARS) {");
	$self->indent;
	$self->pidl("/* This token is not used again (except perhaps below in the NDR_BUFFERS case) */");
	$self->pidl("NDR_CHECK(ndr_push_steal_switch_value($ndr, $varname, &level));");

	$self->ParseUnionPushPrimitives($e, $ndr, $varname);
	$self->deindent;
	$self->pidl("}");
        if (is_deferred_switch_non_empty($e)) {
                $self->pidl("if (ndr_flags & NDR_BUFFERS) {");
                $self->indent;
                # In case we had ndr_flags of NDR_SCALERS|NDR_BUFFERS
                $self->pidl("if (!(ndr_flags & NDR_SCALARS)) {");
                $self->indent;
                $self->pidl("/* We didn't get it above, and the token is not needed after this. */");
                $self->pidl("NDR_CHECK(ndr_push_steal_switch_value($ndr, $varname, &level));");
                $self->deindent;
                $self->pidl("}");
                $self->ParseUnionPushDeferred($e, $ndr, $varname);
                $self->deindent;
                $self->pidl("}");
        }
	$self->end_flags($e, $ndr);
}

#####################################################################
# print a union
sub ParseUnionPrint($$$$$)
{
	my ($self,$e,$ndr,$name,$varname) = @_;
	my $have_default = 0;

	$self->pidl("uint32_t level;");
	foreach my $el (@{$e->{ELEMENTS}}) {
		$self->DeclareArrayVariables($el);
	}

	$self->start_flags($e, $ndr);

	$self->pidl("level = ndr_print_steal_switch_value($ndr, $varname);");

	$self->pidl("ndr_print_union($ndr, name, level, \"$name\");");

	$self->pidl("switch (level) {");
	$self->indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		}
		$self->pidl("$el->{CASE}:");
		if ($el->{TYPE} ne "EMPTY") {
			$self->indent;
			$self->ParseElementPrint($el, $ndr, "$varname->$el->{NAME}", {});
			$self->deindent;
		}
		$self->pidl("break;");
		$self->pidl("");
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->pidl("\tndr_print_bad_level($ndr, name, level);");
	}
	$self->deindent;
	$self->pidl("}");

	$self->end_flags($e, $ndr);
}

sub ParseUnionPullPrimitives($$$$$)
{
	my ($self,$e,$ndr,$varname,$switch_type) = @_;
	my $have_default = 0;


	if (defined($switch_type)) {
		if (defined($e->{ALIGN})) {
			$self->pidl("NDR_CHECK(ndr_pull_union_align($ndr, $e->{ALIGN}));");
		}

		$self->pidl("NDR_CHECK(ndr_pull_$switch_type($ndr, NDR_SCALARS, &_level));");
		$self->pidl("if (_level != level) {"); 
		$self->pidl("\treturn ndr_pull_error($ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value %u for $varname at \%s\", _level, __location__);");
		$self->pidl("}");
	}

	if (defined($e->{ALIGN})) {
		if ($e->{IS_MS_UNION}) {
			$self->pidl("/* ms_union is always aligned to the largest union arm*/");
			$self->pidl("NDR_CHECK(ndr_pull_align($ndr, $e->{ALIGN}));");
		} else {
			$self->pidl("NDR_CHECK(ndr_pull_union_align($ndr, $e->{ALIGN}));");
		}
	}

	$self->pidl("switch (level) {");
	$self->indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		} 
		$self->pidl("$el->{CASE}: {");

		if ($el->{TYPE} ne "EMPTY") {
			$self->indent;
			if (defined($e->{PROPERTIES}{relative_base})) {
				$self->pidl("NDR_CHECK(ndr_pull_align($ndr, $el->{ALIGN}));");
				# set the current offset as base for relative pointers
				# and store it based on the toplevel struct/union
				$self->pidl("NDR_CHECK(ndr_pull_setup_relative_base_offset1($ndr, $varname, $ndr->offset));");
			}
			$self->ParseElementPull($el, $ndr, {$el->{NAME} => "$varname->$el->{NAME}"}, 1, 0);
			$self->deindent;
		}
		$self->pidl("break; }");
		$self->pidl("");
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->pidl("\treturn ndr_pull_error($ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u at \%s\", level, __location__);");
	}
	$self->deindent;
	$self->pidl("}");
}

sub ParseUnionPullDeferred($$$$)
{
	my ($self,$e,$ndr,$varname) = @_;
	my $have_default = 0;

	$self->pidl("switch (level) {");
	$self->indent;
	foreach my $el (@{$e->{ELEMENTS}}) {
		if ($el->{CASE} eq "default") {
			$have_default = 1;
		} 

		$self->pidl("$el->{CASE}:");
		if ($el->{TYPE} ne "EMPTY") {
			$self->indent;
			if (defined($e->{PROPERTIES}{relative_base})) {
				# retrieve the current offset as base for relative pointers
				# based on the toplevel struct/union
				$self->pidl("NDR_CHECK(ndr_pull_setup_relative_base_offset2($ndr, $varname));");
			}
			$self->ParseElementPull($el, $ndr, {$el->{NAME} => "$varname->$el->{NAME}"}, 0, 1);
			$self->deindent;
		}
		$self->pidl("break;");
		$self->pidl("");
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->pidl("\treturn ndr_pull_error($ndr, NDR_ERR_BAD_SWITCH, \"Bad switch value \%u at \%s\", level, __location__);");
	}
	$self->deindent;
	$self->pidl("}");


}

#####################################################################
# parse a union - pull side
sub ParseUnionPull($$$$)
{
	my ($self,$e,$ndr,$varname) = @_;
	my $switch_type = $e->{SWITCH_TYPE};
        my $needs_deferred_switch = is_deferred_switch_non_empty($e);
	$self->pidl("uint32_t level;");
	if (defined($switch_type)) {
		if (Parse::Pidl::Typelist::typeIs($switch_type, "ENUM")) {
			$switch_type = Parse::Pidl::Typelist::enum_type_fn(getType($switch_type)->{DATA});
		}
		$self->pidl(mapTypeName($switch_type) . " _level;");
	}

	my %double_cases = ();
	foreach my $el (@{$e->{ELEMENTS}}) {
		next if ($el->{TYPE} eq "EMPTY");
		next if ($double_cases{"$el->{NAME}"});
		$self->DeclareMemCtxVariables($el);
		$self->DeclarePtrVariables($el);
		$self->DeclareArrayVariables($el, "pull");
		$double_cases{"$el->{NAME}"} = 1;
	}

	$self->start_flags($e, $ndr);

	$self->pidl("NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);");
	$self->pidl("if (ndr_flags & NDR_SCALARS) {");
	$self->indent;
	$self->pidl("/* This token is not used again (except perhaps below in the NDR_BUFFERS case) */");
	$self->pidl("NDR_CHECK(ndr_pull_steal_switch_value($ndr, $varname, &level));");
	$self->ParseUnionPullPrimitives($e,$ndr,$varname,$switch_type);
	$self->deindent;
	$self->pidl("}");
	if ($needs_deferred_switch) {
		$self->pidl("if (ndr_flags & NDR_BUFFERS) {");
		$self->indent;
		# In case we had ndr_flags of NDR_SCALERS|NDR_BUFFERS
		$self->pidl("if (!(ndr_flags & NDR_SCALARS)) {");
		$self->indent;
		$self->pidl("/* We didn't get it above, and the token is not needed after this. */");
		$self->pidl("NDR_CHECK(ndr_pull_steal_switch_value($ndr, $varname, &level));");
		$self->deindent;
		$self->pidl("}");
		$self->ParseUnionPullDeferred($e,$ndr,$varname);
		$self->deindent;
		$self->pidl("}");
	}
	$self->add_deferred();

	$self->end_flags($e, $ndr);
}

sub DeclUnion($$$$)
{
	my ($e,$t,$name,$varname) = @_;
	if ($t eq "base") {
	        return "union $name $varname";
	}
	return ($t ne "pull"?"const ":"") . "union $name *$varname";
}

sub ArgsUnionNdrSize($$)
{
	my ($d,$name) = @_;
	return "const union $name *r, uint32_t level, int flags";
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
sub ParseTypedefPush($$$$)
{
	my($self,$e,$ndr,$varname) = @_;

	my $env;

	$env->{$e->{NAME}} = $varname;

	$self->ParseElementPushLevel($e, $e->{LEVELS}[0], $ndr, $varname, $env, 1, 1);
}

#####################################################################
# parse a typedef - pull side
sub ParseTypedefPull($$$$)
{
	my($self,$e,$ndr,$varname) = @_;

	my $env;

	$env->{$e->{NAME}} = $varname;

	$self->ParseElementPullLevel($e, $e->{LEVELS}[0], $ndr, $varname, $env, 1, 1);
}

#####################################################################
# parse a typedef - print side
sub ParseTypedefPrint($$$$$)
{
	my($self,$e,$ndr,$name,$varname) = @_;

	$typefamily{$e->{DATA}->{TYPE}}->{PRINT_FN_BODY}->($self, $e->{DATA}, $ndr, $name, $varname);
}

#####################################################################
## calculate the size of a structure
sub ParseTypedefNdrSize($$$$)
{
	my($self,$t,$name,$varname) = @_;

	$typefamily{$t->{DATA}->{TYPE}}->{SIZE_FN_BODY}->($self, $t->{DATA}, $name, $varname);
}

sub DeclTypedef($$$$)
{
	my ($e, $t, $name, $varname) = @_;
	
	return $typefamily{$e->{DATA}->{TYPE}}->{DECL}->($e->{DATA}, $t, $name, $varname);
}

sub ArgsTypedefNdrSize($$$)
{
	my ($d, $name, $varname) = @_;
	return $typefamily{$d->{DATA}->{TYPE}}->{SIZE_FN_ARGS}->($d->{DATA}, $name, $varname);
}

$typefamily{TYPEDEF} = {
	PUSH_FN_BODY => \&ParseTypedefPush,
	DECL => \&DeclTypedef,
	PULL_FN_BODY => \&ParseTypedefPull,
	PRINT_FN_BODY => \&ParseTypedefPrint,
	SIZE_FN_ARGS => \&ArgsTypedefNdrSize,
	SIZE_FN_BODY => \&ParseTypedefNdrSize,
};

sub ParsePipePushChunk($$)
{
	my ($self, $t) = @_;

	my $pipe = $t;
	$pipe = $t->{DATA} if ($t->{TYPE} eq "TYPEDEF");
	my $struct = $pipe->{DATA};

	my $name = "$struct->{NAME}";
	my $ndr = "ndr";
	my $varname = "r";

	my $args = $typefamily{$struct->{TYPE}}->{DECL}->($struct, "push", $name, $varname);

	$self->fn_declare("push", $struct, "enum ndr_err_code ndr_push_$name(struct ndr_push *$ndr, int ndr_flags, $args)") or return;

	return if has_property($t, "nopush");

	$self->pidl("{");
	$self->indent;

	$self->ParseStructPush($struct, $ndr, $varname);
	$self->pidl("");

	$self->pidl("NDR_CHECK(ndr_push_pipe_chunk_trailer(ndr, ndr_flags, $varname->count));");
	$self->pidl("");

	$self->pidl("return NDR_ERR_SUCCESS;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParsePipePullChunk($$)
{
	my ($self, $t) = @_;

	my $pipe = $t;
	$pipe = $t->{DATA} if ($t->{TYPE} eq "TYPEDEF");
	my $struct = $pipe->{DATA};

	my $name = "$struct->{NAME}";
	my $ndr = "ndr";
	my $varname = "r";

	my $args = $typefamily{$struct->{TYPE}}->{DECL}->($struct, "pull", $name, $varname);

	$self->fn_declare("pull", $struct, "enum ndr_err_code ndr_pull_$name(struct ndr_pull *$ndr, int ndr_flags, $args)") or return;

	return if has_property($struct, "nopull");

	$self->pidl("{");
	$self->indent;

	$self->ParseStructPull($struct, $ndr, $varname);
	$self->pidl("");

	$self->pidl("NDR_CHECK(ndr_check_pipe_chunk_trailer($ndr, ndr_flags, $varname->count));");
	$self->pidl("");

	$self->pidl("return NDR_ERR_SUCCESS;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParsePipePrintChunk($$)
{
	my ($self, $t) = @_;

	my $pipe = $t;
	$pipe = $t->{DATA} if ($t->{TYPE} eq "TYPEDEF");
	my $struct = $pipe->{DATA};

	my $name = "$struct->{NAME}";
	my $ndr = "ndr";
	my $varname = "r";

	my $args = $typefamily{$struct->{TYPE}}->{DECL}->($struct, "print", $name, $varname);

	$self->pidl_hdr("void ndr_print_$name(struct ndr_print *ndr, const char *name, $args);");

	return if (has_property($t, "noprint"));

	$self->pidl("_PUBLIC_ void ndr_print_$name(struct ndr_print *$ndr, const char *name, $args)");
	$self->pidl("{");
	$self->indent;
	$self->ParseTypePrint($struct, $ndr, $varname);
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

#####################################################################
# parse a function - print side
sub ParseFunctionPrint($$)
{
	my($self, $fn) = @_;
	my $ndr = "ndr";

	$self->pidl_hdr("void ndr_print_$fn->{NAME}(struct ndr_print *$ndr, const char *name, int flags, const struct $fn->{NAME} *r);");

	return if has_property($fn, "noprint");

	$self->pidl("_PUBLIC_ void ndr_print_$fn->{NAME}(struct ndr_print *$ndr, const char *name, int flags, const struct $fn->{NAME} *r)");
	$self->pidl("{");
	$self->indent;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		$self->DeclareArrayVariables($e);
	}

	$self->pidl("ndr_print_struct($ndr, name, \"$fn->{NAME}\");");
	$self->pidl("if (r == NULL) { ndr_print_null($ndr); return; }");
	$self->pidl("$ndr->depth++;");

	$self->pidl("if (flags & NDR_SET_VALUES) {");
	$self->pidl("\t$ndr->flags |= LIBNDR_PRINT_SET_VALUES;");
	$self->pidl("}");

	$self->pidl("if (flags & NDR_IN) {");
	$self->indent;
	$self->pidl("ndr_print_struct($ndr, \"in\", \"$fn->{NAME}\");");
	$self->pidl("$ndr->depth++;");

	my $env = GenerateFunctionInEnv($fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->ParseElementPrint($e, $ndr, $env->{$e->{NAME}}, $env);
		}
	}
	$self->pidl("$ndr->depth--;");
	$self->deindent;
	$self->pidl("}");
	
	$self->pidl("if (flags & NDR_OUT) {");
	$self->indent;
	$self->pidl("ndr_print_struct($ndr, \"out\", \"$fn->{NAME}\");");
	$self->pidl("$ndr->depth++;");

	$env = GenerateFunctionOutEnv($fn);
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->ParseElementPrint($e, $ndr, $env->{$e->{NAME}}, $env);
		}
	}
	if ($fn->{RETURN_TYPE}) {
		$self->pidl("ndr_print_$fn->{RETURN_TYPE}($ndr, \"result\", r->out.result);");
	}
	$self->pidl("$ndr->depth--;");
	$self->deindent;
	$self->pidl("}");
	
	$self->pidl("$ndr->depth--;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

#####################################################################
# parse a function
sub ParseFunctionPush($$)
{ 
	my($self, $fn) = @_;
	my $ndr = "ndr";

	$self->fn_declare("push", $fn, "enum ndr_err_code ndr_push_$fn->{NAME}(struct ndr_push *$ndr, int flags, const struct $fn->{NAME} *r)") or return;

	return if has_property($fn, "nopush");

	$self->pidl("{");
	$self->indent;

	foreach my $e (@{$fn->{ELEMENTS}}) { 
		$self->DeclareArrayVariables($e);
	}

	$self->pidl("NDR_PUSH_CHECK_FN_FLAGS(ndr, flags);");

	$self->pidl("if (flags & NDR_IN) {");
	$self->indent;

	my $env = GenerateFunctionInEnv($fn);

	EnvSubstituteValue($env, $fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->CheckRefPtrs($e, $ndr, $env);
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->ParseElementPush($e, $ndr, $env, 1, 1);
		}
	}

	$self->deindent;
	$self->pidl("}");

	$self->pidl("if (flags & NDR_OUT) {");
	$self->indent;

	$env = GenerateFunctionOutEnv($fn);
	EnvSubstituteValue($env, $fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->CheckRefPtrs($e, $ndr, $env);
		}
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->ParseElementPush($e, $ndr, $env, 1, 1);
		}
	}

	if ($fn->{RETURN_TYPE}) {
		$self->pidl("NDR_CHECK(ndr_push_$fn->{RETURN_TYPE}($ndr, NDR_SCALARS, r->out.result));");
	}
    
	$self->deindent;
	$self->pidl("}");
	$self->pidl("return NDR_ERR_SUCCESS;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub AllocateArrayLevel($$$$$$)
{
	my ($self,$e,$l,$ndr,$var,$size) = @_;

	my $pl = GetPrevLevel($e, $l);
	if (defined($pl) and 
	    $pl->{TYPE} eq "POINTER" and 
	    $pl->{POINTER_TYPE} eq "ref"
	    and not $l->{IS_ZERO_TERMINATED}) {
		$self->pidl("if ($ndr->flags & LIBNDR_FLAG_REF_ALLOC) {");
		$self->pidl("\tNDR_PULL_ALLOC_N($ndr, $var, $size);");
		$self->pidl("}");
		if (grep(/in/,@{$e->{DIRECTION}}) and
		    grep(/out/,@{$e->{DIRECTION}})) {
			$self->pidl("memcpy(r->out.$e->{NAME}, r->in.$e->{NAME}, ($size) * sizeof(*r->in.$e->{NAME}));");
		}
		return;
	}

	$self->pidl("NDR_PULL_ALLOC_N($ndr, $var, $size);");
}

#####################################################################
# parse a function
sub ParseFunctionPull($$)
{ 
	my($self,$fn) = @_;
	my $ndr = "ndr";

	# pull function args
	$self->fn_declare("pull", $fn, "enum ndr_err_code ndr_pull_$fn->{NAME}(struct ndr_pull *$ndr, int flags, struct $fn->{NAME} *r)") or return;

	$self->pidl("{");
	$self->indent;

	# declare any internal pointers we need
	foreach my $e (@{$fn->{ELEMENTS}}) { 
		$self->DeclarePtrVariables($e);
		$self->DeclareArrayVariables($e, "pull");
	}

	my %double_cases = ();
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next if ($e->{TYPE} eq "EMPTY");
		next if ($double_cases{"$e->{NAME}"});
		$self->DeclareMemCtxVariables($e);
		$double_cases{"$e->{NAME}"} = 1;
	}

	$self->pidl("NDR_PULL_CHECK_FN_FLAGS(ndr, flags);");

	$self->pidl("if (flags & NDR_IN) {");
	$self->indent;

	# auto-init the out section of a structure. I originally argued that
	# this was a bad idea as it hides bugs, but coping correctly
	# with initialisation and not wiping ref vars is turning
	# out to be too tricky (tridge)
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});
		$self->pidl("NDR_ZERO_STRUCT(r->out);");
		$self->pidl("");
		last;
	}

	my $env = GenerateFunctionInEnv($fn);

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		$self->ParseElementPull($e, $ndr, $env, 1, 1);
	}

	# allocate the "simple" out ref variables. FIXME: Shouldn't this have it's
	# own flag rather than be in NDR_IN ?

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));
		next unless ($e->{LEVELS}[0]->{TYPE} eq "POINTER" and 
		             $e->{LEVELS}[0]->{POINTER_TYPE} eq "ref");
		next if (($e->{LEVELS}[1]->{TYPE} eq "DATA") and 
				 ($e->{LEVELS}[1]->{DATA_TYPE} eq "string"));
		next if ($e->{LEVELS}[1]->{TYPE} eq "PIPE");
		next if (($e->{LEVELS}[1]->{TYPE} eq "ARRAY") 
			and   $e->{LEVELS}[1]->{IS_ZERO_TERMINATED});

		if ($e->{LEVELS}[1]->{TYPE} eq "ARRAY") {
			my $size = ParseExprExt($e->{LEVELS}[1]->{SIZE_IS}, $env, $e->{ORIGINAL},
				check_null_pointer($e, $env, sub { $self->pidl(shift); },
						   "return ndr_pull_error($ndr, NDR_ERR_INVALID_POINTER, \"NULL Pointer for size_is()\");"),
				check_fully_dereferenced($e, $env));
			$self->pidl("NDR_PULL_ALLOC_N($ndr, r->out.$e->{NAME}, $size);");

			if (grep(/in/, @{$e->{DIRECTION}})) {
				$self->pidl("memcpy(r->out.$e->{NAME}, r->in.$e->{NAME}, ($size) * sizeof(*r->in.$e->{NAME}));");
			} else {
				$self->pidl("memset(r->out.$e->{NAME}, 0, ($size) * sizeof(*r->out.$e->{NAME}));");
			}
		} elsif ($e->{LEVELS}[1]->{TYPE} eq "ARRAY") {
			if (grep(/in/, @{$e->{DIRECTION}})) {
				$self->pidl("r->out.$e->{NAME} = r->in.$e->{NAME};");
			} else {
				$self->pidl("r->out.$e->{NAME} = NULL;");
			}
		} else {
			$self->pidl("NDR_PULL_ALLOC($ndr, r->out.$e->{NAME});");
		
			if (grep(/in/, @{$e->{DIRECTION}})) {
				$self->pidl("*r->out.$e->{NAME} = *r->in.$e->{NAME};");
			} else {
				$self->pidl("NDR_ZERO_STRUCTP(r->out.$e->{NAME});");
			}
		}
	}

	$self->add_deferred();
	$self->deindent;
	$self->pidl("}");
	
	$self->pidl("if (flags & NDR_OUT) {");
	$self->indent;

	$self->pidl("#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION");

	# This for fuzzers of ndr_pull where the out elements refer to
	# in elements in size_is or length_is.
	#
	# Not actually very harmful but also not useful outsie a fuzzer
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		next unless ($e->{LEVELS}[0]->{TYPE} eq "POINTER" and
		             $e->{LEVELS}[0]->{POINTER_TYPE} eq "ref");
		next if (($e->{LEVELS}[1]->{TYPE} eq "DATA") and
				 ($e->{LEVELS}[1]->{DATA_TYPE} eq "string"));
		next if ($e->{LEVELS}[1]->{TYPE} eq "PIPE");
		next if ($e->{LEVELS}[1]->{TYPE} eq "ARRAY");

		$self->pidl("if (r->in.$e->{NAME} == NULL) {");
		$self->indent;
		$self->pidl("NDR_PULL_ALLOC($ndr, r->in.$e->{NAME});");
		$self->pidl("NDR_ZERO_STRUCTP(r->in.$e->{NAME});");
		$self->deindent;
		$self->pidl("}");
	}

	$self->pidl("#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */");

	$env = GenerateFunctionOutEnv($fn);
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});
		$self->ParseElementPull($e, $ndr, $env, 1, 1);
	}

	if ($fn->{RETURN_TYPE}) {
		$self->pidl("NDR_CHECK(ndr_pull_$fn->{RETURN_TYPE}($ndr, NDR_SCALARS, &r->out.result));");
	}

	$self->add_deferred();
	$self->deindent;
	$self->pidl("}");

	$self->pidl("return NDR_ERR_SUCCESS;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub AuthServiceStruct($$$)
{
	my ($self, $ifacename, $authservice) = @_;
	my @a = split /,/, $authservice;
	my $authservice_count = $#a + 1;

	$self->pidl("static const char * const $ifacename\_authservice_strings[] = {");
	foreach my $ap (@a) {
		$self->pidl("\t$ap, ");
	}
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static const struct ndr_interface_string_array $ifacename\_authservices = {");
	$self->pidl("\t.count\t= $authservice_count,");
	$self->pidl("\t.names\t= $ifacename\_authservice_strings");
	$self->pidl("};");
	$self->pidl("");
}

sub ParseGeneratePipeArray($$$)
{
	my ($self, $fn, $direction) = @_;

	$self->pidl("static const struct ndr_interface_call_pipe $fn->{NAME}\_$direction\_pipes[] = {");
	$self->indent;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless ContainsPipe($e, $e->{LEVELS}[0]);
		next unless (grep(/$direction/, @{$e->{DIRECTION}}));

		my $cname = "$e->{TYPE}_chunk";

		$self->pidl("{");
		$self->indent;
		$self->pidl("\"$direction.$e->{NAME}\",");
		$self->pidl("\"$cname\",");
		$self->pidl("sizeof(struct $cname),");
		$self->pidl("(ndr_push_flags_fn_t) ndr_push_$cname,");
		$self->pidl("(ndr_pull_flags_fn_t) ndr_pull_$cname,");
		$self->pidl("(ndr_print_fn_t) ndr_print_$cname,");
		$self->deindent;
		$self->pidl("},");
	}
	$self->pidl("{ .name = NULL }");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");
}

sub FunctionCallPipes($$)
{
	my ($self, $d) = @_;
	return if not defined($d->{OPNUM});

	my $in_pipes = 0;
	my $out_pipes = 0;

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless ContainsPipe($e, $e->{LEVELS}[0]);

		if (grep(/in/, @{$e->{DIRECTION}})) {
			$in_pipes++;
		}
		if (grep(/out/, @{$e->{DIRECTION}})) {
			$out_pipes++;
		}
	}

	if ($in_pipes) {
		$self->ParseGeneratePipeArray($d, "in");
	}

	if ($out_pipes) {
		$self->ParseGeneratePipeArray($d, "out");
	}
}

sub FunctionCallEntry($$)
{
	my ($self, $d) = @_;
	return 0 if not defined($d->{OPNUM});

	my $in_pipes = 0;
	my $out_pipes = 0;

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless ContainsPipe($e, $e->{LEVELS}[0]);

		if (grep(/in/, @{$e->{DIRECTION}})) {
			$in_pipes++;
		}
		if (grep(/out/, @{$e->{DIRECTION}})) {
			$out_pipes++;
		}
	}

	my $in_pipes_ptr = "NULL";
	my $out_pipes_ptr = "NULL";

	if ($in_pipes) {
		$in_pipes_ptr = "$d->{NAME}_in_pipes";
	}

	if ($out_pipes) {
		$out_pipes_ptr = "$d->{NAME}_out_pipes";
	}

	$self->pidl("\t{");
	$self->pidl("\t\t\"$d->{NAME}\",");
	$self->pidl("\t\tsizeof(struct $d->{NAME}),");
	$self->pidl("\t\t(ndr_push_flags_fn_t) ndr_push_$d->{NAME},");
	$self->pidl("\t\t(ndr_pull_flags_fn_t) ndr_pull_$d->{NAME},");
	$self->pidl("\t\t(ndr_print_function_t) ndr_print_$d->{NAME},");
	$self->pidl("\t\t{ $in_pipes, $in_pipes_ptr },");
	$self->pidl("\t\t{ $out_pipes, $out_pipes_ptr },");
	$self->pidl("\t},");
	return 1;
}

sub StructEntry($$)
{
	my ($self, $d) = @_;
	my $type_decl = $typefamily{$d->{TYPE}}->{DECL}->($d, "base", $d->{NAME}, "");

	$self->pidl("\t{");
	$self->pidl("\t\t.name = \"$d->{NAME}\",");
	$self->pidl("\t\t.struct_size = sizeof($type_decl),");
	$self->pidl("\t\t.ndr_push = (ndr_push_flags_fn_t) ndr_push_$d->{NAME},");
	$self->pidl("\t\t.ndr_pull = (ndr_pull_flags_fn_t) ndr_pull_$d->{NAME},");
	$self->pidl("\t\t.ndr_print = (ndr_print_function_t) ndr_print_flags_$d->{NAME},");
	$self->pidl("\t},");
	return 1;
}

#####################################################################
# produce a function call table
sub FunctionTable($$)
{
	my($self,$interface) = @_;
	my $count = 0;
	my $count_public_structs = 0;
	my $uname = uc $interface->{NAME};

	foreach my $d (@{$interface->{TYPES}}) {
	        next unless (is_public_struct($d));
		$count_public_structs += 1;
	}
	return if ($#{$interface->{FUNCTIONS}}+1 == 0 and
		   $count_public_structs == 0);

	foreach my $d (@{$interface->{INHERITED_FUNCTIONS}},@{$interface->{FUNCTIONS}}) {
		$self->FunctionCallPipes($d);
	}

	$self->pidl("static const struct ndr_interface_public_struct $interface->{NAME}\_public_structs[] = {");

	foreach my $d (@{$interface->{TYPES}}) {
	        next unless (is_public_struct($d));
		$self->StructEntry($d);
	}
	$self->pidl("\t{ .name = NULL }");
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static const struct ndr_interface_call $interface->{NAME}\_calls[] = {");

	foreach my $d (@{$interface->{INHERITED_FUNCTIONS}},@{$interface->{FUNCTIONS}}) {
		$count += $self->FunctionCallEntry($d);
	}
	$self->pidl("\t{ .name = NULL }");
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static const char * const $interface->{NAME}\_endpoint_strings[] = {");
	foreach my $ep (@{$interface->{ENDPOINTS}}) {
		$self->pidl("\t$ep, ");
	}
	my $endpoint_count = $#{$interface->{ENDPOINTS}}+1;
	
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static const struct ndr_interface_string_array $interface->{NAME}\_endpoints = {");
	$self->pidl("\t.count\t= $endpoint_count,");
	$self->pidl("\t.names\t= $interface->{NAME}\_endpoint_strings");
	$self->pidl("};");
	$self->pidl("");

	if (! defined $interface->{PROPERTIES}->{authservice}) {
		$interface->{PROPERTIES}->{authservice} = "\"host\"";
	}

	$self->AuthServiceStruct($interface->{NAME},
		                     $interface->{PROPERTIES}->{authservice});

	$self->pidl("\nconst struct ndr_interface_table ndr_table_$interface->{NAME} = {");
	$self->pidl("\t.name\t\t= \"$interface->{NAME}\",");
	if (defined $interface->{PROPERTIES}->{uuid}) {
		$self->pidl("\t.syntax_id\t= {");
		$self->pidl("\t\t" . print_uuid($interface->{UUID}) .",");
		$self->pidl("\t\tNDR_$uname\_VERSION");
		$self->pidl("\t},");
		$self->pidl("\t.helpstring\t= NDR_$uname\_HELPSTRING,");
	}
	$self->pidl("\t.num_calls\t= $count,");
	$self->pidl("\t.calls\t\t= $interface->{NAME}\_calls,");
	$self->pidl("\t.num_public_structs\t= $count_public_structs,");
	$self->pidl("\t.public_structs\t\t= $interface->{NAME}\_public_structs,");
	$self->pidl("\t.endpoints\t= &$interface->{NAME}\_endpoints,");
	$self->pidl("\t.authservices\t= &$interface->{NAME}\_authservices");
	$self->pidl("};");
	$self->pidl("");

}

#####################################################################
# generate include statements for imported idl files
sub HeaderImport
{
	my $self = shift;
	my @imports = @_;
	foreach (@imports) {
		$_ = unmake_str($_);
		s/\.idl$//;
		$self->pidl(choose_header("librpc/gen_ndr/ndr_$_\.h", "gen_ndr/ndr_$_.h"));
	}
}

#####################################################################
# generate include statements for included header files
sub HeaderInclude
{
	my $self = shift;
	my @includes = @_;
	foreach (@includes) {
		$self->pidl_hdr("#include $_");
	}
}

#####################################################################
# generate prototypes and defines for the interface definitions
# FIXME: these prototypes are for the DCE/RPC client functions, not the 
# NDR parser and so do not belong here, technically speaking
sub HeaderInterface($$$)
{
	my($self,$interface,$needed) = @_;

	my $count = 0;

	if ($needed->{"compression"}) {
		$self->pidl(choose_header("librpc/ndr/ndr_compression.h", "ndr/compression.h"));
	}

	if (has_property($interface, "object")) {
		$self->pidl(choose_header("librpc/gen_ndr/ndr_orpc.h", "ndr/orpc.h"));
	}

	if (defined $interface->{PROPERTIES}->{helper}) {
		$self->HeaderInclude(split /,/, $interface->{PROPERTIES}->{helper});
	}

	if (defined $interface->{PROPERTIES}->{uuid}) {
		my $name = uc $interface->{NAME};
		$self->pidl_hdr("#define NDR_$name\_UUID " . 
		Parse::Pidl::Util::make_str(lc($interface->{UUID})));

		$self->pidl_hdr("#define NDR_$name\_VERSION $interface->{VERSION}");

		$self->pidl_hdr("#define NDR_$name\_NAME \"$interface->{NAME}\"");

		if(!defined $interface->{PROPERTIES}->{helpstring}) { $interface->{PROPERTIES}->{helpstring} = "NULL"; }
		$self->pidl_hdr("#define NDR_$name\_HELPSTRING $interface->{PROPERTIES}->{helpstring}");
	}

	my $count_public_structs = 0;
	foreach my $d (@{$interface->{TYPES}}) {
	        next unless (has_property($d, "public"));
		$count_public_structs += 1;
	}
	if ($#{$interface->{FUNCTIONS}}+1 > 0 or
		   $count_public_structs > 0) {
		$self->pidl_hdr("extern const struct ndr_interface_table ndr_table_$interface->{NAME};");
	}

	foreach (@{$interface->{FUNCTIONS}}) {
		next if has_property($_, "noopnum");
		next if grep(/^$_->{NAME}$/,@{$interface->{INHERITED_FUNCTIONS}});
		my $u_name = uc $_->{NAME};
	
		my $val = sprintf("0x%02x", $count);
		if (defined($interface->{BASE})) {
			$val .= " + NDR_" . uc $interface->{BASE} . "_CALL_COUNT";
		}
		
		$self->pidl_hdr("#define NDR_$u_name ($val)");

		$self->pidl_hdr("");
		$count++;
	}

	my $val = $count;

	if (defined($interface->{BASE})) {
		$val .= " + NDR_" . uc $interface->{BASE} . "_CALL_COUNT";
	}

	$self->pidl_hdr("#define NDR_" . uc $interface->{NAME} . "_CALL_COUNT ($val)");

}

sub ParseTypePush($$$$$$)
{
	my ($self,$e, $ndr, $varname, $primitives, $deferred) = @_;

	# save the old relative_base_offset
	$self->pidl("uint32_t _save_relative_base_offset = ndr_push_get_relative_base_offset($ndr);") if defined(has_property($e, "relative_base"));
	$typefamily{$e->{TYPE}}->{PUSH_FN_BODY}->($self, $e, $ndr, $varname);
	# restore the old relative_base_offset
	$self->pidl("ndr_push_restore_relative_base_offset($ndr, _save_relative_base_offset);") if defined(has_property($e, "relative_base"));
}

sub ParseTypePushFunction($$$)
{
	my ($self, $e, $varname) = @_;
	my $ndr = "ndr";

	my $args = $typefamily{$e->{TYPE}}->{DECL}->($e, "push", $e->{NAME}, $varname);

	$self->fn_declare("push", $e, "enum ndr_err_code ".TypeFunctionName("ndr_push", $e)."(struct ndr_push *$ndr, int ndr_flags, $args)") or return;

	$self->pidl("{");
	$self->indent;
	$self->ParseTypePush($e, $ndr, $varname, 1, 1);
	$self->pidl("return NDR_ERR_SUCCESS;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");;
}

sub ParseTypePull($$$$$$)
{
	my ($self, $e, $ndr, $varname, $primitives, $deferred) = @_;

	# save the old relative_base_offset
	$self->pidl("uint32_t _save_relative_base_offset = ndr_pull_get_relative_base_offset($ndr);") if defined(has_property($e, "relative_base"));
	$typefamily{$e->{TYPE}}->{PULL_FN_BODY}->($self, $e, $ndr, $varname);
	# restore the old relative_base_offset
	$self->pidl("ndr_pull_restore_relative_base_offset($ndr, _save_relative_base_offset);") if defined(has_property($e, "relative_base"));
}

sub ParseTypePullFunction($$)
{
	my ($self, $e, $varname) = @_;
	my $ndr = "ndr";

	my $args = $typefamily{$e->{TYPE}}->{DECL}->($e, "pull", $e->{NAME}, $varname);

	$self->fn_declare("pull", $e, "enum ndr_err_code ".TypeFunctionName("ndr_pull", $e)."(struct ndr_pull *$ndr, int ndr_flags, $args)") or return;

	$self->pidl("{");
	$self->indent;
	$self->ParseTypePull($e, $ndr, $varname, 1, 1);
	$self->pidl("return NDR_ERR_SUCCESS;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseTypePrint($$$$)
{
	my ($self, $e, $ndr, $varname) = @_;

	$typefamily{$e->{TYPE}}->{PRINT_FN_BODY}->($self, $e, $ndr, $e->{NAME}, $varname);
}

sub ParseTypePrintFunction($$$)
{
	my ($self, $e, $varname) = @_;
	my $ndr = "ndr";

	my $args = $typefamily{$e->{TYPE}}->{DECL}->($e, "print", $e->{NAME}, $varname);

	$self->pidl_hdr("void ".TypeFunctionName("ndr_print", $e)."(struct ndr_print *ndr, const char *name, $args);");

	if (is_public_struct($e)) {
                $self->pidl("static void ".TypeFunctionName("ndr_print_flags", $e).
                             "(struct ndr_print *$ndr, const char *name, int unused, $args)"
                             );
		$self->pidl("{");
		$self->indent;
		$self->pidl(TypeFunctionName("ndr_print", $e)."($ndr, name, $varname);");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
	}

	return if (has_property($e, "noprint"));

	$self->pidl("_PUBLIC_ void ".TypeFunctionName("ndr_print", $e)."(struct ndr_print *$ndr, const char *name, $args)");
	$self->pidl("{");
	$self->indent;
	$self->ParseTypePrint($e, $ndr, $varname);
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseTypeNdrSize($$)
{
	my ($self,$t) = @_;

	my $varname = "r";
	my $tf = $typefamily{$t->{TYPE}};
	my $args = $tf->{SIZE_FN_ARGS}->($t, $t->{NAME}, $varname);

	$self->fn_declare("size", $t, "size_t ndr_size_$t->{NAME}($args)") or return;

	$self->pidl("{");
	$self->indent;
	$typefamily{$t->{TYPE}}->{SIZE_FN_BODY}->($self,$t, $t->{NAME}, $varname);
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

#####################################################################
# parse the interface definitions
sub ParseInterface($$$)
{
	my($self,$interface,$needed) = @_;

	$self->pidl_hdr("#ifndef _HEADER_NDR_$interface->{NAME}");
	$self->pidl_hdr("#define _HEADER_NDR_$interface->{NAME}");

	$self->pidl_hdr("");

	$self->HeaderInterface($interface, $needed);

	# Typedefs
	foreach my $d (@{$interface->{TYPES}}) {
		if (Parse::Pidl::Typelist::typeIs($d, "PIPE")) {
			($needed->{TypeFunctionName("ndr_push", $d)}) &&
				$self->ParsePipePushChunk($d);
			($needed->{TypeFunctionName("ndr_pull", $d)}) &&
				$self->ParsePipePullChunk($d);
			($needed->{TypeFunctionName("ndr_print", $d)}) &&
				$self->ParsePipePrintChunk($d);

			$needed->{TypeFunctionName("ndr_pull", $d)} = 0;
			$needed->{TypeFunctionName("ndr_push", $d)} = 0;
			$needed->{TypeFunctionName("ndr_print", $d)} = 0;
			next;
		}

		next unless(typeHasBody($d));

		($needed->{TypeFunctionName("ndr_push", $d)}) && $self->ParseTypePushFunction($d, "r");
		($needed->{TypeFunctionName("ndr_pull", $d)}) && $self->ParseTypePullFunction($d, "r");
		($needed->{TypeFunctionName("ndr_print", $d)}) && $self->ParseTypePrintFunction($d, "r");

		# Make sure we don't generate a function twice...
		$needed->{TypeFunctionName("ndr_push", $d)} = 
		    $needed->{TypeFunctionName("ndr_pull", $d)} = 
			$needed->{TypeFunctionName("ndr_print", $d)} = 0;

		($needed->{"ndr_size_$d->{NAME}"}) && $self->ParseTypeNdrSize($d);
	}

	# Functions
	foreach my $d (@{$interface->{FUNCTIONS}}) {
		($needed->{"ndr_push_$d->{NAME}"}) && $self->ParseFunctionPush($d);
		($needed->{"ndr_pull_$d->{NAME}"}) && $self->ParseFunctionPull($d);
		($needed->{"ndr_print_$d->{NAME}"}) && $self->ParseFunctionPrint($d);
	}

        # Allow compilation of generated files where replacement functions
        # for structures declared nopull/nopush have not been provided.
        #
        # This makes sense when only the print functions are used
        #
        # Otherwise the ndr_table XXX will reference these

        $self->pidl("#ifndef SKIP_NDR_TABLE_$interface->{NAME}");
	$self->FunctionTable($interface);
        $self->pidl("#endif /* SKIP_NDR_TABLE_$interface->{NAME} */");

	$self->pidl_hdr("#endif /* _HEADER_NDR_$interface->{NAME} */");
}

sub GenerateIncludes($)
{
	my ($self) = @_;
	if (is_intree()) {
		$self->pidl("#include \"includes.h\"");
	} else {
		$self->pidl("#ifndef _GNU_SOURCE");
		$self->pidl("#define _GNU_SOURCE");
		$self->pidl("#endif");
		$self->pidl("#include <stdint.h>");
		$self->pidl("#include <stdlib.h>");
		$self->pidl("#include <stdio.h>");
		$self->pidl("#include <stdbool.h>");
		$self->pidl("#include <stdarg.h>");
		$self->pidl("#include <string.h>");
	}
}

#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($$$$)
{
	my($self, $ndr,$gen_header,$ndr_header) = @_;

	$self->pidl_hdr("/* header auto-generated by pidl */");
	$self->pidl_hdr("");
	$self->pidl_hdr(choose_header("librpc/ndr/libndr.h", "ndr.h"));
	$self->pidl_hdr("#include \"$gen_header\"") if ($gen_header);
	$self->pidl_hdr("");

	$self->pidl("/* parser auto-generated by pidl */");
	$self->pidl("");
	$self->GenerateIncludes();
	$self->pidl("#include \"$ndr_header\"") if ($ndr_header);
	$self->pidl("");

	my %needed = ();

	foreach (@{$ndr}) {
		($_->{TYPE} eq "INTERFACE") && NeededInterface($_, \%needed);
	}

	foreach (@{$ndr}) {
		($_->{TYPE} eq "INTERFACE") && $self->ParseInterface($_, \%needed);
		($_->{TYPE} eq "IMPORT") && $self->HeaderImport(@{$_->{PATHS}});
		($_->{TYPE} eq "INCLUDE") && $self->HeaderInclude(@{$_->{PATHS}});
	}

	return ($self->{res_hdr}, $self->{res});
}

sub NeededElement($$$)
{
	my ($e, $dir, $needed) = @_;

	return if ($e->{TYPE} eq "EMPTY");

	return if (ref($e->{TYPE}) eq "HASH" and 
		       not defined($e->{TYPE}->{NAME}));

	my ($t, $rt);
	if (ref($e->{TYPE}) eq "HASH") {
		$t = $e->{TYPE}->{TYPE}."_".$e->{TYPE}->{NAME};
	} else {
		$t = $e->{TYPE};
	}

	if (ref($e->{REPRESENTATION_TYPE}) eq "HASH") {
		$rt = $e->{REPRESENTATION_TYPE}->{TYPE}."_".$e->{REPRESENTATION_TYPE}->{NAME};
	} else {
		$rt = $e->{REPRESENTATION_TYPE};
	}

	die ("$e->{NAME} $t, $rt FOO") unless ($rt ne "");

	my @fn = ();
	if ($dir eq "print") {
		push(@fn, TypeFunctionName("ndr_print", $e->{REPRESENTATION_TYPE}));
	} elsif ($dir eq "pull") {
		push (@fn, TypeFunctionName("ndr_pull", $e->{TYPE}));
		push (@fn, "ndr_$t\_to_$rt")
			if ($rt ne $t);
	} elsif ($dir eq "push") {
		push (@fn, TypeFunctionName("ndr_push", $e->{TYPE}));
		push (@fn, "ndr_$rt\_to_$t")
			if ($rt ne $t);
	} else {
		die("invalid direction `$dir'");
	}

	foreach (@fn) {
		unless (defined($needed->{$_})) {
			$needed->{$_} = 1;
		}
	}
}

sub NeededFunction($$)
{
	my ($fn,$needed) = @_;
	$needed->{"ndr_pull_$fn->{NAME}"} = 1;
	$needed->{"ndr_push_$fn->{NAME}"} = 1;
	$needed->{"ndr_print_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		NeededElement($e, $_, $needed) foreach ("pull", "push", "print");
	}
}

sub NeededType($$$)
{
	sub NeededType($$$);
	my ($t,$needed,$req) = @_;

	NeededType($t->{DATA}, $needed, $req) if ($t->{TYPE} eq "TYPEDEF");
	NeededType($t->{DATA}, $needed, $req) if ($t->{TYPE} eq "PIPE");

	if ($t->{TYPE} eq "STRUCT" or $t->{TYPE} eq "UNION") {
		return unless defined($t->{ELEMENTS});
		for my $e (@{$t->{ELEMENTS}}) {
			$e->{PARENT} = $t;
			if (has_property($e, "compression")) { 
				$needed->{"compression"} = 1;
			}
			NeededElement($e, $req, $needed);
			NeededType($e->{TYPE}, $needed, $req) if (ref($e->{TYPE}) eq "HASH");
		}
	}
}

#####################################################################
# work out what parse functions are needed
sub NeededInterface($$)
{
	my ($interface,$needed) = @_;
	NeededFunction($_, $needed) foreach (@{$interface->{FUNCTIONS}});
	foreach (reverse @{$interface->{TYPES}}) {

		if (has_property($_, "public")) {
			$needed->{TypeFunctionName("ndr_pull", $_)} = $needed->{TypeFunctionName("ndr_push", $_)} = 
				$needed->{TypeFunctionName("ndr_print", $_)} = 1;
		}

		NeededType($_, $needed, "pull") if ($needed->{TypeFunctionName("ndr_pull", $_)});
		NeededType($_, $needed, "push") if ($needed->{TypeFunctionName("ndr_push", $_)});
		NeededType($_, $needed, "print") if ($needed->{TypeFunctionName("ndr_print", $_)});
		if (has_property($_, "gensize")) {
			$needed->{"ndr_size_$_->{NAME}"} = 1;
		}
	}
}

sub TypeFunctionName($$)
{
	my ($prefix, $t) = @_;

	return "$prefix\_$t->{NAME}" if (ref($t) eq "HASH" and 
			$t->{TYPE} eq "TYPEDEF");
	return "$prefix\_$t->{TYPE}_$t->{NAME}" if (ref($t) eq "HASH");
	return "$prefix\_$t";
}

1;
