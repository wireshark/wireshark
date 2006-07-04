###################################################
# Samba3 NDR parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba3::Parser;

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapType);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);
use Parse::Pidl::Samba3::Types qw(DeclShort DeclLong InitType DissectType StringType);

use vars qw($VERSION);
$VERSION = '0.01';

use constant PRIMITIVES => 1;
use constant DEFERRED => 2;

my $res = "";
my $tabs = "";
sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { $res .= $tabs.(shift)."\n"; }
sub fatal($$) { my ($e,$s) = @_; die("$e->{ORIGINAL}->{FILE}:$e->{ORIGINAL}->{LINE}: $s\n"); }

#TODO:
# - Add some security checks (array sizes, memory alloc == NULL, etc)
# - Don't add seperate _p and _d functions if there is no deferred data
# - [string] with non-varying arrays and "surrounding" strings 
# - subcontext()
# - DATA_BLOB

sub Align($$)
{
	my ($a,$b) = @_;

	# Only align if previous element was smaller than current one
	if ($$a < $b) {
		pidl "if (!prs_align_custom(ps, $b))";
		pidl "\treturn False;";
		pidl "";
	}

	$$a = $b;
}

sub DeclareArrayVariables
{
	my $es = shift;
	my $what = shift;

	my $output = 0;

	foreach my $e (@$es) {
		foreach my $l (@{$e->{LEVELS}}) {
			if ($what) {
				next if ($l->{IS_DEFERRED} and $what == PRIMITIVES);
				next if (not $l->{IS_DEFERRED} and $what == DEFERRED);
			}
			if ($l->{TYPE} eq "ARRAY" and not $l->{IS_ZERO_TERMINATED}) {
				pidl "uint32 i_$e->{NAME}_$l->{LEVEL_INDEX};";
				$output = 1;
			}
		}
	}
	pidl "" if $output;
}

sub ParseElementLevelData($$$$$$$)
{
	my ($e,$l,$nl,$env,$varname,$what,$align) = @_;

	my $c = DissectType($e,$l,$varname,$what,$align);
	return if not $c;

	if (defined($e->{ALIGN})) {
		Align($align, $e->{ALIGN});
	} else {
		# Default to 4
		Align($align, 4);
	}

	pidl "if (!$c)";
	pidl "\treturn False;";
}

sub ParseElementLevelArray($$$$$$$)
{
	my ($e,$l,$nl,$env,$varname,$what,$align) = @_;

	if ($l->{IS_ZERO_TERMINATED}) {
		return if ($what == DEFERRED);
		
		my ($t,$f) = StringType($e,$l);

		Align($align, 4);
		pidl "if (!smb_io_$t(\"$e->{NAME}\", &$varname, 1, ps, depth))";
		pidl "\treturn False;";

		$$align = 0;
		return;
	}

	my $len = ParseExpr($l->{LENGTH_IS}, $env);
	my $size = ParseExpr($l->{SIZE_IS}, $env);

	if ($what == PRIMITIVES) {
		# Fetch headers
		if ($l->{IS_CONFORMANT} and not $l->{IS_SURROUNDING}) {
			Align($align, 4);
			pidl "if (!prs_uint32(\"size_$e->{NAME}\", ps, depth, &" . ParseExpr("size_$e->{NAME}", $env) . "))";
			pidl "\treturn False;";
			pidl "";
		}
	
		if ($l->{IS_VARYING}) {
			Align($align, 4);
			pidl "if (!prs_uint32(\"offset_$e->{NAME}\", ps, depth, &" . ParseExpr("offset_$e->{NAME}", $env) . "))";
			pidl "\treturn False;";
			pidl "";

			pidl "if (!prs_uint32(\"length_$e->{NAME}\", ps, depth, &" . ParseExpr("length_$e->{NAME}", $env) . "))";
			pidl "\treturn False;";
			pidl "";
		}
	}

	# Everything but fixed arrays have to be allocated
	if (!$l->{IS_FIXED} and $what == PRIMITIVES) {
		pidl "if (UNMARSHALLING(ps)) {";
		indent;
		pidl "$varname = (void *)PRS_ALLOC_MEM_VOID(ps,sizeof(*$varname)*$size);";
		deindent;
		pidl "}";
	}

	return if ($what == DEFERRED and not ContainsDeferred($e,$l));

	my $i = "i_$e->{NAME}_$l->{LEVEL_INDEX}";
	pidl "for ($i=0; $i<$len;$i++) {";
	indent;
	ParseElementLevel($e,$nl,$env,$varname."[$i]",$what,$align);
	deindent;
	pidl "}";
}

sub ParseElementLevelSwitch($$$$$$$)
{
	my ($e,$l,$nl,$env,$varname,$what,$align) = @_;

	ParseElementLevel($e,$nl,$env,$varname,$what,$align);
}

sub ParseElementLevelPtr($$$$$$$)
{
	my ($e,$l,$nl,$env,$varname,$what,$align) = @_;

	if ($what == PRIMITIVES) {
		if (($l->{POINTER_TYPE} eq "ref") and ($l->{LEVEL} eq "EMBEDDED")) {
			# Ref pointers always have to be non-NULL
			pidl "if (MARSHALLING(ps) && !" . ParseExpr("ptr$l->{POINTER_INDEX}_$e->{NAME}", $env) . ")";
			pidl "\treturn False;";
			pidl "";
		} 
		
		unless ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP") {
			Align($align, 4);
			pidl "if (!prs_uint32(\"ptr$l->{POINTER_INDEX}_$e->{NAME}\", ps, depth, &" . ParseExpr("ptr$l->{POINTER_INDEX}_$e->{NAME}", $env) . "))";
			pidl "\treturn False;";
			pidl "";
		}
	}

	if ($l->{POINTER_TYPE} eq "relative") {
		fatal($e, "relative pointers not supported for Samba 3");
		#FIXME
	}
	
	if ($what == DEFERRED) {
		if ($l->{POINTER_TYPE} ne "ref") {
			pidl "if (" . ParseExpr("ptr$l->{POINTER_INDEX}_$e->{NAME}", $env) . ") {";
			indent;
		}
		ParseElementLevel($e,$nl,$env,$varname,PRIMITIVES,$align);
		ParseElementLevel($e,$nl,$env,$varname,DEFERRED,$align);
		if ($l->{POINTER_TYPE} ne "ref") {
			deindent;
			pidl "}";
		}
		$$align = 0;
	}
}

sub ParseElementLevelSubcontext($$$$$$$)
{
	my ($e,$l,$nl,$env,$varname,$what,$align) = @_;

	fatal($e, "subcontext() not supported for Samba 3");
	#FIXME
}

sub ParseElementLevel($$$$$$)
{
	my ($e,$l,$env,$varname,$what,$align) = @_;

	{
		DATA => \&ParseElementLevelData,
		SUBCONTEXT => \&ParseElementLevelSubcontext,
		POINTER => \&ParseElementLevelPtr,
		SWITCH => \&ParseElementLevelSwitch,
		ARRAY => \&ParseElementLevelArray
	}->{$l->{TYPE}}->($e,$l,GetNextLevel($e,$l),$env,$varname,$what,$align);
}

sub ParseElement($$$$)
{
	my ($e,$env,$what,$align) = @_;

	ParseElementLevel($e, $e->{LEVELS}[0], $env, ParseExpr($e->{NAME}, $env), $what, $align);
}

sub InitLevel($$$$)
{
	sub InitLevel($$$$);
	my ($e,$l,$varname,$env) = @_;

	if ($l->{TYPE} eq "POINTER") {
		if ($l->{POINTER_TYPE} eq "ref") {
			pidl "if (!$varname)";
			pidl "\treturn False;";
			pidl "";
		} else {
			pidl "if ($varname) {";
			indent;
		}

		unless ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP") {
			pidl ParseExpr("ptr$l->{POINTER_INDEX}_$e->{NAME}", $env) . " = 1;";
		}
		InitLevel($e, GetNextLevel($e,$l), "*$varname", $env);
		
		if ($l->{POINTER_TYPE} ne "ref") {
			deindent;
			pidl "} else {";
			pidl "\t" . ParseExpr("ptr$l->{POINTER_INDEX}_$e->{NAME}", $env) . " = 0;";
			pidl "}";
		}
	} elsif ($l->{TYPE} eq "ARRAY" and $l->{IS_ZERO_TERMINATED}) {
		my ($t,$f) = StringType($e,$l);
		pidl "init_$t(&" . ParseExpr($e->{NAME}, $env) . ", ".substr($varname, 1) . ", $f);"; 
	} elsif ($l->{TYPE} eq "ARRAY") {
		pidl ParseExpr($e->{NAME}, $env) . " = $varname;";
	} elsif ($l->{TYPE} eq "DATA") {
		pidl InitType($e, $l, ParseExpr($e->{NAME}, $env), $varname);
	} elsif ($l->{TYPE} eq "SWITCH") {
		InitLevel($e, GetNextLevel($e,$l), $varname, $env);
		pidl ParseExpr($e->{NAME}, $env) . ".switch_value = " . ParseExpr($l->{SWITCH_IS}, $env) . ";";
	}
}

sub GenerateEnvElement($$)
{
	my ($e,$env) = @_;
	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "DATA") {
			$env->{$e->{NAME}} = "v->$e->{NAME}";
		} elsif ($l->{TYPE} eq "POINTER") {
			$env->{"ptr$l->{POINTER_INDEX}_$e->{NAME}"} = "v->ptr$l->{POINTER_INDEX}_$e->{NAME}";
		} elsif ($l->{TYPE} eq "SWITCH") {
		} elsif ($l->{TYPE} eq "ARRAY" and not $l->{IS_ZERO_TERMINATED}) {
			$env->{"length_$e->{NAME}"} = "v->length_$e->{NAME}";
			$env->{"size_$e->{NAME}"} = "v->size_$e->{NAME}";
			$env->{"offset_$e->{NAME}"} = "v->offset_$e->{NAME}";
		}
	}
}

sub ParseStruct($$$)
{
	my ($if,$s,$n) = @_;

	my $fn = "$if->{NAME}_io_$n";
	my $sn = uc("$if->{NAME}_$n");
	my $ifn = "init_$if->{NAME}_$n";

	my $args = "";
	foreach (@{$s->{ELEMENTS}}) {
		$args .= ", " . DeclLong($_);
	}

	my $env = { "this" => "v" };
	GenerateEnvElement($_, $env) foreach (@{$s->{ELEMENTS}});

	pidl "BOOL $ifn($sn *v$args)";
	pidl "{";
	indent;
	pidl "DEBUG(5,(\"$ifn\\n\"));";
	pidl "";
	# Call init for all arguments
	foreach (@{$s->{ELEMENTS}}) {
		InitLevel($_, $_->{LEVELS}[0], $_->{NAME}, $env);
		pidl "";
	}
	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";

	my $pfn = "$fn\_p";
	my $dfn = "$fn\_d";
	
	pidl "BOOL $pfn(const char *desc, $sn *v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($s->{ELEMENTS}, PRIMITIVES);
	pidl "if (v == NULL)";
	pidl "\treturn False;";
	pidl "";
	pidl "prs_debug(ps, depth, desc, \"$pfn\");";
	pidl "depth++;";

	my $align = 8;
	if ($s->{SURROUNDING_ELEMENT}) {
		pidl "if (!prs_uint32(\"size_$s->{SURROUNDING_ELEMENT}->{NAME}\", ps, depth, &" . ParseExpr("size_$s->{SURROUNDING_ELEMENT}->{NAME}", $env) . "))";
		pidl "\treturn False;";
		pidl "";
		$align = 4;
		
	}

	foreach (@{$s->{ELEMENTS}}) {
		ParseElement($_, $env, PRIMITIVES, \$align); 
		pidl "";
	}

	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";

	pidl "BOOL $dfn(const char *desc, $sn *v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($s->{ELEMENTS}, DEFERRED);
	pidl "if (v == NULL)";
	pidl "\treturn False;";
	pidl "";
	pidl "prs_debug(ps, depth, desc, \"$dfn\");";
	pidl "depth++;";

	$align = 0;
	foreach (@{$s->{ELEMENTS}}) {
		ParseElement($_, $env, DEFERRED, \$align); 
		pidl "";
	}

	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
}

sub UnionGenerateEnvElement($)
{
	my $e = shift;
	my $env = {};

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "DATA") {
			$env->{$e->{NAME}} = "v->u.$e->{NAME}";
		} elsif ($l->{TYPE} eq "POINTER") {
			$env->{"ptr$l->{POINTER_INDEX}_$e->{NAME}"} = "v->ptr$l->{POINTER_INDEX}";
		} elsif ($l->{TYPE} eq "SWITCH") {
		} elsif ($l->{TYPE} eq "ARRAY" and not $l->{IS_ZERO_TERMINATED}) {
			$env->{"length_$e->{NAME}"} = "v->length";
			$env->{"size_$e->{NAME}"} = "v->size";
			$env->{"offset_$e->{NAME}"} = "v->offset";
		}
	}

	return $env;
}

sub ParseUnion($$$)
{
	my ($if,$u,$n) = @_;

	my $fn = "$if->{NAME}_io_$n";
	my $sn = uc("$if->{NAME}_$n\_ctr");

	my $pfn = "$fn\_p";
	my $dfn = "$fn\_d";
	
	pidl "BOOL $pfn(const char *desc, $sn* v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($u->{ELEMENTS});

	if (defined ($u->{SWITCH_TYPE})) {
		pidl "if (!prs_$u->{SWITCH_TYPE}(\"switch_value\", ps, depth, &v->switch_value))";
		pidl "\treturn False;";
		pidl "";
	}

	# Maybe check here that level and v->switch_value are equal?

	pidl "switch (v->switch_value) {";
	indent;

	foreach (@{$u->{ELEMENTS}}) {
		pidl "$_->{CASE}:";
		indent;
		if ($_->{TYPE} ne "EMPTY") {
			pidl "depth++;";
			my $env = UnionGenerateEnvElement($_);
			my $align = 8;
			ParseElement($_, $env, PRIMITIVES, \$align); 
			pidl "depth--;";
		}
		pidl "break;";
		deindent;
		pidl "";
	}

	unless ($u->{HAS_DEFAULT}) {
		pidl "default:";
		pidl "\treturn False;";
		pidl "";
	}

	deindent;
	pidl "}";
	pidl "";
	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";

	pidl "BOOL $dfn(const char *desc, $sn* v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($u->{ELEMENTS});

	if (defined($u->{SWITCH_TYPE})) {
		pidl "switch (v->switch_value) {";
	} else {
		pidl "switch (level) {";
	}
	indent;

	foreach (@{$u->{ELEMENTS}}) {
		pidl "$_->{CASE}:";
		indent;
		if ($_->{TYPE} ne "EMPTY") {
			pidl "depth++;";
			my $env = UnionGenerateEnvElement($_);
			my $align = 0;
			ParseElement($_, $env, DEFERRED, \$align); 
			pidl "depth--;";
		}
		pidl "break;";
		deindent;
		pidl "";
	}

	deindent;
	pidl "}";
	pidl "";
	pidl "return True;";
	deindent;
	pidl "}";

}

sub CreateFnDirection($$$$$)
{
	my ($fn,$ifn,$s,$all,$es) = @_;

	my $args = "";
	foreach (@$all) { $args .= ", " . DeclLong($_); }

	my $env = { };
	GenerateEnvElement($_, $env) foreach (@$es);

	pidl "BOOL $ifn($s *v$args)";
	pidl "{";
	indent;
	pidl "DEBUG(5,(\"$ifn\\n\"));";
	pidl "";
	# Call init for all arguments
	foreach (@$es) {
		InitLevel($_, $_->{LEVELS}[0], $_->{NAME}, $env);
		pidl "";
	}
	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
	
	pidl "BOOL $fn(const char *desc, $s *v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($es);
	pidl "if (v == NULL)";
	pidl "\treturn False;";
	pidl "";
	pidl "prs_debug(ps, depth, desc, \"$fn\");";
	pidl "depth++;";

	my $align = 8;
	foreach (@$es) {
		ParseElement($_, $env, PRIMITIVES, \$align); 
		ParseElement($_, $env, DEFERRED, \$align); 
		pidl "";
	}

	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
}

sub ParseFunction($$)
{
	my ($if,$fn) = @_;

	my @in = ();
	my @out = ();
	my @all = @{$fn->{ELEMENTS}};

	foreach (@{$fn->{ELEMENTS}}) {
		push (@in, $_) if (grep(/in/, @{$_->{DIRECTION}}));
		push (@out, $_) if (grep(/out/, @{$_->{DIRECTION}}));
	}

	if (defined($fn->{RETURN_TYPE})) {
		my $status = { 
			NAME => "status", 
			TYPE => $fn->{RETURN_TYPE},
			LEVELS => [
				{
					TYPE => "DATA",
					DATA_TYPE => $fn->{RETURN_TYPE}
				}
			]
		};

		push (@out, $status);
		push (@all, $status);
	}

	CreateFnDirection("$if->{NAME}_io_q_$fn->{NAME}", 
				 "init_$if->{NAME}_q_$fn->{NAME}", 
				 uc("$if->{NAME}_q_$fn->{NAME}"), 
				 \@in, \@in);
	CreateFnDirection("$if->{NAME}_io_r_$fn->{NAME}", 
				 "init_$if->{NAME}_r_$fn->{NAME}",
				 uc("$if->{NAME}_r_$fn->{NAME}"), 
				 \@all, \@out);
}

sub ParseInterface($)
{
	my $if = shift;

	# Structures first 
	pidl "/* $if->{NAME} structures */";
	foreach (@{$if->{TYPES}}) {
		ParseStruct($if, $_->{DATA}, $_->{NAME}) if ($_->{DATA}->{TYPE} eq "STRUCT");
		ParseUnion($if, $_->{DATA}, $_->{NAME}) if ($_->{DATA}->{TYPE} eq "UNION");
	}

	pidl "/* $if->{NAME} functions */";
	ParseFunction($if, $_) foreach (@{$if->{FUNCTIONS}});
}

sub Parse($$)
{
	my($ndr,$filename) = @_;

	$tabs = "";
	$res = "";

	pidl "/*";
	pidl " * Unix SMB/CIFS implementation.";
	pidl " * parser auto-generated by pidl. DO NOT MODIFY!";
	pidl " */";
	pidl "";
	pidl "#include \"includes.h\"";
	pidl "";
	pidl "#undef DBGC_CLASS";
	pidl "#define DBGC_CLASS DBGC_RPC_PARSE";
	pidl "";

	foreach (@$ndr) {
		ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return $res;
}

1;
