###################################################
# Trivial Parser Generator
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba4::TDR;
use Parse::Pidl::Util qw(has_property ParseExpr is_constant);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

my $ret;
my $ret_hdr;
my $tabs = "";

sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { $ret .= $tabs.(shift)."\n"; }
sub pidl_hdr($) { $ret_hdr .= (shift)."\n"; }
sub fatal($$) { my ($e,$s) = @_; die("$e->{FILE}:$e->{LINE}: $s\n"); }
sub typearg($) { 
	my $t = shift; 
	return(", const char *name") if ($t eq "print");
	return(", TALLOC_CTX *mem_ctx") if ($t eq "pull");
	return("");
}

sub fn_declare($$)
{
	my ($p, $d) = @_;
	if ($p) { pidl $d; pidl_hdr "$d;"; } else { pidl "static $d"; }
}

sub ContainsArray($)
{
	my $e = shift;
	foreach (@{$e->{ELEMENTS}}) {
		next if (has_property($_, "charset") and
			scalar(@{$_->{ARRAY_LEN}}) == 1);
		return 1 if (defined($_->{ARRAY_LEN}) and 
				scalar(@{$_->{ARRAY_LEN}}) > 0);
	}
	return 0;
}

sub ParserElement($$$)
{
	my ($e,$t,$env) = @_;
	my $switch = "";
	my $array = "";
	my $name = "";
	my $mem_ctx = "mem_ctx";

	fatal($e,"Pointers not supported in TDR") if ($e->{POINTERS} > 0);
	fatal($e,"size_is() not supported in TDR") if (has_property($e, "size_is"));
	fatal($e,"length_is() not supported in TDR") if (has_property($e, "length_is"));

	if ($t eq "print") {
		$name = ", \"$e->{NAME}\"$array";
	}

	if (has_property($e, "flag")) {
		pidl "{";
		indent;
		pidl "uint32_t saved_flags = tdr->flags;";
		pidl "tdr->flags |= $e->{PROPERTIES}->{flag};";
	}

	if (has_property($e, "charset")) {
		fatal($e,"charset() on non-array element") unless (defined($e->{ARRAY_LEN}) and scalar(@{$e->{ARRAY_LEN}}) > 0);
		
		my $len = ParseExpr(@{$e->{ARRAY_LEN}}[0], $env);
		if ($len eq "*") { $len = "-1"; }
		$name = ", mem_ctx" if ($t eq "pull");
		pidl "TDR_CHECK(tdr_$t\_charset(tdr$name, &v->$e->{NAME}, $len, sizeof($e->{TYPE}_t), CH_$e->{PROPERTIES}->{charset}));";
		return;
	}

	if (has_property($e, "switch_is")) {
		$switch = ", " . ParseExpr($e->{PROPERTIES}->{switch_is}, $env);
	}

	if (defined($e->{ARRAY_LEN}) and scalar(@{$e->{ARRAY_LEN}}) > 0) {
		my $len = ParseExpr($e->{ARRAY_LEN}[0], $env);

		if ($t eq "pull" and not is_constant($len)) {
			pidl "TDR_ALLOC(mem_ctx, v->$e->{NAME}, $len);";
			$mem_ctx = "v->$e->{NAME}";
		}

		pidl "for (i = 0; i < $len; i++) {";
		indent;
		$array = "[i]";
	}

	if ($t eq "pull") {
		$name = ", $mem_ctx";
	}

	if (has_property($e, "value") && $t eq "push") {
		pidl "v->$e->{NAME} = ".ParseExpr($e->{PROPERTIES}->{value}, $env).";";
	}

	pidl "TDR_CHECK(tdr_$t\_$e->{TYPE}(tdr$name$switch, &v->$e->{NAME}$array));";

	if ($array) { deindent; pidl "}"; }

	if (has_property($e, "flag")) {
		pidl "tdr->flags = saved_flags;";
		deindent;
		pidl "}";
	}
}

sub ParserStruct($$$$)
{
	my ($e,$n,$t,$p) = @_;

	fn_declare($p,,"NTSTATUS tdr_$t\_$n (struct tdr_$t *tdr".typearg($t).", struct $n *v)");
	pidl "{"; indent;
	pidl "int i;" if (ContainsArray($e));

	if ($t eq "print") {
		pidl "tdr->print(tdr, \"\%-25s: struct $n\", name);";
		pidl "tdr->level++;";
	}

	my %env = map { $_->{NAME} => "v->$_->{NAME}" } @{$e->{ELEMENTS}};
	$env{"this"} = "v";
	ParserElement($_, $t, \%env) foreach (@{$e->{ELEMENTS}});
	
	if ($t eq "print") {
		pidl "tdr->level--;";
	}

	pidl "return NT_STATUS_OK;";

	deindent; pidl "}";
}

sub ParserUnion($$$$)
{
	my ($e,$n,$t,$p) = @_;

	fn_declare($p,"NTSTATUS tdr_$t\_$n(struct tdr_$t *tdr".typearg($t).", int level, union $n *v)");
	pidl "{"; indent;
	pidl "int i;" if (ContainsArray($e));

	if ($t eq "print") {
		pidl "tdr->print(tdr, \"\%-25s: union $n\", name);";
		pidl "tdr->level++;";
	}
	
	pidl "switch (level) {"; indent;
	foreach (@{$e->{ELEMENTS}}) {
		if (has_property($_, "case")) {
			pidl "case " . $_->{PROPERTIES}->{case} . ":";
		} elsif (has_property($_, "default")) {
			pidl "default:";
		}
		indent; ParserElement($_, $t, {}); deindent;
		pidl "break;";
	}
	deindent; pidl "}";

	if ($t eq "print") {
		pidl "tdr->level--;";
	}
	
	pidl "return NT_STATUS_OK;\n";
	deindent; pidl "}";
}

sub ParserBitmap($$$$)
{
	my ($e,$n,$t,$p) = @_;
	return if ($p);
	pidl "#define tdr_$t\_$n tdr_$t\_" . Parse::Pidl::Typelist::bitmap_type_fn($e);
}

sub ParserEnum($$$$)
{
	my ($e,$n,$t,$p) = @_;
	my $bt = ($e->{PROPERTIES}->{base_type} or "uint8");
	
	fn_declare($p, "NTSTATUS tdr_$t\_$n (struct tdr_$t *tdr".typearg($t).", enum $n *v)");
	pidl "{";
	if ($t eq "pull") {
		pidl "\t$bt\_t r;";
		pidl "\tTDR_CHECK(tdr_$t\_$bt(tdr, mem_ctx, \&r));";
		pidl "\t*v = r;";
	} elsif ($t eq "push") {
		pidl "\tTDR_CHECK(tdr_$t\_$bt(tdr, ($bt\_t *)v));";
	} elsif ($t eq "print") {
		pidl "\t/* FIXME */";
	}
	pidl "\treturn NT_STATUS_OK;";
	pidl "}";
}

sub ParserTypedef($$)
{
	my ($e,$t) = @_;

	return if (has_property($e, "no$t"));

	$e->{DATA}->{PROPERTIES} = $e->{PROPERTIES};

	{ STRUCT => \&ParserStruct, UNION => \&ParserUnion, 
		ENUM => \&ParserEnum, BITMAP => \&ParserBitmap
	}->{$e->{DATA}->{TYPE}}->($e->{DATA}, $e->{NAME}, $t, has_property($e, "public"));

	pidl "";
}

sub ParserInterface($)
{
	my $x = shift;
	
	pidl_hdr "#ifndef __TDR_$x->{NAME}_HEADER__";
	pidl_hdr "#define __TDR_$x->{NAME}_HEADER__";

	foreach (@{$x->{DATA}}) {
		next if ($_->{TYPE} ne "TYPEDEF");
		ParserTypedef($_, "pull");
		ParserTypedef($_, "push");
		ParserTypedef($_, "print");
	}

	pidl_hdr "#endif /* __TDR_$x->{NAME}_HEADER__ */";
}

sub Parser($$$)
{
	my ($idl,$hdrname,$baseheader) = @_;
	$ret = ""; $ret_hdr = "";
	pidl "/* autogenerated by pidl */";
	pidl "#include \"includes.h\"";
	pidl "#include \"$hdrname\"";
	pidl "";
	pidl_hdr "/* autogenerated by pidl */";
	pidl_hdr "#include \"$baseheader\"";
	pidl_hdr "";

	foreach (@$idl) { ParserInterface($_) if ($_->{TYPE} eq "INTERFACE"); }	
	return ($ret_hdr, $ret);
}

1;
