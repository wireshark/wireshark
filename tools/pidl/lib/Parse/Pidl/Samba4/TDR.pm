###################################################
# Trivial Parser Generator
# Copyright jelmer@samba.org 2005-2007
# released under the GNU GPL

package Parse::Pidl::Samba4::TDR;
use Parse::Pidl qw(fatal);
use Parse::Pidl::Util qw(has_property ParseExpr is_constant);
use Parse::Pidl::Samba4 qw(is_intree choose_header);

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(ParserType $ret $ret_hdr);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

sub new($) {
	my ($class) = shift;
	my $self = { ret => "", ret_hdr => "", tabs => "" };
	bless($self, $class);
}

sub indent($) { my $self = shift; $self->{tabs}.="\t"; }
sub deindent($) { my $self = shift; $self->{tabs} = substr($self->{tabs}, 1); }
sub pidl($$) { my $self = shift; $self->{ret} .= $self->{tabs}.(shift)."\n"; }
sub pidl_hdr($$) { my $self = shift; $self->{ret_hdr} .= (shift)."\n"; }
sub typearg($) { 
	my $t = shift; 
	return(", const char *name") if ($t eq "print");
	return(", TALLOC_CTX *mem_ctx") if ($t eq "pull");
	return("");
}

sub fn_declare($$$)
{
	my ($self, $p, $d) = @_;
	if ($p) { 
		$self->pidl($d); $self->pidl_hdr("$d;"); 
	} else { 
		$self->pidl("static $d"); 
	}
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

sub ParserElement($$$$)
{
	my ($self, $e,$t,$env) = @_;
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
		$self->pidl("{");
		$self->indent;
		$self->pidl("uint32_t saved_flags = tdr->flags;");
		$self->pidl("tdr->flags |= $e->{PROPERTIES}->{flag};");
	}

	if (has_property($e, "charset")) {
		fatal($e,"charset() on non-array element") unless (defined($e->{ARRAY_LEN}) and scalar(@{$e->{ARRAY_LEN}}) > 0);
		
		my $len = ParseExpr(@{$e->{ARRAY_LEN}}[0], $env, $e);
		if ($len eq "*") { $len = "-1"; }
		$name = ", mem_ctx" if ($t eq "pull");
		$self->pidl("TDR_CHECK(tdr_$t\_charset(tdr$name, &v->$e->{NAME}, $len, sizeof($e->{TYPE}_t), CH_$e->{PROPERTIES}->{charset}));");
		return;
	}

	if (has_property($e, "switch_is")) {
		$switch = ", " . ParseExpr($e->{PROPERTIES}->{switch_is}, $env, $e);
	}

	if (defined($e->{ARRAY_LEN}) and scalar(@{$e->{ARRAY_LEN}}) > 0) {
		my $len = ParseExpr($e->{ARRAY_LEN}[0], $env, $e);

		if ($t eq "pull" and not is_constant($len)) {
			$self->pidl("TDR_ALLOC(mem_ctx, v->$e->{NAME}, $len);");
			$mem_ctx = "v->$e->{NAME}";
		}

		$self->pidl("for (i = 0; i < $len; i++) {");
		$self->indent;
		$array = "[i]";
	}

	if ($t eq "pull") {
		$name = ", $mem_ctx";
	}

	if (has_property($e, "value") && $t eq "push") {
		$self->pidl("v->$e->{NAME} = ".ParseExpr($e->{PROPERTIES}->{value}, $env, $e).";");
	}

	$self->pidl("TDR_CHECK(tdr_$t\_$e->{TYPE}(tdr$name$switch, &v->$e->{NAME}$array));");

	if ($array) { $self->deindent; $self->pidl("}"); }

	if (has_property($e, "flag")) {
		$self->pidl("tdr->flags = saved_flags;");
		$self->deindent;
		$self->pidl("}");
	}
}

sub ParserStruct($$$$$)
{
	my ($self, $e,$t,$p) = @_;

	$self->fn_declare($p,"NTSTATUS tdr_$t\_$e->{NAME} (struct tdr_$t *tdr".typearg($t).", struct $e->{NAME} *v)");
	$self->pidl("{"); $self->indent;
	$self->pidl("int i;") if (ContainsArray($e));

	if ($t eq "print") {
		$self->pidl("tdr->print(tdr, \"\%-25s: struct $e->{NAME}\", name);");
		$self->pidl("tdr->level++;");
	}

	my %env = map { $_->{NAME} => "v->$_->{NAME}" } @{$e->{ELEMENTS}};
	$env{"this"} = "v";
	$self->ParserElement($_, $t, \%env) foreach (@{$e->{ELEMENTS}});
	
	if ($t eq "print") {
		$self->pidl("tdr->level--;");
	}

	$self->pidl("return NT_STATUS_OK;");

	$self->deindent; $self->pidl("}");
}

sub ParserUnion($$$$)
{
	my ($self, $e,$t,$p) = @_;

	$self->fn_declare($p,"NTSTATUS tdr_$t\_$e->{NAME}(struct tdr_$t *tdr".typearg($t).", int level, union $e->{NAME} *v)");
	$self->pidl("{"); $self->indent;
	$self->pidl("int i;") if (ContainsArray($e));

	if ($t eq "print") {
		$self->pidl("tdr->print(tdr, \"\%-25s: union $e->{NAME}\", name);");
		$self->pidl("tdr->level++;");
	}
	
	$self->pidl("switch (level) {"); $self->indent;
	foreach (@{$e->{ELEMENTS}}) {
		if (has_property($_, "case")) {
			$self->pidl("case " . $_->{PROPERTIES}->{case} . ":");
		} elsif (has_property($_, "default")) {
			$self->pidl("default:");
		}
		$self->indent; $self->ParserElement($_, $t, {}); $self->deindent;
		$self->pidl("break;");
	}
	$self->deindent; $self->pidl("}");

	if ($t eq "print") {
		$self->pidl("tdr->level--;");
	}
	
	$self->pidl("return NT_STATUS_OK;\n");
	$self->deindent; $self->pidl("}");
}

sub ParserBitmap($$$$)
{
	my ($self,$e,$t,$p) = @_;
	return if ($p);
	$self->pidl("#define tdr_$t\_$e->{NAME} tdr_$t\_" . Parse::Pidl::Typelist::bitmap_type_fn($e));
}

sub ParserEnum($$$$)
{
	my ($self,$e,$t,$p) = @_;
	my $bt = Parse::Pidl::Typelist::enum_type_fn($e);

	$self->fn_declare($p, "NTSTATUS tdr_$t\_$e->{NAME} (struct tdr_$t *tdr".typearg($t).", enum $e->{NAME} *v)");
	$self->pidl("{");
	if ($t eq "pull") {
		$self->pidl("\t$bt\_t r;");
		$self->pidl("\tTDR_CHECK(tdr_$t\_$bt(tdr, mem_ctx, \&r));");
		$self->pidl("\t*v = r;");
	} elsif ($t eq "push") {
		$self->pidl("\tTDR_CHECK(tdr_$t\_$bt(tdr, ($bt\_t *)v));");
	} elsif ($t eq "print") {
		$self->pidl("\t/* FIXME */");
	}
	$self->pidl("\treturn NT_STATUS_OK;");
	$self->pidl("}");
}

sub ParserTypedef($$$$)
{
	my ($self, $e,$t,$p) = @_;

	$self->ParserType($e->{DATA},$t);
}

sub ParserType($$$)
{
	my ($self, $e,$t) = @_;

	return if (has_property($e, "no$t"));

	my $handlers = { 
		STRUCT => \&ParserStruct, UNION => \&ParserUnion, 
		ENUM => \&ParserEnum, BITMAP => \&ParserBitmap,
		TYPEDEF => \&ParserTypedef
	};
	
	$handlers->{$e->{TYPE}}->($self, $e, $t, has_property($e, "public")) 
		if (defined($handlers->{$e->{TYPE}}));

	$self->pidl("");
}

sub ParserInterface($$)
{
	my ($self,$x) = @_;
	
	$self->pidl_hdr("#ifndef __TDR_$x->{NAME}_HEADER__");
	$self->pidl_hdr("#define __TDR_$x->{NAME}_HEADER__");

	foreach (@{$x->{DATA}}) {
		$self->ParserType($_, "pull");
		$self->ParserType($_, "push");
		$self->ParserType($_, "print");
	}

	$self->pidl_hdr("#endif /* __TDR_$x->{NAME}_HEADER__ */");
}

sub Parser($$$$)
{
	my ($self,$idl,$hdrname,$baseheader) = @_;
	$self->pidl("/* autogenerated by pidl */");
	if (is_intree()) {
		$self->pidl("#include \"includes.h\"");
	} else {
		$self->pidl("#include <stdio.h>");
		$self->pidl("#include <stdbool.h>");
		$self->pidl("#include <stdlib.h>");
		$self->pidl("#include <stdint.h>");
		$self->pidl("#include <stdarg.h>");
		$self->pidl("#include <string.h>");
		$self->pidl("#include <core/ntstatus.h>");
	}
	$self->pidl("#include \"$hdrname\"");
	$self->pidl("");
	$self->pidl_hdr("/* autogenerated by pidl */");
	$self->pidl_hdr("#include \"$baseheader\"");
	$self->pidl_hdr(choose_header("tdr/tdr.h", "tdr.h"));
	$self->pidl_hdr("");

	foreach (@$idl) { $self->ParserInterface($_) if ($_->{TYPE} eq "INTERFACE"); }	
	return ($self->{ret_hdr}, $self->{ret});
}

1;
