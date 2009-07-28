###################################################
# Samba3 client generator for IDL structures
# on top of Samba4 style NDR functions
# Copyright jelmer@samba.org 2005-2006
# Copyright gd@samba.org 2008
# released under the GNU GPL

package Parse::Pidl::Samba3::ClientNDR;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(ParseFunction $res $res_hdr ParseOutputArgument);

use strict;
use Parse::Pidl qw(fatal warning error);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::Samba4 qw(DeclLong);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv);

use vars qw($VERSION);
$VERSION = '0.01';

sub indent($) { my ($self) = @_; $self->{tabs}.="\t"; }
sub deindent($) { my ($self) = @_; $self->{tabs} = substr($self->{tabs}, 1); }
sub pidl($$) { my ($self,$txt) = @_; $self->{res} .= $txt ? "$self->{tabs}$txt\n" : "\n"; }
sub pidl_hdr($$) { my ($self, $txt) = @_; $self->{res_hdr} .= "$txt\n"; } 
sub fn_declare($$) { my ($self,$n) = @_; $self->pidl($n); $self->pidl_hdr("$n;"); }

sub genpad($)
{
	my ($s) = @_;
	my $nt = int((length($s)+1)/8);
	my $lt = ($nt*8)-1;
	my $ns = (length($s)-$lt);
	return "\t"x($nt)." "x($ns);
}

sub new($)
{
	my ($class) = shift;
	my $self = { res => "", res_hdr => "", tabs => "" };
	bless($self, $class);
}

sub ElementDirection($)
{
	my ($e) = @_;

	return "[in,out]" if (has_property($e, "in") and has_property($e, "out"));
	return "[in]" if (has_property($e, "in"));
	return "[out]" if (has_property($e, "out"));
	return "[in,out]";
}

sub HeaderProperties($$)
{
	my($props,$ignores) = @_;
	my $ret = "";

	foreach my $d (keys %{$props}) {
		next if (grep(/^$d$/, @$ignores));
		if($props->{$d} ne "1") {
			$ret.= "$d($props->{$d}),";
		} else {
			$ret.="$d,";
		}
	}

	if ($ret) {
		return "[" . substr($ret, 0, -1) . "]";
	}
}

sub ParseOutputArgument($$$)
{
	my ($self, $fn, $e) = @_;
	my $level = 0;

	if ($e->{LEVELS}[0]->{TYPE} ne "POINTER" and $e->{LEVELS}[0]->{TYPE} ne "ARRAY") {
		$self->pidl("return NT_STATUS_NOT_SUPPORTED;");
		error($e->{ORIGINAL}, "[out] argument is not a pointer or array");
		return;
	}

	if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
		$level = 1;
		if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($e->{NAME} && r.out.$e->{NAME}) {");
			$self->indent;
		}
	}

	if ($e->{LEVELS}[$level]->{TYPE} eq "ARRAY") {
		# This is a call to GenerateFunctionInEnv intentionally. 
		# Since the data is being copied into a user-provided data 
		# structure, the user should be able to know the size beforehand 
		# to allocate a structure of the right size.
		my $env = GenerateFunctionInEnv($fn, "r.");
		my $l = $e->{LEVELS}[$level];
		unless (defined($l->{SIZE_IS})) {
			error($e->{ORIGINAL}, "no size known for [out] array `$e->{NAME}'");
			$self->pidl('#error No size known for [out] array `$e->{NAME}');
		} else {
			my $size_is = ParseExpr($l->{SIZE_IS}, $env, $e->{ORIGINAL});
			if (has_property($e, "charset")) {
				$self->pidl("memcpy(CONST_DISCARD(char *, $e->{NAME}), r.out.$e->{NAME}, $size_is * sizeof(*$e->{NAME}));");
			} else {
				$self->pidl("memcpy($e->{NAME}, r.out.$e->{NAME}, $size_is * sizeof(*$e->{NAME}));");
			}
		}
	} else {
		$self->pidl("*$e->{NAME} = *r.out.$e->{NAME};");
	}

	if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
		if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref") {
			$self->deindent;
			$self->pidl("}");
		}
	}
}

sub ParseFunction($$$)
{
	my ($self, $if, $fn) = @_;

	my $fn_args = "";
	my $uif = uc($if);
	my $ufn = "NDR_".uc($fn->{NAME});
	my $fn_str = "NTSTATUS rpccli_$fn->{NAME}";
	my $pad = genpad($fn_str);

	$fn_args .= "struct rpc_pipe_client *cli,\n" . $pad . "TALLOC_CTX *mem_ctx";

	foreach (@{$fn->{ELEMENTS}}) {
		my $dir = ElementDirection($_);
		my $prop = HeaderProperties($_->{PROPERTIES}, ["in", "out"]);
		$fn_args .= ",\n" . $pad . DeclLong($_) . " /* $dir $prop */";
	}

	if (defined($fn->{RETURN_TYPE}) && ($fn->{RETURN_TYPE} eq "WERROR")) {
		$fn_args .= ",\n" . $pad . "WERROR *werror";
	}

	$self->fn_declare("$fn_str($fn_args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("struct $fn->{NAME} r;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");
	$self->pidl("/* In parameters */");

	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/in/, @{$_->{DIRECTION}})) {
			$self->pidl("r.in.$_->{NAME} = $_->{NAME};");
		}
	}

	$self->pidl("");
	$self->pidl("if (DEBUGLEVEL >= 10) {");
	$self->indent;
	$self->pidl("NDR_PRINT_IN_DEBUG($fn->{NAME}, &r);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("status = cli->dispatch(cli,");
	$self->pidl("\t\t\tmem_ctx,");
	$self->pidl("\t\t\t&ndr_table_$if,");
	$self->pidl("\t\t\t$ufn,");
	$self->pidl("\t\t\t&r);");
	$self->pidl("");

	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");

	$self->pidl("");
	$self->pidl("if (DEBUGLEVEL >= 10) {");
	$self->indent;
	$self->pidl("NDR_PRINT_OUT_DEBUG($fn->{NAME}, &r);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("if (NT_STATUS_IS_ERR(status)) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("/* Return variables */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));

		$self->ParseOutputArgument($fn, $e);

	}

	$self->pidl("");
	$self->pidl("/* Return result */");
	if (not $fn->{RETURN_TYPE}) {
		$self->pidl("return NT_STATUS_OK;");
	} elsif ($fn->{RETURN_TYPE} eq "NTSTATUS") {
		$self->pidl("return r.out.result;");
	} elsif ($fn->{RETURN_TYPE} eq "WERROR") {
		$self->pidl("if (werror) {");
		$self->indent;
		$self->pidl("*werror = r.out.result;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("return werror_to_ntstatus(r.out.result);");
	} else {
		warning($fn->{ORIGINAL}, "Unable to convert $fn->{RETURN_TYPE} to NTSTATUS");
		$self->pidl("return NT_STATUS_OK;");
	}

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseInterface($$)
{
	my ($self, $if) = @_;

	my $uif = uc($if->{NAME});

	$self->pidl_hdr("#ifndef __CLI_$uif\__");
	$self->pidl_hdr("#define __CLI_$uif\__");
	foreach (@{$if->{FUNCTIONS}}) {
		next if ($_->{PROPERTIES}{noopnum});
		$self->ParseFunction($if->{NAME}, $_);
	}
	$self->pidl_hdr("#endif /* __CLI_$uif\__ */");
}

sub Parse($$$$)
{
	my($self,$ndr,$header,$ndr_header) = @_;

	$self->pidl("/*");
	$self->pidl(" * Unix SMB/CIFS implementation.");
	$self->pidl(" * client auto-generated by pidl. DO NOT MODIFY!");
	$self->pidl(" */");
	$self->pidl("");
	$self->pidl("#include \"includes.h\"");
	$self->pidl("#include \"$header\"");
	$self->pidl_hdr("#include \"$ndr_header\"");
	$self->pidl("");
	
	foreach (@$ndr) {
		$self->ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return ($self->{res}, $self->{res_hdr});
}

1;
