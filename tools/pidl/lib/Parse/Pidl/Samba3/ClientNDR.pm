###################################################
# Samba3 client generator for IDL structures
# on top of Samba4 style NDR functions
# Copyright jelmer@samba.org 2005-2006
# Copyright gd@samba.org 2008
# released under the GNU GPL

package Parse::Pidl::Samba3::ClientNDR;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(ParseFunction $res $res_hdr);

use strict;
use Parse::Pidl qw(fatal warning error);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(ContainsPipe);
use Parse::Pidl::Typelist qw(mapTypeName);
use Parse::Pidl::Samba4 qw(DeclLong);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv);

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

	foreach my $d (sort(keys %{$props})) {
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

sub ParseInvalidResponse($$)
{
	my ($self, $type) = @_;

	if ($type eq "sync") {
		$self->pidl("return NT_STATUS_INVALID_NETWORK_RESPONSE;");
	} elsif ($type eq "async") {
		$self->pidl("tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);");
		$self->pidl("return;");
	} else {
		die("ParseInvalidResponse($type)");
	}
}

sub ParseFunctionAsyncState($$$)
{
	my ($self, $if, $fn) = @_;

	my $state_str = "struct rpccli_$fn->{NAME}_state";
	my $done_fn = "rpccli_$fn->{NAME}_done";

	$self->pidl("$state_str {");
	$self->indent;
	$self->pidl("TALLOC_CTX *out_mem_ctx;");
	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl(mapTypeName($fn->{RETURN_TYPE}). " result;");
	}
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");
	$self->pidl("static void $done_fn(struct tevent_req *subreq);");
	$self->pidl("");
}

sub ParseFunctionAsyncSend($$$)
{
	my ($self, $if, $fn) = @_;

	my $fn_args = "";
	my $uif = uc($if);
	my $ufn = "NDR_".uc($fn->{NAME});
	my $state_str = "struct rpccli_$fn->{NAME}_state";
	my $done_fn = "rpccli_$fn->{NAME}_done";
	my $out_mem_ctx = "rpccli_$fn->{NAME}_out_memory";
	my $fn_str = "struct tevent_req *rpccli_$fn->{NAME}_send";
	my $pad = genpad($fn_str);

	$fn_args .= "TALLOC_CTX *mem_ctx";
	$fn_args .= ",\n" . $pad . "struct tevent_context *ev";
	$fn_args .= ",\n" . $pad . "struct rpc_pipe_client *cli";

	foreach (@{$fn->{ELEMENTS}}) {
		my $dir = ElementDirection($_);
		my $prop = HeaderProperties($_->{PROPERTIES}, ["in", "out"]);
		$fn_args .= ",\n" . $pad . DeclLong($_, "_") . " /* $dir $prop */";
	}

	$self->fn_declare("$fn_str($fn_args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("struct tevent_req *req;");
	$self->pidl("$state_str *state;");
	$self->pidl("struct tevent_req *subreq;");
	$self->pidl("");
	$self->pidl("req = tevent_req_create(mem_ctx, &state,");
	$self->pidl("\t\t\t$state_str);");
	$self->pidl("if (req == NULL) {");
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("state->out_mem_ctx = NULL;");
	$self->pidl("");

	my $out_params = 0;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/, @{$_->{DIRECTION}})) {
			$out_params++;
		}
	}

	if ($out_params > 0) {
		$self->pidl("state->out_mem_ctx = talloc_named_const(state, 0,");
		$self->pidl("\t\t     \"$out_mem_ctx\");");
		$self->pidl("if (tevent_req_nomem(state->out_mem_ctx, req)) {");
		$self->indent;
		$self->pidl("return tevent_req_post(req, ev);");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
	}

	$fn_str = "subreq = dcerpc_$fn->{NAME}_send";
	$pad = "\t" . genpad($fn_str);
	$fn_args = "state,\n" . $pad . "ev,\n" . $pad . "cli->binding_handle";
	foreach (@{$fn->{ELEMENTS}}) {
		$fn_args .= ",\n" . $pad . "_". $_->{NAME};
	}

	$self->pidl("$fn_str($fn_args);");
	$self->pidl("if (tevent_req_nomem(subreq, req)) {");
	$self->indent;
	$self->pidl("return tevent_req_post(req, ev);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("tevent_req_set_callback(subreq, $done_fn, req);");
	$self->pidl("return req;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunctionAsyncDone($$$)
{
	my ($self, $if, $fn) = @_;

	my $state_str = "struct rpccli_$fn->{NAME}_state";
	my $done_fn = "rpccli_$fn->{NAME}_done";

	$self->pidl("static void $done_fn(struct tevent_req *subreq)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("struct tevent_req *req = tevent_req_callback_data(");
	$self->pidl("\tsubreq, struct tevent_req);");
	$self->pidl("$state_str *state = tevent_req_data(");
	$self->pidl("\treq, $state_str);");
	$self->pidl("NTSTATUS status;");
	$self->pidl("TALLOC_CTX *mem_ctx;");
	$self->pidl("");

	$self->pidl("if (state->out_mem_ctx) {");
	$self->indent;
	$self->pidl("mem_ctx = state->out_mem_ctx;");
	$self->deindent;
	$self->pidl("} else {");
	$self->indent;
	$self->pidl("mem_ctx = state;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	my $fn_str = "status = dcerpc_$fn->{NAME}_recv";
	my $pad = "\t" . genpad($fn_str);
	my $fn_args = "subreq,\n" . $pad . "mem_ctx";
	if (defined($fn->{RETURN_TYPE})) {
		$fn_args .= ",\n" . $pad . "&state->result";
	}

	$self->pidl("$fn_str($fn_args);");
	$self->pidl("TALLOC_FREE(subreq);");
	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("tevent_req_nterror(req, status);");
	$self->pidl("return;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("tevent_req_done(req);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunctionAsyncRecv($$$)
{
	my ($self, $if, $fn) = @_;

	my $fn_args = "";
	my $state_str = "struct rpccli_$fn->{NAME}_state";
	my $fn_str = "NTSTATUS rpccli_$fn->{NAME}_recv";
	my $pad = genpad($fn_str);

	$fn_args .= "struct tevent_req *req,\n" . $pad . "TALLOC_CTX *mem_ctx";

	if (defined($fn->{RETURN_TYPE})) {
		$fn_args .= ",\n" . $pad . "$fn->{RETURN_TYPE} *result";
	}

	$self->fn_declare("$fn_str($fn_args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$state_str *state = tevent_req_data(");
	$self->pidl("\treq, $state_str);");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");
	$self->pidl("if (tevent_req_is_nterror(req, &status)) {");
	$self->indent;
	$self->pidl("tevent_req_received(req);");
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("/* Steal possible out parameters to the callers context */");
	$self->pidl("talloc_steal(mem_ctx, state->out_mem_ctx);");
	$self->pidl("");

	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl("/* Return result */");
		$self->pidl("*result = state->result;");
		$self->pidl("");
	}

	$self->pidl("tevent_req_received(req);");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunctionSync($$$)
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
		$fn_args .= ",\n" . $pad . DeclLong($_, "_") . " /* $dir $prop */";
	}

	if (defined($fn->{RETURN_TYPE}) && ($fn->{RETURN_TYPE} eq "WERROR")) {
		$fn_args .= ",\n" . $pad . "WERROR *werror";
	}

	$self->fn_declare("$fn_str($fn_args)");
	$self->pidl("{");
	$self->indent;
	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl(mapTypeName($fn->{RETURN_TYPE})." result;");
	}
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$fn_str = "status = dcerpc_$fn->{NAME}";
	$pad = "\t" . genpad($fn_str);
	$fn_args = "cli->binding_handle,\n" . $pad . "mem_ctx";
	foreach (@{$fn->{ELEMENTS}}) {
		$fn_args .= ",\n" . $pad . "_". $_->{NAME};
	}
	if (defined($fn->{RETURN_TYPE})) {
		$fn_args .= ",\n" . $pad . "&result";
	}

	$self->pidl("$fn_str($fn_args);");
	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("/* Return result */");
	if (not $fn->{RETURN_TYPE}) {
		$self->pidl("return NT_STATUS_OK;");
	} elsif ($fn->{RETURN_TYPE} eq "NTSTATUS") {
		$self->pidl("return result;");
	} elsif ($fn->{RETURN_TYPE} eq "WERROR") {
		$self->pidl("if (werror) {");
		$self->indent;
		$self->pidl("*werror = result;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("return werror_to_ntstatus(result);");
	} else {
		warning($fn->{ORIGINAL}, "Unable to convert $fn->{RETURN_TYPE} to NTSTATUS");
		$self->pidl("return NT_STATUS_OK;");
	}

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction($$$)
{
	my ($self, $if, $fn) = @_;

	$self->ParseFunctionAsyncState($if, $fn);
	$self->ParseFunctionAsyncSend($if, $fn);
	$self->ParseFunctionAsyncDone($if, $fn);
	$self->ParseFunctionAsyncRecv($if, $fn);

	$self->ParseFunctionSync($if, $fn);
}

sub ParseInterface($$)
{
	my ($self, $if) = @_;

	my $uif = uc($if->{NAME});

	$self->pidl_hdr("#ifndef __CLI_$uif\__");
	$self->pidl_hdr("#define __CLI_$uif\__");
	foreach my $fn (@{$if->{FUNCTIONS}}) {
		next if has_property($fn, "noopnum");
		next if has_property($fn, "todo");

		my $skip = 0;
		foreach my $e (@{$fn->{ELEMENTS}}) {
			if (ContainsPipe($e, $e->{LEVELS}[0])) {
				$skip = 1;
				last;
			}
		}
		next if $skip;

		$self->ParseFunction($if->{NAME}, $fn);
	}
	$self->pidl_hdr("#endif /* __CLI_$uif\__ */");
}

sub Parse($$$$)
{
	my($self,$ndr,$header,$c_header) = @_;

	$self->pidl("/*");
	$self->pidl(" * Unix SMB/CIFS implementation.");
	$self->pidl(" * client auto-generated by pidl. DO NOT MODIFY!");
	$self->pidl(" */");
	$self->pidl("");
	$self->pidl("#include \"includes.h\"");
	$self->pidl("#include \"$header\"");
	$self->pidl_hdr("#include \"$c_header\"");
	$self->pidl("");
	
	foreach (@$ndr) {
		$self->ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return ($self->{res}, $self->{res_hdr});
}

1;
