###################################################
# client calls generator
# Copyright tridge@samba.org 2003
# Copyright jelmer@samba.org 2005-2006
# released under the GNU GPL

package Parse::Pidl::Samba4::NDR::Client;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(Parse);

use Parse::Pidl qw(fatal warning error);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(ContainsPipe);
use Parse::Pidl::Typelist qw(mapTypeName);
use Parse::Pidl::Samba4 qw(choose_header is_intree DeclLong);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

sub indent($) { my ($self) = @_; $self->{tabs}.="\t"; }
sub deindent($) { my ($self) = @_; $self->{tabs} = substr($self->{tabs}, 1); }
sub pidl($$) { my ($self,$txt) = @_; $self->{res} .= $txt ? "$self->{tabs}$txt\n" : "\n"; }
sub pidl_hdr($$) { my ($self, $txt) = @_; $self->{res_hdr} .= "$txt\n"; }
sub pidl_both($$) { my ($self, $txt) = @_; $self->{hdr} .= "$txt\n"; $self->{res_hdr} .= "$txt\n"; }
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

sub ParseFunctionHasPipes($$)
{
	my ($self, $fn) = @_;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		return 1 if ContainsPipe($e, $e->{LEVELS}[0]);
	}

	return 0;
}

sub ParseFunction_r_State($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	$self->pidl("struct dcerpc_$name\_r_state {");
	$self->indent;
	$self->pidl("TALLOC_CTX *out_mem_ctx;");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");
	$self->pidl("static void dcerpc_$name\_r_done(struct tevent_req *subreq);");
	$self->pidl("");
}

sub ParseFunction_r_Send($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "struct tevent_req *dcerpc_$name\_r_send(TALLOC_CTX *mem_ctx,\n";
	$proto   .= "\tstruct tevent_context *ev,\n",
	$proto   .= "\tstruct dcerpc_binding_handle *h,\n",
	$proto   .= "\tstruct $name *r)";

	$self->fn_declare($proto);

	$self->pidl("{");
	$self->indent;

	$self->pidl("struct tevent_req *req;");
	$self->pidl("struct dcerpc_$name\_r_state *state;");
	$self->pidl("struct tevent_req *subreq;");
	$self->pidl("");

	$self->pidl("req = tevent_req_create(mem_ctx, &state,");
	$self->pidl("\t\t\tstruct dcerpc_$name\_r_state);");
	$self->pidl("if (req == NULL) {");
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	my $out_params = 0;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});
		next if ContainsPipe($e, $e->{LEVELS}[0]);
		$out_params++;

	}

	my $submem;
	if ($out_params > 0) {
		$self->pidl("state->out_mem_ctx = talloc_new(state);");
		$self->pidl("if (tevent_req_nomem(state->out_mem_ctx, req)) {");
		$self->indent;
		$self->pidl("return tevent_req_post(req, ev);");
		$self->deindent;
		$self->pidl("}");
		$submem = "state->out_mem_ctx";
	} else {
		$self->pidl("state->out_mem_ctx = NULL;");
		$submem = "state";
	}
	$self->pidl("");

	$self->pidl("subreq = dcerpc_binding_handle_call_send(state, ev, h,");
	$self->pidl("\t\tNULL, &ndr_table_$if->{NAME},");
	$self->pidl("\t\tNDR_$uname, $submem, r);");
	$self->pidl("if (tevent_req_nomem(subreq, req)) {");
	$self->indent;
	$self->pidl("return tevent_req_post(req, ev);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("tevent_req_set_callback(subreq, dcerpc_$name\_r_done, req);");
	$self->pidl("");

	$self->pidl("return req;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_r_Done($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "static void dcerpc_$name\_r_done(struct tevent_req *subreq)";

	$self->pidl("$proto");
	$self->pidl("{");
	$self->indent;

	$self->pidl("struct tevent_req *req =");
	$self->pidl("\ttevent_req_callback_data(subreq,");
	$self->pidl("\tstruct tevent_req);");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("status = dcerpc_binding_handle_call_recv(subreq);");
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

sub ParseFunction_r_Recv($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	my $proto = "NTSTATUS dcerpc_$name\_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx)";

	$self->fn_declare($proto);

	$self->pidl("{");
	$self->indent;

	$self->pidl("struct dcerpc_$name\_r_state *state =");
	$self->pidl("\ttevent_req_data(req,");
	$self->pidl("\tstruct dcerpc_$name\_r_state);");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("if (tevent_req_is_nterror(req, &status)) {");
	$self->indent;
	$self->pidl("tevent_req_received(req);");
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("talloc_steal(mem_ctx, state->out_mem_ctx);");
	$self->pidl("");

	$self->pidl("tevent_req_received(req);");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_r_Sync($$$$)
{
	my ($self, $if, $fn, $name) = @_;
	my $uname = uc $name;

	if ($self->ParseFunctionHasPipes($fn)) {
		$self->pidl_both("/*");
		$self->pidl_both(" * The following function is skipped because");
		$self->pidl_both(" * it uses pipes:");
		$self->pidl_both(" *");
		$self->pidl_both(" * dcerpc_$name\_r()");
		$self->pidl_both(" */");
		$self->pidl_both("");
		return;
	}

	my $proto = "NTSTATUS dcerpc_$name\_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct $name *r)";

	$self->fn_declare($proto);

	$self->pidl("{");
	$self->indent;
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("status = dcerpc_binding_handle_call(h,");
	$self->pidl("\t\tNULL, &ndr_table_$if->{NAME},");
	$self->pidl("\t\tNDR_$uname, mem_ctx, r);");
	$self->pidl("");
	$self->pidl("return status;");

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
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

sub ParseCopyArgument($$$$$)
{
	my ($self, $fn, $e, $r, $i) = @_;
	my $l = $e->{LEVELS}[0];

	if ($l->{TYPE} eq "ARRAY" and $l->{IS_FIXED} == 1) {
		$self->pidl("memcpy(${r}$e->{NAME}, ${i}$e->{NAME}, sizeof(${r}$e->{NAME}));");
	} else {
		$self->pidl("${r}$e->{NAME} = ${i}$e->{NAME};");
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

sub ParseOutputArgument($$$$$$)
{
	my ($self, $fn, $e, $r, $o, $invalid_response_type) = @_;
	my $level = 0;

	if ($e->{LEVELS}[0]->{TYPE} ne "POINTER" and $e->{LEVELS}[0]->{TYPE} ne "ARRAY") {
		fatal($e->{ORIGINAL}, "[out] argument is not a pointer or array");
		return;
	}

	if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
		$level = 1;
		if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($o$e->{NAME} && ${r}out.$e->{NAME}) {");
			$self->indent;
		}
	}

	if ($e->{LEVELS}[$level]->{TYPE} eq "ARRAY") {
		# This is a call to GenerateFunctionInEnv intentionally.
		# Since the data is being copied into a user-provided data
		# structure, the user should be able to know the size beforehand
		# to allocate a structure of the right size.
		my $in_env = GenerateFunctionInEnv($fn, $r);
		my $out_env = GenerateFunctionOutEnv($fn, $r);
		my $l = $e->{LEVELS}[$level];

		my $in_var = undef;
		if (grep(/in/, @{$e->{DIRECTION}})) {
			$in_var = ParseExpr($e->{NAME}, $in_env, $e->{ORIGINAL});
		}
		my $out_var = ParseExpr($e->{NAME}, $out_env, $e->{ORIGINAL});

		my $in_size_is = undef;
		my $out_size_is = undef;
		my $out_length_is = undef;

		my $avail_len = undef;
		my $needed_len = undef;

		$self->pidl("{");
		$self->indent;
		my $copy_len_var = "_copy_len_$e->{NAME}";
		$self->pidl("size_t $copy_len_var;");

		if (not defined($l->{SIZE_IS})) {
			if (not $l->{IS_ZERO_TERMINATED}) {
				fatal($e->{ORIGINAL}, "no size known for [out] array `$e->{NAME}'");
			}
			if (has_property($e, "charset")) {
				$avail_len = "ndr_charset_length($in_var, CH_UNIX)";
				$needed_len = "ndr_charset_length($out_var, CH_UNIX)";
			} else {
				$avail_len = "ndr_string_length($in_var, sizeof(*$in_var))";
				$needed_len = "ndr_string_length($out_var, sizeof(*$out_var))";
			}
			$in_size_is = "";
			$out_size_is = "";
			$out_length_is = "";
		} else {
			$in_size_is = ParseExpr($l->{SIZE_IS}, $in_env, $e->{ORIGINAL});
			$out_size_is = ParseExpr($l->{SIZE_IS}, $out_env, $e->{ORIGINAL});
			$out_length_is = $out_size_is;
			if (defined($l->{LENGTH_IS})) {
				$out_length_is = ParseExpr($l->{LENGTH_IS}, $out_env, $e->{ORIGINAL});
			}
			if (has_property($e, "charset")) {
				if (defined($in_var)) {
					$avail_len = "ndr_charset_length($in_var, CH_UNIX)";
				} else {
					$avail_len = $out_length_is;
				}
				$needed_len = "ndr_charset_length($out_var, CH_UNIX)";
			}
		}

		if ($out_size_is ne $in_size_is) {
			$self->pidl("if (($out_size_is) > ($in_size_is)) {");
			$self->indent;
			$self->ParseInvalidResponse($invalid_response_type);
			$self->deindent;
			$self->pidl("}");
		}
		if ($out_length_is ne $out_size_is) {
			$self->pidl("if (($out_length_is) > ($out_size_is)) {");
			$self->indent;
			$self->ParseInvalidResponse($invalid_response_type);
			$self->deindent;
			$self->pidl("}");
		}
		if (defined($needed_len)) {
			$self->pidl("$copy_len_var = $needed_len;");
			$self->pidl("if ($copy_len_var > $avail_len) {");
			$self->indent;
			$self->ParseInvalidResponse($invalid_response_type);
			$self->deindent;
			$self->pidl("}");
		} else {
			$self->pidl("$copy_len_var = $out_length_is;");
		}

		if (has_property($e, "charset")) {
			$self->pidl("memcpy(discard_const_p(uint8_t *, $o$e->{NAME}), $out_var, $copy_len_var * sizeof(*$o$e->{NAME}));");
		} else {
			$self->pidl("memcpy($o$e->{NAME}, $out_var, $copy_len_var * sizeof(*$o$e->{NAME}));");
		}

		$self->deindent;
		$self->pidl("}");
	} else {
		$self->pidl("*$o$e->{NAME} = *${r}out.$e->{NAME};");
	}

	if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
		if ($e->{LEVELS}[0]->{POINTER_TYPE} ne "ref") {
			$self->deindent;
			$self->pidl("}");
		}
	}
}

sub ParseFunction_State($$$$)
{
	my ($self, $if, $fn, $name) = @_;

	my $state_str = "struct dcerpc_$name\_state";
	my $done_fn = "dcerpc_$name\_done";

	$self->pidl("$state_str {");
	$self->indent;
	$self->pidl("struct $name orig;");
	$self->pidl("struct $name tmp;");
	$self->pidl("TALLOC_CTX *out_mem_ctx;");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");
	$self->pidl("static void $done_fn(struct tevent_req *subreq);");
	$self->pidl("");
}

sub ParseFunction_Send($$$$)
{
	my ($self, $if, $fn, $name) = @_;

	my $fn_args = "";
	my $state_str = "struct dcerpc_$name\_state";
	my $done_fn = "dcerpc_$name\_done";
	my $out_mem_ctx = "dcerpc_$name\_out_memory";
	my $fn_str = "struct tevent_req *dcerpc_$name\_send";
	my $pad = genpad($fn_str);

	$fn_args .= "TALLOC_CTX *mem_ctx";
	$fn_args .= ",\n" . $pad . "struct tevent_context *ev";
	$fn_args .= ",\n" . $pad . "struct dcerpc_binding_handle *h";

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

	$self->pidl("/* In parameters */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));

		$self->ParseCopyArgument($fn, $e, "state->orig.in.", "_");
	}
	$self->pidl("");

	my $out_params = 0;
	$self->pidl("/* Out parameters */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless grep(/out/, @{$e->{DIRECTION}});

		$self->ParseCopyArgument($fn, $e, "state->orig.out.", "_");

		next if ContainsPipe($e, $e->{LEVELS}[0]);

		$out_params++;
	}
	$self->pidl("");

	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl("/* Result */");
		$self->pidl("ZERO_STRUCT(state->orig.out.result);");
		$self->pidl("");
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

	$self->pidl("/* make a temporary copy, that we pass to the dispatch function */");
	$self->pidl("state->tmp = state->orig;");
	$self->pidl("");

	$self->pidl("subreq = dcerpc_$name\_r_send(state, ev, h, &state->tmp);");
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

sub ParseFunction_Done($$$$)
{
	my ($self, $if, $fn, $name) = @_;

	my $state_str = "struct dcerpc_$name\_state";
	my $done_fn = "dcerpc_$name\_done";

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

	$self->pidl("status = dcerpc_$name\_r_recv(subreq, mem_ctx);");
	$self->pidl("TALLOC_FREE(subreq);");
	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("tevent_req_nterror(req, status);");
	$self->pidl("return;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("/* Copy out parameters */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next if ContainsPipe($e, $e->{LEVELS}[0]);
		next unless (grep(/out/, @{$e->{DIRECTION}}));

		$self->ParseOutputArgument($fn, $e,
					   "state->tmp.",
					   "state->orig.out.",
					   "async");
	}
	$self->pidl("");

	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl("/* Copy result */");
		$self->pidl("state->orig.out.result = state->tmp.out.result;");
		$self->pidl("");
	}

	$self->pidl("/* Reset temporary structure */");
	$self->pidl("ZERO_STRUCT(state->tmp);");
	$self->pidl("");

	$self->pidl("tevent_req_done(req);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_Recv($$$$)
{
	my ($self, $if, $fn, $name) = @_;

	my $fn_args = "";
	my $state_str = "struct dcerpc_$name\_state";
	my $fn_str = "NTSTATUS dcerpc_$name\_recv";
	my $pad = genpad($fn_str);

	$fn_args .= "struct tevent_req *req,\n" . $pad . "TALLOC_CTX *mem_ctx";

	if (defined($fn->{RETURN_TYPE})) {
		$fn_args .= ",\n" . $pad . mapTypeName($fn->{RETURN_TYPE}). " *result";
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
		$self->pidl("*result = state->orig.out.result;");
		$self->pidl("");
	}

	$self->pidl("tevent_req_received(req);");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub ParseFunction_Sync($$$$)
{
	my ($self, $if, $fn, $name) = @_;

	if ($self->ParseFunctionHasPipes($fn)) {
		$self->pidl_both("/*");
		$self->pidl_both(" * The following function is skipped because");
		$self->pidl_both(" * it uses pipes:");
		$self->pidl_both(" *");
		$self->pidl_both(" * dcerpc_$name()");
		$self->pidl_both(" */");
		$self->pidl_both("");
		return;
	}

	my $uname = uc $name;
	my $fn_args = "";
	my $fn_str = "NTSTATUS dcerpc_$name";
	my $pad = genpad($fn_str);

	$fn_args .= "struct dcerpc_binding_handle *h,\n" . $pad . "TALLOC_CTX *mem_ctx";

	foreach (@{$fn->{ELEMENTS}}) {
		my $dir = ElementDirection($_);
		my $prop = HeaderProperties($_->{PROPERTIES}, ["in", "out"]);
		$fn_args .= ",\n" . $pad . DeclLong($_, "_") . " /* $dir $prop */";
	}

	if (defined($fn->{RETURN_TYPE})) {
		$fn_args .= ",\n" . $pad . mapTypeName($fn->{RETURN_TYPE}). " *result";
	}

	$self->fn_declare("$fn_str($fn_args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("struct $name r;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	$self->pidl("/* In parameters */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));

		$self->ParseCopyArgument($fn, $e, "r.in.", "_");
	}
	$self->pidl("");

	$self->pidl("status = dcerpc_$name\_r(h, mem_ctx, &r);");
	$self->pidl("if (!NT_STATUS_IS_OK(status)) {");
	$self->indent;
	$self->pidl("return status;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("/* Return variables */");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next if ContainsPipe($e, $e->{LEVELS}[0]);
		next unless (grep(/out/, @{$e->{DIRECTION}}));

		$self->ParseOutputArgument($fn, $e, "r.", "_", "sync");
	}
	$self->pidl("");

	$self->pidl("/* Return result */");
	if ($fn->{RETURN_TYPE}) {
		$self->pidl("*result = r.out.result;");
	}
	$self->pidl("");

	$self->pidl("return NT_STATUS_OK;");

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

#####################################################################
# parse a function
sub ParseFunction($$$)
{
	my ($self, $if, $fn) = @_;

	if ($self->ParseFunctionHasPipes($fn)) {
		$self->pidl_both("/*");
		$self->pidl_both(" * The following function is skipped because");
		$self->pidl_both(" * it uses pipes:");
		$self->pidl_both(" *");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_r_send()");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_r_recv()");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_r()");
		$self->pidl_both(" *");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_send()");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_recv()");
		$self->pidl_both(" * dcerpc_$fn->{NAME}()");
		$self->pidl_both(" */");
		$self->pidl_both("");
		warning($fn->{ORIGINAL}, "$fn->{NAME}: dcerpc client does not support pipe yet");
		return;
	}

	$self->ParseFunction_r_State($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Send($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Done($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Recv($if, $fn, $fn->{NAME});
	$self->ParseFunction_r_Sync($if, $fn, $fn->{NAME});

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));

		my $reason = "is not a pointer or array";

		# TODO: make this fatal at NDR level
		if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
			if ($e->{LEVELS}[1]->{TYPE} eq "DATA" and
			    $e->{LEVELS}[1]->{DATA_TYPE} eq "string") {
				$reason = "is a pointer to type 'string'";
			} elsif ($e->{LEVELS}[1]->{TYPE} eq "ARRAY" and
				 $e->{LEVELS}[1]->{IS_ZERO_TERMINATED}) {
				next;
			} elsif ($e->{LEVELS}[1]->{TYPE} eq "ARRAY" and
				 not defined($e->{LEVELS}[1]->{SIZE_IS})) {
				$reason = "is a pointer to an unsized array";
			} else {
				next;
			}
		}
		if ($e->{LEVELS}[0]->{TYPE} eq "ARRAY") {
			if (not defined($e->{LEVELS}[0]->{SIZE_IS})) {
				$reason = "is an unsized array";
			} else {
				next;
			}
		}

		$self->pidl_both("/*");
		$self->pidl_both(" * The following functions are skipped because");
		$self->pidl_both(" * an [out] argument $e->{NAME} $reason:");
		$self->pidl_both(" *");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_send()");
		$self->pidl_both(" * dcerpc_$fn->{NAME}_recv()");
		$self->pidl_both(" * dcerpc_$fn->{NAME}()");
		$self->pidl_both(" */");
		$self->pidl_both("");

		error($e->{ORIGINAL}, "$fn->{NAME}: [out] argument '$e->{NAME}' $reason, skip client functions");
		return;
	}

	$self->ParseFunction_State($if, $fn, $fn->{NAME});
	$self->ParseFunction_Send($if, $fn, $fn->{NAME});
	$self->ParseFunction_Done($if, $fn, $fn->{NAME});
	$self->ParseFunction_Recv($if, $fn, $fn->{NAME});
	$self->ParseFunction_Sync($if, $fn, $fn->{NAME});

	$self->pidl_hdr("");
}

my %done;

#####################################################################
# parse the interface definitions
sub ParseInterface($$)
{
	my ($self, $if) = @_;
	my $ifu = uc($if->{NAME});

	$self->pidl_hdr("#ifndef _HEADER_RPC_$if->{NAME}");
	$self->pidl_hdr("#define _HEADER_RPC_$if->{NAME}");
	$self->pidl_hdr("");

	if (defined $if->{PROPERTIES}->{uuid}) {
		$self->pidl_hdr("extern const struct ndr_interface_table ndr_table_$if->{NAME};");
		$self->pidl_hdr("");
	}

	$self->pidl("/* $if->{NAME} - client functions generated by pidl */");
	$self->pidl("");

	foreach my $fn (@{$if->{FUNCTIONS}}) {
		next if defined($done{$fn->{NAME}});
		next if has_property($fn, "noopnum");
		next if has_property($fn, "todo");
		$self->ParseFunction($if, $fn);
		$done{$fn->{NAME}} = 1;
	}

	$self->pidl_hdr("#endif /* _HEADER_RPC_$if->{NAME} */");
}

sub Parse($$$$$$)
{
	my($self,$ndr,$header,$ndr_header,$client_header) = @_;

	$self->pidl("/* client functions auto-generated by pidl */");
	$self->pidl("");
	if (is_intree()) {
		$self->pidl("#include \"includes.h\"");
	} else {
		$self->pidl("#ifndef _GNU_SOURCE");
		$self->pidl("#define _GNU_SOURCE");
		$self->pidl("#endif");
		$self->pidl("#include <stdio.h>");
		$self->pidl("#include <stdbool.h>");
		$self->pidl("#include <stdlib.h>");
		$self->pidl("#include <stdint.h>");
		$self->pidl("#include <stdarg.h>");
		$self->pidl("#include <string.h>");
		$self->pidl("#include <core/ntstatus.h>");
	}
	$self->pidl("#include <tevent.h>");
	$self->pidl(choose_header("lib/util/tevent_ntstatus.h", "util/tevent_ntstatus.h")."");
	$self->pidl("#include \"$ndr_header\"");
	$self->pidl("#include \"$client_header\"");
	$self->pidl("");

	$self->pidl_hdr(choose_header("librpc/rpc/dcerpc.h", "dcerpc.h")."");
	$self->pidl_hdr("#include \"$header\"");

	foreach my $x (@{$ndr}) {
		($x->{TYPE} eq "INTERFACE") && $self->ParseInterface($x);
	}

	return ($self->{res},$self->{res_hdr});
}

1;
