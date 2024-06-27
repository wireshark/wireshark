###################################################
# server boilerplate generator
# Copyright tridge@samba.org 2003
# Copyright metze@samba.org 2004
# Copyright scabrero@samba.org 2019
# released under the GNU GPL

package Parse::Pidl::Samba4::NDR::ServerCompat;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(Parse);

use Parse::Pidl::Util qw(print_uuid has_property ParseExpr);
use Parse::Pidl::Typelist qw(mapTypeName);
use Parse::Pidl qw(error fatal);
use Parse::Pidl::NDR qw(ContainsPipe GetNextLevel);
use Parse::Pidl::Samba4 qw(ElementStars);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionOutEnv);

use vars qw($VERSION);
$VERSION = '1.0';

use strict;

sub indent($) { my ($self) = @_; $self->{tabs}.="\t"; }
sub deindent($) { my ($self) = @_; $self->{tabs} = substr($self->{tabs}, 1); }
sub pidl($$) { my ($self,$txt) = @_; $self->{res} .= $txt ? "$self->{tabs}$txt\n" : "\n"; }
sub pidlnoindent($$) { my ($self,$txt) = @_; $self->{res} .= $txt ? "$txt\n" : "\n"; }
sub pidl_hdr($$) { my ($self, $txt) = @_; $self->{res_hdr} .= "$txt\n"; }
sub pidl_both($$) { my ($self, $txt) = @_; $self->{hdr} .= "$txt\n"; $self->{res_hdr} .= "$txt\n"; }

sub new($)
{
	my ($class) = shift;
	my $self = { res => "", res_hdr => "", tabs => "" };
	bless($self, $class);
}

sub decl_level($$)
{
	my ($self, $e, $l) = @_;
	my $res = "";

	if (has_property($e, "charset")) {
		$res .= "const char";
	} else {
		$res .= mapTypeName($e->{TYPE});
	}

	my $stars = ElementStars($e, $l);

	$res .= " ".$stars unless ($stars eq "");

	return $res;
}

sub alloc_out_var($$$$$)
{
	my ($self, $e, $mem_ctx, $name, $env, $alloc_error_block) = @_;

	my $l = $e->{LEVELS}[0];

	# we skip pointer to arrays
	if ($l->{TYPE} eq "POINTER") {
		my $nl = GetNextLevel($e, $l);
		$l = $nl if ($nl->{TYPE} eq "ARRAY");
	} elsif

	# we don't support multi-dimensional arrays yet
	($l->{TYPE} eq "ARRAY") {
		my $nl = GetNextLevel($e, $l);
		if ($nl->{TYPE} eq "ARRAY") {
			fatal($e->{ORIGINAL},"multi-dimensional [out] arrays are not supported!");
		}
	} else {
		# neither pointer nor array, no need to alloc something.
		return;
	}

	if ($l->{TYPE} eq "ARRAY") {
		unless(defined($l->{SIZE_IS})) {
			error($e->{ORIGINAL}, "No size known for array `$e->{NAME}'");
			$self->pidl("#error No size known for array `$e->{NAME}'");
		} else {
			my $size = ParseExpr($l->{SIZE_IS}, $env, $e);
			$self->pidl("$name = talloc_zero_array($mem_ctx, " . $self->decl_level($e, 1) . ", $size);");
		}
	} else {
		$self->pidl("$name = talloc_zero($mem_ctx, " . $self->decl_level($e, 1) . ");");
	}

	$self->pidl("if ($name == NULL) {");
	$self->indent();
	foreach (@{$alloc_error_block}) {
		$self->pidl($_);
	}
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
}

sub gen_fn_out($$)
{
	my ($self, $fn, $alloc_error_block) = @_;

	my $hasout = 0;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/, @{$_->{DIRECTION}})) {
			$hasout = 1;
		}
	}

	if ($hasout) {
		$self->pidl("NDR_ZERO_STRUCT(r2->out);");
	}

	foreach (@{$fn->{ELEMENTS}}) {
		my @dir = @{$_->{DIRECTION}};
		if (grep(/in/, @dir) and grep(/out/, @dir)) {
			$self->pidl("r2->out.$_->{NAME} = r2->in.$_->{NAME};");
		}
	}

	foreach (@{$fn->{ELEMENTS}}) {
		next if ContainsPipe($_, $_->{LEVELS}[0]);

		my @dir = @{$_->{DIRECTION}};

		if (grep(/in/, @dir) and grep(/out/, @dir)) {
			# noop
		} elsif (grep(/out/, @dir) and not has_property($_, "represent_as")) {
			my $env = GenerateFunctionOutEnv($fn, "r2->");
			$self->alloc_out_var($_, "r2", "r2->out.$_->{NAME}", $env, $alloc_error_block);
		}

	}
}

#####################################################
# generate the switch statement for function dispatch
sub gen_dispatch_switch($)
{
	my ($self, $interface) = @_;

	my @alloc_error_block = ("status = NT_STATUS_NO_MEMORY;",
				 "p->fault_state = DCERPC_FAULT_CANT_PERFORM;",
				 "goto fail;");
	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		next if not defined($fn->{OPNUM});

		my $fname = $fn->{NAME};
		my $ufname = uc($fname);

		$self->pidl("case $fn->{OPNUM}: { /* $fn->{NAME} */");
		$self->indent();
		$self->pidl("struct $fname *r2 = (struct $fname *)r;");
		$self->pidl("if (DEBUGLEVEL >= 10) {");
		$self->indent();
		$self->pidl("NDR_PRINT_FUNCTION_DEBUG($fname, NDR_IN, r2);");
		$self->deindent();
		$self->pidl("}");

		$self->gen_fn_out($fn, \@alloc_error_block);

		$self->pidl_hdr("struct $fname;");

		if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
			$self->pidl_hdr(mapTypeName($fn->{RETURN_TYPE}) . " _$fname(struct pipes_struct *p, struct $fname *r);");
			$self->pidl("r2->out.result = _$fname(p, r2);");
		} else {
			$self->pidl_hdr("void _$fname(struct pipes_struct *p, struct $fname *r);");
			$self->pidl("_$fname(p, r2);");
		}

		$self->pidl("break;");
		$self->deindent();
		$self->pidl("}");
	}
}

#####################################################
# generate the switch statement for function reply
sub gen_reply_switch($)
{
	my ($self, $interface) = @_;

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		next if not defined($fn->{OPNUM});

		$self->pidl("case $fn->{OPNUM}: { /* $fn->{NAME} */");
		$self->indent();
		$self->pidl("struct $fn->{NAME} *r2 = (struct $fn->{NAME} *)r;");
		$self->pidl("if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {");
		$self->indent();
		$self->pidl("DEBUG(5,(\"function $fn->{NAME} replied async\\n\"));");
		$self->deindent();
		$self->pidl("}");
		$self->pidl("if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {");
		$self->indent();
		$self->pidl("NDR_PRINT_FUNCTION_DEBUG($fn->{NAME}, NDR_OUT | NDR_SET_VALUES, r2);");
		$self->deindent();
		$self->pidl("}");
		$self->pidl("if (dce_call->fault_code != 0) {");
		$self->indent();
		$self->pidl("DBG_WARNING(\"dcerpc_fault %s in $fn->{NAME}\\n\", dcerpc_errstr(mem_ctx, dce_call->fault_code));");
		$self->deindent();
		$self->pidl("}");
		$self->pidl("break;");
		$self->deindent();
		$self->pidl("}");
	}
}

#####################################################################
# produce boilerplate code for a interface
sub boilerplate_iface($)
{
	my ($self, $interface) = @_;

	my $name = $interface->{NAME};
	my $uname = uc $name;
	my $uuid = lc($interface->{UUID});
	my $if_version = $interface->{VERSION};

	$self->pidl("static NTSTATUS $name\__op_bind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)");
	$self->pidl("{");
	$self->indent();
	$self->pidlnoindent("#ifdef DCESRV_INTERFACE_$uname\_BIND");
	$self->pidl("return DCESRV_INTERFACE_$uname\_BIND(context,iface);");
	$self->pidlnoindent("#else");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent();
	$self->pidl("#endif");
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static void $name\__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)");
	$self->pidl("{");
	$self->pidlnoindent("#ifdef DCESRV_INTERFACE_$uname\_UNBIND");
	$self->indent();
	$self->pidl("DCESRV_INTERFACE_$uname\_UNBIND(context, iface);");
	$self->pidlnoindent("#else");
	$self->pidl("return;");
	$self->pidlnoindent("#endif");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl_hdr("NTSTATUS $name\__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r);");
	$self->pidl("NTSTATUS $name\__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("enum ndr_err_code ndr_err;");
	$self->pidl("uint16_t opnum = dce_call->pkt.u.request.opnum;");
	$self->pidl("");
	$self->pidl("dce_call->fault_code = 0;");
	$self->pidl("");
	$self->pidl("if (opnum >= ndr_table_$name.num_calls) {");
	$self->indent();
	$self->pidl("dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;");
	$self->pidl("return NT_STATUS_NET_WRITE_FAULT;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("*r = talloc_named(mem_ctx, ndr_table_$name.calls[opnum].struct_size, \"struct %s\", ndr_table_$name.calls[opnum].name);");
	$self->pidl("NT_STATUS_HAVE_NO_MEMORY(*r);");
	$self->pidl("");
	$self->pidl("/* unravel the NDR for the packet */");
	$self->pidl("ndr_err = ndr_table_$name.calls[opnum].ndr_pull(pull, NDR_IN, *r);");
	$self->pidl("if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {");
	$self->indent();
	$self->pidl("dce_call->fault_code = DCERPC_FAULT_NDR;");
	$self->pidl("return NT_STATUS_NET_WRITE_FAULT;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static NTSTATUS $name\__op_dispatch_internal(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r, enum s3compat_rpc_dispatch dispatch)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("uint16_t opnum = dce_call->pkt.u.request.opnum;");
	$self->pidl("struct pipes_struct *p = NULL;");
	$self->pidl("NTSTATUS status = NT_STATUS_OK;");
	$self->pidl("bool impersonated = false;");
	$self->pidl("");
	$self->pidl("/* Retrieve pipes struct */");
	$self->pidl("p = dcesrv_get_pipes_struct(dce_call->conn);");
	$self->pidl("p->dce_call = dce_call;");
	$self->pidl("p->mem_ctx = mem_ctx;");
	$self->pidl("/* Reset pipes struct fault state */");
	$self->pidl("p->fault_state = 0;");
	$self->pidl("");

	$self->pidl("/* Impersonate */");
	$self->pidl("if (dispatch == S3COMPAT_RPC_DISPATCH_EXTERNAL) {");
	$self->indent();
	$self->pidl("impersonated = become_authenticated_pipe_user(dce_call->auth_state->session_info);");
	$self->pidl("if (!impersonated) {");
	$self->indent();
	$self->pidl("dce_call->fault_code = DCERPC_FAULT_ACCESS_DENIED;");
	$self->pidl("status = NT_STATUS_NET_WRITE_FAULT;");
	$self->pidl("goto fail;");
	$self->deindent();
	$self->pidl("}");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("switch (opnum) {");
	$self->gen_dispatch_switch($interface);
	$self->pidl("default:");
	$self->indent();
	$self->pidl("dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;");
	$self->pidl("break;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidlnoindent("fail:");
	$self->pidl("/* Unimpersonate */");
	$self->pidl("if (impersonated) {");
	$self->indent();
	$self->pidl("unbecome_authenticated_pipe_user();");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("p->dce_call = NULL;");
	$self->pidl("p->mem_ctx = NULL;");
	$self->pidl("/* Check pipes struct fault state */");
	$self->pidl("if (p->fault_state != 0) {");
	$self->indent();
	$self->pidl("dce_call->fault_code = p->fault_state;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("if (dce_call->fault_code != 0) {");
	$self->indent();
	$self->pidl("status = NT_STATUS_NET_WRITE_FAULT;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("return status;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl_hdr("NTSTATUS $name\__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r);");
	$self->pidl("NTSTATUS $name\__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("return $name\__op_dispatch_internal(dce_call, mem_ctx, r, S3COMPAT_RPC_DISPATCH_EXTERNAL);");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl_hdr("NTSTATUS $name\__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r);");
	$self->pidl("NTSTATUS $name\__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("uint16_t opnum = dce_call->pkt.u.request.opnum;");
	$self->pidl("");
	$self->pidl("switch (opnum) {");
	$self->gen_reply_switch($interface);
	$self->pidl("default:");
	$self->indent();
	$self->pidl("dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;");
	$self->pidl("break;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("if (dce_call->fault_code != 0) {");
	$self->indent();
	$self->pidl("return NT_STATUS_NET_WRITE_FAULT;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl_hdr("NTSTATUS $name\__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r);");
	$self->pidl("NTSTATUS $name\__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("enum ndr_err_code ndr_err;");
	$self->pidl("uint16_t opnum = dce_call->pkt.u.request.opnum;");
	$self->pidl("");
	$self->pidl("ndr_err = ndr_table_$name.calls[opnum].ndr_push(push, NDR_OUT, r);");
	$self->pidl("if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {");
	$self->indent();
	$self->pidl("dce_call->fault_code = DCERPC_FAULT_NDR;");
	$self->pidl("return NT_STATUS_NET_WRITE_FAULT;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	##############################
	####    LOCAL DISPATCH    ####
	##############################
	$self->pidl_hdr("NTSTATUS $name\__op_local(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r);");
	$self->pidl("NTSTATUS $name\__op_local(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("return $name\__op_dispatch_internal(dce_call, mem_ctx, r, S3COMPAT_RPC_DISPATCH_INTERNAL);");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static const struct dcesrv_interface dcesrv\_$name\_interface = {");
	$self->indent();
	$self->pidl(".name      = \"$name\",");
	$self->pidl(".syntax_id = {".print_uuid($uuid).",$if_version},");
	$self->pidl(".bind      = $name\__op_bind,");
	$self->pidl(".unbind    = $name\__op_unbind,");
	$self->pidl(".ndr_pull  = $name\__op_ndr_pull,");
	$self->pidl(".dispatch  = $name\__op_dispatch,");
	$self->pidl(".reply     = $name\__op_reply,");
	$self->pidl(".ndr_push  = $name\__op_ndr_push,");
	$self->pidl(".local     = $name\__op_local,");
	$self->pidlnoindent("#ifdef DCESRV_INTERFACE_$uname\_FLAGS");
	$self->pidl(".flags     = DCESRV_INTERFACE_$uname\_FLAGS");
	$self->pidlnoindent("#else");
	$self->pidl(".flags     = 0");
	$self->pidlnoindent("#endif");
	$self->deindent();
	$self->pidl("};");
	$self->pidl("");
}

#####################################################################
# produce boilerplate code for an endpoint server
sub boilerplate_ep_server($)
{
	my ($self, $interface) = @_;
	my $name = $interface->{NAME};
	my $uname = uc $name;

	$self->pidl("static NTSTATUS $name\__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("uint32_t i;");
	$self->pidl("NTSTATUS ret;");
	$self->pidl("");
	$self->pidlnoindent("#ifdef DCESRV_INTERFACE_$uname\_NCACN_NP_SECONDARY_ENDPOINT");
	$self->pidl("const char *ncacn_np_secondary_endpoint = DCESRV_INTERFACE_$uname\_NCACN_NP_SECONDARY_ENDPOINT;");
	$self->pidlnoindent("#else");
	$self->pidl("const char *ncacn_np_secondary_endpoint = NULL;");
	$self->pidlnoindent("#endif");
	$self->pidl("");
	$self->pidl("for (i=0;i<ndr_table_$name.endpoints->count;i++) {");
	$self->indent();
	$self->pidl("const char *name = ndr_table_$name.endpoints->names[i];");
	$self->pidl("");
	$self->pidl("ret = dcesrv_interface_register(dce_ctx, name, ncacn_np_secondary_endpoint, &dcesrv_$name\_interface, NULL);");
	$self->pidl("if (!NT_STATUS_IS_OK(ret)) {");
	$self->indent();
	$self->pidl("DBG_ERR(\"Failed to register endpoint \'%s\'\\n\",name);");
	$self->pidl("return ret;");
	$self->deindent();
	$self->pidl("}");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static NTSTATUS $name\__op_shutdown_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static bool $name\__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("if (dcesrv_$name\_interface.syntax_id.if_version == if_version && GUID_equal(\&dcesrv\_$name\_interface.syntax_id.uuid, uuid)) {");
	$self->indent();
	$self->pidl("memcpy(iface,&dcesrv\_$name\_interface, sizeof(*iface));");
	$self->pidl("return true;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return false;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static bool $name\__op_interface_by_name(struct dcesrv_interface *iface, const char *name)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("if (strcmp(dcesrv_$name\_interface.name, name)==0) {");
	$self->indent();
	$self->pidl("memcpy(iface, &dcesrv_$name\_interface, sizeof(*iface));");
	$self->pidl("return true;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return false;");
	$self->deindent();
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static const struct dcesrv_endpoint_server $name\_ep_server = {");
	$self->indent();
	$self->pidl("/* fill in our name */");
	$self->pidl(".name = \"$name\",");
	$self->pidl("");
	$self->pidl("/* Initialization flag */");
	$self->pidl(".initialized = false,");
	$self->pidl("");
	$self->pidl("/* fill in all the operations */");
	$self->pidlnoindent("#ifdef DCESRV_INTERFACE_$uname\_INIT_SERVER");
	$self->pidl(".init_server = DCESRV_INTERFACE_$uname\_INIT_SERVER,");
	$self->pidlnoindent("#else");
	$self->pidl(".init_server = $name\__op_init_server,");
	$self->pidlnoindent("#endif");
	$self->pidlnoindent("#ifdef DCESRV_INTERFACE_$uname\_SHUTDOWN_SERVER");
	$self->pidl(".shutdown_server = DCESRV_INTERFACE_$uname\_SHUTDOWN_SERVER,");
	$self->pidlnoindent("#else");
	$self->pidl(".shutdown_server = $name\__op_shutdown_server,");
	$self->pidlnoindent("#endif");
	$self->pidl(".interface_by_uuid = $name\__op_interface_by_uuid,");
	$self->pidl(".interface_by_name = $name\__op_interface_by_name");
	$self->deindent();
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("const struct dcesrv_endpoint_server *$name\_get_ep_server(void)");
	$self->pidl("{");
	$self->indent();
	$self->pidl("return &$name\_ep_server;");
	$self->deindent();
	$self->pidl("}");
}

#####################################################################
# dcerpc server boilerplate from a parsed IDL structure
sub parse_interface($)
{
	my ($self, $interface) = @_;
	my $count = 0;
	my $uif = uc($interface->{NAME});


	$self->pidl_hdr("#ifndef __NDR_${uif}_SCOMPAT_H__");
	$self->pidl_hdr("#define __NDR_${uif}_SCOMPAT_H__");
	$self->pidl_hdr("");
	$self->pidl_hdr("struct pipes_struct;");
	$self->pidl_hdr("struct dcesrv_endpoint_server;");
	$self->pidl_hdr("struct dcesrv_call_state;");
	$self->pidl_hdr("");
	$self->pidl_hdr("const struct dcesrv_endpoint_server *$interface->{NAME}\_get_ep_server(void);");
	$self->pidl_hdr("");

	if (!defined $interface->{PROPERTIES}->{uuid}) {
		$self->pidl_hdr("#endif /* __NDR_${uif}_SCOMPAT_H__ */");
		return;
	}

	if (!defined $interface->{PROPERTIES}->{version}) {
		$interface->{PROPERTIES}->{version} = "0.0";
	}

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		if (defined($fn->{OPNUM})) { $count++; }
	}

	if ($count == 0) {
		$self->pidl_hdr("#endif /* __NDR_${uif}_SCOMPAT_H__ */");
		return;
	}

	$self->pidl("/* $interface->{NAME} - dcerpc server boilerplate generated by pidl */");
	$self->boilerplate_iface($interface);
	$self->boilerplate_ep_server($interface);

	$self->pidl_hdr("#endif /* __NDR_${uif}_SCOMPAT_H__ */");
}

sub Parse($$)
{
	my ($self, $ndr, $h_scompat, $header) = @_;

	$self->pidl("/* s3 compat server functions auto-generated by pidl */");
	$self->pidl("#include \"$header\"");
	$self->pidl("#include \"$h_scompat\"");

	$self->pidl("#include <librpc/rpc/dcesrv_core.h>");
	$self->pidl("#include <rpc_server/rpc_config.h>");
	$self->pidl("#include <rpc_server/rpc_server.h>");
	$self->pidl("#include <util/debug.h>");
	$self->pidl("");
	$self->pidl("enum s3compat_rpc_dispatch {");
	$self->indent();
	$self->pidl("S3COMPAT_RPC_DISPATCH_EXTERNAL = 0x00000001,");
	$self->pidl("S3COMPAT_RPC_DISPATCH_INTERNAL = 0x00000002,");
	$self->deindent();
	$self->pidl("};");
	$self->pidl("");

	foreach my $x (@{$ndr}) {
		$self->parse_interface($x) if ($x->{TYPE} eq "INTERFACE" and not defined($x->{PROPERTIES}{object}));
	}

	return ($self->{res}, $self->{res_hdr});
}

1;
