###################################################
# server boilerplate generator
# Copyright tridge@samba.org 2003
# Copyright metze@samba.org 2004
# released under the GNU GPL

package Parse::Pidl::Samba4::NDR::Server;

use strict;
use Parse::Pidl::Util;

use vars qw($VERSION);
$VERSION = '0.01';

my($res);

sub pidl($)
{
	$res .= shift;
}


#####################################################
# generate the switch statement for function dispatch
sub gen_dispatch_switch($)
{
	my $interface = shift;

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		next if not defined($fn->{OPNUM});

		pidl "\tcase $fn->{OPNUM}: {\n";
		pidl "\t\tstruct $fn->{NAME} *r2 = (struct $fn->{NAME} *)r;\n";
		pidl "\t\tif (DEBUGLEVEL >= 10) {\n";
		pidl "\t\t\tNDR_PRINT_FUNCTION_DEBUG($fn->{NAME}, NDR_IN, r2);\n";
		pidl "\t\t}\n";
		if ($fn->{RETURN_TYPE} && $fn->{RETURN_TYPE} ne "void") {
			pidl "\t\tr2->out.result = dcesrv_$fn->{NAME}(dce_call, mem_ctx, r2);\n";
		} else {
			pidl "\t\tdcesrv_$fn->{NAME}(dce_call, mem_ctx, r2);\n";
		}
		pidl "\t\tif (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {\n";
		pidl "\t\t\tDEBUG(5,(\"function $fn->{NAME} will reply async\\n\"));\n";
		pidl "\t\t}\n";
		pidl "\t\tbreak;\n\t}\n";
	}
}

#####################################################
# generate the switch statement for function reply
sub gen_reply_switch($)
{
	my $interface = shift;

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		next if not defined($fn->{OPNUM});

		pidl "\tcase $fn->{OPNUM}: {\n";
		pidl "\t\tstruct $fn->{NAME} *r2 = (struct $fn->{NAME} *)r;\n";
		pidl "\t\tif (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {\n";
		pidl "\t\t\tDEBUG(5,(\"function $fn->{NAME} replied async\\n\"));\n";
		pidl "\t\t}\n";
		pidl "\t\tif (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {\n";
		pidl "\t\t\tNDR_PRINT_FUNCTION_DEBUG($fn->{NAME}, NDR_OUT | NDR_SET_VALUES, r2);\n";
		pidl "\t\t}\n";
		pidl "\t\tif (dce_call->fault_code != 0) {\n";
		pidl "\t\t\tDEBUG(2,(\"dcerpc_fault %s in $fn->{NAME}\\n\", dcerpc_errstr(mem_ctx, dce_call->fault_code)));\n";
		pidl "\t\t}\n";
		pidl "\t\tbreak;\n\t}\n";
	}
}

#####################################################################
# produce boilerplate code for a interface
sub Boilerplate_Iface($)
{
	my($interface) = shift;
	my $name = $interface->{NAME}; 
	my $uname = uc $name;
	my $uuid = lc($interface->{PROPERTIES}->{uuid});
	my $if_version = $interface->{PROPERTIES}->{version};

	pidl "
static NTSTATUS $name\__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_$uname\_BIND
	return DCESRV_INTERFACE_$uname\_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void $name\__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_$uname\_UNBIND
	DCESRV_INTERFACE_$uname\_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS $name\__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_$name.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_$name.calls[opnum].struct_size,
			  \"struct %s\",
			  ndr_table_$name.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_$name.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_$name, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
";
	gen_dispatch_switch($interface);

pidl "
	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_$name, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
";
	gen_reply_switch($interface);

pidl "
	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_$name, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_$name.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

const struct dcesrv_interface dcesrv\_$name\_interface = {
	.name		= \"$name\",
	.syntax_id  = {".print_uuid($uuid).",$if_version},
	.bind		= $name\__op_bind,
	.unbind		= $name\__op_unbind,
	.ndr_pull	= $name\__op_ndr_pull,
	.dispatch	= $name\__op_dispatch,
	.reply		= $name\__op_reply,
	.ndr_push	= $name\__op_ndr_push
};

";
}

#####################################################################
# produce boilerplate code for an endpoint server
sub Boilerplate_Ep_Server($)
{
	my($interface) = shift;
	my $name = $interface->{NAME};
	my $uname = uc $name;

	pidl "
static NTSTATUS $name\__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_$name.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_$name.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_$name\_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,(\"$name\_op_init_server: failed to register endpoint \'%s\'\\n\",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool $name\__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_$name\_interface.syntax_id.if_version == if_version &&
		GUID_equal(\&dcesrv\_$name\_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv\_$name\_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool $name\__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_$name\_interface.name, name)==0) {
		memcpy(iface, &dcesrv_$name\_interface, sizeof(*iface));
		return true;
	}

	return false;	
}
	
NTSTATUS dcerpc_server_$name\_init(void)
{
	NTSTATUS ret;
	struct dcesrv_endpoint_server ep_server;

	/* fill in our name */
	ep_server.name = \"$name\";

	/* fill in all the operations */
	ep_server.init_server = $name\__op_init_server;

	ep_server.interface_by_uuid = $name\__op_interface_by_uuid;
	ep_server.interface_by_name = $name\__op_interface_by_name;

	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,(\"Failed to register \'$name\' endpoint server!\\n\"));
		return ret;
	}

	return ret;
}

";
}

#####################################################################
# dcerpc server boilerplate from a parsed IDL structure 
sub ParseInterface($)
{
	my($interface) = shift;
	my $count = 0;

	if (!defined $interface->{PROPERTIES}->{uuid}) {
		return $res;
	}

	if (!defined $interface->{PROPERTIES}->{version}) {
		$interface->{PROPERTIES}->{version} = "0.0";
	}

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		if (defined($fn->{OPNUM})) { $count++; }
	}

	if ($count == 0) {
		return $res;
	}

	$res .= "/* $interface->{NAME} - dcerpc server boilerplate generated by pidl */\n\n";
	Boilerplate_Iface($interface);
	Boilerplate_Ep_Server($interface);

	return $res;
}

sub Parse($$)
{
	my($ndr,$header) = @_;

	$res =  "";
	$res .= "/* server functions auto-generated by pidl */\n";
	$res .= "#include \"$header\"\n";
	$res .= "\n";

	foreach my $x (@{$ndr}) {
		ParseInterface($x) if ($x->{TYPE} eq "INTERFACE" and not defined($x->{PROPERTIES}{object}));
	}

	return $res;
}

1;
