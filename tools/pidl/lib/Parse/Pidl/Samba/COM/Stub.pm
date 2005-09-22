###################################################
# DCOM stub boilerplate generator
# Copyright jelmer@samba.org 2004-2005
# Copyright tridge@samba.org 2003
# Copyright metze@samba.org 2004
# released under the GNU GPL

package Parse::Pidl::Samba::COM::Stub;

use Parse::Pidl::Util qw(has_property);
use strict;

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
	my $data = shift;

	my $count = 0;
	foreach my $d (@{$data}) {
		next if ($d->{TYPE} ne "FUNCTION");

		pidl "\tcase $count: {\n";
		if ($d->{RETURN_TYPE} && $d->{RETURN_TYPE} ne "void") {
			pidl "\t\tNTSTATUS result;\n";
		}
		pidl "\t\tstruct $d->{NAME} *r2 = r;\n";
		pidl "\t\tif (DEBUGLEVEL > 10) {\n";
		pidl "\t\t\tNDR_PRINT_FUNCTION_DEBUG($d->{NAME}, NDR_IN, r2);\n";
		pidl "\t\t}\n";
		if ($d->{RETURN_TYPE} && $d->{RETURN_TYPE} ne "void") {
			pidl "\t\tresult = vtable->$d->{NAME}(iface, mem_ctx, r2);\n";
		} else {
			pidl "\t\tvtable->$d->{NAME}(iface, mem_ctx, r2);\n";
		}
		pidl "\t\tif (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {\n";
		pidl "\t\t\tDEBUG(5,(\"function $d->{NAME} will reply async\\n\"));\n";
		pidl "\t\t}\n";
		pidl "\t\tbreak;\n\t}\n";
		$count++; 
	}
}

#####################################################
# generate the switch statement for function reply
sub gen_reply_switch($)
{
	my $data = shift;

	my $count = 0;
	foreach my $d (@{$data}) {
		next if ($d->{TYPE} ne "FUNCTION");

		pidl "\tcase $count: {\n";
		pidl "\t\tstruct $d->{NAME} *r2 = r;\n";
		pidl "\t\tif (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {\n";
		pidl "\t\t\tDEBUG(5,(\"function $d->{NAME} replied async\\n\"));\n";
		pidl "\t\t}\n";
		pidl "\t\tif (DEBUGLEVEL > 10 && dce_call->fault_code == 0) {\n";
		pidl "\t\t\tNDR_PRINT_FUNCTION_DEBUG($d->{NAME}, NDR_OUT | NDR_SET_VALUES, r2);\n";
		pidl "\t\t}\n";
		pidl "\t\tif (dce_call->fault_code != 0) {\n";
		pidl "\t\t\tDEBUG(2,(\"dcerpc_fault %s in $d->{NAME}\\n\", dcerpc_errstr(mem_ctx, dce_call->fault_code)));\n";
		pidl "\t\t}\n";
		pidl "\t\tbreak;\n\t}\n";
		$count++; 
	}
}

#####################################################################
# produce boilerplate code for a interface
sub Boilerplate_Iface($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $name = $interface->{NAME};
	my $uname = uc $name;
	my $uuid = Parse::Pidl::Util::make_str($interface->{PROPERTIES}->{uuid});
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
	NTSTATUS status;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= dcerpc_table_$name.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_size(mem_ctx, dcerpc_table_$name.calls[opnum].struct_size);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	status = dcerpc_table_$name.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_log_packet(&dcerpc_table_$name, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;
	struct GUID ipid = dce_call->pkt.u.request.object.object;
	struct dcom_interface_p *iface = dcom_get_local_iface_p(&ipid);
	const struct dcom_$name\_vtable *vtable = iface->vtable;

	switch (opnum) {
";
	gen_dispatch_switch($data);

pidl "
	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(&dcerpc_table_$name, opnum, NDR_IN,
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
	gen_reply_switch($data);

pidl "
	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(&dcerpc_table_$name, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS $name\__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	NTSTATUS status;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	status = dcerpc_table_$name.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NT_STATUS_IS_OK(status)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface $name\_interface = {
	.name		= \"$name\",
	.uuid		= $uuid,
	.if_version	= $if_version,
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

	for (i=0;i<dcerpc_table_$name.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = dcerpc_table_$name.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &$name\_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,(\"$name\_op_init_server: failed to register endpoint \'%s\'\\n\",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static BOOL $name\__op_interface_by_uuid(struct dcesrv_interface *iface, const char *uuid, uint32_t if_version)
{
	if (dcerpc_table_$name.if_version == if_version &&
		strcmp(dcerpc_table_$name.uuid, uuid)==0) {
		memcpy(iface,&dcerpc_table_$name, sizeof(*iface));
		return True;
	}

	return False;
}

static BOOL $name\__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcerpc_table_$name.name, name)==0) {
		memcpy(iface,&dcerpc_table_$name, sizeof(*iface));
		return True;
	}

	return False;	
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
# dcom interface stub from a parsed IDL structure 
sub ParseInterface($)
{
	my($interface) = shift;
	
	return "" if has_property($interface, "local");
	
	my($data) = $interface->{DATA};
	my $count = 0;

	$res = "";

	if (!defined $interface->{PROPERTIES}->{uuid}) {
		return $res;
	}

	if (!defined $interface->{PROPERTIES}->{version}) {
		$interface->{PROPERTIES}->{version} = "0.0";
	}

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") { $count++; }
	}

	if ($count == 0) {
		return $res;
	}

	$res = "/* dcom interface stub generated by pidl */\n\n";
	Boilerplate_Iface($interface);
	Boilerplate_Ep_Server($interface);

	return $res;
}

1;
