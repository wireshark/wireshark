###################################################
# client calls generator
# Copyright tridge@samba.org 2003
# Copyright jelmer@samba.org 2005-2006
# released under the GNU GPL

package Parse::Pidl::Samba4::NDR::Client;

use Parse::Pidl::Samba4 qw(choose_header is_intree);
use Parse::Pidl::Util qw(has_property);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

my($res,$res_hdr);

sub ParseFunctionOldSend($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "static struct rpc_request *dcerpc_$name\_send(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $name *r)";

	$res .= "$proto\n{\n";

	$res .= "
	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG($name, r);
	}

	return dcerpc_ndr_request_send(p, NULL, &ndr_table_$interface->{NAME},
				       NDR_$uname, true, mem_ctx, r);
";

	$res .= "}\n\n";
}

sub ParseFunctionOldRecv($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "static NTSTATUS dcerpc_$name\_recv(struct rpc_request *rreq)";

	$res .= "$proto\n{\n";

	$res .= "NTSTATUS status;
	struct dcerpc_pipe *p = rreq->p;
	struct $name *r = (struct $name *)rreq->ndr.struct_ptr;

	status = dcerpc_ndr_request_recv(rreq);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG($name, r);
	}

	return status;
";

	$res .= "}\n\n";
}

sub ParseFunctionSync($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "NTSTATUS dcerpc_$name(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $name *r)";

	$res_hdr .= "\n$proto;\n";
	$res .= "$proto\n{\n";

	$res .= "
	NTSTATUS status;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG($name, r);
	}

	status = dcerpc_ndr_request(p, NULL, &ndr_table_$interface->{NAME},
				    NDR_$uname, mem_ctx, r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG($name, r);		
	}
";
    
        if (defined($fn->{RETURN_TYPE}) and $fn->{RETURN_TYPE} eq "NTSTATUS") {
             $res .= "\tif (NT_STATUS_IS_OK(status)) status = r->out.result;\n";
        }
	$res .= 
"
	return status;
";

	$res .= "}\n\n";
}

sub ParseFunction_r_State($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	$res .= "struct dcerpc_$name\_r_state {\n";
	$res .= "\tTALLOC_CTX *out_mem_ctx;\n";
	$res .= "};\n";
	$res .= "\n";
	$res .= "static void dcerpc_$name\_r_done(struct rpc_request *subreq);\n";
	$res .= "\n";
}

sub ParseFunction_r_Send($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "struct tevent_req *dcerpc_$name\_r_send(TALLOC_CTX *mem_ctx,\n";
	$proto   .= "\tstruct tevent_context *ev,\n",
	$proto   .= "\tstruct dcerpc_binding_handle *h,\n",
	$proto   .= "\tstruct $name *r)";

	$res_hdr .= "\n$proto;\n";

	$res .= "$proto\n{\n";

	$res .= "\tstruct tevent_req *req;\n";
	$res .= "\tstruct dcerpc_$name\_r_state *state;\n";
	$res .= "\tstruct dcerpc_pipe *p =\n";
	$res .= "\t\ttalloc_get_type_abort(h->private_data,\n";
	$res .= "\t\tstruct dcerpc_pipe);\n";
	$res .= "\tstruct rpc_request *subreq;\n";
	$res .= "\n";

	$res .= "\treq = tevent_req_create(mem_ctx, &state,\n";
	$res .= "\t\t\t\tstruct dcerpc_$name\_r_state);\n";
	$res .= "\tif (req == NULL) {\n";
	$res .= "\t\treturn NULL;\n";
	$res .= "\t}\n";
	$res .= "\n";

	my $out_params = 0;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/, @{$_->{DIRECTION}})) {
			$out_params++;
		}
	}

	my $submem;
	if ($out_params > 0) {
		$res .= "\tstate->out_mem_ctx = talloc_new(state);\n";
		$res .= "\tif (tevent_req_nomem(state->out_mem_ctx, req)) {\n";
		$res .= "\t\treturn tevent_req_post(req, ev);\n";
		$res .= "\t}\n";
		$res .= "\n";
		$submem = "state->out_mem_ctx";
	} else {
		$res .= "\tstate->out_mem_ctx = NULL;\n";
		$submem = "state";
	}

	$res .= "\tsubreq = dcerpc_$name\_send(p, $submem, r);\n";
	$res .= "\tif (tevent_req_nomem(subreq, req)) {\n";
	$res .= "\t\treturn tevent_req_post(req, ev);\n";
	$res .= "\t}\n";
	$res .= "\tsubreq->async.callback = dcerpc_$name\_r_done;\n";
	$res .= "\tsubreq->async.private_data = req;\n";
	$res .= "\n";

	$res .= "\treturn req;\n";
	$res .= "}\n";
	$res .= "\n";
}

sub ParseFunction_r_Done($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "static void dcerpc_$name\_r_done(struct rpc_request *subreq)";

	$res .= "$proto\n";
	$res .= "{\n";

	$res .= "\tstruct tevent_req *req =\n";
	$res .= "\t\ttalloc_get_type_abort(subreq->async.private_data,\n";
	$res .= "\t\tstruct tevent_req);\n";
	$res .= "\tNTSTATUS status;\n";
	$res .= "\n";

	$res .= "\tstatus = dcerpc_$name\_recv(subreq);\n";
	$res .= "\tif (!NT_STATUS_IS_OK(status)) {\n";
	$res .= "\t\ttevent_req_nterror(req, status);\n";
	$res .= "\t\treturn;\n";
	$res .= "\t}\n";
	$res .= "\n";

	$res .= "\ttevent_req_done(req);\n";
	$res .= "}\n";
	$res .= "\n";
}

sub ParseFunction_r_Recv($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "NTSTATUS dcerpc_$name\_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx)";

	$res_hdr .= "\n$proto;\n";

	$res .= "$proto\n{\n";

	$res .= "\tstruct dcerpc_$name\_r_state *state =\n";
	$res .= "\t\ttevent_req_data(req,\n";
	$res .= "\t\tstruct dcerpc_$name\_r_state);\n";
	$res .= "\tNTSTATUS status;\n";
	$res .= "\n";

	$res .= "\tif (tevent_req_is_nterror(req, &status)) {\n";
	$res .= "\t\ttevent_req_received(req);\n";
	$res .= "\t\treturn status;\n";
	$res .= "\t}\n";
	$res .= "\n";

	$res .= "\ttalloc_steal(mem_ctx, state->out_mem_ctx);\n";
	$res .= "\n";

	$res .= "\ttevent_req_received(req);\n";
	$res .= "\treturn NT_STATUS_OK;\n";
	$res .= "}\n";
	$res .= "\n";
}

sub ParseFunction_r_Sync($$$)
{
	my ($interface, $fn, $name) = @_;
	my $uname = uc $name;

	if (has_property($fn, "todo")) {
		return;
	}

	my $proto = "NTSTATUS dcerpc_$name\_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct $name *r)";

	$res_hdr .= "\n$proto;\n";
	$res .= "$proto\n{\n";

	$res .= "\tstruct dcerpc_pipe *p =\n";
	$res .= "\t\ttalloc_get_type_abort(h->private_data,\n";
	$res .= "\t\tstruct dcerpc_pipe);\n";
	$res .= "\n";

	$res .= "\treturn dcerpc_$name(p, mem_ctx, r);\n";
	$res .= "}\n";
	$res .= "\n";
}

#####################################################################
# parse a function
sub ParseFunction($$)
{
	my ($interface, $fn) = @_;

	ParseFunctionSync($interface, $fn, $fn->{NAME});

	ParseFunctionOldSend($interface, $fn, $fn->{NAME});
	ParseFunctionOldRecv($interface, $fn, $fn->{NAME});
	ParseFunction_r_State($interface, $fn, $fn->{NAME});
	ParseFunction_r_Send($interface, $fn, $fn->{NAME});
	ParseFunction_r_Done($interface, $fn, $fn->{NAME});
	ParseFunction_r_Recv($interface, $fn, $fn->{NAME});
	ParseFunction_r_Sync($interface, $fn, $fn->{NAME});
}

my %done;

#####################################################################
# parse the interface definitions
sub ParseInterface($)
{
	my($interface) = shift;

	$res_hdr .= "#ifndef _HEADER_RPC_$interface->{NAME}\n";
	$res_hdr .= "#define _HEADER_RPC_$interface->{NAME}\n\n";

	if (defined $interface->{PROPERTIES}->{uuid}) {
		$res_hdr .= "extern const struct ndr_interface_table ndr_table_$interface->{NAME};\n";
	}

	$res .= "/* $interface->{NAME} - client functions generated by pidl */\n\n";

	foreach my $fn (@{$interface->{FUNCTIONS}}) {
		next if not defined($fn->{OPNUM});
		next if defined($done{$fn->{NAME}});
		ParseFunction($interface, $fn);
		$done{$fn->{NAME}} = 1;
	}

	$res_hdr .= "#endif /* _HEADER_RPC_$interface->{NAME} */\n";

	return $res;
}

sub Parse($$$$)
{
	my($ndr,$header,$ndr_header,$client_header) = @_;

	$res = "";
	$res_hdr = "";

	$res .= "/* client functions auto-generated by pidl */\n";
	$res .= "\n";
	if (is_intree()) {
		$res .= "#include \"includes.h\"\n";
	} else {
		$res .= "#ifndef _GNU_SOURCE\n";
		$res .= "#define _GNU_SOURCE\n";
		$res .= "#endif\n";
		$res .= "#include <stdio.h>\n";
		$res .= "#include <stdbool.h>\n";
		$res .= "#include <stdlib.h>\n";
		$res .= "#include <stdint.h>\n";
		$res .= "#include <stdarg.h>\n";
		$res .= "#include <core/ntstatus.h>\n";
	}
	$res .= "#include <tevent.h>\n";
	$res .= "#include \"lib/util/tevent_ntstatus.h\"\n";
	$res .= "#include \"$ndr_header\"\n";
	$res .= "#include \"$client_header\"\n";
	$res .= "\n";

	$res_hdr .= choose_header("librpc/rpc/dcerpc.h", "dcerpc.h")."\n";
	$res_hdr .= "#include \"$header\"\n";

	foreach my $x (@{$ndr}) {
		($x->{TYPE} eq "INTERFACE") && ParseInterface($x);
	}

	return ($res,$res_hdr);
}

1;
