#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::Samba3::ClientNDR qw(ParseFunction);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv);

# Make sure GenerateFunctionInEnv and GenerateFunctionOutEnv work
my $fn = { ELEMENTS => [ { DIRECTION => ["in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionInEnv($fn, "r."));
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionOutEnv($fn, "r."));

$fn = { ELEMENTS => [ { DIRECTION => ["out", "in"], NAME => "foo" } ] };
is_deeply({ "foo" => "r.in.foo" }, GenerateFunctionInEnv($fn, "r."));
is_deeply({ "foo" => "r.out.foo" }, GenerateFunctionOutEnv($fn, "r."));

$fn = { ELEMENTS => [ { DIRECTION => ["out"], NAME => "foo" } ] };
is_deeply({ }, GenerateFunctionInEnv($fn, "r."));
is_deeply({ "foo" => "r.out.foo" }, GenerateFunctionOutEnv($fn, "r."));

my $x = new Parse::Pidl::Samba3::ClientNDR();

$fn = { NAME => "bar", ELEMENTS => [ ] };
$x->ParseFunction("foo", $fn);
is($x->{res}, 
"struct rpccli_bar_state {
	TALLOC_CTX *out_mem_ctx;
};

static void rpccli_bar_done(struct tevent_req *subreq);

struct tevent_req *rpccli_bar_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct rpc_pipe_client *cli)
{
	struct tevent_req *req;
	struct rpccli_bar_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct rpccli_bar_state);
	if (req == NULL) {
		return NULL;
	}
	state->out_mem_ctx = NULL;

	subreq = dcerpc_bar_send(state,
				 ev,
				 cli->binding_handle);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpccli_bar_done, req);
	return req;
}

static void rpccli_bar_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpccli_bar_state *state = tevent_req_data(
		req, struct rpccli_bar_state);
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	if (state->out_mem_ctx) {
		mem_ctx = state->out_mem_ctx;
	} else {
		mem_ctx = state;
	}

	status = dcerpc_bar_recv(subreq,
				 mem_ctx);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS rpccli_bar_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx)
{
	struct rpccli_bar_state *state = tevent_req_data(
		req, struct rpccli_bar_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	/* Steal possible out parameters to the callers context */
	talloc_steal(mem_ctx, state->out_mem_ctx);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS rpccli_bar(struct rpc_pipe_client *cli,
		    TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	status = dcerpc_bar(cli->binding_handle,
			    mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Return result */
	return NT_STATUS_OK;
}

");

$x = new Parse::Pidl::Samba3::ClientNDR();

$fn = { NAME => "bar", ELEMENTS => [ ], RETURN_TYPE => "WERROR" };
$x->ParseFunction("foo", $fn);
is($x->{res}, 
"struct rpccli_bar_state {
	TALLOC_CTX *out_mem_ctx;
	WERROR result;
};

static void rpccli_bar_done(struct tevent_req *subreq);

struct tevent_req *rpccli_bar_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct rpc_pipe_client *cli)
{
	struct tevent_req *req;
	struct rpccli_bar_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct rpccli_bar_state);
	if (req == NULL) {
		return NULL;
	}
	state->out_mem_ctx = NULL;

	subreq = dcerpc_bar_send(state,
				 ev,
				 cli->binding_handle);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpccli_bar_done, req);
	return req;
}

static void rpccli_bar_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpccli_bar_state *state = tevent_req_data(
		req, struct rpccli_bar_state);
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	if (state->out_mem_ctx) {
		mem_ctx = state->out_mem_ctx;
	} else {
		mem_ctx = state;
	}

	status = dcerpc_bar_recv(subreq,
				 mem_ctx,
				 &state->result);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS rpccli_bar_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 WERROR *result)
{
	struct rpccli_bar_state *state = tevent_req_data(
		req, struct rpccli_bar_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	/* Steal possible out parameters to the callers context */
	talloc_steal(mem_ctx, state->out_mem_ctx);

	/* Return result */
	*result = state->result;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS rpccli_bar(struct rpc_pipe_client *cli,
		    TALLOC_CTX *mem_ctx,
		    WERROR *werror)
{
	WERROR result;
	NTSTATUS status;

	status = dcerpc_bar(cli->binding_handle,
			    mem_ctx,
			    &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Return result */
	if (werror) {
		*werror = result;
	}

	return werror_to_ntstatus(result);
}

");

