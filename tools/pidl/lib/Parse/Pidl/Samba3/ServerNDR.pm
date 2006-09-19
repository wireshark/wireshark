###################################################
# Samba3 server generator for IDL structures
# on top of Samba4 style NDR functions
# Copyright jelmer@samba.org 2005-2006
# released under the GNU GPL

package Parse::Pidl::Samba3::ServerNDR;

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapType scalar_is_reference);
use Parse::Pidl::Util qw(has_property ParseExpr is_constant);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);
use Parse::Pidl::Samba4 qw(DeclLong);

use vars qw($VERSION);
$VERSION = '0.01';

my $res;
my $res_hdr;
my $tabs = "";
sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { $res .= $tabs.(shift)."\n"; }
sub pidl_hdr($) { $res_hdr .= (shift)."\n"; }
sub fatal($$) { my ($e,$s) = @_; die("$e->{ORIGINAL}->{FILE}:$e->{ORIGINAL}->{LINE}: $s\n"); }
sub warning($$) { my ($e,$s) = @_; warn("$e->{ORIGINAL}->{FILE}:$e->{ORIGINAL}->{LINE}: $s\n"); }
sub fn_declare($) { my ($n) = @_; pidl $n; pidl_hdr "$n;"; }

sub AllocOutVar($$$$)
{
	my ($e, $mem_ctx, $name, $env) = @_;

	my $l = $e->{LEVELS}[0];

	if ($l->{TYPE} eq "POINTER") {
		$l = GetNextLevel($e, $l);
	}

	if ($l->{TYPE} eq "ARRAY") {
		my $size = ParseExpr($l->{SIZE_IS}, $env);
		pidl "$name = talloc_array_size($mem_ctx, sizeof(*$name), $size);";
	} else {
		pidl "$name = talloc_size($mem_ctx, sizeof(*$name));";
	}

	pidl "if ($name == NULL) {";
	pidl "\ttalloc_free(mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
}

sub ParseFunction($$)
{
	my ($if,$fn) = @_;

	pidl "static BOOL api_$fn->{NAME}(pipes_struct *p)";
	pidl "{";
	indent;
	pidl "struct ndr_pull *pull;";
	pidl "struct ndr_push *push;";
	pidl "NTSTATUS status;";
	pidl "DATA_BLOB blob;";
	pidl "struct $fn->{NAME} r;";
	pidl "TALLOC_CTX *mem_ctx = talloc_init(\"api_$fn->{NAME}\");";
	pidl "";
	pidl "if (!prs_data_blob(&p->in_data.data, &blob, mem_ctx)) {";
	pidl "\ttalloc_free(mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "pull = ndr_pull_init_blob(&blob, mem_ctx);";
	pidl "if (pull == NULL)";
	pidl "\treturn False;";
	pidl "";
	pidl "pull->flags |= LIBNDR_FLAG_REF_ALLOC;";
	pidl "status = ndr_pull_$fn->{NAME}(pull, NDR_IN, &r);";
	pidl "if (NT_STATUS_IS_ERR(status)) {";
	pidl "\ttalloc_free(mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";

	my %env = ();
	foreach (@{$fn->{ELEMENTS}}) {
		next unless (grep (/in/, @{$_->{DIRECTION}}));
		$env{$_->{NAME}} = "r.in.$_->{NAME}";
	}

	my $proto = "_$fn->{NAME}(pipes_struct *p";
	my $ret = "_$fn->{NAME}(p";
	foreach (@{$fn->{ELEMENTS}}) {
		my @dir = @{$_->{DIRECTION}};
		if (grep(/in/, @dir) and grep(/out/, @dir)) {
			pidl "r.out.$_->{NAME} = r.in.$_->{NAME};";
		} elsif (grep(/out/, @dir)) {
			AllocOutVar($_, "mem_ctx", "r.out.$_->{NAME}", \%env);
		}
		if (grep(/in/, @dir)) { $ret .= ", r.in.$_->{NAME}"; }
		else { $ret .= ", r.out.$_->{NAME}"; }

		$proto .= ", " . DeclLong($_);
	}
	$ret .= ")";
	$proto .= ");";

	if ($fn->{RETURN_TYPE}) {
		$ret = "r.out.result = $ret";
		$proto = "$fn->{RETURN_TYPE} $proto";
	} else {
		$proto = "void $proto";
	}

	pidl_hdr "$proto";
	pidl "$ret;";

	pidl "";
	pidl "push = ndr_push_init_ctx(mem_ctx);";
	pidl "if (push == NULL) {";
	pidl "\ttalloc_free(mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "status = ndr_push_$fn->{NAME}(push, NDR_OUT, &r);";
	pidl "if (NT_STATUS_IS_ERR(status)) {";
	pidl "\ttalloc_free(mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "blob = ndr_push_blob(push);";
	pidl "if (!prs_init_data_blob(&p->out_data.rdata, &blob, p->mem_ctx)) {";
	pidl "\ttalloc_free(mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "talloc_free(mem_ctx);";
	pidl "";
	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
}

sub ParseInterface($)
{
	my $if = shift;

	my $uif = uc($if->{NAME});

	pidl_hdr "#ifndef __SRV_$uif\__";
	pidl_hdr "#define __SRV_$uif\__";
	ParseFunction($if, $_) foreach (@{$if->{FUNCTIONS}});

	pidl "";
	pidl "/* Tables */";
	pidl "static struct api_struct api_$if->{NAME}_cmds[] = ";
	pidl "{";
	indent;

	foreach (@{$if->{FUNCTIONS}}) {
		pidl "{\"" . uc($_->{NAME}) . "\", DCERPC_" . uc($_->{NAME}) . ", api_$_->{NAME}},";
	}

	deindent;
	pidl "};";

	pidl "";

	pidl_hdr "void $if->{NAME}_get_pipe_fns(struct api_struct **fns, int *n_fns);";
	pidl "void $if->{NAME}_get_pipe_fns(struct api_struct **fns, int *n_fns)";
	pidl "{";
	indent;
	pidl "*fns = api_$if->{NAME}_cmds;";
	pidl "*n_fns = sizeof(api_$if->{NAME}_cmds) / sizeof(struct api_struct);";
	deindent;
	pidl "}";
	pidl "";

	pidl_hdr "NTSTATUS rpc_$if->{NAME}_init(void);";
	pidl "NTSTATUS rpc_$if->{NAME}_init(void)";
	pidl "{";
	pidl "\treturn rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION, \"$if->{NAME}\", \"$if->{NAME}\", api_$if->{NAME}_cmds, sizeof(api_$if->{NAME}_cmds) / sizeof(struct api_struct));";
	pidl "}";

	pidl_hdr "#endif /* __SRV_$uif\__ */";
}

sub Parse($$$)
{
	my($ndr,$header,$ndr_header) = @_;

	$res = "";
	$res_hdr = "";

	pidl "/*";
	pidl " * Unix SMB/CIFS implementation.";
	pidl " * server auto-generated by pidl. DO NOT MODIFY!";
	pidl " */";
	pidl "";
	pidl "#include \"includes.h\"";
	pidl "#include \"$header\"";
	pidl_hdr "#include \"$ndr_header\"";
	pidl "";
	
	foreach (@$ndr) {
		ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return ($res, $res_hdr);
}

1;
