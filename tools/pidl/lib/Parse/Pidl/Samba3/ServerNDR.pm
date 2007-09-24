###################################################
# Samba3 server generator for IDL structures
# on top of Samba4 style NDR functions
# Copyright jelmer@samba.org 2005-2006
# released under the GNU GPL

package Parse::Pidl::Samba3::ServerNDR;

use strict;
use Parse::Pidl qw(warning fatal);
use Parse::Pidl::Typelist qw(mapTypeName scalar_is_reference);
use Parse::Pidl::Util qw(ParseExpr has_property is_constant);
use Parse::Pidl::NDR qw(GetNextLevel);
use Parse::Pidl::Samba4 qw(ElementStars DeclLong);
use Parse::Pidl::Samba4::NDR::Parser qw(GenerateFunctionOutEnv);

use vars qw($VERSION);
$VERSION = '0.01';

my $res;
my $res_hdr;
my $tabs = "";
sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { $res .= $tabs.(shift)."\n"; }
sub pidl_hdr($) { $res_hdr .= (shift)."\n"; }
sub fn_declare($) { my ($n) = @_; pidl $n; pidl_hdr "$n;"; }

sub DeclLevel($$) 
{
	my ($e, $l) = @_;
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

sub AllocOutVar($$$$)
{
	my ($e, $mem_ctx, $name, $env) = @_;

	my $l = $e->{LEVELS}[0];

	# we skip pointer to arrays
	if ($l->{TYPE} eq "POINTER") {
		my $nl = GetNextLevel($e, $l);
		$l = $nl if ($nl->{TYPE} eq "ARRAY");
	}

	# we don't support multi-dimentional arrays yet
	if ($l->{TYPE} eq "ARRAY") {
		my $nl = GetNextLevel($e, $l);
		if ($nl->{TYPE} eq "ARRAY") {
			fatal($e->{ORIGINAL},"multi-dimentional [out] arrays are not supported!");
		}
	}

	if ($l->{TYPE} eq "ARRAY") {
		my $size = ParseExpr($l->{SIZE_IS}, $env, $e);
		pidl "$name = talloc_zero_array($mem_ctx, " . DeclLevel($e, 1) . ", $size);";
	} else {
		pidl "$name = talloc_zero($mem_ctx, " . DeclLevel($e, 1) . ");";
	}

	pidl "if ($name == NULL) {";
	pidl "\ttalloc_free($mem_ctx);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
}

sub ParseFunction($$)
{
	my ($if,$fn) = @_;

	my $op = "NDR_".uc($fn->{NAME});

	pidl "static BOOL api_$fn->{NAME}(pipes_struct *p)";
	pidl "{";
	indent;
	pidl "const struct ndr_interface_call *call;";
	pidl "struct ndr_pull *pull;";
	pidl "struct ndr_push *push;";
	pidl "NTSTATUS status;";
	pidl "DATA_BLOB blob;";
	pidl "struct $fn->{NAME} *r;";
	pidl "";
	pidl "call = &ndr_table_$if->{NAME}.calls[$op];";
	pidl "";
	pidl "r = talloc(NULL, struct $fn->{NAME});";
	pidl "if (r == NULL) {";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "if (!prs_data_blob(&p->in_data.data, &blob, r)) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "pull = ndr_pull_init_blob(&blob, r);";
	pidl "if (pull == NULL) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "pull->flags |= LIBNDR_FLAG_REF_ALLOC;";
	pidl "status = call->ndr_pull(pull, NDR_IN, r);";
	pidl "if (NT_STATUS_IS_ERR(status)) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "if (DEBUGLEVEL >= 10)";
	pidl "\tNDR_PRINT_IN_DEBUG($fn->{NAME}, r);";
	pidl "";

	my $env = GenerateFunctionOutEnv($fn);
	my $hasout = 0;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/, @{$_->{DIRECTION}})) { $hasout = 1; }
	}

	pidl "ZERO_STRUCT(r->out);" if ($hasout);

	my $proto = "_$fn->{NAME}(pipes_struct *p, struct $fn->{NAME} *r";
	my $ret = "_$fn->{NAME}(p, r";
	foreach (@{$fn->{ELEMENTS}}) {
		my @dir = @{$_->{DIRECTION}};
		if (grep(/in/, @dir) and grep(/out/, @dir)) {
			pidl "r->out.$_->{NAME} = r->in.$_->{NAME};";
		} elsif (grep(/out/, @dir) and not 
				 has_property($_, "represent_as")) {
			AllocOutVar($_, "r", "r->out.$_->{NAME}", $env);
		}
	}
	$ret .= ")";
	$proto .= ");";

	if ($fn->{RETURN_TYPE}) {
		$ret = "r->out.result = $ret";
		$proto = "$fn->{RETURN_TYPE} $proto";
	} else {
		$proto = "void $proto";
	}

	pidl_hdr "$proto";
	pidl "$ret;";

	pidl "";
	pidl "if (p->rng_fault_state) {";
	pidl "\ttalloc_free(r);";
	pidl "\t/* Return True here, srv_pipe_hnd.c will take care */";
	pidl "\treturn True;";
	pidl "}";
	pidl "";
	pidl "if (DEBUGLEVEL >= 10)";
	pidl "\tNDR_PRINT_OUT_DEBUG($fn->{NAME}, r);";
	pidl "";
	pidl "push = ndr_push_init_ctx(r);";
	pidl "if (push == NULL) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "status = call->ndr_push(push, NDR_OUT, r);";
	pidl "if (NT_STATUS_IS_ERR(status)) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "blob = ndr_push_blob(push);";
	pidl "if (!prs_copy_data_in(&p->out_data.rdata, (const char *)blob.data, (uint32)blob.length)) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn False;";
	pidl "}";
	pidl "";
	pidl "talloc_free(r);";
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
		pidl "{\"" . uc($_->{NAME}) . "\", NDR_" . uc($_->{NAME}) . ", api_$_->{NAME}},";
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
