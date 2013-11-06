###################################################
# Samba3 server generator for IDL structures
# on top of Samba4 style NDR functions
# Copyright jelmer@samba.org 2005-2006
# released under the GNU GPL

package Parse::Pidl::Samba3::ServerNDR;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(DeclLevel);

use strict;
use Parse::Pidl qw(warning error fatal);
use Parse::Pidl::Typelist qw(mapTypeName scalar_is_reference);
use Parse::Pidl::Util qw(ParseExpr has_property is_constant);
use Parse::Pidl::NDR qw(GetNextLevel);
use Parse::Pidl::Samba4 qw(ElementStars DeclLong);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionOutEnv);

use vars qw($VERSION);
$VERSION = '0.01';

my $res;
my $res_hdr;
my $tabs = "";
sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { my ($txt) = @_; $res .= $txt?$tabs.(shift)."\n":"\n"; }
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

sub AllocOutVar($$$$$)
{
	my ($e, $mem_ctx, $name, $env, $fail) = @_;

	my $l = $e->{LEVELS}[0];

	# we skip pointer to arrays
	if ($l->{TYPE} eq "POINTER") {
		my $nl = GetNextLevel($e, $l);
		$l = $nl if ($nl->{TYPE} eq "ARRAY");
	} elsif

	# we don't support multi-dimentional arrays yet
	($l->{TYPE} eq "ARRAY") {
		my $nl = GetNextLevel($e, $l);
		if ($nl->{TYPE} eq "ARRAY") {
			fatal($e->{ORIGINAL},"multi-dimentional [out] arrays are not supported!");
		}
	} else {
		# neither pointer nor array, no need to alloc something.
		return;
	}

	if ($l->{TYPE} eq "ARRAY") {
		unless(defined($l->{SIZE_IS})) {
			error($e->{ORIGINAL}, "No size known for array `$e->{NAME}'");
			pidl "#error No size known for array `$e->{NAME}'";
		} else {
			my $size = ParseExpr($l->{SIZE_IS}, $env, $e);
			pidl "$name = talloc_zero_array($mem_ctx, " . DeclLevel($e, 1) . ", $size);";
		}
	} else {
		pidl "$name = talloc_zero($mem_ctx, " . DeclLevel($e, 1) . ");";
	}

	pidl "if ($name == NULL) {";
	$fail->();
	pidl "}";
	pidl "";
}

sub CallWithStruct($$$$)
{
	my ($pipes_struct, $mem_ctx, $fn, $fail) = @_;
	my $env = GenerateFunctionOutEnv($fn);
	my $hasout = 0;
	foreach (@{$fn->{ELEMENTS}}) {
		if (grep(/out/, @{$_->{DIRECTION}})) { $hasout = 1; }
	}

	pidl "ZERO_STRUCT(r->out);" if ($hasout);

	my $proto = "_$fn->{NAME}(struct pipes_struct *p, struct $fn->{NAME} *r";
	my $ret = "_$fn->{NAME}($pipes_struct, r";
	foreach (@{$fn->{ELEMENTS}}) {
		my @dir = @{$_->{DIRECTION}};
		if (grep(/in/, @dir) and grep(/out/, @dir)) {
			pidl "r->out.$_->{NAME} = r->in.$_->{NAME};";
		}
	}

	foreach (@{$fn->{ELEMENTS}}) {
		my @dir = @{$_->{DIRECTION}};
		if (grep(/in/, @dir) and grep(/out/, @dir)) {
			# noop
		} elsif (grep(/out/, @dir) and not
				 has_property($_, "represent_as")) {
			AllocOutVar($_, $mem_ctx, "r->out.$_->{NAME}", $env, $fail);
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
}

sub ParseFunction($$)
{
	my ($if,$fn) = @_;

	my $op = "NDR_".uc($fn->{NAME});

	pidl "static bool api_$fn->{NAME}(struct pipes_struct *p)";
	pidl "{";
	indent;
	pidl "const struct ndr_interface_call *call;";
	pidl "struct ndr_pull *pull;";
	pidl "struct ndr_push *push;";
	pidl "enum ndr_err_code ndr_err;";
	pidl "struct $fn->{NAME} *r;";
	pidl "";
	pidl "call = &ndr_table_$if->{NAME}.calls[$op];";
	pidl "";
	pidl "r = talloc(talloc_tos(), struct $fn->{NAME});";
	pidl "if (r == NULL) {";
	pidl "\treturn false;";
	pidl "}";
	pidl "";
	pidl "pull = ndr_pull_init_blob(&p->in_data.data, r);";
	pidl "if (pull == NULL) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn false;";
	pidl "}";
	pidl "";
	pidl "pull->flags |= LIBNDR_FLAG_REF_ALLOC;";
	pidl "if (p->endian) {";
	pidl "\tpull->flags |= LIBNDR_FLAG_BIGENDIAN;";
	pidl "}";
	pidl "ndr_err = call->ndr_pull(pull, NDR_IN, r);";
	pidl "if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn false;";
	pidl "}";
	pidl "";
	pidl "if (DEBUGLEVEL >= 10) {";
	pidl "\tNDR_PRINT_FUNCTION_DEBUG($fn->{NAME}, NDR_IN, r);";
	pidl "}";
	pidl "";

	CallWithStruct("p", "r", $fn, 
	sub { 
			pidl "\ttalloc_free(r);";
			pidl "\treturn false;";
		}
	);

	pidl "";
	pidl "if (p->fault_state) {";
	pidl "\ttalloc_free(r);";
	pidl "\t/* Return true here, srv_pipe_hnd.c will take care */";
	pidl "\treturn true;";
	pidl "}";
	pidl "";
	pidl "if (DEBUGLEVEL >= 10) {";
	pidl "\tNDR_PRINT_FUNCTION_DEBUG($fn->{NAME}, NDR_OUT | NDR_SET_VALUES, r);";
	pidl "}";
	pidl "";
	pidl "push = ndr_push_init_ctx(r);";
	pidl "if (push == NULL) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn false;";
	pidl "}";
	pidl "";
	pidl "/*";
	pidl " * carry over the pointer count to the reply in case we are";
	pidl " * using full pointer. See NDR specification for full pointers";
	pidl " */";
	pidl "push->ptr_count = pull->ptr_count;";
	pidl "";
	pidl "ndr_err = call->ndr_push(push, NDR_OUT, r);";
	pidl "if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {";
	pidl "\ttalloc_free(r);";
	pidl "\treturn false;";
	pidl "}";
	pidl "";
	pidl "p->out_data.rdata = ndr_push_blob(push);";
	pidl "talloc_steal(p->mem_ctx, p->out_data.rdata.data);";
	pidl "";
	pidl "talloc_free(r);";
	pidl "";
	pidl "return true;";
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

	foreach (@{$if->{FUNCTIONS}}) {
		next if ($_->{PROPERTIES}{noopnum});
		ParseFunction($if, $_);
	}

	pidl "";
	pidl "/* Tables */";
	pidl "static struct api_struct api_$if->{NAME}_cmds[] = ";
	pidl "{";
	indent;

	foreach (@{$if->{FUNCTIONS}}) {
		next if ($_->{PROPERTIES}{noopnum});
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

	if (not has_property($if, "no_srv_register")) {
	    pidl_hdr "struct rpc_srv_callbacks;";
	    pidl_hdr "NTSTATUS rpc_$if->{NAME}_init(const struct rpc_srv_callbacks *rpc_srv_cb);";
	    pidl "NTSTATUS rpc_$if->{NAME}_init(const struct rpc_srv_callbacks *rpc_srv_cb)";
	    pidl "{";
	    pidl "\treturn rpc_srv_register(SMB_RPC_INTERFACE_VERSION, \"$if->{NAME}\", \"$if->{NAME}\", \&ndr_table_$if->{NAME}, api_$if->{NAME}_cmds, sizeof(api_$if->{NAME}_cmds) / sizeof(struct api_struct), rpc_srv_cb);";
	    pidl "}";

	    pidl "";

	    pidl_hdr "NTSTATUS rpc_$if->{NAME}_shutdown(void);";
	    pidl "NTSTATUS rpc_$if->{NAME}_shutdown(void)";
	    pidl "{";
	    pidl "\treturn rpc_srv_unregister(\&ndr_table_$if->{NAME});";
	    pidl "}";
	}
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
	pidl "#include \"ntdomain.h\"";
	pidl "#include \"$header\"";
	pidl_hdr "#include \"$ndr_header\"";
	pidl "";

	foreach (@$ndr) {
		ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return ($res, $res_hdr);
}

1;
