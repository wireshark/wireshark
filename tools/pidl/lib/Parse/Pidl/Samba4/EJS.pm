###################################################
# EJS function wrapper generator
# Copyright jelmer@samba.org 2005
# Copyright Andrew Tridgell 2005
# released under the GNU GPL

package Parse::Pidl::Samba4::EJS;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(get_pointer_to get_value_of check_null_pointer $res
                $res_hdr fn_declare TypeFunctionName);

use strict;
use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel);
use Parse::Pidl::Samba4::NDR::Parser qw(GenerateStructEnv GenerateFunctionInEnv
                                        GenerateFunctionOutEnv);

use vars qw($VERSION);
$VERSION = '0.01';

our $res;
our $res_hdr;

my %constants;

my $tabs = "";

sub pidl_hdr ($)
{
	$res_hdr .= shift;
}

sub pidl($)
{
	my $d = shift;
	if ($d) {
		$res .= $tabs;
		$res .= $d;
	}
	$res .= "\n";
}

sub indent()
{
	$tabs .= "\t";
}

sub deindent()
{
	$tabs = substr($tabs, 0, -1);
}

sub get_pointer_to($)
{
	my $var_name = shift;
	
	if ($var_name =~ /^\*(.*)$/) {
		return $1;
	} elsif ($var_name =~ /^\&(.*)$/) {
		return "&($var_name)";
	} else {
		return "&$var_name";
	}
}

sub get_value_of($)
{
	my $var_name = shift;

	if ($var_name =~ /^\&(.*)$/) {
		return $1;
	} else {
		return "*$var_name";
	}
}

#####################################################################
# check that a variable we get from ParseExpr isn't a null pointer
sub check_null_pointer($)
{
	my $size = shift;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		pidl "if ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;";
	}
}

#####################################################################
# work out is a parse function should be declared static or not
sub fn_declare($$)
{
	my ($fn,$decl) = @_;

	if (has_property($fn, "public")) {
		pidl_hdr "$decl;\n";
		pidl "_PUBLIC_ $decl";
	} else {
		pidl "static $decl";
	}
}

###########################
# pull a scalar element
sub EjsPullScalar($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;

	return if (has_property($e, "value"));

	if (ref($e->{TYPE}) eq "HASH" and not defined($e->{TYPE}->{NAME})) {
		EjsTypePull($e->{TYPE}, $var);
	} else {
		my $pl = Parse::Pidl::NDR::GetPrevLevel($e, $l);
        $var = get_pointer_to($var);
        # have to handle strings specially :(
		if (Parse::Pidl::Typelist::scalar_is_reference($e->{TYPE})
			and (defined($pl) and $pl->{TYPE} eq "POINTER")) {
                $var = get_pointer_to($var);
        }

    	my $t;
		if (ref($e->{TYPE}) eq "HASH") {
			$t = "$e->{TYPE}->{TYPE}_$e->{TYPE}->{NAME}";
		} else {
			$t = $e->{TYPE};
		}
		pidl "NDR_CHECK(ejs_pull_$t(ejs, v, $name, $var));";
	}
}

###########################
# pull a pointer element
sub EjsPullPointer($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "if (ejs_pull_null(ejs, v, $name)) {";
	indent;
	if ($l->{POINTER_TYPE} eq "ref") {
		pidl "return NT_STATUS_INVALID_PARAMETER_MIX;";
	} else {
		pidl "$var = NULL;";
	}
	deindent;
	pidl "} else {";
	indent;
	pidl "EJS_ALLOC(ejs, $var);";
	$var = get_value_of($var);		
	EjsPullElement($e, GetNextLevel($e, $l), $var, $name, $env);
	deindent;
	pidl "}";
}

###########################
# pull a string element
sub EjsPullString($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $pl = GetPrevLevel($e, $l);
	$var = get_pointer_to($var);
	if (defined($pl) and $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	pidl "NDR_CHECK(ejs_pull_string(ejs, v, $name, $var));";
}

###########################
# pull an array element
sub EjsPullArray($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $nl = GetNextLevel($e, $l);
	my $length = ParseExpr($l->{LENGTH_IS}, $env, $e);
	my $size = ParseExpr($l->{SIZE_IS}, $env, $e);
	my $pl = GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	# uint8 arrays are treated as data blobs
	if ($nl->{TYPE} eq 'DATA' && $e->{TYPE} eq 'uint8') {
		if (!$l->{IS_FIXED}) {
			check_null_pointer($size);
			pidl "EJS_ALLOC_N(ejs, $var, $size);";
		}
		check_null_pointer($length);
		pidl "ejs_pull_array_uint8(ejs, v, $name, $var, $length);";
		return;
	}
	my $avar = $var . "[i]";
	pidl "{";
	indent;
	pidl "uint32_t i;";
	if (!$l->{IS_FIXED}) {
		pidl "EJS_ALLOC_N(ejs, $var, $size);";
	}
	pidl "for (i=0;i<$length;i++) {";
	indent;
	pidl "char *id = talloc_asprintf(ejs, \"%s.%u\", $name, i);";
	EjsPullElement($e, $nl, $avar, "id", $env);
	pidl "talloc_free(id);";
	deindent;
	pidl "}";
	pidl "ejs_push_uint32(ejs, v, $name \".length\", &i);";
	deindent;
	pidl "}";
}

###########################
# pull a switch element
sub EjsPullSwitch($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env, $e);
	pidl "ejs_set_switch(ejs, $switch_var);";
	EjsPullElement($e, GetNextLevel($e, $l), $var, $name, $env);
}

###########################
# pull a structure element
sub EjsPullElement($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	if (($l->{TYPE} eq "POINTER")) {
		EjsPullPointer($e, $l, $var, $name, $env);
	} elsif (has_property($e, "charset")) {
		EjsPullString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPullArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPullScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "SWITCH")) {
		EjsPullSwitch($e, $l, $var, $name, $env);
	} else {
		pidl "return ejs_panic(ejs, \"unhandled pull type $l->{TYPE}\");";
	}
}

#############################################
# pull a structure/union element at top level
sub EjsPullElementTop($$)
{
	my ($e, $env) = @_;
	my $l = $e->{LEVELS}[0];
	my $var = ParseExpr($e->{NAME}, $env, $e);
	my $name = "\"$e->{NAME}\"";
	EjsPullElement($e, $l, $var, $name, $env);
}

###########################
# pull a struct
sub EjsStructPull($$)
{
	my ($d, $varname) = @_;
	my $env = GenerateStructEnv($d, $varname);
	pidl "NDR_CHECK(ejs_pull_struct_start(ejs, &v, name));";
    foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPullElementTop($e, $env);
	}
}

###########################
# pull a union
sub EjsUnionPull($$)
{
	my ($d, $varname) = @_;
	my $have_default = 0;
	pidl "NDR_CHECK(ejs_pull_struct_start(ejs, &v, name));";
	pidl "switch (ejs->switch_var) {";
	indent;
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e->{CASE} eq "default") {
			$have_default = 1;
		}
		pidl "$e->{CASE}:";
		indent;
		if ($e->{TYPE} ne "EMPTY") {
			EjsPullElementTop($e, { $e->{NAME} => "$varname->$e->{NAME}"});
		}
		pidl "break;";
		deindent;
	}
	if (! $have_default) {
		pidl "default:";
		indent;
		pidl "return ejs_panic(ejs, \"Bad switch value\");";
		deindent;
	}
	deindent;
	pidl "}";
}

##############################################
# put the enum elements in the constants array
sub EjsEnumConstant($)
{
	my $d = shift;
	my $v = 0;
	foreach my $e (@{$d->{ELEMENTS}}) {
		my $el = $e;
		chomp $el;
		if ($el =~ /^(.*)=\s*(.*)\s*$/) {
			$el = $1;
			$v = $2;
		}
		$constants{$el} = $v;
		$v++;
	}
}

###########################
# pull a enum
sub EjsEnumPull($$)
{
	my ($d, $varname) = @_;
	EjsEnumConstant($d);
	pidl "unsigned e;";
	pidl "NDR_CHECK(ejs_pull_enum(ejs, v, name, &e));";
	pidl "*$varname = e;";
}

###########################
# pull a bitmap
sub EjsBitmapPull($$)
{
	my ($d, $varname) = @_;
	my $type_fn = $d->{BASE_TYPE};
	pidl "NDR_CHECK(ejs_pull_$type_fn(ejs, v, name, $varname));";
}

sub EjsTypePullFunction($$)
{
	sub EjsTypePullFunction($$);
	my ($d, $name) = @_;
	return if (has_property($d, "noejs"));

	if ($d->{TYPE} eq "TYPEDEF") {
		EjsTypePullFunction($d->{DATA}, $name);
		return;
	}

	if ($d->{TYPE} eq "STRUCT") {
		fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, struct $name *r)");
	} elsif ($d->{TYPE} eq "UNION") {
		fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, union $name *r)");
	} elsif ($d->{TYPE} eq "ENUM") {
		fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, enum $name *r)");
	} elsif ($d->{TYPE} eq "BITMAP") {
		my($type_decl) = Parse::Pidl::Typelist::mapTypeName($d->{BASE_TYPE});
		fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, $type_decl *r)");
	}
	pidl "{";
	indent;

	EjsTypePull($d, "r");

	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

sub EjsTypePull($$)
{
	my ($d, $varname) = @_;
	if ($d->{TYPE} eq 'STRUCT') {
		EjsStructPull($d, $varname);
	} elsif ($d->{TYPE} eq 'UNION') {
		EjsUnionPull($d, $varname);
	} elsif ($d->{TYPE} eq 'ENUM') {
		EjsEnumPull($d, $varname);
	} elsif ($d->{TYPE} eq 'BITMAP') {
		EjsBitmapPull($d, $varname);
	} else {
		warn "Unhandled pull $varname of type $d->{TYPE}";
	}
}

#####################
# generate a function
sub EjsPullFunction($)
{
	my $d = shift;
	my $env = GenerateFunctionInEnv($d);
	my $name = $d->{NAME};

	pidl "\nstatic NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, struct $name *r)";
	pidl "{";
	indent;
	pidl "NDR_CHECK(ejs_pull_struct_start(ejs, &v, \"input\"));";

	# we pull non-array elements before array elements as arrays
	# may have length_is() or size_is() properties that depend
	# on the non-array elements
	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		next if (has_property($e, "length_is") || has_property($e, "size_is"));
		EjsPullElementTop($e, $env);
	}

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		next unless (has_property($e, "length_is") || has_property($e, "size_is"));
		EjsPullElementTop($e, $env);
	}

	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

###########################
# push a scalar element
sub EjsPushScalar($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;

	if (ref($e->{TYPE}) eq "HASH" and not defined($e->{TYPE}->{NAME})) {
		EjsTypePush($e->{TYPE}, get_pointer_to($var));
	} else {
    # have to handle strings specially :(
        my $pl = GetPrevLevel($e, $l);

		if ((not Parse::Pidl::Typelist::scalar_is_reference($e->{TYPE}))
			or (defined($pl) and $pl->{TYPE} eq "POINTER")) {
					$var = get_pointer_to($var);
			}

		pidl "NDR_CHECK(".TypeFunctionName("ejs_push", $e->{TYPE})."(ejs, v, $name, $var));";
	}
}

###########################
# push a string element
sub EjsPushString($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $pl = GetPrevLevel($e, $l);
	if (defined($pl) and $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	pidl "NDR_CHECK(ejs_push_string(ejs, v, $name, $var));";
}

###########################
# push a pointer element
sub EjsPushPointer($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "if (NULL == $var) {";
	indent;
	if ($l->{POINTER_TYPE} eq "ref") {
		pidl "return NT_STATUS_INVALID_PARAMETER_MIX;";
	} else {
		pidl "NDR_CHECK(ejs_push_null(ejs, v, $name));";
	}
	deindent;
	pidl "} else {";
	indent;
	$var = get_value_of($var);		
	EjsPushElement($e, GetNextLevel($e, $l), $var, $name, $env);
	deindent;
	pidl "}";
}

###########################
# push a switch element
sub EjsPushSwitch($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env, $e);
	pidl "ejs_set_switch(ejs, $switch_var);";
	EjsPushElement($e, GetNextLevel($e, $l), $var, $name, $env);
}

###########################
# push an array element
sub EjsPushArray($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $nl = GetNextLevel($e, $l);
	my $length = ParseExpr($l->{LENGTH_IS}, $env, $e);
	my $pl = GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	# uint8 arrays are treated as data blobs
	if ($nl->{TYPE} eq 'DATA' && $e->{TYPE} eq 'uint8') {
		check_null_pointer($length);
		pidl "ejs_push_array_uint8(ejs, v, $name, $var, $length);";
		return;
	}
	my $avar = $var . "[i]";
	pidl "{";
	indent;
	pidl "uint32_t i;";
	pidl "for (i=0;i<$length;i++) {";
	indent;
	pidl "const char *id = talloc_asprintf(ejs, \"%s.%u\", $name, i);";
	EjsPushElement($e, $nl, $avar, "id", $env);
	deindent;
	pidl "}";
	pidl "ejs_push_uint32(ejs, v, $name \".length\", &i);";
	deindent;
	pidl "}";
}

################################
# push a structure/union element
sub EjsPushElement($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	if (($l->{TYPE} eq "POINTER")) {
		EjsPushPointer($e, $l, $var, $name, $env);
	} elsif (has_property($e, "charset")) {
		EjsPushString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPushArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPushScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "SWITCH")) {
		EjsPushSwitch($e, $l, $var, $name, $env);
	} else {
		pidl "return ejs_panic(ejs, \"unhandled push type $l->{TYPE}\");";
	}
}

#############################################
# push a structure/union element at top level
sub EjsPushElementTop($$)
{
	my ($e, $env) = @_;
	my $l = $e->{LEVELS}[0];
	my $var = ParseExpr($e->{NAME}, $env, $e);
	my $name = "\"$e->{NAME}\"";
	EjsPushElement($e, $l, $var, $name, $env);
}

###########################
# push a struct
sub EjsStructPush($$)
{
	my ($d, $varname) = @_;
	my $env = GenerateStructEnv($d, $varname);
	pidl "NDR_CHECK(ejs_push_struct_start(ejs, &v, name));";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPushElementTop($e, $env);
	}
}

###########################
# push a union
sub EjsUnionPush($$)
{
	my ($d, $varname) = @_;
	my $have_default = 0;
	pidl "NDR_CHECK(ejs_push_struct_start(ejs, &v, name));";
	pidl "switch (ejs->switch_var) {";
	indent;
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e->{CASE} eq "default") {
			$have_default = 1;
		}
		pidl "$e->{CASE}:";
		indent;
		if ($e->{TYPE} ne "EMPTY") {
			EjsPushElementTop($e, { $e->{NAME} => "$varname->$e->{NAME}"} );
		}
		pidl "break;";
		deindent;
	}
	if (! $have_default) {
		pidl "default:";
		indent;
		pidl "return ejs_panic(ejs, \"Bad switch value\");";
		deindent;
	}
	deindent;
	pidl "}";
}

###########################
# push a enum
sub EjsEnumPush($$)
{
	my ($d, $varname) = @_;
	EjsEnumConstant($d);
	pidl "unsigned e = ".get_value_of($varname).";";
	pidl "NDR_CHECK(ejs_push_enum(ejs, v, name, &e));";
}

###########################
# push a bitmap
sub EjsBitmapPush($$)
{
	my ($d, $varname) = @_;
	my $type_fn = $d->{BASE_TYPE};
	# put the bitmap elements in the constants array
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e =~ /^(\w*)\s*(.*)\s*$/) {
			my $bname = $1;
			my $v = $2;
			$constants{$bname} = $v;
		}
	}
	pidl "NDR_CHECK(ejs_push_$type_fn(ejs, v, name, $varname));";
}

sub EjsTypePushFunction($$)
{
	sub EjsTypePushFunction($$);
	my ($d, $name) = @_;
	return if (has_property($d, "noejs"));

	my $var = undef;
	my $dt = $d;
	if ($dt->{TYPE} eq "TYPEDEF") {
		$dt = $dt->{DATA};
	}
	if ($dt->{TYPE} eq "STRUCT") {
		$var = "const struct $name *r";
	} elsif ($dt->{TYPE} eq "UNION") {
		$var = "const union $name *r";
	} elsif ($dt->{TYPE} eq "ENUM") {
		$var = "const enum $name *r";
	} elsif ($dt->{TYPE} eq "BITMAP") {
		my($type_decl) = Parse::Pidl::Typelist::mapTypeName($dt->{BASE_TYPE});
		$var = "const $type_decl *r";
	}
	fn_declare($d, "NTSTATUS ".TypeFunctionName("ejs_push", $d) . "(struct ejs_rpc *ejs, struct MprVar *v, const char *name, $var)");
	pidl "{";
	indent;
	EjsTypePush($d, "r");
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

sub EjsTypePush($$)
{
	sub EjsTypePush($$);
	my ($d, $varname) = @_;

	if ($d->{TYPE} eq 'STRUCT') {
		EjsStructPush($d, $varname);
	} elsif ($d->{TYPE} eq 'UNION') {
		EjsUnionPush($d, $varname);
	} elsif ($d->{TYPE} eq 'ENUM') {
		EjsEnumPush($d, $varname);
	} elsif ($d->{TYPE} eq 'BITMAP') {
		EjsBitmapPush($d, $varname);
	} elsif ($d->{TYPE} eq 'TYPEDEF') {
		EjsTypePush($d->{DATA}, $varname);
	} else {
		warn "Unhandled push $varname of type $d->{TYPE}";
	}
}

#####################
# generate a function
sub EjsPushFunction($)
{
	my $d = shift;
	my $env = GenerateFunctionOutEnv($d);

	pidl "\nstatic NTSTATUS ejs_push_$d->{NAME}(struct ejs_rpc *ejs, struct MprVar *v, const struct $d->{NAME} *r)";
	pidl "{";
	indent;
	pidl "NDR_CHECK(ejs_push_struct_start(ejs, &v, \"output\"));";

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));
		EjsPushElementTop($e, $env);
	}

	if ($d->{RETURN_TYPE}) {
		pidl "NDR_CHECK(".TypeFunctionName("ejs_push", $d->{RETURN_TYPE})."(ejs, v, \"result\", &r->out.result));";
	}

	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

#################################
# generate a ejs mapping function
sub EjsFunction($$)
{
	my ($d, $iface) = @_;
	my $name = $d->{NAME};
	my $callnum = uc("DCERPC_$name");
	my $table = "&dcerpc_table_$iface";

	pidl "static int ejs_$name(int eid, int argc, struct MprVar **argv)";
	pidl "{";
	indent;
	pidl "return ejs_rpc_call(eid, argc, argv, $table, $callnum, (ejs_pull_function_t)ejs_pull_$name, (ejs_push_function_t)ejs_push_$name);";
	deindent;
	pidl "}\n";
}

###################
# handle a constant
sub EjsConst($)
{
    my $const = shift;
    $constants{$const->{NAME}} = $const->{VALUE};
}

sub EjsImport
{
	my @imports = @_;
	foreach (@imports) {
		s/\.idl\"$//;
		s/^\"//;
		pidl_hdr "#include \"librpc/gen_ndr/ndr_$_\_ejs\.h\"\n";
	}
}

#####################################################################
# parse the interface definitions
sub EjsInterface($$)
{
	my($interface,$needed) = @_;
	my @fns = ();
	my $name = $interface->{NAME};

	%constants = ();

	pidl_hdr "#ifndef _HEADER_EJS_$interface->{NAME}\n";
	pidl_hdr "#define _HEADER_EJS_$interface->{NAME}\n\n";

	pidl_hdr "\n";

	foreach my $d (@{$interface->{TYPES}}) {
		($needed->{TypeFunctionName("ejs_push", $d)}) && EjsTypePushFunction($d, $d->{NAME});
		($needed->{TypeFunctionName("ejs_pull", $d)}) && EjsTypePullFunction($d, $d->{NAME});
	}

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		next if has_property($d, "noejs");

		EjsPullFunction($d);
		EjsPushFunction($d);
		EjsFunction($d, $name);

		push (@fns, $d->{NAME});
	}

	foreach my $d (@{$interface->{CONSTS}}) {
		EjsConst($d);
	}

	pidl "static int ejs_$name\_init(int eid, int argc, struct MprVar **argv)";
	pidl "{";
	indent;
	pidl "struct MprVar *obj = mprInitObject(eid, \"$name\", argc, argv);";
	foreach (@fns) {
		pidl "mprSetCFunction(obj, \"$_\", ejs_$_);";
	}
	foreach my $v (keys %constants) {
		my $value = $constants{$v};
		if (substr($value, 0, 1) eq "\"") {
			pidl "mprSetVar(obj, \"$v\", mprString($value));";
		} else {
			pidl "mprSetVar(obj, \"$v\", mprCreateNumberVar($value));";
		}
	}
	pidl "return ejs_rpc_init(obj, \"$name\");";
	deindent;
	pidl "}\n";

	pidl "NTSTATUS ejs_init_$name(void)";
	pidl "{";
	indent;
	pidl "ejsDefineCFunction(-1, \"$name\_init\", ejs_$name\_init, NULL, MPR_VAR_SCRIPT_HANDLE);";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";

	pidl_hdr "\n";
	pidl_hdr "#endif /* _HEADER_EJS_$interface->{NAME} */\n";
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($$)
{
    my($ndr,$hdr) = @_;
    
    my $ejs_hdr = $hdr;
    $ejs_hdr =~ s/.h$/_ejs.h/;
    $res = "";
	$res_hdr = "";

    pidl_hdr "/* header auto-generated by pidl */\n\n";
	
    pidl "
/* EJS wrapper functions auto-generated by pidl */
#include \"includes.h\"
#include \"librpc/rpc/dcerpc.h\"
#include \"lib/appweb/ejs/ejs.h\"
#include \"scripting/ejs/ejsrpc.h\"
#include \"scripting/ejs/smbcalls.h\"
#include \"librpc/gen_ndr/ndr_misc_ejs.h\"
#include \"$hdr\"
#include \"$ejs_hdr\"

";

    my %needed = ();

    foreach my $x (@{$ndr}) {
	    ($x->{TYPE} eq "INTERFACE") && NeededInterface($x, \%needed);
    }

    foreach my $x (@$ndr) {
	    ($x->{TYPE} eq "INTERFACE") && EjsInterface($x, \%needed);
		($x->{TYPE} eq "IMPORT") && EjsImport(@{$x->{PATHS}});
    }

    return ($res_hdr, $res);
}

sub NeededFunction($$)
{
	my ($fn,$needed) = @_;

	$needed->{"ejs_pull_$fn->{NAME}"} = 1;
	$needed->{"ejs_push_$fn->{NAME}"} = 1;
	 
	foreach (@{$fn->{ELEMENTS}}) {
		next if (has_property($_, "subcontext")); #FIXME: Support subcontexts
		if (grep(/in/, @{$_->{DIRECTION}})) {
			$needed->{TypeFunctionName("ejs_pull", $_->{TYPE})} = 1;
		}
		if (grep(/out/, @{$_->{DIRECTION}})) {
			$needed->{TypeFunctionName("ejs_push", $_->{TYPE})} = 1;
		}
	}
}

sub NeededType($$$)
{
	sub NeededType($$$);
	my ($t,$needed,$req) = @_;

	NeededType($t->{DATA}, $needed, $req) if ($t->{TYPE} eq "TYPEDEF");

	return if (($t->{TYPE} ne "STRUCT") and 
			   ($t->{TYPE} ne "UNION"));

	foreach (@{$t->{ELEMENTS}}) {
		next if (has_property($_, "subcontext")); #FIXME: Support subcontexts
		my $n;
		if (ref($_->{TYPE}) ne "HASH" or defined($_->{TYPE}->{NAME})) {
			$needed->{TypeFunctionName("ejs_$req", $_->{TYPE})} = 1;
		}
		NeededType($_->{TYPE}, $needed, $req) if (ref($_->{TYPE}) eq "HASH");
	}
}

#####################################################################
# work out what parse functions are needed
sub NeededInterface($$)
{
	my ($interface,$needed) = @_;

	NeededFunction($_, $needed) foreach (@{$interface->{FUNCTIONS}});

	foreach (reverse @{$interface->{TYPES}}) {
		if (has_property($_, "public")) {
			$needed->{TypeFunctionName("ejs_pull", $_)} = not has_property($_, "noejs");
			$needed->{TypeFunctionName("ejs_push", $_)} = not has_property($_, "noejs");
		}

		NeededType($_, $needed, "pull")  if ($needed->{TypeFunctionName("ejs_pull", $_)});
		NeededType($_, $needed, "push")  if ($needed->{TypeFunctionName("ejs_push", $_)});
	}
}

sub TypeFunctionName($$)
{
	my ($prefix, $t) = @_;

	return "$prefix\_$t->{NAME}" if (ref($t) eq "HASH" and 
			($t->{TYPE} eq "TYPEDEF" or $t->{TYPE} eq "DECLARE"));
	return "$prefix\_$t->{TYPE}_$t->{NAME}" if (ref($t) eq "HASH");
	return "$prefix\_$t";
}



1;
