###################################################
# EJS function wrapper generator
# Copyright jelmer@samba.org 2005
# Copyright Andrew Tridgell 2005
# released under the GNU GPL

package Parse::Pidl::Samba4::EJS;

use strict;
use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property);

use vars qw($VERSION);
$VERSION = '0.01';

my $res;
my $res_hdr;

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

# this should probably be in ndr.pm
sub GenerateStructEnv($)
{
	my $x = shift;
	my %env;

	foreach my $e (@{$x->{ELEMENTS}}) {
		if ($e->{NAME}) {
			$env{$e->{NAME}} = "r->$e->{NAME}";
		}
	}

	$env{"this"} = "r";

	return \%env;
}

sub GenerateFunctionInEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
}

sub GenerateFunctionOutEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/out/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->out.$e->{NAME}";
		} elsif (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
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

        my $pl = Parse::Pidl::NDR::GetPrevLevel($e, $l);
        $var = get_pointer_to($var);
        # have to handle strings specially :(
        if ($e->{TYPE} eq "string" && $pl && $pl->{TYPE} eq "POINTER") {
                $var = get_pointer_to($var);
        }
	pidl "NDR_CHECK(ejs_pull_$e->{TYPE}(ejs, v, $name, $var));";
}

###########################
# pull a pointer element
sub EjsPullPointer($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "if (ejs_pull_null(ejs, v, $name)) {";
	indent;
	pidl "$var = NULL;";
	deindent;
	pidl "} else {";
	indent;
	pidl "EJS_ALLOC(ejs, $var);";
	$var = get_value_of($var);		
	EjsPullElement($e, Parse::Pidl::NDR::GetNextLevel($e, $l), $var, $name, $env);
	deindent;
	pidl "}";
}

###########################
# pull a string element
sub EjsPullString($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	$var = get_pointer_to($var);
	pidl "NDR_CHECK(ejs_pull_string(ejs, v, $name, $var));";
}


###########################
# pull an array element
sub EjsPullArray($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $nl = Parse::Pidl::NDR::GetNextLevel($e, $l);
	my $length = Parse::Pidl::Util::ParseExpr($l->{LENGTH_IS}, $env);
	my $size = Parse::Pidl::Util::ParseExpr($l->{SIZE_IS}, $env);
	my $pl = Parse::Pidl::NDR::GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	# uint8 arrays are treated as data blobs
	if ($nl->{TYPE} eq 'DATA' && $e->{TYPE} eq 'uint8') {
		if (!$l->{IS_FIXED}) {
			pidl "EJS_ALLOC_N(ejs, $var, $size);";
		}
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
	my $switch_var = Parse::Pidl::Util::ParseExpr($l->{SWITCH_IS}, $env);
	pidl "ejs_set_switch(ejs, $switch_var);";
	EjsPullElement($e, Parse::Pidl::NDR::GetNextLevel($e, $l), $var, $name, $env);
}

###########################
# pull a structure element
sub EjsPullElement($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	if (has_property($e, "charset")) {
		EjsPullString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPullArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPullScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "POINTER")) {
		EjsPullPointer($e, $l, $var, $name, $env);
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
	my $e = shift;
	my $env = shift;
	my $l = $e->{LEVELS}[0];
	my $var = Parse::Pidl::Util::ParseExpr($e->{NAME}, $env);
	my $name = "\"$e->{NAME}\"";
	EjsPullElement($e, $l, $var, $name, $env);
}

###########################
# pull a struct
sub EjsStructPull($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, struct $name *r)");
	pidl "{";
	indent;
	pidl "NDR_CHECK(ejs_pull_struct_start(ejs, &v, name));";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPullElementTop($e, $env);
	}
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

###########################
# pull a union
sub EjsUnionPull($$)
{
	my $name = shift;
	my $d = shift;
	my $have_default = 0;
	my $env = GenerateStructEnv($d);
	fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, union $name *r)");
	pidl "{";
	indent;
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
			EjsPullElementTop($e, $env);
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
	pidl "return NT_STATUS_OK;";
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
	my $name = shift;
	my $d = shift;
	EjsEnumConstant($d);
	fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, enum $name *r)");
	pidl "{";
	indent;
	pidl "unsigned e;";
	pidl "NDR_CHECK(ejs_pull_enum(ejs, v, name, &e));";
	pidl "*r = e;";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

###########################
# pull a bitmap
sub EjsBitmapPull($$)
{
	my $name = shift;
	my $d = shift;
	my $type_fn = $d->{BASE_TYPE};
	my($type_decl) = Parse::Pidl::Typelist::mapType($d->{BASE_TYPE});
	fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, $type_decl *r)");
	pidl "{";
	indent;
	pidl "return ejs_pull_$type_fn(ejs, v, name, r);";
	deindent;
	pidl "}";
}


###########################
# generate a structure pull
sub EjsTypedefPull($)
{
	my $d = shift;
	return if (has_property($d, "noejs"));
	if ($d->{DATA}->{TYPE} eq 'STRUCT') {
		EjsStructPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'UNION') {
		EjsUnionPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'ENUM') {
		EjsEnumPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'BITMAP') {
		EjsBitmapPull($d->{NAME}, $d->{DATA});
	} else {
		warn "Unhandled pull typedef $d->{NAME} of type $d->{DATA}->{TYPE}";
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
		next if (has_property($e, "length_is") || 
			 has_property($e, "size_is"));
		EjsPullElementTop($e, $env);
	}

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		next unless (has_property($e, "length_is") || 
			     has_property($e, "size_is"));
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
        # have to handle strings specially :(
        my $pl = Parse::Pidl::NDR::GetPrevLevel($e, $l);
        if ($e->{TYPE} ne "string" || ($pl && $pl->{TYPE} eq "POINTER")) {
                $var = get_pointer_to($var);
        }
	pidl "NDR_CHECK(ejs_push_$e->{TYPE}(ejs, v, $name, $var));";
}

###########################
# push a string element
sub EjsPushString($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "NDR_CHECK(ejs_push_string(ejs, v, $name, $var));";
}

###########################
# push a pointer element
sub EjsPushPointer($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "if (NULL == $var) {";
	indent;
	pidl "NDR_CHECK(ejs_push_null(ejs, v, $name));";
	deindent;
	pidl "} else {";
	indent;
	$var = get_value_of($var);		
	EjsPushElement($e, Parse::Pidl::NDR::GetNextLevel($e, $l), $var, $name, $env);
	deindent;
	pidl "}";
}

###########################
# push a switch element
sub EjsPushSwitch($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $switch_var = Parse::Pidl::Util::ParseExpr($l->{SWITCH_IS}, $env);
	pidl "ejs_set_switch(ejs, $switch_var);";
	EjsPushElement($e, Parse::Pidl::NDR::GetNextLevel($e, $l), $var, $name, $env);
}


###########################
# push an array element
sub EjsPushArray($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $nl = Parse::Pidl::NDR::GetNextLevel($e, $l);
	my $length = Parse::Pidl::Util::ParseExpr($l->{LENGTH_IS}, $env);
	my $pl = Parse::Pidl::NDR::GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	# uint8 arrays are treated as data blobs
	if ($nl->{TYPE} eq 'DATA' && $e->{TYPE} eq 'uint8') {
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
	if (has_property($e, "charset")) {
		EjsPushString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPushArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPushScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "POINTER")) {
		EjsPushPointer($e, $l, $var, $name, $env);
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
	my $e = shift;
	my $env = shift;
	my $l = $e->{LEVELS}[0];
	my $var = Parse::Pidl::Util::ParseExpr($e->{NAME}, $env);
	my $name = "\"$e->{NAME}\"";
	EjsPushElement($e, $l, $var, $name, $env);
}

###########################
# push a struct
sub EjsStructPush($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	fn_declare($d, "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const struct $name *r)");
	pidl "{";
	indent;
	pidl "NDR_CHECK(ejs_push_struct_start(ejs, &v, name));";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPushElementTop($e, $env);
	}
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

###########################
# push a union
sub EjsUnionPush($$)
{
	my $name = shift;
	my $d = shift;
	my $have_default = 0;
	my $env = GenerateStructEnv($d);
	fn_declare($d, "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const union $name *r)");
	pidl "{";
	indent;
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
			EjsPushElementTop($e, $env);
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
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}";
}

###########################
# push a enum
sub EjsEnumPush($$)
{
	my $name = shift;
	my $d = shift;
	EjsEnumConstant($d);
	fn_declare($d, "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const enum $name *r)");
	pidl "{";
	indent;
	pidl "unsigned e = *r;";
	pidl "NDR_CHECK(ejs_push_enum(ejs, v, name, &e));";
	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}

###########################
# push a bitmap
sub EjsBitmapPush($$)
{
	my $name = shift;
	my $d = shift;
	my $type_fn = $d->{BASE_TYPE};
	my($type_decl) = Parse::Pidl::Typelist::mapType($d->{BASE_TYPE});
	# put the bitmap elements in the constants array
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e =~ /^(\w*)\s*(.*)\s*$/) {
			my $bname = $1;
			my $v = $2;
			$constants{$bname} = $v;
		}
	}
	fn_declare($d, "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const $type_decl *r)");
	pidl "{";
	indent;
	pidl "return ejs_push_$type_fn(ejs, v, name, r);";
	deindent;
	pidl "}";
}


###########################
# generate a structure push
sub EjsTypedefPush($)
{
	my $d = shift;
	return if (has_property($d, "noejs"));

	if ($d->{DATA}->{TYPE} eq 'STRUCT') {
		EjsStructPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'UNION') {
		EjsUnionPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'ENUM') {
		EjsEnumPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'BITMAP') {
		EjsBitmapPush($d->{NAME}, $d->{DATA});
	} else {
		warn "Unhandled push typedef $d->{NAME} of type $d->{DATA}->{TYPE}";
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
		my $t = $d->{RETURN_TYPE};
		pidl "NDR_CHECK(ejs_push_$t(ejs, v, \"result\", &r->out.result));";
	}

	pidl "return NT_STATUS_OK;";
	deindent;
	pidl "}\n";
}


#################################
# generate a ejs mapping function
sub EjsFunction($$)
{
	my $d = shift;
	my $iface = shift;
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

	if (has_property($interface, "depends")) {
		foreach (split / /, $interface->{PROPERTIES}->{depends}) {
			pidl_hdr "#include \"librpc/gen_ndr/ndr_$_\_ejs\.h\"\n";
		}
	}

	pidl_hdr "\n";

	foreach my $d (@{$interface->{TYPES}}) {
		($needed->{"push_$d->{NAME}"}) && EjsTypedefPush($d);
		($needed->{"pull_$d->{NAME}"}) && EjsTypedefPull($d);
	}

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		next if Parse::Pidl::Util::has_property($d, "noejs");

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

    foreach my $x (@{$ndr}) {
	    ($x->{TYPE} eq "INTERFACE") && EjsInterface($x, \%needed);
    }

    return ($res_hdr, $res);
}

sub NeededFunction($$)
{
	my ($fn,$needed) = @_;
	$needed->{"pull_$fn->{NAME}"} = 1;
	$needed->{"push_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/in/, @{$e->{DIRECTION}})) {
			$needed->{"pull_$e->{TYPE}"} = 1;
		}
		if (grep (/out/, @{$e->{DIRECTION}})) {
			$needed->{"push_$e->{TYPE}"} = 1;
		}
	}
}

sub NeededTypedef($$)
{
	my ($t,$needed) = @_;
	if (Parse::Pidl::Util::has_property($t, "public")) {
		$needed->{"pull_$t->{NAME}"} = not Parse::Pidl::Util::has_property($t, "noejs");
		$needed->{"push_$t->{NAME}"} = not Parse::Pidl::Util::has_property($t, "noejs");
	}
	if ($t->{DATA}->{TYPE} ne "STRUCT" && 
	    $t->{DATA}->{TYPE} ne "UNION") {
		return;
	}
	for my $e (@{$t->{DATA}->{ELEMENTS}}) {
		if ($needed->{"pull_$t->{NAME}"}) {
			$needed->{"pull_$e->{TYPE}"} = 1;
		}
		if ($needed->{"push_$t->{NAME}"}) {
			$needed->{"push_$e->{TYPE}"} = 1;
		}
	}
}

#####################################################################
# work out what parse functions are needed
sub NeededInterface($$)
{
	my ($interface,$needed) = @_;
	foreach my $d (@{$interface->{FUNCTIONS}}) {
	    NeededFunction($d, $needed);
	}
	foreach my $d (reverse @{$interface->{TYPES}}) {
	    NeededTypedef($d, $needed);
	}
}

1;
