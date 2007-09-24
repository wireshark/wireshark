###################################################
# EJS function wrapper generator
# Copyright jelmer@samba.org 2005
# Copyright Andrew Tridgell 2005
# released under the GNU GPL

package Parse::Pidl::Samba4::EJS;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(get_pointer_to get_value_of check_null_pointer fn_declare TypeFunctionName);

use strict;
use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel);
use Parse::Pidl::Samba4::NDR::Parser qw(GenerateStructEnv GenerateFunctionInEnv
                                        GenerateFunctionOutEnv);

use vars qw($VERSION);
$VERSION = '0.01';

sub new($) {
	my ($class) = @_;
	my $self = { res => "", res_hdr => "", tabs => "", constants => {}};
	bless($self, $class);
}

sub pidl_hdr ($$)
{
	my $self = shift;
	$self->{res_hdr} .= shift;
}

sub pidl($$)
{
	my ($self, $d) = @_;
	if ($d) {
		$self->{res} .= $self->{tabs};
		$self->{res} .= $d;
	}
	$self->{res} .= "\n";
}

sub indent($)
{
	my ($self) = @_;
	$self->{tabs} .= "\t";
}

sub deindent($)
{
	my ($self) = @_;
	$self->{tabs} = substr($self->{tabs}, 0, -1);
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
sub check_null_pointer($$)
{
	my ($self, $size) = @_;
	if ($size =~ /^\*/) {
		my $size2 = substr($size, 1);
		$self->pidl("if ($size2 == NULL) return NT_STATUS_INVALID_PARAMETER_MIX;");
	}
}

#####################################################################
# work out is a parse function should be declared static or not
sub fn_declare($$$)
{
	my ($self,$fn,$decl) = @_;

	if (has_property($fn, "public")) {
		$self->pidl_hdr("$decl;\n");
		$self->pidl("_PUBLIC_ $decl");
	} else {
		$self->pidl("static $decl");
	}
}

###########################
# pull a scalar element
sub EjsPullScalar($$$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;

	return if (has_property($e, "value"));

	if (ref($e->{TYPE}) eq "HASH" and not defined($e->{TYPE}->{NAME})) {
		$self->EjsTypePull($e->{TYPE}, $var);
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
		$self->pidl("NDR_CHECK(ejs_pull_$t(ejs, v, $name, $var));");
	}
}

###########################
# pull a pointer element
sub EjsPullPointer($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	$self->pidl("if (ejs_pull_null(ejs, v, $name)) {");
	$self->indent;
	if ($l->{POINTER_TYPE} eq "ref") {
		$self->pidl("return NT_STATUS_INVALID_PARAMETER_MIX;");
	} else {
		$self->pidl("$var = NULL;");
	}
	$self->deindent;
	$self->pidl("} else {");
	$self->indent;
	$self->pidl("EJS_ALLOC(ejs, $var);");
	$var = get_value_of($var);		
	$self->EjsPullElement($e, GetNextLevel($e, $l), $var, $name, $env);
	$self->deindent;
	$self->pidl("}");
}

###########################
# pull a string element
sub EjsPullString($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	my $pl = GetPrevLevel($e, $l);
	$var = get_pointer_to($var);
	if (defined($pl) and $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	$self->pidl("NDR_CHECK(ejs_pull_string(ejs, v, $name, $var));");
}

###########################
# pull an array element
sub EjsPullArray($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
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
			$self->check_null_pointer($size);
			$self->pidl("EJS_ALLOC_N(ejs, $var, $size);");
		}
		$self->check_null_pointer($length);
		$self->pidl("ejs_pull_array_uint8(ejs, v, $name, $var, $length);");
		return;
	}
	my $avar = $var . "[i]";
	$self->pidl("{");
	$self->indent;
	$self->pidl("uint32_t i;");
	if (!$l->{IS_FIXED}) {
		$self->pidl("EJS_ALLOC_N(ejs, $var, $size);");
	}
	$self->pidl("for (i=0;i<$length;i++) {");
	$self->indent;
	$self->pidl("char *id = talloc_asprintf(ejs, \"%s.%u\", $name, i);");
	$self->EjsPullElement($e, $nl, $avar, "id", $env);
	$self->pidl("talloc_free(id);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("ejs_push_uint32(ejs, v, $name \".length\", &i);");
	$self->deindent;
	$self->pidl("}");
}

###########################
# pull a switch element
sub EjsPullSwitch($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env, $e);
	$self->pidl("ejs_set_switch(ejs, $switch_var);");
	$self->EjsPullElement($e, GetNextLevel($e, $l), $var, $name, $env);
}

###########################
# pull a structure element
sub EjsPullElement($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	if (($l->{TYPE} eq "POINTER")) {
		$self->EjsPullPointer($e, $l, $var, $name, $env);
	} elsif (has_property($e, "charset")) {
		$self->EjsPullString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		$self->EjsPullArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		$self->EjsPullScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "SWITCH")) {
		$self->EjsPullSwitch($e, $l, $var, $name, $env);
	} else {
		$self->pidl("return ejs_panic(ejs, \"unhandled pull type $l->{TYPE}\");");
	}
}

#############################################
# pull a structure/union element at top level
sub EjsPullElementTop($$$)
{
	my ($self, $e, $env) = @_;
	my $l = $e->{LEVELS}[0];
	my $var = ParseExpr($e->{NAME}, $env, $e);
	my $name = "\"$e->{NAME}\"";
	$self->EjsPullElement($e, $l, $var, $name, $env);
}

###########################
# pull a struct
sub EjsStructPull($$$)
{
	my ($self, $d, $varname) = @_;
	my $env = GenerateStructEnv($d, $varname);
	$self->pidl("NDR_CHECK(ejs_pull_struct_start(ejs, &v, name));");
    foreach my $e (@{$d->{ELEMENTS}}) {
		$self->EjsPullElementTop($e, $env);
	}
}

###########################
# pull a union
sub EjsUnionPull($$$)
{
	my ($self, $d, $varname) = @_;
	my $have_default = 0;
	$self->pidl("NDR_CHECK(ejs_pull_struct_start(ejs, &v, name));");
	$self->pidl("switch (ejs->switch_var) {");
	$self->indent;
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e->{CASE} eq "default") {
			$have_default = 1;
		}
		$self->pidl("$e->{CASE}:");
		$self->indent;
		if ($e->{TYPE} ne "EMPTY") {
			$self->EjsPullElementTop($e, { $e->{NAME} => "$varname->$e->{NAME}"});
		}
		$self->pidl("break;");
		$self->deindent;
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->indent;
		$self->pidl("return ejs_panic(ejs, \"Bad switch value\");");
		$self->deindent;
	}
	$self->deindent;
	$self->pidl("}");
}

##############################################
# put the enum elements in the constants array
sub EjsEnumConstant($$)
{
	my ($self, $d) = @_;
	my $v = 0;
	foreach my $e (@{$d->{ELEMENTS}}) {
		my $el = $e;
		chomp $el;
		if ($el =~ /^(.*)=\s*(.*)\s*$/) {
			$el = $1;
			$v = $2;
		}
		$self->{constants}->{$el} = $v;
		$v++;
	}
}

###########################
# pull a enum
sub EjsEnumPull($$$)
{
	my ($self, $d, $varname) = @_;
	$self->EjsEnumConstant($d);
	$self->pidl("unsigned e;");
	$self->pidl("NDR_CHECK(ejs_pull_enum(ejs, v, name, &e));");
	$self->pidl("*$varname = e;");
}

###########################
# pull a bitmap
sub EjsBitmapPull($$$)
{
	my ($self, $d, $varname) = @_;
	my $type_fn = $d->{BASE_TYPE};
	$self->pidl("NDR_CHECK(ejs_pull_$type_fn(ejs, v, name, $varname));");
}

sub EjsTypePullFunction($$$)
{
	sub EjsTypePullFunction($$$);
	my ($self, $d, $name) = @_;
	return if (has_property($d, "noejs"));

	if ($d->{TYPE} eq "TYPEDEF") {
		$self->EjsTypePullFunction($d->{DATA}, $name);
		return;
	}

	if ($d->{TYPE} eq "STRUCT") {
		$self->fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, struct $name *r)");
	} elsif ($d->{TYPE} eq "UNION") {
		$self->fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, union $name *r)");
	} elsif ($d->{TYPE} eq "ENUM") {
		$self->fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, enum $name *r)");
	} elsif ($d->{TYPE} eq "BITMAP") {
		my($type_decl) = Parse::Pidl::Typelist::mapTypeName($d->{BASE_TYPE});
		$self->fn_declare($d, "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, $type_decl *r)");
	}
	$self->pidl("{");
	$self->indent;

	$self->EjsTypePull($d, "r");

	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}\n");
}

sub EjsTypePull($$$)
{
	my ($self, $d, $varname) = @_;
	if ($d->{TYPE} eq 'STRUCT') {
		$self->EjsStructPull($d, $varname);
	} elsif ($d->{TYPE} eq 'UNION') {
		$self->EjsUnionPull($d, $varname);
	} elsif ($d->{TYPE} eq 'ENUM') {
		$self->EjsEnumPull($d, $varname);
	} elsif ($d->{TYPE} eq 'BITMAP') {
		$self->EjsBitmapPull($d, $varname);
	} else {
		warn "Unhandled pull $varname of type $d->{TYPE}";
	}
}

#####################
# generate a function
sub EjsPullFunction($$)
{
	my ($self, $d) = @_;
	my $env = GenerateFunctionInEnv($d);
	my $name = $d->{NAME};

	$self->pidl("\nstatic NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, struct $name *r)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("NDR_CHECK(ejs_pull_struct_start(ejs, &v, \"input\"));");

	# we pull non-array elements before array elements as arrays
	# may have length_is() or size_is() properties that depend
	# on the non-array elements
	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		next if (has_property($e, "length_is") || has_property($e, "size_is"));
		$self->EjsPullElementTop($e, $env);
	}

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		next unless (has_property($e, "length_is") || has_property($e, "size_is"));
		$self->EjsPullElementTop($e, $env);
	}

	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}\n");
}

###########################
# push a scalar element
sub EjsPushScalar($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;

	if (ref($e->{TYPE}) eq "HASH" and not defined($e->{TYPE}->{NAME})) {
		$self->EjsTypePush($e->{TYPE}, get_pointer_to($var));
	} else {
    # have to handle strings specially :(
        my $pl = GetPrevLevel($e, $l);

		if ((not Parse::Pidl::Typelist::scalar_is_reference($e->{TYPE}))
			or (defined($pl) and $pl->{TYPE} eq "POINTER")) {
					$var = get_pointer_to($var);
			}

		$self->pidl("NDR_CHECK(".TypeFunctionName("ejs_push", $e->{TYPE})."(ejs, v, $name, $var));");
	}
}

###########################
# push a string element
sub EjsPushString($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	my $pl = GetPrevLevel($e, $l);
	if (defined($pl) and $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	$self->pidl("NDR_CHECK(ejs_push_string(ejs, v, $name, $var));");
}

###########################
# push a pointer element
sub EjsPushPointer($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	$self->pidl("if (NULL == $var) {");
	$self->indent;
	if ($l->{POINTER_TYPE} eq "ref") {
		$self->pidl("return NT_STATUS_INVALID_PARAMETER_MIX;");
	} else {
		$self->pidl("NDR_CHECK(ejs_push_null(ejs, v, $name));");
	}
	$self->deindent;
	$self->pidl("} else {");
	$self->indent;
	$var = get_value_of($var);		
	$self->EjsPushElement($e, GetNextLevel($e, $l), $var, $name, $env);
	$self->deindent;
	$self->pidl("}");
}

###########################
# push a switch element
sub EjsPushSwitch($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	my $switch_var = ParseExpr($l->{SWITCH_IS}, $env, $e);
	$self->pidl("ejs_set_switch(ejs, $switch_var);");
	$self->EjsPushElement($e, GetNextLevel($e, $l), $var, $name, $env);
}

###########################
# push an array element
sub EjsPushArray($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	my $nl = GetNextLevel($e, $l);
	my $length = ParseExpr($l->{LENGTH_IS}, $env, $e);
	my $pl = GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	# uint8 arrays are treated as data blobs
	if ($nl->{TYPE} eq 'DATA' && $e->{TYPE} eq 'uint8') {
		$self->check_null_pointer($length);
		$self->pidl("ejs_push_array_uint8(ejs, v, $name, $var, $length);");
		return;
	}
	my $avar = $var . "[i]";
	$self->pidl("{");
	$self->indent;
	$self->pidl("uint32_t i;");
	$self->pidl("for (i=0;i<$length;i++) {");
	$self->indent;
	$self->pidl("const char *id = talloc_asprintf(ejs, \"%s.%u\", $name, i);");
	$self->EjsPushElement($e, $nl, $avar, "id", $env);
	$self->deindent;
	$self->pidl("}");
	$self->pidl("ejs_push_uint32(ejs, v, $name \".length\", &i);");
	$self->deindent;
	$self->pidl("}");
}

################################
# push a structure/union element
sub EjsPushElement($$$$$$)
{
	my ($self, $e, $l, $var, $name, $env) = @_;
	if (($l->{TYPE} eq "POINTER")) {
		$self->EjsPushPointer($e, $l, $var, $name, $env);
	} elsif (has_property($e, "charset")) {
		$self->EjsPushString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		$self->EjsPushArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		$self->EjsPushScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "SWITCH")) {
		$self->EjsPushSwitch($e, $l, $var, $name, $env);
	} else {
		$self->pidl("return ejs_panic(ejs, \"unhandled push type $l->{TYPE}\");");
	}
}

#############################################
# push a structure/union element at top level
sub EjsPushElementTop($$$)
{
	my ($self, $e, $env) = @_;
	my $l = $e->{LEVELS}[0];
	my $var = ParseExpr($e->{NAME}, $env, $e);
	my $name = "\"$e->{NAME}\"";
	$self->EjsPushElement($e, $l, $var, $name, $env);
}

###########################
# push a struct
sub EjsStructPush($$$)
{
	my ($self, $d, $varname) = @_;
	my $env = GenerateStructEnv($d, $varname);
	$self->pidl("NDR_CHECK(ejs_push_struct_start(ejs, &v, name));");
        foreach my $e (@{$d->{ELEMENTS}}) {
		$self->EjsPushElementTop($e, $env);
	}
}

###########################
# push a union
sub EjsUnionPush($$$)
{
	my ($self, $d, $varname) = @_;
	my $have_default = 0;
	$self->pidl("NDR_CHECK(ejs_push_struct_start(ejs, &v, name));");
	$self->pidl("switch (ejs->switch_var) {");
	$self->indent;
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e->{CASE} eq "default") {
			$have_default = 1;
		}
		$self->pidl("$e->{CASE}:");
		$self->indent;
		if ($e->{TYPE} ne "EMPTY") {
			$self->EjsPushElementTop($e, { $e->{NAME} => "$varname->$e->{NAME}"} );
		}
		$self->pidl("break;");
		$self->deindent;
	}
	if (! $have_default) {
		$self->pidl("default:");
		$self->indent;
		$self->pidl("return ejs_panic(ejs, \"Bad switch value\");");
		$self->deindent;
	}
	$self->deindent;
	$self->pidl("}");
}

###########################
# push a enum
sub EjsEnumPush($$$)
{
	my ($self, $d, $varname) = @_;
	$self->EjsEnumConstant($d);
	$self->pidl("unsigned e = ".get_value_of($varname).";");
	$self->pidl("NDR_CHECK(ejs_push_enum(ejs, v, name, &e));");
}

###########################
# push a bitmap
sub EjsBitmapPush($$$)
{
	my ($self, $d, $varname) = @_;
	my $type_fn = $d->{BASE_TYPE};
	# put the bitmap elements in the constants array
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e =~ /^(\w*)\s*(.*)\s*$/) {
			my $bname = $1;
			my $v = $2;
			$self->{constants}->{$bname} = $v;
		}
	}
	$self->pidl("NDR_CHECK(ejs_push_$type_fn(ejs, v, name, $varname));");
}

sub EjsTypePushFunction($$$)
{
	sub EjsTypePushFunction($$$);
	my ($self, $d, $name) = @_;
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
	$self->fn_declare($d, "NTSTATUS ".TypeFunctionName("ejs_push", $d) . "(struct ejs_rpc *ejs, struct MprVar *v, const char *name, $var)");
	$self->pidl("{");
	$self->indent;
	$self->EjsTypePush($d, "r");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}\n");
}

sub EjsTypePush($$$)
{
	sub EjsTypePush($$$);
	my ($self, $d, $varname) = @_;

	if ($d->{TYPE} eq 'STRUCT') {
		$self->EjsStructPush($d, $varname);
	} elsif ($d->{TYPE} eq 'UNION') {
		$self->EjsUnionPush($d, $varname);
	} elsif ($d->{TYPE} eq 'ENUM') {
		$self->EjsEnumPush($d, $varname);
	} elsif ($d->{TYPE} eq 'BITMAP') {
		$self->EjsBitmapPush($d, $varname);
	} elsif ($d->{TYPE} eq 'TYPEDEF') {
		$self->EjsTypePush($d->{DATA}, $varname);
	} else {
		warn "Unhandled push $varname of type $d->{TYPE}";
	}
}

#####################
# generate a function
sub EjsPushFunction($$)
{
	my ($self, $d) = @_;
	my $env = GenerateFunctionOutEnv($d);

	$self->pidl("\nstatic NTSTATUS ejs_push_$d->{NAME}(struct ejs_rpc *ejs, struct MprVar *v, const struct $d->{NAME} *r)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("NDR_CHECK(ejs_push_struct_start(ejs, &v, \"output\"));");

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));
		$self->EjsPushElementTop($e, $env);
	}

	if ($d->{RETURN_TYPE}) {
		$self->pidl("NDR_CHECK(".TypeFunctionName("ejs_push", $d->{RETURN_TYPE})."(ejs, v, \"result\", &r->out.result));");
	}

	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}\n");
}

#################################
# generate a ejs mapping function
sub EjsFunction($$$)
{
	my ($self, $d, $iface) = @_;
	my $name = $d->{NAME};
	my $callnum = uc("NDR_$name");
	my $table = "&ndr_table_$iface";

	$self->pidl("static int ejs_$name(int eid, int argc, struct MprVar **argv)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return ejs_rpc_call(eid, argc, argv, $table, $callnum, (ejs_pull_function_t)ejs_pull_$name, (ejs_push_function_t)ejs_push_$name);");
	$self->deindent;
	$self->pidl("}\n");
}

###################
# handle a constant
sub EjsConst($$)
{
    my ($self, $const) = @_;
    $self->{constants}->{$const->{NAME}} = $const->{VALUE};
}

sub EjsImport
{
	my $self = shift;
	my @imports = @_;
	foreach (@imports) {
		s/\.idl\"$//;
		s/^\"//;
		$self->pidl_hdr("#include \"librpc/gen_ndr/ndr_$_\_ejs\.h\"\n");
	}
}

#####################################################################
# parse the interface definitions
sub EjsInterface($$$)
{
	my($self,$interface,$needed) = @_;
	my @fns = ();
	my $name = $interface->{NAME};

	$self->pidl_hdr("#ifndef _HEADER_EJS_$interface->{NAME}\n");
	$self->pidl_hdr("#define _HEADER_EJS_$interface->{NAME}\n\n");

	$self->pidl_hdr("\n");

	foreach my $d (@{$interface->{TYPES}}) {
		($needed->{TypeFunctionName("ejs_push", $d)}) && $self->EjsTypePushFunction($d, $d->{NAME});
		($needed->{TypeFunctionName("ejs_pull", $d)}) && $self->EjsTypePullFunction($d, $d->{NAME});
	}

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		next if has_property($d, "noejs");

		$self->EjsPullFunction($d);
		$self->EjsPushFunction($d);
		$self->EjsFunction($d, $name);

		push (@fns, $d->{NAME});
	}

	foreach my $d (@{$interface->{CONSTS}}) {
		$self->EjsConst($d);
	}

	$self->pidl("static int ejs_$name\_init(int eid, int argc, struct MprVar **argv)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("struct MprVar *obj = mprInitObject(eid, \"$name\", argc, argv);");
	foreach (@fns) {
		$self->pidl("mprSetCFunction(obj, \"$_\", ejs_$_);");
	}
	foreach my $v (keys %{$self->{constants}}) {
		my $value = $self->{constants}->{$v};
		if (substr($value, 0, 1) eq "\"") {
			$self->pidl("mprSetVar(obj, \"$v\", mprString($value));");
		} else {
			$self->pidl("mprSetVar(obj, \"$v\", mprCreateNumberVar($value));");
		}
	}
	$self->pidl("return ejs_rpc_init(obj, \"$name\");");
	$self->deindent;
	$self->pidl("}\n");

	$self->pidl("NTSTATUS ejs_init_$name(void)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("ejsDefineCFunction(-1, \"$name\_init\", ejs_$name\_init, NULL, MPR_VAR_SCRIPT_HANDLE);");
	$self->pidl("return NT_STATUS_OK;");
	$self->deindent;
	$self->pidl("}");

	$self->pidl_hdr("\n");
	$self->pidl_hdr("#endif /* _HEADER_EJS_$interface->{NAME} */\n");
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($$$)
{
    my($self,$ndr,$hdr) = @_;
    
    my $ejs_hdr = $hdr;
    $ejs_hdr =~ s/.h$/_ejs.h/;

    $self->pidl_hdr("/* header auto-generated by pidl */\n\n");
	
    $self->pidl("
/* EJS wrapper functions auto-generated by pidl */
#include \"includes.h\"
#include \"librpc/rpc/dcerpc.h\"
#include \"lib/appweb/ejs/ejs.h\"
#include \"scripting/ejs/ejsrpc.h\"
#include \"scripting/ejs/smbcalls.h\"
#include \"librpc/gen_ndr/ndr_misc_ejs.h\"
#include \"$hdr\"
#include \"$ejs_hdr\"

");

    my %needed = ();

    foreach my $x (@{$ndr}) {
	    ($x->{TYPE} eq "INTERFACE") && NeededInterface($x, \%needed);
    }

    foreach my $x (@$ndr) {
	    ($x->{TYPE} eq "INTERFACE") && $self->EjsInterface($x, \%needed);
		($x->{TYPE} eq "IMPORT") && $self->EjsImport(@{$x->{PATHS}});
    }

    return ($self->{res_hdr}, $self->{res});
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
