###################################################
# Python function wrapper generator
# Copyright jelmer@samba.org 2007-2008
# released under the GNU GPL

package Parse::Pidl::Samba4::Python;
use parent Parse::Pidl::Base;

use strict;
use warnings;
use Parse::Pidl qw(warning fatal error);
use Parse::Pidl::Typelist qw(hasType resolveType getType mapTypeName expandAlias bitmap_type_fn enum_type_fn);
use Parse::Pidl::Util qw(has_property ParseExpr unmake_str);
use Parse::Pidl::NDR qw(ReturnTypeElement GetPrevLevel GetNextLevel ContainsDeferred ContainsPipe is_charset_array);
use Parse::Pidl::CUtil qw(get_value_of get_pointer_to);
use Parse::Pidl::Samba4 qw(ArrayDynamicallyAllocated);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv EnvSubstituteValue GenerateStructEnv);


use vars qw($VERSION);
$VERSION = '0.01';

sub new($) {
	my ($class) = @_;
	my $self = { res => "", res_hdr => "", tabs => "",
				 constants => [], constants_uniq => {},
				 module_methods => [],
				 module_objects => [], module_objects_uniq => {},
				 ready_types => [],
				 module_imports => [], module_imports_uniq => {},
				 type_imports => [], type_imports_uniq => {},
				 patch_type_calls => [], prereadycode => [],
			 	 postreadycode => []};
	bless($self, $class);
}

sub PrettifyTypeName($$)
{
	my ($name, $basename) = @_;

	$basename =~ s/^.*\.([^.]+)$/$1/;

	$name =~ s/^$basename\_//;


	return $name;
}

sub Import
{
	my $self = shift;
	my @imports = @_;
	foreach (@imports) {
		$_ = unmake_str($_);
		s/\.idl$//;
		$self->pidl_hdr("#include \"librpc/gen_ndr/$_\.h\"");
		$self->register_module_import("samba.dcerpc.$_");
	}
}

sub Const($$)
{
    my ($self, $const) = @_;
	$self->register_constant($const->{NAME}, $const->{DTYPE}, $const->{VALUE});
}

sub register_constant($$$$)
{
	my ($self, $name, $type, $value) = @_;

	unless (defined $self->{constants_uniq}->{$name}) {
		my $h = {"key" => $name, "val" => [$type, $value]};
		push @{$self->{constants}}, $h;
		$self->{constants_uniq}->{$name} = $h;
	}
}

sub EnumAndBitmapConsts($$$)
{
	my ($self, $name, $d) = @_;

	return unless (defined($d->{ELEMENTS}));

	foreach my $e (@{$d->{ELEMENTS}}) {
		$e =~ /^([A-Za-z0-9_]+)/;
		my $cname = $1;

		$self->register_constant($cname, $d, $cname);
	}
}

sub FromUnionToPythonFunction($$$$)
{
	my ($self, $mem_ctx, $type, $switch, $name) = @_;

	$self->pidl("PyObject *ret;");
	$self->pidl("");

	$self->pidl("switch ($switch) {");
	$self->indent;

	foreach my $e (@{$type->{ELEMENTS}}) {
		$self->pidl("$e->{CASE}:");

		$self->indent;

		if ($e->{NAME}) {
			$self->ConvertObjectToPython($mem_ctx, {}, $e, "$name->$e->{NAME}", "ret", "return NULL;");
		} else {
			$self->pidl("ret = Py_None;");
			$self->pidl("Py_INCREF(ret);");
		}

		$self->pidl("return ret;");
		$self->pidl("");

		$self->deindent;
	}

	$self->deindent;
	$self->pidl("}");

	$self->pidl("PyErr_SetString(PyExc_TypeError, \"unknown union level\");");
	$self->pidl("return NULL;");
}

sub FromPythonToUnionFunction($$$$$)
{
	my ($self, $type, $typename, $switch, $mem_ctx, $name) = @_;

	my $has_default = 0;

	$self->pidl("$typename *ret = talloc_zero($mem_ctx, $typename);");

	$self->pidl("switch ($switch) {");
	$self->indent;

	foreach my $e (@{$type->{ELEMENTS}}) {
		$self->pidl("$e->{CASE}:");
		if ($e->{CASE} eq "default") { $has_default = 1; }
		$self->indent;
		if ($e->{NAME}) {
			$self->ConvertObjectFromPython({}, $mem_ctx, $e, $name, "ret->$e->{NAME}", "talloc_free(ret); return NULL;");
		}
		$self->pidl("break;");
		$self->deindent;
		$self->pidl("");
	}

	if (!$has_default) {
		$self->pidl("default:");
		$self->indent;
		$self->pidl("PyErr_SetString(PyExc_TypeError, \"invalid union level value\");");
		$self->pidl("talloc_free(ret);");
		$self->pidl("ret = NULL;");
		$self->deindent;
	}

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return ret;");
}

sub PythonElementGetSet($$$$$$) {
	my ($self, $name, $cname, $ename, $e, $env) = @_;

	my $varname = "object->$ename";
	$self->pidl("static PyObject *py_$name\_get_$e->{NAME}(PyObject *obj, void *closure)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$cname *object = pytalloc_get_ptr(obj);");
	$self->pidl("PyObject *py_$e->{NAME};");
	my $l = $e->{LEVELS}[0];
	if ($l->{TYPE} eq "POINTER") {
		$self->pidl("if ($varname == NULL) {");
		$self->indent;
		$self->pidl("Py_RETURN_NONE;");
		$self->deindent;
		$self->pidl("}");
	}
	$self->ConvertObjectToPython("pytalloc_get_mem_ctx(obj)", $env, $e, $varname, "py_$e->{NAME}", "return NULL;");
	$self->pidl("return py_$e->{NAME};");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static int py_$name\_set_$e->{NAME}(PyObject *py_obj, PyObject *value, void *closure)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$cname *object = pytalloc_get_ptr(py_obj);");
	my $mem_ctx = "pytalloc_get_mem_ctx(py_obj)";
	my $nl = GetNextLevel($e, $l);
	if ($l->{TYPE} eq "POINTER" and
		not ($nl->{TYPE} eq "ARRAY" and ($nl->{IS_FIXED} or is_charset_array($e, $nl))) and
		not ($nl->{TYPE} eq "DATA" and Parse::Pidl::Typelist::scalar_is_reference($nl->{DATA_TYPE}))) {
		$self->pidl("talloc_unlink($mem_ctx, discard_const($varname));");
	}
	$self->ConvertObjectFromPython($env, $mem_ctx, $e, "value", $varname, "return -1;");
	$self->pidl("return 0;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub PythonStruct($$$$$$)
{
	my ($self, $modulename, $prettyname, $name, $cname, $d) = @_;

	my $env = GenerateStructEnv($d, "object");

	$self->pidl("");

	my $getsetters = "NULL";

	if ($#{$d->{ELEMENTS}} > -1) {
		foreach my $e (@{$d->{ELEMENTS}}) {
			$self->PythonElementGetSet($name, $cname, $e->{NAME}, $e, $env);
		}

		$getsetters = "py_$name\_getsetters";
		$self->pidl("static PyGetSetDef ".$getsetters."[] = {");
		$self->indent;
		foreach my $e (@{$d->{ELEMENTS}}) {
			my $etype = "";
			if (ref($e->{TYPE}) eq "HASH") {
				$etype = $e->{TYPE}->{NAME};
			} else {
				$etype = $e->{TYPE};
			}
			$self->pidl("{");
			$self->indent;
			$self->pidl(".name = discard_const_p(char, \"$e->{NAME}\"),");
			$self->pidl(".get = py_$name\_get_$e->{NAME},");
			$self->pidl(".set = py_$name\_set_$e->{NAME},");
			$self->pidl(".doc = discard_const_p(char, \"PIDL-generated element of base type $etype\")");
			$self->deindent;
			$self->pidl("},");
		}
		$self->pidl("{ .name = NULL }");
		$self->deindent;
		$self->pidl("};");
		$self->pidl("");
	}

	$self->pidl("static PyObject *py_$name\_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return pytalloc_new($cname, type);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	my $py_methods = "NULL";

	# If the struct is not public there ndr_pull/ndr_push functions will
	# be static so not callable from here
	if (has_property($d, "public")) {
		$self->pidl("static PyObject *py_$name\_ndr_pack(PyObject *py_obj,  PyObject *Py_UNUSED(ignored))");
		$self->pidl("{");
		$self->indent;
		$self->pidl("$cname *object = pytalloc_get_ptr(py_obj);");
		$self->pidl("PyObject *ret = NULL;");
		$self->pidl("DATA_BLOB blob;");
		$self->pidl("enum ndr_err_code err;");
		$self->pidl("TALLOC_CTX *tmp_ctx = talloc_new(pytalloc_get_mem_ctx(py_obj));");
		$self->pidl("if (tmp_ctx == NULL) {");
		$self->indent;
		$self->pidl("PyErr_SetNdrError(NDR_ERR_ALLOC);");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("err = ndr_push_struct_blob(&blob, tmp_ctx, object, (ndr_push_flags_fn_t)ndr_push_$name);");
		$self->pidl("if (!NDR_ERR_CODE_IS_SUCCESS(err)) {");
		$self->indent;
		$self->pidl("TALLOC_FREE(tmp_ctx);");
		$self->pidl("PyErr_SetNdrError(err);");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("ret = PyBytes_FromStringAndSize((char *)blob.data, blob.length);");
		$self->pidl("TALLOC_FREE(tmp_ctx);");
		$self->pidl("return ret;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl("static PyObject *py_$name\_ndr_unpack(PyObject *py_obj, PyObject *args, PyObject *kwargs)");
		$self->pidl("{");
		$self->indent;
		$self->pidl("$cname *object = pytalloc_get_ptr(py_obj);");
		$self->pidl("DATA_BLOB blob = {.data = NULL, .length = 0};");
		$self->pidl("Py_ssize_t blob_length = 0;");
		$self->pidl("enum ndr_err_code err;");
		$self->pidl("const char * const kwnames[] = { \"data_blob\", \"allow_remaining\", NULL };");
		$self->pidl("PyObject *allow_remaining_obj = NULL;");
		$self->pidl("bool allow_remaining = false;");
		$self->pidl("");
		$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, PYARG_BYTES_LEN \"|O:__ndr_unpack__\",");
		$self->indent;
		$self->pidl("discard_const_p(char *, kwnames),");
		$self->pidl("&blob.data, &blob_length,");
		$self->pidl("&allow_remaining_obj)) {");
		$self->deindent;
		$self->indent;
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("blob.length = blob_length;");
		$self->pidl("");
		$self->pidl("if (allow_remaining_obj && PyObject_IsTrue(allow_remaining_obj)) {");
		$self->indent;
		$self->pidl("allow_remaining = true;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("if (allow_remaining) {");
		$self->indent;
		$self->pidl("err = ndr_pull_struct_blob(&blob, pytalloc_get_mem_ctx(py_obj), object, (ndr_pull_flags_fn_t)ndr_pull_$name);");
		$self->deindent;
		$self->pidl("} else {");
		$self->indent;
		$self->pidl("err = ndr_pull_struct_blob_all(&blob, pytalloc_get_mem_ctx(py_obj), object, (ndr_pull_flags_fn_t)ndr_pull_$name);");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("if (!NDR_ERR_CODE_IS_SUCCESS(err)) {");
		$self->indent;
		$self->pidl("PyErr_SetNdrError(err);");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("Py_RETURN_NONE;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl("static PyObject *py_$name\_ndr_print(PyObject *py_obj, PyObject *Py_UNUSED(ignored))");
		$self->pidl("{");
		$self->indent;
		$self->pidl("$cname *object = pytalloc_get_ptr(py_obj);");
		$self->pidl("PyObject *ret;");
		$self->pidl("char *retstr;");
		$self->pidl("");
		$self->pidl("retstr = ndr_print_struct_string(pytalloc_get_mem_ctx(py_obj), (ndr_print_fn_t)ndr_print_$name, \"$name\", object);");
		$self->pidl("ret = PyUnicode_FromString(retstr);");
		$self->pidl("talloc_free(retstr);");
		$self->pidl("");
		$self->pidl("return ret;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$py_methods = "py_$name\_methods";
		$self->pidl("static PyMethodDef $py_methods\[] = {");
		$self->indent;
		$self->pidl("{ \"__ndr_pack__\", (PyCFunction)py_$name\_ndr_pack, METH_NOARGS, \"S.ndr_pack(object) -> blob\\nNDR pack\" },");
		$self->pidl("{ \"__ndr_unpack__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$name\_ndr_unpack), METH_VARARGS|METH_KEYWORDS, \"S.ndr_unpack(class, blob, allow_remaining=False) -> None\\nNDR unpack\" },");
		$self->pidl("{ \"__ndr_print__\", (PyCFunction)py_$name\_ndr_print, METH_NOARGS, \"S.ndr_print(object) -> None\\nNDR print\" },");
		$self->pidl("{ NULL, NULL, 0, NULL }");
		$self->deindent;
		$self->pidl("};");
		$self->pidl("");
	}

	$self->pidl_hdr("static PyTypeObject $name\_Type;");
	$self->pidl("");
	my $docstring = $self->DocString($d, $name);
	my $typeobject = "$name\_Type";
	$self->pidl("static PyTypeObject $typeobject = {");
	$self->indent;
	$self->pidl("PyVarObject_HEAD_INIT(NULL, 0)");
	$self->pidl(".tp_name = \"$modulename.$prettyname\",");
	$self->pidl(".tp_getset = $getsetters,");
	if ($docstring) {
		$self->pidl(".tp_doc = $docstring,");
	}
	$self->pidl(".tp_methods = $py_methods,");
	$self->pidl(".tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,");
	$self->pidl(".tp_new = py_$name\_new,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	my $talloc_typename = $self->import_type_variable("talloc", "BaseObject");
	$self->register_module_prereadycode(["$name\_Type.tp_base = $talloc_typename;",
					     "$name\_Type.tp_basicsize = pytalloc_BaseObject_size();",
					     ""]);

	return "&$typeobject";
}

sub PythonFunctionStruct($$$$)
{
	my ($self, $modulename, $fn, $iface, $prettyname) = @_;

	my $inenv = GenerateFunctionInEnv($fn, "object->");
	my $outenv = GenerateFunctionOutEnv($fn, "object->");

	my $name = "$fn->{NAME}";
	my $cname = "struct $name";

	$self->pidl("");

	my $getsetters = "NULL";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			my $inname = "$name\_in";
			my $ename = "in.$e->{NAME}";
			$self->PythonElementGetSet($inname, $cname, $ename, $e, $inenv);
		}
		if (grep(/out/,@{$e->{DIRECTION}})) {
			my $outname = "$name\_out";
			my $ename = "out.$e->{NAME}";
			$self->PythonElementGetSet($outname, $cname, $ename, $e, $outenv);
		}
	}

	if (defined($fn->{RETURN_TYPE})) {
		my $e = ReturnTypeElement($fn);
		my $ename = "out.result";
		$self->PythonElementGetSet($name, $cname, $ename, $e, $outenv);
	}

	$getsetters = "py_$name\_getsetters";
	$self->pidl("static PyGetSetDef ".$getsetters."[] = {");
	$self->indent;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->pidl("{");
			$self->indent;
			$self->pidl(".name = discard_const_p(char, \"in_$e->{NAME}\"),");
			$self->pidl(".get = py_$name\_in_get_$e->{NAME},");
			$self->pidl(".set = py_$name\_in_set_$e->{NAME},");
			$self->pidl(".doc = discard_const_p(char, \"PIDL-generated element of base type $e->{TYPE}\")");
			$self->deindent;
			$self->pidl("},");
		}
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->pidl("{");
			$self->indent;
			$self->pidl(".name = discard_const_p(char, \"out_$e->{NAME}\"),");
			$self->pidl(".get = py_$name\_out_get_$e->{NAME},");
			$self->pidl(".set = py_$name\_out_set_$e->{NAME},");
			$self->pidl(".doc = discard_const_p(char, \"PIDL-generated element of base type $e->{TYPE}\")");
			$self->deindent;
			$self->pidl("},");
		}
	}
	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl("{");
		$self->indent;
		$self->pidl(".name = discard_const_p(char, \"result\"),");
		$self->pidl(".get = py_$name\_get_result,");
		$self->pidl(".set = py_$name\_set_result,");
		$self->pidl(".doc = discard_const_p(char, \"PIDL-generated element of type $fn->{RETURN_TYPE}\")");
		$self->deindent;
		$self->pidl("},");
	}
	$self->pidl("{ .name = NULL }");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;

	# This creates a new, zeroed C structure and python object.
	# These may not be valid or sensible values, but this is as
	# well as we can do.

	$self->pidl("PyObject *self = pytalloc_new($cname, type);");

	# If there are any children that are ref pointers, we need to
	# allocate something for them to point to just as the pull
	# routine will when parsing the structure from NDR.
	#
	# We then make those pointers point to zeroed memory
	#
	# A ref pointer is a pointer in the C structure but a scalar
	# on the wire. It is for a remote function like:
	#
	# int foo(int *i)
	#
	# This may be called with the pointer by reference eg foo(&i)
	#
	# That is why this only goes as far as the next level; deeply
	# nested pointer chains will end in a NULL.

	my @ref_elements;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (has_property($e, "ref") && ! has_property($e, "charset")) {
			if (!has_property($e, 'in') && !has_property($e, 'out')) {
				die "ref pointer that is not in or out";
			}
			push @ref_elements, $e;
		}
	}
	if (@ref_elements) {
		$self->pidl("$cname *_self = ($cname *)pytalloc_get_ptr(self);");
		$self->pidl("TALLOC_CTX *mem_ctx = pytalloc_get_mem_ctx(self);");
		foreach my $e (@ref_elements) {
			my $ename = $e->{NAME};
			my $t = mapTypeName($e->{TYPE});
			my $p = $e->{ORIGINAL}->{POINTERS} // 1;
			if ($p > 1) {
				$self->pidl("/* a pointer to a NULL pointer */");
				$t .= ' ' . '*' x ($p - 1);
			}

			# We checked in the loop above that each ref
			# pointer is in or out (or both)
			if (has_property($e, 'in')) {
				$self->pidl("_self->in.$ename = talloc_zero(mem_ctx, $t);");
			}

			if (has_property($e, 'out')) {
				$self->pidl("_self->out.$ename = talloc_zero(mem_ctx, $t);");
			}
		}
	}
	$self->pidl("return self;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	my $py_methods = "NULL";

	my $ndr_call = "const struct ndr_interface_call *call = NULL;";
	my $object_ptr = "$cname *object = pytalloc_get_ptr(py_obj);";

	$self->pidl("static PyObject *py_$name\_ndr_opnum(PyTypeObject *type, PyObject *Py_UNUSED(ignored))");
	$self->pidl("{");
	$self->indent;
	$self->pidl("");
	$self->pidl("");
	$self->pidl("return PyLong_FromLong($fn->{OPNUM});");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_pack(PyObject *py_obj, ndr_flags_type ndr_inout_flags, libndr_flags ndr_push_flags)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$ndr_call");
	$self->pidl("$object_ptr");
	$self->pidl("PyObject *ret = NULL;");
	$self->pidl("struct ndr_push *push = NULL;");
	$self->pidl("DATA_BLOB blob;");
	$self->pidl("enum ndr_err_code err;");
	$self->pidl("");
	$self->pidl("if (ndr_table_$iface\.num_calls < " . ($fn->{OPNUM}+1) .
		    ") {");
	$self->indent;
	$self->pidl("PyErr_SetString(PyExc_TypeError, \"Internal Error, ndr_interface_call missing for py_$name\_ndr_pack\");");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("call = &ndr_table_$iface\.calls[$fn->{OPNUM}];");
	$self->pidl("");
	$self->pidl("push = ndr_push_init_ctx(pytalloc_get_mem_ctx(py_obj));");
	$self->pidl("if (push == NULL) {");
	$self->indent;
	$self->pidl("PyErr_SetNdrError(NDR_ERR_ALLOC);");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("push->flags |= ndr_push_flags;");
	$self->pidl("");
	$self->pidl("err = call->ndr_push(push, ndr_inout_flags, object);");
	$self->pidl("if (!NDR_ERR_CODE_IS_SUCCESS(err)) {");
	$self->indent;
	$self->pidl("TALLOC_FREE(push);");
	$self->pidl("PyErr_SetNdrError(err);");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("blob = ndr_push_blob(push);");
	$self->pidl("ret = PyBytes_FromStringAndSize((char *)blob.data, blob.length);");
	$self->pidl("TALLOC_FREE(push);");
	$self->pidl("return ret;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_pack_in(PyObject *py_obj, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("const char * const kwnames[] = { \"bigendian\", \"ndr64\", NULL };");
	$self->pidl("PyObject *bigendian_obj = NULL;");
	$self->pidl("PyObject *ndr64_obj = NULL;");
	$self->pidl("libndr_flags ndr_push_flags = 0;");
	$self->pidl("");
	$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, \"|OO:__ndr_pack_in__\",");
	$self->indent;
	$self->pidl("discard_const_p(char *, kwnames),");
	$self->pidl("&bigendian_obj,");
	$self->pidl("&ndr64_obj)) {");
	$self->deindent;
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("if (bigendian_obj && PyObject_IsTrue(bigendian_obj)) {");
	$self->indent;
	$self->pidl("ndr_push_flags |= LIBNDR_FLAG_BIGENDIAN;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (ndr64_obj && PyObject_IsTrue(ndr64_obj)) {");
	$self->indent;
	$self->pidl("ndr_push_flags |= LIBNDR_FLAG_NDR64;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return py_$name\_ndr_pack(py_obj, NDR_IN, ndr_push_flags);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_pack_out(PyObject *py_obj, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("const char * const kwnames[] = { \"bigendian\", \"ndr64\", NULL };");
	$self->pidl("PyObject *bigendian_obj = NULL;");
	$self->pidl("PyObject *ndr64_obj = NULL;");
	$self->pidl("libndr_flags ndr_push_flags = 0;");
	$self->pidl("");
	$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, \"|OO:__ndr_pack_out__\",");
	$self->indent;
	$self->pidl("discard_const_p(char *, kwnames),");
	$self->pidl("&bigendian_obj,");
	$self->pidl("&ndr64_obj)) {");
	$self->deindent;
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("if (bigendian_obj && PyObject_IsTrue(bigendian_obj)) {");
	$self->indent;
	$self->pidl("ndr_push_flags |= LIBNDR_FLAG_BIGENDIAN;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (ndr64_obj && PyObject_IsTrue(ndr64_obj)) {");
	$self->indent;
	$self->pidl("ndr_push_flags |= LIBNDR_FLAG_NDR64;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return py_$name\_ndr_pack(py_obj, NDR_OUT, ndr_push_flags);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_unpack(PyObject *py_obj, const DATA_BLOB *blob, ndr_flags_type ndr_inout_flags, libndr_flags ndr_pull_flags, bool allow_remaining)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$ndr_call");
	$self->pidl("$object_ptr");
	$self->pidl("struct ndr_pull *pull = NULL;");
	$self->pidl("enum ndr_err_code err;");
	$self->pidl("");
	$self->pidl("if (ndr_table_$iface\.num_calls < " . ($fn->{OPNUM}+1) .
		    ") {");
	$self->indent;
	$self->pidl("PyErr_SetString(PyExc_TypeError, \"Internal Error, ndr_interface_call missing for py_$name\_ndr_unpack\");");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("call = &ndr_table_$iface\.calls[$fn->{OPNUM}];");
	$self->pidl("");
	$self->pidl("pull = ndr_pull_init_blob(blob, object);");
	$self->pidl("if (pull == NULL) {");
	$self->indent;
	$self->pidl("PyErr_SetNdrError(NDR_ERR_ALLOC);");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("pull->flags |= ndr_pull_flags;");
	$self->pidl("");
	$self->pidl("err = call->ndr_pull(pull, ndr_inout_flags, object);");
	$self->pidl("if (!NDR_ERR_CODE_IS_SUCCESS(err)) {");
	$self->indent;
	$self->pidl("TALLOC_FREE(pull);");
	$self->pidl("PyErr_SetNdrError(err);");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (!allow_remaining) {");
	$self->indent;
	$self->pidl("uint32_t highest_ofs;");
	$self->pidl("");
	$self->pidl("if (pull->offset > pull->relative_highest_offset) {");
	$self->indent;
	$self->pidl("highest_ofs = pull->offset;");
	$self->deindent;
	$self->pidl("} else {");
	$self->indent;
	$self->pidl("highest_ofs = pull->relative_highest_offset;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (highest_ofs < pull->data_size) {");
	$self->indent;
	$self->pidl("err = ndr_pull_error(pull, NDR_ERR_UNREAD_BYTES,");
	$self->indent;
	$self->pidl("\"not all bytes consumed ofs[%u] size[%u]\",");
	$self->pidl("highest_ofs, pull->data_size);");
	$self->deindent;
	$self->pidl("TALLOC_FREE(pull);");
	$self->pidl("PyErr_SetNdrError(err);");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("TALLOC_FREE(pull);");
	$self->pidl("Py_RETURN_NONE;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_unpack_in(PyObject *py_obj, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("DATA_BLOB blob;");
	$self->pidl("Py_ssize_t blob_length = 0;");
	$self->pidl("const char * const kwnames[] = { \"data_blob\", \"bigendian\", \"ndr64\", \"allow_remaining\", NULL };");
	$self->pidl("PyObject *bigendian_obj = NULL;");
	$self->pidl("PyObject *ndr64_obj = NULL;");
	$self->pidl("libndr_flags ndr_pull_flags = LIBNDR_FLAG_REF_ALLOC;");
	$self->pidl("PyObject *allow_remaining_obj = NULL;");
	$self->pidl("bool allow_remaining = false;");
	$self->pidl("");
	$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, PYARG_BYTES_LEN \"|OOO:__ndr_unpack_in__\",");
	$self->indent;
	$self->pidl("discard_const_p(char *, kwnames),");
	$self->pidl("&blob.data, &blob_length,");
	$self->pidl("&bigendian_obj,");
	$self->pidl("&ndr64_obj,");
	$self->pidl("&allow_remaining_obj)) {");
	$self->deindent;
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("blob.length = blob_length;");
	$self->pidl("");
	$self->pidl("if (bigendian_obj && PyObject_IsTrue(bigendian_obj)) {");
	$self->indent;
	$self->pidl("ndr_pull_flags |= LIBNDR_FLAG_BIGENDIAN;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (ndr64_obj && PyObject_IsTrue(ndr64_obj)) {");
	$self->indent;
	$self->pidl("ndr_pull_flags |= LIBNDR_FLAG_NDR64;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("if (allow_remaining_obj && PyObject_IsTrue(allow_remaining_obj)) {");
	$self->indent;
	$self->pidl("allow_remaining = true;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return py_$name\_ndr_unpack(py_obj, &blob, NDR_IN, ndr_pull_flags, allow_remaining);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_unpack_out(PyObject *py_obj, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("DATA_BLOB blob;");
	$self->pidl("Py_ssize_t blob_length = 0;");
	$self->pidl("const char * const kwnames[] = { \"data_blob\", \"bigendian\", \"ndr64\", \"allow_remaining\", NULL };");
	$self->pidl("PyObject *bigendian_obj = NULL;");
	$self->pidl("PyObject *ndr64_obj = NULL;");
	$self->pidl("libndr_flags ndr_pull_flags = LIBNDR_FLAG_REF_ALLOC;");
	$self->pidl("PyObject *allow_remaining_obj = NULL;");
	$self->pidl("bool allow_remaining = false;");
	$self->pidl("");
	$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, PYARG_BYTES_LEN \"|OOO:__ndr_unpack_out__\",");
	$self->indent;
	$self->pidl("discard_const_p(char *, kwnames),");
	$self->pidl("&blob.data, &blob_length,");
	$self->pidl("&bigendian_obj,");
	$self->pidl("&ndr64_obj,");
	$self->pidl("&allow_remaining_obj)) {");
	$self->deindent;
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("blob.length = blob_length;");
	$self->pidl("");
	$self->pidl("if (bigendian_obj && PyObject_IsTrue(bigendian_obj)) {");
	$self->indent;
	$self->pidl("ndr_pull_flags |= LIBNDR_FLAG_BIGENDIAN;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (ndr64_obj && PyObject_IsTrue(ndr64_obj)) {");
	$self->indent;
	$self->pidl("ndr_pull_flags |= LIBNDR_FLAG_NDR64;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("if (allow_remaining_obj && PyObject_IsTrue(allow_remaining_obj)) {");
	$self->indent;
	$self->pidl("allow_remaining = true;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return py_$name\_ndr_unpack(py_obj, &blob, NDR_OUT, ndr_pull_flags, allow_remaining);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_print(PyObject *py_obj, const char *name, ndr_flags_type ndr_inout_flags)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$ndr_call");
	$self->pidl("$object_ptr");
	$self->pidl("PyObject *ret;");
	$self->pidl("char *retstr;");
	$self->pidl("");
	$self->pidl("if (ndr_table_$iface\.num_calls < " . ($fn->{OPNUM}+1) .
		    ") {");
	$self->indent;
	$self->pidl("PyErr_SetString(PyExc_TypeError, \"Internal Error, ndr_interface_call missing for py_$name\_ndr_print\");");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("call = &ndr_table_$iface\.calls[$fn->{OPNUM}];");
	$self->pidl("");
	$self->pidl("retstr = ndr_print_function_string(pytalloc_get_mem_ctx(py_obj), call->ndr_print, name, ndr_inout_flags, object);");
	$self->pidl("ret = PyUnicode_FromString(retstr);");
	$self->pidl("TALLOC_FREE(retstr);");
	$self->pidl("");
	$self->pidl("return ret;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_print_in(PyObject *py_obj, PyObject *Py_UNUSED(ignored))");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return py_$name\_ndr_print(py_obj, \"$name\_in\", NDR_IN);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_ndr_print_out(PyObject *py_obj, PyObject *Py_UNUSED(ignored))");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return py_$name\_ndr_print(py_obj, \"$name\_out\", NDR_OUT);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$py_methods = "py_$name\_methods";
	$self->pidl("static PyMethodDef $py_methods\[] = {");
	$self->indent;
	$self->pidl("{ \"opnum\", (PyCFunction)py_$name\_ndr_opnum, METH_NOARGS|METH_CLASS,");
	$self->indent;
	$self->pidl("\"$modulename.$prettyname.opnum() -> ".sprintf("%d (0x%02x)", $fn->{OPNUM}, $fn->{OPNUM})." \" },");
	$self->deindent;
	$self->pidl("{ \"__ndr_pack_in__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$name\_ndr_pack_in), METH_VARARGS|METH_KEYWORDS,");
	$self->indent;
	$self->pidl("\"S.ndr_pack_in(object, bigendian=False, ndr64=False) -> blob\\nNDR pack input\" },");
	$self->deindent;
	$self->pidl("{ \"__ndr_pack_out__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$name\_ndr_pack_out), METH_VARARGS|METH_KEYWORDS,");
	$self->indent;
	$self->pidl("\"S.ndr_pack_out(object, bigendian=False, ndr64=False) -> blob\\nNDR pack output\" },");
	$self->deindent;
	$self->pidl("{ \"__ndr_unpack_in__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$name\_ndr_unpack_in), METH_VARARGS|METH_KEYWORDS,");
	$self->indent;
	$self->pidl("\"S.ndr_unpack_in(class, blob, bigendian=False, ndr64=False, allow_remaining=False) -> None\\nNDR unpack input\" },");
	$self->deindent;
	$self->pidl("{ \"__ndr_unpack_out__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$name\_ndr_unpack_out), METH_VARARGS|METH_KEYWORDS,");
	$self->indent;
	$self->pidl("\"S.ndr_unpack_out(class, blob, bigendian=False, ndr64=False, allow_remaining=False) -> None\\nNDR unpack output\" },");
	$self->deindent;
	$self->pidl("{ \"__ndr_print_in__\", (PyCFunction)py_$name\_ndr_print_in, METH_NOARGS, \"S.ndr_print_in(object) -> None\\nNDR print input\" },");
	$self->pidl("{ \"__ndr_print_out__\", (PyCFunction)py_$name\_ndr_print_out, METH_NOARGS, \"S.ndr_print_out(object) -> None\\nNDR print output\" },");
	$self->pidl("{ NULL, NULL, 0, NULL }");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");

	$self->pidl_hdr("static PyTypeObject $name\_Type;");
	$self->pidl("");
	my $docstring = $self->DocString($fn, $name);
	my $typeobject = "$name\_Type";
	$self->pidl("static PyTypeObject $typeobject = {");
	$self->indent;
	$self->pidl("PyVarObject_HEAD_INIT(NULL, 0)");
	$self->pidl(".tp_name = \"$modulename.$prettyname\",");
	$self->pidl(".tp_getset = $getsetters,");
	if ($docstring) {
		$self->pidl(".tp_doc = $docstring,");
	}
	$self->pidl(".tp_methods = $py_methods,");
	$self->pidl(".tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,");
	$self->pidl(".tp_new = py_$name\_new,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	my $talloc_typename = $self->import_type_variable("talloc", "BaseObject");
	$self->register_module_prereadycode(["$name\_Type.tp_base = $talloc_typename;",
					     "$name\_Type.tp_basicsize = pytalloc_BaseObject_size();",
					     ""]);

	return "&$typeobject";
}

sub get_metadata_var($)
{
	my ($e) = @_;
	sub get_var($) { my $x = shift; $x =~ s/\*//g; return $x; }

	 if (has_property($e, "length_is")) {
		return get_var($e->{PROPERTIES}->{length_is});
	 } elsif (has_property($e, "size_is")) {
		return get_var($e->{PROPERTIES}->{size_is});
	 }

	 return undef;
}

sub find_metadata_args($)
{
	my ($fn) = @_;
	my $metadata_args = { in => {}, out => {} };

	# Determine arguments that are metadata for other arguments (size_is/length_is)
	foreach my $e (@{$fn->{ELEMENTS}}) {
		foreach my $dir (@{$e->{DIRECTION}}) {
			 my $main = get_metadata_var($e);
			 if ($main) {
				 $metadata_args->{$dir}->{$main} = $e->{NAME};
			 }
		 }
	}

	return $metadata_args;
}

sub PythonFunctionUnpackOut($$$)
{
	my ($self, $fn, $fnname) = @_;

	my $outfnname = "unpack_$fnname\_args_out";
	my $signature = "";

	my $metadata_args = find_metadata_args($fn);

	my $env = GenerateFunctionOutEnv($fn, "r->");
	my $result_size = 0;

	$self->pidl("static PyObject *$outfnname(struct $fn->{NAME} *r)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("PyObject *result;");
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/out/,@{$e->{DIRECTION}}));
		next if (($metadata_args->{in}->{$e->{NAME}} and grep(/in/, @{$e->{DIRECTION}})) or
		         ($metadata_args->{out}->{$e->{NAME}}) and grep(/out/, @{$e->{DIRECTION}}));
		$self->pidl("PyObject *py_$e->{NAME};");
		$result_size++;
	}

	if ($fn->{RETURN_TYPE}) {
		$result_size++ unless ($fn->{RETURN_TYPE} eq "WERROR" or $fn->{RETURN_TYPE} eq "NTSTATUS");
	}

	my $i = 0;

	if ($result_size > 1) {
		$self->pidl("result = PyTuple_New($result_size);");
		$signature .= "(";
	} elsif ($result_size == 0) {
		$self->pidl("result = Py_None;");
		$self->pidl("Py_INCREF(result);");
		$signature .= "None";
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next if ($metadata_args->{out}->{$e->{NAME}});
		my $py_name = "py_$e->{NAME}";
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->ConvertObjectToPython("r", $env, $e, "r->out.$e->{NAME}", $py_name, "return NULL;");
			if ($result_size > 1) {
				$self->pidl("PyTuple_SetItem(result, $i, $py_name);");
				$i++;
				$signature .= "$e->{NAME}, ";
			} else {
				$self->pidl("result = $py_name;");
				$signature .= $e->{NAME};
			}
		}
	}

	if (defined($fn->{RETURN_TYPE}) and $fn->{RETURN_TYPE} eq "NTSTATUS") {
		$self->handle_ntstatus("r->out.result", "NULL", undef);
	} elsif (defined($fn->{RETURN_TYPE}) and $fn->{RETURN_TYPE} eq "WERROR") {
		$self->handle_werror("r->out.result", "NULL", undef);
	} elsif (defined($fn->{RETURN_TYPE})) {
		my $conv = $self->ConvertObjectToPythonData("r", $fn->{RETURN_TYPE}, "r->out.result", $fn);
		if ($result_size > 1) {
			$self->pidl("PyTuple_SetItem(result, $i, $conv);");
		} else {
			$self->pidl("result = $conv;");
		}
		$signature .= "result";
	}

	if (substr($signature, -2) eq ", ") {
		$signature = substr($signature, 0, -2);
	}
	if ($result_size > 1) {
		$signature .= ")";
	}

	$self->pidl("return result;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	return ($outfnname, $signature);
}

sub PythonFunctionPackIn($$$)
{
	my ($self, $fn, $fnname) = @_;
	my $metadata_args = find_metadata_args($fn);

	my $infnname = "pack_$fnname\_args_in";

	$self->pidl("static bool $infnname(PyObject *args, PyObject *kwargs, struct $fn->{NAME} *r)");
	$self->pidl("{");
	$self->indent;
	my $args_format = "";
	my $args_string = "";
	my $args_names = "";
	my $signature = "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/,@{$e->{DIRECTION}}));
		next if (($metadata_args->{in}->{$e->{NAME}} and grep(/in/, @{$e->{DIRECTION}})) or
				 ($metadata_args->{out}->{$e->{NAME}}) and grep(/out/, @{$e->{DIRECTION}}));
		$self->pidl("PyObject *py_$e->{NAME};");
		$args_format .= "O";
		$args_string .= ", &py_$e->{NAME}";
		$args_names .= "\"$e->{NAME}\", ";
		$signature .= "$e->{NAME}, ";
	}
	if (substr($signature, -2) eq ", ") {
		$signature = substr($signature, 0, -2);
	}
	$self->pidl("const char *kwnames[] = {");
	$self->indent;
	$self->pidl($args_names . "NULL");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");
	$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, \"$args_format:$fn->{NAME}\", discard_const_p(char *, kwnames)$args_string)) {");
	$self->indent;
	$self->pidl("return false;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	my $env = GenerateFunctionInEnv($fn, "r->");

	my $fail = "return false;";
	foreach my $e (@{$fn->{ELEMENTS}}) {
		next unless (grep(/in/,@{$e->{DIRECTION}}));
		if ($metadata_args->{in}->{$e->{NAME}}) {
			my $py_var = "py_".$metadata_args->{in}->{$e->{NAME}};
			$self->pidl("PY_CHECK_TYPE(&PyList_Type, $py_var, $fail);");
			my $val = "PyList_GET_SIZE($py_var)";
			if ($e->{LEVELS}[0]->{TYPE} eq "POINTER") {
				$self->pidl("r->in.$e->{NAME} = talloc_ptrtype(r, r->in.$e->{NAME});");
				$self->pidl("if (r->in.$e->{NAME} == NULL) {");
				$self->indent;
				$self->pidl("PyErr_NoMemory();");
				$self->pidl($fail);
				$self->deindent;
				$self->pidl("}");
				$self->pidl("*r->in.$e->{NAME} = $val;");
			} else {
				$self->pidl("r->in.$e->{NAME} = $val;");
			}
		} else {
			$self->ConvertObjectFromPython($env, "r", $e, "py_$e->{NAME}", "r->in.$e->{NAME}", $fail);
		}
	}
	$self->pidl("return true;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	return ($infnname, $signature);
}

sub PythonFunction($$$)
{
	my ($self, $fn, $iface, $prettyname) = @_;

	my $fnname = "py_$fn->{NAME}";
	my $docstring = $self->DocString($fn, $fn->{NAME});

	my ($infn, $insignature) = $self->PythonFunctionPackIn($fn, $fnname);
	my ($outfn, $outsignature) = $self->PythonFunctionUnpackOut($fn, $fnname);
	my $signature = "S.$prettyname($insignature) -> $outsignature";
	if ($docstring) {
		$docstring = "\"$signature\\n\\n\"$docstring";
	} else {
		$docstring = "\"$signature\"";
	}

	return ($infn, $outfn, $docstring);
}

sub handle_werror($$$$)
{
	my ($self, $var, $retval, $mem_ctx) = @_;

	$self->pidl("if (!W_ERROR_IS_OK($var)) {");
	$self->indent;
	$self->pidl("PyErr_SetWERROR($var);");
	$self->pidl("talloc_free($mem_ctx);") if ($mem_ctx);
	$self->pidl("return $retval;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub handle_ntstatus($$$$)
{
	my ($self, $var, $retval, $mem_ctx) = @_;

	$self->pidl("if (NT_STATUS_IS_ERR($var)) {");
	$self->indent;
	$self->pidl("PyErr_SetNTSTATUS($var);");
	$self->pidl("talloc_free($mem_ctx);") if ($mem_ctx);
	$self->pidl("return $retval;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub PythonType($$$$)
{
	my ($self, $modulename, $d, $interface, $basename) = @_;

	my $actual_ctype = $d;
	if ($actual_ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $actual_ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "STRUCT") {
		my $typeobject;
		my $fn_name = PrettifyTypeName($d->{NAME}, $basename);

		if ($d->{TYPE} eq "STRUCT") {
			$typeobject = $self->PythonStruct($modulename, $fn_name, $d->{NAME}, mapTypeName($d), $d);
		} else {
			$typeobject = $self->PythonStruct($modulename, $fn_name, $d->{NAME}, mapTypeName($d), $d->{DATA});
		}

		$self->register_module_typeobject($fn_name, $typeobject, $d->{ORIGINAL});
	}

	if ($d->{TYPE} eq "ENUM" or $d->{TYPE} eq "BITMAP") {
		$self->EnumAndBitmapConsts($d->{NAME}, $d);
	}

	if ($d->{TYPE} eq "TYPEDEF" and ($d->{DATA}->{TYPE} eq "ENUM" or $d->{DATA}->{TYPE} eq "BITMAP")) {
		$self->EnumAndBitmapConsts($d->{NAME}, $d->{DATA});
	}

	if ($actual_ctype->{TYPE} eq "UNION" and defined($actual_ctype->{ELEMENTS})) {
		my $prettyname = PrettifyTypeName($d->{NAME}, $basename);
		my $typeobject = "$d->{NAME}\_Type";
		my $docstring = $self->DocString($d, $d->{NAME});
		my $cname = "union $d->{NAME}";

		$self->pidl("static PyObject *py_import_$d->{NAME}(TALLOC_CTX *mem_ctx, int level, " .mapTypeName($d) . " *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromUnionToPythonFunction("mem_ctx", $actual_ctype, "level", "in") if ($actual_ctype->{TYPE} eq "UNION");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl("static ".mapTypeName($d) . " *py_export_$d->{NAME}(TALLOC_CTX *mem_ctx, int level, PyObject *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromPythonToUnionFunction($actual_ctype, mapTypeName($d), "level", "mem_ctx", "in") if ($actual_ctype->{TYPE} eq "UNION");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		my $getsetters = "NULL";
		my $py_methods = "NULL";
		my $typename = mapTypeName($d);

		$self->pidl("static PyObject *py_$d->{NAME}\_import(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
		$self->pidl("{");
		$self->indent;
		$self->pidl("const char * const kwnames[] = { \"mem_ctx\", \"level\", \"in\", NULL };");
		$self->pidl("PyObject *mem_ctx_obj = NULL;");
		$self->pidl("TALLOC_CTX *mem_ctx = NULL;");
		$self->pidl("int level = 0;");
		$self->pidl("PyObject *in_obj = NULL;");
		$self->pidl("$typename *in = NULL;");
		$self->pidl("");
		$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, \"OiO:import\",");
		$self->indent;
		$self->pidl("discard_const_p(char *, kwnames),");
		$self->pidl("&mem_ctx_obj,");
		$self->pidl("&level,");
		$self->pidl("&in_obj)) {");
		$self->deindent;
		$self->indent;
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("mem_ctx = pytalloc_get_ptr(mem_ctx_obj);");
		$self->pidl("if (mem_ctx == NULL) {");
		$self->indent;
		$self->pidl("PyErr_SetString(PyExc_TypeError, \"mem_ctx is NULL)!\");");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("in = ($typename *)pytalloc_get_ptr(in_obj);");
		$self->pidl("if (in == NULL) {");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_TypeError, \"in needs to be a pointer to $typename!\");");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("return py_import_$d->{NAME}(mem_ctx, level, in);");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl("static PyObject *py_$d->{NAME}\_export(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
		$self->pidl("{");
		$self->indent;
		$self->pidl("const char * const kwnames[] = { \"mem_ctx\", \"level\", \"in\", NULL };");
		$self->pidl("PyObject *mem_ctx_obj = NULL;");
		$self->pidl("TALLOC_CTX *mem_ctx = NULL;");
		$self->pidl("int level = 0;");
		$self->pidl("PyObject *in = NULL;");
		$self->pidl("$typename *out = NULL;");
		$self->pidl("");
		$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, \"OiO:export\",");
		$self->indent;
		$self->pidl("discard_const_p(char *, kwnames),");
		$self->pidl("&mem_ctx_obj,");
		$self->pidl("&level,");
		$self->pidl("&in)) {");
		$self->deindent;
		$self->indent;
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("mem_ctx = pytalloc_get_ptr(mem_ctx_obj);");
		$self->pidl("if (mem_ctx == NULL) {");
		$self->indent;
		$self->pidl("PyErr_SetString(PyExc_TypeError, \"mem_ctx is NULL)!\");");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("out = py_export_$d->{NAME}(mem_ctx, level, in);");
		$self->pidl("if (out == NULL) {");
		$self->indent;
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
		$self->pidl("return pytalloc_GenericObject_reference(out);");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$py_methods = "py_$d->{NAME}_methods";
		$self->pidl("static PyMethodDef $py_methods\[] = {");
		$self->indent;
		$self->pidl("{ \"__import__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$d->{NAME}\_import),");
		$self->indent;
		$self->pidl("METH_VARARGS|METH_KEYWORDS|METH_CLASS,");
		$self->pidl("\"T.__import__(mem_ctx, level, in) => ret.\" },");
		$self->deindent;
		$self->pidl("{ \"__export__\", PY_DISCARD_FUNC_SIG(PyCFunction,py_$d->{NAME}\_export),");
		$self->indent;
		$self->pidl("METH_VARARGS|METH_KEYWORDS|METH_CLASS,");
		$self->pidl("\"T.__export__(mem_ctx, level, in) => ret.\" },");
		$self->deindent;
		$self->pidl("{ NULL, NULL, 0, NULL }");
		$self->deindent;
		$self->pidl("};");
		$self->pidl("");

		$self->pidl("static PyObject *py_$d->{NAME}\_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
		$self->pidl("{");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_TypeError, \"New %s Objects are not supported\", type->tp_name);");
		$self->pidl("return NULL;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl("");
		$self->pidl_hdr("static PyTypeObject $typeobject;");
		$self->pidl("static PyTypeObject $typeobject = {");
		$self->indent;
		$self->pidl("PyVarObject_HEAD_INIT(NULL, 0)");
		$self->pidl(".tp_name = \"$modulename.$prettyname\",");
		$self->pidl(".tp_getset = $getsetters,");
		if ($docstring) {
			$self->pidl(".tp_doc = $docstring,");
		}
		$self->pidl(".tp_methods = $py_methods,");
		$self->pidl(".tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,");
		$self->pidl(".tp_new = py_$d->{NAME}\_new,");
		$self->deindent;
		$self->pidl("};");

		$self->pidl("");

		my $talloc_typename = $self->import_type_variable("talloc", "BaseObject");
		$self->register_module_prereadycode(["$typeobject.tp_base = $talloc_typename;",
						     "$typeobject.tp_basicsize = pytalloc_BaseObject_size();",
						     ""]);

		$self->register_module_typeobject($prettyname, "&$typeobject", $d->{ORIGINAL});
	}
}

sub DocString($$$)
{
	my ($self, $d, $name) = @_;
	if (has_property($d, "helpstring")) {
		my $docstring = uc("py_doc_$name");
		$self->pidl("#define $docstring ".has_property($d, "helpstring"));
		return $docstring;
	}

	return undef;
}

sub Interface($$$)
{
	my($self,$interface,$basename) = @_;

	if (has_property($interface, "pyhelper")) {
		$self->pidl("#include \"".unmake_str($interface->{PROPERTIES}->{pyhelper})."\"\n");
	}

	$self->Const($_) foreach (@{$interface->{CONSTS}});

	foreach my $d (@{$interface->{TYPES}}) {
		next if has_property($d, "nopython");

		$self->PythonType($basename, $d, $interface, $basename);
	}

	if (defined $interface->{PROPERTIES}->{uuid}) {
		$self->pidl_hdr("static PyTypeObject $interface->{NAME}_InterfaceType;");
		$self->pidl("");

		my @fns = ();

		foreach my $d (@{$interface->{FUNCTIONS}}) {
			next if has_property($d, "noopnum");
			next if has_property($d, "nopython");
			next if has_property($d, "todo");

			my $skip = 0;
			foreach my $e (@{$d->{ELEMENTS}}) {
				if (ContainsPipe($e, $e->{LEVELS}[0])) {
					$skip = 1;
					last;
				}
			}
			next if $skip;

			my $prettyname = $d->{NAME};

			$prettyname =~ s/^$interface->{NAME}_//;
			$prettyname =~ s/^$basename\_//;

			my $typeobject = $self->PythonFunctionStruct($basename, $d, $interface->{NAME}, $prettyname);
			$self->register_module_typeobject($prettyname, $typeobject, $d->{ORIGINAL});

			my ($infn, $outfn, $fndocstring) = $self->PythonFunction($d, $interface->{NAME}, $prettyname);

			push (@fns, [$infn, $outfn, "dcerpc_$d->{NAME}_r", $prettyname, $fndocstring, $d->{OPNUM}]);
		}

		$self->pidl("const struct PyNdrRpcMethodDef py_ndr_$interface->{NAME}\_methods[] = {");
		$self->indent;
		foreach my $d (@fns) {
			my ($infn, $outfn, $callfn, $prettyname, $docstring, $opnum) = @$d;
			$self->pidl("{ \"$prettyname\", $docstring, (py_dcerpc_call_fn)$callfn, (py_data_pack_fn)$infn, (py_data_unpack_fn)$outfn, $opnum, &ndr_table_$interface->{NAME} },");
		}
		$self->pidl("{0}");
		$self->deindent;
		$self->pidl("};");
		$self->pidl("");

		$self->pidl("static PyObject *interface_$interface->{NAME}_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
		$self->pidl("{");
		$self->indent;
		$self->pidl("return py_dcerpc_interface_init_helper(type, args, kwargs, &ndr_table_$interface->{NAME});");
		$self->deindent;
		$self->pidl("}");

		$self->pidl("");

		my $signature =
"\"$interface->{NAME}(binding, lp_ctx=None, credentials=None) -> connection\\n\"
\"\\n\"
\"binding should be a DCE/RPC binding string (for example: ncacn_ip_tcp:127.0.0.1)\\n\"
\"lp_ctx should be a path to a smb.conf file or a param.LoadParm object\\n\"
\"credentials should be a credentials.Credentials object.\\n\\n\"";

		my $docstring = $self->DocString($interface, $interface->{NAME});

		if ($docstring) {
			$docstring = "$signature$docstring";
		} else {
			$docstring = $signature;
		}

		my $if_typename = "$interface->{NAME}_InterfaceType";

		$self->pidl("static PyTypeObject $if_typename = {");
		$self->indent;
		$self->pidl("PyVarObject_HEAD_INIT(NULL, 0)");
		$self->pidl(".tp_name = \"$basename.$interface->{NAME}\",");
		$self->pidl(".tp_basicsize = sizeof(dcerpc_InterfaceObject),");
		$self->pidl(".tp_doc = $docstring,");
		$self->pidl(".tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,");
		$self->pidl(".tp_new = interface_$interface->{NAME}_new,");
		$self->deindent;
		$self->pidl("};");

		$self->pidl("");

		$self->register_module_typeobject($interface->{NAME}, "&$if_typename", $interface->{ORIGINAL});
		my $dcerpc_typename = $self->import_type_variable("samba.dcerpc.base", "ClientConnection");
		$self->register_module_prereadycode(["$if_typename.tp_base = $dcerpc_typename;", ""]);
		$self->register_module_postreadycode(["if (!PyInterface_AddNdrRpcMethods(&$if_typename, py_ndr_$interface->{NAME}\_methods))", "\treturn NULL;", ""]);


		$self->pidl("static PyObject *syntax_$interface->{NAME}_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)");
		$self->pidl("{");
		$self->indent;
		$self->pidl("return py_dcerpc_syntax_init_helper(type, args, kwargs, &ndr_table_$interface->{NAME}.syntax_id);");
		$self->deindent;
		$self->pidl("}");

		$self->pidl("");

		$signature = "\"$interface->{NAME}_abstract_syntax()\\n\"";

		$docstring = $self->DocString($interface, $interface->{NAME}."_syntax");

		if ($docstring) {
			$docstring = "$signature$docstring";
		} else {
			$docstring = $signature;
		}

		my $syntax_typename = "$interface->{NAME}_SyntaxType";

		$self->pidl("static PyTypeObject $syntax_typename = {");
		$self->indent;
		$self->pidl("PyVarObject_HEAD_INIT(NULL, 0)");
		$self->pidl(".tp_name = \"$basename.$interface->{NAME}_abstract_syntax\",");
		$self->pidl(".tp_doc = $docstring,");
		$self->pidl(".tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,");
		$self->pidl(".tp_new = syntax_$interface->{NAME}_new,");
		$self->deindent;
		$self->pidl("};");

		$self->pidl("");

		$self->register_module_typeobject("$interface->{NAME}_abstract_syntax", "&$syntax_typename", $interface->{ORIGINAL});
		if (not defined($self->existing_module_object("abstract_syntax"))) {
			# Only the first syntax gets registered with the legacy
			# "abstract_syntax" name
			$self->register_module_typeobject("abstract_syntax", "&$syntax_typename", $interface->{ORIGINAL});
		}
		my $ndr_typename = $self->import_type_variable("samba.dcerpc.misc", "ndr_syntax_id");
		$self->register_module_prereadycode(["$syntax_typename.tp_base = $ndr_typename;",
						     "$syntax_typename.tp_basicsize = pytalloc_BaseObject_size();",
						     ""]);
	}

	$self->pidl_hdr("");
}

sub register_module_method($$$$$)
{
	my ($self, $fn_name, $pyfn_name, $flags, $doc) = @_;

	push (@{$self->{module_methods}}, [$fn_name, $pyfn_name, $flags, $doc])
}

sub register_module_typeobject($$$$)
{
	my ($self, $name, $py_name, $location) = @_;

	$self->register_module_object($name, "(PyObject *)(void *)$py_name", $location);

	$self->check_ready_type($py_name);

	$self->register_patch_type_call($name, $py_name);
}

sub check_ready_type($$)
{
	my ($self, $py_name) = @_;
	push (@{$self->{ready_types}}, $py_name) unless (grep(/^$py_name$/,@{$self->{ready_types}}));
}

sub register_module_import($$)
{
	my ($self, $module_path) = @_;

	my $var_name = $module_path;
	$var_name =~ s/\./_/g;
	$var_name = "dep_$var_name";

	unless (defined $self->{module_imports_uniq}->{$var_name}) {
		my $h = { "key" => $var_name, "val" => $module_path};
		push @{$self->{module_imports}}, $h;
		$self->{module_imports_uniq}->{$var_name} = $h;
	}
	return $var_name;
}

sub import_type_variable($$$)
{
	my ($self, $module, $name) = @_;

	$self->register_module_import($module);
	unless (defined $self->{type_imports_uniq}->{$name}) {
		my $h = { "key" => $name, "val" => $module};
		push @{$self->{type_imports}}, $h;
		$self->{type_imports_uniq}->{$name} = $h;
	}
	return "$name\_Type";
}

sub use_type_variable($$)
{
	my ($self, $orig_ctype) = @_;
	# FIXME: Have a global lookup table for types that look different on the
	# wire than they are named in C?
	if ($orig_ctype->{NAME} eq "dom_sid2" or
	    $orig_ctype->{NAME} eq "dom_sid28" or
	    $orig_ctype->{NAME} eq "dom_sid0") {
		$orig_ctype->{NAME} = "dom_sid";
	}
	if ($orig_ctype->{NAME} eq "spoolss_security_descriptor") {
		$orig_ctype->{NAME} = "security_descriptor";
	}

	my $ctype = resolveType($orig_ctype);
	unless (defined($ctype->{BASEFILE})) {
		return undef;
	}
	# If this is an external type, make sure we do the right imports.
	if (($ctype->{BASEFILE} ne $self->{BASENAME})) {
		return $self->import_type_variable("samba.dcerpc.$ctype->{BASEFILE}", $ctype->{NAME});
	}
	return "&$ctype->{NAME}_Type";
}

sub register_patch_type_call($$$)
{
	my ($self, $typename, $cvar) = @_;

	push(@{$self->{patch_type_calls}}, [$typename, $cvar]);

}

sub register_module_prereadycode($$)
{
	my ($self, $code) = @_;

	push (@{$self->{prereadycode}}, @$code);
}

sub register_module_postreadycode($$)
{
	my ($self, $code) = @_;

	push (@{$self->{postreadycode}}, @$code);
}

sub existing_module_object($$)
{
	my ($self, $name) = @_;

	if (defined($self->{module_object_uniq}->{$name})) {
		return $self->{module_object_uniq}->{$name};
	}

	return undef;
}

sub register_module_object($$$$)
{
	my ($self, $name, $py_name, $location) = @_;

	my $existing = $self->existing_module_object($name);
	fatal($location, "module_object($name, $py_name) registered twice! $existing.") if defined($existing);

	push (@{$self->{module_objects}}, [$name, $py_name]);
	$self->{module_object_uniq}->{$name} = $py_name;
}

sub assign($$$)
{
	my ($self, $dest, $src) = @_;
	if ($dest =~ /^\&/ and $src eq "NULL") {
		$self->pidl("memset($dest, 0, sizeof(" . get_value_of($dest) . "));");
	} elsif ($dest =~ /^\&/) {
		my $destvar = get_value_of($dest);
		$self->pidl("$destvar = *$src;");
	} else {
		$self->pidl("$dest = $src;");
	}
}

sub ConvertStringFromPythonData($$$$$)
{
	my ($self, $mem_ctx, $py_var, $target, $fail) = @_;

	$self->pidl("{");
	$self->indent;
	$self->pidl("const char *test_str;");
	$self->pidl("const char *talloc_str;");
	$self->pidl("PyObject *unicode = NULL;");
	$self->pidl("if (PyUnicode_Check($py_var)) {");
	$self->indent;
	# FIXME: Use Unix charset setting rather than utf-8
	$self->pidl("unicode = PyUnicode_AsEncodedString($py_var, \"utf-8\", \"ignore\");");
	$self->pidl("if (unicode == NULL) {");
	$self->indent;
	$self->pidl("$fail");
	$self->deindent;
	$self->pidl("}");

	$self->pidl("test_str = PyBytes_AS_STRING(unicode);");
	$self->deindent;
	$self->pidl("} else if (PyBytes_Check($py_var)) {");
	$self->indent;
	$self->pidl("test_str = PyBytes_AS_STRING($py_var);");
	$self->deindent;
	$self->pidl("} else {");
	$self->indent;
	$self->pidl("PyErr_Format(PyExc_TypeError, \"Expected string or unicode object, got %s\", Py_TYPE($py_var)->tp_name);");
	$self->pidl("$fail");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("talloc_str = talloc_strdup($mem_ctx, test_str);");
	$self->pidl("if (unicode != NULL) {");
	$self->indent;
	$self->pidl("Py_DECREF(unicode);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("if (talloc_str == NULL) {");
	$self->indent;
	$self->pidl("PyErr_NoMemory();");
	$self->pidl("$fail");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("$target = talloc_str;");
	$self->deindent;
	$self->pidl("}");
}

sub ConvertU16StringFromPythonData($$$$$)
{
	my ($self, $mem_ctx, $py_var, $target, $fail) = @_;

	$self->pidl("{");
	$self->indent;
	$self->pidl("unsigned char *str = NULL;");
	$self->pidl("");
	$self->pidl("str = PyUtf16String_FromBytes(");
	$self->pidl("	$mem_ctx, $py_var);");
	$self->pidl("if (str == NULL) {");
	$self->indent;
	$self->pidl("$fail");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("$target = str;");
	$self->deindent;
	$self->pidl("}");
}

sub ConvertObjectFromPythonData($$$$$$;$$)
{
	my ($self, $mem_ctx, $cvar, $ctype, $target, $fail, $location, $switch) = @_;

	fatal($location, "undef type for $cvar") unless(defined($ctype));

	$ctype = resolveType($ctype);

	my $actual_ctype = $ctype;
	if ($actual_ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $actual_ctype->{DATA};
	}

	# We need to cover ENUMs, BITMAPS and SCALAR values here, as
	# all could otherwise be assigned invalid integer values
	my $ctype_alias = "";
	my $uint_max = "";
	if ($actual_ctype->{TYPE} eq "ENUM") {
		# Importantly, ENUM values are unsigned in pidl, and
		# typically map to uint32
		$ctype_alias = enum_type_fn($actual_ctype);
	} elsif ($actual_ctype->{TYPE} eq "BITMAP") {
		$ctype_alias = bitmap_type_fn($actual_ctype);
	} elsif ($actual_ctype->{TYPE} eq "SCALAR") {
		$ctype_alias = expandAlias($actual_ctype->{NAME});
	}

	# This is the unsigned Python Integer -> C integer validation
	# case.	 The signed case is below.
	if ($ctype_alias  =~ /^(uint[0-9]*|hyper|udlong|udlongr
				|NTTIME_hyper|NTTIME|NTTIME_1sec
				|uid_t|gid_t)$/x) {
		$self->pidl("{");
		$self->indent;
		$self->pidl("const unsigned long long uint_max = ndr_sizeof2uintmax(sizeof($target));");
		$self->pidl("if (PyLong_Check($cvar)) {");
		$self->indent;
		$self->pidl("unsigned long long test_var;");
		$self->pidl("test_var = PyLong_AsUnsignedLongLong($cvar);");
		$self->pidl("if (PyErr_Occurred() != NULL) {");
		$self->indent;
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
		$self->pidl("if (test_var > uint_max) {");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_OverflowError, \"Expected type %s within range 0 - %llu, got %llu\",");
		$self->pidl("  PyLong_Type.tp_name, uint_max, test_var);");
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
		$self->pidl("$target = test_var;");
		$self->deindent;
		$self->pidl("} else {");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_TypeError, \"Expected type %s\",");
		$self->pidl("  PyLong_Type.tp_name);");
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
		$self->deindent;
		$self->pidl("}");
		return;
	}

	# Confirm the signed python integer fits in the C type
	# correctly.  It is subtly different from the unsigned case
	# above, so while it looks like a duplicate, it is not
	# actually a duplicate.
	if ($ctype_alias  =~ /^(dlong|char|int[0-9]*|time_t)$/x) {
		$self->pidl("{");
		$self->indent;
		$self->pidl("const long long int_max = ndr_sizeof2intmax(sizeof($target));");
		$self->pidl("const long long int_min = -int_max - 1;");
		$self->pidl("if (PyLong_Check($cvar)) {");
		$self->indent;
		$self->pidl("long long test_var;");
		$self->pidl("test_var = PyLong_AsLongLong($cvar);");
		$self->pidl("if (PyErr_Occurred() != NULL) {");
		$self->indent;
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
		$self->pidl("if (test_var < int_min || test_var > int_max) {");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_OverflowError, \"Expected type %s within range %lld - %lld, got %lld\",");
		$self->pidl("  PyLong_Type.tp_name, int_min, int_max, test_var);");
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
		$self->pidl("$target = test_var;");
		$self->deindent;
		$self->pidl("} else {");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_TypeError, \"Expected type %s\",");
		$self->pidl("  PyLong_Type.tp_name);");
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
		$self->deindent;
		$self->pidl("}");
		return;
	}

	if ($actual_ctype->{TYPE} eq "STRUCT" or $actual_ctype->{TYPE} eq "INTERFACE") {
		my $ctype_name = $self->use_type_variable($ctype);
		unless (defined ($ctype_name)) {
			error($location, "Unable to determine origin of type `" . mapTypeName($ctype) . "'");
			$self->pidl("PyErr_SetString(PyExc_TypeError, \"Cannot convert Python object to NDR $target\");");
			$self->pidl("$fail");
			return;
		}
		$self->pidl("PY_CHECK_TYPE($ctype_name, $cvar, $fail);");
		$self->pidl("if (talloc_reference($mem_ctx, pytalloc_get_mem_ctx($cvar)) == NULL) {");
		$self->indent;
		$self->pidl("PyErr_NoMemory();");
		$self->pidl("$fail");
		$self->deindent;
		$self->pidl("}");
		$self->assign($target, "(".mapTypeName($ctype)." *)pytalloc_get_ptr($cvar)");
		return;
	}

	if ($actual_ctype->{TYPE} eq "UNION") {
		my $ctype_name = $self->use_type_variable($ctype);
		unless (defined ($ctype_name)) {
			error($location, "Unable to determine origin of type `" . mapTypeName($ctype) . "'");
			$self->pidl("PyErr_SetString(PyExc_TypeError, \"Can not convert C Type " . mapTypeName($ctype) . " from Python\");");
			return;
		}
		my $export = "pyrpc_export_union($ctype_name, $mem_ctx, $switch, $cvar, \"".mapTypeName($ctype)."\")";
		$self->assign($target, "(".mapTypeName($ctype)." *)$export");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "DATA_BLOB") {
		$self->pidl("$target = data_blob_talloc($mem_ctx, PyBytes_AS_STRING($cvar), PyBytes_GET_SIZE($cvar));");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and
		($actual_ctype->{NAME} eq "string"
		 or $actual_ctype->{NAME} eq "nbt_string"
		 or $actual_ctype->{NAME} eq "nbt_name"
		 or $actual_ctype->{NAME} eq "wrepl_nbt_name"
		 or $actual_ctype->{NAME} eq "dns_string"
		 or $actual_ctype->{NAME} eq "dnsp_string"
		 or $actual_ctype->{NAME} eq "dns_name"
		 or $actual_ctype->{NAME} eq "ipv4address"
		 or $actual_ctype->{NAME} eq "ipv6address"
		 or $actual_ctype->{NAME} eq "dnsp_name")) {
	        $self->ConvertStringFromPythonData($mem_ctx, $cvar, $target, $fail);
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and
		$actual_ctype->{NAME} eq "u16string") {
	        $self->ConvertU16StringFromPythonData($mem_ctx, $cvar, $target, $fail);
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "NTSTATUS") {
		$self->pidl("$target = NT_STATUS(PyLong_AsLong($cvar));");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "WERROR") {
		$self->pidl("$target = W_ERROR(PyLong_AsLong($cvar));");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "HRESULT") {
		$self->pidl("$target = HRES_ERROR(PyLong_AsLong($cvar));");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "string_array") {
		$self->pidl("$target = pytalloc_get_ptr($cvar);");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "pointer") {
		$self->assign($target, "pytalloc_get_ptr($cvar)");
		return;
	}

	fatal($location, "unknown type `$actual_ctype->{TYPE}' for ".mapTypeName($ctype) . ": $cvar");

}

sub ConvertObjectFromPythonLevel($$$$$$$$$)
{
	my ($self, $env, $mem_ctx, $py_var, $e, $l, $var_name, $fail, $recurse) = @_;
	my $nl = GetNextLevel($e, $l);
	if ($nl and $nl->{TYPE} eq "SUBCONTEXT") {
		$nl = GetNextLevel($e, $nl);
	}
	my $pl = GetPrevLevel($e, $l);
	if ($pl and $pl->{TYPE} eq "SUBCONTEXT") {
		$pl = GetPrevLevel($e, $pl);
	}

	if ($recurse == 0) {
	        $self->pidl("if ($py_var == NULL) {");
		$self->indent;
		$self->pidl("PyErr_Format(PyExc_AttributeError, \"Cannot delete NDR object: $var_name\");");
		$self->pidl($fail);
		$self->deindent;
		$self->pidl("}");
	}
	$recurse = $recurse + 1;

	if ($l->{TYPE} eq "POINTER") {
		my $need_deindent = 0;
		my $need_deref = 0;

		if ($l->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($py_var == Py_None) {");
			$self->indent;
			$self->pidl("$var_name = NULL;");
			$self->deindent;
			$self->pidl("} else {");
			$self->indent;
			$need_deindent = 1;
			if ($nl->{TYPE} eq "POINTER") {
				$need_deref = 1;
			}
		}

		if ($l->{POINTER_TYPE} eq "ref" or $need_deref == 1) {
			$self->pidl("$var_name = talloc_ptrtype($mem_ctx, $var_name);");
			$self->pidl("if ($var_name == NULL) {");
			$self->indent;
			$self->pidl("PyErr_NoMemory();");
			$self->pidl($fail);
			$self->deindent;
			$self->pidl("}");
		} elsif ($nl->{TYPE} eq "DATA" and Parse::Pidl::Typelist::is_scalar($nl->{DATA_TYPE})
			 and not Parse::Pidl::Typelist::scalar_is_reference($nl->{DATA_TYPE})) {
			$self->pidl("$var_name = talloc_ptrtype($mem_ctx, $var_name);");
			$self->pidl("if ($var_name == NULL) {");
			$self->indent;
			$self->pidl("PyErr_NoMemory();");
			$self->pidl($fail);
			$self->deindent;
			$self->pidl("}");
		} else {
			$self->pidl("$var_name = NULL;");
		}
		if ($need_deref == 1) {
			my $ndr_pointer_typename = $self->import_type_variable("samba.dcerpc.base", "ndr_pointer");
			$self->pidl("$py_var = py_dcerpc_ndr_pointer_deref($ndr_pointer_typename, $py_var);");
			$self->pidl("if ($py_var == NULL) {");
			$self->indent;
                        $self->pidl($fail);
			$self->deindent;
			$self->pidl("}");
		}
		unless ($nl->{TYPE} eq "DATA" and Parse::Pidl::Typelist::scalar_is_reference($nl->{DATA_TYPE})) {
			$var_name = get_value_of($var_name);
		}
		$self->ConvertObjectFromPythonLevel($env, $mem_ctx, $py_var, $e, $nl, $var_name, $fail, $recurse);
		if ($need_deindent == 1) {
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "ARRAY") {
		if ($pl && $pl->{TYPE} eq "POINTER") {
			$var_name = get_pointer_to($var_name);
		}

		if (is_charset_array($e, $l)) {
		        $self->ConvertStringFromPythonData($mem_ctx, $py_var, $var_name, $fail);
		} else {
			my $counter = "$e->{NAME}_cntr_$l->{LEVEL_INDEX}";
			$self->pidl("PY_CHECK_TYPE(&PyList_Type, $py_var, $fail);");
			$self->pidl("{");
			$self->indent;
			$self->pidl("int $counter;");
			if (ArrayDynamicallyAllocated($e, $l)) {
				$self->pidl("$var_name = talloc_array_ptrtype($mem_ctx, $var_name, PyList_GET_SIZE($py_var));");
				$self->pidl("if (!$var_name) { $fail }");
				$self->pidl("talloc_set_name_const($var_name, \"ARRAY: $var_name\");");
			} else {
				$self->pidl("if (ARRAY_SIZE($var_name) != PyList_GET_SIZE($py_var)) {");
				$self->indent;
				$self->pidl("PyErr_Format(PyExc_TypeError, \"Expected list of type %s, length %zu, got %zd\", Py_TYPE($py_var)->tp_name, ARRAY_SIZE($var_name),  PyList_GET_SIZE($py_var));");
				$self->pidl("$fail");
				$self->deindent;
				$self->pidl("}");
			}
			$self->pidl("for ($counter = 0; $counter < PyList_GET_SIZE($py_var); $counter++) {");
			$self->indent;
			if (ArrayDynamicallyAllocated($e, $l)) {
				$self->ConvertObjectFromPythonLevel($env, $var_name, "PyList_GET_ITEM($py_var, $counter)", $e, $nl, "($var_name)"."[$counter]", $fail, 0);
			} else {
				$self->ConvertObjectFromPythonLevel($env, $mem_ctx, "PyList_GET_ITEM($py_var, $counter)", $e, $nl, "($var_name)"."[$counter]", $fail, 0);
			}
			$self->deindent;
			$self->pidl("}");
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "DATA") {
		if (not Parse::Pidl::Typelist::is_scalar($l->{DATA_TYPE})) {
			$var_name = get_pointer_to($var_name);
		}
		$self->ConvertObjectFromPythonData($mem_ctx, $py_var, $l->{DATA_TYPE}, $var_name, $fail, $e->{ORIGINAL});
	} elsif ($l->{TYPE} eq "SWITCH") {
		$var_name = get_pointer_to($var_name);
		my $switch = ParseExpr($l->{SWITCH_IS}, $env, $e);
		my $switch_ptr = "$e->{NAME}_switch_$l->{LEVEL_INDEX}";
		$self->pidl("{");
		$self->indent;
		my $union_type = mapTypeName($nl->{DATA_TYPE});
		$self->pidl("$union_type *$switch_ptr;");
		$self->ConvertObjectFromPythonData($mem_ctx, $py_var, $nl->{DATA_TYPE}, $switch_ptr, $fail, $e->{ORIGINAL}, $switch);
		$self->fail_on_null($switch_ptr, $fail);
		$self->assign($var_name, "$switch_ptr");
		$self->deindent;
		$self->pidl("}");
	} elsif ($l->{TYPE} eq "SUBCONTEXT") {
		$self->ConvertObjectFromPythonLevel($env, $mem_ctx, $py_var, $e, $nl, $var_name, $fail, $recurse);
	} else {
		fatal($e->{ORIGINAL}, "unknown level type $l->{TYPE}");
	}
}

sub ConvertObjectFromPython($$$$$$$)
{
	my ($self, $env, $mem_ctx, $ctype, $cvar, $target, $fail) = @_;
	my $recurse = 0;

	$self->ConvertObjectFromPythonLevel($env, $mem_ctx, $cvar, $ctype, $ctype->{LEVELS}[0], $target, $fail, $recurse);
}

sub ConvertScalarToPython($$$$)
{
	my ($self, $ctypename, $cvar, $mem_ctx) = @_;

	die("expected string for $cvar, not $ctypename") if (ref($ctypename) eq "HASH");

	$ctypename = expandAlias($ctypename);

	if ($ctypename =~ /^(int64|dlong)$/) {
		return "PyLong_FromLongLong($cvar)";
	}

	if ($ctypename =~ /^(uint64|hyper|NTTIME_hyper|NTTIME|NTTIME_1sec|udlong|udlongr|uid_t|gid_t)$/) {
		return "PyLong_FromUnsignedLongLong($cvar)";
	}

	if ($ctypename =~ /^(char|int|int8|int16|int32|time_t)$/) {
		return "PyLong_FromLong($cvar)";
	}

	# Needed to ensure unsigned values in a 32 or 16 bit enum is
	# cast correctly to a uint32_t, not sign extended to a a
	# possibly 64 bit unsigned long.  (enums are signed in C,
	# unsigned in NDR)
	if ($ctypename =~ /^(uint32|uint3264)$/) {
		return "PyLong_FromUnsignedLongLong((uint32_t)($cvar))";
	}

	if ($ctypename =~ /^(uint|uint8|uint16|uint1632)$/) {
		return "PyLong_FromLong((uint16_t)($cvar))";
	}

	if ($ctypename eq "DATA_BLOB") {
		return "PyBytes_FromStringAndSize((char *)($cvar).data, ($cvar).length)";
	}

	if ($ctypename eq "NTSTATUS") {
		return "PyErr_FromNTSTATUS($cvar)";
	}

	if ($ctypename eq "WERROR") {
		return "PyErr_FromWERROR($cvar)";
	}

	if ($ctypename eq "HRESULT") {
		return "PyErr_FromHRESULT($cvar)";
	}

	if (($ctypename eq "string" or $ctypename eq "nbt_string" or $ctypename eq "nbt_name" or $ctypename eq "wrepl_nbt_name")) {
		return "PyString_FromStringOrNULL($cvar)";
	}

	if (($ctypename eq "dns_string" or $ctypename eq "dns_name")) {
		return "PyString_FromStringOrNULL($cvar)";
	}

	if ($ctypename eq "u16string") {
		return "PyBytes_FromUtf16StringOrNULL($cvar)";
	}

	# Not yet supported
	if ($ctypename eq "string_array") {
		return "pytalloc_GenericObject_reference_ex($mem_ctx, $cvar)";
	}
	if ($ctypename eq "ipv4address") { return "PyString_FromStringOrNULL($cvar)"; }
	if ($ctypename eq "ipv6address") { return "PyString_FromStringOrNULL($cvar)"; }
	if ($ctypename eq "dnsp_name") { return "PyString_FromStringOrNULL($cvar)"; }
	if ($ctypename eq "dnsp_string") { return "PyString_FromStringOrNULL($cvar)"; }
	if ($ctypename eq "pointer") {
		return "pytalloc_GenericObject_reference_ex($mem_ctx, $cvar)";
	}

	die("Unknown scalar type $ctypename");
}

sub ConvertObjectToPythonData($$$$$;$$)
{
	my ($self, $mem_ctx, $ctype, $cvar, $location, $switch) = @_;

	die("undef type for $cvar") unless(defined($ctype));

	$ctype = resolveType($ctype);

	my $actual_ctype = $ctype;
	if ($actual_ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $actual_ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "ENUM") {
		return $self->ConvertScalarToPython(Parse::Pidl::Typelist::enum_type_fn($actual_ctype), $cvar, $mem_ctx);
	} elsif ($actual_ctype->{TYPE} eq "BITMAP") {
		return $self->ConvertScalarToPython(Parse::Pidl::Typelist::bitmap_type_fn($actual_ctype), $cvar, $mem_ctx);
	} elsif ($actual_ctype->{TYPE} eq "SCALAR") {
		return $self->ConvertScalarToPython($actual_ctype->{NAME}, $cvar, $mem_ctx);
	} elsif ($actual_ctype->{TYPE} eq "UNION") {
		my $ctype_name = $self->use_type_variable($ctype);
		unless (defined($ctype_name)) {
			error($location, "Unable to determine origin of type `" . mapTypeName($ctype) . "'");
			return "NULL"; # FIXME!
		}
		return "pyrpc_import_union($ctype_name, $mem_ctx, $switch, $cvar, \"".mapTypeName($ctype)."\")";
	} elsif ($actual_ctype->{TYPE} eq "STRUCT" or $actual_ctype->{TYPE} eq "INTERFACE") {
		my $ctype_name = $self->use_type_variable($ctype);
		unless (defined($ctype_name)) {
			error($location, "Unable to determine origin of type `" . mapTypeName($ctype) . "'");
			return "NULL"; # FIXME!
		}
		return "pytalloc_reference_ex($ctype_name, $mem_ctx, $cvar)";
	}

	fatal($location, "unknown type $actual_ctype->{TYPE} for ".mapTypeName($ctype) . ": $cvar");
}

sub fail_on_null($$$)
{
	my ($self, $var, $fail) = @_;
	$self->pidl("if ($var == NULL) {");
	$self->indent;
	$self->pidl($fail);
	$self->deindent;
	$self->pidl("}");
}

sub ConvertObjectToPythonLevel($$$$$$$)
{
	my ($self, $mem_ctx, $env, $e, $l, $var_name, $py_var, $fail, $recurse) = @_;
	my $nl = GetNextLevel($e, $l);
	if ($nl and $nl->{TYPE} eq "SUBCONTEXT") {
		$nl = GetNextLevel($e, $nl);
	}
	my $pl = GetPrevLevel($e, $l);
	if ($pl and $pl->{TYPE} eq "SUBCONTEXT") {
		$pl = GetPrevLevel($e, $pl);
	}

	if ($l->{TYPE} eq "POINTER") {
		my $need_wrap = 0;
		if ($l->{POINTER_TYPE} ne "ref" and $nl->{TYPE} eq "POINTER") {
			$need_wrap = 1;
		}
		if ($l->{POINTER_TYPE} ne "ref") {
			if ($recurse == 0) {
				$self->pidl("if ($var_name == NULL) {");
				$self->indent;
				$self->pidl("$py_var = Py_None;");
				$self->pidl("Py_INCREF($py_var);");
				$self->deindent;
				$self->pidl("} else {");
				$self->indent;
			} else {
				$self->pidl("{");
				$self->indent;
			}
			$recurse = $recurse + 1;
		}
		my $var_name2 = $var_name;
		my $recurse2 = $recurse;
		unless ($nl->{TYPE} eq "DATA" and Parse::Pidl::Typelist::scalar_is_reference($nl->{DATA_TYPE})) {
			$var_name2 = get_value_of($var_name);
			$recurse2 = 0;
		}
		$self->ConvertObjectToPythonLevel($var_name, $env, $e, $nl, $var_name2, $py_var, $fail, $recurse2);
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->deindent;
			$self->pidl("}");
		}
		if ($need_wrap) {
			my $py_var_wrap = undef;
			$need_wrap = 1;
			$self->pidl("{");
			$self->indent;
			$py_var_wrap = "py_$e->{NAME}_level_$l->{LEVEL_INDEX}";
			$self->pidl("PyObject *$py_var_wrap = $py_var;");
			my $ndr_pointer_typename = $self->import_type_variable("samba.dcerpc.base", "ndr_pointer");
			$self->pidl("$py_var = py_dcerpc_ndr_pointer_wrap($ndr_pointer_typename, $py_var_wrap);");
			$self->pidl("Py_XDECREF($py_var_wrap);");
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "ARRAY") {
		if ($pl && $pl->{TYPE} eq "POINTER") {
			$var_name = get_pointer_to($var_name);
		}

		if (is_charset_array($e, $l)) {
			# FIXME: Use Unix charset setting rather than utf-8
			$self->pidl("if ($var_name == NULL) {");
			$self->indent;
			$self->pidl("$py_var = Py_None;");
			$self->pidl("Py_INCREF($py_var);");
			$self->deindent;
			$self->pidl("} else {");
			$self->indent;
			$self->pidl("$py_var = PyUnicode_Decode($var_name, strlen($var_name), \"utf-8\", \"ignore\");");
			$self->deindent;
			$self->pidl("}");
		} else {
			die("No SIZE_IS for array $var_name") unless (defined($l->{SIZE_IS}));
			my $length = $l->{SIZE_IS};
			if (defined($l->{LENGTH_IS})) {
				$length = $l->{LENGTH_IS};
			}

			$length = ParseExpr($length, $env, $e);
			$self->pidl("$py_var = PyList_New($length);");
			$self->fail_on_null($py_var, $fail);
			$self->pidl("{");
			$self->indent;
			my $counter = "$e->{NAME}_cntr_$l->{LEVEL_INDEX}";
			$self->pidl("int $counter;");
			$self->pidl("for ($counter = 0; $counter < ($length); $counter++) {");
			$self->indent;
			my $member_var = "py_$e->{NAME}_$l->{LEVEL_INDEX}";
			$self->pidl("PyObject *$member_var;");
			if (ArrayDynamicallyAllocated($e, $l)) {
				$self->ConvertObjectToPythonLevel($var_name, $env, $e, $nl, "($var_name)"."[$counter]", $member_var, $fail, $recurse);
			} else {
				$self->ConvertObjectToPythonLevel($mem_ctx, $env, $e, $nl, "($var_name)"."[$counter]", $member_var, $fail, $recurse);
			}
			$self->pidl("PyList_SetItem($py_var, $counter, $member_var);");
			$self->deindent;
			$self->pidl("}");
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "SWITCH") {
		$var_name = get_pointer_to($var_name);
		my $switch = ParseExpr($l->{SWITCH_IS}, $env, $e);
		my $conv = $self->ConvertObjectToPythonData($mem_ctx, $nl->{DATA_TYPE}, $var_name, $e->{ORIGINAL}, $switch);
		$self->pidl("$py_var = $conv;");
		$self->fail_on_null($py_var, $fail);

	} elsif ($l->{TYPE} eq "DATA") {
		if (not Parse::Pidl::Typelist::is_scalar($l->{DATA_TYPE})) {
			$var_name = get_pointer_to($var_name);
		}
		my $conv = $self->ConvertObjectToPythonData($mem_ctx, $l->{DATA_TYPE}, $var_name, $e->{ORIGINAL});
		$self->pidl("$py_var = $conv;");
		if ($conv eq "NULL") {
			$self->pidl("PyErr_SetString(PyExc_NotImplementedError, \"Cannot convert NDR $var_name to Python\");");
			$self->pidl("$fail");
		}
	} elsif ($l->{TYPE} eq "SUBCONTEXT") {
		$self->ConvertObjectToPythonLevel($mem_ctx, $env, $e, $nl, $var_name, $py_var, $fail, $recurse);
	} else {
		fatal($e->{ORIGINAL}, "Unknown level type $l->{TYPE} $var_name");
	}
}

sub ConvertObjectToPython($$$$$$)
{
	my ($self, $mem_ctx, $env, $ctype, $cvar, $py_var, $fail) = @_;
	my $recurse = 0;

	$self->ConvertObjectToPythonLevel($mem_ctx, $env, $ctype, $ctype->{LEVELS}[0], $cvar, $py_var, $fail, $recurse);
}

sub Parse($$$$$)
{
    my($self,$basename,$ndr,$ndr_hdr,$hdr) = @_;

	$self->{BASENAME} = $basename;

        my $ndr_hdr_include = "";
	if (defined($ndr_hdr)) {
		$ndr_hdr_include = "#include \"$ndr_hdr\"";
	}
    $self->pidl_hdr("
/* Python wrapper functions auto-generated by pidl */
#define PY_SSIZE_T_CLEAN 1 /* We use Py_ssize_t for PyArg_ParseTupleAndKeywords */
#include \"lib/replace/system/python.h\"
#include \"python/py3compat.h\"
#include \"includes.h\"
#include \"python/modules.h\"
#include <pytalloc.h>
#include \"librpc/rpc/pyrpc.h\"
#include \"librpc/rpc/pyrpc_util.h\"
#include \"$hdr\"
$ndr_hdr_include

/*
 * Suppress compiler warnings if the generated code does not call these
 * functions
 */
#ifndef _MAYBE_UNUSED_
#ifdef __has_attribute
#if __has_attribute(unused)
#define _MAYBE_UNUSED_ __attribute__ ((unused))
#else
#define _MAYBE_UNUSED_
#endif
#endif
#endif
/*
 * These functions are here to ensure they can be optimized out by
 * the compiler based on the constant input values
 */

static inline unsigned long long ndr_sizeof2uintmax(size_t var_size)
{
	switch (var_size) {
	case 8:
		return UINT64_MAX;
	case 4:
		return UINT32_MAX;
	case 2:
		return UINT16_MAX;
	case 1:
		return UINT8_MAX;
	}

	return 0;
}

static inline _MAYBE_UNUSED_ long long ndr_sizeof2intmax(size_t var_size)
{
	switch (var_size) {
	case 8:
		return INT64_MAX;
	case 4:
		return INT32_MAX;
	case 2:
		return INT16_MAX;
	case 1:
		return INT8_MAX;
	}

	return 0;
}
");

	foreach my $x (@$ndr) {
		($x->{TYPE} eq "IMPORT") && $self->Import(@{$x->{PATHS}});
	    ($x->{TYPE} eq "INTERFACE") && $self->Interface($x, $basename);
	}

	$self->pidl("static PyMethodDef $basename\_methods[] = {");
	$self->indent;
	foreach (@{$self->{module_methods}}) {
		my ($fn_name, $pyfn_name, $flags, $doc) = @$_;
		$self->pidl("{ \"$fn_name\", (PyCFunction)$pyfn_name, $flags, $doc },");
	}

	$self->pidl("{ NULL, NULL, 0, NULL }");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	$self->pidl("static struct PyModuleDef moduledef = {");
	$self->indent;
	$self->pidl("PyModuleDef_HEAD_INIT,");
	$self->pidl(".m_name = \"$basename\",");
	$self->pidl(".m_doc = \"$basename DCE/RPC\",");
	$self->pidl(".m_size = -1,");
	$self->pidl(".m_methods = $basename\_methods,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("MODULE_INIT_FUNC($basename)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("PyObject *m = NULL;");
	foreach my $h (@{$self->{module_imports}}) {
		$self->pidl("PyObject *$h->{'key'} = NULL;");
	}
	$self->pidl("");

	foreach my $h (@{$self->{module_imports}}) {
		my $var_name = $h->{'key'};
		my $module_path = $h->{'val'};
		$self->pidl("$var_name = PyImport_ImportModule(\"$module_path\");");
		$self->pidl("if ($var_name == NULL)");
		$self->pidl("\tgoto out;");
		$self->pidl("");
	}

	foreach my $h (@{$self->{type_imports}}) {
		my $type_var = "$h->{'key'}\_Type";
		my $module_path = $h->{'val'};
		$self->pidl_hdr("static PyTypeObject *$type_var;");
		my $pretty_name = PrettifyTypeName($h->{'key'}, $module_path);
		my $module_var = "dep_$module_path";
		$module_var =~ s/\./_/g;
		$self->pidl("$type_var = (PyTypeObject *)PyObject_GetAttrString($module_var, \"$pretty_name\");");
		$self->pidl("if ($type_var == NULL)");
		$self->pidl("\tgoto out;");
		$self->pidl("");
	}

	$self->pidl($_) foreach (@{$self->{prereadycode}});

	foreach (@{$self->{ready_types}}) {
		$self->pidl("if (PyType_Ready($_) < 0)");
		$self->pidl("\tgoto out;");
	}

	$self->pidl($_) foreach (@{$self->{postreadycode}});

	foreach (@{$self->{patch_type_calls}}) {
		my ($typename, $cvar) = @$_;
		$self->pidl("#ifdef PY_".uc($typename)."_PATCH");
		$self->pidl("PY_".uc($typename)."_PATCH($cvar);");
		$self->pidl("#endif");
	}

	$self->pidl("");

	$self->pidl("m = PyModule_Create(&moduledef);");
	$self->pidl("if (m == NULL)");
	$self->pidl("\tgoto out;");
	$self->pidl("");
	foreach my $h (@{$self->{constants}}) {
		my $pretty_name = PrettifyTypeName($h->{'key'}, $basename);
		my $py_obj;
		my ($ctype, $cvar) = @{$h->{'val'}};
		if ($cvar =~ /^[0-9]+$/ or $cvar =~ /^0x[0-9a-fA-F]+$/) {
			$py_obj = "PyLong_FromUnsignedLongLong($cvar)";
		} elsif ($cvar =~ /^".*"$/) {
			$py_obj = "PyUnicode_FromString($cvar)";
		} else {
			$py_obj = $self->ConvertObjectToPythonData("NULL", expandAlias($ctype), $cvar, undef);
		}

		$self->pidl("PyModule_AddObject(m, \"$pretty_name\", $py_obj);");
	}

	foreach (@{$self->{module_objects}}) {
		my ($object_name, $c_name) = @$_;
		$self->pidl("Py_INCREF($c_name);");
		$self->pidl("PyModule_AddObject(m, \"$object_name\", $c_name);");
	}

	$self->pidl("#ifdef PY_MOD_".uc($basename)."_PATCH");
	$self->pidl("PY_MOD_".uc($basename)."_PATCH(m);");
	$self->pidl("#endif");
	$self->pidl("out:");
	foreach my $h (@{$self->{module_imports}}) {
		my $mod_var = $h->{'key'};
		$self->pidl("Py_XDECREF($mod_var);");
	}
	$self->pidl("return m;");
	$self->pidl("");
	$self->deindent;
	$self->pidl("}");
    return ($self->{res_hdr} . $self->{res});
}

1;
