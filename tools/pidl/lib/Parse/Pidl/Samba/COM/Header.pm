# COM Header generation
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>

package Parse::Pidl::Samba::COM::Header;

use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property);

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

sub GetArgumentProtoList($)
{
	my $f = shift;
	my $res = "";

	foreach my $a (@{$f->{ELEMENTS}}) {

		$res .= ", " . Parse::Pidl::Typelist::mapType($a->{TYPE}) . " ";

		my $l = $a->{POINTERS};
		$l-- if (Parse::Pidl::Typelist::scalar_is_reference($a->{TYPE}));
		foreach my $i (1..$l) {
			$res .= "*";
		}

		if (defined $a->{ARRAY_LEN}[0] && 
		!Parse::Pidl::Util::is_constant($a->{ARRAY_LEN}[0]) &&
		!$a->{POINTERS}) {
			$res .= "*";
		}
		$res .= $a->{NAME};
		if (defined $a->{ARRAY_LEN}[0] && Parse::Pidl::Util::is_constant($a->{ARRAY_LEN}[0])) {
			$res .= "[$a->{ARRAY_LEN}[0]]";
		}
	}

	return $res;
}

sub GetArgumentList($)
{
	my $f = shift;
	my $res = "";

	foreach my $a (@{$f->{ELEMENTS}}) {
		$res .= ", $a->{NAME}";
	}

	return $res;
}

#####################################################################
# generate vtable structure for COM interface
sub HeaderVTable($)
{
	my $interface = shift;
	my $res;
	$res .= "#define " . uc($interface->{NAME}) . "_METHODS \\\n";
	if (defined($interface->{BASE})) {
		$res .= "\t" . uc($interface->{BASE} . "_METHODS") . "\\\n";
	}

	my $data = $interface->{DATA};
	foreach my $d (@{$data}) {
		$res .= "\t" . Parse::Pidl::Typelist::mapType($d->{RETURN_TYPE}) . " (*$d->{NAME}) (struct $interface->{NAME} *d, TALLOC_CTX *mem_ctx" . GetArgumentProtoList($d) . ");\\\n" if ($d->{TYPE} eq "FUNCTION");
	}
	$res .= "\n";
	$res .= "struct $interface->{NAME}_vtable {\n";
	$res .= "\tstruct GUID iid;\n";
	$res .= "\t" . uc($interface->{NAME}) . "_METHODS\n";
	$res .= "};\n\n";

	return $res;
}

sub ParseInterface($)
{
	my $if = shift;
	my $res;

	$res .="\n\n/* $if->{NAME} */\n";

	$res .="#define COM_" . uc($if->{NAME}) . "_UUID $if->{PROPERTIES}->{uuid}\n\n";

	$res .="struct $if->{NAME}_vtable;\n\n";

	$res .="struct $if->{NAME} {
	struct com_context *ctx;
	struct $if->{NAME}_vtable *vtable;
	void *object_data;
};\n\n";

	$res.=HeaderVTable($if);

	foreach my $d (@{$if->{DATA}}) {
		next if ($d->{TYPE} ne "FUNCTION");

		$res .= "#define $if->{NAME}_$d->{NAME}(interface, mem_ctx" . GetArgumentList($d) . ") ";

		$res .= "((interface)->vtable->$d->{NAME}(interface, mem_ctx" . GetArgumentList($d) . "))";

		$res .="\n";
	}

	return $res;
}

sub ParseCoClass($)
{
	my $c = shift;
	my $res = "";
	$res .= "#define CLSID_" . uc($c->{NAME}) . " $c->{PROPERTIES}->{uuid}\n";
	if (has_property($c, "progid")) {
		$res .= "#define PROGID_" . uc($c->{NAME}) . " $c->{PROPERTIES}->{progid}\n";
	}
	$res .= "\n";
	return $res;
}

sub Parse($)
{
	my $idl = shift;
	my $res = "";

	foreach my $x (@{$idl})
	{
		if ($x->{TYPE} eq "INTERFACE" && has_property($x, "object")) {
			$res.=ParseInterface($x);
		} 

		if ($x->{TYPE} eq "COCLASS") {
			$res.=ParseCoClass($x);
		}
	}

	return $res;
}

1;
