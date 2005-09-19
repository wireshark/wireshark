###################################################
# IDL Compatibility checker
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Compat;

use Parse::Pidl::Util qw(has_property);
use strict;

my %supported_properties = (
	# interface
	"helpstring"		=> ["INTERFACE", "FUNCTION"],
	"version"		=> ["INTERFACE"],
	"uuid"			=> ["INTERFACE"],
	"endpoint"		=> ["INTERFACE"],
	"pointer_default"	=> ["INTERFACE"],

	# dcom
	"object"		=> ["INTERFACE"],
	"local"			=> ["INTERFACE", "FUNCTION"],
	"iid_is"		=> ["ELEMENT"],
	"call_as"		=> ["FUNCTION"],
	"idempotent"		=> ["FUNCTION"],

	# function
	"in"			=> ["ELEMENT"],
	"out"			=> ["ELEMENT"],

	# pointer
	"ref"			=> ["ELEMENT"],
	"ptr"			=> ["ELEMENT"],
	"unique"		=> ["ELEMENT"],
	"ignore"		=> ["ELEMENT"],

	"value"			=> ["ELEMENT"],

	# generic
	"public"		=> ["FUNCTION", "TYPEDEF"],
	"nopush"		=> ["FUNCTION", "TYPEDEF"],
	"nopull"		=> ["FUNCTION", "TYPEDEF"],
	"noprint"		=> ["FUNCTION", "TYPEDEF"],
	"noejs"			=> ["FUNCTION", "TYPEDEF"],

	# union
	"switch_is"		=> ["ELEMENT"],
	"switch_type"		=> ["ELEMENT", "TYPEDEF"],
	"case"			=> ["ELEMENT"],
	"default"		=> ["ELEMENT"],

	# subcontext
	"subcontext"		=> ["ELEMENT"],
	"subcontext_size"	=> ["ELEMENT"],

	# enum
	"enum16bit"		=> ["TYPEDEF"],
	"v1_enum"		=> ["TYPEDEF"],

	# bitmap
	"bitmap8bit"		=> ["TYPEDEF"],
	"bitmap16bit"		=> ["TYPEDEF"],
	"bitmap32bit"		=> ["TYPEDEF"],
	"bitmap64bit"		=> ["TYPEDEF"],

	# array
	"range"			=> ["ELEMENT"],
	"size_is"		=> ["ELEMENT"],
	"string"		=> ["ELEMENT"],
	"noheader"		=> ["ELEMENT"],
	"charset"		=> ["ELEMENT"],
	"length_is"		=> ["ELEMENT"],
);


my($res);

sub warning($$)
{
	my $l = shift;
	my $m = shift;

	print "$l->{FILE}:$l->{LINE}:Warning:$m\n";
}

sub error($$)
{
	my ($l,$m) = @_;
	print "$l->{FILE}:$l->{LINE}:$m\n";
}

sub CheckTypedef($)
{
	my $td = shift;

	if (has_property($td, "nodiscriminant")) {
		error($td, "nodiscriminant property not supported");
	}

	if ($td->{TYPE} eq "BITMAP") {
		warning($td, "converting bitmap to scalar");
		#FIXME
	}

	if (has_property($td, "gensize")) {
		warning($td, "ignoring gensize() property. ");
	}

	if (has_property($td, "enum8bit") and has_property($td, "enum16bit")) {
		warning($td, "8 and 16 bit enums not supported, converting to scalar");
		#FIXME
	}

	StripProperties($td);
}

sub CheckElement($)
{
	my $e = shift;

	if (has_property($e, "noheader")) {
		error($e, "noheader property not supported");
		return;
	}

	if (has_property($e, "subcontext")) {
		warning($e, "converting subcontext to byte array");
		#FIXME
	}

	if (has_property($e, "compression")) {
		error($e, "compression() property not supported");
	}

	if (has_property($e, "obfuscation")) {
		error($e, "obfuscation() property not supported");
	}

	if (has_property($e, "sptr")) {
		error($e, "sptr() pointer property not supported");
	}

	if (has_property($e, "relative")) {
		error($e, "relative() pointer property not supported");
	}

	if (has_property($td, "flag")) {
		warning($e, "ignoring flag() property");
	}
	
	if (has_property($td, "value")) {
		warning($e, "ignoring value() property");
	}

	StripProperties($e);
}

sub CheckFunction($)
{
	my $fn = shift;

	if (has_property($fn, "noopnum")) {
		error($fn, "noopnum not converted. Opcodes will be out of sync.");
	}

	StripProperties($fn);


}

sub CheckInterface($)
{
	my $if = shift;

	if (has_property($if, "pointer_default_top") and 
		$if->{PROPERTIES}->{pointer_default_top} ne "ref") {
		error($if, "pointer_default_top() is pidl-specific");
	}

	StripProperties($if);

	foreach my $x (@{$if->{DATA}}) {
		if ($x->{TYPE} eq "DECLARE") {
			warning($if, "the declare keyword is pidl-specific");
			next;
		}
	}
}

sub Check($)
{
	my $pidl = shift;
	my $nidl = [];
	my $res = "";

	foreach my $x (@{$pidl}) {
		push (@$nidl, CheckInterface($x)) 
			if ($x->{TYPE} eq "INTERFACE");
	}

	return $res;
}

1;
