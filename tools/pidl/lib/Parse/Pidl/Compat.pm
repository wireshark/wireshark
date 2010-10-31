###################################################
# IDL Compatibility checker
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Compat;

use Parse::Pidl qw(warning);
use Parse::Pidl::Util qw(has_property);
use strict;

use vars qw($VERSION);
$VERSION = '0.01';

my %supported_properties = (
	# interface
	"helpstring"		=> ["INTERFACE", "FUNCTION"],
	"version"		=> ["INTERFACE"],
	"uuid"			=> ["INTERFACE"],
	"endpoint"		=> ["INTERFACE"],
	"pointer_default"	=> ["INTERFACE"],
	"no_srv_register"	=> ["INTERFACE"],

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
        "nopython"              => ["FUNCTION", "TYPEDEF"],

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

sub CheckTypedef($)
{
	my ($td) = @_;

	if (has_property($td, "nodiscriminant")) {
		warning($td, "nodiscriminant property not supported");
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
		warning($e, "noheader property not supported");
		return;
	}

	if (has_property($e, "subcontext")) {
		warning($e, "converting subcontext to byte array");
		#FIXME
	}

	if (has_property($e, "compression")) {
		warning($e, "compression() property not supported");
	}

	if (has_property($e, "sptr")) {
		warning($e, "sptr() pointer property not supported");
	}

	if (has_property($e, "relative")) {
		warning($e, "relative() pointer property not supported");
	}

	if (has_property($e, "relative_short")) {
		warning($e, "relative_short() pointer property not supported");
	}

	if (has_property($e, "flag")) {
		warning($e, "ignoring flag() property");
	}
	
	if (has_property($e, "value")) {
		warning($e, "ignoring value() property");
	}
}

sub CheckFunction($)
{
	my $fn = shift;

	if (has_property($fn, "noopnum")) {
		warning($fn, "noopnum not converted. Opcodes will be out of sync.");
	}
}

sub CheckInterface($)
{
	my $if = shift;

}

sub Check($)
{
	my $pidl = shift;
	my $nidl = [];

	foreach (@{$pidl}) {
		push (@$nidl, CheckInterface($_)) if ($_->{TYPE} eq "INTERFACE");
	}
}

1;
