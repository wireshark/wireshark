###################################################
# server template function generator
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package Parse::Pidl::Samba4::Template;

use vars qw($VERSION);
$VERSION = '0.01';

use Parse::Pidl::Util qw(genpad);

use strict;
use warnings;

my($res);

#####################################################################
# produce boilerplate code for a interface
sub Template($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $name = $interface->{NAME};

	$res .=
"/*
   Unix SMB/CIFS implementation.

   endpoint server for the $name pipe

   Copyright (C) YOUR NAME HERE YEAR

   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include \"includes.h\"
#include \"rpc_server/dcerpc_server.h\"
#include \"librpc/gen_ndr/ndr_$name.h\"
#include \"rpc_server/common/common.h\"

";

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			my $fname = $d->{NAME};
			my $pad = genpad("static $d->{RETURN_TYPE} dcesrv_$fname");
			$res .=
"
/*
  $fname
*/

static $d->{RETURN_TYPE} dcesrv_$fname(struct dcesrv_call_state *dce_call,
$pad"."TALLOC_CTX *mem_ctx,
$pad"."struct $fname *r)
{
";

	if ($d->{RETURN_TYPE} eq "void") {
		$res .= "\tDCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);\n";
	} else {
		$res .= "\tDCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);\n";
	}

	$res .= "}

";
		}
	}

	$res .=
"
/* include the generated boilerplate */
#include \"librpc/gen_ndr/ndr_$name\_s.c\"
"
}


#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($)
{
	my($idl) = shift;
	$res = "";
	foreach my $x (@{$idl}) {
		($x->{TYPE} eq "INTERFACE") &&
		    Template($x);
	}
	return $res;
}

1;
