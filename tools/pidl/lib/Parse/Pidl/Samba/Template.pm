###################################################
# server template function generator
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package Parse::Pidl::Samba::Template;

use vars qw($VERSION);
$VERSION = '0.01';

use strict;

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
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include \"includes.h\"
#include \"rpc_server/dcerpc_server.h\"
#include \"librpc/gen_ndr/ndr_$name.h\"
#include \"rpc_server/common/common.h\"

";

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			my $fname = $d->{NAME};
			$res .=
"
/* 
  $fname 
*/
static $d->{RETURN_TYPE} $fname(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct $fname *r)
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
