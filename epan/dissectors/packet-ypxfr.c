/* packet-ypxfr.c
 * Routines for ypxfr dissection
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



#include "packet-rpc.h"
#include "packet-ypxfr.h"

static int proto_ypxfr = -1;
static int hf_ypxfr_procedure_v1 = -1;

static gint ett_ypxfr = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff ypxfr1_proc[] = {
	{ YPXFRPROC_NULL,	"NULL",		NULL,		NULL },
	{ YPXFRPROC_GETMAP,	"GETMAP",	NULL,		NULL },
	{ 0,			NULL,		NULL,		NULL }
};
static const value_string ypxfr1_proc_vals[] = {
	{ YPXFRPROC_NULL,	"NULL" },
	{ YPXFRPROC_GETMAP,	"GETMAP" },
	{ 0,			NULL }
};
/* end of YPXFR version 1 */

void
proto_register_ypxfr(void)
{
	static hf_register_info hf[] = {
		{ &hf_ypxfr_procedure_v1, {
			"V1 Procedure", "ypxfr.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(ypxfr1_proc_vals), 0, "V1 Procedure", HFILL }}
	};

	static gint *ett[] = {
		&ett_ypxfr
	};

	proto_ypxfr = proto_register_protocol("Yellow Pages Transfer",
	    "YPXFR", "ypxfr");
	proto_register_field_array(proto_ypxfr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ypxfr(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_ypxfr, YPXFR_PROGRAM, ett_ypxfr);
	/* Register the procedure tables */
	rpc_init_proc_table(YPXFR_PROGRAM, 1, ypxfr1_proc, hf_ypxfr_procedure_v1);
}
