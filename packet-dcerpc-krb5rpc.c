/* packet-dcerpc-krb5rpc.c
 *
 * Routines for dcerpc DCE/KRB5 interface
 * Copyright 2002, Jaime Fournier <jafour1@yahoo.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/krb5rpc.idl
 *
 *
 * $Id: packet-dcerpc-krb5rpc.c,v 1.2 2002/11/08 19:42:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_krb5rpc = -1;
static int hf_krb5rpc_opnum = -1;


static gint ett_krb5rpc = -1;


static e_uuid_t uuid_krb5rpc = { 0x8f73de50, 0x768c, 0x11ca, { 0xbf, 0xfc, 0x08, 0x00, 0x1e, 0x03, 0x94, 0x31 } };
static guint16  ver_krb5rpc = 1;


static dcerpc_sub_dissector krb5rpc_dissectors[] = {
	{ 0, "rsec_krb5rpc_sendto_kdc", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

static const value_string krb5rpc_opnum_vals[] = {
	{ 0, "rsec_krb5rpc_sendto_kdc" },
	{ 0, NULL }
};

void
proto_register_krb5rpc (void)
{
	static hf_register_info hf[] = {
	  { &hf_krb5rpc_opnum,
	    { "Operation", "krb5rpc.opnum", FT_UINT16, BASE_DEC,
	      VALS(krb5rpc_opnum_vals), 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_krb5rpc,
	};
	proto_krb5rpc = proto_register_protocol ("DCE/RPC Kerberos V", "KRB5RPC", "krb5rpc");
	proto_register_field_array (proto_krb5rpc, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_krb5rpc (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_krb5rpc, ett_krb5rpc, &uuid_krb5rpc, ver_krb5rpc, krb5rpc_dissectors, hf_krb5rpc_opnum);
}
