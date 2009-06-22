/* packet-dcerpc-rs_replist.c
 *
 * Routines for dcerpc RepServer Calls
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_repadm.idl
 *      
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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


static int proto_rs_replist = -1;
static int hf_rs_replist_opnum = -1;


static gint ett_rs_replist = -1;


static e_uuid_t uuid_rs_replist = { 0x850446b0, 0xe95b, 0x11CA, { 0xad, 0x90, 0x08, 0x00, 0x1e, 0x01, 0x45, 0xb1 } };
static guint16  ver_rs_replist = 2;


static dcerpc_sub_dissector rs_replist_dissectors[] = {
    { 0, "rs_replist_add_replica", NULL, NULL},
    { 1, "rs_replist_replace_replica", NULL, NULL},
    { 2, "rs_replist_delete_replica", NULL, NULL},
    { 3, "rs_replist_read", NULL, NULL},
    { 4, "rs_replist_read_full", NULL, NULL},
    { 5, "rs_replist_add_replica", NULL, NULL},
    { 6, "rs_replist_replace_replica", NULL, NULL},
    { 7, "rs_replist_delete_replica", NULL, NULL},
    { 8, "rs_replist_read", NULL, NULL},
    { 9, "rs_replist_read_full", NULL, NULL},
    { 0, NULL, NULL, NULL }
};

void
proto_register_rs_replist (void)
{
	static hf_register_info hf[] = {
	{ &hf_rs_replist_opnum,
		{ "Operation", "rs_replist.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
	};

	static gint *ett[] = {
		&ett_rs_replist,
	};
	proto_rs_replist = proto_register_protocol ("DCE/RPC Repserver Calls", "RS_REPLIST", "rs_replist");

	proto_register_field_array (proto_rs_replist, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_replist (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_replist, ett_rs_replist, &uuid_rs_replist, ver_rs_replist, rs_replist_dissectors, hf_rs_replist_opnum);
}
