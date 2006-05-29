/* packet-dcerpc-roverride.c
 *
 * Routines for Remote Override Interface
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/roverride.idl
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


static int proto_roverride = -1;
static int hf_roverride_opnum = -1;


static gint ett_roverride = -1;


static e_uuid_t uuid_roverride = { 0x5d978990, 0x4851, 0x11ca, { 0x99, 0x37, 0x08, 0x00, 0x1e, 0x03, 0x94, 0x48 } };
static guint16  ver_roverride = 1;


static dcerpc_sub_dissector roverride_dissectors[] = {
    { 0, "roverride_get_login_info", NULL, NULL},
    { 1, "roverride_check_passwd", NULL, NULL},
    { 2, "roverride_is_passwd_overridden", NULL, NULL},
    { 3, "roverride_get_by_unix_num", NULL, NULL},
    { 4, "roverride_get_group_info", NULL, NULL},
    { 5, "roverride_check_group_passwd", NULL, NULL},
    { 6, "roverride_is_grp_pwd_overridden", NULL, NULL},
    { 0, NULL, NULL, NULL }
};

void
proto_register_roverride (void)
{
	static hf_register_info hf[] = {
      { &hf_roverride_opnum,
         { "Operation", "roverride.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
	};

	static gint *ett[] = {
		&ett_roverride,
	};
	proto_roverride = proto_register_protocol ("Remote Override interface", "roverride", "roverride");
	proto_register_field_array (proto_roverride, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_roverride (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_roverride, ett_roverride, &uuid_roverride, ver_roverride, roverride_dissectors, hf_roverride_opnum);
}
