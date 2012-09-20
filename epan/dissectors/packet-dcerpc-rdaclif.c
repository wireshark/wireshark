/* packet-dcerpc-rdaclif.c
 *
 * Routines for rdaclif dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz ../security/idl/rdaclif.idl
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"

static int proto_rdaclif = -1;
static int hf_rdaclif_opnum = -1;


static gint ett_rdaclif = -1;
static e_uuid_t uuid_rdaclif =
  { 0x47b33331, 0x8000, 0x0000, {0x0d, 0x00, 0x01, 0xdc, 0x6c, 0x00, 0x00,
				 0x00} };

static guint16 ver_rdaclif = 1;


static dcerpc_sub_dissector rdaclif_dissectors[] = {
  {0, "lookup", NULL, NULL},
  {1, "replace", NULL, NULL},
  {2, "get_access", NULL, NULL},
  {3, "test_access", NULL, NULL},
  {4, "test_access_on_behalf", NULL, NULL},
  {5, "get_manager_types", NULL, NULL},
  {6, "get_printstring", NULL, NULL},
  {7, "get_referral", NULL, NULL},
  {8, "get_mgr_types_semantics", NULL, NULL},
  {0, NULL, NULL, NULL}
};

void
proto_register_rdaclif (void)
{
  static hf_register_info hf[] = {
    {&hf_rdaclif_opnum,
     {"Operation", "rdaclif.opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_rdaclif,
  };
  proto_rdaclif =
    proto_register_protocol ("DCE/RPC Directory Acl Interface", "rdaclif",
			     "rdaclif");
  proto_register_field_array (proto_rdaclif, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rdaclif (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_rdaclif, ett_rdaclif, &uuid_rdaclif, ver_rdaclif,
		    rdaclif_dissectors, hf_rdaclif_opnum);
}
