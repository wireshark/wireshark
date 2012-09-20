/* packet-dcerpc-llb.c
 *
 * Routines for llb dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/admin.tar.gz ./admin/dced/idl/llb.idl
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
#include "packet-dcerpc-dce122.h"


static int proto_llb = -1;
static int hf_llb_opnum = -1;

static gint ett_llb = -1;


static e_uuid_t uuid_llb =
  { 0x333b33c3, 0x0000, 0x0000, {0x0d, 0x00, 0x00, 0x87, 0x84, 0x00, 0x00,
				 0x00} };
static guint16 ver_llb = 4;


static dcerpc_sub_dissector llb_dissectors[] = {
  {0, "insert", NULL, NULL},
  {1, "delete", NULL, NULL},
  {2, "lookup", NULL, NULL},
  {0, NULL, NULL, NULL}
};

void
proto_register_llb (void)
{
  static hf_register_info hf[] = {
    {&hf_llb_opnum,
     {"Operation", "llb.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
      HFILL}},
  };

  static gint *ett[] = {
    &ett_llb,
  };
  proto_llb =
    proto_register_protocol ("DCE/RPC NCS 1.5.1 Local Location Broker", "llb",
			     "llb");
  proto_register_field_array (proto_llb, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_llb (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_llb, ett_llb, &uuid_llb, ver_llb, llb_dissectors,
		    hf_llb_opnum);
}
