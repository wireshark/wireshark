/* packet-dcerpc-rs_pwd_mgmt.c
 *
 * Routines for rs_pwd_mgmt dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_pwd_mgmt.idl
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

static int proto_rs_pwd_mgmt = -1;
static int hf_rs_pwd_mgmt_opnum = -1;


static gint ett_rs_pwd_mgmt = -1;
static e_uuid_t uuid_rs_pwd_mgmt =
  { 0x3139a0e2, 0x68da, 0x11cd, {0x91, 0xc7, 0x08, 0x00, 0x09, 0x24, 0x24,
				 0x44} };

static guint16 ver_rs_pwd_mgmt = 1;


static dcerpc_sub_dissector rs_pwd_mgmt_dissectors[] = {
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
proto_register_rs_pwd_mgmt (void)
{
  static hf_register_info hf[] = {
    {&hf_rs_pwd_mgmt_opnum,
     {"Operation", "rs_pwd_mgmt.opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      "Operation", HFILL}},
  };

  static gint *ett[] = {
    &ett_rs_pwd_mgmt,
  };
  proto_rs_pwd_mgmt =
    proto_register_protocol ("DCE/RPC Registry Password Management ",
			     "rs_pwd_mgmt", "rs_pwd_mgmt");
  proto_register_field_array (proto_rs_pwd_mgmt, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_pwd_mgmt (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_rs_pwd_mgmt, ett_rs_pwd_mgmt, &uuid_rs_pwd_mgmt,
		    ver_rs_pwd_mgmt, rs_pwd_mgmt_dissectors,
		    hf_rs_pwd_mgmt_opnum);
}
