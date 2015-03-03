/* packet-dcerpc-rs_attr_schema.c
 *
 * Routines for rs_attr_schema dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_attr_schema.idl
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


#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_rs_attr_schema (void);
void proto_reg_handoff_rs_attr_schema (void);

static int proto_rs_attr_schema = -1;
static int hf_rs_attr_schema_opnum = -1;


static gint ett_rs_attr_schema = -1;
static e_guid_t uuid_rs_attr_schema =
  { 0xb47c9460, 0x567f, 0x11cb, {0x8c, 0x09, 0x08, 0x00, 0x1e, 0x04, 0xde,
                                 0x8c} };
static guint16 ver_rs_attr_schema = 0;


static dcerpc_sub_dissector rs_attr_schema_dissectors[] = {
  {0, "create_entry",   NULL, NULL},
  {1, "delete_entry",   NULL, NULL},
  {2, "update_entry",   NULL, NULL},
  {3, "cursor_init",    NULL, NULL},
  {4, "scan",           NULL, NULL},
  {5, "lookup_by_name", NULL, NULL},
  {6, "lookup_by_id",   NULL, NULL},
  {7, "get_referral",   NULL, NULL},
  {8, "get_acl_mgrs",   NULL, NULL},
  {9, "aclmgr_strings", NULL, NULL},
  {0, NULL, NULL, NULL}
};

void
proto_register_rs_attr_schema (void)
{
  static hf_register_info hf[] = {
    {&hf_rs_attr_schema_opnum,
     {"Operation", "rs_attr_schema.opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_rs_attr_schema,
  };
  proto_rs_attr_schema =
    proto_register_protocol ("DCE/RPC Registry Server Attributes Schema",
                             "rs_attr_schema", "rs_attr_schema");
  proto_register_field_array (proto_rs_attr_schema, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_attr_schema (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_rs_attr_schema, ett_rs_attr_schema,
                    &uuid_rs_attr_schema, ver_rs_attr_schema,
                    rs_attr_schema_dissectors, hf_rs_attr_schema_opnum);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
