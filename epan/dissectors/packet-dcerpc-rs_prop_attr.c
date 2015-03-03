/* packet-dcerpc-rs_prop_attr.c
 *
 * Routines for rs_prop_attr dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_prop_attr.idl
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

void proto_register_rs_prop_attr (void);
void proto_reg_handoff_rs_prop_attr (void);

static int proto_rs_prop_attr = -1;
static int hf_rs_prop_attr_opnum = -1;


static gint ett_rs_prop_attr = -1;
static e_guid_t uuid_rs_prop_attr =
  { 0x0eff23e6, 0x555a, 0x11cd, {0x95, 0xbf, 0x08, 0x00, 0x09, 0x27, 0x84,
                                 0xc3} };

static guint16 ver_rs_prop_attr = 1;


static dcerpc_sub_dissector rs_prop_attr_dissectors[] = {
  {0, "update", NULL, NULL},
  {1, "delete", NULL, NULL},
  {0, NULL, NULL, NULL}
};

void
proto_register_rs_prop_attr (void)
{
  static hf_register_info hf[] = {
    {&hf_rs_prop_attr_opnum,
     {"Operation", "rs_prop_attr.opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_rs_prop_attr,
  };
  proto_rs_prop_attr =
    proto_register_protocol ("DCE/RPC Prop Attr", "rs_prop_attr",
                             "rs_prop_attr");
  proto_register_field_array (proto_rs_prop_attr, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_prop_attr (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_rs_prop_attr, ett_rs_prop_attr, &uuid_rs_prop_attr,
                    ver_rs_prop_attr, rs_prop_attr_dissectors,
                    hf_rs_prop_attr_opnum);
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
