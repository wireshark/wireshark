/* packet-dcerpc-rs_prop_acl.c
 *
 * Routines for rs_prop_acl dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_prop_acl.idl
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_rs_prop_acl (void);
void proto_reg_handoff_rs_prop_acl (void);

static int proto_rs_prop_acl;
static int hf_rs_prop_acl_opnum;


static int ett_rs_prop_acl;
static e_guid_t uuid_rs_prop_acl =
  { 0x591d87d0, 0xde64, 0x11ca, {0xa1, 0x1c, 0x08, 0x00, 0x1e, 0x03, 0x94,
                                 0xc7} };

static uint16_t ver_rs_prop_acl = 1;


static const dcerpc_sub_dissector rs_prop_acl_dissectors[] = {
  {0, "replace", NULL, NULL},
  {0, NULL, NULL, NULL}
};

void
proto_register_rs_prop_acl (void)
{
  static hf_register_info hf[] = {
    {&hf_rs_prop_acl_opnum,
     {"Operation", "rs_prop_acl.opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}},
  };

  static int *ett[] = {
    &ett_rs_prop_acl,
  };
  proto_rs_prop_acl =
    proto_register_protocol
    ("DCE/RPC Registry server propagation interface - ACLs", "rs_prop_acl",
     "rs_prop_acl");
  proto_register_field_array (proto_rs_prop_acl, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_prop_acl (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_rs_prop_acl, ett_rs_prop_acl, &uuid_rs_prop_acl,
                    ver_rs_prop_acl, rs_prop_acl_dissectors,
                    hf_rs_prop_acl_opnum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
