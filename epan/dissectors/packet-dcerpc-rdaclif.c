/* packet-dcerpc-rdaclif.c
 *
 * Routines for rdaclif dissection
 * Copyright 2004, Jaime Fournier <jaime.fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz ../security/idl/rdaclif.idl
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

void proto_register_rdaclif (void);
void proto_reg_handoff_rdaclif (void);

static int proto_rdaclif;
static int hf_rdaclif_opnum;


static gint ett_rdaclif;
static e_guid_t uuid_rdaclif =
  { 0x47b33331, 0x8000, 0x0000, {0x0d, 0x00, 0x01, 0xdc, 0x6c, 0x00, 0x00,
                                 0x00} };

static guint16 ver_rdaclif = 1;


static const dcerpc_sub_dissector rdaclif_dissectors[] = {
  {0, "lookup",                  NULL, NULL},
  {1, "replace",                 NULL, NULL},
  {2, "get_access",              NULL, NULL},
  {3, "test_access",             NULL, NULL},
  {4, "test_access_on_behalf",   NULL, NULL},
  {5, "get_manager_types",       NULL, NULL},
  {6, "get_printstring",         NULL, NULL},
  {7, "get_referral",            NULL, NULL},
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
