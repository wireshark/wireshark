/* packet-macmgmt.c
 * Routines for docsis Mac Management Header dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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

#define MGT_SYNC 1
#define MGT_UCD 2
#define MGT_MAP 3
#define MGT_RNG_REQ 4
#define MGT_RNG_RSP 5
#define MGT_REG_REQ 6
#define MGT_REG_RSP 7
#define MGT_UCC_REQ 8
#define MGT_UCC_RSP 9
#define MGT_TRI_TCD 10
#define MGT_TRI_TSI 11
#define MGT_BPKM_REQ 12
#define MGT_BPKM_RSP 13
#define MGT_REG_ACK 14
#define MGT_DSA_REQ 15
#define MGT_DSA_RSP 16
#define MGT_DSA_ACK 17
#define MGT_DSC_REQ 18
#define MGT_DSC_RSP 19
#define MGT_DSC_ACK 20
#define MGT_DSD_REQ 21
#define MGT_DSD_RSP 22
#define MGT_DCC_REQ 23
#define MGT_DCC_RSP 24
#define MGT_DCC_ACK 25
#define MGT_DCI_REQ 26
#define MGT_DCI_RSP 27
#define MGT_UP_DIS 28
#define MGT_TYPE29UCD 29
#define MGT_INIT_RNG_REQ 30
#define MGT_TEST_REQ 31
#define MGT_DS_CH_DESC 32
#define MGT_MDD 33
#define MGT_B_INIT_RNG_REQ 34
#define MGT_TYPE35UCD 35
#define MGT_DBC_REQ 36
#define MGT_DBC_RSP 37
#define MGT_DBC_ACK 38
#define MGT_DPV_REQ 39
#define MGT_DPV_RSP 40
#define MGT_CM_STATUS 41
#define MGT_CM_CTRL_REQ 42
#define MGT_CM_CTRL_RSP 43
#define MGT_REG_REQ_MP 44
#define MGT_REG_RSP_MP 45
#define MGT_EM_REQ 46
#define MGT_EM_RSP 47
#define MGT_STATUS_ACK 48
#define MGT_OCD 49
#define MGT_DPD 50


void proto_register_docsis_mgmt(void);
void proto_reg_handoff_docsis_mgmt(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_mgmt = -1;
static int hf_docsis_mgt_dst_addr = -1;
static int hf_docsis_mgt_src_addr = -1;
static int hf_docsis_mgt_msg_len = -1;
static int hf_docsis_mgt_dsap = -1;
static int hf_docsis_mgt_ssap = -1;
static int hf_docsis_mgt_control = -1;
static int hf_docsis_mgt_version = -1;
static int hf_docsis_mgt_type = -1;
static int hf_docsis_mgt_rsvd = -1;

static dissector_table_t docsis_mgmt_dissector_table;

/* Initialize the subtree pointers */
static gint ett_docsis_mgmt = -1;
static gint ett_mgmt_pay = -1;

static const value_string mgmt_type_vals[] = {
  {MGT_SYNC,           "Timing Synchronisation"},
  {MGT_UCD,            "Upstream Channel Descriptor"},
  {MGT_TYPE29UCD,      "Upstream Channel Descriptor Type 29"},
  {MGT_TYPE35UCD,      "Upstream Channel Descriptor Type 35"},
  {MGT_MAP,            "Upstream Bandwidth Allocation"},
  {MGT_RNG_REQ,        "Ranging Request"},
  {MGT_RNG_RSP,        "Ranging Response"},
  {MGT_REG_REQ,        "Registration Request"},
  {MGT_REG_RSP,        "Registration Response"},
  {MGT_UCC_REQ,        "Upstream Channel Change Request"},
  {MGT_UCC_RSP,        "Upstream Channel Change Response"},
  {MGT_TRI_TCD,        "Telephony Channel Descriptor"},
  {MGT_TRI_TSI,        "Termination System Information"},
  {MGT_BPKM_REQ,       "Privacy Key Management Request"},
  {MGT_BPKM_RSP,       "Privacy Key Management Response"},
  {MGT_REG_ACK,        "Registration Acknowledge"},
  {MGT_DSA_REQ,        "Dynamic Service Addition Request"},
  {MGT_DSA_RSP,        "Dynamic Service Addition Response"},
  {MGT_DSA_ACK,        "Dynamic Service Addition  Acknowledge"},
  {MGT_DSC_REQ,        "Dynamic Service Change Request"},
  {MGT_DSC_RSP,        "Dynamic Service Change Response"},
  {MGT_DSC_ACK,        "Dynamic Service Change Acknowledge"},
  {MGT_DSD_REQ,        "Dynamic Service Delete Request"},
  {MGT_DSD_RSP,        "Dynamic Service Delete Response"},
  {MGT_DCC_REQ,        "Dynamic Channel Change Request"},
  {MGT_DCC_RSP,        "Dynamic Channel Change Response"},
  {MGT_DCC_ACK,        "Dynamic Channel Change Acknowledge"},
  {MGT_DCI_REQ,        "Device Class Identification Request"},
  {MGT_DCI_RSP,        "Device Class Identification Response"},
  {MGT_UP_DIS,         "Upstream Channel Disable"},
  {MGT_INIT_RNG_REQ,   "Initial Ranging Request"},
  {MGT_TEST_REQ,       "Test Request Message"},
  {MGT_DS_CH_DESC,     "Downstream Channel Descriptor"},
  {MGT_MDD,            "MAC Domain Descriptor"},
  {MGT_B_INIT_RNG_REQ, "Bonded Initial Ranging Request"},
  {MGT_DBC_REQ,        "Dynamic Bonding Change Request"},
  {MGT_DBC_RSP,        "Dynamic Bonding Change Response"},
  {MGT_DBC_ACK,        "Dynamic Bonding Change Acknowledge"},
  {MGT_DPV_REQ,        "DOCSIS Path Verify Request"},
  {MGT_DPV_RSP,        "DOCSIS Path Verify Response"},
  {MGT_CM_STATUS,      "CM Status Report"},
  {MGT_CM_CTRL_REQ,    "CM Control Request"},
  {MGT_CM_CTRL_RSP,    "CM Control Response"},
  {MGT_REG_REQ_MP,     "Multipart Registration Request"},
  {MGT_REG_RSP_MP,     "Multipart Registration Response"},
  {MGT_EM_REQ,         "Energy Management Request"},
  {MGT_EM_RSP,         "Energy Management Response"},
  {MGT_STATUS_ACK,     "Status Report Acknowledge"},
  {MGT_OCD,            "OFDM Channel Descriptor"},
  {MGT_DPD,            "Downstream Profile Descriptor"},
  {0, NULL}
};

/* Dissection */
static int
dissect_macmgmt (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 msg_len;
  proto_item *mgt_hdr_it;
  proto_tree *mgt_hdr_tree;
  tvbuff_t *payload_tvb;
  guint8 type;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "DOCSIS MGMT");

  col_clear(pinfo->cinfo, COL_INFO);

  set_address_tvb (&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  set_address_tvb (&pinfo->dl_dst, AT_ETHER, 6, tvb, 0);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

  if (tree)
    {
      mgt_hdr_it =
        proto_tree_add_protocol_format (tree, proto_docsis_mgmt, tvb, 0, 20,
                                        "Mac Management");
      mgt_hdr_tree = proto_item_add_subtree (mgt_hdr_it, ett_docsis_mgmt);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dst_addr, tvb, 0, 6,
                           ENC_NA);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_src_addr, tvb, 6, 6,
                           ENC_NA);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_msg_len, tvb, 12, 2,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dsap, tvb, 14, 1,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_ssap, tvb, 15, 1,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_control, tvb, 16, 1,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_version, tvb, 17, 1,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_type, tvb, 18, 1,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_rsvd, tvb, 19, 1,
                           ENC_BIG_ENDIAN);
    }
  /* Code to Call subdissector */
  /* sub-dissectors are based on the type field */
  type = tvb_get_guint8 (tvb, 18);
  msg_len = tvb_get_ntohs (tvb, 12);
  payload_tvb = tvb_new_subset_length (tvb, 20, msg_len - 6);

  if (!dissector_try_uint(docsis_mgmt_dissector_table, type, payload_tvb, pinfo, tree))
    call_data_dissector(payload_tvb, pinfo, tree);

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_mgmt (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_mgt_dst_addr,
     {"Destination Address", "docsis_mgmt.dst",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_src_addr,
     {"Source Address", "docsis_mgmt.src",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_msg_len,
     {"Message Length - DSAP to End (Bytes)", "docsis_mgmt.msglen",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Message Length", HFILL}
    },
    {&hf_docsis_mgt_dsap,
     {"DSAP [0x00]", "docsis_mgmt.dsap",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Destination SAP", HFILL}
    },
    {&hf_docsis_mgt_ssap,
     {"SSAP [0x00]", "docsis_mgmt.ssap",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Source SAP", HFILL}
    },
    {&hf_docsis_mgt_control,
     {"Control [0x03]", "docsis_mgmt.control",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Control", HFILL}
    },
    {&hf_docsis_mgt_version,
     {"Version", "docsis_mgmt.version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_type,
     {"Type", "docsis_mgmt.type",
      FT_UINT8, BASE_DEC, VALS (mgmt_type_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_rsvd,
     {"Reserved [0x00]", "docsis_mgmt.rsvd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reserved", HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_mgmt,
    &ett_mgmt_pay,
  };

  proto_docsis_mgmt = proto_register_protocol ("DOCSIS Mac Management",
                                               "DOCSIS MAC MGMT",
                                               "docsis_mgmt");

  proto_register_field_array (proto_docsis_mgmt, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  docsis_mgmt_dissector_table = register_dissector_table ("docsis_mgmt",
                                                          "DOCSIS Mac Management", proto_docsis_mgmt,
                                                          FT_UINT8, BASE_DEC);

  register_dissector ("docsis_mgmt", dissect_macmgmt, proto_docsis_mgmt);
}

void
proto_reg_handoff_docsis_mgmt (void)
{
#if 0
  dissector_handle_t docsis_mgmt_handle;

  docsis_mgmt_handle = find_dissector ("docsis_mgmt");
  dissector_add_uint ("docsis", 0x03, docsis_mgmt_handle);
#endif
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
