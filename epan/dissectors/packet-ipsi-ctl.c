/* packet-ipsi-ctl.c
 * Routines for Avaya IPSI Control packet disassembly
 * Traffic is encapsulated Avaya proprietary CCMS
 * (Control Channel Message Set) between PCD and SIM
 *
 * Copyright 2008, Randy McEoin <rmceoin@ahbelo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_ipsictl(void);
void proto_reg_handoff_ipsictl(void);

static dissector_handle_t ipsictl_handle;

#define IPSICTL_PORT            5010 /* Not IANA registered */
#define IPSICTL_PDU_MAGIC       0x0300

static int proto_ipsictl;

static int hf_ipsictl_pdu;
static int hf_ipsictl_magic;
static int hf_ipsictl_length;
static int hf_ipsictl_type;
static int hf_ipsictl_sequence;
static int hf_ipsictl_field1;
static int hf_ipsictl_data;

static int ett_ipsictl;
static int ett_ipsictl_pdu;

static int dissect_ipsictl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

  proto_tree   *ipsictl_tree;
  proto_tree   *pdu_tree;
  proto_item   *ti;
  int           offset = 0;
  int           loffset = 0;
  int           llength = 0;
  int           remaining_length;
  uint16_t      magic;
  uint16_t      length;
  uint16_t      type=0;
  uint16_t      sequence=0;
  int           first_sequence=-1;
  int           last_sequence=-1;
  uint16_t      field1=0;
  uint16_t      pdu=0;
  int           haspdus=0;

  remaining_length=tvb_reported_length_remaining(tvb, offset);

  ti = proto_tree_add_item(tree, proto_ipsictl, tvb, offset, remaining_length, ENC_NA);
  ipsictl_tree = proto_item_add_subtree(ti, ett_ipsictl);

  magic = tvb_get_ntohs(tvb, offset);
  if (magic == IPSICTL_PDU_MAGIC)
  {
    haspdus=1;
  }

  while (haspdus &&
    ((remaining_length=tvb_reported_length_remaining(tvb, offset)) > 6))
  {
    loffset = offset;

    magic = tvb_get_ntohs(tvb, loffset); loffset+=2;
    length = tvb_get_ntohs(tvb, loffset); loffset+=2;
    llength=length;
    remaining_length-=4;
    if (remaining_length>=2)
    {
      type = tvb_get_ntohs(tvb, loffset); loffset+=2;
      remaining_length-=2;
      llength-=2;
    }
    if (remaining_length>=2)
    {
      sequence = tvb_get_ntohs(tvb, loffset); loffset+=2;
      remaining_length-=2;
      llength-=2;
      if (first_sequence==-1)
      {
        first_sequence=sequence;
      }else{
        last_sequence=sequence;
      }
    }
    if (remaining_length>=2)
    {
      field1 = tvb_get_ntohs(tvb, loffset);
      llength-=2;
    }

    ti = proto_tree_add_uint(ipsictl_tree, hf_ipsictl_pdu, tvb,
           offset, (length+4), pdu);
    pdu_tree = proto_item_add_subtree(ti, ett_ipsictl_pdu);

    loffset=offset;
    remaining_length=tvb_reported_length_remaining(tvb, offset);

    if (tree) {
      proto_tree_add_uint(pdu_tree, hf_ipsictl_magic, tvb, loffset, 2, magic);
    }
    loffset+=2; remaining_length-=2;
    if (tree) {
      proto_tree_add_uint(pdu_tree, hf_ipsictl_length, tvb, loffset, 2, length);
    }
    loffset+=2; remaining_length-=2;

    if (remaining_length>=2)
    {
      if (tree) {
        proto_tree_add_uint(pdu_tree, hf_ipsictl_type, tvb, loffset, 2, type);
      }
      loffset+=2; remaining_length-=2;
    }
    if (remaining_length>=2)
    {
      if (tree) {
        proto_tree_add_uint(pdu_tree, hf_ipsictl_sequence, tvb, loffset, 2, sequence);
      }
      loffset+=2; remaining_length-=2;
    }
    if (remaining_length>=2)
    {
      if (tree) {
        proto_tree_add_uint(pdu_tree, hf_ipsictl_field1, tvb, loffset, 2, field1);
      }
      loffset+=2; remaining_length-=2;
    }
    if (remaining_length>=2)
    {
      if (tree) {
        proto_tree_add_item(pdu_tree, hf_ipsictl_data, tvb, loffset, llength, ENC_NA);
      }
      loffset+=llength;
    }

    offset=loffset;
    pdu++;
  }

  if (!haspdus)
  {
    proto_tree_add_item(ipsictl_tree, hf_ipsictl_data, tvb, offset, -1, ENC_NA);
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPSICTL");

  if (haspdus)
  {
    if (last_sequence==-1)
    {
      col_add_fstr(pinfo->cinfo, COL_INFO, "PDUS=%d, Seq=0x%04x",
        pdu,first_sequence);
    }else{
      col_add_fstr(pinfo->cinfo, COL_INFO, "PDUS=%d, Seq=0x%04x-0x%04x",
        pdu,first_sequence,last_sequence);
    }
  }else{
    col_set_str(pinfo->cinfo, COL_INFO, "Initialization");
  }

  return tvb_captured_length(tvb);

} /* dissect_ipsictl */

void proto_register_ipsictl(void)
{

  static hf_register_info hf[] = {
    { &hf_ipsictl_pdu,
      { "PDU",  "ipsictl.pdu",
        FT_UINT16,      BASE_DEC,       NULL,   0x0,
        "IPSICTL PDU", HFILL }},
    { &hf_ipsictl_magic,
      { "Magic",        "ipsictl.magic",
        FT_UINT16,      BASE_HEX,       NULL,   0x0,
        "IPSICTL Magic", HFILL }},
    { &hf_ipsictl_length,
      { "Length",       "ipsictl.length",
        FT_UINT16,      BASE_HEX,       NULL,   0x0,
        "IPSICTL Length", HFILL }},
    { &hf_ipsictl_type,
      { "Type", "ipsictl.type",
        FT_UINT16,      BASE_HEX,       NULL,   0x0,
        "IPSICTL Type", HFILL }},
    { &hf_ipsictl_sequence,
      { "Sequence",     "ipsictl.sequence",
        FT_UINT16,      BASE_HEX,       NULL,   0x0,
        "IPSICTL Sequence", HFILL }},
    { &hf_ipsictl_field1,
      { "Field1",       "ipsictl.field1",
        FT_UINT16,      BASE_HEX,       NULL,   0x0,
        "IPSICTL Field1", HFILL }},
    { &hf_ipsictl_data,
      { "Data", "ipsictl.data",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        "IPSICTL data", HFILL }},
  };

  static int *ett[] = {
    &ett_ipsictl,
    &ett_ipsictl_pdu
  };

  proto_ipsictl = proto_register_protocol("IPSICTL", "IPSICTL", "ipsictl");
  proto_register_field_array(proto_ipsictl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ipsictl_handle = register_dissector("ipsictl", dissect_ipsictl, proto_ipsictl);
}

void proto_reg_handoff_ipsictl(void)
{

  dissector_add_uint_with_preference("tcp.port", IPSICTL_PORT, ipsictl_handle);

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
