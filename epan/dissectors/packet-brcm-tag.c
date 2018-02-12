/* packet-brcm-tag.c
 * Routines for Broadcom tag dissection
 *
 * Copyright 2017, Florian Fainelli <f.fainelli[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/ptvcursor.h>

void proto_register_brcm_tag(void);
void proto_reg_handoff_brcm_tag(void);

#define BRCM_TAG_LEN                    4
#define BRCM_TAG_OPCODE_MASK            0x7
#define BRCM_TAG_DEV_ID_MASK            0x3
#define BRCM_TAG_SRC_DEV_ID_SHIFT       4
#define BRCM_TAG_PORT_ID_MASK           0xF

#define BRCM_TAG_OPCODE_UNICAST         0x0
#define BRCM_TAG_OPCODE_MULTICAST       0x1
#define BRCM_TAG_OPCODE_EG_DIRECT       0x2
#define BRCM_TAG_OPCODE_IG_DIRECT       0x3
#define BRCM_TAG_OPCODE_SHIFT           5

#define BRCM_TAG_MR_SHIFT               4
#define BRCM_TAG_MO_SHIFT               3

static int proto_brcm_tag               = -1;

static int hf_brcm_tag_opcode           = -1;
static int hf_brcm_tag_frame_octet_cnt  = -1;
static int hf_brcm_tag_mr               = -1;
static int hf_brcm_tag_mo               = -1;
static int hf_brcm_tag_reserved         = -1;
static int hf_brcm_tag_dest_dev_id      = -1;
static int hf_brcm_tag_dest_port_id     = -1;
static int hf_brcm_tag_src_dev_id       = -1;
static int hf_brcm_tag_src_port_id      = -1;

static gint ett_brcm_tag                = -1;

#define TVB_LEN_GREATEST  1
#define TVB_LEN_UNDEF     0
#define TVB_LEN_SHORTEST -1

static int check_tvb_length(ptvcursor_t *cursor, const gint length)
{
   if (!cursor)
      return TVB_LEN_UNDEF;

   if (tvb_reported_length_remaining(ptvcursor_tvbuff(cursor),
            ptvcursor_current_offset(cursor)) < length)
      return TVB_LEN_SHORTEST;

   return TVB_LEN_GREATEST;
}

static const value_string brcm_tag_opcode_vals[] = {
   { BRCM_TAG_OPCODE_UNICAST, "Unicast" },
   { BRCM_TAG_OPCODE_MULTICAST, "Multicast" },
   { BRCM_TAG_OPCODE_EG_DIRECT, "Egress directed" },
   { BRCM_TAG_OPCODE_IG_DIRECT, "Ingress directed" },
   { 0, NULL }
};

static int
dissect_brcm_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item  *ti;
   proto_tree  *brcm_tag_tree;
   ptvcursor_t *cursor;
   guint8 opcode_mr_mo;
   guint8 opcode;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "Broadcom tag");
   col_set_str(pinfo->cinfo, COL_INFO, "MAC Management");

   ti = proto_tree_add_item(tree, proto_brcm_tag, tvb, 0, -1, ENC_NA);
   brcm_tag_tree = proto_item_add_subtree(ti, ett_brcm_tag);

   cursor = ptvcursor_new(brcm_tag_tree, tvb, 0);

   /* Check if we have enough data to process the header */
   if (check_tvb_length(cursor, BRCM_TAG_LEN) != TVB_LEN_SHORTEST) {
      opcode_mr_mo = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
      opcode = (opcode_mr_mo >> BRCM_TAG_OPCODE_SHIFT) & BRCM_TAG_OPCODE_MASK;

      ptvcursor_add_no_advance(cursor, hf_brcm_tag_opcode, 1, ENC_NA);
      ptvcursor_add_no_advance(cursor, hf_brcm_tag_mr, 1, ENC_NA);
      ptvcursor_add(cursor, hf_brcm_tag_mo, 1, ENC_NA);
      ptvcursor_add(cursor, hf_brcm_tag_frame_octet_cnt, 2, ENC_BIG_ENDIAN);

      if (opcode == BRCM_TAG_OPCODE_UNICAST || opcode == BRCM_TAG_OPCODE_EG_DIRECT)
         ptvcursor_add(cursor, hf_brcm_tag_dest_dev_id, 1, ENC_NA);
      else
         ptvcursor_add(cursor, hf_brcm_tag_reserved, 1, ENC_NA);
      ptvcursor_add_no_advance(cursor, hf_brcm_tag_src_dev_id, 1, ENC_NA);
      if (opcode == BRCM_TAG_OPCODE_EG_DIRECT)
         ptvcursor_add_no_advance(cursor, hf_brcm_tag_dest_port_id, 1, ENC_NA);
      else
         ptvcursor_add_no_advance(cursor, hf_brcm_tag_src_port_id, 1, ENC_NA);
   }

   ptvcursor_free(cursor);
   return tvb_captured_length(tvb);
}

void
proto_register_brcm_tag(void)
{
   static hf_register_info hf[] = {
      { &hf_brcm_tag_opcode,
         { "Opcode", "brcm_tag.opcode",
            FT_UINT8, BASE_HEX, VALS(brcm_tag_opcode_vals),
            BRCM_TAG_OPCODE_MASK << BRCM_TAG_OPCODE_SHIFT, NULL, HFILL }
      },
      { &hf_brcm_tag_mr,
         { "Mirror bit", "brcm_tag.mr",
            FT_UINT8, BASE_HEX, NULL, 1 << BRCM_TAG_MR_SHIFT, NULL, HFILL }
      },
      { &hf_brcm_tag_mo,
         { "Mirror only", "brcm_tag.mo",
            FT_UINT8, BASE_HEX, NULL, 1 << BRCM_TAG_MO_SHIFT, NULL, HFILL }
      },
      { &hf_brcm_tag_reserved,
         { "Reserved", "brcm_tag.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_brcm_tag_frame_octet_cnt,
         { "Frame octet count", "brcm_tag.frame_octet_cnt",
            FT_UINT16, BASE_DEC, NULL, 0xFFF, NULL, HFILL }
      },
      { &hf_brcm_tag_dest_dev_id,
         { "Destination device ID", "brcm_tag.dest_dev_id",
            FT_UINT8, BASE_DEC, NULL, BRCM_TAG_DEV_ID_MASK, NULL, HFILL }
      },
      { &hf_brcm_tag_dest_port_id,
         { "Destination port ID", "brcm_tag.dest_port_id",
            FT_UINT8, BASE_DEC, NULL, BRCM_TAG_PORT_ID_MASK, NULL, HFILL }
      },
      { &hf_brcm_tag_src_dev_id,
         { "Source device ID", "brcm_tag.src_dev_id",
            FT_UINT8, BASE_DEC, NULL, BRCM_TAG_DEV_ID_MASK << BRCM_TAG_SRC_DEV_ID_SHIFT, NULL, HFILL }
      },
      { &hf_brcm_tag_src_port_id,
         { "Source port ID", "brcm_tag.src_port_id",
            FT_UINT8, BASE_DEC, NULL, BRCM_TAG_PORT_ID_MASK, NULL, HFILL }
      },
   };

   static gint *ett[] = {
      &ett_brcm_tag,
   };
   proto_brcm_tag = proto_register_protocol("Broadcom tag protocol", "Broadcom tag", "brcm-tag");

   proto_register_field_array(proto_brcm_tag, hf, array_length(hf));

   proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_brcm_tag(void)
{
   dissector_handle_t brcm_tag_handle;

   brcm_tag_handle = create_dissector_handle(dissect_brcm_tag, proto_brcm_tag);
   dissector_add_uint("ethertype", ETHERTYPE_BRCM_TYPE, brcm_tag_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
