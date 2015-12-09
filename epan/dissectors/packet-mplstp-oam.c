/* packet-mplstp-oam.c
*
* Routines for MPLS-TP Lock Instruct Protocol    : RFC 6435
*              MPLS-TP Fault-Management Protocol : RFC 6427
*
* Authors:
* Krishnamurthy Mayya <krishnamurthymayya@gmail.com>
* Nikitha Malgi <nikitha01@gmail.com>
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
#include "packet-bfd.h"

void proto_register_mplstp_lock(void);
void proto_register_mplstp_fm(void);
void proto_reg_handoff_mplstp_lock(void);
void proto_reg_handoff_mplstp_fm(void);

/* MPLS-TP FM protocol specific variables */
static gint proto_mplstp_fm     = -1;
static gint ett_mplstp_fm       = -1;
static gint ett_mplstp_fm_flags = -1;
static gint ett_mplstp_fm_tlv_tree     = -1;

static int hf_mplstp_fm_version         = -1;

static int hf_mplstp_fm_reserved        = -1;
static int hf_mplstp_fm_msg_type        = -1;
static int hf_mplstp_fm_flags           = -1;
static int hf_mplstp_fm_flags_l         = -1;
static int hf_mplstp_fm_flags_r         = -1;
static int hf_mplstp_fm_refresh_timer   = -1;
static int hf_mplstp_fm_total_tlv_len   = -1;
static int hf_mplstp_fm_if_tlv_type     = -1;
static int hf_mplstp_fm_global_tlv_type = -1;
static int hf_mplstp_fm_tlv_len         = -1;
static int hf_mplstp_fm_node_id         = -1;
static int hf_mplstp_fm_if_num          = -1;
static int hf_mplstp_fm_global_id       = -1;

static const value_string fm_msg_type[] = {
  {0, "No Return Code"},
  {1, "Alarm-Indication Signal(A)"},
  {2, "Lock-Report(L)"},
  {0, NULL}
};

/* MPLS-TP Lock protocol specific variables */
static gint proto_mplstp_lock = -1;
static gint ett_mplstp_lock   = -1;

static int hf_mplstp_lock_version       = -1;
static int hf_mplstp_lock_reserved      = -1;
static int hf_mplstp_lock_refresh_timer = -1;

static void
dissect_mplstp_fm_tlv (tvbuff_t *tvb, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fm_tlv_tree;

  guint offset = 0;

  if (!tree)
    return;

  ti = proto_tree_add_protocol_format (tree, proto_mplstp_fm, tvb, offset, 16,
                                       "Fault-Management TLVs");

  fm_tlv_tree = proto_item_add_subtree (ti, ett_mplstp_fm_tlv_tree);

  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_if_tlv_type , tvb, offset,
                                    1, ENC_BIG_ENDIAN);
  offset = offset + 1;
  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_tlv_len, tvb, offset,
                                    1, ENC_BIG_ENDIAN);
  offset = offset + 1;
  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_node_id, tvb, offset,
                                    4, ENC_BIG_ENDIAN);
  offset = offset + 4;
  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_if_num, tvb, offset,
                                    4, ENC_BIG_ENDIAN);
  offset = offset + 4;
  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_global_tlv_type , tvb, offset,
                                    1, ENC_BIG_ENDIAN);
  offset = offset + 1;
  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_tlv_len, tvb, offset,
                                    1, ENC_BIG_ENDIAN);
  offset = offset + 1;
  proto_tree_add_item (fm_tlv_tree, hf_mplstp_fm_global_id, tvb, offset,
                                    4, ENC_BIG_ENDIAN);
  /* offset = offset + 4; */

  return;
}

/* Dissector for MPLS-TP LI protocol: RFC 6435 */
static int
dissect_mplstp_lock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *lock_tree;
  tvbuff_t   *next_tvb;

  guint8      offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS-TP LI");
  col_clear(pinfo->cinfo, COL_INFO);

  if (!tree)
    return tvb_captured_length(tvb);

  ti = proto_tree_add_item(tree, proto_mplstp_lock, tvb, 0, -1, ENC_NA);

  lock_tree = proto_item_add_subtree (ti, ett_mplstp_lock);

  /* Version field */
  proto_tree_add_item (lock_tree, hf_mplstp_lock_version , tvb, offset,
                       1, ENC_BIG_ENDIAN);

  /* Reserved field */
  proto_tree_add_item (lock_tree, hf_mplstp_lock_reserved, tvb, offset,
                       3, ENC_BIG_ENDIAN);
  offset = offset + 3;

  /* Refresh-Timer field */
  proto_tree_add_item (lock_tree, hf_mplstp_lock_refresh_timer, tvb, offset,
                       1, ENC_BIG_ENDIAN);
  offset = offset + 1;

  /* Source-MEP TLVs  */
  next_tvb = tvb_new_subset_remaining (tvb, offset);
  dissect_bfd_mep (next_tvb, tree, proto_mplstp_lock);

  return tvb_captured_length(tvb);
}


/* Dissector for MPLS-TP FM protocol: RFC 6427 */
static int
dissect_mplstp_fm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item *ti, *ti_flags;
   proto_tree *fm_tree, *fm_flags;

   guint8 offset = 0;
   guint8 tlv_len;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS-TP FM");
   col_clear(pinfo->cinfo, COL_INFO);

   tlv_len = tvb_get_guint8 (tvb, (offset + 4));

   if (!tree)
     return tvb_captured_length(tvb);

   ti = proto_tree_add_item(tree, proto_mplstp_fm, tvb, 0, (tlv_len + 5), ENC_NA);
   fm_tree = proto_item_add_subtree (ti, ett_mplstp_fm);

   /* Version and Reserved fields */
   proto_tree_add_item (fm_tree, hf_mplstp_fm_version , tvb, offset,
                        1, ENC_BIG_ENDIAN);
   proto_tree_add_item (fm_tree, hf_mplstp_fm_reserved, tvb, offset,
                        1, ENC_BIG_ENDIAN);
   offset = offset + 1;

   /* FM-Message type field */
   proto_tree_add_item (fm_tree, hf_mplstp_fm_msg_type, tvb, offset,
                        1,ENC_BIG_ENDIAN);
   offset = offset + 1;

   /* Flags field */
   ti_flags = proto_tree_add_item (fm_tree, hf_mplstp_fm_flags, tvb,
                                   offset, 1, ENC_BIG_ENDIAN);
   fm_flags = proto_item_add_subtree(ti_flags, ett_mplstp_fm_flags);

   proto_tree_add_item (fm_flags, hf_mplstp_fm_flags_l, tvb, offset, 1, ENC_BIG_ENDIAN);
   proto_tree_add_item (fm_flags, hf_mplstp_fm_flags_r, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset = offset + 1;

   /* Refresh-Timer field */
   proto_tree_add_item (fm_tree, hf_mplstp_fm_refresh_timer, tvb, offset,
                        1, ENC_BIG_ENDIAN);
   offset = offset + 1;

   /* FM-TLV Length field*/
   proto_tree_add_item (fm_tree, hf_mplstp_fm_total_tlv_len, tvb, offset,
                        1, ENC_BIG_ENDIAN);
   offset = offset + 1;

   if (tlv_len != 0)
     {
       tvbuff_t *next_tvb;

       /* FM TLVs*/
       next_tvb = tvb_new_subset_remaining (tvb, offset);
       dissect_mplstp_fm_tlv (next_tvb, tree);
     }
   return tvb_captured_length(tvb);
}

void
proto_register_mplstp_lock(void)
{
  static hf_register_info hf[] = {

    {&hf_mplstp_lock_version,
     {"Version", "mplstp_lock.version", FT_UINT8,
      BASE_HEX, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_lock_reserved,
     {"Reserved", "mplstp_lock.reserved", FT_UINT24,
      BASE_HEX, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_lock_refresh_timer,
     {"Refresh-timer value", "mplstp_lock.refresh-timer", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_mplstp_lock,
  };

  proto_mplstp_lock =
    proto_register_protocol("MPLS-TP Lock-Instruct", "MPLS[-TP] Lock-Instruct "
                            "Lock-Instruct (LI) Protocol",
                            "mplstp_lock");

  proto_register_field_array(proto_mplstp_lock, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mplstp_lock(void)
{
  dissector_handle_t mplstp_lock_handle;

  mplstp_lock_handle    = create_dissector_handle( dissect_mplstp_lock, proto_mplstp_lock );
  dissector_add_uint("pwach.channel_type", 0x0026, mplstp_lock_handle); /* KM: MPLSTP LOCK, RFC 6435 */
}

void
proto_register_mplstp_fm(void)
{
  static hf_register_info hf[] = {

    {&hf_mplstp_fm_version,
     {"Version", "mplstp_oam.version", FT_UINT8,
      BASE_HEX, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_reserved,
     {"Reserved", "mplstp_oam.reserved", FT_UINT8,
      BASE_HEX, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_refresh_timer,
     {"Refresh-timer value", "mplstp_oam.refresh.timer", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_total_tlv_len,
     {"FM TLV Length", "mplstp_oam.total.tlv.len", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_if_tlv_type,
     {"Type     : IF-ID TLV", "mplstp_oam.if_id_tlv_type", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_global_tlv_type,
     {"Type     : GLOBAL-ID TLV", "mplstp_oam.global_id_tlv_type", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_tlv_len,
     {"Length", "mplstp_oam.tlv_len", FT_UINT8,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_node_id,
     {"Node id", "mplstp_oam.node_id", FT_IPv4,
      BASE_NONE, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_if_num,
     {"Interface Number", "mplstp_oam.if_num", FT_UINT32,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_global_id,
     {"Global id", "mplstp_oam.global_id", FT_UINT32,
      BASE_DEC, NULL, 0x0, NULL, HFILL }},

    {&hf_mplstp_fm_msg_type,
     {"Message Type", "mplstp_oam.message.type", FT_UINT8,
      BASE_DEC, VALS(fm_msg_type), 0x0, "MPLS-TP FM Message Type", HFILL }},

    { &hf_mplstp_fm_flags,
      { "FM Flags", "mplstp_oam.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0000, "MPLS-TP FM Flags", HFILL}
    },

    { &hf_mplstp_fm_flags_l,
      { "Link Down Indication", "mplstp_oam.flag_l",
        FT_BOOLEAN, 8, NULL, 0x0002, NULL, HFILL}
    },

    { &hf_mplstp_fm_flags_r,
      { "FM Condition Cleared", "mplstp_oam.flag_r",
        FT_BOOLEAN, 8, NULL, 0x0001, "Fault Condition Cleared", HFILL}
    },
  };

  static gint *ett[] = {
    &ett_mplstp_fm,
    &ett_mplstp_fm_tlv_tree,
    &ett_mplstp_fm_flags,
  };

  proto_mplstp_fm =
    proto_register_protocol("MPLS-TP Fault-Management", "MPLS[-TP] Fault-Management "
                            "Fault-Management (FM) Protocol",
                            "mplstp_fm");

  proto_register_field_array(proto_mplstp_fm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mplstp_fm(void)
{
  dissector_handle_t mplstp_fm_handle;

  mplstp_fm_handle = create_dissector_handle( dissect_mplstp_fm, proto_mplstp_fm );
  dissector_add_uint("pwach.channel_type", 0x0058, mplstp_fm_handle); /* KM: MPLSTP FM, RFC 6427 */
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
