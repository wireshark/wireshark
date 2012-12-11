/* packet-pw-oam.c
*
* Routines for Pseudowire Status for static pseudowires : RFC 6478
*
* (c) Copyright 2012, Krishnamurthy Mayya <krishnamurthymayya@gmail.com>
*                     Nikitha Malgi <nikitha01@gmail.com>     
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

/* MPLS-TP FM protocol specific variables */
static gint proto_pw_oam             = -1;
static gint ett_pw_oam               = -1;
static gint ett_pw_oam_flags         = -1;
static gint ett_pw_oam_tlv_tree      = -1;

static int hf_pw_oam_tlv_reserved    = -1;
static int hf_pw_oam_tlv_type        = -1;
static int hf_pw_oam_total_tlv_len   = -1;
static int hf_pw_oam_code            = -1;
static int hf_pw_oam_flags           = -1;
static int hf_pw_oam_flags_a         = -1;
static int hf_pw_oam_refresh_timer   = -1;
static int hf_pw_oam_tlv_len         = -1;

static const value_string pw_oam_code[] = {
  {0x00000002, "Local Attachment Circuit(ingress) Receive Fault"},
  {0x00000004, "Local Attachment Circuit(egress) Transmit Fault"},
  {0x00000020, "PW Forwarding Standby"},
  {0x00000040, "Request Switchover to this PW"},
  {0, NULL}
};

/* PW-Status TLV dissector */
void
dissect_pw_status_tlv (tvbuff_t *tvb, proto_tree *tree, gint offset)
{
  proto_item *ti;
  proto_tree *pw_oam_tlv_tree;


  ti = proto_tree_add_protocol_format (tree, proto_pw_oam, tvb, offset, 8, 
                                       "Pseudo-Wire Status TLV");


  if (!tree)
    return;

  pw_oam_tlv_tree = proto_item_add_subtree (ti, ett_pw_oam_tlv_tree);

  proto_tree_add_item (pw_oam_tlv_tree, hf_pw_oam_tlv_reserved, tvb, offset,
                                    2, ENC_BIG_ENDIAN);
  proto_tree_add_item (pw_oam_tlv_tree, hf_pw_oam_tlv_type, tvb, offset,
                                    2, ENC_BIG_ENDIAN);
  offset = offset + 2;

  proto_tree_add_item (pw_oam_tlv_tree, hf_pw_oam_tlv_len, tvb, offset,
                                    2, ENC_BIG_ENDIAN);
  offset = offset + 2;
  proto_tree_add_item (pw_oam_tlv_tree, hf_pw_oam_code, tvb, offset,
                                    4, ENC_BIG_ENDIAN);
  offset = offset + 4;

  return ;
}

/* Dissector for PW OAM protocol: RFC 6478 */
static void
dissect_pw_oam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item  *ti = NULL, *ti_flags = NULL;
  proto_tree  *pw_oam_tree = NULL, *pw_oam_flags = NULL;

  guint8  offset        = 0;
  guint16 pw_tlv_type   = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PW OAM");
  col_clear(pinfo->cinfo, COL_INFO);

  if (!tree)
    return;

  ti = proto_tree_add_item(tree, proto_pw_oam, tvb, 0, -1, ENC_NA);

  pw_oam_tree = proto_item_add_subtree (ti, ett_pw_oam);

  /* Refresh-Timer field */
  proto_tree_add_item (pw_oam_tree, hf_pw_oam_refresh_timer, tvb, offset,
                       2, ENC_BIG_ENDIAN);
  offset = offset + 2;

  /* Total-TLV length */
  proto_tree_add_item (pw_oam_tree, hf_pw_oam_total_tlv_len, tvb, offset,
                       1, ENC_BIG_ENDIAN);
  offset = offset + 1;

  /* Flags field */
  ti_flags = proto_tree_add_item (pw_oam_tree, hf_pw_oam_flags, tvb, 
                                  offset, 1, ENC_BIG_ENDIAN);
  pw_oam_flags = proto_item_add_subtree(ti_flags, ett_pw_oam_flags);
  proto_tree_add_item (pw_oam_flags, hf_pw_oam_flags_a, tvb, offset, 1, FALSE);

  offset = offset + 1;
  pw_tlv_type = tvb_get_ntohs (tvb, offset);

  /* TLVs  */
  switch (pw_tlv_type)
    {
      /* The switch cases below have to be based on the LDP-name space.
          http://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xml */

      case 0x096A: /* PW-Status TLV */
        dissect_pw_status_tlv (tvb, tree, offset);
        break;

      default:
        break;
    }

  return;
}

void
proto_register_pw_oam(void)
{
  static hf_register_info hf[] = {

    {&hf_pw_oam_refresh_timer,
      {"Refresh-Timer", "pw_oam.refresh-timer", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL }},

    {&hf_pw_oam_total_tlv_len,
      {"TLV Length", "pw_oam.total-tlv-len", FT_UINT8,
        BASE_HEX, NULL, 0x0, NULL, HFILL }},

    {&hf_pw_oam_flags,
      {"Flags", "pw_oam.flags", FT_UINT8,
        BASE_HEX, NULL, 0x0000, "OAM Flags", HFILL }},

    {&hf_pw_oam_flags_a,
      {"Acknowledgement", "pw_oam.flags_a",
        FT_BOOLEAN, 8, NULL, 0x0080, "ACK bit", HFILL}
    },

    {&hf_pw_oam_tlv_reserved,
      {"Reserved", "pw_oam.tlv-reserved",
        FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL}
    },

    {&hf_pw_oam_tlv_type,
      {"TLV Type", "pw_oam.tlv-type",
        FT_UINT16, BASE_HEX, NULL, 0x3FFF, NULL, HFILL}
    },

    {&hf_pw_oam_tlv_len,
      {"TLV Length", "pw_oam.tlv-len",
        FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },

    {&hf_pw_oam_code,
      {"Status code", "pw_oam.code", FT_UINT16,
        BASE_HEX, VALS(pw_oam_code), 0x0, "PW Status Code", HFILL }
    },

  };

  static gint *ett[] = {
    &ett_pw_oam,
    &ett_pw_oam_tlv_tree,
    &ett_pw_oam_flags,
  };

  proto_pw_oam =
    proto_register_protocol("Pseudo-Wire OAM", "PW-OAM "
        "Pseudo-Wire OAM Protocol",
        "pw_oam");

  proto_register_field_array (proto_pw_oam, hf, array_length(hf));
  proto_register_subtree_array (ett, array_length(ett));

  register_dissector("pw_oam", dissect_pw_oam, proto_pw_oam);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
