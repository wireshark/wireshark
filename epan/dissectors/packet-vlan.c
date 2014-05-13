/* packet-vlan.c
 * Routines for VLAN 802.1Q ethernet header disassembly
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <wsutil/pint.h>
#include <epan/expert.h>
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-vlan.h"
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

void proto_register_vlan(void);
void proto_reg_handoff_vlan(void);

static unsigned int q_in_q_ethertype = 0x9100;

static gboolean vlan_summary_in_tree = TRUE;


static dissector_handle_t vlan_handle;
static dissector_handle_t ethertype_handle;

static header_field_info *hfi_vlan = NULL;

#define VLAN_HFI_INIT HFI_INIT(proto_vlan)

/* From Table G-2 of IEEE standard 802.1D-2004 */
static const value_string pri_vals[] = {
  { 1, "Background"                        },
  { 2, "Spare"                             },
  { 0, "Best Effort (default)"             },
  { 3, "Excellent Effort"                  },
  { 4, "Controlled Load"                   },
  { 5, "Video, < 100ms latency and jitter" },
  { 6, "Voice, < 10ms latency and jitter"  },
  { 7, "Network Control"                   },
  { 0, NULL                                }
};

static header_field_info hfi_vlan_priority VLAN_HFI_INIT = {
        "Priority", "vlan.priority", FT_UINT16, BASE_DEC,
        VALS(pri_vals), 0xE000, "Descriptions are recommendations from IEEE standard 802.1D-2004", HFILL };

static const value_string cfi_vals[] = {
  { 0, "Canonical"     },
  { 1, "Non-canonical" },
  { 0, NULL            }
};

static header_field_info hfi_vlan_cfi VLAN_HFI_INIT = {
        "CFI", "vlan.cfi", FT_UINT16, BASE_DEC,
        VALS(cfi_vals), 0x1000, "Canonical Format Identifier", HFILL };

static header_field_info hfi_vlan_id VLAN_HFI_INIT = {
        "ID", "vlan.id", FT_UINT16, BASE_DEC,
        NULL, 0x0FFF, "VLAN ID", HFILL };

static header_field_info hfi_vlan_etype VLAN_HFI_INIT = {
        "Type", "vlan.etype", FT_UINT16, BASE_HEX,
        VALS(etype_vals), 0x0, "Ethertype", HFILL };

static header_field_info hfi_vlan_len VLAN_HFI_INIT = {
        "Length", "vlan.len", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL };

static header_field_info hfi_vlan_trailer VLAN_HFI_INIT = {
        "Trailer", "vlan.trailer", FT_BYTES, BASE_NONE,
        NULL, 0x0, "VLAN Trailer", HFILL };


static gint ett_vlan = -1;

static expert_field ei_vlan_len = EI_INIT;

void
capture_vlan(const guchar *pd, int offset, int len, packet_counts *ld ) {
  guint16 encap_proto;
  if ( !BYTES_ARE_IN_FRAME(offset,len,5) ) {
    ld->other++;
    return;
  }
  encap_proto = pntoh16( &pd[offset+2] );
  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    if ( pd[offset+4] == 0xff && pd[offset+5] == 0xff ) {
      capture_ipx(ld);
    } else {
      capture_llc(pd,offset+4,len,ld);
    }
  } else {
    capture_ethertype(encap_proto, pd, offset+4, len, ld);
  }
}

static void
columns_set_vlan(column_info *cinfo, guint16 tci)
{
  static const char fast_str[][2] = { "0", "1", "2", "3", "4", "5", "6", "7" };

  char id_str[16];

  guint32_to_str_buf(tci & 0xFFF, id_str, sizeof(id_str));

  col_add_lstr(cinfo, COL_INFO,
               "PRI: ", fast_str[(tci >> 13) & 7], "  "
               "CFI: ", fast_str[(tci >> 12) & 1], "  "
                "ID: ", id_str,
               COL_ADD_LSTR_TERMINATOR);
  col_add_str(cinfo, COL_8021Q_VLAN_ID, id_str);
}

static void
dissect_vlan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint16 tci;
  volatile guint16 encap_proto;
  volatile gboolean is_802_2;
  proto_tree *volatile vlan_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLAN");
  col_clear(pinfo->cinfo, COL_INFO);

  tci = tvb_get_ntohs( tvb, 0 );

  columns_set_vlan(pinfo->cinfo, tci);

  vlan_tree = NULL;

  if (tree) {
    ti = proto_tree_add_item(tree, hfi_vlan, tvb, 0, 4, ENC_NA);

    if (vlan_summary_in_tree) {
        proto_item_append_text(ti, ", PRI: %u, CFI: %u, ID: %u",
                (tci >> 13), ((tci >> 12) & 1), (tci & 0xFFF));
    }

    vlan_tree = proto_item_add_subtree(ti, ett_vlan);

    proto_tree_add_item(vlan_tree, &hfi_vlan_priority, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(vlan_tree, &hfi_vlan_cfi, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(vlan_tree, &hfi_vlan_id, tvb, 0, 2, ENC_BIG_ENDIAN);
  }

  encap_proto = tvb_get_ntohs(tvb, 2);
  if (encap_proto <= IEEE_802_3_MAX_LEN) {
    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the VLAN header. If they are 0xffff, then what
       follows the VLAN header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet, so presumably the same applies for
       Ethernet VLAN packets). A non-0xffff value means that there's an
       802.2 layer inside the VLAN layer */
    is_802_2 = TRUE;

    /* Don't throw an exception for this check (even a BoundsError) */
    if (tvb_length_remaining(tvb, 4) >= 2) {
      if (tvb_get_ntohs(tvb, 4) == 0xffff) {
        is_802_2 = FALSE;
      }
    }

    dissect_802_3(encap_proto, is_802_2, tvb, 4, pinfo, tree, vlan_tree,
                  hfi_vlan_len.id, hfi_vlan_trailer.id, &ei_vlan_len, 0);
  } else {
    ethertype_data_t ethertype_data;

    ethertype_data.etype = encap_proto;
    ethertype_data.offset_after_ethertype = 4;
    ethertype_data.fh_tree = vlan_tree;
    ethertype_data.etype_id = hfi_vlan_etype.id;
    ethertype_data.trailer_id = hfi_vlan_trailer.id;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
  }
}

void
proto_register_vlan(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_vlan_priority,
    &hfi_vlan_cfi,
    &hfi_vlan_id,
    &hfi_vlan_etype,
    &hfi_vlan_len,
    &hfi_vlan_trailer,
  };
#endif /* HAVE_HFI_SECTION_INIT */

  static gint *ett[] = {
    &ett_vlan
  };

  static ei_register_info ei[] = {
     { &ei_vlan_len, { "vlan.len.past_end", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
  };

  module_t *vlan_module;
  expert_module_t* expert_vlan;
  int proto_vlan;

  proto_vlan = proto_register_protocol("802.1Q Virtual LAN", "VLAN", "vlan");
  hfi_vlan = proto_registrar_get_nth(proto_vlan);

  proto_register_fields(proto_vlan, hfi, array_length(hfi));
  proto_register_subtree_array(ett, array_length(ett));
  expert_vlan = expert_register_protocol(proto_vlan);
  expert_register_field_array(expert_vlan, ei, array_length(ei));

  vlan_module = prefs_register_protocol(proto_vlan, proto_reg_handoff_vlan);
  prefs_register_bool_preference(vlan_module, "summary_in_tree",
        "Show vlan summary in protocol tree",
        "Whether the vlan summary line should be shown in the protocol tree",
        &vlan_summary_in_tree);
  prefs_register_uint_preference(vlan_module, "qinq_ethertype",
        "802.1QinQ Ethertype (in hex)",
        "The (hexadecimal) Ethertype used to indicate 802.1QinQ VLAN in VLAN tunneling.",
        16, &q_in_q_ethertype);

  vlan_handle = create_dissector_handle(dissect_vlan, proto_vlan);
}

void
proto_reg_handoff_vlan(void)
{
  static gboolean prefs_initialized = FALSE;
  static unsigned int old_q_in_q_ethertype;

  if (!prefs_initialized)
  {
    dissector_add_uint("ethertype", ETHERTYPE_VLAN, vlan_handle);
    prefs_initialized = TRUE;
  }
  else
  {
    dissector_delete_uint("ethertype", old_q_in_q_ethertype, vlan_handle);
  }

  old_q_in_q_ethertype = q_in_q_ethertype;
  ethertype_handle = find_dissector("ethertype");

  dissector_add_uint("ethertype", q_in_q_ethertype, vlan_handle);
}
