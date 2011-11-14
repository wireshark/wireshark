/* packet-hsr-prp-supervision.c
 * Routines for HSR/PRP supervision dissection (IEC62439 Part 3)
 * Copyright 2009, Florian Reichert <refl[AT]zhaw.ch>
 * Copyright 2011, Martin Renold <reld[AT]zhaw.ch>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

/**********************************************************/
/* Channel values for the supervision type field          */
/**********************************************************/

static const value_string type_vals[] = {
  {20, "PRP Node (Duplicate Discard)"},
  {21, "PRP Node (Duplicate Accept)"},
  {22, "Obsolete TLV value"},
  {23, "HSR Node"},
  {30, "Redundancy Box MAC Address"},
  {31, "Virtual Dual Attached Node"},
  {0,  "End of TLVs"},
  {0,  NULL}
};

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/

static int proto_hsr_prp_supervision = -1;

/* Initialize supervision frame fields */
static int hf_hsr_prp_supervision_path = -1;
static int hf_hsr_prp_supervision_version = -1;
static int hf_hsr_prp_supervision_seqno = -1;
static int hf_hsr_prp_supervision_tlv_type = -1;
static int hf_hsr_prp_supervision_tlv_length = -1;
static int hf_hsr_prp_supervision_source_mac_address_A = -1;
static int hf_hsr_prp_supervision_source_mac_address_B = -1;
static int hf_hsr_prp_supervision_source_mac_address = -1;
static int hf_hsr_prp_supervision_red_box_mac_address = -1;
static int hf_hsr_prp_supervision_vdan_mac_address = -1;

/* Initialize the subtree pointers */
static gint ett_hsr_prp_supervision = -1;

/* Code to actually dissect the packets */
static void
dissect_hsr_prp_supervision(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *hsr_prp_supervision_tree;
    guint8 tlv_type;
    guint8 tlv_length;
    guint16 sup_version;
    int offset;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSR/PRP");

    /* may get modified later while parsing */
    col_set_str(pinfo->cinfo, COL_INFO, "HSR or PRP Supervision");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_hsr_prp_supervision, tvb, 0, -1, ENC_NA);

    hsr_prp_supervision_tree = proto_item_add_subtree(ti, ett_hsr_prp_supervision);

    offset = 0;

    /* SupVersion */
    proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_path,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_version,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    sup_version = tvb_get_ntohs(tvb, 0) & 0x0fff;
    offset += 2;

    if (sup_version > 0) {
        /* SupSequenceNumber */
        proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_seqno,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /* TLV.type */
        tlv_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_tlv_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* TLV.length */
        tlv_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_tlv_length,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* TLV.value */
        if ((tlv_type == 20 || tlv_type == 21 || tlv_type == 23) && (tlv_length == 6 || tlv_length == 12)) {
            if (tlv_type == 23) {
                col_set_str(pinfo->cinfo, COL_INFO, "HSR Supervision");
            } else {
                col_set_str(pinfo->cinfo, COL_INFO, "PRP Supervision");
            }
            if (tlv_length == 12) {
                /* MacAddressA, MacAddressB (PRP only) */
                proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_source_mac_address_A,
                                    tvb, offset, 6, ENC_NA);
                proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_source_mac_address_B,
                                    tvb, offset+6, 6, ENC_NA);
                /* PRP-0 supervision: if the node is not a RedBox, we have
                   just read the last TLV. The next two octets are
                   required to be zero by PRP-0. We will dissect those as
                   "end of list" and break. */
            } else {
                /* MacAddress */
                proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_source_mac_address,
                                    tvb, offset, 6, ENC_NA);
            }
        } else if (tlv_type == 30 && tlv_length == 6) {
            /* RedBoxMacAddress */
            proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_red_box_mac_address,
                                tvb, offset, 6, ENC_NA);
            if (sup_version == 0) {
                /* PRP-0 supervision: end of TLV data. Stop now, don't
                   interpret the padding. */
                offset += tlv_length;
                break;
            }
        } else if (tlv_type == 31 && tlv_length == 6) {
            /* VdanMacAddress */
            proto_tree_add_item(hsr_prp_supervision_tree, hf_hsr_prp_supervision_vdan_mac_address,
                                tvb, offset, 6, ENC_NA);
            if (sup_version == 0) {
                /* PRP-0 supervision: end of TLV data, padding starts */
                offset += tlv_length;
                break;
            }
        } else if (tlv_type == 0) {
            /* End of TLV list. */
            offset += tlv_length;
            break;
        } else {
            /* unknown TLV.type, or unexpected TLV.length */
        }
        offset += tlv_length;
    }

    proto_item_set_len(ti, offset);
    /* Adjust the length of this tvbuff to include only the supervision data.
       This allows the rest to be marked as padding. */
    tvb_set_reported_length(tvb, offset);
}


/* Register the protocol with Wireshark */
void proto_register_hsr_prp_supervision(void)
{

    static hf_register_info hf[] = {

        { &hf_hsr_prp_supervision_path,
            { "Path", "hsr_prp_supervision.path",
            FT_UINT16, BASE_DEC, NULL, 0xf000,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_version,
            { "Version", "hsr_prp_supervision.version",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_seqno,
            { "Sequence number", "hsr_prp_supervision.supervision_seqno",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_tlv_type,
            { "TLV type", "hsr_prp_supervision.tlv.type",
            FT_UINT8, BASE_DEC, VALS(type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_tlv_length,
            { "TLV length", "hsr_prp_supervision.tlv.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_source_mac_address_A,
            { "Source MAC Address A", "hsr_prp_supervision.source_mac_address_A",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_source_mac_address_B,
            { "Source MAC Address B", "hsr_prp_supervision.source_mac_address_B",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_source_mac_address,
            { "Source MAC Address", "hsr_prp_supervision.source_mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_red_box_mac_address,
            { "RedBox MAC Address", "hsr_prp_supervision.red_box_mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hsr_prp_supervision_vdan_mac_address,
            { "VDAN MAC Address", "hsr_prp_supervision.vdan_mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };


    static gint *ett[] = {
        &ett_hsr_prp_supervision
    };

    /* Register the protocol name and description */
    proto_hsr_prp_supervision = proto_register_protocol("HSR/PRP Supervision (IEC62439 Part 3)",
                        "HSR_PRP_SUPERVISION", "hsr_prp_supervision");


    /* Required function calls to register the header fields and subtree used */
    proto_register_field_array(proto_hsr_prp_supervision, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_hsr_prp_supervision(void)
{
    dissector_handle_t hsr_prp_supervision_handle;
    hsr_prp_supervision_handle = create_dissector_handle(dissect_hsr_prp_supervision, proto_hsr_prp_supervision);
    dissector_add_uint("ethertype", ETHERTYPE_PRP, hsr_prp_supervision_handle);
}
