/* packet-tte.c
 * Routines for Time Triggered Ethernet dissection
 *
 * Author: Valentin Ecker, valentin.ecker (AT) tttech.com
 * Author: Benjamin Roch, benjamin.roch (AT) tttech.com
 *
 * TTTech Computertechnik AG, Austria.
 * http://www.tttech.com/solutions/ttethernet/
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

#include "packet-tte.h"

void proto_register_tte(void);
void proto_reg_handoff_tte(void);

static dissector_handle_t ethertype_handle;

/* Initialize the protocol and registered fields */
static int proto_tte = -1;

static int hf_eth_dst       = -1;
static int hf_tte_dst_cf    = -1;
static int hf_tte_ctid      = -1;
static int hf_eth_src       = -1;
static int hf_eth_type      = -1;

/* preference value pointers */
static guint32    tte_pref_ct_marker    = 0xFFFFFFFF;
static guint32    tte_pref_ct_mask      = 0x0;

/* Initialize the subtree pointers */
static gint ett_tte = -1;
static gint ett_tte_macdest = -1;


/* Code to actually dissect the packets */
static int
dissect_tte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int is_frame_pcf;
    ethertype_data_t ethertype_data;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *tte_root_item, *tte_macdest_item;
    proto_tree *tte_tree, *tte_macdest_tree;

    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < TTE_HEADER_LENGTH)
        return 0;

    /* check if data of pcf frame */
    is_frame_pcf =
       (tvb_get_ntohs(tvb, TTE_MAC_LENGTH * 2) == ETHERTYPE_TTE_PCF);

    /* return if no valid constant field is found */
    if (!is_frame_pcf)
    {
        if ( (tvb_get_ntohl(tvb, 0) & tte_pref_ct_mask) != tte_pref_ct_marker)
            return 0;
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TTE ");

    if (tvb_get_ntohs(tvb, TTE_MAC_LENGTH * 2) <= IEEE_802_3_MAX_LEN)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "TTEthernet Frame");
    }
    else
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Bogus TTEthernet Frame");
    }

    if (tree) {

        /* create display subtree for the protocol */
        tte_root_item = proto_tree_add_item(tree, proto_tte, tvb, 0,
            TTE_HEADER_LENGTH, ENC_NA);

        tte_tree = proto_item_add_subtree(tte_root_item, ett_tte);

        tte_macdest_item = proto_tree_add_item(tte_tree,
            hf_eth_dst, tvb, 0, TTE_MAC_LENGTH, ENC_NA);

        proto_tree_add_item(tte_tree,
            hf_eth_src, tvb, TTE_MAC_LENGTH, TTE_MAC_LENGTH, ENC_NA);

        proto_tree_add_item(tte_tree,
            hf_eth_type, tvb, TTE_MAC_LENGTH*2, TTE_ETHERTYPE_LENGTH,
            ENC_BIG_ENDIAN);

        tte_macdest_tree = proto_item_add_subtree(tte_macdest_item,
            ett_tte_macdest);

        proto_tree_add_item(tte_macdest_tree,
            hf_tte_dst_cf, tvb, 0, TTE_MACDEST_CF_LENGTH, ENC_BIG_ENDIAN);

        proto_tree_add_item(tte_macdest_tree,
            hf_tte_ctid, tvb, TTE_MACDEST_CF_LENGTH,
            TTE_MACDEST_CTID_LENGTH, ENC_BIG_ENDIAN);
    }

    /* prevent clearing the Columns...appending cannot be prevented */
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);

    /* call std Ethernet dissector */
    ethertype_data.etype = tvb_get_ntohs(tvb, TTE_MAC_LENGTH * 2);
    ethertype_data.offset_after_ethertype = 14;
    ethertype_data.fh_tree = NULL;
    ethertype_data.etype_id = hf_eth_type;
    ethertype_data.trailer_id = 0;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    return tvb_reported_length(tvb);
}


void
proto_register_tte(void)
{
    module_t *tte_module;

    static hf_register_info hf[] = {
        { &hf_tte_dst_cf,
          { "Constant Field",   "tte.cf",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tte_ctid,
          { "Critical Traffic Identifier", "tte.ctid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tte,
        &ett_tte_macdest
    };

    /* Register the protocol name and description */
    proto_tte = proto_register_protocol("TTEthernet", "TTE", "tte");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_tte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences module */
    tte_module = prefs_register_protocol(proto_tte, NULL);

    /* Register preferences */
    prefs_register_uint_preference(tte_module, "ct_mask_value",
        "CT Mask (in hex)",
        "Critical Traffic Mask (base hex)",
        16, &tte_pref_ct_mask);

    prefs_register_uint_preference(tte_module, "ct_marker_value",
        "CT Marker (in hex)",
        "Critical Traffic Marker (base hex)",
        16, &tte_pref_ct_marker);
}


void
proto_reg_handoff_tte(void)
{
    heur_dissector_add("eth", dissect_tte, "TTEthernet", "tte_eth", proto_tte, HEURISTIC_ENABLE);

    hf_eth_dst  = proto_registrar_get_id_byname ("eth.dst");
    hf_eth_src  = proto_registrar_get_id_byname ("eth.src");
    hf_eth_type = proto_registrar_get_id_byname ("eth.type");

    ethertype_handle = find_dissector_add_dependency("ethertype", proto_tte);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
