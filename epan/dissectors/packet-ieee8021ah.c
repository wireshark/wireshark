/* packet-ieee8021ah.c
 * Routines for 802.1ah ethernet header disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/addr_resolv.h>

#include "packet-ipx.h"
#include "packet-llc.h"
#include <epan/etypes.h>
#include <epan/prefs.h>

void proto_register_ieee8021ah(void);
void proto_reg_handoff_ieee8021ah(void);

static dissector_handle_t ethertype_handle;

static capture_dissector_handle_t ipx_cap_handle;
static capture_dissector_handle_t llc_cap_handle;

static void dissect_ieee8021ah_common(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, proto_tree *parent, int tree_index);

/* GLOBALS ************************************************************/

/* ethertype for 802.1ah tag - encapsulating an Ethernet packet */
static unsigned int ieee8021ah_ethertype = ETHERTYPE_IEEE_802_1AH;

static int proto_ieee8021ah = -1;
static int proto_ieee8021ad = -1;

/* dot1ad B-tag fields */
static int hf_ieee8021ad_priority = -1;
static int hf_ieee8021ad_cfi = -1;
static int hf_ieee8021ad_id = -1;
static int hf_ieee8021ad_svid = -1;
static int hf_ieee8021ad_cvid = -1;

/* dot1ah C-tag fields */
static int hf_ieee8021ah_priority = -1;
static int hf_ieee8021ah_drop = -1;    /* drop eligibility */
static int hf_ieee8021ah_nca = -1;     /* no customer addresses (c_daddr & c_saddr are 0) */
static int hf_ieee8021ah_res1 = -1;    /* 2 bits reserved; ignored on receive */
static int hf_ieee8021ah_res2 = -1;    /* 2 bits reserved; delete frame if non-zero */
static int hf_ieee8021ah_isid = -1;    /* I-SID */
static int hf_ieee8021ah_c_daddr = -1; /* encapsulated customer dest addr */
static int hf_ieee8021ah_c_saddr = -1; /* encapsulated customer src addr */

static int hf_ieee8021ah_etype = -1;
/* static int hf_ieee8021ah_len = -1; */
static int hf_ieee8021ah_trailer = -1;

static gint ett_ieee8021ah = -1;
static gint ett_ieee8021ad = -1;

#define IEEE8021AD_LEN 4
#define IEEE8021AH_LEN 18
#define IEEE8021AH_ISIDMASK 0x00FFFFFF

/* FUNCTIONS ************************************************************/


static gboolean
capture_ieee8021ah(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    guint16 encap_proto;

    if (!BYTES_ARE_IN_FRAME(offset, len, IEEE8021AH_LEN + 1))
        return FALSE;

    encap_proto = pntoh16( &pd[offset + IEEE8021AH_LEN - 2] );
    if (encap_proto <= IEEE_802_3_MAX_LEN) {
        if ( pd[offset + IEEE8021AH_LEN] == 0xff
             && pd[offset + IEEE8021AH_LEN + 1] == 0xff ) {
            return call_capture_dissector(ipx_cap_handle, pd, offset + IEEE8021AH_LEN, len, cpinfo, pseudo_header);
        }
        else {
            return call_capture_dissector(llc_cap_handle, pd, offset + IEEE8021AH_LEN, len, cpinfo, pseudo_header);
        }
    }

    return try_capture_dissector("ethertype", encap_proto, pd, offset + IEEE8021AH_LEN, len, cpinfo, pseudo_header);
}

/* Dissector *************************************************************/
static
int dissect_ieee8021ad(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, void* data _U_)
{
    proto_tree       *ptree   = NULL;
    proto_tree       *tagtree = NULL;
    guint32           tci, ctci;
    guint16           encap_proto;
    int               proto_tree_index;
    ethertype_data_t  ethertype_data;

    tvbuff_t   *next_tvb = NULL;
    proto_tree *ieee8021ad_tree;
    proto_tree *ieee8021ad_tag_tree;

    /* set tree index */
    proto_tree_index = proto_ieee8021ad;

    /* add info to column display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.1ad");
    col_clear(pinfo->cinfo, COL_INFO);

    tci = tvb_get_ntohs( tvb, 0 );

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "PRI: %d  DROP: %d ID: %d",
                 (tci >> 13), ((tci >> 12) & 1), (tci & 0xFFF));

    /* create the protocol tree */
    ptree = proto_tree_add_item(tree, proto_tree_index, tvb, 0, IEEE8021AD_LEN, ENC_NA);
    ieee8021ad_tree = proto_item_add_subtree(ptree, ett_ieee8021ad);

    encap_proto = tvb_get_ntohs(tvb, IEEE8021AD_LEN - 2);
    ethertype_data.fh_tree = ieee8021ad_tree;
    ethertype_data.trailer_id = hf_ieee8021ah_trailer;
    ethertype_data.fcs_len = 0;

    /* If it's a 1ah frame, create subtree for B-Tag, rename overall
       tree to 802.1ah, pass to 1ah dissector */
    if (encap_proto == ETHERTYPE_IEEE_802_1AH) {
        if (tree) {
            tagtree = proto_tree_add_item(ptree, proto_tree_index, tvb, 0, 2, ENC_NA);
            ieee8021ad_tag_tree = proto_item_add_subtree(tagtree, ett_ieee8021ad);

            /* add fields */
            proto_tree_add_uint(ieee8021ad_tag_tree, hf_ieee8021ad_priority, tvb,
                                0, 1, tci);
            proto_tree_add_uint(ieee8021ad_tag_tree, hf_ieee8021ad_cfi, tvb, 0, 1, tci);
            proto_tree_add_uint(ieee8021ad_tag_tree, hf_ieee8021ad_id, tvb, 0, 2, tci);

            /* set label of B-tag subtree */
            proto_item_set_text(ieee8021ad_tag_tree, "B-Tag, B-VID: %d", tci & 0x0FFF);
        }

        next_tvb = tvb_new_subset_remaining(tvb, IEEE8021AD_LEN);

        if (ptree) {
            /* add bvid to label */
            proto_item_set_text(ptree, "IEEE 802.1ah, B-VID: %d", tci & 0x0FFF);

            dissect_ieee8021ah_common(next_tvb, pinfo, ptree, tree, proto_tree_index);
        }
        else {
            dissect_ieee8021ah_common(next_tvb, pinfo, tree, NULL, proto_tree_index);
        }

    } else if (encap_proto == ETHERTYPE_IEEE_802_1AD) {
        /* two VLAN tags (i.e. Q-in-Q) */
        ctci = tvb_get_ntohs(tvb, IEEE8021AD_LEN);

        if (tree) {
            /* add fields */
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_priority, tvb,
                                0, 1, tci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cfi, tvb, 0, 1, tci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_svid, tvb, 0, 2, tci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_priority, tvb,
                                IEEE8021AD_LEN, 1, ctci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cfi, tvb,
                                IEEE8021AD_LEN, 1, ctci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cvid, tvb, IEEE8021AD_LEN,
                                2, ctci);
        }

        proto_item_set_text(ptree, "IEEE 802.1ad, S-VID: %d, C-VID: %d", tci & 0x0FFF,
                            ctci & 0x0FFF);

        ethertype_data.etype = tvb_get_ntohs(tvb, IEEE8021AD_LEN * 2 - 2);
        proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ah_etype, tvb,
                            IEEE8021AD_LEN * 2 - 2, 2, ethertype_data.etype);

        ethertype_data.payload_offset = IEEE8021AD_LEN * 2;

        /* 802.1ad tags are always followed by an ethertype; call next
           dissector based on ethertype */
        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    } else {
        /* Something else (shouldn't really happen, but we'll support it anyways) */
        if (tree) {
            /* add fields */
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_priority, tvb,
                                0, 1, tci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cfi, tvb, 0, 1, tci);
            proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_id, tvb, 0, 2, tci);
        }

        /* label should be 802.1ad not .1ah */
        proto_item_set_text(ptree, "IEEE 802.1ad, ID: %d", tci & 0x0FFF);

        /* Add the Ethernet type to the protocol tree */
        proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ah_etype, tvb,
                            IEEE8021AD_LEN - 2, 2, encap_proto);

        ethertype_data.etype = encap_proto;
        ethertype_data.payload_offset = IEEE8021AD_LEN;

        /* 802.1ad tags are always followed by an ethertype; call next
           dissector based on ethertype */
        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    }
    return tvb_captured_length(tvb);
}

static void
dissect_ieee8021ah_common(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_tree *parent, int tree_index) {
    guint32           tci;
    guint16           encap_proto;
    proto_tree       *ptree;
    ethertype_data_t  ethertype_data;

    proto_tree *ieee8021ah_tag_tree;

    tci = tvb_get_ntohl( tvb, 0 );

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "PRI: %d  Drop: %d  NCA: %d  Res1: %d  Res2: %d  I-SID: %d",
                 (tci >> 29), ((tci >> 28) & 1), ((tci >> 27) & 1),
                 ((tci >> 26) & 1), ((tci >> 24) & 3), tci & IEEE8021AH_ISIDMASK);

    /* create the protocol tree */
    ptree = NULL;
    ieee8021ah_tag_tree = NULL;

    if (tree) {
        /* 802.1ah I-Tag */
        ptree = proto_tree_add_item(tree, tree_index, tvb, 0, 4, ENC_NA);
        ieee8021ah_tag_tree = proto_item_add_subtree(ptree, ett_ieee8021ah);

        /* add fields */
        proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_priority, tvb,
                            0, 1, tci);
        proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_drop, tvb, 0, 1, tci);
        proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_nca, tvb, 0, 1, tci);
        proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_res1, tvb, 0, 1, tci);
        proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_res2, tvb, 0, 1, tci);
        proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_isid, tvb, 1, 3, tci);

        proto_item_set_text(ieee8021ah_tag_tree, "I-Tag, I-SID: %d",
                            tci & IEEE8021AH_ISIDMASK);

        proto_tree_add_item(tree, hf_ieee8021ah_c_daddr, tvb, 4, 6, ENC_NA);
        proto_tree_add_item(tree, hf_ieee8021ah_c_saddr, tvb, 10, 6, ENC_NA);

        /* add text to 802.1ad label */
        if (parent) {
            proto_item_append_text(tree, ", I-SID: %d, C-Src: %s, C-Dst: %s",
                                   tci & IEEE8021AH_ISIDMASK,
                                   tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_ETHER, 10),
                                   tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_ETHER, 4));
        }
    }

    encap_proto = tvb_get_ntohs(tvb, IEEE8021AH_LEN - 2);
    proto_tree_add_uint(tree, hf_ieee8021ah_etype, tvb,
                        IEEE8021AD_LEN - 2, 2, encap_proto);

    /* 802.1ah I-tags are always followed by an ethertype; call next
       dissector based on ethertype */

    /* If this was preceded by a 802.1ad tag, must pass original tree
       to next dissector, not 802.1ad tree */
    ethertype_data.etype = encap_proto;
    ethertype_data.fh_tree = tree;
    ethertype_data.payload_offset = IEEE8021AH_LEN;
    ethertype_data.trailer_id = hf_ieee8021ah_trailer;
    ethertype_data.fcs_len = 0;

    if (parent) {
    call_dissector_with_data(ethertype_handle, tvb, pinfo, parent, &ethertype_data);
    }
    else {
    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    }
}

static
int dissect_ieee8021ah(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, void* data _U_)
{
    proto_item *pi;
    guint32     tci;
    int         proto_tree_index;
    proto_tree *ieee8021ah_tree;

    /* set tree index */
    proto_tree_index = proto_ieee8021ah;

    /* add info to column display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.1ah");
    col_clear(pinfo->cinfo, COL_INFO);

    tci = tvb_get_ntohl( tvb, 0 );

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "PRI: %d  Drop: %d  NCA: %d  Res1: %d  Res2: %d  I-SID: %d",
                 (tci >> 29), ((tci >> 28) & 1), ((tci >> 27) & 1),
                 ((tci >> 26) & 1), ((tci >> 24) & 3), (tci & 0x00FFFFFF));

    pi = proto_tree_add_item(tree, proto_tree_index, tvb, 0, IEEE8021AH_LEN, ENC_NA);
    ieee8021ah_tree = proto_item_add_subtree(pi, ett_ieee8021ah);

    if (ieee8021ah_tree) {
        dissect_ieee8021ah_common(tvb, pinfo, ieee8021ah_tree, tree, proto_tree_index);
    } else {
        dissect_ieee8021ah_common(tvb, pinfo, tree, NULL, proto_tree_index);
    }
    return tvb_captured_length(tvb);
}

/* Protocol Registration **************************************************/

void
proto_register_ieee8021ah(void)
{
    static hf_register_info hf[] = {
        { &hf_ieee8021ah_priority, {
                "Priority", "ieee8021ah.priority", FT_UINT32, BASE_DEC,
                0, 0xE0000000, NULL, HFILL }},
        { &hf_ieee8021ah_drop, {
                "DROP", "ieee8021ah.drop", FT_UINT32, BASE_DEC,
                0, 0x10000000, NULL, HFILL }},
        { &hf_ieee8021ah_nca, {
                "NCA", "ieee8021ah.nca", FT_UINT32, BASE_DEC,
                0, 0x08000000, "No Customer Addresses", HFILL }},
        { &hf_ieee8021ah_res1, {
                "RES1", "ieee8021ah.res1", FT_UINT32, BASE_DEC,
                0, 0x04000000, "Reserved1", HFILL }},
        { &hf_ieee8021ah_res2, {
                "RES2", "ieee8021ah.res2", FT_UINT32, BASE_DEC,
                0, 0x03000000, "Reserved2", HFILL }},
        { &hf_ieee8021ah_isid, {
                "I-SID", "ieee8021ah.isid", FT_UINT32, BASE_DEC,
                0, 0x00FFFFFF, NULL, HFILL }},
        { &hf_ieee8021ah_c_daddr, {
                "C-Destination", "ieee8021ah.cdst", FT_ETHER, BASE_NONE,
                NULL, 0x0, "Customer Destination Address", HFILL }},
        { &hf_ieee8021ah_c_saddr, {
                "C-Source", "ieee8021ah.csrc", FT_ETHER, BASE_NONE,
                NULL, 0x0, "Customer Source Address", HFILL }},
        { &hf_ieee8021ah_etype, {
                "Type", "ieee8021ah.etype", FT_UINT16, BASE_HEX,
                VALS(etype_vals), 0x0, NULL, HFILL }},
#if 0
        { &hf_ieee8021ah_len, {
                "Length", "ieee8021ah.len", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
#endif
        { &hf_ieee8021ah_trailer, {
                "Trailer", "ieee8021ah.trailer", FT_BYTES, BASE_NONE,
                NULL, 0x0, "802.1ah Trailer", HFILL }}
    };

    static hf_register_info hf_1ad[] = {
        { &hf_ieee8021ad_priority, {
                "Priority", "ieee8021ad.priority", FT_UINT16, BASE_DEC,
                0, 0xE000, NULL, HFILL }},
        { &hf_ieee8021ad_cfi, {
                "DEI", "ieee8021ad.dei", FT_UINT16, BASE_DEC,
                0, 0x1000, "Drop Eligibility", HFILL }},
        { &hf_ieee8021ad_id, {
                "ID", "ieee8021ad.id", FT_UINT16, BASE_DEC,
                0, 0x0FFF, "Vlan ID", HFILL }},
        { &hf_ieee8021ad_svid, {
                "ID", "ieee8021ad.svid", FT_UINT16, BASE_DEC,
                0, 0x0FFF, "S-Vlan ID", HFILL }},
        { &hf_ieee8021ad_cvid, {
                "ID", "ieee8021ad.cvid", FT_UINT16, BASE_DEC,
                0, 0x0FFF, "C-Vlan ID", HFILL }},
    };

    static gint *ett[] = {
        &ett_ieee8021ah,
        &ett_ieee8021ad
    };


    module_t *ieee8021ah_module;

    /* registration */
    /* dot1ah */
    proto_ieee8021ah = proto_register_protocol("IEEE 802.1ah", "IEEE 802.1AH",
                                               "ieee8021ah");
    proto_register_field_array(proto_ieee8021ah, hf, array_length(hf));

    proto_ieee8021ad = proto_register_protocol("IEEE 802.1ad", "IEEE 802.1AD",
                                               "ieee8021ad");
    proto_register_field_array(proto_ieee8021ad, hf_1ad, array_length(hf_1ad));

    /* register subtree array for both */
    proto_register_subtree_array(ett, array_length(ett));

    /* add a user preference to set the 802.1ah ethertype */
    ieee8021ah_module = prefs_register_protocol(proto_ieee8021ah,
                                                proto_reg_handoff_ieee8021ah);
    prefs_register_uint_preference(ieee8021ah_module, "8021ah_ethertype",
                                   "802.1ah Ethertype (in hex)",
                                   "(Hexadecimal) Ethertype used to indicate IEEE 802.1ah tag.",
                                   16, &ieee8021ah_ethertype);
}

void
proto_reg_handoff_ieee8021ah(void)
{
    static gboolean           prefs_initialized = FALSE;
    static dissector_handle_t ieee8021ah_handle;
    static unsigned int       old_ieee8021ah_ethertype;
    static capture_dissector_handle_t ieee8021ah_cap_handle;

    if (!prefs_initialized){
        dissector_handle_t ieee8021ad_handle;
        ieee8021ah_handle = create_dissector_handle(dissect_ieee8021ah,
                                                    proto_ieee8021ah);
        ieee8021ad_handle = create_dissector_handle(dissect_ieee8021ad,
                                                    proto_ieee8021ad);
        dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1AD, ieee8021ad_handle);
        ethertype_handle = find_dissector_add_dependency("ethertype", proto_ieee8021ah);
        find_dissector_add_dependency("ethertype", proto_ieee8021ad);
        ieee8021ah_cap_handle = create_capture_dissector_handle(capture_ieee8021ah, proto_ieee8021ah);
        capture_dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1AD, ieee8021ah_cap_handle);
        capture_dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1AH, ieee8021ah_cap_handle);

        ipx_cap_handle = find_capture_dissector("ipx");
        llc_cap_handle = find_capture_dissector("llc");

        prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("ethertype", old_ieee8021ah_ethertype, ieee8021ah_handle);
    }

    old_ieee8021ah_ethertype = ieee8021ah_ethertype;
    dissector_add_uint("ethertype", ieee8021ah_ethertype, ieee8021ah_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
