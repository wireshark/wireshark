/* packet-ieee8021CB.c
 * Routines for 802.1CB R-tag ethernet header disassembly
 *
 * Copyright 2020, Rene Nielsen <rene.nielsen@microchip.com>
 * In association with Microchip Technology Inc.
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

void proto_register_ieee8021cb(void);
void proto_reg_handoff_ieee8021cb(void);

static dissector_handle_t ieee8021cb_handle;
static dissector_handle_t ethertype_handle;

static capture_dissector_handle_t ieee8021cb_cap_handle;
static capture_dissector_handle_t ipx_cap_handle;
static capture_dissector_handle_t llc_cap_handle;

/* GLOBALS ************************************************************/

static int proto_ieee8021cb;

/* dot1cb R-tag fields */
static int hf_ieee8021cb_res;
static int hf_ieee8021cb_seq;

/* Encapsulated protocol */
static int hf_ieee8021cb_etype;

static int ett_ieee8021cb;

#define IEEE8021CB_LEN 6

static bool
capture_ieee8021cb(const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
    uint16_t encap_proto;

    if (!BYTES_ARE_IN_FRAME(offset, len, IEEE8021CB_LEN + 1))
        return false;

    encap_proto = pntoh16( &pd[offset + IEEE8021CB_LEN - 2] );
    if (encap_proto <= IEEE_802_3_MAX_LEN) {
        if ( pd[offset + IEEE8021CB_LEN] == 0xff
             && pd[offset + IEEE8021CB_LEN + 1] == 0xff ) {
            return call_capture_dissector(ipx_cap_handle, pd, offset + IEEE8021CB_LEN, len, cpinfo, pseudo_header);
        }
        else {
            return call_capture_dissector(llc_cap_handle, pd, offset + IEEE8021CB_LEN, len, cpinfo, pseudo_header);
        }
    }

    return try_capture_dissector("ethertype", encap_proto, pd, offset + IEEE8021CB_LEN, len, cpinfo, pseudo_header);
}

/* Dissector *************************************************************/
static
int dissect_ieee8021cb(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, void* data _U_)
{
    proto_tree       *ptree   = NULL;
    uint16_t          seq, pro;
    ethertype_data_t  ethertype_data;
    proto_tree       *ieee8021cb_tree;

    /* add info to column display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.1CB R-Tag");
    col_clear(pinfo->cinfo, COL_INFO);

    seq = tvb_get_ntohs(tvb, 2);
    pro = tvb_get_ntohs(tvb, 4);

    col_add_fstr(pinfo->cinfo, COL_INFO, "SEQ: %u", seq);

    /* create the protocol tree */
    ptree = proto_tree_add_item(tree, proto_ieee8021cb, tvb, 0, IEEE8021CB_LEN, ENC_NA);
    ieee8021cb_tree = proto_item_add_subtree(ptree, ett_ieee8021cb);

    /* add fields */
    proto_tree_add_uint(ieee8021cb_tree, hf_ieee8021cb_seq,   tvb, 2, 2, seq);
    proto_tree_add_uint(ieee8021cb_tree, hf_ieee8021cb_etype, tvb, 4, 2, pro);

    proto_item_append_text(ptree, ", SEQ: %u", seq);

    ethertype_data.fh_tree        = ieee8021cb_tree;
    ethertype_data.fcs_len        = 0;
    ethertype_data.etype          = pro;
    ethertype_data.payload_offset = IEEE8021CB_LEN;

    /* 802.1CB tags are always followed by an ethertype; call next dissector
       based on ethertype */
    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);

    return tvb_captured_length(tvb);
}

void
proto_register_ieee8021cb(void)
{
    static hf_register_info hf_1cb[] = {
        { &hf_ieee8021cb_res, {
                "Reserved", "ieee8021cb.reserved", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ieee8021cb_seq, {
                "SEQ", "ieee8021cb.seq", FT_UINT16, BASE_HEX_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ieee8021cb_etype, {
                "Type", "ieee8021cb.etype", FT_UINT16, BASE_HEX,
                VALS(etype_vals), 0x0, "Ethertype", HFILL }}
    };

    static int *ett[] = {
        &ett_ieee8021cb
    };

    /* registration */
    proto_ieee8021cb = proto_register_protocol("802.1CB Redundancy Tag", "R-Tag", "ieee8021cb");
    proto_register_field_array(proto_ieee8021cb, hf_1cb, array_length(hf_1cb));
    proto_register_subtree_array(ett, array_length(ett));

    ieee8021cb_handle = register_dissector("ieee8021cb", dissect_ieee8021cb, proto_ieee8021cb);
    ieee8021cb_cap_handle = register_capture_dissector("ieee8021cb", capture_ieee8021cb, proto_ieee8021cb);
}

void
proto_reg_handoff_ieee8021cb(void)
{

    dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1CB, ieee8021cb_handle);
    ethertype_handle = find_dissector_add_dependency("ethertype", proto_ieee8021cb);
    capture_dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1CB, ieee8021cb_cap_handle);

    ipx_cap_handle = find_capture_dissector("ipx");
    llc_cap_handle = find_capture_dissector("llc");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
