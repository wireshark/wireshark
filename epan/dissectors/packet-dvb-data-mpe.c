/* packet-dvb-data-mpe.c
 * Routines for DVB-DATA (ETSI EN 301 192) MultiProtocol Encapsulation
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include "packet-mpeg-sect.h"

void proto_register_dvb_data_mpe(void);
void proto_reg_handoff_dvb_data_mpe(void);

static int proto_dvb_data_mpe;
static int hf_dvb_data_mpe_reserved;
static int hf_dvb_data_mpe_payload_scrambling_control;
static int hf_dvb_data_mpe_address_scrambling_control;
static int hf_dvb_data_mpe_llc_snap_flag;
static int hf_dvb_data_mpe_current_next_indicator;
static int hf_dvb_data_mpe_section_number;
static int hf_dvb_data_mpe_last_section_number;
static int hf_dvb_data_mpe_dst_mac;
static int hf_dvb_data_mpe_dst_mac_scrambled;

static int ett_dvb_data_mpe;

static expert_field ei_dvb_data_mpe_reserved_not_one;
static expert_field ei_dvb_data_mpe_payload_scrambled;
static expert_field ei_dvb_data_mpe_address_scrambled;

static dissector_handle_t dvb_data_mpe_handle;

static dissector_handle_t ip_handle;
static dissector_handle_t llc_handle;

#define DVB_DATA_MPE_RESERVED_MASK                0xC0
#define DVB_DATA_MPE_PAYLOAD_SCRAMBLING_MASK      0x30
#define DVB_DATA_MPE_ADDRESS_SCRAMBLING_MASK      0x0C
#define DVB_DATA_MPE_LLC_SNAP_FLAG_MASK           0x02
#define DVB_DATA_MPE_CURRENT_NEXT_INDICATOR_MASK  0x01

/* Field positions for the MAC Address */
/* It is split into two chunks, one of two octets and a second
 * one of four octets. Also, the octets are in reverse order. */
#define DVB_DATA_MPE_DST_MAC_FIRST 3
#define DVB_DATA_MPE_DST_MAC_SECOND 8

static const value_string dvb_data_mpe_scrambling_vals[] = {
    { 0, "Unscrambled" },
    { 1, "Defined by service" },
    { 2, "Defined by service" },
    { 3, "Defined by service" },
    { 0, NULL }
};

static int
dissect_dvb_data_mpe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    unsigned    offset = 0, tot_len = 0;
    uint32_t    reserved, address_scrambling, payload_scrambling, llc_snap_flag;
    int         i;

    proto_item *ti;
    proto_tree *dvb_data_mpe_tree;
    unsigned char     *dst = (unsigned char*)wmem_alloc(pinfo->pool, 6);
    address     dst_addr;
    tvbuff_t   *data_tvb;

    /* The TVB should start right after the section_length in the Section packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-DATA");
    col_set_str(pinfo->cinfo, COL_INFO, "MultiProtocol Encapsulation");

    ti = proto_tree_add_item(tree, proto_dvb_data_mpe, tvb, offset, -1, ENC_NA);
    dvb_data_mpe_tree = proto_item_add_subtree(ti, ett_dvb_data_mpe);

    offset += packet_mpeg_sect_header(tvb, offset, dvb_data_mpe_tree, &tot_len, NULL);


    /* Parse the DMC-CC private section header */

    dst[5] = tvb_get_uint8(tvb, offset);
    offset += 1;
    dst[4] = tvb_get_uint8(tvb, offset);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(dvb_data_mpe_tree, hf_dvb_data_mpe_reserved,     tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
    if (reserved != 3) {
        expert_add_info(pinfo, ti, &ei_dvb_data_mpe_reserved_not_one);
    }
    ti = proto_tree_add_item_ret_uint(dvb_data_mpe_tree, hf_dvb_data_mpe_payload_scrambling_control, tvb, offset, 1, ENC_BIG_ENDIAN, &payload_scrambling);
    if (payload_scrambling) {
        expert_add_info(pinfo, ti, &ei_dvb_data_mpe_payload_scrambled);
    }
    proto_tree_add_item_ret_uint(dvb_data_mpe_tree, hf_dvb_data_mpe_address_scrambling_control, tvb, offset, 1, ENC_BIG_ENDIAN, &address_scrambling);
    proto_tree_add_item_ret_uint(dvb_data_mpe_tree, hf_dvb_data_mpe_llc_snap_flag,     tvb, offset, 1, ENC_BIG_ENDIAN, &llc_snap_flag);
    proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_current_next_indicator,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_section_number,             tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_last_section_number,        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    for (i = 3; i >= 0; i--) {
        dst[i] = tvb_get_uint8(tvb, offset);
        offset += 1;
    }

    if (address_scrambling) {
        ti = proto_tree_add_bytes_with_length(dvb_data_mpe_tree, hf_dvb_data_mpe_dst_mac_scrambled, tvb, DVB_DATA_MPE_DST_MAC_FIRST, 2, dst, 6);
        expert_add_info(pinfo, ti, &ei_dvb_data_mpe_address_scrambled);
    } else {
        ti = proto_tree_add_ether(dvb_data_mpe_tree, hf_dvb_data_mpe_dst_mac, tvb, DVB_DATA_MPE_DST_MAC_FIRST, 2, dst);
        set_address(&dst_addr, AT_ETHER, 6, dst);
        col_add_str(pinfo->cinfo, COL_RES_DL_DST, address_to_str(pinfo->pool, &dst_addr));
    }
    /* Extend the highlighting for the second chunk. */
    proto_tree_set_appendix(ti, tvb, DVB_DATA_MPE_DST_MAC_SECOND, 4);

    data_tvb = tvb_new_subset_remaining(tvb, offset);

    if (payload_scrambling) {
        call_data_dissector(data_tvb, pinfo, tree);
    } else if (llc_snap_flag) {
        call_dissector(llc_handle, data_tvb, pinfo, tree);
    } else {
        call_dissector(ip_handle, data_tvb, pinfo, tree);
    }

    packet_mpeg_sect_crc(tvb, pinfo, dvb_data_mpe_tree, 0, tot_len - 1);
    return tvb_captured_length(tvb);
}

void
proto_register_dvb_data_mpe(void)
{

    static hf_register_info hf[] = {

        /* DSM-CC common fields */
        { &hf_dvb_data_mpe_reserved, {
            "Reserved", "dvb_data_mpe.reserved",
            FT_UINT8, BASE_HEX, NULL, DVB_DATA_MPE_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_payload_scrambling_control, {
            "Payload Scrambling Control", "dvb_data_mpe.pload_scrambling",
            FT_UINT8, BASE_HEX, VALS(dvb_data_mpe_scrambling_vals),
            DVB_DATA_MPE_PAYLOAD_SCRAMBLING_MASK, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_address_scrambling_control, {
            "Address Scrambling Control", "dvb_data_mpe.addr_scrambling",
            FT_UINT8, BASE_HEX, VALS(dvb_data_mpe_scrambling_vals),
            DVB_DATA_MPE_ADDRESS_SCRAMBLING_MASK, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_llc_snap_flag, {
            "LLC SNAP Flag", "dvb_data_mpe.llc_snap_flag",
            FT_UINT8, BASE_HEX, NULL, DVB_DATA_MPE_LLC_SNAP_FLAG_MASK, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_current_next_indicator, {
            "Current/Next Indicator", "mpeg_sect.cur_next_ind",
            FT_BOOLEAN, 8, TFS(&tfs_current_not_yet), DVB_DATA_MPE_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_section_number, {
            "Section Number", "dvb_data_mpe.sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_last_section_number, {
            "Last Section Number", "dvb_data_mpe.last_sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_dst_mac, {
            "Destination MAC address", "dvb_data_mpe.dst_mac",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_data_mpe_dst_mac_scrambled, {
            "Destination MAC address (scrambled)",
            "dvb_data_mpe.dst_mac.scrambled",
            FT_BYTES, SEP_COLON, NULL, 0, NULL, HFILL
        } },

    };

    static int *ett[] = {
        &ett_dvb_data_mpe,
    };

    expert_module_t *expert_dvb_data_mpe;
    static ei_register_info ei[] = {
        { &ei_dvb_data_mpe_reserved_not_one,
            { "dvb_data_mpe.reserved.not_one", PI_PROTOCOL, PI_WARN,
                "Reserved bits not all ones", EXPFILL }},
        { &ei_dvb_data_mpe_address_scrambled,
            { "dvb_data_mpe.address_scrambled", PI_UNDECODED, PI_WARN,
                "Cannot descramble destination MAC address (user private scrambling)", EXPFILL }},
        { &ei_dvb_data_mpe_payload_scrambled,
            { "dvb_data_mpe.payload.scrambled", PI_UNDECODED, PI_WARN,
                "Cannot descramble payload (user private scrambling)", EXPFILL }},
    };

    proto_dvb_data_mpe = proto_register_protocol("DVB-DATA MultiProtocol Encapsulation", "DVB-DATA MPE", "dvb_data_mpe");
    proto_register_field_array(proto_dvb_data_mpe, hf, array_length(hf));
    expert_dvb_data_mpe = expert_register_protocol(proto_dvb_data_mpe);
    expert_register_field_array(expert_dvb_data_mpe, ei, array_length(ei));

    proto_register_subtree_array(ett, array_length(ett));

    dvb_data_mpe_handle = register_dissector("dvb_data_mpe", dissect_dvb_data_mpe, proto_dvb_data_mpe);
}


void
proto_reg_handoff_dvb_data_mpe(void)
{
    dissector_add_uint("mpeg_sect.tid", DVB_DATA_MPE_TID, dvb_data_mpe_handle);

    ip_handle  = find_dissector_add_dependency("ip", proto_dvb_data_mpe);
    llc_handle = find_dissector_add_dependency("llc", proto_dvb_data_mpe);

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
