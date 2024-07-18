/* packet-pcaplog.c
 * Routines for pcaplog dissection
 * Copyright 2023, Dr. Lars Völker <lars.voelker@technica-engineering.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#define WS_LOG_DOMAIN "pcaplog"

#define PEN_VCTR 46254

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>

void proto_reg_handoff_pcaplog(void);
void proto_register_pcaplog(void);

static int proto_pcaplog;
static int hf_pcaplog_type;
static int hf_pcaplog_length;
static int hf_pcaplog_data;

static dissector_handle_t pcaplog_handle;
static dissector_handle_t xml_handle;

static int ett_pcaplog;
static int ett_pcaplog_data;

static int
dissect_pcaplog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    uint32_t data_type;
    uint32_t data_length;
    proto_item *pcaplog_item;
    proto_tree *pcaplog_tree;
    proto_item *pi_tmp;
    proto_tree *pt_pcaplog_data;

    pcaplog_item = proto_tree_add_item(tree, proto_pcaplog, tvb, 0, -1, ENC_NA);
    pcaplog_tree = proto_item_add_subtree(pcaplog_item, ett_pcaplog);

    proto_tree_add_item_ret_uint(pcaplog_tree, hf_pcaplog_type, tvb, 0, 4, ENC_LITTLE_ENDIAN, &data_type);
    proto_tree_add_item_ret_uint(pcaplog_tree, hf_pcaplog_length, tvb, 4, 4, ENC_LITTLE_ENDIAN, &data_length);
    pi_tmp = proto_tree_add_item(pcaplog_tree, hf_pcaplog_data, tvb, 8, data_length, ENC_NA);
    pt_pcaplog_data = proto_item_add_subtree(pi_tmp, ett_pcaplog_data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "pcaplog");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Custom Block: PEN = %s (%d), will%s be copied",
                 enterprises_lookup(pinfo->rec->rec_header.custom_block_header.pen, "Unknown"),
                 pinfo->rec->rec_header.custom_block_header.pen,
                 pinfo->rec->rec_header.custom_block_header.copy_allowed ? "" : " not");

    /* at least data_types 1-3 seem XML-based */
    if (data_type > 0 && data_type <= 3) {
        call_dissector(xml_handle, tvb_new_subset_remaining(tvb, 8), pinfo, pt_pcaplog_data);
    } else {
        call_data_dissector(tvb_new_subset_remaining(tvb, 8), pinfo, pt_pcaplog_data);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_pcaplog(void)
{
    static hf_register_info hf[] = {
        { &hf_pcaplog_type,
            { "Date Type", "pcaplog.data_type",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL} },

        { &hf_pcaplog_length,
            { "Data Length", "pcaplog.data_length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL} },

        { &hf_pcaplog_data,
            { "Data", "pcaplog.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL} },
    };

    static int *ett[] = {
        &ett_pcaplog,
        &ett_pcaplog_data,
    };

    proto_pcaplog = proto_register_protocol("pcaplog",
            "pcaplog", "pcaplog");

    proto_register_field_array(proto_pcaplog, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pcaplog_handle = register_dissector("pcaplog", dissect_pcaplog,
            proto_pcaplog);

}

void
proto_reg_handoff_pcaplog(void)
{
    xml_handle = find_dissector_add_dependency("xml", proto_pcaplog);
    dissector_add_uint("pcapng_custom_block", PEN_VCTR, pcaplog_handle);
}
