/* packet-avsp.c
 * Arista Vendor Specific ethertype Protocol (AVSP)
 *
 * Copyright (c) 2018 by Arista Networks
 * Author: Nikhil AP <nikhilap@arista.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Arista Vendor-Specific EtherType Protocol Identifier
 *
 * Arista applied for, and received the assignment of, a vendor-specific EtherType Protocol Identifier in May of 2016. Details below:
 *
 * Ethertype number is: D28B
 * Issue date is: May 12, 2016
 *
 * Arista Subtype 0x01 is Timestamp L2 Header
 *
 * The timestamp L2 header consist of the following fields:
 *
 * Arista EtherType (0xD28B)
 *     Two-byte protocol subtype of 0x1
 *     Two-byte protocol version: 0x10 for 64-bit timestamp and 0x20 for 48-bit timestamp
 *     UTC timestamp value in IEEE 1588 time of day format (either 64-bit or 48-bit) with the lower 32-bits representing nanoseconds and upper bits representing seconds.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#define ARISTA_TIMESTAMP_SUBTYPE 0x01

#define ARISTA_TIMESTAMP_64_TAI 0x10
#define ARISTA_TIMESTAMP_64_UTC 0x110
#define ARISTA_TIMESTAMP_48_TAI 0x20
#define ARISTA_TIMESTAMP_48_UTC 0x120

void proto_reg_handoff_avsp(void);
void proto_register_avsp(void);

static int proto_avsp = -1;

/* sub trees */
static gint ett_avsp = -1;
static gint ett_avsp_ts_48 = -1;
static gint ett_avsp_ts_64 = -1;

/* avsp variables */
static int hf_avsp_sub_type = -1;
static int hf_avsp_ts_version = -1;
static int hf_avsp_ts_64_tai = -1;
static int hf_avsp_ts_64_utc = -1;
static int hf_avsp_ts_64_sec = -1;
static int hf_avsp_ts_64_ns = -1;
static int hf_avsp_ts_48_tai = -1;
static int hf_avsp_ts_48_utc = -1;
static int hf_avsp_ts_48_sec = -1;
static int hf_avsp_ts_48_ns = -1;
static int hf_avsp_etype = -1;
static int hf_avsp_trailer = -1;

static dissector_handle_t ethertype_handle;

static expert_field ei_avsp_ts_unknown_version = EI_INIT;

static const value_string arista_subtype[] = {
    {ARISTA_TIMESTAMP_SUBTYPE, "timestamp"},
    {0, NULL}
};

static const value_string ts_versions[] = {
    {ARISTA_TIMESTAMP_64_TAI, "Version 1"},
    {ARISTA_TIMESTAMP_64_UTC, "Version 11"},
    {ARISTA_TIMESTAMP_48_TAI, "Version 2"},
    {ARISTA_TIMESTAMP_48_UTC, "Version 12"},
    {0, NULL}
};

static ei_register_info ei[] = {
    { &ei_avsp_ts_unknown_version, { "avsp.ts.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown timestamp version", EXPFILL }},
};

static int
dissect_avsp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data _U_)
{
    guint8 offset = 0;
    int version, subtype;

    /* col_set_str() function is used to set the column string */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVSP");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = NULL;
    proto_tree *avsp_tree = NULL, *avsp_48_tree = NULL, *avsp_64_tree;

    /* Adding Items and Values to the Protocol Tree */
    ti = proto_tree_add_item(tree, proto_avsp, tvb, 0, -1,
            ENC_NA);
    avsp_tree = proto_item_add_subtree(ti, ett_avsp);

    /* adding each item to avsp */
    proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_sub_type, tvb,
            offset, 2, ENC_BIG_ENDIAN, &subtype);
    offset += 2;

    if (subtype == ARISTA_TIMESTAMP_SUBTYPE) {
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_ts_version, tvb, offset,
                2, ENC_BIG_ENDIAN, &version);
        offset += 2;

        switch (version) {
        case ARISTA_TIMESTAMP_64_TAI:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_64_tai, tvb, 0, -1,
                    ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti, ett_avsp);
            col_add_fstr(pinfo->cinfo, COL_INFO, "64bit TAI timestamp");
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_sec, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_TIMESTAMP_64_UTC:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_64_utc, tvb, 0, -1,
                    ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti, ett_avsp);
            col_add_fstr(pinfo->cinfo, COL_INFO, "64bit UTC timestamp");
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_sec, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_TIMESTAMP_48_TAI:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_48_tai, tvb, 0, -1,
                    ENC_NA);
            avsp_48_tree = proto_item_add_subtree(ti, ett_avsp);
            col_add_fstr(pinfo->cinfo, COL_INFO, "48bit TAI timestamp");
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_sec, tvb, offset,
                2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_TIMESTAMP_48_UTC:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_48_utc, tvb, 0, -1,
                    ENC_NA);
            avsp_48_tree = proto_item_add_subtree(ti, ett_avsp);
            col_add_fstr(pinfo->cinfo, COL_INFO, "48bit UTC timestamp");
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_sec, tvb, offset,
                2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, ti, &ei_avsp_ts_unknown_version,
                    "Unknown timestamp version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }
    }

    guint16 encap_proto;
    encap_proto = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(avsp_tree, hf_avsp_etype, tvb, offset, 2, encap_proto);
    offset += 2;

    ethertype_data_t ethertype_data;
    ethertype_data.etype = encap_proto;
    ethertype_data.payload_offset = offset;
    ethertype_data.fh_tree = avsp_tree;
    ethertype_data.trailer_id = hf_avsp_trailer;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    return tvb_captured_length(tvb);
}

void proto_reg_handoff_avsp(void)
{
    /* the handle for the dynamic dissector */
    dissector_handle_t avsp_handle;

    avsp_handle =
        create_dissector_handle(dissect_avsp, proto_avsp);

    dissector_add_uint("ethertype", ETHERTYPE_AVSP, avsp_handle);
    ethertype_handle = find_dissector_add_dependency("ethertype", proto_avsp);
}

void proto_register_avsp(void)
{
    /* Field Registration */
    static hf_register_info hf[] = {
        /* For avsp */
        {&hf_avsp_sub_type,
            {"Sub Type", "avsp.sub_type",
                FT_UINT16, BASE_DEC,
                VALS(arista_subtype), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_version,
            {"Version", "avsp.ver",
                FT_UINT16, BASE_HEX,
                VALS(ts_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_tai,
            {"Timestamp (TAI)", "avsp.64ts",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_utc,
            {"Timestamp (UTC)", "avsp.64ts",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_sec,
            {"Seconds", "avsp.64sec",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_ns,
            {"Nanoseconds", "avsp.64ns",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_tai,
            {"Timestamp (TAI)", "avsp.48ts",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_utc,
            {"Timestamp (UTC)", "avsp.48ts",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_sec,
            {"Seconds", "avsp.48sec",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_ns,
            {"Nanoseconds", "avsp.48ns",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_etype,
            {"Type", "avsp.etype",
                FT_UINT16, BASE_HEX,
                VALS(etype_vals), 0x0,
                "Ethertype", HFILL}
        },
        {&hf_avsp_trailer,
            {"Trailer", "avsp.trailer",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "AVSP Trailer", HFILL}
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_avsp,    /* main avsp tree */
        &ett_avsp_ts_48, /* subtree above for 48 bit timestamp */
        &ett_avsp_ts_64, /* subtree above for 64 bit timestamp */
    };

    /* registering the avsp protocol with 3 names */
    proto_avsp = proto_register_protocol("Arista Vendor Specific Protocol",
            "avsp",
            "avsp"
            );

    /* Register header fields and subtrees. */
    proto_register_field_array(proto_avsp, hf, array_length(hf));

    /*  To register subtree types, pass an array of pointers */
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_register_protocol(proto_avsp),
            ei, array_length(ei));

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
