/* packet-avsp.c
 * Arista Vendor Specific ethertype Protocol (AVSP)
 *
 * Copyright (c) 2018-2022 by Arista Networks
 * Author: Nikhil AP <nikhilap@arista.com>
 * Author: PMcL <peterm@arista.com>
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
  * Arista Subtype 0x0001 is a Timestamp L2 Header
  * Arista Subtype 0xCAFE is a TGen L2 header
  *
  * The timestamp L2 header consists of the following fields:
  *
  * Arista Vendor Specific Protocol EtherType (0xD28B)
  *     Two-byte protocol subtype of 0x0001
  *     Two-byte protocol version: 0x0010 for 64-bit timestamp and 0x0020 for 48-bit timestamp
  *     UTC timestamp value in IEEE 1588 time of day format (either 64-bit or 48-bit) with the lower 32-bits representing nanoseconds and upper bits representing seconds.
  *
  * The TGen L2 header consists of the following fields:
  *
  * Arista Vendor Specific Protocol EtherType (0xD28B)
  *     Two-byte protocol subtype of 0xCAFE
  *     Two-byte protocol version: 0x0001
  */

#include "config.h"
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

#include "packet-eth.h"

#define ARISTA_SUBTYPE_TIMESTAMP 0x0001

#define ARISTA_TIMESTAMP_64_TAI 0x0010
#define ARISTA_TIMESTAMP_64_UTC 0x0110
#define ARISTA_TIMESTAMP_48_TAI 0x0020
#define ARISTA_TIMESTAMP_48_UTC 0x0120

#define ARISTA_SUBTYPE_TGEN 0xCAFE
#define ARISTA_TGEN_VER_1 0x0001

void proto_reg_handoff_avsp(void);
void proto_register_avsp(void);

static dissector_handle_t avsp_handle;
static int proto_avsp;

/* sub trees */
static int ett_avsp;
static int ett_avsp_ts_48;
static int ett_avsp_ts_64;
static int ett_avsp_tgen_hdr;
static int ett_avsp_tgen_hdr_ctrl;
static int ett_avsp_tgen_payload;

/* AVSP Timestamp subtype header fields */
static int hf_avsp_subtype;
static int hf_avsp_ts_version;
static int hf_avsp_ts_64_tai;
static int hf_avsp_ts_64_utc;
static int hf_avsp_ts_64_sec;
static int hf_avsp_ts_64_ns;
static int hf_avsp_ts_48_tai;
static int hf_avsp_ts_48_utc;
static int hf_avsp_ts_48_sec;
static int hf_avsp_ts_48_ns;

static int hf_avsp_etype;
static int hf_avsp_trailer;

/*
  TGen subtype format
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      Ethertype = 0xD28B       |   Protocol Subtype = 0xCAFE   |
  +---------------+---------------+---------------+---------------+
  |   Protocol Version = 0x0001   |      TGen Control Word        |
  +---------------+---------------+---------------+---------------+
  |     TGen Sequence Number      |      TGen Payload Length      |
  +---------------+---------------+---------------+---------------+
  |                        TGen Data Payload                      |
  +---------------+---------------+---------------+---------------+
  |                              ...                              |
  +---------------+---------------+---------------+---------------+
  |                        TGen Data Payload                      |
  +---------------+---------------+---------------+---------------+
*/

/* AVSP TGen subtype header fields */
static int hf_avsp_tgen_version;
static int hf_avsp_tgen_hdr;
static int hf_avsp_tgen_hdr_ctrl;
static int hf_avsp_tgen_hdr_ctrl_fcs_inverted;
static int hf_avsp_tgen_hdr_ctrl_reserved;
static int hf_avsp_tgen_hdr_seq_num;
static int hf_avsp_tgen_hdr_payload_len;
static int hf_avsp_tgen_payload;
static int hf_avsp_tgen_payload_data;

static int* const avsp_tgen_ctrl[] = {
    &hf_avsp_tgen_hdr_ctrl_fcs_inverted,
    &hf_avsp_tgen_hdr_ctrl_reserved,
    NULL
};

static dissector_handle_t ethertype_handle;

static const value_string arista_subtypes[] = {
    {ARISTA_SUBTYPE_TIMESTAMP, "timestamp"},
    {ARISTA_SUBTYPE_TGEN, "TGen"},
    {0, NULL}
};

static const value_string ts_versions[] = {
    {ARISTA_TIMESTAMP_64_TAI, "Version 1"},
    {ARISTA_TIMESTAMP_64_UTC, "Version 11"},
    {ARISTA_TIMESTAMP_48_TAI, "Version 2"},
    {ARISTA_TIMESTAMP_48_UTC, "Version 12"},
    {0, NULL}
};

static const value_string tgen_versions[] = {
    {ARISTA_TGEN_VER_1, "1"},
    {0, NULL}
};

static expert_field ei_avsp_unknown_subtype;
static expert_field ei_avsp_ts_unknown_version;
static expert_field ei_avsp_tgen_unknown_version;

static int
dissect_avsp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    volatile int offset = 0;
    uint32_t version, subtype, tgen_payload_len = 0;
    uint64_t tgen_ctrl;
    uint32_t tgen_seq_num;
    const char* str;

    tvbuff_t* volatile tgen_payload_tvb = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVSP");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item* avsp_ti, * ti;
    proto_tree* avsp_tree, * avsp_48_tree = NULL, * avsp_64_tree = NULL,
        * avsp_tgen_hdr = NULL, * avsp_tgen_payload = NULL;

    /* Adding Items and Values to the Protocol Tree */
    avsp_ti = proto_tree_add_item(tree, proto_avsp, tvb, 0, -1,
        ENC_NA);
    avsp_tree = proto_item_add_subtree(avsp_ti, ett_avsp);

    /* add the subtype to avsp */
    proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_subtype, tvb,
        offset, 2, ENC_BIG_ENDIAN, &subtype);
    str = try_val_to_str(subtype, arista_subtypes);
    if (str) {
        proto_item_append_text(avsp_ti, ", Subtype: %s", str);
    }
    offset += 2;

    /* Based on the subtype, add the version and further custom protocol fields */
    switch (subtype) {
    case ARISTA_SUBTYPE_TIMESTAMP:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_ts_version, tvb, offset,
            2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, ts_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_TIMESTAMP_64_TAI:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_64_tai, tvb, 0, -1,
                ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti, ett_avsp);
            col_add_str(pinfo->cinfo, COL_INFO, "64bit TAI timestamp");
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
            col_add_str(pinfo->cinfo, COL_INFO, "64bit UTC timestamp");
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
            col_add_str(pinfo->cinfo, COL_INFO, "48bit TAI timestamp");
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
            col_add_str(pinfo->cinfo, COL_INFO, "48bit UTC timestamp");
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_sec, tvb, offset,
                2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, avsp_ti, &ei_avsp_ts_unknown_version,
                "Unknown timestamp version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }

        uint16_t encap_proto;
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
        break;

    case ARISTA_SUBTYPE_TGEN:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_tgen_version, tvb,
            offset, 2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, tgen_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_TGEN_VER_1:
            col_add_str(pinfo->cinfo, COL_INFO, "Arista TGen Frame");

            /* Get TGen Header Control Word. */
            ti = proto_tree_add_item(avsp_tree, hf_avsp_tgen_hdr, tvb, offset, 6,
                ENC_NA);
            avsp_tgen_hdr = proto_item_add_subtree(ti, ett_avsp_tgen_hdr);
            proto_tree_add_bitmask_ret_uint64(avsp_tgen_hdr, tvb, offset,
                hf_avsp_tgen_hdr_ctrl, ett_avsp_tgen_hdr_ctrl, avsp_tgen_ctrl,
                ENC_BIG_ENDIAN, &tgen_ctrl);
            proto_item_append_text(ti, ", Control Word: 0x%04" PRIx64, tgen_ctrl);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Ctrl=0x%04" PRIx64, tgen_ctrl);
            offset += 2;

            /* Get TGen Header Sequence Number*/
            proto_tree_add_item_ret_uint(avsp_tgen_hdr, hf_avsp_tgen_hdr_seq_num, tvb,
                offset, 2, ENC_BIG_ENDIAN, &tgen_seq_num);
            proto_item_append_text(ti, ", Sequence Number: %u", tgen_seq_num);
            col_append_str_uint(pinfo->cinfo, COL_INFO, "Seq", tgen_seq_num, ", ");
            offset += 2;

            /* Get TGen Header Payload Length */
            proto_tree_add_item_ret_uint(avsp_tgen_hdr,
                hf_avsp_tgen_hdr_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN,
                &tgen_payload_len);
            proto_item_append_text(ti, ", Payload Length: %u", tgen_payload_len);
            col_append_str_uint(pinfo->cinfo, COL_INFO, "Len", tgen_payload_len, ", ");
            offset += 2;

            /* Try to construct a tvbuff containing only
                the data specified by the tgen_payload_len field. */

            TRY {
                tgen_payload_tvb = tvb_new_subset_length(tvb, offset, tgen_payload_len);
            }
                CATCH_BOUNDS_ERRORS {
                /* So:
                    the packet doesn't have "tgen_payload_len" bytes worth of
                    captured data left in it so the "tvb_new_subset_length()"
                    creating "payload_tvb" threw an exception

                    This means that all the data in the frame is within the
                    length value, so we give all the data to the payload. */
                tgen_payload_tvb = tvb_new_subset_remaining(tvb, offset);
            }
            ENDTRY;

            /* Get the TGen payload captured length. */
            uint16_t tgen_payload_captured_len = tvb_captured_length(tgen_payload_tvb);

            /* Add the TGen payload to the tree, with a heading that displays
               the TGgen payload captured length. */
            ti = proto_tree_add_none_format(avsp_tree, hf_avsp_tgen_payload,
                tgen_payload_tvb, 0, -1, "TGen Payload (%u byte%s)",
                tgen_payload_captured_len,
                plurality(tgen_payload_captured_len, "", "s"));
            avsp_tgen_payload = proto_item_add_subtree(ti, ett_avsp_tgen_payload);
            proto_tree_add_item(avsp_tgen_payload, hf_avsp_tgen_payload_data, tgen_payload_tvb,
                0, -1, ENC_NA);

            /* Now we know the TGen payload captured length (which may be less than
               that specified in the TGen header because the captured frame may have
               been truncated) we can set the length of the entire AVSP protocol. */
            proto_item_set_len(avsp_ti, offset + tgen_payload_captured_len);

            /* We have a length field, so set it here so that the higher level
             * (ethertype) dissector can add the trailer. That way the FCS
             * will be calculated correctly.
             */
            set_actual_length(tvb, offset + tgen_payload_captured_len);
            break;

        default:
            expert_add_info_format(pinfo, avsp_ti, &ei_avsp_tgen_unknown_version,
                "Unknown version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }
        break;

    default:
        expert_add_info_format(pinfo, avsp_ti, &ei_avsp_unknown_subtype,
            "Unknown subtype: 0x%0x", subtype);
        return tvb_captured_length(tvb);
    }
    return tvb_captured_length(tvb);
}

void proto_reg_handoff_avsp(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_AVSP, avsp_handle);
    ethertype_handle = find_dissector_add_dependency("ethertype", proto_avsp);
}

void proto_register_avsp(void)
{
    /* Field Registration */
    static hf_register_info hf[] = {
        /* For avsp */
        {&hf_avsp_subtype,
            {"Subtype", "avsp.subtype",
                FT_UINT16, BASE_HEX,
                VALS(arista_subtypes), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_version,
            {"Version", "avsp.ts.ver",
                FT_UINT16, BASE_HEX,
                VALS(ts_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_tai,
            {"Timestamp (TAI)", "avsp.ts.64.tai",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_utc,
            {"Timestamp (UTC)", "avsp.ts.64.utc",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_sec,
            {"Seconds", "avsp.ts.64.sec",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_64_ns,
            {"Nanoseconds", "avsp.ts.64.ns",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_tai,
            {"Timestamp (TAI)", "avsp.ts.48.tai",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_utc,
            {"Timestamp (UTC)", "avsp.ts.48.utc",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_sec,
            {"Seconds", "avsp.ts.48.sec",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_ts_48_ns,
            {"Nanoseconds", "avsp.ts.48.ns",
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
        {&hf_avsp_tgen_version,
            {"Version", "avsp.tgen.ver",
                FT_UINT16, BASE_DEC,
                VALS(tgen_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_tgen_hdr,
            {"TGen Header", "avsp.tgen.hdr",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_tgen_hdr_ctrl,
            {"Control Word", "avsp.tgen.hdr.ctrl",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_tgen_hdr_ctrl_fcs_inverted,
            {"FCS Inverted", "avsp.tgen.hdr.ctrl.fcs_inverted",
                FT_BOOLEAN, 16,
                NULL, 0x0001,
                NULL, HFILL}
        },
        {&hf_avsp_tgen_hdr_ctrl_reserved,
            {"Reserved", "avsp.tgen.hdr.ctrl.reserved",
                FT_UINT16, BASE_HEX,
                NULL, 0xFFFE,
                NULL, HFILL}
        },
        {&hf_avsp_tgen_hdr_seq_num,
            {"Sequence Number", "avsp.tgen.hdr.seq_num",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_tgen_hdr_payload_len,
            {"Payload Length", "avsp.tgen.hdr.payload_len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        { &hf_avsp_tgen_payload,
            {"TGen Payload", "avsp.tgen.payload",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        { &hf_avsp_tgen_payload_data,
            {"Data", "avsp.tgen.payload.data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_avsp,               /* main avsp tree */
        &ett_avsp_ts_48,         /* subtree above for 48 bit timestamp */
        &ett_avsp_ts_64,         /* subtree above for 64 bit timestamp */
        &ett_avsp_tgen_hdr,      /* subtree for TGen header */
        &ett_avsp_tgen_hdr_ctrl, /* subtree for TGen header control bits */
        &ett_avsp_tgen_payload,  /* subtree for TGen payload */
    };

    static ei_register_info ei[] = {
        { &ei_avsp_unknown_subtype, { "avsp.unknown_subtype", PI_SEQUENCE, PI_WARN, "Unknown AVSP subtype", EXPFILL}},
        { &ei_avsp_ts_unknown_version, { "avsp.ts.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown timestamp version", EXPFILL }},
        { &ei_avsp_tgen_unknown_version, { "avsp.tgen.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown TGen version", EXPFILL }},
    };

    /* Register the AVSP protocol. */
    proto_avsp = proto_register_protocol("Arista Vendor Specific Protocol", "AVSP", "avsp");

    /* Register header fields and subtrees. */
    proto_register_field_array(proto_avsp, hf, array_length(hf));

    /*  Register subtree types. */
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the expert module. */
    expert_register_field_array(expert_register_protocol(proto_avsp), ei, array_length(ei));

    /* Register the dissector handle. */
    avsp_handle = register_dissector("avsp", dissect_avsp, proto_avsp);
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
