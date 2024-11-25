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
#include <epan/address.h>

#include <wsutil/str_util.h>

#include "packet-eth.h"

#define ARISTA_SUBTYPE_TIMESTAMP 0x0001

#define ARISTA_TIMESTAMP_64_TAI 0x0010
#define ARISTA_TIMESTAMP_64_UTC 0x0110
#define ARISTA_TIMESTAMP_48_TAI 0x0020
#define ARISTA_TIMESTAMP_48_UTC 0x0120
#define ARISTA_TIMESTAMP_64_TAI_J2 0x0011
#define ARISTA_TIMESTAMP_64_UTC_J2 0x0111
#define ARISTA_TIMESTAMP_48_TAI_J2 0x0021
#define ARISTA_TIMESTAMP_48_UTC_J2 0x0121

#define ARISTA_SUBTYPE_GREENTAP 0x0003

#define ARISTA_GREENTAP_48_TAI 0x0020
#define ARISTA_GREENTAP_48_UTC 0x0120

#define ARISTA_SUBTYPE_GREENT 0x0004

#define ARISTA_GREENT_VER_1 0x0001

#define ARISTA_SUBTYPE_DZGRE_A  0x0007

#define ARISTA_DZGRE_A_VER_1 0x0001

#define ARISTA_SUBTYPE_DZGRE_B  0x0008

#define ARISTA_DZGRE_B_VER_1 0x0001

#define ARISTA_SUBTYPE_DZGRE_TS  0x0009

#define ARISTA_DZGRE_TS_64_TAI 0x0011
#define ARISTA_DZGRE_TS_64_UTC 0x0111

#define ARISTA_SUBTYPE_TGEN 0xCAFE
#define ARISTA_TGEN_VER_1 0x0001

#define ROUNDUP(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

void proto_reg_handoff_avsp(void);
void proto_register_avsp(void);

static dissector_handle_t avsp_handle;
static int proto_avsp;

/* sub trees */
static int ett_avsp;
static int ett_avsp_ts_48;
static int ett_avsp_ts_64;
static int ett_avsp_dzgre_a_hdr;
static int ett_avsp_dzgre_b_hdr;
static int ett_avsp_dzgre_ts_hdr;
static int ett_avsp_dzgre_ts_tai;
static int ett_avsp_dzgre_ts_utc;
static int ett_avsp_greent_hdr;
static int ett_avsp_greent_sample_hdr;
static int ett_avsp_greent_sample_data;
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
  GREENTAP Timestamping format
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Protocol Subtype = 0x0003   |      Protocol Version         |
  +---------------+---------------+---------------+---------------+
  |          Session ID           |      Timestamp (seconds)      |
  +---------------+---------------+---------------+---------------+
  |0 0|                Timestamp (nanoseconds)                    |
  +---------------+---------------+---------------+---------------+
*/

/* AVSP GREENTAP subtype header fields */
static int hf_avsp_greentap_version;
static int hf_avsp_greentap_tai;
static int hf_avsp_greentap_utc;
static int hf_avsp_greentap_sec;
static int hf_avsp_greentap_ns;

/*
  GREENT subtype format
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Protocol Subtype = 0x0004   |      Protocol Version         |
  +---------------+---------------+---------------+---------------+
  |         Session ID            |     Flags     | Sample Count  |
  +---------------+---------------+---------------+---------------+

  Each sample has a header of the format:
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Length              |     IEEE 1588 TS (seconds)    |
  +---------------+---------------+---------------+---------------+
  |                   IEEE 1588 TS (nanoseconds)                  |
  +---------------+---------------+---------------+---------------+
  |                   Ingress Port (SNMP ifIndex)                 |
  +---------------+---------------+---------------+---------------+
  |                   Egress Port (SNMP ifIndex)                  |
  +---------------+---------------+---------------+---------------+
  |  Sample Rate (multiplier 1K)  |        Payload Checksum       |
  +---------------+---------------+---------------+---------------+
  |               Sample (padded to 4 byte boundary)              |
  +---------------+---------------+---------------+---------------+
*/

/* AVSP GREENT subtype header fields */
static int hf_avsp_greent_hdr;
static int hf_avsp_greent_version;
static int hf_avsp_greent_session;
static int hf_avsp_greent_flags;
static int hf_avsp_greent_sample_count;

/* GREENT sample header fields */
static int hf_avsp_greent_sample_hdr;
static int hf_avsp_greent_sample_len;
static int hf_avsp_greent_sample_sec;
static int hf_avsp_greent_sample_ns;
static int hf_avsp_greent_sample_ingress;
static int hf_avsp_greent_sample_egress;
static int hf_avsp_greent_sample_rate;
static int hf_avsp_greent_sample_sum;
static int hf_avsp_greent_sample_data;

/*
  DzGRE Plan A subtype format
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Protocol Subtype = 0x0007   |      Protocol Version         |
  +---------------+---------------+---------------+---------------+
  |          Switch ID            |           Port ID             |
  +---------------+---------------+---------------+---------------+
  |          Policy ID            |           Reserved            |
  +---------------+---------------+---------------+---------------+

  DzGRE Plan B subtype format
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Protocol Subtype = 0x0008   |      Protocol Version         |
  +---------------+---------------+---------------+---------------+
  |0 0 0 0|      Port ID          |0 0 0 0|     Policy ID         |
  +---------------+---------------+---------------+---------------+

  DzGRE with timestamping
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Protocol Subtype = 0x0009   |      Protocol Version         |
  +---------------+---------------+---------------+---------------+
  |          Switch ID            |           Port ID             |
  +---------------+---------------+---------------+---------------+
  |          Policy ID            |           Reserved            |
  +---------------+---------------+---------------+---------------+
  |                  UTC Timestamp (seconds)                      |
  +---------------+---------------+---------------+---------------+
  |                  UTC Timestamp (nanoseconds)                  |
  +---------------+---------------+---------------+---------------+
*/

/* AVSP DzGRE header fields */
static int hf_avsp_dzgre_a_hdr;
static int hf_avsp_dzgre_a_version;
static int hf_avsp_dzgre_a_switch;
static int hf_avsp_dzgre_a_port;
static int hf_avsp_dzgre_a_policy;
static int hf_avsp_dzgre_a_reserved;

static int hf_avsp_dzgre_b_hdr;
static int hf_avsp_dzgre_b_version;
static int hf_avsp_dzgre_b_port;
static int hf_avsp_dzgre_b_policy;

static int hf_avsp_dzgre_ts_hdr;
static int hf_avsp_dzgre_ts_version;
static int hf_avsp_dzgre_ts_switch;
static int hf_avsp_dzgre_ts_port;
static int hf_avsp_dzgre_ts_policy;
static int hf_avsp_dzgre_ts_reserved;
static int hf_avsp_dzgre_ts_tai;
static int hf_avsp_dzgre_ts_utc;
static int hf_avsp_dzgre_ts_sec;
static int hf_avsp_dzgre_ts_ns;

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
    {ARISTA_SUBTYPE_GREENTAP, "GRE TAP"},
    {ARISTA_SUBTYPE_GREENT, "Postcard"},
    {ARISTA_SUBTYPE_DZGRE_A, "DzGRE (plan A)"},
    {ARISTA_SUBTYPE_DZGRE_B, "DzGRE (plan B)"},
    {ARISTA_SUBTYPE_DZGRE_TS, "DzGRE (timestamped)"},
    {ARISTA_SUBTYPE_TGEN, "TGen"},
    {0, NULL}
};

static const value_string ts_versions[] = {
    {ARISTA_TIMESTAMP_64_TAI, "010"},
    {ARISTA_TIMESTAMP_64_UTC, "110"},
    {ARISTA_TIMESTAMP_48_TAI, "020"},
    {ARISTA_TIMESTAMP_48_UTC, "120"},
    {ARISTA_TIMESTAMP_64_TAI_J2, "011"},
    {ARISTA_TIMESTAMP_64_UTC_J2, "111"},
    {ARISTA_TIMESTAMP_48_TAI_J2, "021"},
    {ARISTA_TIMESTAMP_48_UTC_J2, "121"},
    {0, NULL}
};

static const value_string greentap_versions[] = {
    {ARISTA_GREENTAP_48_TAI, "48bit TAI"},
    {ARISTA_GREENTAP_48_UTC, "48bit UTC"},
    {0, NULL}
};

static const value_string greent_versions[] = {
    {ARISTA_GREENT_VER_1, "1"},
    {0, NULL}
};

static const value_string dzgre_a_versions[] = {
    {ARISTA_DZGRE_A_VER_1, "1"},
    {0, NULL}
};

static const value_string dzgre_b_versions[] = {
    {ARISTA_DZGRE_A_VER_1, "1"},
    {0, NULL}
};

static const value_string dzgre_ts_versions[] = {
    {ARISTA_DZGRE_TS_64_TAI, "64bit TAI"},
    {ARISTA_DZGRE_TS_64_UTC, "64bit UTC"},
    {0, NULL}
};

static const value_string tgen_versions[] = {
    {ARISTA_TGEN_VER_1, "1"},
    {0, NULL}
};

static expert_field ei_avsp_unknown_subtype;
static expert_field ei_avsp_ts_unknown_version;
static expert_field ei_avsp_greentap_unknown_version;
static expert_field ei_avsp_greent_unknown_version;
static expert_field ei_avsp_dzgre_a_unknown_version;
static expert_field ei_avsp_dzgre_b_unknown_version;
static expert_field ei_avsp_dzgre_ts_unknown_version;
static expert_field ei_avsp_tgen_unknown_version;

static int
dissect_avsp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    volatile int offset = 0;
    uint32_t version, subtype, tgen_payload_len = 0;
    uint64_t tgen_ctrl;
    uint32_t tgen_seq_num, sample_len, count, u32;
    volatile uint32_t i; // potentially held across vfork
    const char* str;
    uint16_t encap_proto;
    ethertype_data_t ethertype_data;
    tvbuff_t* volatile tgen_payload_tvb = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVSP");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item* avsp_ti, * ti;
    proto_tree* avsp_tree, * avsp_48_tree = NULL, * avsp_64_tree = NULL,
        * avsp_tgen_hdr = NULL, * avsp_tgen_payload = NULL,
        * avsp_dzgre_hdr = NULL, * avsp_greent_hdr = NULL,
        * avsp_greent_sample_hdr = NULL, *header_tree = NULL;

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
        case ARISTA_TIMESTAMP_64_TAI_J2:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_64_tai, tvb, 0, -1,
                ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti, ett_avsp);
            col_set_str(pinfo->cinfo, COL_INFO, "64bit TAI timestamp");
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_sec, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_TIMESTAMP_64_UTC:
        case ARISTA_TIMESTAMP_64_UTC_J2:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_64_utc, tvb, 0, -1,
                ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti, ett_avsp);
            col_set_str(pinfo->cinfo, COL_INFO, "64bit UTC timestamp");
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_sec, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(avsp_64_tree, hf_avsp_ts_64_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_TIMESTAMP_48_TAI:
        case ARISTA_TIMESTAMP_48_TAI_J2:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_48_tai, tvb, 0, -1,
                ENC_NA);
            avsp_48_tree = proto_item_add_subtree(ti, ett_avsp);
            col_set_str(pinfo->cinfo, COL_INFO, "48bit TAI timestamp");
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_sec, tvb, offset,
                2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(avsp_48_tree, hf_avsp_ts_48_ns, tvb, offset,
                4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_TIMESTAMP_48_UTC:
        case ARISTA_TIMESTAMP_48_UTC_J2:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_ts_48_utc, tvb, 0, -1,
                ENC_NA);
            avsp_48_tree = proto_item_add_subtree(ti, ett_avsp);
            col_set_str(pinfo->cinfo, COL_INFO, "48bit UTC timestamp");
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

        encap_proto = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(avsp_tree, hf_avsp_etype, tvb, offset, 2, encap_proto);
        offset += 2;

        ethertype_data.etype = encap_proto;
        ethertype_data.payload_offset = offset;
        ethertype_data.fh_tree = avsp_tree;
        ethertype_data.trailer_id = hf_avsp_trailer;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
        break;

    case ARISTA_SUBTYPE_GREENTAP:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_greentap_version, tvb,
            offset, 2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, greentap_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_GREENTAP_48_TAI:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_greentap_tai, tvb,
                0, -1, ENC_NA);
            avsp_48_tree = proto_item_add_subtree(ti, ett_avsp);
            col_set_str(pinfo->cinfo, COL_INFO, "48bit TAI timestamp");
            proto_tree_add_item(avsp_48_tree, hf_avsp_greentap_sec,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(avsp_48_tree, hf_avsp_greentap_ns,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_GREENTAP_48_UTC:
            ti = proto_tree_add_item(avsp_tree, hf_avsp_greentap_utc, tvb,
                0, -1, ENC_NA);
            avsp_48_tree = proto_item_add_subtree(ti, ett_avsp);
            col_set_str(pinfo->cinfo, COL_INFO, "48bit TAI timestamp");
            proto_tree_add_item(avsp_48_tree, hf_avsp_greentap_sec,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(avsp_48_tree, hf_avsp_greentap_ns,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, avsp_ti,
                &ei_avsp_greentap_unknown_version,
                "Unknown GRE TAP version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }

        encap_proto = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(avsp_tree, hf_avsp_etype, tvb, offset, 2,
                encap_proto);
        offset += 2;

        ethertype_data.etype = encap_proto;
        ethertype_data.payload_offset = offset;
        ethertype_data.fh_tree = avsp_tree;
        ethertype_data.trailer_id = hf_avsp_trailer;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree,
                &ethertype_data);
        break;

    case ARISTA_SUBTYPE_GREENT:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_greent_version, tvb,
            offset, 2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, greent_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_GREENT_VER_1:
            col_set_str(pinfo->cinfo, COL_INFO, "Arista Postcard Telemetry");
            ti = proto_tree_add_item(avsp_tree, hf_avsp_greent_hdr, tvb, 0,
                -1, ENC_NA);
            avsp_greent_hdr = proto_item_add_subtree(ti, ett_avsp_greent_hdr);

            /* Session ID */
            proto_tree_add_item_ret_uint(avsp_greent_hdr,
                    hf_avsp_greent_session, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Session ID: %u", u32);
            offset += 2;

            /* Flags */
            proto_tree_add_item_ret_uint(avsp_greent_hdr,
                    hf_avsp_greent_flags, tvb, offset, 1, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Flags: 0x%02x", u32);
            offset += 1;

            /* Sample Count */
            proto_tree_add_item_ret_uint(avsp_greent_hdr,
                    hf_avsp_greent_sample_count, tvb, offset, 1, ENC_BIG_ENDIAN,
                    &count);
            proto_item_append_text(ti, ", Count: %u", count);
            offset += 1;

            for (i = 0; i < count; i++) {
                ti = proto_tree_add_item(avsp_greent_hdr,
                        hf_avsp_greent_sample_hdr, tvb, 0, -1, ENC_NA);
                avsp_greent_sample_hdr = proto_item_add_subtree(ti,
                        ett_avsp_greent_sample_hdr);

                /* Length */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_len, tvb, offset, 2,
                        ENC_BIG_ENDIAN, &sample_len);
                proto_item_append_text(ti, ", Length: %u", sample_len);
                offset += 2;

                /* Seconds */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_sec, tvb, offset, 2,
                        ENC_BIG_ENDIAN, &u32);
                proto_item_append_text(ti, ", Seconds: %u", u32);
                offset += 2;

                /* Nanoseconds */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_ns, tvb, offset, 4,
                        ENC_BIG_ENDIAN, &u32);
                proto_item_append_text(ti, ", Nanoseconds: %u", u32);
                offset += 4;

                /* Ingress */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_ingress, tvb, offset, 4,
                        ENC_BIG_ENDIAN, &u32);
                proto_item_append_text(ti, ", Ingress: %u", u32);
                offset += 4;

                /* Egress */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_egress, tvb, offset, 4,
                        ENC_BIG_ENDIAN, &u32);
                proto_item_append_text(ti, ", Egress: %u", u32);
                offset += 4;

                /* Sample Rate */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_rate, tvb, offset, 2,
                        ENC_BIG_ENDIAN, &u32);
                proto_item_append_text(ti, ", Rate: %u", u32);
                offset += 2;

                /* Checksum */
                proto_tree_add_item_ret_uint(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_sum, tvb, offset, 2,
                        ENC_BIG_ENDIAN, &u32);
                proto_item_append_text(ti, ", Checksum: 0x%04x", u32);
                offset += 2;

                /* Sample Data */
                ti = proto_tree_add_item(avsp_greent_sample_hdr,
                        hf_avsp_greent_sample_data, tvb, offset, sample_len,
                        ENC_NA);
                header_tree = proto_item_add_subtree(ti,
                        ett_avsp_greent_sample_data);

                /*
                 * We call the ethernet dissector on the sample, but since
                 * the sample is truncated it will likely generate errors.
                 * This is an attempt to isolate those errors, borrowed from
                 * sflow.
                 */
                {
                    tvbuff_t *next_tvb;
                    address save_dl_src, save_dl_dst, save_net_src,
                            save_net_dst, save_src, save_dst;
                    bool save_writable, save_in_error_pkt;;

                    sample_len = ROUNDUP(sample_len, 4);
                    next_tvb = tvb_new_subset_length(tvb, offset, sample_len);

                    save_in_error_pkt = pinfo->flags.in_error_pkt;
                    pinfo->flags.in_error_pkt = true;

                    save_writable = col_get_writable(pinfo->cinfo, -1);
                    col_set_writable(pinfo->cinfo, -1, false);
                    copy_address_shallow(&save_dl_src, &pinfo->dl_src);
                    copy_address_shallow(&save_dl_dst, &pinfo->dl_dst);
                    copy_address_shallow(&save_net_src, &pinfo->net_src);
                    copy_address_shallow(&save_net_dst, &pinfo->net_dst);
                    copy_address_shallow(&save_src, &pinfo->src);
                    copy_address_shallow(&save_dst, &pinfo->dst);

                    TRY
                    {
                        // always ethernet for greent
                        ethertype_data.etype = ETHERTYPE_ETHBRIDGE;
                        ethertype_data.payload_offset = 0;
                        ethertype_data.fh_tree = header_tree;
                        ethertype_data.trailer_id = hf_avsp_trailer;
                        ethertype_data.fcs_len = 0;

                        call_dissector_with_data(ethertype_handle, next_tvb,
                                pinfo, header_tree, &ethertype_data);
                    }
                    CATCH_BOUNDS_ERRORS {
                    }
                    ENDTRY;

                    col_set_writable(pinfo->cinfo, -1, save_writable);
                    pinfo->flags.in_error_pkt = save_in_error_pkt;
                    copy_address_shallow(&pinfo->dl_src, &save_dl_src);
                    copy_address_shallow(&pinfo->dl_dst, &save_dl_dst);
                    copy_address_shallow(&pinfo->net_src, &save_net_src);
                    copy_address_shallow(&pinfo->net_dst, &save_net_dst);
                    copy_address_shallow(&pinfo->src, &save_src);
                    copy_address_shallow(&pinfo->dst, &save_dst);
                }
            }
            break;
        default:
            expert_add_info_format(pinfo, avsp_ti,
                    &ei_avsp_greent_unknown_version,
                "Unknown version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }
        break;

    case ARISTA_SUBTYPE_DZGRE_A:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_dzgre_a_version, tvb,
            offset, 2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, dzgre_a_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_DZGRE_A_VER_1:
            col_set_str(pinfo->cinfo, COL_INFO, "Arista DzGRE(A) Frame");
            ti = proto_tree_add_item(avsp_tree, hf_avsp_dzgre_a_hdr, tvb,
                    0, -1, ENC_NA);
            avsp_dzgre_hdr = proto_item_add_subtree(ti, ett_avsp_dzgre_a_hdr);

            /* Switch ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_a_switch, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Switch ID: %u", u32);
            offset += 2;

            /* Port ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_a_port, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Port ID: %u", u32);
            offset += 2;

            /* Policy ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_a_policy, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Policy ID: %u", u32);
            offset += 2;

            /* Reserved */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_a_reserved, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            offset += 2;
            break;
        default:
            expert_add_info_format(pinfo, avsp_ti,
                    &ei_avsp_dzgre_a_unknown_version,
                "Unknown version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }

        ethertype_data.etype = ETHERTYPE_ETHBRIDGE; // always ethernet
        ethertype_data.payload_offset = offset;
        ethertype_data.fh_tree = avsp_tree;
        ethertype_data.trailer_id = hf_avsp_trailer;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree,
                &ethertype_data);
        break;

    case ARISTA_SUBTYPE_DZGRE_B:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_dzgre_b_version, tvb,
            offset, 2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, dzgre_b_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_DZGRE_B_VER_1:
            col_set_str(pinfo->cinfo, COL_INFO, "Arista DzGRE(B) Frame");
            ti = proto_tree_add_item(avsp_tree, hf_avsp_dzgre_b_hdr, tvb,
                    0, -1, ENC_NA);
            avsp_dzgre_hdr = proto_item_add_subtree(ti, ett_avsp_dzgre_b_hdr);

            /* Port ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_b_port, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Port ID: %u", u32);
            offset += 2;

            /* Policy ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_b_policy, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Policy ID: %u", u32);
            offset += 2;
            break;
        default:
            expert_add_info_format(pinfo, avsp_ti,
                    &ei_avsp_dzgre_b_unknown_version,
                "Unknown version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }

        ethertype_data.etype = ETHERTYPE_ETHBRIDGE; // always ethernet
        ethertype_data.payload_offset = offset;
        ethertype_data.fh_tree = avsp_tree;
        ethertype_data.trailer_id = hf_avsp_trailer;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree,
                &ethertype_data);
        break;

    case ARISTA_SUBTYPE_DZGRE_TS:
        proto_tree_add_item_ret_uint(avsp_tree, hf_avsp_dzgre_ts_version, tvb,
            offset, 2, ENC_BIG_ENDIAN, &version);
        str = try_val_to_str(version, dzgre_ts_versions);
        if (str) {
            proto_item_append_text(avsp_ti, ", Version: %s", str);
        }
        offset += 2;

        switch (version) {
        case ARISTA_DZGRE_TS_64_TAI:
            col_set_str(pinfo->cinfo, COL_INFO, "Arista DzGRE(A) Frame");
            ti = proto_tree_add_item(avsp_tree, hf_avsp_dzgre_ts_hdr, tvb,
                    0, -1, ENC_NA);
            avsp_dzgre_hdr = proto_item_add_subtree(ti, ett_avsp_dzgre_ts_hdr);

            /* Switch ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_switch, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Switch ID: %u", u32);
            offset += 2;

            /* Port ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_port, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Port ID: %u", u32);
            offset += 2;

            /* Policy ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_policy, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Policy ID: %u", u32);
            offset += 2;

            /* Reserved */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_reserved, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            offset += 2;

            /* Timestamp */
            ti = proto_tree_add_item(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_tai, tvb, 0, -1, ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti,
                    ett_avsp_dzgre_ts_tai);

            col_set_str(pinfo->cinfo, COL_INFO, "64bit TAI timestamp");

            proto_tree_add_item(avsp_64_tree, hf_avsp_dzgre_ts_sec,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(avsp_64_tree, hf_avsp_dzgre_ts_ns,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case ARISTA_DZGRE_TS_64_UTC:
            col_set_str(pinfo->cinfo, COL_INFO,
                    "Arista DzGRE(timestamped) Frame");
            ti = proto_tree_add_item(avsp_tree, hf_avsp_dzgre_ts_hdr, tvb,
                    0, -1, ENC_NA);
            avsp_dzgre_hdr = proto_item_add_subtree(ti, ett_avsp_dzgre_ts_hdr);

            /* Switch ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_switch, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Switch ID: 0x%u", u32);
            offset += 2;

            /* Port ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_port, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Port ID: 0x%u", u32);
            offset += 2;

            /* Policy ID */
            proto_tree_add_item_ret_uint(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_policy, tvb, offset, 2, ENC_BIG_ENDIAN,
                    &u32);
            proto_item_append_text(ti, ", Policy ID: 0x%u", u32);
            offset += 2;

            /* Reserved */
            offset += 2;

            /* Timestamp */
            ti = proto_tree_add_item(avsp_dzgre_hdr,
                    hf_avsp_dzgre_ts_utc, tvb, 0, -1, ENC_NA);
            avsp_64_tree = proto_item_add_subtree(ti,
                    ett_avsp_dzgre_ts_utc);

            col_set_str(pinfo->cinfo, COL_INFO, "64bit UTC timestamp");

            proto_tree_add_item(avsp_64_tree, hf_avsp_dzgre_ts_sec,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(avsp_64_tree, hf_avsp_dzgre_ts_ns,
                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, avsp_ti,
                    &ei_avsp_dzgre_ts_unknown_version,
                "Unknown version: 0x%0x", version);
            return tvb_captured_length(tvb);
        }

        ethertype_data.etype = ETHERTYPE_ETHBRIDGE; // always ethernet
        ethertype_data.payload_offset = offset;
        ethertype_data.fh_tree = avsp_tree;
        ethertype_data.trailer_id = hf_avsp_trailer;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree,
                &ethertype_data);
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
            col_set_str(pinfo->cinfo, COL_INFO, "Arista TGen Frame");

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
    dissector_add_uint("gre.proto", ETHERTYPE_AVSP, avsp_handle);
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
        {&hf_avsp_greentap_version,
            {"Version", "avsp.greentap.ver",
                FT_UINT16, BASE_DEC,
                VALS(greentap_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greentap_tai,
            {"Timestamp (TAI)", "avsp.greentap.tai",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greentap_utc,
            {"Timestamp (UTC)", "avsp.greentap.utc",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greentap_sec,
            {"Seconds", "avsp.greentap.sec",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greentap_ns,
            {"Nanoseconds", "avsp.greentap.ns",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_version,
            {"Version", "avsp.greent.ver",
                FT_UINT16, BASE_DEC,
                VALS(greent_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_hdr,
            {"GREENT Header", "avsp.greent.hdr",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_session,
            {"Session ID", "avsp.greent.session",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_flags,
            {"Flags", "avsp.greent.flags",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_count,
            {"Sample Count", "avsp.greent.sample_count",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_hdr,
            {"Sample Header", "avsp.greent.sample.hdr",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_len,
            {"Length", "avsp.greent.sample.len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_sec,
            {"Seconds", "avsp.greent.sample.sec",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_ns,
            {"Nanoseconds", "avsp.greent.sample.ns",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_ingress,
            {"Ingress Interface", "avsp.greent.sample.ingress",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_egress,
            {"Egress Interface", "avsp.greent.sample.egress",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_rate,
            {"Rate(*1K)", "avsp.greent.sample.rate",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_sum,
            {"Checksum", "avsp.greent.sample.sum",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_greent_sample_data,
            {"Header of sampled packet", "avsp.greent.sample.data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "Data from sampled header", HFILL}
        },
        {&hf_avsp_dzgre_a_version,
            {"Version", "avsp.dzgre_a.ver",
                FT_UINT16, BASE_DEC,
                VALS(dzgre_a_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_a_hdr,
            {"DzGRE(A) Header", "avsp.dzgre_a.hdr",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_a_switch,
            {"Switch ID", "avsp.dzgre_a.switch",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_a_port,
            {"Port ID", "avsp.dzgre_a.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_a_policy,
            {"Policy ID", "avsp.dzgre_a.policy",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_a_reserved,
            {"Reserved", "avsp.dzgre_a.reserved",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_b_version,
            {"Version", "avsp.dzgre_b.ver",
                FT_UINT16, BASE_DEC,
                VALS(dzgre_b_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_b_hdr,
            {"DzGRE(B) Header", "avsp.dzgre_b.hdr",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_b_port,
            {"Port ID", "avsp.dzgre_b.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_b_policy,
            {"Policy ID", "avsp.dzgre_b.policy",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_version,
            {"Version", "avsp.dzgre_ts.ver",
                FT_UINT16, BASE_DEC,
                VALS(dzgre_ts_versions), 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_hdr,
            {"DzGRE(B) Header", "avsp.dzgre_ts.hdr",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_switch,
            {"Switch ID", "avsp.dzgre_ts.switch",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_port,
            {"Port ID", "avsp.dzgre_ts.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_policy,
            {"Policy ID", "avsp.dzgre_ts.policy",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_reserved,
            {"Reserved", "avsp.dzgre_ts.reserved",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_tai,
            {"Timestamp (TAI)", "avsp.dzgre_ts.tai",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_utc,
            {"Timestamp (UTC)", "avsp.dzgre_ts.utc",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_sec,
            {"Seconds", "avsp.ts.dzgre_ts.sec",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        {&hf_avsp_dzgre_ts_ns,
            {"Nanoseconds", "avsp.dzgre_ts.48.ns",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
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
        &ett_avsp_dzgre_a_hdr,   /* subtree for DzGRE plan A */
        &ett_avsp_dzgre_b_hdr,   /* subtree for DzGRE plan B */
        &ett_avsp_dzgre_ts_hdr,  /* subtree for DzGRE with timestamps */
        &ett_avsp_dzgre_ts_tai,  /* subtree for DzGRE timestamp */
        &ett_avsp_dzgre_ts_utc,  /* subtree for DzGRE timestamp */
        &ett_avsp_greent_hdr,    /* subtree for GREENT header */
        &ett_avsp_greent_sample_hdr,    /* subtree for GREENT sample header */
        &ett_avsp_greent_sample_data,   /* subtree for GREENT sample data */
        &ett_avsp_tgen_hdr,      /* subtree for TGen header */
        &ett_avsp_tgen_hdr_ctrl, /* subtree for TGen header control bits */
        &ett_avsp_tgen_payload,  /* subtree for TGen payload */
    };

    static ei_register_info ei[] = {
        { &ei_avsp_unknown_subtype, { "avsp.unknown_subtype", PI_SEQUENCE, PI_WARN, "Unknown AVSP subtype", EXPFILL}},
        { &ei_avsp_ts_unknown_version, { "avsp.ts.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown timestamp version", EXPFILL }},
        { &ei_avsp_greentap_unknown_version, { "avsp.greentap.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown GREENTAP version", EXPFILL }},
        { &ei_avsp_greent_unknown_version, { "avsp.greent.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown GREENT version", EXPFILL }},
        { &ei_avsp_dzgre_a_unknown_version, { "avsp.dzgre_a.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown DzGRE(A) version", EXPFILL }},
        { &ei_avsp_dzgre_b_unknown_version, { "avsp.dzgre_b.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown DzGRE(B) version", EXPFILL }},
        { &ei_avsp_dzgre_ts_unknown_version, { "avsp.dzgre_ts.unknown_version", PI_SEQUENCE, PI_WARN, "Unknown DzGRE(timestamped) version", EXPFILL }},
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
