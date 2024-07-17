/* packet-iperf.c
 * Routines for iPerf dissection
 * By Anish Bhatt <anish@gatech.edu>
 *
 * Updates for iperf 2.1.9
 * By Andrii Vladyka <a.vladyka@ukr.net>
 * By Robert McMahon <rjmcmahon@rjmcmahon.com>
 * TODO: server-side packets (pending clarifications form Bob)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/tvbparse.h>

#define IPERF2_UDP_HDR_SIZE 160

void proto_register_iperf2(void);
void proto_reg_handoff_iperf2(void);

static int proto_iperf2;

static int hf_iperf2_sequence;
static int hf_iperf2_sec;
static int hf_iperf2_usec;
static int hf_iperf2_timestamp;
static int hf_iperf2_sequence_upper;
static int hf_iperf2_flags;
static int hf_iperf2_num_threads;
static int hf_iperf2_mport;
static int hf_iperf2_bufferlen;
static int hf_iperf2_mwinband;
static int hf_iperf2_mamount;
static int hf_iperf2_type;
static int hf_iperf2_length;
static int hf_iperf2_up_flags;
static int hf_iperf2_low_flags;
static int hf_iperf2_version_major;
static int hf_iperf2_version_minor;
static int hf_iperf2_version;
static int hf_iperf2_reserved;
static int hf_iperf2_tos;
static int hf_iperf2_rate;
static int hf_iperf2_rate_units;
static int hf_iperf2_realtime;
static int hf_iperf2_permit_key_len;
static int hf_iperf2_permit_key;
static int hf_iperf2_isoch_burst_period;
static int hf_iperf2_isoch_start_ts_s;
static int hf_iperf2_isoch_start_ts_us;
static int hf_iperf2_isoch_start_ts;
static int hf_iperf2_isoch_prev_frameid;
static int hf_iperf2_isoch_frameid;
static int hf_iperf2_isoch_burstsize;
static int hf_iperf2_isoch_bytes_remaining;
static int hf_iperf2_isoch_reserved;
static int hf_iperf2_reserved2;
static int hf_iperf2_start_tv_sec;
static int hf_iperf2_start_tv_usec;
static int hf_iperf2_start_tv;
static int hf_iperf2_fq_ratel;
static int hf_iperf2_fq_rateu;
static int hf_iperf2_fpsl;
static int hf_iperf2_fpsu;
static int hf_iperf2_meanl;
static int hf_iperf2_meanu;
static int hf_iperf2_variancel;
static int hf_iperf2_varianceu;
static int hf_iperf2_burstipgl;
static int hf_iperf2_burstipg;
static int hf_iperf2_cca_len;
static int hf_iperf2_cca_value;
static int hf_iperf2_bb_size;
static int hf_iperf2_bb_id;
static int hf_iperf2_bb_flags;
static int hf_iperf2_bb_tos;
static int hf_iperf2_bb_run_time;
static int hf_iperf2_bb_clienttx_ts_sec;
static int hf_iperf2_bb_clienttx_ts_usec;
static int hf_iperf2_bb_clienttx_ts;
static int hf_iperf2_bb_serverrx_ts_sec;
static int hf_iperf2_bb_serverrx_ts_usec;
static int hf_iperf2_bb_serverrx_ts;
static int hf_iperf2_bb_servertx_ts_sec;
static int hf_iperf2_bb_servertx_ts_usec;
static int hf_iperf2_bb_servertx_ts;
static int hf_iperf2_bb_hold;
static int hf_iperf2_bb_rtt;
static int hf_iperf2_bb_read_ts_sec;
static int hf_iperf2_bb_read_ts_usec;
static int hf_iperf2_bb_read_ts;
static int hf_iperf2_bb_reply_size;

// Flags definition for hf_iperf2_flags. See include/Listener.hpp in iperf2 source code
#define HEADER_VERSION1      0x80000000
#define HEADER_EXTEND        0x40000000
#define HEADER_UDPTESTS      0x20000000
#define HEADER_SEQNO64B      0x08000000
#define HEADER_VERSION2      0x04000000
#define HEADER_V2PEERDETECT  0x02000000
#define HEADER_UDPAVOID2     0x02000000
#define HEADER_UDPAVOID1     0x01000000
#define HEADER_BOUNCEBACK    0x00800000
#define HEADER32_SMALL_TRIPTIMES 0x00020000
#define HEADER_LEN_BIT       0x00010000
#define HEADER_LEN_MASK      0x000001FE
#define RUN_NOW              0x00000001
#define HEADER16_SMALL_TRIPTIMES 0x00020000

#define HEADER_ISOCH          0x0001
#define HEADER_L2ETHPIPV6     0x0002
#define HEADER_L2LENCHECK     0x0004
#define HEADER_NOUDPFIN       0x0008
#define HEADER_TRIPTIME       0x0010
#define HEADER_UNUSED2        0x0020
#define HEADER_ISOCH_SETTINGS 0x0040
#define HEADER_UNITS_PPS      0x0080
#define HEADER_BWSET          0x0100
#define HEADER_FQRATESET      0x0200
#define HEADER_REVERSE        0x0400
#define HEADER_FULLDUPLEX     0x0800
#define HEADER_EPOCH_START    0x1000
#define HEADER_PERIODICBURST  0x2000
#define HEADER_WRITEPREFETCH  0x4000
#define HEADER_TCPQUICKACK    0x8000
// Bounceback flags
#define HEADER_BBQUICKACK    0x8000
#define HEADER_BBCLOCKSYNCED 0x4000
#define HEADER_BBTOS         0x2000
#define HEADER_BBSTOP        0x1000
#define HEADER_BBREPLYSIZE   0x0800

// lower flags (16 bit)
#define HEADER_CCA          0x8000

// Flags fields declarations for hf_iperf2_flags
static int hf_iperf2_flag_header_version1;
static int hf_iperf2_flag_header_extend;
static int hf_iperf2_header_udptests;
static int hf_iperf2_header_seqno64b;
static int hf_iperf2_header_version2;
static int hf_iperf2_header_v2peerdetect;
static int hf_iperf2_header_udpavoid;
static int hf_iperf2_header_bounceback;
static int hf_iperf2_header_len_bit;
static int hf_iperf2_header_len_mask;
static int hf_iperf2_run_now;
static int hf_iperf2_header16_small_triptimes;
static int hf_iperf2_payload;

static int * const iperf2_flags[] = {
    &hf_iperf2_flag_header_version1,
    &hf_iperf2_flag_header_extend,
    &hf_iperf2_header_udptests,
    &hf_iperf2_header_seqno64b,
    &hf_iperf2_header_version2,
    &hf_iperf2_header_v2peerdetect,
    &hf_iperf2_header_udpavoid,
    &hf_iperf2_header_bounceback,
    &hf_iperf2_header_len_mask,
    &hf_iperf2_header16_small_triptimes,
    &hf_iperf2_header_len_bit,
    &hf_iperf2_run_now,
    NULL
};

// Flags fields declarations for iperf2_upper_flags
static int hf_iperf2_upper_header_isoch;
static int hf_iperf2_upper_header_l2ethpipv6;
static int hf_iperf2_upper_header_l2lencheck;
static int hf_iperf2_upper_header_noudpfin;
static int hf_iperf2_upper_header_triptime;
static int hf_iperf2_upper_header_unused2;
static int hf_iperf2_upper_header_isoch_settings;
static int hf_iperf2_upper_header_units_pps;
static int hf_iperf2_upper_header_bwset;
static int hf_iperf2_upper_header_fqrateset;
static int hf_iperf2_upper_header_reverse;
static int hf_iperf2_upper_header_fullduplex;
static int hf_iperf2_upper_header_epoch_start;
static int hf_iperf2_upper_header_periodicburst;
static int hf_iperf2_upper_header_writeprefetch;
static int hf_iperf2_upper_header_tcpquickack;

static int * const iperf2_upper_flags[] = {
    &hf_iperf2_upper_header_tcpquickack,
    &hf_iperf2_upper_header_writeprefetch,
    &hf_iperf2_upper_header_periodicburst,
    &hf_iperf2_upper_header_epoch_start,
    &hf_iperf2_upper_header_fullduplex,
    &hf_iperf2_upper_header_reverse,
    &hf_iperf2_upper_header_fqrateset,
    &hf_iperf2_upper_header_bwset,
    &hf_iperf2_upper_header_units_pps,
    &hf_iperf2_upper_header_isoch_settings,
    &hf_iperf2_upper_header_unused2,
    &hf_iperf2_upper_header_triptime,
    &hf_iperf2_upper_header_noudpfin,
    &hf_iperf2_upper_header_l2lencheck,
    &hf_iperf2_upper_header_l2ethpipv6,
    &hf_iperf2_upper_header_isoch,
    NULL
};

// Flags fields declarations for iperf2_lower_flags
static int hf_iperf2_lower_header_cca;

static int * const iperf2_lower_flags[] = {
    &hf_iperf2_lower_header_cca,
    NULL
};

// Flags fields declarations for iperf2_bb_flags
static int hf_iperf2_header_bbquickack;
static int hf_iperf2_header_bbclocksynced;
static int hf_iperf2_header_bbtos;
static int hf_iperf2_header_bbstop;
static int hf_iperf2_header_bbreplysize;

static int * const iperf2_bb_flags[] = {
    &hf_iperf2_header_bbquickack,
    &hf_iperf2_header_bbclocksynced,
    &hf_iperf2_header_bbtos,
    &hf_iperf2_header_bbstop,
    &hf_iperf2_header_bbreplysize,
    NULL
};

static int ett_iperf2_udp;
static int ett_iperf2_tcp;
static int ett_udphdr;
static int ett_clienthdr;
static int ett_bbhdr;
static int ett_extendedhdr;
static int ett_permit_key;
static int ett_client_upper_flags;
static int ett_client_lower_flags;
static int ett_isochhdr;
static int ett_fqhdr;
static int ett_ext_isochhdr;
static int ett_client_hdr;
static int ett_client_hdr_flags;
static int ett_cca_hdr;
static int ett_bb_hdr_flags;
static int ett_bbclienttx_ts;
static int ett_bbserverrx_ts;
static int ett_bbservertx_ts;
static int ett_bbread_ts;
static int ett_data;

/* parser definitions for iperf2 payload */
static tvbparse_wanted_t *want;
static tvbparse_wanted_t *want_trailing;

static dissector_handle_t iperf2_handle_tcp;
static dissector_handle_t iperf2_handle_udp;

typedef struct {
    bool first_packet_processed;
    bool second_packet_processed;
} iperf2_conversation_t;

static void
format_version(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%d.%d", (value & 0xFFFF0000) >> 16, (value & 0xFFFF));
}

static void
format_version_long(char *buf, uint64_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%d.%d.%d.%d",
            (uint32_t)((value & 0xFFFF000000000000) >> 48), (uint32_t)((value & 0xFFFF00000000) >> 32),
            (uint32_t)((value & 0xFFFF0000) >> 16), (uint32_t)(value & 0xFFFF));
}

static int
dissect_iperf2_payload(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    proto_tree *data_tree;

    data_tree = proto_tree_add_subtree(tree, tvb, offset, tvb_reported_length(tvb) - offset, ett_data, NULL, "iPerf2 Payload");
    proto_tree_add_item(data_tree, hf_iperf2_payload, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
    offset = tvb_reported_length(tvb);

    return offset;
}

static int
dissect_iperf2_client_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset, bool is_udp)
{
    uint32_t small_packets = 0;
    uint32_t initial_offset = offset;
    int client_header_size = 24;
    proto_tree *client_tree;

    if (is_udp) {
        small_packets = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
        if (small_packets & HEADER32_SMALL_TRIPTIMES) {
            client_header_size = 4;
        }
    }

    client_tree = proto_tree_add_subtree(tree, tvb, offset, client_header_size, ett_clienthdr, NULL, "iPerf2 Client Header");
    proto_tree_add_bitmask(client_tree, tvb, offset, hf_iperf2_flags, ett_client_hdr_flags, iperf2_flags, ENC_BIG_ENDIAN);
    offset += 4;

    if (is_udp) {
        if (small_packets & HEADER32_SMALL_TRIPTIMES) {
            if ((tvb_reported_length(tvb) - offset) > 0) {
                return dissect_iperf2_payload(tvb, tree, offset);
            } else {
                return offset - initial_offset;
            }
        }
    }

    proto_tree_add_item(client_tree, hf_iperf2_num_threads, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_mport, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_bufferlen, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_mwinband, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_mamount, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset - initial_offset;
}

static int
dissect_iperf2_extended_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    uint32_t initial_offset = offset, permit_key_len = 0;
    proto_tree *extended_tree, *permit_key_tree;
    proto_item *ti;

    extended_tree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_extendedhdr, NULL, "iPerf2 Extended Header");
    proto_tree_add_item(extended_tree, hf_iperf2_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(extended_tree, hf_iperf2_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(extended_tree, tvb, offset, hf_iperf2_up_flags, ett_client_upper_flags, iperf2_upper_flags, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(extended_tree, tvb, offset, hf_iperf2_low_flags, ett_client_lower_flags, iperf2_lower_flags, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(extended_tree, hf_iperf2_version_major, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(extended_tree, hf_iperf2_version_minor, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    ti = proto_tree_add_item(extended_tree, hf_iperf2_version, tvb, offset - 8, 8, ENC_BIG_ENDIAN);
    proto_item_set_generated(ti);
    proto_tree_add_item(extended_tree, hf_iperf2_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(extended_tree, hf_iperf2_tos, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(extended_tree, hf_iperf2_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(extended_tree, hf_iperf2_rate_units, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(extended_tree, hf_iperf2_realtime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    // There may be an optional permit key at the end of this header. Flags are not reliable - do some heuristics here instead.
    if (tvb_reported_length(tvb) - offset >= 2) {
        permit_key_len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        if ((permit_key_len != 0) && (permit_key_len <= (tvb_reported_length(tvb) - offset - 2))) {
            permit_key_tree = proto_tree_add_subtree(tree, tvb, offset, permit_key_len + 2, ett_permit_key, NULL, "iPerf2 Permit Key");
            proto_tree_add_item(permit_key_tree, hf_iperf2_permit_key_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(permit_key_tree, hf_iperf2_permit_key, tvb, offset, permit_key_len, ENC_ASCII);
            offset += permit_key_len;
        }
    }
    return offset - initial_offset;
}

static int
dissect_iperf2_isoch_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    uint32_t initial_offset = offset;
    proto_tree *ext_isoch_tree;

    ext_isoch_tree = proto_tree_add_subtree(tree, tvb, offset, 32, ett_ext_isochhdr, NULL, "iPerf2 Extended Isochronous Header");
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_fpsl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_fpsu, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_meanl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_meanu, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_variancel, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_varianceu, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_burstipgl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_isoch_tree, hf_iperf2_burstipg, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset - initial_offset;
}

static int
dissect_iperf2_isoch_payload_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    proto_item *ti;
    uint32_t initial_offset = offset;
    proto_tree *isoch_tree;
    nstime_t isoch_timestamp;
    unsigned isoch_ts_sec = 0;
    unsigned isoch_ts_usec = 0;

    isoch_tree = proto_tree_add_subtree(tree, tvb, offset, 32, ett_isochhdr, NULL, "iPerf2 Isochronous Header");
    proto_tree_add_item(isoch_tree, hf_iperf2_isoch_burst_period, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(isoch_tree, hf_iperf2_isoch_start_ts_s, tvb, offset, 4, ENC_BIG_ENDIAN, &isoch_ts_sec);
    offset += 4;
    proto_tree_add_item_ret_uint(isoch_tree, hf_iperf2_isoch_start_ts_us, tvb, offset, 4, ENC_BIG_ENDIAN, &isoch_ts_usec);
    offset += 4;
    isoch_timestamp.secs  = (time_t)isoch_ts_sec;
    isoch_timestamp.nsecs = (int)isoch_ts_usec * 1000;
    ti = proto_tree_add_time(isoch_tree, hf_iperf2_isoch_start_ts, tvb, offset - 8, 8, &isoch_timestamp);
    proto_item_set_generated(ti);
    proto_tree_add_item(isoch_tree, hf_iperf2_isoch_prev_frameid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(isoch_tree, hf_iperf2_isoch_frameid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(isoch_tree, hf_iperf2_isoch_burstsize, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(isoch_tree, hf_iperf2_isoch_bytes_remaining, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(isoch_tree, hf_iperf2_isoch_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset - initial_offset;
}

static int
dissect_iperf2_fq_start_time_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    proto_item *ti;
    uint32_t initial_offset = offset;
    proto_tree *fq_tree;
    unsigned fq_ts_sec = 0;
    unsigned fq_ts_usec = 0;
    nstime_t fq_timestamp;

    fq_tree = proto_tree_add_subtree(tree, tvb, offset, 20, ett_fqhdr, NULL, "iPerf2 Fair Queue Start Time Header");
    proto_tree_add_item(fq_tree, hf_iperf2_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(fq_tree, hf_iperf2_start_tv_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &fq_ts_sec);
    offset += 4;
    proto_tree_add_item_ret_uint(fq_tree, hf_iperf2_start_tv_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &fq_ts_usec);
    offset += 4;
    fq_timestamp.secs  = (time_t)fq_ts_sec;
    fq_timestamp.nsecs = (int)fq_ts_usec * 1000;
    ti = proto_tree_add_time(fq_tree, hf_iperf2_start_tv, tvb, offset - 8, 8, &fq_timestamp);
    proto_item_set_generated(ti);
    proto_tree_add_item(fq_tree, hf_iperf2_fq_ratel, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(fq_tree, hf_iperf2_fq_rateu, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset - initial_offset;
}

static int
dissect_iperf2_cca_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    uint32_t initial_offset = offset;
    unsigned cca_payload_len;
    proto_tree *cca_tree;

    cca_payload_len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    cca_tree = proto_tree_add_subtree(tree, tvb, offset, cca_payload_len + 2, ett_cca_hdr, NULL, "iPerf2 CCA Header");
    proto_tree_add_item(cca_tree, hf_iperf2_cca_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(cca_tree, hf_iperf2_cca_value, tvb, offset, cca_payload_len, ENC_ASCII);
    offset += cca_payload_len;

    return offset - initial_offset;
}

static int
dissect_iperf2_bounceback_header(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    proto_tree *bb_tree, *bb_tree_clienttx_ts, *bb_tree_serverrx_ts, *bb_tree_servertx_ts, *bb_tree_read_ts;
    proto_item *ti;
    unsigned ts_sec = 0, ts_usec = 0;
    nstime_t clienttx_ts, serverrx_ts, servertx_ts, read_ts;

    bb_tree = proto_tree_add_subtree(tree, tvb, offset, 64, ett_bbhdr, NULL, "iPerf2 Bounceback Header");
    proto_tree_add_bitmask(bb_tree, tvb, offset, hf_iperf2_flags, ett_client_hdr_flags, iperf2_flags, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(bb_tree, hf_iperf2_bb_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(bb_tree, hf_iperf2_bb_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(bb_tree, tvb, offset, hf_iperf2_bb_flags, ett_bb_hdr_flags, iperf2_bb_flags, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(bb_tree, hf_iperf2_bb_tos, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    unsigned bb_run_time = 0;
    ti = proto_tree_add_item_ret_uint(bb_tree, hf_iperf2_bb_run_time, tvb, offset, 4, ENC_BIG_ENDIAN, &bb_run_time);
    proto_item_append_text(ti, "%d ms", bb_run_time * 10);
    offset += 4;

    bb_tree_clienttx_ts = proto_tree_add_subtree(bb_tree, tvb, offset, 8, ett_bbclienttx_ts, NULL, "Client Tx Timestamp");
    proto_tree_add_item_ret_uint(bb_tree_clienttx_ts, hf_iperf2_bb_clienttx_ts_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_sec);
    offset += 4;
    proto_tree_add_item_ret_uint(bb_tree_clienttx_ts, hf_iperf2_bb_clienttx_ts_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_usec);
    offset += 4;
    clienttx_ts.secs  = (time_t)ts_sec;
    clienttx_ts.nsecs = (int)ts_usec * 1000;
    ti = proto_tree_add_time(bb_tree_clienttx_ts, hf_iperf2_bb_clienttx_ts, tvb, offset - 8, 8, &clienttx_ts);
    proto_item_set_generated(ti);

    bb_tree_serverrx_ts = proto_tree_add_subtree(bb_tree, tvb, offset, 8, ett_bbserverrx_ts, NULL, "Server Rx Timestamp");
    proto_tree_add_item_ret_uint(bb_tree_serverrx_ts, hf_iperf2_bb_serverrx_ts_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_sec);
    offset += 4;
    proto_tree_add_item_ret_uint(bb_tree_serverrx_ts, hf_iperf2_bb_serverrx_ts_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_usec);
    offset += 4;
    serverrx_ts.secs  = (time_t)ts_sec;
    serverrx_ts.nsecs = (int)ts_usec * 1000;
    ti = proto_tree_add_time(bb_tree_serverrx_ts, hf_iperf2_bb_serverrx_ts, tvb, offset - 8, 8, &serverrx_ts);
    proto_item_set_generated(ti);

    bb_tree_servertx_ts = proto_tree_add_subtree(bb_tree, tvb, offset, 8, ett_bbservertx_ts, NULL, "Server Tx Timestamp");
    proto_tree_add_item_ret_uint(bb_tree_servertx_ts, hf_iperf2_bb_servertx_ts_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_sec);
    offset += 4;
    proto_tree_add_item_ret_uint(bb_tree_servertx_ts, hf_iperf2_bb_servertx_ts_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_usec);
    offset += 4;
    servertx_ts.secs  = (time_t)ts_sec;
    servertx_ts.nsecs = (int)ts_usec * 1000;
    ti = proto_tree_add_time(bb_tree_servertx_ts, hf_iperf2_bb_servertx_ts, tvb, offset - 8, 8, &servertx_ts);
    proto_item_set_generated(ti);

    proto_tree_add_item(bb_tree, hf_iperf2_bb_hold, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(bb_tree, hf_iperf2_bb_rtt, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    bb_tree_read_ts = proto_tree_add_subtree(bb_tree, tvb, offset, 8, ett_bbread_ts, NULL, "Read Timestamp");
    proto_tree_add_item_ret_uint(bb_tree_read_ts, hf_iperf2_bb_read_ts_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_sec);
    offset += 4;
    proto_tree_add_item_ret_uint(bb_tree_read_ts, hf_iperf2_bb_read_ts_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_usec);
    offset += 4;
    read_ts.secs  = (time_t)ts_sec;
    read_ts.nsecs = (int)ts_usec * 1000;
    ti = proto_tree_add_time(bb_tree_read_ts, hf_iperf2_bb_read_ts, tvb, offset - 8, 8, &read_ts);
    proto_item_set_generated(ti);

    proto_tree_add_item(bb_tree, hf_iperf2_bb_reply_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}

static int
dissect_iperf2_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_item *ti = NULL;
    proto_tree *iperf2_tree = NULL;
    uint32_t offset = 0, flags = 0, upper_flags = 0, lower_flags = 0, pdu_len = 24;
    uint16_t cca_len;
    tvbparse_t *tt;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iPerf2");
    col_clear(pinfo->cinfo, COL_INFO);

    // Is it the TCP first write with test information
    if ((tvb_reported_length(tvb) - offset) < pdu_len) { // We don't have enough data to decode the header
        offset += tvb_reported_length(tvb);
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = pdu_len - offset;
        return tvb_reported_length(tvb);
    }

    flags = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, proto_iperf2, tvb, offset, pdu_len, ENC_NA);
    iperf2_tree = proto_item_add_subtree(ti, ett_iperf2_tcp);

    // Check if we got iPerf2 payload
    // First, check if the first 10 bytes look like payload
    tt = tvbparse_init(pinfo->pool, tvb, offset, 10, NULL, NULL);
    if (tvbparse_get(tt, want)) { // Okay, the first 10 bytes follow the pattern, continue...
        tvbparse_reset(tt, offset + 10, tvb_reported_length(tvb) - 10);
        while(tvbparse_curr_offset(tt) < tvb_reported_length(tvb)) {
            if(tvbparse_get(tt, want) == NULL)
                break;
	    }
        // Special case for the trailing payload bytes less than 10 bytes of length
        if ((tvb_reported_length(tvb) - tvbparse_curr_offset(tt)) <= 10) {
            tvbparse_get(tt, want_trailing);
        }
        if (tvbparse_curr_offset(tt) == tvb_reported_length(tvb)) {
            col_set_str(pinfo->cinfo, COL_INFO, "Payload only");
            offset += dissect_iperf2_payload(tvb, iperf2_tree, offset);
            proto_item_set_len(ti, tvb_reported_length(tvb));
            return offset;
        }
    }
    /* Here we try to understand what extra headers are present. The options are:
    - client_hdrext (36 bytes)
        - may contain permitKey (up to 130 bytes)
    - client_hdrext_starttime_fq (20 bytes)
    - client_hdrext_isoch_settings (40 bytes)
    - cca_field (34 bytes)
    - Combinations of the above
    - OR a bounnceback header (64 bytes in total)

    We do two pass analysis to avoid code duplication:
    - First, we collect the total headers length
    - Second, we confirm that TCP buffer provided enough bytes to decode all headers
    - If needed, stop decoding and ask TCP for more data */
    for (int pass = 1; pass <= 2; pass++) {
        if (flags & HEADER_BOUNCEBACK) {
            (pass == 1) ? (pdu_len = 64) : (offset += dissect_iperf2_bounceback_header(tvb, iperf2_tree, offset));
            col_set_str(pinfo->cinfo, COL_INFO, "Bounceback");
        } else {
            if (pass == 2)
                offset += dissect_iperf2_client_header(tvb, iperf2_tree, offset, false);
            if (flags & HEADER_EXTEND) {
                if (pass == 1)
                    pdu_len += 36;
                else {
                    upper_flags = tvb_get_uint16(tvb, offset + 8, ENC_BIG_ENDIAN);
                    lower_flags = tvb_get_uint16(tvb, offset + 10, ENC_BIG_ENDIAN);
                    offset += dissect_iperf2_extended_header(tvb, iperf2_tree, offset);
                }
            }
            // If CCA header is present, the the previous two headers are also present, though the flags may not be set
            if (lower_flags & HEADER_CCA) {
                if (pass == 1) {
                    cca_len = tvb_get_uint16(tvb, offset + 20 + 40, ENC_BIG_ENDIAN) + 2;
                    pdu_len += 20 + 40 + cca_len;
                }
                else {
                    offset += dissect_iperf2_fq_start_time_header(tvb, iperf2_tree, offset);
                    offset += dissect_iperf2_isoch_header(tvb, iperf2_tree, offset);
                    offset += dissect_iperf2_cca_header(tvb, iperf2_tree, offset);
                }
            } else {
                if (upper_flags & HEADER_TRIPTIME || upper_flags & HEADER_FQRATESET ||
                    upper_flags & HEADER_ISOCH_SETTINGS || upper_flags & HEADER_EPOCH_START) {
                    (pass == 1) ? (pdu_len += 20) : (offset += dissect_iperf2_fq_start_time_header(tvb, iperf2_tree, offset));
                }
                if (upper_flags & HEADER_FULLDUPLEX || upper_flags & HEADER_REVERSE || upper_flags & HEADER_PERIODICBURST) {
                    (pass == 1) ? (pdu_len += 40) : (offset += dissect_iperf2_isoch_header(tvb, iperf2_tree, offset));
                }
            }
        }
        if ((pass == 1) && (tvb_reported_length(tvb) - offset) < pdu_len) { // We don't have enough data to decode all headers
            offset += tvb_reported_length(tvb);
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = pdu_len - offset;
            proto_item_set_len(ti, tvb_reported_length(tvb));
            return tvb_reported_length(tvb);
        }
    }
    if ((tvb_reported_length(tvb) - offset) > 0) {
        offset += dissect_iperf2_payload(tvb, iperf2_tree, offset);
    }
    proto_item_set_len(ti, offset);
    return offset;
}

static int
dissect_iperf2_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    uint32_t offset = 0;
    uint32_t ext_header = 0;
    proto_item *ti;
    proto_tree *iperf2_tree, *udp_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iPerf2");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_iperf2, tvb, offset, IPERF2_UDP_HDR_SIZE, ENC_NA);
    iperf2_tree = proto_item_add_subtree(ti, ett_iperf2_udp);

    udp_tree = proto_tree_add_subtree(iperf2_tree, tvb, offset, 16, ett_udphdr, NULL, "iPerf2 UDP Header");
    proto_tree_add_item(udp_tree, hf_iperf2_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    unsigned ts_sec = 0;
    proto_tree_add_item_ret_uint(udp_tree, hf_iperf2_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_sec);
    offset += 4;
    unsigned ts_usec = 0;
    proto_tree_add_item_ret_uint(udp_tree, hf_iperf2_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &ts_usec);
    offset += 4;
    nstime_t timestamp;
    timestamp.secs  = (time_t)ts_sec;
    timestamp.nsecs = (int)ts_usec * 1000;
    ti = proto_tree_add_time(udp_tree, hf_iperf2_timestamp, tvb, offset - 8, 8, &timestamp);
    proto_item_set_generated(ti);
    proto_tree_add_item(udp_tree, hf_iperf2_sequence_upper, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    ext_header = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);

    offset += dissect_iperf2_client_header(tvb, iperf2_tree, offset, true);

    if (tvb_reported_length(tvb) == offset) {
        return offset;
    }
    //Check is Extended header flag is set, if it's not - do no add more subheaders
    if (!(ext_header & HEADER_EXTEND)) {
        return dissect_iperf2_payload(tvb, iperf2_tree, offset);
    }

    offset += dissect_iperf2_extended_header(tvb, iperf2_tree, offset);

    offset += dissect_iperf2_isoch_payload_header(tvb, iperf2_tree, offset);

    offset += dissect_iperf2_fq_start_time_header(tvb, iperf2_tree, offset);

    offset += dissect_iperf2_isoch_header(tvb, iperf2_tree, offset);

    if ((tvb_reported_length(tvb) - offset) > 0) {
        return dissect_iperf2_payload(tvb, iperf2_tree, offset);
    } else {
        return offset;
    }
}

void
proto_register_iperf2(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_iperf2_sequence,
            { "Sequence Number", "iperf2.udp.sequence", FT_INT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_sec,
            { "Start Time (sec)", "iperf2.udp.sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_usec,
            { "Start Time (usec)", "iperf2.udp.usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_timestamp,
            { "Start Time", "iperf2.udp.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_sequence_upper,
            { "Upper Sequence Number", "iperf2.udp.sequence_upper", FT_INT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_flags,
            { "Flags", "iperf2.client.flags", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_flag_header_version1,
            { "Header Valid", "iperf2.client.flags_version1", FT_BOOLEAN, 32,
            NULL, HEADER_VERSION1, NULL, HFILL }
        },
        { &hf_iperf2_flag_header_extend,
            { "Extended Version", "iperf2.client.flags_extend", FT_BOOLEAN, 32,
            NULL, HEADER_EXTEND, NULL, HFILL }
        },
        { &hf_iperf2_header_udptests,
            { "UDP Tests", "iperf2.client.flags_udp_tests", FT_BOOLEAN, 32,
            NULL, HEADER_UDPTESTS, NULL, HFILL }
        },
        { &hf_iperf2_header_seqno64b,
            { "64 Bit Seq Num", "iperf2.client.flags_seqno64b", FT_BOOLEAN, 32,
            NULL, HEADER_SEQNO64B, "64-bits sequence numbers are used", HFILL }
        },
        { &hf_iperf2_header_version2,
            { "Version 2", "iperf2.client.flags_version2", FT_BOOLEAN, 32,
            NULL, HEADER_VERSION2, NULL, HFILL }
        },
        { &hf_iperf2_header_v2peerdetect,
            { "Version 2 Peer Detect", "iperf2.client.flags_version2_peerdetect", FT_BOOLEAN, 32,
            NULL, HEADER_V2PEERDETECT, NULL, HFILL }
        },
        { &hf_iperf2_header_udpavoid,
            { "Don't use for UDP", "iperf2.client.flags_udpavoid", FT_BOOLEAN, 32,
            NULL, HEADER_UDPAVOID1, "Don't use these bits for UDP", HFILL }
        },
        { &hf_iperf2_header_bounceback,
            { "Bounceback", "iperf2.client.flags_bounceback", FT_BOOLEAN, 32,
            NULL, HEADER_BOUNCEBACK, NULL, HFILL }
        },
        { &hf_iperf2_header_len_bit,
            { "Length Bit", "iperf2.client.flags_len_bit", FT_BOOLEAN, 32,
            NULL, HEADER_LEN_BIT, NULL, HFILL }
        },
        { &hf_iperf2_header_len_mask,
            { "Length Mask", "iperf2.client.flags_len_mask", FT_UINT32, BASE_HEX,
            NULL, HEADER_LEN_MASK, NULL, HFILL }
        },
        { &hf_iperf2_run_now,
            { "Run Now", "iperf2.client.flags_run_now", FT_BOOLEAN, 32,
            NULL, RUN_NOW, NULL, HFILL }
        },
        { &hf_iperf2_header16_small_triptimes,
            { "Small Triptimes", "iperf2.client.flags_small_triptimes", FT_BOOLEAN, 32,
            NULL, HEADER16_SMALL_TRIPTIMES, "Don't decode other fields in this packet", HFILL }
        },
        { &hf_iperf2_num_threads,
            { "Number of Threads", "iperf2.client.numthreads", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_mport,
            { "Port", "iperf2.client.port", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bufferlen,
            { "Buffer Length", "iperf2.client.bufferlen", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_mwinband,
            { "Bandwidth", "iperf2.client.bandwidth", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_mamount,
            { "Amount (Time or Bytes)", "iperf2.client.num_bytes", FT_INT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_type,
            { "Type", "iperf2.client.type", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_length,
            { "Length", "iperf2.client.length", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_up_flags,
            { "Upper Flags", "iperf2.client.up_flags", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_isoch,
            { "Isochronous Header", "iperf2.client.upper_header_isoch", FT_BOOLEAN, 16,
            NULL, HEADER_ISOCH, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_l2ethpipv6,
            { "L2 ETH IPv6", "iperf2.client.upper_header_l2ethpipv6", FT_BOOLEAN, 16,
            NULL, HEADER_L2ETHPIPV6, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_l2lencheck,
            { "L2 Length Check", "iperf2.client.upper_header_l2lencheck", FT_BOOLEAN, 16,
            NULL, HEADER_L2LENCHECK, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_noudpfin,
            { "No UDP Fin", "iperf2.client.upper_header_noudpfin", FT_BOOLEAN, 16,
            NULL, HEADER_NOUDPFIN, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_triptime,
            { "Trip Time", "iperf2.client.upper_header_triptime", FT_BOOLEAN, 16,
            NULL, HEADER_TRIPTIME, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_unused2,
            { "Unused", "iperf2.client.upper_header_unused2", FT_BOOLEAN, 16,
            NULL, HEADER_UNUSED2, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_isoch_settings,
            { "Isochronous Settings", "iperf2.client.upper_header_isoch_settings", FT_BOOLEAN, 16,
            NULL, HEADER_ISOCH_SETTINGS, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_units_pps,
            { "Units PPS", "iperf2.client.upper_header_units_pps", FT_BOOLEAN, 16,
            NULL, HEADER_UNITS_PPS, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_bwset,
            { "Header BW Set", "iperf2.client.upper_header_bwset", FT_BOOLEAN, 16,
            NULL, HEADER_BWSET, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_fqrateset,
            { "Fair Queue Rate Set", "iperf2.client.upper_header_fqrateset", FT_BOOLEAN, 16,
            NULL, HEADER_FQRATESET, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_reverse,
            { "Reverse", "iperf2.client.upper_header_reverse", FT_BOOLEAN, 16,
            NULL, HEADER_REVERSE, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_fullduplex,
            { "Full Duplex", "iperf2.client.upper_header_fullduplex", FT_BOOLEAN, 16,
            NULL, HEADER_FULLDUPLEX, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_epoch_start,
            { "Epoch Start", "iperf2.client.upper_header_epoch_start", FT_BOOLEAN, 16,
            NULL, HEADER_EPOCH_START, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_periodicburst,
            { "Periodic Burst", "iperf2.client.upper_header_periodicburst", FT_BOOLEAN, 16,
            NULL, HEADER_PERIODICBURST, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_writeprefetch,
            { "Write Prefetch", "iperf2.client.upper_header_writeprefetch", FT_BOOLEAN, 16,
            NULL, HEADER_WRITEPREFETCH, NULL, HFILL }
        },
        { &hf_iperf2_upper_header_tcpquickack,
            { "TCP Quick Ack", "iperf2.client.upper_header_tcpquickack", FT_BOOLEAN, 16,
            NULL, HEADER_TCPQUICKACK, NULL, HFILL }
        },
        { &hf_iperf2_low_flags,
            { "Lower Flags", "iperf2.client.low_flags", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_lower_header_cca,
            { "CCA", "iperf2.client.lower_header_cca", FT_BOOLEAN, 16,
            NULL, HEADER_CCA, NULL, HFILL }
        },
        { &hf_iperf2_version_major,
            { "Major Version", "iperf2.client.version_major", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(format_version), 0, NULL, HFILL }
        },
        { &hf_iperf2_version_minor,
            { "Minor Version", "iperf2.client.version_minor", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(format_version), 0, NULL, HFILL }
        },
        { &hf_iperf2_version,
            { "Iperf2 Version", "iperf2.client.version", FT_UINT64, BASE_CUSTOM,
            CF_FUNC(format_version_long), 0, NULL, HFILL }
        },
        { &hf_iperf2_reserved,
            { "Reserved", "iperf2.client.reserved", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_tos,
            { "TOS", "iperf2.client.tos", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_rate,
            { "Rate", "iperf2.client.rate", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_rate_units,
            { "Rate Units", "iperf2.client.rate_units", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_realtime,
            { "TCP Realtime", "iperf2.client.realtime", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_permit_key_len,
            { "Permit Key Length", "iperf2.client.permit_key_length", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_permit_key,
            { "Permit Key", "iperf2.client.permit_key", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_burst_period,
            { "Burst Period", "iperf2.client.isoch_burst_period", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_start_ts_s,
            { "Start Timestamp (s)", "iperf2.client.isoch_start_ts_s", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_start_ts_us,
            { "Start Timestamp (us)", "iperf2.client.isoch_start_ts_us", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_start_ts,
            { "Start Timestamp", "iperf2.client.isoch_start_ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_prev_frameid,
            { "Previous Frame ID", "iperf2.client.isoch_prev_frameid", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_frameid,
            { "Frame ID", "iperf2.client.isoch_frameid", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_burstsize,
            { "Burst Size", "iperf2.client.isoch_burstsize", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_bytes_remaining,
            { "Bytes Remaining", "iperf2.client.isoch_bytes_remaining", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_isoch_reserved,
            { "Reserved", "iperf2.client.isoch_reserved", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_reserved2,
            { "Reserved", "iperf2.client.reserved2", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_start_tv_sec,
            { "Start TV (s)", "iperf2.client.start_tv_sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_start_tv_usec,
            { "Start TV (us)", "iperf2.client.start_tv_usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_start_tv,
            { "Start TV", "iperf2.client.start_tv", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_fq_ratel,
            { "Fair-Queuing Rate Lower", "iperf2.client.fq_ratel", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_fq_rateu,
            { "Fair-Queuing Rate Upper", "iperf2.client.fq_rateu", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_fpsl,
            { "FPS Lower", "iperf2.client.fpsl", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_fpsu,
            { "FPS Upper", "iperf2.client.fpsu", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_meanl,
            { "Mean Lower", "iperf2.client.meanl", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_meanu,
            { "Mean Upper", "iperf2.client.meanu", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_variancel,
            { "Variance Lower", "iperf2.client.variancel", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_varianceu,
            { "Variance Upper", "iperf2.client.varianceu", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_burstipgl,
            { "Burst Inter-packet Gap Lower", "iperf2.client.burstipgl", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_burstipg,
            { "Burst Inter-packet Gap", "iperf2.client.burstipg", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_cca_len,
            { "CCA Length", "iperf2.client.cca_len", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_cca_value,
            { "CCA Value", "iperf2.client.cca_value", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_size,
            { "Bounceback Size", "iperf2.client.bb_size", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_id,
            { "Bounceback ID", "iperf2.client.bb_id", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_flags,
            { "Bounceback Flags", "iperf2.client.bb_flags", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_header_bbquickack,
            { "Quick Ack", "iperf2.client.bb_flags_quickack", FT_BOOLEAN, 16,
            NULL, HEADER_BBQUICKACK, NULL, HFILL }
        },
        { &hf_iperf2_header_bbclocksynced,
            { "Clock Synced", "iperf2.client.bb_flags_clock_synced", FT_BOOLEAN, 16,
            NULL, HEADER_BBCLOCKSYNCED, NULL, HFILL }
        },
        { &hf_iperf2_header_bbtos,
            { "ToS", "iperf2.client.bb_flags_tos", FT_BOOLEAN, 16,
            NULL, HEADER_BBTOS, NULL, HFILL }
        },
        { &hf_iperf2_header_bbstop,
            { "Stop", "iperf2.client.bb_flags_stop", FT_BOOLEAN, 16,
            NULL, HEADER_BBSTOP, NULL, HFILL }
        },
        { &hf_iperf2_header_bbreplysize,
            { "Reply Size", "iperf2.client.bb_flags_reply_size", FT_BOOLEAN, 16,
            NULL, HEADER_BBREPLYSIZE, NULL, HFILL }
        },
        { &hf_iperf2_bb_tos,
            { "Bounceback ToS", "iperf2.client.bb_tos", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_run_time,
            { "Bounceback Run Time", "iperf2.client.bb_run_time", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_clienttx_ts_sec,
            { "Client TX Timestamp (s)", "iperf2.client.bb_clienttx_ts_sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_clienttx_ts_usec,
            { "Client TX Timestamp (us)", "iperf2.client.bb_clienttx_ts_usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_clienttx_ts,
            { "Client TX Timestamp", "iperf2.client.bb_clienttx_ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_serverrx_ts_sec,
            { "Server RX Timestamp (s)", "iperf2.client.bb_serverrx_ts_sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_serverrx_ts_usec,
            { "Server RX Timestamp (us)", "iperf2.client.bb_serverrx_ts_usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_serverrx_ts,
            { "Server RX Timestamp", "iperf2.client.bb_serverrx_ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_servertx_ts_sec,
            { "Server TX Timestamp (s)", "iperf2.client.bb_servertx_ts_sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_servertx_ts_usec,
            { "Server TX Timestamp (us)", "iperf2.client.bb_servertx_ts_usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_servertx_ts,
            { "Server TX Timestamp", "iperf2.client.bb_servertx_ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_hold,
            { "Bounceback Hold", "iperf2.client.bb_hold", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_rtt,
            { "Bounceback RTT", "iperf2.client.bb_rtt", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_read_ts_sec,
            { "Read Timestamp (s)", "iperf2.client.bb_read_ts_sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_read_ts_usec,
            { "Read Timestamp (us)", "iperf2.client.bb_read_ts_usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_read_ts,
            { "Read Timestamp", "iperf2.client.bb_read_ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bb_reply_size,
            { "Bounceback Reply Size", "iperf2.client.bb_reply_size", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_payload,
            { "Data", "iperf2.client.payload", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_iperf2_udp,
        &ett_iperf2_tcp,
        &ett_udphdr,
        &ett_clienthdr,
        &ett_bbhdr,
        &ett_extendedhdr,
        &ett_permit_key,
        &ett_client_upper_flags,
        &ett_client_lower_flags,
        &ett_isochhdr,
        &ett_fqhdr,
        &ett_ext_isochhdr,
        &ett_client_hdr,
        &ett_client_hdr_flags,
        &ett_cca_hdr,
        &ett_bb_hdr_flags,
        &ett_bbclienttx_ts,
        &ett_bbserverrx_ts,
        &ett_bbservertx_ts,
        &ett_bbread_ts,
        &ett_data
    };

    /* Register the protocol name and description */
    proto_iperf2 = proto_register_protocol("iPerf2 Packet Data", "iPerf2", "iperf2");

    proto_register_field_array(proto_iperf2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Set up string templates for iperf2 payload */
    want = tvbparse_set_oneof(0, NULL, NULL, NULL,
		                        tvbparse_string(-1,"0123456789",NULL,NULL,NULL),
		                        tvbparse_string(-1,"1234567890",NULL,NULL,NULL),
		                        tvbparse_string(-1,"2345678901",NULL,NULL,NULL),
		                        tvbparse_string(-1,"3456789012",NULL,NULL,NULL),
		                        tvbparse_string(-1,"4567890123",NULL,NULL,NULL),
		                        tvbparse_string(-1,"5678901234",NULL,NULL,NULL),
		                        tvbparse_string(-1,"6789012345",NULL,NULL,NULL),
		                        tvbparse_string(-1,"7890123456",NULL,NULL,NULL),
		                        tvbparse_string(-1,"8901234567",NULL,NULL,NULL),
		                        tvbparse_string(-1,"9012345678",NULL,NULL,NULL),
                                NULL);
    want_trailing = tvbparse_chars(-1, 1, 0, "0123456789", NULL, NULL, NULL);

    iperf2_handle_tcp = register_dissector("iperf2_tcp", dissect_iperf2_tcp, proto_iperf2);
    iperf2_handle_udp = register_dissector("iperf2_udp", dissect_iperf2_udp, proto_iperf2);
}

void
proto_reg_handoff_iperf2(void)
{
    dissector_add_for_decode_as_with_preference("tcp.port", iperf2_handle_tcp);
    dissector_add_for_decode_as_with_preference("udp.port", iperf2_handle_udp);
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
