/* packet-bpv7.c
 * Routines for Bundle Protocol Version 7 dissection
 * References:
 *     RFC 9171: https://www.rfc-editor.org/rfc/rfc9171.html
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "config.h"
#define WS_LOG_DOMAIN "packet-bpv7"

#include "packet-bpv7.h"
#include "epan/wscbor.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/reassemble.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/exceptions.h>
#include <epan/ftypes/ftypes.h>
#include <wsutil/crc16.h>
#include <wsutil/crc32.h>
#include <wsutil/utf8_entities.h>
#include <inttypes.h>

void proto_register_bpv7(void);
void proto_reg_handoff_bpv7(void);

/// Protocol column name
static const char *const proto_name_bp = "BPv7";
static const char *const proto_name_bp_admin = "BPv7 Admin";

/// Protocol preferences and defaults
static bool bp_compute_crc = true;
static bool bp_reassemble_payload = true;
static bool bp_payload_try_heur;

/// Protocol handles
static int proto_bp;
static int bp_tap;
static int proto_blocktype;
static int proto_bp_admin;
static int proto_admintype;
/// Protocol-level data
static bp_history_t *bp_history;

static dissector_handle_t handle_admin;
/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor;
static dissector_handle_t handle_cborseq;
/// Extension sub-dissectors
static dissector_table_t block_dissectors;
static dissector_table_t payload_dissectors_dtn_wkssp;
static dissector_table_t payload_dissectors_dtn_serv;
static dissector_table_t payload_dissectors_ipn_serv;
static dissector_table_t admin_dissectors;
/// BTSD heuristic
static heur_dissector_list_t btsd_heur;

/// Fragment reassembly
static reassembly_table bp_reassembly_table;

static const val64_string eid_schemes[] = {
    {EID_SCHEME_DTN, "dtn"},
    {EID_SCHEME_IPN, "ipn"},
    {0, NULL},
};

static const val64_string crc_vals[] = {
    {BP_CRC_NONE, "None"},
    {BP_CRC_16, "CRC-16"},
    {BP_CRC_32, "CRC-32C"},
    {0, NULL},
};

typedef struct {
    /// Type of block
    uint64_t type_code;
    /// Limit on total count
    uint64_t limit;
} blocktype_limit;
/// Block type count limits
static const blocktype_limit blocktype_limits[] = {
    {BP_BLOCKTYPE_PAYLOAD, 1},
    {BP_BLOCKTYPE_PREV_NODE, 1},
    {BP_BLOCKTYPE_BUNDLE_AGE, 1},
    {BP_BLOCKTYPE_HOP_COUNT, 1},
    // Mandatory last row
    {BP_BLOCKTYPE_INVALID, 0},
};

/// Dissection order by block type
static int blocktype_order(const bp_block_canonical_t *block) {
    if (block->type_code) {
        switch (*(block->type_code)) {
            case BP_BLOCKTYPE_BCB:
                return -2;
            case BP_BLOCKTYPE_BIB:
                return -1;
            default:
                return 0;
        }
    }
    return 0;
}

static const val64_string status_report_reason_vals[] = {
    {0, "No additional information"},
    {1, "Lifetime expired"},
    {2, "Forwarded over unidirectional link"},
    {3, "Transmission canceled"},
    {4, "Depleted storage"},
    {5, "Destination endpoint ID unintelligible"},
    {6, "No known route to destination from here"},
    {7, "No timely contact with next node on route"},
    {8, "Block unintelligible"},
    {9, "Hop limit exceeded"},
    {10, "Traffic pared"},
    {11, "Block unsupported"},
    {12, "Missing Security Operation"},
    {13, "Unknown Security Operation"},
    {14, "Unexpected Security Operation"},
    {15, "Failed Security Operation"},
    {16, "Conflicting Security Operation"},
    {0, NULL},
};

enum {
    /// The last bundle in the frame (as a bp_bundle_t*)
    PROTO_DATA_BUNDLE = 1,
};

static int hf_bundle_head;
static int hf_bundle_break;
static int hf_block;

static int hf_crc_type;
static int hf_crc_field_uint16;
static int hf_crc_field_uint32;
static int hf_crc_status;

static int hf_time_dtntime;
static int hf_time_utctime;

static int hf_create_ts_time;
static int hf_create_ts_seqno;

static int hf_eid_scheme;
static int hf_eid_dtn_ssp_code;
static int hf_eid_dtn_ssp_text;
static int hf_eid_ipn_node;
static int hf_eid_ipn_service;
static int hf_eid_dtn_wkssp;
static int hf_eid_dtn_serv;

static int hf_primary_version;
static int hf_primary_bundle_flags;
static int hf_primary_bundle_flags_deletion_report;
static int hf_primary_bundle_flags_delivery_report;
static int hf_primary_bundle_flags_forwarding_report;
static int hf_primary_bundle_flags_reception_report;
static int hf_primary_bundle_flags_req_status_time;
static int hf_primary_bundle_flags_user_app_ack;
static int hf_primary_bundle_flags_no_fragment;
static int hf_primary_bundle_flags_payload_admin;
static int hf_primary_bundle_flags_is_fragment;
static int hf_primary_dst_eid;
static int hf_primary_dst_uri;
static int hf_primary_src_nodeid;
static int hf_primary_src_uri;
static int hf_primary_srcdst_uri;
static int hf_primary_report_nodeid;
static int hf_primary_report_uri;
static int hf_primary_create_ts;
static int hf_primary_lifetime;
static int hf_primary_lifetime_exp;
static int hf_primary_expire_ts;
static int hf_primary_frag_offset;
static int hf_primary_total_length;

static int hf_bundle_ident;
static int hf_bundle_first_seen;
static int hf_bundle_retrans_seen;
static int hf_bundle_seen_time_diff;
static int hf_bundle_dst_dtn_srv;
static int hf_bundle_dst_ipn_srv;
static int hf_bundle_status_ref;

static int hf_canonical_type_code;
static int hf_canonical_block_num;
static int hf_canonical_block_flags;
static int hf_canonical_block_flags_delete_no_process;
static int hf_canonical_block_flags_status_no_process;
static int hf_canonical_block_flags_remove_no_process;
static int hf_canonical_block_flags_replicate_in_fragment;
static int hf_canonical_data_size;
static int hf_canonical_data;

static int hf_previous_node_nodeid;
static int hf_previous_node_uri;
static int hf_bundle_age_time;
static int hf_hop_count_limit;
static int hf_hop_count_current;

static int hf_admin_record_type;
static int hf_status_rep;
static int hf_status_rep_status_info;
static int hf_status_assert_val;
static int hf_status_assert_time;
static int hf_status_rep_received;
static int hf_status_rep_forwarded;
static int hf_status_rep_delivered;
static int hf_status_rep_deleted;
static int hf_status_rep_reason_code;
static int hf_status_rep_subj_src_nodeid;
static int hf_status_rep_subj_src_uri;
static int hf_status_rep_subj_ts;
static int hf_status_rep_subj_frag_offset;
static int hf_status_rep_subj_payload_len;
static int hf_status_rep_subj_ident;
static int hf_status_rep_subj_ref;
static int hf_status_time_diff;

static int hf_payload_fragments;
static int hf_payload_fragment;
static int hf_payload_fragment_overlap;
static int hf_payload_fragment_overlap_conflicts;
static int hf_payload_fragment_multiple_tails;
static int hf_payload_fragment_too_long_fragment;
static int hf_payload_fragment_error;
static int hf_payload_fragment_count;
static int hf_payload_reassembled_in;
static int hf_payload_reassembled_length;
static int hf_payload_reassembled_data;
static int ett_payload_fragment;
static int ett_payload_fragments;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_bundle_head, {"Indefinite Array", "bpv7.bundle_head", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_break, {"Indefinite Break", "bpv7.bundle_break", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_block, {"Block", "bpv7.block", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_crc_type, {"CRC Type", "bpv7.crc_type", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(crc_vals), 0x0, NULL, HFILL}},
    {&hf_crc_field_uint16, {"CRC Field Integer", "bpv7.crc_field", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_crc_field_uint32, {"CRC field Integer", "bpv7.crc_field", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_crc_status, {"CRC Status", "bpv7.crc_status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL}},

    {&hf_time_dtntime, {"DTN Time", "bpv7.time.dtntime", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
    {&hf_time_utctime, {"UTC Time", "bpv7.time.utctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}},

    {&hf_create_ts_time, {"Time", "bpv7.create_ts.time", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_create_ts_seqno, {"Sequence Number", "bpv7.create_ts.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_scheme, {"Scheme Code", "bpv7.eid.scheme", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(eid_schemes), 0x0, NULL, HFILL}},
    {&hf_eid_dtn_ssp_code, {"DTN SSP", "bpv7.eid.dtn_ssp_code", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_dtn_ssp_text, {"DTN SSP", "bpv7.eid.dtn_ssp_text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_ipn_node, {"IPN Node Number", "bpv7.eid.ipn_node", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_ipn_service, {"IPN Service Number", "bpv7.eid.ipn_service", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_dtn_wkssp, {"Well-known SSP", "bpv7.eid.wkssp", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_eid_dtn_serv, {"Service Name", "bpv7.eid.serv", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_primary_version, {"Version", "bpv7.primary.version", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_bundle_flags, {"Bundle Flags", "bpv7.primary.bundle_flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_bundle_flags_is_fragment, {"Bundle is a fragment", "bpv7.primary.bundle_flags.is_fragment", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_IS_FRAGMENT, NULL, HFILL}},
    {&hf_primary_bundle_flags_payload_admin, {"Payload is an administrative record", "bpv7.primary.bundle_flags.payload_admin", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_PAYLOAD_ADMIN, NULL, HFILL}},
    {&hf_primary_bundle_flags_no_fragment, {"Bundle must not be fragmented", "bpv7.primary.bundle_flags.no_fragment", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_NO_FRAGMENT, NULL, HFILL}},
    {&hf_primary_bundle_flags_user_app_ack, {"Acknowledgement by application is requested", "bpv7.primary.bundle_flags.user_app_ack", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_USER_APP_ACK, NULL, HFILL}},
    {&hf_primary_bundle_flags_req_status_time, {"Status time requested in reports", "bpv7.primary.bundle_flags.req_status_time", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_REQ_STATUS_TIME, NULL, HFILL}},
    {&hf_primary_bundle_flags_reception_report, {"Request reporting of bundle reception", "bpv7.primary.bundle_flags.reception_report", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_REQ_RECEPTION_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_forwarding_report, {"Request reporting of bundle forwarding", "bpv7.primary.bundle_flags.forwarding_report", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_REQ_FORWARDING_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_delivery_report, {"Request reporting of bundle delivery", "bpv7.primary.bundle_flags.delivery_report", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_REQ_DELIVERY_REPORT, NULL, HFILL}},
    {&hf_primary_bundle_flags_deletion_report, {"Request reporting of bundle deletion", "bpv7.primary.bundle_flags.deletion_report", FT_BOOLEAN, 24, TFS(&tfs_set_notset), BP_BUNDLE_REQ_DELETION_REPORT, NULL, HFILL}},
    {&hf_primary_dst_eid, {"Destination Endpoint ID", "bpv7.primary.dst_eid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_dst_uri, {"Destination URI", "bpv7.primary.dst_uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_src_nodeid, {"Source Node ID", "bpv7.primary.src_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_src_uri, {"Source URI", "bpv7.primary.src_uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_srcdst_uri, {"Source or Destination URI", "bpv7.primary.srcdst_uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_report_nodeid, {"Report-to Node ID", "bpv7.primary.report_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_report_uri, {"Report-to URI", "bpv7.primary.report_uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_create_ts, {"Creation Timestamp", "bpv7.primary.create_ts", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_lifetime, {"Lifetime", "bpv7.primary.lifetime", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
    {&hf_primary_lifetime_exp, {"Lifetime Expanded", "bpv7.primary.lifetime_exp", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_expire_ts, {"Expire Time", "bpv7.primary.expire_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}},
    {&hf_primary_frag_offset, {"Fragment Offset", "bpv7.primary.frag_offset", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_primary_total_length, {"Total Application Data Unit Length", "bpv7.primary.total_len", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},

    {&hf_bundle_ident, {"Bundle Identity", "bpv7.bundle.identity", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_first_seen, {"First Seen", "bpv7.bundle.first_seen", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0, NULL, HFILL}},
    {&hf_bundle_retrans_seen, {"Retransmit Seen", "bpv7.bundle.retransmit_seen", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_NEXT), 0x0, NULL, HFILL}},
    {&hf_bundle_seen_time_diff, {"Seen Time", "bpv7.bundle.seen_time_diff", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_dst_dtn_srv, {"Destination Service", "bpv7.bundle.dst_dtn_srv", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_bundle_dst_ipn_srv, {"Destination Service", "bpv7.bundle.dst_ipn_srv", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_bundle_status_ref, {"Status Bundle", "bpv7.bundle.status_ref", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_canonical_type_code, {"Type Code", "bpv7.canonical.type_code", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_num, {"Block Number", "bpv7.canonical.block_num", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_flags, {"Block Flags", "bpv7.canonical.block_flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_canonical_block_flags_replicate_in_fragment, {"Replicate block in fragment", "bpv7.canonical.block_flags.replicate_in_fragment", FT_BOOLEAN, 8, TFS(&tfs_set_notset), BP_BLOCK_REPLICATE_IN_FRAGMENT, NULL, HFILL}},
    {&hf_canonical_block_flags_status_no_process, {"Status bundle if not processed", "bpv7.canonical.block_flags.status_if_no_process", FT_BOOLEAN, 8, TFS(&tfs_set_notset), BP_BLOCK_STATUS_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_delete_no_process, {"Delete bundle if not processed", "bpv7.canonical.block_flags.delete_if_no_process", FT_BOOLEAN, 8, TFS(&tfs_set_notset), BP_BLOCK_DELETE_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_block_flags_remove_no_process, {"Discard block if not processed", "bpv7.canonical.block_flags.discard_if_no_process", FT_BOOLEAN, 8, TFS(&tfs_set_notset), BP_BLOCK_REMOVE_IF_NO_PROCESS, NULL, HFILL}},
    {&hf_canonical_data_size, {"Block Type-Specific Data Length", "bpv7.canonical.data_length", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_canonical_data, {"Block Type-Specific Data", "bpv7.canonical.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_payload_fragments,
        {"Payload fragments", "bpv7.payload.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment,
        {"Payload fragment", "bpv7.payload.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment_overlap,
        {"Payload fragment overlap", "bpv7.payload.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment_overlap_conflicts,
        {"Payload fragment overlapping with conflicting data",
        "bpv7.payload.fragment.overlap.conflicts",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment_multiple_tails,
        {"Message has multiple tail fragments",
        "bpv7.payload.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment_too_long_fragment,
        {"Payload fragment too long", "bpv7.payload.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment_error,
        {"Payload defragmentation error", "bpv7.payload.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_fragment_count,
        {"Payload fragment count", "bpv7.payload.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_reassembled_in,
        {"Reassembled in", "bpv7.payload.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_reassembled_length,
        {"Reassembled length", "bpv7.payload.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_payload_reassembled_data,
        {"Reassembled data", "bpv7.payload.reassembled.data",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

    {&hf_previous_node_nodeid, {"Previous Node ID", "bpv7.previous_node.nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_previous_node_uri, {"Previous URI", "bpv7.previous_node.uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_bundle_age_time, {"Bundle Age", "bpv7.bundle_age.time", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},

    {&hf_hop_count_limit, {"Hop Limit", "bpv7.hop_count.limit", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_hop_count_current, {"Hop Count", "bpv7.hop_count.current", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_admin_record_type, {"Record Type Code", "bpv7.admin_rec.type_code", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_status_rep, {"Status Report", "bpv7.status_rep", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_status_info, {"Status Information", "bpv7.status_rep.status_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_assert_val, {"Status Value", "bpv7.status_assert.val", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_assert_time, {"Status at", "bpv7.status_assert.time", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_received, {"Reporting node received bundle", "bpv7.status_rep.received", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_forwarded, {"Reporting node forwarded bundle", "bpv7.status_rep.forwarded", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_delivered, {"Reporting node delivered bundle", "bpv7.status_rep.delivered", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_deleted, {"Reporting node deleted bundle", "bpv7.status_rep.deleted", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_reason_code, {"Reason Code", "bpv7.status_rep.reason_code", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(status_report_reason_vals), 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_src_nodeid, {"Subject Source Node ID", "bpv7.status_rep.subj_src_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_src_uri, {"Subject Source URI", "bpv7.status_rep.subj_src_uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_ts, {"Subject Creation Timestamp", "bpv7.status_rep.subj_ts", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_frag_offset, {"Subject Fragment Offset", "bpv7.status_rep.subj_frag_offset", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_payload_len, {"Subject Payload Length", "bpv7.status_rep.subj_payload_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_ident, {"Subject Identity", "bpv7.status_rep.identity", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_status_rep_subj_ref, {"Subject Bundle", "bpv7.status_rep.subj_ref", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, NULL, HFILL}},
    {&hf_status_time_diff, {"Status Time", "bpv7.status_rep.subj_time_diff", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static int *const bundle_flags[] = {
    &hf_primary_bundle_flags_deletion_report,
    &hf_primary_bundle_flags_delivery_report,
    &hf_primary_bundle_flags_forwarding_report,
    &hf_primary_bundle_flags_reception_report,
    &hf_primary_bundle_flags_req_status_time,
    &hf_primary_bundle_flags_user_app_ack,
    &hf_primary_bundle_flags_no_fragment,
    &hf_primary_bundle_flags_payload_admin,
    &hf_primary_bundle_flags_is_fragment,
    NULL
};

static int *const block_flags[] = {
    &hf_canonical_block_flags_remove_no_process,
    &hf_canonical_block_flags_delete_no_process,
    &hf_canonical_block_flags_status_no_process,
    &hf_canonical_block_flags_replicate_in_fragment,
    NULL
};

static int ett_bundle;
static int ett_bundle_flags;
static int ett_block;
static int ett_eid;
static int ett_time;
static int ett_create_ts;
static int ett_ident;
static int ett_block_flags;
static int ett_canonical_data;
static int ett_payload;
static int ett_admin;
static int ett_status_rep;
static int ett_status_info;
static int ett_status_assert;
/// Tree structures
static int *ett[] = {
    &ett_bundle,
    &ett_bundle_flags,
    &ett_block,
    &ett_eid,
    &ett_time,
    &ett_create_ts,
    &ett_ident,
    &ett_block_flags,
    &ett_canonical_data,
    &ett_payload,
    &ett_admin,
    &ett_status_rep,
    &ett_status_info,
    &ett_status_assert,
    &ett_payload_fragment,
    &ett_payload_fragments,
};

static const fragment_items payload_frag_items = {
    /* Fragment subtrees */
    &ett_payload_fragment,
    &ett_payload_fragments,
    /* Fragment fields */
    &hf_payload_fragments,
    &hf_payload_fragment,
    &hf_payload_fragment_overlap,
    &hf_payload_fragment_overlap_conflicts,
    &hf_payload_fragment_multiple_tails,
    &hf_payload_fragment_too_long_fragment,
    &hf_payload_fragment_error,
    &hf_payload_fragment_count,
    /* Reassembled in field */
    &hf_payload_reassembled_in,
    &hf_payload_reassembled_length,
    &hf_payload_reassembled_data,
    /* Tag */
    "Payload fragments"
};

static expert_field ei_invalid_framing;
static expert_field ei_invalid_bp_version;
static expert_field ei_eid_scheme_unknown;
static expert_field ei_eid_ssp_type_invalid;
static expert_field ei_eid_wkssp_unknown;
static expert_field ei_block_type_dupe;
static expert_field ei_sub_type_unknown;
static expert_field ei_sub_partial_decode;
static expert_field ei_crc_type_unknown;
static expert_field ei_block_failed_crc;
static expert_field ei_block_num_dupe;
static expert_field ei_block_payload_index;
static expert_field ei_block_payload_num;
static expert_field ei_fragment_reassemble_size;
static expert_field ei_fragment_tot_mismatch;
static expert_field ei_block_sec_bib_tgt;
static expert_field ei_block_sec_bcb_tgt;
static ei_register_info expertitems[] = {
    {&ei_invalid_framing, {"bpv7.invalid_framing", PI_MALFORMED, PI_WARN, "Invalid framing", EXPFILL}},
    {&ei_invalid_bp_version, {"bpv7.invalid_bp_version", PI_MALFORMED, PI_ERROR, "Invalid BP version", EXPFILL}},
    {&ei_eid_scheme_unknown, {"bpv7.eid_scheme_unknown", PI_UNDECODED, PI_WARN, "Unknown Node ID scheme code", EXPFILL}},
    {&ei_eid_ssp_type_invalid, {"bpv7.eid_ssp_type_invalid", PI_UNDECODED, PI_WARN, "Invalid scheme-specific part major type", EXPFILL}},
    {&ei_eid_wkssp_unknown, {"bpv7.eid_wkssp_unknown", PI_UNDECODED, PI_WARN, "Unknown well-known scheme-specific code point", EXPFILL}},
    {&ei_block_type_dupe, {"bpv7.block_type_dupe", PI_PROTOCOL, PI_WARN, "Too many blocks of this type", EXPFILL}},
    {&ei_sub_type_unknown, {"bpv7.sub_type_unknown", PI_UNDECODED, PI_WARN, "Unknown type code", EXPFILL}},
    {&ei_sub_partial_decode, {"bpv7.sub_partial_decode", PI_UNDECODED, PI_WARN, "Data not fully dissected", EXPFILL}},
    {&ei_crc_type_unknown, {"bpv7.crc_type_unknown", PI_UNDECODED, PI_WARN, "Unknown CRC Type code", EXPFILL}},
    {&ei_block_failed_crc, {"bpv7.block_failed_crc", PI_CHECKSUM, PI_WARN, "Block failed CRC", EXPFILL}},
    {&ei_block_num_dupe, {"bpv7.block_num_dupe", PI_PROTOCOL, PI_WARN, "Duplicate block number", EXPFILL}},
    {&ei_block_payload_index, {"bpv7.block_payload_index", PI_PROTOCOL, PI_WARN, "Payload must be the last block", EXPFILL}},
    {&ei_block_payload_num, {"bpv7.block_payload_num", PI_PROTOCOL, PI_WARN, "Invalid payload block number", EXPFILL}},
    {&ei_fragment_reassemble_size, {"bpv7.fragment_reassemble_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this size (wireshark limitation)", EXPFILL}},
    {&ei_fragment_tot_mismatch, {"bpv7.fragment_tot_mismatch", PI_REASSEMBLE, PI_ERROR, "Inconsistent total length between fragments", EXPFILL}},
    {&ei_block_sec_bib_tgt, {"bpv7.bpsec.bib_target", PI_COMMENTS_GROUP, PI_COMMENT, "Block is an integrity target", EXPFILL}},
    {&ei_block_sec_bcb_tgt, {"bpv7.bpsec.bcb_target", PI_COMMENTS_GROUP, PI_COMMENT, "Block is a confidentiality target", EXPFILL}},
};

/** Delete an arbitrary object allocated under this file scope.
 *
 * @param ptr The object to delete.
 */
static void file_scope_delete(void *ptr) {
    wmem_free(wmem_file_scope(), ptr);
}

int bp_creation_ts_compare(const void *a, const void *b, void *user_data _U_) {
    const bp_creation_ts_t *ats = a;
    const bp_creation_ts_t *bts = b;
    if (ats->abstime.dtntime < bts->abstime.dtntime) {
        return -1;
    }
    else if (ats->abstime.dtntime > bts->abstime.dtntime) {
        return 1;
    }

    if (ats->seqno < bts->seqno) {
        return -1;
    }
    else if (ats->seqno > bts->seqno) {
        return 1;
    }

    return 0;
}

bp_eid_t * bp_eid_new(wmem_allocator_t *alloc) {
    bp_eid_t *obj = wmem_new0(alloc, bp_eid_t);
    clear_address(&(obj->uri));
    return obj;
}

void bp_eid_free(wmem_allocator_t *alloc, bp_eid_t *obj) {
    wmem_free(alloc, (char *)(obj->dtn_wkssp));
    wmem_free(alloc, (char *)(obj->dtn_serv));
    wmem_free(alloc, (void *)(obj->ipn_serv));
    wmem_free(alloc, obj);
}

bool bp_eid_equal(const void *a, const void *b) {
    const bp_eid_t *aobj = a;
    const bp_eid_t *bobj = b;
    return addresses_equal(&(aobj->uri), &(bobj->uri));
}

bp_block_primary_t * bp_block_primary_new(wmem_allocator_t *alloc) {
    bp_block_primary_t *obj = wmem_new0(alloc, bp_block_primary_t);
    obj->dst_eid = bp_eid_new(alloc);
    obj->src_nodeid = bp_eid_new(alloc);
    obj->rep_nodeid = bp_eid_new(alloc);
    obj->frag_offset = NULL;
    obj->total_len = NULL;
    obj->sec.data_i = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
    obj->sec.data_c = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
    return obj;
}

void bp_block_primary_free(wmem_allocator_t *alloc, bp_block_primary_t *obj) {
    if (!obj) {
        return;
    }
    bp_eid_free(alloc, obj->dst_eid);
    bp_eid_free(alloc, obj->src_nodeid);
    bp_eid_free(alloc, obj->rep_nodeid);
    wmem_free(alloc, obj->frag_offset);
    wmem_free(alloc, obj->total_len);
    wmem_free(alloc, obj->sec.data_i);
    wmem_free(alloc, obj->sec.data_c);
    wmem_free(alloc, obj);
}

bp_block_canonical_t * bp_block_canonical_new(wmem_allocator_t *alloc, uint64_t blk_ix) {
    bp_block_canonical_t *obj = wmem_new0(alloc, bp_block_canonical_t);
    obj->blk_ix = blk_ix;
    obj->sec.data_i = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
    obj->sec.data_c = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
    return obj;
}

static uint64_t * guint64_new(wmem_allocator_t *alloc, const uint64_t val) {
    uint64_t *obj = wmem_new(alloc, uint64_t);
    *obj = val;
    return obj;
}

bp_bundle_t * bp_bundle_new(wmem_allocator_t *alloc) {
    bp_bundle_t *obj = wmem_new0(alloc, bp_bundle_t);
    obj->primary = bp_block_primary_new(alloc);
    obj->blocks = wmem_list_new(alloc);
    obj->block_nums = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
    obj->block_types = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
    return obj;
}

void bp_bundle_free(wmem_allocator_t *alloc, bp_bundle_t *obj) {
    bp_bundle_ident_free(alloc, obj->ident);
    bp_block_primary_free(alloc, obj->primary);
    wmem_destroy_list(obj->blocks);
    wmem_free(alloc, obj);
}

/** Function to match the GCompareFunc signature.
 */
static int bp_bundle_frameloc_compare(const void *a, const void *b) {
  const bp_bundle_t *aobj = a;
  const bp_bundle_t *bobj = b;
  if (aobj->frame_num < bobj->frame_num) {
      return -1;
  }
  if (aobj->frame_num > bobj->frame_num) {
      return 1;
  }
  if (aobj->layer_num < bobj->layer_num) {
      return -1;
  }
  if (aobj->layer_num > bobj->layer_num) {
      return 1;
  }
  return 0;
}

bp_bundle_ident_t * bp_bundle_ident_new(wmem_allocator_t *alloc, const bp_eid_t *src, const bp_creation_ts_t *ts, const uint64_t *off, const uint64_t *len) {
    DISSECTOR_ASSERT(src != NULL);
    DISSECTOR_ASSERT(ts != NULL);
    bp_bundle_ident_t *ident = wmem_new(alloc, bp_bundle_ident_t);
    copy_address_wmem(alloc, &(ident->src), &(src->uri));
    ident->ts = *ts;
    ident->frag_offset = off;
    ident->total_len = len;
    return ident;
}

void bp_bundle_ident_free(wmem_allocator_t *alloc, bp_bundle_ident_t *obj) {
    wmem_free(alloc, obj);
}

/** Either both values are defined and equal or both are null.
 */
static bool optional_uint64_equal(const uint64_t *a, const uint64_t *b) {
    if (a && b) {
        return (*a == *b);
    }
    else {
        return (a == NULL) && (b == NULL);
    }
}

gboolean bp_bundle_ident_equal(const void *a, const void *b) {
    const bp_bundle_ident_t *aobj = a;
    const bp_bundle_ident_t *bobj = b;
    return (
        addresses_equal(&(aobj->src), &(bobj->src))
        && (aobj->ts.abstime.dtntime == bobj->ts.abstime.dtntime)
        && (aobj->ts.seqno == bobj->ts.seqno)
        && optional_uint64_equal(aobj->frag_offset, bobj->frag_offset)
        && optional_uint64_equal(aobj->total_len, bobj->total_len)
    );
}

unsigned bp_bundle_ident_hash(const void *key) {
    const bp_bundle_ident_t *obj = key;
    return (
        add_address_to_hash(0, &(obj->src))
        ^ g_int64_hash(&(obj->ts.abstime.dtntime))
        ^ g_int64_hash(&(obj->ts.seqno))
    );
}

/** Convert DTN time to time delta.
 * DTN Time is defined in Section 4.1.6.
 *
 * @param dtntime Number of milliseconds from an epoch.
 * @return The associated absolute time.
 */
static nstime_t dtn_to_delta(const int64_t dtntime) {
    nstime_t utctime;
    utctime.secs = dtntime / 1000;
    utctime.nsecs = 1000000 * (dtntime % 1000);
    return utctime;
}

/** Convert DTN time to absolute time.
 * DTN Time is defined in Section 4.1.6.
 *
 * @param dtntime Number of milliseconds from an epoch.
 * @return The associated absolute time.
 */
static nstime_t dtn_to_utctime(const int64_t dtntime) {
    nstime_t utctime;
    utctime.secs = 946684800 + dtntime / 1000;
    utctime.nsecs = 1000000 * (dtntime % 1000);
    return utctime;
}

proto_item * proto_tree_add_cbor_eid(proto_tree *tree, int hfindex, int hfindex_uri, packet_info *pinfo, tvbuff_t *tvb, int *offset, bp_eid_t *eid) {
    wmem_allocator_t *alloc_eid = wmem_file_scope();
    proto_item *item_eid = proto_tree_add_item(tree, hfindex, tvb, *offset, -1, ENC_NA);
    proto_tree *tree_eid = proto_item_add_subtree(item_eid, ett_eid);
    const int eid_start = *offset;

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    wscbor_require_array_size(chunk, 2, 2);
    if (!chunk) {
        proto_item_set_len(item_eid, *offset - eid_start);
        return item_eid;
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    const uint64_t *scheme = wscbor_require_uint64(alloc_eid, chunk);
    proto_item *item_scheme = proto_tree_add_cbor_uint64(tree_eid, hf_eid_scheme, pinfo, tvb, chunk, scheme);
    if (!scheme) {
        wscbor_skip_next_item(pinfo->pool, tvb, offset);
        return item_eid;
    }

    wmem_strbuf_t *uribuf = wmem_strbuf_new(alloc_eid, NULL);
    const char *dtn_wkssp = NULL;
    const char *dtn_serv = NULL;
    uint64_t *ipn_serv = NULL;
    switch (*scheme) {
        case EID_SCHEME_DTN: {
            chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
            switch (chunk->type_major) {
                case CBOR_TYPE_UINT: {
                    const uint64_t *ssp_code = wscbor_require_uint64(pinfo->pool, chunk);
                    proto_item *item = proto_tree_add_cbor_uint64(tree_eid, hf_eid_dtn_ssp_code, pinfo, tvb, chunk, ssp_code);

                    switch (*ssp_code) {
                        case 0:
                            dtn_wkssp = wmem_strdup(alloc_eid, "none");
                            break;
                        default:
                            expert_add_info(pinfo, item, &ei_eid_wkssp_unknown);
                            break;
                    }
                    if (dtn_wkssp) {
                        wmem_strbuf_append_printf(uribuf, "dtn:%s", dtn_wkssp);
                    }
                    break;
                }
                case CBOR_TYPE_STRING: {
                    char *ssp = wscbor_require_tstr(pinfo->pool, chunk);
                    proto_tree_add_cbor_tstr(tree_eid, hf_eid_dtn_ssp_text, pinfo, tvb, chunk);
                    wmem_strbuf_append_printf(uribuf, "dtn:%s", ssp);

                    char *path_sep;
                    if ((path_sep = strrchr(ssp, '/')) != NULL) {
                        dtn_serv = wmem_strdup(alloc_eid, path_sep + 1);
                    }
                    else {
                        // no separator also means no authority part, so it's well-known
                        dtn_wkssp = wmem_strdup(alloc_eid, ssp);
                    }

                    wmem_free(pinfo->pool, ssp);
                    break;
                }
                default: {
                    *offset = chunk->start;
                    wscbor_skip_next_item(pinfo->pool, tvb, offset);
                    tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, chunk->start, *offset);
                    call_dissector(handle_cbor, sub_tvb, pinfo, tree_eid);
                    expert_add_info(pinfo, item_eid, &ei_eid_ssp_type_invalid);
                    break;
                }
            }

            break;
        }
        case EID_SCHEME_IPN: {
            chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
            wscbor_require_array_size(chunk, 2, 2);
            if (!wscbor_skip_if_errors(pinfo->pool, tvb, offset, chunk)) {
                chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
                const uint64_t *node = wscbor_require_uint64(pinfo->pool, chunk);
                proto_tree_add_cbor_uint64(tree_eid, hf_eid_ipn_node, pinfo, tvb, chunk, node);

                chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
                ipn_serv = wscbor_require_uint64(wmem_file_scope(), chunk);
                proto_tree_add_cbor_uint64(tree_eid, hf_eid_ipn_service, pinfo, tvb, chunk, ipn_serv);

                wmem_strbuf_append_printf(uribuf, "ipn:%" PRIu64 ".%" PRIu64, node ? *node : 0, ipn_serv ? *ipn_serv : 0);
            }
            break;
        }
        default:
            wscbor_skip_next_item(pinfo->pool, tvb, offset);
            expert_add_info(pinfo, item_scheme, &ei_eid_scheme_unknown);
            break;
    }

    if (dtn_wkssp) {
        proto_item *item = proto_tree_add_string(tree_eid, hf_eid_dtn_wkssp, tvb, eid_start, *offset - eid_start, dtn_wkssp);
        proto_item_set_generated(item);
    }
    if (dtn_serv) {
        proto_item *item = proto_tree_add_string(tree_eid, hf_eid_dtn_serv, tvb, eid_start, *offset - eid_start, dtn_serv);
        proto_item_set_generated(item);
    }

    char *uri = NULL;
    if (wmem_strbuf_get_len(uribuf) > 0) {
        uri = wmem_strbuf_finalize(uribuf);

        proto_item *item_uri = proto_tree_add_string(tree_eid, hfindex_uri, tvb, eid_start, *offset - eid_start, uri);
        proto_item_set_generated(item_uri);

        proto_item_append_text(item_eid, ": %s", uri);
    }

    if (eid) {
        eid->scheme = (scheme ? *scheme : 0);
        if (uri) {
            set_address(&(eid->uri), AT_STRINGZ, (int)strlen(uri) + 1, uri);
        }
        else {
            clear_address(&(eid->uri));
        }
        eid->dtn_wkssp = dtn_wkssp;
        eid->dtn_serv = dtn_serv;
        eid->ipn_serv = ipn_serv;
    }
    else {
        file_scope_delete(uri);
        file_scope_delete((char *)dtn_wkssp);
        file_scope_delete((char *)dtn_serv);
        file_scope_delete(ipn_serv);
    }

    proto_item_set_len(item_eid, *offset - eid_start);
    return item_eid;
}

static void dissect_dtn_time(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, int *offset, bp_dtn_time_t *out)
{
    proto_item *item_time = proto_tree_add_item(tree, hfindex, tvb, *offset, -1, ENC_NA);
    proto_tree *tree_time = proto_item_add_subtree(item_time, ett_time);
    const int offset_start = *offset;

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    if (chunk) {
        const uint64_t *dtntime = wscbor_require_uint64(pinfo->pool, chunk);
        proto_tree_add_cbor_uint64(tree_time, hf_time_dtntime, pinfo, tvb, chunk, dtntime);

        if (dtntime) {
            if (out) {
                out->dtntime = *dtntime;
            }

            if (*dtntime > 0) {
                const nstime_t utctime = dtn_to_utctime(*dtntime);
                proto_item *item_utctime = proto_tree_add_time(tree_time, hf_time_utctime, tvb, chunk->start, chunk->data_length, &utctime);
                proto_item_set_generated(item_utctime);

                char *time_text = abs_time_to_str(pinfo->pool, &utctime, ABSOLUTE_TIME_UTC, true);
                proto_item_append_text(item_time, ": %s", time_text);

                if (out) {
                    out->utctime = utctime;
                }
            }
            else {
                proto_item_append_text(item_time, ": undefined");
            }
        }
        else if (out) {
            out->dtntime = 0;
            nstime_set_zero(&(out->utctime));
        }
    }
    proto_item_set_len(item_time, *offset - offset_start);
}

/** Extract a timestamp.
 *
 * @param tree The tree to write items under.
 * @param hfindex The root item field.
 * @param pinfo Packet info to update.
 * @param tvb Buffer to read from.
 * @param[in,out] offset Starting offset within @c tvb.
 * @param[out] ts If non-null, the timestamp to write to.
 */
static void dissect_cbor_timestamp(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, int *offset, bp_creation_ts_t *ts)
{
    proto_item *item_ts = proto_tree_add_item(tree, hfindex, tvb, *offset, -1, ENC_NA);
    proto_tree *tree_ts = proto_item_add_subtree(item_ts, ett_create_ts);

    wscbor_chunk_t *chunk_ts = wscbor_chunk_read(pinfo->pool, tvb, offset);
    wscbor_require_array_size(chunk_ts, 2, 2);
    wscbor_chunk_mark_errors(pinfo, item_ts, chunk_ts);
    if (!wscbor_skip_if_errors(pinfo->pool, tvb, offset, chunk_ts)) {
        bp_dtn_time_t abstime;
        dissect_dtn_time(tree_ts, hf_create_ts_time, pinfo, tvb, offset, &abstime);

        wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
        const uint64_t *seqno = wscbor_require_uint64(wmem_file_scope(), chunk);
        proto_tree_add_cbor_uint64(tree_ts, hf_create_ts_seqno, pinfo, tvb, chunk, seqno);

        if (ts) {
            ts->abstime = abstime;
            ts->seqno = (seqno ? *seqno : 0);
        }
    }
    proto_item_set_len(item_ts, *offset - chunk_ts->start);
}

/** Label type-field items with sub-dissector name.
 * This is similar to using val64_string labels but based on dissector name.
 *
 * @param type_code The dissected value, which must not be null.
 * @param type_dissect The associated sub-dissector, which may be null.
 * @param[in,out] item_type The item associated with the type field.
 * @param[in,out] item_parent The parent item to label.
 */
static void label_type_field(const uint64_t *type_code, dissector_handle_t type_dissect, proto_item *item_type, proto_item *item_parent)
{
    if (!item_type || !item_parent) {
        return;
    }
    const char *type_name = dissector_handle_get_description(type_dissect);
    if (type_name) {
        proto_item_append_text(item_parent, ": %s", type_name);
    }
    else {
        proto_item_append_text(item_parent, ": Type %" PRIu64, *type_code);
        type_name = "Unknown";
    }
    proto_item_set_text(item_type, "%s: %s (%" PRIu64 ")", PITEM_FINFO(item_type)->hfinfo->name, type_name, *type_code);
}

/** Show read-in and actual CRC information.
 *
 * @param tvb The single-block data.
 * @param crc_type Type of CRC to compute.
 * @param crc_field The read-in field value.
 */
static void show_crc_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_block, const uint64_t *crc_type, tvbuff_t *crc_field) {
    if (!crc_type || !crc_field) {
        return;
    }

    // Display the data field information
    int hf_crc_field;
    switch (*crc_type) {
        case BP_CRC_16:
            hf_crc_field = hf_crc_field_uint16;
            break;
        case BP_CRC_32:
            hf_crc_field = hf_crc_field_uint32;
            break;
        default:
            hf_crc_field = -1;
            break;
    }

    // Compare against expected result
    uint32_t crc_actual = 0;
    unsigned chksum_flags = PROTO_CHECKSUM_NO_FLAGS;
    if (bp_compute_crc) {
        if (*crc_type == BP_CRC_NONE) {
            chksum_flags |= PROTO_CHECKSUM_NOT_PRESENT;
        }
        else {
            const unsigned block_len = tvb_reported_length(tvb);
            uint8_t *crcbuf = tvb_memdup(pinfo->pool, tvb, 0, block_len);
            switch (*crc_type) {
                case BP_CRC_16:
                    memset(crcbuf + block_len - 2, 0, 2);
                    crc_actual = crc16_ccitt(crcbuf, block_len);
                    break;
                case BP_CRC_32:
                    memset(crcbuf + block_len - 4, 0, 4);
                    crc_actual = ~crc32c_calculate_no_swap(crcbuf, block_len, CRC32C_PRELOAD);
                    break;
                default:
                    break;
            }
            wmem_free(pinfo->pool, crcbuf);

            chksum_flags |= PROTO_CHECKSUM_VERIFY;
        }
    }
    proto_tree_add_checksum(tree_block, crc_field, 0, hf_crc_field, hf_crc_status, &ei_block_failed_crc, pinfo, crc_actual, ENC_BIG_ENDIAN, chksum_flags);
}

static proto_item * proto_tree_add_ident(packet_info *pinfo, proto_tree *tree, int hfindex, tvbuff_t *tvb, const bp_bundle_ident_t *ident) {
    wmem_strbuf_t *ident_text = wmem_strbuf_new(pinfo->pool, NULL);
    wmem_strbuf_append_printf(
        ident_text,
        "Source: %s, DTN Time: %" PRIu64 ", Seq: %" PRIu64,
        address_to_name(&(ident->src)),
        ident->ts.abstime.dtntime,
        ident->ts.seqno
    );
    if (ident->frag_offset) {
        wmem_strbuf_append_printf(ident_text, ", Frag Offset: %" PRIu64, *(ident->frag_offset));
    }
    if (ident->total_len) {
        wmem_strbuf_append_printf(ident_text, ", Total Length: %" PRIu64, *(ident->total_len));
    }

    proto_item *item_ident = proto_tree_add_string(tree, hfindex, tvb, 0, 0, wmem_strbuf_get_str(ident_text));
    proto_item_set_generated(item_ident);
    wmem_strbuf_finalize(ident_text);
    return item_ident;
}


static int dissect_block_primary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_block,
                                  int start, bp_block_primary_t *block,
                                  bp_bundle_t *bundle _U_) {
    proto_item *item_block = proto_tree_get_parent(tree_block);
    int field_ix = 0;
    int offset = start;
    block->item_block = item_block;

    wscbor_chunk_t *chunk_block = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_block, 8, 11);
    wscbor_chunk_mark_errors(pinfo, item_block, chunk_block);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_block)) {
        return offset - start;
    }
#if 0
    proto_item_append_text(item_block, ", Items: %" PRIu64, chunk_block->head_value);
#endif

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *version = wscbor_require_uint64(pinfo->pool, chunk);
    proto_item *item_version = proto_tree_add_cbor_uint64(tree_block, hf_primary_version, pinfo, tvb, chunk, version);
    field_ix++;
    if (version && (*version != 7)) {
        expert_add_info(pinfo, item_version, &ei_invalid_bp_version);
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *flags = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_bitmask(tree_block, hf_primary_bundle_flags, ett_bundle_flags, bundle_flags, pinfo, tvb, chunk, flags);
    field_ix++;
    block->flags = (flags ? *flags : 0);

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *crc_type = wscbor_require_uint64(pinfo->pool, chunk);
    proto_item *item_crc_type = proto_tree_add_cbor_uint64(tree_block, hf_crc_type, pinfo, tvb, chunk, crc_type);
    field_ix++;
    block->crc_type = (crc_type ? *crc_type : BP_CRC_NONE);
    if (crc_type) {
        proto_item_append_text(item_block, ", CRC Type: %s", val64_to_str(*crc_type, crc_vals, "%" PRIu64));
    }

    proto_tree_add_cbor_eid(tree_block, hf_primary_dst_eid, hf_primary_dst_uri, pinfo, tvb, &offset, block->dst_eid);
    field_ix++;
    if (block->dst_eid->uri.type != AT_NONE) {
        proto_item_set_hidden(
            proto_tree_add_string(tree_block, hf_primary_srcdst_uri, tvb, 0, 0, address_to_name(&(block->dst_eid->uri)))
        );
    }

    proto_tree_add_cbor_eid(tree_block, hf_primary_src_nodeid, hf_primary_src_uri, pinfo, tvb, &offset, block->src_nodeid);
    field_ix++;
    if (block->src_nodeid->uri.type != AT_NONE) {
        proto_item_set_hidden(
            proto_tree_add_string(tree_block, hf_primary_srcdst_uri, tvb, 0, 0, address_to_name(&(block->src_nodeid->uri)))
        );
    }

    proto_tree_add_cbor_eid(tree_block, hf_primary_report_nodeid, hf_primary_report_uri, pinfo, tvb, &offset, block->rep_nodeid);
    field_ix++;

    // Complex type
    dissect_cbor_timestamp(tree_block, hf_primary_create_ts, pinfo, tvb, &offset, &(block->ts));
    field_ix++;

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *lifetime = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_block, hf_primary_lifetime, pinfo, tvb, chunk, lifetime);
    if (lifetime) {
        nstime_t lifetime_exp = dtn_to_delta(*lifetime);
        proto_item *item_lifetime_exp = proto_tree_add_time(tree_block, hf_primary_lifetime_exp, tvb, chunk->start, chunk->head_length, &lifetime_exp);
        proto_item_set_generated(item_lifetime_exp);

        if (block->ts.abstime.dtntime > 0) {
            nstime_t expiretime;
            nstime_sum(&expiretime, &(block->ts.abstime.utctime), &lifetime_exp);
            proto_item *item_expiretime = proto_tree_add_time(tree_block, hf_primary_expire_ts, tvb, 0, 0, &expiretime);
            proto_item_set_generated(item_expiretime);
        }
    }
    field_ix++;

    // optional items
    if (flags && (*flags & BP_BUNDLE_IS_FRAGMENT)) {
        if (!wscbor_require_array_size(chunk_block, field_ix + 1, field_ix + 3)) {
            // Skip whole array
            offset = start;
            wscbor_skip_next_item(pinfo->pool, tvb, &offset);

            return offset - start;
        }

        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        block->frag_offset = wscbor_require_uint64(wmem_file_scope(), chunk);
        proto_tree_add_cbor_uint64(tree_block, hf_primary_frag_offset, pinfo, tvb, chunk, block->frag_offset);
        field_ix++;

        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        block->total_len = wscbor_require_uint64(wmem_file_scope(), chunk);
        proto_tree_add_cbor_uint64(tree_block, hf_primary_total_length, pinfo, tvb, chunk, block->total_len);
        field_ix++;
    }

    switch (block->crc_type) {
        case BP_CRC_NONE:
            break;
        case BP_CRC_16:
        case BP_CRC_32: {
            if (!wscbor_require_array_size(chunk_block, field_ix + 1, field_ix + 1)) {
                // Skip whole array
                offset = start;
                wscbor_skip_next_item(pinfo->pool, tvb, &offset);

                return offset - start;
            }

            chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            tvbuff_t *crc_field = wscbor_require_bstr(wmem_file_scope(), chunk);
            field_ix++;
            block->crc_field = crc_field;

            tvbuff_t *tvb_block = tvb_new_subset_length(tvb, start, offset - start);
            show_crc_info(tvb_block, pinfo, tree_block, crc_type, crc_field);
            break;
        }
        default:
            expert_add_info(pinfo, item_crc_type, &ei_crc_type_unknown);
            break;
    }

    return offset - start;
}

static int dissect_block_canonical(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_block,
                                    int start, bp_block_canonical_t *block,
                                    bp_bundle_t *bundle _U_) {
    proto_item *item_block = proto_tree_get_parent(tree_block);
    int field_ix = 0;
    int offset = start;
    block->item_block = item_block;

    wscbor_chunk_t *chunk_block = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_block, 5, 6);
    wscbor_chunk_mark_errors(pinfo, item_block, chunk_block);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_block)) {
        return offset - start;
    }
#if 0
    proto_item_append_text(item_block, ", Items: %" PRIu64, chunk_block->head_value);
#endif

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *type_code = wscbor_require_uint64(wmem_file_scope(), chunk);
    proto_item *item_type = proto_tree_add_cbor_uint64(tree_block, hf_canonical_type_code, pinfo, tvb, chunk, type_code);
    field_ix++;
    block->type_code = type_code;

    if (type_code) {
        dissector_handle_t type_dissect = dissector_get_custom_table_handle(block_dissectors, type_code);
        label_type_field(type_code, type_dissect, item_type, item_block);

        // Check duplicate of this type
        uint64_t limit = UINT64_MAX;
        for (int ix = 0; ; ++ix) {
            const blocktype_limit *row = blocktype_limits + ix;
            if (row->type_code == BP_BLOCKTYPE_INVALID) {
                break;
            }
            if (row->type_code == *type_code) {
                limit = row->limit;
                break;
            }
        }

        uint64_t count = 1; // this block counts regardless of presence in the map
        wmem_list_t *list_found = wmem_map_lookup(bundle->block_types, type_code);
        if (list_found) {
            for (wmem_list_frame_t *it = wmem_list_head(list_found); it;
                    it = wmem_list_frame_next(it)) {
                bp_block_canonical_t *block_found = wmem_list_frame_data(it);
                if (block == block_found) {
                    continue;
                }
                ++count;
            }
        }
        if (count > limit) {
            // First non-identical block triggers the error
            expert_add_info(pinfo, item_type, &ei_block_type_dupe);
        }
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *block_num = wscbor_require_uint64(wmem_file_scope(), chunk);
    proto_item *item_block_num = proto_tree_add_cbor_uint64(tree_block, hf_canonical_block_num, pinfo, tvb, chunk, block_num);
    field_ix++;
    block->block_number = block_num;
    if (block_num) {
        proto_item_append_text(item_block, ", Block Num: %" PRIu64, *block_num);
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *flags = wscbor_require_uint64(wmem_file_scope(), chunk);
    proto_tree_add_cbor_bitmask(tree_block, hf_canonical_block_flags, ett_block_flags, block_flags, pinfo, tvb, chunk, flags);
    field_ix++;
    block->flags = (flags ? *flags : 0);

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *crc_type = wscbor_require_uint64(wmem_file_scope(), chunk);
    proto_item *item_crc_type = proto_tree_add_cbor_uint64(tree_block, hf_crc_type, pinfo, tvb, chunk, crc_type);
    field_ix++;
    block->crc_type = (crc_type ? *crc_type : BP_CRC_NONE);
    if (crc_type) {
        proto_item_append_text(item_block, ", CRC Type: %s", val64_to_str(*crc_type, crc_vals, "%" PRIu64));
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    tvbuff_t *tvb_data = wscbor_require_bstr(wmem_file_scope(), chunk);
    field_ix++;
    block->data = tvb_data;

    proto_item_set_generated(
        proto_tree_add_cbor_strlen(tree_block, hf_canonical_data_size, pinfo, tvb, chunk)
    );
    proto_item *item_data = proto_tree_add_cbor_bstr(tree_block, hf_canonical_data, pinfo, tvb, chunk);
    proto_tree *tree_data = proto_item_add_subtree(item_data, ett_canonical_data);
    block->tree_data = tree_data;

    switch (block->crc_type) {
        case BP_CRC_NONE:
            break;
        case BP_CRC_16:
        case BP_CRC_32: {
            if (!wscbor_require_array_size(chunk_block, field_ix + 1, field_ix + 1)) {
                // Skip whole array
                offset = start;
                wscbor_skip_next_item(pinfo->pool, tvb, &offset);

                return offset - start;
            }

            chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            tvbuff_t *crc_field = wscbor_require_bstr(wmem_file_scope(), chunk);
            field_ix++;
            block->crc_field = crc_field;

            tvbuff_t *tvb_block = tvb_new_subset_length(tvb, start, offset - start);
            show_crc_info(tvb_block, pinfo, tree_block, crc_type, crc_field);
            break;
        }
        default:
            expert_add_info(pinfo, item_crc_type, &ei_crc_type_unknown);
            break;
    }

    wmem_list_append(bundle->blocks, block);

    if (block->type_code) {
        wmem_list_t *type_list = wmem_map_lookup(bundle->block_types, block->type_code);
        if (!type_list) {
            uint64_t *key = guint64_new(wmem_file_scope(), *(block->type_code));
            type_list = wmem_list_new(wmem_file_scope());
            wmem_map_insert(bundle->block_types, key, type_list);
        }
        wmem_list_append(type_list, block);
    }
    if (block->block_number) {
        bp_block_canonical_t *found = wmem_map_lookup(bundle->block_nums, block->block_number);
        if (found) {
            expert_add_info(pinfo, item_block_num, &ei_block_num_dupe);
        }
        else {
            uint64_t *key = guint64_new(wmem_file_scope(), *(block->block_number));
            wmem_map_insert(bundle->block_nums, key, block);
        }
    }
    // Payload block requirements
    if (block->type_code && (*(block->type_code) == BP_BLOCKTYPE_PAYLOAD)) {
        // must have index zero
        if (block->block_number && (*(block->block_number) != 1)) {
            expert_add_info(pinfo, item_block_num, &ei_block_payload_num);
        }
    }

    return offset - start;
}

typedef struct {
    packet_info *pinfo;
    proto_item *pi;
    expert_field *eiindex;
    const char *sectype;
} bpsec_block_mark_t;
/// Mark blocks with BPSec expert info
static void mark_target_block(void *key, void *value _U_, void *user_data) {
    const uint64_t *blk_num = (uint64_t *)key;
    const bpsec_block_mark_t *mark = (bpsec_block_mark_t *)user_data;
    expert_add_info_format(
        mark->pinfo, mark->pi, mark->eiindex,
        "Block is targed by %s block number %" PRIu64, mark->sectype, *blk_num
    );
}
static void apply_bpsec_mark(const security_mark_t *sec, packet_info *pinfo, proto_item *pi) {
    {
        bpsec_block_mark_t mark;
        mark.pinfo = pinfo;
        mark.pi = pi;
        mark.eiindex = &ei_block_sec_bib_tgt;
        mark.sectype = "BIB";
        wmem_map_foreach(sec->data_i, mark_target_block, &mark);
    }
    {
        bpsec_block_mark_t mark;
        mark.pinfo = pinfo;
        mark.pi = pi;
        mark.eiindex = &ei_block_sec_bcb_tgt;
        mark.sectype = "BCB";
        wmem_map_foreach(sec->data_c, mark_target_block, &mark);
    }
}

/** Extract data from a block (including payload and admin).
 *
 * @param dissector The optional dissector to call.
 * @param context Context for the @c dissector.
 * @param tvb Buffer to read from.
 * @param pinfo Packet info to update.
 * @param tree The tree to write items under.
 * @param type_exp True if the type code is in the private/experimental range.
 * @return The number of dissected octets.
 */
static int dissect_carried_data(dissector_handle_t dissector, void *context, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool type_exp) {
    int sublen = 0;
    if (dissector) {
        sublen = call_dissector_only(dissector, tvb, pinfo, tree, context);
        if ((sublen < 0) ||
            ((sublen > 0) && ((unsigned)sublen < tvb_reported_length(tvb)))) {
            expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_sub_partial_decode);
        }
    }
    else if (!type_exp) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_sub_type_unknown);
    }

    if ((sublen <= 0) && bp_payload_try_heur) {
        heur_dtbl_entry_t *entry = NULL;
        if (dissector_try_heuristic(btsd_heur, tvb, pinfo, tree, &entry, context)) {
            sublen = tvb_reported_length(tvb);
        }
    }
    if (sublen == 0) {
        sublen = call_data_dissector(tvb, pinfo, tree);
    }
    return sublen;
}

/** Handle iteration over status subject set.
 *
 */
static void show_status_subj_ref(void *key, void *val _U_, void *data) {
    bp_bundle_ident_t *status_ident = key;
    proto_tree *tree_bundle = data;
    const wmem_list_t *subj_list = wmem_map_lookup(bp_history->bundles, status_ident);
    const wmem_list_frame_t *subj_it = subj_list ? wmem_list_head(subj_list) : NULL;
    const bp_bundle_t *subj_found = subj_it ? wmem_list_frame_data(subj_it) : NULL;
    if (subj_found) {
        proto_item *item_subj_ref = proto_tree_add_uint(tree_bundle, hf_bundle_status_ref, NULL, 0, 0, subj_found->frame_num);
        proto_item_set_generated(item_subj_ref);
    }
}

/// Stable sort, preserving relative order of same priority
static int block_dissect_sort(const void *a, const void *b) {
    DISSECTOR_ASSERT(a && b);
    const bp_block_canonical_t *aobj = *(bp_block_canonical_t **)a;
    const bp_block_canonical_t *bobj = *(bp_block_canonical_t **)b;
    const int aord = blocktype_order(aobj);
    const int bord = blocktype_order(bobj);
    if (aord < bord) {
        return -1;
    }
    else if (aord > bord) {
        return 1;
    }

    return g_int_equal(&(aobj->blk_ix), &(bobj->blk_ix));
}

/// Top-level protocol dissector
static int dissect_bp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    {
        const char *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (g_strcmp0(proto_name, proto_name_bp) != 0) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_bp);
            col_clear(pinfo->cinfo, COL_INFO);
        }
    }
    int offset = 0;

    proto_item *item_bundle = proto_tree_add_item(tree, proto_bp, tvb, 0, -1, ENC_NA);
    proto_tree *tree_bundle = proto_item_add_subtree(item_bundle, ett_bundle);

    bp_bundle_t *bundle = bp_bundle_new(wmem_file_scope());
    bundle->frame_num = pinfo->num;
    bundle->layer_num = pinfo->curr_layer_num;
    bundle->frame_time = pinfo->abs_ts;

    // Read blocks directly from buffer with same addresses as #tvb
    const unsigned buflen = tvb_reported_length(tvb);

    // Require indefinite-length array type
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    proto_item *item_head = proto_tree_add_item(tree_bundle, hf_bundle_head, tvb, chunk->start, chunk->data_length, ENC_NA);
    wscbor_require_array(chunk);
    if (wscbor_chunk_mark_errors(pinfo, item_head, chunk)) {
        return 0;
    }
    else if (chunk->type_minor != 31) {
        expert_add_info_format(pinfo, item_head, &ei_invalid_framing, "Expected indefinite length array");
        // continue on even for definite-length array
    }

    uint64_t block_ix = 0;
    while (true) {
        if (offset >= (int)buflen) {
            proto_item *item_break = proto_tree_add_item(tree_bundle, hf_bundle_break, tvb, offset, -1, ENC_NA);
            expert_add_info_format(pinfo, item_break, &ei_invalid_framing, "Array break missing");
            break;
        }

        // Either detect BREAK or decode block
        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        if (wscbor_is_indefinite_break(chunk)) {
            proto_tree_add_cbor_ctrl(tree_bundle, hf_bundle_break, pinfo, tvb, chunk);
            break;
        }
        offset = chunk->start;

        // Load just the array start
        const int block_start = offset;
        proto_item *item_block = proto_tree_add_item(tree_bundle, hf_block, tvb, block_start, -1, ENC_NA);
        proto_tree *tree_block = proto_item_add_subtree(item_block, ett_block);

        if (block_ix == 0) {
            // Primary block
            proto_item_prepend_text(item_block, "Primary ");
            const int sublen = dissect_block_primary(tvb, pinfo, tree_block, offset, bundle->primary, bundle);
            if (sublen <= 0) {
                break;
            }
            offset += sublen;

            if (!(bundle->ident)) {
                bundle->ident = bp_bundle_ident_new(
                    wmem_file_scope(),
                    bundle->primary->src_nodeid,
                    &(bundle->primary->ts),
                    bundle->primary->frag_offset,
                    bundle->primary->total_len
                );
                proto_item *item_ident = proto_tree_add_ident(pinfo, tree_bundle, hf_bundle_ident, tvb, bundle->ident);
                proto_tree *tree_ident = proto_item_add_subtree(item_ident, ett_ident);

                const wmem_list_t *seen_list = wmem_map_lookup(bp_history->bundles, bundle->ident);
                wmem_list_frame_t *seen_it = seen_list ? wmem_list_head(seen_list) : NULL;
                const bp_bundle_t *seen_first = seen_it ? wmem_list_frame_data(seen_it) : NULL;
                // show first occurrence if not this one
                if (seen_first && (seen_first->frame_num != pinfo->num)) {
                    proto_item *item_seen = proto_tree_add_uint(tree_ident, hf_bundle_first_seen, tvb, 0, 0, seen_first->frame_num);
                    proto_item_set_generated(item_seen);

                    nstime_t td;
                    nstime_delta(&td, &(bundle->frame_time), &(seen_first->frame_time));
                    proto_item *item_td = proto_tree_add_time(tree_ident, hf_bundle_seen_time_diff, tvb, 0, 0, &td);
                    proto_item_set_generated(item_td);
                }
                // show any retransmits
                else if (seen_it) {
                    for (seen_it = wmem_list_frame_next(seen_it); seen_it != NULL; seen_it = wmem_list_frame_next(seen_it)) {
                        const bp_bundle_t *seen_re = wmem_list_frame_data(seen_it);
                        if (seen_re && (seen_re->frame_num != pinfo->num)) {
                            proto_item *item_seen = proto_tree_add_uint(tree_ident, hf_bundle_retrans_seen, tvb, 0, 0, seen_re->frame_num);
                            proto_item_set_generated(item_seen);
                        }
                    }
                }

                // Indicate related status (may be multiple)
                wmem_map_t *status_set = wmem_map_lookup(bp_history->admin_status, bundle->ident);
                if (status_set) {
                    wmem_map_foreach(status_set, show_status_subj_ref, tree_ident);
                }
            }
            {
                const bp_eid_t *dst = bundle->primary->dst_eid;
                if (dst) {
                    proto_item *item_dst = NULL;
                    if (dst->dtn_serv) {
                        item_dst = proto_tree_add_string(tree_bundle, hf_bundle_dst_dtn_srv, tvb, 0, 0, dst->dtn_serv);
                    }
                    else if (dst->ipn_serv) {
                        item_dst = proto_tree_add_uint64(tree_bundle, hf_bundle_dst_ipn_srv, tvb, 0, 0, *(dst->ipn_serv));
                    }
                    if (item_dst) {
                        proto_item_set_generated(item_dst);
                    }
                }
            }
        }
        else {
            // Non-primary block
            proto_item_prepend_text(item_block, "Canonical ");
            bp_block_canonical_t *block = bp_block_canonical_new(wmem_file_scope(), block_ix);
            const int sublen = dissect_block_canonical(tvb, pinfo, tree_block, offset, block, bundle);
            if (sublen <= 0) {
                break;
            }
            offset += sublen;
        }

        proto_item_set_len(item_block, offset - block_start);
        block_ix++;
    }

    // Block ordering requirements
    for (wmem_list_frame_t *it = wmem_list_head(bundle->blocks); it;
            it = wmem_list_frame_next(it)) {
        bp_block_canonical_t *block = wmem_list_frame_data(it);
        if (block->type_code && (*(block->type_code) == BP_BLOCKTYPE_PAYLOAD)) {
            // must be last block (i.e. next is NULL)
            if (wmem_list_frame_next(it)) {
                expert_add_info(pinfo, block->item_block, &ei_block_payload_index);
            }

            if (block->data) {
                bundle->pyld_start = wmem_new(wmem_file_scope(), unsigned);
                *(bundle->pyld_start) = tvb_raw_offset(block->data) - tvb_raw_offset(tvb);
                bundle->pyld_len = wmem_new(wmem_file_scope(), unsigned);
                *(bundle->pyld_len) = tvb_reported_length(block->data);
            }
        }
    }

    // Handle block-type-specific data after all blocks are present
    wmem_array_t *sorted = wmem_array_sized_new(
        pinfo->pool,  sizeof(bp_block_canonical_t*),
        wmem_list_count(bundle->blocks)
    );
    unsigned ix = 0;
    for (wmem_list_frame_t *it = wmem_list_head(bundle->blocks); it;
            it = wmem_list_frame_next(it), ++ix) {
        bp_block_canonical_t *block = wmem_list_frame_data(it);
        wmem_array_append_one(sorted, block);
    }
    wmem_array_sort(sorted, block_dissect_sort);

    // Dissect in sorted order
    for (ix = 0; ix < wmem_array_get_count(sorted); ++ix) {
        bp_block_canonical_t *block = *(bp_block_canonical_t **)wmem_array_index(sorted, ix);

        // Ignore when data is absent or is a
        // confidentiality target (i.e. ciphertext)
        if (!(block->data) || (wmem_map_size(block->sec.data_c) > 0)) {
            continue;
        }

        // sub-dissect after all is read
        dissector_handle_t data_dissect = NULL;
        bool type_exp = false;
        if (block->type_code) {
            data_dissect = dissector_get_custom_table_handle(block_dissectors, block->type_code);
            type_exp = (*(block->type_code) >= 192) && (*(block->type_code) <= 255);
        }

        bp_dissector_data_t dissect_data;
        dissect_data.bundle = bundle;
        dissect_data.block = block;
        dissect_carried_data(data_dissect, &dissect_data, block->data, pinfo, block->tree_data, type_exp);
    }

    // Block-data-derived markings
    apply_bpsec_mark(&(bundle->primary->sec), pinfo, bundle->primary->item_block);
    for (wmem_list_frame_t *it = wmem_list_head(bundle->blocks); it;
            it = wmem_list_frame_next(it)) {
        bp_block_canonical_t *block = wmem_list_frame_data(it);
        apply_bpsec_mark(&(block->sec), pinfo, block->item_block);
    }

    {
        const bp_block_primary_t *primary = bundle->primary;

        proto_item_append_text(item_bundle, ", Src: %s", address_to_name(&(primary->src_nodeid->uri)));
        proto_item_append_text(item_bundle, ", Dst: %s", address_to_name(&(primary->dst_eid->uri)));
        if (bundle->ident) {
            proto_item_append_text(item_bundle, ", Time: %" PRIu64, bundle->ident->ts.abstime.dtntime);
            proto_item_append_text(item_bundle, ", Seq: %" PRIu64, bundle->ident->ts.seqno);
        }
        proto_item_append_text(item_bundle, ", Blocks: %" PRIu64, block_ix);

        if ((primary->src_nodeid->uri.type != AT_NONE)
                && (primary->dst_eid->uri.type != AT_NONE)) {
            // conversation starts in either order
            address *addra, *addrb;
            if (cmp_address(&(primary->src_nodeid->uri), &(primary->dst_eid->uri)) < 0) {
                addra = &(primary->src_nodeid->uri);
                addrb = &(primary->dst_eid->uri);
            }
            else {
                addra = &(primary->dst_eid->uri);
                addrb = &(primary->src_nodeid->uri);
            }

            copy_address_shallow(&(pinfo->src), &(primary->src_nodeid->uri));
            copy_address_shallow(&(pinfo->dst), &(primary->dst_eid->uri));
            pinfo->ptype = PT_NONE;

            conversation_element_t *conv_el = wmem_alloc_array(pinfo->pool, conversation_element_t, 3);
            conv_el[0].type=CE_ADDRESS;
            copy_address_shallow(&(conv_el[0].addr_val), addra);
            conv_el[1].type=CE_ADDRESS;
            copy_address_shallow(&(conv_el[1].addr_val), addrb);
            conv_el[2].type=CE_CONVERSATION_TYPE;
            conv_el[2].conversation_type_val=CONVERSATION_BP;

            pinfo->use_conv_addr_port_endpoints = false;
            pinfo->conv_addr_port_endpoints = NULL;
            pinfo->conv_elements = conv_el;
            find_or_create_conversation(pinfo);
        }
    }

    if (bundle->pyld_start && bundle->pyld_len) {
        proto_item_append_text(item_bundle, ", Payload-Size: %d", *(bundle->pyld_len));

        // Treat payload as non-protocol data
        const unsigned trailer_start = *(bundle->pyld_start) + *(bundle->pyld_len);
        proto_item_set_len(item_bundle, *(bundle->pyld_start));
        proto_tree_set_appendix(tree_bundle, tvb, trailer_start, offset - trailer_start);
    }
    else {
        proto_item_set_len(item_bundle, offset);
    }

    bp_bundle_t *unique_bundle = bundle;
    if (bundle->ident) {
        // Keep bundle metadata around for the whole file
        wmem_list_t *found_list = wmem_map_lookup(bp_history->bundles, bundle->ident);
        if (!found_list) {
            found_list = wmem_list_new(wmem_file_scope());
            wmem_map_insert(bp_history->bundles, bundle->ident, found_list);
        }

        const wmem_list_frame_t *found_it = wmem_list_find_custom(found_list, bundle, bp_bundle_frameloc_compare);
        bp_bundle_t *found_item = found_it ? wmem_list_frame_data(found_it) : NULL;
        if (!found_item) {
            wmem_list_append(found_list, bundle);
        }
        else {
            bp_bundle_free(wmem_file_scope(), bundle);
            unique_bundle = found_item;
        }
    }
    p_add_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE, unique_bundle);
    tap_queue_packet(bp_tap, pinfo, unique_bundle);

    return offset;
}

static bool dissect_status_assertion(proto_tree *tree, int hfassert, packet_info *pinfo, tvbuff_t *tvb, int *offset)
{
    proto_item *item_assert = proto_tree_add_item(tree, hfassert, tvb, *offset, -1, ENC_NA);

    bool result = false;

    wscbor_chunk_t *chunk_assert = wscbor_chunk_read(pinfo->pool, tvb, offset);
    wscbor_require_array_size(chunk_assert, 1, 2);
    wscbor_chunk_mark_errors(pinfo, item_assert, chunk_assert);
    if (!wscbor_skip_if_errors(pinfo->pool, tvb, offset, chunk_assert)) {
        proto_tree *tree_assert = proto_item_add_subtree(item_assert, ett_status_assert);

        wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
        bool *status_val = wscbor_require_boolean(pinfo->pool, chunk);
        proto_tree_add_cbor_boolean(tree_assert, hf_status_assert_val, pinfo, tvb, chunk, status_val);
        if (status_val) {
            result = *status_val;
        }

        if (chunk_assert->head_value > 1) {
            bp_dtn_time_t abstime;
            dissect_dtn_time(tree_assert, hf_status_assert_time, pinfo, tvb, offset, &abstime);
        }
    }

    proto_item_set_len(item_assert, *offset - chunk_assert->start);
    return result;
}

static int dissect_payload_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    DISSECTOR_ASSERT(context);
    {
        const char *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (g_strcmp0(proto_name, proto_name_bp_admin) != 0) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_bp_admin);
            col_clear(pinfo->cinfo, COL_INFO);
        }
    }
    proto_item *item_rec = proto_tree_add_item(tree, proto_bp_admin, tvb, 0, -1, ENC_NA);
    int offset = 0;

    wscbor_chunk_t *chunk_rec = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_rec, 1, 2);
    wscbor_chunk_mark_errors(pinfo, item_rec, chunk_rec);
    if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_rec)) {
        proto_tree *tree_rec = proto_item_add_subtree(item_rec, ett_admin);

        wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        uint64_t *type_code = wscbor_require_uint64(pinfo->pool, chunk);
        proto_item *item_type = proto_tree_add_cbor_uint64(tree_rec, hf_admin_record_type, pinfo, tvb, chunk, type_code);

        dissector_handle_t type_dissect = NULL;
        bool type_exp = false;
        if (type_code) {
            type_dissect = dissector_get_custom_table_handle(admin_dissectors, type_code);
            label_type_field(type_code, type_dissect, item_type, item_rec);
            type_exp = (*type_code >= 65536);
        }
        tvbuff_t *tvb_record = tvb_new_subset_remaining(tvb, offset);
        int sublen = dissect_carried_data(type_dissect, context, tvb_record, pinfo, tree_rec, type_exp);
        offset += sublen;
    }

    proto_item_set_len(item_rec, offset);
    return offset;
}

static int dissect_status_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    if (!context) {
        return -1;
    }
    int offset = 0;

    // Status Information array head
    proto_item *item_status = proto_tree_add_item(tree, hf_status_rep, tvb, offset, -1, ENC_NA);
    proto_tree *tree_status = proto_item_add_subtree(item_status, ett_status_rep);
    unsigned status_field_ix = 0;

    wscbor_chunk_t *chunk_status = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_status, 4, 6);
    wscbor_chunk_mark_errors(pinfo, item_status, chunk_status);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_status)) {
        proto_item_set_len(item_status, offset - chunk_status->start);
        return 0;
    }

    wscbor_chunk_t *chunk;
    bool status_received = false;
    bool status_forwarded = false;
    bool status_delivered = false;
    bool status_deleted = false;

    wscbor_chunk_t *chunk_info = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_info, 4, 4);
    {
        proto_item *item_info = proto_tree_add_item(tree_status, hf_status_rep_status_info, tvb, offset, -1, ENC_NA);
        wscbor_chunk_mark_errors(pinfo, item_info, chunk_info);
        if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_info)) {
            proto_tree *tree_info = proto_item_add_subtree(item_info, ett_status_info);

            status_received = dissect_status_assertion(tree_info, hf_status_rep_received, pinfo, tvb, &offset);
            status_forwarded = dissect_status_assertion(tree_info, hf_status_rep_forwarded, pinfo, tvb, &offset);
            status_delivered = dissect_status_assertion(tree_info, hf_status_rep_delivered, pinfo, tvb, &offset);
            status_deleted = dissect_status_assertion(tree_info, hf_status_rep_deleted, pinfo, tvb, &offset);
        }

        proto_item_set_len(item_info, offset - chunk_info->start);
        status_field_ix++;
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *reason_code = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_status, hf_status_rep_reason_code, pinfo, tvb, chunk, reason_code);
    status_field_ix++;

    bp_eid_t *subj_eid = bp_eid_new(pinfo->pool);
    proto_tree_add_cbor_eid(tree_status, hf_status_rep_subj_src_nodeid, hf_status_rep_subj_src_uri, pinfo, tvb, &offset, subj_eid);
    status_field_ix++;

    bp_creation_ts_t subj_ts;
    dissect_cbor_timestamp(tree_status, hf_status_rep_subj_ts, pinfo, tvb, &offset, &subj_ts);
    status_field_ix++;

    bp_bundle_ident_t *subj = bp_bundle_ident_new(wmem_file_scope(), subj_eid, &subj_ts, NULL, NULL);

    if (chunk_info->head_value > status_field_ix) {
        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        subj->frag_offset = wscbor_require_uint64(wmem_file_scope(), chunk);
        proto_tree_add_cbor_uint64(tree_status, hf_status_rep_subj_frag_offset, pinfo, tvb, chunk, subj->frag_offset);
        status_field_ix++;
    }

    if (chunk_info->head_value > status_field_ix) {
        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        subj->total_len = wscbor_require_uint64(wmem_file_scope(), chunk);
        proto_tree_add_cbor_uint64(tree_status, hf_status_rep_subj_payload_len, pinfo, tvb, chunk, subj->total_len);
        status_field_ix++;
    }

    proto_tree_add_ident(pinfo, tree_status, hf_status_rep_subj_ident, tvb, subj);

    {
        // Pointer back to subject
        const wmem_list_t *subj_list = wmem_map_lookup(bp_history->bundles, subj);
        const wmem_list_frame_t *subj_it = subj_list ? wmem_list_head(subj_list) : NULL;
        const bp_bundle_t *subj_found = subj_it ? wmem_list_frame_data(subj_it) : NULL;
        if (subj_found) {
            proto_item *item_subj_ref = proto_tree_add_uint(tree_status, hf_status_rep_subj_ref, tvb, 0, 0, subj_found->frame_num);
            proto_item_set_generated(item_subj_ref);

            nstime_t td;
            nstime_delta(&td, &(context->bundle->frame_time), &(subj_found->frame_time));
            proto_item *item_td = proto_tree_add_time(tree_status, hf_status_time_diff, tvb, 0, 0, &td);
            proto_item_set_generated(item_td);
        }
    }
    {
        // Pointers from subject to this status
        wmem_map_t *status_set = wmem_map_lookup(bp_history->admin_status, subj);
        if (!status_set) {
            status_set = wmem_map_new(wmem_file_scope(), bp_bundle_ident_hash, bp_bundle_ident_equal);
            wmem_map_insert(bp_history->admin_status, subj, status_set);
        }
        else {
            bp_bundle_ident_free(wmem_file_scope(), subj);
        }

        // Back-references to this status
        if (!wmem_map_contains(status_set, context->bundle->ident)) {
            ws_debug("status for %p in frame %d", (void*)context->bundle, context->bundle->frame_num);
            wmem_map_insert(status_set, context->bundle->ident, NULL);
        }
    }

    proto_item *item_admin = proto_tree_get_parent(tree);
    {
        wmem_strbuf_t *status_text = wmem_strbuf_new(pinfo->pool, NULL);
        bool sep = false;
        if (status_received) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "RECEIVED");
            sep = true;
        }
        if (status_forwarded) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "FORWARDED");
            sep = true;
        }
        if (status_delivered) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "DELIVERED");
            sep = true;
        }
        if (status_deleted) {
            if (sep) {
                wmem_strbuf_append(status_text, "|");
            }
            wmem_strbuf_append(status_text, "DELETED");
        }
        const char *status_buf = wmem_strbuf_finalize(status_text);
        proto_item_append_text(item_admin, ", Status: %s", status_buf);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Status: %s",
                            status_buf);
    }
    if (reason_code) {
        proto_item_append_text(item_admin, ", Reason: %s", val64_to_str(*reason_code, status_report_reason_vals, "%" PRIu64));
    }

    proto_item_set_len(item_status, offset - chunk_status->start);
    return offset;
}

/** Dissector for Bundle Payload block.
 */
static int dissect_block_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    if (!context) {
        return -1;
    }
    const bp_bundle_t *bundle = context->bundle;

    // Parent bundle tree
    proto_tree *tree_block = proto_tree_get_parent_tree(tree);
    proto_tree *tree_bundle = proto_tree_get_parent_tree(tree_block);
    // Back up to top-level
    proto_item *tree_top = proto_tree_get_parent_tree(tree_bundle);

    const bool is_fragment = bundle->primary->flags & BP_BUNDLE_IS_FRAGMENT;
    const bool is_admin = bundle->primary->flags & BP_BUNDLE_PAYLOAD_ADMIN;
    const unsigned payload_len = tvb_reported_length(tvb);

    // Set if the payload is fully defragmented
    tvbuff_t *tvb_payload = NULL;
    const char *col_suffix = NULL;
    if (is_fragment) {
        col_suffix = " (fragment)";

        if (bp_reassemble_payload) {
            if (!(bundle->primary->frag_offset
                  && bundle->primary->total_len)) {
                return -1;
            }
            // correlate by non-fragment bundle identity hash
            bp_bundle_ident_t *corr_ident = bp_bundle_ident_new(
                pinfo->pool,
                bundle->primary->src_nodeid,
                &(bundle->primary->ts),
                NULL,
                NULL
            );

            if (
                (UINT32_MAX < *(bundle->primary->frag_offset))
                || (UINT32_MAX < *(bundle->primary->total_len))) {
                expert_add_info(pinfo, bundle->primary->item_block, &ei_fragment_reassemble_size);
            }
            else {
                const uint32_t frag_offset = (uint32_t)*(bundle->primary->frag_offset);
                const uint32_t total_len = (uint32_t)*(bundle->primary->total_len);
                fragment_head *payload_frag_msg = fragment_add_check(
                    &bp_reassembly_table,
                    tvb, 0,
                    pinfo, 0, corr_ident,
                    frag_offset,
                    payload_len,
                    true
                );
                const uint32_t old_total_len = fragment_get_tot_len(
                    &bp_reassembly_table,
                    pinfo, 0, corr_ident
                );
                if (old_total_len > 0) {
                    if (total_len != old_total_len) {
                        expert_add_info(pinfo, bundle->primary->item_block, &ei_fragment_tot_mismatch);
                    }
                }
                else {
                    fragment_set_tot_len(
                        &bp_reassembly_table,
                        pinfo, 0, corr_ident,
                        total_len
                    );
                }
                tvb_payload = process_reassembled_data(
                    tvb, 0, pinfo,
                    "Reassembled Payload",
                    payload_frag_msg,
                    &payload_frag_items,
                    NULL,
                    tree_bundle
                );
                if (tvb_payload) {
                    col_suffix = " (reassembled)";
                }
            }
            bp_bundle_ident_free(pinfo->pool, corr_ident);
        }
    }
    else {
        tvb_payload = tvb;
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Payload-Size: %d", payload_len);
    if (col_suffix) {
        col_append_str(pinfo->cinfo, COL_INFO, col_suffix);
    }
    if (!tvb_payload) {
        return payload_len;
    }

    // Payload is known to be administrative, independent of destination EID
    if (is_admin) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Admin]");
        const int sublen = call_dissector_only(handle_admin, tvb_payload, pinfo, tree_top, context);
        if (sublen > 0) {
            return sublen;
        }
    }

    // an EID shouldn't have multiple of these set
    dissector_handle_t payload_dissect = NULL;
    if (bundle->primary->dst_eid->dtn_wkssp) {
        payload_dissect = dissector_get_string_handle(payload_dissectors_dtn_wkssp, bundle->primary->dst_eid->dtn_wkssp);
    }
    else if (bundle->primary->dst_eid->dtn_serv) {
        payload_dissect = dissector_get_string_handle(payload_dissectors_dtn_serv, bundle->primary->dst_eid->dtn_serv);
    }
    else if (bundle->primary->dst_eid->ipn_serv &&
        (*(bundle->primary->dst_eid->ipn_serv) <= UINT_MAX)) {
        payload_dissect = dissector_get_uint_handle(payload_dissectors_ipn_serv, (unsigned)(*(bundle->primary->dst_eid->ipn_serv)));
    }

    return dissect_carried_data(payload_dissect, context, tvb_payload, pinfo, tree_top, true);
}

/** Dissector for Previous Node block.
 */
static int dissect_block_prev_node(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    proto_tree_add_cbor_eid(tree, hf_previous_node_nodeid, hf_previous_node_uri, pinfo, tvb, &offset, NULL);

    return offset;
}

/** Dissector for Bundle Age block.
 */
static int dissect_block_bundle_age(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *age = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree, hf_bundle_age_time, pinfo, tvb, chunk, age);

    return offset;
}

/** Dissector for Hop Count block.
 */
static int dissect_block_hop_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk, 2, 2);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk)) {
        return 0;
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *limit = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree, hf_hop_count_limit, pinfo, tvb, chunk, limit);

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    const uint64_t *current = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree, hf_hop_count_current, pinfo, tvb, chunk, current);

    return offset;
}

static bool btsd_heur_cbor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    volatile int count = 0;

    while ((unsigned)offset < tvb_reported_length(tvb)) {
        volatile bool valid = false;
        TRY {
            valid = wscbor_skip_next_item(pinfo->pool, tvb, &offset);
        }
        CATCH_BOUNDS_AND_DISSECTOR_ERRORS {}
        ENDTRY;
        if (!valid) {
            break;
        }
        ++count;
    }

    // Anything went wrong with any part of the data
    if ((count == 0) || ((unsigned)offset != tvb_reported_length(tvb))) {
        return false;
    }

    if (count == 1) {
        call_dissector(handle_cbor, tvb, pinfo, tree);
    }
    else {
        call_dissector(handle_cborseq, tvb, pinfo, tree);
    }
    return true;
}

/// Clear state when new file scope is entered
static void bp_init(void) {
    bp_history = wmem_new0(wmem_file_scope(), bp_history_t);
    // ident keys are owned by the respective bundles
    bp_history->bundles = wmem_map_new(wmem_file_scope(), bp_bundle_ident_hash, bp_bundle_ident_equal);
    // subject ident key is not kept
    bp_history->admin_status = wmem_map_new(wmem_file_scope(), bp_bundle_ident_hash, bp_bundle_ident_equal);
}

static void bp_cleanup(void) {}

/// Re-initialize after a configuration change
static void bp_reinit_config(void) {}


static void *fragment_bundle_ident_temporary_key(
        const packet_info *pinfo _U_, const uint32_t id _U_, const void *data) {
    return (bp_bundle_ident_t *)data;
}
static void *fragment_bundle_ident_persistent_key(
        const packet_info *pinfo _U_, const uint32_t id _U_, const void *data) {
    const bp_bundle_ident_t *ident = (const bp_bundle_ident_t *)data;

    bp_bundle_ident_t *key = g_slice_new0(bp_bundle_ident_t);

    copy_address(&(key->src), &(ident->src));
    key->ts = ident->ts;
    if (ident->frag_offset) {
        key->frag_offset = g_slice_new(uint64_t);
        key->frag_offset = ident->frag_offset;
    }
    if (ident->total_len) {
        key->total_len = g_slice_new(uint64_t);
        key->total_len = ident->total_len;
    }
    return key;
}
static void fragment_bundle_ident_free_temporary_key(void *ptr _U_) {}
static void fragment_bundle_ident_free_persistent_key(void *ptr) {
    bp_bundle_ident_t *key = (bp_bundle_ident_t *)ptr;

    free_address(&(key->src));
    g_slice_free(uint64_t, (void *)(key->frag_offset));
    g_slice_free(uint64_t, (void *)(key->total_len));

    g_slice_free(bp_bundle_ident_t, key);
}
static const reassembly_table_functions bundle_reassembly_table_functions = {
    bp_bundle_ident_hash,
    bp_bundle_ident_equal,
    fragment_bundle_ident_temporary_key,
    fragment_bundle_ident_persistent_key,
    fragment_bundle_ident_free_temporary_key,
    fragment_bundle_ident_free_persistent_key
};

static void dtn_serv_prompt(packet_info *pinfo, char *result) {
    const bp_bundle_t *bundle = p_get_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE);

    const char *serv = NULL;
    if (bundle && bundle->primary->dst_eid->dtn_serv) {
        serv = bundle->primary->dst_eid->dtn_serv;
    }

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "dst (%s)", serv);
}

static void *dtn_serv_value(packet_info *pinfo) {
    const bp_bundle_t *bundle = p_get_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE);
    if (bundle && bundle->primary->dst_eid->dtn_serv) {
        const char *serv = bundle->primary->dst_eid->dtn_serv;
        return (char *)serv;
    }
    return 0;
}

static void ipn_serv_prompt(packet_info *pinfo, char *result) {
    const bp_bundle_t *bundle = p_get_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE);

    uint32_t serv = 0;
    if (bundle && bundle->primary->dst_eid->ipn_serv
        && (*(bundle->primary->dst_eid->ipn_serv) <= UINT_MAX)) {
        serv = (unsigned int) *(bundle->primary->dst_eid->ipn_serv);
    }

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "dst (%u)", serv);
}

static void *ipn_serv_value(packet_info *pinfo) {
    const bp_bundle_t *bundle = p_get_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE);
    if (bundle && bundle->primary->dst_eid->ipn_serv
        && (*(bundle->primary->dst_eid->ipn_serv) <= UINT_MAX)) {
        uint64_t serv = *(bundle->primary->dst_eid->ipn_serv);
        return GUINT_TO_POINTER(serv);
    }
    return 0;
}

static const char * bp_conv_get_filter_type(conv_item_t *item, conv_filter_type_e filter) {
    if ((filter == CONV_FT_SRC_ADDRESS) && (item->src_address.type == AT_STRINGZ)) {
        return "bpv7.primary.src_uri";
    }
    if ((filter == CONV_FT_DST_ADDRESS) && (item->dst_address.type == AT_STRINGZ)) {
        return "bpv7.primary.dst_uri";
    }
    if ((filter == CONV_FT_ANY_ADDRESS) && (
            (item->src_address.type == AT_STRINGZ)
            || (item->dst_address.type == AT_STRINGZ))) {
        return "bpv7.primary.srcdst_uri";
    }
    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t bp_ct_dissector_info = {&bp_conv_get_filter_type};

static tap_packet_status bp_conv_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags) {
    conv_hash_t *hash = (conv_hash_t*) pct;
    const bp_bundle_t *bundle = (const bp_bundle_t *)vip;
    hash->flags = flags;

    add_conversation_table_data(
        hash,
        &(bundle->primary->src_nodeid->uri),
        &(bundle->primary->dst_eid->uri),
        0, 0,
        1, pinfo->fd->pkt_len,
        &pinfo->rel_ts, &pinfo->abs_ts,
        &bp_ct_dissector_info, CONVERSATION_NONE
    );

    return TAP_PACKET_REDRAW;
}

static const char * bp_endp_get_filter_type(endpoint_item_t *item, conv_filter_type_e filter) {
    if ((filter == CONV_FT_SRC_ADDRESS) && (item->myaddress.type == AT_STRINGZ)) {
        return "bpv7.primary.src_uri";
    }
    if ((filter == CONV_FT_DST_ADDRESS) && (item->myaddress.type == AT_STRINGZ)) {
        return "bpv7.primary.dst_uri";
    }
    if ((filter == CONV_FT_ANY_ADDRESS) && (item->myaddress.type == AT_STRINGZ)) {
        return "bpv7.primary.srcdst_uri";
    }
    return CONV_FILTER_INVALID;
}

static et_dissector_info_t bp_endp_dissector_info = {&bp_endp_get_filter_type};

static tap_packet_status bp_endp_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags) {
    conv_hash_t *hash = (conv_hash_t*)pit;
    const bp_bundle_t *bundle = (const bp_bundle_t *)vip;
    hash->flags = flags;

    if (bundle->primary->src_nodeid->uri.type == AT_STRINGZ) {
        add_endpoint_table_data(
            hash, &(bundle->primary->src_nodeid->uri), 0, true,
            1, pinfo->fd->pkt_len,
            &bp_endp_dissector_info, ENDPOINT_NONE
        );
    }
    if (bundle->primary->dst_eid->uri.type == AT_STRINGZ) {
        add_endpoint_table_data(
            hash, &(bundle->primary->dst_eid->uri), 0, false,
            1, pinfo->fd->pkt_len,
            &bp_endp_dissector_info, ENDPOINT_NONE
        );
    }
    return TAP_PACKET_REDRAW;
}

static bool bp_filter_valid(packet_info *pinfo, void *user_data _U_) {
    const bp_bundle_t *bundle = p_get_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE);
    return bundle != NULL;
}

static char * bp_build_filter(packet_info *pinfo, void *user_data _U_) {
    const bp_bundle_t *bundle = p_get_proto_data(pinfo->pool, pinfo, proto_bp, PROTO_DATA_BUNDLE);
    if (!bundle) {
        return NULL;
    }

    return ws_strdup_printf(
        "bpv7.primary.srcdst_uri == \"%s\" and bpv7.primary.srcdst_uri == \"%s\"",
        address_to_name(&(bundle->primary->src_nodeid->uri)),
        address_to_name(&(bundle->primary->dst_eid->uri))
    );
}

/// Overall registration of the protocol
void proto_register_bpv7(void) {
    proto_bp = proto_register_protocol("DTN Bundle Protocol Version 7", "BPv7", "bpv7");
    register_init_routine(&bp_init);
    register_cleanup_routine(&bp_cleanup);

    proto_register_field_array(proto_bp, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bp);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    register_dissector("bpv7", dissect_bp, proto_bp);
    block_dissectors = register_custom_dissector_table("bpv7.block_type", "BPv7 Block", proto_bp, g_int64_hash, g_int64_equal, g_free);
    // Blocks don't count as protocol layers
    proto_blocktype = proto_register_protocol_in_name_only("BPv7 Block Type", "Block Type", "bpv7.block_type", proto_bp, FT_PROTOCOL);

    // case-sensitive string matching
    payload_dissectors_dtn_wkssp = register_dissector_table("bpv7.payload.dtn_wkssp", "BPv7 DTN-scheme well-known SSP", proto_bp, FT_STRING, STRING_CASE_SENSITIVE);

    payload_dissectors_dtn_serv = register_dissector_table("bpv7.payload.dtn_serv", "BPv7 DTN-scheme service", proto_bp, FT_STRING, STRING_CASE_SENSITIVE);
    dissector_table_allow_decode_as(payload_dissectors_dtn_serv);

    static build_valid_func dtn_serv_da_build_value[1] = {dtn_serv_value};
    static decode_as_value_t dtn_serv_da_values[1] = {
        {dtn_serv_prompt, 1, dtn_serv_da_build_value}
    };
    static decode_as_t dtn_serv_da = {
        "bpv7", "bpv7.payload.dtn_serv",
        1, 0, dtn_serv_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset,
        decode_as_default_change, NULL
    };
    register_decode_as(&dtn_serv_da);

    payload_dissectors_ipn_serv = register_dissector_table("bpv7.payload.ipn_serv", "BPv7 IPN-scheme service", proto_bp, FT_UINT32, BASE_DEC);
    dissector_table_allow_decode_as(payload_dissectors_ipn_serv);

    static build_valid_func ipn_serv_da_build_value[1] = {ipn_serv_value};
    static decode_as_value_t ipn_serv_da_values[1] = {
        {ipn_serv_prompt, 1, ipn_serv_da_build_value}
    };
    static decode_as_t ipn_serv_da = {
        "bpv7", "bpv7.payload.ipn_serv",
        1, 0, ipn_serv_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset,
        decode_as_default_change, NULL
    };
    register_decode_as(&ipn_serv_da);

    module_t *module_bp = prefs_register_protocol(proto_bp, bp_reinit_config);
    prefs_register_bool_preference(
        module_bp,
        "bp_compute_crc",
        "Compute and compare CRCs",
        "If enabled, the blocks will have CRC checks performed.",
        &bp_compute_crc
    );
    prefs_register_bool_preference(
        module_bp,
        "bp_reassemble_payload",
        "Reassemble fragmented payloads",
        "Whether the dissector should reassemble fragmented bundle payloads.",
        &bp_reassemble_payload
    );
    prefs_register_bool_preference(
        module_bp,
        "bp_payload_try_heur",
        "Attempt heuristic dissection of BTSD/payload",
        "When dissecting block type-specific data and payload and no destination matches, attempt heuristic dissection.",
        &bp_payload_try_heur
    );

    reassembly_table_register(
        &bp_reassembly_table,
        &bundle_reassembly_table_functions
    );

    btsd_heur = register_heur_dissector_list_with_description("bpv7.btsd", "BPv7 block data fallback", proto_bp);

    bp_tap = register_tap("bpv7");
    register_conversation_table(proto_bp, true, bp_conv_packet, bp_endp_packet);
    register_conversation_filter("bpv7", "BPv7", bp_filter_valid, bp_build_filter, NULL);

    proto_bp_admin = proto_register_protocol("BPv7 Administrative Record", "BPv7 Admin", "bpv7.admin_rec");
    handle_admin = register_dissector("bpv7.admin_rec", dissect_payload_admin, proto_bp_admin);
    admin_dissectors = register_custom_dissector_table("bpv7.admin_record_type", "BPv7 Administrative Record Type", proto_bp_admin, g_int64_hash, g_int64_equal, g_free);
    proto_admintype = proto_register_protocol_in_name_only("BPv7 Administrative Record Type", "Admin Type", "bpv7.admin_record_type", proto_bp, FT_PROTOCOL);
}

void proto_reg_handoff_bpv7(void) {
    const int proto_cbor = proto_get_id_by_filter_name("cbor");
    heur_dissector_add("bpv7.btsd", btsd_heur_cbor, "CBOR in Bundle BTSD", "cbor_bpv7", proto_cbor, HEURISTIC_ENABLE);

    handle_cbor = find_dissector("cbor");
    handle_cborseq = find_dissector("cborseq");

    /* Packaged extensions */
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_BLOCKTYPE_PAYLOAD;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_block_payload, proto_blocktype, NULL, "Payload");
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_BLOCKTYPE_PREV_NODE;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_block_prev_node, proto_blocktype, NULL, "Previous Node");
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_BLOCKTYPE_BUNDLE_AGE;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_block_bundle_age, proto_blocktype, NULL, "Bundle Age");
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_BLOCKTYPE_HOP_COUNT;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_block_hop_count, proto_blocktype, NULL, "Hop Count");
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_ADMINTYPE_BUNDLE_STATUS;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_status_report, proto_admintype, NULL, "Bundle Status Report");
        dissector_add_custom_table_handle("bpv7.admin_record_type", key, hdl);
    }

    bp_reinit_config();
}
