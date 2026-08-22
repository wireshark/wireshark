/* packet-tcg-storage.c
 * TCG Storage Workgroup security-protocol dissector (Opal/Pyrite/Enterprise)
 * Copyright 2026, Brandon Chiu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* References:
 *   TCG Storage Architecture Core Specification, Version 2.01
 *   (ComPacket/Packet/Subpacket framing §3.2.3; protocol layer /
 *   ComID management, Security Protocol 02h, §3.3.10)
 *   TCG Storage Security Subsystem Classes: Opal, Pyrite, Enterprise
 *   https://trustedcomputinggroup.org/work-groups/storage/
 *
 * Carried over NVMe Security Send/Security Receive (dispatched by
 * packet-nvme.c through the "nvme.security.secp" dissector table with
 * struct nvme_security_info as the data pointer).
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-nvme.h"

void proto_register_tcg_storage(void);
void proto_reg_handoff_tcg_storage(void);

static int proto_tcg_storage;

static dissector_handle_t tcg_storage_handle;

/* ComPacket header */
static int hf_tcg_compacket;
static int hf_tcg_compacket_reserved;
static int hf_tcg_compacket_comid;
static int hf_tcg_compacket_comid_ext;
static int hf_tcg_compacket_outstanding;
static int hf_tcg_compacket_min_transfer;
static int hf_tcg_compacket_length;
/* Packet header */
static int hf_tcg_packet;
static int hf_tcg_packet_tsn;
static int hf_tcg_packet_hsn;
static int hf_tcg_packet_seq;
static int hf_tcg_packet_reserved;
static int hf_tcg_packet_ack_type;
static int hf_tcg_packet_ack;
static int hf_tcg_packet_length;
/* Subpacket header */
static int hf_tcg_subpacket;
static int hf_tcg_subpacket_reserved;
static int hf_tcg_subpacket_kind;
static int hf_tcg_subpacket_length;
static int hf_tcg_subpacket_credit;
static int hf_tcg_subpacket_pad;
/* Token stream */
static int hf_tcg_token_stream;
static int hf_tcg_tok_uint;
static int hf_tcg_tok_int;
static int hf_tcg_tok_bytes;
static int hf_tcg_tok_uid;
static int hf_tcg_tok_control;
static int hf_tcg_tok_status;
/* Level 0 Discovery */
static int hf_tcg_level0_discovery;
static int hf_tcg_l0_length;
static int hf_tcg_l0_major_version;
static int hf_tcg_l0_minor_version;
static int hf_tcg_l0_reserved;
static int hf_tcg_l0_vendor;
/* Feature descriptor common header */
static int hf_tcg_l0_feat;
static int hf_tcg_l0_feat_code;
static int hf_tcg_l0_feat_version;
static int hf_tcg_l0_feat_reserved;
static int hf_tcg_l0_feat_ssc_minor;
static int hf_tcg_l0_feat_length;
static int hf_tcg_l0_feat_data;
/* TPer Feature (0x0001) */
static int hf_tcg_l0_tper_flags;
static int hf_tcg_l0_tper_comid_mgmt;
static int hf_tcg_l0_tper_streaming;
static int hf_tcg_l0_tper_buffer_mgmt;
static int hf_tcg_l0_tper_acknak;
static int hf_tcg_l0_tper_async;
static int hf_tcg_l0_tper_sync;
/* Locking Feature (0x0002) */
static int hf_tcg_l0_locking_flags;
static int hf_tcg_l0_locking_supported;
static int hf_tcg_l0_locking_enabled;
static int hf_tcg_l0_locking_locked;
static int hf_tcg_l0_locking_media_encryption;
static int hf_tcg_l0_locking_mbr_enabled;
static int hf_tcg_l0_locking_mbr_done;
static int hf_tcg_l0_locking_mbr_shadowing_not_supported;
static int hf_tcg_l0_locking_hw_reset;
/* Geometry Reporting Feature (0x0003) */
static int hf_tcg_l0_geometry_flags;
static int hf_tcg_l0_geometry_align;
static int hf_tcg_l0_geometry_reserved;
static int hf_tcg_l0_geometry_lbs;
static int hf_tcg_l0_geometry_granularity;
static int hf_tcg_l0_geometry_lowest_lba;
/* SIIS Feature (0x0005) */
static int hf_tcg_l0_siis_revision;
static int hf_tcg_l0_siis_flags;
static int hf_tcg_l0_siis_id_usage_scope;
static int hf_tcg_l0_siis_key_change_zone;
/* Enterprise SSC Feature (0x0100) */
static int hf_tcg_l0_ent_base_comid;
static int hf_tcg_l0_ent_num_comids;
static int hf_tcg_l0_ent_flags;
static int hf_tcg_l0_ent_range_crossing;
/* Opal SSC 1.00 Feature (0x0200) */
static int hf_tcg_l0_opal1_base_comid;
static int hf_tcg_l0_opal1_num_comids;
static int hf_tcg_l0_opal1_flags;
static int hf_tcg_l0_opal1_range_crossing;
/* Opal SSC 2.x Feature (0x0203) */
static int hf_tcg_l0_opal2_base_comid;
static int hf_tcg_l0_opal2_num_comids;
static int hf_tcg_l0_opal2_flags;
static int hf_tcg_l0_opal2_range_crossing;
static int hf_tcg_l0_opal2_num_admins;
static int hf_tcg_l0_opal2_num_users;
static int hf_tcg_l0_opal2_initial_cpin_sid;
static int hf_tcg_l0_opal2_revert_cpin_sid;
static int hf_tcg_l0_opal2_reserved;
/* Single User Mode Feature (0x0201) */
static int hf_tcg_l0_sum_num_objects;
static int hf_tcg_l0_sum_flags;
static int hf_tcg_l0_sum_any;
static int hf_tcg_l0_sum_all;
static int hf_tcg_l0_sum_policy;
/* DataStore Table Feature (0x0202) */
static int hf_tcg_l0_ds_reserved;
static int hf_tcg_l0_ds_max_tables;
static int hf_tcg_l0_ds_max_size;
static int hf_tcg_l0_ds_alignment;
/* Opalite / Pyrite 1.0 / Pyrite 2.0 SSC (0x0301-0x0303); Ruby SSC (0x0304)
 * uses the Opal 2.x descriptor layout instead. */
static int hf_tcg_l0_ssc_base_comid;
static int hf_tcg_l0_ssc_num_comids;
static int hf_tcg_l0_ssc_reserved;
static int hf_tcg_l0_ssc_initial_cpin_sid;
static int hf_tcg_l0_ssc_revert_cpin_sid;
/* Block SID Authentication Feature (0x0402) */
static int hf_tcg_l0_bsid_flags;
static int hf_tcg_l0_bsid_sid_value_state;
static int hf_tcg_l0_bsid_sid_blocked_state;
static int hf_tcg_l0_bsid_flags2;
static int hf_tcg_l0_bsid_hw_reset;
/* Configurable Namespace Locking Feature (0x0403) */
static int hf_tcg_l0_cnl_flags;
static int hf_tcg_l0_cnl_range_c;
static int hf_tcg_l0_cnl_range_p;
static int hf_tcg_l0_cnl_sum_c;
static int hf_tcg_l0_cnl_reserved;
static int hf_tcg_l0_cnl_max_key_count;
static int hf_tcg_l0_cnl_unused_key_count;
static int hf_tcg_l0_cnl_max_ranges_per_ns;
/* Data Removal Mechanism Feature (0x0404) */
static int hf_tcg_l0_drm_reserved;
static int hf_tcg_l0_drm_reserved1;
static int hf_tcg_l0_drm_flags;
static int hf_tcg_l0_drm_processing;
static int hf_tcg_l0_drm_interrupted;
static int hf_tcg_l0_drm_mechanism;
static int hf_tcg_l0_drm_mech_overwrite;
static int hf_tcg_l0_drm_mech_block_erase;
static int hf_tcg_l0_drm_mech_crypto_erase;
static int hf_tcg_l0_drm_mech_vendor;
static int hf_tcg_l0_drm_format;
static int hf_tcg_l0_drm_fmt_overwrite;
static int hf_tcg_l0_drm_fmt_block_erase;
static int hf_tcg_l0_drm_fmt_crypto_erase;
static int hf_tcg_l0_drm_fmt_vendor;
static int hf_tcg_l0_drm_time_overwrite;
static int hf_tcg_l0_drm_time_block_erase;
static int hf_tcg_l0_drm_time_crypto_erase;
static int hf_tcg_l0_drm_time_vendor;
/* SECP 02h ComID management */
static int hf_tcg_comid_mgmt_comid;
static int hf_tcg_comid_mgmt_comid_ext;
static int hf_tcg_comid_mgmt_request_code;
static int hf_tcg_comid_mgmt_avail_len;
static int hf_tcg_comid_mgmt_reserved;
static int hf_tcg_comid_mgmt_data;
/* SECP 02h GET COMID */
static int hf_tcg_comid_get_ext_comid;
/* Fallbacks */
static int hf_tcg_padding;
static int hf_tcg_raw_data;

static int ett_tcg_storage;
static int ett_tcg_compacket;
static int ett_tcg_packet;
static int ett_tcg_session;
static int ett_tcg_subpacket;
static int ett_tcg_token_stream;
static int ett_tcg_tok_seq;
static int ett_tcg_comid_mgmt;
static int ett_tcg_l0;
static int ett_tcg_l0_feat;
static int ett_tcg_l0_tper_flags;
static int ett_tcg_l0_locking_flags;
static int ett_tcg_l0_geometry_flags;
static int ett_tcg_l0_siis_flags;
static int ett_tcg_l0_ent_flags;
static int ett_tcg_l0_opal1_flags;
static int ett_tcg_l0_opal2_flags;
static int ett_tcg_l0_sum_flags;
static int ett_tcg_l0_bsid_flags;
static int ett_tcg_l0_bsid_flags2;
static int ett_tcg_l0_cnl_flags;
static int ett_tcg_l0_drm_flags;
static int ett_tcg_l0_drm_mechanism;
static int ett_tcg_l0_drm_format;

static expert_field ei_tcg_truncated;
static expert_field ei_tcg_length_overrun;
static expert_field ei_tcg_tok_reserved;
static expert_field ei_tcg_tok_status_range;
static expert_field ei_tcg_feat_length_align;

/* Security Protocol values (SPC-5 / NVMe Security Send/Receive SECP).  Only
 * 01h and 02h are defined for NVMe: SIIS Tables 17 and 18 state that
 * "Security Protocol 0x06 is not defined for NVMe" (06h is the byte-granular
 * SCSI-only variant), so it is deliberately not registered here. */
#define TCG_SECP_COMPACKET  0x01
#define TCG_SECP_PROTO_MGMT 0x02

/* Level 0 Discovery is requested with SECP 01h, ComID (SPSP) 0001h */
#define TCG_COMID_LEVEL0_DISCOVERY 0x0001

/* TPer Reset is an IF-SEND with SECP 02h and ComID (SPSP) 0004h; the transfer
 * length is non-zero and the payload is ignored by the TPer, and there is no
 * IF-RECV response (Opal SSC 2.02 Table 14). */
#define TCG_COMID_TPER_RESET 0x0004

/* GET COMID is an IF-RECV with SECP 02h and ComID (SPSP) 0000h; the response
 * payload is only a 4-byte Extended ComID, not a ComID management header
 * (Core Spec §3.3.4.3.1 Tables 27 and 28). */
#define TCG_COMID_GET_COMID 0x0000

#define TCG_COMPACKET_HDR_LEN 20
#define TCG_PACKET_HDR_LEN    24
#define TCG_SUBPACKET_HDR_LEN 12

#define TCG_SUBPACKET_KIND_DATA   0x0000
#define TCG_SUBPACKET_KIND_CREDIT 0x8001

/* Token stream control tokens (Core Spec §3.2.2) */
#define TCG_TOK_START_LIST  0xF0
#define TCG_TOK_END_LIST    0xF1
#define TCG_TOK_START_NAME  0xF2
#define TCG_TOK_END_NAME    0xF3
#define TCG_TOK_CALL        0xF8
#define TCG_TOK_END_OF_DATA 0xF9
#define TCG_TOK_END_SESSION 0xFA
#define TCG_TOK_START_TXN   0xFB
#define TCG_TOK_END_TXN     0xFC
#define TCG_TOK_EMPTY       0xFF

/* Maximum list/name nesting rendered with distinct subtrees; deeper
 * content stays at the maximum level. */
#define TCG_TOK_MAX_NEST 32

/* Level 0 Discovery (Core Spec §3.3.6) */
#define TCG_L0_HDR_LEN      48
#define TCG_L0_FEAT_HDR_LEN 4

#define TCG_L0_FEAT_TPER         0x0001
#define TCG_L0_FEAT_LOCKING      0x0002
#define TCG_L0_FEAT_GEOMETRY     0x0003
/* SIIS v1.20 §3.6 Table 2; Mandatory since SIIS v1.10 */
#define TCG_L0_FEAT_SIIS         0x0005
#define TCG_L0_FEAT_ENTERPRISE   0x0100
#define TCG_L0_FEAT_OPAL_V1      0x0200
#define TCG_L0_FEAT_SUM          0x0201
#define TCG_L0_FEAT_DATASTORE    0x0202
#define TCG_L0_FEAT_OPAL_V2      0x0203
#define TCG_L0_FEAT_OPALITE      0x0301
#define TCG_L0_FEAT_PYRITE_V1    0x0302
#define TCG_L0_FEAT_PYRITE_V2    0x0303
#define TCG_L0_FEAT_RUBY         0x0304
#define TCG_L0_FEAT_BLOCK_SID    0x0402
#define TCG_L0_FEAT_CNL          0x0403
#define TCG_L0_FEAT_DATA_REMOVAL 0x0404
/* SIIS v1.20 §4.7.7 / §5.7.3 name this feature code; the descriptor layout
 * is defined by a feature-set specification that is not available here, so
 * only the name is decoded and the body is rendered raw. */
#define TCG_L0_FEAT_NS_GEOMETRY  0x0405

/* Vendor-specific feature code range */
#define TCG_L0_FEAT_VENDOR_FIRST 0xC000

static const value_string tcg_ack_type_vals[] = {
    { 0, "None" },
    { 1, "ACK" },
    { 2, "NAK" },
    { 0, NULL },
};

static const value_string tcg_subpacket_kind_vals[] = {
    { TCG_SUBPACKET_KIND_DATA,   "Data" },
    { TCG_SUBPACKET_KIND_CREDIT, "Credit Control" },
    { 0, NULL },
};

static const value_string tcg_token_control_vals[] = {
    { 0xE4,                "Reserved" },
    { 0xE5,                "Reserved" },
    { 0xE6,                "Reserved" },
    { 0xE7,                "Reserved" },
    { 0xE8,                "Reserved" },
    { 0xE9,                "Reserved" },
    { 0xEA,                "Reserved" },
    { 0xEB,                "Reserved" },
    { 0xEC,                "Reserved" },
    { 0xED,                "Reserved" },
    { 0xEE,                "Reserved" },
    { 0xEF,                "Reserved" },
    { TCG_TOK_START_LIST,  "Start List" },
    { TCG_TOK_END_LIST,    "End List" },
    { TCG_TOK_START_NAME,  "Start Name" },
    { TCG_TOK_END_NAME,    "End Name" },
    { 0xF4,                "Reserved" },
    { 0xF5,                "Reserved" },
    { 0xF6,                "Reserved" },
    { 0xF7,                "Reserved" },
    { TCG_TOK_CALL,        "Call" },
    { TCG_TOK_END_OF_DATA, "End of Data" },
    { TCG_TOK_END_SESSION, "End of Session" },
    { TCG_TOK_START_TXN,   "Start Transaction" },
    { TCG_TOK_END_TXN,     "End Transaction" },
    { 0xFD,                "Reserved" },
    { 0xFE,                "Reserved" },
    { TCG_TOK_EMPTY,       "Empty" },
    { 0, NULL },
};

/* Well-known 8-byte UIDs (Core Spec §5.2; Opal SSC).  Unknown UIDs are
 * rendered as plain hex by the BASE_VAL64_STRING fallback. */
static const val64_string tcg_uid_vals[] = {
    { 0x0000000000000000, "Null UID" },
    { 0x0000000000000001, "This SP" },
    { 0x00000000000000FF, "Session Manager (SMUID)" },
    /* Session Manager methods */
    { 0x000000000000FF01, "Properties" },
    { 0x000000000000FF02, "StartSession" },
    { 0x000000000000FF03, "SyncSession" },
    { 0x000000000000FF04, "StartTrustedSession" },
    { 0x000000000000FF05, "SyncTrustedSession" },
    { 0x000000000000FF06, "CloseSession" },
    /* MethodID UIDs (Core Spec §6.3 Assigned UIDs).  0006h/0007h/000Ch are
     * the Enterprise SSC variants of Get/Set/Authenticate; Opal uses
     * 0016h/0017h/001Ch. */
    { 0x0000000600000006, "Get (Enterprise)" },
    { 0x0000000600000007, "Set (Enterprise)" },
    { 0x0000000600000008, "Next" },
    { 0x000000060000000C, "Authenticate (Enterprise)" },
    { 0x000000060000000D, "GetACL" },
    { 0x0000000600000010, "GenKey" },
    { 0x0000000600000011, "RevertSP" },
    { 0x0000000600000016, "Get" },
    { 0x0000000600000017, "Set" },
    { 0x000000060000001C, "Authenticate" },
    { 0x0000000600000202, "Revert" },
    { 0x0000000600000203, "Activate" },
    { 0x0000000600000601, "Random" },
    { 0x0000000600000803, "Erase (Enterprise)" },
    /* SP UIDs */
    { 0x0000020500000001, "Admin SP" },
    { 0x0000020500000002, "Locking SP" },
    { 0x0000020500010001, "Locking SP (Enterprise)" },
    /* Authority UIDs */
    { 0x0000000900000001, "Anybody" },
    { 0x0000000900000002, "Admins" },
    { 0x0000000900000003, "Makers" },
    { 0x0000000900000006, "SID" },
    { 0x0000000900010001, "Admin1" },
    { 0x0000000900030001, "User1" },
    { 0x0000000900030002, "User2" },
    /* C_PIN UIDs */
    { 0x0000000B00000001, "C_PIN_SID" },
    { 0x0000000B00008402, "C_PIN_MSID" },
    { 0x0000000B00010001, "C_PIN_Admin1" },
    { 0x0000000B00030001, "C_PIN_User1" },
    /* Locking objects */
    { 0x0000080100000001, "LockingInfo" },
    { 0x0000080200000001, "Locking_GlobalRange" },
    { 0x0000080200030001, "Locking_Range1" },
    { 0x0000080200030002, "Locking_Range2" },
    { 0x0000080300000001, "MBRControl" },
    { 0x0000080400000000, "MBR (Shadow MBR table)" },
    { 0, NULL },
};

/* Method Status codes (Core Spec §5.1.5 Table 166).  Table 166 runs from
 * 0x00 to 0x12 and then jumps to 0x3F; note that it skips 0x0B, which is
 * therefore left undefined here rather than being named. */
static const value_string tcg_method_status_vals[] = {
    { 0x00, "SUCCESS" },
    { 0x01, "NOT_AUTHORIZED" },
    { 0x02, "OBSOLETE" },
    { 0x03, "SP_BUSY" },
    { 0x04, "SP_FAILED" },
    { 0x05, "SP_DISABLED" },
    { 0x06, "SP_FROZEN" },
    { 0x07, "NO_SESSIONS_AVAILABLE" },
    { 0x08, "UNIQUENESS_CONFLICT" },
    { 0x09, "INSUFFICIENT_SPACE" },
    { 0x0A, "INSUFFICIENT_ROWS" },
    { 0x0C, "INVALID_PARAMETER" },
    { 0x0D, "INVALID_REFERENCE (obsolete)" },
    { 0x0E, "OBSOLETE" },
    { 0x0F, "TPER_MALFUNCTION" },
    { 0x10, "TRANSACTION_FAILURE" },
    { 0x11, "RESPONSE_OVERFLOW" },
    { 0x12, "AUTHORITY_LOCKED_OUT" },
    { 0x3F, "FAIL" },
    { 0, NULL },
};

/* Protocol-layer request codes (Core Spec §3.3.10) */
static const value_string tcg_request_code_vals[] = {
    { 0x00000001, "VERIFY COMID VALID" },
    { 0x00000002, "PROTOCOL STACK RESET" },
    { 0, NULL },
};

static const value_string tcg_l0_feature_code_vals[] = {
    { TCG_L0_FEAT_TPER,         "TPer Feature" },
    { TCG_L0_FEAT_LOCKING,      "Locking Feature" },
    { TCG_L0_FEAT_GEOMETRY,     "Geometry Reporting Feature" },
    { TCG_L0_FEAT_SIIS,         "SIIS Feature" },
    { TCG_L0_FEAT_ENTERPRISE,   "Enterprise SSC Feature" },
    { TCG_L0_FEAT_OPAL_V1,      "Opal SSC 1.00 Feature" },
    { TCG_L0_FEAT_SUM,          "Single User Mode Feature" },
    { TCG_L0_FEAT_DATASTORE,    "DataStore Table Feature" },
    { TCG_L0_FEAT_OPAL_V2,      "Opal SSC 2.x Feature" },
    { TCG_L0_FEAT_OPALITE,      "Opalite SSC Feature" },
    { TCG_L0_FEAT_PYRITE_V1,    "Pyrite SSC 1.0 Feature" },
    { TCG_L0_FEAT_PYRITE_V2,    "Pyrite SSC 2.0 Feature" },
    { TCG_L0_FEAT_RUBY,         "Ruby SSC Feature" },
    { TCG_L0_FEAT_BLOCK_SID,    "Block SID Authentication Feature" },
    { TCG_L0_FEAT_CNL,          "Configurable Namespace Locking Feature" },
    { TCG_L0_FEAT_DATA_REMOVAL, "Data Removal Mechanism Feature" },
    { TCG_L0_FEAT_NS_GEOMETRY,  "Namespace Geometry Reporting Feature" },
    { 0, NULL },
};

/* SIIS v1.20 Table 4 */
static const value_string tcg_l0_siis_id_scope_vals[] = {
    { 0x0, "Not indicated" },
    { 0x1, "Transport identifier not used for Persistent Reservation impact" },
    { 0x2, "Transport identifier used for Persistent Reservation impact" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* The low nibble of a feature descriptor's version byte is Reserved for every
 * feature except Opal SSC V2, where it is the SSC Minor Version Number
 * (Opal SSC 2.02 Tables 7 and 8). */
static const value_string tcg_l0_opal2_minor_vals[] = {
    { 0x0, "Opal SSC 2.00" },
    { 0x1, "Opal SSC 2.01" },
    { 0x2, "Opal SSC 2.02" },
    { 0, NULL },
};

/* Short SSC names appended to COL_INFO and the Level 0 Discovery item */
static const value_string tcg_l0_ssc_name_vals[] = {
    { TCG_L0_FEAT_ENTERPRISE, "Enterprise" },
    { TCG_L0_FEAT_OPAL_V1,    "Opal 1.00" },
    { TCG_L0_FEAT_OPAL_V2,    "Opal 2.x" },
    { TCG_L0_FEAT_OPALITE,    "Opalite" },
    { TCG_L0_FEAT_PYRITE_V1,  "Pyrite 1.0" },
    { TCG_L0_FEAT_PYRITE_V2,  "Pyrite 2.0" },
    { TCG_L0_FEAT_RUBY,       "Ruby" },
    { 0, NULL },
};

static const true_false_string tfs_tcg_l0_drm_fmt = {
    "Minutes (value x2)",
    "Seconds (value x2)",
};

/*
 * Token stream (Data subpacket payload) — TCG byte-stream encoding
 * (Core Spec §3.2.2).  Iterative token walk (no recursion); Start
 * List/Name nesting is presented with subtrees tracked by a small
 * explicit stack bounded at TCG_TOK_MAX_NEST levels (deeper content
 * stays at the maximum level).  Every atom length is clamped against
 * the remaining stream and each iteration consumes at least one byte,
 * so the loop always terminates.
 *
 * A Call token followed by two 8-byte byte-sequence atoms is recognized
 * as a method invocation ("Invoking.Method()" in COL_INFO); the first
 * unsigned integer atom in the list following an End of Data token is
 * decoded as the Method Status.
 */
static void
dissect_tcg_token_stream(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, int offset, int len)
{
    proto_tree *stack_tree[TCG_TOK_MAX_NEST];
    proto_item *stack_item[TCG_TOK_MAX_NEST];
    int         stack_start[TCG_TOK_MAX_NEST];
    int         depth = 0, overflow = 0;
    proto_item *ts_item;
    proto_tree *ts_tree;
    int         end = offset + len;
    enum { CALL_NONE = 0, CALL_INVOKING, CALL_METHOD };
    int         call_state = CALL_NONE;
    const char *invoking_name = NULL;
    bool        eod_seen = false;
    bool        awaiting_status = false;
    int         status_depth = 0;

    if (len <= 0)
        return;

    ts_item = proto_tree_add_item(tree, hf_tcg_token_stream, tvb, offset,
                                  len, ENC_NA);
    ts_tree = proto_item_add_subtree(ts_item, ett_tcg_token_stream);
    stack_tree[0]  = ts_tree;
    stack_item[0]  = ts_item;
    stack_start[0] = offset;

    while (offset < end) {
        proto_tree *cur = stack_tree[depth];
        uint8_t     b = tvb_get_uint8(tvb, offset);
        int         pending_call = call_state;
        bool        was_eod = eod_seen;
        proto_item *it;
        int         hdr_len, data_len, data_offset, atom_len;
        bool        byte_flag, sign_flag, clamped;

        /* Core Spec §3.2.2.3.1.5: an Empty atom "MAY appear at any point in
         * the stream encoding where any other atom is able to appear ... and
         * it SHALL be ignored"; §3.2.2.4.2 describes the payload structure
         * "(discounting empty atoms)".  Real devices emit them to align
         * values inside a Data subpacket, so an Empty atom must leave every
         * token-adjacency latch (Call and End of Data) exactly as it found
         * it rather than consuming it. */
        if (b == TCG_TOK_EMPTY) {
            proto_tree_add_item(cur, hf_tcg_tok_control, tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;
            continue;
        }

        call_state = CALL_NONE;
        eod_seen = false;

        /* Control / sequence tokens (single byte, 0xF0-0xFF) */
        if (b >= 0xF0) {
            it = proto_tree_add_item(cur, hf_tcg_tok_control, tvb, offset,
                                     1, ENC_BIG_ENDIAN);
            switch (b) {
            case TCG_TOK_START_LIST:
            case TCG_TOK_START_NAME:
                if (depth < TCG_TOK_MAX_NEST - 1) {
                    depth++;
                    stack_tree[depth]  = proto_item_add_subtree(it,
                                                ett_tcg_tok_seq);
                    stack_item[depth]  = it;
                    stack_start[depth] = offset;
                } else {
                    overflow++;
                }
                /* Responses carry the method status as a list right
                 * after End of Data. */
                if (b == TCG_TOK_START_LIST && was_eod) {
                    awaiting_status = true;
                    /* Past TCG_TOK_MAX_NEST the stack stops moving and the
                     * excess levels are counted in `overflow` instead, so the
                     * latch has to be anchored to the combined nesting level
                     * or it could never be released. */
                    status_depth = depth + overflow;
                }
                break;
            case TCG_TOK_END_LIST:
            case TCG_TOK_END_NAME:
                if (overflow > 0) {
                    overflow--;
                } else if (depth > 0) {
                    proto_item_set_len(stack_item[depth],
                                       offset + 1 - stack_start[depth]);
                    depth--;
                }
                /* The status list closed without an integer atom; drop the
                 * expectation so no later atom is decoded as a status. */
                if (awaiting_status && depth + overflow < status_depth)
                    awaiting_status = false;
                break;
            case TCG_TOK_CALL:
                call_state = CALL_INVOKING;
                break;
            case TCG_TOK_END_OF_DATA:
                eod_seen = true;
                break;
            case TCG_TOK_END_SESSION:
            case TCG_TOK_START_TXN:
            case TCG_TOK_END_TXN:
                break;
            default:
                /* 0xF4-0xF7, 0xFD-0xFE */
                expert_add_info(pinfo, it, &ei_tcg_tok_reserved);
                break;
            }
            offset += 1;
            continue;
        }

        /* Tiny Atom: single byte, 6-bit value, bit 6 = Sign */
        if ((b & 0x80) == 0) {
            if (b & 0x40) {
                int64_t sval = b & 0x3F;

                if (sval & 0x20)
                    sval -= 0x40;
                proto_tree_add_int64_format(cur, hf_tcg_tok_int, tvb,
                        offset, 1, sval,
                        "Tiny Atom (signed): %" PRId64, sval);
            } else if (awaiting_status) {
                proto_tree_add_uint(cur, hf_tcg_tok_status, tvb, offset, 1,
                                    b & 0x3F);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",
                        val_to_str_const(b & 0x3F, tcg_method_status_vals,
                                         "Unknown"));
                awaiting_status = false;
            } else {
                proto_tree_add_uint64_format(cur, hf_tcg_tok_uint, tvb,
                        offset, 1, b & 0x3F,
                        "Tiny Atom (unsigned): %u (0x%x)",
                        (unsigned)(b & 0x3F), (unsigned)(b & 0x3F));
            }
            offset += 1;
            continue;
        }

        /* Short / Medium / Long Atom */
        if (b <= 0xBF) {                        /* Short Atom */
            hdr_len   = 1;
            byte_flag = (b & 0x20) != 0;
            sign_flag = (b & 0x10) != 0;
            data_len  = b & 0x0F;
        } else if (b <= 0xDF) {                 /* Medium Atom */
            hdr_len   = 2;
            byte_flag = (b & 0x10) != 0;
            sign_flag = (b & 0x08) != 0;
            data_len  = 0;
        } else if (b <= 0xE3) {                 /* Long Atom (1110 00BS) */
            hdr_len   = 4;
            byte_flag = (b & 0x02) != 0;
            sign_flag = (b & 0x01) != 0;
            data_len  = 0;
        } else {
            /* 0xE4-0xEF: TCG reserved token values (Core Spec §3.2.2.4) */
            it = proto_tree_add_item(cur, hf_tcg_tok_control, tvb, offset,
                                     1, ENC_BIG_ENDIAN);
            expert_add_info(pinfo, it, &ei_tcg_tok_reserved);
            offset += 1;
            continue;
        }
        if (end - offset < hdr_len) {
            it = proto_tree_add_item(cur, hf_tcg_raw_data, tvb, offset,
                                     end - offset, ENC_NA);
            expert_add_info(pinfo, it, &ei_tcg_truncated);
            break;
        }
        if (hdr_len == 2)
            data_len = ((b & 0x07) << 8) | tvb_get_uint8(tvb, offset + 1);
        else if (hdr_len == 4)
            data_len = (int)tvb_get_ntoh24(tvb, offset + 1);

        clamped = false;
        if (data_len > end - offset - hdr_len) {
            data_len = end - offset - hdr_len;
            clamped = true;
        }
        data_offset = offset + hdr_len;
        atom_len    = hdr_len + data_len;

        if (byte_flag) {
            /* Byte-sequence atom; S=1 means "continued".  The item spans only
             * the payload, not the atom header, so the FT_BYTES value stays
             * filterable against the on-wire byte sequence (e.g. a UID). */
            it = proto_tree_add_item(cur, hf_tcg_tok_bytes, tvb,
                                     data_offset, data_len, ENC_NA);
            if (sign_flag)
                proto_item_append_text(it, " (continued)");
            if (data_len == 8) {
                uint64_t    uid = tvb_get_ntoh64(tvb, data_offset);
                const char *name = try_val64_to_str(uid, tcg_uid_vals);
                proto_item *uid_item;

                uid_item = proto_tree_add_uint64(cur, hf_tcg_tok_uid, tvb,
                                                 data_offset, 8, uid);
                proto_item_set_generated(uid_item);
                if (pending_call == CALL_INVOKING) {
                    proto_item_append_text(uid_item, " [Invoking UID]");
                    invoking_name = name ? name :
                            wmem_strdup_printf(pinfo->pool,
                                               "0x%016" PRIx64, uid);
                    call_state = CALL_METHOD;
                } else if (pending_call == CALL_METHOD) {
                    const char *method_name = name ? name :
                            wmem_strdup_printf(pinfo->pool,
                                               "0x%016" PRIx64, uid);

                    proto_item_append_text(uid_item, " [Method UID]");
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s.%s()",
                                    invoking_name, method_name);
                    proto_item_append_text(ts_item, ": %s.%s()",
                                           invoking_name, method_name);
                }
            }
        } else if (data_len <= 8) {
            /* Integer atom */
            uint64_t uval = 0;
            int      i;

            for (i = 0; i < data_len; i++)
                uval = (uval << 8) | tvb_get_uint8(tvb, data_offset + i);
            if (sign_flag) {
                /* Sign-extend from the atom width */
                if (data_len > 0 && data_len < 8 &&
                    (uval & (UINT64_C(1) << (data_len * 8 - 1))))
                    uval |= ~UINT64_C(0) << (data_len * 8);
                it = proto_tree_add_int64_format(cur, hf_tcg_tok_int, tvb,
                        offset, atom_len, (int64_t)uval,
                        "Integer Atom (signed): %" PRId64, (int64_t)uval);
            } else if (awaiting_status) {
                /* Core Spec §3.2.2.4.2 item 5: the first element of the list
                 * that follows End of Data is the Method Status, a value in
                 * 00h-FFh (Table 166).  A wider value is malformed input, so
                 * flag it and drop the expectation — leaving the latch armed
                 * would render some later unrelated integer as a status. */
                awaiting_status = false;
                if (uval <= 0xFF) {
                    it = proto_tree_add_uint(cur, hf_tcg_tok_status, tvb,
                                             offset, atom_len, (uint32_t)uval);
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",
                            val_to_str_const((uint32_t)uval,
                                             tcg_method_status_vals,
                                             "Unknown"));
                } else {
                    it = proto_tree_add_uint64_format(cur, hf_tcg_tok_uint,
                            tvb, offset, atom_len, uval,
                            "Integer Atom (unsigned): %" PRIu64
                            " (0x%" PRIx64 ")", uval, uval);
                    expert_add_info(pinfo, it, &ei_tcg_tok_status_range);
                }
            } else {
                it = proto_tree_add_uint64_format(cur, hf_tcg_tok_uint,
                        tvb, offset, atom_len, uval,
                        "Integer Atom (unsigned): %" PRIu64
                        " (0x%" PRIx64 ")", uval, uval);
            }
        } else {
            /* Integer wider than 64 bits: render the data raw */
            it = proto_tree_add_item(cur, hf_tcg_tok_bytes, tvb,
                                     data_offset, data_len, ENC_NA);
            proto_item_append_text(it,
                    " (integer atom wider than 64 bits)");
        }

        if (clamped) {
            expert_add_info(pinfo, it, &ei_tcg_length_overrun);
            break;
        }
        offset += atom_len;
    }

    /* Stretch any unterminated Start List/Name subtrees to the end of
     * the stream so their highlight covers the enclosed tokens. */
    for (; depth > 0; depth--)
        proto_item_set_len(stack_item[depth], end - stack_start[depth]);
}

/*
 * Level 0 Discovery response (SECP 01h, ComID 0001h, receive).
 * Core Spec §3.3.6: a 48-byte discovery header followed by a sequence of
 * feature descriptors, each with a 4-byte common header (Feature Code,
 * Version, Length) and Length bytes of feature data.  All big-endian.
 *
 * Each per-feature decoder bounds-checks against the descriptor's own
 * data length so fields never bleed into the next descriptor; anything
 * shorter than the feature's minimum is rendered raw with a truncation
 * expert info.  Trailing feature data beyond the decoded fields is
 * rendered raw.
 */

static void
dissect_tcg_l0_feat_data(tvbuff_t *tvb, proto_tree *tree, int offset,
                         int len)
{
    if (len > 0)
        proto_tree_add_item(tree, hf_tcg_l0_feat_data, tvb, offset, len,
                            ENC_NA);
}

static void
dissect_tcg_l0_feat_short(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, int offset, int len)
{
    proto_item *ti = proto_tree_add_item(tree, hf_tcg_l0_feat_data, tvb,
                                         offset, len, ENC_NA);
    expert_add_info(pinfo, ti, &ei_tcg_truncated);
}

/* 0x0001 TPer Feature */
static void
dissect_tcg_l0_feat_tper(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, int offset, int data_len)
{
    static int * const tper_flags[] = {
        &hf_tcg_l0_tper_comid_mgmt,
        &hf_tcg_l0_tper_streaming,
        &hf_tcg_l0_tper_buffer_mgmt,
        &hf_tcg_l0_tper_acknak,
        &hf_tcg_l0_tper_async,
        &hf_tcg_l0_tper_sync,
        NULL,
    };

    if (data_len < 1) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, offset, hf_tcg_l0_tper_flags,
                           ett_tcg_l0_tper_flags, tper_flags,
                           ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 1, data_len - 1);
}

/* 0x0002 Locking Feature */
static void
dissect_tcg_l0_feat_locking(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, int offset, int data_len)
{
    static int * const locking_flags[] = {
        &hf_tcg_l0_locking_hw_reset,
        &hf_tcg_l0_locking_mbr_shadowing_not_supported,
        &hf_tcg_l0_locking_mbr_done,
        &hf_tcg_l0_locking_mbr_enabled,
        &hf_tcg_l0_locking_media_encryption,
        &hf_tcg_l0_locking_locked,
        &hf_tcg_l0_locking_enabled,
        &hf_tcg_l0_locking_supported,
        NULL,
    };

    if (data_len < 1) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, offset, hf_tcg_l0_locking_flags,
                           ett_tcg_l0_locking_flags, locking_flags,
                           ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 1, data_len - 1);
}

/* 0x0003 Geometry Reporting Feature */
static void
dissect_tcg_l0_feat_geometry(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, int offset, int data_len)
{
    static int * const geometry_flags[] = {
        &hf_tcg_l0_geometry_align,
        NULL,
    };

    if (data_len < 28) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, offset, hf_tcg_l0_geometry_flags,
                           ett_tcg_l0_geometry_flags, geometry_flags,
                           ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_geometry_reserved, tvb, offset + 1,
                        7, ENC_NA);
    proto_tree_add_item(tree, hf_tcg_l0_geometry_lbs, tvb, offset + 8, 4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_geometry_granularity, tvb,
                        offset + 12, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_geometry_lowest_lba, tvb,
                        offset + 20, 8, ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 28, data_len - 28);
}

/* 0x0005 SIIS Feature (SIIS v1.20 §3.6 Table 2).  Data byte 0 is the SIIS
 * Revision Number, data byte 1 carries the Identifier Usage Scope (bits 2:1,
 * Table 4) and the Key Change Zone Behavior bit (bit 0); the rest is
 * Reserved. */
static void
dissect_tcg_l0_feat_siis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         int offset, int data_len)
{
    static int * const siis_flags[] = {
        &hf_tcg_l0_siis_id_usage_scope,
        &hf_tcg_l0_siis_key_change_zone,
        NULL,
    };

    if (data_len < 2) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_siis_revision, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 1, hf_tcg_l0_siis_flags,
                           ett_tcg_l0_siis_flags, siis_flags,
                           ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 2, data_len - 2);
}

/* 0x0100 Enterprise SSC / 0x0200 Opal SSC 1.00 (shared layout) */
static void
dissect_tcg_l0_feat_ssc_v1(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, int offset, int data_len,
                           bool enterprise)
{
    static int * const ent_flags[] = {
        &hf_tcg_l0_ent_range_crossing,
        NULL,
    };
    static int * const opal1_flags[] = {
        &hf_tcg_l0_opal1_range_crossing,
        NULL,
    };

    if (data_len < 4) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree,
            enterprise ? hf_tcg_l0_ent_base_comid : hf_tcg_l0_opal1_base_comid,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,
            enterprise ? hf_tcg_l0_ent_num_comids : hf_tcg_l0_opal1_num_comids,
            tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    if (data_len < 5)
        return;
    if (enterprise)
        proto_tree_add_bitmask(tree, tvb, offset + 4, hf_tcg_l0_ent_flags,
                               ett_tcg_l0_ent_flags, ent_flags,
                               ENC_BIG_ENDIAN);
    else
        proto_tree_add_bitmask(tree, tvb, offset + 4, hf_tcg_l0_opal1_flags,
                               ett_tcg_l0_opal1_flags, opal1_flags,
                               ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 5, data_len - 5);
}

/* 0x0203 Opal SSC 2.x */
static void
dissect_tcg_l0_feat_opal_v2(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, int offset, int data_len)
{
    static int * const opal2_flags[] = {
        &hf_tcg_l0_opal2_range_crossing,
        NULL,
    };

    if (data_len < 12) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_opal2_base_comid, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_opal2_num_comids, tvb, offset + 2,
                        2, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 4, hf_tcg_l0_opal2_flags,
                           ett_tcg_l0_opal2_flags, opal2_flags,
                           ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_opal2_num_admins, tvb, offset + 5,
                        2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_opal2_num_users, tvb, offset + 7,
                        2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_opal2_initial_cpin_sid, tvb,
                        offset + 9, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_opal2_revert_cpin_sid, tvb,
                        offset + 10, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_opal2_reserved, tvb, offset + 11,
                        data_len - 11, ENC_NA);
}

/* 0x0201 Single User Mode */
static void
dissect_tcg_l0_feat_sum(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree, int offset, int data_len)
{
    static int * const sum_flags[] = {
        &hf_tcg_l0_sum_policy,
        &hf_tcg_l0_sum_all,
        &hf_tcg_l0_sum_any,
        NULL,
    };

    if (data_len < 5) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_sum_num_objects, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 4, hf_tcg_l0_sum_flags,
                           ett_tcg_l0_sum_flags, sum_flags, ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 5, data_len - 5);
}

/* 0x0202 DataStore Table */
static void
dissect_tcg_l0_feat_datastore(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, int offset, int data_len)
{
    if (data_len < 12) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_ds_reserved, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ds_max_tables, tvb, offset + 2, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ds_max_size, tvb, offset + 4, 4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ds_alignment, tvb, offset + 8, 4,
                        ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 12, data_len - 12);
}

/* 0x0301 Opalite / 0x0302 Pyrite 1.0 / 0x0303 Pyrite 2.0
 * (Opal 2.x-style layout with bytes 8-12 Reserved instead of the authority
 * counts; Pyrite SSC 2.01 Table 6).  Ruby (0x0304) does carry the authority
 * counts and is dissected as Opal 2.x. */
static void
dissect_tcg_l0_feat_ssc_lite(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, int offset, int data_len)
{
    if (data_len < 12) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_ssc_base_comid, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ssc_num_comids, tvb, offset + 2, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ssc_reserved, tvb, offset + 4, 5,
                        ENC_NA);
    proto_tree_add_item(tree, hf_tcg_l0_ssc_initial_cpin_sid, tvb,
                        offset + 9, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ssc_revert_cpin_sid, tvb,
                        offset + 10, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_ssc_reserved, tvb, offset + 11,
                        data_len - 11, ENC_NA);
}

/* 0x0402 Block SID Authentication */
static void
dissect_tcg_l0_feat_block_sid(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, int offset, int data_len)
{
    static int * const bsid_flags[] = {
        &hf_tcg_l0_bsid_sid_blocked_state,
        &hf_tcg_l0_bsid_sid_value_state,
        NULL,
    };
    static int * const bsid_flags2[] = {
        &hf_tcg_l0_bsid_hw_reset,
        NULL,
    };

    if (data_len < 2) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, offset, hf_tcg_l0_bsid_flags,
                           ett_tcg_l0_bsid_flags, bsid_flags,
                           ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 1, hf_tcg_l0_bsid_flags2,
                           ett_tcg_l0_bsid_flags2, bsid_flags2,
                           ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 2, data_len - 2);
}

/* 0x0403 Configurable Namespace Locking */
static void
dissect_tcg_l0_feat_cnl(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree, int offset, int data_len)
{
    static int * const cnl_flags[] = {
        &hf_tcg_l0_cnl_range_c,
        &hf_tcg_l0_cnl_range_p,
        &hf_tcg_l0_cnl_sum_c,
        NULL,
    };

    if (data_len < 12) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, offset, hf_tcg_l0_cnl_flags,
                           ett_tcg_l0_cnl_flags, cnl_flags, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_cnl_reserved, tvb, offset + 1, 3,
                        ENC_NA);
    proto_tree_add_item(tree, hf_tcg_l0_cnl_max_key_count, tvb, offset + 4,
                        4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_cnl_unused_key_count, tvb,
                        offset + 8, 4, ENC_BIG_ENDIAN);
    if (data_len < 16) {
        dissect_tcg_l0_feat_data(tvb, tree, offset + 12, data_len - 12);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_cnl_max_ranges_per_ns, tvb,
                        offset + 12, 4, ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 16, data_len - 16);
}

/* 0x0404 Data Removal Mechanism */
static void
dissect_tcg_l0_feat_data_removal(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, int offset, int data_len)
{
    static int * const drm_flags[] = {
        &hf_tcg_l0_drm_interrupted,
        &hf_tcg_l0_drm_processing,
        NULL,
    };
    static int * const drm_mechanism[] = {
        &hf_tcg_l0_drm_mech_vendor,
        &hf_tcg_l0_drm_mech_crypto_erase,
        &hf_tcg_l0_drm_mech_block_erase,
        &hf_tcg_l0_drm_mech_overwrite,
        NULL,
    };
    static int * const drm_format[] = {
        &hf_tcg_l0_drm_fmt_vendor,
        &hf_tcg_l0_drm_fmt_crypto_erase,
        &hf_tcg_l0_drm_fmt_block_erase,
        &hf_tcg_l0_drm_fmt_overwrite,
        NULL,
    };

    if (data_len < 4) {
        dissect_tcg_l0_feat_short(tvb, pinfo, tree, offset, data_len);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_drm_reserved, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 1, hf_tcg_l0_drm_flags,
                           ett_tcg_l0_drm_flags, drm_flags, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 2, hf_tcg_l0_drm_mechanism,
                           ett_tcg_l0_drm_mechanism, drm_mechanism,
                           ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 3, hf_tcg_l0_drm_format,
                           ett_tcg_l0_drm_format, drm_format,
                           ENC_BIG_ENDIAN);
    /* A Data Removal Time field is defined only for the mechanism bits that
     * are themselves defined: bits 0, 1 and 2 at data offsets 4, 6 and 8,
     * then four Reserved bytes (mechanism bits 3 and 4 are Reserved), then
     * bit 5 (Vendor Specific Erase) at data offset 14. */
    if (data_len < 10) {
        dissect_tcg_l0_feat_data(tvb, tree, offset + 4, data_len - 4);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_drm_time_overwrite, tvb, offset + 4,
                        2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_drm_time_block_erase, tvb,
                        offset + 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_tcg_l0_drm_time_crypto_erase, tvb,
                        offset + 8, 2, ENC_BIG_ENDIAN);
    if (data_len < 16) {
        dissect_tcg_l0_feat_data(tvb, tree, offset + 10, data_len - 10);
        return;
    }
    proto_tree_add_item(tree, hf_tcg_l0_drm_reserved1, tvb, offset + 10, 4,
                        ENC_NA);
    proto_tree_add_item(tree, hf_tcg_l0_drm_time_vendor, tvb, offset + 14, 2,
                        ENC_BIG_ENDIAN);
    dissect_tcg_l0_feat_data(tvb, tree, offset + 16, data_len - 16);
}

static void
dissect_tcg_level0_discovery(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, int offset, int len)
{
    proto_tree   *l0_tree;
    proto_item   *l0_item, *len_item;
    uint32_t      param_len;
    int           param_end;
    wmem_strbuf_t *sscs = wmem_strbuf_new(pinfo->pool, "");

    if (len < TCG_L0_HDR_LEN) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb,
                                             offset, len, ENC_NA);
        expert_add_info(pinfo, ti, &ei_tcg_truncated);
        return;
    }

    l0_item = proto_tree_add_item(tree, hf_tcg_level0_discovery, tvb,
                                  offset, len, ENC_NA);
    l0_tree = proto_item_add_subtree(l0_item, ett_tcg_l0);

    len_item = proto_tree_add_item_ret_uint(l0_tree, hf_tcg_l0_length, tvb,
                                            offset, 4, ENC_BIG_ENDIAN,
                                            &param_len);
    proto_tree_add_item(l0_tree, hf_tcg_l0_major_version, tvb, offset + 4, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(l0_tree, hf_tcg_l0_minor_version, tvb, offset + 6, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(l0_tree, hf_tcg_l0_reserved, tvb, offset + 8, 8,
                        ENC_NA);
    proto_tree_add_item(l0_tree, hf_tcg_l0_vendor, tvb, offset + 16, 32,
                        ENC_NA);

    /* Length counts the valid bytes following the Length field itself */
    if (param_len > (uint32_t)(len - 4)) {
        expert_add_info(pinfo, len_item, &ei_tcg_length_overrun);
        param_len = len - 4;
    }
    param_end = offset + 4 + (int)param_len;
    offset += TCG_L0_HDR_LEN;

    /* Feature descriptors */
    while (offset < param_end) {
        proto_tree *feat_tree;
        proto_item *feat_item, *feat_len_item;
        uint32_t    feat_code, feat_len;
        int         data_len;

        if (param_end - offset < TCG_L0_FEAT_HDR_LEN) {
            proto_item *ti = proto_tree_add_item(l0_tree, hf_tcg_raw_data,
                                                 tvb, offset,
                                                 param_end - offset, ENC_NA);
            expert_add_info(pinfo, ti, &ei_tcg_truncated);
            break;
        }

        feat_code = tvb_get_ntohs(tvb, offset);

        feat_item = proto_tree_add_item(l0_tree, hf_tcg_l0_feat, tvb,
                                        offset, -1, ENC_NA);
        feat_tree = proto_item_add_subtree(feat_item, ett_tcg_l0_feat);
        if (feat_code >= TCG_L0_FEAT_VENDOR_FIRST)
            proto_item_set_text(feat_item, "Vendor Specific Feature"
                                " (0x%04x)", feat_code);
        else
            proto_item_set_text(feat_item, "%s",
                    val_to_str_const(feat_code, tcg_l0_feature_code_vals,
                                     "Unknown Feature"));

        proto_tree_add_item(feat_tree, hf_tcg_l0_feat_code, tvb, offset, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(feat_tree, hf_tcg_l0_feat_version, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(feat_tree,
                            (feat_code == TCG_L0_FEAT_OPAL_V2)
                                ? hf_tcg_l0_feat_ssc_minor
                                : hf_tcg_l0_feat_reserved,
                            tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        feat_len_item = proto_tree_add_item_ret_uint(feat_tree,
                hf_tcg_l0_feat_length, tvb, offset + 3, 1, ENC_BIG_ENDIAN,
                &feat_len);

        /* Core Spec §3.3.6.3.1.3: "This field SHALL be an integral multiple
         * of 4."  A violation shifts every descriptor that follows, which
         * shows up as a cascade of Unknown Feature entries, so name the
         * cause rather than leaving the cascade unexplained. */
        if ((feat_len & 0x03) != 0)
            expert_add_info(pinfo, feat_len_item, &ei_tcg_feat_length_align);

        offset += TCG_L0_FEAT_HDR_LEN;

        data_len = (int)feat_len;
        if (feat_len > (uint32_t)(param_end - offset)) {
            expert_add_info(pinfo, feat_len_item, &ei_tcg_length_overrun);
            data_len = param_end - offset;
        }
        proto_item_set_len(feat_item, TCG_L0_FEAT_HDR_LEN + data_len);

        switch (feat_code) {
        case TCG_L0_FEAT_TPER:
            dissect_tcg_l0_feat_tper(tvb, pinfo, feat_tree, offset,
                                     data_len);
            break;
        case TCG_L0_FEAT_LOCKING:
            dissect_tcg_l0_feat_locking(tvb, pinfo, feat_tree, offset,
                                        data_len);
            break;
        case TCG_L0_FEAT_GEOMETRY:
            dissect_tcg_l0_feat_geometry(tvb, pinfo, feat_tree, offset,
                                         data_len);
            break;
        case TCG_L0_FEAT_SIIS:
            dissect_tcg_l0_feat_siis(tvb, pinfo, feat_tree, offset, data_len);
            break;
        case TCG_L0_FEAT_ENTERPRISE:
            dissect_tcg_l0_feat_ssc_v1(tvb, pinfo, feat_tree, offset,
                                       data_len, true);
            break;
        case TCG_L0_FEAT_OPAL_V1:
            dissect_tcg_l0_feat_ssc_v1(tvb, pinfo, feat_tree, offset,
                                       data_len, false);
            break;
        case TCG_L0_FEAT_SUM:
            dissect_tcg_l0_feat_sum(tvb, pinfo, feat_tree, offset,
                                    data_len);
            break;
        case TCG_L0_FEAT_DATASTORE:
            dissect_tcg_l0_feat_datastore(tvb, pinfo, feat_tree, offset,
                                          data_len);
            break;
        case TCG_L0_FEAT_OPAL_V2:
        /* Ruby SSC 1.00 Table 7 is byte-for-byte the Opal 2.x descriptor */
        case TCG_L0_FEAT_RUBY:
            dissect_tcg_l0_feat_opal_v2(tvb, pinfo, feat_tree, offset,
                                        data_len);
            break;
        case TCG_L0_FEAT_OPALITE:
        case TCG_L0_FEAT_PYRITE_V1:
        case TCG_L0_FEAT_PYRITE_V2:
            dissect_tcg_l0_feat_ssc_lite(tvb, pinfo, feat_tree, offset,
                                         data_len);
            break;
        case TCG_L0_FEAT_BLOCK_SID:
            dissect_tcg_l0_feat_block_sid(tvb, pinfo, feat_tree, offset,
                                          data_len);
            break;
        case TCG_L0_FEAT_CNL:
            dissect_tcg_l0_feat_cnl(tvb, pinfo, feat_tree, offset,
                                    data_len);
            break;
        case TCG_L0_FEAT_DATA_REMOVAL:
            dissect_tcg_l0_feat_data_removal(tvb, pinfo, feat_tree, offset,
                                             data_len);
            break;
        default:
            dissect_tcg_l0_feat_data(tvb, feat_tree, offset, data_len);
            break;
        }

        if (try_val_to_str(feat_code, tcg_l0_ssc_name_vals)) {
            if (wmem_strbuf_get_len(sscs) > 0)
                wmem_strbuf_append(sscs, ", ");
            wmem_strbuf_append(sscs,
                    val_to_str_const(feat_code, tcg_l0_ssc_name_vals, ""));
        }

        offset += data_len;
        /* Forward progress: a zero-length descriptor still consumed the
         * 4-byte header, so offset strictly increased. */
    }

    if (wmem_strbuf_get_len(sscs) > 0) {
        proto_item_append_text(l0_item, " (%s)",
                               wmem_strbuf_get_str(sscs));
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                        wmem_strbuf_get_str(sscs));
    }
}

/*
 * ComPacket framing (Core Spec §3.2.3).  All fields big-endian.  The
 * ComPacket carries zero or more Packets; each Packet carries zero or more
 * Subpackets.  Iterative (non-recursive) walk with per-level length
 * clamping so a corrupt Length field cannot overrun the capture or stall
 * the loop.
 */
static void
dissect_tcg_compacket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *cp_tree;
    proto_item *cp_item, *len_item;
    int         offset = 0;
    int         remaining;
    uint32_t    cp_len;
    int         cp_payload_len, cp_payload_end;

    remaining = tvb_reported_length_remaining(tvb, offset);
    if (remaining < TCG_COMPACKET_HDR_LEN) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb,
                                             offset, remaining, ENC_NA);
        expert_add_info(pinfo, ti, &ei_tcg_truncated);
        return;
    }

    cp_item = proto_tree_add_item(tree, hf_tcg_compacket, tvb, offset,
                                  -1, ENC_NA);
    cp_tree = proto_item_add_subtree(cp_item, ett_tcg_compacket);

    proto_tree_add_item(cp_tree, hf_tcg_compacket_reserved, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(cp_tree, hf_tcg_compacket_comid, tvb, offset + 4, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(cp_tree, hf_tcg_compacket_comid_ext, tvb, offset + 6,
                        2, ENC_BIG_ENDIAN);
    proto_tree_add_item(cp_tree, hf_tcg_compacket_outstanding, tvb,
                        offset + 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cp_tree, hf_tcg_compacket_min_transfer, tvb,
                        offset + 12, 4, ENC_BIG_ENDIAN);
    len_item = proto_tree_add_item_ret_uint(cp_tree, hf_tcg_compacket_length,
                                            tvb, offset + 16, 4,
                                            ENC_BIG_ENDIAN, &cp_len);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", ComID 0x%04x",
                    tvb_get_ntohs(tvb, offset + 4));
    if (cp_len == 0) {
        /* Legal: an empty ComPacket is a polling response */
        proto_item_append_text(cp_item, " (empty — polling response)");
        col_append_str(pinfo->cinfo, COL_INFO, " (empty ComPacket)");
    }

    offset += TCG_COMPACKET_HDR_LEN;
    remaining = tvb_reported_length_remaining(tvb, offset);

    cp_payload_len = (int)cp_len;
    if (cp_len > (uint32_t)remaining) {
        expert_add_info(pinfo, len_item, &ei_tcg_length_overrun);
        cp_payload_len = remaining;
    }
    cp_payload_end = offset + cp_payload_len;
    proto_item_set_len(cp_item, TCG_COMPACKET_HDR_LEN + cp_payload_len);

    /* Packets */
    while (offset < cp_payload_end) {
        proto_tree *pkt_tree, *ses_tree;
        proto_item *pkt_item, *pkt_len_item;
        uint32_t    pkt_len;
        int         pkt_payload_len, pkt_payload_end;

        if (cp_payload_end - offset < TCG_PACKET_HDR_LEN) {
            proto_item *ti = proto_tree_add_item(cp_tree, hf_tcg_raw_data,
                                                 tvb, offset,
                                                 cp_payload_end - offset,
                                                 ENC_NA);
            expert_add_info(pinfo, ti, &ei_tcg_truncated);
            break;
        }

        pkt_item = proto_tree_add_item(cp_tree, hf_tcg_packet, tvb, offset,
                                       -1, ENC_NA);
        pkt_tree = proto_item_add_subtree(pkt_item, ett_tcg_packet);

        ses_tree = proto_tree_add_subtree_format(pkt_tree, tvb, offset, 8,
                ett_tcg_session, NULL, "Session (TSN 0x%08x, HSN 0x%08x)",
                tvb_get_ntohl(tvb, offset), tvb_get_ntohl(tvb, offset + 4));
        proto_tree_add_item(ses_tree, hf_tcg_packet_tsn, tvb, offset, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ses_tree, hf_tcg_packet_hsn, tvb, offset + 4, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(pkt_tree, hf_tcg_packet_seq, tvb, offset + 8, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(pkt_tree, hf_tcg_packet_reserved, tvb,
                            offset + 12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pkt_tree, hf_tcg_packet_ack_type, tvb,
                            offset + 14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pkt_tree, hf_tcg_packet_ack, tvb, offset + 16, 4,
                            ENC_BIG_ENDIAN);
        pkt_len_item = proto_tree_add_item_ret_uint(pkt_tree,
                hf_tcg_packet_length, tvb, offset + 20, 4, ENC_BIG_ENDIAN,
                &pkt_len);
        proto_item_append_text(pkt_item, " (TSN 0x%08x, HSN 0x%08x, Seq %u)",
                               tvb_get_ntohl(tvb, offset),
                               tvb_get_ntohl(tvb, offset + 4),
                               tvb_get_ntohl(tvb, offset + 8));

        offset += TCG_PACKET_HDR_LEN;

        pkt_payload_len = (int)pkt_len;
        if (pkt_len > (uint32_t)(cp_payload_end - offset)) {
            expert_add_info(pinfo, pkt_len_item, &ei_tcg_length_overrun);
            pkt_payload_len = cp_payload_end - offset;
        }
        pkt_payload_end = offset + pkt_payload_len;
        proto_item_set_len(pkt_item, TCG_PACKET_HDR_LEN + pkt_payload_len);

        /* Subpackets */
        while (offset < pkt_payload_end) {
            proto_tree *sp_tree;
            proto_item *sp_item, *sp_len_item;
            uint32_t    sp_kind, sp_len;
            int         sp_payload_len, pad;

            if (pkt_payload_end - offset < TCG_SUBPACKET_HDR_LEN) {
                proto_item *ti = proto_tree_add_item(pkt_tree,
                        hf_tcg_raw_data, tvb, offset,
                        pkt_payload_end - offset, ENC_NA);
                expert_add_info(pinfo, ti, &ei_tcg_truncated);
                break;
            }

            sp_item = proto_tree_add_item(pkt_tree, hf_tcg_subpacket, tvb,
                                          offset, -1, ENC_NA);
            sp_tree = proto_item_add_subtree(sp_item, ett_tcg_subpacket);

            proto_tree_add_item(sp_tree, hf_tcg_subpacket_reserved, tvb,
                                offset, 6, ENC_NA);
            proto_tree_add_item_ret_uint(sp_tree, hf_tcg_subpacket_kind, tvb,
                                         offset + 6, 2, ENC_BIG_ENDIAN,
                                         &sp_kind);
            sp_len_item = proto_tree_add_item_ret_uint(sp_tree,
                    hf_tcg_subpacket_length, tvb, offset + 8, 4,
                    ENC_BIG_ENDIAN, &sp_len);
            proto_item_append_text(sp_item, " (%s, %u bytes)",
                    val_to_str_const(sp_kind, tcg_subpacket_kind_vals,
                                     "Unknown"), sp_len);

            offset += TCG_SUBPACKET_HDR_LEN;

            sp_payload_len = (int)sp_len;
            if (sp_len > (uint32_t)(pkt_payload_end - offset)) {
                expert_add_info(pinfo, sp_len_item, &ei_tcg_length_overrun);
                sp_payload_len = pkt_payload_end - offset;
            }

            if (sp_payload_len > 0) {
                switch (sp_kind) {
                case TCG_SUBPACKET_KIND_DATA:
                    dissect_tcg_token_stream(tvb, pinfo, sp_tree, offset,
                                             sp_payload_len);
                    break;
                case TCG_SUBPACKET_KIND_CREDIT:
                    if (sp_payload_len >= 4) {
                        proto_tree_add_item(sp_tree, hf_tcg_subpacket_credit,
                                            tvb, offset, 4, ENC_BIG_ENDIAN);
                        if (sp_payload_len > 4)
                            proto_tree_add_item(sp_tree, hf_tcg_raw_data,
                                                tvb, offset + 4,
                                                sp_payload_len - 4, ENC_NA);
                    } else {
                        proto_item *ti = proto_tree_add_item(sp_tree,
                                hf_tcg_raw_data, tvb, offset,
                                sp_payload_len, ENC_NA);
                        expert_add_info(pinfo, ti, &ei_tcg_truncated);
                    }
                    break;
                default:
                    proto_tree_add_item(sp_tree, hf_tcg_raw_data, tvb,
                                        offset, sp_payload_len, ENC_NA);
                    break;
                }
            }
            offset += sp_payload_len;

            /* Subpacket payloads are padded to 4-byte alignment; the pad is
             * not included in the Length field. */
            pad = (4 - (int)(sp_len % 4)) % 4;
            if (pad > pkt_payload_end - offset)
                pad = pkt_payload_end - offset;
            if (pad > 0) {
                proto_tree_add_item(sp_tree, hf_tcg_subpacket_pad, tvb,
                                    offset, pad, ENC_NA);
                offset += pad;
            }
            proto_item_set_len(sp_item,
                    TCG_SUBPACKET_HDR_LEN + sp_payload_len + pad);
            /* Forward progress: a zero-length subpacket still consumed the
             * 12-byte header, so offset strictly increased. */
        }
        offset = pkt_payload_end;
    }
    offset = cp_payload_end;

    /* The transfer may be padded past the ComPacket (Security Receive
     * Allocation Length); render any trailing bytes as raw padding. */
    remaining = tvb_reported_length_remaining(tvb, offset);
    if (remaining > 0)
        proto_tree_add_item(tree, hf_tcg_padding, tvb, offset, remaining,
                            ENC_NA);
}

/*
 * SECP 02h — TCG protocol layer / ComID management (Core Spec §3.3.10).
 * Send:    ComID(2) + ComID Ext(2) + Request Code(4) [+ reserved].
 * Receive: ComID(2) + ComID Ext(2) + Request Code(4) +
 *          Available Data Length(2) + response-specific data.
 */
static void
dissect_tcg_comid_mgmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       bool send)
{
    proto_tree *cm_tree;
    proto_item *cm_item;
    int         offset    = 0;
    int         remaining = tvb_reported_length_remaining(tvb, offset);
    /* Response: ComID(2) + Ext(2) + Request Code(4) + Reserved(2) +
     * Available Data Length(2) (Core Spec §3.3.10.3 STACK_RESET response) */
    int         hdr_len   = send ? 8 : 12;
    uint32_t    req_code;

    if (remaining < hdr_len) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb,
                                             offset, remaining, ENC_NA);
        expert_add_info(pinfo, ti, &ei_tcg_truncated);
        return;
    }

    cm_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_tcg_comid_mgmt, &cm_item,
                                     "ComID Management");

    proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_comid, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_comid_ext, tvb,
                        offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(cm_tree, hf_tcg_comid_mgmt_request_code,
                                 tvb, offset + 4, 4, ENC_BIG_ENDIAN,
                                 &req_code);
    offset += 8;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                    val_to_str_const(req_code, tcg_request_code_vals,
                                     "Unknown request code"));

    if (!send) {
        proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_reserved, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_avail_len, tvb,
                            offset + 2, 2, ENC_BIG_ENDIAN);
        offset += 4;
    }

    remaining = tvb_reported_length_remaining(tvb, offset);
    if (remaining > 0) {
        /* IF-SEND: the request is padded to the transfer length; only a
         * response carries meaningful data past the header. */
        proto_tree_add_item(cm_tree,
                            send ? hf_tcg_padding : hf_tcg_comid_mgmt_data,
                            tvb, offset, remaining, ENC_NA);
    }
}

/*
 * SECP 02h, ComID 0000h, IF-RECV — GET COMID (Core Spec §3.3.4.3.1).
 * The whole payload is the 4-byte Extended ComID, zero-padded out to the
 * transfer length; all zeroes means the TPer could not assign a ComID.
 */
static void
dissect_tcg_get_comid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int remaining = tvb_reported_length_remaining(tvb, 0);

    if (remaining < 4) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb, 0,
                                             remaining, ENC_NA);
        expert_add_info(pinfo, ti, &ei_tcg_truncated);
        return;
    }

    proto_tree_add_item(tree, hf_tcg_comid_get_ext_comid, tvb, 0, 4,
                        ENC_BIG_ENDIAN);
    if (remaining > 4)
        proto_tree_add_item(tree, hf_tcg_padding, tvb, 4, remaining - 4,
                            ENC_NA);
}

static int
dissect_tcg_storage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data)
{
    struct nvme_security_info *sec = (struct nvme_security_info *)data;
    proto_tree *tcg_tree;
    proto_item *ti;

    if (!sec)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCG");
    col_append_fstr(pinfo->cinfo, COL_INFO, ", TCG %s",
                    sec->send ? "Security Send" : "Security Receive");

    /* Root every decode path under one protocol item so the "tcg-storage"
     * display filter matches uniformly. */
    ti = proto_tree_add_item(tree, proto_tcg_storage, tvb, 0, -1, ENC_NA);
    tcg_tree = proto_item_add_subtree(ti, ett_tcg_storage);

    if (sec->secp == TCG_SECP_PROTO_MGMT) {
        if (sec->send && sec->spsp == TCG_COMID_TPER_RESET) {
            /* TPer Reset: the transfer payload is ignored by the TPer, so it
             * must not be parsed as a ComID management request. */
            col_append_str(pinfo->cinfo, COL_INFO, " (TPer Reset)");
            proto_item_append_text(ti, " (TPer Reset)");
            if (tvb_reported_length(tvb) > 0)
                proto_tree_add_item(tcg_tree, hf_tcg_padding, tvb, 0,
                        tvb_reported_length(tvb), ENC_NA);
        } else if (!sec->send && sec->spsp == TCG_COMID_GET_COMID) {
            /* GET COMID: the response carries only the Extended ComID, so it
             * must not be parsed as a ComID management response. */
            col_append_str(pinfo->cinfo, COL_INFO, " (GET_COMID)");
            proto_item_append_text(ti, " (GET_COMID)");
            dissect_tcg_get_comid(tvb, pinfo, tcg_tree);
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, " (ComID Management)");
            dissect_tcg_comid_mgmt(tvb, pinfo, tcg_tree, sec->send);
        }
    } else if (sec->spsp == TCG_COMID_LEVEL0_DISCOVERY) {
        if (!sec->send) {
            col_append_str(pinfo->cinfo, COL_INFO, " (Level 0 Discovery)");
            dissect_tcg_level0_discovery(tvb, pinfo, tcg_tree, 0,
                    tvb_reported_length(tvb));
        } else {
            /* ComID 0001h has no defined Security Send payload */
            proto_tree_add_item(tcg_tree, hf_tcg_raw_data, tvb, 0,
                    tvb_reported_length(tvb), ENC_NA);
        }
    } else {
        dissect_tcg_compacket(tvb, pinfo, tcg_tree);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_tcg_storage(void)
{
    static hf_register_info hf[] = {
        /* ComPacket */
        { &hf_tcg_compacket,
          { "ComPacket", "tcg-storage.compacket",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_compacket_reserved,
          { "Reserved", "tcg-storage.compacket.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_compacket_comid,
          { "ComID", "tcg-storage.compacket.comid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Communication channel identifier", HFILL },
        },
        { &hf_tcg_compacket_comid_ext,
          { "ComID Extension", "tcg-storage.compacket.comid_ext",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_compacket_outstanding,
          { "Outstanding Data", "tcg-storage.compacket.outstanding",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Bytes buffered by the TPer awaiting transfer to the host",
            HFILL },
        },
        { &hf_tcg_compacket_min_transfer,
          { "Min Transfer", "tcg-storage.compacket.min_transfer",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Minimum transfer length needed to receive the next ComPacket",
            HFILL },
        },
        { &hf_tcg_compacket_length,
          { "Length", "tcg-storage.compacket.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of payload bytes following the ComPacket header",
            HFILL },
        },
        /* Packet */
        { &hf_tcg_packet,
          { "Packet", "tcg-storage.packet",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_tsn,
          { "TPer Session Number (TSN)", "tcg-storage.packet.tsn",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_hsn,
          { "Host Session Number (HSN)", "tcg-storage.packet.hsn",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_seq,
          { "Seq Number", "tcg-storage.packet.seq",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_reserved,
          { "Reserved", "tcg-storage.packet.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_ack_type,
          { "Ack Type", "tcg-storage.packet.ack_type",
            FT_UINT16, BASE_DEC, VALS(tcg_ack_type_vals), 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_ack,
          { "Acknowledgement", "tcg-storage.packet.ack",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_packet_length,
          { "Length", "tcg-storage.packet.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of payload bytes following the Packet header", HFILL },
        },
        /* Subpacket */
        { &hf_tcg_subpacket,
          { "Subpacket", "tcg-storage.subpacket",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_subpacket_reserved,
          { "Reserved", "tcg-storage.subpacket.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_subpacket_kind,
          { "Kind", "tcg-storage.subpacket.kind",
            FT_UINT16, BASE_HEX, VALS(tcg_subpacket_kind_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_tcg_subpacket_length,
          { "Length", "tcg-storage.subpacket.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of payload bytes following the Subpacket header (pad"
            " not included)", HFILL },
        },
        { &hf_tcg_subpacket_credit,
          { "Credit", "tcg-storage.subpacket.credit",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Flow-control credit granted (Credit Control subpacket)",
            HFILL },
        },
        { &hf_tcg_subpacket_pad,
          { "Pad", "tcg-storage.subpacket.pad",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Padding to 4-byte alignment", HFILL },
        },
        { &hf_tcg_token_stream,
          { "Token Stream", "tcg-storage.token_stream",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "TCG byte-stream encoded tokens", HFILL },
        },
        { &hf_tcg_tok_uint,
          { "Unsigned Integer", "tcg-storage.tok.uint",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Integer atom (unsigned)", HFILL },
        },
        { &hf_tcg_tok_int,
          { "Signed Integer", "tcg-storage.tok.int",
            FT_INT64, BASE_DEC, NULL, 0x0,
            "Integer atom (signed)", HFILL },
        },
        { &hf_tcg_tok_bytes,
          { "Bytes", "tcg-storage.tok.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Byte-sequence atom", HFILL },
        },
        { &hf_tcg_tok_uid,
          { "UID", "tcg-storage.tok.uid",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(tcg_uid_vals),
            0x0, "8-byte byte sequence interpreted as a UID", HFILL },
        },
        { &hf_tcg_tok_control,
          { "Control Token", "tcg-storage.tok.control",
            FT_UINT8, BASE_HEX, VALS(tcg_token_control_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_tcg_tok_status,
          { "Method Status", "tcg-storage.tok.status",
            FT_UINT32, BASE_HEX, VALS(tcg_method_status_vals), 0x0,
            "Method Status from the End of Data status list", HFILL },
        },
        /* Level 0 Discovery */
        { &hf_tcg_level0_discovery,
          { "Level 0 Discovery", "tcg-storage.level0_discovery",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Level 0 Discovery response", HFILL },
        },
        { &hf_tcg_l0_length,
          { "Length of Parameter Data", "tcg-storage.l0.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of valid bytes following this field", HFILL },
        },
        { &hf_tcg_l0_major_version,
          { "Data Structure Major Version",
            "tcg-storage.l0.major_version",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_minor_version,
          { "Data Structure Minor Version",
            "tcg-storage.l0.minor_version",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_reserved,
          { "Reserved", "tcg-storage.l0.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_vendor,
          { "Vendor Unique", "tcg-storage.l0.vendor",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        /* Feature descriptor common header */
        { &hf_tcg_l0_feat,
          { "Feature Descriptor", "tcg-storage.l0.feat",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_feat_code,
          { "Feature Code", "tcg-storage.l0.feat.code",
            FT_UINT16, BASE_HEX, VALS(tcg_l0_feature_code_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_tcg_l0_feat_version,
          { "Version", "tcg-storage.l0.feat.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL },
        },
        { &hf_tcg_l0_feat_reserved,
          { "Reserved", "tcg-storage.l0.feat.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL },
        },
        { &hf_tcg_l0_feat_ssc_minor,
          { "SSC Minor Version Number", "tcg-storage.l0.feat.ssc_minor",
            FT_UINT8, BASE_HEX, VALS(tcg_l0_opal2_minor_vals), 0x0F,
            NULL, HFILL },
        },
        { &hf_tcg_l0_feat_length,
          { "Length", "tcg-storage.l0.feat.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Number of feature data bytes following the descriptor header",
            HFILL },
        },
        { &hf_tcg_l0_feat_data,
          { "Feature Data", "tcg-storage.l0.feat.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        /* TPer Feature (0x0001) */
        { &hf_tcg_l0_tper_flags,
          { "TPer Flags", "tcg-storage.l0.feat.tper.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_tper_comid_mgmt,
          { "ComID Management Supported",
            "tcg-storage.l0.feat.tper.comid_mgmt",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL },
        },
        { &hf_tcg_l0_tper_streaming,
          { "Streaming Supported", "tcg-storage.l0.feat.tper.streaming",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL },
        },
        { &hf_tcg_l0_tper_buffer_mgmt,
          { "Buffer Management Supported",
            "tcg-storage.l0.feat.tper.buffer_mgmt",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL },
        },
        { &hf_tcg_l0_tper_acknak,
          { "ACK/NAK Supported", "tcg-storage.l0.feat.tper.acknak",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL },
        },
        { &hf_tcg_l0_tper_async,
          { "Async Supported", "tcg-storage.l0.feat.tper.async",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL },
        },
        { &hf_tcg_l0_tper_sync,
          { "Sync Supported", "tcg-storage.l0.feat.tper.sync",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        /* Locking Feature (0x0002) */
        { &hf_tcg_l0_locking_flags,
          { "Locking Flags", "tcg-storage.l0.feat.locking.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_supported,
          { "Locking Supported", "tcg-storage.l0.feat.locking.supported",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_enabled,
          { "Locking Enabled", "tcg-storage.l0.feat.locking.enabled",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_locked,
          { "Locked", "tcg-storage.l0.feat.locking.locked",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_media_encryption,
          { "Media Encryption",
            "tcg-storage.l0.feat.locking.media_encryption",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_mbr_enabled,
          { "MBR Enabled", "tcg-storage.l0.feat.locking.mbr_enabled",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_mbr_done,
          { "MBR Done", "tcg-storage.l0.feat.locking.mbr_done",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_mbr_shadowing_not_supported,
          { "MBR Shadowing Not Supported",
            "tcg-storage.l0.feat.locking.mbr_shadowing_not_supported",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_hw_reset,
          { "HW Reset for LOR/DOR Supported",
            "tcg-storage.l0.feat.locking.hw_reset",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL },
        },
        /* Geometry Reporting Feature (0x0003) */
        { &hf_tcg_l0_geometry_flags,
          { "Geometry Flags", "tcg-storage.l0.feat.geometry.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_geometry_align,
          { "Alignment Required (ALIGN)",
            "tcg-storage.l0.feat.geometry.align",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        { &hf_tcg_l0_geometry_reserved,
          { "Reserved", "tcg-storage.l0.feat.geometry.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_geometry_lbs,
          { "Logical Block Size", "tcg-storage.l0.feat.geometry.lbs",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_geometry_granularity,
          { "Alignment Granularity",
            "tcg-storage.l0.feat.geometry.granularity",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of logical blocks per alignment unit", HFILL },
        },
        { &hf_tcg_l0_geometry_lowest_lba,
          { "Lowest Aligned LBA", "tcg-storage.l0.feat.geometry.lowest_lba",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        /* SIIS Feature (0x0005) */
        { &hf_tcg_l0_siis_revision,
          { "SIIS Revision Number", "tcg-storage.l0.feat.siis.revision",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_siis_flags,
          { "Flags", "tcg-storage.l0.feat.siis.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_siis_id_usage_scope,
          { "Identifier Usage Scope",
            "tcg-storage.l0.feat.siis.id_usage_scope",
            FT_UINT8, BASE_HEX, VALS(tcg_l0_siis_id_scope_vals), 0x06,
            NULL, HFILL },
        },
        { &hf_tcg_l0_siis_key_change_zone,
          { "Key Change Zone Behavior",
            "tcg-storage.l0.feat.siis.key_change_zone",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        /* Enterprise SSC Feature (0x0100) */
        { &hf_tcg_l0_ent_base_comid,
          { "Base ComID", "tcg-storage.l0.feat.enterprise.base_comid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ent_num_comids,
          { "Number of ComIDs", "tcg-storage.l0.feat.enterprise.num_comids",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ent_flags,
          { "Flags", "tcg-storage.l0.feat.enterprise.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ent_range_crossing,
          { "Range Crossing", "tcg-storage.l0.feat.enterprise.range_crossing",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        /* Opal SSC 1.00 Feature (0x0200) */
        { &hf_tcg_l0_opal1_base_comid,
          { "Base ComID", "tcg-storage.l0.feat.opal1.base_comid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal1_num_comids,
          { "Number of ComIDs", "tcg-storage.l0.feat.opal1.num_comids",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal1_flags,
          { "Flags", "tcg-storage.l0.feat.opal1.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal1_range_crossing,
          { "Range Crossing", "tcg-storage.l0.feat.opal1.range_crossing",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        /* Opal SSC 2.x Feature (0x0203) */
        { &hf_tcg_l0_opal2_base_comid,
          { "Base ComID", "tcg-storage.l0.feat.opal2.base_comid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_num_comids,
          { "Number of ComIDs", "tcg-storage.l0.feat.opal2.num_comids",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_flags,
          { "Flags", "tcg-storage.l0.feat.opal2.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_range_crossing,
          { "Range Crossing Behavior",
            "tcg-storage.l0.feat.opal2.range_crossing",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_num_admins,
          { "Number of Locking SP Admin Authorities",
            "tcg-storage.l0.feat.opal2.num_admins",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_num_users,
          { "Number of Locking SP User Authorities",
            "tcg-storage.l0.feat.opal2.num_users",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_initial_cpin_sid,
          { "Initial C_PIN_SID PIN Indicator",
            "tcg-storage.l0.feat.opal2.initial_cpin_sid",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_revert_cpin_sid,
          { "Behavior of C_PIN_SID PIN upon TPer Revert",
            "tcg-storage.l0.feat.opal2.revert_cpin_sid",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_reserved,
          { "Reserved", "tcg-storage.l0.feat.opal2.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        /* Single User Mode Feature (0x0201) */
        { &hf_tcg_l0_sum_num_objects,
          { "Number of Locking Objects Supported",
            "tcg-storage.l0.feat.sum.num_objects",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_sum_flags,
          { "Flags", "tcg-storage.l0.feat.sum.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_sum_any,
          { "Any", "tcg-storage.l0.feat.sum.any",
            FT_BOOLEAN, 8, NULL, 0x01,
            "At least one locking object is in Single User Mode", HFILL },
        },
        { &hf_tcg_l0_sum_all,
          { "All", "tcg-storage.l0.feat.sum.all",
            FT_BOOLEAN, 8, NULL, 0x02,
            "All locking objects are in Single User Mode", HFILL },
        },
        { &hf_tcg_l0_sum_policy,
          { "Policy", "tcg-storage.l0.feat.sum.policy",
            FT_BOOLEAN, 8, NULL, 0x04,
            "Owner of the Single User Mode ranges (0 = user, 1 = admin)",
            HFILL },
        },
        /* DataStore Table Feature (0x0202) */
        { &hf_tcg_l0_ds_reserved,
          { "Reserved", "tcg-storage.l0.feat.datastore.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ds_max_tables,
          { "Max Number of DataStore Tables",
            "tcg-storage.l0.feat.datastore.max_tables",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ds_max_size,
          { "Max Total Size of DataStore Tables",
            "tcg-storage.l0.feat.datastore.max_size",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ds_alignment,
          { "DataStore Table Size Alignment",
            "tcg-storage.l0.feat.datastore.alignment",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        /* Opalite / Pyrite 1.0 / Pyrite 2.0 SSC (0x0301-0x0303); Ruby SSC
         * (0x0304) uses the Opal 2.x fields above. */
        { &hf_tcg_l0_ssc_base_comid,
          { "Base ComID", "tcg-storage.l0.feat.ssc.base_comid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ssc_num_comids,
          { "Number of ComIDs", "tcg-storage.l0.feat.ssc.num_comids",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ssc_reserved,
          { "Reserved", "tcg-storage.l0.feat.ssc.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ssc_initial_cpin_sid,
          { "Initial C_PIN_SID PIN Indicator",
            "tcg-storage.l0.feat.ssc.initial_cpin_sid",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_ssc_revert_cpin_sid,
          { "Behavior of C_PIN_SID PIN upon TPer Revert",
            "tcg-storage.l0.feat.ssc.revert_cpin_sid",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        /* Block SID Authentication Feature (0x0402) */
        { &hf_tcg_l0_bsid_flags,
          { "SID States", "tcg-storage.l0.feat.block_sid.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_bsid_sid_value_state,
          { "SID Value State", "tcg-storage.l0.feat.block_sid.sid_value_state",
            FT_BOOLEAN, 8, NULL, 0x01,
            "SID PIN differs from MSID PIN", HFILL },
        },
        { &hf_tcg_l0_bsid_sid_blocked_state,
          { "SID Blocked State",
            "tcg-storage.l0.feat.block_sid.sid_blocked_state",
            FT_BOOLEAN, 8, NULL, 0x02,
            "SID authentication is blocked", HFILL },
        },
        { &hf_tcg_l0_bsid_flags2,
          { "Reset Behavior", "tcg-storage.l0.feat.block_sid.flags2",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_bsid_hw_reset,
          { "Hardware Reset", "tcg-storage.l0.feat.block_sid.hw_reset",
            FT_BOOLEAN, 8, NULL, 0x01,
            "Hardware reset clears the Block SID Authentication state",
            HFILL },
        },
        /* Configurable Namespace Locking Feature (0x0403) */
        { &hf_tcg_l0_cnl_flags,
          { "CNL Flags", "tcg-storage.l0.feat.cnl.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_cnl_range_c,
          { "Range_C", "tcg-storage.l0.feat.cnl.range_c",
            FT_BOOLEAN, 8, NULL, 0x80,
            "Namespace-scoped ranges may be created", HFILL },
        },
        { &hf_tcg_l0_cnl_range_p,
          { "Range_P", "tcg-storage.l0.feat.cnl.range_p",
            FT_BOOLEAN, 8, NULL, 0x40,
            "Namespace-scoped ranges are present", HFILL },
        },
        { &hf_tcg_l0_cnl_sum_c,
          { "SUM_C", "tcg-storage.l0.feat.cnl.sum_c",
            FT_BOOLEAN, 8, NULL, 0x20,
            "Namespace-scoped ranges support Single User Mode", HFILL },
        },
        { &hf_tcg_l0_cnl_reserved,
          { "Reserved", "tcg-storage.l0.feat.cnl.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_cnl_max_key_count,
          { "Maximum Key Count", "tcg-storage.l0.feat.cnl.max_key_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_cnl_unused_key_count,
          { "Unused Key Count", "tcg-storage.l0.feat.cnl.unused_key_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_cnl_max_ranges_per_ns,
          { "Maximum Ranges Per Namespace",
            "tcg-storage.l0.feat.cnl.max_ranges_per_ns",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        /* Data Removal Mechanism Feature (0x0404) */
        { &hf_tcg_l0_drm_reserved,
          { "Reserved", "tcg-storage.l0.feat.data_removal.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_flags,
          { "Flags", "tcg-storage.l0.feat.data_removal.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_reserved1,
          { "Reserved", "tcg-storage.l0.feat.data_removal.reserved1",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_processing,
          { "Data Removal Operation Processing",
            "tcg-storage.l0.feat.data_removal.processing",
            FT_BOOLEAN, 8, NULL, 0x01,
            "A data removal operation is in progress", HFILL },
        },
        { &hf_tcg_l0_drm_interrupted,
          { "Data Removal Operation Interrupted",
            "tcg-storage.l0.feat.data_removal.interrupted",
            FT_BOOLEAN, 8, NULL, 0x02,
            "A previously issued data removal operation was interrupted",
            HFILL },
        },
        { &hf_tcg_l0_drm_mechanism,
          { "Supported Data Removal Mechanism",
            "tcg-storage.l0.feat.data_removal.mechanism",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_mech_overwrite,
          { "Overwrite Data Erase",
            "tcg-storage.l0.feat.data_removal.mechanism.overwrite",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_mech_block_erase,
          { "Block Erase",
            "tcg-storage.l0.feat.data_removal.mechanism.block_erase",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_mech_crypto_erase,
          { "Cryptographic Erase",
            "tcg-storage.l0.feat.data_removal.mechanism.crypto_erase",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_mech_vendor,
          { "Vendor Specific Erase",
            "tcg-storage.l0.feat.data_removal.mechanism.vendor",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_format,
          { "Data Removal Time Format",
            "tcg-storage.l0.feat.data_removal.format",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_fmt_overwrite,
          { "Overwrite Data Erase Time Format",
            "tcg-storage.l0.feat.data_removal.format.overwrite",
            FT_BOOLEAN, 8, TFS(&tfs_tcg_l0_drm_fmt), 0x01, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_fmt_block_erase,
          { "Block Erase Time Format",
            "tcg-storage.l0.feat.data_removal.format.block_erase",
            FT_BOOLEAN, 8, TFS(&tfs_tcg_l0_drm_fmt), 0x02, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_fmt_crypto_erase,
          { "Cryptographic Erase Time Format",
            "tcg-storage.l0.feat.data_removal.format.crypto_erase",
            FT_BOOLEAN, 8, TFS(&tfs_tcg_l0_drm_fmt), 0x04, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_fmt_vendor,
          { "Vendor Specific Erase Time Format",
            "tcg-storage.l0.feat.data_removal.format.vendor",
            FT_BOOLEAN, 8, TFS(&tfs_tcg_l0_drm_fmt), 0x20, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_time_overwrite,
          { "Data Removal Time (Overwrite Data Erase)",
            "tcg-storage.l0.feat.data_removal.time_overwrite",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_time_block_erase,
          { "Data Removal Time (Block Erase)",
            "tcg-storage.l0.feat.data_removal.time_block_erase",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_time_crypto_erase,
          { "Data Removal Time (Cryptographic Erase)",
            "tcg-storage.l0.feat.data_removal.time_crypto_erase",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_time_vendor,
          { "Data Removal Time (Vendor Specific Erase)",
            "tcg-storage.l0.feat.data_removal.time_vendor",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        /* SECP 02h ComID management */
        { &hf_tcg_comid_mgmt_comid,
          { "ComID", "tcg-storage.comid_mgmt.comid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_comid_ext,
          { "ComID Extension", "tcg-storage.comid_mgmt.comid_ext",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_request_code,
          { "Request Code", "tcg-storage.comid_mgmt.request_code",
            FT_UINT32, BASE_HEX, VALS(tcg_request_code_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_reserved,
          { "Reserved", "tcg-storage.comid_mgmt.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_avail_len,
          { "Available Data Length", "tcg-storage.comid_mgmt.available_data_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_data,
          { "Response Data", "tcg-storage.comid_mgmt.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        /* SECP 02h GET COMID */
        { &hf_tcg_comid_get_ext_comid,
          { "Extended ComID", "tcg-storage.get_comid.ext_comid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Newly assigned Extended ComID; zero if none could be assigned",
            HFILL },
        },
        /* Fallbacks */
        { &hf_tcg_padding,
          { "Padding", "tcg-storage.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Padding to the transfer length", HFILL },
        },
        { &hf_tcg_raw_data,
          { "Data", "tcg-storage.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
    };

    static ei_register_info ei[] = {
        { &ei_tcg_truncated,
          { "tcg-storage.truncated", PI_MALFORMED, PI_WARN,
            "TCG Storage structure truncated", EXPFILL }},
        { &ei_tcg_length_overrun,
          { "tcg-storage.length_overrun", PI_MALFORMED, PI_WARN,
            "Length field exceeds the remaining payload; clamped",
            EXPFILL }},
        { &ei_tcg_tok_reserved,
          { "tcg-storage.tok.reserved_token", PI_PROTOCOL, PI_WARN,
            "Reserved token value", EXPFILL }},
        { &ei_tcg_tok_status_range,
          { "tcg-storage.tok.status_out_of_range", PI_MALFORMED, PI_WARN,
            "Method Status list element is larger than 0xFF", EXPFILL }},
        { &ei_tcg_feat_length_align,
          { "tcg-storage.l0.feat.length_not_aligned", PI_MALFORMED, PI_WARN,
            "Feature descriptor Length is not an integral multiple of 4;"
            " the descriptors that follow are misaligned", EXPFILL }},
    };

    static int *ett[] = {
        &ett_tcg_storage,
        &ett_tcg_compacket,
        &ett_tcg_packet,
        &ett_tcg_session,
        &ett_tcg_subpacket,
        &ett_tcg_token_stream,
        &ett_tcg_tok_seq,
        &ett_tcg_comid_mgmt,
        &ett_tcg_l0,
        &ett_tcg_l0_feat,
        &ett_tcg_l0_tper_flags,
        &ett_tcg_l0_locking_flags,
        &ett_tcg_l0_geometry_flags,
        &ett_tcg_l0_siis_flags,
        &ett_tcg_l0_ent_flags,
        &ett_tcg_l0_opal1_flags,
        &ett_tcg_l0_opal2_flags,
        &ett_tcg_l0_sum_flags,
        &ett_tcg_l0_bsid_flags,
        &ett_tcg_l0_bsid_flags2,
        &ett_tcg_l0_cnl_flags,
        &ett_tcg_l0_drm_flags,
        &ett_tcg_l0_drm_mechanism,
        &ett_tcg_l0_drm_format,
    };

    expert_module_t *expert_tcg_storage;

    proto_tcg_storage = proto_register_protocol("TCG Storage Interface",
                                                "TCG Storage",
                                                "tcg-storage");
    proto_register_field_array(proto_tcg_storage, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_tcg_storage = expert_register_protocol(proto_tcg_storage);
    expert_register_field_array(expert_tcg_storage, ei, array_length(ei));

    tcg_storage_handle = register_dissector_with_description("tcg-storage",
            "TCG Storage Interface", dissect_tcg_storage, proto_tcg_storage);
}

void
proto_reg_handoff_tcg_storage(void)
{
    dissector_add_uint("nvme.security.secp", TCG_SECP_COMPACKET,
                       tcg_storage_handle);
    dissector_add_uint("nvme.security.secp", TCG_SECP_PROTO_MGMT,
                       tcg_storage_handle);
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
