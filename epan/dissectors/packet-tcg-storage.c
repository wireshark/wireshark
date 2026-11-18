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

/* TCG Storage Architecture Core Specification 2.01 and the Opal, Pyrite and
 * Enterprise SSCs, carried in NVMe Security Send/Receive: packet-nvme.c
 * dispatches through "nvme.security.secp" with a struct nvme_security_info.
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>
#include "packet-nvme.h"
#include "packet-tcg-storage.h"

void proto_register_tcg_storage(void);
void proto_reg_handoff_tcg_storage(void);

static int proto_tcg_storage;

static dissector_handle_t tcg_storage_handle;
static dissector_handle_t tcg_storage_send_failed_handle;

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
static int hf_tcg_tok_host_status;
static int hf_tcg_tok_fragment;
static int hf_tcg_tok_name;
static int hf_tcg_param;
static int hf_tcg_param_uid;
static int hf_tcg_response_to;
static int hf_tcg_request_in;
static int hf_tcg_response_in;
static int hf_tcg_txn_start_status;
static int hf_tcg_txn_end_status;
static int hf_tcg_secure_data;
/* Level 0 Discovery */
static int hf_tcg_level0_discovery;
static int hf_tcg_l0_length;
static int hf_tcg_l0_major_version;
static int hf_tcg_l0_minor_version;
static int hf_tcg_l0_unsupported_version;
static int hf_tcg_l0_reserved;
static int hf_tcg_l0_vendor;
/* Feature descriptor common header */
static int hf_tcg_l0_feat;
static int hf_tcg_l0_feat_code;
static int hf_tcg_l0_feat_version;
static int hf_tcg_l0_feat_reserved;
static int hf_tcg_l0_feat_ssc_minor;
static int hf_tcg_l0_feat_ds_minor;
static int hf_tcg_l0_feat_cnl_minor;
static int hf_tcg_l0_feat_length;
static int hf_tcg_l0_feat_data;
static int hf_tcg_l0_feat_reserved_tail;
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
static int hf_tcg_l0_locking_reserved_v1;
static int hf_tcg_l0_locking_reserved_v2;
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
/* Opal SSC V2 Feature (0x0203) */
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
/* Additional DataStore Tables Feature (0x0202) */
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
static int hf_tcg_l0_bsid_freeze_supported;
static int hf_tcg_l0_bsid_freeze_state;
/* Configurable Namespace Locking Feature (0x0403) */
static int hf_tcg_l0_cnl_flags;
static int hf_tcg_l0_cnl_range_c;
static int hf_tcg_l0_cnl_range_p;
static int hf_tcg_l0_cnl_sum_c;
static int hf_tcg_l0_cnl_reserved;
static int hf_tcg_l0_cnl_max_key_count;
static int hf_tcg_l0_cnl_unused_key_count;
static int hf_tcg_l0_cnl_max_ranges_per_ns;
/* Supported Data Removal Mechanism Feature (0x0404) */
static int hf_tcg_l0_drm_reserved;
static int hf_tcg_l0_drm_reserved1;
static int hf_tcg_l0_drm_reserved2;
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
static int hf_tcg_l0_drm_mech_unmap;
static int hf_tcg_l0_drm_mech_reset_wp;
static int hf_tcg_l0_drm_fmt_unmap;
static int hf_tcg_l0_drm_fmt_reset_wp;
static int hf_tcg_l0_drm_time_unmap;
static int hf_tcg_l0_drm_time_reset_wp;
/* SECP 02h ComID management */
static int hf_tcg_comid_mgmt_comid;
static int hf_tcg_comid_mgmt_comid_ext;
static int hf_tcg_comid_mgmt_request_code;
static int hf_tcg_comid_mgmt_avail_len;
static int hf_tcg_comid_mgmt_reserved;
static int hf_tcg_comid_mgmt_data;
static int hf_tcg_comid_mgmt_req_data;
static int hf_tcg_comid_mgmt_state;
static int hf_tcg_comid_mgmt_time_alloc;
static int hf_tcg_comid_mgmt_time_expiry;
static int hf_tcg_comid_mgmt_time_reset;
static int hf_tcg_comid_mgmt_date_year;
static int hf_tcg_comid_mgmt_date_month;
static int hf_tcg_comid_mgmt_date_day;
static int hf_tcg_comid_mgmt_date_hour;
static int hf_tcg_comid_mgmt_date_minute;
static int hf_tcg_comid_mgmt_date_second;
static int hf_tcg_comid_mgmt_date_fraction;
static int hf_tcg_comid_mgmt_date_reserved;
static int hf_tcg_comid_mgmt_stack_reset_result;
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
static int ett_tcg_comid_mgmt_date;
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
static expert_field ei_tcg_transfer_short;
static expert_field ei_tcg_tok_reserved;
static expert_field ei_tcg_tok_zero_length;
static expert_field ei_tcg_tok_pair;
static expert_field ei_tcg_tok_status_type;
static expert_field ei_tcg_tok_spans_compacket;
static expert_field ei_tcg_txn_status_type;
static expert_field ei_tcg_feat_length_align;
static expert_field ei_tcg_feat_length;
static expert_field ei_tcg_sequence_gap;
static expert_field ei_tcg_comid_mismatch;
static expert_field ei_tcg_subpacket_kind;
static expert_field ei_tcg_credit_length;
static expert_field ei_tcg_tper_reset_recv;
static expert_field ei_tcg_comid_mgmt_mismatch;

/* SIIS v1.20 Tables 23/24 map NVMe Security Send/Receive, including 03h;
 * only 06h is explicitly not defined for NVMe. No local 03h payload format
 * is available, so this dissector registers only 01h and 02h. */
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

/* ComID management request codes (Core Spec §3.3.4.7 Tables 32 and 35) */
#define TCG_REQ_NO_RESPONSE        0x00000000
#define TCG_REQ_VERIFY_COMID_VALID 0x00000001
#define TCG_REQ_STACK_RESET        0x00000002

/* 10-byte date value used by the VERIFY_COMID_VALID response (Table 34) */
#define TCG_COMID_DATE_LEN 10

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
/* Version 1 and 2 Length: Pyrite SSC 2.01 Table 7, Key Per I/O SSC 1.00
 * Table 6, Opal SSC 2.30 Table 9 */
#define TCG_L0_DRM_LEN           0x20
#define TCG_L0_GEOMETRY_V1_LEN   0x1C
#define TCG_L0_OPAL_V2_V2_LEN    0x10
#define TCG_L0_PYRITE_V2_LEN     0x10
/* Namespace Geometry Reporting: CNL 1.00 Table 10, Configurable Locking 1.30
 * Table 11 (Version 1, Length 0x1C), the Geometry Reporting layout. */
#define TCG_L0_FEAT_NS_GEOMETRY  0x0405

/* Vendor-specific feature code range */
#define TCG_L0_FEAT_VENDOR_FIRST 0xC000

/* TPer Feature Async flag (Core Table 42 byte 4); matches hf_tcg_l0_tper_async */
#define TCG_L0_TPER_ASYNC        0x02

static const value_string tcg_ack_type_vals[] = {
    { 0, "None" },
    { 1, "ACK" },
    { 2, "NAK" },
    { 0, NULL },
};

/* Core 2.01 Table 19: every other Kind is reserved. */
static const range_string tcg_subpacket_kind_rvals[] = {
    { TCG_SUBPACKET_KIND_DATA,       TCG_SUBPACKET_KIND_DATA,       "Data" },
    { TCG_SUBPACKET_KIND_DATA + 1,   TCG_SUBPACKET_KIND_CREDIT - 1, "Reserved" },
    { TCG_SUBPACKET_KIND_CREDIT,     TCG_SUBPACKET_KIND_CREDIT,     "Credit Control" },
    { TCG_SUBPACKET_KIND_CREDIT + 1, 0xFFFF,                        "Reserved" },
    { 0, 0, NULL },
};

/* Core 2.01 Table 04; atom encodings below E4h are not reserved tokens. */
static const range_string tcg_token_control_vals[] = {
    { 0xE4, 0xEF, "Reserved" },
    { TCG_TOK_START_LIST, TCG_TOK_START_LIST, "Start List" },
    { TCG_TOK_END_LIST, TCG_TOK_END_LIST, "End List" },
    { TCG_TOK_START_NAME, TCG_TOK_START_NAME, "Start Name" },
    { TCG_TOK_END_NAME, TCG_TOK_END_NAME, "End Name" },
    { 0xF4, 0xF7, "Reserved" },
    { TCG_TOK_CALL, TCG_TOK_CALL, "Call" },
    { TCG_TOK_END_OF_DATA, TCG_TOK_END_OF_DATA, "End of Data" },
    { TCG_TOK_END_SESSION, TCG_TOK_END_SESSION, "End of Session" },
    { TCG_TOK_START_TXN, TCG_TOK_START_TXN, "Start Transaction" },
    { TCG_TOK_END_TXN, TCG_TOK_END_TXN, "End Transaction" },
    { 0xFD, 0xFE, "Reserved" },
    { TCG_TOK_EMPTY, TCG_TOK_EMPTY, "Empty" },
    { 0, 0, NULL },
};

/* Well-known 8-byte UIDs: Core 2.01 Appendix 1 (Tables 239-248) and the
 * Opal SSC 2.30 Admin/Locking SP preconfiguration.  tcg_uid_name() adds the
 * numbered families and table rows these exact entries do not list. */
static const val64_string tcg_uid_vals[] = {
    /* Special purpose UIDs (Table 239) */
    { 0x0000000000000000, "Null UID" },
    { 0x0000000000000001, "This SP" },
    { 0x00000000000000FF, "Session Manager (SMUID)" },
    /* Session Manager methods (Table 241) */
    { 0x000000000000FF01, "Properties" },
    { 0x000000000000FF02, "StartSession" },
    { 0x000000000000FF03, "SyncSession" },
    { 0x000000000000FF04, "StartTrustedSession" },
    { 0x000000000000FF05, "SyncTrustedSession" },
    { 0x000000000000FF06, "CloseSession" },
    /* MethodID UIDs (Table 242).  06h/07h/0Ch are obsolete in Core 2.01;
     * the Enterprise SSC still uses them for Get/Set/Authenticate. 11h,
     * 202h and 203h are Opal's RevertSP, Revert and Activate; 803h is the
     * Enterprise Erase. */
    { 0x0000000600000001, "DeleteSP" },
    { 0x0000000600000002, "CreateTable" },
    { 0x0000000600000003, "Delete" },
    { 0x0000000600000004, "CreateRow" },
    { 0x0000000600000005, "DeleteRow" },
    { 0x0000000600000006, "Get (Enterprise)" },
    { 0x0000000600000007, "Set (Enterprise)" },
    { 0x0000000600000008, "Next" },
    { 0x0000000600000009, "GetFreeSpace" },
    { 0x000000060000000A, "GetFreeRows" },
    { 0x000000060000000B, "DeleteMethod" },
    { 0x000000060000000C, "Authenticate (Enterprise)" },
    { 0x000000060000000D, "GetACL" },
    { 0x000000060000000E, "AddACE" },
    { 0x000000060000000F, "RemoveACE" },
    { 0x0000000600000010, "GenKey" },
    { 0x0000000600000011, "RevertSP" },
    { 0x0000000600000012, "GetPackage" },
    { 0x0000000600000013, "SetPackage" },
    { 0x0000000600000016, "Get" },
    { 0x0000000600000017, "Set" },
    { 0x000000060000001C, "Authenticate" },
    { 0x0000000600000201, "IssueSP" },
    { 0x0000000600000202, "Revert" },
    { 0x0000000600000203, "Activate" },
    { 0x0000000600000401, "GetClock" },
    { 0x0000000600000402, "ResetClock" },
    { 0x0000000600000403, "SetClockHigh" },
    { 0x0000000600000404, "SetLagHigh" },
    { 0x0000000600000405, "SetClockLow" },
    { 0x0000000600000406, "SetLagLow" },
    { 0x0000000600000407, "IncrementCounter" },
    { 0x0000000600000601, "Random" },
    { 0x0000000600000602, "Salt" },
    { 0x0000000600000603, "DecryptInit" },
    { 0x0000000600000604, "Decrypt" },
    { 0x0000000600000605, "DecryptFinalize" },
    { 0x0000000600000606, "EncryptInit" },
    { 0x0000000600000607, "Encrypt" },
    { 0x0000000600000608, "EncryptFinalize" },
    { 0x0000000600000609, "HMACInit" },
    { 0x000000060000060A, "HMAC" },
    { 0x000000060000060B, "HMACFinalize" },
    { 0x000000060000060C, "HashInit" },
    { 0x000000060000060D, "Hash" },
    { 0x000000060000060E, "HashFinalize" },
    { 0x000000060000060F, "Sign" },
    { 0x0000000600000610, "Verify" },
    { 0x0000000600000611, "XOR" },
    { 0x0000000600000803, "Erase (Enterprise)" },
    { 0x0000000600000A01, "AddLog" },
    { 0x0000000600000A02, "CreateLog" },
    { 0x0000000600000A03, "ClearLog" },
    { 0x0000000600000A04, "FlushLog" },
    /* SP UIDs (Table 245; Opal Locking SP) */
    { 0x0000020500000001, "Admin SP" },
    { 0x0000020500000002, "Locking SP" },
    { 0x0000020500010001, "Locking SP (Enterprise)" },
    /* Authority UIDs (Table 243).  Opal's Admin SP AdminXX authorities
     * (0x0000000900000200 + XX) override Core's Admin template
     * Issuers..Reserve3 at 201h-208h; tcg_uid_name() names them. */
    { 0x0000000900000001, "Anybody" },
    { 0x0000000900000002, "Admins" },
    { 0x0000000900000003, "Makers" },
    { 0x0000000900000004, "MakerSymK" },
    { 0x0000000900000005, "MakerPuK" },
    { 0x0000000900000006, "SID" },
    { 0x0000000900000007, "TPerSign" },
    { 0x0000000900000008, "TPerExch" },
    { 0x0000000900000009, "AdminExch" },
    { 0x0000000900030000, "Users" },
    /* C_PIN (Table 245; Opal Admin SP) */
    { 0x0000000B00000001, "C_PIN_SID" },
    { 0x0000000B00008402, "C_PIN_MSID" },
    /* Single row tables (Table 244) and default rows (Table 245) */
    { 0x0000000200000001, "SPInfo" },
    { 0x0000020100000001, "TPerInfo" },
    { 0x0000040100000001, "Clock" },
    { 0x00000A0200000001, "Log" },
    { 0x0000080100000001, "LockingInfo" },
    { 0x0000080200000001, "Locking_GlobalRange" },
    { 0x0000080300000001, "MBRControl" },
    { 0x0000080400000000, "MBR (Shadow MBR table)" },
    { 0x0000080500000001, "K_AES_128_GlobalRange_Key" },
    { 0x0000080600000001, "K_AES_256_GlobalRange_Key" },
    /* Template (Table 246) and SPTemplates (Table 247) rows */
    { 0x0000020400000001, "Base Template" },
    { 0x0000020400000002, "Admin Template" },
    { 0x0000020400000003, "Clock Template" },
    { 0x0000020400000004, "Crypto Template" },
    { 0x0000020400000005, "Log Template" },
    { 0x0000020400000006, "Locking Template" },
    { 0x0000000300000001, "SPTemplates Base" },
    { 0x0000000300000002, "SPTemplates Admin" },
    { 0x0000000300000003, "SPTemplates Clock" },
    { 0x0000000300000004, "SPTemplates Crypto" },
    { 0x0000000300000005, "SPTemplates Log" },
    { 0x0000000300000006, "SPTemplates Locking" },
    /* Opal SecretProtect rows for the media encryption keys */
    { 0x0000001D0000001D, "SecretProtect K_AES_128" },
    { 0x0000001D0000001E, "SecretProtect K_AES_256" },
    /* Opal Admin SP ACEs */
    { 0x0000000800000001, "ACE_Anybody" },
    { 0x0000000800000002, "ACE_Admin" },
    { 0x0000000800008C02, "ACE_C_PIN_SID_Get_NOPIN" },
    { 0x0000000800008C03, "ACE_C_PIN_SID_Set_PIN" },
    { 0x0000000800008C04, "ACE_C_PIN_MSID_Get_PIN" },
    { 0x0000000800030001, "ACE_Set_Enabled" },
    { 0x0000000800030002, "ACE_SP_SID" },
    { 0x0000000800030003, "ACE_TPerInfo_Set_ProgrammaticResetEnable" },
    { 0x000000080003A001, "ACE_C_PIN_Admins_Set_PIN" },
    { 0x0000000800050001, "ACE_DataRemovalMechanism_Set_ActiveDataRemovalMechanism" },
    /* Opal Locking SP ACEs */
    { 0x0000000800000003, "ACE_Anybody_Get_CommonName" },
    { 0x0000000800000004, "ACE_Admins_Set_CommonName" },
    { 0x0000000800038000, "ACE_ACE_Get_All" },
    { 0x0000000800038001, "ACE_ACE_Set_BooleanExpression" },
    { 0x0000000800039000, "ACE_Authority_Get_All" },
    { 0x0000000800039001, "ACE_Authority_Set_Enabled" },
    { 0x000000080003A000, "ACE_C_PIN_Admins_Get_All_NOPIN" },
    { 0x000000080003BFFF, "ACE_K_AES_Mode" },
    { 0x000000080003F000, "ACE_Locking_GlblRng_Admins_Set" },
    { 0x000000080003F001, "ACE_Locking_Admins_RangeStartToLOR" },
    { 0x000000080003F800, "ACE_MBRControl_Admins_Set" },
    { 0x000000080003F801, "ACE_MBRControl_Set_DoneToDOR" },
    { 0x000000080003FC00, "ACE_DataStore_Get_All" },
    { 0x000000080003FC01, "ACE_DataStore_Set_All" },
    { 0, NULL },
};

/* Table UIDs TTTTTTTT_00000000 by their upper half (Core Table 240; Opal
 * DataStore).  The Table table row describing table T is 00000001_TTTTTTTT. */
static const value_string tcg_table_vals[] = {
    { 0x00000001, "Table" },
    { 0x00000002, "SPInfo" },
    { 0x00000003, "SPTemplates" },
    { 0x00000004, "Column" },
    { 0x00000005, "Type" },
    { 0x00000006, "MethodID" },
    { 0x00000007, "AccessControl" },
    { 0x00000008, "ACE" },
    { 0x00000009, "Authority" },
    { 0x0000000A, "Certificates" },
    { 0x0000000B, "C_PIN" },
    { 0x0000000C, "C_RSA_1024" },
    { 0x0000000D, "C_RSA_2048" },
    { 0x0000000E, "C_AES_128" },
    { 0x0000000F, "C_AES_256" },
    { 0x00000010, "C_EC_160" },
    { 0x00000011, "C_EC_192" },
    { 0x00000012, "C_EC_224" },
    { 0x00000013, "C_EC_256" },
    { 0x00000014, "C_EC_384" },
    { 0x00000015, "C_EC_521" },
    { 0x00000016, "C_EC_163" },
    { 0x00000017, "C_EC_233" },
    { 0x00000018, "C_EC_283" },
    { 0x00000019, "C_HMAC_160" },
    { 0x0000001A, "C_HMAC_256" },
    { 0x0000001B, "C_HMAC_384" },
    { 0x0000001C, "C_HMAC_512" },
    { 0x0000001D, "SecretProtect" },
    { 0x00000201, "TPerInfo" },
    { 0x00000203, "CryptoSuite" },
    { 0x00000204, "Template" },
    { 0x00000205, "SP" },
    { 0x00000401, "ClockTime" },
    { 0x00000601, "H_SHA_1" },
    { 0x00000602, "H_SHA_256" },
    { 0x00000603, "H_SHA_384" },
    { 0x00000604, "H_SHA_512" },
    { 0x00000801, "LockingInfo" },
    { 0x00000802, "Locking" },
    { 0x00000803, "MBRControl" },
    { 0x00000804, "MBR" },
    { 0x00000805, "K_AES_128" },
    { 0x00000806, "K_AES_256" },
    { 0x00000A01, "Log" },
    { 0x00000A02, "LogList" },
    { 0x00001001, "DataStore" },
    { 0, NULL },
};

/* Opal SSC 2.30 numbered object families (Admin SP 4.2, Locking SP 4.3):
 * the row number carries the Admin, User or Range number. */
static const char *
tcg_uid_family_name(wmem_allocator_t *scope, uint64_t uid)
{
    uint32_t row = (uint32_t)uid;

    switch ((uint32_t)(uid >> 32)) {
    case 0x00000009:
        if (row > 0x200 && row <= 0x2FF)
            return wmem_strdup_printf(scope, "Admin%u (Admin SP)", row - 0x200);
        if (row > 0x00010000 && row <= 0x0001FFFF)
            return wmem_strdup_printf(scope, "Admin%u", row - 0x00010000);
        if (row > 0x00030000 && row <= 0x0003FFFF)
            return wmem_strdup_printf(scope, "User%u", row - 0x00030000);
        break;
    case 0x0000000B:
        if (row > 0x200 && row <= 0x2FF)
            return wmem_strdup_printf(scope, "C_PIN_Admin%u (Admin SP)", row - 0x200);
        if (row > 0x00010000 && row <= 0x0001FFFF)
            return wmem_strdup_printf(scope, "C_PIN_Admin%u", row - 0x00010000);
        if (row > 0x00030000 && row <= 0x0003FFFF)
            return wmem_strdup_printf(scope, "C_PIN_User%u", row - 0x00030000);
        break;
    case 0x00000802:
        if (row > 0x00030000 && row <= 0x0003FFFF)
            return wmem_strdup_printf(scope, "Locking_Range%u", row - 0x00030000);
        break;
    case 0x00000805:
    case 0x00000806:
        if (row > 0x00030000 && row <= 0x0003FFFF)
            return wmem_strdup_printf(scope, "K_AES_%s_Range%u_Key",
                                      (uid >> 32) == 0x805 ? "128" : "256",
                                      row - 0x00030000);
        break;
    case 0x00000008:
    {
        static const struct {
            uint32_t base, last;
            bool ranges;    /* base + 0 is the Global Range, base + N RangeN */
            const char *prefix, *suffix;
        } aces[] = {
            { 0x0003A800, 0x0003AFFF, false, "ACE_C_PIN_User", "_Set_PIN" },
            { 0x0003B000, 0x0003B7FF, true, "ACE_K_AES_128_", "_GenKey" },
            { 0x0003B800, 0x0003BFFE, true, "ACE_K_AES_256_", "_GenKey" },
            { 0x0003D000, 0x0003DFFF, true, "ACE_Locking_", "_Get_RangeStartToActiveKey" },
            { 0x0003E000, 0x0003E7FF, true, "ACE_Locking_", "_Set_RdLocked" },
            { 0x0003E800, 0x0003EFFF, true, "ACE_Locking_", "_Set_WrLocked" },
            { 0x00044000, 0x00050000, false, "ACE_User", "_Set_CommonName" },
        };
        for (unsigned i = 0; i < array_length(aces); i++) {
            unsigned n = row - aces[i].base;
            if (row < aces[i].base || row > aces[i].last || (!n && !aces[i].ranges))
                continue;
            if (!aces[i].ranges)
                return wmem_strdup_printf(scope, "%s%u%s", aces[i].prefix, n, aces[i].suffix);
            if (!n)
                return wmem_strdup_printf(scope, "%sGlobalRange%s", aces[i].prefix, aces[i].suffix);
            return wmem_strdup_printf(scope, "%sRange%u%s", aces[i].prefix, n, aces[i].suffix);
        }
        break;
    }
    default:
        break;
    }
    return NULL;
}

/* Name a UID; NULL if it has none.  An unlisted row of a known table is
 * named after the table only where the position is defined to be a UID
 * (rows), never for a method UID or an arbitrary 8-byte value. */
static const char *
tcg_uid_name(wmem_allocator_t *scope, uint64_t uid, bool rows)
{
    const char *name = try_val64_to_str(uid, tcg_uid_vals);
    uint32_t    table = (uint32_t)(uid >> 32), row = (uint32_t)uid;

    if (!name)
        name = tcg_uid_family_name(scope, uid);
    if (name || !rows)
        return name;
    if (table == 0x00000001 && try_val_to_str(row, tcg_table_vals))
        return wmem_strdup_printf(scope, "%s table descriptor",
                                  val_to_str_const(row, tcg_table_vals, ""));
    name = try_val_to_str(table, tcg_table_vals);
    if (!name || row == 0)
        return name;
    return wmem_strdup_printf(scope, "%s row 0x%08x", name, row);
}

/* Method signatures (Core 2.01 5.2.3, 5.3.3, 5.3.4.1, 5.6.4; Opal SSC 2.30
 * 5.1.3).  Required parameters are positional; optional ones are
 * "StartName <uinteger number> value EndName" (Core 3.2.4.1).  Only the
 * kinds below decode further; Feature Set options stay numbered. */
enum {
    TCG_PARAM_PLAIN,
    TCG_PARAM_UID,          /* a uidref: resolve an 8-byte bytes atom */
    TCG_PARAM_UID_LIST,     /* a list of uidrefs */
    TCG_PARAM_CELLBLOCK     /* Core 5.1.4.2.6 cell_block */
};

typedef struct {
    uint32_t    number;     /* optional parameter or Cellblock name */
    const char *name;
    uint8_t     kind;
} tcg_param_def;

#define TCG_PARAMS_END { 0, NULL, TCG_PARAM_PLAIN }

static const tcg_param_def tcg_cellblock_names[] = {
    { 0, "Table", TCG_PARAM_UID },
    { 1, "startRow", TCG_PARAM_UID },
    { 2, "endRow", TCG_PARAM_PLAIN },
    { 3, "startColumn", TCG_PARAM_PLAIN },
    { 4, "endColumn", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};

static const tcg_param_def tcg_req_none[] = { TCG_PARAMS_END };
static const tcg_param_def tcg_req_properties[] = {
    { 0, "Properties", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_opt_properties[] = {
    { 0, "HostProperties", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_req_start_session[] = {
    { 0, "HostSessionID", TCG_PARAM_PLAIN },
    { 0, "SPID", TCG_PARAM_UID },
    { 0, "Write", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_start_session[] = {
    { 0, "HostChallenge", TCG_PARAM_PLAIN },
    { 1, "HostExchangeAuthority", TCG_PARAM_UID },
    { 2, "HostExchangeCert", TCG_PARAM_PLAIN },
    { 3, "HostSigningAuthority", TCG_PARAM_UID },
    { 4, "HostSigningCert", TCG_PARAM_PLAIN },
    { 5, "SessionTimeout", TCG_PARAM_PLAIN },
    { 6, "TransTimeout", TCG_PARAM_PLAIN },
    { 7, "InitialCredit", TCG_PARAM_PLAIN },
    { 8, "SignedHash", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_session_ids[] = {
    { 0, "HostSessionID", TCG_PARAM_PLAIN },
    { 0, "SPSessionID", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_sync_session[] = {
    { 0, "SPChallenge", TCG_PARAM_PLAIN },
    { 1, "SPExchangeCert", TCG_PARAM_PLAIN },
    { 2, "SPSigningCert", TCG_PARAM_PLAIN },
    { 3, "TransTimeout", TCG_PARAM_PLAIN },
    { 4, "InitialCredit", TCG_PARAM_PLAIN },
    { 5, "SignedHash", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_start_trusted[] = {
    { 0, "HostResponse", TCG_PARAM_PLAIN },
    { 1, "HostEncryptSessionKey", TCG_PARAM_PLAIN },
    { 2, "HostIntegritySessionKey", TCG_PARAM_PLAIN },
    { 3, "SignedHash", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_sync_trusted[] = {
    { 0, "SPResponse", TCG_PARAM_PLAIN },
    { 1, "SPEncryptSessionKey", TCG_PARAM_PLAIN },
    { 2, "SPIntegritySessionKey", TCG_PARAM_PLAIN },
    { 3, "SignedHash", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_close_session[] = {
    { 0, "RemoteSessionNumber", TCG_PARAM_PLAIN },
    { 0, "LocalSessionNumber", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_get[] = {
    { 0, "Cellblock", TCG_PARAM_CELLBLOCK }, TCG_PARAMS_END };
static const tcg_param_def tcg_opt_set[] = {
    { 0, "Where", TCG_PARAM_UID },
    { 1, "Values", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_next[] = {
    { 0, "Where", TCG_PARAM_UID },
    { 1, "Count", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_authenticate[] = {
    { 0, "Authority", TCG_PARAM_UID }, TCG_PARAMS_END };
static const tcg_param_def tcg_opt_authenticate[] = {
    { 0, "Proof", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_req_method_ref[] = {
    { 0, "InvokingID", TCG_PARAM_UID },
    { 0, "MethodID", TCG_PARAM_UID },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_ace[] = {
    { 0, "InvokingID", TCG_PARAM_UID },
    { 0, "MethodID", TCG_PARAM_UID },
    { 0, "ACE", TCG_PARAM_UID },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_genkey[] = {
    { 0, "PublicExponent", TCG_PARAM_PLAIN },
    { 1, "PinLength", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_create_row[] = {
    { 0, "Row", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_req_delete_row[] = {
    { 0, "Rows", TCG_PARAM_UID_LIST }, TCG_PARAMS_END };
static const tcg_param_def tcg_req_get_package[] = {
    { 0, "Purpose", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_opt_get_package[] = {
    { 0, "WrappingKey", TCG_PARAM_UID },
    { 1, "SigningKey", TCG_PARAM_UID },
    { 2, "Date", TCG_PARAM_PLAIN },
    { 3, "Log", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_set_package[] = {
    { 0, "Value", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_opt_set_package[] = {
    { 0, "WrappingKey", TCG_PARAM_UID },
    { 1, "SigningKey", TCG_PARAM_UID },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_create_table[] = {
    { 0, "NewTableName", TCG_PARAM_PLAIN },
    { 0, "Kind", TCG_PARAM_PLAIN },
    { 0, "GetSetACL", TCG_PARAM_PLAIN },
    { 0, "Columns", TCG_PARAM_PLAIN },
    { 0, "MinSize", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_opt_create_table[] = {
    { 0, "MaxSize", TCG_PARAM_PLAIN },
    { 1, "HintSize", TCG_PARAM_PLAIN },
    { 2, "CommonName", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_req_random[] = {
    { 0, "Count", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_opt_random[] = {
    { 0, "BufferOut", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
/* Opal 5.1.3.2: the parameter number SHALL be 0x060000. */
static const tcg_param_def tcg_opt_revert_sp[] = {
    { 0x060000, "KeepGlobalRangeKey", TCG_PARAM_PLAIN }, TCG_PARAMS_END };

typedef struct {
    uint64_t method;
    const tcg_param_def *req, *opt;
} tcg_signature;

static const tcg_signature tcg_signatures[] = {
    { 0xFF02, tcg_req_start_session, tcg_opt_start_session },
    { 0xFF03, tcg_req_session_ids, tcg_opt_sync_session },
    { 0xFF04, tcg_req_session_ids, tcg_opt_start_trusted },
    { 0xFF05, tcg_req_session_ids, tcg_opt_sync_trusted },
    { 0xFF06, tcg_req_close_session, tcg_req_none },
    { 0x0000000600000001, tcg_req_none, tcg_req_none },     /* DeleteSP */
    { 0x0000000600000002, tcg_req_create_table, tcg_opt_create_table },
    { 0x0000000600000003, tcg_req_none, tcg_req_none },     /* Delete */
    { 0x0000000600000004, tcg_req_create_row, tcg_req_none },
    { 0x0000000600000005, tcg_req_delete_row, tcg_req_none },
    { 0x0000000600000008, tcg_req_none, tcg_opt_next },
    { 0x0000000600000009, tcg_req_none, tcg_req_none },     /* GetFreeSpace */
    { 0x000000060000000A, tcg_req_none, tcg_req_none },     /* GetFreeRows */
    { 0x000000060000000B, tcg_req_method_ref, tcg_req_none }, /* DeleteMethod */
    { 0x000000060000000D, tcg_req_method_ref, tcg_req_none }, /* GetACL */
    { 0x000000060000000E, tcg_req_ace, tcg_req_none },      /* AddACE */
    { 0x000000060000000F, tcg_req_ace, tcg_req_none },      /* RemoveACE */
    { 0x0000000600000010, tcg_req_none, tcg_opt_genkey },
    { 0x0000000600000011, tcg_req_none, tcg_opt_revert_sp },
    { 0x0000000600000012, tcg_req_get_package, tcg_opt_get_package },
    { 0x0000000600000013, tcg_req_set_package, tcg_opt_set_package },
    { 0x0000000600000016, tcg_req_get, tcg_req_none },
    { 0x0000000600000017, tcg_req_none, tcg_opt_set },
    { 0x000000060000001C, tcg_req_authenticate, tcg_opt_authenticate },
    { 0x0000000600000202, tcg_req_none, tcg_req_none },     /* Revert */
    { 0x0000000600000203, tcg_req_none, tcg_req_none },     /* Activate */
    { 0x0000000600000601, tcg_req_random, tcg_opt_random },
};

/* Method results (Core 5.3.3, 5.4.3.1 Random), the required "parameters"
 * of the response's result list.  Methods returning [ ] are not listed. */
static const tcg_param_def tcg_res_create_table[] = {
    { 0, "UID", TCG_PARAM_UID },
    { 0, "Rows", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_res_uid_list[] = {
    { 0, "Result", TCG_PARAM_UID_LIST }, TCG_PARAMS_END };
static const tcg_param_def tcg_res_plain[] = {
    { 0, "Result", TCG_PARAM_PLAIN }, TCG_PARAMS_END };
static const tcg_param_def tcg_res_free_space[] = {
    { 0, "FreeSpace", TCG_PARAM_PLAIN },
    { 0, "TableRows", TCG_PARAM_PLAIN },
    TCG_PARAMS_END
};
static const tcg_param_def tcg_res_free_rows[] = {
    { 0, "FreeRows", TCG_PARAM_PLAIN }, TCG_PARAMS_END };

static const tcg_signature tcg_result_signatures[] = {
    { 0x0000000600000002, tcg_res_create_table, tcg_req_none },
    { 0x0000000600000004, tcg_res_uid_list, tcg_req_none },     /* CreateRow */
    { 0x0000000600000005, tcg_res_plain, tcg_req_none },        /* DeleteRow */
    { 0x0000000600000008, tcg_res_uid_list, tcg_req_none },     /* Next */
    { 0x0000000600000009, tcg_res_free_space, tcg_req_none },
    { 0x000000060000000A, tcg_res_free_rows, tcg_req_none },
    { 0x000000060000000D, tcg_res_uid_list, tcg_req_none },     /* GetACL */
    { 0x0000000600000012, tcg_res_plain, tcg_req_none },        /* GetPackage */
    { 0x0000000600000016, tcg_res_plain, tcg_req_none },        /* Get */
    { 0x000000060000001C, tcg_res_plain, tcg_req_none },        /* Authenticate */
    { 0x0000000600000601, tcg_res_plain, tcg_req_none },        /* Random */
};

static const tcg_signature *
tcg_find_result_signature(uint64_t method)
{
    for (unsigned i = 0; i < array_length(tcg_result_signatures); i++)
        if (tcg_result_signatures[i].method == method)
            return &tcg_result_signatures[i];
    return NULL;
}

/* Properties (5.2.2.1/5.2.2.2) differs by direction: the TPer's call
 * carries the required Properties list before HostProperties. */
static const tcg_signature tcg_sig_properties_host = {
    0xFF01, tcg_req_none, tcg_opt_properties };
static const tcg_signature tcg_sig_properties_tper = {
    0xFF01, tcg_req_properties, tcg_opt_properties };

static const tcg_signature *
tcg_find_signature(uint64_t invoking, uint64_t method, bool send)
{
    bool session_manager = invoking == 0xFF;

    if (session_manager != ((method >> 8) == 0xFF))
        return NULL;
    if (method == 0xFF01)
        return send ? &tcg_sig_properties_host : &tcg_sig_properties_tper;
    for (unsigned i = 0; i < array_length(tcg_signatures); i++)
        if (tcg_signatures[i].method == method)
            return &tcg_signatures[i];
    return NULL;
}

/* Core Table 166 and SIIS Table 1. The uinteger domain is open. */
static const val64_string tcg_method_status_vals[] = {
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
    { 0x0D, "OBSOLETE" },
    { 0x0E, "OBSOLETE" },
    { 0x0F, "TPER_MALFUNCTION" },
    { 0x10, "TRANSACTION_FAILURE" },
    { 0x11, "RESPONSE_OVERFLOW" },
    { 0x12, "AUTHORITY_LOCKED_OUT" },
    { 0x13, "INCOMPATIBLE_MBR_FORMAT" },
    { 0x14, "WP_DATA_REMAIN" },
    { 0x3F, "FAIL" },
    { 0, NULL },
};

/* Core 3.3.4.7.3-.5 define two request codes, with an open allocation.
 * Zero is a response-only marker (Table 31), not a third request. */
static const value_string tcg_request_code_vals[] = {
    { TCG_REQ_VERIFY_COMID_VALID, "VERIFY COMID VALID" },
    { TCG_REQ_STACK_RESET,        "PROTOCOL STACK RESET" },
    { 0, NULL },
};

/* Current state of the Extended ComID (Core Spec Table 33) */
static const value_string tcg_comid_state_vals[] = {
    { 0x00000000, "Invalid" },
    { 0x00000001, "Inactive" },
    { 0x00000002, "Issued" },
    { 0x00000003, "Associated" },
    { 0, NULL },
};

/* STACK_RESET response status (Core Spec Table 36) */
static const value_string tcg_stack_reset_result_vals[] = {
    { 0x00000000, "Success" },
    { 0x00000001, "Failure" },
    { 0, NULL },
};

static const value_string tcg_l0_feature_code_vals[] = {
    { 0x0000,                   "Reserved" },
    { TCG_L0_FEAT_TPER,         "TPer Feature" },
    { TCG_L0_FEAT_LOCKING,      "Locking Feature" },
    { TCG_L0_FEAT_GEOMETRY,     "Geometry Reporting Feature" },
    { TCG_L0_FEAT_SIIS,         "SIIS Feature" },
    { TCG_L0_FEAT_ENTERPRISE,   "Enterprise SSC Feature" },
    { TCG_L0_FEAT_OPAL_V1,      "Opal SSC 1.00 Feature" },
    { TCG_L0_FEAT_SUM,          "Single User Mode Feature" },
    { TCG_L0_FEAT_DATASTORE,    "Additional DataStore Tables Feature" },
    { TCG_L0_FEAT_OPAL_V2,      "Opal SSC V2 Feature" },
    { TCG_L0_FEAT_OPALITE,      "Opalite SSC Feature" },
    { TCG_L0_FEAT_PYRITE_V1,    "Pyrite SSC 1.0 Feature" },
    { TCG_L0_FEAT_PYRITE_V2,    "Pyrite SSC 2.0 Feature" },
    { TCG_L0_FEAT_RUBY,         "Ruby SSC Feature" },
    /* Named only; their bodies are shown raw. Key Per I/O SSC 1.00 §3.1.1.3 */
    { 0x0305,                   "Key Per I/O SSC v1.00 Feature" },
    /* Locking LBA Ranges Control 1.00 §4.1.1 */
    { 0x0401,                   "Locking LBA Ranges Control Feature" },
    { TCG_L0_FEAT_BLOCK_SID,    "Block SID Authentication Feature" },
    { TCG_L0_FEAT_CNL,          "Configurable Namespace Locking Feature" },
    { TCG_L0_FEAT_DATA_REMOVAL, "Supported Data Removal Mechanism Feature" },
    { TCG_L0_FEAT_NS_GEOMETRY,  "Namespace Geometry Reporting Feature" },
    /* Named only. Shadow MBR for Multiple Namespaces 1.00 §3.1.1, C_PIN
     * Enhancements 1.00 §4.2.1, Key Per I/O SSC 1.00 §3.1.2.5, Logical Port
     * Locking 1.00 §5.2.1, MEK Multiparty Authorization 1.00 §5.2.1, Epoch
     * Key Purge V1 §5.2.1 */
    { 0x0407,                   "Shadow MBR for Multiple Namespaces Feature" },
    { 0x0409,                   "C_PIN Enhancements Feature" },
    { 0x040A,                   "Namespace Key Per I/O Capabilities Feature" },
    { 0x040B,                   "Logical Port Locking Feature" },
    { 0x040C,                   "MEK Multiparty Authorization Feature" },
    { 0x040D,                   "Epoch Key Purge Feature" },
    { 0, NULL },
};

/* SIIS 1.20 Table 3: 1.20 is encoded as 20h, not the next ordinal. */
static const range_string tcg_l0_siis_revision_vals[] = {
    { 0x00, 0x00, "SIIS v1.00 r1.00" },
    { 0x01, 0x01, "SIIS v1.01 r1.00" },
    { 0x02, 0x02, "SIIS v1.02 r1.00" },
    { 0x03, 0x03, "SIIS v1.03 r1.00" },
    { 0x04, 0x04, "SIIS v1.04 r1.00" },
    { 0x05, 0x05, "SIIS v1.05 r1.00" },
    { 0x06, 0x06, "SIIS v1.06 r1.00" },
    { 0x07, 0x07, "SIIS v1.07 r1.00" },
    { 0x08, 0x08, "SIIS v1.08 r1.00" },
    { 0x09, 0x09, "SIIS v1.09 r1.00" },
    { 0x0a, 0x0a, "SIIS v1.10 r1.00" },
    { 0x0b, 0x0b, "SIIS v1.11 r1.00" },
    { 0x0c, 0x1f, "Reserved" },
    { 0x20, 0x20, "SIIS v1.20 r1.00" },
    { 0x21, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* SIIS v1.20 Table 4 */
static const value_string tcg_l0_siis_id_scope_vals[] = {
    { 0x0, "Not indicated" },
    { 0x1, "Transport identifier not used for Persistent Reservation impact" },
    { 0x2, "Transport identifier used for Persistent Reservation impact" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* The low nibble of a feature descriptor's version byte is Reserved except
 * from Version 2 of Opal SSC V2, where it is the SSC Minor Version Number
 * (Opal SSC 2.30 Tables 6/7; Reserved in Version 1, Opal SSC 2.00/2.01 Table
 * 7), and of Additional DataStore Tables and Configurable Namespace Locking,
 * where it is the Feature Set Minor Version Number (below). */
static const range_string tcg_l0_opal2_minor_rvals[] = {
    { 0x0, 0x0, "Opal SSC 2.00" },
    { 0x1, 0x1, "Opal SSC 2.01" },
    { 0x2, 0x2, "Opal SSC 2.02" },
    { 0x3, 0x3, "Opal SSC 2.30" },
    { 0x4, 0xF, "Reserved" },
    { 0, 0, NULL },
};

/* Additional DataStore Tables 1.01 Table 3 (Version 2) */
static const range_string tcg_l0_ds_minor_rvals[] = {
    { 0x0, 0x0, "Additional DataStore Tables Feature Set v1.00" },
    { 0x1, 0x1, "Additional DataStore Tables Feature Set v1.01" },
    { 0x2, 0xF, "Reserved" },
    { 0, 0, NULL },
};

/* Configurable Locking for NVMe Namespaces and SCSI LUNs 1.30 Table 7
 * (Version 2; Reserved in Version 1, CNL 1.00 Table 6) */
static const range_string tcg_l0_cnl_minor_rvals[] = {
    { 0x0, 0x0, "Configurable Namespace Locking v1.00" },
    { 0x1, 0x1, "Configurable Locking for NVMe Namespaces and SCSI LUNs v1.01" },
    { 0x2, 0x2, "Configurable Locking for NVMe Namespaces and SCSI LUNs v1.02" },
    { 0x3, 0x3, "Configurable Locking for NVMe Namespaces and SCSI LUNs v1.30" },
    { 0x4, 0xF, "Reserved" },
    { 0, 0, NULL },
};

/* Opal SSC 2.30 §3.1.1.5: Initial C_PIN_SID PIN Indicator and Behavior of
 * C_PIN_SID PIN upon TPer Revert share one encoding. */
static const range_string tcg_l0_opal2_cpin_sid_rvals[] = {
    { 0x00, 0x00, "C_PIN_SID PIN equals C_PIN_MSID PIN" },
    { 0x01, 0xFE, "Reserved" },
    { 0xFF, 0xFF, "Vendor Unique (may differ from C_PIN_MSID PIN)" },
    { 0, 0, NULL },
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

/* Blame the transfer only when no enclosing structure is complete.
 * Base 2.3 Fig 395 (Receive AL), Fig 399 (Send TL). */
static void
tcg_report_length_overrun(packet_info *pinfo, proto_item *len_item,
                          proto_item *struct_item, uint64_t declared_end,
                          uint32_t xfer_len, bool parent_complete)
{
    if (!parent_complete && xfer_len != 0 && declared_end <= (uint64_t)xfer_len)
        expert_add_info(pinfo, struct_item, &ei_tcg_transfer_short);
    else
        expert_add_info(pinfo, len_item, &ei_tcg_length_overrun);
}

/*
 * A leftover run too short for the next header, ending at `end`.  It is the
 * TPer contradicting itself (Malformed) unless it is the tail of a transfer
 * that delivered fewer bytes than requested, which is a short transfer.
 */
static void
tcg_report_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_item *item,
                     int end, uint32_t xfer_len)
{
    unsigned delivered = tvb_reported_length(tvb);

    if (xfer_len != 0 && delivered < xfer_len && end >= (int)delivered)
        expert_add_info(pinfo, item, &ei_tcg_transfer_short);
    else
        expert_add_info(pinfo, item, &ei_tcg_truncated);
}

/* Immutable stack/fragment links make a shallow per-subpacket snapshot safe
 * on redissection. Only an unfinished atom is retained, not the whole stream. */
typedef struct tcg_delimiter {
    uint8_t type;
    struct tcg_delimiter *next;
} tcg_delimiter;

typedef struct tcg_fragment {
    const uint8_t *data;
    unsigned len;
    struct tcg_fragment *next;
} tcg_fragment;

typedef struct {
    unsigned known, value;
} tcg_properties;

#define TCG_PROP_SEQUENCE 1U
#define TCG_PROP_ASYNC    2U

enum {
    TCG_PROP_TPER_LIST, TCG_PROP_HOST_PARAM, TCG_PROP_HOST_NAME,
    TCG_PROP_HOST_LIST, TCG_PROP_ENTRY, TCG_PROP_NAME, TCG_PROP_VALUE,
    TCG_PROP_SKIP_VALUE, TCG_PROP_END_NAME, TCG_PROP_HOST_END, TCG_PROP_DONE
};

/* A regular-session method call and the response that answers it.  Every
 * call in a session gets a response (Core 3.2.4.2), and a session's methods
 * are processed in order (3.3.10), so calls wait in a per-session FIFO. */
typedef struct tcg_pair {
    uint64_t invoking, method;
    uint32_t request_frame, response_frame;
    uint16_t request_ordinal;   /* among the Sends that end in request_frame */
    bool cancelled;         /* its IF-SEND failed: no response will come */
    struct tcg_pair *next;
} tcg_pair;

typedef struct {
    uint64_t method;
    uint32_t hsn, tsn;
    unsigned args, param_depth, option_stage;
    uint64_t option;
    bool valid, params, keys, success;
    tcg_properties properties[2];
    unsigned property_state, property_side, property;
    unsigned property_depth;
    bool property_continued;
    /* Parameter naming (Core 3.2.4.1), independent of .valid */
    const tcg_signature *sig;
    unsigned req_index;
    uint8_t name_stage, cb_stage;
    bool name_known, cb_known, value_continued;
    uint64_t name, cb_name;
    const tcg_param_def *list_param;
    unsigned list_depth;
    bool results;           /* naming a response's result list */
} tcg_method;

typedef struct {
    unsigned depth;
    tcg_delimiter *delimiters;
    int call_state;
    uint64_t invoking;
    bool eod, awaiting_status, eos;
    unsigned status_depth;
    unsigned status_count;
    bool status_valid;
    tcg_fragment *fragments;
    unsigned fragment_len;
    uint8_t header[4];
    bool name_key;          /* the previous token was Start Name */
    uint8_t txn_token;      /* Start/End Transaction awaiting its status */
    tcg_method method;
} tcg_stream;

typedef struct {
    tcg_stream streams[2];
    bool start_seen, started, trusted_pending, host_keys;
    uint32_t trusted_frame;     /* the IF-SEND that set trusted_pending */
    uint16_t trusted_ordinal;
    bool secure[2];
    tcg_properties properties[2];
    uint32_t last_sequence[2], last_frame[2];
    unsigned last_layer[2];
    bool sequence_seen[2];
    const char *aborted;
    tcg_pair *pending, *pending_tail;   /* calls awaiting a response */
} tcg_session;

/* What an IF-SEND changed in one session, undone if the command fails.
 * Core 3.3.10.2.1 item 3 describes the ComID after an IF-SEND that completed
 * without error; that the TPer did not act on one completed with an error is
 * inferred from it. */
typedef struct tcg_send_undo {
    struct tcg_send_undo *next;
    tcg_session *session;
    tcg_stream stream;          /* streams[1] before the IF-SEND */
    uint32_t last_sequence;     /* last_sequence[1] before the IF-SEND */
    uint32_t sequence;          /* last_sequence[1] as the IF-SEND left it */
    bool sequence_seen, stream_set, sequence_set, start_set;
    bool trusted_set;           /* a StartTrustedSession set trusted_pending */
    bool trusted_pending, host_keys;    /* their values before it */
    uint32_t trusted_frame;     /* and trusted_frame/ordinal before it */
    uint16_t trusted_ordinal;
} tcg_send_undo;

typedef struct {
    tcg_stream stream;
    uint32_t expected;
    const char *aborted;
    bool secure, duplicate, gap, wrapped, numbered, synchronous;
    wmem_array_t *pairs;    /* tcg_pair * per call or response, in order */
} tcg_snapshot;

typedef struct {
    wmem_map_t *sessions;
    tcg_properties properties[2];
} tcg_channel;

/* One per transport scope; a verified TPer Reset (Opal SSC 2.30 3.2.3)
 * replaces it, so every ComID of the scope starts again from defaults. */
typedef struct {
    bool reset_defaults;
    wmem_map_t *channels;   /* ComID -> tcg_channel */
} tcg_scope_gen;

static wmem_map_t *tcg_scope_gens;
/* Per transport scope: the last Level 0 TPer Feature had Async Supported
 * cleared (Core 3.3.6.4.2), so no ComID of that TPer runs asynchronously. */
static wmem_map_t *tcg_sync_only;
/* IF-SEND (frame << 16 | ordinal) -> its tcg_send_undo list.  An entry goes
 * only when its Send fails, so one per Send that tracks state stays until the
 * file closes. */
static wmem_map_t *tcg_send_undos;

static uint64_t
tcg_send_key(uint32_t frame, uint16_t ordinal)
{
    return ((uint64_t)frame << 16) | ordinal;
}

/* The IF-SEND's undo record for 'session', created before the Send changes
 * that session. */
static tcg_send_undo *
tcg_send_undo_entry(packet_info *pinfo, const struct nvme_security_info *sec,
                    tcg_session *session)
{
    uint64_t key = tcg_send_key(pinfo->num, sec->request_ordinal);
    tcg_send_undo *head = wmem_map_lookup(tcg_send_undos, &key);
    tcg_send_undo *undo;

    for (undo = head; undo; undo = undo->next) {
        if (undo->session == session)
            return undo;
    }
    undo = wmem_new0(wmem_file_scope(), tcg_send_undo);
    undo->next = head;
    undo->session = session;
    undo->stream = session->streams[1];
    undo->last_sequence = session->last_sequence[1];
    undo->sequence_seen = session->sequence_seen[1];
    wmem_map_insert(tcg_send_undos,
                    wmem_memdup(wmem_file_scope(), &key, sizeof(key)), undo);
    return undo;
}

static tcg_scope_gen *
tcg_new_scope_gen(const void *scope, bool reset_defaults)
{
    tcg_scope_gen *gen = wmem_new(wmem_file_scope(), tcg_scope_gen);
    gen->reset_defaults = reset_defaults;
    gen->channels = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    wmem_map_insert(tcg_scope_gens, scope, gen);
    return gen;
}

static tcg_scope_gen *
tcg_get_scope_gen(const void *scope)
{
    tcg_scope_gen *gen = wmem_map_lookup(tcg_scope_gens, scope);
    return gen ? gen : tcg_new_scope_gen(scope, false);
}

static tcg_channel *
tcg_get_channel(const struct nvme_security_info *sec, uint32_t comid, bool reset)
{
    /* SIIS 1.20 6.7.1.1: the TPer belongs to the subsystem, not CTLID.
     * Transport scope still distinguishes ingress and the endpoint pair. */
    tcg_scope_gen *gen = tcg_get_scope_gen(sec->scope);
    tcg_channel *channel = wmem_map_lookup(gen->channels, GUINT_TO_POINTER(comid));
    if (!channel || reset) {
        channel = wmem_new0(wmem_file_scope(), tcg_channel);
        channel->sessions = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        /* A new generation starts from the Table 168 initial assumptions
         * (Core 5.2.2.4.5): Asynchronous is FALSE. */
        if (reset || gen->reset_defaults)
            channel->properties[0].known = channel->properties[1].known = TCG_PROP_ASYNC;
        wmem_map_insert(gen->channels, GUINT_TO_POINTER(comid), channel);
    }
    return channel;
}

static tcg_session *
tcg_get_session(const struct nvme_security_info *sec, uint32_t comid,
                uint32_t tsn, uint32_t hsn)
{
    tcg_channel *channel = tcg_get_channel(sec, comid, false);
    uint64_t key = ((uint64_t)tsn << 32) | hsn;
    tcg_session *session = wmem_map_lookup(channel->sessions, &key);
    if (!session) {
        session = wmem_new0(wmem_file_scope(), tcg_session);
        memcpy(session->properties, channel->properties, sizeof(session->properties));
        wmem_map_insert(channel->sessions,
                        wmem_memdup(wmem_file_scope(), &key, sizeof(key)), session);
    }
    return session;
}

/* The session if the capture has one, else 'fallback', a session as a new one
 * would be.  Data that cannot advance state only reads it. */
static tcg_session *
tcg_peek_session(const struct nvme_security_info *sec, uint32_t comid,
                 uint32_t tsn, uint32_t hsn, tcg_session *fallback)
{
    tcg_channel *channel = tcg_get_channel(sec, comid, false);
    uint64_t key = ((uint64_t)tsn << 32) | hsn;
    tcg_session *session = wmem_map_lookup(channel->sessions, &key);

    if (session)
        return session;
    memcpy(fallback->properties, channel->properties, sizeof(fallback->properties));
    return fallback;
}

/* A regular session ends after a sequence wrap (Core 3.2.3.3.1.2), a
 * malformed status list or a synchronous atom that cannot fit its
 * ComPacket; its later Packets are not decoded. */
static void
tcg_abort_session(tcg_session *session, const char *reason)
{
    session->aborted = reason;
    session->started = session->trusted_pending = session->host_keys = false;
    memset(session->secure, 0, sizeof(session->secure));
    memset(session->streams, 0, sizeof(session->streams));
    session->pending = session->pending_tail = NULL;
}

/* Core 3.2.4.1 assigns optional names by ordinal. 5.2.3.3/.4 names
 * 1 and 2 carry encryption/integrity session keys; authentication alone
 * (Host/SPResponse or SignedHash) does NOT prove secure messaging.
 * No cipher sizes or SSC capabilities are inferred from these observations. */
static void
tcg_observe_method(packet_info *pinfo, const struct nvme_security_info *sec,
                   uint32_t comid, tcg_method *method)
{
    /* Core 5.3.4.1.5: a failed StartTrustedSession is answered by a
     * SyncTrustedSession with a non-Success status. */
    bool failed_sync = method->method == 0xff05 && !sec->send && !method->success;
    tcg_session *session;
    if (!method->valid || (!method->success && !failed_sync) ||
        !sec->state_valid || !sec->scope)
        return;
    if (method->method == 0xff01) {
        if (!sec->send) {
            tcg_channel *channel = tcg_get_channel(sec, comid, false);
            for (unsigned i = 0; i < 2; i++) {
                unsigned known = method->properties[i].known;
                channel->properties[i].value = (channel->properties[i].value & ~known) |
                                                method->properties[i].value;
                channel->properties[i].known |= known;
            }
            /* Core 5.2.2.2: the TPer omits what it does not support, and
             * 5.2.2.4: an omitted property keeps the host's assumption,
             * initially Asynchronous = FALSE (Table 168). */
            channel->properties[0].known |= TCG_PROP_ASYNC;
            /* Properties apply to subsequently started sessions. The control
             * session is permanently open and uses the current negotiation. */
            session = tcg_get_session(sec, comid, 0, 0);
            if ((session->properties[0].value & session->properties[1].value &
                 TCG_PROP_SEQUENCE) !=
                (channel->properties[0].value & channel->properties[1].value &
                 TCG_PROP_SEQUENCE))
                memset(session->sequence_seen, 0, sizeof(session->sequence_seen));
            memcpy(session->properties, channel->properties, sizeof(session->properties));
        }
        return;
    }
    if (method->args < 2)
        return;
    if (method->method != 0xff02 && method->tsn < 0x1000)
        return;
    if (method->method == 0xff02 && sec->send) {
        session = tcg_get_session(sec, comid, 0, method->hsn);
        if (!session->start_seen)
            tcg_send_undo_entry(pinfo, sec, session)->start_set = true;
        session->start_seen = true;
    } else if (method->method == 0xff03 && !sec->send) {
        tcg_session *pending = tcg_get_session(sec, comid, 0, method->hsn);

        if (!pending->start_seen)
            return;
        pending->start_seen = false;
        session = tcg_get_session(sec, comid, method->tsn, method->hsn);
        memset(session, 0, sizeof(*session));
        memcpy(session->properties, tcg_get_channel(sec, comid, false)->properties,
               sizeof(session->properties));
        session->started = true;
    } else if (method->method == 0xff04 && sec->send) {
        session = tcg_get_session(sec, comid, method->tsn, method->hsn);
        if (session->started) {
            tcg_send_undo *undo = tcg_send_undo_entry(pinfo, sec, session);

            if (!undo->trusted_set) {
                undo->trusted_set = true;
                undo->trusted_pending = session->trusted_pending;
                undo->host_keys = session->host_keys;
                undo->trusted_frame = session->trusted_frame;
                undo->trusted_ordinal = session->trusted_ordinal;
            }
            session->trusted_pending = true;
            session->host_keys = method->keys;
            session->trusted_frame = pinfo->num;
            session->trusted_ordinal = sec->request_ordinal;
        }
    } else if (method->method == 0xff05 && !sec->send) {
        session = tcg_get_session(sec, comid, method->tsn, method->hsn);
        if (session->started && session->trusted_pending) {
            /* A failure reply answers the request too: none is pending. */
            if (!failed_sync) {
                session->secure[1] = session->host_keys;
                session->secure[0] = method->keys;
            }
            session->trusted_pending = session->host_keys = false;
        }
    }
}

/* Core 5.2.2: accept only the complete Properties/HostProperties list grammar.
 * The small iterative recognizer shares the stream's atom continuation. */
static void
tcg_property_token(tcg_method *m, uint8_t token, bool bytes, bool sign,
                   unsigned len, uint64_t value, tvbuff_t *tvb, int offset)
{
    bool integer = token < 0xf0 && !bytes && !sign && len > 0 && len <= 8;
    switch (m->property_state) {
    case TCG_PROP_TPER_LIST:
    case TCG_PROP_HOST_LIST:
        if (token != TCG_TOK_START_LIST)
            break;
        m->property_side = m->property_state == TCG_PROP_HOST_LIST;
        m->property_state = TCG_PROP_ENTRY;
        return;
    case TCG_PROP_HOST_PARAM:
        if (token == TCG_TOK_END_LIST)
            return;
        if (token != TCG_TOK_START_NAME)
            break;
        m->property_state = TCG_PROP_HOST_NAME;
        return;
    case TCG_PROP_HOST_NAME:
        if (!integer || value != 0)
            break;
        m->property_state = TCG_PROP_HOST_LIST;
        return;
    case TCG_PROP_ENTRY:
        if (token == TCG_TOK_END_LIST) {
            m->property_state = m->property_side ? TCG_PROP_HOST_END : TCG_PROP_HOST_PARAM;
            return;
        }
        if (token != TCG_TOK_START_NAME)
            break;
        m->property_state = TCG_PROP_NAME;
        return;
    case TCG_PROP_NAME:
        if (token >= 0xf0 || (bytes && sign))
            break;
        m->property = 0;
        if (bytes && len == 15 &&
            tvb_memeql(tvb, offset, (const uint8_t *)"SequenceNumbers", 15) == 0)
            m->property = TCG_PROP_SEQUENCE;
        else if (bytes && len == 12 &&
                 tvb_memeql(tvb, offset, (const uint8_t *)"Asynchronous", 12) == 0)
            m->property = TCG_PROP_ASYNC;
        m->property_state = TCG_PROP_VALUE;
        return;
    case TCG_PROP_VALUE:
        if (m->property) {
            if (!integer || value > 1 ||
                (m->properties[m->property_side].known & m->property))
                break;
            m->properties[m->property_side].known |= m->property;
            if (value)
                m->properties[m->property_side].value |= m->property;
            m->property_state = TCG_PROP_END_NAME;
            return;
        }
        m->property_state = TCG_PROP_SKIP_VALUE;
        /* Core 3.2.2.3.2.1: an extension's value can be any messaging
         * value. Existing stream delimiters check pairing; keep only its
         * depth and continued-byte latch, including across Subpackets. */
        /* FALLTHROUGH */
    case TCG_PROP_SKIP_VALUE:
        if (m->property_continued && (token >= 0xf0 || !bytes))
            break;
        if (token == TCG_TOK_START_LIST || token == TCG_TOK_START_NAME)
            m->property_depth++;
        else if (token == TCG_TOK_END_LIST || token == TCG_TOK_END_NAME) {
            if (!m->property_depth)
                break;
            m->property_depth--;
        } else if (token >= 0xf0)
            break;
        m->property_continued = bytes && sign;
        if (!m->property_depth && !m->property_continued)
            m->property_state = TCG_PROP_END_NAME;
        return;
    case TCG_PROP_END_NAME:
    case TCG_PROP_HOST_END:
        if (token != TCG_TOK_END_NAME)
            break;
        m->property_state = m->property_state == TCG_PROP_END_NAME ?
                            TCG_PROP_ENTRY : TCG_PROP_DONE;
        return;
    case TCG_PROP_DONE:
        if (token == TCG_TOK_END_LIST)
            return;
        break;
    }
    m->valid = false;
}

static void
tcg_method_atom(tcg_stream *stream, bool bytes, bool sign, unsigned len,
                uint64_t value, tvbuff_t *tvb, int offset)
{
    tcg_method *m = &stream->method;
    if (!m->valid || !m->params)
        return;
    if (m->method == 0xff01) {
        tcg_property_token(m, 0, bytes, sign, len, value, tvb, offset);
        return;
    }
    if (stream->depth == m->param_depth) {
        if (m->args == 0 && !bytes && !sign && len <= 4)
            m->hsn = (uint32_t)value;
        else if (m->args == 1 && m->method != 0xff02 &&
                 !bytes && !sign && len <= 4)
            m->tsn = (uint32_t)value;
        else if (!(m->method == 0xff02 &&
                   ((m->args == 1 && bytes && !sign && len == 8) ||
                    (m->args == 2 && !bytes && !sign && value <= 1))))
            m->valid = false;
        m->args++;
    } else if (stream->depth == m->param_depth + 1 &&
               stream->delimiters && stream->delimiters->type == TCG_TOK_START_NAME) {
        if (m->option_stage == 0 && !bytes && !sign) {
            m->option = value;
            m->option_stage = 1;
        } else if (m->option_stage == 1) {
            if ((m->option == 1 || m->option == 2) && bytes && !sign && len > 0)
                m->keys = true;
            m->option_stage = 2;
        } else {
            m->valid = false;
        }
    }
}

static unsigned
tcg_atom_size(const uint8_t *header, unsigned available)
{
    unsigned hdr = header[0] < 0xc0 ? 1 : header[0] < 0xe0 ? 2 : 4;
    if (available < hdr)
        return hdr;
    if (hdr == 1)
        return hdr + (header[0] & 15);
    if (hdr == 2)
        return hdr + ((header[0] & 7) << 8) + header[1];
    return hdr + (header[1] << 16) + (header[2] << 8) + header[3];
}

static void
tcg_defer_atom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned len,
               tcg_stream *stream)
{
    wmem_allocator_t *scope = pinfo->fd->visited ? pinfo->pool : wmem_file_scope();
    tcg_fragment *part = wmem_new(scope, tcg_fragment);
    for (unsigned i = stream->fragment_len; i < 4 && i < stream->fragment_len + len; i++)
        stream->header[i] = tvb_get_uint8(tvb, offset + i - stream->fragment_len);
    part->data = tvb_memdup(scope, tvb, offset, len);
    part->len = len;
    part->next = stream->fragments;
    stream->fragments = part;
    stream->fragment_len += len;
    proto_tree_add_item(tree, hf_tcg_tok_fragment, tvb, offset, len, ENC_NA);
}

/* Per-Packet context of the token stream walk. */
typedef struct {
    const struct nvme_security_info *sec;
    uint32_t comid;
    uint32_t xfer_len;
    int sync_cp_end;            /* end of a complete synchronous ComPacket, or 0 */
    bool observe;               /* this Data subpacket may update session state */
    bool control_session;
    bool control_invalid;       /* out: the control session is invalid */
    bool status_violation;      /* out: a status list was malformed */
    bool atom_violation;        /* out: a synchronous atom cannot complete */
    tcg_session *session;       /* NULL unless session state may change */
    tcg_snapshot *snapshot;
    bool record_pairs;          /* first dissection of this Packet */
    unsigned pair_index;        /* replay position in snapshot->pairs */
} tcg_ts_ctx;

/* Pair a call with its response.  The first dissection decides and keeps
 * the result in the Packet's snapshot; later ones replay it in order. */
static tcg_pair *
tcg_pair_event(tcg_ts_ctx *ctx, packet_info *pinfo, uint64_t invoking,
               uint64_t method, bool call)
{
    tcg_pair *pair = NULL;
    tcg_session *session = ctx->session;

    if (!ctx->snapshot)
        return NULL;
    if (!ctx->record_pairs) {
        wmem_array_t *pairs = ctx->snapshot->pairs;
        if (pairs && ctx->pair_index < wmem_array_get_count(pairs))
            pair = *(tcg_pair **)wmem_array_index(pairs, ctx->pair_index++);
        return pair;
    }
    if (call) {
        pair = wmem_new0(wmem_file_scope(), tcg_pair);
        pair->invoking = invoking;
        pair->method = method;
        pair->request_frame = pinfo->num;
        pair->request_ordinal = ctx->sec->request_ordinal;
        if (session) {
            if (session->pending_tail)
                session->pending_tail->next = pair;
            else
                session->pending = pair;
            session->pending_tail = pair;
        }
    } else if (session) {
        while (session->pending && session->pending->cancelled)
            session->pending = session->pending->next;
        pair = session->pending;
        if (pair) {
            session->pending = pair->next;
            pair->next = NULL;
            pair->response_frame = pinfo->num;
        }
        if (!session->pending)
            session->pending_tail = NULL;
    }
    if (!ctx->snapshot->pairs)
        ctx->snapshot->pairs = wmem_array_new(wmem_file_scope(), sizeof(tcg_pair *));
    wmem_array_append_one(ctx->snapshot->pairs, pair);
    return pair;
}

static bool
tcg_incomplete_atom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    int offset, unsigned len, unsigned have, unsigned need,
                    tvbuff_t *xfer_tvb, int xfer_end, tcg_stream *stream,
                    bool complete, tcg_ts_ctx *ctx)
{
    if (have >= need)
        return false;

    if (!complete) {
        proto_item *item = proto_tree_add_item(tree, hf_tcg_raw_data, tvb, offset,
                                               len, ENC_NA);
        tcg_report_truncated(xfer_tvb, pinfo, item, xfer_end, ctx->xfer_len);
    } else if (ctx->sync_cp_end &&
               need > (uint64_t)have + (unsigned)(ctx->sync_cp_end - xfer_end)) {
        proto_item *item = proto_tree_add_item(tree, hf_tcg_raw_data, tvb, offset,
                                               len, ENC_NA);
        expert_add_info(pinfo, item, &ei_tcg_tok_spans_compacket);
        stream->method.valid = false;
        stream->fragment_len = 0;
        stream->fragments = NULL;
        ctx->control_invalid |= ctx->control_session;
        ctx->atom_violation = true;
    } else {
        tcg_defer_atom(tvb, pinfo, tree, offset, len, stream);
    }
    return true;
}

static void
tcg_add_method_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      const struct nvme_security_info *sec, tcg_stream *stream,
                      int offset, int len, uint64_t value)
{
    proto_tree_add_uint64(tree, sec->send ? hf_tcg_tok_host_status : hf_tcg_tok_status,
                          tvb, offset, len, value);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s: %s",
                    sec->send ? "Expected Status" : "Status",
                    val64_to_str_const(value, tcg_method_status_vals, "Unknown"));
    stream->method.success = value == 0;
}

enum { TCG_NAME_NONE = 0, TCG_NAME_KEY, TCG_NAME_VALUE, TCG_NAME_DONE };

static const tcg_param_def *
tcg_find_param(const tcg_param_def *defs, uint64_t number)
{
    for (; defs && defs->name; defs++)
        if (defs->number == number)
            return defs;
    return NULL;
}

/* Label the token that starts a parameter value.  A uidref is resolved
 * only when it is an 8-byte bytes atom, so other values that happen to
 * hold the same bytes are never named. */
static void
tcg_param_label(packet_info *pinfo, proto_tree *tree, proto_item *item,
                tvbuff_t *tvb, int offset, int len, const char *label,
                uint8_t kind, bool bytes, bool sign, unsigned data_len,
                int data_offset)
{
    proto_item *pi = proto_tree_add_string(tree, hf_tcg_param, tvb, offset, len, label);
    const char *uid_name = NULL;

    proto_item_set_generated(pi);
    if (kind == TCG_PARAM_UID && bytes && !sign && data_len == 8) {
        uint64_t uid = tvb_get_ntoh64(tvb, data_offset);

        uid_name = tcg_uid_name(pinfo->pool, uid, true);
        pi = proto_tree_add_uint64_format_value(tree, hf_tcg_param_uid, tvb,
                data_offset, 8, uid, "%s (0x%016" PRIx64 ")",
                uid_name ? uid_name : "Unknown", uid);
        proto_item_set_generated(pi);
    }
    if (!item)
        return;
    if (uid_name)
        proto_item_append_text(item, " [%s: %s]", label, uid_name);
    else
        proto_item_append_text(item, " [%s]", label);
}

/* Name method parameters (Core 3.2.4.1).  Called for each complete atom
 * (token 0) and each List/Name delimiter, before the depth changes.  Only
 * positions the signature defines are named; anything else gets the
 * mechanical "Required/Optional parameter N", and malformed or unknown
 * content inside one parameter never shifts the meaning of later ones. */
static void
tcg_param_token(tcg_stream *stream, packet_info *pinfo, proto_tree *tree,
                proto_item *item, tvbuff_t *tvb, int offset, int len,
                uint8_t token, bool bytes, bool sign, unsigned data_len,
                uint64_t value, int data_offset)
{
    tcg_method *m = &stream->method;
    unsigned    d = stream->depth;
    bool        value_token = token == 0 || token == TCG_TOK_START_LIST;
    bool        uinteger = token == 0 && !bytes && !sign && data_len <= 8;
    const tcg_param_def *def = NULL;
    const char *label;

    if (!m->params && !m->results)
        return;
    if (d == m->param_depth) {
        if (token == TCG_TOK_START_NAME) {
            m->name_stage = TCG_NAME_KEY;
            m->name_known = false;
            m->value_continued = false;
            return;
        }
        if (!value_token)
            return;
        if (m->value_continued) {
            m->value_continued = token == 0 && bytes && sign;
            return;
        }
        if (m->sig)
            def = &m->sig->req[0];
        for (unsigned i = 0; def && def->name && i < m->req_index; i++)
            def++;
        if (def && !def->name)
            def = NULL;
        if (def)
            label = def->name;
        else if (m->results)
            label = wmem_strdup_printf(pinfo->pool, "Result value %u", m->req_index);
        else
            label = wmem_strdup_printf(pinfo->pool, "Required parameter %u", m->req_index);
        m->req_index++;
    } else if (d == m->param_depth + 1 && m->name_stage != TCG_NAME_NONE) {
        if (token == TCG_TOK_END_NAME) {
            m->name_stage = TCG_NAME_NONE;
            return;
        }
        if (m->name_stage == TCG_NAME_KEY) {
            if (token != 0) {
                m->name_stage = TCG_NAME_DONE;
                return;
            }
            m->name_known = uinteger;
            m->name = value;
            m->name_stage = TCG_NAME_VALUE;
            if (item)
                proto_item_append_text(item, " [Parameter name]");
            return;
        }
        if (m->name_stage != TCG_NAME_VALUE || !value_token)
            return;
        if (m->value_continued) {
            m->value_continued = token == 0 && bytes && sign;
            if (!m->value_continued)
                m->name_stage = TCG_NAME_DONE;
            return;
        }
        def = m->name_known && m->sig ? tcg_find_param(m->sig->opt, m->name) : NULL;
        if (def)
            label = def->name;
        else if (!m->name_known)
            label = "Optional parameter (name is not a uinteger)";
        else if (m->name > 0xff)
            label = wmem_strdup_printf(pinfo->pool, "Optional parameter 0x%" PRIx64, m->name);
        else
            label = wmem_strdup_printf(pinfo->pool, "Optional parameter %" PRIu64, m->name);
        m->name_stage = TCG_NAME_DONE;
    } else if (m->list_param && d == m->list_depth) {
        if (token == TCG_TOK_END_LIST) {
            m->list_param = NULL;
        } else if (m->list_param->kind == TCG_PARAM_CELLBLOCK) {
            if (token == TCG_TOK_START_NAME) {
                m->cb_stage = TCG_NAME_KEY;
                m->cb_known = false;
            }
        } else if (token == 0) {
            tcg_param_label(pinfo, tree, item, tvb, offset, len,
                            wmem_strdup_printf(pinfo->pool, "%s entry", m->list_param->name),
                            TCG_PARAM_UID, bytes, sign, data_len, data_offset);
        }
        return;
    } else if (m->list_param && d == m->list_depth + 1 && m->cb_stage != TCG_NAME_NONE) {
        if (token == TCG_TOK_END_NAME) {
            m->cb_stage = TCG_NAME_NONE;
        } else if (m->cb_stage == TCG_NAME_KEY) {
            m->cb_known = uinteger;
            m->cb_name = value;
            m->cb_stage = token == 0 ? TCG_NAME_VALUE : TCG_NAME_DONE;
        } else if (m->cb_stage == TCG_NAME_VALUE && value_token) {
            def = m->cb_known ? tcg_find_param(tcg_cellblock_names, m->cb_name) : NULL;
            tcg_param_label(pinfo, tree, item, tvb, offset, len,
                            def ? def->name : "Cellblock component (unrecognized name)",
                            def ? def->kind : TCG_PARAM_PLAIN,
                            bytes, sign, data_len, data_offset);
            m->cb_stage = TCG_NAME_DONE;
        }
        return;
    } else {
        return;
    }

    if (token == 0 && bytes && sign) {
        m->value_continued = true;
        if (m->name_stage == TCG_NAME_DONE)
            m->name_stage = TCG_NAME_VALUE;
    }
    tcg_param_label(pinfo, tree, item, tvb, offset, len, label,
                    def ? def->kind : TCG_PARAM_PLAIN, bytes, sign, data_len, data_offset);
    if (token == TCG_TOK_START_LIST && def &&
        (def->kind == TCG_PARAM_CELLBLOCK || def->kind == TCG_PARAM_UID_LIST)) {
        m->list_param = def;
        m->list_depth = d + 1;
        m->cb_stage = TCG_NAME_NONE;
    }
}

/* Show which call a regular-session response answers and name its
 * results from the method's result signature. */
static void
tcg_add_response_to(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    tcg_stream *stream, tcg_ts_ctx *ctx, int offset)
{
    tcg_pair *pair = tcg_pair_event(ctx, pinfo, 0, 0, false);
    const char *invoking, *method;
    proto_item *pi;

    if (!pair)
        return;
    invoking = tcg_uid_name(pinfo->pool, pair->invoking, true);
    method = tcg_uid_name(pinfo->pool, pair->method, false);
    if (!invoking)
        invoking = wmem_strdup_printf(pinfo->pool, "0x%016" PRIx64, pair->invoking);
    if (!method)
        method = wmem_strdup_printf(pinfo->pool, "0x%016" PRIx64, pair->method);
    pi = proto_tree_add_string_format_value(tree, hf_tcg_response_to, tvb, offset, 1,
            wmem_strdup_printf(pinfo->pool, "%s.%s", invoking, method),
            "%s.%s()", invoking, method);
    proto_item_set_generated(pi);
    pi = proto_tree_add_uint(tree, hf_tcg_request_in, tvb, 0, 0, pair->request_frame);
    proto_item_set_generated(pi);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Response to %s.%s()", invoking, method);
    stream->method.results = true;
    stream->method.param_depth = stream->depth;
    stream->method.sig = tcg_find_result_signature(pair->method);
    stream->method.req_index = 0;
}

/* Core 3.2.2.3.3.4/5 (Tables 15/16): the uinteger status that follows a
 * Start or End Transaction token. */
static proto_item *
tcg_add_txn_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   const struct nvme_security_info *sec, uint8_t txn,
                   int offset, int len, uint64_t value)
{
    const char *meaning;
    proto_item *item;

    if (txn == TCG_TOK_START_TXN)
        meaning = value == 0 ? "Success" : "Reserved";
    else
        meaning = value == 0 ? "Commit" : value == 1 ? "Abort" : "Reserved";
    item = proto_tree_add_uint64_format_value(tree, txn == TCG_TOK_START_TXN ?
            hf_tcg_txn_start_status : hf_tcg_txn_end_status,
            tvb, offset, len, value, "%s (%" PRIu64 ")", meaning, value);
    /* 3.2.2.3.3.5: an SP status other than 0 means it aborted. */
    if (txn == TCG_TOK_END_TXN && !sec->send && value != 0)
        col_append_str(pinfo->cinfo, COL_INFO, ", Transaction aborted");
    return item;
}

/* Data subpacket token stream (Core 3.2.2), walked iteratively.
 * Incomplete atoms continue in the next Data subpacket (3.2.3.1) unless
 * sync_cp_end proves they cannot (3.3.10.3(a)). */
static void
dissect_tcg_token_stream(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, int offset, int len,
                         tcg_stream *stream, bool complete, tcg_ts_ctx *ctx)
{
    const struct nvme_security_info *sec = ctx->sec;
    tvbuff_t   *xfer_tvb = tvb;
    int         xfer_end = offset + len;
    proto_tree *stack_tree[TCG_TOK_MAX_NEST];
    proto_item *stack_item[TCG_TOK_MAX_NEST];
    int         stack_start[TCG_TOK_MAX_NEST];
    int         depth = MIN(stream->depth, TCG_TOK_MAX_NEST - 1);
    int         overflow = stream->depth - depth;
    proto_item *ts_item;
    proto_tree *ts_tree;
    int         end = offset + len;
    enum { CALL_NONE = 0, CALL_INVOKING, CALL_METHOD, CALL_ARGS };
    int         call_state = stream->call_state;
    const char *invoking_name = tcg_uid_name(pinfo->pool, stream->invoking, true);
    bool        eod_seen = stream->eod;
    bool        awaiting_status = stream->awaiting_status;
    unsigned    status_depth = stream->status_depth;

    if (stream->eos) {
        proto_tree_add_item(tree, hf_tcg_raw_data, tvb, offset, len, ENC_NA);
        return;
    }
    if (ctx->sync_cp_end)
        DISSECTOR_ASSERT(ctx->sync_cp_end >= xfer_end);
    if (stream->fragment_len) {
        unsigned previous = stream->fragment_len;
        unsigned total = previous + len;
        uint8_t header[4];
        memcpy(header, stream->header, sizeof(header));
        for (unsigned i = previous; i < 4 && i < total; i++)
            header[i] = tvb_get_uint8(tvb, offset + i - previous);
        if (tcg_incomplete_atom(tvb, pinfo, tree, offset, len, total,
                                tcg_atom_size(header, total), xfer_tvb,
                                xfer_end, stream, complete, ctx))
            return;
        uint8_t *bytes = wmem_alloc(pinfo->pool, total);
        unsigned pos = previous;
        for (tcg_fragment *part = stream->fragments; part; part = part->next) {
            pos -= part->len;
            memcpy(bytes + pos, part->data, part->len);
        }
        tvb_memcpy(tvb, bytes + previous, offset, len);
        tvb = tvb_new_child_real_data(tvb, bytes, total, total);
        add_new_data_source(pinfo, tvb, "TCG continued token stream");
        offset = 0;
        len = total;
        end = len;
        stream->fragment_len = 0;
        stream->fragments = NULL;
    }
    ts_item = proto_tree_add_item(tree, hf_tcg_token_stream, tvb, offset,
                                  len, ENC_NA);
    ts_tree = proto_item_add_subtree(ts_item, ett_tcg_token_stream);
    for (int i = 0; i <= depth; i++) {
        stack_tree[i] = ts_tree;
        stack_item[i] = NULL;
        stack_start[i] = offset;
    }

    while (offset < end) {
        proto_tree *cur = stack_tree[depth];
        uint8_t     b = tvb_get_uint8(tvb, offset);
        int         pending_call = call_state;
        bool        was_eod = eod_seen;
        proto_item *it;
        int         hdr_len, data_len, data_offset, atom_len;
        bool        byte_flag, sign_flag;
        bool        status_atom;
        bool        name_key;
        uint8_t     txn;

        /* Empty atoms are ignored and leave every adjacency latch unchanged
         * (Core 3.2.2.3.1.5). */
        if (b == TCG_TOK_EMPTY) {
            proto_tree_add_item(cur, hf_tcg_tok_control, tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;
            continue;
        }
        if (ctx->control_session && (b == TCG_TOK_END_SESSION ||
            b == TCG_TOK_START_TXN || b == TCG_TOK_END_TXN)) {
            it = proto_tree_add_item(cur, hf_tcg_tok_control, tvb, offset++, 1, ENC_BIG_ENDIAN);
            if (status_depth) {
                if (stream->status_valid)
                    expert_add_info(pinfo, it, &ei_tcg_tok_status_type);
                stream->status_valid = false;
                stream->method.valid = false;
                ctx->control_invalid = true;
            }
            continue;
        }

        /* Wait for a whole atom before consuming adjacency or list state. */
        if (b >= 0x80 && b <= 0xe3) {
            uint8_t header[4] = { 0 };
            unsigned available = MIN(4, end - offset);
            tvb_memcpy(tvb, header, offset, available);
            if (tcg_incomplete_atom(tvb, pinfo, cur, offset, end - offset,
                                    end - offset, tcg_atom_size(header, available),
                                    xfer_tvb, xfer_end, stream, complete, ctx))
                break;
        }
        call_state = CALL_NONE;
        eod_seen = false;
        name_key = stream->name_key;
        txn = stream->txn_token;
        stream->name_key = b == TCG_TOK_START_NAME;
        stream->txn_token = 0;
        status_atom = awaiting_status && stream->depth == status_depth;
        if (status_depth && !(b == TCG_TOK_END_LIST && stream->depth == status_depth)) {
            bool invalid = stream->depth != status_depth ||
                b >= 0xe4 || (b < 0x80 && (b & 0x40)) ||
                (b >= 0x80 && b < 0xc0 && (b & 0x30)) ||
                (b >= 0xc0 && b < 0xe0 && (b & 0x18)) ||
                (b >= 0xe0 && (b & 3));
            if (invalid) {
                it = proto_tree_add_item(cur, hf_tcg_raw_data, tvb, offset, 1, ENC_NA);
                if (stream->status_valid)
                    expert_add_info(pinfo, it, &ei_tcg_tok_status_type);
                stream->status_valid = false;
                stream->method.valid = false;
                ctx->control_invalid |= ctx->control_session;
                ctx->status_violation = true;
            } else
                stream->status_count++;
        }
        awaiting_status = false;

        /* Control / sequence tokens (single byte, 0xF0-0xFF) */
        if (b >= 0xF0) {
            it = proto_tree_add_item(cur, hf_tcg_tok_control, tvb, offset,
                                     1, ENC_BIG_ENDIAN);
            if (txn)
                expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            tcg_param_token(stream, pinfo, cur, it, tvb, offset, 1, b,
                            false, false, 0, 0, offset);
            if (stream->method.valid && stream->method.params &&
                stream->method.method == 0xff01)
                tcg_property_token(&stream->method, b, false, false, 0, 0, tvb, offset);
            switch (b) {
            case TCG_TOK_START_LIST:
            case TCG_TOK_START_NAME:
            {
                if (stream->method.params && stream->method.method != 0xff01 &&
                    (b == TCG_TOK_START_LIST ||
                     stream->depth != stream->method.param_depth))
                    stream->method.valid = false;
                tcg_delimiter *delimiter = wmem_new(pinfo->fd->visited ?
                                                   pinfo->pool : wmem_file_scope(), tcg_delimiter);
                delimiter->type = b;
                delimiter->next = stream->delimiters;
                stream->delimiters = delimiter;
                stream->depth++;
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
                    stream->status_count = 0;
                    stream->status_valid = true;
                    /* Past TCG_TOK_MAX_NEST the stack stops moving and the
                     * excess levels are counted in `overflow` instead, so the
                     * latch has to be anchored to the combined nesting level
                     * or it could never be released. */
                    status_depth = stream->depth;
                } else if (b == TCG_TOK_START_LIST && stream->depth == 1 &&
                           pending_call != CALL_ARGS && !sec->send &&
                           !ctx->control_session) {
                    /* Core 3.2.4.2: a regular session's response is a
                     * result list, End of Data and the status list. */
                    tcg_add_response_to(tvb, pinfo, cur, stream, ctx, offset);
                } else if (b == TCG_TOK_START_LIST && pending_call == CALL_ARGS) {
                    stream->method.params = true;
                    stream->method.param_depth = stream->depth;
                    stream->method.property_state = sec->send ?
                        TCG_PROP_HOST_PARAM : TCG_PROP_TPER_LIST;
                }
                if (b == TCG_TOK_START_NAME)
                    stream->method.option_stage = 0;
                break;
            }
            case TCG_TOK_END_LIST:
            case TCG_TOK_END_NAME:
                if (!stream->delimiters ||
                    stream->delimiters->type != b - 1) {
                    expert_add_info(pinfo, it, &ei_tcg_tok_pair);
                    stream->method.valid = false;
                    stream->delimiters = NULL;
                    stream->depth = 0;
                    depth = overflow = 0;
                    status_depth = 0;
                    if (end > offset + 1)
                        proto_tree_add_item(cur, hf_tcg_raw_data, tvb,
                                             offset + 1, end - offset - 1, ENC_NA);
                    offset = end - 1;
                    break;
                }
                stream->delimiters = stream->delimiters->next;
                stream->depth--;
                if (overflow > 0) {
                    overflow--;
                } else if (depth > 0) {
                    proto_item_set_len(stack_item[depth],
                                       offset + 1 - stack_start[depth]);
                    depth--;
                }
                if (stream->depth + 1 == stream->method.param_depth) {
                    stream->method.params = false;
                    stream->method.results = false;
                    if (stream->method.method != 0xff01 &&
                        stream->method.args != (stream->method.method == 0xff02 ? 3U : 2U))
                        stream->method.valid = false;
                }
                if (b == TCG_TOK_END_NAME &&
                    stream->method.method != 0xff01 &&
                    stream->depth == stream->method.param_depth &&
                    stream->method.option_stage != 2)
                    stream->method.valid = false;
                if (b == TCG_TOK_END_LIST && stream->depth + 1 == status_depth) {
                    if (stream->status_count < 3) {
                        if (stream->status_valid)
                            expert_add_info(pinfo, it, &ei_tcg_tok_status_type);
                        stream->status_valid = false;
                        ctx->control_invalid |= ctx->control_session;
                        ctx->status_violation = true;
                    }
                    if (ctx->observe && !ctx->control_invalid && stream->status_valid)
                        tcg_observe_method(pinfo, sec, ctx->comid, &stream->method);
                    memset(&stream->method, 0, sizeof(stream->method));
                    status_depth = 0;
                }
                break;
            case TCG_TOK_CALL:
                call_state = stream->depth == 0 ? CALL_INVOKING : CALL_NONE;
                memset(&stream->method, 0, sizeof(stream->method));
                break;
            case TCG_TOK_END_OF_DATA:
                if (stream->depth) {
                    expert_add_info(pinfo, it, &ei_tcg_tok_pair);
                    stream->delimiters = NULL;
                    stream->depth = 0;
                    depth = overflow = 0;
                    status_depth = 0;
                    stream->method.valid = false;
                }
                eod_seen = true;
                break;
            case TCG_TOK_END_SESSION:
                if (stream->depth)
                    expert_add_info(pinfo, it, &ei_tcg_tok_pair);
                stream->eos = true;
                if (end > offset + 1)
                    proto_tree_add_item(cur, hf_tcg_raw_data, tvb,
                                         offset + 1, end - offset - 1, ENC_NA);
                offset = end - 1;
                break;
            case TCG_TOK_START_TXN:
            case TCG_TOK_END_TXN:
                stream->txn_token = b;
                break;
            default:
                /* 0xF4-0xF7, 0xFD-0xFE */
                expert_add_info(pinfo, it, &ei_tcg_tok_reserved);
                stream->method.valid = false;
                ctx->control_invalid |= ctx->control_session;
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
                it = proto_tree_add_int64_format(cur, hf_tcg_tok_int, tvb,
                        offset, 1, sval,
                        "Tiny Atom (signed): %" PRId64, sval);
                if (txn)
                    expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            } else if (status_atom) {
                tcg_add_method_status(tvb, pinfo, cur, sec, stream, offset, 1,
                                      b & 0x3F);
                it = NULL;
            } else if (txn) {
                it = tcg_add_txn_status(tvb, pinfo, cur, sec, txn, offset, 1, b & 0x3F);
            } else {
                it = proto_tree_add_uint64_format(cur, hf_tcg_tok_uint, tvb,
                        offset, 1, b & 0x3F,
                        "Tiny Atom (unsigned): %u (0x%x)",
                        (unsigned)(b & 0x3F), (unsigned)(b & 0x3F));
            }
            tcg_param_token(stream, pinfo, cur, it, tvb, offset, 1, 0, false,
                            (b & 0x40) != 0, 1, b & 0x3f, offset);
            tcg_method_atom(stream, false, (b & 0x40) != 0, 1, b & 0x3f, tvb, offset);
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
            if (txn)
                expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            /* Core 3.2.2.4.1(6): no later method in this control Packet
             * may become state evidence, even across Subpackets. */
            stream->method.valid = false;
            ctx->control_invalid |= ctx->control_session;
            offset += 1;
            continue;
        }
        if (hdr_len == 2)
            data_len = ((b & 0x07) << 8) | tvb_get_uint8(tvb, offset + 1);
        else if (hdr_len == 4)
            data_len = (int)tvb_get_ntoh24(tvb, offset + 1);

        if (data_len == 0 && b != 0xa0) {
            it = proto_tree_add_item(cur, hf_tcg_raw_data, tvb, offset, hdr_len, ENC_NA);
            expert_add_info(pinfo, it, &ei_tcg_tok_zero_length);
            if (txn)
                expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            stream->method.valid = false;
            if (status_depth) {
                stream->status_valid = false;
                ctx->control_invalid |= ctx->control_session;
                ctx->status_violation = true;
            }
            offset += hdr_len;
            continue;
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
            if (txn)
                expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            /* Core 3.2.2.3.2.1: a Name may be a byte sequence, such as a
             * Properties name; show it as text when it is printable. */
            if (name_key && !sign_flag && tvb_ascii_isprint(tvb, data_offset, data_len))
                proto_item_set_generated(proto_tree_add_item(cur, hf_tcg_tok_name, tvb,
                                         data_offset, data_len, ENC_ASCII));
            tcg_param_token(stream, pinfo, cur, it, tvb, offset, atom_len, 0, true,
                            sign_flag, data_len, 0, data_offset);
            if (data_len == 8 && !sign_flag &&
                (pending_call == CALL_INVOKING || pending_call == CALL_METHOD)) {
                uint64_t    uid = tvb_get_ntoh64(tvb, data_offset);
                const char *name = tcg_uid_name(pinfo->pool, uid,
                                                pending_call == CALL_INVOKING);
                proto_item *uid_item;

                uid_item = proto_tree_add_uint64_format_value(cur, hf_tcg_tok_uid, tvb,
                        data_offset, 8, uid, "%s (0x%016" PRIx64 ")",
                        name ? name : "Unknown", uid);
                proto_item_set_generated(uid_item);
                if (pending_call == CALL_INVOKING) {
                    proto_item_append_text(uid_item, " [Invoking UID]");
                    invoking_name = name ? name :
                            wmem_strdup_printf(pinfo->pool,
                                               "0x%016" PRIx64, uid);
                    stream->invoking = uid;
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
                    call_state = CALL_ARGS;
                    stream->method.method = uid;
                    stream->method.sig = tcg_find_signature(stream->invoking, uid,
                                                            sec->send);
                    stream->method.valid = stream->invoking == 0xff &&
                        uid >= 0xff01 && uid <= 0xff05 && stream->depth == 0;
                    if (sec->send && !ctx->control_session) {
                        tcg_pair *pair = tcg_pair_event(ctx, pinfo, stream->invoking,
                                                        uid, true);
                        if (pair && pair->response_frame)
                            proto_item_set_generated(proto_tree_add_uint(cur,
                                    hf_tcg_response_in, tvb, 0, 0, pair->response_frame));
                    }
                }
            }
            tcg_method_atom(stream, true, sign_flag, data_len, 0, tvb, data_offset);
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
                if (txn)
                    expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            } else if (status_atom) {
                tcg_add_method_status(tvb, pinfo, cur, sec, stream, offset,
                                      atom_len, uval);
                it = NULL;
            } else if (txn) {
                it = tcg_add_txn_status(tvb, pinfo, cur, sec, txn, offset, atom_len, uval);
            } else {
                it = proto_tree_add_uint64_format(cur, hf_tcg_tok_uint,
                        tvb, offset, atom_len, uval,
                        "Integer Atom (unsigned): %" PRIu64
                        " (0x%" PRIx64 ")", uval, uval);
            }
            tcg_param_token(stream, pinfo, cur, it, tvb, offset, atom_len, 0, false,
                            sign_flag, data_len, uval, data_offset);
            tcg_method_atom(stream, false, sign_flag, data_len, uval, tvb, data_offset);
        } else {
            /* Integer wider than 64 bits: render the data raw */
            it = proto_tree_add_item(cur, hf_tcg_tok_bytes, tvb,
                                     data_offset, data_len, ENC_NA);
            proto_item_append_text(it,
                    " (integer atom wider than 64 bits)");
            if (txn)
                expert_add_info(pinfo, it, &ei_tcg_txn_status_type);
            tcg_param_token(stream, pinfo, cur, it, tvb, offset, atom_len, 0, false,
                            sign_flag, data_len, 0, data_offset);
            if (stream->method.valid && stream->method.params) {
                if (stream->method.method == 0xff01)
                    tcg_property_token(&stream->method, 0, false, sign_flag,
                                       data_len, 0, tvb, data_offset);
                else
                    stream->method.valid = false;
            }
        }
        offset += atom_len;
    }

    /* Stretch any unterminated Start List/Name subtrees to the end of
     * the stream so their highlight covers the enclosed tokens. */
    for (; depth > 0; depth--)
        proto_item_set_len(stack_item[depth], end - stack_start[depth]);
    stream->call_state = call_state;
    stream->eod = eod_seen;
    stream->awaiting_status = awaiting_status;
    stream->status_depth = status_depth;
}

/* Level 0 Discovery response (Core 3.3.6): 48-byte header, then
 * feature descriptors, each bounded by its own Length. Big-endian. */

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

static void
dissect_tcg_l0_reserved_tail(tvbuff_t *tvb, proto_tree *tree, int offset, int len)
{
    proto_tree_add_item(tree, hf_tcg_l0_feat_reserved_tail, tvb, offset, len, ENC_NA);
}

/* Bytes after the flags byte of a fixed descriptor. For a Version newer than
 * the defining table they may carry fields defined later, so keep them raw. */
static void
dissect_tcg_l0_fixed_tail(tvbuff_t *tvb, proto_tree *tree, int offset, int len,
                          bool known_version)
{
    if (known_version)
        dissect_tcg_l0_reserved_tail(tvb, tree, offset, len);
    else
        dissect_tcg_l0_feat_data(tvb, tree, offset, len);
}

/* 0x0001 TPer Feature; returns the flags byte */
static uint64_t
dissect_tcg_l0_feat_tper(tvbuff_t *tvb, proto_tree *tree, int offset, int data_len,
                         bool known_version)
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
    uint64_t flags;

    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_tcg_l0_tper_flags,
                                      ett_tcg_l0_tper_flags, tper_flags,
                                      ENC_BIG_ENDIAN, &flags);
    dissect_tcg_l0_fixed_tail(tvb, tree, offset + 1, data_len - 1, known_version);
    return flags;
}

/* 0x0002 Locking Feature: Core 2.01 Table 43 (Version 1, bits 7:6 Reserved);
 * Pyrite SSC 2.01 / Ruby SSC 1.00 Table 5 (Version 2) name bit 6 and keep
 * bit 7 Reserved; Opal SSC 2.30 Table 4 (Version 3) names bits 7:6. Later
 * versions extend earlier ones (Core §3.3.6.3.1.2), so bits 5:0 are decoded
 * for any version. */
static void
dissect_tcg_l0_feat_locking(tvbuff_t *tvb, proto_tree *tree, int offset,
                            int data_len, uint32_t version, bool known_version)
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
    static int * const locking_flags_v1[] = {
        &hf_tcg_l0_locking_reserved_v1,
        &hf_tcg_l0_locking_mbr_done,
        &hf_tcg_l0_locking_mbr_enabled,
        &hf_tcg_l0_locking_media_encryption,
        &hf_tcg_l0_locking_locked,
        &hf_tcg_l0_locking_enabled,
        &hf_tcg_l0_locking_supported,
        NULL,
    };
    static int * const locking_flags_v2[] = {
        &hf_tcg_l0_locking_reserved_v2,
        &hf_tcg_l0_locking_mbr_shadowing_not_supported,
        &hf_tcg_l0_locking_mbr_done,
        &hf_tcg_l0_locking_mbr_enabled,
        &hf_tcg_l0_locking_media_encryption,
        &hf_tcg_l0_locking_locked,
        &hf_tcg_l0_locking_enabled,
        &hf_tcg_l0_locking_supported,
        NULL,
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_tcg_l0_locking_flags,
                           ett_tcg_l0_locking_flags,
                           version <= 1 ? locking_flags_v1 :
                           version == 2 ? locking_flags_v2 : locking_flags,
                           ENC_BIG_ENDIAN);
    dissect_tcg_l0_fixed_tail(tvb, tree, offset + 1, data_len - 1, known_version);
}

/* 0x0003 Geometry Reporting Feature (Opal SSC 2.30 Table 5); also 0x0405
 * Namespace Geometry Reporting, which has the same layout */
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
dissect_tcg_l0_feat_siis(tvbuff_t *tvb, proto_tree *tree,
                         int offset, int data_len)
{
    static int * const siis_flags[] = {
        &hf_tcg_l0_siis_id_usage_scope,
        &hf_tcg_l0_siis_key_change_zone,
        NULL,
    };

    proto_tree_add_item(tree, hf_tcg_l0_siis_revision, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 1, hf_tcg_l0_siis_flags,
                           ett_tcg_l0_siis_flags, siis_flags,
                           ENC_BIG_ENDIAN);
    dissect_tcg_l0_reserved_tail(tvb, tree, offset + 2, data_len - 2);
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

/* 0x0203 Opal SSC V2 */
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

/* 0x0202 Additional DataStore Tables (ADT 1.01 Table 2) */
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

/* 0x0402 Block SID Authentication: Block SID 1.00 Table 1 (Version 1) and
 * 1.01 Table 2 (Version 2, adds the Locking SP Freeze Lock bits) */
static void
dissect_tcg_l0_feat_block_sid(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, int offset, int data_len,
                              uint32_t version)
{
    static int * const bsid_flags[] = {
        &hf_tcg_l0_bsid_sid_blocked_state,
        &hf_tcg_l0_bsid_sid_value_state,
        NULL,
    };
    static int * const bsid_flags_v2[] = {
        &hf_tcg_l0_bsid_freeze_state,
        &hf_tcg_l0_bsid_freeze_supported,
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
                           ett_tcg_l0_bsid_flags,
                           version >= 2 ? bsid_flags_v2 : bsid_flags,
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

/* Opal SSC 2.30 §3.1.1.6.4 Tables 11/12 */
static void
dissect_tcg_l0_drm_time(tvbuff_t *tvb, proto_tree *tree, int hf, int offset,
                        bool minutes)
{
    const char *unit = minutes ? "minutes" : "seconds";
    uint32_t    value;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf, tvb, offset, 2,
                                                  ENC_BIG_ENDIAN, &value);

    if (value == 0)
        proto_item_append_text(ti, " (Not reported)");
    else if (value == 0xFFFF)
        proto_item_append_text(ti, " (>= 131068 %s)", unit);
    else
        proto_item_append_text(ti, " (%u %s)", value * 2, unit);
}

/* 0x0404 Data Removal Mechanism: Version 1 (Pyrite SSC 2.01 Tables 7/8, Key
 * Per I/O SSC 1.00 Tables 6/7) and Version 2 (Opal SSC 2.30 Tables 8/9).
 * Version 2 makes mechanism bits 3 and 4 and their times Reserved, so the
 * walker shows any other version raw. */
static void
dissect_tcg_l0_feat_data_removal(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, int offset, int data_len,
                                 uint32_t version)
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
    static int * const drm_mechanism_v1[] = {
        &hf_tcg_l0_drm_mech_vendor,
        &hf_tcg_l0_drm_mech_reset_wp,
        &hf_tcg_l0_drm_mech_unmap,
        &hf_tcg_l0_drm_mech_crypto_erase,
        &hf_tcg_l0_drm_mech_block_erase,
        &hf_tcg_l0_drm_mech_overwrite,
        NULL,
    };
    static int * const drm_format_v1[] = {
        &hf_tcg_l0_drm_fmt_vendor,
        &hf_tcg_l0_drm_fmt_reset_wp,
        &hf_tcg_l0_drm_fmt_unmap,
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
                           ett_tcg_l0_drm_mechanism,
                           version == 1 ? drm_mechanism_v1 : drm_mechanism,
                           ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset + 3, hf_tcg_l0_drm_format,
                           ett_tcg_l0_drm_format,
                           version == 1 ? drm_format_v1 : drm_format,
                           ENC_BIG_ENDIAN);
    uint8_t fmt = tvb_get_uint8(tvb, offset + 3);
    /* One Data Removal Time per mechanism bit 0-5 at data offsets 4-15.
     * Version 2 defines only those of bits 0, 1, 2 and 5: data offsets 10-13
     * (bits 3 and 4) are Reserved there. */
    if (data_len < 10) {
        dissect_tcg_l0_feat_data(tvb, tree, offset + 4, data_len - 4);
        return;
    }
    dissect_tcg_l0_drm_time(tvb, tree, hf_tcg_l0_drm_time_overwrite,
                            offset + 4, fmt & 0x01);
    dissect_tcg_l0_drm_time(tvb, tree, hf_tcg_l0_drm_time_block_erase,
                            offset + 6, fmt & 0x02);
    dissect_tcg_l0_drm_time(tvb, tree, hf_tcg_l0_drm_time_crypto_erase,
                            offset + 8, fmt & 0x04);
    if (data_len < 16) {
        dissect_tcg_l0_feat_data(tvb, tree, offset + 10, data_len - 10);
        return;
    }
    if (version == 1) {
        dissect_tcg_l0_drm_time(tvb, tree, hf_tcg_l0_drm_time_unmap,
                                offset + 10, fmt & 0x08);
        dissect_tcg_l0_drm_time(tvb, tree, hf_tcg_l0_drm_time_reset_wp,
                                offset + 12, fmt & 0x10);
    } else {
        proto_tree_add_item(tree, hf_tcg_l0_drm_reserved1, tvb, offset + 10, 4,
                            ENC_NA);
    }
    dissect_tcg_l0_drm_time(tvb, tree, hf_tcg_l0_drm_time_vendor,
                            offset + 14, fmt & 0x20);
    /* Bytes 20-35 (Length 0x20) are "Reserved for future Supported Data
     * Removal Mechanism parameters" in both versions; a later version may
     * define them. */
    if (data_len >= 32) {
        proto_tree_add_item(tree, hf_tcg_l0_drm_reserved2, tvb, offset + 16,
                            16, ENC_NA);
        dissect_tcg_l0_feat_data(tvb, tree, offset + 32, data_len - 32);
    } else {
        dissect_tcg_l0_feat_data(tvb, tree, offset + 16, data_len - 16);
    }
}

static void
tcg_l0_unknown_version(proto_tree *tree, tvbuff_t *tvb,
                       proto_item *version_item, int offset)
{
    proto_item_append_text(version_item,
                           " (version not recognized here; a later specification may define it)");
    proto_item *marker = proto_tree_add_boolean(tree, hf_tcg_l0_unsupported_version,
                                                tvb, offset, 0, TRUE);
    proto_item_set_generated(marker);
    proto_item_set_hidden(marker);
}

static void
dissect_tcg_level0_discovery(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, int offset, int len,
                             const struct nvme_security_info *sec)
{
    uint32_t      xfer_len = sec->xfer_len;
    proto_tree   *l0_tree;
    proto_item   *l0_item, *len_item;
    uint32_t      param_len;
    int           param_end;
    wmem_strbuf_t *sscs = wmem_strbuf_new(pinfo->pool, "");

    if (len < TCG_L0_HDR_LEN) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb,
                                             offset, len, ENC_NA);
        if (len >= 4 && tvb_bytes_exist(tvb, offset, 4) &&
            tvb_get_ntohl(tvb, offset) < TCG_L0_HDR_LEN - 4)
            expert_add_info(pinfo, ti, &ei_tcg_length_overrun);
        else if ((unsigned)len != xfer_len && !sec->level0_prefix)
            tcg_report_truncated(tvb, pinfo, ti, offset + len, xfer_len);
        return;
    }

    l0_item = proto_tree_add_item(tree, hf_tcg_level0_discovery, tvb,
                                  offset, len, ENC_NA);
    l0_tree = proto_item_add_subtree(l0_item, ett_tcg_l0);

    len_item = proto_tree_add_item_ret_uint(l0_tree, hf_tcg_l0_length, tvb,
                                            offset, 4, ENC_BIG_ENDIAN,
                                            &param_len);
    if (param_len < TCG_L0_HDR_LEN - 4) {
        expert_add_info(pinfo, len_item, &ei_tcg_length_overrun);
        proto_tree_add_item(l0_tree, hf_tcg_raw_data, tvb, offset + 4,
                            len - 4, ENC_NA);
        return;
    }
    uint32_t major, minor;
    proto_item *major_item = proto_tree_add_item_ret_uint(l0_tree, hf_tcg_l0_major_version, tvb, offset + 4, 2,
                        ENC_BIG_ENDIAN, &major);
    proto_item *minor_item = proto_tree_add_item_ret_uint(l0_tree, hf_tcg_l0_minor_version, tvb, offset + 6, 2,
                        ENC_BIG_ENDIAN, &minor);
    if (major != 0 || minor != 1)
        tcg_l0_unknown_version(l0_tree, tvb, major != 0 ? major_item : minor_item,
                               offset + (major != 0 ? 4 : 6));
    if (major != 0) {
        /* Core 3.3.6.2.2: major changes are not backwards compatible. */
        proto_tree_add_item(l0_tree, hf_tcg_raw_data, tvb, offset + 8,
                            len - 8, ENC_NA);
        return;
    }
    proto_tree_add_item(l0_tree, hf_tcg_l0_reserved, tvb, offset + 8, 8,
                        ENC_NA);
    proto_tree_add_item(l0_tree, hf_tcg_l0_vendor, tvb, offset + 16, 32,
                        ENC_NA);

    /* Length counts the valid bytes following the Length field itself */
    bool parent_complete = param_len <= (uint32_t)(len - 4);
    /* Core 3.3.6.2: AL (or a transport-fulfilled narrower window) may
     * legally truncate the discovery data. */
    bool allocation_prefix = (unsigned)len == xfer_len || sec->level0_prefix;
    /* A complete discovery in a completed window short of AL lacks owed
     * padding (Core 3.3.6.2). */
    if (!allocation_prefix && (!parent_complete || (unsigned)len < xfer_len))
        expert_add_info(pinfo, l0_item, &ei_tcg_transfer_short);
    if (!parent_complete)
        param_len = len - 4;
    param_end = offset + 4 + (int)param_len;
    proto_item_set_len(l0_item, 4 + param_len);
    if (param_end < offset + len)
        proto_tree_add_item(tree, hf_tcg_padding, tvb, param_end,
                            offset + len - param_end, ENC_NA);
    offset += TCG_L0_HDR_LEN;

    /* Feature descriptors */
    while (offset < param_end) {
        proto_tree *feat_tree;
        proto_item *feat_item, *feat_len_item;
        uint32_t    feat_code, feat_len, feat_version;
        int         data_len;

        if (param_end - offset < TCG_L0_FEAT_HDR_LEN) {
            proto_item *ti = proto_tree_add_item(l0_tree, hf_tcg_raw_data,
                                                 tvb, offset,
                                                 param_end - offset, ENC_NA);
            if (parent_complete)
                expert_add_info(pinfo, ti, &ei_tcg_truncated);
            else if (!allocation_prefix)
                expert_add_info(pinfo, ti, &ei_tcg_transfer_short);
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

        proto_tree_add_item(feat_tree, hf_tcg_l0_feat_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item *version_item = proto_tree_add_item_ret_uint(feat_tree, hf_tcg_l0_feat_version, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN, &feat_version);
        int minor_hf = hf_tcg_l0_feat_reserved;
        if (feat_version >= 2) {
            if (feat_code == TCG_L0_FEAT_OPAL_V2)
                minor_hf = hf_tcg_l0_feat_ssc_minor;
            else if (feat_code == TCG_L0_FEAT_DATASTORE)
                minor_hf = hf_tcg_l0_feat_ds_minor;
            else if (feat_code == TCG_L0_FEAT_CNL)
                minor_hf = hf_tcg_l0_feat_cnl_minor;
        }
        proto_tree_add_item(feat_tree, minor_hf, tvb, offset + 2, 1,
                            ENC_BIG_ENDIAN);
        feat_len_item = proto_tree_add_item_ret_uint(feat_tree,
                hf_tcg_l0_feat_length, tvb, offset + 3, 1, ENC_BIG_ENDIAN,
                &feat_len);

        /* Core Spec §3.3.6.3.1.3: "This field SHALL be an integral multiple
         * of 4."  A violation shifts every descriptor that follows, which
         * shows up as a cascade of Unknown Feature entries, so name the
         * cause rather than leaving the cascade unexplained. */
        if ((feat_len & 0x03) != 0)
            expert_add_info(pinfo, feat_len_item, &ei_tcg_feat_length_align);

        /* Fixed 12-byte layouts: Core 2.01 Tables 42/43 (TPer v1, Locking
         * v1), Pyrite SSC 2.01 / Ruby SSC 1.00 Table 5 (Locking v2), Opal SSC
         * 2.30 Table 4 (Locking v3) and SIIS 1.20 Table 2.
         * Core §3.3.6.3.1.2: a later Version extends an earlier one, so TPer
         * and Locking flags are still decoded for a newer Version; SIIS is
         * not, as its later layouts are not available here. No document
         * defines a TPer Version other than 0x1, and the SSCs accept "0x1 or
         * any version that supports the defined features in this SSC" (Opal
         * SSC 2.30 §3.1.1.2 Table 3, Pyrite SSC 2.01 and Ruby SSC 1.00
         * §3.1.1.2 Table 4), which still require Streaming and Sync
         * Supported. */
        bool fixed_feature = feat_code == TCG_L0_FEAT_TPER ||
                             feat_code == TCG_L0_FEAT_LOCKING ||
                             feat_code == TCG_L0_FEAT_SIIS;
        bool known_version = feat_version == 1 ||
                             (feat_code == TCG_L0_FEAT_LOCKING &&
                              (feat_version == 2 || feat_version == 3));
        bool extended_layout = !known_version && feat_version > 1 &&
                               feat_code != TCG_L0_FEAT_SIIS;
        if (fixed_feature && !known_version)
            tcg_l0_unknown_version(feat_tree, tvb, version_item, offset + 2);
        if (fixed_feature && known_version && feat_len != 12)
            expert_add_info(pinfo, feat_len_item, &ei_tcg_feat_length);
        /* Data Removal Mechanism Version 2 withdrew fields of Version 1, so
         * a later Version could follow either; keep its body raw. */
        bool drm_known = feat_version == 1 || feat_version == 2;
        if (feat_code == TCG_L0_FEAT_DATA_REMOVAL && !drm_known)
            tcg_l0_unknown_version(feat_tree, tvb, version_item, offset + 2);
        /* Versions newer than any defining table (Geometry and Namespace
         * Geometry 1, Ruby 1, Opal SSC V2 2, Block SID 2) are marked; their
         * known fields are still decoded (Core §3.3.6.3.1.2). */
        if (((feat_code == TCG_L0_FEAT_GEOMETRY ||
              feat_code == TCG_L0_FEAT_NS_GEOMETRY ||
              feat_code == TCG_L0_FEAT_RUBY) && feat_version >= 2) ||
            ((feat_code == TCG_L0_FEAT_OPAL_V2 ||
              feat_code == TCG_L0_FEAT_BLOCK_SID) && feat_version >= 3))
            tcg_l0_unknown_version(feat_tree, tvb, version_item, offset + 2);
        /* A later Version may define another Length. The declared value is
         * on the wire whether or not the body was clipped by the transfer. */
        if (feat_code == TCG_L0_FEAT_DATA_REMOVAL && drm_known &&
            feat_len != TCG_L0_DRM_LEN)
            expert_add_info_format(pinfo, feat_len_item, &ei_tcg_feat_length,
                                   "Data Removal Mechanism Version %u"
                                   " feature data must be exactly 32"
                                   " bytes (%s 'Level 0 Discovery -"
                                   " Supported Data Removal Mechanism"
                                   " Feature Descriptor');"
                                   " Length is %u", feat_version,
                                   feat_version == 1
                                       ? "Pyrite SSC 2.01 / Key Per I/O SSC"
                                       : "Opal SSC",
                                   feat_len);
        bool bad_fixed_len = false;
        if (feat_code == TCG_L0_FEAT_GEOMETRY && feat_version == 1 &&
            feat_len != TCG_L0_GEOMETRY_V1_LEN) {
            bad_fixed_len = true;
            expert_add_info_format(pinfo, feat_len_item, &ei_tcg_feat_length,
                                   "Geometry Reporting Version 1 feature data"
                                   " must be exactly 28 bytes (Opal SSC"
                                   " 'Level 0 Discovery - Geometry Reporting"
                                   " Feature Descriptor'); Length is %u",
                                   feat_len);
        } else if (feat_code == TCG_L0_FEAT_NS_GEOMETRY && feat_version == 1 &&
                   feat_len != TCG_L0_GEOMETRY_V1_LEN) {
            bad_fixed_len = true;
            expert_add_info_format(pinfo, feat_len_item, &ei_tcg_feat_length,
                                   "Namespace Geometry Reporting Version 1"
                                   " feature data must be exactly 28 bytes"
                                   " (Configurable Locking 'Namespace Geometry"
                                   " Reporting Feature Descriptor'); Length is %u",
                                   feat_len);
        } else if (feat_code == TCG_L0_FEAT_OPAL_V2 &&
                   (feat_version == 1 || feat_version == 2) &&
                   feat_len != TCG_L0_OPAL_V2_V2_LEN) {
            /* Version 1: Opal SSC 2.00/2.01 Table 7; Version 2: Opal SSC
             * 2.30 Table 6. Both have Length 0x10. */
            bad_fixed_len = true;
            expert_add_info_format(pinfo, feat_len_item, &ei_tcg_feat_length,
                                   "Opal SSC V2 Version %u feature data must be"
                                   " exactly 16 bytes (Opal SSC 'Level 0"
                                   " Discovery - Opal SSC V2 Feature Descriptor');"
                                   " Length is %u", feat_version, feat_len);
        }
        /* Pyrite SSC 2.01 Table 6: Version 1 of the Pyrite SSC V2.00 feature
         * has Length 0x10. Only the fields that fit are still decoded. */
        if (feat_code == TCG_L0_FEAT_PYRITE_V2 && feat_version == 1 &&
            feat_len != TCG_L0_PYRITE_V2_LEN)
            expert_add_info_format(pinfo, feat_len_item, &ei_tcg_feat_length,
                                   "Pyrite SSC V2.00 Version 1 feature data must"
                                   " be exactly 16 bytes (Pyrite SSC 'Level 0"
                                   " Discovery - Pyrite SSC Feature Descriptor');"
                                   " Length is %u", feat_len);

        offset += TCG_L0_FEAT_HDR_LEN;

        data_len = (int)feat_len;
        if (feat_len > (uint32_t)(param_end - offset)) {
            if (parent_complete)
                expert_add_info(pinfo, feat_len_item, &ei_tcg_length_overrun);
            else if (!allocation_prefix)
                expert_add_info(pinfo, feat_item, &ei_tcg_transfer_short);
            data_len = param_end - offset;
        }
        proto_item_set_len(feat_item, TCG_L0_FEAT_HDR_LEN + data_len);

        /* A clipped, sufficiently declared body is not a short declaration.
         * Keep available bytes raw rather than asking a leaf to diagnose an
         * extent that the common walker already attributed to the transfer.
         * A Data Removal Length below 4 already has its Length expert. */
        if ((uint32_t)data_len < feat_len || bad_fixed_len ||
            (feat_code == TCG_L0_FEAT_DATA_REMOVAL && (!drm_known || feat_len < 4)) ||
            (fixed_feature && known_version && feat_len != 12) ||
            (fixed_feature && !known_version &&
             (!extended_layout || feat_len < 12))) {
            dissect_tcg_l0_feat_data(tvb, feat_tree, offset, data_len);
        } else switch (feat_code) {
        case TCG_L0_FEAT_TPER: {
            uint64_t flags = dissect_tcg_l0_feat_tper(tvb, feat_tree, offset,
                                                      data_len, known_version);
            if (!pinfo->fd->visited && sec->state_valid && sec->scope) {
                if (flags & TCG_L0_TPER_ASYNC)
                    wmem_map_remove(tcg_sync_only, sec->scope);
                else
                    wmem_map_insert(tcg_sync_only, sec->scope, GUINT_TO_POINTER(1));
            }
            break;
        }
        case TCG_L0_FEAT_LOCKING:
            dissect_tcg_l0_feat_locking(tvb, feat_tree, offset,
                                        data_len, feat_version, known_version);
            break;
        case TCG_L0_FEAT_GEOMETRY:
        case TCG_L0_FEAT_NS_GEOMETRY:
            dissect_tcg_l0_feat_geometry(tvb, pinfo, feat_tree, offset,
                                         data_len);
            break;
        case TCG_L0_FEAT_SIIS:
            dissect_tcg_l0_feat_siis(tvb, feat_tree, offset, data_len);
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
                                          data_len, feat_version);
            break;
        case TCG_L0_FEAT_CNL:
            dissect_tcg_l0_feat_cnl(tvb, pinfo, feat_tree, offset,
                                    data_len);
            break;
        case TCG_L0_FEAT_DATA_REMOVAL:
            dissect_tcg_l0_feat_data_removal(tvb, pinfo, feat_tree, offset,
                                             data_len, feat_version);
            break;
        default:
            dissect_tcg_l0_feat_data(tvb, feat_tree, offset, data_len);
            break;
        }

        const char *ssc_name = try_val_to_str(feat_code, tcg_l0_ssc_name_vals);
        if (ssc_name) {
            if (wmem_strbuf_get_len(sscs) > 0)
                wmem_strbuf_append(sscs, ", ");
            wmem_strbuf_append(sscs, ssc_name);
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

/* ComPacket / Packet / Subpacket framing (Core 3.2.3), big-endian,
 * walked iteratively with per-level length clamping. */

static void
dissect_tcg_compacket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      const struct nvme_security_info *sec)
{
    proto_tree *cp_tree;
    proto_item *cp_item, *len_item, *comid_item;
    int         offset = 0;
    int         remaining;
    uint32_t    cp_len;
    int         cp_payload_len, cp_payload_end;
    uint32_t    xfer_len = sec->xfer_len;
    bool        cp_complete;
    uint32_t    comid, comid_ext;
    struct nvme_security_info routed;
    wmem_map_t *snapshots = p_get_proto_data(wmem_file_scope(), pinfo,
                                            proto_tcg_storage, pinfo->curr_layer_num);
    if (!snapshots) {
        snapshots = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_tcg_storage,
                         pinfo->curr_layer_num, snapshots);
    }

    remaining = tvb_reported_length_remaining(tvb, offset);
    if (remaining < TCG_COMPACKET_HDR_LEN) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb,
                                             offset, remaining, ENC_NA);
        tcg_report_truncated(tvb, pinfo, ti, offset + remaining, xfer_len);
        return;
    }

    cp_item = proto_tree_add_item(tree, hf_tcg_compacket, tvb, offset,
                                  -1, ENC_NA);
    cp_tree = proto_item_add_subtree(cp_item, ett_tcg_compacket);

    proto_tree_add_item(cp_tree, hf_tcg_compacket_reserved, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
    comid_item = proto_tree_add_item_ret_uint(cp_tree, hf_tcg_compacket_comid, tvb,
                                              offset + 4, 2, ENC_BIG_ENDIAN, &comid);
    proto_tree_add_item_ret_uint(cp_tree, hf_tcg_compacket_comid_ext,
                                 tvb, offset + 6, 2, ENC_BIG_ENDIAN, &comid_ext);
    proto_tree_add_item(cp_tree, sec->send ? hf_tcg_compacket_reserved : hf_tcg_compacket_outstanding, tvb,
                        offset + 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cp_tree, sec->send ? hf_tcg_compacket_reserved : hf_tcg_compacket_min_transfer, tvb,
                        offset + 12, 4, ENC_BIG_ENDIAN);
    len_item = proto_tree_add_item_ret_uint(cp_tree, hf_tcg_compacket_length,
                                            tvb, offset + 16, 4,
                                            ENC_BIG_ENDIAN, &cp_len);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", ComID 0x%04x", comid);
    /* A ComPacket naming another ComID than SPSP is tracked on neither
     * channel (SIIS 1.20 Tables 23/24; Core 3.3.2, 3.3.3.1). */
    if (comid != sec->spsp) {
        expert_add_info_format(pinfo, comid_item, &ei_tcg_comid_mismatch,
                               "ComPacket ComID 0x%04x differs from the command's"
                               " ComID (SPSP) 0x%04x; session state not tracked",
                               comid, sec->spsp);
        routed = *sec;
        routed.scope = NULL;
        sec = &routed;
    }
    comid = comid << 16 | comid_ext;
    if (cp_len == 0) {
        const char *state = "empty ComPacket";
        if (!sec->send) {
            if ((comid >> 16) >= 0x1000 && (comid & 0xffff) == 0xffff &&
                (comid >> 16) == sec->spsp &&
                tvb_get_ntohl(tvb, 8) == 0 && tvb_get_ntohl(tvb, 12) == 0)
                state = "inactive ComID";
            else if (tvb_get_ntohl(tvb, 8) == 1 && tvb_get_ntohl(tvb, 12) == 0)
                state = "response being prepared";
            else if (tvb_get_ntohl(tvb, 8) || tvb_get_ntohl(tvb, 12))
                state = "response available; allocation too small";
            else
                state = "no pending response data";
        }
        proto_item_append_text(cp_item, " (%s)", state);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", state);
    }

    offset += TCG_COMPACKET_HDR_LEN;
    remaining = tvb_reported_length_remaining(tvb, offset);

    cp_payload_len = (int)cp_len;
    cp_complete = cp_len <= (uint32_t)remaining;
    if (cp_len > (uint32_t)remaining) {
        tcg_report_length_overrun(pinfo, len_item, cp_item,
                                  (uint64_t)offset + cp_len, xfer_len, false);
        cp_payload_len = remaining;
    }
    cp_payload_end = offset + cp_payload_len;
    proto_item_set_len(cp_item, TCG_COMPACKET_HDR_LEN + cp_payload_len);

    /* Packets */
    while (offset < cp_payload_end) {
        proto_tree *pkt_tree, *ses_tree;
        proto_item *pkt_item, *pkt_len_item;
        uint32_t    pkt_len, seq_number;
        int         pkt_payload_len, pkt_payload_end;
        bool        pkt_complete;
        tcg_ts_ctx  ts = { .sec = sec, .comid = comid, .xfer_len = xfer_len };
        bool        packet_valid = true;
        int         packet_offset = offset;
        tcg_session scratch = { 0 };
        tcg_session *session;
        tcg_stream stream;
        tcg_snapshot *snapshot;

        if (cp_payload_end - offset < TCG_PACKET_HDR_LEN) {
            proto_item *ti = proto_tree_add_item(cp_tree, hf_tcg_raw_data,
                                                 tvb, offset,
                                                 cp_payload_end - offset,
                                                 ENC_NA);
            if (cp_complete)
                expert_add_info(pinfo, ti, &ei_tcg_truncated);
            else
                tcg_report_truncated(tvb, pinfo, ti, cp_payload_end, xfer_len);
            break;
        }

        /* Only data that may advance state makes a session. */
        if (sec->scope && !pinfo->fd->visited) {
            uint32_t tsn = tvb_get_ntohl(tvb, offset);
            uint32_t hsn = tvb_get_ntohl(tvb, offset + 4);

            session = sec->state_valid ? tcg_get_session(sec, comid, tsn, hsn)
                                       : tcg_peek_session(sec, comid, tsn, hsn, &scratch);
        } else {
            session = &scratch;
        }
        ts.control_session = tvb_get_ntoh64(tvb, offset) == 0;
        snapshot = wmem_map_lookup(snapshots, GUINT_TO_POINTER(packet_offset));
        ts.record_pairs = !snapshot;
        if (!snapshot) {
            snapshot = wmem_new0(wmem_file_scope(), tcg_snapshot);
            if (!pinfo->fd->visited) {
                snapshot->stream = session->streams[sec->send];
                snapshot->secure = session->secure[sec->send];
                snapshot->aborted = session->aborted;
                bool numbered = (session->properties[0].value &
                                 session->properties[1].value & TCG_PROP_SEQUENCE) != 0;
                snapshot->numbered = numbered;
                /* Core 5.2.2.4.1.11: synchronous if either Asynchronous is
                 * FALSE. One never observed stays unknown, as the capture may
                 * have begun after Properties, unless Level 0 showed the TPer
                 * cannot run the Asynchronous protocol (3.3.6.4.2). */
                bool synchronous = (((session->properties[0].known &
                                      ~session->properties[0].value) |
                                     (session->properties[1].known &
                                      ~session->properties[1].value)) & TCG_PROP_ASYNC) ||
                                   (!(session->properties[0].known & TCG_PROP_ASYNC) &&
                                    wmem_map_contains(tcg_sync_only, sec->scope));
                snapshot->synchronous = synchronous;
                uint32_t sequence = tvb_get_ntohl(tvb, offset + 8);
                uint32_t last_sequence = session->last_sequence[sec->send];
                if (numbered && session->sequence_seen[sec->send]) {
                    /* Core 3.2.3.3.1.2: the recipient ignores only a SeqNumber
                     * at or below the last acted-on one, and the 32-bit
                     * counter aborts on wrap; it is not modular ordering. */
                    snapshot->wrapped = last_sequence == UINT32_MAX && sequence == 0;
                    snapshot->duplicate = !snapshot->wrapped && sequence <= last_sequence;
                    snapshot->gap = (uint64_t)sequence > (uint64_t)last_sequence + 1;
                    snapshot->expected = last_sequence + 1;
                } else if (numbered && session->started) {
                    snapshot->gap = sequence != 1;
                    snapshot->expected = 1;
                }
                /* Without observed startup the first acted-on packet, or one after
                 * a gap, anchors the sequence (Core 3.3.9.3 is not tracked). */
                /* A synchronous method may span Subpackets and Packets,
                 * but not the next ComPacket (Core 3.3.10.3(a)). Nothing
                 * spans a gap: the missing packet's tokens are unknown. */
                /* A missing call or response would shift every later
                 * pairing, so pairing restarts after a gap. */
                if (snapshot->gap && sec->state_valid)
                    session->pending = session->pending_tail = NULL;
                if (snapshot->gap || (synchronous &&
                    (session->last_frame[sec->send] != pinfo->num ||
                     session->last_layer[sec->send] != pinfo->curr_layer_num))) {
                    bool eos = snapshot->stream.eos;
                    memset(&snapshot->stream, 0, sizeof(snapshot->stream));
                    snapshot->stream.eos = eos;
                }
            }
            wmem_map_insert(snapshots, GUINT_TO_POINTER(packet_offset), snapshot);
        }
        stream = snapshot->stream;
        ts.snapshot = snapshot;
        /* Pairing is session state: only data that may advance state takes part. */
        ts.session = (session != &scratch && sec->state_valid) ? session : NULL;
        tcg_send_undo *undo = ts.session && sec->send ?
                              tcg_send_undo_entry(pinfo, sec, session) : NULL;
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
        proto_tree_add_item_ret_uint(pkt_tree, hf_tcg_packet_seq, tvb, offset + 8, 4,
                                     ENC_BIG_ENDIAN, &seq_number);
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
        pkt_complete = pkt_len <= (uint32_t)(cp_payload_end - offset);
        if (pkt_len > (uint32_t)(cp_payload_end - offset)) {
            tcg_report_length_overrun(pinfo, pkt_len_item, pkt_item,
                                      (uint64_t)offset + pkt_len, xfer_len, cp_complete);
            pkt_payload_len = cp_payload_end - offset;
        }
        pkt_payload_end = offset + pkt_payload_len;
        proto_item_set_len(pkt_item, TCG_PACKET_HDR_LEN + pkt_payload_len);

        const char *sequence_reason =
            snapshot->aborted ? snapshot->aborted :
            snapshot->wrapped ? "sequence number wrapped; session aborted" :
            snapshot->duplicate ? "previously acted-on sequence" : NULL;
        if (snapshot->gap && !sequence_reason) {
            expert_add_info_format(pinfo, pkt_item, &ei_tcg_sequence_gap,
                                   "SeqNumber %u, expected %u; tracking resumes from this"
                                   " Packet (Core 3.2.3.3.1.2)",
                                   seq_number, snapshot->expected);
            proto_item_append_text(pkt_item, " (sequence gap)");
            col_append_str(pinfo->cinfo, COL_INFO, " (sequence gap)");
        }
        if (sequence_reason || snapshot->secure) {
            proto_tree_add_item(pkt_tree, snapshot->secure ? hf_tcg_secure_data : hf_tcg_raw_data, tvb, offset,
                                pkt_payload_len, ENC_NA);
            if (sequence_reason) {
                proto_item_append_text(pkt_item, " (%s)", sequence_reason);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", sequence_reason);
            }
            if (!pinfo->fd->visited && cp_complete && pkt_complete &&
                sec->state_valid && sec->scope &&
                tvb_captured_length(tvb) >= (unsigned)pkt_payload_end) {
                if (snapshot->wrapped) {
                    tcg_abort_session(session, "session aborted after sequence wrap");
                } else if (!sequence_reason) {
                    session->last_sequence[sec->send] = tvb_get_ntohl(tvb, packet_offset + 8);
                    session->sequence_seen[sec->send] = true;
                    if (undo) {
                        undo->sequence = session->last_sequence[1];
                        undo->sequence_set = true;
                    }
                }
            }
            offset = pkt_payload_end;
            continue;
        }

        /* Validate the complete immediate parent before admitting any stream
         * or session observation from this Packet. Display still walks the
         * bounded available bytes and attributes the structural defect. */
        packet_valid = tvb_captured_length(tvb) >= (unsigned)pkt_payload_end;
        for (int check = offset; packet_valid && check < pkt_payload_end; ) {
            if (pkt_payload_end - check < TCG_SUBPACKET_HDR_LEN) {
                packet_valid = false;
                break;
            }
            uint32_t length = tvb_get_ntohl(tvb, check + 8);
            uint16_t kind = tvb_get_ntohs(tvb, check + 6);
            uint64_t next = (uint64_t)check + TCG_SUBPACKET_HDR_LEN +
                            length + ((4 - length % 4) % 4);
            if (next > (unsigned)pkt_payload_end ||
                (kind == TCG_SUBPACKET_KIND_CREDIT && length != 4)) {
                packet_valid = false;
                break;
            }
            if (kind == TCG_SUBPACKET_KIND_DATA) {
                for (int i = check + TCG_SUBPACKET_HDR_LEN + (int)length;
                     i < (int)next; i++) {
                    if (tvb_get_uint8(tvb, i) != 0)
                        packet_valid = false;
                }
            }
            check = (int)next;
        }

        /* Core 3.3.10.3(a): a synchronous atom cannot need bytes past the
         * end of a complete, fully captured ComPacket. */
        ts.sync_cp_end = snapshot->synchronous && cp_complete &&
                          tvb_captured_length(tvb) >= (unsigned)cp_payload_end ?
                          cp_payload_end : 0;

        /* Subpackets */
        while (offset < pkt_payload_end) {
            proto_tree *sp_tree;
            proto_item *sp_item, *sp_kind_item, *sp_len_item;
            uint32_t    sp_kind, sp_len;
            int         sp_payload_len, pad;

            if (pkt_payload_end - offset < TCG_SUBPACKET_HDR_LEN) {
                packet_valid = false;
                proto_item *ti = proto_tree_add_item(pkt_tree,
                        hf_tcg_raw_data, tvb, offset,
                        pkt_payload_end - offset, ENC_NA);
                if (pkt_complete || cp_complete)
                    expert_add_info(pinfo, ti, &ei_tcg_truncated);
                else
                    tcg_report_truncated(tvb, pinfo, ti, pkt_payload_end, xfer_len);
                break;
            }

            sp_item = proto_tree_add_item(pkt_tree, hf_tcg_subpacket, tvb,
                                          offset, -1, ENC_NA);
            sp_tree = proto_item_add_subtree(sp_item, ett_tcg_subpacket);

            proto_tree_add_item(sp_tree, hf_tcg_subpacket_reserved, tvb,
                                offset, 6, ENC_NA);
            sp_kind_item = proto_tree_add_item_ret_uint(sp_tree,
                    hf_tcg_subpacket_kind, tvb, offset + 6, 2,
                    ENC_BIG_ENDIAN, &sp_kind);
            sp_len_item = proto_tree_add_item_ret_uint(sp_tree,
                    hf_tcg_subpacket_length, tvb, offset + 8, 4,
                    ENC_BIG_ENDIAN, &sp_len);
            proto_item_append_text(sp_item, " (%s, %u bytes)",
                    rval_to_str_const(sp_kind, tcg_subpacket_kind_rvals,
                                      "Reserved"), sp_len);
            if (sp_kind != TCG_SUBPACKET_KIND_DATA &&
                sp_kind != TCG_SUBPACKET_KIND_CREDIT)
                expert_add_info(pinfo, sp_kind_item, &ei_tcg_subpacket_kind);
            /* Core 2.01 3.2.3.4.2.1.3: always 4 for Credit Control. */
            else if (sp_kind == TCG_SUBPACKET_KIND_CREDIT && sp_len != 4)
                expert_add_info(pinfo, sp_len_item, &ei_tcg_credit_length);

            offset += TCG_SUBPACKET_HDR_LEN;

            sp_payload_len = (int)sp_len;
            if (sp_len > (uint32_t)(pkt_payload_end - offset)) {
                packet_valid = false;
                tcg_report_length_overrun(pinfo, sp_len_item, sp_item,
                                          (uint64_t)offset + sp_len, xfer_len,
                                          pkt_complete || cp_complete);
                sp_payload_len = pkt_payload_end - offset;
            }

            if (sp_payload_len > 0) {
                switch (sp_kind) {
                case TCG_SUBPACKET_KIND_DATA:
                    if (ts.atom_violation) {
                        proto_tree_add_item(sp_tree, hf_tcg_raw_data, tvb,
                                            offset, sp_payload_len, ENC_NA);
                        break;
                    }
                    ts.observe = !pinfo->fd->visited && cp_complete &&
                                 pkt_complete && packet_valid &&
                                 ts.control_session && sec->state_valid &&
                                 tvb_captured_length(tvb) >= (unsigned)pkt_payload_end;
                    dissect_tcg_token_stream(tvb, pinfo, sp_tree, offset,
                                             sp_payload_len, &stream,
                                             sp_len == (uint32_t)sp_payload_len,
                                             &ts);
                    break;
                case TCG_SUBPACKET_KIND_CREDIT:
                    if (sp_len == 4 && sp_payload_len == 4) {
                        proto_tree_add_item(sp_tree, hf_tcg_subpacket_credit,
                                            tvb, offset, 4, ENC_BIG_ENDIAN);
                    } else {
                        proto_tree_add_item(sp_tree,
                                hf_tcg_raw_data, tvb, offset,
                                sp_payload_len, ENC_NA);
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
            if (pad > pkt_payload_end - offset) {
                if (sp_kind == TCG_SUBPACKET_KIND_DATA &&
                    sp_len == (uint32_t)sp_payload_len)
                    tcg_report_length_overrun(pinfo, sp_len_item, sp_item,
                                              (uint64_t)offset + pad, xfer_len,
                                              pkt_complete || cp_complete);
                pad = pkt_payload_end - offset;
            }
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
        if (!pinfo->fd->visited && cp_complete && pkt_complete &&
            packet_valid && sec->state_valid && sec->scope &&
            tvb_captured_length(tvb) >= (unsigned)pkt_payload_end) {
            /* Core 3.2.2.4.2(5): keep completed method observations, but
             * discard the violating control Packet's remaining stream,
             * including any forensic parse of subsequent Subpackets. */
            if (ts.control_invalid)
                memset(&stream, 0, sizeof(stream));
            session->streams[sec->send] = stream;
            /* Only a numbered Packet anchors; tcg_observe_method cleared both
             * anchors when numbering was negotiated. */
            if (snapshot->numbered) {
                session->last_sequence[sec->send] = tvb_get_ntohl(tvb, packet_offset + 8);
                session->sequence_seen[sec->send] = true;
            }
            if (undo) {
                undo->stream_set = true;
                undo->sequence_set |= snapshot->numbered;
                undo->sequence = session->last_sequence[1];
            }
            /* Dissector policy after Core 3.2.2.4.2 item 5, in either
             * direction: a malformed status list aborts a regular session. */
            if (ts.status_violation && !ts.control_session)
                tcg_abort_session(session, "session aborted after a malformed status list");
            else if (ts.atom_violation && !ts.control_session)
                tcg_abort_session(session, "session aborted after an atom spanning a"
                                  " synchronous ComPacket");
            session->last_frame[sec->send] = pinfo->num;
            session->last_layer[sec->send] = pinfo->curr_layer_num;
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

/* Core 2.01 Tables 33/34: the caller interprets the complete time tuple and
 * ComID state before formatting any individual date. Keep its bytes and
 * numeric components filterable even when the date is not applicable. */
static void
dissect_tcg_comid_date(tvbuff_t *tvb, proto_tree *tree, int offset, int hf,
                        bool no_rtc, const char *inapplicable_state)
{
    proto_item *ti;
    proto_tree *date_tree;
    uint32_t    year, month, day, hour, minute, second, fraction;

    ti = proto_tree_add_item(tree, hf, tvb, offset, TCG_COMID_DATE_LEN, ENC_NA);
    date_tree = proto_item_add_subtree(ti, ett_tcg_comid_mgmt_date);

    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_year, tvb,
                                 offset, 2, ENC_BIG_ENDIAN, &year);
    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_month, tvb,
                                 offset + 2, 1, ENC_BIG_ENDIAN, &month);
    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_day, tvb,
                                 offset + 3, 1, ENC_BIG_ENDIAN, &day);
    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_hour, tvb,
                                 offset + 4, 1, ENC_BIG_ENDIAN, &hour);
    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_minute, tvb,
                                 offset + 5, 1, ENC_BIG_ENDIAN, &minute);
    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_second, tvb,
                                 offset + 6, 1, ENC_BIG_ENDIAN, &second);
    proto_tree_add_item_ret_uint(date_tree, hf_tcg_comid_mgmt_date_fraction,
                                 tvb, offset + 7, 2, ENC_BIG_ENDIAN, &fraction);
    proto_tree_add_item(date_tree, hf_tcg_comid_mgmt_date_reserved, tvb,
                        offset + 9, 1, ENC_BIG_ENDIAN);

    if (inapplicable_state != NULL) {
        proto_item_append_text(ti, ": Inapplicable (Extended ComID is %s)%s",
                               inapplicable_state, no_rtc ? "; no real-time clock" : "");
    } else if (no_rtc) {
        proto_item_append_text(ti, ": Unavailable (no real-time clock)");
    } else if (year == 0 && month == 0 && day == 0 && hour == 0 &&
               minute == 0 && second == 0 && fraction == 0) {
        proto_item_append_text(ti, ": Unavailable (zero date value)");
    } else {
        proto_item_append_text(ti, ": %04u-%02u-%02u %02u:%02u:%02u.%03u",
                               year, month, day, hour, minute, second, fraction);
    }
}

/* ComID management response body after the 12-byte header
 * (Core Tables 31, 33, 36); body_len is avail_len clamped to the capture. */
static void
dissect_tcg_comid_mgmt_body(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, int offset, int body_len,
                            uint32_t avail_len, uint32_t req_code,
                            proto_item *avail_len_item)
{
    int need;

    switch (req_code) {
    case TCG_REQ_VERIFY_COMID_VALID:
        need = 4 + 3 * TCG_COMID_DATE_LEN;  /* state + 3 date fields = 0x22 */
        break;
    case TCG_REQ_STACK_RESET:
        if (avail_len == 0)
            return;                         /* Table 37: pending */
        need = 4;                           /* Success/Failure */
        break;
    default:                                /* incl. Table 31 No Response */
        if (body_len > 0)
            proto_tree_add_item(tree, hf_tcg_comid_mgmt_data, tvb,
                                offset, body_len, ENC_NA);
        return;
    }

    /* A declared length short of the layout contradicts Tables 33/36; the
     * declaration is wrong whether or not any body bytes were captured. */
    if ((int)avail_len < need)
        expert_add_info(pinfo, avail_len_item, &ei_tcg_truncated);

    /* A body short of the declared length is the §3.3.4.7.2 probe-then-refetch
     * flow, so it renders raw without being called malformed. */
    if (body_len < need) {
        if (body_len > 0)
            proto_tree_add_item(tree, hf_tcg_comid_mgmt_data, tvb, offset,
                                body_len, ENC_NA);
        return;
    }

    if (req_code == TCG_REQ_STACK_RESET) {
        proto_tree_add_item(tree, hf_tcg_comid_mgmt_stack_reset_result, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
    } else {
        static const uint8_t zero_times[3 * TCG_COMID_DATE_LEN] = { 0 };
        uint32_t state;
        bool no_rtc = tvb_memeql(tvb, offset + 4, zero_times, sizeof(zero_times)) == 0;
        proto_tree_add_item_ret_uint(tree, hf_tcg_comid_mgmt_state, tvb, offset, 4,
                                     ENC_BIG_ENDIAN, &state);
        /* Core 2.01 §3.3.4.7.4: only time since reset is valid for Invalid
         * or Inactive ComIDs, even when allocation/expiry bytes are nonzero. */
        const char *inapplicable_state = state == 0 ? "Invalid" : state == 1 ? "Inactive" : NULL;
        dissect_tcg_comid_date(tvb, tree, offset + 4,
                               hf_tcg_comid_mgmt_time_alloc, no_rtc, inapplicable_state);
        dissect_tcg_comid_date(tvb, tree, offset + 14,
                               hf_tcg_comid_mgmt_time_expiry, no_rtc, inapplicable_state);
        dissect_tcg_comid_date(tvb, tree, offset + 24,
                               hf_tcg_comid_mgmt_time_reset, no_rtc, NULL);
    }

    /* A declared length past the layout is inside the declared data
     * (§3.3.4.7.2), so it is not padding. */
    if (body_len > need)
        proto_tree_add_item(tree, hf_tcg_comid_mgmt_data, tvb,
                            offset + need, body_len - need, ENC_NA);
}

/* SECP 02h ComID management commands (Core 3.3.4.7); 12-byte response
 * header (3.3.4.7.2). */
static void
dissect_tcg_comid_mgmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       const struct nvme_security_info *sec)
{
    bool send = sec->send;
    proto_tree *cm_tree;
    proto_item *cm_item;
    int         offset    = 0;
    int         remaining = tvb_reported_length_remaining(tvb, offset);
    /* Response: ComID(2) + Ext(2) + Request Code(4) + Reserved(2) +
     * Available Data Length(2) (Core §3.3.4.7.5, Table 36 STACK_RESET;
     * Tables 31/33/37 share the common response shape). */
    int         hdr_len   = send ? 8 : 12;
    int         tail_hf   = send ? hf_tcg_comid_mgmt_req_data :
                                   hf_tcg_comid_mgmt_data;
    uint32_t    req_code, comid;
    proto_item *comid_item;

    if (remaining < hdr_len) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb,
                                             offset, remaining, ENC_NA);
        /* A filled allocation may legally end within the header. */
        if (send)
            expert_add_info(pinfo, ti, &ei_tcg_truncated);
        else if (sec->xfer_len == 0 || (unsigned)remaining != sec->xfer_len)
            tcg_report_truncated(tvb, pinfo, ti, remaining, sec->xfer_len);
        return;
    }

    cm_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_tcg_comid_mgmt, &cm_item,
                                     "ComID Management");

    comid_item = proto_tree_add_item_ret_uint(cm_tree, hf_tcg_comid_mgmt_comid,
                                              tvb, offset, 2, ENC_BIG_ENDIAN,
                                              &comid);
    proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_comid_ext, tvb,
                        offset + 2, 2, ENC_BIG_ENDIAN);
    req_code = tvb_get_ntohl(tvb, offset + 4);
    /* Core 3.3.4.7.1-2: the request and response go to the ComID they name.
     * An all-zero Extended ComID with No Response Available is what Core
     * 3.3.4.7.5 mandates when no HANDLE_COMID_REQUEST was sent. */
    if (comid != sec->spsp &&
        !(!send && req_code == TCG_REQ_NO_RESPONSE &&
          tvb_get_ntohl(tvb, offset) == 0))
        expert_add_info_format(pinfo, comid_item, &ei_tcg_comid_mgmt_mismatch,
                               "ComID 0x%04x differs from the Security %s"
                               " ComID (SPSP) 0x%04x", comid,
                               send ? "Send" : "Receive", sec->spsp);
    if (!send && req_code == TCG_REQ_NO_RESPONSE)
        proto_tree_add_uint_format_value(cm_tree, hf_tcg_comid_mgmt_request_code,
                                         tvb, offset + 4, 4, req_code,
                                         "No Response Available (0x00000000)");
    else
        proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_request_code,
                            tvb, offset + 4, 4, ENC_BIG_ENDIAN);
    offset += 8;
    /* Core 3.3.4.7.1 explicitly permits future request-specific fields. */
    if (send && (req_code == TCG_REQ_VERIFY_COMID_VALID ||
                 req_code == TCG_REQ_STACK_RESET))
        tail_hf = hf_tcg_padding;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                    !send && req_code == TCG_REQ_NO_RESPONSE ? "No Response Available" :
                    val_to_str_const(req_code, tcg_request_code_vals, "Unknown request code"));

    if (!send) {
        uint32_t    avail_len;
        int         body_len;
        proto_item *avail_len_item;

        proto_tree_add_item(cm_tree, hf_tcg_comid_mgmt_reserved, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        avail_len_item =
            proto_tree_add_item_ret_uint(cm_tree, hf_tcg_comid_mgmt_avail_len,
                                         tvb, offset + 2, 2, ENC_BIG_ENDIAN,
                                         &avail_len);
        offset += 4;

        /* Available Data Length bounds the body; anything past it is pad to
         * the transfer length. Clamp to the bytes actually present. */
        remaining = tvb_reported_length_remaining(tvb, offset);
        body_len = ((int)avail_len < remaining) ? (int)avail_len : remaining;
        dissect_tcg_comid_mgmt_body(tvb, pinfo, cm_tree, offset, body_len,
                                    avail_len, req_code, avail_len_item);
        /* Core Tables 35-36: a trusted Success replaces the Extended ComID's
         * state, which returns to the Table 168 initial assumptions (Core
         * 3.3.4.7.5 item 7, 5.2.2.4.5). Older per-frame snapshots stay valid. */
        if (!pinfo->fd->visited && sec->state_valid && sec->scope &&
            req_code == TCG_REQ_STACK_RESET && avail_len == 4 && body_len == 4 &&
            tvb_captured_length(tvb) >= 16 && tvb_get_ntohl(tvb, 12) == 0 &&
            tvb_get_ntohs(tvb, 0) == sec->spsp)
            tcg_get_channel(sec, tvb_get_ntohl(tvb, 0), true);
        offset += body_len;
        tail_hf = hf_tcg_padding;
    }

    remaining = tvb_reported_length_remaining(tvb, offset);
    if (remaining > 0)
        proto_tree_add_item(cm_tree, tail_hf, tvb, offset, remaining, ENC_NA);
}

/*
 * SECP 02h, ComID 0000h, IF-RECV — GET COMID (Core Spec §3.3.4.3.1).
 * The whole payload is the 4-byte Extended ComID, zero-padded out to the
 * transfer length; all zeroes means the TPer could not assign a ComID.
 */
static void
dissect_tcg_get_comid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       const struct nvme_security_info *sec)
{
    int remaining = tvb_reported_length_remaining(tvb, 0);
    uint32_t ext_comid;

    if (remaining < 4) {
        proto_item *ti = proto_tree_add_item(tree, hf_tcg_raw_data, tvb, 0,
                                             remaining, ENC_NA);
        if (sec->xfer_len == 0 || (unsigned)remaining != sec->xfer_len)
            tcg_report_truncated(tvb, pinfo, ti, remaining, sec->xfer_len);
        return;
    }

    proto_tree_add_item_ret_uint(tree, hf_tcg_comid_get_ext_comid, tvb, 0, 4,
                                 ENC_BIG_ENDIAN, &ext_comid);
    /* An issued Extended ComID starts a new generation with Table 168
     * defaults; all zeroes means none was issued (Core 3.3.3(a), 3.3.4.3.1). */
    if (!pinfo->fd->visited && sec->state_valid && sec->scope &&
        (ext_comid >> 16) >= 0x1000 && (ext_comid & 0xffff) != 0xffff)
        tcg_get_channel(sec, ext_comid, true);

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
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "TCG %s",
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
            dissect_tcg_get_comid(tvb, pinfo, tcg_tree, sec);
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, " (ComID Management)");
            if (!sec->send && sec->spsp == TCG_COMID_TPER_RESET)
                expert_add_info(pinfo, ti, &ei_tcg_tper_reset_recv);
            dissect_tcg_comid_mgmt(tvb, pinfo, tcg_tree, sec);
        }
    } else if (sec->spsp == TCG_COMID_LEVEL0_DISCOVERY) {
        if (!sec->send) {
            col_append_str(pinfo->cinfo, COL_INFO, " (Level 0 Discovery)");
            dissect_tcg_level0_discovery(tvb, pinfo, tcg_tree, 0,
                    tvb_reported_length(tvb), sec);
        } else {
            /* Core §3.3.6.1: the TPer discards IF-SEND to ComID 0001h. */
            proto_item *payload = proto_tree_add_item(tcg_tree, hf_tcg_raw_data, tvb, 0,
                    tvb_reported_length(tvb), ENC_NA);
            proto_item_set_text(payload, "Discarded/Ignored payload");
        }
    } else {
        dissect_tcg_compacket(tvb, pinfo, tcg_tree, sec);
    }

    return tvb_captured_length(tvb);
}

/* Every Protocol 02h route, TPer Reset included (Opal SSC 2.30 3.2.3), may
 * change TCG state; of Protocol 01h only the discarded Level 0 IF-SEND
 * (Core 3.3.6.1) cannot. */
bool
tcg_storage_selector_may_advance_state(bool send, uint8_t secp, uint16_t spsp)
{
    if (secp == TCG_SECP_PROTO_MGMT)
        return true;
    return secp == TCG_SECP_COMPACKET &&
           !(send && spsp == TCG_COMID_LEVEL0_DISCOVERY);
}

bool
tcg_storage_security_send_completed(packet_info *pinfo,
                                    const struct nvme_security_info *sec,
                                    bool apply)
{
    /* Opal SSC 2.30 Table 13: IF-SEND, Protocol 02h, ComID 0004h, TL > 0. */
    bool candidate = sec && sec->send && sec->secp == TCG_SECP_PROTO_MGMT &&
                     sec->spsp == TCG_COMID_TPER_RESET && sec->xfer_len != 0 && sec->scope;

    /* 3.2.3: all ComIDs of the TPer lose their sessions and state. Old
     * channels stay allocated for the snapshots that reference them. */
    if (candidate && apply && sec->state_valid && !pinfo->fd->visited)
        tcg_new_scope_gen(sec->scope, true);
    return candidate;
}

void
tcg_storage_security_send_failed(packet_info *pinfo, uint32_t request_frame,
                                 uint16_t request_ordinal)
{
    uint64_t key = tcg_send_key(request_frame, request_ordinal);
    tcg_send_undo *undo;

    if (pinfo->fd->visited)
        return;
    undo = wmem_map_remove(tcg_send_undos, &key);
    for (; undo; undo = undo->next) {
        tcg_session *session = undo->session;

        /* Cancelled, not unlinked: another command slot may have queued
         * calls behind them. */
        for (tcg_pair *pair = session->pending; pair; pair = pair->next) {
            if (pair->request_frame == request_frame &&
                pair->request_ordinal == request_ordinal)
                pair->cancelled = true;
        }
        if (undo->start_set)
            session->start_seen = false;
        /* An abort or a gap's pairing restart that it caused stays (rare). */
        if (session->aborted)
            continue;
        /* Restore only what no later frame has moved: a later IF-SEND's
         * StartTrustedSession owns the pending request now. */
        if (undo->trusted_set && session->trusted_pending &&
            session->trusted_frame == request_frame &&
            session->trusted_ordinal == request_ordinal) {
            session->trusted_pending = undo->trusted_pending;
            session->host_keys = undo->host_keys;
            session->trusted_frame = undo->trusted_frame;
            session->trusted_ordinal = undo->trusted_ordinal;
        }
        if (undo->stream_set && session->last_frame[1] == request_frame)
            session->streams[1] = undo->stream;
        if (undo->sequence_set && session->sequence_seen[1] &&
            session->last_sequence[1] == undo->sequence) {
            session->last_sequence[1] = undo->last_sequence;
            session->sequence_seen[1] = undo->sequence_seen;
        }
    }
}

/* "nvme.security.send_failed": a Security Send completed with an error. */
static int
dissect_tcg_storage_send_failed(tvbuff_t *tvb _U_, packet_info *pinfo,
                                proto_tree *tree _U_, void *data)
{
    const struct nvme_security_info *sec = (const struct nvme_security_info *)data;

    if (sec && sec->send)
        tcg_storage_security_send_failed(pinfo, sec->request_frame,
                                         sec->request_ordinal);
    return 0;
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
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(tcg_subpacket_kind_rvals), 0x0,
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
            FT_UINT64, BASE_HEX, NULL,
            0x0, "Invoking or Method UID in a CALL header", HFILL },
        },
        { &hf_tcg_tok_control,
          { "Control Token", "tcg-storage.tok.control",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(tcg_token_control_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_tcg_tok_status,
          { "Method Status", "tcg-storage.tok.status",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(tcg_method_status_vals), 0x0,
            "Method Status from the End of Data status list", HFILL },
        },
        { &hf_tcg_tok_host_status,
          { "Expected/Abort Status", "tcg-storage.tok.host_status",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(tcg_method_status_vals), 0x0,
            "Host-supplied status, not a returned Method Status", HFILL },
        },
        { &hf_tcg_tok_fragment,
          { "Token fragment", "tcg-storage.tok.fragment",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_tok_name,
          { "Name", "tcg-storage.tok.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Printable byte-sequence Name of a Named value", HFILL },
        },
        { &hf_tcg_param,
          { "Parameter", "tcg-storage.param",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Method parameter that this value starts (Core 3.2.4.1)", HFILL },
        },
        { &hf_tcg_param_uid,
          { "Parameter UID", "tcg-storage.param.uid",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            "uidref passed in a method parameter", HFILL },
        },
        { &hf_tcg_response_to,
          { "Response to", "tcg-storage.response_to",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Invoking and method UID of the call this response answers", HFILL },
        },
        { &hf_tcg_request_in,
          { "Request In", "tcg-storage.request_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "The method call this response answers is in this frame", HFILL },
        },
        { &hf_tcg_response_in,
          { "Response In", "tcg-storage.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this method call is in this frame", HFILL },
        },
        { &hf_tcg_txn_start_status,
          { "Start Transaction Status", "tcg-storage.txn.start_status",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "TCG Core 'Start Transaction Status Codes': 0 Success, otherwise Reserved", HFILL },
        },
        { &hf_tcg_txn_end_status,
          { "End Transaction Status", "tcg-storage.txn.end_status",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "TCG Core 'End Transaction Status Codes': 0 Commit, 1 Abort,"
            " otherwise Reserved", HFILL },
        },
        { &hf_tcg_secure_data,
          { "Secure messaging payload (IV / SecureData / MAC)", "tcg-storage.packet.secure_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Observed session-key exchange; cipher-dependent boundaries are unknown", HFILL },
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
        { &hf_tcg_l0_unsupported_version,
          { "Level 0 version not recognized", "tcg-storage.l0.unsupported_version",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "The Level 0 version may be defined by a later specification",
            HFILL },
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
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(tcg_l0_opal2_minor_rvals), 0x0F,
            NULL, HFILL },
        },
        { &hf_tcg_l0_feat_ds_minor,
          { "Feature Set Minor Version Number", "tcg-storage.l0.feat.datastore.minor",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(tcg_l0_ds_minor_rvals), 0x0F,
            NULL, HFILL },
        },
        { &hf_tcg_l0_feat_cnl_minor,
          { "Feature Set Minor Version Number", "tcg-storage.l0.feat.cnl.minor",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(tcg_l0_cnl_minor_rvals), 0x0F,
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
        { &hf_tcg_l0_feat_reserved_tail,
          { "Reserved", "tcg-storage.l0.feat.reserved_tail",
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
        { &hf_tcg_l0_locking_reserved_v1,
          { "Reserved", "tcg-storage.l0.feat.locking.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL },
        },
        { &hf_tcg_l0_locking_reserved_v2,
          { "Reserved", "tcg-storage.l0.feat.locking.reserved_v2",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL },
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
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(tcg_l0_siis_revision_vals), 0x0, NULL, HFILL },
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
        /* Opal SSC V2 Feature (0x0203) */
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
          { "Number of Locking SP Admin Authorities Supported",
            "tcg-storage.l0.feat.opal2.num_admins",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_num_users,
          { "Number of Locking SP User Authorities Supported",
            "tcg-storage.l0.feat.opal2.num_users",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_initial_cpin_sid,
          { "Initial C_PIN_SID PIN Indicator",
            "tcg-storage.l0.feat.opal2.initial_cpin_sid",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(tcg_l0_opal2_cpin_sid_rvals), 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_opal2_revert_cpin_sid,
          { "Behavior of C_PIN_SID PIN upon TPer Revert",
            "tcg-storage.l0.feat.opal2.revert_cpin_sid",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
            RVALS(tcg_l0_opal2_cpin_sid_rvals), 0x0, NULL, HFILL },
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
            "1 = Admins own RangeStart, RangeLength and CommonName of the"
            " Single User Mode Locking objects, or the Locking SP is in a life"
            " cycle state other than Manufactured or Issued; 0 = their User"
            " authorities own them",
            HFILL },
        },
        /* Additional DataStore Tables Feature (0x0202) */
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
        { &hf_tcg_l0_bsid_freeze_supported,
          { "Locking SP Freeze Lock supported",
            "tcg-storage.l0.feat.block_sid.freeze_lock_supported",
            FT_BOOLEAN, 8, NULL, 0x04,
            "The Locking SP Freeze Lock capability is supported", HFILL },
        },
        { &hf_tcg_l0_bsid_freeze_state,
          { "Locking SP Freeze Lock State",
            "tcg-storage.l0.feat.block_sid.freeze_lock_state",
            FT_BOOLEAN, 8, NULL, 0x08,
            "The Locking SP is in the Manufactured-Frozen life cycle state",
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
        /* Supported Data Removal Mechanism Feature (0x0404) */
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
        { &hf_tcg_l0_drm_reserved2,
          { "Reserved", "tcg-storage.l0.feat.data_removal.reserved2",
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
        /* Version 1 only (Pyrite SSC 2.01 Table 8, Key Per I/O SSC 1.00
         * Table 7); Reserved in Version 2 */
        { &hf_tcg_l0_drm_mech_unmap,
          { "Unmap",
            "tcg-storage.l0.feat.data_removal.mechanism.unmap",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_mech_reset_wp,
          { "Reset Write Pointers",
            "tcg-storage.l0.feat.data_removal.mechanism.reset_write_pointers",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_fmt_unmap,
          { "Unmap Time Format",
            "tcg-storage.l0.feat.data_removal.format.unmap",
            FT_BOOLEAN, 8, TFS(&tfs_tcg_l0_drm_fmt), 0x08, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_fmt_reset_wp,
          { "Reset Write Pointers Time Format",
            "tcg-storage.l0.feat.data_removal.format.reset_write_pointers",
            FT_BOOLEAN, 8, TFS(&tfs_tcg_l0_drm_fmt), 0x10, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_time_unmap,
          { "Data Removal Time (Unmap)",
            "tcg-storage.l0.feat.data_removal.time_unmap",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_l0_drm_time_reset_wp,
          { "Data Removal Time (Reset Write Pointers)",
            "tcg-storage.l0.feat.data_removal.time_reset_write_pointers",
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
        { &hf_tcg_comid_mgmt_req_data,
          { "Request Data", "tcg-storage.comid_mgmt.request_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_state,
          { "Extended ComID State", "tcg-storage.comid_mgmt.comid_state",
            FT_UINT32, BASE_HEX, VALS(tcg_comid_state_vals), 0x0, NULL,
            HFILL },
        },
        { &hf_tcg_comid_mgmt_time_alloc,
          { "Time of Allocation", "tcg-storage.comid_mgmt.time_allocated",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Absolute time of allocation relative to the last TPer reset",
            HFILL },
        },
        { &hf_tcg_comid_mgmt_time_expiry,
          { "Time of Expiry", "tcg-storage.comid_mgmt.time_expiry",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Absolute time of expiry relative to the last TPer reset", HFILL },
        },
        { &hf_tcg_comid_mgmt_time_reset,
          { "Time Since Last Reset", "tcg-storage.comid_mgmt.time_since_reset",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_year,
          { "Year", "tcg-storage.comid_mgmt.date.year",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_month,
          { "Month", "tcg-storage.comid_mgmt.date.month",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_day,
          { "Day", "tcg-storage.comid_mgmt.date.day",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_hour,
          { "Hour", "tcg-storage.comid_mgmt.date.hour",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_minute,
          { "Minute", "tcg-storage.comid_mgmt.date.minute",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_second,
          { "Second", "tcg-storage.comid_mgmt.date.second",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_date_fraction,
          { "Fraction", "tcg-storage.comid_mgmt.date.fraction",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            "milliseconds, 0–999", HFILL },
        },
        { &hf_tcg_comid_mgmt_date_reserved,
          { "Reserved", "tcg-storage.comid_mgmt.date.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_tcg_comid_mgmt_stack_reset_result,
          { "Stack Reset Result",
            "tcg-storage.comid_mgmt.stack_reset_result",
            FT_UINT32, BASE_HEX, VALS(tcg_stack_reset_result_vals), 0x0,
            NULL, HFILL },
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
        { &ei_tcg_transfer_short,
          { "tcg-storage.transfer_short", PI_UNDECODED, PI_NOTE,
            "The bytes are missing because the transfer stopped short of"
            " the length the NVMe Security command asked for, not because"
            " the structure or its declared length is wrong", EXPFILL }},
        { &ei_tcg_tok_reserved,
          { "tcg-storage.tok.reserved_token", PI_PROTOCOL, PI_WARN,
            "Reserved token value", EXPFILL }},
        { &ei_tcg_tok_zero_length,
          { "tcg-storage.tok.zero_length", PI_MALFORMED, PI_WARN,
            "Only a non-continued short bytes atom may have zero length", EXPFILL }},
        { &ei_tcg_tok_pair,
          { "tcg-storage.tok.delimiter", PI_MALFORMED, PI_WARN,
            "Crossed, unmatched or unterminated List/Name delimiters", EXPFILL }},
        { &ei_tcg_tok_status_type,
          { "tcg-storage.tok.status_type", PI_MALFORMED, PI_WARN,
            "A status list requires at least three unsigned integer elements", EXPFILL }},
        { &ei_tcg_txn_status_type,
          { "tcg-storage.txn.status_type", PI_MALFORMED, PI_WARN,
            "A Start/End Transaction token must be followed by a uinteger"
            " status (Core 3.2.2.3.3.4/5)", EXPFILL }},
        { &ei_tcg_tok_spans_compacket,
          { "tcg-storage.tok.spans_compacket", PI_PROTOCOL, PI_WARN,
            "Atom cannot complete within this ComPacket while synchronous"
            " (Core 3.3.10.3(a)); rest of the Packet not decoded", EXPFILL }},
        { &ei_tcg_feat_length_align,
          { "tcg-storage.l0.feat.length_not_aligned", PI_MALFORMED, PI_WARN,
            "Feature descriptor Length is not an integral multiple of 4;"
            " the descriptors that follow are misaligned", EXPFILL }},
        { &ei_tcg_feat_length,
          { "tcg-storage.l0.feat.invalid_length", PI_MALFORMED, PI_WARN,
            "TPer v1, Locking v1-v3 and SIIS v1 feature data must be exactly 12 bytes", EXPFILL }},
        { &ei_tcg_sequence_gap,
          { "tcg-storage.packet.seq_gap", PI_SEQUENCE, PI_WARN,
            "Sequence gap: earlier Packets of this session are not in the capture"
            " or were not admitted; tracking resumes from this Packet", EXPFILL }},
        { &ei_tcg_comid_mismatch,
          { "tcg-storage.compacket.comid_mismatch", PI_PROTOCOL, PI_WARN,
            "ComPacket ComID differs from the Security Send/Receive ComID (SPSP);"
            " session state not tracked", EXPFILL }},
        { &ei_tcg_subpacket_kind,
          { "tcg-storage.subpacket.kind.reserved", PI_PROTOCOL, PI_WARN,
            "Reserved Subpacket Kind; only 0x0000 (Data) and 0x8001 (Credit"
            " Control) are defined (TCG Core 'Subpacket Types')", EXPFILL }},
        { &ei_tcg_credit_length,
          { "tcg-storage.subpacket.credit.invalid_length", PI_MALFORMED, PI_WARN,
            "Credit Control Subpacket Length must be 4;"
            " session state not tracked", EXPFILL }},
        { &ei_tcg_tper_reset_recv,
          { "tcg-storage.tper_reset.if_recv", PI_PROTOCOL, PI_NOTE,
            "No IF-RECV is defined for the TPER_RESET ComID 0x0004 (Opal SSC"
            " 3.2.3); decoded as a ComID management response", EXPFILL }},
        { &ei_tcg_comid_mgmt_mismatch,
          { "tcg-storage.comid_mgmt.comid_mismatch", PI_PROTOCOL, PI_WARN,
            "ComID management ComID differs from the Security Send/Receive"
            " ComID (SPSP)", EXPFILL }},
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
        &ett_tcg_comid_mgmt_date,
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
    tcg_storage_send_failed_handle = create_dissector_handle(
            dissect_tcg_storage_send_failed, proto_tcg_storage);
    tcg_sync_only = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                           g_direct_hash, g_direct_equal);
    tcg_scope_gens = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                            g_direct_hash, g_direct_equal);
    tcg_send_undos = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                            g_int64_hash, g_int64_equal);
}

void
proto_reg_handoff_tcg_storage(void)
{
    dissector_add_uint("nvme.security.secp", TCG_SECP_COMPACKET,
                       tcg_storage_handle);
    dissector_add_uint("nvme.security.secp", TCG_SECP_PROTO_MGMT,
                       tcg_storage_handle);
    dissector_add_uint("nvme.security.send_failed", TCG_SECP_COMPACKET,
                       tcg_storage_send_failed_handle);
    dissector_add_uint("nvme.security.send_failed", TCG_SECP_PROTO_MGMT,
                       tcg_storage_send_failed_handle);
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
