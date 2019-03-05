/* packet-drbd.c
 * Routines for DRBD dissection
 * By Joel Colledge <joel.colledge@linbit.com>
 * Copyright 2019, LINBIT Information Technologies GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Wireshark dissector for DRBD - Distributed Replicated Block Device.
 * The DRBD Linux kernel module sources can be found at https://github.com/LINBIT/drbd-9.0
 * More information about Linbit and DRBD can be found at https://www.linbit.com/
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/str_util.h>

typedef struct value_payload_decoder {
    int value;
    void (*decoder_fn)(tvbuff_t *, proto_tree*);
} value_payload_decoder;

/* Known as SHARED_SECRET_MAX in the DRBD sources */
#define DRBD_STRING_MAX 64

enum drbd_packet {
    P_DATA                = 0x00,
    P_DATA_REPLY          = 0x01,
    P_RS_DATA_REPLY       = 0x02,
    P_BARRIER             = 0x03,
    P_BITMAP              = 0x04,
    P_BECOME_SYNC_TARGET  = 0x05,
    P_BECOME_SYNC_SOURCE  = 0x06,
    P_UNPLUG_REMOTE       = 0x07,
    P_DATA_REQUEST        = 0x08,
    P_RS_DATA_REQUEST     = 0x09,
    P_SYNC_PARAM          = 0x0a,
    P_PROTOCOL            = 0x0b,
    P_UUIDS               = 0x0c,
    P_SIZES               = 0x0d,
    P_STATE               = 0x0e,
    P_SYNC_UUID           = 0x0f,
    P_AUTH_CHALLENGE      = 0x10,
    P_AUTH_RESPONSE       = 0x11,
    P_STATE_CHG_REQ       = 0x12,

    P_PING                = 0x13,
    P_PING_ACK            = 0x14,
    P_RECV_ACK            = 0x15,
    P_WRITE_ACK           = 0x16,
    P_RS_WRITE_ACK        = 0x17,
    P_SUPERSEDED          = 0x18,
    P_NEG_ACK             = 0x19,
    P_NEG_DREPLY          = 0x1a,
    P_NEG_RS_DREPLY       = 0x1b,
    P_BARRIER_ACK         = 0x1c,
    P_STATE_CHG_REPLY     = 0x1d,

    P_OV_REQUEST          = 0x1e,
    P_OV_REPLY            = 0x1f,
    P_OV_RESULT           = 0x20,
    P_CSUM_RS_REQUEST     = 0x21,
    P_RS_IS_IN_SYNC       = 0x22,
    P_SYNC_PARAM89        = 0x23,
    P_COMPRESSED_BITMAP   = 0x24,

    P_DELAY_PROBE         = 0x27,
    P_OUT_OF_SYNC         = 0x28,
    P_RS_CANCEL           = 0x29,
    P_CONN_ST_CHG_REQ     = 0x2a,
    P_CONN_ST_CHG_REPLY   = 0x2b,
    P_RETRY_WRITE         = 0x2c,
    P_PROTOCOL_UPDATE     = 0x2d,
    P_TWOPC_PREPARE       = 0x2e,
    P_TWOPC_ABORT         = 0x2f,

    P_DAGTAG              = 0x30,

    P_TRIM                = 0x31,

    P_RS_THIN_REQ         = 0x32,
    P_RS_DEALLOCATED      = 0x33,

    P_WSAME               = 0x34,
    P_TWOPC_PREP_RSZ      = 0x35,
    P_ZEROES              = 0x36,

    P_PEER_ACK            = 0x40,
    P_PEERS_IN_SYNC       = 0x41,

    P_UUIDS110            = 0x42,
    P_PEER_DAGTAG         = 0x43,
    P_CURRENT_UUID        = 0x44,

    P_TWOPC_YES           = 0x45,
    P_TWOPC_NO            = 0x46,
    P_TWOPC_COMMIT        = 0x47,
    P_TWOPC_RETRY         = 0x48,

    P_CONFIRM_STABLE      = 0x49,

    P_INITIAL_META        = 0xfff1,
    P_INITIAL_DATA        = 0xfff2,

    P_CONNECTION_FEATURES = 0xfffe
};

static const value_string packet_names[] = {
    { P_DATA, "P_DATA" },
    { P_DATA_REPLY, "P_DATA_REPLY" },
    { P_RS_DATA_REPLY, "P_RS_DATA_REPLY" },
    { P_BARRIER, "P_BARRIER" },
    { P_BITMAP, "P_BITMAP" },
    { P_BECOME_SYNC_TARGET, "P_BECOME_SYNC_TARGET" },
    { P_BECOME_SYNC_SOURCE, "P_BECOME_SYNC_SOURCE" },
    { P_UNPLUG_REMOTE, "P_UNPLUG_REMOTE" },
    { P_DATA_REQUEST, "P_DATA_REQUEST" },
    { P_RS_DATA_REQUEST, "P_RS_DATA_REQUEST" },
    { P_SYNC_PARAM, "P_SYNC_PARAM" },
    { P_PROTOCOL, "P_PROTOCOL" },
    { P_UUIDS, "P_UUIDS" },
    { P_SIZES, "P_SIZES" },
    { P_STATE, "P_STATE" },
    { P_SYNC_UUID, "P_SYNC_UUID" },
    { P_AUTH_CHALLENGE, "P_AUTH_CHALLENGE" },
    { P_AUTH_RESPONSE, "P_AUTH_RESPONSE" },
    { P_STATE_CHG_REQ, "P_STATE_CHG_REQ" },

    { P_PING, "P_PING" },
    { P_PING_ACK, "P_PING_ACK" },
    { P_RECV_ACK, "P_RECV_ACK" },
    { P_WRITE_ACK, "P_WRITE_ACK" },
    { P_RS_WRITE_ACK, "P_RS_WRITE_ACK" },
    { P_SUPERSEDED, "P_SUPERSEDED" },
    { P_NEG_ACK, "P_NEG_ACK" },
    { P_NEG_DREPLY, "P_NEG_DREPLY" },
    { P_NEG_RS_DREPLY, "P_NEG_RS_DREPLY" },
    { P_BARRIER_ACK, "P_BARRIER_ACK" },
    { P_STATE_CHG_REPLY, "P_STATE_CHG_REPLY" },

    { P_OV_REQUEST, "P_OV_REQUEST" },
    { P_OV_REPLY, "P_OV_REPLY" },
    { P_OV_RESULT, "P_OV_RESULT" },
    { P_CSUM_RS_REQUEST, "P_CSUM_RS_REQUEST" },
    { P_RS_IS_IN_SYNC, "P_RS_IS_IN_SYNC" },
    { P_SYNC_PARAM89, "P_SYNC_PARAM89" },
    { P_COMPRESSED_BITMAP, "P_COMPRESSED_BITMAP" },

    { P_DELAY_PROBE, "P_DELAY_PROBE" },
    { P_OUT_OF_SYNC, "P_OUT_OF_SYNC" },
    { P_RS_CANCEL, "P_RS_CANCEL" },
    { P_CONN_ST_CHG_REQ, "P_CONN_ST_CHG_REQ" },
    { P_CONN_ST_CHG_REPLY, "P_CONN_ST_CHG_REPLY" },
    { P_RETRY_WRITE, "P_RETRY_WRITE" },
    { P_PROTOCOL_UPDATE, "P_PROTOCOL_UPDATE" },
    { P_TWOPC_PREPARE, "P_TWOPC_PREPARE" },
    { P_TWOPC_ABORT, "P_TWOPC_ABORT" },

    { P_DAGTAG, "P_DAGTAG" },

    { P_TRIM, "P_TRIM" },

    { P_RS_THIN_REQ, "P_RS_THIN_REQ" },
    { P_RS_DEALLOCATED, "P_RS_DEALLOCATED" },

    { P_WSAME, "P_WSAME" },
    { P_TWOPC_PREP_RSZ, "P_TWOPC_PREP_RSZ" },
    { P_ZEROES, "P_ZEROES" },

    { P_PEER_ACK, "P_PEER_ACK" },
    { P_PEERS_IN_SYNC, "P_PEERS_IN_SYNC" },

    { P_UUIDS110, "P_UUIDS110" },
    { P_PEER_DAGTAG, "P_PEER_DAGTAG" },
    { P_CURRENT_UUID, "P_CURRENT_UUID" },

    { P_TWOPC_YES, "P_TWOPC_YES" },
    { P_TWOPC_NO, "P_TWOPC_NO" },
    { P_TWOPC_COMMIT, "P_TWOPC_COMMIT" },
    { P_TWOPC_RETRY, "P_TWOPC_RETRY" },

    { P_CONFIRM_STABLE, "P_CONFIRM_STABLE" },

    { P_INITIAL_META, "P_INITIAL_META" },
    { P_INITIAL_DATA, "P_INITIAL_DATA" },

    { P_CONNECTION_FEATURES, "P_CONNECTION_FEATURES" },
    { 0, NULL }
};

#define DRBD_PROT_A   1
#define DRBD_PROT_B   2
#define DRBD_PROT_C   3

static const value_string protocol_names[] = {
    { DRBD_PROT_A, "A" },
    { DRBD_PROT_B, "B" },
    { DRBD_PROT_C, "C" },
    { 0, NULL }
};

#define DP_HARDBARRIER        1
#define DP_RW_SYNC            2
#define DP_MAY_SET_IN_SYNC    4
#define DP_UNPLUG             8
#define DP_FUA               16
#define DP_FLUSH             32
#define DP_DISCARD           64
#define DP_SEND_RECEIVE_ACK 128
#define DP_SEND_WRITE_ACK   256
#define DP_WSAME            512
#define DP_ZEROES          1024

static void dissect_drbd_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void decode_payload_connection_features(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_auth_challenge(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_auth_response(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_data(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_data_reply(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_rs_data_reply(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_barrier(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_data_request(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_sync_param(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_protocol(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_uuids(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_sizes(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_state(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_req_state(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_sync_uuid(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_skip(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_out_of_sync(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_twopc(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_dagtag(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_uuids110(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_peer_dagtag(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_current_uuid(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_data_size(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_data_wsame(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_rs_deallocated(tvbuff_t *tvb, proto_tree *tree);

static void decode_payload_block_ack(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_barrier_ack(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_confirm_stable(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_rq_s_reply(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_peer_ack(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_peers_in_sync(tvbuff_t *tvb, proto_tree *tree);
static void decode_payload_twopc_reply(tvbuff_t *tvb, proto_tree *tree);

static const value_payload_decoder payload_decoders[] = {
    { P_CONNECTION_FEATURES, decode_payload_connection_features },
    { P_AUTH_CHALLENGE, decode_payload_auth_challenge },
    { P_AUTH_RESPONSE, decode_payload_auth_response },
    { P_DATA, decode_payload_data },
    { P_DATA_REPLY, decode_payload_data_reply },
    { P_RS_DATA_REPLY, decode_payload_rs_data_reply },
    { P_BARRIER, decode_payload_barrier },
    { P_BITMAP, NULL }, /* TODO: decode additional data */
    { P_COMPRESSED_BITMAP, NULL }, /* TODO: decode additional data */
    { P_UNPLUG_REMOTE, NULL },
    { P_DATA_REQUEST, decode_payload_data_request },
    { P_RS_DATA_REQUEST, decode_payload_data_request },
    { P_SYNC_PARAM, decode_payload_sync_param },
    { P_SYNC_PARAM89, decode_payload_sync_param },
    { P_PROTOCOL, decode_payload_protocol },
    { P_UUIDS, decode_payload_uuids },
    { P_SIZES, decode_payload_sizes },
    { P_STATE, decode_payload_state },
    { P_STATE_CHG_REQ, decode_payload_req_state },
    { P_SYNC_UUID, decode_payload_sync_uuid },
    { P_OV_REQUEST, decode_payload_data_request },
    { P_OV_REPLY, decode_payload_data_request }, /* TODO: decode additional data */
    { P_CSUM_RS_REQUEST, decode_payload_data_request }, /* TODO: decode additional data */
    { P_RS_THIN_REQ, decode_payload_data_request },
    { P_DELAY_PROBE, decode_payload_skip },
    { P_OUT_OF_SYNC, decode_payload_out_of_sync },
    { P_CONN_ST_CHG_REQ, decode_payload_req_state },
    { P_PROTOCOL_UPDATE, decode_payload_protocol }, /* TODO: decode additional data */
    { P_TWOPC_PREPARE, decode_payload_twopc },
    { P_TWOPC_PREP_RSZ, decode_payload_twopc },
    { P_TWOPC_ABORT, decode_payload_twopc },
    { P_DAGTAG, decode_payload_dagtag },
    { P_UUIDS110, decode_payload_uuids110 },
    { P_PEER_DAGTAG, decode_payload_peer_dagtag },
    { P_CURRENT_UUID, decode_payload_current_uuid },
    { P_TWOPC_COMMIT, decode_payload_twopc },
    { P_TRIM, decode_payload_data_size },
    { P_ZEROES, decode_payload_data_size },
    { P_RS_DEALLOCATED, decode_payload_rs_deallocated },
    { P_WSAME, decode_payload_data_wsame },

    { P_PING, NULL },
    { P_PING_ACK, NULL },
    { P_RECV_ACK, decode_payload_block_ack },
    { P_WRITE_ACK, decode_payload_block_ack },
    { P_RS_WRITE_ACK, decode_payload_block_ack },
    { P_SUPERSEDED, decode_payload_block_ack },
    { P_NEG_ACK, decode_payload_block_ack },
    { P_NEG_DREPLY, decode_payload_block_ack },
    { P_NEG_RS_DREPLY, decode_payload_block_ack },
    { P_OV_RESULT, decode_payload_block_ack },
    { P_BARRIER_ACK, decode_payload_barrier_ack },
    { P_CONFIRM_STABLE, decode_payload_confirm_stable },
    { P_STATE_CHG_REPLY, decode_payload_rq_s_reply },
    { P_RS_IS_IN_SYNC, decode_payload_block_ack },
    { P_DELAY_PROBE, decode_payload_skip },
    { P_RS_CANCEL, decode_payload_block_ack },
    { P_CONN_ST_CHG_REPLY, decode_payload_rq_s_reply },
    { P_RETRY_WRITE, decode_payload_block_ack },
    { P_PEER_ACK, decode_payload_peer_ack },
    { P_PEERS_IN_SYNC, decode_payload_peers_in_sync },
    { P_TWOPC_YES, decode_payload_twopc_reply },
    { P_TWOPC_NO, decode_payload_twopc_reply },
    { P_TWOPC_RETRY, decode_payload_twopc_reply },
};


void proto_register_drbd(void);
void proto_reg_handoff_drbd(void);

static dissector_handle_t drbd_handle;

static int proto_drbd = -1;

static int hf_drbd_command = -1;
static int hf_drbd_length = -1;
static int hf_drbd_volume = -1;
static int hf_drbd_auth_challenge_nonce = -1;
static int hf_drbd_auth_response_hash = -1;
static int hf_drbd_sector = -1;
static int hf_drbd_block_id = -1;
static int hf_drbd_seq_num = -1;
static int hf_drbd_dp_flags = -1;
static int hf_drbd_data = -1;
static int hf_drbd_size = -1;
static int hf_drbd_blksize = -1;
static int hf_drbd_protocol_min = -1;
static int hf_drbd_feature_flags = -1;
static int hf_drbd_protocol_max = -1;
static int hf_drbd_sender_node_id = -1;
static int hf_drbd_receiver_node_id = -1;
static int hf_drbd_barrier = -1;
static int hf_drbd_set_size = -1;
static int hf_drbd_oldest_block_id = -1;
static int hf_drbd_youngest_block_id = -1;
static int hf_drbd_resync_rate = -1;
static int hf_drbd_verify_alg = -1;
static int hf_drbd_csums_alg = -1;
static int hf_drbd_c_plan_ahead = -1;
static int hf_drbd_c_delay_target = -1;
static int hf_drbd_c_fill_target = -1;
static int hf_drbd_c_max_rate = -1;
static int hf_drbd_protocol = -1;
static int hf_drbd_after_sb_0p = -1;
static int hf_drbd_after_sb_1p = -1;
static int hf_drbd_after_sb_2p = -1;
static int hf_drbd_conn_flags = -1;
static int hf_drbd_two_primaries = -1;
static int hf_drbd_integrity_alg = -1;
static int hf_drbd_current_uuid = -1;
static int hf_drbd_bitmap_uuid = -1;
static int hf_drbd_history_uuids = -1;
static int hf_drbd_dirty_bits = -1;
static int hf_drbd_uuid_flags = -1;
static int hf_drbd_node_mask = -1;
static int hf_drbd_bitmap_uuids_mask = -1;
static int hf_drbd_uuid = -1;
static int hf_drbd_weak_nodes = -1;
static int hf_drbd_physical_block_size = -1;
static int hf_drbd_logical_block_size = -1;
static int hf_drbd_alignment_offset = -1;
static int hf_drbd_io_min = -1;
static int hf_drbd_io_opt = -1;
static int hf_drbd_discard_enabled = -1;
static int hf_drbd_discard_zeroes_data = -1;
static int hf_drbd_write_same_capable = -1;
static int hf_drbd_d_size = -1;
static int hf_drbd_u_size = -1;
static int hf_drbd_c_size = -1;
static int hf_drbd_max_bio_size = -1;
static int hf_drbd_queue_order_type = -1;
static int hf_drbd_dds_flags = -1;
static int hf_drbd_state = -1;
static int hf_drbd_mask = -1;
static int hf_drbd_val = -1;
static int hf_drbd_retcode = -1;
static int hf_drbd_tid = -1;
static int hf_drbd_initiator_node_id = -1;
static int hf_drbd_target_node_id = -1;
static int hf_drbd_nodes_to_reach = -1;
static int hf_drbd_reachable_nodes = -1;
static int hf_drbd_offset = -1;
static int hf_drbd_dagtag = -1;
static int hf_drbd_node_id = -1;

static int hf_drbd_dp_hardbarrier = -1;
static int hf_drbd_dp_rw_sync = -1;
static int hf_drbd_dp_may_set_in_sync = -1;
static int hf_drbd_dp_unplug = -1;
static int hf_drbd_dp_fua = -1;
static int hf_drbd_dp_flush = -1;
static int hf_drbd_dp_discard = -1;
static int hf_drbd_dp_send_receive_ack = -1;
static int hf_drbd_dp_send_write_ack = -1;
static int hf_drbd_dp_wsame = -1;
static int hf_drbd_dp_zeroes = -1;

static gint ett_drbd = -1;
static gint ett_drbd_data_flags = -1;

static const int *data_flag_fields[] = {
    &hf_drbd_dp_hardbarrier,
    &hf_drbd_dp_rw_sync,
    &hf_drbd_dp_may_set_in_sync,
    &hf_drbd_dp_unplug,
    &hf_drbd_dp_fua,
    &hf_drbd_dp_flush,
    &hf_drbd_dp_discard,
    &hf_drbd_dp_send_receive_ack,
    &hf_drbd_dp_send_write_ack,
    &hf_drbd_dp_wsame,
    &hf_drbd_dp_zeroes,
    NULL
};

#define CHALLENGE_LEN 64

static gboolean is_bit_set_64(guint64 value, int bit) {
    return !!(value & (G_GUINT64_CONSTANT(1) << bit));
}

/*
 * Length of the frame header.
 */
#define DRBD_FRAME_HEADER_80_LEN 8
#define DRBD_FRAME_HEADER_95_LEN 8
#define DRBD_FRAME_HEADER_100_LEN 16

#define DRBD_MAGIC 0x83740267
#define DRBD_MAGIC_BIG 0x835a
#define DRBD_MAGIC_100 0x8620ec20

static guint get_drbd_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint32 magic32;
    guint16 magic16;

    magic32 = tvb_get_ntohl(tvb, offset);

    if (magic32 == DRBD_MAGIC)
        return DRBD_FRAME_HEADER_80_LEN + tvb_get_ntohs(tvb, offset + 6);

    if (tvb_reported_length_remaining(tvb, offset) >= DRBD_FRAME_HEADER_100_LEN && magic32 == DRBD_MAGIC_100)
        return DRBD_FRAME_HEADER_100_LEN + tvb_get_ntohl(tvb, offset + 8);

    magic16 = tvb_get_ntohs(tvb, offset);

    if (magic16 == DRBD_MAGIC_BIG)
        return DRBD_FRAME_HEADER_95_LEN + tvb_get_ntohl(tvb, offset + 4);

    return 0;
}

static int dissect_drbd_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
    dissect_drbd_message(tvb, pinfo, tree);
    return tvb_reported_length(tvb);
}

static int dissect_drbd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRBD");
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DRBD_FRAME_HEADER_80_LEN,
            get_drbd_pdu_len, dissect_drbd_pdu, data);
    return tvb_reported_length(tvb);
}

static gboolean test_drbd_protocol(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    guint reported_length = tvb_reported_length(tvb);
    if (reported_length < DRBD_FRAME_HEADER_80_LEN) {
        return FALSE;
    }

    gboolean match = FALSE;
    guint32 magic32 = tvb_get_ntohl(tvb, 0);

    if (magic32 == DRBD_MAGIC)
        match = TRUE;
    else if (reported_length >= DRBD_FRAME_HEADER_100_LEN && magic32 == DRBD_MAGIC_100)
        match = TRUE;
    else {
        guint16 magic16 = tvb_get_ntohs(tvb, 0);
        if (magic16 == DRBD_MAGIC_BIG)
            match = TRUE;
    }

    if (match) {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, drbd_handle);
        dissect_drbd(tvb, pinfo, tree, data);
    }

    return match;
}

/**
 * Returns buffer containing the payload.
 */
static tvbuff_t *decode_header(tvbuff_t *tvb, proto_tree *pt, guint16 *command)
{
    guint32 magic32;
    guint16 magic16;

    magic32 = tvb_get_ntohl(tvb, 0);

    if (magic32 == DRBD_MAGIC) {
        *command = tvb_get_ntohs(tvb, 4);

        proto_tree_add_item(pt, hf_drbd_command, tvb, 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pt, hf_drbd_length, tvb, 6, 2, ENC_BIG_ENDIAN);

        return tvb_new_subset_remaining(tvb, DRBD_FRAME_HEADER_80_LEN);
    }

    if (tvb_reported_length(tvb) >= DRBD_FRAME_HEADER_100_LEN && magic32 == DRBD_MAGIC_100) {
        *command = tvb_get_ntohs(tvb, 6);

        proto_tree_add_item(pt, hf_drbd_volume, tvb, 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pt, hf_drbd_command, tvb, 6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pt, hf_drbd_length, tvb, 8, 4, ENC_BIG_ENDIAN);

        return tvb_new_subset_remaining(tvb, DRBD_FRAME_HEADER_100_LEN);
    }

    magic16 = tvb_get_ntohs(tvb, 0);

    if (magic16 == DRBD_MAGIC_BIG) {
        *command = tvb_get_ntohs(tvb, 2);

        proto_tree_add_item(pt, hf_drbd_command, tvb, 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pt, hf_drbd_length, tvb, 4, 4, ENC_BIG_ENDIAN);

        return tvb_new_subset_remaining(tvb, DRBD_FRAME_HEADER_95_LEN);
    }

    return NULL;
}

static void dissect_drbd_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *drbd_tree;
    proto_item      *ti;
    guint16         command = -1;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRBD");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_drbd, tvb, 0, -1, ENC_NA);
    drbd_tree = proto_item_add_subtree(ti, ett_drbd);

    tvbuff_t *payload_tvb = decode_header(tvb, drbd_tree, &command);

    if (!payload_tvb)
        return;

    /*
     * Indicate what kind of message this is.
     */
    const gchar *packet_name = val_to_str(command, packet_names, "Unknown (0x%02x)");
    const gchar *info_text = col_get_text(pinfo->cinfo, COL_INFO);
    if (!info_text || !info_text[0]) {
        col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, pinfo->srcport, pinfo->destport);
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", packet_name);
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[%s]", packet_name);
    }
    col_set_fence(pinfo->cinfo, COL_INFO);

    if (tree == NULL)
        return;

    proto_item_set_text(ti, "DRBD [%s]", packet_name);

    const value_payload_decoder *payload_decoder = NULL;
    for (unsigned int i = 0; i < array_length(payload_decoders); i++) {
        if (payload_decoders[i].value == command) {
            payload_decoder = &payload_decoders[i];
            break;
        }
    }

    if (payload_decoder && payload_decoder->decoder_fn)
        (*payload_decoder->decoder_fn) (payload_tvb, drbd_tree);
}

static void decode_payload_connection_features(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_protocol_min, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_feature_flags, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_protocol_max, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_sender_node_id, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_receiver_node_id, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_auth_challenge(tvbuff_t *tvb _U_, proto_tree *tree _U_)
{
    proto_tree_add_bytes_format(tree, hf_drbd_auth_challenge_nonce, tvb, 0, CHALLENGE_LEN, NULL, "Nonce");
}

static void decode_payload_auth_response(tvbuff_t *tvb _U_, proto_tree *tree _U_)
{
    proto_tree_add_bytes_format(tree, hf_drbd_auth_response_hash, tvb, 0, -1, NULL, "Hash");
}

static void decode_data_common(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_seq_num, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 20, hf_drbd_dp_flags, ett_drbd_data_flags, data_flag_fields, ENC_BIG_ENDIAN);
}

static void decode_data_remaining(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint nbytes = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_bytes_format(tree, hf_drbd_data, tvb, offset,
            -1, NULL, "Data (%u byte%s)", nbytes, plurality(nbytes, "", "s"));
}

static void decode_payload_data(tvbuff_t *tvb, proto_tree *tree)
{
    decode_data_common(tvb, tree);
    decode_data_remaining(tvb, tree, 24);
}

static void decode_payload_data_reply(tvbuff_t *tvb, proto_tree *tree)
{
    decode_data_common(tvb, tree);
    decode_data_remaining(tvb, tree, 24);
}

static void decode_payload_rs_data_reply(tvbuff_t *tvb, proto_tree *tree)
{
    decode_data_common(tvb, tree);
    decode_data_remaining(tvb, tree, 24);
}

static void decode_payload_barrier(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_barrier, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_data_request(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_blksize, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_sync_param(tvbuff_t *tvb, proto_tree *tree)
{
    guint length = tvb_reported_length(tvb);
    guint offset = 0;

    proto_tree_add_item(tree, hf_drbd_resync_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_drbd_verify_alg, tvb, offset, DRBD_STRING_MAX, ENC_ASCII | ENC_NA);
    offset += DRBD_STRING_MAX;

    if (length >= offset + DRBD_STRING_MAX) {
        proto_tree_add_item(tree, hf_drbd_csums_alg, tvb, offset, DRBD_STRING_MAX, ENC_ASCII | ENC_NA);
        offset += DRBD_STRING_MAX;
    }

    if (length >= offset + 16) {
        proto_tree_add_item(tree, hf_drbd_c_plan_ahead, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_drbd_c_delay_target, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_drbd_c_fill_target, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_drbd_c_max_rate, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
    }
}

static void decode_payload_protocol(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_protocol, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_after_sb_0p, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_after_sb_1p, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_after_sb_2p, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_conn_flags, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_two_primaries, tvb, 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_integrity_alg, tvb, 24, -1, ENC_ASCII | ENC_NA);
}

static void decode_payload_uuids(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_current_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_bitmap_uuid, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_history_uuids, tvb, 16, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_history_uuids, tvb, 24, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dirty_bits, tvb, 32, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_uuid_flags, tvb, 40, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_sizes(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_d_size, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_u_size, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_c_size, tvb, 16, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_max_bio_size, tvb, 24, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_queue_order_type, tvb, 28, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dds_flags, tvb, 30, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_physical_block_size, tvb, 32, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_logical_block_size, tvb, 36, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_alignment_offset, tvb, 40, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_io_min, tvb, 44, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_io_opt, tvb, 48, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_discard_enabled, tvb, 52, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_discard_zeroes_data, tvb, 53, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_write_same_capable, tvb, 54, 1, ENC_BIG_ENDIAN);
}

static void decode_payload_state(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_state, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_req_state(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_mask, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_val, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_sync_uuid(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_skip(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_seq_num, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_offset, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_out_of_sync(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_blksize, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_twopc(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_tid, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_initiator_node_id, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_target_node_id, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_nodes_to_reach, tvb, 12, 8, ENC_BIG_ENDIAN);
    /* TODO: Decode further fields based on type */
}

static void decode_payload_dagtag(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 0, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_uuids110(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_current_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dirty_bits, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_uuid_flags, tvb, 16, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_node_mask, tvb, 24, 8, ENC_BIG_ENDIAN);

    guint64 bitmap_uuids_mask;
    proto_tree_add_item_ret_uint64(tree, hf_drbd_bitmap_uuids_mask, tvb, 32, 8, ENC_BIG_ENDIAN, &bitmap_uuids_mask);

    guint offset = 40;
    for (int i = 0; i < 64; i++) {
        if (is_bit_set_64(bitmap_uuids_mask, i)) {
            proto_tree_add_item(tree, hf_drbd_bitmap_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
        }
    }

    guint total_length = tvb_reported_length(tvb);
    while (offset < total_length) {
        proto_tree_add_item(tree, hf_drbd_history_uuids, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
}

static void decode_payload_peer_dagtag(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_node_id, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_current_uuid(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_weak_nodes, tvb, 8, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_data_size(tvbuff_t *tvb, proto_tree *tree)
{
    decode_data_common(tvb, tree);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 24, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_data_wsame(tvbuff_t *tvb, proto_tree *tree)
{
    decode_data_common(tvb, tree);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 24, 4, ENC_BIG_ENDIAN);
    decode_data_remaining(tvb, tree, 28);
}

static void decode_payload_rs_deallocated(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_blksize, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_block_ack(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_blksize, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_seq_num, tvb, 20, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_barrier_ack(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_barrier, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_set_size, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_confirm_stable(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_oldest_block_id, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_youngest_block_id, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_set_size, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_rq_s_reply(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_retcode, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_peer_ack(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_node_mask, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 8, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_peers_in_sync(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_node_mask, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_twopc_reply(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_tid, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_initiator_node_id, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_reachable_nodes, tvb, 8, 8, ENC_BIG_ENDIAN);
    /* TODO: Decode further fields based on type */
}

static void format_node_mask(gchar *s, guint64 value)
{
    if (!value) {
        g_strlcpy(s, "<none>", ITEM_LABEL_LENGTH);
        return;
    }

    int written = 0;
    int run_start = -1;
    for (int i = 0; i < 64 && written < ITEM_LABEL_LENGTH; i++) {
        gboolean is_set = is_bit_set_64(value, i);

        int run_end;
        if (!is_set) {
            run_end = i;
        } else if (i == 63) {
            if (run_start == -1)
                run_start = i;
            run_end = 64;
        } else {
            run_end = -1;
        }

        if (run_start != -1 && run_end != -1) {
            int run_length = run_end - run_start;
            const char *sep = written ? ", " : "";

            if (run_length == 1)
                written += g_snprintf(s + written, ITEM_LABEL_LENGTH - written, "%s%d", sep, run_start);
            else if (run_length == 2)
                written += g_snprintf(s + written, ITEM_LABEL_LENGTH - written, "%s%d, %d", sep, run_start, run_start + 1);
            else
                written += g_snprintf(s + written, ITEM_LABEL_LENGTH - written, "%s%d - %d", sep, run_start, run_end - 1);
        }

        if (!is_set)
            run_start = -1;
        else if (run_start == -1)
            run_start = i;
    }
}

void proto_register_drbd(void)
{
    static hf_register_info hf[] = {
        { &hf_drbd_command, { "Command", "drbd.command", FT_UINT16, BASE_HEX, VALS(packet_names), 0x0, NULL, HFILL }},
        { &hf_drbd_length, { "Payload length", "drbd.length", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_volume, { "Volume", "drbd.volume", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_auth_challenge_nonce, { "Nonce", "drbd.auth_nonce", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_auth_response_hash, { "Hash", "drbd.auth_hash", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_sector, { "Sector", "drbd.sector", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_block_id, { "Block ID", "drbd.block_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_seq_num, { "Sequence number", "drbd.seq_num", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dp_flags, { "Data flags", "drbd.dp_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_data, { "Data", "drbd.data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_size, { "size", "drbd.size", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_blksize, { "blksize", "drbd.blksize", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_protocol_min, { "protocol_min", "drbd.protocol_min", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_feature_flags, { "feature_flags", "drbd.feature_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_protocol_max, { "protocol_max", "drbd.protocol_max", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_sender_node_id, { "sender_node_id", "drbd.sender_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_receiver_node_id, { "receiver_node_id", "drbd.receiver_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_barrier, { "barrier", "drbd.barrier", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_set_size, { "set_size", "drbd.set_size", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_oldest_block_id, { "oldest_block_id", "drbd.oldest_block_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_youngest_block_id, { "youngest_block_id", "drbd.youngest_block_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_resync_rate, { "resync_rate", "drbd.resync_rate", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_verify_alg, { "verify_alg", "drbd.verify_alg", FT_STRINGZ, STR_ASCII, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_csums_alg, { "csums_alg", "drbd.csums_alg", FT_STRINGZ, STR_ASCII, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_plan_ahead, { "c_plan_ahead", "drbd.c_plan_ahead", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_delay_target, { "c_delay_target", "drbd.c_delay_target", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_fill_target, { "c_fill_target", "drbd.c_fill_target", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_max_rate, { "c_max_rate", "drbd.c_max_rate", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_protocol, { "protocol", "drbd.protocol", FT_UINT32, BASE_HEX, VALS(protocol_names), 0x0, NULL, HFILL }},
        { &hf_drbd_after_sb_0p, { "after_sb_0p", "drbd.after_sb_0p", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_after_sb_1p, { "after_sb_1p", "drbd.after_sb_1p", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_after_sb_2p, { "after_sb_2p", "drbd.after_sb_2p", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_conn_flags, { "conn_flags", "drbd.conn_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_two_primaries, { "two_primaries", "drbd.two_primaries", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_integrity_alg, { "integrity_alg", "drbd.integrity_alg", FT_STRINGZ, STR_ASCII, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_current_uuid, { "current_uuid", "drbd.current_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_bitmap_uuid, { "bitmap_uuid", "drbd.bitmap_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_history_uuids, { "history_uuids", "drbd.history_uuids", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dirty_bits, { "dirty_bits", "drbd.dirty_bits", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_uuid_flags, { "uuid_flags", "drbd.uuid_flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_node_mask, { "node_mask", "drbd.node_mask", FT_UINT64, BASE_CUSTOM, format_node_mask, 0x0, NULL, HFILL }},
        { &hf_drbd_bitmap_uuids_mask, { "bitmap_uuids_mask", "drbd.bitmap_uuids_mask", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_uuid, { "uuid", "drbd.uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_weak_nodes, { "weak_nodes", "drbd.weak_nodes", FT_UINT64, BASE_CUSTOM, format_node_mask, 0x0, NULL, HFILL }},
        { &hf_drbd_physical_block_size, { "physical_block_size", "drbd.physical_block_size", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_logical_block_size, { "logical_block_size", "drbd.logical_block_size", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_alignment_offset, { "alignment_offset", "drbd.alignment_offset", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_io_min, { "io_min", "drbd.io_min", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_io_opt, { "io_opt", "drbd.io_opt", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_discard_enabled, { "discard_enabled", "drbd.discard_enabled", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_discard_zeroes_data, { "discard_zeroes_data", "drbd.discard_zeroes_data", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_write_same_capable, { "write_same_capable", "drbd.write_same_capable", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_d_size, { "d_size", "drbd.d_size", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_u_size, { "u_size", "drbd.u_size", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_size, { "c_size", "drbd.c_size", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_max_bio_size, { "max_bio_size", "drbd.max_bio_size", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_queue_order_type, { "queue_order_type", "drbd.queue_order_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dds_flags, { "dds_flags", "drbd.dds_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_state, { "state", "drbd.state", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_mask, { "mask", "drbd.mask", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_val, { "val", "drbd.val", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_retcode, { "retcode", "drbd.retcode", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_tid, { "tid", "drbd.tid", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_initiator_node_id, { "initiator_node_id", "drbd.initiator_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_target_node_id, { "target_node_id", "drbd.target_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_nodes_to_reach, { "nodes_to_reach", "drbd.nodes_to_reach", FT_UINT64, BASE_CUSTOM, format_node_mask, 0x0, NULL, HFILL }},
        { &hf_drbd_reachable_nodes, { "reachable_nodes", "drbd.reachable_nodes", FT_UINT64, BASE_CUSTOM, format_node_mask, 0x0, NULL, HFILL }},
        { &hf_drbd_offset, { "offset", "drbd.offset", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dagtag, { "dagtag", "drbd.dagtag", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_node_id, { "node_id", "drbd.node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_drbd_dp_hardbarrier, { "hardbarrier", "drbd.dp_flag.hardbarrier", FT_BOOLEAN, 32, NULL, DP_HARDBARRIER, NULL, HFILL }},
        { &hf_drbd_dp_rw_sync, { "rw_sync", "drbd.dp_flag.rw_sync", FT_BOOLEAN, 32, NULL, DP_RW_SYNC, NULL, HFILL }},
        { &hf_drbd_dp_may_set_in_sync, { "may_set_in_sync", "drbd.dp_flag.may_set_in_sync", FT_BOOLEAN, 32, NULL, DP_MAY_SET_IN_SYNC, NULL, HFILL }},
        { &hf_drbd_dp_unplug, { "unplug", "drbd.dp_flag.unplug", FT_BOOLEAN, 32, NULL, DP_UNPLUG, NULL, HFILL }},
        { &hf_drbd_dp_fua, { "fua", "drbd.dp_flag.fua", FT_BOOLEAN, 32, NULL, DP_FUA, NULL, HFILL }},
        { &hf_drbd_dp_flush, { "flush", "drbd.dp_flag.flush", FT_BOOLEAN, 32, NULL, DP_FLUSH, NULL, HFILL }},
        { &hf_drbd_dp_discard, { "discard", "drbd.dp_flag.discard", FT_BOOLEAN, 32, NULL, DP_DISCARD, NULL, HFILL }},
        { &hf_drbd_dp_send_receive_ack, { "send_receive_ack", "drbd.dp_flag.send_receive_ack", FT_BOOLEAN, 32, NULL, DP_SEND_RECEIVE_ACK, NULL, HFILL }},
        { &hf_drbd_dp_send_write_ack, { "send_write_ack", "drbd.dp_flag.send_write_ack", FT_BOOLEAN, 32, NULL, DP_SEND_WRITE_ACK, NULL, HFILL }},
        { &hf_drbd_dp_wsame, { "wsame", "drbd.dp_flag.wsame", FT_BOOLEAN, 32, NULL, DP_WSAME, NULL, HFILL }},
        { &hf_drbd_dp_zeroes, { "zeroes", "drbd.dp_flag.zeroes", FT_BOOLEAN, 32, NULL, DP_ZEROES, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_drbd,
        &ett_drbd_data_flags,
    };

    proto_drbd = proto_register_protocol("DRBD Protocol", "DRBD", "drbd");
    proto_register_field_array(proto_drbd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_drbd(void)
{
    drbd_handle = create_dissector_handle(dissect_drbd, proto_drbd);
    heur_dissector_add("tcp", test_drbd_protocol, "DRBD over TCP", "drbd_tcp", proto_drbd, HEURISTIC_ENABLE);
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
