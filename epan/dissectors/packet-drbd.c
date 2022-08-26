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
 * The DRBD Linux kernel module sources can be found at https://github.com/LINBIT/drbd
 * More information about Linbit and DRBD can be found at https://www.linbit.com/
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/str_util.h>

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

    P_RS_CANCEL_AHEAD     = 0x4a,

    P_DISCONNECT          = 0x4b,

    P_RS_DAGTAG_REQ       = 0x4c,
    P_RS_CSUM_DAGTAG_REQ  = 0x4d,
    P_RS_THIN_DAGTAG_REQ  = 0x4e,
    P_OV_DAGTAG_REQ       = 0x4f,
    P_OV_DAGTAG_REPLY     = 0x50,

    P_INITIAL_META        = 0xfff1,
    P_INITIAL_DATA        = 0xfff2,

    P_CONNECTION_FEATURES = 0xfffe
};

typedef struct {
    guint32 tid;
    gint32 initiator_node_id;
} drbd_twopc_key;

typedef struct {
    guint32 prepare_frame;
    enum drbd_packet command;
} drbd_twopc_val;

static guint drbd_twopc_key_hash(gconstpointer k)
{
  const drbd_twopc_key *key = (const drbd_twopc_key *) k;

  return key->tid;
}

static gint drbd_twopc_key_equal(gconstpointer k1, gconstpointer k2)
{
  const drbd_twopc_key *key1 = (const drbd_twopc_key*) k1;
  const drbd_twopc_key *key2 = (const drbd_twopc_key*) k2;

  return key1->tid == key2->tid && key1->initiator_node_id == key2->initiator_node_id;
}

typedef struct {
    wmem_map_t *twopc;
} drbd_conv;

typedef struct value_payload_decoder {
    int value;
    void (*state_reader_fn)(tvbuff_t *, packet_info *, drbd_conv *);
    void (*tree_fn)(tvbuff_t *, proto_tree *, drbd_conv *);
} value_payload_decoder;

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

    { P_RS_CANCEL_AHEAD, "P_RS_CANCEL_AHEAD" },

    { P_DISCONNECT, "P_DISCONNECT" },

    { P_RS_DAGTAG_REQ, "P_RS_DAGTAG_REQ" },
    { P_RS_CSUM_DAGTAG_REQ, "P_RS_CSUM_DAGTAG_REQ" },
    { P_RS_THIN_DAGTAG_REQ, "P_RS_THIN_DAGTAG_REQ" },
    { P_OV_DAGTAG_REQ, "P_OV_DAGTAG_REQ" },
    { P_OV_DAGTAG_REPLY, "P_OV_DAGTAG_REPLY" },

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

#define DRBD_ROLE_UNKNOWN   0
#define DRBD_ROLE_PRIMARY   1
#define DRBD_ROLE_SECONDARY 2

static const value_string role_names[] = {
    { DRBD_ROLE_UNKNOWN, "UNKNOWN" },
    { DRBD_ROLE_PRIMARY, "PRIMARY" },
    { DRBD_ROLE_SECONDARY, "SECONDARY" },
    { 0, NULL }
};

#define DRBD_CONNECTION_STATE_C_STANDALONE 0
#define DRBD_CONNECTION_STATE_C_DISCONNECTING 1
#define DRBD_CONNECTION_STATE_C_UNCONNECTED 2
#define DRBD_CONNECTION_STATE_C_TIMEOUT 3
#define DRBD_CONNECTION_STATE_C_BROKEN_PIPE 4
#define DRBD_CONNECTION_STATE_C_NETWORK_FAILURE 5
#define DRBD_CONNECTION_STATE_C_PROTOCOL_ERROR 6
#define DRBD_CONNECTION_STATE_C_TEAR_DOWN 7
#define DRBD_CONNECTION_STATE_C_CONNECTING 8
#define DRBD_CONNECTION_STATE_C_CONNECTED 9
#define DRBD_CONNECTION_STATE_L_ESTABLISHED 10
#define DRBD_CONNECTION_STATE_L_STARTING_SYNC_S 11
#define DRBD_CONNECTION_STATE_L_STARTING_SYNC_T 12
#define DRBD_CONNECTION_STATE_L_WF_BITMAP_S 13
#define DRBD_CONNECTION_STATE_L_WF_BITMAP_T 14
#define DRBD_CONNECTION_STATE_L_WF_SYNC_UUID 15
#define DRBD_CONNECTION_STATE_L_SYNC_SOURCE 16
#define DRBD_CONNECTION_STATE_L_SYNC_TARGET 17
#define DRBD_CONNECTION_STATE_L_VERIFY_S 18
#define DRBD_CONNECTION_STATE_L_VERIFY_T 19
#define DRBD_CONNECTION_STATE_L_PAUSED_SYNC_S 20
#define DRBD_CONNECTION_STATE_L_PAUSED_SYNC_T 21
#define DRBD_CONNECTION_STATE_L_AHEAD 22
#define DRBD_CONNECTION_STATE_L_BEHIND 23

static const value_string connection_state_names[] = {
    { DRBD_CONNECTION_STATE_C_STANDALONE, "C_STANDALONE" },
    { DRBD_CONNECTION_STATE_C_DISCONNECTING, "C_DISCONNECTING" },
    { DRBD_CONNECTION_STATE_C_UNCONNECTED, "C_UNCONNECTED" },
    { DRBD_CONNECTION_STATE_C_TIMEOUT, "C_TIMEOUT" },
    { DRBD_CONNECTION_STATE_C_BROKEN_PIPE, "C_BROKEN_PIPE" },
    { DRBD_CONNECTION_STATE_C_NETWORK_FAILURE, "C_NETWORK_FAILURE" },
    { DRBD_CONNECTION_STATE_C_PROTOCOL_ERROR, "C_PROTOCOL_ERROR" },
    { DRBD_CONNECTION_STATE_C_TEAR_DOWN, "C_TEAR_DOWN" },
    { DRBD_CONNECTION_STATE_C_CONNECTING, "C_CONNECTING" },
    { DRBD_CONNECTION_STATE_C_CONNECTED, "C_CONNECTED" },
    { DRBD_CONNECTION_STATE_L_ESTABLISHED, "L_ESTABLISHED" },
    { DRBD_CONNECTION_STATE_L_STARTING_SYNC_S, "L_STARTING_SYNC_S" },
    { DRBD_CONNECTION_STATE_L_STARTING_SYNC_T, "L_STARTING_SYNC_T" },
    { DRBD_CONNECTION_STATE_L_WF_BITMAP_S, "L_WF_BITMAP_S" },
    { DRBD_CONNECTION_STATE_L_WF_BITMAP_T, "L_WF_BITMAP_T" },
    { DRBD_CONNECTION_STATE_L_WF_SYNC_UUID, "L_WF_SYNC_UUID" },
    { DRBD_CONNECTION_STATE_L_SYNC_SOURCE, "L_SYNC_SOURCE" },
    { DRBD_CONNECTION_STATE_L_SYNC_TARGET, "L_SYNC_TARGET" },
    { DRBD_CONNECTION_STATE_L_VERIFY_S, "L_VERIFY_S" },
    { DRBD_CONNECTION_STATE_L_VERIFY_T, "L_VERIFY_T" },
    { DRBD_CONNECTION_STATE_L_PAUSED_SYNC_S, "L_PAUSED_SYNC_S" },
    { DRBD_CONNECTION_STATE_L_PAUSED_SYNC_T, "L_PAUSED_SYNC_T" },
    { DRBD_CONNECTION_STATE_L_AHEAD, "L_AHEAD" },
    { DRBD_CONNECTION_STATE_L_BEHIND, "L_BEHIND" },
    { 0, NULL }
};

#define DRBD_DISK_STATE_DISKLESS 0
#define DRBD_DISK_STATE_ATTACHING 1
#define DRBD_DISK_STATE_DETACHING 2
#define DRBD_DISK_STATE_FAILED 3
#define DRBD_DISK_STATE_NEGOTIATING 4
#define DRBD_DISK_STATE_INCONSISTENT 5
#define DRBD_DISK_STATE_OUTDATED 6
#define DRBD_DISK_STATE_UNKNOWN 7
#define DRBD_DISK_STATE_CONSISTENT 8
#define DRBD_DISK_STATE_UP_TO_DATE 9

static const value_string disk_state_names[] = {
    { DRBD_DISK_STATE_DISKLESS, "D_DISKLESS" },
    { DRBD_DISK_STATE_ATTACHING, "D_ATTACHING" },
    { DRBD_DISK_STATE_DETACHING, "D_DETACHING" },
    { DRBD_DISK_STATE_FAILED, "D_FAILED" },
    { DRBD_DISK_STATE_NEGOTIATING, "D_NEGOTIATING" },
    { DRBD_DISK_STATE_INCONSISTENT, "D_INCONSISTENT" },
    { DRBD_DISK_STATE_OUTDATED, "D_OUTDATED" },
    { DRBD_DISK_STATE_UNKNOWN, "D_UNKNOWN" },
    { DRBD_DISK_STATE_CONSISTENT, "D_CONSISTENT" },
    { DRBD_DISK_STATE_UP_TO_DATE, "D_UP_TO_DATE" },
    { 0, NULL }
};

#define STATE_ROLE (0x3 << 0)    /* 3/4	 primary/secondary/unknown */
#define STATE_PEER (0x3 << 2)    /* 3/4	 primary/secondary/unknown */
#define STATE_CONN (0x1f << 4)    /* 17/32	 cstates */
#define STATE_DISK (0xf << 9)    /* 8/16	 from D_DISKLESS to D_UP_TO_DATE */
#define STATE_PDSK (0xf << 13)    /* 8/16	 from D_DISKLESS to D_UP_TO_DATE */
#define STATE_SUSP (0x1 << 17)    /* 2/2	 IO suspended no/yes (by user) */
#define STATE_AFTR_ISP (0x1 << 18)  /* isp .. imposed sync pause */
#define STATE_PEER_ISP (0x1 << 19)
#define STATE_USER_ISP (0x1 << 20)
#define STATE_SUSP_NOD (0x1 << 21)  /* IO suspended because no data */
#define STATE_SUSP_FEN (0x1 << 22)  /* IO suspended because fence peer handler runs*/
#define STATE_QUORUM (0x1 << 23)

#define UUID_FLAG_DISCARD_MY_DATA 1
#define UUID_FLAG_CRASHED_PRIMARY 2
#define UUID_FLAG_INCONSISTENT 4
#define UUID_FLAG_SKIP_INITIAL_SYNC 8
#define UUID_FLAG_NEW_DATAGEN 16
#define UUID_FLAG_STABLE 32
#define UUID_FLAG_GOT_STABLE 64
#define UUID_FLAG_RESYNC 128
#define UUID_FLAG_RECONNECT 256
#define UUID_FLAG_DISKLESS_PRIMARY 512
#define UUID_FLAG_PRIMARY_LOST_QUORUM 1024

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

#define DRBD_STREAM_DATA 0
#define DRBD_STREAM_CONTROL 1

static const value_string stream_names[] = {
    { DRBD_STREAM_DATA, "Data" },
    { DRBD_STREAM_CONTROL, "Control" },
    { 0, NULL }
};

static void dissect_drbd_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void read_state_twopc_prepare(tvbuff_t *tvb, packet_info *pinfo, drbd_conv *conv_data);
static void read_state_twopc_prep_rsz(tvbuff_t *tvb, packet_info *pinfo, drbd_conv *conv_data);

static void decode_payload_connection_features(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_auth_challenge(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_auth_response(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_data(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_barrier(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_dagtag_data_request(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_data_request(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_sync_param(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_protocol(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_uuids(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_sizes(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_state(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_req_state(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_sync_uuid(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_skip(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_out_of_sync(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_twopc_prepare(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_twopc_prep_rsz(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_twopc_commit(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_dagtag(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_uuids110(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_peer_dagtag(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_current_uuid(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_data_size(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_data_wsame(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_rs_deallocated(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);

static void decode_payload_block_ack(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_barrier_ack(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_confirm_stable(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_rq_s_reply(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_peer_ack(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_peers_in_sync(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);
static void decode_payload_twopc_reply(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data);

static const value_payload_decoder payload_decoders[] = {
    { P_CONNECTION_FEATURES, NULL, decode_payload_connection_features },
    { P_AUTH_CHALLENGE, NULL, decode_payload_auth_challenge },
    { P_AUTH_RESPONSE, NULL, decode_payload_auth_response },
    { P_DATA, NULL, decode_payload_data },
    { P_DATA_REPLY, NULL, decode_payload_data },
    { P_RS_DATA_REPLY, NULL, decode_payload_data },
    { P_BARRIER, NULL, decode_payload_barrier },
    { P_BITMAP, NULL, NULL }, /* TODO: decode additional data */
    { P_COMPRESSED_BITMAP, NULL, NULL }, /* TODO: decode additional data */
    { P_UNPLUG_REMOTE, NULL, NULL },
    { P_DATA_REQUEST, NULL, decode_payload_data_request },
    { P_RS_DATA_REQUEST, NULL, decode_payload_data_request },
    { P_SYNC_PARAM, NULL, decode_payload_sync_param },
    { P_SYNC_PARAM89, NULL, decode_payload_sync_param },
    { P_PROTOCOL, NULL, decode_payload_protocol },
    { P_UUIDS, NULL, decode_payload_uuids },
    { P_SIZES, NULL, decode_payload_sizes },
    { P_STATE, NULL, decode_payload_state },
    { P_STATE_CHG_REQ, NULL, decode_payload_req_state },
    { P_SYNC_UUID, NULL, decode_payload_sync_uuid },
    { P_OV_REQUEST, NULL, decode_payload_data_request },
    { P_OV_REPLY, NULL, decode_payload_data_request }, /* TODO: decode additional data */
    { P_CSUM_RS_REQUEST, NULL, decode_payload_data_request }, /* TODO: decode additional data */
    { P_RS_THIN_REQ, NULL, decode_payload_data_request },
    { P_DELAY_PROBE, NULL, decode_payload_skip },
    { P_OUT_OF_SYNC, NULL, decode_payload_out_of_sync },
    { P_CONN_ST_CHG_REQ, NULL, decode_payload_req_state },
    { P_PROTOCOL_UPDATE, NULL, decode_payload_protocol }, /* TODO: decode additional data */
    { P_TWOPC_PREPARE, read_state_twopc_prepare, decode_payload_twopc_prepare },
    { P_TWOPC_PREP_RSZ, read_state_twopc_prep_rsz, decode_payload_twopc_prep_rsz },
    { P_TWOPC_ABORT, NULL, decode_payload_twopc_commit },
    { P_DAGTAG, NULL, decode_payload_dagtag },
    { P_UUIDS110, NULL, decode_payload_uuids110 },
    { P_PEER_DAGTAG, NULL, decode_payload_peer_dagtag },
    { P_CURRENT_UUID, NULL, decode_payload_current_uuid },
    { P_TWOPC_COMMIT, NULL, decode_payload_twopc_commit },
    { P_TRIM, NULL, decode_payload_data_size },
    { P_ZEROES, NULL, decode_payload_data_size },
    { P_RS_DEALLOCATED, NULL, decode_payload_rs_deallocated },
    { P_WSAME, NULL, decode_payload_data_wsame },
    { P_DISCONNECT, NULL, NULL },
    { P_RS_DAGTAG_REQ, NULL, decode_payload_dagtag_data_request },
    { P_RS_CSUM_DAGTAG_REQ, NULL, decode_payload_dagtag_data_request },
    { P_RS_THIN_DAGTAG_REQ, NULL, decode_payload_dagtag_data_request },
    { P_OV_DAGTAG_REQ, NULL, decode_payload_dagtag_data_request },
    { P_OV_DAGTAG_REPLY, NULL, decode_payload_dagtag_data_request },

    { P_PING, NULL, NULL },
    { P_PING_ACK, NULL, NULL },
    { P_RECV_ACK, NULL, decode_payload_block_ack },
    { P_WRITE_ACK, NULL, decode_payload_block_ack },
    { P_RS_WRITE_ACK, NULL, decode_payload_block_ack },
    { P_SUPERSEDED, NULL, decode_payload_block_ack },
    { P_NEG_ACK, NULL, decode_payload_block_ack },
    { P_NEG_DREPLY, NULL, decode_payload_block_ack },
    { P_NEG_RS_DREPLY, NULL, decode_payload_block_ack },
    { P_OV_RESULT, NULL, decode_payload_block_ack },
    { P_BARRIER_ACK, NULL, decode_payload_barrier_ack },
    { P_CONFIRM_STABLE, NULL, decode_payload_confirm_stable },
    { P_STATE_CHG_REPLY, NULL, decode_payload_rq_s_reply },
    { P_RS_IS_IN_SYNC, NULL, decode_payload_block_ack },
    { P_DELAY_PROBE, NULL, decode_payload_skip },
    { P_RS_CANCEL, NULL, decode_payload_block_ack },
    { P_RS_CANCEL_AHEAD, NULL, decode_payload_block_ack },
    { P_CONN_ST_CHG_REPLY, NULL, decode_payload_rq_s_reply },
    { P_RETRY_WRITE, NULL, decode_payload_block_ack },
    { P_PEER_ACK, NULL, decode_payload_peer_ack },
    { P_PEERS_IN_SYNC, NULL, decode_payload_peers_in_sync },
    { P_TWOPC_YES, NULL, decode_payload_twopc_reply },
    { P_TWOPC_NO, NULL, decode_payload_twopc_reply },
    { P_TWOPC_RETRY, NULL, decode_payload_twopc_reply },
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
static int hf_drbd_history_uuid_list = -1;
static int hf_drbd_history_uuid = -1;
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
static int hf_drbd_retcode = -1;
static int hf_drbd_twopc_prepare_in = -1;
static int hf_drbd_tid = -1;
static int hf_drbd_initiator_node_id = -1;
static int hf_drbd_target_node_id = -1;
static int hf_drbd_nodes_to_reach = -1;
static int hf_drbd_primary_nodes = -1;
static int hf_drbd_user_size = -1;
static int hf_drbd_diskful_primary_nodes = -1;
static int hf_drbd_exposed_size = -1;
static int hf_drbd_reachable_nodes = -1;
static int hf_drbd_max_possible_size = -1;
static int hf_drbd_offset = -1;
static int hf_drbd_dagtag = -1;
static int hf_drbd_dagtag_node_id = -1;
static int hf_drbd_new_rx_descs_data = -1;
static int hf_drbd_new_rx_descs_control = -1;
static int hf_drbd_rx_desc_stolen_from = -1;

static int hf_drbd_state_role = -1;
static int hf_drbd_state_peer = -1;
static int hf_drbd_state_conn = -1;
static int hf_drbd_state_disk = -1;
static int hf_drbd_state_pdsk = -1;
static int hf_drbd_state_susp = -1;
static int hf_drbd_state_aftr_isp = -1;
static int hf_drbd_state_peer_isp = -1;
static int hf_drbd_state_user_isp = -1;
static int hf_drbd_state_susp_nod = -1;
static int hf_drbd_state_susp_fen = -1;
static int hf_drbd_state_quorum = -1;

static int hf_drbd_uuid_flag_discard_my_data = -1;
static int hf_drbd_uuid_flag_crashed_primary = -1;
static int hf_drbd_uuid_flag_inconsistent = -1;
static int hf_drbd_uuid_flag_skip_initial_sync = -1;
static int hf_drbd_uuid_flag_new_datagen = -1;
static int hf_drbd_uuid_flag_stable = -1;
static int hf_drbd_uuid_flag_got_stable = -1;
static int hf_drbd_uuid_flag_resync = -1;
static int hf_drbd_uuid_flag_reconnect = -1;
static int hf_drbd_uuid_flag_diskless_primary = -1;
static int hf_drbd_uuid_flag_primary_lost_quorum = -1;

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
static gint ett_drbd_state = -1;
static gint ett_drbd_uuid_flags = -1;
static gint ett_drbd_history_uuids = -1;
static gint ett_drbd_data_flags = -1;

static int * const state_fields[] = {
    &hf_drbd_state_role,
    &hf_drbd_state_peer,
    &hf_drbd_state_conn,
    &hf_drbd_state_disk,
    &hf_drbd_state_pdsk,
    &hf_drbd_state_susp,
    &hf_drbd_state_aftr_isp,
    &hf_drbd_state_peer_isp,
    &hf_drbd_state_user_isp,
    &hf_drbd_state_susp_nod,
    &hf_drbd_state_susp_fen,
    &hf_drbd_state_quorum,
    NULL
};

static int * const uuid_flag_fields[] = {
    &hf_drbd_uuid_flag_discard_my_data,
    &hf_drbd_uuid_flag_crashed_primary,
    &hf_drbd_uuid_flag_inconsistent,
    &hf_drbd_uuid_flag_skip_initial_sync,
    &hf_drbd_uuid_flag_new_datagen,
    &hf_drbd_uuid_flag_stable,
    &hf_drbd_uuid_flag_got_stable,
    &hf_drbd_uuid_flag_resync,
    &hf_drbd_uuid_flag_reconnect,
    &hf_drbd_uuid_flag_diskless_primary,
    &hf_drbd_uuid_flag_primary_lost_quorum,
    NULL
};

static int * const data_flag_fields[] = {
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
#define DRBD_TRANSPORT_RDMA_PACKET_LEN 16

#define DRBD_MAGIC 0x83740267
#define DRBD_MAGIC_BIG 0x835a
#define DRBD_MAGIC_100 0x8620ec20
#define DRBD_TRANSPORT_RDMA_MAGIC 0x5257494E

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

static int dissect_drbd_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
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

static gboolean test_drbd_header(tvbuff_t *tvb)
{
    guint reported_length = tvb_reported_length(tvb);
    if (reported_length < DRBD_FRAME_HEADER_80_LEN || tvb_captured_length(tvb) < 4) {
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

    return match;
}

static gboolean test_drbd_rdma_control_header(tvbuff_t *tvb)
{
    guint reported_length = tvb_reported_length(tvb);
    if (reported_length < DRBD_TRANSPORT_RDMA_PACKET_LEN || tvb_captured_length(tvb) < 4) {
        return FALSE;
    }

    guint32 magic32 = tvb_get_ntohl(tvb, 0);
    return magic32 == DRBD_TRANSPORT_RDMA_MAGIC;
}

static gboolean test_drbd_protocol(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    if (!test_drbd_header(tvb))
        return FALSE;

    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, drbd_handle);
    dissect_drbd(tvb, pinfo, tree, data);

    return TRUE;
}

/*
 * A DRBD connection consists of 2 TCP connections. We need information from
 * one to correctly interpret the other. However, it is impossible to determine
 * definitely just from a packet trace which TCP connections belong together.
 * Fortunately, there is an essentially universal convention that the
 * connections have a statically allocated port number in common. One
 * connection uses it on one node, the other connection uses the same port
 * number but on the other node. The other port numbers are dynamically
 * allocated and thus greater.
 *
 * For example, the connections use:
 * 1. Port 7000 on node A, port 44444 on node B
 * 2. Port 55555 on node A, port 7000 on node B
 *
 * Hence we can associate one conversation_t to the DRBD connection by keying
 * it on the lower port number and the two addresses in a consistent order.
 */
static conversation_t *find_drbd_conversation(packet_info *pinfo)
{
    address* addr_a;
    address* addr_b;
    guint32 port_a = MIN(pinfo->srcport, pinfo->destport);

    if (cmp_address(&pinfo->src, &pinfo->dst) < 0) {
        addr_a = &pinfo->src;
        addr_b = &pinfo->dst;
    } else {
        addr_a = &pinfo->dst;
        addr_b = &pinfo->src;
    }

    conversation_t *conv = find_conversation(pinfo->num, addr_a, addr_b, CONVERSATION_TCP, port_a, 0, NO_PORT_B);
    if (!conv)
    {
        /* CONVERSATION_TEMPLATE prevents the port information being added once
         * a wildcard search matches. */
        conv = conversation_new(pinfo->num, addr_a, addr_b, CONVERSATION_TCP, port_a, 0,
                NO_PORT2|CONVERSATION_TEMPLATE);
    }

    return conv;
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

static const value_payload_decoder *find_payload_decoder(guint16 command)
{
    for (unsigned int i = 0; i < array_length(payload_decoders); i++) {
        if (payload_decoders[i].value == command) {
            return &payload_decoders[i];
        }
    }

    return NULL;
}

static void dissect_drbd_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *drbd_tree;
    proto_item      *ti;
    guint16         command = -1;

    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_drbd, tvb, 0, -1, ENC_NA);
    drbd_tree = proto_item_add_subtree(ti, ett_drbd);

    tvbuff_t *payload_tvb = decode_header(tvb, drbd_tree, &command);

    if (!payload_tvb)
        return;

    /* Indicate what kind of message this is. */
    const gchar *packet_name = val_to_str(command, packet_names, "Unknown (0x%02x)");
    const gchar *info_text = col_get_text(pinfo->cinfo, COL_INFO);
    if (!info_text || !info_text[0]) {
        col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, pinfo->srcport, pinfo->destport);
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", packet_name);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", packet_name);
    }
    col_set_fence(pinfo->cinfo, COL_INFO);

    conversation_t *conv = find_drbd_conversation(pinfo);
    drbd_conv *conv_data = (drbd_conv *)conversation_get_proto_data(conv, proto_drbd);
    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), drbd_conv);
        conv_data->twopc = wmem_map_new(wmem_file_scope(), drbd_twopc_key_hash, drbd_twopc_key_equal);
        conversation_add_proto_data(conv, proto_drbd, conv_data);
    }

    const value_payload_decoder *payload_decoder = find_payload_decoder(command);

    if (!PINFO_FD_VISITED(pinfo) && payload_decoder && payload_decoder->state_reader_fn)
        (*payload_decoder->state_reader_fn) (payload_tvb, pinfo, conv_data);

    if (tree == NULL)
        return;

    proto_item_set_text(ti, "DRBD [%s]", packet_name);

    if (payload_decoder && payload_decoder->tree_fn)
        (*payload_decoder->tree_fn) (payload_tvb, drbd_tree, conv_data);
}

static void drbd_ib_append_col_info(packet_info *pinfo, const gchar *packet_name)
{
    const gchar *info_text;

    col_clear(pinfo->cinfo, COL_INFO);
    info_text = col_get_text(pinfo->cinfo, COL_INFO);
    if (!info_text || !info_text[0])
        col_append_fstr(pinfo->cinfo, COL_INFO, "QP=0x%06x [%s]", pinfo->destport, packet_name);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", packet_name);
    col_set_fence(pinfo->cinfo, COL_INFO);
}

static void dissect_drbd_ib_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *drbd_tree;
    proto_item      *ti;
    guint16         command = -1;

    ti = proto_tree_add_item(tree, proto_drbd, tvb, 0, -1, ENC_NA);
    drbd_tree = proto_item_add_subtree(ti, ett_drbd);

    tvbuff_t *payload_tvb = decode_header(tvb, drbd_tree, &command);

    if (!payload_tvb)
        return;

    /* Indicate what kind of message this is. */
    const gchar *packet_name = val_to_str(command, packet_names, "Unknown (0x%02x)");
    drbd_ib_append_col_info(pinfo, packet_name);

    if (tree == NULL)
        return;

    proto_item_set_text(ti, "DRBD [%s]", packet_name);

    const value_payload_decoder *payload_decoder = find_payload_decoder(command);

    if (payload_decoder && payload_decoder->tree_fn)
        (*payload_decoder->tree_fn) (payload_tvb, drbd_tree, NULL);
}

static void dissect_drbd_ib_control_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *drbd_tree;
    proto_item      *ti;

    drbd_ib_append_col_info(pinfo, "RDMA Flow Control");

    if (tree == NULL)
        return;

    ti = proto_tree_add_item(tree, proto_drbd, tvb, 0, -1, ENC_NA);
    proto_item_set_text(ti, "DRBD [RDMA Flow Control]");
    drbd_tree = proto_item_add_subtree(ti, ett_drbd);

    proto_tree_add_item(drbd_tree, hf_drbd_new_rx_descs_data, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(drbd_tree, hf_drbd_new_rx_descs_control, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(drbd_tree, hf_drbd_rx_desc_stolen_from, tvb, 12, 4, ENC_BIG_ENDIAN);
}

static gboolean dissect_drbd_ib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_drbd_header(tvb) && !test_drbd_rdma_control_header(tvb))
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRBD RDMA");
    while (1) {
        guint length;
        gboolean is_control_packet = test_drbd_rdma_control_header(tvb);

        if (is_control_packet)
            length = DRBD_TRANSPORT_RDMA_PACKET_LEN;
        else
            length = get_drbd_pdu_len(pinfo, tvb, 0, data);

        /* Was a header recognized? */
        if (length == 0)
            break;

        tvbuff_t *packet_tvb = tvb_new_subset_length(tvb, 0, length);

        if (is_control_packet)
            dissect_drbd_ib_control_message(packet_tvb, pinfo, tree);
        else
            dissect_drbd_ib_message(packet_tvb, pinfo, tree);

        /* Is there enough data for another DRBD packet? */
        if (tvb_reported_length(tvb) < length + DRBD_FRAME_HEADER_80_LEN)
            break;

        /* Move to the next DRBD packet. */
        tvb = tvb_new_subset_remaining(tvb, length);
    }

    return TRUE;
}

static void insert_twopc(tvbuff_t *tvb, packet_info *pinfo, drbd_conv *conv_data, enum drbd_packet command)
{
    drbd_twopc_key *key = wmem_new0(wmem_file_scope(), drbd_twopc_key);
    key->tid = tvb_get_ntohl(tvb, 0);
    key->initiator_node_id = tvb_get_ntohil(tvb, 4);

    drbd_twopc_val *val = wmem_new0(wmem_file_scope(), drbd_twopc_val);
    val->prepare_frame = pinfo->num;
    val->command = command;

    wmem_map_insert(conv_data->twopc, key, val);
}

static void read_state_twopc_prepare(tvbuff_t *tvb, packet_info *pinfo, drbd_conv *conv_data)
{
    insert_twopc(tvb, pinfo, conv_data, P_TWOPC_PREPARE);
}

static void read_state_twopc_prep_rsz(tvbuff_t *tvb, packet_info *pinfo, drbd_conv *conv_data)
{
    insert_twopc(tvb, pinfo, conv_data, P_TWOPC_PREP_RSZ);
}

static void decode_payload_connection_features(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_protocol_min, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_feature_flags, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_protocol_max, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_sender_node_id, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_receiver_node_id, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_auth_challenge(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_bytes_format(tree, hf_drbd_auth_challenge_nonce, tvb, 0, CHALLENGE_LEN, NULL, "Nonce");
}

static void decode_payload_auth_response(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_bytes_format(tree, hf_drbd_auth_response_hash, tvb, 0, -1, NULL, "Hash");
}

static void decode_data_common(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_seq_num, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 20, hf_drbd_dp_flags, ett_drbd_data_flags, data_flag_fields, ENC_BIG_ENDIAN);
}

static void decode_payload_data(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    decode_data_common(tvb, tree);

    guint nbytes = tvb_reported_length_remaining(tvb, 24);
    proto_tree_add_uint(tree, hf_drbd_size, tvb, 0, 0, nbytes);

    /* For infiniband the data is not in this tvb, so we do not show the data field. */
    if (tvb_captured_length(tvb) >= 24 + nbytes) {
        proto_tree_add_bytes_format(tree, hf_drbd_data, tvb, 24,
                nbytes, NULL, "Data (%u byte%s)", nbytes, plurality(nbytes, "", "s"));
    }
}

static void decode_payload_barrier(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_barrier, tvb, 0, 4, ENC_LITTLE_ENDIAN);
}

static void decode_payload_data_request(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_dagtag_data_request(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dagtag_node_id, tvb, 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 24, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_sync_param(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
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

static void decode_payload_protocol(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_protocol, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_after_sb_0p, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_after_sb_1p, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_after_sb_2p, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_conn_flags, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_two_primaries, tvb, 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_integrity_alg, tvb, 24, -1, ENC_ASCII | ENC_NA);
}

static void decode_payload_uuids(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_current_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_bitmap_uuid, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_history_uuid, tvb, 16, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_history_uuid, tvb, 24, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dirty_bits, tvb, 32, 8, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 40, hf_drbd_uuid_flags, ett_drbd_uuid_flags, uuid_flag_fields, ENC_BIG_ENDIAN);
}

static void decode_payload_sizes(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
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

static void decode_payload_state(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_bitmask(tree, tvb, 0, hf_drbd_state, ett_drbd_state, state_fields, ENC_BIG_ENDIAN);
}

/* Filter fields leaving only those with bitmask overlapping with the given mask. */
static void mask_fields(guint32 mask, int * const fields[], int * masked_fields[])
{
        int masked_i = 0;

        for (int fields_i = 0; fields[fields_i]; fields_i++) {
            header_field_info *hf = proto_registrar_get_nth(*fields[fields_i]);

            if (hf && mask & hf->bitmask) {
                masked_fields[masked_i] = fields[fields_i];
                masked_i++;
            }
        }

        masked_fields[masked_i] = NULL;
}

static void decode_state_change(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
        guint32 state_mask = tvb_get_ntohl(tvb, offset);
        int * masked_state_fields[array_length(state_fields)];
        mask_fields(state_mask, state_fields, masked_state_fields);

        if (masked_state_fields[0]) {
            proto_tree_add_bitmask(tree, tvb, offset + 4, hf_drbd_state, ett_drbd_state, masked_state_fields, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(tree, hf_drbd_state, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        }
}

static void decode_payload_req_state(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    decode_state_change(tvb, tree, 0);
}

static void decode_payload_sync_uuid(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_skip(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_seq_num, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_offset, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_out_of_sync(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_twopc_request_common(tvbuff_t *tvb, proto_tree *tree, drbd_twopc_key *key)
{
    proto_tree_add_item_ret_uint(tree, hf_drbd_tid, tvb, 0, 4, ENC_BIG_ENDIAN,
            key ? &key->tid : NULL);
    proto_tree_add_item_ret_int(tree, hf_drbd_initiator_node_id, tvb, 4, 4, ENC_BIG_ENDIAN,
            key ? &key->initiator_node_id : NULL);
    proto_tree_add_item(tree, hf_drbd_target_node_id, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_nodes_to_reach, tvb, 12, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_twopc_prepare(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    decode_twopc_request_common(tvb, tree, NULL);

    proto_tree_add_item(tree, hf_drbd_primary_nodes, tvb, 20, 8, ENC_BIG_ENDIAN);
    decode_state_change(tvb, tree, 28);
}

static void decode_payload_twopc_prep_rsz(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    decode_twopc_request_common(tvb, tree, NULL);

    proto_tree_add_item(tree, hf_drbd_user_size, tvb, 20, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dds_flags, tvb, 28, 2, ENC_BIG_ENDIAN);
}

static void decode_payload_twopc_commit(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data)
{
    drbd_twopc_key key;
    decode_twopc_request_common(tvb, tree, &key);

    if (!conv_data)
        return;

    drbd_twopc_val *val = wmem_map_lookup(conv_data->twopc, &key);
    if (!val)
        return;

    proto_item *it = proto_tree_add_uint(tree, hf_drbd_twopc_prepare_in,
            tvb, 0, 0, val->prepare_frame);
    proto_item_set_generated(it);

    if (val->command == P_TWOPC_PREPARE) {
        proto_tree_add_item(tree, hf_drbd_primary_nodes, tvb, 20, 8, ENC_BIG_ENDIAN);
        decode_state_change(tvb, tree, 28);
    } else if (val->command == P_TWOPC_PREP_RSZ) {
        proto_tree_add_item(tree, hf_drbd_diskful_primary_nodes, tvb, 20, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_drbd_exposed_size, tvb, 28, 8, ENC_BIG_ENDIAN);
    }
}

static void decode_payload_dagtag(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 0, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_uuids110(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_current_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dirty_bits, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 16, hf_drbd_uuid_flags, ett_drbd_uuid_flags, uuid_flag_fields, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_node_mask, tvb, 24, 8, ENC_BIG_ENDIAN);

    guint64 bitmap_uuids_mask;
    proto_tree_add_item_ret_uint64(tree, hf_drbd_bitmap_uuids_mask, tvb, 32, 8, ENC_BIG_ENDIAN, &bitmap_uuids_mask);

    guint offset = 40;
    for (int i = 0; i < 64; i++) {
        if (is_bit_set_64(bitmap_uuids_mask, i)) {
            guint64 bitmap_uuid = tvb_get_ntoh64(tvb, offset);
            proto_tree_add_uint64_format(tree, hf_drbd_bitmap_uuid, tvb, offset, 8, bitmap_uuid,
                    "Bitmap UUID for node %d: 0x%016" PRIx64, i, bitmap_uuid);
            offset += 8;
        }
    }

    proto_item *history_uuids = proto_tree_add_item(tree, hf_drbd_history_uuid_list, tvb, offset, -1, ENC_NA);
    proto_tree *history_tree = proto_item_add_subtree(history_uuids, ett_drbd_history_uuids);
    guint total_length = tvb_reported_length(tvb);
    while (offset < total_length) {
        proto_tree_add_item(history_tree, hf_drbd_history_uuid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
}

static void decode_payload_peer_dagtag(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dagtag_node_id, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_current_uuid(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_uuid, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_weak_nodes, tvb, 8, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_data_size(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    decode_data_common(tvb, tree);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 24, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_data_wsame(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    decode_data_common(tvb, tree);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 24, 4, ENC_BIG_ENDIAN);

    guint nbytes = tvb_reported_length_remaining(tvb, 28);
    /* For infiniband the data is not in this tvb, so we do not show the data field. */
    if (tvb_captured_length(tvb) >= 28 + nbytes) {
        proto_tree_add_bytes_format(tree, hf_drbd_data, tvb, 28,
                nbytes, NULL, "Data (%u byte%s)", nbytes, plurality(nbytes, "", "s"));
    }
}

static void decode_payload_rs_deallocated(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_block_ack(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_block_id, tvb, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_seq_num, tvb, 20, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_barrier_ack(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_barrier, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_set_size, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_confirm_stable(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_oldest_block_id, tvb, 0, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_youngest_block_id, tvb, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_set_size, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_rq_s_reply(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_retcode, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_peer_ack(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_node_mask, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_dagtag, tvb, 8, 8, ENC_BIG_ENDIAN);
}

static void decode_payload_peers_in_sync(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data _U_)
{
    proto_tree_add_item(tree, hf_drbd_sector, tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_node_mask, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_drbd_size, tvb, 16, 4, ENC_BIG_ENDIAN);
}

static void decode_payload_twopc_reply(tvbuff_t *tvb, proto_tree *tree, drbd_conv *conv_data)
{
    drbd_twopc_key key;

    proto_tree_add_item_ret_uint(tree, hf_drbd_tid, tvb, 0, 4, ENC_BIG_ENDIAN,
            &key.tid);
    proto_tree_add_item_ret_int(tree, hf_drbd_initiator_node_id, tvb, 4, 4, ENC_BIG_ENDIAN,
            &key.initiator_node_id);
    proto_tree_add_item(tree, hf_drbd_reachable_nodes, tvb, 8, 8, ENC_BIG_ENDIAN);

    if (!conv_data)
        return;

    drbd_twopc_val *val = wmem_map_lookup(conv_data->twopc, &key);
    if (!val)
        return;

    proto_item *it = proto_tree_add_uint(tree, hf_drbd_twopc_prepare_in,
            tvb, 0, 0, val->prepare_frame);
    proto_item_set_generated(it);

    if (val->command == P_TWOPC_PREPARE) {
        proto_tree_add_item(tree, hf_drbd_primary_nodes, tvb, 16, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_drbd_weak_nodes, tvb, 24, 8, ENC_BIG_ENDIAN);
    } else if (val->command == P_TWOPC_PREP_RSZ) {
        proto_tree_add_item(tree, hf_drbd_diskful_primary_nodes, tvb, 16, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_drbd_max_possible_size, tvb, 24, 8, ENC_BIG_ENDIAN);
    }
}

static void format_node_mask(gchar *s, guint64 value)
{
    if (!value) {
        (void) g_strlcpy(s, "<none>", ITEM_LABEL_LENGTH);
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
                written += snprintf(s + written, ITEM_LABEL_LENGTH - written, "%s%d", sep, run_start);
            else if (run_length == 2)
                written += snprintf(s + written, ITEM_LABEL_LENGTH - written, "%s%d, %d", sep, run_start, run_start + 1);
            else
                written += snprintf(s + written, ITEM_LABEL_LENGTH - written, "%s%d - %d", sep, run_start, run_end - 1);
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
        { &hf_drbd_sector, { "Sector", "drbd.sector", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_block_id, { "Block ID", "drbd.block_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_seq_num, { "Sequence number", "drbd.seq_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dp_flags, { "Data flags", "drbd.dp_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_data, { "Data", "drbd.data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_size, { "Size", "drbd.size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_protocol_min, { "protocol_min", "drbd.protocol_min", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_feature_flags, { "feature_flags", "drbd.feature_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_protocol_max, { "protocol_max", "drbd.protocol_max", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_sender_node_id, { "sender_node_id", "drbd.sender_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_receiver_node_id, { "receiver_node_id", "drbd.receiver_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_barrier, { "barrier", "drbd.barrier", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_set_size, { "set_size", "drbd.set_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_oldest_block_id, { "oldest_block_id", "drbd.oldest_block_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_youngest_block_id, { "youngest_block_id", "drbd.youngest_block_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_resync_rate, { "resync_rate", "drbd.resync_rate", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_kibps, 0x0, NULL, HFILL }},
        { &hf_drbd_verify_alg, { "verify_alg", "drbd.verify_alg", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_csums_alg, { "csums_alg", "drbd.csums_alg", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_plan_ahead, { "c_plan_ahead", "drbd.c_plan_ahead", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_delay_target, { "c_delay_target", "drbd.c_delay_target", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_fill_target, { "c_fill_target", "drbd.c_fill_target", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_max_rate, { "c_max_rate", "drbd.c_max_rate", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_kibps, 0x0, NULL, HFILL }},
        { &hf_drbd_protocol, { "protocol", "drbd.protocol", FT_UINT32, BASE_HEX, VALS(protocol_names), 0x0, NULL, HFILL }},
        { &hf_drbd_after_sb_0p, { "after_sb_0p", "drbd.after_sb_0p", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_after_sb_1p, { "after_sb_1p", "drbd.after_sb_1p", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_after_sb_2p, { "after_sb_2p", "drbd.after_sb_2p", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_conn_flags, { "conn_flags", "drbd.conn_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_two_primaries, { "two_primaries", "drbd.two_primaries", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_integrity_alg, { "integrity_alg", "drbd.integrity_alg", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_current_uuid, { "Current UUID", "drbd.current_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_bitmap_uuid, { "Bitmap UUID", "drbd.bitmap_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_history_uuid_list, { "History UUIDs", "drbd.history_uuids", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_history_uuid, { "History UUID", "drbd.history_uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dirty_bits, { "Dirty bits", "drbd.dirty_bits", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_uuid_flags, { "UUID flags", "drbd.uuid_flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_node_mask, { "Nodes", "drbd.node_mask", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_bitmap_uuids_mask, { "Bitmap UUID nodes", "drbd.bitmap_uuids_mask", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_uuid, { "uuid", "drbd.uuid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_weak_nodes, { "weak_nodes", "drbd.weak_nodes", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_physical_block_size, { "physical_block_size", "drbd.physical_block_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_logical_block_size, { "logical_block_size", "drbd.logical_block_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_alignment_offset, { "alignment_offset", "drbd.alignment_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_io_min, { "io_min", "drbd.io_min", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_io_opt, { "io_opt", "drbd.io_opt", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_discard_enabled, { "discard_enabled", "drbd.discard_enabled", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_discard_zeroes_data, { "discard_zeroes_data", "drbd.discard_zeroes_data", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_write_same_capable, { "write_same_capable", "drbd.write_same_capable", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_d_size, { "d_size", "drbd.d_size", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_u_size, { "u_size", "drbd.u_size", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_c_size, { "c_size", "drbd.c_size", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_max_bio_size, { "max_bio_size", "drbd.max_bio_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_queue_order_type, { "queue_order_type", "drbd.queue_order_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dds_flags, { "dds_flags", "drbd.dds_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_state, { "state", "drbd.state", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_retcode, { "retcode", "drbd.retcode", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_twopc_prepare_in, { "Two-phase commit prepare in", "drbd.twopc_prepare_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0, NULL, HFILL }},
        { &hf_drbd_tid, { "tid", "drbd.tid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_initiator_node_id, { "initiator_node_id", "drbd.initiator_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_target_node_id, { "target_node_id", "drbd.target_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_nodes_to_reach, { "nodes_to_reach", "drbd.nodes_to_reach", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_primary_nodes, { "primary_nodes", "drbd.primary_nodes", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_user_size, { "user_size", "drbd.user_size", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_diskful_primary_nodes, { "diskful_primary_nodes", "drbd.diskful_primary_nodes", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_exposed_size, { "exposed_size", "drbd.exposed_size", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_reachable_nodes, { "reachable_nodes", "drbd.reachable_nodes", FT_UINT64, BASE_CUSTOM, CF_FUNC(format_node_mask), 0x0, NULL, HFILL }},
        { &hf_drbd_max_possible_size, { "max_possible_size", "drbd.max_possible_size", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_offset, { "offset", "drbd.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dagtag, { "dagtag", "drbd.dagtag", FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_dagtag_node_id, { "dagtag_node_id", "drbd.dagtag_node_id", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_new_rx_descs_data, { "New descriptors received (data)", "drbd.new_rx_descs_data", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_new_rx_descs_control, { "New descriptors received (control)", "drbd.new_rx_descs_control", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_drbd_rx_desc_stolen_from, { "Descriptor stolen from", "drbd.rx_desc_stolen_from", FT_INT32, BASE_DEC, VALS(stream_names), 0x0, NULL, HFILL }},

        { &hf_drbd_state_role, { "role", "drbd.state.role", FT_UINT32, BASE_DEC, VALS(role_names), STATE_ROLE, NULL, HFILL }},
        { &hf_drbd_state_peer, { "peer", "drbd.state.peer", FT_UINT32, BASE_DEC, VALS(role_names), STATE_PEER, NULL, HFILL }},
        { &hf_drbd_state_conn, { "conn", "drbd.state.conn", FT_UINT32, BASE_DEC, VALS(connection_state_names), STATE_CONN, NULL, HFILL }},
        { &hf_drbd_state_disk, { "disk", "drbd.state.disk", FT_UINT32, BASE_DEC, VALS(disk_state_names), STATE_DISK, NULL, HFILL }},
        { &hf_drbd_state_pdsk, { "pdsk", "drbd.state.pdsk", FT_UINT32, BASE_DEC, VALS(disk_state_names), STATE_PDSK, NULL, HFILL }},
        { &hf_drbd_state_susp, { "susp", "drbd.state.susp", FT_BOOLEAN, 32, NULL, STATE_SUSP, NULL, HFILL }},
        { &hf_drbd_state_aftr_isp, { "aftr_isp", "drbd.state.aftr_isp", FT_BOOLEAN, 32, NULL, STATE_AFTR_ISP, NULL, HFILL }},
        { &hf_drbd_state_peer_isp, { "peer_isp", "drbd.state.peer_isp", FT_BOOLEAN, 32, NULL, STATE_PEER_ISP, NULL, HFILL }},
        { &hf_drbd_state_user_isp, { "user_isp", "drbd.state.user_isp", FT_BOOLEAN, 32, NULL, STATE_USER_ISP, NULL, HFILL }},
        { &hf_drbd_state_susp_nod, { "susp_nod", "drbd.state.susp_nod", FT_BOOLEAN, 32, NULL, STATE_SUSP_NOD, NULL, HFILL }},
        { &hf_drbd_state_susp_fen, { "susp_fen", "drbd.state.susp_fen", FT_BOOLEAN, 32, NULL, STATE_SUSP_FEN, NULL, HFILL }},
        { &hf_drbd_state_quorum, { "quorum", "drbd.state.quorum", FT_BOOLEAN, 32, NULL, STATE_QUORUM, NULL, HFILL }},

        { &hf_drbd_uuid_flag_discard_my_data, { "discard_my_data", "drbd.uuid_flag.discard_my_data", FT_BOOLEAN, 64, NULL, UUID_FLAG_DISCARD_MY_DATA, NULL, HFILL }},
        { &hf_drbd_uuid_flag_crashed_primary, { "crashed_primary", "drbd.uuid_flag.crashed_primary", FT_BOOLEAN, 64, NULL, UUID_FLAG_CRASHED_PRIMARY, NULL, HFILL }},
        { &hf_drbd_uuid_flag_inconsistent, { "inconsistent", "drbd.uuid_flag.inconsistent", FT_BOOLEAN, 64, NULL, UUID_FLAG_INCONSISTENT, NULL, HFILL }},
        { &hf_drbd_uuid_flag_skip_initial_sync, { "skip_initial_sync", "drbd.uuid_flag.skip_initial_sync", FT_BOOLEAN, 64, NULL, UUID_FLAG_SKIP_INITIAL_SYNC, NULL, HFILL }},
        { &hf_drbd_uuid_flag_new_datagen, { "new_datagen", "drbd.uuid_flag.new_datagen", FT_BOOLEAN, 64, NULL, UUID_FLAG_NEW_DATAGEN, NULL, HFILL }},
        { &hf_drbd_uuid_flag_stable, { "stable", "drbd.uuid_flag.stable", FT_BOOLEAN, 64, NULL, UUID_FLAG_STABLE, NULL, HFILL }},
        { &hf_drbd_uuid_flag_got_stable, { "got_stable", "drbd.uuid_flag.got_stable", FT_BOOLEAN, 64, NULL, UUID_FLAG_GOT_STABLE, NULL, HFILL }},
        { &hf_drbd_uuid_flag_resync, { "resync", "drbd.uuid_flag.resync", FT_BOOLEAN, 64, NULL, UUID_FLAG_RESYNC, NULL, HFILL }},
        { &hf_drbd_uuid_flag_reconnect, { "reconnect", "drbd.uuid_flag.reconnect", FT_BOOLEAN, 64, NULL, UUID_FLAG_RECONNECT, NULL, HFILL }},
        { &hf_drbd_uuid_flag_diskless_primary, { "diskless_primary", "drbd.uuid_flag.diskless_primary", FT_BOOLEAN, 64, NULL, UUID_FLAG_DISKLESS_PRIMARY, NULL, HFILL }},
        { &hf_drbd_uuid_flag_primary_lost_quorum, { "primary_lost_quorum", "drbd.uuid_flag.primary_lost_quorum", FT_BOOLEAN, 64, NULL, UUID_FLAG_PRIMARY_LOST_QUORUM, NULL, HFILL }},

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
        &ett_drbd_state,
        &ett_drbd_uuid_flags,
        &ett_drbd_history_uuids,
        &ett_drbd_data_flags,
    };

    proto_drbd = proto_register_protocol("DRBD Protocol", "DRBD", "drbd");
    proto_register_field_array(proto_drbd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_drbd(void)
{
    drbd_handle = create_dissector_handle(dissect_drbd, proto_drbd);
    heur_dissector_add("tcp", test_drbd_protocol, "DRBD over TCP", "drbd_tcp", proto_drbd, HEURISTIC_DISABLE);
    heur_dissector_add("infiniband.payload", dissect_drbd_ib, "DRBD over RDMA", "drbd_rdma", proto_drbd, HEURISTIC_DISABLE);
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
