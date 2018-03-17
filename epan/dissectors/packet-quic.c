/* packet-quic.c
 * Routines for QUIC (IETF) dissection
 * Copyright 2017, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 * Copyright 2018 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See https://quicwg.github.io/
 * https://tools.ietf.org/html/draft-ietf-quic-transport-11
 * https://tools.ietf.org/html/draft-ietf-quic-tls-11
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include "packet-ssl-utils.h"
#include "packet-ssl.h"
#include <epan/prefs.h>
#include <wsutil/pint.h>

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
/* Whether to provide support for authentication in addition to decryption. */
#define HAVE_LIBGCRYPT_AEAD
#endif

/* Prototypes */
void proto_reg_handoff_quic(void);
void proto_register_quic(void);

/* Initialize the protocol and registered fields */
static int proto_quic = -1;
static int hf_quic_connection_number = -1;
static int hf_quic_header_form = -1;
static int hf_quic_long_packet_type = -1;
static int hf_quic_dcid = -1;
static int hf_quic_scid = -1;
static int hf_quic_dcil = -1;
static int hf_quic_scil = -1;
static int hf_quic_payload_length = -1;
static int hf_quic_packet_number = -1;
static int hf_quic_packet_number_full = -1;
static int hf_quic_version = -1;
static int hf_quic_supported_version = -1;
static int hf_quic_vn_unused = -1;
static int hf_quic_short_ocid_flag = -1;
static int hf_quic_short_kp_flag_draft10 = -1;
static int hf_quic_short_kp_flag = -1;
static int hf_quic_short_packet_type_draft10 = -1;
static int hf_quic_short_packet_type = -1;
static int hf_quic_initial_payload = -1;
static int hf_quic_handshake_payload = -1;
static int hf_quic_retry_payload = -1;
static int hf_quic_protected_payload = -1;

static int hf_quic_frame = -1;
static int hf_quic_frame_type = -1;
static int hf_quic_frame_type_stream_fin = -1;
static int hf_quic_frame_type_stream_len = -1;
static int hf_quic_frame_type_stream_off = -1;
static int hf_quic_stream_stream_id = -1;
static int hf_quic_stream_offset = -1;
static int hf_quic_stream_length = -1;
static int hf_quic_stream_data = -1;

static int hf_quic_frame_type_ack_largest_acknowledged = -1;
static int hf_quic_frame_type_ack_ack_delay = -1;
static int hf_quic_frame_type_ack_ack_block_count = -1;
static int hf_quic_frame_type_ack_fab = -1;
static int hf_quic_frame_type_ack_gap = -1;
static int hf_quic_frame_type_ack_ack_block = -1;

static int hf_quic_frame_type_path_challenge_data = -1;
static int hf_quic_frame_type_path_response_data = -1;

static int hf_quic_frame_type_padding_length = -1;
static int hf_quic_frame_type_padding = -1;
static int hf_quic_frame_type_rsts_stream_id = -1;
static int hf_quic_frame_type_rsts_application_error_code = -1;
static int hf_quic_frame_type_rsts_final_offset = -1;
static int hf_quic_frame_type_cc_error_code = -1;
static int hf_quic_frame_type_cc_reason_phrase_length = -1;
static int hf_quic_frame_type_cc_reason_phrase = -1;
static int hf_quic_frame_type_ac_error_code = -1;
static int hf_quic_frame_type_ac_reason_phrase_length = -1;
static int hf_quic_frame_type_ac_reason_phrase = -1;
static int hf_quic_frame_type_md_maximum_data = -1;
static int hf_quic_frame_type_msd_stream_id = -1;
static int hf_quic_frame_type_msd_maximum_stream_data = -1;
static int hf_quic_frame_type_msi_stream_id = -1;
static int hf_quic_frame_type_blocked_offset = -1;
static int hf_quic_frame_type_sb_stream_id = -1;
static int hf_quic_frame_type_sb_offset = -1;
static int hf_quic_frame_type_sib_stream_id = -1;
static int hf_quic_frame_type_nci_sequence = -1;
static int hf_quic_frame_type_nci_connection_id_length = -1;
static int hf_quic_frame_type_nci_connection_id = -1;
static int hf_quic_frame_type_nci_stateless_reset_token = -1;
static int hf_quic_frame_type_ss_stream_id = -1;
static int hf_quic_frame_type_ss_application_error_code = -1;

static expert_field ei_quic_connection_unknown = EI_INIT;
static expert_field ei_quic_ft_unknown = EI_INIT;
static expert_field ei_quic_decryption_failed = EI_INIT;
static expert_field ei_quic_protocol_violation = EI_INIT;

static gint ett_quic = -1;
static gint ett_quic_connection_info = -1;
static gint ett_quic_ft = -1;
static gint ett_quic_ftflags = -1;

static dissector_handle_t quic_handle;
static dissector_handle_t ssl_handle;

/*
 * PROTECTED PAYLOAD DECRYPTION (done in first pass)
 *
 * Long packet types always use a single cipher (client_handshake_cipher or
 * server_handshake_cipher).
 * Short packet types always use 1-RTT secrets for packet protection (pp).
 * TODO 0-RTT decryption requires another (client) cipher.
 *
 * Considerations:
 * - QUIC packets might appear out-of-order (short packets before handshake
 *   message is captured), lost or retransmitted/duplicated.
 * - During live capture, keys might not be immediately be available. 1-RTT
 *   client keys will be ready while client proceses Server Hello (Handshake).
 *   1-RTT server keys will be ready while server creates Handshake message in
 *   response to Inititial Handshake.
 * - So delay cipher creation until first short packet is received.
 *
 * Required input from TLS dissector: TLS-Exporter 0-RTT/1-RTT secrets and
 * cipher/hash algorithms.
 *
 * to-do list:
 * DONE key update via KEY_PHASE bit (untested)
 * TODO 0-RTT decryption
 * TODO packet number gap
 */

typedef struct quic_decrypt_result {
    const guchar   *error;      /**< Error message or NULL for success. */
    const guint8   *data;       /**< Decrypted result on success (file-scoped). */
    guint           data_len;   /**< Size of decrypted data. */
} quic_decrypt_result_t;

typedef struct quic_cid {
    guint8      len;
    guint8      cid[18];
} quic_cid_t;

/**
 * Packet protection state for an endpoint.
 */
typedef struct quic_pp_state {
    guint8         *secret;         /**< client_pp_secret_N / server_pp_secret_N */
    tls13_cipher    cipher[2];      /**< Cipher for KEY_PHASE 0/1 */
    guint64         changed_in_pkn; /**< Packet number where key change occurred. */
    gboolean        key_phase : 1;  /**< Current key phase. */
} quic_pp_state_t;

/** Singly-linked list of Connection IDs. */
typedef struct quic_cid_item quic_cid_item_t;
struct quic_cid_item {
    struct quic_cid_item   *next;
    quic_cid_t              data;
};

/**
 * State for a single QUIC connection, identified by one or more Destination
 * Connection IDs (DCID).
 */
typedef struct quic_info_data {
    guint32         number;         /** Similar to "udp.stream", but for identifying QUIC connections across migrations. */
    guint32         version;
    address         server_address;
    guint16         server_port;
    gboolean        skip_decryption : 1; /**< Set to 1 if no keys are available. */
    guint8          cipher_keylen;  /**< Cipher key length. */
    int             hash_algo;      /**< Libgcrypt hash algorithm for key derivation. */
    tls13_cipher    client_handshake_cipher;
    tls13_cipher    server_handshake_cipher;
    quic_pp_state_t client_pp;
    quic_pp_state_t server_pp;
    guint64         max_client_pkn;
    guint64         max_server_pkn;
    quic_cid_item_t client_cids;    /**< SCID of client from first Initial Packet. */
    quic_cid_item_t server_cids;    /**< SCID of server from first Retry/Handshake. */
    quic_cid_t      client_dcid_initial;    /**< DCID from Initial Packet. */
} quic_info_data_t;

/** Per-packet information about QUIC, populated on the first pass. */
typedef struct quic_packet_info {
    quic_info_data_t       *conn;
    guint64                 packet_number;  /**< Reconstructed full packet number. */
    quic_decrypt_result_t   decryption;
    gboolean                from_server : 1;
} quic_packet_info_t;

/**
 * Maps CID (quic_cid_t *) to a QUIC Connection (quic_info_data_t *).
 * This assumes that the CIDs are not shared between two different connections
 * (potentially with different versions) as that would break dissection.
 *
 * These mappings are authorative. For example, Initial.SCID is stored in
 * quic_client_connections while Retry.SCID is stored in
 * quic_server_connections. Retry.DCID should normally correspond to an entry in
 * quic_client_connections.
 */
static wmem_map_t *quic_client_connections, *quic_server_connections;
static wmem_map_t *quic_initial_connections;    /* Initial.DCID -> connection */
static wmem_list_t *quic_connections;   /* All unique connections. */
static guint quic_connections_count;

/* Returns the QUIC draft version or 0 if not applicable. */
static inline guint8 quic_draft_version(guint32 version) {
    if ((version >> 8) == 0xff0000) {
       return (guint8) version;
    }
    return 0;
}
static inline gboolean is_quic_draft_max(guint32 version, guint8 max_version) {
    guint8 draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

const value_string quic_version_vals[] = {
    { 0x00000000, "Version Negotiation" },
    { 0xff000004, "draft-04" },
    { 0xff000005, "draft-05" },
    { 0xff000006, "draft-06" },
    { 0xff000007, "draft-07" },
    { 0xff000008, "draft-08" },
    { 0xff000009, "draft-09" },
    { 0xff00000a, "draft-10" },
    { 0xff00000b, "draft-11" },
    { 0, NULL }
};

static const value_string quic_short_long_header_vals[] = {
    { 0, "Short Header" },
    { 1, "Long Header" },
    { 0, NULL }
};

#define SH_OCID     0x40    /* until draft -10 */
#define SH_KP_10    0x20    /* until draft -10 */
#define SH_PT_10    0x07    /* until draft -10 */
#define SH_KP       0x40    /* since draft -11 */
#define SH_PT       0x03    /* since draft -11 */

static const value_string quic_short_packet_type_vals[] = {
    { 0x00, "1 octet" },
    { 0x01, "2 octet" },
    { 0x02, "4 octet" },
    { 0, NULL }
};

static const value_string quic_cid_len_vals[] = {
    { 0,    "0 octets" },
    { 1,    "4 octets" },
    { 2,    "5 octets" },
    { 3,    "6 octets" },
    { 4,    "7 octets" },
    { 5,    "8 octets" },
    { 6,    "9 octets" },
    { 7,    "10 octets" },
    { 8,    "11 octets" },
    { 9,    "12 octets" },
    { 10,   "13 octets" },
    { 11,   "14 octets" },
    { 12,   "15 octets" },
    { 13,   "16 octets" },
    { 14,   "17 octets" },
    { 15,   "18 octets" },
    { 0, NULL }
};

#define QUIC_LPT_INITIAL    0x7F
#define QUIC_LPT_RETRY      0x7E
#define QUIC_LPT_HANDSHAKE  0x7D
#define QUIC_LPT_0RTT       0x7C
#define QUIC_SHORT_PACKET   0xff    /* dummy value that is definitely not LPT */

static const value_string quic_long_packet_type_vals[] = {
    { QUIC_LPT_INITIAL, "Initial" },
    { QUIC_LPT_RETRY, "Retry" },
    { QUIC_LPT_HANDSHAKE, "Handshake" },
    { QUIC_LPT_0RTT, "0-RTT Protected" },
    { 0, NULL }
};

#define FT_PADDING          0x00
#define FT_RST_STREAM       0x01
#define FT_CONNECTION_CLOSE 0x02
#define FT_APPLICATION_CLOSE 0x03 /* Add in draft07 */
#define FT_MAX_DATA         0x04
#define FT_MAX_STREAM_DATA  0x05
#define FT_MAX_STREAM_ID    0x06
#define FT_PING             0x07
#define FT_BLOCKED          0x08
#define FT_STREAM_BLOCKED   0x09
#define FT_STREAM_ID_BLOCKED 0x0a
#define FT_NEW_CONNECTION_ID 0x0b
#define FT_STOP_SENDING     0x0c
#define FT_ACK              0x0d
#define FT_PATH_CHALLENGE   0x0e
#define FT_PATH_RESPONSE    0x0f
#define FT_STREAM_10        0x10
#define FT_STREAM_11        0x11
#define FT_STREAM_12        0x12
#define FT_STREAM_13        0x13
#define FT_STREAM_14        0x14
#define FT_STREAM_15        0x15
#define FT_STREAM_16        0x16
#define FT_STREAM_17        0x17

static const range_string quic_frame_type_vals[] = {
    { 0x00, 0x00,   "PADDING" },
    { 0x01, 0x01,   "RST_STREAM" },
    { 0x02, 0x02,   "CONNECTION_CLOSE" },
    { 0x03, 0x03,   "APPLICATION_CLOSE" },
    { 0x04, 0x04,   "MAX_DATA" },
    { 0x05, 0x05,   "MAX_STREAM_DATA" },
    { 0x06, 0x06,   "MAX_STREAM_ID" },
    { 0x07, 0x07,   "PING" },
    { 0x08, 0x08,   "BLOCKED" },
    { 0x09, 0x09,   "STREAM_BLOCKED" },
    { 0x0a, 0x0a,   "STREAM_ID_BLOCKED" },
    { 0x0b, 0x0b,   "NEW_CONNECTION_ID" },
    { 0x0c, 0x0c,   "STOP_SENDING" },
    { 0x0d, 0x0d,   "ACK" },
    { 0x0e, 0x0e,   "PATH_CHALLENGE" },
    { 0x0f, 0x0f,   "PATH_RESPONSE" },
    { 0x10, 0x17,   "STREAM" },
    { 0,    0,        NULL },
};


/* >= draft-08 */
#define FTFLAGS_STREAM_FIN 0x01
#define FTFLAGS_STREAM_LEN 0x02
#define FTFLAGS_STREAM_OFF 0x04

/* > draft 07 */
#define QUIC_NO_ERROR                   0x0000
#define QUIC_INTERNAL_ERROR             0x0001
#define QUIC_SERVER_BUSY                0x0002
#define QUIC_FLOW_CONTROL_ERROR         0x0003
#define QUIC_STREAM_ID_ERROR            0x0004
#define QUIC_STREAM_STATE_ERROR         0x0005
#define QUIC_FINAL_OFFSET_ERROR         0x0006
#define QUIC_FRAME_FORMAT_ERROR         0x0007
#define QUIC_TRANSPORT_PARAMETER_ERROR  0x0008
#define QUIC_VERSION_NEGOTIATION_ERROR  0x0009
#define QUIC_PROTOCOL_VIOLATION         0x000A
#define QUIC_UNSOLICITED_PATH_RESPONSE  0x000B
#define TLS_HANDSHAKE_FAILED            0x0201
#define TLS_FATAL_ALERT_GENERATED       0x0202
#define TLS_FATAL_ALERT_RECEIVED        0x0203

static const value_string quic_error_code_vals[] = {
    { QUIC_NO_ERROR, "NO_ERROR (An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed abruptly in the absence of any error.)" },
    { QUIC_INTERNAL_ERROR, "INTERNAL_ERROR (The endpoint encountered an internal error and cannot continue with the connection)" },
    { QUIC_SERVER_BUSY, "SERVER_BUSY (The server is currently busy and does not accept any new connections." },
    { QUIC_FLOW_CONTROL_ERROR, "FLOW_CONTROL_ERROR (An endpoint received more data than An endpoint received more data tha)" },
    { QUIC_STREAM_ID_ERROR, "STREAM_ID_ERROR (An endpoint received a frame for a stream identifier that exceeded its advertised maximum stream ID)" },
    { QUIC_STREAM_STATE_ERROR, "STREAM_STATE_ERROR (An endpoint received a frame for a stream that was not in a state that permitted that frame)" },
    { QUIC_FINAL_OFFSET_ERROR, "FINAL_OFFSET_ERROR (An endpoint received a STREAM frame containing data that exceeded the previously established final offset)" },
    { QUIC_FRAME_FORMAT_ERROR, "FRAME_FORMAT_ERROR (An endpoint received a frame that was badly formatted)" },
    { QUIC_TRANSPORT_PARAMETER_ERROR, "TRANSPORT_PARAMETER_ERROR (An endpoint received transport parameters that were badly formatted)" },
    { QUIC_VERSION_NEGOTIATION_ERROR, "VERSION_NEGOTIATION_ERROR (An endpoint received transport parameters that contained version negotiation parameters that disagreed with the version negotiation that it performed)" },
    { QUIC_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION (An endpoint detected an error with protocol compliance that was not covered by more specific error codes)" },
    { QUIC_UNSOLICITED_PATH_RESPONSE, "An endpoint received a PATH_RESPONSE frame that did not correspond to any PATH_CHALLENGE frame that it previously sent" },
    /* TLS */
    { TLS_HANDSHAKE_FAILED, "TLS_HANDSHAKE_FAILED (The TLS handshake failed)" },
    { TLS_FATAL_ALERT_GENERATED, "TLS_FATAL_ALERT_GENERATED (A TLS fatal alert was sent causing the TLS connection to end prematurely)" },
    { TLS_FATAL_ALERT_RECEIVED, "TLS_FATAL_ALERT_RECEIVED (A TLS fatal alert was sent received the TLS connection to end prematurely)" },
    { 0, NULL }
};
static value_string_ext quic_error_code_vals_ext = VALUE_STRING_EXT_INIT(quic_error_code_vals);

static guint32 get_len_packet_number(guint8 short_packet_type){

    switch (short_packet_type & SH_PT){
        case 0x0:
            return 1;
        case 0x1:
            return 2;
        case 0x2:
            return 4;
        default:
            break;
    }
    return 1;
}

/* Inspired from ngtcp2 */
static guint64 quic_pkt_adjust_pkt_num(guint64 max_pkt_num, guint64 pkt_num,
                                   size_t n) {
  guint64 k = max_pkt_num == G_MAXUINT64 ? max_pkt_num : max_pkt_num + 1;
  guint64 u = k & ~((G_GUINT64_CONSTANT(1) << n) - 1);
  guint64 a = u | pkt_num;
  guint64 b = (u + (G_GUINT64_CONSTANT(1) << n)) | pkt_num;
  guint64 a1 = k < a ? a - k : k - a;
  guint64 b1 = k < b ? b - k : k - b;

  if (a1 < b1) {
    return a;
  }
  return b;
}

/**
 * Calculate the full packet number and store it for later use.
 */
static guint64
dissect_quic_packet_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
                           quic_info_data_t *quic_info, quic_packet_info_t *quic_packet,
                           guint pkn_len)
{
    proto_item *ti;
    guint64     pkn;

    proto_tree_add_item_ret_uint64(tree, hf_quic_packet_number, tvb, offset, pkn_len, ENC_BIG_ENDIAN, &pkn);

    if (!quic_info) {
        // if not part of a connection, the full PKN cannot be reconstructed.
        return pkn;
    }

    /* Sequential first pass, try to reconstruct full packet number. */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (quic_packet->from_server) {
            pkn = quic_pkt_adjust_pkt_num(quic_info->max_server_pkn, pkn, 8 * pkn_len);
            quic_info->max_server_pkn = pkn;
        } else {
            pkn = quic_pkt_adjust_pkt_num(quic_info->max_client_pkn, pkn, 8 * pkn_len);
            quic_info->max_client_pkn = pkn;
        }
        quic_packet->packet_number = pkn;
    } else {
        pkn = quic_packet->packet_number;
    }

    /* always add the full packet number for use in columns */
    ti = proto_tree_add_uint64(tree, hf_quic_packet_number_full, tvb, offset, pkn_len, pkn);
    PROTO_ITEM_SET_GENERATED(ti);

    return pkn;
}

static const char *
cid_to_string(const quic_cid_t *cid)
{
    if (cid->len == 0) {
        return "(none)";
    }
    char *str = (char *)wmem_alloc0(wmem_packet_scope(), 2 * cid->len + 1);
    bytes_to_hexstr(str, cid->cid, cid->len);
    return str;
}

/* QUIC Connection tracking. {{{ */
static guint
quic_connection_hash(gconstpointer key)
{
    const quic_cid_t *cid = (const quic_cid_t *)key;

    return wmem_strong_hash((const guint8 *)cid, cid->len);
}

static gboolean
quic_connection_equal(gconstpointer a, gconstpointer b)
{
    const quic_cid_t *cid1 = (const quic_cid_t *)a;
    const quic_cid_t *cid2 = (const quic_cid_t *)b;

    return cid1->len == cid2->len && !memcmp(cid1->cid, cid2->cid, cid1->len);
}

static gboolean
quic_cids_has_match(const quic_cid_item_t *items, const quic_cid_t *raw_cid)
{
    while (items) {
        const quic_cid_t *cid = &items->data;
        // "raw_cid" potentially has some trailing data that is not part of the
        // actual CID, so accept any prefix match against "cid".
        // Note that this explicitly matches an empty CID.
        if (raw_cid->len >= cid->len && !memcmp(raw_cid->cid, cid->cid, cid->len)) {
            return TRUE;
        }
        items = items->next;
    }
    return FALSE;
}

/**
 * Tries to lookup a matching connection (Connection ID is optional).
 * If connection is found, "from_server" is set accordingly.
 */
static quic_info_data_t *
quic_connection_find_dcid(packet_info *pinfo, const quic_cid_t *dcid, gboolean *from_server)
{
    /* https://tools.ietf.org/html/draft-ietf-quic-transport-11#section-6.1
     *
     * "If the packet has a Destination Connection ID corresponding to an
     * existing connection, QUIC processes that packet accordingly."
     * "If the Destination Connection ID is zero length and the packet matches
     * the address/port tuple of a connection where the host did not require
     * connection IDs, QUIC processes the packet as part of that connection."
     */
    quic_info_data_t *conn = NULL;
    gboolean check_ports = FALSE;

    if (dcid && dcid->len > 0) {
        conn = (quic_info_data_t *) wmem_map_lookup(quic_client_connections, dcid);
        if (conn) {
            // DCID recognized by client, so it was from server.
            *from_server = TRUE;
            // On collision (both client and server choose the same CID), check
            // the port to learn about the side.
            // This is required for supporting draft -10 which has a single CID.
            check_ports = !!wmem_map_lookup(quic_server_connections, dcid);
        } else {
            conn = (quic_info_data_t *) wmem_map_lookup(quic_server_connections, dcid);
            if (conn) {
                // DCID recognized by server, so it was from client.
                *from_server = FALSE;
            }
        }
    } else {
        conversation_t *conv = find_conversation_pinfo(pinfo, 0);
        if (conv) {
            conn = (quic_info_data_t *)conversation_get_proto_data(conv, proto_quic);
            check_ports = !!conn;
        }
    }

    if (check_ports) {
        *from_server = conn->server_port == pinfo->srcport &&
                addresses_equal(&conn->server_address, &pinfo->src);
    }

    return conn;
}

/**
 * Try to find a QUIC connection based on DCID. For short header packets, DCID
 * will be modified in order to find the actual length.
 * DCID can be empty, in that case a connection is looked up by address only.
 */
static quic_info_data_t *
quic_connection_find(packet_info *pinfo, guint8 long_packet_type,
                     quic_cid_t *dcid, gboolean *from_server)
{
    gboolean is_long_packet = long_packet_type != QUIC_SHORT_PACKET;
    quic_info_data_t *conn = NULL;

    if ((long_packet_type == QUIC_LPT_INITIAL || long_packet_type == QUIC_LPT_0RTT) && dcid->len > 0) {
        conn = (quic_info_data_t *) wmem_map_lookup(quic_initial_connections, dcid);
    } else {
        conn = quic_connection_find_dcid(pinfo, dcid, from_server);
    }

    if (!is_long_packet && !conn) {
        // For short packets, first try to find a match based on the address.
        conn = quic_connection_find_dcid(pinfo, NULL, from_server);
        if (conn) {
            if ((from_server && !quic_cids_has_match(&conn->server_cids, dcid)) ||
                (!from_server && !quic_cids_has_match(&conn->client_cids, dcid))) {
                // Connection does not match packet.
                conn = NULL;
            }
        }

        // No match found so far, potentially connection migration. Length of
        // actual DCID is unknown, so just keep decrementing until found.
        while (!conn && dcid->len > 4) {
            dcid->len--;
            conn = quic_connection_find_dcid(pinfo, dcid, from_server);
        }
        if (!conn) {
            // No match found, truncate DCID (not really needed, but this
            // ensures that debug prints clearly show that DCID is invalid).
            dcid->len = 0;
        }
    }
    return conn;
}

/** Create a new QUIC Connection based on a Client Initial packet. */
static quic_info_data_t *
quic_connection_create(packet_info *pinfo, guint32 version, const quic_cid_t *scid, const quic_cid_t *dcid)
{
    quic_info_data_t *conn = NULL;

    conn = wmem_new0(wmem_file_scope(), quic_info_data_t);
    wmem_list_append(quic_connections, conn);
    conn->number = quic_connections_count++;
    conn->version = version;
    copy_address_wmem(wmem_file_scope(), &conn->server_address, &pinfo->dst);
    conn->server_port = pinfo->destport;

    // Key connection by Client CID (if provided).
    if (!is_quic_draft_max(version, 10) && scid->len) {
        memcpy(&conn->client_cids.data, scid, sizeof(quic_cid_t));
        wmem_map_insert(quic_client_connections, &conn->client_cids.data, conn);
    }
    if (dcid->len > 0) {
        // According to the spec, the Initial Packet DCID MUST be at least 8
        // bytes, but non-conforming implementations could exist.
        memcpy(&conn->client_dcid_initial, dcid, sizeof(quic_cid_t));
        wmem_map_insert(quic_initial_connections, &conn->client_dcid_initial, conn);
    }

    // For faster lookups without having to check DCID
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_add_proto_data(conv, proto_quic, conn);

    return conn;
}

/** Create or update a connection. */
static void
quic_connection_create_or_update(quic_info_data_t **conn_p,
                                 packet_info *pinfo, guint32 long_packet_type,
                                 guint32 version, const quic_cid_t *scid,
                                 const quic_cid_t *dcid, gboolean from_server)
{
    quic_info_data_t *conn = *conn_p;

    switch (long_packet_type) {
    case QUIC_LPT_INITIAL:
        // The first Initial Packet creates a new connection.
        if (!conn) {
            *conn_p = quic_connection_create(pinfo, version, scid, dcid);
        }
        break;
    case QUIC_LPT_RETRY:
    case QUIC_LPT_HANDSHAKE:
        // Remember CID from first server Retry/Handshake packet
        if (conn && conn->server_cids.data.len == 0 && from_server) {
            memcpy(&conn->server_cids.data, scid, sizeof(quic_cid_t));
            if (scid->len) {
                wmem_map_insert(quic_server_connections, &conn->server_cids.data, conn);
            }

            // in draft -10, the Initial Packet CID is useless for tracking,
            // instead the CID from this Handshake message is used.
            if (is_quic_draft_max(version, 10)) {
                DISSECTOR_ASSERT(scid->len);
                memcpy(&conn->client_cids.data, scid, sizeof(quic_cid_t));
                wmem_map_insert(quic_client_connections, &conn->client_cids.data, conn);
            }
        }
        break;
    }
}

static void
quic_connection_destroy(gpointer data, gpointer user_data _U_)
{
    quic_info_data_t *conn = (quic_info_data_t *)data;
    gcry_cipher_close(conn->client_handshake_cipher.hd);
    gcry_cipher_close(conn->server_handshake_cipher.hd);

    gcry_cipher_close(conn->client_pp.cipher[0].hd);
    gcry_cipher_close(conn->client_pp.cipher[1].hd);
    gcry_cipher_close(conn->server_pp.cipher[0].hd);
    gcry_cipher_close(conn->server_pp.cipher[1].hd);
}
/* QUIC Connection tracking. }}} */


#ifdef HAVE_LIBGCRYPT_AEAD
static int
dissect_quic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, quic_packet_info_t *quic_packet)
{
    proto_item *ti_ft, *ti_ftflags, *ti;
    proto_tree *ft_tree, *ftflags_tree;
    guint32 frame_type;
    quic_info_data_t *conn = quic_packet->conn;
    guint32 version = conn ? conn->version : 0;

    ti_ft = proto_tree_add_item(quic_tree, hf_quic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_quic_ft);

    ti_ftflags = proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type, tvb, offset, 1, ENC_NA, &frame_type);
    proto_item_set_text(ti_ft, "%s", rval_to_str(frame_type, quic_frame_type_vals, "Unknown"));
    offset += 1;

    switch(frame_type){
        case FT_PADDING:{
            proto_item *ti_pad_len;
            guint32 padding_offset = offset, pad_len;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", PADDING");

            /* get length of padding (with check if it is always a 0) */
            while ( tvb_reported_length_remaining(tvb, padding_offset) > 0) {
                if(tvb_get_guint8(tvb, padding_offset) != 0){
                    break;
                }
                padding_offset ++;
            }
            pad_len = padding_offset - offset;

            ti_pad_len = proto_tree_add_uint(ft_tree, hf_quic_frame_type_padding_length, tvb, offset, 0, pad_len);
            PROTO_ITEM_SET_GENERATED(ti_pad_len);
            proto_item_append_text(ti_ft, " Length: %u", pad_len);
            proto_tree_add_item(ft_tree, hf_quic_frame_type_padding, tvb, offset, pad_len, ENC_NA);
            offset += pad_len;
            proto_item_set_len(ti_ft, 1+pad_len);
        }
        break;
        case FT_RST_STREAM:{
            guint64 stream_id;
            guint32 error_code, len_streamid = 0, len_finaloffset = 0;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", RS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_rsts_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_rsts_application_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_rsts_final_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_finaloffset);
            offset += len_finaloffset;

            proto_item_append_text(ti_ft, " Stream ID: %" G_GINT64_MODIFIER "u, Error code: %s", stream_id, val_to_str_ext(error_code, &quic_error_code_vals_ext, "Unknown (%d)"));

            proto_item_set_len(ti_ft, 1 + len_streamid + 2 + len_finaloffset);
        }
        break;
        case FT_CONNECTION_CLOSE:{
            guint32 len_reasonphrase, error_code;
            guint64 len_reason = 0;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", CC");

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_cc_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_cc_reason_phrase_length, tvb, offset, -1, ENC_VARINT_QUIC, &len_reason, &len_reasonphrase);
            offset += len_reasonphrase;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_cc_reason_phrase, tvb, offset, (guint32)len_reason, ENC_ASCII|ENC_NA);
            offset += (guint32)len_reason;

            proto_item_append_text(ti_ft, " Error code: %s", val_to_str_ext(error_code, &quic_error_code_vals_ext, "Unknown (%d)"));
            proto_item_set_len(ti_ft, 1 + 2 + len_reasonphrase + (guint32)len_reason);
        }
        break;
        case FT_APPLICATION_CLOSE:{
            guint32 len_reasonphrase, error_code;
            guint64 len_reason;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", AC");

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_ac_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ac_reason_phrase_length, tvb, offset, -1, ENC_VARINT_QUIC, &len_reason, &len_reasonphrase);
            offset += len_reasonphrase;
            proto_tree_add_item(ft_tree, hf_quic_frame_type_ac_reason_phrase, tvb, offset, (guint32)len_reason, ENC_ASCII|ENC_NA);
            offset += (guint32)len_reason;

            proto_item_append_text(ti_ft, " Error code: %s", val_to_str_ext(error_code, &quic_error_code_vals_ext, "Unknown (%d)"));
            proto_item_set_len(ti_ft, 1 + 2+ len_reasonphrase + (guint32)len_reason);
        }
        break;
        case FT_MAX_DATA:{
            guint32 len_maximumdata;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_md_maximum_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumdata);
            offset += len_maximumdata;

            proto_item_set_len(ti_ft, 1 + len_maximumdata);
        }
        break;
        case FT_MAX_STREAM_DATA:{
            guint32 len_streamid, len_maximumstreamdata;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MSD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msd_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msd_maximum_stream_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumstreamdata);
            offset += len_maximumstreamdata;

            proto_item_set_len(ti_ft, 1 + len_streamid + len_maximumstreamdata);
        }
        break;
        case FT_MAX_STREAM_ID:{
            guint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MSI");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msi_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_item_set_len(ti_ft, 1 + len_streamid);
        }
        break;
        case FT_PING:{
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PING");
        }
        break;
        case FT_BLOCKED:{
            guint32 len_offset;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", B");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_blocked_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;

            proto_item_set_len(ti_ft, 1 + len_offset);
        }
        break;
        case FT_STREAM_BLOCKED:{
            guint32 len_streamid, len_offset;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sb_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sb_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;

            proto_item_set_len(ti_ft, 1 + len_streamid + len_offset);
        }
        break;
        case FT_STREAM_ID_BLOCKED:{
            guint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SIB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sib_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_item_set_len(ti_ft, 1 + len_streamid);
        }
        break;
        case FT_NEW_CONNECTION_ID:{
            guint32 len_sequence;
            guint32 nci_length;
            gboolean valid_cid = FALSE;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", NCI");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_nci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
            offset += len_sequence;

            if (is_quic_draft_max(version, 10)) {
                nci_length = 8;
            } else {
                ti = proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_nci_connection_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &nci_length);
                offset++;

                valid_cid = nci_length >= 4 && nci_length <= 18;
                if (!valid_cid) {
                    expert_add_info_format(pinfo, ti, &ei_quic_protocol_violation,
                            "Connection ID Length must be between 4 and 18 bytes");
                }
            }

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nci_connection_id, tvb, offset, nci_length, ENC_NA);
            offset += nci_length;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nci_stateless_reset_token, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_item_set_len(ti_ft, 1 + len_sequence + nci_length + 16);
        }
        break;
        case FT_STOP_SENDING:{
            guint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ss_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;


            proto_tree_add_item(ft_tree, hf_quic_frame_type_ss_application_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_item_set_len(ti_ft, 1 + len_streamid + 2);
        }
        break;
        case FT_ACK:{
            guint64 ack_block_count;
            guint32 lenvar;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", ACK");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_largest_acknowledged, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_ack_block_count, tvb, offset, -1, ENC_VARINT_QUIC, &ack_block_count, &lenvar);
            offset += lenvar;

            /* ACK Block */
            /* First ACK Block Length */
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_fab, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            /* Repeated "Ack Block Count" */
            while(ack_block_count){

                /* Gap To Next Block */
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_gap, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_ack_block, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                ack_block_count--;
            }
        }
        break;
        case FT_PATH_CHALLENGE:{
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PC");

            proto_tree_add_item(ft_tree, hf_quic_frame_type_path_challenge_data, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;
        case FT_PATH_RESPONSE:{

            col_append_fstr(pinfo->cinfo, COL_INFO, ", PR");

            proto_tree_add_item(ft_tree, hf_quic_frame_type_path_response_data, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;
        case FT_STREAM_10:
        case FT_STREAM_11:
        case FT_STREAM_12:
        case FT_STREAM_13:
        case FT_STREAM_14:
        case FT_STREAM_15:
        case FT_STREAM_16:
        case FT_STREAM_17: {
            guint64 stream_id, length;
            guint32 lenvar;
            proto_item *ti_stream;

            offset -= 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", STREAM");

            ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_quic_ftflags);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_fin, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_len, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_off, tvb, offset, 1, ENC_NA);
            offset += 1;

            ti_stream = proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &lenvar);
            offset += lenvar;

            proto_item_append_text(ti_ft, " Stream ID: %" G_GINT64_MODIFIER "u", stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" G_GINT64_MODIFIER "u)", stream_id);

            if (frame_type & FTFLAGS_STREAM_OFF) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            }

            if (frame_type & FTFLAGS_STREAM_LEN) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
                offset += lenvar;
            } else {
               length = tvb_reported_length_remaining(tvb, offset);
            }

            proto_tree_add_item(ft_tree, hf_quic_stream_data, tvb, offset, (int)length, ENC_NA);

            if (stream_id == 0) { /* Special Stream */
                tvbuff_t *next_tvb;

                proto_item_append_text(ti_stream, " (Cryptographic handshake)");
                col_set_writable(pinfo->cinfo, -1, FALSE);
                next_tvb = tvb_new_subset_length(tvb, offset, (int)length);
                call_dissector(ssl_handle, next_tvb, pinfo, ft_tree);
                col_set_writable(pinfo->cinfo, -1, TRUE);
            }
            offset += (int)length;


        }
        break;
        default:
            expert_add_info_format(pinfo, ti_ft, &ei_quic_ft_unknown, "Unknown Frame Type %u", frame_type);
        break;
    }

    return offset;
}
#endif /* HAVE_LIBGCRYPT_AEAD */

/* Maximum for draft -11: type, version, DCIL/SCIL, DCID, SCID, payload length, PKN. */
#define QUIC_LONG_HEADER_MAX_LENGTH     (1+4+1+18+18+8+4)

#ifdef HAVE_LIBGCRYPT_AEAD
static gcry_error_t
qhkdf_expand(int md, const guint8 *secret, guint secret_len,
             const char *label, guint8 *out, guint out_len);

static gboolean
quic_cipher_init_keyiv(tls13_cipher *cipher, int hash_algo, guint8 key_length, guint8 *secret);


/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-11#section-4.8
 */
static void
quic_decrypt_message(tls13_cipher *cipher, tvbuff_t *head, guint header_length, guint64 packet_number, quic_decrypt_result_t *result)
{
    gcry_error_t    err;
    guint8          header[QUIC_LONG_HEADER_MAX_LENGTH];
    guint8          nonce[TLS13_AEAD_NONCE_LENGTH];
    guint8         *buffer;
    guint8         *atag[16];
    guint           buffer_length;
    const guchar  **error = &result->error;

    DISSECTOR_ASSERT(cipher != NULL);
    DISSECTOR_ASSERT(cipher->hd != NULL);
    DISSECTOR_ASSERT(header_length <= sizeof(header));
    tvb_memcpy(head, header, 0, header_length);

    /* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
    buffer_length = tvb_captured_length_remaining(head, header_length + 16);
    if (buffer_length == 0) {
        *error = "Decryption not possible, ciphertext is too short";
        return;
    }
    buffer = (guint8 *)tvb_memdup(wmem_file_scope(), head, header_length, buffer_length);
    tvb_memcpy(head, atag, header_length + buffer_length, 16);

    memcpy(nonce, cipher->iv, TLS13_AEAD_NONCE_LENGTH);
    /* Packet number is left-padded with zeroes and XORed with write_iv */
    phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);

    gcry_cipher_reset(cipher->hd);
    err = gcry_cipher_setiv(cipher->hd, nonce, TLS13_AEAD_NONCE_LENGTH);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (setiv) failed: %s", gcry_strerror(err));
        return;
    }

    /* associated data (A) is the contents of QUIC header */
    err = gcry_cipher_authenticate(cipher->hd, header, header_length);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (authenticate) failed: %s", gcry_strerror(err));
        return;
    }

    /* Output ciphertext (C) */
    err = gcry_cipher_decrypt(cipher->hd, buffer, buffer_length, NULL, 0);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (decrypt) failed: %s", gcry_strerror(err));
        return;
    }

    err = gcry_cipher_checktag(cipher->hd, atag, 16);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (checktag) failed: %s", gcry_strerror(err));
        return;
    }

    result->error = NULL;
    result->data = buffer;
    result->data_len = buffer_length;
}

/**
 * Compute the client and server handshake secrets given Connection ID "cid".
 *
 * On success TRUE is returned and the two handshake secrets are set.
 * FALSE is returned on error (see "error" parameter for the reason).
 */
static gboolean
quic_derive_handshake_secrets(const quic_cid_t *cid,
                              guint8 client_handshake_secret[HASH_SHA2_256_LENGTH],
                              guint8 server_handshake_secret[HASH_SHA2_256_LENGTH],
                              quic_info_data_t *quic_info _U_,
                              const gchar **error)
{
    /*
     * https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-5.2.2
     *
     * handshake_salt = 0x9c108f98520a5c5c32968e950e8a2c5fe06d6c38
     * handshake_secret =
     *     HKDF-Extract(handshake_salt, client_connection_id)
     *
     * client_handshake_secret =
     *    QHKDF-Expand(handshake_secret, "client hs", Hash.length)
     * server_handshake_secret =
     *    QHKDF-Expand(handshake_secret, "server hs", Hash.length)
     *
     * Hash for handshake packets is SHA-256 (output size 32).
     */
    static const guint8 handshake_salt[20] = {
        0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
        0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38
    };
    gcry_error_t    err;
    guint8          secret[HASH_SHA2_256_LENGTH];

    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt, sizeof(handshake_salt),
                       cid->cid, cid->len, secret);
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Failed to extract secrets: %s", gcry_strerror(err));
        return FALSE;
    }

    if (qhkdf_expand(GCRY_MD_SHA256, secret, sizeof(secret), "client hs",
                     client_handshake_secret, HASH_SHA2_256_LENGTH)) {
        *error = "Key expansion (client) failed";
        return FALSE;
    }

    if (qhkdf_expand(GCRY_MD_SHA256, secret, sizeof(secret), "server hs",
                     server_handshake_secret, HASH_SHA2_256_LENGTH)) {
        *error = "Key expansion (server) failed";
        return FALSE;
    }

    *error = NULL;
    return TRUE;
}

static gboolean
quic_create_handshake_decoders(const quic_cid_t *cid, const gchar **error, quic_info_data_t *quic_info)
{
    guint8          client_secret[HASH_SHA2_256_LENGTH];
    guint8          server_secret[HASH_SHA2_256_LENGTH];

    if (!quic_derive_handshake_secrets(cid, client_secret, server_secret, quic_info, error)) {
        return FALSE;
    }

    /* Destroy any previous ciphers in case there exist multiple Initial packets */
    gcry_cipher_close(quic_info->client_handshake_cipher.hd);
    gcry_cipher_close(quic_info->server_handshake_cipher.hd);
    memset(&quic_info->client_handshake_cipher, 0, sizeof(tls13_cipher));
    memset(&quic_info->server_handshake_cipher, 0, sizeof(tls13_cipher));

    /* handshake packets are protected with AEAD_AES_128_GCM */
    if (gcry_cipher_open(&quic_info->client_handshake_cipher.hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0) ||
        gcry_cipher_open(&quic_info->server_handshake_cipher.hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0)) {
        *error = "Failed to create ciphers";
        return FALSE;
    }

    guint cipher_keylen = (guint8) gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
    if (!quic_cipher_init_keyiv(&quic_info->client_handshake_cipher, GCRY_MD_SHA256, cipher_keylen, client_secret) ||
        !quic_cipher_init_keyiv(&quic_info->server_handshake_cipher, GCRY_MD_SHA256, cipher_keylen, server_secret)) {
        *error = "Failed to derive key material for cipher";
        return FALSE;
    }

    return TRUE;
}

/**
 * Computes QHKDF-Expand(Secret, Label, Length).
 * Caller must ensure that "out" is large enough for "out_len".
 */
static gcry_error_t
qhkdf_expand(int md, const guint8 *secret, guint secret_len,
             const char *label, guint8 *out, guint out_len)
{
    /* https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-5.2.1
     *     QHKDF-Expand(Secret, Label, Length) =
     *          HKDF-Expand(Secret, QhkdfLabel, Length)
     *     struct {
     *         uint16 length = Length;
     *         opaque label<6..255> = "QUIC " + Label;
     *     } QhkdfLabel;
     */
    gcry_error_t err;
    const guint label_length = (guint) strlen(label);

    /* Some sanity checks */
    DISSECTOR_ASSERT(label_length > 0 && 5 + label_length <= 255);

    /* info = QhkdfLabel { length, label } */
    GByteArray *info = g_byte_array_new();
    const guint16 length = g_htons(out_len);
    g_byte_array_append(info, (const guint8 *)&length, sizeof(length));

    const guint8 label_vector_length = 5 + label_length;
    g_byte_array_append(info, &label_vector_length, 1);
    g_byte_array_append(info, "QUIC ", 5);
    g_byte_array_append(info, label, label_length);

    err = hkdf_expand(md, secret, secret_len, info->data, info->len, out, out_len);
    g_byte_array_free(info, TRUE);
    return err;
}

/**
 * Tries to obtain the "client_pp_secret_0" or "server_pp_secret_0" secret.
 */
static gboolean
quic_get_pp0_secret(packet_info *pinfo, int hash_algo, quic_pp_state_t *pp_state, gboolean from_client)
{
    const char *label = from_client ? "EXPORTER-QUIC client 1rtt" : "EXPORTER-QUIC server 1rtt";
    guint hash_len = gcry_md_get_algo_dlen(hash_algo);
    guchar *pp_secret = NULL;
    if (!tls13_exporter(pinfo, FALSE, label, NULL, 0, hash_len, &pp_secret)) {
        return FALSE;
    }
    pp_state->secret = (guint8 *)wmem_memdup(wmem_file_scope(), pp_secret, hash_len);
    wmem_free(NULL, pp_secret);
    return TRUE;
}

/**
 * Expands the secret (length MUST be the same as the "hash_algo" digest size)
 * and initialize cipher with the new key.
 */
static gboolean
quic_cipher_init_keyiv(tls13_cipher *cipher, int hash_algo, guint8 key_length, guint8 *secret)
{
    guchar      write_key[256/8];   /* Maximum key size is for AES256 cipher. */
    guint       hash_len = gcry_md_get_algo_dlen(hash_algo);

    if (key_length > sizeof(write_key)) {
        return FALSE;
    }

    if (qhkdf_expand(hash_algo, secret, hash_len, "key", write_key, key_length) ||
        qhkdf_expand(hash_algo, secret, hash_len, "iv", cipher->iv, sizeof(cipher->iv))) {
        return FALSE;
    }

    return gcry_cipher_setkey(cipher->hd, write_key, key_length) == 0;
}

/**
 * Updates the packet protection secret to the next one.
 */
static void
quic_update_key(int hash_algo, quic_pp_state_t *pp_state, gboolean from_client)
{
    guint hash_len = gcry_md_get_algo_dlen(hash_algo);
    qhkdf_expand(hash_algo, pp_state->secret, hash_len,
                 from_client ? "client 1rtt" : "server 1rtt",
                 pp_state->secret, hash_len);
}

/**
 * Tries to construct the appropriate cipher for the current key phase.
 * See also "PROTECTED PAYLOAD DECRYPTION" comment on top of this file.
 */
static tls13_cipher *
quic_get_pp_cipher(packet_info *pinfo, gboolean key_phase, guint64 pkn, quic_info_data_t *quic_info, gboolean from_server)
{
    gboolean    needs_key_update = FALSE;

    /* Keys were previously not available. */
    if (quic_info->skip_decryption) {
        return NULL;
    }

    quic_pp_state_t *client_pp = &quic_info->client_pp;
    quic_pp_state_t *server_pp = &quic_info->server_pp;
    quic_pp_state_t *pp_state = !from_server ? client_pp : server_pp;

    /* Try to lookup secrets if not available. */
    if (!quic_info->client_pp.secret) {
        int cipher_algo, cipher_mode;
        /* Query TLS for the cipher suite. */
        if (!tls_get_cipher_info(pinfo, &cipher_algo, &cipher_mode, &quic_info->hash_algo)) {
            /* No previous TLS handshake found or unsupported ciphers, fail. */
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        /* Retrieve secrets for both the client and server. */
        if (!quic_get_pp0_secret(pinfo, quic_info->hash_algo, client_pp, TRUE) ||
            !quic_get_pp0_secret(pinfo, quic_info->hash_algo, server_pp, FALSE)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        /* Create initial cipher handles for KEY_PHASE 0 and 1. */
        if (gcry_cipher_open(&client_pp->cipher[0].hd, cipher_algo, cipher_mode, 0) ||
            gcry_cipher_open(&server_pp->cipher[0].hd, cipher_algo, cipher_mode, 0) ||
            gcry_cipher_open(&client_pp->cipher[1].hd, cipher_algo, cipher_mode, 0) ||
            gcry_cipher_open(&server_pp->cipher[1].hd, cipher_algo, cipher_mode, 0)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }
        quic_info->cipher_keylen = (guint8) gcry_cipher_get_algo_keylen(cipher_algo);

        /* Set key for cipher handles KEY_PHASE 0. */
        if (!quic_cipher_init_keyiv(&client_pp->cipher[0], quic_info->hash_algo, quic_info->cipher_keylen, client_pp->secret) ||
            !quic_cipher_init_keyiv(&server_pp->cipher[0], quic_info->hash_algo, quic_info->cipher_keylen, server_pp->secret)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        pp_state->changed_in_pkn = pkn;

        /*
         * If the first received packet has KEY_PHASE=1, then the key must be
         * updated now.
         */
        needs_key_update = key_phase;
    }

    /*
     * Check for key phase change. Either it is out-of-order (when packet number
     * is lower than the one triggering the most recent key update) or it is
     * actually a key update (if the packet number is higher).
     * TODO verify decryption before switching keys.
     */
    if (key_phase != pp_state->key_phase) {
        if (!needs_key_update && pkn < pp_state->changed_in_pkn) {
            /* Packet is from before the key phase change, use old cipher. */
            return &pp_state->cipher[1 - key_phase];
        } else {
            /* Key update requested, update key. */
            quic_update_key(quic_info->hash_algo, pp_state, !from_server);
            quic_cipher_init_keyiv(&pp_state->cipher[key_phase], quic_info->hash_algo, quic_info->cipher_keylen, pp_state->secret);
            pp_state->key_phase = key_phase;
            pp_state->changed_in_pkn = pkn;
        }
    }

    return &pp_state->cipher[key_phase];
}
#endif /* HAVE_LIBGCRYPT_AEAD */

#ifdef HAVE_LIBGCRYPT_AEAD
/**
 * Process (protected) payload, adding the encrypted payload to the tree. If
 * decryption is possible, frame dissection is also attempted.
 *
 * The given offset must correspond to the end of the QUIC header and begin of
 * the (protected) payload. Dissected frames are appended to "tree" and expert
 * info is attached to "ti" (the field with the encrypted payload).
 */
static void
quic_process_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint offset,
                     quic_info_data_t *quic_info, quic_packet_info_t *quic_packet, tls13_cipher *cipher, guint64 pkn)
{
    quic_decrypt_result_t *decryption = &quic_packet->decryption;

    /*
     * If no decryption error has occurred yet, try decryption on the first
     * pass and store the result for later use.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (!quic_packet->decryption.error && cipher && cipher->hd) {
            quic_decrypt_message(cipher, tvb, offset, pkn, &quic_packet->decryption);
        }
    }

    if (decryption->error) {
        expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed,
                               "Decryption failed: %s", decryption->error);
    } else if (decryption->data_len) {
        tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, decryption->data,
                decryption->data_len, decryption->data_len);
        add_new_data_source(pinfo, decrypted_tvb, "Decrypted QUIC");

        guint decrypted_offset = 0;
        while (tvb_reported_length_remaining(decrypted_tvb, decrypted_offset) > 0) {
            decrypted_offset = dissect_quic_frame_type(decrypted_tvb, pinfo, tree, decrypted_offset, quic_packet);
        }
    } else if (quic_info->skip_decryption) {
        expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed,
                               "Decryption skipped because keys are not available.");
    }
}
#else /* !HAVE_LIBGCRYPT_AEAD */
static void
quic_process_payload(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, proto_item *ti, guint offset _U_,
                     quic_info_data_t *quic_info _U_, quic_packet_info_t *quic_packet _U_, tls13_cipher *cipher _U_, guint64 pkn _U_)
{
    expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Libgcrypt >= 1.6.0 is required for QUIC decryption");
}
#endif /* !HAVE_LIBGCRYPT_AEAD */

static int
dissect_quic_initial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset,
                     quic_info_data_t *quic_info, quic_packet_info_t *quic_packet, guint64 pkn,
#ifdef HAVE_LIBGCRYPT_AEAD
                     const quic_cid_t *cid
#else /* !HAVE_LIBGCRYPT_AEAD */
                     const quic_cid_t *cid _U_
#endif /* !HAVE_LIBGCRYPT_AEAD */
                     )
{
    proto_item *ti;

    ti = proto_tree_add_item(quic_tree, hf_quic_initial_payload, tvb, offset, -1, ENC_NA);

    // An Initial Packet should always result in creating a new connection.
    DISSECTOR_ASSERT(quic_info);

#ifdef HAVE_LIBGCRYPT_AEAD
    if (!PINFO_FD_VISITED(pinfo)) {
        const gchar *error = NULL;
        /* Create new decryption context based on the Client Connection
         * ID from the Client Initial packet. */
        if (!quic_create_handshake_decoders(cid, &error, quic_info)) {
            expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Failed to create decryption context: %s", error);
            quic_packet->decryption.error = wmem_strdup(wmem_file_scope(), error);
        }
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */

    quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                         quic_info, quic_packet, &quic_info->client_handshake_cipher, pkn);
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_quic_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset,
                       quic_info_data_t *quic_info, quic_packet_info_t *quic_packet, guint64 pkn)
{
    proto_item *ti;

    ti = proto_tree_add_item(quic_tree, hf_quic_handshake_payload, tvb, offset, -1, ENC_NA);

    if (!quic_info) {
        // No connection might be available if the Initial Packet is missing.
        return tvb_reported_length_remaining(tvb, offset);
    }

    tls13_cipher *cipher = quic_packet->from_server ? &quic_info->server_handshake_cipher : &quic_info->client_handshake_cipher;
    quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                         quic_info, quic_packet, cipher, pkn);
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_quic_retry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset,
                   quic_info_data_t *quic_info, quic_packet_info_t *quic_packet, guint64 pkn)
{
    proto_item *ti;

    ti = proto_tree_add_item(quic_tree, hf_quic_retry_payload, tvb, offset, -1, ENC_NA);

    if (!quic_info) {
        // No connection might be available if the Initial Packet is missing.
        return tvb_reported_length_remaining(tvb, offset);
    }

    /* Retry coming always from server */
    quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                         quic_info, quic_packet, &quic_info->server_handshake_cipher, pkn);
    offset += tvb_reported_length_remaining(tvb, offset);


    return offset;
}

static void
quic_add_connection_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, quic_packet_info_t *quic_packet)
{
    proto_tree         *ctree;
    proto_item         *pi;
    quic_info_data_t   *conn = quic_packet->conn;

    ctree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_quic_connection_info, NULL, "QUIC Connection information");
    if (!conn) {
        expert_add_info(pinfo, ctree, &ei_quic_connection_unknown);
        return;
    }

    pi = proto_tree_add_uint(ctree, hf_quic_connection_number, tvb, 0, 0, conn->number);
    PROTO_ITEM_SET_GENERATED(pi);
#if 0
    proto_tree_add_debug_text(ctree, "Client CID: %s", cid_to_string(&conn->client_cids.data));
    proto_tree_add_debug_text(ctree, "Server CID: %s", cid_to_string(&conn->server_cids.data));
    proto_tree_add_debug_text(ctree, "InitialCID: %s", cid_to_string(&conn->client_dcid_initial));
#endif
}

/**
 * Dissects the common part after the first byte for packets using the Long
 * Header form.
 */
static int
dissect_quic_long_header_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                                guint offset, const quic_packet_info_t *quic_packet _U_,
                                guint32 *version_out, quic_cid_t *dcid, quic_cid_t *scid)
{
    guint32     version;
    gboolean    is_draft10 = FALSE;
    guint32     dcil, scil;

    version = tvb_get_ntohl(tvb, offset);

    if (!(version == 0 || quic_draft_version(version) >= 11)) {
        // not a draft -11 version negotiation packet nor draft -11 version,
        // assume draft -10 or older. Its version comes after CID.
        guint32 version10 = tvb_get_ntohl(tvb, offset + 8);
        is_draft10 = is_quic_draft_max(version10, 10);
        if (is_draft10) {
            version = version10;
        }
    }
    if (version_out) {
        *version_out = version;
    }

    if (is_draft10) {
        proto_tree_add_item(quic_tree, hf_quic_dcid, tvb, offset, 8, ENC_NA);
        tvb_memcpy(tvb, dcid->cid, offset, 8);
        dcid->len = 8;
        offset += 8;

        proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        // draft -11 and up.
        proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item_ret_uint(quic_tree, hf_quic_dcil, tvb, offset, 1, ENC_BIG_ENDIAN, &dcil);
        proto_tree_add_item_ret_uint(quic_tree, hf_quic_scil, tvb, offset, 1, ENC_BIG_ENDIAN, &scil);
        offset++;

        if (dcil) {
            dcil += 3;
            proto_tree_add_item(quic_tree, hf_quic_dcid, tvb, offset, dcil, ENC_NA);
            // TODO expert info on CID mismatch with connection
            tvb_memcpy(tvb, dcid->cid, offset, dcil);
            dcid->len = dcil;
            offset += dcil;
        }

        if (scil) {
            scil += 3;
            proto_tree_add_item(quic_tree, hf_quic_scid, tvb, offset, scil, ENC_NA);
            // TODO expert info on CID mismatch with connection
            tvb_memcpy(tvb, scid->cid, offset, scil);
            scid->len = scil;
            offset += scil;
        }
    }
    if (dcid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", cid_to_string(dcid));
    }
    if (scid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", SCID=%s", cid_to_string(scid));
    }
    return offset;
}

static int
dissect_quic_long_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset,
                         quic_packet_info_t *quic_packet)
{
    guint32 long_packet_type;
    guint32 version;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    guint32 len_payload_length;
    guint64 payload_length;
    guint64 pkn;
    quic_info_data_t *conn = quic_packet->conn;

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA, &long_packet_type);
    offset += 1;
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(long_packet_type, quic_long_packet_type_vals, "Long Header"));

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &version, &dcid, &scid);

    if (!is_quic_draft_max(version, 10)) {
        proto_tree_add_item_ret_varint(quic_tree, hf_quic_payload_length, tvb, offset, -1, ENC_VARINT_QUIC, &payload_length, &len_payload_length);
        offset += len_payload_length;
    }

    pkn = dissect_quic_packet_number(tvb, pinfo, quic_tree, offset, conn, quic_packet, 4);
    offset += 4;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" G_GINT64_MODIFIER "u", pkn);

    /* Payload */
    switch(long_packet_type) {
        case QUIC_LPT_INITIAL: /* Initial */
            offset = dissect_quic_initial(tvb, pinfo, quic_tree, offset, conn, quic_packet, pkn, &dcid);
        break;
        case QUIC_LPT_HANDSHAKE: /* Handshake */
            offset = dissect_quic_handshake(tvb, pinfo, quic_tree, offset, conn, quic_packet, pkn);
        break;
        case QUIC_LPT_RETRY: /* Retry */
            offset = dissect_quic_retry(tvb, pinfo, quic_tree, offset, conn, quic_packet, pkn);
        break;
        default:
            /* Protected (Encrypted) Payload */
            proto_tree_add_item(quic_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
        break;
    }

    return offset;
}

static int
dissect_quic_short_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset,
                          quic_packet_info_t *quic_packet)
{
    guint8 short_flags;
    quic_cid_t dcid = {.len=0};
    guint32 pkn_len;
    guint64 pkn;
    proto_item *ti;
    gboolean    key_phase = FALSE;
    tls13_cipher *cipher = NULL;
    quic_info_data_t *conn = quic_packet->conn;
    // Best-effort guess: if no connection is known, assume newer draft version.
    gboolean is_draft10 = conn && is_quic_draft_max(conn->version, 10);

    short_flags = tvb_get_guint8(tvb, offset);
    if (is_draft10) {
        gboolean omit_cid;
        proto_tree_add_item_ret_boolean(quic_tree, hf_quic_short_ocid_flag, tvb, offset, 1, ENC_NA, &omit_cid);
        dcid.len = omit_cid ? 0 : 8;
        proto_tree_add_item_ret_boolean(quic_tree, hf_quic_short_kp_flag_draft10, tvb, offset, 1, ENC_NA, &key_phase);
        ti = proto_tree_add_item(quic_tree, hf_quic_short_packet_type_draft10, tvb, offset, 1, ENC_NA);
        if ((short_flags & 0x18) != 0x10) {
            expert_add_info_format(pinfo, ti, &ei_quic_protocol_violation,
                    "Fourth bit (0x10) must be 1, fifth bit (0x8) must be set to 0.");
        }
    } else {
        proto_tree_add_item_ret_boolean(quic_tree, hf_quic_short_kp_flag, tvb, offset, 1, ENC_NA, &key_phase);
        proto_tree_add_item(quic_tree, hf_quic_short_packet_type, tvb, offset, 1, ENC_NA);
        if (conn) {
            dcid.len = quic_packet->from_server ? conn->client_cids.data.len : conn->server_cids.data.len;
        }
    }
    offset += 1;

    /* Connection ID */
    if (dcid.len > 0) {
        proto_tree_add_item(quic_tree, hf_quic_dcid, tvb, offset, dcid.len, ENC_NA);
        tvb_memcpy(tvb, dcid.cid, offset, dcid.len);
        offset += dcid.len;
    }

    /* Packet Number */
    pkn_len = get_len_packet_number(short_flags);
    pkn = dissect_quic_packet_number(tvb, pinfo, quic_tree, offset, conn, quic_packet, pkn_len);
    offset += pkn_len;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Protected Payload (KP%u), PKN: %" G_GINT64_MODIFIER "u", key_phase, pkn);

    if (dcid.len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", cid_to_string(&dcid));
    }

    /* Protected Payload */
    ti = proto_tree_add_item(quic_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);

    if (conn) {
#ifdef HAVE_LIBGCRYPT_AEAD
        if (!PINFO_FD_VISITED(pinfo)) {
            cipher = quic_get_pp_cipher(pinfo, key_phase, pkn, conn, quic_packet->from_server);
        }
#endif /* !HAVE_LIBGCRYPT_AEAD */

        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, cipher, pkn);
    }
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_quic_version_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, const quic_packet_info_t *quic_packet)
{
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    guint32 supported_version;
    proto_item *ti;

    col_set_str(pinfo->cinfo, COL_INFO, "Version Negotiation");

    proto_tree_add_item(quic_tree, hf_quic_vn_unused, tvb, offset, 1, ENC_NA);
    offset += 1;

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, NULL, &dcid, &scid);

    /* Supported Version */
    while(tvb_reported_length_remaining(tvb, offset) > 0){
        ti = proto_tree_add_item_ret_uint(quic_tree, hf_quic_supported_version, tvb, offset, 4, ENC_BIG_ENDIAN, &supported_version);
        if ((supported_version & 0x0F0F0F0F) == 0x0a0a0a0a) {
            proto_item_append_text(ti, " (GREASE)");
        }
        offset += 4;
    }

    return offset;
}

/**
 * Extracts necessary information from header to find any existing connection.
 * "long_packet_type" is set to QUIC_SHORT_PACKET for short header packets.
 * DCID and SCID are not modified unless available. For short header packets,
 * DCID length is unknown, so the caller should truncate it as needed.
 */
static void
quic_extract_header(tvbuff_t *tvb, guint8 *long_packet_type, guint32 *version,
                    quic_cid_t *dcid, quic_cid_t *scid)
{
    guint offset = 0;

    guint8 packet_type = tvb_get_guint8(tvb, offset);
    gboolean is_long_header = packet_type & 0x80;
    if (is_long_header) {
        // long header form
        *long_packet_type = packet_type & 0x7f;
    } else {
        // short header form, store dummy value that is not a long packet type.
        *long_packet_type = QUIC_SHORT_PACKET;
    }
    offset++;

    guint32 maybe_version = tvb_get_ntohl(tvb, offset);
    gboolean is_draft10 = FALSE;
    if (!(maybe_version == 0 || quic_draft_version(maybe_version) >= 11)) {
        // not a draft -11 version negotiation packet nor draft -11 version,
        // assume draft -10 or older. Its version comes after CID.
        guint32 version10 = tvb_get_ntohl(tvb, offset + 8);
        is_draft10 = is_quic_draft_max(version10, 10);
        if (is_draft10) {
            maybe_version = version10;
        }
    }
    *version = maybe_version;

    if (is_draft10) {
        tvb_memcpy(tvb, dcid->cid, offset, 8);
        dcid->len = 8;
    } else if (is_long_header) {
        // skip version
        offset += 4;

        // read DCIL/SCIL (Connection ID Lengths).
        guint8 cid_lengths = tvb_get_guint8(tvb, offset);
        guint8 dcil = cid_lengths >> 4;
        guint8 scil = cid_lengths & 0xf;
        offset++;

        if (dcil) {
            dcil += 3;
            tvb_memcpy(tvb, dcid->cid, offset, dcil);
            dcid->len = dcil;
            offset += dcil;
        }

        if (scil) {
            scil += 3;
            tvb_memcpy(tvb, scid->cid, offset, scil);
            scid->len = scil;
        }
    } else {
        // Definitely not draft -10, set version to dummy value.
        *version = 0;
        // For short headers, the DCID length is unknown and could be 0 or
        // anything from 4 to 18 bytes. Copy the maximum possible and let the
        // consumer truncate it as necessary.
        tvb_memcpy(tvb, dcid->cid, offset, 18);
        dcid->len = 18;
    }
}

static int
dissect_quic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *quic_tree;
    guint       offset = 0;
    guint32     header_form;
    quic_packet_info_t *quic_packet = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUIC");

    if (PINFO_FD_VISITED(pinfo)) {
        quic_packet = (quic_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    }
    if (!quic_packet) {
        quic_packet = wmem_new0(wmem_file_scope(), quic_packet_info_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_quic, 0, quic_packet);
    }

    ti = proto_tree_add_item(tree, proto_quic, tvb, 0, -1, ENC_NA);

    quic_tree = proto_item_add_subtree(ti, ett_quic);

    if (!PINFO_FD_VISITED(pinfo)) {
        guint8      long_packet_type;
        guint32     version;
        quic_cid_t  dcid = {.len=0}, scid = {.len=0};
        gboolean    from_server = FALSE;
        quic_info_data_t *conn;

        quic_extract_header(tvb, &long_packet_type, &version, &dcid, &scid);
        conn = quic_connection_find(pinfo, long_packet_type, &dcid, &from_server);
        if (is_quic_draft_max(version, 10)) {
            // In draft -10 and before, there is only a single CID.
            if (long_packet_type == QUIC_LPT_HANDSHAKE && !conn) {
                // the first handshake packet from server sets CID, only after
                // that it will be possible to match by CID.
                conn = quic_connection_find_dcid(pinfo, NULL, &from_server);
            }
            quic_connection_create_or_update(&conn, pinfo, long_packet_type, version, &dcid, &dcid, from_server);
        } else {
            quic_connection_create_or_update(&conn, pinfo, long_packet_type, version, &scid, &dcid, from_server);
        }
        quic_packet->conn = conn;
        quic_packet->from_server = from_server;
#if 0
        proto_tree_add_debug_text(quic_tree, "Connection: %d %p DCID=%s SCID=%s from_server:%d", pinfo->num, quic_packet->conn, cid_to_string(&dcid), cid_to_string(&scid), quic_packet->from_server);
    } else {
        proto_tree_add_debug_text(quic_tree, "Connection: %d %p from_server:%d", pinfo->num, quic_packet->conn, quic_packet->from_server);
#endif
    }

    quic_add_connection_info(tvb, pinfo, quic_tree, quic_packet);

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_header_form, tvb, offset, 1, ENC_NA, &header_form);
    if(header_form) {
        gboolean is_vn = tvb_get_ntohl(tvb, offset + 1) == 0;
        is_vn = is_vn || tvb_get_ntohl(tvb, offset + 1 + 8) == 0; // before draft -11
        if (is_vn) {
            offset = dissect_quic_version_negotiation(tvb, pinfo, quic_tree, offset, quic_packet);
            return offset;
        }
        offset = dissect_quic_long_header(tvb, pinfo, quic_tree, offset, quic_packet);
    } else {
        offset = dissect_quic_short_header(tvb, pinfo, quic_tree, offset, quic_packet);
    }

    return offset;
}

static gboolean dissect_quic_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /*
     * Since draft -11:
     * Flag (1 byte) + Version (4 bytes) + DCIL/SCIL (1 byte) +
     * Destination Connection ID (0/4..18 based on DCIL) +
     * Source Connection ID (0/4..18 based on SCIL) +
     * Payload length (1/2/4/8) + Packet number (4 bytes) + Payload.
     * (absolute minimum: 11 + payload)
     * (for Version Negotiation, payload len + PKN + payload is replaced by
     * Supported Version (multiple of 4 bytes.)
     *
     * Draft -10 and before:
     * Flag (1 byte) + Connection ID (8 bytes) + Version (4 bytes) + packet
     * number (4 bytes) + Payload.
     * (absolute minimum: 17 + payload)
     */
    conversation_t *conversation = NULL;
    int offset = 0;
    guint8 flags;
    gboolean is_quic = FALSE;

    /* Verify packet size  (Flag (1 byte) + Connection ID (8 bytes) + Version (4 bytes)) */
    if (tvb_captured_length(tvb) < 13)
    {
        return FALSE;
    }

    flags = tvb_get_guint8(tvb, offset);
    /* Check if long Packet is set */
    if((flags & 0x80) == 0) {
        return FALSE;
    }
    offset += 1;

    // check for draft QUIC version (for draft -11 and newer)
    is_quic = quic_draft_version(tvb_get_ntohl(tvb, offset)) >= 11;

    // check for draft QUIC version (after 8 byte CID) for draft -10 and older
    if (!is_quic && tvb_bytes_exist(tvb, offset + 8, 4)) {
        is_quic = is_quic_draft_max(tvb_get_ntohl(tvb, offset + 8), 10);
    }

    if (is_quic) {
        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, quic_handle);
        dissect_quic(tvb, pinfo, tree, data);
    }
    return is_quic;
}


/** Initialize QUIC dissection state for a new capture file. */
static void
quic_init(void)
{
    quic_connections = wmem_list_new(wmem_file_scope());
    quic_connections_count = 0;
    quic_initial_connections = wmem_map_new(wmem_file_scope(), quic_connection_hash, quic_connection_equal);
    quic_client_connections = wmem_map_new(wmem_file_scope(), quic_connection_hash, quic_connection_equal);
    quic_server_connections = wmem_map_new(wmem_file_scope(), quic_connection_hash, quic_connection_equal);
}

/** Release QUIC dissection state on closing a capture file. */
static void
quic_cleanup(void)
{
    wmem_list_foreach(quic_connections, quic_connection_destroy, NULL);
    quic_initial_connections = NULL;
    quic_client_connections = NULL;
    quic_server_connections = NULL;
}

void
proto_register_quic(void)
{
    expert_module_t *expert_quic;

    static hf_register_info hf[] = {
        { &hf_quic_connection_number,
          { "Connection Number", "quic.connection.number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Connection identifier within this capture file", HFILL }
        },

        { &hf_quic_header_form,
          { "Header Form", "quic.header_form",
            FT_UINT8, BASE_DEC, VALS(quic_short_long_header_vals), 0x80,
            "The most significant bit (0x80) of the first octet is set to 1 for long headers and 0 for short headers.", HFILL }
        },

        { &hf_quic_long_packet_type,
          { "Packet Type", "quic.long.packet_type",
            FT_UINT8, BASE_DEC, VALS(quic_long_packet_type_vals), 0x7F,
            "Long Header Packet Type", HFILL }
        },
        { &hf_quic_dcid,
          { "Destination Connection ID", "quic.dcid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_scid,
          { "Source Connection ID", "quic.scid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_dcil,
          { "Destination Connection ID Length", "quic.dcil",
            FT_UINT8, BASE_DEC, VALS(quic_cid_len_vals), 0xf0,
            "Destination Connection ID Length (for non-zero lengths, add 3 for actual length)", HFILL }
        },
        { &hf_quic_scil,
          { "Source Connection ID Length", "quic.scil",
            FT_UINT8, BASE_DEC, VALS(quic_cid_len_vals), 0x0f,
            "Source Connection ID Length (for non-zero lengths, add 3 for actual length)", HFILL }
        },
        { &hf_quic_payload_length,
          { "Payload Length", "quic.payload_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_packet_number,
          { "Packet Number", "quic.packet_number",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_packet_number_full,
          { "Packet Number (full)", "quic.packet_number_full",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Full packet number", HFILL }
        },
        { &hf_quic_version,
          { "Version", "quic.version",
            FT_UINT32, BASE_HEX, VALS(quic_version_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_quic_supported_version,
          { "Supported Version", "quic.supported_version",
            FT_UINT32, BASE_HEX, VALS(quic_version_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_quic_vn_unused, /* <= draft-07 */
          { "Unused", "quic.vn.unused",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_quic_short_ocid_flag,
          { "Omit Connection ID Flag", "quic.short.ocid_flag",
            FT_BOOLEAN, 8, NULL, SH_OCID,
            NULL, HFILL }
        },
        { &hf_quic_short_kp_flag_draft10,
          { "Key Phase Bit", "quic.short.kp_flag_draft10",
            FT_BOOLEAN, 8, NULL, SH_KP_10,
            NULL, HFILL }
        },
        { &hf_quic_short_kp_flag,
          { "Key Phase Bit", "quic.short.kp_flag",
            FT_BOOLEAN, 8, NULL, SH_KP,
            NULL, HFILL }
        },
        { &hf_quic_short_packet_type_draft10,
          { "Packet Type", "quic.short.packet_type_draft10",
            FT_UINT8, BASE_DEC, VALS(quic_short_packet_type_vals), SH_PT_10,
            "Short Header Packet Type", HFILL }
        },
        { &hf_quic_short_packet_type,
          { "Packet Type", "quic.short.packet_type",
            FT_UINT8, BASE_DEC, VALS(quic_short_packet_type_vals), SH_PT,
            "Short Header Packet Type", HFILL }
        },
        { &hf_quic_initial_payload,
          { "Initial Payload", "quic.initial_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_handshake_payload,
          { "Handshake Payload", "quic.handshake_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_retry_payload,
          { "Retry Payload", "quic.retry_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_protected_payload,
          { "Protected Payload", "quic.protected_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_frame,
          { "Frame", "quic.frame",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_frame_type,
          { "Frame Type", "quic.frame_type",
            FT_UINT8, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_frame_type_vals), 0x0,
            NULL, HFILL }
        },

        /* >= draft-08*/
        { &hf_quic_frame_type_stream_fin,
          { "Fin", "quic.frame_type.stream.fin",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_FIN,
            NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_len,
          { "Len(gth)", "quic.frame_type.stream.len",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_LEN,
            NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_off,
          { "Off(set)", "quic.frame_type.stream.off",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_OFF,
            NULL, HFILL }
        },

        { &hf_quic_stream_stream_id,
          { "Stream ID", "quic.stream.stream_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_stream_offset,
          { "Offset", "quic.stream.offset",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_stream_length,
          { "Length", "quic.stream.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_stream_data,
          { "Stream Data", "quic.stream_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_frame_type_ack_largest_acknowledged,
          { "Largest Acknowledged", "quic.frame_type.ack.largest_acknowledged",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Representing the largest packet number the peer is acknowledging in this packet", HFILL }
        },
        { &hf_quic_frame_type_ack_ack_delay,
          { "ACK Delay", "quic.frame_type.ack.ack_delay",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The time from when the largest acknowledged packet, as indicated in the Largest Acknowledged field, was received by this peer to when this ACK was sent", HFILL }
        },
        { &hf_quic_frame_type_ack_ack_block_count,
          { "ACK Block Count", "quic.frame_type.ack.ack_block_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The number of Additional ACK Block (and Gap) fields after the First ACK Block", HFILL }
        },
        { &hf_quic_frame_type_ack_fab,
          { "First ACK Block", "quic.frame_type.ack.fab",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicates the number of contiguous additional packets being acknowledged starting at the Largest Acknowledged", HFILL }
        },
        { &hf_quic_frame_type_ack_gap,
          { "Gap", "quic.frame_type.ack.gap",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicating the number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in the preceding ACK Block", HFILL }
        },
        { &hf_quic_frame_type_ack_ack_block,
          { "ACK Block", "quic.frame_type.ack.ack_block",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicating the number of contiguous acknowledged packets preceding the largest packet number, as determined by the preceding Gap", HFILL }
        },
        /* PATH_CHALLENGE */
        { &hf_quic_frame_type_path_challenge_data,
          { "Data", "quic.frame_type.path_challenge.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Arbitrary data that must be matched by a PATH_RESPONSE frame", HFILL }
        },
        /* PATH_RESPONSE */
        { &hf_quic_frame_type_path_response_data,
          { "Data", "quic.frame_type.path_response.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Arbitrary data that must match a PATH_CHALLENGE frame", HFILL }
        },
        /* PADDING */
        { &hf_quic_frame_type_padding_length,
          { "Padding Length", "quic.frame_type.padding.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_frame_type_padding,
          { "Padding", "quic.frame_type.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Must be zero", HFILL }
        },
        /* RST_STREAM */
        { &hf_quic_frame_type_rsts_stream_id,
            { "Stream ID", "quic.frame_type.rsts.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_rsts_application_error_code,
            { "Application Error code", "quic.frame_type.rsts.application_error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates why the stream is being closed", HFILL }
        },
        { &hf_quic_frame_type_rsts_final_offset,
            { "Final offset", "quic.frame_type.rsts.byte_offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of the end of data written on this stream", HFILL }
        },
        /* CONNECTION_CLOSE */
        { &hf_quic_frame_type_cc_error_code, /* >= draft07 */
            { "Error code", "quic.frame_type.cc.error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates the reason for closing this connection", HFILL }
        },
        { &hf_quic_frame_type_cc_reason_phrase_length,
            { "Reason phrase Length", "quic.frame_type.cc.reason_phrase.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_frame_type_cc_reason_phrase,
            { "Reason phrase", "quic.frame_type.cc.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A human-readable explanation for why the connection was closed", HFILL }
        },
        /* APPLICATION_CLOSE */
        { &hf_quic_frame_type_ac_error_code,
            { "Application Error code", "quic.frame_type.ac.error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates the reason for closing this application", HFILL }
        },
        { &hf_quic_frame_type_ac_reason_phrase_length,
            { "Reason phrase Length", "quic.frame_type.ac.reason_phrase.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_frame_type_ac_reason_phrase,
            { "Reason phrase", "quic.frame_type.ac.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A human-readable explanation for why the application was closed", HFILL }
        },
        /* MAX_DATA */
        { &hf_quic_frame_type_md_maximum_data,
            { "Maximum Data", "quic.frame_type.md.maximum_data",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the maximum amount of data that can be sent on the entire connection, in units of 1024 octets", HFILL }
        },
        /* MAX_STREAM_DATA */
        { &hf_quic_frame_type_msd_stream_id,
            { "Stream ID", "quic.frame_type.msd.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The stream ID of the stream that is affected", HFILL }
        },
        { &hf_quic_frame_type_msd_maximum_stream_data,
            { "Maximum Stream Data", "quic.frame_type.msd.maximum_stream_data",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the maximum amount of data that can be sent on the identified stream, in units of octets", HFILL }
        },
        /* MAX_STREAM_ID */
        { &hf_quic_frame_type_msi_stream_id,
            { "Stream ID", "quic.frame_type.msi.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "ID of the maximum peer-initiated stream ID for the connection", HFILL }
        },
        /* BLOCKED */
        { &hf_quic_frame_type_blocked_offset,
            { "Offset", "quic.frame_type.sb.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the connection-level offset at which the blocking occurred", HFILL }
        },
        /* STREAM_BLOCKED */
        { &hf_quic_frame_type_sb_stream_id,
            { "Stream ID", "quic.frame_type.sb.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the stream which is flow control blocked", HFILL }
        },
        { &hf_quic_frame_type_sb_offset,
            { "Offset", "quic.frame_type.sb.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the offset of the stream at which the blocking occurred", HFILL }
        },
        /* STREAM_ID_BLOCKED */
        { &hf_quic_frame_type_sib_stream_id,
            { "Stream ID", "quic.frame_type.sib.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the highest stream ID that the sender was permitted to open", HFILL }
        },
        /* NEW_CONNECTION_ID */
        { &hf_quic_frame_type_nci_sequence,
            { "Sequence", "quic.frame_type.nci.sequence",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Increases by 1 for each connection ID that is provided by the server", HFILL }
        },
        { &hf_quic_frame_type_nci_connection_id_length,
            { "Connection ID Length", "quic.frame_type.nci.connection_id.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_nci_connection_id,
            { "Connection ID", "quic.frame_type.nci.connection_id",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_nci_stateless_reset_token,
            { "Stateless Reset Token", "quic.frame_type.stateless_reset_token",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        /* STOP_SENDING */
        { &hf_quic_frame_type_ss_stream_id,
            { "Stream ID", "quic.frame_type.ss.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being ignored", HFILL }
        },
        { &hf_quic_frame_type_ss_application_error_code,
            { "Application Error code", "quic.frame_type.ss.application_error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates why the sender is ignoring the stream", HFILL }
        },

    };

    static gint *ett[] = {
        &ett_quic,
        &ett_quic_connection_info,
        &ett_quic_ft,
        &ett_quic_ftflags
    };

    static ei_register_info ei[] = {
        { &ei_quic_connection_unknown,
          { "quic.connection.unknown", PI_PROTOCOL, PI_NOTE,
            "Unknown QUIC connection. Missing Initial Packet or migrated connection?", EXPFILL }
        },
        { &ei_quic_ft_unknown,
          { "quic.ft.unknown", PI_UNDECODED, PI_NOTE,
            "Unknown Frame Type", EXPFILL }
        },
        { &ei_quic_decryption_failed,
          { "quic.decryption_failed", PI_DECRYPTION, PI_WARN,
            "Failed to decrypt handshake", EXPFILL }
        },
        { &ei_quic_protocol_violation,
          { "quic.protocol_violation", PI_PROTOCOL, PI_WARN,
            "Invalid data according to the protocol", EXPFILL }
        },
    };

    proto_quic = proto_register_protocol("QUIC IETF", "QUIC", "quic");

    proto_register_field_array(proto_quic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_quic = expert_register_protocol(proto_quic);
    expert_register_field_array(expert_quic, ei, array_length(ei));

    quic_handle = register_dissector("quic", dissect_quic, proto_quic);

    register_init_routine(quic_init);
    register_cleanup_routine(quic_cleanup);
}

void
proto_reg_handoff_quic(void)
{
    ssl_handle = find_dissector("ssl");
    dissector_add_uint_with_preference("udp.port", 0, quic_handle);
    heur_dissector_add("udp", dissect_quic_heur, "QUIC", "quic", proto_quic, HEURISTIC_ENABLE);
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
