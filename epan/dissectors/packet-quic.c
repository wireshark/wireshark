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
 * See https://quicwg.org
 * https://tools.ietf.org/html/draft-ietf-quic-transport-29
 * https://tools.ietf.org/html/draft-ietf-quic-tls-29
 * https://tools.ietf.org/html/draft-ietf-quic-invariants-09
 *
 * Extension:
 * https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03
 * https://tools.ietf.org/html/draft-pauly-quic-datagram-05
 * https://tools.ietf.org/html/draft-huitema-quic-ts-02
 * https://tools.ietf.org/html/draft-iyengar-quic-delayed-ack-00
 *
 * Currently supported QUIC version(s): draft-21, draft-22, draft-23, draft-24,
 * draft-25, draft-26, draft-27, draft-28, draft-29.
 * For a table of supported QUIC versions per Wireshark version, see
 * https://github.com/quicwg/base-drafts/wiki/Tools#wireshark
 *
 * Decryption is supported via TLS 1.3 secrets in the "TLS Key Log File",
 * configured either at the TLS Protocol preferences, or embedded in a pcapng
 * file. Sample captures and secrets can be found at:
 * https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13881
 *
 * Limitations:
 * - STREAM offsets larger than 32-bit are unsupported.
 * - STREAM with sizes larger than 32 bit are unsupported. STREAM sizes can be
 *   up to 62 bit in QUIC, but the TVB and reassembly API is limited to 32 bit.
 * - Out-of-order and overlapping STREAM frame data is not handled.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include "packet-tls-utils.h"
#include "packet-tls.h"
#include "packet-tcp.h"     /* used for STREAM reassembly. */
#include "packet-quic.h"
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <wsutil/pint.h>

#include <epan/tap.h>
#include <epan/follow.h>
#include <epan/addr_resolv.h>

/* Prototypes */
void proto_reg_handoff_quic(void);
void proto_register_quic(void);

static int quic_follow_tap = -1;

/* Initialize the protocol and registered fields */
static int proto_quic = -1;
static int hf_quic_connection_number = -1;
static int hf_quic_packet_length = -1;
static int hf_quic_header_form = -1;
static int hf_quic_long_packet_type = -1;
static int hf_quic_long_reserved = -1;
static int hf_quic_packet_number_length = -1;
static int hf_quic_dcid = -1;
static int hf_quic_scid = -1;
static int hf_quic_dcil = -1;
static int hf_quic_scil = -1;
static int hf_quic_token_length = -1;
static int hf_quic_token = -1;
static int hf_quic_length = -1;
static int hf_quic_packet_number = -1;
static int hf_quic_version = -1;
static int hf_quic_supported_version = -1;
static int hf_quic_vn_unused = -1;
static int hf_quic_short = -1;
static int hf_quic_fixed_bit = -1;
static int hf_quic_spin_bit = -1;
static int hf_quic_short_reserved = -1;
static int hf_quic_key_phase = -1;
static int hf_quic_payload = -1;
static int hf_quic_protected_payload = -1;
static int hf_quic_remaining_payload = -1;
static int hf_quic_odcil = -1;
static int hf_quic_odcid = -1;
static int hf_quic_retry_token = -1;
static int hf_quic_retry_integrity_tag = -1;

static int hf_quic_frame = -1;
static int hf_quic_frame_type = -1;

static int hf_quic_padding_length = -1;
static int hf_quic_ack_largest_acknowledged = -1;
static int hf_quic_ack_ack_delay = -1;
static int hf_quic_ack_ack_range_count = -1;
static int hf_quic_ack_first_ack_range = -1;
static int hf_quic_ack_gap = -1;
static int hf_quic_ack_ack_range = -1;
static int hf_quic_ack_ect0_count = -1;
static int hf_quic_ack_ect1_count = -1;
static int hf_quic_ack_ecn_ce_count = -1;
static int hf_quic_rsts_stream_id = -1;
static int hf_quic_rsts_application_error_code = -1;
static int hf_quic_rsts_final_size = -1;
static int hf_quic_ss_stream_id = -1;
static int hf_quic_ss_application_error_code = -1;
static int hf_quic_crypto_offset = -1;
static int hf_quic_crypto_length = -1;
static int hf_quic_crypto_crypto_data = -1;
static int hf_quic_nt_length = -1;
static int hf_quic_nt_token = -1;
static int hf_quic_stream_fin = -1;
static int hf_quic_stream_len = -1;
static int hf_quic_stream_off = -1;
static int hf_quic_stream_stream_id = -1;
static int hf_quic_stream_offset = -1;
static int hf_quic_stream_length = -1;
static int hf_quic_stream_data = -1;
static int hf_quic_md_maximum_data = -1;
static int hf_quic_msd_stream_id = -1;
static int hf_quic_msd_maximum_stream_data = -1;
static int hf_quic_ms_max_streams = -1;
static int hf_quic_db_stream_data_limit = -1;
static int hf_quic_sdb_stream_id = -1;
static int hf_quic_sdb_stream_data_limit = -1;
static int hf_quic_sb_stream_limit = -1;
static int hf_quic_nci_retire_prior_to = -1;
static int hf_quic_nci_sequence = -1;
static int hf_quic_nci_connection_id_length = -1;
static int hf_quic_nci_connection_id = -1;
static int hf_quic_nci_stateless_reset_token = -1;
static int hf_quic_rci_sequence = -1;
static int hf_quic_path_challenge_data = -1;
static int hf_quic_path_response_data = -1;
static int hf_quic_cc_error_code = -1;
static int hf_quic_cc_error_code_app = -1;
static int hf_quic_cc_error_code_tls_alert = -1;
static int hf_quic_cc_frame_type = -1;
static int hf_quic_cc_reason_phrase_length = -1;
static int hf_quic_cc_reason_phrase = -1;
static int hf_quic_dg_length = -1;
static int hf_quic_dg = -1;
static int hf_quic_af_sequence_number = -1;
static int hf_quic_af_packet_tolerance = -1;
static int hf_quic_af_update_max_ack_delay = -1;
static int hf_quic_ts = -1;
static int hf_quic_reassembled_in = -1;
static int hf_quic_reassembled_length = -1;
static int hf_quic_reassembled_data = -1;
static int hf_quic_fragments = -1;
static int hf_quic_fragment = -1;
static int hf_quic_fragment_overlap = -1;
static int hf_quic_fragment_overlap_conflict = -1;
static int hf_quic_fragment_multiple_tails = -1;
static int hf_quic_fragment_too_long_fragment = -1;
static int hf_quic_fragment_error = -1;
static int hf_quic_fragment_count = -1;

static expert_field ei_quic_connection_unknown = EI_INIT;
static expert_field ei_quic_ft_unknown = EI_INIT;
static expert_field ei_quic_decryption_failed = EI_INIT;
static expert_field ei_quic_protocol_violation = EI_INIT;
static expert_field ei_quic_bad_retry = EI_INIT;

static gint ett_quic = -1;
static gint ett_quic_short_header = -1;
static gint ett_quic_connection_info = -1;
static gint ett_quic_ft = -1;
static gint ett_quic_ftflags = -1;
static gint ett_quic_fragments = -1;
static gint ett_quic_fragment = -1;

static dissector_handle_t quic_handle;
static dissector_handle_t tls13_handshake_handle;

static dissector_table_t quic_proto_dissector_table;

/* Fields for showing reassembly results for fragments of QUIC stream data. */
static const fragment_items quic_stream_fragment_items = {
    &ett_quic_fragment,
    &ett_quic_fragments,
    &hf_quic_fragments,
    &hf_quic_fragment,
    &hf_quic_fragment_overlap,
    &hf_quic_fragment_overlap_conflict,
    &hf_quic_fragment_multiple_tails,
    &hf_quic_fragment_too_long_fragment,
    &hf_quic_fragment_error,
    &hf_quic_fragment_count,
    &hf_quic_reassembled_in,
    &hf_quic_reassembled_length,
    &hf_quic_reassembled_data,
    "Fragments"
};

/*
 * PROTECTED PAYLOAD DECRYPTION (done in first pass)
 *
 * Long packet types always use a single cipher depending on packet type.
 * Short packet types always use 1-RTT secrets for packet protection (pp).
 *
 * Considerations:
 * - QUIC packets might appear out-of-order (short packets before handshake
 *   message is captured), lost or retransmitted/duplicated.
 * - During live capture, keys might not be immediately be available. 1-RTT
 *   client keys will be ready while client proceses Server Hello (Handshake).
 *   1-RTT server keys will be ready while server creates Handshake message in
 *   response to Initial Handshake.
 * - So delay cipher creation until first short packet is received.
 *
 * Required input from TLS dissector: TLS-Exporter 0-RTT/1-RTT secrets and
 * cipher/hash algorithms.
 *
 * QUIC payload decryption requires proper reconstruction of the packet number
 * which requires proper header decryption. The different states are:
 *
 *  Packet type             Packet number space     Secrets
 *  Long: Initial           Initial                 Initial secrets
 *  Long: Handshake         Handshake               Handshake
 *  Long: 0-RTT             0/1-RTT (appdata)       0-RTT
 *  Short header            0/1-RTT (appdata)       1-RTT (KP0 / KP1)
 *
 * Important to note is that Short Header decryption requires TWO ciphers (one
 * for each key phase), but that header protection uses only KP0. Total state
 * needed for each peer (client and server):
 * - 3 packet number spaces: Initial, Handshake, 0/1-RTT (appdata).
 * - 4 header protection ciphers: initial, 0-RTT, HS, 1-RTT.
 * - 5 payload protection ciphers: initial, 0-RTT, HS, 1-RTT (KP0), 1-RTT (KP1).
 */

typedef struct quic_decrypt_result {
    const guchar   *error;      /**< Error message or NULL for success. */
    const guint8   *data;       /**< Decrypted result on success (file-scoped). */
    guint           data_len;   /**< Size of decrypted data. */
} quic_decrypt_result_t;

/*
 * Although the QUIC SCID/DCID length field can store at most 255, v1 limits the
 * CID length to 20.
 */
#define QUIC_MAX_CID_LENGTH  20

typedef struct quic_cid {
    guint8      len;
    guint8      cid[QUIC_MAX_CID_LENGTH];
} quic_cid_t;

/** QUIC decryption context. */
typedef struct quic_cipher {
    // TODO hp_cipher does not change after KeyUpdate, but is still tied to the
    //      current encryption level (initial, 0rtt, handshake, appdata).
    //      Maybe move this into quic_info_data (2x) and quic_pp_state?
    //      See https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4
    gcry_cipher_hd_t    hp_cipher;  /**< Header protection cipher. */
    gcry_cipher_hd_t    pp_cipher;  /**< Packet protection cipher. */
    guint8              pp_iv[TLS13_AEAD_NONCE_LENGTH];
} quic_cipher;

/**
 * Packet protection state for an endpoint.
 */
typedef struct quic_pp_state {
    guint8         *next_secret;    /**< Next application traffic secret. */
    quic_cipher     cipher[2];      /**< Cipher for Key Phase 0/1 */
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
 * Per-STREAM state, identified by QUIC Stream ID.
 *
 * Assume that every QUIC Short Header packet has no STREAM frames that overlap
 * each other in the same QUIC packet (identified by "frame_num"). Thus, the
 * Stream ID and offset uniquely identifies the STREAM Frame info in per packet.
 */
typedef struct _quic_stream_state {
    guint64         stream_id;
    wmem_tree_t    *multisegment_pdus;
    void           *subdissector_private;
} quic_stream_state;

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
    gboolean        client_dcid_set : 1; /**< Set to 1 if client_dcid_initial is set. */
    int             hash_algo;      /**< Libgcrypt hash algorithm for key derivation. */
    int             cipher_algo;    /**< Cipher algorithm for packet number and packet encryption. */
    int             cipher_mode;    /**< Cipher mode for packet encryption. */
    quic_cipher     client_initial_cipher;
    quic_cipher     server_initial_cipher;
    quic_cipher     client_0rtt_cipher;
    quic_cipher     client_handshake_cipher;
    quic_cipher     server_handshake_cipher;
    quic_pp_state_t client_pp;
    quic_pp_state_t server_pp;
    guint64         max_client_pkn[3];  /**< Packet number spaces for Initial, Handshake and appdata. */
    guint64         max_server_pkn[3];
    quic_cid_item_t client_cids;    /**< SCID of client from first Initial Packet. */
    quic_cid_item_t server_cids;    /**< SCID of server from first Retry/Handshake. */
    quic_cid_t      client_dcid_initial;    /**< DCID from Initial Packet. */
    dissector_handle_t app_handle;  /**< Application protocol handle (NULL if unknown). */
    wmem_map_t     *client_streams; /**< Map from Stream ID -> STREAM info (guint64 -> quic_stream_state), sent by the client. */
    wmem_map_t     *server_streams; /**< Map from Stream ID -> STREAM info (guint64 -> quic_stream_state), sent by the server. */
} quic_info_data_t;

/** Per-packet information about QUIC, populated on the first pass. */
struct quic_packet_info {
    struct quic_packet_info *next;
    guint64                 packet_number;  /**< Reconstructed full packet number. */
    quic_decrypt_result_t   decryption;
    guint8                  pkn_len;        /**< Length of PKN (1/2/3/4) or unknown (0). */
    guint8                  first_byte;     /**< Decrypted flag byte, valid only if pkn_len is non-zero. */
    gboolean                retry_integrity_failure : 1;
    gboolean                retry_integrity_success : 1;
};
typedef struct quic_packet_info quic_packet_info_t;

/** A UDP datagram contains one or more QUIC packets. */
typedef struct quic_datagram {
    quic_info_data_t       *conn;
    quic_packet_info_t      first_packet;
    gboolean                from_server : 1;
} quic_datagram;

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
static guint32 quic_cid_lengths;        /* Bitmap of CID lengths. */
static guint quic_connections_count;

/* Returns the QUIC draft version or 0 if not applicable. */
static inline guint8 quic_draft_version(guint32 version) {
    if ((version >> 8) == 0xff0000) {
       return (guint8) version;
    }
    /* Facebook mvfst, based on draft -22. */
    if (version == 0xfaceb001) {
        return 22;
    }
    /* Facebook mvfst, based on draft -27. */
    if (version == 0xfaceb002) {
        return 27;
    }
    return 0;
}

static inline gboolean is_quic_draft_max(guint32 version, guint8 max_version) {
    guint8 draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

const value_string quic_version_vals[] = {
    { 0x00000000, "Version Negotiation" },
    { 0x51303434, "Google Q044" },
    { 0x51303530, "Google Q050 (draft-27)" },
    { 0xfaceb001, "Facebook mvfst (draft-22)" },
    { 0xfaceb002, "Facebook mvfst (draft-27)" },
    { 0xff000004, "draft-04" },
    { 0xff000005, "draft-05" },
    { 0xff000006, "draft-06" },
    { 0xff000007, "draft-07" },
    { 0xff000008, "draft-08" },
    { 0xff000009, "draft-09" },
    { 0xff00000a, "draft-10" },
    { 0xff00000b, "draft-11" },
    { 0xff00000c, "draft-12" },
    { 0xff00000d, "draft-13" },
    { 0xff00000e, "draft-14" },
    { 0xff00000f, "draft-15" },
    { 0xff000010, "draft-16" },
    { 0xff000011, "draft-17" },
    { 0xff000012, "draft-18" },
    { 0xff000013, "draft-19" },
    { 0xff000014, "draft-20" },
    { 0xff000015, "draft-21" },
    { 0xff000016, "draft-22" },
    { 0xff000017, "draft-23" },
    { 0xff000018, "draft-24" },
    { 0xff000019, "draft-25" },
    { 0xff00001a, "draft-26" },
    { 0xff00001b, "draft-27" },
    { 0xff00001c, "draft-28" },
    { 0xff00001d, "draft-29" },
    { 0, NULL }
};

static const value_string quic_short_long_header_vals[] = {
    { 0, "Short Header" },
    { 1, "Long Header" },
    { 0, NULL }
};

#define SH_KP       0x04

#define QUIC_LPT_INITIAL    0x0
#define QUIC_LPT_0RTT       0x1
#define QUIC_LPT_HANDSHAKE  0x2
#define QUIC_LPT_RETRY      0x3
#define QUIC_SHORT_PACKET   0xff    /* dummy value that is definitely not LPT */

static const value_string quic_long_packet_type_vals[] = {
    { QUIC_LPT_INITIAL, "Initial" },
    { QUIC_LPT_RETRY, "Retry" },
    { QUIC_LPT_HANDSHAKE, "Handshake" },
    { QUIC_LPT_0RTT, "0-RTT" },
    { 0, NULL }
};

/* https://github.com/quicwg/base-drafts/wiki/Temporary-IANA-Registry#quic-frame-types */
#define FT_PADDING              0x00
#define FT_PING                 0x01
#define FT_ACK                  0x02
#define FT_ACK_ECN              0x03
#define FT_RESET_STREAM         0x04
#define FT_STOP_SENDING         0x05
#define FT_CRYPTO               0x06
#define FT_NEW_TOKEN            0x07
#define FT_STREAM_8             0x08
#define FT_STREAM_9             0x09
#define FT_STREAM_A             0x0a
#define FT_STREAM_B             0x0b
#define FT_STREAM_C             0x0c
#define FT_STREAM_D             0x0d
#define FT_STREAM_E             0x0e
#define FT_STREAM_F             0x0f
#define FT_MAX_DATA             0x10
#define FT_MAX_STREAM_DATA      0x11
#define FT_MAX_STREAMS_BIDI     0x12
#define FT_MAX_STREAMS_UNI      0x13
#define FT_DATA_BLOCKED         0x14
#define FT_STREAM_DATA_BLOCKED  0x15
#define FT_STREAMS_BLOCKED_BIDI 0x16
#define FT_STREAMS_BLOCKED_UNI  0x17
#define FT_NEW_CONNECTION_ID    0x18
#define FT_RETIRE_CONNECTION_ID 0x19
#define FT_PATH_CHALLENGE       0x1a
#define FT_PATH_RESPONSE        0x1b
#define FT_CONNECTION_CLOSE_TPT 0x1c
#define FT_CONNECTION_CLOSE_APP 0x1d
#define FT_HANDSHAKE_DONE       0x1e
#define FT_DATAGRAM             0x30
#define FT_DATAGRAM_LENGTH      0x31
#define FT_ACK_FREQUENCY        0xAF
#define FT_TIME_STAMP           0x02F5

static const range_string quic_frame_type_vals[] = {
    { 0x00, 0x00,   "PADDING" },
    { 0x01, 0x01,   "PING" },
    { 0x02, 0x03,   "ACK" },
    { 0x04, 0x04,   "RESET_STREAM" },
    { 0x05, 0x05,   "STOP_SENDING" },
    { 0x06, 0x06,   "CRYPTO" },
    { 0x07, 0x07,   "NEW_TOKEN" },
    { 0x08, 0x0f,   "STREAM" },
    { 0x10, 0x10,   "MAX_DATA" },
    { 0x11, 0x11,   "MAX_STREAM_DATA" },
    { 0x12, 0x12,   "MAX_STREAMS (BIDI)" },
    { 0x13, 0x13,   "MAX_STREAMS (UNI)" },
    { 0x14, 0x14,   "DATA_BLOCKED" },
    { 0x15, 0x15,   "STREAM_DATA_BLOCKED" },
    { 0x16, 0x16,   "STREAMS_BLOCKED (BIDI)" },
    { 0x16, 0x17,   "STREAMS_BLOCKED (UNI)" },
    { 0x18, 0x18,   "NEW_CONNECTION_ID" },
    { 0x19, 0x19,   "RETIRE_CONNECTION_ID" },
    { 0x1a, 0x1a,   "PATH_CHALLENGE" },
    { 0x1b, 0x1b,   "PATH_RESPONSE" },
    { 0x1c, 0x1c,   "CONNECTION_CLOSE (Transport)" },
    { 0x1d, 0x1d,   "CONNECTION_CLOSE (Application)" },
    { 0x1e, 0x1e,   "HANDSHAKE_DONE" },
    { 0x30, 0x31,   "DATAGRAM" },
    { 0xAF, 0xAF,   "ACK_FREQUENCY" },
    { 0x02F5, 0x02F5, "TIME_STAMP" },
    { 0,    0,        NULL },
};


/* >= draft-08 */
#define FTFLAGS_STREAM_FIN 0x01
#define FTFLAGS_STREAM_LEN 0x02
#define FTFLAGS_STREAM_OFF 0x04

static const range_string quic_transport_error_code_vals[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Review policies. */
    { 0x0000, 0x0000, "NO_ERROR" },
    { 0x0001, 0x0001, "INTERNAL_ERROR" },
    { 0x0002, 0x0002, "CONNECTION_REFUSED" },
    { 0x0003, 0x0003, "FLOW_CONTROL_ERROR" },
    { 0x0004, 0x0004, "STREAM_ID_ERROR" },
    { 0x0005, 0x0005, "STREAM_STATE_ERROR" },
    { 0x0006, 0x0006, "FINAL_SIZE_ERROR" },
    { 0x0007, 0x0007, "FRAME_ENCODING_ERROR" },
    { 0x0008, 0x0008, "TRANSPORT_PARAMETER_ERROR" },
    { 0x0009, 0x0009, "CONNECTION_ID_LIMIT_ERROR" },
    { 0x000A, 0x000A, "PROTOCOL_VIOLATION" },
    { 0x000B, 0x000B, "INVALID_TOKEN" },
    { 0x000C, 0x000C, "APPLICATION_ERROR" },
    { 0x000D, 0x000D, "CRYPTO_BUFFER_EXCEEDED" },
    { 0x000E, 0x000E, "KEY_UPDATE_ERROR" },
    { 0x0100, 0x01FF, "CRYPTO_ERROR" },
    /* 0x40 - 0x3fff Assigned via Specification Required policy. */
    { 0, 0, NULL }
};

static const value_string quic_packet_number_lengths[] = {
    { 0, "1 bytes" },
    { 1, "2 bytes" },
    { 2, "3 bytes" },
    { 3, "4 bytes" },
    { 0, NULL }
};


static void
quic_extract_header(tvbuff_t *tvb, guint8 *long_packet_type, guint32 *version,
                    quic_cid_t *dcid, quic_cid_t *scid);


static void
quic_cipher_reset(quic_cipher *cipher)
{
    gcry_cipher_close(cipher->hp_cipher);
    gcry_cipher_close(cipher->pp_cipher);
    memset(cipher, 0, sizeof(*cipher));
}

#ifdef HAVE_LIBGCRYPT_AEAD
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
 * Given a header protection cipher, a buffer and the packet number offset,
 * return the unmasked first byte and packet number.
 */
static gboolean
quic_decrypt_header(tvbuff_t *tvb, guint pn_offset, gcry_cipher_hd_t hp_cipher, int hp_cipher_algo,
                    guint8 *first_byte, guint32 *pn)
{
    gcry_cipher_hd_t h = hp_cipher;
    if (!hp_cipher) {
        // need to know the cipher.
        return FALSE;
    }

    // Sample is always 16 bytes and starts after PKN (assuming length 4).
    // https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.2
    guint8 sample[16];
    tvb_memcpy(tvb, sample, pn_offset + 4, 16);

    guint8  mask[5] = { 0 };
    switch (hp_cipher_algo) {
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES256:
        /* Encrypt in-place with AES-ECB and extract the mask. */
        if (gcry_cipher_encrypt(h, sample, sizeof(sample), NULL, 0)) {
            return FALSE;
        }
        memcpy(mask, sample, sizeof(mask));
        break;
#ifdef HAVE_LIBGCRYPT_CHACHA20
    case GCRY_CIPHER_CHACHA20:
        /* If Gcrypt receives a 16 byte IV, it will assume the buffer to be
         * counter || nonce (in little endian), as desired. */
        if (gcry_cipher_setiv(h, sample, 16)) {
            return FALSE;
        }
        /* Apply ChaCha20, encrypt in-place five zero bytes. */
        if (gcry_cipher_encrypt(h, mask, sizeof(mask), NULL, 0)) {
            return FALSE;
        }
        break;
#endif /* HAVE_LIBGCRYPT_CHACHA20 */
    default:
        return FALSE;
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.1
    guint8 packet0 = tvb_get_guint8(tvb, 0);
    if ((packet0 & 0x80) == 0x80) {
        // Long header: 4 bits masked
        packet0 ^= mask[0] & 0x0f;
    } else {
        // Short header: 5 bits masked
        packet0 ^= mask[0] & 0x1f;
    }
    guint pkn_len = (packet0 & 0x03) + 1;

    guint8 pkn_bytes[4];
    tvb_memcpy(tvb, pkn_bytes, pn_offset, pkn_len);
    guint32 pkt_pkn = 0;
    for (guint i = 0; i < pkn_len; i++) {
        pkt_pkn |= (pkn_bytes[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
    }
    *first_byte = packet0;
    *pn = pkt_pkn;
    return TRUE;
}

/**
 * Retrieve the maximum valid packet number space for a peer.
 */
static guint64 *
quic_max_packet_number(quic_info_data_t *quic_info, gboolean from_server, guint8 first_byte)
{
    int pkn_space;
    if ((first_byte & 0x80) && (first_byte & 0x30) >> 4 == QUIC_LPT_INITIAL) {
        // Long header, Initial
        pkn_space = 0;
    } else if ((first_byte & 0x80) && (first_byte & 0x30) >> 4 == QUIC_LPT_HANDSHAKE) {
        // Long header, Handshake
        pkn_space = 1;
    } else {
        // Long header (0-RTT) or Short Header (1-RTT appdata).
        pkn_space = 2;
    }
    if (from_server) {
        return &quic_info->max_server_pkn[pkn_space];
    } else {
        return &quic_info->max_client_pkn[pkn_space];
    }
}

/**
 * Calculate the full packet number and store it for later use.
 */
static void
quic_set_full_packet_number(quic_info_data_t *quic_info, quic_packet_info_t *quic_packet,
                            gboolean from_server, guint8 first_byte, guint32 pkn32)
{
    guint       pkn_len = (first_byte & 3) + 1;
    guint64     pkn_full;
    guint64     max_pn = *quic_max_packet_number(quic_info, from_server, first_byte);

    /* Sequential first pass, try to reconstruct full packet number. */
    pkn_full = quic_pkt_adjust_pkt_num(max_pn, pkn32, 8 * pkn_len);
    quic_packet->pkn_len = pkn_len;
    quic_packet->packet_number = pkn_full;
}
#endif /* !HAVE_LIBGCRYPT_AEAD */

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

static void
quic_cids_insert(quic_cid_t *cid, quic_info_data_t *conn, gboolean from_server)
{
    wmem_map_t *connections = from_server ? quic_server_connections : quic_client_connections;
    // Replace any previous CID key with the new one.
    wmem_map_remove(connections, cid);
    wmem_map_insert(connections, cid, conn);
    G_STATIC_ASSERT(QUIC_MAX_CID_LENGTH <= 8 * sizeof(quic_cid_lengths));
    quic_cid_lengths |= (1ULL << cid->len);
}

static inline gboolean
quic_cids_is_known_length(const quic_cid_t *cid)
{
    return (quic_cid_lengths & (1ULL << cid->len)) != 0;
}

/**
 * Returns the QUIC connection for the current UDP stream. This may return NULL
 * after connection migration if the new UDP association was not properly linked
 * via a match based on the Connection ID.
 */
static quic_info_data_t *
quic_connection_from_conv(packet_info *pinfo)
{
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);
    if (conv) {
        return (quic_info_data_t *)conversation_get_proto_data(conv, proto_quic);
    }
    return NULL;
}

/**
 * Tries to lookup a matching connection (Connection ID is optional).
 * If connection is found, "from_server" is set accordingly.
 */
static quic_info_data_t *
quic_connection_find_dcid(packet_info *pinfo, const quic_cid_t *dcid, gboolean *from_server)
{
    /* https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-5.2
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
        // Optimization: avoid lookup for invalid CIDs.
        if (!quic_cids_is_known_length(dcid)) {
            return NULL;
        }
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
        conn = quic_connection_from_conv(pinfo);
        if (conn) {
            check_ports = TRUE;
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

    if (long_packet_type == QUIC_LPT_0RTT && dcid->len > 0) {
        // The 0-RTT packet always matches the SCID/DCID of the Client Initial
        conn = (quic_info_data_t *) wmem_map_lookup(quic_initial_connections, dcid);
        *from_server = FALSE;
    } else {
        // Find a connection for Handshake and Server Initial packets by
        // matching their DCID against the SCIDs of the original Initial packets
        // from the peer. For Client Initial packets, match DCID of the first
        // Client Initial (these may contain ACK frames).
        conn = quic_connection_find_dcid(pinfo, dcid, from_server);
        if (long_packet_type == QUIC_LPT_INITIAL && conn && !*from_server && dcid->len > 0 &&
            memcmp(dcid, &conn->client_dcid_initial, sizeof(quic_cid_t)) &&
            !quic_cids_has_match(&conn->server_cids, dcid)) {
            // If the Initial Packet is from the client, it must either match
            // the DCID from the first Client Initial, or the DCID that was
            // assigned by the server. Otherwise this must be considered a fresh
            // Client Initial, for example after the Version Negotiation packet,
            // and the connection must be cleared to avoid decryption failure.
            conn = NULL;
        }
    }

    if (!is_long_packet && !conn) {
        // For short packets, first try to find a match based on the address.
        conn = quic_connection_find_dcid(pinfo, NULL, from_server);
        if (conn) {
            if ((*from_server && !quic_cids_has_match(&conn->client_cids, dcid)) ||
                (!*from_server && !quic_cids_has_match(&conn->server_cids, dcid))) {
                // Connection does not match packet.
                conn = NULL;
            }
        }

        // No match found so far, potentially connection migration. Length of
        // actual DCID is unknown, so just keep decrementing until found.
        while (!conn && dcid->len > 1) {
            dcid->len--;
            if (quic_cids_is_known_length(dcid)) {
                conn = quic_connection_find_dcid(pinfo, dcid, from_server);
            }
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
quic_connection_create(packet_info *pinfo, guint32 version)
{
    quic_info_data_t *conn = NULL;

    conn = wmem_new0(wmem_file_scope(), quic_info_data_t);
    wmem_list_append(quic_connections, conn);
    conn->number = quic_connections_count++;
    conn->version = version;
    copy_address_wmem(wmem_file_scope(), &conn->server_address, &pinfo->dst);
    conn->server_port = pinfo->destport;

    // For faster lookups without having to check DCID
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_add_proto_data(conv, proto_quic, conn);

    return conn;
}

/** Update client/server connection identifiers, assuming the information is
 * from the Client Initial. */
static void
quic_connection_update_initial(quic_info_data_t *conn, const quic_cid_t *scid, const quic_cid_t *dcid)
{
    // Key connection by Client CID (if provided).
    if (scid->len) {
        memcpy(&conn->client_cids.data, scid, sizeof(quic_cid_t));
        quic_cids_insert(&conn->client_cids.data, conn, FALSE);
    }
    if (dcid->len > 0) {
        // According to the spec, the Initial Packet DCID MUST be at least 8
        // bytes, but non-conforming implementations could exist.
        memcpy(&conn->client_dcid_initial, dcid, sizeof(quic_cid_t));
        wmem_map_insert(quic_initial_connections, &conn->client_dcid_initial, conn);
        conn->client_dcid_set = TRUE;
    }
}

#ifdef HAVE_LIBGCRYPT_AEAD
/**
 * Use the new CID as additional identifier for the specified connection and
 * remember it for connection tracking.
 */
static void
quic_connection_add_cid(quic_info_data_t *conn, const quic_cid_t *new_cid, gboolean from_server)
{
    DISSECTOR_ASSERT(new_cid->len > 0);
    quic_cid_item_t *items = from_server ? &conn->server_cids : &conn->client_cids;

    if (quic_cids_has_match(items, new_cid)) {
        // CID is already known for this connection.
        return;
    }

    // Insert new CID right after the first known CID (the very first CID cannot
    // be overwritten since it might be used as key somewhere else).
    quic_cid_item_t *new_item = wmem_new0(wmem_file_scope(), quic_cid_item_t);
    new_item->data = *new_cid;
    new_item->next = items->next;
    items->next = new_item;

    quic_cids_insert(&new_item->data, conn, from_server);
}
#endif

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
        if (!from_server) {
            if (!conn) {
                // The first Initial Packet from the client creates a new connection.
                *conn_p = quic_connection_create(pinfo, version);
                quic_connection_update_initial(*conn_p, scid, dcid);
            } else if (!conn->client_dcid_set && dcid->len) {
                // If this client Initial Packet responds to a Retry Packet,
                // then remember the new client SCID and initial DCID for the
                // new Initial cipher and clear the first server CID such that
                // the next server Initial Packet can link the connection with
                // that new SCID.
                quic_connection_update_initial(conn, scid, dcid);
                wmem_map_remove(quic_server_connections, &conn->server_cids.data);
                memset(&conn->server_cids, 0, sizeof(quic_cid_t));
            }
            break;
        }
        /* fallthrough */
    case QUIC_LPT_RETRY:
    case QUIC_LPT_HANDSHAKE:
        // Remember CID from first server Retry/Handshake packet
        // (or from the first server Initial packet, since draft -13).
        if (from_server && conn) {
            if (long_packet_type == QUIC_LPT_RETRY) {
                // Retry Packet: the next Initial Packet from the
                // client should start a new cryptographic handshake. Erase the
                // current "Initial DCID" such that the next client Initial
                // packet populates the new value.
                wmem_map_remove(quic_initial_connections, &conn->client_dcid_initial);
                memset(&conn->client_dcid_initial, 0, sizeof(quic_cid_t));
                conn->client_dcid_set = FALSE;
            }
            if (conn->server_cids.data.len == 0 && scid->len) {
                memcpy(&conn->server_cids.data, scid, sizeof(quic_cid_t));
                quic_cids_insert(&conn->server_cids.data, conn, TRUE);
            }
        }
        break;
    }
}

static void
quic_connection_destroy(gpointer data, gpointer user_data _U_)
{
    quic_info_data_t *conn = (quic_info_data_t *)data;
    quic_cipher_reset(&conn->client_initial_cipher);
    quic_cipher_reset(&conn->server_initial_cipher);
    quic_cipher_reset(&conn->client_handshake_cipher);
    quic_cipher_reset(&conn->server_handshake_cipher);

    for (int i = 0; i < 2; i++) {
        quic_cipher_reset(&conn->client_pp.cipher[i]);
        quic_cipher_reset(&conn->server_pp.cipher[i]);
    }
}
/* QUIC Connection tracking. }}} */

/* QUIC Streams tracking and reassembly. {{{ */
static reassembly_table quic_reassembly_table;

#ifdef HAVE_LIBGCRYPT_AEAD
/** Perform sequence analysis for STREAM frames. */
static quic_stream_state *
quic_get_stream_state(packet_info *pinfo, quic_info_data_t *quic_info, gboolean from_server, guint64 stream_id)
{
    wmem_map_t **streams_p = from_server ? &quic_info->server_streams : &quic_info->client_streams;
    wmem_map_t *streams = *streams_p;
    quic_stream_state *stream = NULL;

    if (PINFO_FD_VISITED(pinfo)) {
        DISSECTOR_ASSERT(streams);
        stream = (quic_stream_state *)wmem_map_lookup(streams, &stream_id);
        DISSECTOR_ASSERT(stream);
        return stream;
    }

    // Initialize per-connection and per-stream state.
    if (!streams) {
        streams = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
        *streams_p = streams;
    } else {
        stream = (quic_stream_state *)wmem_map_lookup(streams, &stream_id);
    }
    if (!stream) {
        stream = wmem_new0(wmem_file_scope(), quic_stream_state);
        stream->stream_id = stream_id;
        stream->multisegment_pdus = wmem_tree_new(wmem_file_scope());
        wmem_map_insert(streams, &stream->stream_id, stream);
    }
    return stream;
}

static void
process_quic_stream(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                    quic_info_data_t *quic_info, quic_stream_info *stream_info)
{
    if (quic_info->app_handle) {
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
        // Traverse the STREAM frame tree.
        proto_tree *top_tree = proto_tree_get_parent_tree(tree);
        //top_tree = proto_tree_get_parent_tree(top_tree);
        call_dissector_with_data(quic_info->app_handle, next_tvb, pinfo, top_tree, stream_info);
    }
}

/**
 * Reassemble stream data within a STREAM frame.
 */
static void
desegment_quic_stream(tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
                      proto_tree *tree, quic_info_data_t *quic_info,
                      quic_stream_info *stream_info,
                      quic_stream_state *stream)
{
    fragment_head *fh;
    int last_fragment_len;
    gboolean must_desegment;
    gboolean called_dissector;
    int another_pdu_follows;
    int deseg_offset;
    struct tcp_multisegment_pdu *msp;
    guint32 seq = (guint32)stream_info->stream_offset;
    const guint32 nxtseq = seq + (guint32)length;
    guint32 reassembly_id = 0;

    // XXX fix the tvb accessors below such that no new tvb is needed.
    tvb = tvb_new_subset_length(tvb, 0, offset + length);

again:
    fh = NULL;
    last_fragment_len = 0;
    must_desegment = FALSE;
    called_dissector = FALSE;
    another_pdu_follows = 0;
    msp = NULL;

    /*
     * Initialize these to assume no desegmentation.
     * If that's not the case, these will be set appropriately
     * by the subdissector.
     */
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    /*
     * Initialize this to assume that this segment will just be
     * added to the middle of a desegmented chunk of data, so
     * that we should show it all as data.
     * If that's not the case, it will be set appropriately.
     */
    deseg_offset = offset;

    /* Have we seen this PDU before (and is it the start of a multi-
     * segment PDU)?
     */
    if ((msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32(stream->multisegment_pdus, seq)) &&
            nxtseq <= msp->nxtpdu) {
        // TODO show expert info for retransmission? Additional checks may be
        // necessary here to tell a retransmission apart from other (normal?)
        // conditions. See also similar code in packet-tcp.c.
#if 0
        proto_tree_add_debug_text(tree, "TODO retransmission expert info frame %d stream_id=%" G_GINT64_MODIFIER "u offset=%d visited=%d reassembly_id=0x%08x",
                pinfo->num, stream->stream_id, offset, PINFO_FD_VISITED(pinfo), reassembly_id);
#endif
        return;
    }
    /* Else, find the most previous PDU starting before this sequence number */
    if (!msp && seq > 0) {
        msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(stream->multisegment_pdus, seq-1);
    }

    {
        // A single stream can contain multiple fragments (e.g. for HTTP/3
        // HEADERS and DATA frames). Let's hope that a single stream within a
        // QUIC packet does not contain multiple partial fragments, that would
        // result in a reassembly ID collision here. If that collision becomes
        // an issue, we would have to replace "msp->first_frame" with a new
        // field in "msp" that is initialized with "stream_info->stream_offset".
#if 0
        guint64 reassembly_id_data[2];
        reassembly_id_data[0] = stream_info->stream_id;
        reassembly_id_data[1] = msp ? msp->first_frame : pinfo->num;
        reassembly_id = wmem_strong_hash((const guint8 *)&reassembly_id_data, sizeof(reassembly_id_data));
#else
        // XXX for debug (visibility) purposes, do not use a hash but concatenate
        reassembly_id = ((msp ? msp->first_frame : pinfo->num) << 16) | (guint32)stream_info->stream_id;
#endif
    }

    if (msp && msp->seq <= seq && msp->nxtpdu > seq) {
        int len;

        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame=pinfo->num;
            msp->last_frame_time=pinfo->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        if (msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /* The dissector asked for the entire segment */
            len = tvb_captured_length_remaining(tvb, offset);
        } else {
            len = MIN(nxtseq, msp->nxtpdu) - seq;
        }
        last_fragment_len = len;

        fh = fragment_add(&quic_reassembly_table, tvb, offset,
                          pinfo, reassembly_id, NULL,
                          seq - msp->seq, len,
                          nxtseq < msp->nxtpdu);

        if (!PINFO_FD_VISITED(pinfo)
        && msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            msp->flags &= (~MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT);

            /* If we consumed the entire segment there is no
             * other pdu starting anywhere inside this segment.
             * So update nxtpdu to point at least to the start
             * of the next segment.
             * (If the subdissector asks for even more data we
             * will advance nxtpdu even further later down in
             * the code.)
             */
            msp->nxtpdu = nxtseq;
        }

        if( (msp->nxtpdu < nxtseq)
        &&  (msp->nxtpdu >= seq)
        &&  (len > 0)) {
            another_pdu_follows=msp->nxtpdu - seq;
        }
    } else {
        /* This segment was not found in our table, so it doesn't
         * contain a continuation of a higher-level PDU.
         * Call the normal subdissector.
         */

        stream_info->offset = seq;
        process_quic_stream(tvb, offset, pinfo, tree, quic_info, stream_info);
        called_dissector = TRUE;

        /* Did the subdissector ask us to desegment some more data
         * before it could handle the packet?
         * If so we have to create some structures in our table but
         * this is something we only do the first time we see this
         * packet.
         */
        if (pinfo->desegment_len) {
            if (!PINFO_FD_VISITED(pinfo))
                must_desegment = TRUE;

            /*
             * Set "deseg_offset" to the offset in "tvb"
             * of the first byte of data that the
             * subdissector didn't process.
             */
            deseg_offset = offset + pinfo->desegment_offset;
        }

        /* Either no desegmentation is necessary, or this is
         * segment contains the beginning but not the end of
         * a higher-level PDU and thus isn't completely
         * desegmented.
         */
        fh = NULL;
    }

    /* is it completely desegmented? */
    if (fh) {
        /*
         * Yes, we think it is.
         * We only call subdissector for the last segment.
         * Note that the last segment may include more than what
         * we needed.
         */
        if (fh->reassembled_in == pinfo->num) {
            /*
             * OK, this is the last segment.
             * Let's call the subdissector with the desegmented data.
             */

            tvbuff_t *next_tvb = tvb_new_chain(tvb, fh->tvb_data);
            add_new_data_source(pinfo, next_tvb, "Reassembled QUIC");
            stream_info->offset = seq;
            process_quic_stream(next_tvb, 0, pinfo, tree, quic_info, stream_info);
            called_dissector = TRUE;

            int old_len = (int)(tvb_reported_length(next_tvb) - last_fragment_len);
            if (pinfo->desegment_len &&
                pinfo->desegment_offset <= old_len) {
                /*
                 * "desegment_len" isn't 0, so it needs more
                 * data for something - and "desegment_offset"
                 * is before "old_len", so it needs more data
                 * to dissect the stuff we thought was
                 * completely desegmented (as opposed to the
                 * stuff at the beginning being completely
                 * desegmented, but the stuff at the end
                 * being a new higher-level PDU that also
                 * needs desegmentation).
                 */
                fragment_set_partial_reassembly(&quic_reassembly_table,
                                                pinfo, reassembly_id, NULL);

                /* Update msp->nxtpdu to point to the new next
                 * pdu boundary.
                 */
                if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                    /* We want reassembly of at least one
                     * more segment so set the nxtpdu
                     * boundary to one byte into the next
                     * segment.
                     * This means that the next segment
                     * will complete reassembly even if it
                     * is only one single byte in length.
                     * If this is an OoO segment, then increment the MSP end.
                     */
                    msp->nxtpdu = MAX(seq + tvb_reported_length_remaining(tvb, offset), msp->nxtpdu) + 1;
                    msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
#if 0
                } else if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                    tcpd->fwd->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
#endif
                } else {
                    if (seq + last_fragment_len >= msp->nxtpdu) {
                        /* This is the segment (overlapping) the end of the MSP. */
                        msp->nxtpdu = seq + last_fragment_len + pinfo->desegment_len;
                    } else {
                        /* This is a segment before the end of the MSP, so it
                         * must be an out-of-order segmented that completed the
                         * MSP. The requested additional data is relative to
                         * that end.
                         */
                        msp->nxtpdu += pinfo->desegment_len;
                    }
                }

                /* Since we need at least some more data
                 * there can be no pdu following in the
                 * tail of this segment.
                 */
                another_pdu_follows = 0;
                offset += last_fragment_len;
                seq += last_fragment_len;
                if (tvb_captured_length_remaining(tvb, offset) > 0)
                    goto again;
            } else {
                proto_item *frag_tree_item;
                proto_tree *parent_tree = proto_tree_get_parent(tree);
                show_fragment_tree(fh, &quic_stream_fragment_items,
                        parent_tree, pinfo, next_tvb, &frag_tree_item);
                // TODO move tree item if needed.

                if(pinfo->desegment_len) {
                    if (!PINFO_FD_VISITED(pinfo))
                        must_desegment = TRUE;
                    /* See packet-tcp.h for details about this. */
                    deseg_offset = fh->datalen - pinfo->desegment_offset;
                    deseg_offset = tvb_reported_length(tvb) - deseg_offset;
                }
            }
        }
    }

    if (must_desegment && !PINFO_FD_VISITED(pinfo)) {
        // TODO handle DESEGMENT_UNTIL_FIN if needed, maybe use the FIN bit?

        guint32 deseg_seq = seq + (deseg_offset - offset);

        if (((nxtseq - deseg_seq) <= 1024*1024)
            && (!PINFO_FD_VISITED(pinfo))) {
            if(pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                /* The subdissector asked to reassemble using the
                 * entire next segment.
                 * Just ask reassembly for one more byte
                 * but set this msp flag so we can pick it up
                 * above.
                 */
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo, deseg_seq,
                    nxtseq+1, stream->multisegment_pdus);
                msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
            } else {
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+pinfo->desegment_len, stream->multisegment_pdus);
            }

            /* add this segment as the first one for this new pdu */
            fragment_add(&quic_reassembly_table, tvb, deseg_offset,
                         pinfo, reassembly_id, NULL,
                         0, nxtseq - deseg_seq,
                         nxtseq < msp->nxtpdu);
        }
    }

    if (!called_dissector || pinfo->desegment_len != 0) {
        if (fh != NULL && fh->reassembled_in != 0 &&
            !(fh->flags & FD_PARTIAL_REASSEMBLY)) {
            /*
             * We know what frame this PDU is reassembled in;
             * let the user know.
             */
            proto_item *item = proto_tree_add_uint(tree, hf_quic_reassembled_in, tvb, 0,
                                                   0, fh->reassembled_in);
            proto_item_set_generated(item);
        }
    }
    pinfo->can_desegment = 0;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    if (another_pdu_follows) {
        /* there was another pdu following this one. */
        pinfo->can_desegment = 2;
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    }
}

static void
dissect_quic_stream_payload(tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
                            proto_tree *tree, quic_info_data_t *quic_info,
                            quic_stream_info *stream_info,
                            quic_stream_state *stream)
{
    /* QUIC application data is most likely not properly dissected when
     * reassembly is not enabled. Therefore we do not even offer "desegment"
     * preference to disable reassembly.
     */

    pinfo->can_desegment = 2;
    desegment_quic_stream(tvb, offset, length, pinfo, tree, quic_info, stream_info, stream);
}
/* QUIC Streams tracking and reassembly. }}} */

void
quic_stream_add_proto_data(packet_info *pinfo, quic_stream_info *stream_info, void *proto_data)
{
    quic_stream_state *stream = quic_get_stream_state(pinfo, stream_info->quic_info, stream_info->from_server, stream_info->stream_id);
    stream->subdissector_private = proto_data;
}

void *quic_stream_get_proto_data(packet_info *pinfo, quic_stream_info *stream_info)
{
    quic_stream_state *stream = quic_get_stream_state(pinfo, stream_info->quic_info, stream_info->from_server, stream_info->stream_id);
    return stream->subdissector_private;
}

static int
dissect_quic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, quic_info_data_t *quic_info, gboolean from_server)
{
    proto_item *ti_ft, *ti_ftflags, *ti;
    proto_tree *ft_tree, *ftflags_tree;
    guint64 frame_type;
    gint32 lenft;
    guint   orig_offset = offset;

    ti_ft = proto_tree_add_item(quic_tree, hf_quic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_quic_ft);

    ti_ftflags = proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, &frame_type, &lenft);
    proto_item_set_text(ti_ft, "%s", rval_to_str_const((guint32)frame_type, quic_frame_type_vals, "Unknown"));
    offset += lenft;

    switch(frame_type){
        case FT_PADDING:{
            guint32 pad_len;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", PADDING");

            /* A padding frame consists of a single zero octet, but for brevity
             * sake let's combine multiple zeroes into a single field. */
            pad_len = 1 + tvb_skip_guint8(tvb, offset, tvb_reported_length_remaining(tvb, offset), '\0') - offset;
            ti = proto_tree_add_uint(ft_tree, hf_quic_padding_length, tvb, offset, 0, pad_len);
            proto_item_set_generated(ti);
            proto_item_append_text(ti_ft, " Length: %u", pad_len);
            offset += pad_len - 1;
        }
        break;
        case FT_PING:{
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PING");
        }
        break;
        case FT_ACK:
        case FT_ACK_ECN:{
            guint64 ack_range_count;
            gint32 lenvar;

            if (frame_type == FT_ACK) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", ACK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", ACK_ECN");
            }

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_largest_acknowledged, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_ack_range_count, tvb, offset, -1, ENC_VARINT_QUIC, &ack_range_count, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_first_ack_range, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            /* ACK Ranges - Repeated "Ack Range Count" */
            while (ack_range_count) {

                /* Gap To Next Block */
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_gap, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_ack_range, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                ack_range_count--;
            }

            /* ECN Counts. */
            if (frame_type == FT_ACK_ECN) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_ect0_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_ect1_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_ack_ecn_ce_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            }
        }
        break;
        case FT_RESET_STREAM:{
            guint64 stream_id, error_code;
            gint32 len_streamid = 0, len_finalsize = 0, len_error_code = 0;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", RS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rsts_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" G_GINT64_MODIFIER "u", stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" G_GINT64_MODIFIER "u)", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rsts_application_error_code, tvb, offset, -1, ENC_VARINT_QUIC, &error_code, &len_error_code);
            offset += len_error_code;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rsts_final_size, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_finalsize);
            offset += len_finalsize;

            proto_item_append_text(ti_ft, " Error code: %#" G_GINT64_MODIFIER "x", error_code);
        }
        break;
        case FT_STOP_SENDING:{
            gint32 len_streamid;
            guint64 stream_id, error_code;
            gint32 len_error_code = 0;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ss_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" G_GINT64_MODIFIER "u", stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" G_GINT64_MODIFIER "u)", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ss_application_error_code, tvb, offset, -1, ENC_VARINT_QUIC, &error_code, &len_error_code);
            offset += len_error_code;

            proto_item_append_text(ti_ft, " Error code: %#" G_GINT64_MODIFIER "x", error_code);
        }
        break;
        case FT_CRYPTO: {
            guint64 crypto_offset, crypto_length;
            gint32 lenvar;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CRYPTO");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_crypto_offset, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_offset, &lenvar);
            offset += lenvar;
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_crypto_length, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_length, &lenvar);
            offset += lenvar;
            proto_tree_add_item(ft_tree, hf_quic_crypto_crypto_data, tvb, offset, (guint32)crypto_length, ENC_NA);
            {
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)crypto_length);
                col_set_writable(pinfo->cinfo, -1, FALSE);
                /*
                 * Dissect TLS handshake record. The Client/Server Hello (CH/SH)
                 * are contained in the Initial Packet. 0-RTT keys are ready
                 * after CH. HS + 1-RTT keys are ready after SH.
                 * (Note: keys captured from the client might become available
                 * after capturing the packets due to processing delay.)
                 * These keys will be loaded in the first HS/0-RTT/1-RTT msg.
                 */
                call_dissector_with_data(tls13_handshake_handle, next_tvb, pinfo, ft_tree, GUINT_TO_POINTER(crypto_offset));
                col_set_writable(pinfo->cinfo, -1, TRUE);
            }
            offset += (guint32)crypto_length;
        }
        break;
        case FT_NEW_TOKEN: {
            guint64 token_length;
            gint32 lenvar;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", NT");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_nt_length, tvb, offset, -1, ENC_VARINT_QUIC, &token_length, &lenvar);
            offset += lenvar;

            proto_tree_add_item(ft_tree, hf_quic_nt_token, tvb, offset, (guint32)token_length, ENC_NA);
            offset += (guint32)token_length;
        }
        break;
        case FT_STREAM_8:
        case FT_STREAM_9:
        case FT_STREAM_A:
        case FT_STREAM_B:
        case FT_STREAM_C:
        case FT_STREAM_D:
        case FT_STREAM_E:
        case FT_STREAM_F: {
            guint64 stream_id, stream_offset = 0, length;
            gint32 lenvar;

            offset -= 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", STREAM");

            ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_quic_ftflags);
            proto_tree_add_item(ftflags_tree, hf_quic_stream_fin, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_stream_len, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_stream_off, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &lenvar);
            offset += lenvar;

            proto_item_append_text(ti_ft, " id=%" G_GINT64_MODIFIER "u", stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" G_GINT64_MODIFIER "u)", stream_id);

            proto_item_append_text(ti_ft, " fin=%d", !!(frame_type & FTFLAGS_STREAM_FIN));

            if (frame_type & FTFLAGS_STREAM_OFF) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_offset, tvb, offset, -1, ENC_VARINT_QUIC, &stream_offset, &lenvar);
                offset += lenvar;
            }
            proto_item_append_text(ti_ft, " off=%" G_GINT64_MODIFIER "u", stream_offset);

            if (frame_type & FTFLAGS_STREAM_LEN) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
                offset += lenvar;
            } else {
                length = tvb_reported_length_remaining(tvb, offset);
            }
            proto_item_append_text(ti_ft, " len=%" G_GINT64_MODIFIER "u uni=%d", length, !!(stream_id & 2U));

            proto_tree_add_item(ft_tree, hf_quic_stream_data, tvb, offset, (int)length, ENC_NA);
            if (have_tap_listener(quic_follow_tap)) {
                tap_queue_packet(quic_follow_tap, pinfo, tvb_new_subset_length(tvb, offset, (int)length));
            }
            quic_stream_state *stream = quic_get_stream_state(pinfo, quic_info, from_server, stream_id);
            quic_stream_info stream_info = {
                .stream_id = stream_id,
                .stream_offset = stream_offset,
                .quic_info = quic_info,
                .from_server = from_server,
            };
            dissect_quic_stream_payload(tvb, offset, (int)length, pinfo, ft_tree, quic_info, &stream_info, stream);
            offset += (int)length;
        }
        break;
        case FT_MAX_DATA:{
            gint32 len_maximumdata;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_md_maximum_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumdata);
            offset += len_maximumdata;
        }
        break;
        case FT_MAX_STREAM_DATA:{
            gint32 len_streamid, len_maximumstreamdata;
            guint64 stream_id;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MSD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_msd_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" G_GINT64_MODIFIER "u", stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" G_GINT64_MODIFIER "u)", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_msd_maximum_stream_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumstreamdata);
            offset += len_maximumstreamdata;
        }
        break;
        case FT_MAX_STREAMS_BIDI:
        case FT_MAX_STREAMS_UNI:{
            gint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ms_max_streams, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;
        }
        break;
        case FT_DATA_BLOCKED:{
            gint32 len_offset;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", DB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_db_stream_data_limit, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;
        }
        break;
        case FT_STREAM_DATA_BLOCKED:{
            gint32 len_streamid, len_offset;
            guint64 stream_id;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SDB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_sdb_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" G_GINT64_MODIFIER "u", stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" G_GINT64_MODIFIER "u)", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_sdb_stream_data_limit, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;
        }
        break;
        case FT_STREAMS_BLOCKED_BIDI:
        case FT_STREAMS_BLOCKED_UNI:{
            gint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_sb_stream_limit, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;
        }
        break;
        case FT_NEW_CONNECTION_ID:{
            gint32 len_sequence;
            gint32 len_retire_prior_to;
            gint32 nci_length;
            gboolean valid_cid = FALSE;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", NCI");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_nci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
            offset += len_sequence;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_nci_retire_prior_to, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_retire_prior_to);
            offset += len_retire_prior_to;

            ti = proto_tree_add_item_ret_uint(ft_tree, hf_quic_nci_connection_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &nci_length);
            offset++;

            valid_cid = nci_length >= 1 && nci_length <= QUIC_MAX_CID_LENGTH;
            if (!valid_cid) {
                expert_add_info_format(pinfo, ti, &ei_quic_protocol_violation,
                            "Connection ID Length must be between 1 and %d bytes", QUIC_MAX_CID_LENGTH);
            }

            proto_tree_add_item(ft_tree, hf_quic_nci_connection_id, tvb, offset, nci_length, ENC_NA);
            if (valid_cid && quic_info) {
                quic_cid_t cid = {.len=0};
                tvb_memcpy(tvb, cid.cid, offset, nci_length);
                cid.len = nci_length;
                quic_connection_add_cid(quic_info, &cid, from_server);
            }
            offset += nci_length;

            proto_tree_add_item(ft_tree, hf_quic_nci_stateless_reset_token, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        break;
        case FT_RETIRE_CONNECTION_ID:{
            gint32 len_sequence;
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
            offset += len_sequence;
        }
        break;
        case FT_PATH_CHALLENGE:{
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PC");

            proto_tree_add_item(ft_tree, hf_quic_path_challenge_data, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;
        case FT_PATH_RESPONSE:{
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PR");

            proto_tree_add_item(ft_tree, hf_quic_path_response_data, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;
        case FT_CONNECTION_CLOSE_TPT:
        case FT_CONNECTION_CLOSE_APP:{
            gint32 len_reasonphrase, len_frametype, len_error_code;
            guint64 len_reason = 0;
            guint64 error_code;
            const char *tls_alert = NULL;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", CC");

            if (frame_type == FT_CONNECTION_CLOSE_TPT) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_cc_error_code, tvb, offset, -1, ENC_VARINT_QUIC, &error_code, &len_error_code);
                if ((error_code >> 8) == 1) {  // CRYPTO_ERROR (0x1XX)
                    tls_alert = try_val_to_str(error_code & 0xff, ssl_31_alert_description);
                    if (tls_alert) {
                        proto_tree_add_item(ft_tree, hf_quic_cc_error_code_tls_alert, tvb, offset + len_error_code - 1, 1, ENC_BIG_ENDIAN);
                    }
                }
                offset += len_error_code;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_cc_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_frametype);
                offset += len_frametype;
            } else { /* FT_CONNECTION_CLOSE_APP) */
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_cc_error_code_app, tvb, offset, -1, ENC_VARINT_QUIC, &error_code, &len_error_code);
                offset += len_error_code;
            }


            proto_tree_add_item_ret_varint(ft_tree, hf_quic_cc_reason_phrase_length, tvb, offset, -1, ENC_VARINT_QUIC, &len_reason, &len_reasonphrase);
            offset += len_reasonphrase;

            proto_tree_add_item(ft_tree, hf_quic_cc_reason_phrase, tvb, offset, (guint32)len_reason, ENC_ASCII|ENC_NA);
            offset += (guint32)len_reason;

            // Transport Error codes higher than 0x3fff are for Private Use.
            if (frame_type == FT_CONNECTION_CLOSE_TPT && error_code <= 0x3fff) {
                proto_item_append_text(ti_ft, " Error code: %s", rval_to_str((guint32)error_code, quic_transport_error_code_vals, "Unknown (%d)"));
            } else {
                proto_item_append_text(ti_ft, " Error code: %#" G_GINT64_MODIFIER "x", error_code);
            }
            if (tls_alert) {
                proto_item_append_text(ti_ft, " (%s)", tls_alert);
            }
        }
        break;
        case FT_HANDSHAKE_DONE:
            col_append_fstr(pinfo->cinfo, COL_INFO, ", DONE");
        break;
        case FT_DATAGRAM:
        case FT_DATAGRAM_LENGTH:{
            gint32 dg_length;
            guint64 length;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", DG");
            if (frame_type == FT_DATAGRAM_LENGTH) {

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_dg_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &dg_length);
                offset += dg_length;
            } else {
                length = (guint32) tvb_reported_length_remaining(tvb, offset);
            }
            proto_tree_add_item(ft_tree, hf_quic_dg, tvb, offset, (guint32)length, ENC_NA);
            offset += (guint32)length;
        }
        break;
        case FT_ACK_FREQUENCY:{
            gint32 length;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", ACK_FREQ");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_sequence_number, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (guint32)length;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_packet_tolerance, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (guint32)length;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_update_max_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (guint32)length;
        }
        break;
        case FT_TIME_STAMP:{
            gint32 length;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", TS");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ts, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (guint32)length;

        }
        break;
        default:
            expert_add_info_format(pinfo, ti_ft, &ei_quic_ft_unknown, "Unknown Frame Type %#" G_GINT64_MODIFIER "x", frame_type);
        break;
    }

    proto_item_set_len(ti_ft, offset - orig_offset);

    return offset;
}
#endif /* HAVE_LIBGCRYPT_AEAD */

#ifdef HAVE_LIBGCRYPT_AEAD
static gboolean
quic_cipher_init(quic_cipher *cipher, int hash_algo, guint8 key_length, guint8 *secret);


/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 * As the header points to the original buffer with an encrypted packet number,
 * the (encrypted) packet number length is also included.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-12.3
 */
static void
quic_decrypt_message(quic_cipher *cipher, tvbuff_t *head, guint header_length,
                     guint8 first_byte, guint pkn_len, guint64 packet_number, quic_decrypt_result_t *result)
{
    gcry_error_t    err;
    guint8         *header;
    guint8          nonce[TLS13_AEAD_NONCE_LENGTH];
    guint8         *buffer;
    guint8          atag[16];
    guint           buffer_length;
    const guchar  **error = &result->error;

    DISSECTOR_ASSERT(cipher != NULL);
    DISSECTOR_ASSERT(cipher->pp_cipher != NULL);
    DISSECTOR_ASSERT(pkn_len < header_length);
    DISSECTOR_ASSERT(1 <= pkn_len && pkn_len <= 4);
    // copy header, but replace encrypted first byte and PKN by plaintext.
    header = (guint8 *)tvb_memdup(wmem_packet_scope(), head, 0, header_length);
    header[0] = first_byte;
    for (guint i = 0; i < pkn_len; i++) {
        header[header_length - 1 - i] = (guint8)(packet_number >> (8 * i));
    }

    /* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
    buffer_length = tvb_captured_length_remaining(head, header_length + 16);
    if (buffer_length == 0) {
        *error = "Decryption not possible, ciphertext is too short";
        return;
    }
    buffer = (guint8 *)tvb_memdup(wmem_file_scope(), head, header_length, buffer_length);
    tvb_memcpy(head, atag, header_length + buffer_length, 16);

    memcpy(nonce, cipher->pp_iv, TLS13_AEAD_NONCE_LENGTH);
    /* Packet number is left-padded with zeroes and XORed with write_iv */
    phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);

    gcry_cipher_reset(cipher->pp_cipher);
    err = gcry_cipher_setiv(cipher->pp_cipher, nonce, TLS13_AEAD_NONCE_LENGTH);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (setiv) failed: %s", gcry_strerror(err));
        return;
    }

    /* associated data (A) is the contents of QUIC header */
    err = gcry_cipher_authenticate(cipher->pp_cipher, header, header_length);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (authenticate) failed: %s", gcry_strerror(err));
        return;
    }

    /* Output ciphertext (C) */
    err = gcry_cipher_decrypt(cipher->pp_cipher, buffer, buffer_length, NULL, 0);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (decrypt) failed: %s", gcry_strerror(err));
        return;
    }

    err = gcry_cipher_checktag(cipher->pp_cipher, atag, 16);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (checktag) failed: %s", gcry_strerror(err));
        return;
    }

    result->error = NULL;
    result->data = buffer;
    result->data_len = buffer_length;
}

static gboolean
quic_hkdf_expand_label(int hash_algo, guint8 *secret, guint secret_len, const char *label, guint8 *out, guint out_len)
{
    const StringInfo secret_si = { secret, secret_len };
    guchar *out_mem = NULL;
    if (tls13_hkdf_expand_label(hash_algo, &secret_si, "tls13 ", label, out_len, &out_mem)) {
        memcpy(out, out_mem, out_len);
        wmem_free(NULL, out_mem);
        return TRUE;
    }
    return FALSE;
}

/**
 * Compute the client and server initial secrets given Connection ID "cid".
 *
 * On success TRUE is returned and the two initial secrets are set.
 * FALSE is returned on error (see "error" parameter for the reason).
 */
static gboolean
quic_derive_initial_secrets(const quic_cid_t *cid,
                            guint8 client_initial_secret[HASH_SHA2_256_LENGTH],
                            guint8 server_initial_secret[HASH_SHA2_256_LENGTH],
                            guint32 version,
                            const gchar **error)
{
    /*
     * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
     *
     * initial_salt = 0xafbfec289993d24c9e9786f19c6111e04390a899
     * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *
     * client_initial_secret = HKDF-Expand-Label(initial_secret,
     *                                           "client in", "", Hash.length)
     * server_initial_secret = HKDF-Expand-Label(initial_secret,
     *                                           "server in", "", Hash.length)
     *
     * Hash for handshake packets is SHA-256 (output size 32).
     */
    static const guint8 handshake_salt_draft_22[20] = {
        0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
        0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
    };
    static const guint8 handshake_salt_draft_23[20] = {
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
        0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
    };
    static const guint8 handshake_salt_draft_29[20] = {
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    };
    static const guint8 hanshake_salt_draft_q50[20] = {
        0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
        0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
    };

    gcry_error_t    err;
    guint8          secret[HASH_SHA2_256_LENGTH];

    if (version == 0x51303530) {
        err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_q50, sizeof(hanshake_salt_draft_q50),
                           cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 22)) {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_22, sizeof(handshake_salt_draft_22),
                           cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 28)) {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_23, sizeof(handshake_salt_draft_23),
                           cid->cid, cid->len, secret);
    } else {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_29, sizeof(handshake_salt_draft_29),
                           cid->cid, cid->len, secret);
    }
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Failed to extract secrets: %s", gcry_strerror(err));
        return FALSE;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, sizeof(secret), "client in",
                                client_initial_secret, HASH_SHA2_256_LENGTH)) {
        *error = "Key expansion (client) failed";
        return FALSE;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, sizeof(secret), "server in",
                                server_initial_secret, HASH_SHA2_256_LENGTH)) {
        *error = "Key expansion (server) failed";
        return FALSE;
    }

    *error = NULL;
    return TRUE;
}

/**
 * Maps a Packet Protection cipher to the Packet Number protection cipher.
 * See https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.3
 */
static gboolean
quic_get_pn_cipher_algo(int cipher_algo, int *hp_cipher_mode)
{
    switch (cipher_algo) {
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES256:
        *hp_cipher_mode = GCRY_CIPHER_MODE_ECB;
        return TRUE;
#ifdef HAVE_LIBGCRYPT_CHACHA20
    case GCRY_CIPHER_CHACHA20:
        *hp_cipher_mode = GCRY_CIPHER_MODE_STREAM;
        return TRUE;
#endif /* HAVE_LIBGCRYPT_CHACHA20 */
    default:
        return FALSE;
    }
}

/*
 * (Re)initialize the PNE/PP ciphers using the given cipher algorithm.
 * If the optional base secret is given, then its length MUST match the hash
 * algorithm output.
 */
static gboolean
quic_cipher_prepare(quic_cipher *cipher, int hash_algo, int cipher_algo, int cipher_mode, guint8 *secret, const char **error)
{
    /* Clear previous state (if any). */
    quic_cipher_reset(cipher);

    int hp_cipher_mode;
    if (!quic_get_pn_cipher_algo(cipher_algo, &hp_cipher_mode)) {
        *error = "Unsupported cipher algorithm";
        return FALSE;
    }

    if (gcry_cipher_open(&cipher->hp_cipher, cipher_algo, hp_cipher_mode, 0) ||
        gcry_cipher_open(&cipher->pp_cipher, cipher_algo, cipher_mode, 0)) {
        quic_cipher_reset(cipher);
        *error = "Failed to create ciphers";
        return FALSE;
    }

    if (secret) {
        guint cipher_keylen = (guint8) gcry_cipher_get_algo_keylen(cipher_algo);
        if (!quic_cipher_init(cipher, hash_algo, cipher_keylen, secret)) {
            quic_cipher_reset(cipher);
            *error = "Failed to derive key material for cipher";
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
quic_create_initial_decoders(const quic_cid_t *cid, const gchar **error, quic_info_data_t *quic_info)
{
    guint8          client_secret[HASH_SHA2_256_LENGTH];
    guint8          server_secret[HASH_SHA2_256_LENGTH];

    if (!quic_derive_initial_secrets(cid, client_secret, server_secret, quic_info->version, error)) {
        return FALSE;
    }

    /* Packet numbers are protected with AES128-CTR,
     * initial packets are protected with AEAD_AES_128_GCM. */
    if (!quic_cipher_prepare(&quic_info->client_initial_cipher, GCRY_MD_SHA256,
                             GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, client_secret, error) ||
        !quic_cipher_prepare(&quic_info->server_initial_cipher, GCRY_MD_SHA256,
                             GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, server_secret, error)) {
        return FALSE;
    }

    return TRUE;
}

static gboolean
quic_create_0rtt_decoder(guint i, gchar *early_data_secret, guint early_data_secret_len,
                         quic_cipher *cipher, int *cipher_algo)
{
    static const guint16 tls13_ciphers[] = {
        0x1301, /* TLS_AES_128_GCM_SHA256 */
        0x1302, /* TLS_AES_256_GCM_SHA384 */
        0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
        0x1304, /* TLS_AES_128_CCM_SHA256 */
        0x1305, /* TLS_AES_128_CCM_8_SHA256 */
    };
    if (i >= G_N_ELEMENTS(tls13_ciphers)) {
        // end of list
        return FALSE;
    }
    int cipher_mode = 0, hash_algo = 0;
    const char *error_ignored = NULL;
    if (tls_get_cipher_info(NULL, tls13_ciphers[i], cipher_algo, &cipher_mode, &hash_algo)) {
        guint hash_len = gcry_md_get_algo_dlen(hash_algo);
        if (hash_len == early_data_secret_len && quic_cipher_prepare(cipher, hash_algo, *cipher_algo, cipher_mode, early_data_secret, &error_ignored)) {
            return TRUE;
        }
    }
    /* This cipher failed, but there are more to try. */
    quic_cipher_reset(cipher);
    return TRUE;
}

static gboolean
quic_create_decoders(packet_info *pinfo, quic_info_data_t *quic_info, quic_cipher *cipher,
                     gboolean from_server, TLSRecordType type, const char **error)
{
    if (!quic_info->hash_algo) {
        if (!tls_get_cipher_info(pinfo, 0, &quic_info->cipher_algo, &quic_info->cipher_mode, &quic_info->hash_algo)) {
#ifndef HAVE_LIBGCRYPT_CHACHA20
            /* If this stream uses the ChaCha20-Poly1305 cipher, Libgcrypt 1.7.0
             * or newer is required. */
            *error = "Unable to retrieve cipher information; try upgrading Libgcrypt >= 1.7.0";
#else
            *error = "Unable to retrieve cipher information";
#endif
            return FALSE;
        }
    }

    guint hash_len = gcry_md_get_algo_dlen(quic_info->hash_algo);
    char *secret = (char *)wmem_alloc0(wmem_packet_scope(), hash_len);

    if (!tls13_get_quic_secret(pinfo, from_server, type, hash_len, hash_len, secret)) {
        *error = "Secrets are not available";
        return FALSE;
    }

    if (!quic_cipher_prepare(cipher, quic_info->hash_algo,
                             quic_info->cipher_algo, quic_info->cipher_mode, secret, error)) {
        return FALSE;
    }

    return TRUE;
}

/**
 * Tries to obtain the QUIC application traffic secrets.
 */
static gboolean
quic_get_traffic_secret(packet_info *pinfo, int hash_algo, quic_pp_state_t *pp_state, gboolean from_client)
{
    guint hash_len = gcry_md_get_algo_dlen(hash_algo);
    char *secret = (char *)wmem_alloc0(wmem_packet_scope(), hash_len);
    if (!tls13_get_quic_secret(pinfo, !from_client, TLS_SECRET_APP, hash_len, hash_len, secret)) {
        return FALSE;
    }
    pp_state->next_secret = (guint8 *)wmem_memdup(wmem_file_scope(), secret, hash_len);
    return TRUE;
}

/**
 * Expands the secret (length MUST be the same as the "hash_algo" digest size)
 * and initialize cipher with the new key.
 */
static gboolean
quic_cipher_init(quic_cipher *cipher, int hash_algo, guint8 key_length, guint8 *secret)
{
    guchar      write_key[256/8];   /* Maximum key size is for AES256 cipher. */
    guchar      hp_key[256/8];
    guint       hash_len = gcry_md_get_algo_dlen(hash_algo);

    if (key_length > sizeof(write_key)) {
        return FALSE;
    }

    if (!quic_hkdf_expand_label(hash_algo, secret, hash_len, "quic key", write_key, key_length) ||
        !quic_hkdf_expand_label(hash_algo, secret, hash_len, "quic iv", cipher->pp_iv, sizeof(cipher->pp_iv)) ||
        !quic_hkdf_expand_label(hash_algo, secret, hash_len, "quic hp", hp_key, key_length)) {
        return FALSE;
    }

    return gcry_cipher_setkey(cipher->hp_cipher, hp_key, key_length) == 0 &&
           gcry_cipher_setkey(cipher->pp_cipher, write_key, key_length) == 0;
}

/**
 * Updates the packet protection secret to the next one.
 */
static void
quic_update_key(guint32 version, int hash_algo, quic_pp_state_t *pp_state)
{
    guint hash_len = gcry_md_get_algo_dlen(hash_algo);
    const char *label = is_quic_draft_max(version, 23) ? "traffic upd" : "quic ku";
    gboolean ret = quic_hkdf_expand_label(hash_algo, pp_state->next_secret, hash_len,
                                          label, pp_state->next_secret, hash_len);
    /* This must always succeed as our hash algorithm was already validated. */
    DISSECTOR_ASSERT(ret);
}

/**
 * Retrieves the header protection cipher for short header packets and prepares
 * the packet protection cipher. The application layer protocol is also queried.
 */
static gcry_cipher_hd_t
quic_get_1rtt_hp_cipher(packet_info *pinfo, quic_info_data_t *quic_info, gboolean from_server)
{
    const char *error = NULL;

    /* Keys were previously not available. */
    if (quic_info->skip_decryption) {
        return NULL;
    }

    quic_pp_state_t *client_pp = &quic_info->client_pp;
    quic_pp_state_t *server_pp = &quic_info->server_pp;
    quic_pp_state_t *pp_state = !from_server ? client_pp : server_pp;

    /* Try to lookup secrets if not available. */
    if (!quic_info->client_pp.next_secret) {
        /* Query TLS for the cipher suite. */
        if (!tls_get_cipher_info(pinfo, 0, &quic_info->cipher_algo, &quic_info->cipher_mode, &quic_info->hash_algo)) {
            // No previous TLS handshake found or unsupported ciphers, fail.
            // This is an optimization that allows skipping checks for future
            // packets in case the capture starts in midst of a connection where
            // the handshake is not present.
            // If this breaks decryption because packets prior to the Server
            // Hello are somehow misdetected as Short Packet, then this
            // optimization should probably be removed.
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        /* Retrieve secrets for both the client and server. */
        if (!quic_get_traffic_secret(pinfo, quic_info->hash_algo, client_pp, TRUE) ||
            !quic_get_traffic_secret(pinfo, quic_info->hash_algo, server_pp, FALSE)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        // Create initial cipher handles for Key Phase 0 using the 1-RTT keys.
        if (!quic_cipher_prepare(&client_pp->cipher[0], quic_info->hash_algo,
                                 quic_info->cipher_algo, quic_info->cipher_mode, client_pp->next_secret, &error) ||
            !quic_cipher_prepare(&server_pp->cipher[0], quic_info->hash_algo,
                                 quic_info->cipher_algo, quic_info->cipher_mode, server_pp->next_secret, &error)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }
        // Rotate the 1-RTT key for the client and server for the next key update.
        quic_update_key(quic_info->version, quic_info->hash_algo, client_pp);
        quic_update_key(quic_info->version, quic_info->hash_algo, server_pp);

        // For efficiency, look up the application layer protocol once. The
        // handshake must have been completed before, so ALPN is known.
        const char *proto_name = tls_get_alpn(pinfo);
        if (proto_name) {
            quic_info->app_handle = dissector_get_string_handle(quic_proto_dissector_table, proto_name);
            // If no specific handle is found, alias "h3-*" to "h3".
            if (!quic_info->app_handle && g_str_has_prefix(proto_name, "h3-")) {
                quic_info->app_handle = dissector_get_string_handle(quic_proto_dissector_table, "h3");
            }
        }
    }

    // Note: Header Protect cipher does not change after Key Update.
    return pp_state->cipher[0].hp_cipher;
}

/**
 * Tries to construct the appropriate cipher for the current key phase.
 * See also "PROTECTED PAYLOAD DECRYPTION" comment on top of this file.
 */
static quic_cipher *
quic_get_pp_cipher(gboolean key_phase, quic_info_data_t *quic_info, gboolean from_server)
{
    const char *error = NULL;
    gboolean    success = FALSE;

    /* Keys were previously not available. */
    if (quic_info->skip_decryption) {
        return NULL;
    }

    quic_pp_state_t *client_pp = &quic_info->client_pp;
    quic_pp_state_t *server_pp = &quic_info->server_pp;
    quic_pp_state_t *pp_state = !from_server ? client_pp : server_pp;

    /*
     * If the key phase changed, try to decrypt the packet using the new cipher.
     * If that fails, then it is either a malicious packet or out-of-order.
     * In that case, try the previous cipher (unless it is the very first KP1).
     * '!!' is due to key_phase being a signed bitfield, it forces -1 into 1.
     */
    if (key_phase != !!pp_state->key_phase) {
        quic_cipher new_cipher;

        memset(&new_cipher, 0, sizeof(quic_cipher));
        if (!quic_cipher_prepare(&new_cipher, quic_info->hash_algo,
                                 quic_info->cipher_algo, quic_info->cipher_mode, pp_state->next_secret, &error)) {
            /* This should never be reached, if the parameters were wrong
             * before, then it should have set "skip_decryption". */
            REPORT_DISSECTOR_BUG("quic_cipher_prepare unexpectedly failed: %s", error);
            return NULL;
        }

        // TODO verify decryption before switching keys.
        success = TRUE;

        if (success) {
            /* Verified the cipher, use it from now on and rotate the key. */
            quic_cipher_reset(&pp_state->cipher[key_phase]);
            pp_state->cipher[key_phase] = new_cipher;
            quic_update_key(quic_info->version, quic_info->hash_algo, pp_state);

            pp_state->key_phase = key_phase;
            //pp_state->changed_in_pkn = pkn;

            return &pp_state->cipher[key_phase];
        } else {
            // TODO fallback to previous cipher
            return NULL;
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
                     quic_info_data_t *quic_info, quic_packet_info_t *quic_packet, gboolean from_server,
                     quic_cipher *cipher, guint8 first_byte, guint pkn_len)
{
    quic_decrypt_result_t *decryption = &quic_packet->decryption;

    /*
     * If no decryption error has occurred yet, try decryption on the first
     * pass and store the result for later use.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (!quic_packet->decryption.error && cipher && cipher->pp_cipher) {
            quic_decrypt_message(cipher, tvb, offset, first_byte, pkn_len, quic_packet->packet_number, &quic_packet->decryption);
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
            decrypted_offset = dissect_quic_frame_type(decrypted_tvb, pinfo, tree, decrypted_offset, quic_info, from_server);
        }
    } else if (quic_info->skip_decryption) {
        expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed,
                               "Decryption skipped because keys are not available.");
    }
}

static void
quic_verify_retry_token(tvbuff_t *tvb, quic_packet_info_t *quic_packet, const quic_cid_t *odcid, guint32 version)
{
    /*
     * Verify the Retry Integrity Tag using the fixed key from
     * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
     */
    static const guint8 key_draft_29[] = {
        0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0,
        0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1
    };
    static const guint8 nonce_draft_29[] = {
        0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c
    };
    static const guint8 key_draft_25[] = {
        0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8,
        0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30,
    };
    static const guint8 nonce_draft_25[] = {
        0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75,
    };
    gcry_cipher_hd_t    h = NULL;
    gcry_error_t        err;
    gint                pseudo_packet_tail_length = tvb_reported_length(tvb) - 16;

    DISSECTOR_ASSERT(pseudo_packet_tail_length > 0);

    err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
    DISSECTOR_ASSERT_HINT(err == 0, "create cipher");
    if (is_quic_draft_max(version, 28)) {
       err = gcry_cipher_setkey(h, key_draft_25, sizeof(key_draft_25));
    } else {
       err = gcry_cipher_setkey(h, key_draft_29, sizeof(key_draft_29));
    }
    DISSECTOR_ASSERT_HINT(err == 0, "set key");
    if (is_quic_draft_max(version, 28)) {
        err = gcry_cipher_setiv(h, nonce_draft_25, sizeof(nonce_draft_25));
    } else {
        err = gcry_cipher_setiv(h, nonce_draft_29, sizeof(nonce_draft_29));
    }
    DISSECTOR_ASSERT_HINT(err == 0, "set nonce");
    G_STATIC_ASSERT(sizeof(odcid->len) == 1);
    err = gcry_cipher_authenticate(h, odcid, 1 + odcid->len);
    DISSECTOR_ASSERT_HINT(err == 0, "aad1");
    err = gcry_cipher_authenticate(h, tvb_get_ptr(tvb, 0, pseudo_packet_tail_length), pseudo_packet_tail_length);
    DISSECTOR_ASSERT_HINT(err == 0, "aad2");
    // Plaintext is empty, there is no need to call gcry_cipher_encrypt.
    err = gcry_cipher_checktag(h, tvb_get_ptr(tvb, pseudo_packet_tail_length, 16), 16);
    if (err) {
        quic_packet->retry_integrity_failure = TRUE;
    } else {
        quic_packet->retry_integrity_success = TRUE;
    }
    gcry_cipher_close(h);
}
#endif /* HAVE_LIBGCRYPT_AEAD */

static void
quic_add_connection_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, quic_info_data_t *conn)
{
    proto_tree         *ctree;
    proto_item         *pi;

    ctree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_quic_connection_info, NULL, "QUIC Connection information");
    if (!conn) {
        expert_add_info(pinfo, ctree, &ei_quic_connection_unknown);
        return;
    }

    pi = proto_tree_add_uint(ctree, hf_quic_connection_number, tvb, 0, 0, conn->number);
    proto_item_set_generated(pi);
#if 0
    proto_tree_add_debug_text(ctree, "Client CID: %s", cid_to_string(&conn->client_cids.data));
    proto_tree_add_debug_text(ctree, "Server CID: %s", cid_to_string(&conn->server_cids.data));
    // Note: for Retry, this value has been cleared before.
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
    guint32     dcil, scil;

    version = tvb_get_ntohl(tvb, offset);

    if (version_out) {
        *version_out = version;
    }

    proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_dcil, tvb, offset, 1, ENC_BIG_ENDIAN, &dcil);
    offset++;
    if (dcil) {
        proto_tree_add_item(quic_tree, hf_quic_dcid, tvb, offset, dcil, ENC_NA);
        // TODO expert info on CID mismatch with connection
        if (dcil <= QUIC_MAX_CID_LENGTH) {
            tvb_memcpy(tvb, dcid->cid, offset, dcil);
            dcid->len = dcil;
        }
        offset += dcil;
    }

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_scil, tvb, offset, 1, ENC_BIG_ENDIAN, &scil);
    offset++;
    if (scil) {
        proto_tree_add_item(quic_tree, hf_quic_scid, tvb, offset, scil, ENC_NA);
        // TODO expert info on CID mismatch with connection
        if (scil <= QUIC_MAX_CID_LENGTH) {
            tvb_memcpy(tvb, scid->cid, offset, scil);
            scid->len = scil;
        }
        offset += scil;
    }

    if (dcid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", cid_to_string(dcid));
    }
    if (scid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", SCID=%s", cid_to_string(scid));
    }
    return offset;
}

/* Retry Packet dissection */
static int
dissect_quic_retry_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                          quic_datagram *dgram_info _U_, quic_packet_info_t *quic_packet,
                          const quic_cid_t *odcid)
{
    guint       offset = 0;
    guint32     version;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    guint32     odcil = 0;
    guint       retry_token_len;
    proto_item *ti;

    proto_tree_add_item(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    col_set_str(pinfo->cinfo, COL_INFO, "Retry");

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &version, &dcid, &scid);

    if (is_quic_draft_max(version, 24)) {
        proto_tree_add_item_ret_uint(quic_tree, hf_quic_odcil, tvb, offset, 1, ENC_NA, &odcil);
        offset++;
        proto_tree_add_item(quic_tree, hf_quic_odcid, tvb, offset, odcil, ENC_NA);
        offset += odcil;
    }

    retry_token_len = tvb_reported_length_remaining(tvb, offset);
    // Remove length of Retry Integrity Tag"
    if (!is_quic_draft_max(version, 24) && retry_token_len >= 16) {
        retry_token_len -= 16;
    }
    proto_tree_add_item(quic_tree, hf_quic_retry_token, tvb, offset, retry_token_len, ENC_NA);
    offset += retry_token_len;

    if (!is_quic_draft_max(version, 24)) {
        // Verify the Retry Integrity Tag according to
        // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
        ti = proto_tree_add_item(quic_tree, hf_quic_retry_integrity_tag, tvb, offset, 16, ENC_NA);
#ifdef HAVE_LIBGCRYPT_AEAD
        if (!PINFO_FD_VISITED(pinfo) && odcid) {
            // Skip validation if the Initial Packet is unknown, for example due
            // to packet loss in the capture file.
            quic_verify_retry_token(tvb, quic_packet, odcid, version);
        }
        if (quic_packet->retry_integrity_failure) {
            expert_add_info(pinfo, ti, &ei_quic_bad_retry);
        } else if (!quic_packet->retry_integrity_success) {
            expert_add_info_format(pinfo, ti, &ei_quic_bad_retry,
                    "Cannot verify Retry Packet due to unknown ODCID");
        } else {
            proto_item_append_text(ti, " [verified]");
        }
#else
        (void)odcid;
        expert_add_info_format(pinfo, ti, &ei_quic_bad_retry,
                "Libgcrypt >= 1.6.0 is required for Retry Packet verification");
#endif
        offset += 16;
    }

    return offset;
}

static int
dissect_quic_long_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                         quic_datagram *dgram_info, quic_packet_info_t *quic_packet)
{
    guint offset = 0;
    guint8 long_packet_type;
    guint32 version;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    gint32 len_token_length;
    guint64 token_length;
    gint32 len_payload_length;
    guint64 payload_length;
    guint8  first_byte = 0;
    quic_info_data_t *conn = dgram_info->conn;
#ifdef HAVE_LIBGCRYPT_AEAD
    const gboolean from_server = dgram_info->from_server;
    quic_cipher *cipher = NULL;
    proto_item *ti;
#endif

    quic_extract_header(tvb, &long_packet_type, &version, &dcid, &scid);
#ifdef HAVE_LIBGCRYPT_AEAD
    if (conn) {
        if (long_packet_type == QUIC_LPT_INITIAL) {
            cipher = !from_server ? &conn->client_initial_cipher : &conn->server_initial_cipher;
        } else if (long_packet_type == QUIC_LPT_0RTT && !from_server) {
            cipher = &conn->client_0rtt_cipher;
        } else if (long_packet_type == QUIC_LPT_HANDSHAKE) {
            cipher = !from_server ? &conn->client_handshake_cipher : &conn->server_handshake_cipher;
        }
    }
    /* Prepare the Initial/Handshake cipher for header/payload decryption. */
    if (!PINFO_FD_VISITED(pinfo) && conn && cipher) {
#define DIGEST_MIN_SIZE 32  /* SHA256 */
#define DIGEST_MAX_SIZE 48  /* SHA384 */
        const gchar *error = NULL;
        gchar early_data_secret[DIGEST_MAX_SIZE];
        guint early_data_secret_len = 0;
        if (long_packet_type == QUIC_LPT_INITIAL && !from_server &&
            !memcmp(&dcid, &conn->client_dcid_initial, sizeof(quic_cid_t))) {
            /* Create new decryption context based on the Client Connection
             * ID from the *very first* Client Initial packet. */
            quic_create_initial_decoders(&dcid, &error, conn);
        } else if (long_packet_type == QUIC_LPT_0RTT) {
            early_data_secret_len = tls13_get_quic_secret(pinfo, FALSE, TLS_SECRET_0RTT_APP, DIGEST_MIN_SIZE, DIGEST_MAX_SIZE, early_data_secret);
            if (early_data_secret_len == 0) {
                error = "Secrets are not available";
            }
        } else if (long_packet_type == QUIC_LPT_HANDSHAKE) {
            if (!cipher->hp_cipher) {
                quic_create_decoders(pinfo, conn, cipher, from_server, TLS_SECRET_HANDSHAKE, &error);
            }
        }
        if (!error) {
            guint32 pkn32 = 0;
            int hp_cipher_algo = long_packet_type != QUIC_LPT_INITIAL && conn ? conn->cipher_algo : GCRY_CIPHER_AES128;
            // PKN is after type(1) + version(4) + DCIL+DCID + SCIL+SCID
            guint pn_offset = 1 + 4 + 1 + dcid.len + 1 + scid.len;
            if (long_packet_type == QUIC_LPT_INITIAL) {
                pn_offset += tvb_get_varint(tvb, pn_offset, 8, &token_length, ENC_VARINT_QUIC);
                pn_offset += (guint)token_length;
            }
            pn_offset += tvb_get_varint(tvb, pn_offset, 8, &payload_length, ENC_VARINT_QUIC);

            // Assume failure unless proven otherwise.
            error = "Header deprotection failed";
            if (long_packet_type != QUIC_LPT_0RTT) {
                if (quic_decrypt_header(tvb, pn_offset, cipher->hp_cipher, hp_cipher_algo, &first_byte, &pkn32)) {
                    error = NULL;
                }
            } else {
                // Cipher is not stored with 0-RTT data or key, perform trial decryption.
                for (guint i = 0; quic_create_0rtt_decoder(i, early_data_secret, early_data_secret_len, cipher, &hp_cipher_algo); i++) {
                    if (cipher->hp_cipher && quic_decrypt_header(tvb, pn_offset, cipher->hp_cipher, hp_cipher_algo, &first_byte, &pkn32)) {
                        error = NULL;
                        break;
                    }
                }
            }
            if (!error) {
                quic_set_full_packet_number(conn, quic_packet, from_server, first_byte, pkn32);
                quic_packet->first_byte = first_byte;
            }
        }
        if (error) {
            quic_packet->decryption.error = wmem_strdup(wmem_file_scope(), error);
        }
    } else if (conn && quic_packet->pkn_len) {
        first_byte = quic_packet->first_byte;
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */

    proto_tree_add_item(quic_tree, hf_quic_fixed_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA);
    if (quic_packet->pkn_len) {
        proto_tree_add_uint(quic_tree, hf_quic_long_reserved, tvb, offset, 1, first_byte);
        proto_tree_add_uint(quic_tree, hf_quic_packet_number_length, tvb, offset, 1, first_byte);
    }
    offset += 1;
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(long_packet_type, quic_long_packet_type_vals, "Long Header"));

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, NULL, &dcid, &scid);

    if (long_packet_type == QUIC_LPT_INITIAL) {
        proto_tree_add_item_ret_varint(quic_tree, hf_quic_token_length, tvb, offset, -1, ENC_VARINT_QUIC, &token_length, &len_token_length);
        offset += len_token_length;

        if (token_length) {
            proto_tree_add_item(quic_tree, hf_quic_token, tvb, offset, (guint32)token_length, ENC_NA);
            offset += (guint)token_length;
        }
    }

    proto_tree_add_item_ret_varint(quic_tree, hf_quic_length, tvb, offset, -1, ENC_VARINT_QUIC, &payload_length, &len_payload_length);
    offset += len_payload_length;

    if (quic_packet->decryption.error) {
        expert_add_info_format(pinfo, quic_tree, &ei_quic_decryption_failed,
                               "Failed to create decryption context: %s", quic_packet->decryption.error);
        return offset;
    }
    if (!conn || quic_packet->pkn_len == 0) {
#ifndef HAVE_LIBGCRYPT_AEAD
        expert_add_info_format(pinfo, quic_tree, &ei_quic_decryption_failed, "Libgcrypt >= 1.6.0 is required for QUIC decryption");
#else
        // if not part of a connection, the full PKN cannot be reconstructed.
        expert_add_info_format(pinfo, quic_tree, &ei_quic_decryption_failed, "Failed to decrypt packet number");
#endif
        return offset;
    }

    proto_tree_add_uint64(quic_tree, hf_quic_packet_number, tvb, offset, quic_packet->pkn_len, quic_packet->packet_number);
    offset += quic_packet->pkn_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" G_GINT64_MODIFIER "u", quic_packet->packet_number);

    /* Payload */
#ifdef HAVE_LIBGCRYPT_AEAD
    ti = proto_tree_add_item(quic_tree, hf_quic_payload, tvb, offset, -1, ENC_NA);
#else
    proto_tree_add_item(quic_tree, hf_quic_payload, tvb, offset, -1, ENC_NA);
#endif

#ifdef HAVE_LIBGCRYPT_AEAD
    if (conn) {
        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, from_server, cipher, first_byte, quic_packet->pkn_len);
    }
    if (!PINFO_FD_VISITED(pinfo) && !quic_packet->decryption.error) {
        // Packet number is verified to be valid, remember it.
        *quic_max_packet_number(conn, from_server, first_byte) = quic_packet->packet_number;
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_quic_short_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                          quic_datagram *dgram_info, quic_packet_info_t *quic_packet)
{
    guint offset = 0;
    quic_cid_t dcid = {.len=0};
    guint8  first_byte = 0;
    gboolean    key_phase = FALSE;
#ifdef HAVE_LIBGCRYPT_AEAD
    proto_item *ti;
    quic_cipher *cipher = NULL;
#endif
    quic_info_data_t *conn = dgram_info->conn;
    const gboolean from_server = dgram_info->from_server;

    proto_item *pi = proto_tree_add_item(quic_tree, hf_quic_short, tvb, 0, -1, ENC_NA);
    proto_tree *hdr_tree = proto_item_add_subtree(pi, ett_quic_short_header);
    proto_tree_add_item(hdr_tree, hf_quic_header_form, tvb, 0, 1, ENC_NA);

    if (conn) {
       dcid.len = from_server ? conn->client_cids.data.len : conn->server_cids.data.len;
    }
#ifdef HAVE_LIBGCRYPT_AEAD
    if (!PINFO_FD_VISITED(pinfo) && conn) {
        guint32 pkn32 = 0;
        gcry_cipher_hd_t hp_cipher = quic_get_1rtt_hp_cipher(pinfo, conn, from_server);
        if (hp_cipher && quic_decrypt_header(tvb, 1 + dcid.len, hp_cipher, conn->cipher_algo, &first_byte, &pkn32)) {
            quic_set_full_packet_number(conn, quic_packet, from_server, first_byte, pkn32);
            quic_packet->first_byte = first_byte;
        }
    } else if (conn && quic_packet->pkn_len) {
        first_byte = quic_packet->first_byte;
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */
    proto_tree_add_item(hdr_tree, hf_quic_fixed_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(hdr_tree, hf_quic_spin_bit, tvb, offset, 1, ENC_NA);
    if (quic_packet->pkn_len) {
        key_phase = (first_byte & SH_KP) != 0;
        proto_tree_add_uint(hdr_tree, hf_quic_short_reserved, tvb, offset, 1, first_byte);
        proto_tree_add_boolean(hdr_tree, hf_quic_key_phase, tvb, offset, 1, key_phase);
        proto_tree_add_uint(hdr_tree, hf_quic_packet_number_length, tvb, offset, 1, first_byte);
    }
    offset += 1;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Protected Payload (KP%u)", key_phase);

    /* Connection ID */
    if (dcid.len > 0) {
        proto_tree_add_item(hdr_tree, hf_quic_dcid, tvb, offset, dcid.len, ENC_NA);
        tvb_memcpy(tvb, dcid.cid, offset, dcid.len);
        offset += dcid.len;
        const char *dcid_str = cid_to_string(&dcid);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", dcid_str);
        proto_item_append_text(pi, " DCID=%s", dcid_str);
    }

#ifdef HAVE_LIBGCRYPT_AEAD
    if (!PINFO_FD_VISITED(pinfo) && conn) {
        cipher = quic_get_pp_cipher(key_phase, conn, from_server);
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */
    if (!conn || conn->skip_decryption || quic_packet->pkn_len == 0) {
        return offset;
    }

    /* Packet Number */
    proto_tree_add_uint64(hdr_tree, hf_quic_packet_number, tvb, offset, quic_packet->pkn_len, quic_packet->packet_number);
    offset += quic_packet->pkn_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" G_GINT64_MODIFIER "u", quic_packet->packet_number);
    proto_item_append_text(pi, " PKN=%" G_GINT64_MODIFIER "u", quic_packet->packet_number);

    /* Protected Payload */
#ifdef HAVE_LIBGCRYPT_AEAD
    ti = proto_tree_add_item(hdr_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);
#else
    proto_tree_add_item(hdr_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);
#endif

#ifdef HAVE_LIBGCRYPT_AEAD
    if (conn) {
        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, from_server, cipher, first_byte, quic_packet->pkn_len);
        if (!PINFO_FD_VISITED(pinfo) && !quic_packet->decryption.error) {
            // Packet number is verified to be valid, remember it.
            *quic_max_packet_number(conn, from_server, first_byte) = quic_packet->packet_number;
        }
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_quic_version_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, const quic_packet_info_t *quic_packet)
{
    guint       offset = 0;
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

static tvbuff_t *
quic_get_message_tvb(tvbuff_t *tvb, const guint offset)
{
    guint64 token_length;
    guint64 payload_length;
    guint8 packet_type = tvb_get_guint8(tvb, offset);
    guint8 long_packet_type = (packet_type & 0x30) >> 4;
    // Retry and VN packets cannot be coalesced (clarified in draft -14).
    if ((packet_type & 0x80) && long_packet_type != QUIC_LPT_RETRY) {
        // long header form, check version
        guint version = tvb_get_ntohl(tvb, offset + 1);
        // If this is not a VN packet but a valid long form, extract a subset.
        // TODO check for valid QUIC versions as future versions might change the format.
        if (version != 0) {
            guint length = 5;   // flag (1 byte) + version (4 bytes)
            length += 1 + tvb_get_guint8(tvb, offset + length); // DCID
            length += 1 + tvb_get_guint8(tvb, offset + length); // SCID
            if (long_packet_type == QUIC_LPT_INITIAL) {
                length += tvb_get_varint(tvb, offset + length, 8, &token_length, ENC_VARINT_QUIC);
                length += (guint)token_length;
            }
            length += tvb_get_varint(tvb, offset + length, 8, &payload_length, ENC_VARINT_QUIC);
            length += (guint)payload_length;
            if (payload_length <= G_MAXINT32 && length < (guint)tvb_reported_length_remaining(tvb, offset)) {
                return tvb_new_subset_length(tvb, offset, length);
            }
        }
    }

    // short header form, VN or unknown message, return remaining data.
    return tvb_new_subset_remaining(tvb, offset);
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
        *long_packet_type = (packet_type & 0x30) >> 4;
    } else {
        // short header form, store dummy value that is not a long packet type.
        *long_packet_type = QUIC_SHORT_PACKET;
    }
    offset++;

    *version = tvb_get_ntohl(tvb, offset);

    if (is_long_header) {
        // skip version
        offset += 4;

        // read DCID and SCID (both are prefixed by a length byte).
        guint8 dcil = tvb_get_guint8(tvb, offset);
        offset++;

        if (dcil && dcil <= QUIC_MAX_CID_LENGTH) {
            tvb_memcpy(tvb, dcid->cid, offset, dcil);
            dcid->len = dcil;
        }
        offset += dcil;

        guint8 scil = tvb_get_guint8(tvb, offset);
        offset++;
        if (scil && scil <= QUIC_MAX_CID_LENGTH) {
            tvb_memcpy(tvb, scid->cid, offset, scil);
            scid->len = scil;
        }
    } else {
        // Definitely not draft -10, set version to dummy value.
        *version = 0;
        // For short headers, the DCID length is unknown and could be 0 or
        // anything from 1 to 20 bytes. Copy the maximum possible and let the
        // consumer truncate it as necessary.
        tvb_memcpy(tvb, dcid->cid, offset, QUIC_MAX_CID_LENGTH);
        dcid->len = QUIC_MAX_CID_LENGTH;
    }
}

static int
dissect_quic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *quic_ti, *ti;
    proto_tree *quic_tree;
    guint       offset = 0;
    quic_datagram *dgram_info = NULL;
    quic_packet_info_t *quic_packet = NULL;
    quic_cid_t  real_retry_odcid = {.len=0}, *retry_odcid = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUIC");

    if (PINFO_FD_VISITED(pinfo)) {
        dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    }
    if (!dgram_info) {
        dgram_info = wmem_new0(wmem_file_scope(), quic_datagram);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_quic, 0, dgram_info);
    }

    quic_ti = proto_tree_add_item(tree, proto_quic, tvb, 0, -1, ENC_NA);
    quic_tree = proto_item_add_subtree(quic_ti, ett_quic);

    if (!PINFO_FD_VISITED(pinfo)) {
        guint8      long_packet_type;
        guint32     version;
        quic_cid_t  dcid = {.len=0}, scid = {.len=0};
        gboolean    from_server = FALSE;
        quic_info_data_t *conn;

        quic_extract_header(tvb, &long_packet_type, &version, &dcid, &scid);
        conn = quic_connection_find(pinfo, long_packet_type, &dcid, &from_server);
        if (conn && long_packet_type == QUIC_LPT_RETRY && conn->client_dcid_set) {
            // Save the original client DCID before erasure.
            real_retry_odcid = conn->client_dcid_initial;
            retry_odcid = &real_retry_odcid;
        }
        quic_connection_create_or_update(&conn, pinfo, long_packet_type, version, &scid, &dcid, from_server);
        dgram_info->conn = conn;
        dgram_info->from_server = from_server;
#if 0
        proto_tree_add_debug_text(quic_tree, "Connection: %d %p DCID=%s SCID=%s from_server:%d", pinfo->num, dgram_info->conn, cid_to_string(&dcid), cid_to_string(&scid), dgram_info->from_server);
    } else {
        proto_tree_add_debug_text(quic_tree, "Connection: %d %p from_server:%d", pinfo->num, dgram_info->conn, dgram_info->from_server);
#endif
    }

    quic_add_connection_info(tvb, pinfo, quic_tree, dgram_info->conn);

    do {
        if (!quic_packet) {
            quic_packet = &dgram_info->first_packet;
        } else if (!PINFO_FD_VISITED(pinfo)) {
            quic_packet->next = wmem_new0(wmem_file_scope(), quic_packet_info_t);
            quic_packet = quic_packet->next;
        } else {
            quic_packet = quic_packet->next;
            DISSECTOR_ASSERT(quic_packet);
        }

        /* Ensure that coalesced QUIC packets end up separated. */
        if (offset > 0) {
            quic_ti = proto_tree_add_item(tree, proto_quic, tvb, offset, -1, ENC_NA);
            quic_tree = proto_item_add_subtree(quic_ti, ett_quic);
        }

        tvbuff_t *next_tvb = quic_get_message_tvb(tvb, offset);
        proto_item_set_len(quic_ti, tvb_reported_length(next_tvb));
        ti = proto_tree_add_uint(quic_tree, hf_quic_packet_length, next_tvb, 0, 0, tvb_reported_length(next_tvb));
        proto_item_set_generated(ti);
        guint new_offset = 0;
        guint8 first_byte = tvb_get_guint8(next_tvb, 0);
        if (first_byte & 0x80) {
            guint8 long_packet_type = (first_byte & 0x30) >> 4;
            proto_tree_add_item(quic_tree, hf_quic_header_form, next_tvb, 0, 1, ENC_NA);
            guint32 version = tvb_get_ntohl(next_tvb, 1);
            if (version == 0) {
                offset += dissect_quic_version_negotiation(next_tvb, pinfo, quic_tree, quic_packet);
                break;
            }
            if (long_packet_type == QUIC_LPT_RETRY) {
                new_offset = dissect_quic_retry_packet(next_tvb, pinfo, quic_tree, dgram_info, quic_packet, retry_odcid);
            } else {
                new_offset = dissect_quic_long_header(next_tvb, pinfo, quic_tree, dgram_info, quic_packet);
            }
        } else if (first_byte != 0) {
            // Firefox neqo adds unencrypted padding consisting of all zeroes
            // after an Initial Packet. Whether that is valid or not is
            // discussed at https://github.com/quicwg/base-drafts/issues/3333
            // As it happens, at least draft -25 requires the "Fixed" bit to be
            // set, so any zero first byte is definitely invalid.
            new_offset = dissect_quic_short_header(next_tvb, pinfo, quic_tree, dgram_info, quic_packet);
        }
        if (tvb_reported_length_remaining(next_tvb, new_offset)) {
            // should usually not be present unless decryption is not possible.
            proto_tree_add_item(quic_tree, hf_quic_remaining_payload, next_tvb, new_offset, -1, ENC_NA);
        }
        offset += tvb_reported_length(next_tvb);
    } while (tvb_reported_length_remaining(tvb, offset));

    return offset;
}

static gboolean
dissect_quic_short_header_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    // If this capture does not contain QUIC, skip the more expensive checks.
    if (quic_cid_lengths == 0) {
        return FALSE;
    }

    // Is this a SH packet after connection migration? SH (since draft -22):
    // Flag (1) + DCID (1-20) + PKN (1/2/4) + encrypted payload (>= 16).
    if (tvb_captured_length(tvb) < 1 + 1 + 1 + 16) {
        return FALSE;
    }

    // DCID length is unknown, so extract the maximum and look for a match.
    quic_cid_t dcid = {.len=QUIC_MAX_CID_LENGTH};
    tvb_memcpy(tvb, dcid.cid, 1, QUIC_MAX_CID_LENGTH);
    gboolean from_server;
    if (!quic_connection_find(pinfo, QUIC_SHORT_PACKET, &dcid, &from_server)) {
        return FALSE;
    }

    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, quic_handle);
    dissect_quic(tvb, pinfo, tree, NULL);
    return TRUE;
}

static gboolean dissect_quic_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /*
     * Since draft -22:
     * Flag (1 byte) + Version (4 bytes) +
     * Length (1 byte) + Destination Connection ID (0..255) +
     * Length (1 byte) + Source Connection ID (0..255) +
     * Payload length (1/2/4/8) + Packet number (1/2/4 bytes) + Payload.
     * (absolute minimum: 9 + payload)
     * (for Version Negotiation, payload len + PKN + payload is replaced by
     * Supported Version (multiple of 4 bytes.)
     */
    conversation_t *conversation = NULL;
    int offset = 0;
    guint8 flags;
    guint32 version;
    gboolean is_quic = FALSE;

    /* Verify packet size  (Flag (1 byte) + Connection ID (8 bytes) + Version (4 bytes)) */
    if (tvb_captured_length(tvb) < 13)
    {
        return FALSE;
    }

    flags = tvb_get_guint8(tvb, offset);
    /* Check if long Packet is set */
    if((flags & 0x80) == 0) {
        // Perhaps this is a short header, check it.
        return dissect_quic_short_header_heur(tvb, pinfo, tree);
    }
    offset += 1;

    // check for draft QUIC version (for draft -11 and newer)
    version = tvb_get_ntohl(tvb, offset);
    is_quic = (quic_draft_version(version) >= 11);

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
    quic_cid_lengths = 0;
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

/* Follow QUIC Stream functionality {{{ */

static gchar *
quic_follow_conv_filter(packet_info *pinfo, guint *stream, guint *sub_stream)
{
    if (((pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) ||
        (pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6))) {
        gboolean from_server;
        quic_info_data_t *conn = quic_connection_find_dcid(pinfo, NULL, &from_server);
        if (!conn) {
            return NULL;
        }
        // XXX Look up stream ID for the current packet.
        guint stream_id = 0;
        *stream = conn->number;
        *sub_stream = stream_id;
        return g_strdup_printf("quic.connection.number eq %u and quic.stream.stream_id eq %u", conn->number, stream_id);
    }

    return NULL;
}

static gchar *
quic_follow_index_filter(guint stream, guint sub_stream)
{
    return g_strdup_printf("quic.connection.number eq %u and quic.stream.stream_id eq %u", stream, sub_stream);
}

static gchar *
quic_follow_address_filter(address *src_addr _U_, address *dst_addr _U_, int src_port _U_, int dst_port _U_)
{
    // This appears to be solely used for tshark. Let's not support matching by
    // IP addresses and UDP ports for now since that fails after connection
    // migration. If necessary, use udp_follow_address_filter.
    return NULL;
}

static tap_packet_status
follow_quic_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data)
{
    // TODO fix filtering for multiple streams, see
    // https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16093
    follow_tvb_tap_listener(tapdata, pinfo, NULL, data);
    return TAP_PACKET_DONT_REDRAW;
}

guint32 get_quic_connections_count(void)
{
    return quic_connections_count;
}
/* Follow QUIC Stream functionality }}} */

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

        { &hf_quic_packet_length,
          { "Packet Length", "quic.packet_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Size of the QUIC packet", HFILL }
        },

        { &hf_quic_header_form,
          { "Header Form", "quic.header_form",
            FT_UINT8, BASE_DEC, VALS(quic_short_long_header_vals), 0x80,
            "The most significant bit (0x80) of the first octet is set to 1 for long headers and 0 for short headers.", HFILL }
        },

        { &hf_quic_long_packet_type,
          { "Packet Type", "quic.long.packet_type",
            FT_UINT8, BASE_DEC, VALS(quic_long_packet_type_vals), 0x30,
            "Long Header Packet Type", HFILL }
        },
        { &hf_quic_long_reserved,
          { "Reserved", "quic.long.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0c,
            "Reserved bits (protected using header protection)", HFILL }
        },
        { &hf_quic_packet_number_length,
          { "Packet Number Length", "quic.packet_number_length",
            FT_UINT8, BASE_DEC, VALS(quic_packet_number_lengths), 0x03,
            "Packet Number field length (protected using header protection)", HFILL }
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
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_scil,
          { "Source Connection ID Length", "quic.scil",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_token_length,
          { "Token Length", "quic.token_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_token,
          { "Token", "quic.token",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_length,
          { "Length", "quic.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of Packet Number and Payload fields", HFILL }
        },

        { &hf_quic_packet_number,
          { "Packet Number", "quic.packet_number",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Decoded packet number", HFILL }
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
        { &hf_quic_vn_unused,
          { "Unused", "quic.vn.unused",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_quic_short,
          { "QUIC Short Header", "quic.short",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_fixed_bit,
          { "Fixed Bit", "quic.fixed_bit",
            FT_BOOLEAN, 8, NULL, 0x40,
            "Must be 1", HFILL }
        },
        { &hf_quic_spin_bit,
          { "Spin Bit", "quic.spin_bit",
            FT_BOOLEAN, 8, NULL, 0x20,
            "Latency Spin Bit", HFILL }
        },
        { &hf_quic_short_reserved,
          { "Reserved", "quic.short.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x18,
            "Reserved bits (protected using header protection)", HFILL }
        },
        { &hf_quic_key_phase,
          { "Key Phase Bit", "quic.key_phase",
            FT_BOOLEAN, 8, NULL, SH_KP,
            "Selects the packet protection keys to use (protected using header protection)", HFILL }
        },

        { &hf_quic_payload,
          { "Payload", "quic.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "(Encrypted) payload of a packet", HFILL }
        },
        { &hf_quic_protected_payload,
          { "Protected Payload", "quic.protected_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "1-RTT protected payload", HFILL }
        },
        { &hf_quic_remaining_payload,
          { "Remaining Payload", "quic.remaining_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Remaining payload in a packet (possibly PKN followed by encrypted payload)", HFILL }
        },

        { &hf_quic_odcil,
          { "Original Destination Connection ID Length", "quic.odcil",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_odcid,
          { "Original Destination Connection ID", "quic.odcid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_retry_token,
          { "Retry Token", "quic.retry_token",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_retry_integrity_tag,
          { "Retry Integrity Tag", "quic.retry_integrity_tag",
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
            FT_UINT64, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_frame_type_vals), 0x0,
            NULL, HFILL }
        },

        /* PADDING */
        { &hf_quic_padding_length,
          { "Padding Length", "quic.padding_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        /* ACK */
        { &hf_quic_ack_largest_acknowledged,
          { "Largest Acknowledged", "quic.ack.largest_acknowledged",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Largest packet number the peer is acknowledging in this packet", HFILL }
        },
        { &hf_quic_ack_ack_delay,
          { "ACK Delay", "quic.ack.ack_delay",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Time from when the largest acknowledged packet, as indicated in the Largest Acknowledged field, was received by this peer to when this ACK was sent", HFILL }
        },
        { &hf_quic_ack_ack_range_count,
          { "ACK Range Count", "quic.ack.ack_range_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of Gap and ACK Range fields in the frame", HFILL }
        },
        { &hf_quic_ack_first_ack_range,
          { "First ACK Range", "quic.ack.first_ack_range",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of contiguous packets preceding the Largest Acknowledged that are being acknowledged", HFILL }
        },
        { &hf_quic_ack_gap,
          { "Gap", "quic.ack.gap",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in the preceding ACK Range", HFILL }
        },
        { &hf_quic_ack_ack_range,
          { "ACK Range", "quic.ack.ack_range",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of contiguous acknowledged packets preceding the largest packet number, as determined by the preceding Gap", HFILL }
        },
        { &hf_quic_ack_ect0_count,
          { "ECT(0) Count", "quic.ack.ect0_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Total number of packets received with the ECT(0) codepoint", HFILL }
        },
        { &hf_quic_ack_ect1_count,
          { "ECT(1) Count", "quic.ack.ect1_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Total number of packets received with the ECT(1) codepoint", HFILL }
        },
        { &hf_quic_ack_ecn_ce_count,
          { "ECN-CE Count", "quic.ack.ecn_ce_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Total number of packets received with the CE codepoint", HFILL }
        },
        /* RESET_STREAM */
        { &hf_quic_rsts_stream_id,
            { "Stream ID", "quic.rsts.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_rsts_application_error_code,
            { "Application Error code", "quic.rsts.application_error_code",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicates why the stream is being closed", HFILL }
        },
        { &hf_quic_rsts_final_size,
            { "Final Size", "quic.rsts.final_size",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The final size of the stream by the RESET_STREAM sender (in bytes)", HFILL }
        },
        /* STOP_SENDING */
        { &hf_quic_ss_stream_id,
            { "Stream ID", "quic.ss.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being ignored", HFILL }
        },
        { &hf_quic_ss_application_error_code,
            { "Application Error code", "quic.ss.application_error_code",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicates why the sender is ignoring the stream", HFILL }
        },
        /* CRYPTO */
        { &hf_quic_crypto_offset,
            { "Offset", "quic.crypto.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Byte offset into the stream", HFILL }
        },
        { &hf_quic_crypto_length,
            { "Length", "quic.crypto.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Length of the Crypto Data field", HFILL }
        },
        { &hf_quic_crypto_crypto_data,
            { "Crypto Data", "quic.crypto.crypto_data",
              FT_NONE, BASE_NONE, NULL, 0x0,
              "The cryptographic message data", HFILL }
        },
        /* NEW_TOKEN */
        { &hf_quic_nt_length,
            { "(Token) Length", "quic.nt.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the token", HFILL }
        },
        { &hf_quic_nt_token,
            { "Token", "quic.nt.token",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "An opaque blob that the client may use with a future Initial packet", HFILL }
        },
        /* STREAM */
        { &hf_quic_stream_fin,
          { "Fin", "quic.stream.fin",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_FIN,
            NULL, HFILL }
        },
        { &hf_quic_stream_len,
          { "Len(gth)", "quic.stream.len",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_LEN,
            NULL, HFILL }
        },
        { &hf_quic_stream_off,
          { "Off(set)", "quic.stream.off",
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

        /* MAX_DATA */
        { &hf_quic_md_maximum_data,
            { "Maximum Data", "quic.md.maximum_data",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the maximum amount of data that can be sent on the entire connection, in units of 1024 octets", HFILL }
        },
        /* MAX_STREAM_DATA */
        { &hf_quic_msd_stream_id,
            { "Stream ID", "quic.msd.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The stream ID of the stream that is affected", HFILL }
        },
        { &hf_quic_msd_maximum_stream_data,
            { "Maximum Stream Data", "quic.msd.maximum_stream_data",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the maximum amount of data that can be sent on the identified stream, in units of octets", HFILL }
        },
        /* MAX_STREAMS */
        { &hf_quic_ms_max_streams,
            { "Max Streams", "quic.ms.max_streams",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "A count of the cumulative number of streams of the corresponding type that can be opened over the lifetime of the connection", HFILL }
        },
        /* DATA_BLOCKED */
        { &hf_quic_db_stream_data_limit,
            { "Stream Data Limit", "quic.sb.stream_data_limit",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the connection-level limit at which the blocking occurred", HFILL }
        },
        /* STREAM_DATA_BLOCKED */
        { &hf_quic_sdb_stream_id,
            { "Stream ID", "quic.sdb.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the stream which is flow control blocked", HFILL }
        },
        { &hf_quic_sdb_stream_data_limit,
            { "Stream Data Limit", "quic.sb.stream_data_limit",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the offset of the stream at which the blocking occurred", HFILL }
        },
        /* STREAMS_BLOCKED */
        { &hf_quic_sb_stream_limit,
            { "Stream Limit", "quic.sib.stream_limit",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the stream limit at the time the frame was sent", HFILL }
        },
        /* NEW_CONNECTION_ID */
        { &hf_quic_nci_retire_prior_to,
            { "Retire Prior To", "quic.nci.retire_prior_to",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "A variable-length integer indicating which connection IDs should be retired", HFILL }
        },
        { &hf_quic_nci_sequence,
            { "Sequence", "quic.nci.sequence",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Increases by 1 for each connection ID that is provided by the server", HFILL }
        },
        { &hf_quic_nci_connection_id_length,
            { "Connection ID Length", "quic.nci.connection_id.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_nci_connection_id,
            { "Connection ID", "quic.nci.connection_id",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_nci_stateless_reset_token,
            { "Stateless Reset Token", "quic.stateless_reset_token",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        /* RETIRE_CONNECTION_ID */
        { &hf_quic_rci_sequence,
            { "Sequence", "quic.rci.sequence",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The sequence number of the connection ID being retired", HFILL }
        },
        /* PATH_CHALLENGE */
        { &hf_quic_path_challenge_data,
          { "Data", "quic.path_challenge.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Arbitrary data that must be matched by a PATH_RESPONSE frame", HFILL }
        },
        /* PATH_RESPONSE */
        { &hf_quic_path_response_data,
          { "Data", "quic.path_response.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Arbitrary data that must match a PATH_CHALLENGE frame", HFILL }
        },
        /* CONNECTION_CLOSE */
        { &hf_quic_cc_error_code,
            { "Error code", "quic.cc.error_code",
              FT_UINT64, BASE_DEC|BASE_RANGE_STRING, RVALS(quic_transport_error_code_vals), 0x0,
              "Indicates the reason for closing this connection", HFILL }
        },
        { &hf_quic_cc_error_code_app,
            { "Application Error code", "quic.cc.error_code.app",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicates the reason for closing this application", HFILL }
        },
        { &hf_quic_cc_error_code_tls_alert,
            { "TLS Alert Description", "quic.cc.error_code.tls_alert",
              FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
              NULL, HFILL }
        },
        { &hf_quic_cc_frame_type,
            { "Frame Type", "quic.cc.frame_type",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The type of frame that triggered the error", HFILL }
        },
        { &hf_quic_cc_reason_phrase_length,
            { "Reason phrase Length", "quic.cc.reason_phrase.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_cc_reason_phrase,
            { "Reason phrase", "quic.cc.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A human-readable explanation for why the connection was closed", HFILL }
        },
        /* DATAGRAM */
        { &hf_quic_dg_length,
            { "Datagram Length", "quic.dg.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the the datagram in bytes", HFILL }
        },
        { &hf_quic_dg,
            { "Datagram", "quic.dg",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "The bytes of the datagram to be delivered", HFILL }
        },
        /* ACK-FREQUENCY */
        { &hf_quic_af_sequence_number,
            { "Sequence Number", "quic.af.sequence_number",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Sequence number assigned to the ACK-FREQUENCY frame by the sender to allow receivers to ignore obsolete frames", HFILL }
        },
        { &hf_quic_af_packet_tolerance,
            { "Packet Tolerance", "quic.af.packet_tolerance",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing the maximum number of ack-eliciting packets after which the receiver sends an acknowledgement", HFILL }
        },
        { &hf_quic_af_update_max_ack_delay,
            { "Update Max Ack Delay", "quic.af.update_max_ack_delay",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing an update to the peer's 'max_ack_delay' transport parameter", HFILL }
        },
        { &hf_quic_ts,
            { "Time Stamp", "quic.ts",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* Fields for QUIC Stream data reassembly. */
        { &hf_quic_fragment_overlap,
          { "Fragment overlap", "quic.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_quic_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "quic.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_quic_fragment_multiple_tails,
          { "Multiple tail fragments found", "quic.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the pdu", HFILL }
        },
        { &hf_quic_fragment_too_long_fragment,
          { "Fragment too long", "quic.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of the pdu", HFILL }
        },
        { &hf_quic_fragment_error,
          { "Reassembling error", "quic.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembling error due to illegal fragments", HFILL }
        },
        { &hf_quic_fragment_count,
          { "Fragment count", "quic.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_fragment,
          { "QUIC STREAM Data Fragment", "quic.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_fragments,
          { "Reassembled QUIC STREAM Data Fragments", "quic.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "QUIC STREAM Data Fragments", HFILL }
        },
        { &hf_quic_reassembled_in,
          { "Reassembled PDU in frame", "quic.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this fragment is reassembled in this frame", HFILL }
        },
        { &hf_quic_reassembled_length,
          { "Reassembled QUIC STREAM Data length", "quic.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }
        },
        { &hf_quic_reassembled_data,
          { "Reassembled QUIC STREAM Data", "quic.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "The reassembled payload", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_quic,
        &ett_quic_short_header,
        &ett_quic_connection_info,
        &ett_quic_ft,
        &ett_quic_ftflags,
        &ett_quic_fragments,
        &ett_quic_fragment,
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
        { &ei_quic_bad_retry,
          { "quic.bad_retry", PI_PROTOCOL, PI_WARN,
            "Retry Integrity Tag verification failure", EXPFILL }
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

    register_follow_stream(proto_quic, "quic_follow", quic_follow_conv_filter, quic_follow_index_filter, quic_follow_address_filter,
                           udp_port_to_display, follow_quic_tap_listener);

    // TODO implement custom reassembly functions that uses the QUIC Connection
    // ID instead of address and port numbers.
    reassembly_table_register(&quic_reassembly_table,
                              &addresses_ports_reassembly_table_functions);

    /*
     * Application protocol. QUIC with TLS uses ALPN.
     * https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-7
     * This could in theory be an arbitrary octet string with embedded NUL
     * bytes, but in practice these do not exist yet.
     */
    quic_proto_dissector_table = register_dissector_table("quic.proto", "QUIC Protocol", proto_quic, FT_STRING, FALSE);
}

void
proto_reg_handoff_quic(void)
{
    tls13_handshake_handle = find_dissector("tls13-handshake");
    dissector_add_uint_with_preference("udp.port", 0, quic_handle);
    heur_dissector_add("udp", dissect_quic_heur, "QUIC", "quic", proto_quic, HEURISTIC_ENABLE);
    quic_follow_tap = register_tap("quic_follow");
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
