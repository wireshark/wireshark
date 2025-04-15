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
 * RFC9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 * RFC9001 Using TLS to Secure QUIC
 * RFC8889 Version-Independent Properties of QUIC
 * RFC9221 An Unreliable Datagram Extension to QUIC
 * RFC9369 QUIC Version 2
 * RFC9368 Compatible Version Negotiation for QUIC
 *
 * Extension:
 * https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03
 * https://tools.ietf.org/html/draft-huitema-quic-ts-02
 * https://tools.ietf.org/html/draft-ietf-quic-ack-frequency-07 (and also draft-04/05)
 * https://tools.ietf.org/html/draft-banks-quic-cibir-01
 * https://tools.ietf.org/html/draft-ietf-quic-multipath-10 (and also >= draft-07)

 *
 * Currently supported QUIC version(s): draft-21, draft-22, draft-23, draft-24,
 * draft-25, draft-26, draft-27, draft-28, draft-29, draft-30, draft-31, draft-32,
 * draft-33, draft-34, v1, v2
 * For a table of supported QUIC versions per Wireshark version, see
 * https://github.com/quicwg/base-drafts/wiki/Tools#wireshark
 *
 * Decryption is supported via TLS 1.3 secrets in the "TLS Key Log File",
 * configured either at the TLS Protocol preferences, or embedded in a pcapng
 * file. Sample captures and secrets can be found at:
 * https://gitlab.com/wireshark/wireshark/-/issues/13881
 *
 * Limitations:
 * - STREAM offsets larger than 32-bit are unsupported.
 * - STREAM with sizes larger than 32 bit are unsupported. STREAM sizes can be
 *   up to 62 bit in QUIC, but the TVB and reassembly API is limited to 32 bit.
 * - Out-of-order and overlapping STREAM frame data is not handled.
 * - "Follow QUIC Stream" doesn't work with STREAM IDs larger than 32 bit
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

static int quic_follow_tap;

/* Initialize the protocol and registered fields */
static int proto_quic;
static int hf_quic_connection_number;
static int hf_quic_packet_length;
static int hf_quic_header_form;
static int hf_quic_long_packet_type;
static int hf_quic_long_packet_type_v2;
static int hf_quic_long_reserved;
static int hf_quic_packet_number_length;
static int hf_quic_dcid;
static int hf_quic_scid;
static int hf_quic_dcil;
static int hf_quic_scil;
static int hf_quic_token_length;
static int hf_quic_token;
static int hf_quic_length;
static int hf_quic_packet_number;
static int hf_quic_version;
static int hf_quic_supported_version;
static int hf_quic_vn_unused;
static int hf_quic_short;
static int hf_quic_fixed_bit;
static int hf_quic_spin_bit;
static int hf_quic_short_reserved;
static int hf_quic_q_bit;
static int hf_quic_l_bit;
static int hf_quic_key_phase;
static int hf_quic_payload;
static int hf_quic_protected_payload;
static int hf_quic_remaining_payload;
static int hf_quic_odcil;
static int hf_quic_odcid;
static int hf_quic_retry_token;
static int hf_quic_retry_integrity_tag;

static int hf_quic_frame;
static int hf_quic_frame_type;

static int hf_quic_padding_length;
static int hf_quic_ack_largest_acknowledged;
static int hf_quic_ack_ack_delay;
static int hf_quic_ack_ack_range_count;
static int hf_quic_ack_first_ack_range;
static int hf_quic_ack_gap;
static int hf_quic_ack_ack_range;
static int hf_quic_ack_ect0_count;
static int hf_quic_ack_ect1_count;
static int hf_quic_ack_ecn_ce_count;
static int hf_quic_rsts_stream_id;
static int hf_quic_rsts_application_error_code;
static int hf_quic_rsts_final_size;
static int hf_quic_ss_stream_id;
static int hf_quic_ss_application_error_code;
static int hf_quic_crypto_offset;
static int hf_quic_crypto_length;
static int hf_quic_crypto_crypto_data;
static int hf_quic_nt_length;
static int hf_quic_nt_token;
static int hf_quic_stream_fin;
static int hf_quic_stream_len;
static int hf_quic_stream_off;
static int hf_quic_stream_stream_id;
static int hf_quic_stream_initiator;
static int hf_quic_stream_direction;
static int hf_quic_stream_offset;
static int hf_quic_stream_length;
static int hf_quic_stream_data;
static int hf_quic_md_maximum_data;
static int hf_quic_msd_stream_id;
static int hf_quic_msd_maximum_stream_data;
static int hf_quic_ms_max_streams;
static int hf_quic_db_stream_data_limit;
static int hf_quic_sdb_stream_id;
static int hf_quic_sdb_stream_data_limit;
static int hf_quic_sb_stream_limit;
static int hf_quic_nci_retire_prior_to;
static int hf_quic_nci_sequence;
static int hf_quic_nci_connection_id_length;
static int hf_quic_nci_connection_id;
static int hf_quic_nci_stateless_reset_token;
static int hf_quic_rci_sequence;
static int hf_quic_path_challenge_data;
static int hf_quic_path_response_data;
static int hf_quic_cc_error_code;
static int hf_quic_cc_error_code_app;
static int hf_quic_cc_error_code_tls_alert;
static int hf_quic_cc_frame_type;
static int hf_quic_cc_reason_phrase_length;
static int hf_quic_cc_reason_phrase;
static int hf_quic_dg_length;
static int hf_quic_dg;
static int hf_quic_af_sequence_number;
static int hf_quic_af_ack_eliciting_threshold;
static int hf_quic_af_request_max_ack_delay;
static int hf_quic_af_reordering_threshold;
//static int hf_quic_af_ignore_order;
//static int hf_quic_af_ignore_ce;
static int hf_quic_ts;
static int hf_quic_unpredictable_bits;
static int hf_quic_stateless_reset_token;
static int hf_quic_reassembled_in;
static int hf_quic_reassembled_length;
static int hf_quic_reassembled_data;
static int hf_quic_fragments;
static int hf_quic_fragment;
static int hf_quic_fragment_overlap;
static int hf_quic_fragment_overlap_conflict;
static int hf_quic_fragment_multiple_tails;
static int hf_quic_fragment_too_long_fragment;
static int hf_quic_fragment_error;
static int hf_quic_fragment_count;

static int hf_quic_crypto_reassembled_in;
static int hf_quic_crypto_fragments;
static int hf_quic_crypto_fragment;
static int hf_quic_crypto_fragment_count;

/* multipath*/
static int hf_quic_mp_nci_path_identifier;
static int hf_quic_mp_rc_path_identifier;
static int hf_quic_mp_ack_path_identifier;
static int hf_quic_mp_pa_path_identifier;
static int hf_quic_mp_ps_path_identifier;
static int hf_quic_mp_ps_path_status_sequence_number;
static int hf_quic_mp_ps_path_status;
static int hf_quic_mp_maximum_paths;
static int hf_quic_mp_maximum_path_identifier;

static expert_field ei_quic_connection_unknown;
static expert_field ei_quic_ft_unknown;
static expert_field ei_quic_decryption_failed;
static expert_field ei_quic_protocol_violation;
static expert_field ei_quic_bad_retry;
static expert_field ei_quic_coalesced_padding_data;
static expert_field ei_quic_retransmission;
static expert_field ei_quic_overlap;
static expert_field ei_quic_data_after_forcing_vn;

static int ett_quic;
static int ett_quic_af;
static int ett_quic_short_header;
static int ett_quic_connection_info;
static int ett_quic_ft;
static int ett_quic_ftflags;
static int ett_quic_ftid;
static int ett_quic_fragments;
static int ett_quic_fragment;
static int ett_quic_crypto_fragments;
static int ett_quic_crypto_fragment;

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

/* Fields for showing reassembly results for fragments of QUIC crypto packets. */
static const fragment_items quic_crypto_fragment_items = {
    &ett_quic_crypto_fragment,
    &ett_quic_crypto_fragments,
    &hf_quic_crypto_fragments,
    &hf_quic_crypto_fragment,
    &hf_quic_fragment_overlap, /* We can reuse the error fields. */
    &hf_quic_fragment_overlap_conflict,
    &hf_quic_fragment_multiple_tails,
    &hf_quic_fragment_too_long_fragment,
    &hf_quic_fragment_error,
    &hf_quic_crypto_fragment_count,
    &hf_quic_crypto_reassembled_in,
    NULL, /* length, redundant */
    NULL, /* data, redundant */
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
 *   client keys will be ready while client processes Server Hello (Handshake).
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
 *
 * The multipath draft features introduces separate appdata number spaces for
 * each Path ID. (prior to draft-07, for each Destination Connection ID.)
 */

/* Loss bits feature: https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03
   "The use of the loss bits is negotiated using a transport parameter.
    [..]
    When loss_bits parameter is present, the peer is allowed to use
    reserved bits in the short packet header as loss bits if the peer
    sends loss_bits=1.
    When loss_bits is set to 1, the sender will use reserved bits as loss
    bits if the peer includes the loss_bits transport parameter.
    [..]
    Unlike the reserved (R) bits, the loss (Q and L) bits are not
    protected.  When sending loss bits has been negotiated, the first
    byte of the header protection mask used to protect short packet
    headers has its five most significant bits masked out instead of
    three.
*/

typedef struct quic_decrypt_result {
    const unsigned char   *error;      /**< Error message or NULL for success. */
    const uint8_t  *data;       /**< Decrypted result on success (file-scoped). */
    unsigned        data_len;   /**< Size of decrypted data. */
} quic_decrypt_result_t;

/** QUIC decryption context. */


typedef struct quic_hp_cipher {
    gcry_cipher_hd_t    hp_cipher;  /**< Header protection cipher. */
} quic_hp_cipher;
typedef struct quic_pp_cipher {
    gcry_cipher_hd_t    pp_cipher;  /**< Packet protection cipher. */
    uint8_t             pp_iv[TLS13_AEAD_NONCE_LENGTH];
} quic_pp_cipher;
typedef struct quic_ciphers {
    quic_hp_cipher hp_cipher;
    quic_pp_cipher pp_cipher;
} quic_ciphers;

/**
 * Packet protection state for an endpoint.
 */
typedef struct quic_pp_state {
    uint8_t        *next_secret;    /**< Next application traffic secret. */
    quic_pp_cipher  pp_ciphers[2];  /**< PP cipher for Key Phase 0/1 */
    quic_hp_cipher  hp_cipher;      /**< HP cipher for both Key Phases; it does not change after KeyUpdate */
    uint64_t        changed_in_pkn; /**< Packet number where key change occurred. */
    bool            key_phase : 1;  /**< Current key phase. */
} quic_pp_state_t;

/** Singly-linked list of Connection IDs. */
typedef struct quic_cid_item quic_cid_item_t;
struct quic_cid_item {
    struct quic_cid_item   *next;
    quic_cid_t              data;
};

/**
 * CRYPTO stream state.
 *
 */
typedef struct _quic_crypto_state {
    uint64_t        max_contiguous_offset;
    uint8_t         encryption_level; /**< AKA packet type */
    wmem_tree_t    *multisegment_pdus;
    wmem_map_t     *retrans_offsets;
} quic_crypto_state;

/**
 * Per-STREAM state, identified by QUIC Stream ID.
 *
 * Assume that every QUIC Short Header packet has no STREAM frames that overlap
 * each other in the same QUIC packet (identified by "frame_num"). Thus, the
 * Stream ID and offset uniquely identifies the STREAM Frame info in per packet.
 */
typedef struct _quic_stream_state {
    uint64_t        stream_id;
    wmem_tree_t    *multisegment_pdus;
    void           *subdissector_private;
} quic_stream_state;

/**
 * Data used to allow "Follow QUIC Stream" functionality
 */
typedef struct _quic_follow_stream {
    uint32_t        num;
    uint64_t        stream_id;
} quic_follow_stream;

typedef struct quic_follow_tap_data {
    tvbuff_t *tvb;
    uint64_t stream_id;
    bool from_server;
} quic_follow_tap_data_t;

/**
 * State for a single QUIC connection, identified by one or more Destination
 * Connection IDs (DCID).
 */
typedef struct quic_info_data quic_info_data_t;
struct quic_info_data {
    uint32_t        number;         /** Similar to "udp.stream", but for identifying QUIC connections across migrations. */
    uint32_t        version;
    address         server_address;
    uint16_t        server_port;
    bool            skip_decryption : 1; /**< Set to 1 if no keys are available. */
    bool            client_dcid_set : 1; /**< Set to 1 if client_dcid_initial is set. */
    bool            client_loss_bits_recv : 1; /**< The client is able to read loss bits info */
    bool            client_loss_bits_send : 1; /**< The client wants to send loss bits info */
    bool            server_loss_bits_recv : 1; /**< The server is able to read loss bits info */
    bool            server_loss_bits_send : 1; /**< The server wants to send loss bits info */
    unsigned        client_multipath : 2; /**< The client supports multipath */
    unsigned        server_multipath : 2; /**< The server supports multipath */
    bool            client_grease_quic_bit : 1; /**< The client supports greasing the Fixed (QUIC) bit */
    bool            server_grease_quic_bit : 1; /**< The server supports greasing the Fixed (QUIC) bit */
    int             hash_algo;      /**< Libgcrypt hash algorithm for key derivation. */
    int             cipher_algo;    /**< Cipher algorithm for packet number and packet encryption. */
    int             cipher_mode;    /**< Cipher mode for packet encryption. */
    quic_ciphers    client_initial_ciphers;
    quic_ciphers    server_initial_ciphers;
    quic_ciphers    client_0rtt_ciphers;
    quic_ciphers    client_handshake_ciphers;
    quic_ciphers    server_handshake_ciphers;
    quic_pp_state_t client_pp;
    quic_pp_state_t server_pp;
    uint64_t        max_client_pkn[3];  /**< Packet number spaces for Initial, Handshake and appdata. */
    uint64_t        max_server_pkn[3];
    wmem_map_t      *max_client_mp_pkn; /**< Appdata packet number spaces for multipath, by sequence number. */
    wmem_map_t      *max_server_mp_pkn;
    quic_cid_item_t client_cids;    /**< SCID of client from first Initial Packet. */
    quic_cid_item_t server_cids;    /**< SCID of server from first Retry/Handshake. */
    quic_cid_t      client_dcid_initial;    /**< DCID from Initial Packet. */
    dissector_handle_t app_handle;  /**< Application protocol handle (NULL if unknown). */
    dissector_handle_t zrtt_app_handle;  /**< Application protocol handle (NULL if unknown) for 0-RTT data. */
    wmem_map_t     *client_streams; /**< Map from Stream ID -> STREAM info (uint64_t -> quic_stream_state), sent by the client. */
    wmem_map_t     *server_streams; /**< Map from Stream ID -> STREAM info (uint64_t -> quic_stream_state), sent by the server. */
    wmem_list_t    *streams_list;   /**< Ordered list of QUIC Stream ID in this connection (both directions). Used by "Follow QUIC Stream" functionality */
    wmem_map_t     *streams_map;    /**< Map pinfo->num --> First stream in that frame (unsigned -> quic_follow_stream). Used by "Follow QUIC Stream" functionality */
    wmem_map_t     *client_crypto;
    wmem_map_t     *server_crypto;
    gquic_info_data_t *gquic_info; /**< GQUIC info for >Q050 flows. */
    quic_info_data_t *prev; /**< The previous QUIC connection multiplexed on the same network 5-tuple. Used by checking Stateless Reset tokens */
};

typedef struct _quic_crypto_info {
    const uint64_t packet_number; /**< Reconstructed full packet number. */
    uint64_t    crypto_offset;  /**< 62-bit stream offset. */
    uint32_t    offset;         /**< Offset within the stream (different for reassembled data). */
    bool        from_server;
} quic_crypto_info;

/** Per-packet information about QUIC, populated on the first pass. */
struct quic_packet_info {
    struct quic_packet_info *next;
    uint64_t                packet_number;  /**< Reconstructed full packet number. */
    quic_decrypt_result_t   decryption;
    uint8_t                 pkn_len;        /**< Length of PKN (1/2/3/4) or unknown (0). */
    uint8_t                 first_byte;     /**< Decrypted flag byte, valid only if pkn_len is non-zero. */
    uint8_t                 packet_type;
    bool                    retry_integrity_failure : 1;
    bool                    retry_integrity_success : 1;
};
typedef struct quic_packet_info quic_packet_info_t;

/** A UDP datagram contains one or more QUIC packets. */
typedef struct quic_datagram {
    quic_info_data_t       *conn;
    quic_packet_info_t      first_packet;
    uint64_t                path_id; /**< Path ID of the connection ID */
    /* For multipath prior to draft-07, sequence number and path ID are the
     * same and unique for each CID on the connection.
     */
    bool                    from_server : 1;
    bool                    stateless_reset : 1;
} quic_datagram;

/**
 * Maps CID (quic_cid_t *) to a QUIC Connection (quic_info_data_t *).
 * This assumes that the CIDs are not shared between two different connections
 * (potentially with different versions) as that would break dissection.
 *
 * These mappings are authoritative. For example, Initial.SCID is stored in
 * quic_client_connections while Retry.SCID is stored in
 * quic_server_connections. Retry.DCID should normally correspond to an entry in
 * quic_client_connections.
 */
static wmem_map_t *quic_client_connections, *quic_server_connections;
static wmem_map_t *quic_initial_connections;    /* Initial.DCID -> connection */
static wmem_list_t *quic_connections;   /* All unique connections. */
static uint32_t quic_cid_lengths;        /* Bitmap of CID lengths. */
static unsigned quic_connections_count;

static unsigned
quic_multipath_negotiated(quic_info_data_t *conn);

/* Returns the QUIC draft version or 0 if not applicable. */
static inline uint8_t quic_draft_version(uint32_t version) {
    /* IETF Draft versions */
    if ((version >> 8) == 0xff0000) {
       return (uint8_t) version;
    }
    /* Facebook mvfst, based on draft -22. */
    if (version == 0xfaceb001) {
        return 22;
    }
    /* Facebook mvfst, based on draft -27. */
    if (version == 0xfaceb002 || version == 0xfaceb00e) {
        return 27;
    }
    /* GQUIC Q050, T050 and T051: they are not really based on any drafts,
     * but we must return a sensible value */
    if (version == 0x51303530 ||
        version == 0x54303530 ||
        version == 0x54303531) {
        return 27;
    }
    /* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
       "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
       forcing version negotiation to be exercised"
       We can't return a correct draft version because we don't have a real
       version here! That means that we can't decode any data and we can dissect
       only the cleartext header.
       Let's return v1 (any other numbers should be fine, anyway) to only allow
       the dissection of the (expected) long header */
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
        return 34;
    }
    /* QUIC (final?) constants for v1 are defined in draft-33, but draft-34 is the
       final draft version */
    if (version == 0x00000001) {
        return 34;
    }
    /* QUIC Version 2 */
    if (version == 0x6b3343cf) {
       return 100;
    }
    return 0;
}

static inline bool is_quic_v2(uint32_t version) {
    return version == 0x6b3343cf;
}

static inline bool is_quic_draft_max(uint32_t version, uint8_t max_version) {
    uint8_t draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

const range_string quic_version_vals[] = {
    { 0x00000000, 0x00000000, "Version Negotiation" },
    { 0x00000001, 0x00000001, "1" },
    { 0x45474700, 0x454747ff, "Quant" },
    { 0x50435130, 0x50435131, "Picoquic internal" },
    { 0x50524f58, 0x50524f58, "Proxied QUIC (PROX)" },
    /* Versions QXXX < Q050 are dissected by Wireshark as GQUIC and not as QUIC.
       Nonetheless, some implementations report these values in "Version Negotiation"
       packets, so decode these fields */
    { 0x51303433, 0x51303433, "Google Q043" },
    { 0x51303434, 0x51303434, "Google Q044" },
    { 0x51303436, 0x51303436, "Google Q046" },
    { 0x51303530, 0x51303530, "Google Q050" },
    { 0x51474f00, 0x51474fff, "QGO (QUIC GO)" },
    { 0x54303530, 0x54303530, "Google T050" },
    { 0x54303531, 0x54303531, "Google T051" },
    { 0x91c17000, 0x91c170ff, "Quicly" },
    { 0xabcd0000, 0xabcd000f, "MsQuic" },
    { 0xf0f0f0f0, 0xf0f0f0ff, "ETH Zürich (Measurability experiments)" },
    { 0xf0f0f1f0, 0xf0f0f1ff, "Telecom Italia (Measurability experiments)" },
    { 0xf123f0c0, 0xf123f0cf, "MozQuic" },
    { 0xfaceb001, 0xfaceb001, "Facebook mvfst (draft-22)" },
    { 0xfaceb002, 0xfaceb002, "Facebook mvfst (draft-27)" },
    { 0xfaceb003, 0xfaceb00d, "Facebook mvfst" },
    { 0xfaceb00e, 0xfaceb00e, "Facebook mvfst (Experimental)" },
    { 0xfaceb00f, 0xfaceb00f, "Facebook mvfst" },
    { 0xff000004, 0xff000004, "draft-04" },
    { 0xff000005, 0xff000005, "draft-05" },
    { 0xff000006, 0xff000006, "draft-06" },
    { 0xff000007, 0xff000007, "draft-07" },
    { 0xff000008, 0xff000008, "draft-08" },
    { 0xff000009, 0xff000009, "draft-09" },
    { 0xff00000a, 0xff00000a, "draft-10" },
    { 0xff00000b, 0xff00000b, "draft-11" },
    { 0xff00000c, 0xff00000c, "draft-12" },
    { 0xff00000d, 0xff00000d, "draft-13" },
    { 0xff00000e, 0xff00000e, "draft-14" },
    { 0xff00000f, 0xff00000f, "draft-15" },
    { 0xff000010, 0xff000010, "draft-16" },
    { 0xff000011, 0xff000011, "draft-17" },
    { 0xff000012, 0xff000012, "draft-18" },
    { 0xff000013, 0xff000013, "draft-19" },
    { 0xff000014, 0xff000014, "draft-20" },
    { 0xff000015, 0xff000015, "draft-21" },
    { 0xff000016, 0xff000016, "draft-22" },
    { 0xff000017, 0xff000017, "draft-23" },
    { 0xff000018, 0xff000018, "draft-24" },
    { 0xff000019, 0xff000019, "draft-25" },
    { 0xff00001a, 0xff00001a, "draft-26" },
    { 0xff00001b, 0xff00001b, "draft-27" },
    { 0xff00001c, 0xff00001c, "draft-28" },
    { 0xff00001d, 0xff00001d, "draft-29" },
    { 0xff00001e, 0xff00001e, "draft-30" },
    { 0xff00001f, 0xff00001f, "draft-31" },
    { 0xff000020, 0xff000020, "draft-32" },
    { 0xff000021, 0xff000021, "draft-33" },
    { 0xff000022, 0xff000022, "draft-34" },
    /* QUICv2 */
    { 0xff020000, 0xff020000, "v2-draft-00" }, /* Never used; not really supported */
    { 0x709A50C4, 0x709A50C4, "v2-draft-01" }, /* Never used; not really supported */
    { 0x6b3343cf, 0x6b3343cf, "2" },
    { 0, 0, NULL }
};

static const value_string quic_short_long_header_vals[] = {
    { 0, "Short Header" },
    { 1, "Long Header" },
    { 0, NULL }
};

#define SH_KP       0x04

/* Note that these values are "internal-value" used by Wireshark only.
   Real wire-format values depends on QUIC version */
#define QUIC_LPT_INITIAL    0x0
#define QUIC_LPT_0RTT       0x1
#define QUIC_LPT_HANDSHAKE  0x2
#define QUIC_LPT_RETRY      0x3
#define QUIC_LPT_VER_NEG    0xfe    /* Version Negotiation packets don't have any real packet type */
#define QUIC_SHORT_PACKET   0xff    /* dummy value that is definitely not LPT */

static const value_string quic_v1_long_packet_type_vals[] = {
    { 0x00, "Initial" },
    { 0x03, "Retry" },
    { 0x02, "Handshake" },
    { 0x01, "0-RTT" },
    /* Version Negotiation packets never use this mapping, so no need to add QUIC_LPT_VER_NEG */
    { 0, NULL }
};
static const value_string quic_v2_long_packet_type_vals[] = {
    { 0x00, "Retry" },
    { 0x01, "Initial" },
    { 0x02, "0-RTT" },
    { 0x03, "Handshake" },
    /* Version Negotiation packets never use this mapping, so no need to add QUIC_LPT_VER_NEG */
    { 0, NULL }
};

/* https://github.com/quicwg/base-drafts/wiki/Temporary-IANA-Registry#quic-frame-types */
#define FT_PADDING                  0x00
#define FT_PING                     0x01
#define FT_ACK                      0x02
#define FT_ACK_ECN                  0x03
#define FT_RESET_STREAM             0x04
#define FT_STOP_SENDING             0x05
#define FT_CRYPTO                   0x06
#define FT_NEW_TOKEN                0x07
#define FT_STREAM_8                 0x08
#define FT_STREAM_9                 0x09
#define FT_STREAM_A                 0x0a
#define FT_STREAM_B                 0x0b
#define FT_STREAM_C                 0x0c
#define FT_STREAM_D                 0x0d
#define FT_STREAM_E                 0x0e
#define FT_STREAM_F                 0x0f
#define FT_MAX_DATA                 0x10
#define FT_MAX_STREAM_DATA          0x11
#define FT_MAX_STREAMS_BIDI         0x12
#define FT_MAX_STREAMS_UNI          0x13
#define FT_DATA_BLOCKED             0x14
#define FT_STREAM_DATA_BLOCKED      0x15
#define FT_STREAMS_BLOCKED_BIDI     0x16
#define FT_STREAMS_BLOCKED_UNI      0x17
#define FT_NEW_CONNECTION_ID        0x18
#define FT_RETIRE_CONNECTION_ID     0x19
#define FT_PATH_CHALLENGE           0x1a
#define FT_PATH_RESPONSE            0x1b
#define FT_IMMEDIATE_ACK            0x1f
#define FT_CONNECTION_CLOSE_TPT     0x1c
#define FT_CONNECTION_CLOSE_APP     0x1d
#define FT_HANDSHAKE_DONE           0x1e
#define FT_DATAGRAM                 0x30
#define FT_DATAGRAM_LENGTH          0x31
#define FT_IMMEDIATE_ACK_DRAFT05    0xac /* ack-frequency-draft-05 */
#define FT_ACK_FREQUENCY            0xaf
#define FT_MP_ACK                   0x15228c00
#define FT_MP_ACK_ECN               0x15228c01
#define FT_PATH_ABANDON             0x15228c05
#define FT_PATH_STATUS              0x15228c06 /* multipath-draft-05 */
#define FT_PATH_STANDBY             0x15228c07 /* multipath-draft-06 */
#define FT_PATH_AVAILABLE           0x15228c08 /* multipath-draft-06 */
#define FT_MP_NEW_CONNECTION_ID     0x15228c09 /* multipath-draft-07 */
#define FT_MP_RETIRE_CONNECTION_ID  0x15228c0a /* multipath-draft-07 */
#define FT_MAX_PATHS                0x15228c0b /* multipath-draft-07 */
#define FT_MAX_PATH_ID              0x15228c0c /* multipath-draft-09 */
#define FT_TIME_STAMP               0x02F5

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
    { 0x1f, 0x1f,   "IMMEDIATE_ACK" },
    { 0x30, 0x31,   "DATAGRAM" },
    { 0xac, 0xac,   "IMMEDIATE_ACK (draft05)" }, /* ack-frequency-draft-05 */
    { 0xaf, 0xaf,   "ACK_FREQUENCY" },
    { 0x02f5, 0x02f5, "TIME_STAMP" },
    { 0xbaba00, 0xbaba01, "ACK_MP" }, /* multipath-draft-04 */
    { 0xbaba05, 0xbaba05, "PATH_ABANDON" }, /* multipath-draft-04 */
    { 0xbaba06, 0xbaba06, "PATH_STATUS" }, /* multipath-draft-04 */
    { 0x15228c00, 0x15228c01, "MP_ACK" }, /* >= multipath-draft-05 */
    { 0x15228c05, 0x15228c05, "PATH_ABANDON" }, /* >= multipath-draft-05 */
    { 0x15228c06, 0x15228c06, "PATH_STATUS" }, /* = multipath-draft-05 */
    { 0x15228c07, 0x15228c07, "PATH_STANDBY" }, /* >= multipath-draft-06 */
    { 0x15228c08, 0x15228c08, "PATH_AVAILABLE" }, /* >= multipath-draft-06 */
    { 0x15228c09, 0x15228c09, "MP_NEW_CONNECTION_ID" }, /* >= multipath-draft-07 */
    { 0x15228c0a, 0x15228c0a, "MP_RETIRE_CONNECTION_ID" }, /* >= multipath-draft-07 */
    { 0x15228c0b, 0x15228c0b, "MAX_PATHS" }, /* >= multipath-draft-07 */
    { 0x15228c0c, 0x15228c0c, "MAX_PATH_ID" }, /* >= multipath-draft-09 */
    { 0,    0,        NULL },
};


/* >= draft-08 */
#define FTFLAGS_STREAM_FIN 0x01
#define FTFLAGS_STREAM_LEN 0x02
#define FTFLAGS_STREAM_OFF 0x04

#define FTFLAGS_STREAM_INITIATOR 0x01
#define FTFLAGS_STREAM_DIRECTION 0x02

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
    { 0x000a, 0x000a, "PROTOCOL_VIOLATION" },
    { 0x000b, 0x000b, "INVALID_TOKEN" },
    { 0x000c, 0x000c, "APPLICATION_ERROR" },
    { 0x000d, 0x000d, "CRYPTO_BUFFER_EXCEEDED" },
    { 0x000e, 0x000e, "KEY_UPDATE_ERROR" },
    { 0x000f, 0x000f, "AEAD_LIMIT_REACHED" },
    { 0x0010, 0x0010, "NO_VIABLE_PATH" },
    { 0x0011, 0x0011, "VERSION_NEGOTIATION_ERROR" },
    { 0x0100, 0x01ff, "CRYPTO_ERROR" },
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

static const val64_string quic_frame_id_initiator[] = {
    { 0, "Client-initiated" },
    { 1, "Server-initiated" },
    { 0, NULL }
};

static const val64_string quic_frame_id_direction[] = {
    { 0, "Bidirectional" },
    { 1, "Unidirectional" },
    { 0, NULL }
};

static const val64_string quic_mp_path_status[] = {
    { 1, "Standby" },
    { 2, "Available" },
    { 0, NULL }
};


static void
quic_extract_header(tvbuff_t *tvb, uint8_t *long_packet_type, uint32_t *version,
                    quic_cid_t *dcid, quic_cid_t *scid);

static int
quic_get_long_packet_type(uint8_t first_byte, uint32_t version)
{
    /* Up to V1 */
    if (!is_quic_v2(version)) {
        if ((first_byte & 0x30) >> 4 == 0)
            return QUIC_LPT_INITIAL;
        if ((first_byte & 0x30) >> 4 == 1)
            return QUIC_LPT_0RTT;
        if ((first_byte & 0x30) >> 4 == 2)
            return QUIC_LPT_HANDSHAKE;
        return QUIC_LPT_RETRY;
    } else {
        if ((first_byte & 0x30) >> 4 == 0)
            return QUIC_LPT_RETRY;
        if ((first_byte & 0x30) >> 4 == 1)
            return QUIC_LPT_INITIAL;
        if ((first_byte & 0x30) >> 4 == 2)
            return QUIC_LPT_0RTT;
        return QUIC_LPT_HANDSHAKE;
    }
}

static void
quic_streams_add(packet_info *pinfo, quic_info_data_t *quic_info, uint64_t stream_id);

static void
quic_hp_cipher_reset(quic_hp_cipher *hp_cipher)
{
    gcry_cipher_close(hp_cipher->hp_cipher);
    memset(hp_cipher, 0, sizeof(*hp_cipher));
}
static void
quic_pp_cipher_reset(quic_pp_cipher *pp_cipher)
{
    gcry_cipher_close(pp_cipher->pp_cipher);
    memset(pp_cipher, 0, sizeof(*pp_cipher));
}
static void
quic_ciphers_reset(quic_ciphers *ciphers)
{
    quic_hp_cipher_reset(&ciphers->hp_cipher);
    quic_pp_cipher_reset(&ciphers->pp_cipher);
}

static bool
quic_is_hp_cipher_initialized(quic_hp_cipher *hp_cipher)
{
    return hp_cipher && hp_cipher->hp_cipher;
}
static bool
quic_is_pp_cipher_initialized(quic_pp_cipher *pp_cipher)
{
    return pp_cipher && pp_cipher->pp_cipher;
}
static bool
quic_are_ciphers_initialized(quic_ciphers *ciphers)
{
    return ciphers &&
           quic_is_hp_cipher_initialized(&ciphers->hp_cipher) &&
           quic_is_pp_cipher_initialized(&ciphers->pp_cipher);
}

/* Inspired from ngtcp2 */
static uint64_t quic_pkt_adjust_pkt_num(uint64_t max_pkt_num, uint64_t pkt_num,
                                   size_t n) {
  uint64_t k = max_pkt_num == UINT64_MAX ? max_pkt_num : max_pkt_num + 1;
  uint64_t u = k & ~((UINT64_C(1) << n) - 1);
  uint64_t a = u | pkt_num;
  uint64_t b = (u + (UINT64_C(1) << n)) | pkt_num;
  uint64_t a1 = k < a ? a - k : k - a;
  uint64_t b1 = k < b ? b - k : k - b;

  if (a1 < b1) {
    return a;
  }
  return b;
}

/**
 * Given a header protection cipher, a buffer and the packet number offset,
 * return the unmasked first byte and packet number.
 * If the loss bits feature is enabled, the protected bits in the first byte
 * are fewer than usual: 3 instead of 5 (on short headers only)
 */
static bool
quic_decrypt_header(tvbuff_t *tvb, unsigned pn_offset, quic_hp_cipher *hp_cipher, int hp_cipher_algo,
                    uint8_t *first_byte, uint32_t *pn, bool loss_bits_negotiated)
{
    if (!hp_cipher->hp_cipher) {
        // need to know the cipher.
        return false;
    }
    gcry_cipher_hd_t h = hp_cipher->hp_cipher;

    // Sample is always 16 bytes and starts after PKN (assuming length 4).
    // https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.2
    uint8_t sample[16];
    tvb_memcpy(tvb, sample, pn_offset + 4, 16);

    uint8_t mask[5] = { 0 };
    switch (hp_cipher_algo) {
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES256:
        /* Encrypt in-place with AES-ECB and extract the mask. */
        if (gcry_cipher_encrypt(h, sample, sizeof(sample), NULL, 0)) {
            return false;
        }
        memcpy(mask, sample, sizeof(mask));
        break;
    case GCRY_CIPHER_CHACHA20:
        /* If Gcrypt receives a 16 byte IV, it will assume the buffer to be
         * counter || nonce (in little endian), as desired. */
        if (gcry_cipher_setiv(h, sample, 16)) {
            return false;
        }
        /* Apply ChaCha20, encrypt in-place five zero bytes. */
        if (gcry_cipher_encrypt(h, mask, sizeof(mask), NULL, 0)) {
            return false;
        }
        break;
    default:
        return false;
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.1
    uint8_t packet0 = tvb_get_uint8(tvb, 0);
    if ((packet0 & 0x80) == 0x80) {
        // Long header: 4 bits masked
        packet0 ^= mask[0] & 0x0f;
    } else {
        // Short header
        if (loss_bits_negotiated == false) {
            // Standard mask: 5 bits masked
            packet0 ^= mask[0] & 0x1F;
        } else {
            // https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03#section-5.3
            packet0 ^= mask[0] & 0x07;
        }
    }
    unsigned pkn_len = (packet0 & 0x03) + 1;

    uint8_t pkn_bytes[4];
    tvb_memcpy(tvb, pkn_bytes, pn_offset, pkn_len);
    uint32_t pkt_pkn = 0;
    for (unsigned i = 0; i < pkn_len; i++) {
        pkt_pkn |= (pkn_bytes[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
    }
    *first_byte = packet0;
    *pn = pkt_pkn;
    return true;
}

/**
 * Retrieve the maximum valid packet number space for a peer.
 */
static uint64_t *
quic_max_packet_number(quic_info_data_t *quic_info, uint64_t path_id, bool from_server, uint8_t first_byte)
{
    int pkn_space;
    if ((first_byte & 0x80) && quic_get_long_packet_type(first_byte, quic_info->version) == QUIC_LPT_INITIAL) {
        // Long header, Initial
        pkn_space = 0;
    } else if ((first_byte & 0x80) && quic_get_long_packet_type(first_byte, quic_info->version) == QUIC_LPT_HANDSHAKE) {
        // Long header, Handshake
        pkn_space = 1;
    } else {
        // Long header (0-RTT) or Short Header (1-RTT appdata).
        pkn_space = 2;
    }
    if (quic_multipath_negotiated(quic_info) && path_id > 0) {
        /* The multipath draft states that key negotiation must
         * happen before 2^32 CID sequence numbers are used, so
         * possibly we could get away with using GUINT_TO_POINTER
         * and saving some memory here.
         */
        wmem_map_t **mp_pkn_map;
        if (from_server) {
            if (quic_info->max_server_mp_pkn == NULL) {
                quic_info->max_server_mp_pkn = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
            }
            mp_pkn_map = &quic_info->max_server_mp_pkn;
        } else {
            if (quic_info->max_client_mp_pkn == NULL) {
                quic_info->max_client_mp_pkn = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
            }
            mp_pkn_map = &quic_info->max_client_mp_pkn;
        }
        uint64_t *pkt_num = wmem_map_lookup(*mp_pkn_map, &path_id);
        if (pkt_num == NULL) {
            uint64_t *path_id_p = wmem_new(wmem_file_scope(), uint64_t);
            *path_id_p = path_id;
            pkt_num = wmem_new0(wmem_file_scope(), uint64_t);
            wmem_map_insert(*mp_pkn_map, path_id_p, pkt_num);
        }
        return pkt_num;
    } else {
        if (from_server) {
            return &quic_info->max_server_pkn[pkn_space];
        } else {
            return &quic_info->max_client_pkn[pkn_space];
        }
    }
}

/**
 * Calculate the full packet number and store it for later use.
 */
static void
quic_set_full_packet_number(quic_info_data_t *quic_info, quic_packet_info_t *quic_packet,
                            uint64_t path_id, bool from_server,
                            uint8_t first_byte, uint32_t pkn32)
{
    unsigned    pkn_len = (first_byte & 3) + 1;
    uint64_t    pkn_full;
    uint64_t    max_pn = *quic_max_packet_number(quic_info, path_id, from_server, first_byte);

    /* Sequential first pass, try to reconstruct full packet number. */
    pkn_full = quic_pkt_adjust_pkt_num(max_pn, pkn32, 8 * pkn_len);
    quic_packet->pkn_len = pkn_len;
    quic_packet->packet_number = pkn_full;
}

static const char *
cid_to_string(wmem_allocator_t *pool, const quic_cid_t *cid)
{
    if (cid->len == 0) {
        return "(none)";
    }
    char *str = (char *)wmem_alloc0(pool, 2 * cid->len + 1);
    bytes_to_hexstr(str, cid->cid, cid->len);
    return str;
}

/* QUIC Connection tracking. {{{ */
static unsigned
quic_connection_hash(const void *key)
{
    const quic_cid_t *cid = (const quic_cid_t *)key;

    return wmem_strong_hash((const uint8_t *)cid->cid, cid->len);
}

/* Note this function intentionally does not consider the reset token. */
static gboolean
quic_connection_equal(const void *a, const void *b)
{
    const quic_cid_t *cid1 = (const quic_cid_t *)a;
    const quic_cid_t *cid2 = (const quic_cid_t *)b;

    return cid1->len == cid2->len && !memcmp(cid1->cid, cid2->cid, cid1->len);
}

static gboolean
quic_cids_has_match(const quic_cid_item_t *items, quic_cid_t *raw_cid)
{
    while (items) {
        const quic_cid_t *cid = &items->data;
        // "raw_cid" potentially has some trailing data that is not part of the
        // actual CID, so accept any prefix match against "cid".
        // Note that this explicitly matches an empty CID.
        if (raw_cid->len >= cid->len && !memcmp(raw_cid->cid, cid->cid, cid->len)) {
            raw_cid->seq_num = cid->seq_num;
            raw_cid->path_id = cid->path_id;
            return true;
        }
        items = items->next;
    }
    return false;
}

static void
quic_cids_insert(quic_cid_t *cid, quic_info_data_t *conn, bool from_server)
{
    wmem_map_t *connections = from_server ? quic_server_connections : quic_client_connections;
    // Replace any previous CID key with the new one.
    wmem_map_remove(connections, cid);
    wmem_map_insert(connections, cid, conn);
    G_STATIC_ASSERT(QUIC_MAX_CID_LENGTH <= 8 * sizeof(quic_cid_lengths));
    quic_cid_lengths |= (1ULL << cid->len);
}

static inline bool
quic_cids_is_known_length(const quic_cid_t *cid)
{
    return (quic_cid_lengths & (1ULL << cid->len)) != 0;
}

/**
 * Returns the most recent QUIC connection for the current UDP stream. This may
 * return NULL after connection migration if the new UDP association was not
 * properly linked via a match based on the Connection ID.
 *
 * There may be more than one QUIC connection multiplexed on the same UDP
 * 5-tuple; previous connections can be found by looking at the ->prev pointer.
 * Per RFC 9000, multiplexed connections with zero-length CIDs will fail.
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
 * Tries to lookup a matching connection (if Connection ID is NULL, the
 * most recent connection on the network 5-tuple is returned, if any).
 * If connection is found, "from_server" is set accordingly.
 */
static quic_info_data_t *
quic_connection_find_dcid(packet_info *pinfo, quic_cid_t *dcid, bool *from_server)
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
    const quic_cid_t *original_dcid;
    bool check_ports = false;

    if (dcid && dcid->len > 0) {
        // Optimization: avoid lookup for invalid CIDs.
        if (!quic_cids_is_known_length(dcid)) {
            return NULL;
        }
        if (wmem_map_lookup_extended(quic_client_connections, dcid, (const void**)&original_dcid, (void**)&conn)) {
            // DCID recognized by client, so it was from server.
            *from_server = true;
            // On collision (both client and server choose the same CID), check
            // the port to learn about the side.
            // This is required for supporting draft -10 which has a single CID.
            check_ports = !!wmem_map_lookup(quic_server_connections, dcid);
            // Copy the other information, like sequence number and path ID
            // (for multipath).
            *dcid = *original_dcid;
        } else {
            if (wmem_map_lookup_extended(quic_server_connections, dcid, (const void**)&original_dcid, (void**)&conn)) {
                // DCID recognized by server, so it was from client.
                *from_server = false;
                // Copy the other information, like sequence number and path ID.
                *dcid = *original_dcid;
            }
        }
    } else {
        conn = quic_connection_from_conv(pinfo);
        if (conn) {
            check_ports = true;
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
quic_connection_find(packet_info *pinfo, uint8_t long_packet_type,
                     quic_cid_t *dcid, bool *from_server)
{
    bool is_long_packet = long_packet_type != QUIC_SHORT_PACKET;
    quic_info_data_t *conn = NULL;

    if (long_packet_type == QUIC_LPT_0RTT && dcid->len > 0) {
        // The 0-RTT packet always matches the SCID/DCID of the Client Initial
        conn = (quic_info_data_t *) wmem_map_lookup(quic_initial_connections, dcid);
        *from_server = false;
    } else {
        // Find a connection for Handshake, Version Negotiation and Server Initial packets by
        // matching their DCID against the SCIDs of the original Initial packets
        // from the peer. For Client Initial packets, match DCID of the first
        // Client Initial (these may contain ACK frames).
        conn = quic_connection_find_dcid(pinfo, dcid, from_server);
        /* Handle cases where we get a second Client Initial packet before a
         * Server Initial packet (so this is not recognized by the server yet),
         * e.g. the TLS Client Hello is fragmented in more than one frame.
         */
        if (long_packet_type == QUIC_LPT_INITIAL && !conn && dcid->len > 0) {
            conn = (quic_info_data_t *) wmem_map_lookup(quic_initial_connections, dcid);
            if (conn) {
                *from_server = false;
            }
        }
        if (long_packet_type == QUIC_LPT_INITIAL && conn && !*from_server && dcid->len > 0 &&
            !quic_connection_equal(dcid, &conn->client_dcid_initial) &&
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
        // (This is necessary to match a zero-length connection ID - for
        // other cases, the second method below also works, and it can vary
        // which is faster to try first.)
        conn = quic_connection_find_dcid(pinfo, NULL, from_server);
        /* Since we don't know the DCID, check all connections multiplexed
         * on the same 5-tuple for a match. */
        while (conn) {
            if ((*from_server && quic_cids_has_match(&conn->client_cids, dcid)) ||
                (!*from_server && quic_cids_has_match(&conn->server_cids, dcid))) {
                // Connection matches packet.
                break;
            }
            conn = conn->prev;
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
        } else if (quic_connection_from_conv(pinfo) == NULL) {
            // Connection information might not be attached to the conversation,
            // because of connection migration.
            conversation_t *conv = find_conversation_pinfo(pinfo, 0);
            if (conv) {
                // attach the connection information to the conversation.
                conversation_add_proto_data(conv, proto_quic, conn);
            }
        }
    }
    return conn;
}

/** Create a new QUIC Connection based on a Client Initial packet. */
static quic_info_data_t *
quic_connection_create(packet_info *pinfo, uint32_t version)
{
    conversation_t   *conv;
    quic_info_data_t *prev_conn, *conn = NULL;

    conn = wmem_new0(wmem_file_scope(), quic_info_data_t);
    wmem_list_append(quic_connections, conn);
    conn->number = quic_connections_count++;
    conn->version = version;
    copy_address_wmem(wmem_file_scope(), &conn->server_address, &pinfo->dst);
    conn->server_port = pinfo->destport;

    // For faster lookups without having to check DCID
    conv = find_or_create_conversation(pinfo);
    // Check for another connection multiplexed on the 5-tuple
    prev_conn = conversation_get_proto_data(conv, proto_quic);
    if (prev_conn) {
        conn->prev = prev_conn;
    }
    conversation_add_proto_data(conv, proto_quic, conn);

    conv = find_or_create_conversation_by_id(pinfo, CONVERSATION_QUIC, conn->number);
    conversation_add_proto_data(conv, proto_quic, conn);

    if (version == 0x51303530 || version == 0x54303530 || version == 0x54303531) {
        gquic_info_data_t  *gquic_info;

        gquic_info = wmem_new(wmem_file_scope(), gquic_info_data_t);
        if (version == 0x51303530)
            gquic_info->version = 50;
        else if (version == 0x54303530)
            gquic_info->version = 150;
        else
            gquic_info->version = 151;
        gquic_info->encoding = ENC_BIG_ENDIAN;
        gquic_info->version_valid = true;
        gquic_info->server_port = pinfo->destport;
        conn->gquic_info = gquic_info;
    }

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
        quic_cids_insert(&conn->client_cids.data, conn, false);
    }
    if (dcid->len > 0) {
        // According to the spec, the Initial Packet DCID MUST be at least 8
        // bytes, but non-conforming implementations could exist.
        memcpy(&conn->client_dcid_initial, dcid, sizeof(quic_cid_t));
        wmem_map_insert(quic_initial_connections, &conn->client_dcid_initial, conn);
        conn->client_dcid_set = true;
    }
}

/**
 * Use the new CID as additional identifier for the specified connection and
 * remember it for connection tracking.
 */
static void
quic_connection_add_cid(quic_info_data_t *conn, quic_cid_t *new_cid, bool from_server)
{
    DISSECTOR_ASSERT(new_cid->len > 0);
    quic_cid_item_t *items = from_server ? &conn->server_cids : &conn->client_cids;

    if (quic_cids_has_match(items, new_cid)) {
        // CID is already known for this connection.
        // XXX: If the same CID is reused with a new sequence number or path
        // id and multipath is being used, that's an issue. (Expert info?)
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

/** Create or update a connection. */
static void
quic_connection_create_or_update(quic_info_data_t **conn_p,
                                 packet_info *pinfo, uint32_t long_packet_type,
                                 uint32_t version, const quic_cid_t *scid,
                                 const quic_cid_t *dcid, bool from_server)
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
                conn->client_dcid_set = false;
            }
            if (conn->server_cids.data.len == 0 && scid->len) {
                memcpy(&conn->server_cids.data, scid, sizeof(quic_cid_t));
                quic_cids_insert(&conn->server_cids.data, conn, true);
            }
        }
        break;
    }
}

static void
quic_connection_destroy(void *data, void *user_data _U_)
{
    quic_info_data_t *conn = (quic_info_data_t *)data;
    quic_ciphers_reset(&conn->client_initial_ciphers);
    quic_ciphers_reset(&conn->server_initial_ciphers);
    quic_ciphers_reset(&conn->client_handshake_ciphers);
    quic_ciphers_reset(&conn->server_handshake_ciphers);

    quic_ciphers_reset(&conn->client_0rtt_ciphers);

    quic_hp_cipher_reset(&conn->client_pp.hp_cipher);
    quic_pp_cipher_reset(&conn->client_pp.pp_ciphers[0]);
    quic_pp_cipher_reset(&conn->client_pp.pp_ciphers[1]);

    quic_hp_cipher_reset(&conn->server_pp.hp_cipher);
    quic_pp_cipher_reset(&conn->server_pp.pp_ciphers[0]);
    quic_pp_cipher_reset(&conn->server_pp.pp_ciphers[1]);
}
/* QUIC Connection tracking. }}} */

/* QUIC Streams tracking and reassembly. {{{ */
static reassembly_table quic_reassembly_table;

typedef struct _quic_stream_key {
    uint64_t stream_id;
    uint32_t id;
    uint32_t conn_number;
    bool     from_server;
} quic_stream_key;

static unsigned
quic_stream_hash(const void *k)
{
    const quic_stream_key *key = (const quic_stream_key*)k;
    unsigned hash_val;

    hash_val = key->id;

    return hash_val;
}

static int
quic_stream_equal(const void *k1, const void *k2)
{
    const quic_stream_key* key1 = (const quic_stream_key*)k1;
    const quic_stream_key* key2 = (const quic_stream_key*)k2;

    return (key1->id == key2->id) &&
        (key1->stream_id == key2->stream_id) &&
        (key1->conn_number == key2->conn_number) &&
        (key1->from_server == key2->from_server);
}

static void *
quic_stream_persistent_key(const packet_info *pinfo _U_, const uint32_t id,
    const void *data)
{
    const quic_stream_info* stream_info = (const quic_stream_info*)data;
    DISSECTOR_ASSERT(stream_info != NULL);
    quic_stream_key *key = g_slice_new(quic_stream_key);

    key->id = id;
    key->stream_id = stream_info->stream_id;
    key->conn_number = stream_info->quic_info->number;
    key->from_server = stream_info->from_server;

    return (void *)key;
}

static void
quic_stream_free_persistent_key(void *ptr)
{
    quic_stream_key *key = (quic_stream_key *)ptr;
    g_slice_free(quic_stream_key, key);
}

const reassembly_table_functions
quic_reassembly_table_functions = {
    quic_stream_hash,
    quic_stream_equal,
    quic_stream_persistent_key,
    quic_stream_persistent_key,
    quic_stream_free_persistent_key,
    quic_stream_free_persistent_key
};

/** Perform sequence analysis for STREAM frames. */
static quic_stream_state *
quic_get_stream_state(packet_info *pinfo, quic_info_data_t *quic_info, bool from_server, uint64_t stream_id)
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
                    quic_info_data_t *quic_info, quic_stream_info *stream_info,
                    const quic_packet_info_t *quic_packet)
{
    if (quic_packet->packet_type != QUIC_LPT_0RTT && quic_info->app_handle) {
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
        // Traverse the STREAM frame tree.
        proto_tree *top_tree = proto_tree_get_parent_tree(tree);
        top_tree = proto_tree_get_parent_tree(top_tree);
        // Subdissectors MUST NOT assume that 'stream_info' remains valid after
        // returning. Copying the pointer will result in illegal memory access.
        call_dissector_with_data(quic_info->app_handle, next_tvb, pinfo, top_tree, stream_info);
    } else if (quic_packet->packet_type == QUIC_LPT_0RTT && quic_info->zrtt_app_handle) {
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
        proto_tree *top_tree = proto_tree_get_parent_tree(tree);
        top_tree = proto_tree_get_parent_tree(top_tree);
        call_dissector_with_data(quic_info->zrtt_app_handle, next_tvb, pinfo, top_tree, stream_info);
    }
}

/**
 * Reassemble stream data within a STREAM frame.
 */
static void
desegment_quic_stream(tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
                      proto_tree *tree, quic_info_data_t *quic_info,
                      quic_stream_info *stream_info,
                      quic_stream_state *stream,
                      const quic_packet_info_t *quic_packet)
{
    fragment_head *fh;
    int last_fragment_len;
    bool must_desegment;
    bool called_dissector;
    int another_pdu_follows;
    int deseg_offset;
    struct tcp_multisegment_pdu *msp;
    uint32_t seq = (uint32_t)stream_info->stream_offset;
    const uint32_t nxtseq = seq + (uint32_t)length;
    uint32_t reassembly_id = 0;

    // XXX fix the tvb accessors below such that no new tvb is needed.
    tvb = tvb_new_subset_length(tvb, 0, offset + length);

again:
    fh = NULL;
    last_fragment_len = 0;
    must_desegment = false;
    called_dissector = false;
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
        // XXX: This also happens the second time through the data for an MSP normally
        // TODO show expert info for retransmission? Additional checks may be
        // necessary here to tell a retransmission apart from other (normal?)
        // conditions. See also similar code in packet-tcp.c.
#if 0
        proto_tree_add_debug_text(tree, "TODO retransmission expert info frame %d stream_id=%" PRIu64 " offset=%d visited=%d reassembly_id=0x%08x",
                pinfo->num, stream->stream_id, offset, PINFO_FD_VISITED(pinfo), reassembly_id);
#endif
        return;
    }
    /* Else, find the most previous PDU starting before this sequence number */
    if (!msp && seq > 0) {
        msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(stream->multisegment_pdus, seq-1);
        /* Unless if we already fully reassembled the msp that covers seq-1
         * and seq is beyond the end of that msp. In that case this segment
         * will be the start of a new msp.
         */
        if (msp && (msp->flags & MSP_FLAGS_GOT_ALL_SEGMENTS) &&
            seq >= msp->nxtpdu) {
            msp = NULL;
        }
    }

    {
        // A single stream can contain multiple fragments (e.g. for HTTP/3
        // HEADERS and DATA frames). Let's hope that a single stream within a
        // QUIC packet does not contain multiple partial fragments, that would
        // result in a reassembly ID collision here. If that collision becomes
        // an issue, we would have to replace "msp->first_frame" with a new
        // field in "msp" that is initialized with "stream_info->stream_offset".
        reassembly_id = msp ? msp->first_frame : pinfo->num;
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
                          pinfo, reassembly_id, stream_info,
                          seq - msp->seq, len,
                          nxtseq < msp->nxtpdu);
        if (fh) {
            msp->flags |= MSP_FLAGS_GOT_ALL_SEGMENTS;
        }
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
        process_quic_stream(tvb, offset, pinfo, tree, quic_info, stream_info, quic_packet);
        called_dissector = true;

        /* Did the subdissector ask us to desegment some more data
         * before it could handle the packet?
         * If so we'll have to handle that later.
         */
        if (pinfo->desegment_len) {
            must_desegment = true;
            if (!PINFO_FD_VISITED(pinfo)) {
                if (msp)
                    msp->flags &= ~MSP_FLAGS_GOT_ALL_SEGMENTS;
            }

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
            process_quic_stream(next_tvb, 0, pinfo, tree, quic_info, stream_info, quic_packet);
            called_dissector = true;

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
                                                pinfo, reassembly_id, stream_info);

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
                    if (!PINFO_FD_VISITED(pinfo)) {
                        must_desegment = true;
                        if (msp)
                            msp->flags &= ~MSP_FLAGS_GOT_ALL_SEGMENTS;
                    }
                    /* See packet-tcp.h for details about this. */
                    deseg_offset = fh->datalen - pinfo->desegment_offset;
                    deseg_offset = tvb_reported_length(tvb) - deseg_offset;
                }
            }
        }
    }

    if (must_desegment) {

        uint32_t deseg_seq = seq + (deseg_offset - offset);

        if (!PINFO_FD_VISITED(pinfo)) {
            // TODO handle DESEGMENT_UNTIL_FIN if needed, maybe use the FIN bit?
            if ((nxtseq - deseg_seq) <= 1024*1024) {
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
                             pinfo, reassembly_id, stream_info,
                             0, nxtseq - deseg_seq,
                             nxtseq < msp->nxtpdu);
            }
        } else {
            /* If this is not the first time we have seen the packet, then
             * the MSP should already be created. Retrieve it to see if we
             * know what later frame the PDU is reassembled in.
             */
            if (((struct tcp_multisegment_pdu *)wmem_tree_lookup32(stream->multisegment_pdus, deseg_seq))) {
                fh = fragment_get(&quic_reassembly_table, pinfo, reassembly_id, stream_info);
            }
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

        /* TODO: Show what's left in the packet as a raw QUIC "segment", like
         * packet-tcp.c does here.
         */
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
                            quic_stream_state *stream,
                            const quic_packet_info_t *quic_packet)
{
    /* QUIC application data is most likely not properly dissected when
     * reassembly is not enabled. Therefore we do not even offer "desegment"
     * preference to disable reassembly.
     */

    if (length > 0) {
        /* Don't call a subdissector for a zero length segment. It won't
         * work for dissection (see #12368), and our methods of determing
         * if desegmentation is needed won't work either (#19497). If there
         * ever is an app_handle on top of QUIC that needs to be called with
         * a zero length segment, revisit this. (Cf. #15159)
         */
        pinfo->can_desegment = 2;
        desegment_quic_stream(tvb, offset, length, pinfo, tree, quic_info, stream_info, stream, quic_packet);
    }
}
/* QUIC Streams tracking and reassembly. }}} */

static bool quic_crypto_out_of_order = true;

static reassembly_table quic_crypto_reassembly_table;

typedef struct _quic_crypto_retrans_key {
    uint64_t pkt_number; /* QUIC packet number */
    int offset;
    uint32_t num;        /* Frame number in the capture file, pinfo->num */
} quic_crypto_retrans_key;

static unsigned
quic_crypto_retrans_hash(const void *k)
{
    const quic_crypto_retrans_key* key = (const quic_crypto_retrans_key*) k;

#if 0
    return wmem_strong_hash((const uint8_t *)key, sizeof(quic_crypto_retrans_key));
#endif
    unsigned hash_val;

    /* Most of the time the packet number in the capture file suffices. */
    hash_val = key->num;

    return hash_val;
}

static int
quic_crypto_retrans_equal(const void *k1, const void *k2)
{
    const quic_crypto_retrans_key* key1 = (const quic_crypto_retrans_key*) k1;
    const quic_crypto_retrans_key* key2 = (const quic_crypto_retrans_key*) k2;

    return (key1->num == key2->num) &&
           (key1->pkt_number == key2->pkt_number) &&
           (key1->offset == key2->offset);
}

static quic_crypto_state *
quic_get_crypto_state(packet_info *pinfo, quic_info_data_t *quic_info, bool from_server, const uint8_t encryption_level)
{
    wmem_map_t **cryptos_p = from_server ? &quic_info->server_crypto : &quic_info->client_crypto;
    wmem_map_t *cryptos = *cryptos_p;
    quic_crypto_state *crypto = NULL;

    if (PINFO_FD_VISITED(pinfo)) {
        DISSECTOR_ASSERT(cryptos);
        crypto = (quic_crypto_state *)wmem_map_lookup(cryptos, GUINT_TO_POINTER(encryption_level));
        DISSECTOR_ASSERT(crypto);
        return crypto;
    }

    // Initialize per-connection and per-stream state.
    if (!cryptos) {
        cryptos = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        *cryptos_p = cryptos;
    } else {
        crypto = (quic_crypto_state *)wmem_map_lookup(cryptos, GUINT_TO_POINTER(encryption_level));
    }
    if (!crypto) {
        crypto = wmem_new0(wmem_file_scope(), quic_crypto_state);
        crypto->multisegment_pdus = wmem_tree_new(wmem_file_scope());
        crypto->retrans_offsets = wmem_map_new(wmem_file_scope(),
                quic_crypto_retrans_hash, quic_crypto_retrans_equal);
        crypto->encryption_level = encryption_level;
        wmem_map_insert(cryptos, GUINT_TO_POINTER(encryption_level), crypto);
    }

    return crypto;
}

static void
process_quic_crypto(tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
                    proto_tree *tree, quic_crypto_info *crypto_info)
{

    tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, length);
    col_set_writable(pinfo->cinfo, -1, false);
    /*
     * Dissect TLS handshake record. The Client/Server Hello (CH/SH)
     * are contained in the Initial Packet. 0-RTT keys are ready
     * after CH. HS + 1-RTT keys are ready after SH.
     * (Note: keys captured from the client might become available
     * after capturing the packets due to processing delay.)
     * These keys will be loaded in the first HS/0-RTT/1-RTT msg.
     */
    call_dissector_with_data(tls13_handshake_handle, next_tvb, pinfo, tree, GUINT_TO_POINTER(crypto_info->offset));
    col_set_writable(pinfo->cinfo, -1, true);
}

/**
 * Reassemble data within a CRYPTO frame.
 *
 * This always gets handed to the TLS handshake dissector, which does its own
 * fragmentation handling, so all we do is the Out Of Order handling.
 * RFC 9001 4.1.3 "Sending and Receiving Handshake Messages"
 * "TLS is responsible for buffering handshake bytes that have arrived in order.
 * QUIC is responsible for buffering handshake bytes that arrive out of order or
 * for encryption levels that are not yet ready."
 *
 * XXX: We are only buffering bytes that arive out of order within an encryption
 * level. Buffering for encryption levels that are not yet ready requires
 * determining that they are not ready (and they may never be ready from our
 * perspective if we don't have the keys.)
 */

static void
desegment_quic_crypto(tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
                      proto_tree *tree, quic_info_data_t *quic_info _U_,
                      quic_crypto_info *crypto_info,
                      quic_crypto_state *crypto)
{
    fragment_head *fh;
    bool called_dissector;
    bool has_gap;
    struct tcp_multisegment_pdu *msp;

    /* XXX: There are a few elements in QUIC that can be up to 64 bit
     * integers that we're truncating to 32 bit here to re-use current
     * code.
     */

    uint32_t seq = (uint32_t)crypto_info->crypto_offset;
    const uint32_t nxtseq = seq + (uint32_t)length;
    uint32_t reassembly_id = 0;

    fh = NULL;
    called_dissector = false;
    has_gap = false;
    msp = NULL;

    /* Look for retransmissions and overlap and discard them, only handing
     * new in order bytes to TLS.
     *
     * It's possible to have multiple QUIC packets in the same capture
     * file frame, so to really be assured of no collision we need the
     * QUIC connection ID, the QUIC packet number space, the QUIC
     * packet number, and the offset within the QUIC packet in addition
     * to the frame number in the capture file.
     *
     * crypto (a quic_crypto_state*) is already unique to the connection
     * ID and packet number space, so we need to store the other two
     * in its map.
     *
     * Alternatively we could have the real offset in the capture
     * file frame, but we can't easily get that since the tvb is the
     * result of decryption.
     */
    quic_crypto_retrans_key *tmp_key = wmem_new(pinfo->pool, quic_crypto_retrans_key);
    tmp_key->num = pinfo->num;
    tmp_key->offset = offset;
    tmp_key->pkt_number = crypto_info->packet_number;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (crypto_info->crypto_offset + length <= crypto->max_contiguous_offset) {
            /* No new data. Remember this. */
            proto_tree_add_expert(tree, pinfo, &ei_quic_retransmission, tvb, offset, length);
            uint64_t* contiguous_offset = wmem_new(wmem_file_scope(), uint64_t);
            *contiguous_offset = crypto->max_contiguous_offset;
            quic_crypto_retrans_key *fkey = wmem_new(wmem_file_scope(), quic_crypto_retrans_key);
            *fkey = *tmp_key;
            wmem_map_insert(crypto->retrans_offsets, fkey, contiguous_offset);
            return;
        } else if (crypto_info->crypto_offset < crypto->max_contiguous_offset) {
            /* XXX: Retrieve the previous data and compare for conflicts? */
            proto_tree_add_expert(tree, pinfo, &ei_quic_overlap, tvb, offset, length);
            uint64_t overlap = crypto->max_contiguous_offset - crypto_info->crypto_offset;
            length -= (int)overlap;
            seq = (uint32_t)(crypto->max_contiguous_offset);
            offset += (uint32_t)(overlap);
            /* Store this offset */
            uint64_t* contiguous_offset = wmem_new(wmem_file_scope(), uint64_t);
            *contiguous_offset = crypto->max_contiguous_offset;
            quic_crypto_retrans_key *fkey = wmem_new(wmem_file_scope(), quic_crypto_retrans_key);
            *fkey = *tmp_key;
            wmem_map_insert(crypto->retrans_offsets, fkey, contiguous_offset);
        }
    } else {
        /* Retrieve any per-frame state about retransmitted and overlapping
         * data.
         */
        uint64_t *contiguous_offset = (uint64_t *)wmem_map_lookup(crypto->retrans_offsets, tmp_key);
        if (contiguous_offset != NULL) {
            if (crypto_info->crypto_offset + length <= *contiguous_offset) {
                proto_tree_add_expert(tree, pinfo, &ei_quic_retransmission, tvb, offset, length);
                return;
            } else if (crypto_info->crypto_offset < *contiguous_offset) {
                /* XXX: Retrieve the previous data and compare for conflicts? */
                proto_tree_add_expert(tree, pinfo, &ei_quic_overlap, tvb, offset, length);
                uint64_t overlap = *contiguous_offset - crypto_info->crypto_offset;
                length -= (int)overlap;
                seq = (uint32_t)(*contiguous_offset);
                offset += (uint32_t)(overlap);
            } else {
                DISSECTOR_ASSERT_NOT_REACHED();
            }
        }
    }

    /* By doing the above we should not have any retransmissions from in
     * order bytes. Retransmission and overlaps in out of order bytes are
     * still possible, but those will be handled by adding them to the
     * msp fragments. TLS is also going to handle defragmenting (instead
     * of returning info about PDU ends via pinfo->desegment_offset and
     * pinfo->desegment_len), so we can make this simpler than for payload
     * streams or TCP.
     *
     * Since TLS doesn't set pinfo->desegment_offset and pinfo->desegment_len,
     * we can't align our msps to PDU boundaries, and so we can't skip past
     * any missing out of order bytes to send TLS later whole received PDUs.
     */

    /* Find the most recent msp that starts before this sequence number. */
    msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(crypto->multisegment_pdus, seq);

    /* If we already fully reassembled that msp and seq is beyond its end
     * (the latter should always be the case since we're discarding
     * retransmitted bytes above), this segment isn't part of the msp.
     */
    if (msp && (msp->flags & MSP_FLAGS_GOT_ALL_SEGMENTS) &&
        seq >= msp->nxtpdu) {
        msp = NULL;
    }

    /* The TCP reassembly functions already use msp->seq as a tiebreaker in
     * case we do have more than one OOO reassembly in a given frame, which
     * happens with Chrome's "Chaos Protection".
     *
     * XXX: It would be better to use functions that use the QUIC connection
     * instead of addresses and ports, since concurrent connections on the
     * same 5 tuple is possible, but using the frame number as well limits
     * problems to more unusual encapsulations.
     *
     * RFC 9000 9. "Connection Migration": "An endpoint MUST NOT initiate
     * connection migration before the handshake is confirmed" so we shouldn't
     * have to worry about CRYPTO packets for the same connection being
     * fragmented on different 5-tuples. (There may be new CRYPTO packets
     * with session tickets later, but we should handle that.)
     */
    reassembly_id = ((msp ? msp->first_frame : pinfo->num) << 8) | crypto->encryption_level;

    if (!PINFO_FD_VISITED(pinfo)) {
        has_gap = crypto->max_contiguous_offset < seq;

        if (!has_gap) {
            /* No gap, so either this is a standalone in order
             * segment, or it's part of our in progress out of
             * order MSP and we need to look at the MSP fragments
             * to see what the last contiguous offset is.
             * Advance the contiguous offset appropriately.
             *
             * XXX: A slightly different approach would involve splitting
             * the MSP as now done in the TCP dissector. That would send
             * any new bytes to TLS sooner and is closer to what RFC 9001
             * recommends. It's less important to do so than in TCP, but
             * is a possible future improvement.
             */
            if (msp) {
                fh = fragment_get(&quic_crypto_reassembly_table, pinfo, reassembly_id, msp);
                DISSECTOR_ASSERT(fh);
                /* The offsets in the fragment list are relative to msp->seq */
                uint32_t max = nxtseq - msp->seq;
                for (fragment_item *frag = fh->next; frag; frag = frag->next) {
                    uint32_t frag_end = frag->offset + frag->len;
                    if (frag->offset <= max && max < frag_end) {
                        max = frag_end;
                    }
                }
                crypto->max_contiguous_offset = max + msp->seq;
            } else {
                crypto->max_contiguous_offset = nxtseq;
            }
        }

        /* We always want to hand the entire segment to the TLS dissector.
         * So update nxtpdu to point at least to the start of the next segment.
         */
        if (msp) {
            msp->nxtpdu = MAX(msp->nxtpdu, nxtseq);
        }
    }

    if (msp && msp->seq <= seq && msp->nxtpdu > seq) {
        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame=pinfo->num;
            msp->last_frame_time=pinfo->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        fragment_reset_tot_len(&quic_crypto_reassembly_table, pinfo, reassembly_id, msp,
            MAX(nxtseq, msp->nxtpdu) - msp->seq);

        fh = fragment_add(&quic_crypto_reassembly_table, tvb, offset,
                          pinfo, reassembly_id, msp,
                          seq - msp->seq, length,
                          nxtseq < msp->nxtpdu);
        if (fh) {
            msp->flags |= MSP_FLAGS_GOT_ALL_SEGMENTS;
            if (msp->flags & MSP_FLAGS_MISSING_FIRST_SEGMENT) {
                msp->first_frame_with_seq = seq; // Overloading this
                /* We use "first_frame_with_seq" to mean "the sequence number
                 * of the fragment that completed the MSP" because many
                 * CRYPTO frames can be at the same layer, so the normal
                 * methods of determining the reassembled in fragment don't
                 * work. (We could store the seq in last_frame instead.)
                 */
                msp->flags &= (~MSP_FLAGS_MISSING_FIRST_SEGMENT);
            }
        }
    } else if (has_gap) {
        /* We need to start a new Out of Order MSP on our first visit.
         * We shouldn't get here on a second visit.
         */
        if (!PINFO_FD_VISITED(pinfo)) {
            msp = pdu_store_sequencenumber_of_next_pdu(pinfo, (uint32_t)crypto->max_contiguous_offset, nxtseq, crypto->multisegment_pdus);
            msp->flags |= MSP_FLAGS_MISSING_FIRST_SEGMENT;
            fh = fragment_add(&quic_crypto_reassembly_table, tvb, offset,
                              pinfo, reassembly_id, msp,
                              seq - msp->seq, length,
                              nxtseq < msp->nxtpdu);
        }
    } else {
        /* This segment was not found in our table, so it doesn't
         * contain a continuation of a higher-level PDU.
         * Call the normal subdissector.
         */

        crypto_info->offset = seq;
        process_quic_crypto(tvb, offset, length, pinfo, tree, crypto_info);
        called_dissector = true;
    }

    /* is it completely desegmented? */
    if (fh) {
        /*
         * Yes, we think it is.
         * We only call TLS for the segment that reassembled it.
         */
        if (fh->reassembled_in == pinfo->num && seq == msp->first_frame_with_seq) {
            /*
             * OK, this is it.
             * Let's call the subdissector with the desegmented data.
             */

            tvbuff_t *next_tvb = tvb_new_chain(tvb, fh->tvb_data);
            add_new_data_source(pinfo, next_tvb, "Reassembled QUIC CRYPTO");
            proto_item *frag_tree_item;
            /* XXX: Should we use the proto_tree_get_root for these?
             * There are PADDING and PINGs after the crypto, so maybe not?
             */
            show_fragment_tree(fh, &quic_crypto_fragment_items, tree, pinfo, next_tvb, &frag_tree_item);
            crypto_info->offset = seq;
            process_quic_crypto(next_tvb, 0, tvb_captured_length(next_tvb), pinfo, tree, crypto_info);
            called_dissector = true;
        }
    }

    if (!called_dissector) {
        if (fh != NULL && fh->reassembled_in != 0 &&
            fh->reassembled_in != pinfo->num ) {
            /*
             * We know what frame this PDU is reassembled in;
             * let the user know.
             */
            proto_item *item = proto_tree_add_uint(tree, hf_quic_reassembled_in, tvb, 0,
                                                   0, fh->reassembled_in);
            proto_item_set_generated(item);
        }
    }
}

static void
dissect_quic_crypto_payload(tvbuff_t *tvb, int offset, int length, packet_info *pinfo,
                            proto_tree *tree, quic_info_data_t *quic_info,
                            quic_crypto_info *crypto_info,
                            quic_crypto_state *crypto)
{
    /* Make sure that TLS can also desegment */
    pinfo->can_desegment = 2;
    if (quic_crypto_out_of_order) {
        desegment_quic_crypto(tvb, offset, length, pinfo, tree, quic_info, crypto_info, crypto);
    } else {
        crypto_info->offset = (uint32_t)crypto_info->crypto_offset;
        process_quic_crypto(tvb, offset, length, pinfo, tree, crypto_info);
    }
}

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
dissect_quic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, unsigned offset, quic_info_data_t *quic_info, const quic_packet_info_t *quic_packet, bool from_server)
{
    proto_item *ti_ft, *ti_ftflags, *ti_ftid, *ti;
    proto_tree *ft_tree, *ftflags_tree, *ftid_tree;
    uint64_t frame_type;
    int32_t lenft;
    unsigned   orig_offset = offset;

    ti_ft = proto_tree_add_item(quic_tree, hf_quic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_quic_ft);

    ti_ftflags = proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, &frame_type, &lenft);
    proto_item_set_text(ti_ft, "%s", rval_to_str_const((uint32_t)frame_type, quic_frame_type_vals, "Unknown"));
    offset += lenft;

    switch(frame_type){
        case FT_PADDING:{
            uint32_t pad_len;

            col_append_str(pinfo->cinfo, COL_INFO, ", PADDING");

            /* A padding frame consists of a single zero octet, but for brevity
             * sake let's combine multiple zeroes into a single field. */
            pad_len = 1 + tvb_skip_uint8(tvb, offset, tvb_reported_length_remaining(tvb, offset), '\0') - offset;
            ti = proto_tree_add_uint(ft_tree, hf_quic_padding_length, tvb, offset, 0, pad_len);
            proto_item_set_generated(ti);
            proto_item_append_text(ti_ft, " Length: %u", pad_len);
            offset += pad_len - 1;
        }
        break;
        case FT_PING:{
            col_append_str(pinfo->cinfo, COL_INFO, ", PING");
        }
        break;
        case FT_ACK:
        case FT_ACK_ECN:
        case FT_MP_ACK:
        case FT_MP_ACK_ECN:{
            uint64_t ack_range_count;
            int32_t lenvar;

            switch(frame_type){
                case FT_ACK:
                    col_append_str(pinfo->cinfo, COL_INFO, ", ACK");
                break;
                case FT_ACK_ECN:
                    col_append_str(pinfo->cinfo, COL_INFO, ", ACK_ECN");
                break;
                case FT_MP_ACK:
                    col_append_str(pinfo->cinfo, COL_INFO, ", MP_ACK");
                    proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_ack_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                    offset += lenvar;
                break;
                case FT_MP_ACK_ECN:
                    col_append_str(pinfo->cinfo, COL_INFO, ", MP_ACK_ECN");
                    proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_ack_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                    offset += lenvar;
                break;
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
            if (frame_type == FT_ACK_ECN || frame_type == FT_MP_ACK_ECN ) {
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
            uint64_t stream_id, error_code;
            int32_t len_streamid = 0, len_finalsize = 0, len_error_code = 0;

            col_append_str(pinfo->cinfo, COL_INFO, ", RS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rsts_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" PRIu64, stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 ")", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rsts_application_error_code, tvb, offset, -1, ENC_VARINT_QUIC, &error_code, &len_error_code);
            offset += len_error_code;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rsts_final_size, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_finalsize);
            offset += len_finalsize;

            proto_item_append_text(ti_ft, " Error code: %#" PRIx64, error_code);
        }
        break;
        case FT_STOP_SENDING:{
            int32_t len_streamid;
            uint64_t stream_id, error_code;
            int32_t len_error_code = 0;

            col_append_str(pinfo->cinfo, COL_INFO, ", SS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ss_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" PRIu64, stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 ")", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ss_application_error_code, tvb, offset, -1, ENC_VARINT_QUIC, &error_code, &len_error_code);
            offset += len_error_code;

            proto_item_append_text(ti_ft, " Error code: %#" PRIx64, error_code);
        }
        break;
        case FT_CRYPTO: {
            uint64_t crypto_offset, crypto_length;
            int32_t lenvar;
            col_append_str(pinfo->cinfo, COL_INFO, ", CRYPTO");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_crypto_offset, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_offset, &lenvar);
            offset += lenvar;
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_crypto_length, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_length, &lenvar);
            offset += lenvar;
            proto_tree_add_item(ft_tree, hf_quic_crypto_crypto_data, tvb, offset, (uint32_t)crypto_length, ENC_NA);
            quic_crypto_state *crypto = quic_get_crypto_state(pinfo, quic_info, from_server, quic_packet->packet_type);
            quic_crypto_info crypto_info = {
                .packet_number = quic_packet->packet_number,
                .crypto_offset = crypto_offset,
                .from_server = from_server,
            };
            dissect_quic_crypto_payload(tvb, offset, (int)crypto_length, pinfo, ft_tree, quic_info, &crypto_info, crypto);
            offset += (uint32_t)crypto_length;
        }
        break;
        case FT_NEW_TOKEN: {
            uint64_t token_length;
            int32_t lenvar;

            col_append_str(pinfo->cinfo, COL_INFO, ", NT");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_nt_length, tvb, offset, -1, ENC_VARINT_QUIC, &token_length, &lenvar);
            offset += lenvar;

            proto_tree_add_item(ft_tree, hf_quic_nt_token, tvb, offset, (uint32_t)token_length, ENC_NA);
            offset += (uint32_t)token_length;
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
            uint64_t stream_id, stream_offset = 0, length;
            int32_t lenvar;

            offset -= 1;

            col_append_str(pinfo->cinfo, COL_INFO, ", STREAM");

            ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_quic_ftflags);
            proto_tree_add_item(ftflags_tree, hf_quic_stream_fin, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_stream_len, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_stream_off, tvb, offset, 1, ENC_NA);
            offset += 1;

            ti_ftid = proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &lenvar);
            ftid_tree = proto_item_add_subtree(ti_ftid, ett_quic_ftid);
            proto_tree_add_item_ret_varint(ftid_tree, hf_quic_stream_initiator, tvb, offset, -1, ENC_VARINT_QUIC, NULL, NULL);
            proto_tree_add_item_ret_varint(ftid_tree, hf_quic_stream_direction, tvb, offset, -1, ENC_VARINT_QUIC, NULL, NULL);
            offset += lenvar;

            proto_item_append_text(ti_ft, " id=%" PRIu64, stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 ")", stream_id);

            proto_item_append_text(ti_ft, " fin=%d", !!(frame_type & FTFLAGS_STREAM_FIN));

            if (!PINFO_FD_VISITED(pinfo)) {
                quic_streams_add(pinfo, quic_info, stream_id);
            }

            if (frame_type & FTFLAGS_STREAM_OFF) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_offset, tvb, offset, -1, ENC_VARINT_QUIC, &stream_offset, &lenvar);
                offset += lenvar;
            }
            proto_item_append_text(ti_ft, " off=%" PRIu64, stream_offset);

            if (frame_type & FTFLAGS_STREAM_LEN) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
                offset += lenvar;
            } else {
                length = tvb_reported_length_remaining(tvb, offset);
            }
            proto_item_append_text(ti_ft, " len=%" PRIu64 " dir=%s origin=%s", length,
                                   val64_to_str_const(!!(stream_id & FTFLAGS_STREAM_DIRECTION), quic_frame_id_direction, "unknown"),
                                   val64_to_str_const(!!(stream_id & FTFLAGS_STREAM_INITIATOR), quic_frame_id_initiator, "unknown"));

            proto_tree_add_item(ft_tree, hf_quic_stream_data, tvb, offset, (int)length, ENC_NA);
            if (have_tap_listener(quic_follow_tap)) {
                quic_follow_tap_data_t *follow_data = wmem_new0(pinfo->pool, quic_follow_tap_data_t);

                follow_data->tvb = tvb_new_subset_length(tvb, offset, (int)length);
                follow_data->stream_id = stream_id;
                follow_data->from_server = from_server;

                tap_queue_packet(quic_follow_tap, pinfo, follow_data);
            }
            quic_stream_state *stream = quic_get_stream_state(pinfo, quic_info, from_server, stream_id);
            quic_stream_info stream_info = {
                .stream_id = stream_id,
                .stream_offset = stream_offset,
                .quic_info = quic_info,
                .from_server = from_server,
            };
            dissect_quic_stream_payload(tvb, offset, (int)length, pinfo, ft_tree, quic_info, &stream_info, stream, quic_packet);
            offset += (int)length;
        }
        break;
        case FT_MAX_DATA:{
            int32_t len_maximumdata;

            col_append_str(pinfo->cinfo, COL_INFO, ", MD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_md_maximum_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumdata);
            offset += len_maximumdata;
        }
        break;
        case FT_MAX_STREAM_DATA:{
            int32_t len_streamid, len_maximumstreamdata;
            uint64_t stream_id;

            col_append_str(pinfo->cinfo, COL_INFO, ", MSD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_msd_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" PRIu64, stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 ")", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_msd_maximum_stream_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumstreamdata);
            offset += len_maximumstreamdata;
        }
        break;
        case FT_MAX_STREAMS_BIDI:
        case FT_MAX_STREAMS_UNI:{
            int32_t len_streamid;

            col_append_str(pinfo->cinfo, COL_INFO, ", MS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ms_max_streams, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;
        }
        break;
        case FT_DATA_BLOCKED:{
            int32_t len_offset;

            col_append_str(pinfo->cinfo, COL_INFO, ", DB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_db_stream_data_limit, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;
        }
        break;
        case FT_STREAM_DATA_BLOCKED:{
            int32_t len_streamid, len_offset;
            uint64_t stream_id;

            col_append_str(pinfo->cinfo, COL_INFO, ", SDB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_sdb_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_item_append_text(ti_ft, " id=%" PRIu64, stream_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 ")", stream_id);

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_sdb_stream_data_limit, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;
        }
        break;
        case FT_STREAMS_BLOCKED_BIDI:
        case FT_STREAMS_BLOCKED_UNI:{
            int32_t len_streamid;

            col_append_str(pinfo->cinfo, COL_INFO, ", SB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_sb_stream_limit, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;
        }
        break;
        case FT_NEW_CONNECTION_ID:
        case FT_MP_NEW_CONNECTION_ID:{
            int32_t len_sequence;
            int32_t len_retire_prior_to;
            uint64_t seq_num = 0, path_id = 0;
            int32_t nci_length;
            int32_t lenvar = 0;
            bool valid_cid = false;

            switch(frame_type){
                case FT_NEW_CONNECTION_ID:
                    col_append_str(pinfo->cinfo, COL_INFO, ", NCI");
                 break;
                case FT_MP_NEW_CONNECTION_ID:
                    col_append_str(pinfo->cinfo, COL_INFO, ", MP_NCI");
                    proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_nci_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, &path_id, &lenvar);
                    offset += lenvar;
                 break;
            }

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_nci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, &seq_num, &len_sequence);
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
            quic_cid_t cid = {.len=0};
            if (valid_cid && quic_info) {
                tvb_memcpy(tvb, cid.cid, offset, nci_length);
                cid.len = nci_length;
                cid.seq_num = seq_num;
                cid.path_id = path_id;
                quic_connection_add_cid(quic_info, &cid, from_server);
            }
            offset += nci_length;

            proto_tree_add_item(ft_tree, hf_quic_nci_stateless_reset_token, tvb, offset, 16, ENC_NA);
            if (valid_cid && quic_info) {
                quic_add_stateless_reset_token(pinfo, tvb, offset, &cid);
            }
            offset += 16;
        }
        break;
        case FT_RETIRE_CONNECTION_ID:
        case FT_MP_RETIRE_CONNECTION_ID:{
            int32_t len_sequence;
            int32_t lenvar;

            switch(frame_type){
                case FT_RETIRE_CONNECTION_ID:
                    col_append_str(pinfo->cinfo, COL_INFO, ", RC");
                break;
                case FT_MP_RETIRE_CONNECTION_ID:
                    col_append_str(pinfo->cinfo, COL_INFO, ", MP_RC");
                    proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_rc_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                    offset += lenvar;
                break;
            }

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_rci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
            offset += len_sequence;
        }
        break;
        case FT_PATH_CHALLENGE:{
            col_append_str(pinfo->cinfo, COL_INFO, ", PC");

            proto_tree_add_item(ft_tree, hf_quic_path_challenge_data, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;
        case FT_PATH_RESPONSE:{
            col_append_str(pinfo->cinfo, COL_INFO, ", PR");

            proto_tree_add_item(ft_tree, hf_quic_path_response_data, tvb, offset, 8, ENC_NA);
            offset += 8;
        }
        break;
        case FT_CONNECTION_CLOSE_TPT:
        case FT_CONNECTION_CLOSE_APP:
        case FT_PATH_ABANDON:{
            int32_t len_reasonphrase, len_frametype, len_error_code;
            uint64_t len_reason = 0;
            uint64_t error_code;
            const char *tls_alert = NULL;

            if ( frame_type == FT_PATH_ABANDON) {
                int32_t lenvar;
                col_append_str(pinfo->cinfo, COL_INFO, ", PA");
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_pa_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            } else {
                col_append_str(pinfo->cinfo, COL_INFO, ", CC");
            }
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

            proto_tree_add_item(ft_tree, hf_quic_cc_reason_phrase, tvb, offset, (uint32_t)len_reason, ENC_ASCII);
            offset += (uint32_t)len_reason;

            // Transport Error codes higher than 0x3fff are for Private Use.
            if (frame_type == FT_CONNECTION_CLOSE_TPT && error_code <= 0x3fff) {
                proto_item_append_text(ti_ft, " Error code: %s", rval_to_str((uint32_t)error_code, quic_transport_error_code_vals, "Unknown (%d)"));
            } else {
                proto_item_append_text(ti_ft, " Error code: %#" PRIx64, error_code);
            }
            if (tls_alert) {
                proto_item_append_text(ti_ft, " (%s)", tls_alert);
            }
        }
        break;
        case FT_HANDSHAKE_DONE:
            col_append_str(pinfo->cinfo, COL_INFO, ", DONE");
        break;
        case FT_DATAGRAM:
        case FT_DATAGRAM_LENGTH:{
            int32_t dg_length;
            uint64_t length;
            col_append_str(pinfo->cinfo, COL_INFO, ", DG");
            if (frame_type == FT_DATAGRAM_LENGTH) {

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_dg_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &dg_length);
                offset += dg_length;
            } else {
                length = (uint32_t) tvb_reported_length_remaining(tvb, offset);
            }
            proto_tree_add_item(ft_tree, hf_quic_dg, tvb, offset, (uint32_t)length, ENC_NA);
            offset += (uint32_t)length;
        }
        break;
        case FT_IMMEDIATE_ACK_DRAFT05:
        case FT_IMMEDIATE_ACK:
            col_append_str(pinfo->cinfo, COL_INFO, ", IA");
        break;
        case FT_ACK_FREQUENCY:{
            int32_t length;

            col_append_str(pinfo->cinfo, COL_INFO, ", AF");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_sequence_number, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_ack_eliciting_threshold, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_request_max_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_af_reordering_threshold, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;
        }
        break;
        case FT_TIME_STAMP:{
            int32_t length;

            col_append_str(pinfo->cinfo, COL_INFO, ", TS");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_ts, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;

        }
        break;
        case FT_PATH_STATUS:
        case FT_PATH_STANDBY:
        case FT_PATH_AVAILABLE:{
            int32_t length;

            col_append_str(pinfo->cinfo, COL_INFO, ", PS");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_ps_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_ps_path_status_sequence_number, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;

            if (frame_type == FT_PATH_STATUS ) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_ps_path_status, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
                offset += (uint32_t)length;
            }
        }
        break;
        case FT_MAX_PATHS:{
            int32_t length;

            /* multipath draft-07: "If any of the endpoints does not advertise
             * the initial_max_paths transport parameter, then the endpoints
             * MUST NOT use any frame or mechanism defined in this document."
             *
             * So we do not call quic_add_multipath here, and possibly should
             * set a expert info if MP is not supported (similar with other
             * MP frames.)
             */
            col_append_str(pinfo->cinfo, COL_INFO, ", MP");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_maximum_paths, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;
        }
        break;
        case FT_MAX_PATH_ID:{
            int32_t length;

            col_append_str(pinfo->cinfo, COL_INFO, ", MPI");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_mp_maximum_path_identifier, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &length);
            offset += (uint32_t)length;
        }
        break;
        default:
            expert_add_info_format(pinfo, ti_ft, &ei_quic_ft_unknown, "Unknown Frame Type %#" PRIx64, frame_type);
        break;
    }

    proto_item_set_len(ti_ft, offset - orig_offset);

    return offset;
}

static bool
quic_hp_cipher_init(quic_hp_cipher *hp_cipher, int hash_algo, uint8_t key_length, uint8_t *secret, uint32_t version);
static bool
quic_pp_cipher_init(quic_pp_cipher *pp_cipher, int hash_algo, uint8_t key_length, uint8_t *secret, uint32_t version);

/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the PP cipher.
 * As the header points to the original buffer with an encrypted packet number,
 * the (encrypted) packet number length is also included.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-12.3
 */
static void
quic_decrypt_message(quic_pp_cipher *pp_cipher, tvbuff_t *head, unsigned header_length,
                     uint8_t first_byte, unsigned pkn_len, uint64_t packet_number, quic_decrypt_result_t *result, packet_info *pinfo)
{
    gcry_error_t    err;
    uint8_t        *header;
    uint8_t         nonce[TLS13_AEAD_NONCE_LENGTH];
    uint8_t        *buffer;
    uint8_t         atag[16];
    unsigned        buffer_length;
    const unsigned char  **error = &result->error;
    quic_datagram *dgram_info;

    dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);

    DISSECTOR_ASSERT(pp_cipher != NULL);
    DISSECTOR_ASSERT(pp_cipher->pp_cipher != NULL);
    DISSECTOR_ASSERT(pkn_len < header_length);
    DISSECTOR_ASSERT(1 <= pkn_len && pkn_len <= 4);
    // copy header, but replace encrypted first byte and PKN by plaintext.
    header = (uint8_t *)tvb_memdup(pinfo->pool, head, 0, header_length);
    header[0] = first_byte;
    for (unsigned i = 0; i < pkn_len; i++) {
        header[header_length - 1 - i] = (uint8_t)(packet_number >> (8 * i));
    }

    /* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
    buffer_length = tvb_captured_length_remaining(head, header_length + 16);
    if (buffer_length == 0) {
        *error = "Decryption not possible, ciphertext is too short";
        return;
    }
    buffer = (uint8_t *)tvb_memdup(wmem_file_scope(), head, header_length, buffer_length);
    tvb_memcpy(head, atag, header_length + buffer_length, 16);

    memcpy(nonce, pp_cipher->pp_iv, TLS13_AEAD_NONCE_LENGTH);
    /* Packet number is left-padded with zeroes and XORed with write_iv */
    phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);
    /* QUIC Multipath draft-07 also uses the lower 32 bits of the Path ID
     * (CID sequence number prior to draft-07), which MUST NOT go over 2^32
     * when multipath is used; also, the nonce must be at least 12 bytes.
     */
    if (dgram_info && dgram_info->conn && quic_multipath_negotiated(dgram_info->conn)) {
        DISSECTOR_ASSERT_CMPINT(TLS13_AEAD_NONCE_LENGTH, >=, 12);
        phton32(nonce + sizeof(nonce) - 12, pntoh32(nonce + sizeof(nonce) - 12) ^ (UINT32_MAX & dgram_info->path_id));
    }

    gcry_cipher_reset(pp_cipher->pp_cipher);
    err = gcry_cipher_setiv(pp_cipher->pp_cipher, nonce, TLS13_AEAD_NONCE_LENGTH);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (setiv) failed: %s", gcry_strerror(err));
        return;
    }

    /* associated data (A) is the contents of QUIC header */
    err = gcry_cipher_authenticate(pp_cipher->pp_cipher, header, header_length);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (authenticate) failed: %s", gcry_strerror(err));
        return;
    }

    /* Output ciphertext (C) */
    err = gcry_cipher_decrypt(pp_cipher->pp_cipher, buffer, buffer_length, NULL, 0);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (decrypt) failed: %s", gcry_strerror(err));
        return;
    }

    err = gcry_cipher_checktag(pp_cipher->pp_cipher, atag, 16);
    if (err) {
        *error = wmem_strdup_printf(wmem_file_scope(), "Decryption (checktag) failed: %s", gcry_strerror(err));
        return;
    }

    result->error = NULL;
    result->data = buffer;
    result->data_len = buffer_length;
}

static bool
quic_hkdf_expand_label(int hash_algo, uint8_t *secret, unsigned secret_len, const char *label, uint8_t *out, unsigned out_len)
{
    const StringInfo secret_si = { secret, secret_len };
    unsigned char *out_mem = NULL;
    if (tls13_hkdf_expand_label(hash_algo, &secret_si, "tls13 ", label, out_len, &out_mem)) {
        memcpy(out, out_mem, out_len);
        wmem_free(NULL, out_mem);
        return true;
    }
    return false;
}

/**
 * Compute the client and server initial secrets given Connection ID "cid".
 *
 * On success true is returned and the two initial secrets are set.
 * false is returned on error (see "error" parameter for the reason).
 */
static bool
quic_derive_initial_secrets(const quic_cid_t *cid,
                            uint8_t client_initial_secret[HASH_SHA2_256_LENGTH],
                            uint8_t server_initial_secret[HASH_SHA2_256_LENGTH],
                            uint32_t version,
                            const char **error)
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
    static const uint8_t handshake_salt_draft_22[20] = {
        0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
        0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
    };
    static const uint8_t handshake_salt_draft_23[20] = {
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
        0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
    };
    static const uint8_t handshake_salt_draft_29[20] = {
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    };
    static const uint8_t handshake_salt_v1[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    static const uint8_t hanshake_salt_draft_q50[20] = {
        0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
        0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
    };
    static const uint8_t hanshake_salt_draft_t50[20] = {
        0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
        0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10
    };
    static const int8_t hanshake_salt_draft_t51[20] = {
        0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
        0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d
    };
    static const uint8_t handshake_salt_v2[20] = {
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    };

    gcry_error_t    err;
    uint8_t         secret[HASH_SHA2_256_LENGTH];

    if (version == 0x51303530) {
        err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_q50, sizeof(hanshake_salt_draft_q50),
                           cid->cid, cid->len, secret);
    } else if (version == 0x54303530) {
        err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_t50, sizeof(hanshake_salt_draft_t50),
                           cid->cid, cid->len, secret);
    } else if (version == 0x54303531) {
        err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_t51, sizeof(hanshake_salt_draft_t51),
                           cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 22)) {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_22, sizeof(handshake_salt_draft_22),
                           cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 28)) {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_23, sizeof(handshake_salt_draft_23),
                           cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 32)) {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_29, sizeof(handshake_salt_draft_29),
                           cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 34)) {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_v1, sizeof(handshake_salt_v1),
                           cid->cid, cid->len, secret);
    } else {
        err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_v2, sizeof(handshake_salt_v2),
                           cid->cid, cid->len, secret);
    }
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Failed to extract secrets: %s", gcry_strerror(err));
        return false;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, sizeof(secret), "client in",
                                client_initial_secret, HASH_SHA2_256_LENGTH)) {
        *error = "Key expansion (client) failed";
        return false;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, sizeof(secret), "server in",
                                server_initial_secret, HASH_SHA2_256_LENGTH)) {
        *error = "Key expansion (server) failed";
        return false;
    }

    *error = NULL;
    return true;
}

/**
 * Maps a Packet Protection cipher to the Packet Number protection cipher.
 * See https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.3
 */
static bool
quic_get_pn_cipher_algo(int cipher_algo, int *hp_cipher_mode)
{
    switch (cipher_algo) {
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES256:
        *hp_cipher_mode = GCRY_CIPHER_MODE_ECB;
        return true;
    case GCRY_CIPHER_CHACHA20:
        *hp_cipher_mode = GCRY_CIPHER_MODE_STREAM;
        return true;
    default:
        return false;
    }
}

/*
 * (Re)initialize the PNE/PP ciphers using the given cipher algorithm.
 * If the optional base secret is given, then its length MUST match the hash
 * algorithm output.
 */
static bool
quic_hp_cipher_prepare(quic_hp_cipher *hp_cipher, int hash_algo, int cipher_algo, uint8_t *secret, const char **error, uint32_t version)
{
    /* Clear previous state (if any). */
    quic_hp_cipher_reset(hp_cipher);

    int hp_cipher_mode;
    if (!quic_get_pn_cipher_algo(cipher_algo, &hp_cipher_mode)) {
        *error = "Unsupported cipher algorithm";
        return false;
    }

    if (gcry_cipher_open(&hp_cipher->hp_cipher, cipher_algo, hp_cipher_mode, 0)) {
        quic_hp_cipher_reset(hp_cipher);
        *error = "Failed to create HP cipher";
        return false;
    }

    if (secret) {
        unsigned cipher_keylen = (uint8_t) gcry_cipher_get_algo_keylen(cipher_algo);
        if (!quic_hp_cipher_init(hp_cipher, hash_algo, cipher_keylen, secret, version)) {
            quic_hp_cipher_reset(hp_cipher);
            *error = "Failed to derive key material for HP cipher";
            return false;
        }
    }

    return true;
}
static bool
quic_pp_cipher_prepare(quic_pp_cipher *pp_cipher, int hash_algo, int cipher_algo, int cipher_mode, uint8_t *secret, const char **error, uint32_t version)
{
    /* Clear previous state (if any). */
    quic_pp_cipher_reset(pp_cipher);

    int hp_cipher_mode;
    if (!quic_get_pn_cipher_algo(cipher_algo, &hp_cipher_mode)) {
        *error = "Unsupported cipher algorithm";
        return false;
    }

    if (gcry_cipher_open(&pp_cipher->pp_cipher, cipher_algo, cipher_mode, 0)) {
        quic_pp_cipher_reset(pp_cipher);
        *error = "Failed to create PP cipher";
        return false;
    }

    if (secret) {
        unsigned cipher_keylen = (uint8_t) gcry_cipher_get_algo_keylen(cipher_algo);
        if (!quic_pp_cipher_init(pp_cipher, hash_algo, cipher_keylen, secret, version)) {
            quic_pp_cipher_reset(pp_cipher);
            *error = "Failed to derive key material for PP cipher";
            return false;
        }
    }

    return true;
}
static bool
quic_ciphers_prepare(quic_ciphers *ciphers, int hash_algo, int cipher_algo, int cipher_mode, uint8_t *secret, const char **error, uint32_t version)
{
    return quic_hp_cipher_prepare(&ciphers->hp_cipher, hash_algo, cipher_algo, secret, error, version) &&
           quic_pp_cipher_prepare(&ciphers->pp_cipher, hash_algo, cipher_algo, cipher_mode, secret, error, version);
}


static bool
quic_create_initial_decoders(const quic_cid_t *cid, const char **error, quic_info_data_t *quic_info)
{
    uint8_t         client_secret[HASH_SHA2_256_LENGTH];
    uint8_t         server_secret[HASH_SHA2_256_LENGTH];

    if (!quic_derive_initial_secrets(cid, client_secret, server_secret, quic_info->version, error)) {
        return false;
    }

    /* Packet numbers are protected with AES128-CTR,
     * initial packets are protected with AEAD_AES_128_GCM. */
    if (!quic_ciphers_prepare(&quic_info->client_initial_ciphers, GCRY_MD_SHA256,
                              GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, client_secret, error, quic_info->version) ||
        !quic_ciphers_prepare(&quic_info->server_initial_ciphers, GCRY_MD_SHA256,
                              GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, server_secret, error, quic_info->version)) {
        return false;
    }

    return true;
}

static bool
quic_create_0rtt_decoder(unsigned i, char *early_data_secret, unsigned early_data_secret_len,
                         quic_ciphers *ciphers, int *cipher_algo, uint32_t version)
{
    static const uint16_t tls13_ciphers[] = {
        0x1301, /* TLS_AES_128_GCM_SHA256 */
        0x1302, /* TLS_AES_256_GCM_SHA384 */
        0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
        0x1304, /* TLS_AES_128_CCM_SHA256 */
        0x1305, /* TLS_AES_128_CCM_8_SHA256 */
    };
    if (i >= G_N_ELEMENTS(tls13_ciphers)) {
        // end of list
        return false;
    }
    int cipher_mode = 0, hash_algo = 0;
    const char *error_ignored = NULL;
    if (tls_get_cipher_info(NULL, tls13_ciphers[i], cipher_algo, &cipher_mode, &hash_algo)) {
        unsigned hash_len = gcry_md_get_algo_dlen(hash_algo);
        if (hash_len == early_data_secret_len && quic_ciphers_prepare(ciphers, hash_algo, *cipher_algo, cipher_mode, early_data_secret, &error_ignored, version)) {
            return true;
        }
    }
    /* This cipher failed, but there are more to try. */
    quic_ciphers_reset(ciphers);
    return true;
}

static bool
quic_create_decoders(packet_info *pinfo, quic_info_data_t *quic_info, quic_ciphers *ciphers,
                     bool from_server, TLSRecordType type, const char **error)
{
    if (!quic_info->hash_algo) {
        if (!tls_get_cipher_info(pinfo, 0, &quic_info->cipher_algo, &quic_info->cipher_mode, &quic_info->hash_algo)) {
            *error = "Unable to retrieve cipher information";
            return false;
        }
    }

    unsigned hash_len = gcry_md_get_algo_dlen(quic_info->hash_algo);
    char *secret = (char *)wmem_alloc0(pinfo->pool, hash_len);

    if (!tls13_get_quic_secret(pinfo, from_server, type, hash_len, hash_len, secret)) {
        *error = "Secrets are not available";
        return false;
    }

    if (!quic_ciphers_prepare(ciphers, quic_info->hash_algo,
                              quic_info->cipher_algo, quic_info->cipher_mode, secret, error, quic_info->version)) {
        return false;
    }

    return true;
}

/**
 * Tries to obtain the QUIC application traffic secrets.
 */
static bool
quic_get_traffic_secret(packet_info *pinfo, int hash_algo, quic_pp_state_t *pp_state, bool from_client)
{
    unsigned hash_len = gcry_md_get_algo_dlen(hash_algo);
    char *secret = (char *)wmem_alloc0(pinfo->pool, hash_len);
    if (!tls13_get_quic_secret(pinfo, !from_client, TLS_SECRET_APP, hash_len, hash_len, secret)) {
        return false;
    }
    pp_state->next_secret = (uint8_t *)wmem_memdup(wmem_file_scope(), secret, hash_len);
    return true;
}

/**
 * Expands the secret (length MUST be the same as the "hash_algo" digest size)
 * and initialize cipher with the new key.
 */
static bool
quic_hp_cipher_init(quic_hp_cipher *hp_cipher, int hash_algo, uint8_t key_length, uint8_t *secret, uint32_t version)
{
    unsigned char      hp_key[256/8];
    unsigned    hash_len = gcry_md_get_algo_dlen(hash_algo);
    char        *label = !is_quic_v2(version) ? "quic hp" : "quicv2 hp";

    if (!quic_hkdf_expand_label(hash_algo, secret, hash_len, label, hp_key, key_length)) {
        return false;
    }

    return gcry_cipher_setkey(hp_cipher->hp_cipher, hp_key, key_length) == 0;
}
static bool
quic_pp_cipher_init(quic_pp_cipher *pp_cipher, int hash_algo, uint8_t key_length, uint8_t *secret, uint32_t version)
{
    unsigned char      write_key[256/8];   /* Maximum key size is for AES256 cipher. */
    unsigned    hash_len = gcry_md_get_algo_dlen(hash_algo);
    char        *key_label = !is_quic_v2(version) ? "quic key" : "quicv2 key";
    char        *iv_label = !is_quic_v2(version) ? "quic iv" : "quicv2 iv";

    if (key_length > sizeof(write_key)) {
        return false;
    }

    if (!quic_hkdf_expand_label(hash_algo, secret, hash_len, key_label, write_key, key_length) ||
        !quic_hkdf_expand_label(hash_algo, secret, hash_len, iv_label, pp_cipher->pp_iv, sizeof(pp_cipher->pp_iv))) {
        return false;
    }

    return gcry_cipher_setkey(pp_cipher->pp_cipher, write_key, key_length) == 0;
}


/**
 * Updates the packet protection secret to the next one.
 */
static void
quic_update_key(uint32_t version, int hash_algo, quic_pp_state_t *pp_state)
{
    unsigned hash_len = gcry_md_get_algo_dlen(hash_algo);
    const char *label = is_quic_draft_max(version, 23) ? "traffic upd" : (is_quic_draft_max(version, 34) ? "quic ku" : "quicv2 ku");
    bool ret = quic_hkdf_expand_label(hash_algo, pp_state->next_secret, hash_len,
                                          label, pp_state->next_secret, hash_len);
    /* This must always succeed as our hash algorithm was already validated. */
    DISSECTOR_ASSERT(ret);
}

/**
 * Retrieves the header protection cipher for short header packets and prepares
 * the packet protection cipher. The application layer protocol is also queried.
 */
static quic_hp_cipher *
quic_get_1rtt_hp_cipher(packet_info *pinfo, quic_info_data_t *quic_info, bool from_server, const char **error)
{
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
            /* We end up here if:
                * no previous TLS handshake is found
                * the used ciphers are unsupported
                * some (unencrypted) padding is misdetected as SH coalesced packet
               Because of the third scenario, we can't set quic_info->skip_decryption
               to true; otherwise we will stop decrypting the entire session, even if
               we are able to.
               Unfortunately, this way, we lost the optimization that allows skipping checks
               for future packets in case the capture starts in midst of a
               connection where the handshake is not present.
               Note that even if we have a basic logic to detect unencrypted padding (via
               check_dcid_on_coalesced_packet()), there is not a proper way to detect it
               other than checking if the decryption successed
            */
            *error = "Missing TLS handshake, unsupported ciphers or padding";
            return NULL;
        }

        /* XXX: What if this is padding (or anything else) that is falsely
         * detected as a SH packet after the TLS handshake in Initial frames
         * but before the TLS handshake in the Handshake frames? The most
         * likely case is padding that starts with a byte that looks like
         * a short header when a 0 length DCID is being used. Then the check
         * above won't fail and we will retrieve the wrong TLS information,
         * including ALPN.
         */

        /* Retrieve secrets for both the client and server. */
        if (!quic_get_traffic_secret(pinfo, quic_info->hash_algo, client_pp, true) ||
            !quic_get_traffic_secret(pinfo, quic_info->hash_algo, server_pp, false)) {
            quic_info->skip_decryption = true;
            *error = "Secrets are not available";
            return NULL;
        }

        // Create initial cipher handles for Key Phase 0 using the 1-RTT keys.
        if (!quic_hp_cipher_prepare(&client_pp->hp_cipher, quic_info->hash_algo,
                                    quic_info->cipher_algo, client_pp->next_secret, error, quic_info->version) ||
            !quic_pp_cipher_prepare(&client_pp->pp_ciphers[0], quic_info->hash_algo,
                                    quic_info->cipher_algo, quic_info->cipher_mode, client_pp->next_secret, error, quic_info->version) ||
            !quic_hp_cipher_prepare(&server_pp->hp_cipher, quic_info->hash_algo,
                                    quic_info->cipher_algo, server_pp->next_secret, error, quic_info->version) ||
            !quic_pp_cipher_prepare(&server_pp->pp_ciphers[0], quic_info->hash_algo,
                                    quic_info->cipher_algo, quic_info->cipher_mode, server_pp->next_secret, error, quic_info->version)) {
            quic_info->skip_decryption = true;
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
            // If no specific handle is found, alias "h3-*" to "h3" and "doq-*" to "doq"
            if (!quic_info->app_handle) {
                if (g_str_has_prefix(proto_name, "h3-")) {
                    quic_info->app_handle = dissector_get_string_handle(quic_proto_dissector_table, "h3");
                } else if (g_str_has_prefix(proto_name, "doq-")) {
                    quic_info->app_handle = dissector_get_string_handle(quic_proto_dissector_table, "doq");
                }
            }
        }
    }

    // Note: Header Protect cipher does not change after Key Update.
    return &pp_state->hp_cipher;
}

/**
 * Tries to construct the appropriate cipher for the current key phase.
 * See also "PROTECTED PAYLOAD DECRYPTION" comment on top of this file.
 * Returns true if the cipher was newly created (and needs to be either
 * freed or added to the array of ciphers), false if an existing cipher
 * was returned.
 */
static bool
quic_get_pp_cipher(quic_pp_cipher *pp_cipher, bool key_phase, quic_info_data_t *quic_info, bool from_server, uint64_t pkn)
{
    const char *error = NULL;

    /* Keys were previously not available. */
    if (quic_info->skip_decryption) {
        return false;
    }

    quic_pp_state_t *client_pp = &quic_info->client_pp;
    quic_pp_state_t *server_pp = &quic_info->server_pp;
    quic_pp_state_t *pp_state = !from_server ? client_pp : server_pp;

    /*
     * If the key phase changed, try to decrypt the packet using the new cipher.
     * However, if the packet number is before we changed to the current phase,
     * try the previous cipher instead.
     * If that fails, then it is either a malicious packet or out-of-order.
     * '!!' is due to key_phase being a signed bitfield, it forces -1 into 1.
     */
    if (key_phase != !!pp_state->key_phase && pkn > pp_state->changed_in_pkn) {
        memset(pp_cipher, 0, sizeof(quic_pp_cipher));
        if (!quic_pp_cipher_prepare(pp_cipher, quic_info->hash_algo,
                                    quic_info->cipher_algo, quic_info->cipher_mode, pp_state->next_secret, &error, quic_info->version)) {
            /* This should never be reached, if the parameters were wrong
             * before, then it should have set "skip_decryption". */
            REPORT_DISSECTOR_BUG("quic_pp_cipher_prepare unexpectedly failed: %s", error);
            return false;
        }

        return true;
    }

    *pp_cipher = pp_state->pp_ciphers[key_phase];
    return false;
}

/**
 * After success decrypting payload, replaces the previous cipher for this
 * phase with the new one, and stores the packet number where this occurred.
 */
static void
quic_set_pp_cipher(quic_pp_cipher *pp_cipher, bool key_phase, quic_info_data_t *quic_info, bool from_server, uint64_t pkn)
{
    /* Keys were previously not available. */
    if (quic_info->skip_decryption) {
        return;
    }

    quic_pp_state_t *client_pp = &quic_info->client_pp;
    quic_pp_state_t *server_pp = &quic_info->server_pp;
    quic_pp_state_t *pp_state = !from_server ? client_pp : server_pp;

    /*
     * If the key phase changed, replace the old cipher at this phase
     * with the new one, since we succeeded.
     *
     * XXX - Perhaps optimally we should have a dynamic array of ciphers,
     * and a tree storing the packet numbers at which they changed,
     * instead of storing only two ciphers at once. We could even try
     * more than one cipher for a given polarity when things are badly
     * out of order and missing. (Servers and clients are not supposed
     * to switch a second time until they have received acks for the
     * previous changes, but there can still be old outstanding packets.
     * See RFC 9001 6. Key Update.)
     */
    if (key_phase != !!pp_state->key_phase && pkn > pp_state->changed_in_pkn) {

        /* Verified the cipher, use it from now on and rotate the key. */
        /* Note that HP cipher is not touched.
           https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.4
           "The same header protection key is used for the duration of the
            connection, with the value not changing after a key update" */
        quic_pp_cipher_reset(&pp_state->pp_ciphers[key_phase]);
        pp_state->pp_ciphers[key_phase] = *pp_cipher;
        quic_update_key(quic_info->version, quic_info->hash_algo, pp_state);

        pp_state->key_phase = key_phase;
        pp_state->changed_in_pkn = pkn;
    }
}

/**
 * Process (protected) payload, adding the encrypted payload to the tree. If
 * decryption is possible, frame dissection is also attempted.
 *
 * The given offset must correspond to the end of the QUIC header and begin of
 * the (protected) payload. Dissected frames are appended to "tree" and expert
 * info is attached to "ti" (the field with the encrypted payload).
 */
static void
quic_process_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, unsigned offset,
                     quic_info_data_t *quic_info, quic_packet_info_t *quic_packet, bool from_server,
                     quic_pp_cipher *pp_cipher, uint8_t first_byte, unsigned pkn_len)
{
    quic_decrypt_result_t *decryption = &quic_packet->decryption;

    /*
     * If no decryption error has occurred yet, try decryption on the first
     * pass and store the result for later use.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (!quic_packet->decryption.error && quic_is_pp_cipher_initialized(pp_cipher)) {
            quic_decrypt_message(pp_cipher, tvb, offset, first_byte, pkn_len, quic_packet->packet_number, &quic_packet->decryption, pinfo);
        }
    }

    if (decryption->error) {
        expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed,
                               "Decryption failed: %s", decryption->error);
    } else if (decryption->data_len) {
        tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, decryption->data,
                decryption->data_len, decryption->data_len);
        add_new_data_source(pinfo, decrypted_tvb, "Decrypted QUIC");

        unsigned decrypted_offset = 0;
        while (tvb_reported_length_remaining(decrypted_tvb, decrypted_offset) > 0) {
            if (quic_info->version == 0x51303530 || quic_info->version == 0x54303530 || quic_info->version == 0x54303531) {
                decrypted_offset = dissect_gquic_frame_type(decrypted_tvb, pinfo, tree, decrypted_offset, pkn_len, quic_info->gquic_info);
            } else {
                decrypted_offset = dissect_quic_frame_type(decrypted_tvb, pinfo, tree, decrypted_offset, quic_info, quic_packet, from_server);
            }
        }
    } else if (quic_info->skip_decryption) {
        expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed,
                               "Decryption skipped because keys are not available.");
    }
}

static void
quic_verify_retry_token(tvbuff_t *tvb, quic_packet_info_t *quic_packet, const quic_cid_t *odcid, uint32_t version)
{
    /*
     * Verify the Retry Integrity Tag using the fixed key from
     * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
     */
    static const uint8_t key_v1[] = {
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
    };
    static const uint8_t nonce_v1[] = {
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb
    };
    static const uint8_t key_draft_29[] = {
        0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0,
        0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1
    };
    static const uint8_t key_v2[] = {
        0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
        0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
    };
    static const uint8_t nonce_draft_29[] = {
        0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c
    };
    static const uint8_t key_draft_25[] = {
        0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8,
        0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30,
    };
    static const uint8_t nonce_draft_25[] = {
        0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75,
    };
    static const uint8_t nonce_v2[] = {
        0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a
    };
    gcry_cipher_hd_t    h = NULL;
    gcry_error_t        err;
    int                 pseudo_packet_tail_length = tvb_reported_length(tvb) - 16;

    DISSECTOR_ASSERT(pseudo_packet_tail_length > 0);

    err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
    DISSECTOR_ASSERT_HINT(err == 0, "create cipher");
    if (is_quic_draft_max(version, 28)) {
       err = gcry_cipher_setkey(h, key_draft_25, sizeof(key_draft_25));
    } else if (is_quic_draft_max(version, 32)) {
       err = gcry_cipher_setkey(h, key_draft_29, sizeof(key_draft_29));
    } else if (is_quic_draft_max(version, 34)) {
       err = gcry_cipher_setkey(h, key_v1, sizeof(key_v1));
    } else {
       err = gcry_cipher_setkey(h, key_v2, sizeof(key_v2));
    }
    DISSECTOR_ASSERT_HINT(err == 0, "set key");
    if (is_quic_draft_max(version, 28)) {
        err = gcry_cipher_setiv(h, nonce_draft_25, sizeof(nonce_draft_25));
    } else if (is_quic_draft_max(version, 32)) {
        err = gcry_cipher_setiv(h, nonce_draft_29, sizeof(nonce_draft_29));
    } else if (is_quic_draft_max(version, 34)) {
        err = gcry_cipher_setiv(h, nonce_v1, sizeof(nonce_v1));
    } else {
        err = gcry_cipher_setiv(h, nonce_v2, sizeof(nonce_v2));
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
        quic_packet->retry_integrity_failure = true;
    } else {
        quic_packet->retry_integrity_success = true;
    }
    gcry_cipher_close(h);
}

void
quic_add_connection(packet_info *pinfo, quic_cid_t *cid)
{
    quic_datagram *dgram_info;

    dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    if (dgram_info && dgram_info->conn) {
        quic_connection_add_cid(dgram_info->conn, cid, dgram_info->from_server);
    }
}

void
quic_add_loss_bits(packet_info *pinfo, uint64_t value)
{
    quic_datagram *dgram_info;
    quic_info_data_t *conn;

    dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    if (dgram_info && dgram_info->conn) {
        conn = dgram_info->conn;
        if (dgram_info->from_server) {
            conn->server_loss_bits_recv = true;
            if (value == 1) {
                conn->server_loss_bits_send = true;
            }
        } else {
            conn->client_loss_bits_recv = true;
            if (value == 1) {
                conn->client_loss_bits_send = true;
            }
        }
    }
}

/* Check if "multipath" feature has been negotiated */
static unsigned
quic_multipath_negotiated(quic_info_data_t *conn)
{
    if (conn->client_multipath != conn->server_multipath)
        return 0;

    return conn->client_multipath;
}

void
quic_add_multipath(packet_info *pinfo, unsigned version)
{
    quic_datagram *dgram_info;
    quic_info_data_t *conn;

    dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    if (dgram_info && dgram_info->conn) {
        conn = dgram_info->conn;
        if (dgram_info->from_server) {
            conn->server_multipath = version;
        } else {
            conn->client_multipath = version;
        }
    }
}

void
quic_add_grease_quic_bit(packet_info *pinfo)
{
    quic_datagram *dgram_info;
    quic_info_data_t *conn;

    dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    if (dgram_info && dgram_info->conn) {
        conn = dgram_info->conn;
        if (dgram_info->from_server) {
            conn->server_grease_quic_bit = true;
        } else {
            conn->client_grease_quic_bit = true;
        }
    }
}

static quic_info_data_t *
quic_find_stateless_reset_token(packet_info *pinfo, tvbuff_t *tvb, bool *from_server)
{
    /* RFC 9000 10.3.1 Detecting a Stateless Reset
     * "The endpoint identifies a received datagram as a Stateless
     * Reset by comparing the last 16 bytes of the datagram with all
     * stateless reset tokens associated with the remote address on
     * which the datagram was received." That means we check all QUIC
     * connections on the 5-tuple (as when a nonzero Connection ID is
     * used there can be more than one.)
     */
    quic_info_data_t* conn = quic_connection_from_conv(pinfo);
    const quic_cid_item_t *cids;

    while (conn) {
        bool conn_from_server;
        conn_from_server = conn->server_port == pinfo->srcport &&
                addresses_equal(&conn->server_address, &pinfo->src);
        cids = conn_from_server ? &conn->server_cids : &conn->client_cids;
        while (cids) {
            const quic_cid_t *cid = &cids->data;
            /* XXX: Ibid., "An endpoint MUST NOT check for any stateless
             * reset token associated with connection IDs it has not
             * used or for connection IDs that have been retired,"
             * so we ideally should track when they are retired.
             */
            if (cid->reset_token_set &&
                    !tvb_memeql(tvb, -16, cid->reset_token, 16) ) {
                *from_server = conn_from_server;
                return conn;
            }
            cids = cids->next;
        }
        conn = conn->prev;
    }
    return NULL;
}

void
quic_add_stateless_reset_token(packet_info *pinfo, tvbuff_t *tvb, int offset, const quic_cid_t *cid)
{
    quic_datagram *dgram_info;
    quic_info_data_t *conn;
    quic_cid_item_t *cids;

    dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    if (dgram_info && dgram_info->conn) {
        conn = dgram_info->conn;
        if (dgram_info->from_server) {
            cids = &conn->server_cids;
        } else {
            cids = &conn->client_cids;
        }

        if (cid) {
            while (cids) {
                quic_cid_t *old_cid = &cids->data;
                if (quic_connection_equal(old_cid, cid) ) {
                    tvb_memcpy(tvb, old_cid->reset_token, offset, 16);
                    old_cid->reset_token_set = true;
                    return;
                }
                cids = cids->next;
            }
        } else {
            /* If cid is NULL (this is a Handshake message),
             * add it to the most recent cid. (There could
             * have been a Retry.)
             */
            while (cids->next != NULL) cids = cids->next;
            quic_cid_t *old_cid = &cids->data;
            tvb_memcpy(tvb, old_cid->reset_token, offset, 16);
            old_cid->reset_token_set = true;
            return;
        }
    }
    /* Failed to find cid. */
    return;
}

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

    /* Set the conversation elements so that TLS and other subdissectors
     * calling find_conversation_pinfo() find this QUIC connection and
     * not all QUIC connections multiplexed on the same network 5-tuple.
     */
    conversation_set_elements_by_id(pinfo, CONVERSATION_QUIC, conn->number);
    pi = proto_tree_add_uint(ctree, hf_quic_connection_number, tvb, 0, 0, conn->number);
    proto_item_set_generated(pi);
#if 0
    proto_tree_add_debug_text(ctree, "Client CID: %s", cid_to_string(pinfo->pool, &conn->client_cids.data));
    proto_tree_add_debug_text(ctree, "Server CID: %s", cid_to_string(pinfo->pool, &conn->server_cids.data));
    // Note: for Retry, this value has been cleared before.
    proto_tree_add_debug_text(ctree, "InitialCID: %s", cid_to_string(pinfo->pool, &conn->client_dcid_initial));
#endif
}

/**
 * Dissects the common part after the first byte for packets using the Long
 * Header form.
 */
static int
dissect_quic_long_header_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                                unsigned offset, const quic_packet_info_t *quic_packet _U_,
                                quic_cid_t *dcid, quic_cid_t *scid)
{
    uint32_t    version;
    uint32_t    dcil, scil;
    proto_item  *ti;

    version = tvb_get_ntohl(tvb, offset);

    ti = proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
        proto_item_append_text(ti, " (Forcing Version Negotiation)");
    }
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
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", cid_to_string(pinfo->pool, dcid));
    }
    if (scid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", SCID=%s", cid_to_string(pinfo->pool, scid));
    }
    return offset;
}

/* Retry Packet dissection */
static int
dissect_quic_retry_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                          quic_datagram *dgram_info _U_, quic_packet_info_t *quic_packet,
                          const quic_cid_t *odcid, uint32_t version)
{
    unsigned    offset = 0;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    uint32_t    odcil = 0;
    unsigned    retry_token_len;
    proto_item *ti;

    if (is_quic_v2(version)) {
        proto_tree_add_item(quic_tree, hf_quic_long_packet_type_v2, tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA);
    }
    offset += 1;
    col_set_str(pinfo->cinfo, COL_INFO, "Retry");

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &dcid, &scid);

    if (is_quic_draft_max(version, 24)) {
        proto_tree_add_item_ret_uint(quic_tree, hf_quic_odcil, tvb, offset, 1, ENC_NA, &odcil);
        offset++;
        proto_tree_add_item(quic_tree, hf_quic_odcid, tvb, offset, odcil, ENC_NA);
        offset += odcil;
    }

    retry_token_len = tvb_reported_length_remaining(tvb, offset);
    // Remove length of Retry Integrity Tag
    if (!is_quic_draft_max(version, 24) && retry_token_len >= 16) {
        retry_token_len -= 16;
    }
    proto_tree_add_item(quic_tree, hf_quic_retry_token, tvb, offset, retry_token_len, ENC_NA);
    offset += retry_token_len;

    if (!is_quic_draft_max(version, 24)) {
        // Verify the Retry Integrity Tag according to
        // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
        ti = proto_tree_add_item(quic_tree, hf_quic_retry_integrity_tag, tvb, offset, 16, ENC_NA);
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
        offset += 16;
    }

    return offset;
}

static int
dissect_quic_long_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                         quic_datagram *dgram_info, quic_packet_info_t *quic_packet)
{
    unsigned offset = 0;
    uint8_t long_packet_type;
    uint32_t version;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    int32_t len_token_length;
    uint64_t token_length;
    int32_t len_payload_length;
    uint64_t payload_length;
    uint8_t first_byte = 0;
    quic_info_data_t *conn = dgram_info->conn;
    const bool from_server = dgram_info->from_server;
    quic_ciphers *ciphers = NULL;
    proto_item *ti;

    quic_extract_header(tvb, &long_packet_type, &version, &dcid, &scid);
    if (!PINFO_FD_VISITED(pinfo)) {
        quic_packet->packet_type = long_packet_type;
    }
    if (conn) {
        if (long_packet_type == QUIC_LPT_INITIAL) {
            ciphers = !from_server ? &conn->client_initial_ciphers : &conn->server_initial_ciphers;
        } else if (long_packet_type == QUIC_LPT_0RTT && !from_server) {
            ciphers = &conn->client_0rtt_ciphers;
        } else if (long_packet_type == QUIC_LPT_HANDSHAKE) {
            ciphers = !from_server ? &conn->client_handshake_ciphers : &conn->server_handshake_ciphers;
        }
    }
    /* Prepare the Initial/Handshake cipher for header/payload decryption. */
    if (!PINFO_FD_VISITED(pinfo) && conn && ciphers) {
#define DIGEST_MIN_SIZE 32  /* SHA256 */
#define DIGEST_MAX_SIZE 48  /* SHA384 */
        const char *error = NULL;
        char early_data_secret[DIGEST_MAX_SIZE];
        unsigned early_data_secret_len = 0;
        if (long_packet_type == QUIC_LPT_INITIAL && !from_server &&
            quic_connection_equal(&dcid, &conn->client_dcid_initial)) {
            /* Create new decryption context based on the Client Connection
             * ID from the *very first* Client Initial packet. */
            quic_create_initial_decoders(&dcid, &error, conn);
        } else if (long_packet_type == QUIC_LPT_INITIAL && from_server &&
                   version != conn->version) {
            /* Compatibile Version Negotiation: the server (probably) updated the connection version.
               We need to restart the ciphers since HP depends on version.
               If/when updating the ciphers is a bit tricky during Compatible Version Negotiation.
               TODO: do we really need to restart all the initial ciphers?
             */
            conn->version = version;
            quic_ciphers_reset(ciphers);
            quic_create_initial_decoders(&conn->client_dcid_initial, &error, conn);
        } else if (long_packet_type == QUIC_LPT_0RTT) {
            early_data_secret_len = tls13_get_quic_secret(pinfo, false, TLS_SECRET_0RTT_APP, DIGEST_MIN_SIZE, DIGEST_MAX_SIZE, early_data_secret);
            if (early_data_secret_len == 0) {
                error = "Secrets are not available";
            }
        } else if (long_packet_type == QUIC_LPT_HANDSHAKE) {
            if (!quic_are_ciphers_initialized(ciphers)) {
                quic_create_decoders(pinfo, conn, ciphers, from_server, TLS_SECRET_HANDSHAKE, &error);
            }
        }
        if (!error) {
            uint32_t pkn32 = 0;
            int hp_cipher_algo = long_packet_type != QUIC_LPT_INITIAL && conn ? conn->cipher_algo : GCRY_CIPHER_AES128;
            // PKN is after type(1) + version(4) + DCIL+DCID + SCIL+SCID
            unsigned pn_offset = 1 + 4 + 1 + dcid.len + 1 + scid.len;
            if (long_packet_type == QUIC_LPT_INITIAL) {
                pn_offset += tvb_get_varint(tvb, pn_offset, 8, &token_length, ENC_VARINT_QUIC);
                pn_offset += (unsigned)token_length;
            }
            pn_offset += tvb_get_varint(tvb, pn_offset, 8, &payload_length, ENC_VARINT_QUIC);

            // Assume failure unless proven otherwise.
            error = "Header deprotection failed";
            if (long_packet_type != QUIC_LPT_0RTT) {
                if (quic_decrypt_header(tvb, pn_offset, &ciphers->hp_cipher, hp_cipher_algo, &first_byte, &pkn32, false)) {
                    error = NULL;
                }
            } else {
                // Cipher is not stored with 0-RTT data or key, perform trial decryption.
                for (unsigned i = 0; quic_create_0rtt_decoder(i, early_data_secret, early_data_secret_len, ciphers, &hp_cipher_algo, version); i++) {
                    if (quic_is_hp_cipher_initialized(&ciphers->hp_cipher) && quic_decrypt_header(tvb, pn_offset, &ciphers->hp_cipher, hp_cipher_algo, &first_byte, &pkn32, false)) {
                        error = NULL;
                        break;
                    }
                }
            }
            if (!error) {
                quic_set_full_packet_number(conn, quic_packet, dgram_info->path_id, from_server, first_byte, pkn32);
                quic_packet->first_byte = first_byte;
            }
        }
        if (error) {
            quic_packet->decryption.error = wmem_strdup(wmem_file_scope(), error);
        }
    } else if (conn && quic_packet->pkn_len) {
        first_byte = quic_packet->first_byte;
    }

    proto_tree_add_item(quic_tree, hf_quic_fixed_bit, tvb, offset, 1, ENC_NA);
    if (is_quic_v2(version)) {
        proto_tree_add_item(quic_tree, hf_quic_long_packet_type_v2, tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA);
    }
    if (quic_packet->pkn_len) {
        ti = proto_tree_add_uint(quic_tree, hf_quic_long_reserved, tvb, offset, 1, first_byte);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(quic_tree, hf_quic_packet_number_length, tvb, offset, 1, first_byte);
        proto_item_set_generated(ti);
    }
    offset += 1;
    /* Trick: internal values in `long_packet_type` are always correctly mapped by V1 enum */
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(long_packet_type, quic_v1_long_packet_type_vals, "Long Header"));

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &dcid, &scid);

    if (long_packet_type == QUIC_LPT_INITIAL) {
        ti = proto_tree_add_item_ret_varint(quic_tree, hf_quic_token_length, tvb, offset, -1, ENC_VARINT_QUIC, &token_length, &len_token_length);
        offset += len_token_length;

        if (token_length) {
            proto_tree_add_item(quic_tree, hf_quic_token, tvb, offset, (uint32_t)token_length, ENC_NA);
            /* RFC 9287: "A client MAY also set the QUIC Bit to 0 in Initial,
             * Handshake, or 0-RTT packets that are sent prior to receiving
             * transport parameters from the server. However, a client MUST
             * NOT set the QUIC Bit to 0 unless the Initial packets it sends
             * include a token provided by the server in a NEW_TOKEN frame,
             * received less than 604800 seconds (7 days) prior on a
             * connection where the server also included the grease_quic_bit
             * transport parameter."
             */
            if (from_server) {
                expert_add_info_format(pinfo, ti, &ei_quic_protocol_violation,
                            "Initial packets sent by the server must set the Token Length field to 0");
            } else if (conn) {
                /* The client [may] know that the server supports greasing the
                 * QUIC bit, and perhaps will do so. (We can't really test if
                 * this token came less than 7 days ago from a server that
                 * supports it, so we'll assume it might be to be safe.)
                 */
                conn->server_grease_quic_bit = true;
            }
            offset += (unsigned)token_length;
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
        // if not part of a connection, the full PKN cannot be reconstructed.
        expert_add_info_format(pinfo, quic_tree, &ei_quic_decryption_failed, "Failed to decrypt packet number");
        return offset;
    }

    ti = proto_tree_add_uint64(quic_tree, hf_quic_packet_number, tvb, offset, quic_packet->pkn_len, quic_packet->packet_number);
    proto_item_set_generated(ti);

    offset += quic_packet->pkn_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" PRIu64, quic_packet->packet_number);

    /* Payload */
    ti = proto_tree_add_item(quic_tree, hf_quic_payload, tvb, offset, -1, ENC_NA);

    if (conn) {
        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, from_server, &ciphers->pp_cipher, first_byte, quic_packet->pkn_len);
    }
    if (!PINFO_FD_VISITED(pinfo) && !quic_packet->decryption.error) {
        // Packet number is verified to be valid, remember it.
        *quic_max_packet_number(conn, dgram_info->path_id, from_server, first_byte) = quic_packet->packet_number;

        // To be able to understand 0-RTT data sent we need to grab the ALPN the client wanted.
        if (long_packet_type == QUIC_LPT_INITIAL) {
            const char *proto_name = tls_get_client_alpn(pinfo);
            if (proto_name) {
                conn->zrtt_app_handle = dissector_get_string_handle(quic_proto_dissector_table, proto_name);
                // If no specific handle is found, alias "h3-*" to "h3" and "doq-*" to "doq"
                if (!conn->zrtt_app_handle) {
                    if (g_str_has_prefix(proto_name, "h3-")) {
                        conn->zrtt_app_handle = dissector_get_string_handle(quic_proto_dissector_table, "h3");
                    } else if (g_str_has_prefix(proto_name, "doq-")) {
                        conn->zrtt_app_handle = dissector_get_string_handle(quic_proto_dissector_table, "doq");
                    }
                }
            }
        }
    }
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

/* Check if "loss bits" feature has been negotiated */
static bool
quic_loss_bits_negotiated(quic_info_data_t *conn, bool from_server)
{
    if (from_server) {
        return conn->client_loss_bits_recv && conn->server_loss_bits_send;
    } else {
        return conn->server_loss_bits_recv && conn->client_loss_bits_send;
    }
}

static int
dissect_quic_short_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                          quic_datagram *dgram_info, quic_packet_info_t *quic_packet)
{
    unsigned offset = 0;
    quic_cid_t dcid = {.len=0};
    uint8_t first_byte = 0;
    bool        key_phase = false;
    proto_item *ti;
    quic_pp_cipher pp_cipher = {0};
    quic_info_data_t *conn = dgram_info->conn;
    const bool from_server = dgram_info->from_server;
    bool loss_bits_negotiated = false;

    proto_item *pi = proto_tree_add_item(quic_tree, hf_quic_short, tvb, 0, -1, ENC_NA);
    proto_tree *hdr_tree = proto_item_add_subtree(pi, ett_quic_short_header);
    proto_tree_add_item(hdr_tree, hf_quic_header_form, tvb, 0, 1, ENC_NA);

    if (!PINFO_FD_VISITED(pinfo)) {
        quic_packet->packet_type = QUIC_SHORT_PACKET;
    }
    if (conn) {
       dcid.len = from_server ? conn->client_cids.data.len : conn->server_cids.data.len;
       loss_bits_negotiated = quic_loss_bits_negotiated(conn, from_server);
    }
    if (!PINFO_FD_VISITED(pinfo) && conn) {
        const char *error = NULL;
        uint32_t pkn32 = 0;
        quic_hp_cipher *hp_cipher = quic_get_1rtt_hp_cipher(pinfo, conn, from_server, &error);
        if (quic_is_hp_cipher_initialized(hp_cipher) && quic_decrypt_header(tvb, 1 + dcid.len, hp_cipher, conn->cipher_algo, &first_byte, &pkn32, loss_bits_negotiated)) {
            quic_set_full_packet_number(conn, quic_packet, dgram_info->path_id, from_server, first_byte, pkn32);
            quic_packet->first_byte = first_byte;
        }
        if (error) {
            quic_packet->decryption.error = wmem_strdup(wmem_file_scope(), error);
        }
    } else if (conn && quic_packet->pkn_len) {
        first_byte = quic_packet->first_byte;
    }
    proto_tree_add_item(hdr_tree, hf_quic_fixed_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(hdr_tree, hf_quic_spin_bit, tvb, offset, 1, ENC_NA);
    /* Q and L bits are not protected by HP cipher */
    if (loss_bits_negotiated) {
        proto_tree_add_item(hdr_tree, hf_quic_q_bit, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(hdr_tree, hf_quic_l_bit, tvb, offset, 1, ENC_NA);
    }
    if (quic_packet->pkn_len) {
        key_phase = (first_byte & SH_KP) != 0;
        /* No room for reserved bits with "loss bits" feature is enable */
        if (!loss_bits_negotiated) {
            ti = proto_tree_add_uint(hdr_tree, hf_quic_short_reserved, tvb, offset, 1, first_byte);
            proto_item_set_generated(ti);
        }
        ti = proto_tree_add_boolean(hdr_tree, hf_quic_key_phase, tvb, offset, 1, key_phase<<2);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(hdr_tree, hf_quic_packet_number_length, tvb, offset, 1, first_byte);
        proto_item_set_generated(ti);
    }
    offset += 1;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Protected Payload (KP%u)", key_phase);

    /* Connection ID */
    if (dcid.len > 0) {
        proto_tree_add_item(hdr_tree, hf_quic_dcid, tvb, offset, dcid.len, ENC_NA);
        tvb_memcpy(tvb, dcid.cid, offset, dcid.len);
        offset += dcid.len;
        const char *dcid_str = cid_to_string(pinfo->pool, &dcid);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", dcid_str);
        proto_item_append_text(pi, " DCID=%s", dcid_str);
    }

    if (quic_packet->decryption.error) {
        expert_add_info_format(pinfo, quic_tree, &ei_quic_decryption_failed,
                               "Failed to create decryption context: %s", quic_packet->decryption.error);
        return offset;
    }
    if (!conn || conn->skip_decryption || quic_packet->pkn_len == 0) {
        return offset;
    }

    /* Packet Number */
    ti = proto_tree_add_uint64(hdr_tree, hf_quic_packet_number, tvb, offset, quic_packet->pkn_len, quic_packet->packet_number);
    proto_item_set_generated(ti);
    offset += quic_packet->pkn_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" PRIu64, quic_packet->packet_number);
    proto_item_append_text(pi, " PKN=%" PRIu64, quic_packet->packet_number);

    /* Protected Payload */
    ti = proto_tree_add_item(hdr_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);

    if (conn) {
        bool phase_change = false;
        if (!PINFO_FD_VISITED(pinfo)) {
            phase_change = quic_get_pp_cipher(&pp_cipher, key_phase, conn, from_server, quic_packet->packet_number);
        }

        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, from_server, &pp_cipher,
                             first_byte, quic_packet->pkn_len);
        if (!PINFO_FD_VISITED(pinfo)) {
            if (!quic_packet->decryption.error) {
                // Packet number is verified to be valid, remember it.
                *quic_max_packet_number(conn, dgram_info->path_id, from_server, first_byte) = quic_packet->packet_number;
                // pp cipher is verified to be valid, remember if it new.
                quic_set_pp_cipher(&pp_cipher, key_phase, conn, from_server, quic_packet->packet_number);
            } else if (phase_change) {
                quic_pp_cipher_reset(&pp_cipher);
            }
        }
    }
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

void
quic_proto_tree_add_version(tvbuff_t *tvb, proto_tree *tree, int hfindex, unsigned offset)
{
    uint32_t version;
    proto_item *ti;

    ti = proto_tree_add_item_ret_uint(tree, hfindex, tvb, offset, 4, ENC_BIG_ENDIAN, &version);
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
        proto_item_append_text(ti, " (GREASE)");
    }
}

static int
dissect_quic_version_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, const quic_packet_info_t *quic_packet)
{
    unsigned    offset = 0;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};

    col_set_str(pinfo->cinfo, COL_INFO, "Version Negotiation");

    proto_tree_add_item(quic_tree, hf_quic_vn_unused, tvb, offset, 1, ENC_NA);
    offset += 1;

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &dcid, &scid);

    /* Supported Version */
    while(tvb_reported_length_remaining(tvb, offset) > 0){
        quic_proto_tree_add_version(tvb, quic_tree, hf_quic_supported_version, offset);
        offset += 4;
    }

    return offset;
}

static int
dissect_quic_forcing_version_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, const quic_packet_info_t *quic_packet)
{
    unsigned    offset = 0;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};

    col_set_str(pinfo->cinfo, COL_INFO, "Forcing Version Negotiation");

    proto_tree_add_item(quic_tree, hf_quic_vn_unused, tvb, offset, 1, ENC_NA);
    offset += 1;

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &dcid, &scid);

    return offset;
}

static unsigned quic_gso_heur_dcid_len = 8;

static tvbuff_t *
quic_get_message_tvb(tvbuff_t *tvb, const unsigned offset, const quic_cid_t *dcid)
{
    uint64_t token_length;
    uint64_t payload_length;
    uint8_t packet_type = tvb_get_uint8(tvb, offset);
    // Retry and VN packets cannot be coalesced (clarified in draft -14).
    if (packet_type & 0x80) {
        unsigned version = tvb_get_ntohl(tvb, offset + 1);
        uint8_t long_packet_type = quic_get_long_packet_type(packet_type, version);
        if (long_packet_type != QUIC_LPT_RETRY) {
            // long header form, check version
            // If this is not a VN packet but a valid long form, extract a subset.
            // TODO check for valid QUIC versions as future versions might change the format.
            if (version != 0) {
                unsigned length = 5;   // flag (1 byte) + version (4 bytes)
                length += 1 + tvb_get_uint8(tvb, offset + length); // DCID
                length += 1 + tvb_get_uint8(tvb, offset + length); // SCID
                if (long_packet_type == QUIC_LPT_INITIAL) {
                    length += tvb_get_varint(tvb, offset + length, 8, &token_length, ENC_VARINT_QUIC);
                    length += (unsigned)token_length;
                }
                length += tvb_get_varint(tvb, offset + length, 8, &payload_length, ENC_VARINT_QUIC);
                length += (unsigned)payload_length;
                if (payload_length <= INT32_MAX && length < (unsigned)tvb_reported_length_remaining(tvb, offset)) {
                    return tvb_new_subset_length(tvb, offset, length);
                }
            }
        }
    } else {
        if (quic_gso_heur_dcid_len && (dcid->len >= quic_gso_heur_dcid_len)) {
            unsigned dcid_offset = offset + 1;
            tvbuff_t *needle_tvb = tvb_new_subset_length(tvb, dcid_offset, dcid->len);
            int needle_pos = tvb_find_tvb(tvb, needle_tvb, dcid_offset + dcid->len);
            if (needle_pos != -1) {
                return tvb_new_subset_length(tvb, offset, needle_pos - offset - 1);
            }
        }
    }

    // short header form, VN or unknown message, return remaining data.
    return tvb_new_subset_remaining(tvb, offset);
}

static int
dissect_quic_stateless_reset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *quic_tree, const quic_datagram *dgram_info _U_)
{
    proto_item *ti;

    col_set_str(pinfo->cinfo, COL_INFO, "Stateless Reset");

    ti = proto_tree_add_uint(quic_tree, hf_quic_packet_length, tvb, 0, 0, tvb_reported_length(tvb));
    proto_item_set_generated(ti);
    ti = proto_tree_add_item(quic_tree, hf_quic_header_form, tvb, 0, 1, ENC_NA);
    if (tvb_get_uint8(tvb, 0) & 0x80) {
        /* RFC 9000 says that endpoints MUST treat any packets ending in a valid
         * stateless reset token as a Stateless Reset, even though they MUST
         * send them formatted as packets with short headers.
         */
        expert_add_info_format(pinfo, ti, &ei_quic_protocol_violation,
                "Stateless Reset packets must be formatted as with short header");
    }
    proto_tree_add_item(quic_tree, hf_quic_fixed_bit, tvb, 0, 1, ENC_NA);
    proto_tree_add_bits_item(quic_tree, hf_quic_unpredictable_bits, tvb, 2, (tvb_reported_length(tvb) - 16)*8 - 2, ENC_NA);
    proto_tree_add_item(quic_tree, hf_quic_stateless_reset_token, tvb, tvb_reported_length(tvb)-16, 16, ENC_NA);

    return tvb_reported_length(tvb);
}

/**
 * Extracts necessary information from header to find any existing connection.
 * There are two special values for "long_packet_type":
 *  * QUIC_SHORT_PACKET for short header packets;
 *  * QUIC_LPT_VER_NEG for Version Negotiation packets.
 * DCID and SCID are not modified unless available. For short header packets,
 * DCID length is unknown, so the caller should truncate it as needed.
 */
static void
quic_extract_header(tvbuff_t *tvb, uint8_t *long_packet_type, uint32_t *version,
                    quic_cid_t *dcid, quic_cid_t *scid)
{
    unsigned offset = 0;

    uint8_t packet_type = tvb_get_uint8(tvb, offset);
    bool is_long_header = packet_type & 0x80;

    offset++;

    if (is_long_header) {
        // long header form
        *version = tvb_get_ntohl(tvb, offset);
        *long_packet_type = quic_get_long_packet_type(packet_type, *version);
    } else {
        // short header form, store dummy value that is not a long packet type.
        *long_packet_type = QUIC_SHORT_PACKET;
    }


    if (is_long_header) {
        /* VN packets don't have any real packet type field, even if they have
           a long header: use a dummy value */
        if (*version == 0x00000000)
            *long_packet_type = QUIC_LPT_VER_NEG;

        // skip version
        offset += 4;

        // read DCID and SCID (both are prefixed by a length byte).
        uint8_t dcil = tvb_get_uint8(tvb, offset);
        offset++;

        if (dcil && dcil <= QUIC_MAX_CID_LENGTH) {
            tvb_memcpy(tvb, dcid->cid, offset, dcil);
            dcid->len = dcil;
        }
        offset += dcil;

        uint8_t scil = tvb_get_uint8(tvb, offset);
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

/**
 * Sanity check on (coalesced) packet.
 * https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12.2
 * "Senders MUST NOT coalesce QUIC packets with different connection IDs
 *  into a single UDP datagram"
 * For the first packet of the datagram, we simply save the DCID for later usage (no real check).
 * For any subsequent packets, we control if DCID is valid.
 * XXX: Generic Segmentation Offload (GSO) captures from Linux create headaches
 * here, and even more so with short header packets. (#19109)
 */
static bool
check_dcid_on_coalesced_packet(tvbuff_t *tvb, const quic_datagram *dgram_info,
                               unsigned offset, quic_cid_t *first_packet_dcid)
{
    bool is_first_packet = (offset == 0);
    uint8_t first_byte, dcid_len;
    quic_cid_t dcid = {.len=0};
    quic_info_data_t *conn = dgram_info->conn;
    bool from_server = dgram_info->from_server;
    bool grease_quic_bit;

    first_byte = tvb_get_uint8(tvb, offset);
    offset++;
    if (first_byte & 0x80) {
        offset += 4; /* Skip version */
        dcid_len = tvb_get_uint8(tvb, offset);
        offset++;
        if (dcid_len && dcid_len <= QUIC_MAX_CID_LENGTH) {
            dcid.len = dcid_len;
            tvb_memcpy(tvb, dcid.cid, offset, dcid.len);
        }
    } else {
        if (conn) {
            dcid.len = from_server ? conn->client_cids.data.len : conn->server_cids.data.len;
            if (dcid.len) {
                tvb_memcpy(tvb, dcid.cid, offset, dcid.len);
            }
        } else {
            /* If we don't have a valid quic_info_data_t structure for this flow,
               we can't really validate the CID. */
            return true;
        }
    }

    if (conn) {
        grease_quic_bit = from_server ? conn->client_grease_quic_bit : conn->server_grease_quic_bit;
    } else {
        /* Assume we're allowed to grease the Fixed bit if no connection. */
        grease_quic_bit = true;
    }

    if (is_first_packet) {
        *first_packet_dcid = dcid;
        return true; /* Nothing to check */
    }

    if (!grease_quic_bit && (first_byte & 0x40) == 0) {
        return false;
    }

    const quic_packet_info_t *last_packet = &dgram_info->first_packet;
    while (last_packet->next) {
        last_packet = last_packet->next;
    }
    /* We should not see any Short Header (1-RTT) packets before the 1-RTT keys
     * have been negotiated. Under normal circumstances, that means that if the
     * last QUIC packet in the frame before this one is an Initial packet or a
     * 0-RTT packet, then this cannot be a SH packet but instead is presumably
     * padding data.
     */
    if (last_packet->packet_type == QUIC_LPT_INITIAL ||
        last_packet->packet_type == QUIC_LPT_0RTT) {
        if ((first_byte & 0x80) == 0) {
            return false;
        }
    }

#if 0
    /* XXX - That seems almost certainly true for Initial packets, but due
     * to packet loss, 0-RTT packets might get resent and interleaved with
     * Handshake packets, see
     * https://www.rfc-editor.org/rfc/rfc9001#section-4.1.4
     * If we have a connection, perhaps on the first pass we should check:
     */
    if (conn && ((first_byte & 0x80) == 0)) {
        quic_ciphers ciphers = !from_server ? &conn->client_handshake_ciphers : &conn->server_handshake_ciphers;
        if (!quic_are_ciphers_initialized(ciphers)) {
            return false;
        }
    }
    /* But on the second pass the ciphers would already be initialized from
     * later frames so we would need to remember the result from the first pass.
     * Or, instead of the DISSECTOR_ASSERT(quic_packet); below, we just assume
     * that if there's no quic packet that's because this failed here.
     *
     * However, this other solution has issues if the Server Handshake is
     * fragmented, the server sends 1-RTT data (as "0.5-RTT" data) after the
     * last Handshake fragment, but then is forced to resend an earlier
     * Handshake fragment due to not getting an ACK. We need to recognize the
     * 1-RTT data when it's first sent, not when the Handshake is reassembled.
     * (Or at least store it as potential 1-RTT to handle later, even if it
     * turns out to be padding.)
     */
#endif

    /* Compare the DCID. Note this doesn't help with a 0 length DCID. */
    return quic_connection_equal(&dcid, first_packet_dcid);
}

static int
dissect_quic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *quic_ti, *ti;
    proto_tree *quic_tree;
    unsigned    offset = 0;
    quic_datagram *dgram_info = NULL;
    quic_packet_info_t *quic_packet = NULL;
    quic_cid_t  real_retry_odcid = {.len=0}, *retry_odcid = NULL;
    quic_cid_t  first_packet_dcid = {.len=0}; /* DCID of the first packet of the datagram */

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
        uint8_t     long_packet_type;
        uint32_t    version;
        quic_cid_t  dcid = {.len=0}, scid = {.len=0};
        bool        from_server = false;
        quic_info_data_t *conn;

        quic_extract_header(tvb, &long_packet_type, &version, &dcid, &scid);
        conn = quic_connection_find(pinfo, long_packet_type, &dcid, &from_server);
        if (conn && long_packet_type == QUIC_LPT_RETRY && conn->client_dcid_set) {
            // Save the original client DCID before erasure.
            real_retry_odcid = conn->client_dcid_initial;
            retry_odcid = &real_retry_odcid;
        }
        if (!conn && tvb_bytes_exist(tvb, -16, 16) && (conn = quic_find_stateless_reset_token(pinfo, tvb, &from_server))) {
            dgram_info->stateless_reset = true;
        } else {
            quic_connection_create_or_update(&conn, pinfo, long_packet_type, version, &scid, &dcid, from_server);
        }
        dgram_info->conn = conn;
        dgram_info->from_server = from_server;
        /* Senders MUST not coalesce packets with a different Connection ID
         * into the same datagram, so we can store the path ID here.
         */
        if (conn && quic_multipath_negotiated(conn) == QUIC_MP_NO_PATH_ID) {
            dgram_info->path_id = dcid.seq_num;
        } else {
            dgram_info->path_id = dcid.path_id;
        }
#if 0
        proto_tree_add_debug_text(quic_tree, "Connection: %d %p DCID=%s SCID=%s from_server:%d", pinfo->num, dgram_info->conn, cid_to_string(pinfo->pool, &dcid), cid_to_string(pinfo->pool, &scid), dgram_info->from_server);
    } else {
        proto_tree_add_debug_text(quic_tree, "Connection: %d %p from_server:%d", pinfo->num, dgram_info->conn, dgram_info->from_server);
#endif
    }

    quic_add_connection_info(tvb, pinfo, quic_tree, dgram_info->conn);

    if (dgram_info->stateless_reset) {
        return dissect_quic_stateless_reset(tvb, pinfo, quic_tree, dgram_info);
    }

    do {
        /* Ensure that coalesced QUIC packets end up separated. */
        if (offset > 0) {
            quic_ti = proto_tree_add_item(tree, proto_quic, tvb, offset, -1, ENC_NA);
            quic_tree = proto_item_add_subtree(quic_ti, ett_quic);
        }

        if (!check_dcid_on_coalesced_packet(tvb, dgram_info, offset, &first_packet_dcid)) {
            /* Coalesced packet with unexpected CID; it probably is some kind
               of unencrypted padding data added after the valid QUIC payload */
            expert_add_info_format(pinfo, quic_tree, &ei_quic_coalesced_padding_data,
                                   "(Random) padding data appended to the datagram");
            break;
        }

        if (!quic_packet) {
            quic_packet = &dgram_info->first_packet;
        } else if (!PINFO_FD_VISITED(pinfo)) {
            quic_packet->next = wmem_new0(wmem_file_scope(), quic_packet_info_t);
            quic_packet = quic_packet->next;
        } else {
            quic_packet = quic_packet->next;
            DISSECTOR_ASSERT(quic_packet);
        }

        tvbuff_t *next_tvb = quic_get_message_tvb(tvb, offset, &first_packet_dcid);

        proto_item_set_len(quic_ti, tvb_reported_length(next_tvb));
        ti = proto_tree_add_uint(quic_tree, hf_quic_packet_length, next_tvb, 0, 0, tvb_reported_length(next_tvb));
        proto_item_set_generated(ti);
        unsigned new_offset = 0;
        uint8_t first_byte = tvb_get_uint8(next_tvb, 0);
        if (first_byte & 0x80) {
            proto_tree_add_item(quic_tree, hf_quic_header_form, next_tvb, 0, 1, ENC_NA);
            uint32_t version = tvb_get_ntohl(next_tvb, 1);
            uint8_t long_packet_type = quic_get_long_packet_type(first_byte, version);
            if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
                offset += dissect_quic_forcing_version_negotiation(next_tvb, pinfo, quic_tree, quic_packet);
                if (tvb_reported_length_remaining(tvb, offset)) {
                    /* We can't decrypt any remaining data because we don't have a valid version */
                    expert_add_info_format(pinfo, quic_tree, &ei_quic_data_after_forcing_vn,
                                           "Data appended after a Forcing VN can't be decrypted");
                }
                break;
            }
            if (version == 0) {
                offset += dissect_quic_version_negotiation(next_tvb, pinfo, quic_tree, quic_packet);
                break;
            }
            if (long_packet_type == QUIC_LPT_RETRY) {
                new_offset = dissect_quic_retry_packet(next_tvb, pinfo, quic_tree, dgram_info, quic_packet, retry_odcid, version);
            } else {
                new_offset = dissect_quic_long_header(next_tvb, pinfo, quic_tree, dgram_info, quic_packet);
            }
        } else { /* Note that the "Fixed" bit might have been greased,
                    so 0x00 is a perfectly valid value as first_byte */
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

static bool
dissect_quic_short_header_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    // If this capture does not contain QUIC, skip the more expensive checks.
    if (quic_cid_lengths == 0) {
        return false;
    }

    // Is this a SH packet after connection migration? SH (since draft -22):
    // Flag (1) + DCID (1-20) + PKN (1/2/4) + encrypted payload (>= 16).
    if (tvb_captured_length(tvb) < 1 + 1 + 1 + 16) {
        return false;
    }

    // DCID length is unknown, so extract the maximum and look for a match.
    quic_cid_t dcid = {.len = MIN(QUIC_MAX_CID_LENGTH, tvb_captured_length(tvb) - 1 - 1 - 16)};
    tvb_memcpy(tvb, dcid.cid, 1, dcid.len);
    bool from_server;
    if (!quic_connection_find(pinfo, QUIC_SHORT_PACKET, &dcid, &from_server)) {
        return false;
    }

    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, quic_handle);
    dissect_quic(tvb, pinfo, tree, NULL);
    return true;
}

static bool dissect_quic_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
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
    uint8_t flags, dcid, scid;
    uint32_t version;
    bool is_quic = false;

    /* Verify packet size  (Flag (1 byte) + Connection ID (8 bytes) + Version (4 bytes)) */
    if (tvb_captured_length(tvb) < 13)
    {
        return false;
    }

    flags = tvb_get_uint8(tvb, offset);
    /* Check if long Packet is set */
    if((flags & 0x80) == 0) {
        // Perhaps this is a short header, check it.
        return dissect_quic_short_header_heur(tvb, pinfo, tree);
    }
    offset += 1;

    // check for draft QUIC version (for draft -11 and newer)
    version = tvb_get_ntohl(tvb, offset);
    is_quic = (quic_draft_version(version) >= 11);
    if (!is_quic) {
        return false;
    }

    /* Check that CIDs lengths are valid */
    offset += 4;
    dcid = tvb_get_uint8(tvb, offset);
    if (dcid > QUIC_MAX_CID_LENGTH) {
        return false;
    }
    offset += 1 + dcid;
    if (offset >= (int)tvb_captured_length(tvb)) {
        return false;
    }
    scid = tvb_get_uint8(tvb, offset);
    if (scid > QUIC_MAX_CID_LENGTH) {
        return false;
    }

    /* Ok! */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, quic_handle);
    dissect_quic(tvb, pinfo, tree, data);

    return true;
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
static void
quic_streams_add(packet_info *pinfo, quic_info_data_t *quic_info, uint64_t stream_id)
{
    /* List: ordered list of Stream IDs in this connection */
    if (!quic_info->streams_list) {
        quic_info->streams_list = wmem_list_new(wmem_file_scope());
    }
    if (!wmem_list_find(quic_info->streams_list, GUINT_TO_POINTER(stream_id))) {
        wmem_list_insert_sorted(quic_info->streams_list, GUINT_TO_POINTER(stream_id),
                                wmem_compare_uint);
    }

    /* Map: first Stream ID for each UDP payload */
    quic_follow_stream *stream;
    if (!quic_info->streams_map) {
        quic_info->streams_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    }
    stream = wmem_map_lookup(quic_info->streams_map, GUINT_TO_POINTER(pinfo->num));
    if (!stream) {
        stream = wmem_new0(wmem_file_scope(), quic_follow_stream);
        stream->num = pinfo->num;
        stream->stream_id = stream_id;
        wmem_map_insert(quic_info->streams_map, GUINT_TO_POINTER(stream->num), stream);
    }
}

static quic_info_data_t *
get_conn_by_number(unsigned conn_number)
{
    quic_info_data_t *conn;
    wmem_list_frame_t *elem;

    elem = wmem_list_head(quic_connections);
    while (elem) {
        conn = (quic_info_data_t *)wmem_list_frame_data(elem);
        if (conn->number == conn_number)
            return conn;
        elem = wmem_list_frame_next(elem);
    }
    return NULL;
}

bool
quic_get_stream_id_le(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out)
{
    quic_info_data_t *quic_info;
    wmem_list_frame_t *curr_entry;
    unsigned prev_stream_id;

    quic_info = get_conn_by_number(streamid);
    if (!quic_info) {
        return false;
    }
    if (!quic_info->streams_list) {
        return false;
    }

    prev_stream_id = UINT32_MAX;
    curr_entry = wmem_list_head(quic_info->streams_list);
    while (curr_entry) {
        if (GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)) > sub_stream_id &&
            prev_stream_id != UINT32_MAX) {
            *sub_stream_id_out = (unsigned)prev_stream_id;
            return true;
        }
        prev_stream_id = GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry));
        curr_entry = wmem_list_frame_next(curr_entry);
    }

    if (prev_stream_id != UINT32_MAX) {
        *sub_stream_id_out = prev_stream_id;
        return true;
    }

    return false;
}

bool
quic_get_stream_id_ge(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out)
{
    quic_info_data_t *quic_info;
    wmem_list_frame_t *curr_entry;

    quic_info = get_conn_by_number(streamid);
    if (!quic_info) {
        return false;
    }
    if (!quic_info->streams_list) {
        return false;
    }

    curr_entry = wmem_list_head(quic_info->streams_list);
    while (curr_entry) {
        if (GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)) >= sub_stream_id) {
            /* StreamIDs are 64 bits long in QUIC, but "Follow Stream" generic code uses unsigned variables */
            *sub_stream_id_out = GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry));
            return true;
        }
        curr_entry = wmem_list_frame_next(curr_entry);
    }

    return false;
}

static bool
quic_get_sub_stream_id(unsigned streamid, unsigned sub_stream_id, bool le, unsigned *sub_stream_id_out)
{
    if (le) {
        return quic_get_stream_id_le(streamid, sub_stream_id, sub_stream_id_out);
    } else {
        return quic_get_stream_id_ge(streamid, sub_stream_id, sub_stream_id_out);
    }
}

static char *
quic_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo, unsigned *stream, unsigned *sub_stream)
{
    quic_datagram *dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);

    if (!dgram_info || !dgram_info->conn) {
        return NULL;
    }

    quic_info_data_t *conn = dgram_info->conn;

    /* First Stream ID in the selected packet */
    quic_follow_stream *s;
    if (conn->streams_map) {
        s = wmem_map_lookup(conn->streams_map, GUINT_TO_POINTER(pinfo->num));
        if (s) {
            *stream = conn->number;
            *sub_stream = (unsigned)s->stream_id;
            return ws_strdup_printf("quic.connection.number eq %u and quic.stream.stream_id eq %u", conn->number, *sub_stream);
        }
    }

    return NULL;
}

static char *
quic_follow_index_filter(unsigned stream, unsigned sub_stream)
{
    return ws_strdup_printf("quic.connection.number eq %u and quic.stream.stream_id eq %u", stream, sub_stream);
}

static char *
quic_follow_address_filter(address *src_addr _U_, address *dst_addr _U_, int src_port _U_, int dst_port _U_)
{
    // This appears to be solely used for tshark. Let's not support matching by
    // IP addresses and UDP ports for now since that fails after connection
    // migration. If necessary, use udp_follow_address_filter.
    return NULL;
}

static tap_packet_status
follow_quic_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    follow_record_t *follow_record;
    follow_info_t *follow_info = (follow_info_t *)tapdata;
    const quic_follow_tap_data_t *follow_data = (const quic_follow_tap_data_t *)data;

    if (follow_info->substream_id != SUBSTREAM_UNUSED &&
        follow_info->substream_id != follow_data->stream_id) {
        return TAP_PACKET_DONT_REDRAW;
    }

    follow_record = g_new(follow_record_t, 1);

    // XXX: Ideally, we should also deal with stream retransmission
    // and out of order packets in a similar manner to the TCP dissector,
    // using the offset, plus ACKs and other information.
    follow_record->data = g_byte_array_sized_new(tvb_captured_length(follow_data->tvb));
    follow_record->data = g_byte_array_append(follow_record->data, tvb_get_ptr(follow_data->tvb, 0, -1), tvb_captured_length(follow_data->tvb));
    follow_record->packet_num = pinfo->fd->num;
    follow_record->abs_ts = pinfo->fd->abs_ts;

    /* This sets the address and port information the first time this
     * stream is tapped. It will no longer be true after migration, but
     * as it seems it's only used for display, using the initial values
     * is the best we can do.
     */

    if (follow_data->from_server) {
        follow_record->is_server = true;
        if (follow_info->client_port == 0) {
            follow_info->server_port = pinfo->srcport;
            copy_address(&follow_info->server_ip, &pinfo->src);
            follow_info->client_port = pinfo->destport;
            copy_address(&follow_info->client_ip, &pinfo->dst);
        }
    } else {
        follow_record->is_server = false;
        if (follow_info->client_port == 0) {
            follow_info->client_port = pinfo->srcport;
            copy_address(&follow_info->client_ip, &pinfo->src);
            follow_info->server_port = pinfo->destport;
            copy_address(&follow_info->server_ip, &pinfo->dst);
        }
    }

    follow_info->bytes_written[follow_record->is_server] += follow_record->data->len;

    follow_info->payload = g_list_prepend(follow_info->payload, follow_record);
    return TAP_PACKET_DONT_REDRAW;
}

uint32_t get_quic_connections_count(void)
{
    return quic_connections_count;
}
/* Follow QUIC Stream functionality }}} */

void
proto_register_quic(void)
{
    expert_module_t *expert_quic;
    module_t *quic_module;

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
            FT_UINT8, BASE_DEC, VALS(quic_v1_long_packet_type_vals), 0x30,
            "Long Header Packet Type", HFILL }
        },
        { &hf_quic_long_packet_type_v2,
          { "Packet Type", "quic.long.packet_type_v2",
            FT_UINT8, BASE_DEC, VALS(quic_v2_long_packet_type_vals), 0x30,
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
            FT_UINT32, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_version_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_quic_supported_version,
          { "Supported Version", "quic.supported_version",
            FT_UINT32, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_version_vals), 0x0,
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

        /* multipath */
       { &hf_quic_mp_nci_path_identifier,
          { "Path identifier", "quic.mp_nci_path_identifier",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_rc_path_identifier,
          { "Path identifier", "quic.mp_rc_path_identifier",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_ack_path_identifier,
          { "Path Identifier", "quic.mp_ack_path_identifier",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_pa_path_identifier,
          { "Path Identifier", "quic.mp_pa_path_identifier",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_ps_path_identifier,
          { "Path Identifier", "quic.mp_ps_path_identifier",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_ps_path_status_sequence_number,
          { "Path Status Sequence Number", "quic.mp_ps_path_status_sequence_number",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_ps_path_status,
          { "Path Status", "quic.mp_ps_path_status",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(quic_mp_path_status), 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_maximum_paths,
          { "Maximum Paths", "quic.mp_maximum_paths",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_quic_mp_maximum_path_identifier,
          { "Maximum Path identifier", "quic.mp_maximum_path_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_short_reserved,
          { "Reserved", "quic.short.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x18,
            "Reserved bits (protected using header protection)", HFILL }
        },
        { &hf_quic_q_bit,
          { "Square Signal Bit (Q)", "quic.q_bit",
            FT_BOOLEAN, 8, NULL, 0x10,
            "Square Signal Bit (used to measure and locate the source of packet loss)", HFILL }
        },
        { &hf_quic_l_bit,
          { "Loss Event Bit (L)", "quic.l_bit",
            FT_BOOLEAN, 8, NULL, 0x08,
            "Loss Event Bit (used to measure and locate the source of packet loss)",  HFILL }
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
        { &hf_quic_stream_initiator,
          { "Stream initiator", "quic.stream.initiator",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(quic_frame_id_initiator), FTFLAGS_STREAM_INITIATOR,
            NULL, HFILL }
        },
        { &hf_quic_stream_direction,
          { "Stream direction", "quic.stream.direction",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(quic_frame_id_direction), FTFLAGS_STREAM_DIRECTION,
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
            { "Stateless Reset Token", "quic.nci.stateless_reset_token",
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
              "Specifies the length of the datagram data in bytes", HFILL }
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
              "Sequence number assigned to the ACK_FREQUENCY frame by the sender to allow receivers to ignore obsolete frames", HFILL }
        },
        { &hf_quic_af_ack_eliciting_threshold,
            { "Ack-Eliciting Threshold", "quic.af.ack_eliciting_threshold",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The maximum number of ack-eliciting packets the recipient of this frame can receive without sending an acknowledgment", HFILL }
        },
        { &hf_quic_af_request_max_ack_delay,
            { "Request Max Ack Delay", "quic.af.request_max_ack_delay",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The value to which the endpoint requests the peer update its max_ack_delay", HFILL }
        },
        { &hf_quic_af_reordering_threshold,
            { "Reordering Threshold", "quic.af.reordering_threshold",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The value that indicates the maximum packet reordering before eliciting an immediate ACK", HFILL }
        },
        //{ &hf_quic_af_ignore_order,
        //    { "Ignore Order", "quic.af.ignore_order",
        //      FT_BOOLEAN, 8, NULL, 0x02,
        //      "This field is set to true by an endpoint that does not wish to receive an immediate acknowledgement when the peer receives a packet out of order", HFILL }
        //},
        //{ &hf_quic_af_ignore_ce,
        //    { "Ignore CE", "quic.af.ignore_ce",
        //      FT_BOOLEAN, 8, NULL, 0x01,
        //      "This field is set to true by an endpoint that does not wish to receive an immediate acknowledgement when the peer receives CE-marked packets", HFILL }
        //},

        /* TIME STAMP */
        { &hf_quic_ts,
            { "Time Stamp", "quic.ts",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* STATELESS RESET */
        { &hf_quic_unpredictable_bits,
            { "Unpredictable Bits", "quic.unpredictable_bits",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Bytes indistinguishable from random",
              HFILL }
        },
        { &hf_quic_stateless_reset_token,
            { "Stateless Reset Token", "quic.stateless_reset_token",
              FT_BYTES, BASE_NONE, NULL, 0x0,
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
            NULL, HFILL }
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
        { &hf_quic_crypto_fragment_count,
          { "Fragment count", "quic.crypto.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_crypto_fragment,
          { "QUIC CRYPTO Data Fragment", "quic.crypto.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_crypto_fragments,
          { "Reassembled QUIC CRYPTO Data Fragments", "quic.crypto.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "QUIC STREAM Data Fragments", HFILL }
        },
        { &hf_quic_crypto_reassembled_in,
          { "Reassembled PDU in frame", "quic.crypto.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this fragment is reassembled in this frame", HFILL }
        },
    };

    static int *ett[] = {
        &ett_quic,
        &ett_quic_af,
        &ett_quic_short_header,
        &ett_quic_connection_info,
        &ett_quic_ft,
        &ett_quic_ftflags,
        &ett_quic_ftid,
        &ett_quic_fragments,
        &ett_quic_fragment,
        &ett_quic_crypto_fragments,
        &ett_quic_crypto_fragment,
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
        { &ei_quic_coalesced_padding_data,
          { "quic.coalesced_padding_data", PI_PROTOCOL, PI_NOTE,
            "Coalesced Padding Data", EXPFILL }
        },
        { &ei_quic_retransmission,
          { "quic.retransmission", PI_SEQUENCE, PI_NOTE,
            "This QUIC frame has a reused stream offset (retransmission?)", EXPFILL }
        },
        { &ei_quic_overlap,
          { "quic.overlap", PI_SEQUENCE, PI_NOTE,
            "This QUIC frame overlaps a previous frame in the stream", EXPFILL }
        },
        { &ei_quic_data_after_forcing_vn,
          { "quic.data_after_forcing_vn", PI_PROTOCOL, PI_NOTE,
            "Unexpected data on a Forcing Version Negotiation packet", EXPFILL }
        },
    };

    proto_quic = proto_register_protocol("QUIC IETF", "QUIC", "quic");

    proto_register_field_array(proto_quic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_quic = expert_register_protocol(proto_quic);
    expert_register_field_array(expert_quic, ei, array_length(ei));

    quic_module = prefs_register_protocol(proto_quic, NULL);
    prefs_register_bool_preference(quic_module, "reassemble_crypto_out_of_order",
        "Reassemble out-of-order CRYPTO frames",
        "Whether out-of-order CRYPTO frames should be buffered and reordered before "
        "passing them to the TLS handshake dissector.",
        &quic_crypto_out_of_order);

    prefs_register_uint_preference(quic_module, "gso_heur_min_dcid_len",
        "Search for coalesced short header packets at DCID length",
        "Heuristically search for coalesced QUIC packets with a short header "
        "(e.g., when Generic Segmentation Offload (GSO) or similar is used), "
        "if the DCID is at least this many bytes long (0 to disable). ",
        10, &quic_gso_heur_dcid_len);

    quic_handle = register_dissector("quic", dissect_quic, proto_quic);

    register_init_routine(quic_init);
    register_cleanup_routine(quic_cleanup);

    register_follow_stream(proto_quic, "quic_follow", quic_follow_conv_filter, quic_follow_index_filter, quic_follow_address_filter,
                           udp_port_to_display, follow_quic_tap_listener, get_quic_connections_count,
                           quic_get_sub_stream_id);

    reassembly_table_register(&quic_reassembly_table,
                              &quic_reassembly_table_functions);

    // TODO do we need custom reassembly functions that use the QUIC Connection
    // ID instead of address and port numbers here? It seems less likely that
    // something will change the address or port than with STREAM frames.
    reassembly_table_register(&quic_crypto_reassembly_table,
                              &tcp_reassembly_table_functions);

    /*
     * Application protocol. QUIC with TLS uses ALPN.
     * https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-7
     * This could in theory be an arbitrary octet string with embedded NUL
     * bytes, but in practice these do not exist yet.
     */
    quic_proto_dissector_table = register_dissector_table("quic.proto", "QUIC Protocol", proto_quic, FT_STRING, STRING_CASE_SENSITIVE);

    quic_follow_tap = register_tap("quic_follow");
}

void
proto_reg_handoff_quic(void)
{
    tls13_handshake_handle = find_dissector("tls13-handshake");
    dissector_add_uint_with_preference("udp.port", 0, quic_handle);
    heur_dissector_add("udp", dissect_quic_heur, "QUIC", "quic", proto_quic, HEURISTIC_ENABLE);
}

bool
quic_conn_data_get_conn_client_dcid_initial(struct _packet_info *pinfo, quic_cid_t *dcid)
{
    if (pinfo == NULL || dcid == NULL) {
        return false;
    }

    quic_info_data_t * conn = quic_connection_from_conv(pinfo);
    if (conn == NULL) {
        return false;
    }

    dcid->len = conn->client_dcid_initial.len;
    memset(dcid->cid, 0, QUIC_MAX_CID_LENGTH);
    memcpy(dcid->cid, conn->client_dcid_initial.cid, dcid->len);

    return true;
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
