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
 * https://tools.ietf.org/html/draft-ietf-quic-transport-15
 * https://tools.ietf.org/html/draft-ietf-quic-tls-15
 * https://tools.ietf.org/html/draft-ietf-quic-invariants-02
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include "packet-tls-utils.h"
#include "packet-tls.h"
#include <epan/prefs.h>
#include <wsutil/pint.h>
#include "packet-gquic.h"

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
/* Whether to provide support for authentication in addition to decryption. */
#define HAVE_LIBGCRYPT_AEAD
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
/* Whether ChaCh20 PNE can be supported. */
#define HAVE_LIBGCRYPT_CHACHA20
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
static int hf_quic_token_length = -1;
static int hf_quic_token = -1;
static int hf_quic_length = -1;
static int hf_quic_packet_number = -1;
static int hf_quic_packet_number_full = -1;
static int hf_quic_version = -1;
static int hf_quic_supported_version = -1;
static int hf_quic_vn_unused = -1;
static int hf_quic_short_kp_flag = -1;
static int hf_quic_short_reserved = -1;
static int hf_quic_payload = -1;
static int hf_quic_protected_payload = -1;
static int hf_quic_remaining_payload = -1;
static int hf_quic_odcil_draft13 = -1;
static int hf_quic_odcil = -1;
static int hf_quic_odcid = -1;
static int hf_quic_retry_token = -1;

static int hf_quic_frame = -1;
static int hf_quic_frame_type = -1;
static int hf_quic_frame_type_draft14 = -1;
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
static int hf_quic_frame_type_rsts_stream_id = -1;
static int hf_quic_frame_type_rsts_application_error_code = -1;
static int hf_quic_frame_type_rsts_final_offset = -1;
static int hf_quic_frame_type_cc_error_code = -1;
static int hf_quic_frame_type_cc_error_code_tls_alert = -1;
static int hf_quic_frame_type_cc_frame_type = -1;
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
static int hf_quic_frame_type_crypto_offset = -1;
static int hf_quic_frame_type_crypto_length = -1;
static int hf_quic_frame_type_crypto_crypto_data = -1;
static int hf_quic_frame_type_nt_length = -1;
static int hf_quic_frame_type_nt_token = -1;
static int hf_quic_frame_type_ae_largest_acknowledged = -1;
static int hf_quic_frame_type_ae_ack_delay = -1;
static int hf_quic_frame_type_ae_ect0_count = -1;
static int hf_quic_frame_type_ae_ect1_count = -1;
static int hf_quic_frame_type_ae_ecn_ce_count = -1;
static int hf_quic_frame_type_ae_ack_block_count = -1;
static int hf_quic_frame_type_ae_fab = -1;
static int hf_quic_frame_type_ae_gap = -1;
static int hf_quic_frame_type_ae_ack_block = -1;
static int hf_quic_frame_type_rci_sequence = -1;

static expert_field ei_quic_connection_unknown = EI_INIT;
static expert_field ei_quic_ft_unknown = EI_INIT;
static expert_field ei_quic_decryption_failed = EI_INIT;
static expert_field ei_quic_protocol_violation = EI_INIT;

static gint ett_quic = -1;
static gint ett_quic_connection_info = -1;
static gint ett_quic_ft = -1;
static gint ett_quic_ftflags = -1;

static dissector_handle_t quic_handle;
static dissector_handle_t tls13_handshake_handle;

/*
 * PROTECTED PAYLOAD DECRYPTION (done in first pass)
 *
 * Long packet types always use a single cipher depending on packet type.
 * Short packet types always use 1-RTT secrets for packet protection (pp).
 * TODO 0-RTT decryption requires another (client) cipher.
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
 * to-do list:
 * DONE key update via KEY_PHASE bit (untested)
 * TODO 0-RTT decryption
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

/** QUIC decryption context. */
typedef struct quic_cipher {
    gcry_cipher_hd_t    pn_cipher;  /* Packet number protection cipher. */
    gcry_cipher_hd_t    pp_cipher;  /* Packet protection cipher. */
    guint8              pp_iv[TLS13_AEAD_NONCE_LENGTH];
} quic_cipher;

/**
 * Packet protection state for an endpoint.
 */
typedef struct quic_pp_state {
    guint8         *next_secret;    /**< Next application traffic secret. */
    quic_cipher     cipher[2];      /**< Cipher for KEY_PHASE 0/1 */
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
    int             hash_algo;      /**< Libgcrypt hash algorithm for key derivation. */
    int             cipher_algo;    /**< Cipher algorithm for packet number and packet encryption. */
    int             cipher_mode;    /**< Cipher mode for packet encryption. */
    quic_cipher     client_initial_cipher;
    quic_cipher     server_initial_cipher;
    quic_cipher     client_handshake_cipher;
    quic_cipher     server_handshake_cipher;
    quic_pp_state_t client_pp;
    quic_pp_state_t server_pp;
    guint64         max_client_pkn;
    guint64         max_server_pkn;
    quic_cid_item_t client_cids;    /**< SCID of client from first Initial Packet. */
    quic_cid_item_t server_cids;    /**< SCID of server from first Retry/Handshake. */
    quic_cid_t      client_dcid_initial;    /**< DCID from Initial Packet. */
} quic_info_data_t;

/** Per-packet information about QUIC, populated on the first pass. */
struct quic_packet_info {
    struct quic_packet_info *next;
    guint64                 packet_number;  /**< Reconstructed full packet number. */
    quic_decrypt_result_t   decryption;
    guint8                  pkn_len;        /**< Length of PKN (1/2/4) or unknown (0). */
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
    return 0;
}
static inline gboolean is_quic_draft_max(guint32 version, guint8 max_version) {
    guint8 draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

static inline guint8 is_gquic_version(guint32 version) {
    return version == 0x51303434; /* Q044 is the first release to use IETF QUIC (draft-12) packet header */
}

const value_string quic_version_vals[] = {
    { 0x00000000, "Version Negotiation" },
    { 0x51303434, "Google Q044" },
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
    { 0, NULL }
};

static const value_string quic_short_long_header_vals[] = {
    { 0, "Short Header" },
    { 1, "Long Header" },
    { 0, NULL }
};

#define SH_KP       0x40    /* since draft -11 */

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
#define FT_ACK_OLD          0x0d /* Remove in draft 15, replaced by 0x1a */
#define FT_RETIRE_CONNECTION_ID 0x0d
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
#define FT_CRYPTO           0x18
#define FT_NEW_TOKEN        0x19 /* Add in draft 13 */
#define FT_ACK              0x1a
#define FT_ACK_ECN          0x1b
#define FT_ACK_ECN_OLD      0x1a /* Add in draft 14 */
#define FT_ACK_ECN_OLD_OLD  0x20 /* Remove in draft 14 */

static const range_string quic_frame_type_draft14_vals[] = {
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
    { 0x18, 0x18,   "CRYPTO" },
    { 0x19, 0x19,   "NEW_TOKEN" },
    { 0x1a, 0x1a,   "ACK_ECN" },
    { 0x20, 0x20,   "ACK_ECN" },
    { 0,    0,        NULL },
};

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
    { 0x0d, 0x0d,   "RETIRE_CONNECTION_ID" },
    { 0x0e, 0x0e,   "PATH_CHALLENGE" },
    { 0x0f, 0x0f,   "PATH_RESPONSE" },
    { 0x10, 0x17,   "STREAM" },
    { 0x18, 0x18,   "CRYPTO" },
    { 0x19, 0x19,   "NEW_TOKEN" },
    { 0x1a, 0x1a,   "ACK" },
    { 0x1b, 0x1b,   "ACK_ECN" },
    { 0,    0,        NULL },
};


/* >= draft-08 */
#define FTFLAGS_STREAM_FIN 0x01
#define FTFLAGS_STREAM_LEN 0x02
#define FTFLAGS_STREAM_OFF 0x04

static const range_string quic_transport_error_code_vals[] = {
    { 0x0000, 0x0000, "NO_ERROR" },
    { 0x0001, 0x0001, "INTERNAL_ERROR" },
    { 0x0002, 0x0002, "SERVER_BUSY" },
    { 0x0003, 0x0003, "FLOW_CONTROL_ERROR" },
    { 0x0004, 0x0004, "STREAM_ID_ERROR" },
    { 0x0005, 0x0005, "STREAM_STATE_ERROR" },
    { 0x0006, 0x0006, "FINAL_OFFSET_ERROR" },
    { 0x0007, 0x0007, "FRAME_ENCODING_ERROR" },
    { 0x0008, 0x0008, "TRANSPORT_PARAMETER_ERROR" },
    { 0x0009, 0x0009, "VERSION_NEGOTIATION_ERROR" },
    { 0x000A, 0x000A, "PROTOCOL_VIOLATION" },
    { 0x000C, 0x000C, "INVALID_MIGRATION" },
    { 0x0100, 0x01FF, "CRYPTO_ERROR" },
    { 0, 0, NULL }
};

static const value_string quic_application_error_code_vals[] = {
    { 0x0000, "STOPPING" },
    { 0, NULL }
};

static void
quic_cipher_reset(quic_cipher *cipher)
{
    gcry_cipher_close(cipher->pn_cipher);
    gcry_cipher_close(cipher->pp_cipher);
    memset(cipher, 0, sizeof(*cipher));
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

#ifdef HAVE_LIBGCRYPT_AEAD
static guint
quic_decrypt_packet_number(tvbuff_t *tvb, guint offset, quic_cipher *cipher,
                           int pn_cipher_algo, guint64 *pkn)
{
    guint32 pkt_pkn;
    guint   pkn_len;
    guint8 *pkn_bytes = (guint8 *)&pkt_pkn;
    gcry_cipher_hd_t h;
    if (!cipher || !(h = cipher->pn_cipher)) {
        // need to know the cipher.
        return 0;
    }

    tvb_memcpy(tvb, pkn_bytes, offset, sizeof(pkt_pkn));

    // Both AES-CTR and ChaCha20 use 16 octets as sample length.
    // https://tools.ietf.org/html/draft-ietf-quic-tls-13#section-5.3
    const guint sample_length = 16;
    guint sample_offset = offset + 4;
    guint8 sample[16];
    if (sample_offset + sample_length > tvb_reported_length(tvb)) {
        sample_offset = tvb_reported_length(tvb) - sample_length;
    }
    tvb_memcpy(tvb, sample, sample_offset, sample_length);

    switch (pn_cipher_algo) {
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES256:
        if (gcry_cipher_setctr(h, sample, sample_length)) {
            return 0;
        }
        break;
#ifdef HAVE_LIBGCRYPT_CHACHA20
    case GCRY_CIPHER_CHACHA20:
        /* If Gcrypt receives a 16 byte IV, it will assume the buffer to be
         * counter || nonce (in little endian), as desired. */
        if (gcry_cipher_setiv(h, sample, 16)) {
            return 0;
        }
        break;
#endif /* HAVE_LIBGCRYPT_CHACHA20 */
    default:
        return 0;
    }

    /* in-place decrypt. */
    if (gcry_cipher_decrypt(h, pkn_bytes, 4, NULL, 0)) {
        return 0;
    }

    // | First octet pattern | Encoded Length | Bits Present |
    // | 0b0xxxxxxx          | 1 octet        | 7            |
    // | 0b10xxxxxx          | 2              | 14           |
    // | 0b11xxxxxx          | 4              | 30           |
    switch (pkn_bytes[0] >> 6) {
    default:
        pkn_len = 1;
        break;
    case 2:
        pkn_len = 2;
        pkn_bytes[0] &= 0x3f;
        break;
    case 3:
        pkn_len = 4;
        pkn_bytes[0] &= 0x3f;
        break;
    }
    *pkn = g_htonl(pkt_pkn) >> (8 * (4 - pkn_len));
    return pkn_len;
}

static void
quic_encode_packet_number(guint8 *output, guint32 pkn, guint pkn_len)
{
    switch (pkn_len) {
    default:
        output[0] = (guint8)pkn;
        break;
    case 2:
        phton16(output, (guint16)pkn);
        output[0] |= 0x80;
        break;
    case 4:
        phton32(output, pkn);
        output[0] |= 0xc0;
        break;
    }
}
#else /* !HAVE_LIBGCRYPT_AEAD */
static inline guint
quic_decrypt_packet_number(tvbuff_t *tvb _U_, guint offset _U_, quic_cipher *cipher _U_,
                           int pn_cipher_algo _U_, guint64 *pkn _U_)
{
    return 0;
}
#endif /* !HAVE_LIBGCRYPT_AEAD */

/**
 * Calculate the full packet number and store it for later use.
 */
static guint32
dissect_quic_packet_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
                           quic_info_data_t *quic_info, quic_packet_info_t *quic_packet,
                           gboolean from_server,
                           quic_cipher *cipher, int pn_cipher_algo, guint64 *pkn_out)
{
    proto_item *ti;
    guint       pkn_len;
    guint64     pkn;

    /* Try to decrypt on the first pass, reuse results on the second pass. */
    if (!PINFO_FD_VISITED(pinfo)) {
        pkn_len = quic_decrypt_packet_number(tvb, offset, cipher, pn_cipher_algo, &pkn);
        quic_packet->pkn_len = pkn_len;
    } else {
        pkn_len = quic_packet->pkn_len;
        pkn = quic_packet->packet_number & ((1UL << (8 * pkn_len)) - 1);
    }
    if (!pkn_len) {
        expert_add_info_format(pinfo, tree, &ei_quic_decryption_failed, "Failed to decrypt packet number");
        return 0;
    }

    // TODO separate field for encrypted and decrypted PKN?
    proto_tree_add_uint64(tree, hf_quic_packet_number, tvb, offset, pkn_len, pkn);

    if (!quic_info) {
        // if not part of a connection, the full PKN cannot be reconstructed.
        *pkn_out = pkn;
        return pkn_len;
    }

    /* Sequential first pass, try to reconstruct full packet number. */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (from_server) {
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

    *pkn_out = pkn;
    return pkn_len;
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

static void
quic_cids_insert(quic_cid_t *cid, quic_info_data_t *conn, gboolean from_server)
{
    wmem_map_t *connections = from_server ? quic_server_connections : quic_client_connections;
    // Replace any previous CID key with the new one.
    wmem_map_remove(connections, cid);
    wmem_map_insert(connections, cid, conn);
    quic_cid_lengths |= (1 << cid->len);
}

static inline gboolean
quic_cids_is_known_length(const quic_cid_t *cid)
{
    return (quic_cid_lengths & (1 << cid->len)) != 0;
}

/**
 * Tries to lookup a matching connection (Connection ID is optional).
 * If connection is found, "from_server" is set accordingly.
 */
static quic_info_data_t *
quic_connection_find_dcid(packet_info *pinfo, const quic_cid_t *dcid, gboolean *from_server)
{
    /* https://tools.ietf.org/html/draft-ietf-quic-transport-13#section-6.2
     *
     * "If the packet has a Destination Connection ID corresponding to an
     * existing connection, QUIC processes that packet accordingly."
     * "If the Destination Connection ID is zero length and the packet matches
     * the address/port tuple of a connection where the host did not require
     * connection IDs, QUIC processes the packet as part of that connection."
     */
    quic_info_data_t *conn = NULL;
    gboolean check_ports = FALSE;

    if (dcid && dcid->len > 0 && quic_cids_is_known_length(dcid)) {
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
        // Both the client and server can send Initial (since draft -13).
        if (!conn && long_packet_type == QUIC_LPT_INITIAL) {
            conn = quic_connection_find_dcid(pinfo, dcid, from_server);
        }
    } else {
        conn = quic_connection_find_dcid(pinfo, dcid, from_server);
    }

    if (!is_long_packet && !conn) {
        // For short packets, first try to find a match based on the address.
        conn = quic_connection_find_dcid(pinfo, NULL, from_server);
        if (conn) {
            if ((*from_server && !quic_cids_has_match(&conn->server_cids, dcid)) ||
                (!*from_server && !quic_cids_has_match(&conn->client_cids, dcid))) {
                // Connection does not match packet.
                conn = NULL;
            }
        }

        // No match found so far, potentially connection migration. Length of
        // actual DCID is unknown, so just keep decrementing until found.
        while (!conn && dcid->len > 4) {
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
    if (scid->len) {
        memcpy(&conn->client_cids.data, scid, sizeof(quic_cid_t));
        quic_cids_insert(&conn->client_cids.data, conn, FALSE);
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
                *conn_p = quic_connection_create(pinfo, version, scid, dcid);
            } else if (conn->client_dcid_initial.len == 0 && dcid->len &&
                       scid->len && !quic_cids_has_match(&conn->server_cids, scid)) {
                // If this client Initial Packet responds to a Retry Packet,
                // then remember the new DCID for the new Initial cipher and
                // clear the first server CID such that the next server Initial
                // Packet can link the connection with that new SCID.
                memcpy(&conn->client_dcid_initial, dcid, sizeof(quic_cid_t));
                wmem_map_insert(quic_initial_connections, &conn->client_dcid_initial, conn);
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
                // Stateless Retry Packet: the next Initial Packet from the
                // client should start a new cryptographic handshake. Erase the
                // current "Initial DCID" such that the next client Initial
                // packet populates the new value.
                wmem_map_remove(quic_initial_connections, &conn->client_dcid_initial);
                memset(&conn->client_dcid_initial, 0, sizeof(quic_cid_t));
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


#ifdef HAVE_LIBGCRYPT_AEAD
static int
dissect_quic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, quic_info_data_t *quic_info, gboolean from_server)
{
    proto_item *ti_ft, *ti_ftflags, *ti;
    proto_tree *ft_tree, *ftflags_tree;
    guint32 frame_type;
    guint   orig_offset = offset;

    ti_ft = proto_tree_add_item(quic_tree, hf_quic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_quic_ft);

    if (is_quic_draft_max(quic_info->version, 14)) {
        ti_ftflags = proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_draft14, tvb, offset, 1, ENC_NA, &frame_type);
        proto_item_set_text(ti_ft, "%s", rval_to_str(frame_type, quic_frame_type_draft14_vals, "Unknown"));
    } else {
        ti_ftflags = proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type, tvb, offset, 1, ENC_NA, &frame_type);
        proto_item_set_text(ti_ft, "%s", rval_to_str(frame_type, quic_frame_type_vals, "Unknown"));
    }
    offset += 1;

    switch(frame_type){
        case FT_PADDING:{
            guint32 pad_len;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", PADDING");

            /* A padding frame consists of a single zero octet, but for brevity
             * sake let's combine multiple zeroes into a single field. */
            pad_len = 1 + tvb_skip_guint8(tvb, offset, tvb_reported_length_remaining(tvb, offset), '\0') - offset;
            ti = proto_tree_add_uint(ft_tree, hf_quic_frame_type_padding_length, tvb, offset, 0, pad_len);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(ti_ft, " Length: %u", pad_len);
            offset += pad_len - 1;
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

            proto_item_append_text(ti_ft, " Stream ID: %" G_GINT64_MODIFIER "u, Error code: %s", stream_id, val_to_str(error_code, quic_application_error_code_vals, "0x%04x"));
        }
        break;
        case FT_CONNECTION_CLOSE:{
            guint32 len_reasonphrase, len_frametype, error_code;
            guint64 len_reason = 0;
            const char *tls_alert = NULL;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", CC");

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_cc_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            if ((error_code & 0xff00) == 0x0100) {  // CRYPTO_ERROR
                tls_alert = try_val_to_str(error_code & 0xff, ssl_31_alert_description);
                if (tls_alert) {
                    proto_tree_add_item(ft_tree, hf_quic_frame_type_cc_error_code_tls_alert, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
                }
            }
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_cc_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_frametype);
            offset += len_frametype;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_cc_reason_phrase_length, tvb, offset, -1, ENC_VARINT_QUIC, &len_reason, &len_reasonphrase);
            offset += len_reasonphrase;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_cc_reason_phrase, tvb, offset, (guint32)len_reason, ENC_ASCII|ENC_NA);
            offset += (guint32)len_reason;

            proto_item_append_text(ti_ft, " Error code: %s", rval_to_str(error_code, quic_transport_error_code_vals, "Unknown (%d)"));
            if (tls_alert) {
                proto_item_append_text(ti_ft, " (%s)", tls_alert);
            }
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

            proto_item_append_text(ti_ft, " Error code: %s", val_to_str(error_code, quic_application_error_code_vals, "0x%04x"));
        }
        break;
        case FT_MAX_DATA:{
            guint32 len_maximumdata;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_md_maximum_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumdata);
            offset += len_maximumdata;
        }
        break;
        case FT_MAX_STREAM_DATA:{
            guint32 len_streamid, len_maximumstreamdata;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MSD");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msd_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msd_maximum_stream_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumstreamdata);
            offset += len_maximumstreamdata;
        }
        break;
        case FT_MAX_STREAM_ID:{
            guint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", MSI");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msi_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;
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
        }
        break;
        case FT_STREAM_BLOCKED:{
            guint32 len_streamid, len_offset;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sb_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sb_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;
        }
        break;
        case FT_STREAM_ID_BLOCKED:{
            guint32 len_streamid;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SIB");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sib_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;
        }
        break;
        case FT_NEW_CONNECTION_ID:{
            guint32 len_sequence;
            guint32 nci_length;
            gboolean valid_cid = FALSE;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", NCI");

            if (is_quic_draft_max(quic_info->version, 14)) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_nci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
                offset += len_sequence;
            }
            ti = proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_nci_connection_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &nci_length);
            offset++;

            valid_cid = nci_length >= 4 && nci_length <= 18;
            if (!valid_cid) {
                expert_add_info_format(pinfo, ti, &ei_quic_protocol_violation,
                            "Connection ID Length must be between 4 and 18 bytes");
            }

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nci_connection_id, tvb, offset, nci_length, ENC_NA);
            if (valid_cid && quic_info) {
                quic_cid_t cid = {.len=0};
                tvb_memcpy(tvb, cid.cid, offset, nci_length);
                cid.len = nci_length;
                quic_connection_add_cid(quic_info, &cid, from_server);
            }
            offset += nci_length;

            if (!is_quic_draft_max(quic_info->version, 14)) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_nci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
                offset += len_sequence;
            }

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nci_stateless_reset_token, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        break;
        case FT_STOP_SENDING:{
            guint32 len_streamid, error_code;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", SS");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ss_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_ss_application_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_item_append_text(ti_ft, " Error code: 0x%04x", error_code);
        }
        break;
        case FT_RETIRE_CONNECTION_ID:{
            if (is_quic_draft_max(quic_info->version, 14)) { /* FT_ACK_OLD */
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
            } else {
                guint32 len_sequence;
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_rci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
                offset += len_sequence;
            }
        }
        break;
        case FT_ACK:{
            if (is_quic_draft_max(quic_info->version, 14)) { /* FT_ACK_ECN_OLD */
                guint64 ack_block_count;
                guint32 lenvar;

                col_append_fstr(pinfo->cinfo, COL_INFO, ", AE");

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_largest_acknowledged, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ect0_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ect1_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ecn_ce_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ack_block_count, tvb, offset, -1, ENC_VARINT_QUIC, &ack_block_count, &lenvar);
                offset += lenvar;

                /* ACK Block */
                /* First ACK Block Length */
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_fab, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                /* Repeated "Ack Block Count" */
                while(ack_block_count){

                    /* Gap To Next Block */
                    proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_gap, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                    offset += lenvar;

                    proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ack_block, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                    offset += lenvar;

                    ack_block_count--;
                }
            } else {
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

            offset -= 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", STREAM");

            ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_quic_ftflags);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_fin, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_len, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_off, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &lenvar);
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
            offset += (int)length;
        }
        break;
        case FT_CRYPTO: {
            guint64 crypto_offset, crypto_length;
            guint32 lenvar;
            col_append_fstr(pinfo->cinfo, COL_INFO, ", CRYPTO");
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_crypto_offset, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_offset, &lenvar);
            offset += lenvar;
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_crypto_length, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_length, &lenvar);
            offset += lenvar;
            proto_tree_add_item(ft_tree, hf_quic_frame_type_crypto_crypto_data, tvb, offset, (guint32)crypto_length, ENC_NA);
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
                call_dissector(tls13_handshake_handle, next_tvb, pinfo, ft_tree);
                col_set_writable(pinfo->cinfo, -1, TRUE);
            }
            offset += (guint32)crypto_length;
        }
        break;
        case FT_NEW_TOKEN: {
            guint64 token_length;
            guint32 lenvar;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", NT");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_nt_length, tvb, offset, -1, ENC_VARINT_QUIC, &token_length, &lenvar);
            offset += lenvar;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nt_token, tvb, offset, (guint32)token_length, ENC_NA);
            offset += (guint32)token_length;
        }
        break;
        case FT_ACK_ECN:{
            guint64 ack_block_count;
            guint32 lenvar;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", AE");

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_largest_acknowledged, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ack_block_count, tvb, offset, -1, ENC_VARINT_QUIC, &ack_block_count, &lenvar);
            offset += lenvar;

            /* ACK Block */
            /* First ACK Block Length */
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_fab, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            /* Repeated "Ack Block Count" */
            while(ack_block_count){

                /* Gap To Next Block */
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_gap, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ack_block, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                ack_block_count--;
            }

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ect0_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ect1_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ae_ecn_ce_count, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;
        }
        break;
        default:
            expert_add_info_format(pinfo, ti_ft, &ei_quic_ft_unknown, "Unknown Frame Type %u", frame_type);
        break;
    }

    proto_item_set_len(ti_ft, offset - orig_offset);

    return offset;
}
#endif /* HAVE_LIBGCRYPT_AEAD */

#ifdef HAVE_LIBGCRYPT_AEAD
static gcry_error_t
qhkdf_expand(int md, const guint8 *secret, guint secret_len,
             const char *label, guint8 *out, guint out_len);

static gboolean
quic_cipher_init(guint32 version, quic_cipher *cipher, int hash_algo, guint8 key_length, guint8 *secret);


/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 * As the header points to the original buffer with an encrypted packet number,
 * the (encrypted) packet number length is also included.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-13#section-4.8
 */
static void
quic_decrypt_message(quic_cipher *cipher, tvbuff_t *head, guint header_length, guint pkn_len, guint64 packet_number, quic_decrypt_result_t *result)
{
    gcry_error_t    err;
    guint8         *header;
    guint8          nonce[TLS13_AEAD_NONCE_LENGTH];
    guint8         *buffer;
    guint8         *atag[16];
    guint           buffer_length;
    const guchar  **error = &result->error;

    DISSECTOR_ASSERT(cipher != NULL);
    DISSECTOR_ASSERT(cipher->pp_cipher != NULL);
    DISSECTOR_ASSERT(pkn_len < header_length);
    DISSECTOR_ASSERT(1 <= pkn_len && pkn_len <= 4);
    // copy header, but replace encrypted PKN by plaintext PKN.
    header = (guint8 *)tvb_memdup(wmem_packet_scope(), head, 0, header_length);
    quic_encode_packet_number(header + header_length - pkn_len, (guint32)packet_number, pkn_len);

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
    if (tls13_hkdf_expand_label(hash_algo, &secret_si, "quic ", label, out_len, &out_mem)) {
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
                            const gchar **error)
{
    /*
     * https://tools.ietf.org/html/draft-ietf-quic-tls-14#section-5.1.1
     *
     * initial_salt = 0x9c108f98520a5c5c32968e950e8a2c5fe06d6c38
     * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *
     * client_initial_secret = HKDF-Expand-Label(initial_secret,
     *                                           "client in", "", Hash.length)
     * server_initial_secret = HKDF-Expand-Label(initial_secret,
     *                                           "server in", "", Hash.length)
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
 * See https://tools.ietf.org/html/draft-ietf-quic-tls-14#section-5.3
 */
static gboolean
quic_get_pn_cipher_algo(int cipher_algo, int *pn_cipher_mode)
{
    switch (cipher_algo) {
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES256:
        *pn_cipher_mode = GCRY_CIPHER_MODE_CTR;
        return TRUE;
#ifdef HAVE_LIBGCRYPT_CHACHA20
    case GCRY_CIPHER_CHACHA20:
        *pn_cipher_mode = 0;
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
quic_cipher_prepare(guint32 version, quic_cipher *cipher, int hash_algo, int cipher_algo, int cipher_mode, guint8 *secret, const char **error)
{
    /* Clear previous state (if any). */
    quic_cipher_reset(cipher);

    int pn_cipher_mode;
    if (!quic_get_pn_cipher_algo(cipher_algo, &pn_cipher_mode)) {
        *error = "Unsupported cipher algorithm";
        return FALSE;
    }

    if (gcry_cipher_open(&cipher->pn_cipher, cipher_algo, pn_cipher_mode, 0) ||
        gcry_cipher_open(&cipher->pp_cipher, cipher_algo, cipher_mode, 0)) {
        quic_cipher_reset(cipher);
        *error = "Failed to create ciphers";
        return FALSE;
    }

    if (secret) {
        guint cipher_keylen = (guint8) gcry_cipher_get_algo_keylen(cipher_algo);
        if (!quic_cipher_init(version, cipher, hash_algo, cipher_keylen, secret)) {
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
    guint32         version = quic_info->version;

    if (!quic_derive_initial_secrets(cid, client_secret, server_secret, error)) {
        return FALSE;
    }

    /* Packet numbers are protected with AES128-CTR,
     * initial packets are protected with AEAD_AES_128_GCM. */
    if (!quic_cipher_prepare(version, &quic_info->client_initial_cipher, GCRY_MD_SHA256,
                             GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, client_secret, error) ||
        !quic_cipher_prepare(version, &quic_info->server_initial_cipher, GCRY_MD_SHA256,
                             GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, server_secret, error)) {
        return FALSE;
    }

    return TRUE;
}

static gboolean
quic_create_decoders(packet_info *pinfo, guint32 version, quic_info_data_t *quic_info, quic_cipher *cipher,
                     gboolean from_server, TLSRecordType type, const char **error)
{
    if (!quic_info->hash_algo) {
        if (!tls_get_cipher_info(pinfo, &quic_info->cipher_algo, &quic_info->cipher_mode, &quic_info->hash_algo)) {
            *error = "Unable to retrieve cipher information";
            return FALSE;
        }
    }

    guint hash_len = gcry_md_get_algo_dlen(quic_info->hash_algo);
    char *secret = (char *)wmem_alloc0(wmem_packet_scope(), hash_len);

    if (!tls13_get_quic_secret(pinfo, from_server, type, hash_len, secret)) {
        *error = "Secrets are not available";
        return FALSE;
    }

    if (!quic_cipher_prepare(version, cipher, quic_info->hash_algo,
                             quic_info->cipher_algo, quic_info->cipher_mode, secret, error)) {
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
 * Tries to obtain the QUIC application traffic secrets.
 */
static gboolean
quic_get_traffic_secret(packet_info *pinfo, int hash_algo, quic_pp_state_t *pp_state, gboolean from_client)
{
    guint hash_len = gcry_md_get_algo_dlen(hash_algo);
    char *secret = (char *)wmem_alloc0(wmem_packet_scope(), hash_len);
    if (!tls13_get_quic_secret(pinfo, !from_client, TLS_SECRET_APP, hash_len, secret)) {
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
quic_cipher_init(guint32 version _U_, quic_cipher *cipher, int hash_algo, guint8 key_length, guint8 *secret)
{
    guchar      write_key[256/8];   /* Maximum key size is for AES256 cipher. */
    guchar      pn_key[256/8];
    guint       hash_len = gcry_md_get_algo_dlen(hash_algo);

    if (key_length > sizeof(write_key)) {
        return FALSE;
    }

    if (!quic_hkdf_expand_label(hash_algo, secret, hash_len, "key", write_key, key_length) ||
        !quic_hkdf_expand_label(hash_algo, secret, hash_len, "iv", cipher->pp_iv, sizeof(cipher->pp_iv)) ||
        !quic_hkdf_expand_label(hash_algo, secret, hash_len, "pn", pn_key, key_length)) {
        return FALSE;
    }

    return gcry_cipher_setkey(cipher->pn_cipher, pn_key, key_length) == 0 &&
           gcry_cipher_setkey(cipher->pp_cipher, write_key, key_length) == 0;
}

/**
 * Updates the packet protection secret to the next one.
 */
static void
quic_update_key(int hash_algo, quic_pp_state_t *pp_state, gboolean from_client)
{
    guint hash_len = gcry_md_get_algo_dlen(hash_algo);
    qhkdf_expand(hash_algo, pp_state->next_secret, hash_len,
                 from_client ? "client 1rtt" : "server 1rtt",
                 pp_state->next_secret, hash_len);
}

/**
 * Tries to construct the appropriate cipher for the current key phase.
 * See also "PROTECTED PAYLOAD DECRYPTION" comment on top of this file.
 */
static quic_cipher *
quic_get_pp_cipher(packet_info *pinfo, gboolean key_phase, quic_info_data_t *quic_info, gboolean from_server)
{
    guint32     version = quic_info->version;
    const char *error = NULL;
    gboolean    success = FALSE;

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
        if (!tls_get_cipher_info(pinfo, &quic_info->cipher_algo, &quic_info->cipher_mode, &quic_info->hash_algo)) {
            /* No previous TLS handshake found or unsupported ciphers, fail. */
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        /* Retrieve secrets for both the client and server. */
        if (!quic_get_traffic_secret(pinfo, quic_info->hash_algo, client_pp, TRUE) ||
            !quic_get_traffic_secret(pinfo, quic_info->hash_algo, server_pp, FALSE)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }

        /* Create initial cipher handles for KEY_PHASE 0 and 1. */
        if (!quic_cipher_prepare(version, &client_pp->cipher[0], quic_info->hash_algo,
                                 quic_info->cipher_algo, quic_info->cipher_mode, client_pp->next_secret, &error) ||
            !quic_cipher_prepare(version, &server_pp->cipher[0], quic_info->hash_algo,
                                 quic_info->cipher_algo, quic_info->cipher_mode, server_pp->next_secret, &error)) {
            quic_info->skip_decryption = TRUE;
            return NULL;
        }
        quic_update_key(quic_info->hash_algo, pp_state, !from_server);
    }

    /*
     * If the key phase changed, try to decrypt the packet using the new cipher.
     * If that fails, then it is either a malicious packet or out-of-order.
     * In that case, try the previous cipher (unless it is the very first KP1).
     */
    if (key_phase != pp_state->key_phase) {
        quic_cipher new_cipher;

        memset(&new_cipher, 0, sizeof(quic_cipher));
        if (!quic_cipher_prepare(version, &new_cipher, quic_info->hash_algo,
                                 quic_info->cipher_algo, quic_info->cipher_mode, server_pp->next_secret, &error)) {
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
            quic_update_key(quic_info->hash_algo, pp_state, !from_server);

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
                     quic_cipher *cipher, guint pkn_len)
{
    quic_decrypt_result_t *decryption = &quic_packet->decryption;

    /*
     * If no decryption error has occurred yet, try decryption on the first
     * pass and store the result for later use.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (!quic_packet->decryption.error && cipher && cipher->pp_cipher) {
            quic_decrypt_message(cipher, tvb, offset, pkn_len, quic_packet->packet_number, &quic_packet->decryption);
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
#else /* !HAVE_LIBGCRYPT_AEAD */
static void
quic_process_payload(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, proto_item *ti, guint offset _U_,
                     quic_info_data_t *quic_info _U_, quic_packet_info_t *quic_packet _U_, gboolean from_server _U_,
                     quic_cipher *cipher _U_, guint pkn_len _U_)
{
    expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Libgcrypt >= 1.6.0 is required for QUIC decryption");
}
#endif /* !HAVE_LIBGCRYPT_AEAD */

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
    guint32     dcil, scil;

    version = tvb_get_ntohl(tvb, offset);

    if (version_out) {
        *version_out = version;
    }

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

    if (dcid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", cid_to_string(dcid));
    }
    if (scid->len > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", SCID=%s", cid_to_string(scid));
    }
    return offset;
}

/* Retry Packet dissection for draft -13 and newer. */
static int
dissect_quic_retry_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                          quic_datagram *dgram_info _U_, quic_packet_info_t *quic_packet)
{
    guint       offset = 0;
    guint32     version;
    guint32     len_payload_length;
    guint64     payload_length;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    guint32     odcil = 0;
    guint       retry_token_len;

    proto_tree_add_item(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    col_set_str(pinfo->cinfo, COL_INFO, "Retry");

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &version, &dcid, &scid);

    if (is_quic_draft_max(version, 13)) {
        proto_tree_add_item_ret_varint(quic_tree, hf_quic_length, tvb, offset, -1, ENC_VARINT_QUIC, &payload_length, &len_payload_length);
        offset += len_payload_length;
        // PKN is encrypted, but who cares about draft -13 anyway.
        proto_tree_add_item(quic_tree, hf_quic_packet_number, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item_ret_uint(quic_tree, hf_quic_odcil_draft13, tvb, offset, 1, ENC_NA, &odcil);
    } else {
        proto_tree_add_item_ret_uint(quic_tree, hf_quic_odcil, tvb, offset, 1, ENC_NA, &odcil);
        if (odcil) {
            odcil += 3;
        }
    }
    offset += 1;
    proto_tree_add_item(quic_tree, hf_quic_odcid, tvb, offset, odcil, ENC_NA);
    offset += odcil;
    retry_token_len = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(quic_tree, hf_quic_retry_token, tvb, offset, retry_token_len, ENC_NA);
    offset += retry_token_len;

    return offset;
}

static int
dissect_quic_long_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                         quic_datagram *dgram_info, quic_packet_info_t *quic_packet)
{
    guint offset = 0;
    guint32 long_packet_type;
    guint32 version;
    quic_cid_t  dcid = {.len=0}, scid = {.len=0};
    guint32 len_token_length;
    guint64 token_length;
    guint32 len_payload_length;
    guint64 payload_length;
    guint32 pkn_len;
    guint64 pkn;
    quic_info_data_t *conn = dgram_info->conn;
    const gboolean from_server = dgram_info->from_server;
    quic_cipher *cipher = NULL;
    proto_item *ti;

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA, &long_packet_type);
    offset += 1;
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(long_packet_type, quic_long_packet_type_vals, "Long Header"));

    offset = dissect_quic_long_header_common(tvb, pinfo, quic_tree, offset, quic_packet, &version, &dcid, &scid);

    if (conn && conn->version == 0x51303434) { /* gQUIC Q044 */
        return dissect_gquic_ietf(tvb, pinfo, quic_tree, offset, conn->version);
    }

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

#ifdef HAVE_LIBGCRYPT_AEAD
    if (conn) {
        if (long_packet_type == QUIC_LPT_INITIAL) {
            cipher = !from_server ? &conn->client_initial_cipher : &conn->server_initial_cipher;
        } else if (long_packet_type == QUIC_LPT_HANDSHAKE) {
            cipher = !from_server ? &conn->client_handshake_cipher : &conn->server_handshake_cipher;
        }
    }
    /* Build handshake cipher now for PKN (and handshake) decryption. */
    if (!PINFO_FD_VISITED(pinfo) && conn) {
        const gchar *error = NULL;
        if (long_packet_type == QUIC_LPT_INITIAL && !from_server &&
            !memcmp(&dcid, &conn->client_dcid_initial, sizeof(quic_cid_t))) {
            /* Create new decryption context based on the Client Connection
             * ID from the *very first* Client Initial packet. */
            quic_create_initial_decoders(&dcid, &error, conn);
        } else if (long_packet_type == QUIC_LPT_HANDSHAKE) {
            if (!cipher->pn_cipher) {
                quic_create_decoders(pinfo, version, conn, cipher, from_server, TLS_SECRET_HANDSHAKE, &error);
            }
        }
        if (error) {
            quic_packet->decryption.error = wmem_strdup(wmem_file_scope(), error);
        }
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */
    if (quic_packet->decryption.error) {
        expert_add_info_format(pinfo, quic_tree, &ei_quic_decryption_failed,
                               "Failed to create decryption context: %s", quic_packet->decryption.error);
        return offset;
    }

    pkn_len = dissect_quic_packet_number(tvb, pinfo, quic_tree, offset, conn, quic_packet, from_server,
                                         cipher, GCRY_CIPHER_AES128, &pkn);
    if (pkn_len == 0) {
        return offset;
    }
    offset += pkn_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" G_GINT64_MODIFIER "u", pkn);

    /* Payload */
    ti = proto_tree_add_item(quic_tree, hf_quic_payload, tvb, offset, -1, ENC_NA);

    if (conn) {
        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, from_server, cipher, pkn_len);
    }
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_quic_short_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree,
                          quic_datagram *dgram_info, quic_packet_info_t *quic_packet)
{
    guint offset = 0;
    quic_cid_t dcid = {.len=0};
    guint32 pkn_len;
    guint64 pkn;
    proto_item *ti;
    gboolean    key_phase = FALSE;
    quic_cipher *cipher = NULL;
    quic_info_data_t *conn = dgram_info->conn;
    const gboolean from_server = dgram_info->from_server;

    proto_tree_add_item_ret_boolean(quic_tree, hf_quic_short_kp_flag, tvb, offset, 1, ENC_NA, &key_phase);
    proto_tree_add_item(quic_tree, hf_quic_short_reserved, tvb, offset, 1, ENC_NA);
    if (conn) {
       dcid.len = from_server ? conn->client_cids.data.len : conn->server_cids.data.len;
    }
    offset += 1;

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Protected Payload (KP%u)", key_phase);

    /* Connection ID */
    if (dcid.len > 0) {
        proto_tree_add_item(quic_tree, hf_quic_dcid, tvb, offset, dcid.len, ENC_NA);
        tvb_memcpy(tvb, dcid.cid, offset, dcid.len);
        offset += dcid.len;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", DCID=%s", cid_to_string(&dcid));
    }

#ifdef HAVE_LIBGCRYPT_AEAD
    if (!PINFO_FD_VISITED(pinfo) && conn) {
        cipher = quic_get_pp_cipher(pinfo, key_phase, conn, from_server);
    }
#endif /* !HAVE_LIBGCRYPT_AEAD */
    if (!conn || conn->skip_decryption) {
        return offset;
    }

    /* Packet Number */
    pkn_len = dissect_quic_packet_number(tvb, pinfo, quic_tree, offset, conn, quic_packet, from_server,
                                         cipher, conn ? conn->cipher_algo : 0, &pkn);
    if (pkn_len == 0) {
        return offset;
    }
    offset += pkn_len;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" G_GINT64_MODIFIER "u", pkn);

    /* Protected Payload */
    ti = proto_tree_add_item(quic_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);

    if (conn) {
        quic_process_payload(tvb, pinfo, quic_tree, ti, offset,
                             conn, quic_packet, from_server, cipher, pkn_len);
    }
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
    guint8 long_packet_type = packet_type & 0x7f;
    // Retry and VN packets cannot be coalesced (clarified in draft -14).
    if ((packet_type & 0x80) && long_packet_type != QUIC_LPT_RETRY) {
        // long header form, check version
        guint version = tvb_get_ntohl(tvb, offset + 1);
        // If this is not a VN packet but a valid long form, extract a subset.
        // TODO check for valid QUIC versions as future versions might change the format.
        if (version != 0 && !is_gquic_version(version)) {
            guint8 cid_lengths = tvb_get_guint8(tvb, offset + 5);
            guint8 dcil = cid_lengths >> 4;
            guint8 scil = cid_lengths & 0xf;
            guint length = 6;
            if (dcil) {
                length += 3 + dcil;
            }
            if (scil) {
                length += 3 + scil;
            }
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
        *long_packet_type = packet_type & 0x7f;
    } else {
        // short header form, store dummy value that is not a long packet type.
        *long_packet_type = QUIC_SHORT_PACKET;
    }
    offset++;

    *version = tvb_get_ntohl(tvb, offset);

    if (is_long_header) {
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
    quic_datagram *dgram_info = NULL;
    quic_packet_info_t *quic_packet = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUIC");

    if (PINFO_FD_VISITED(pinfo)) {
        dgram_info = (quic_datagram *)p_get_proto_data(wmem_file_scope(), pinfo, proto_quic, 0);
    }
    if (!dgram_info) {
        dgram_info = wmem_new0(wmem_file_scope(), quic_datagram);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_quic, 0, dgram_info);
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

        tvbuff_t *next_tvb = quic_get_message_tvb(tvb, offset);
        proto_tree_add_item_ret_uint(quic_tree, hf_quic_header_form, next_tvb, 0, 1, ENC_NA, &header_form);
        guint new_offset = 0;
        if (header_form) {
            guint8 long_packet_type = tvb_get_guint8(next_tvb, 0) & 0x7f;
            guint32 version = tvb_get_ntohl(next_tvb, 1);
            if (version == 0) {
                offset += dissect_quic_version_negotiation(next_tvb, pinfo, quic_tree, quic_packet);
                break;
            }
            if (long_packet_type == QUIC_LPT_RETRY) {
                new_offset = dissect_quic_retry_packet(next_tvb, pinfo, quic_tree, dgram_info, quic_packet);
            } else {
                new_offset = dissect_quic_long_header(next_tvb, pinfo, quic_tree, dgram_info, quic_packet);
            }
        } else {
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

    // Is this a SH packet after connection migration? SH (draft -14):
    // Flag (1) + DCID (4-18) + PKN (1/2/4) + encrypted payload (>= 16).
    if (tvb_captured_length(tvb) < 1 + 4 + 1 + 16) {
        return FALSE;
    }

    // DCID length is unknown, so extract the maximum and look for a match.
    quic_cid_t dcid = {.len=18};
    tvb_memcpy(tvb, dcid.cid, 1, 18);
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
     * Since draft -12:
     * Flag (1 byte) + Version (4 bytes) + DCIL/SCIL (1 byte) +
     * Destination Connection ID (0/4..18 based on DCIL) +
     * Source Connection ID (0/4..18 based on SCIL) +
     * Payload length (1/2/4/8) + Packet number (1/2/4 bytes) + Payload.
     * (absolute minimum: 8 + payload)
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

    // check for draft QUIC version (for draft -11 and newer) or check for gQUIC version (= Q044)
    version = tvb_get_ntohl(tvb, offset);
    is_quic = (quic_draft_version(version) >= 11) || is_gquic_version(version);

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
        { &hf_quic_short_kp_flag,
          { "Key Phase Bit", "quic.short.kp_flag",
            FT_BOOLEAN, 8, NULL, SH_KP,
            NULL, HFILL }
        },
        { &hf_quic_short_reserved,
          { "Reserved", "quic.short.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Reserved bits for experimentation", HFILL }
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

        { &hf_quic_odcil_draft13,
          { "Original Destination Connection ID Length", "quic.odcil_draft13",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_odcil,
          { "Original Destination Connection ID Length", "quic.odcil",
            FT_UINT8, BASE_DEC, VALS(quic_cid_len_vals), 0x0f,
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

        { &hf_quic_frame,
          { "Frame", "quic.frame",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_frame_type_draft14,
          { "Frame Type", "quic.frame_type.draft14",
            FT_UINT8, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_frame_type_draft14_vals), 0x0,
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
          { "Padding Length", "quic.frame_type.padding_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        /* RST_STREAM */
        { &hf_quic_frame_type_rsts_stream_id,
            { "Stream ID", "quic.frame_type.rsts.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_rsts_application_error_code,
            { "Application Error code", "quic.frame_type.rsts.application_error_code",
              FT_UINT16, BASE_DEC, VALS(quic_application_error_code_vals), 0x0,
              "Indicates why the stream is being closed", HFILL }
        },
        { &hf_quic_frame_type_rsts_final_offset,
            { "Final offset", "quic.frame_type.rsts.byte_offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of the end of data written on this stream", HFILL }
        },
        /* CONNECTION_CLOSE */
        { &hf_quic_frame_type_cc_error_code,
            { "Error code", "quic.frame_type.cc.error_code",
              FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(quic_transport_error_code_vals), 0x0,
              "Indicates the reason for closing this connection", HFILL }
        },
        { &hf_quic_frame_type_cc_error_code_tls_alert,
            { "TLS Alert Description", "quic.frame_type.cc.error_code.tls_alert",
              FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_cc_frame_type,
            { "Frame Type", "quic.frame_type.cc.frame_type",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The type of frame that triggered the error", HFILL }
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
              FT_UINT16, BASE_DEC, VALS(quic_application_error_code_vals), 0x0,
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
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Indicates why the sender is ignoring the stream", HFILL }
        },

        /* CRYPTO */
        { &hf_quic_frame_type_crypto_offset,
            { "Offset", "quic.frame_type.crypto.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Byte offset into the stream", HFILL }
        },
        { &hf_quic_frame_type_crypto_length,
            { "Length", "quic.frame_type.crypto.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Length of the Crypto Data field", HFILL }
        },
        { &hf_quic_frame_type_crypto_crypto_data,
            { "Crypto Data", "quic.frame_type.crypto.crypto_data",
              FT_NONE, BASE_NONE, NULL, 0x0,
              "The cryptographic message data", HFILL }
        },

        /* NEW_TOKEN */
        { &hf_quic_frame_type_nt_length,
            { "(Token) Length", "quic.frame_type.nt.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the token", HFILL }
        },
        { &hf_quic_frame_type_nt_token,
            { "Token", "quic.frame_type.nt.token",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "An opaque blob that the client may use with a future Initial packet", HFILL }
        },

        /* ACK_ECN */
        { &hf_quic_frame_type_ae_largest_acknowledged,
          { "Largest Acknowledged", "quic.frame_type.ae.largest_acknowledged",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Representing the largest packet number the peer is acknowledging in this packet", HFILL }
        },
        { &hf_quic_frame_type_ae_ack_delay,
          { "ACK Delay", "quic.frame_type.ae.ack_delay",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The time from when the largest acknowledged packet, as indicated in the Largest Acknowledged field, was received by this peer to when this ACK was sent", HFILL }
        },
        { &hf_quic_frame_type_ae_ect0_count,
          { "ECT(0) Count", "quic.frame_type.ae.ect0_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Representing the total number packets received with the ECT(0) codepoint", HFILL }
        },
        { &hf_quic_frame_type_ae_ect1_count,
          { "ECT(1) Count", "quic.frame_type.ae.ect1_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Representing the total number packets received with the ECT(1) codepoint", HFILL }
        },
        { &hf_quic_frame_type_ae_ecn_ce_count,
          { "CE Count", "quic.frame_type.ae.ecn_ce_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Representing the total number packets received with the CE codepoint", HFILL }
        },
        { &hf_quic_frame_type_ae_ack_block_count,
          { "ACK Block Count", "quic.frame_type.ae.ack_block_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The number of Additional ACK Block (and Gap) fields after the First ACK Block", HFILL }
        },
        { &hf_quic_frame_type_ae_fab,
          { "First ACK Block", "quic.frame_type.ack.fab",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicates the number of contiguous additional packets being acknowledged starting at the Largest Acknowledged", HFILL }
        },
        { &hf_quic_frame_type_ae_gap,
          { "Gap", "quic.frame_type.ae.gap",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicating the number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in the preceding ACK Block", HFILL }
        },
        { &hf_quic_frame_type_ae_ack_block,
          { "ACK Block", "quic.frame_type.ae.ack_block",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicating the number of contiguous acknowledged packets preceding the largest packet number, as determined by the preceding Gap", HFILL }
        },

        /* RETIRE_CONNECTION_ID */
        { &hf_quic_frame_type_rci_sequence,
            { "Sequence", "quic.frame_type.rci.sequence",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The sequence number of the connection ID being retired", HFILL }
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
    tls13_handshake_handle = find_dissector("tls13-handshake");
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
