/* packet-tls-utils.h
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TLS_UTILS_H__
#define __PACKET_TLS_UTILS_H__

#include <stdio.h>      /* some APIs we declare take a stdio stream as an argument */

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem_scopes.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/unit_strings.h>
#include <wsutil/wsgcrypt.h>

#ifdef HAVE_LIBGNUTLS
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#endif /* HAVE_LIBGNUTLS */

/* TODO inline this now that Libgcrypt is mandatory? */
#define SSL_CIPHER_CTX gcry_cipher_hd_t
#define SSL_DECRYPT_DEBUG


/* other defines */
typedef enum {
    SSL_ID_CHG_CIPHER_SPEC         = 0x14,
    SSL_ID_ALERT                   = 0x15,
    SSL_ID_HANDSHAKE               = 0x16,
    SSL_ID_APP_DATA                = 0x17,
    SSL_ID_HEARTBEAT               = 0x18,
    SSL_ID_TLS12_CID               = 0x19
} ContentType;

typedef enum {
    SSL_HND_HELLO_REQUEST          = 0,
    SSL_HND_CLIENT_HELLO           = 1,
    SSL_HND_SERVER_HELLO           = 2,
    SSL_HND_HELLO_VERIFY_REQUEST   = 3,
    SSL_HND_NEWSESSION_TICKET      = 4,
    SSL_HND_END_OF_EARLY_DATA      = 5,
    SSL_HND_HELLO_RETRY_REQUEST    = 6,
    SSL_HND_ENCRYPTED_EXTENSIONS   = 8,
    SSL_HND_CERTIFICATE            = 11,
    SSL_HND_SERVER_KEY_EXCHG       = 12,
    SSL_HND_CERT_REQUEST           = 13,
    SSL_HND_SVR_HELLO_DONE         = 14,
    SSL_HND_CERT_VERIFY            = 15,
    SSL_HND_CLIENT_KEY_EXCHG       = 16,
    SSL_HND_FINISHED               = 20,
    SSL_HND_CERT_URL               = 21,
    SSL_HND_CERT_STATUS            = 22,
    SSL_HND_SUPPLEMENTAL_DATA      = 23,
    SSL_HND_KEY_UPDATE             = 24,
    SSL_HND_COMPRESSED_CERTIFICATE = 25,
    /* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03
     * and changed in draft 04. Not to be confused with TLS 1.3 EE. */
    SSL_HND_ENCRYPTED_EXTS         = 67
} HandshakeType;

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define SSL_HND_HELLO_EXT_SERVER_NAME                   0
#define SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH           1
#define SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL        2
#define SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS               3
#define SSL_HND_HELLO_EXT_TRUNCATED_HMAC                4
#define SSL_HND_HELLO_EXT_STATUS_REQUEST                5
#define SSL_HND_HELLO_EXT_USER_MAPPING                  6
#define SSL_HND_HELLO_EXT_CLIENT_AUTHZ                  7
#define SSL_HND_HELLO_EXT_SERVER_AUTHZ                  8
#define SSL_HND_HELLO_EXT_CERT_TYPE                     9
#define SSL_HND_HELLO_EXT_SUPPORTED_GROUPS              10 /* renamed from "elliptic_curves" (RFC 7919 / TLS 1.3) */
#define SSL_HND_HELLO_EXT_EC_POINT_FORMATS              11
#define SSL_HND_HELLO_EXT_SRP                           12
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS          13
#define SSL_HND_HELLO_EXT_USE_SRTP                      14
#define SSL_HND_HELLO_EXT_HEARTBEAT                     15
#define SSL_HND_HELLO_EXT_ALPN                          16
#define SSL_HND_HELLO_EXT_STATUS_REQUEST_V2             17
#define SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP  18
#define SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE              19
#define SSL_HND_HELLO_EXT_SERVER_CERT_TYPE              20
#define SSL_HND_HELLO_EXT_PADDING                       21
#define SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC              22
#define SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET        23
#define SSL_HND_HELLO_EXT_TOKEN_BINDING                 24
#define SSL_HND_HELLO_EXT_CACHED_INFO                   25
#define SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE          27
#define SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT             28
/* 26-33  Unassigned*/
#define SSL_HND_HELLO_EXT_DELEGATED_CREDENTIALS         34 /* draft-ietf-tls-subcerts-10.txt */
#define SSL_HND_HELLO_EXT_SESSION_TICKET_TLS            35
/* RFC 8446 (TLS 1.3) */
#define SSL_HND_HELLO_EXT_KEY_SHARE_OLD                 40 /* draft-ietf-tls-tls13-22 (removed in -23) */
#define SSL_HND_HELLO_EXT_PRE_SHARED_KEY                41
#define SSL_HND_HELLO_EXT_EARLY_DATA                    42
#define SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS            43
#define SSL_HND_HELLO_EXT_COOKIE                        44
#define SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES        45
#define SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO        46 /* draft-ietf-tls-tls13-18 (removed in -19) */
#define SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES       47
#define SSL_HND_HELLO_EXT_OID_FILTERS                   48
#define SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH           49
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT     50
#define SSL_HND_HELLO_EXT_KEY_SHARE                     51
#define SSL_HND_HELLO_EXT_TRANSPARENCY_INFO             52 /* draft-ietf-trans-rfc6962-bis-41 */
#define SSL_HND_HELLO_EXT_CONNECTION_ID_DEPRECATED      53 /* draft-ietf-tls-dtls-connection-id-07 */
#define SSL_HND_HELLO_EXT_CONNECTION_ID                 54
#define SSL_HND_HELLO_EXT_EXTERNAL_ID_HASH              55 /* RFC 8844 */
#define SSL_HND_HELLO_EXT_EXTERNAL_SESSION_ID           56 /* RFC 8844 */
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1  57 /* draft-ietf-quic-tls-33 */
#define SSL_HND_HELLO_EXT_TICKET_REQUEST                58 /* draft-ietf-tls-ticketrequests-07 */
#define SSL_HND_HELLO_EXT_DNSSEC_CHAIN                  59 /* RFC 9102 */
#define SSL_HND_HELLO_EXT_GREASE_0A0A                   2570
#define SSL_HND_HELLO_EXT_GREASE_1A1A                   6682
#define SSL_HND_HELLO_EXT_GREASE_2A2A                   10794
#define SSL_HND_HELLO_EXT_NPN                           13172 /* 0x3374 */
#define SSL_HND_HELLO_EXT_GREASE_3A3A                   14906
#define SSL_HND_HELLO_EXT_ALPS                          17513 /* draft-vvv-tls-alps-01, temporary value used in BoringSSL implementation */
#define SSL_HND_HELLO_EXT_GREASE_4A4A                   19018
#define SSL_HND_HELLO_EXT_GREASE_5A5A                   23130
#define SSL_HND_HELLO_EXT_GREASE_6A6A                   27242
#define SSL_HND_HELLO_EXT_CHANNEL_ID_OLD                30031 /* 0x754f */
#define SSL_HND_HELLO_EXT_CHANNEL_ID                    30032 /* 0x7550 */
#define SSL_HND_HELLO_EXT_GREASE_7A7A                   31354
#define SSL_HND_HELLO_EXT_GREASE_8A8A                   35466
#define SSL_HND_HELLO_EXT_GREASE_9A9A                   39578
#define SSL_HND_HELLO_EXT_GREASE_AAAA                   43690
#define SSL_HND_HELLO_EXT_GREASE_BABA                   47802
#define SSL_HND_HELLO_EXT_GREASE_CACA                   51914
#define SSL_HND_HELLO_EXT_GREASE_DADA                   56026
#define SSL_HND_HELLO_EXT_GREASE_EAEA                   60138
#define SSL_HND_HELLO_EXT_GREASE_FAFA                   64250
#define SSL_HND_HELLO_EXT_RENEGOTIATION_INFO            65281 /* 0xFF01 */
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS     65445 /* 0xffa5 draft-ietf-quic-tls-13 */
#define SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME         65486 /* 0xffce draft-ietf-tls-esni-01 */

#define SSL_HND_CERT_URL_TYPE_INDIVIDUAL_CERT       1
#define SSL_HND_CERT_URL_TYPE_PKIPATH               2
#define SSL_HND_CERT_STATUS_TYPE_OCSP        1
#define SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI  2
#define SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY     2

/* https://github.com/quicwg/base-drafts/wiki/Temporary-IANA-Registry#quic-transport-parameters */
#define SSL_HND_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID  0x00
#define SSL_HND_QUIC_TP_MAX_IDLE_TIMEOUT                    0x01
#define SSL_HND_QUIC_TP_STATELESS_RESET_TOKEN               0x02
#define SSL_HND_QUIC_TP_MAX_UDP_PAYLOAD_SIZE                0x03
#define SSL_HND_QUIC_TP_INITIAL_MAX_DATA                    0x04
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  0x05
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI         0x07
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_BIDI            0x08
#define SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_UNI             0x09
#define SSL_HND_QUIC_TP_ACK_DELAY_EXPONENT                  0x0a
#define SSL_HND_QUIC_TP_MAX_ACK_DELAY                       0x0b
#define SSL_HND_QUIC_TP_DISABLE_ACTIVE_MIGRATION            0x0c
#define SSL_HND_QUIC_TP_PREFERRED_ADDRESS                   0x0d
#define SSL_HND_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT          0x0e
#define SSL_HND_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID        0x0f
#define SSL_HND_QUIC_TP_RETRY_SOURCE_CONNECTION_ID          0x10
#define SSL_HND_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE             0x20 /* https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram-06 */
#define SSL_HND_QUIC_TP_CIBIR_ENCODING                      0x1000 /* https://datatracker.ietf.org/doc/html/draft-banks-quic-cibir-01 */
#define SSL_HND_QUIC_TP_LOSS_BITS                           0x1057 /* https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03 */
#define SSL_HND_QUIC_TP_GREASE_QUIC_BIT                     0x2ab2 /* https://tools.ietf.org/html/draft-thomson-quic-bit-grease-00 */
#define SSL_HND_QUIC_TP_ENABLE_TIME_STAMP                   0x7157 /* https://tools.ietf.org/html/draft-huitema-quic-ts-02 */
#define SSL_HND_QUIC_TP_ENABLE_TIME_STAMP_V2                0x7158 /* https://tools.ietf.org/html/draft-huitema-quic-ts-03 */
#define SSL_HND_QUIC_TP_MIN_ACK_DELAY_OLD                   0xde1a /* https://tools.ietf.org/html/draft-iyengar-quic-delayed-ack-00 */
/* https://quiche.googlesource.com/quiche/+/refs/heads/master/quic/core/crypto/transport_parameters.cc */
#define SSL_HND_QUIC_TP_GOOGLE_USER_AGENT                   0x3129
#define SSL_HND_QUIC_TP_GOOGLE_KEY_UPDATE_NOT_YET_SUPPORTED 0x312B
#define SSL_HND_QUIC_TP_GOOGLE_QUIC_VERSION                 0x4752
#define SSL_HND_QUIC_TP_GOOGLE_INITIAL_RTT                  0x3127
#define SSL_HND_QUIC_TP_GOOGLE_SUPPORT_HANDSHAKE_DONE       0x312A
#define SSL_HND_QUIC_TP_GOOGLE_QUIC_PARAMS                  0x4751
#define SSL_HND_QUIC_TP_GOOGLE_CONNECTION_OPTIONS           0x3128
/* https://github.com/facebookincubator/mvfst/blob/master/quic/QuicConstants.h */
#define SSL_HND_QUIC_TP_FACEBOOK_PARTIAL_RELIABILITY        0xFF00
#define SSL_HND_QUIC_TP_VERSION_INFORMATION                 0xFF73DB /* https://tools.ietf.org/html/draft-ietf-quic-version-negotiation-06 */
#define SSL_HND_QUIC_TP_MIN_ACK_DELAY                       0xFF03DE1A /* https://tools.ietf.org/html/draft-ietf-quic-ack-frequency-01 */
/*
 * Lookup tables
 */
extern const value_string ssl_version_short_names[];
extern const value_string ssl_20_msg_types[];
extern value_string_ext ssl_20_cipher_suites_ext;
extern const value_string ssl_20_certificate_type[];
extern const value_string ssl_31_content_type[];
extern const value_string ssl_versions[];
extern const value_string ssl_31_change_cipher_spec[];
extern const value_string ssl_31_alert_level[];
extern const value_string ssl_31_alert_description[];
extern const value_string ssl_31_handshake_type[];
extern const value_string tls_heartbeat_type[];
extern const value_string tls_heartbeat_mode[];
extern const value_string ssl_31_compression_method[];
extern const value_string ssl_31_key_exchange_algorithm[];
extern const value_string ssl_31_signature_algorithm[];
extern const value_string ssl_31_client_certificate_type[];
extern const value_string ssl_31_public_value_encoding[];
extern value_string_ext ssl_31_ciphersuite_ext;
extern const value_string tls_hello_extension_types[];
extern const value_string tls_hash_algorithm[];
extern const value_string tls_signature_algorithm[];
extern const value_string tls13_signature_algorithm[];
extern const value_string tls_certificate_type[];
extern const value_string tls_cert_chain_type[];
extern const value_string tls_cert_status_type[];
extern const value_string ssl_extension_curves[];
extern const value_string ssl_extension_ec_point_formats[];
extern const value_string ssl_curve_types[];
extern const value_string tls_hello_ext_server_name_type_vs[];
extern const value_string tls_hello_ext_max_fragment_length[];
extern const value_string tls_hello_ext_psk_ke_mode[];
extern const value_string tls13_key_update_request[];
extern const value_string compress_certificate_algorithm_vals[];
extern const value_string quic_transport_parameter_id[];
extern const range_string quic_version_vals[];
extern const val64_string quic_enable_time_stamp_v2_vals[];

/* XXX Should we use GByteArray instead? */
typedef struct _StringInfo {
    guchar  *data;      /* Backing storage which may be larger than data_len */
    guint    data_len;  /* Length of the meaningful part of data */
} StringInfo;

#define SSL_WRITE_KEY           1

#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define GMTLSV1_VERSION        0x101
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd

/* Returns the TLS 1.3 draft version or 0 if not applicable. */
static inline guint8 extract_tls13_draft_version(guint32 version) {
    if ((version & 0xff00) == 0x7f00) {
        return (guint8) version;
    }
    return 0;
}


#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)
#define SSL_CLIENT_EXTENDED_MASTER_SECRET (1<<7)
#define SSL_SERVER_EXTENDED_MASTER_SECRET (1<<8)
#define SSL_NEW_SESSION_TICKET  (1<<10)
#define SSL_ENCRYPT_THEN_MAC    (1<<11)
#define SSL_SEEN_0RTT_APPDATA   (1<<12)
#define SSL_QUIC_RECORD_LAYER   (1<<13) /* For QUIC (draft >= -13) */

#define SSL_EXTENDED_MASTER_SECRET_MASK (SSL_CLIENT_EXTENDED_MASTER_SECRET|SSL_SERVER_EXTENDED_MASTER_SECRET)

/* SSL Cipher Suite modes */
typedef enum {
    MODE_STREAM,    /* GenericStreamCipher */
    MODE_CBC,       /* GenericBlockCipher */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_CCM,       /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
    MODE_CCM_8,     /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} ssl_cipher_mode_t;

/* Explicit and implicit nonce length (RFC 5116 - Section 3.2.1) */
#define IMPLICIT_NONCE_LEN  4
#define EXPLICIT_NONCE_LEN  8
#define TLS13_AEAD_NONCE_LENGTH     12

/* TLS 1.3 Record type for selecting the appropriate secret. */
typedef enum {
    TLS_SECRET_0RTT_APP,
    TLS_SECRET_HANDSHAKE,
    TLS_SECRET_APP,
} TLSRecordType;

#define SSL_DEBUG_USE_STDERR "-"

#define SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES 16

/* Record fragment lengths MUST NOT exceed 2^14 (= 0x4000) */
#define TLS_MAX_RECORD_LENGTH 0x4000

typedef struct _SslCipherSuite {
    gint number;
    gint kex;
    gint enc;
    gint dig;
    ssl_cipher_mode_t mode;
} SslCipherSuite;

typedef struct _SslFlow {
    guint32 byte_seq;
    guint16 flags;
    wmem_tree_t *multisegment_pdus;
} SslFlow;

typedef struct _SslDecompress SslDecompress;

typedef struct _SslDecoder {
    const SslCipherSuite *cipher_suite;
    gint compression;
    guchar _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    guint64 seq;    /**< Implicit (TLS) or explicit (DTLS) record sequence number. */
    guint16 epoch;
    SslFlow *flow;
    StringInfo app_traffic_secret;  /**< TLS 1.3 application traffic secret (if applicable), wmem file scope. */
} SslDecoder;

/*
 * TLS 1.3 Cipher context. Simpler than SslDecoder since no compression is
 * required and all keys are calculated internally.
 */
typedef struct {
    gcry_cipher_hd_t    hd;
    guint8              iv[TLS13_AEAD_NONCE_LENGTH];
} tls13_cipher;

#define KEX_DHE_DSS     0x10
#define KEX_DHE_PSK     0x11
#define KEX_DHE_RSA     0x12
#define KEX_DH_ANON     0x13
#define KEX_DH_DSS      0x14
#define KEX_DH_RSA      0x15
#define KEX_ECDHE_ECDSA 0x16
#define KEX_ECDHE_PSK   0x17
#define KEX_ECDHE_RSA   0x18
#define KEX_ECDH_ANON   0x19
#define KEX_ECDH_ECDSA  0x1a
#define KEX_ECDH_RSA    0x1b
#define KEX_KRB5        0x1c
#define KEX_PSK         0x1d
#define KEX_RSA         0x1e
#define KEX_RSA_PSK     0x1f
#define KEX_SRP_SHA     0x20
#define KEX_SRP_SHA_DSS 0x21
#define KEX_SRP_SHA_RSA 0x22
#define KEX_IS_DH(n)    ((n) >= KEX_DHE_DSS && (n) <= KEX_ECDH_RSA)
#define KEX_TLS13       0x23
#define KEX_ECJPAKE     0x24

#define KEX_ECDHE_SM2   0x25
#define KEX_ECC_SM2     0x26
#define KEX_IBSDH_SM9   0x27
#define KEX_IBC_SM9     0x28

/* Order is significant, must match "ciphers" array in packet-tls-utils.c */

#define ENC_START       0x30
#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_CAMELLIA128 0x37
#define ENC_CAMELLIA256 0x38
#define ENC_SEED        0x39
#define ENC_CHACHA20    0x3A
#define ENC_SM1         0x3B
#define ENC_SM4         0x3C
#define ENC_NULL        0x3D


#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_SM3         0x44
#define DIG_NA          0x45 /* Not Applicable */

typedef struct {
    const gchar *name;
    guint len;
} SslDigestAlgo;

typedef struct _SslRecordInfo {
    guchar *plain_data;     /**< Decrypted data. */
    guint   data_len;       /**< Length of decrypted data. */
    gint    id;             /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    ContentType type;       /**< Content type of the decrypted record data. */
    SslFlow *flow;          /**< Flow where this record fragment is a part of.
                                 Can be NULL if this record type may not be fragmented. */
    guint32 seq;            /**< Data offset within the flow. */
    struct _SslRecordInfo* next;
} SslRecordInfo;

/**
 * Stored information about a part of a reassembled handshake message. A single
 * handshake record is uniquely identified by (record_id, reassembly_id).
 */
typedef struct _TlsHsFragment {
    guint   record_id;      /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    guint   reassembly_id;  /**< Identifies the reassembly that this fragment is part of. */
    guint32 offset;         /**< Offset within a reassembly. */
    guint8  type;           /**< Handshake type (first byte of the buffer). */
    int     is_last : 1;    /**< Whether this fragment completes the message. */
    struct _TlsHsFragment *next;
} TlsHsFragment;

typedef struct {
    SslRecordInfo *records; /**< Decrypted records within this frame. */
    TlsHsFragment *hs_fragments;    /**< Handshake records that are part of a reassembly. */
    guint32 srcport;        /**< Used for Decode As */
    guint32 destport;
} SslPacketInfo;

typedef struct _SslSession {
    gint cipher;
    gint compression;
    guint16 version;
    guchar tls13_draft_version;
    gint8 client_cert_type;
    gint8 server_cert_type;
    guint32 client_ccs_frame;
    guint32 server_ccs_frame;

    /* The address/proto/port of the server as determined from heuristics
     * (e.g. ClientHello) or set externally (via ssl_set_master_secret()). */
    address srv_addr;
    port_type srv_ptype;
    guint srv_port;

    /* The Application layer protocol if known (for STARTTLS support) */
    dissector_handle_t   app_handle;
    const char          *alpn_name;
    guint32              last_nontls_frame;
    gboolean             is_session_resumed;

    /* First pass only: track an in-progress handshake reassembly (>0) */
    guint32     client_hs_reassembly_id;
    guint32     server_hs_reassembly_id;

    /* Connection ID extension

    struct {
        opaque cid<0..2^8-1>;
    } ConnectionId;
    */

    guint8 *client_cid;
    guint8 *server_cid;
    guint8  client_cid_len;
    gboolean client_cid_len_present;
    guint8  server_cid_len;
    gboolean server_cid_len_present;
    gboolean deprecated_cid; /* Set when handshake is using the deprecated CID extention type */
} SslSession;

/* RFC 5246, section 8.1 says that the master secret is always 48 bytes */
#define SSL_MASTER_SECRET_LENGTH        48

struct cert_key_id; /* defined in epan/secrets.h */

/* This holds state information for a SSL conversation */
typedef struct _SslDecryptSession {
    guchar _master_secret[SSL_MASTER_SECRET_LENGTH];
    guchar _session_id[256];
    guchar _client_random[32];
    guchar _server_random[32];
    StringInfo session_id;
    StringInfo session_ticket;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    StringInfo handshake_data;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    guchar _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    guchar _client_data_for_iv[24];
    StringInfo client_data_for_iv;

    gint state;
    const SslCipherSuite *cipher_suite;
    SslDecoder *server;
    SslDecoder *client;
    SslDecoder *server_new;
    SslDecoder *client_new;
#if defined(HAVE_LIBGNUTLS)
    struct cert_key_id *cert_key_id;   /**< SHA-1 Key ID of public key in certificate. */
#endif
    StringInfo psk;
    StringInfo app_data_segment;
    SslSession session;
    gboolean   has_early_data;

} SslDecryptSession;

/* User Access Table */
typedef struct _ssldecrypt_assoc_t {
    char* ipaddr;
    char* port;
    char* protocol;
    char* keyfile;
    char* password;
} ssldecrypt_assoc_t;

typedef struct ssl_common_options {
    const gchar        *psk;
    const gchar        *keylog_filename;
} ssl_common_options_t;

/** Map from something to a (pre-)master secret */
typedef struct {
    GHashTable *session;    /* Session ID (1-32 bytes) to master secret. */
    GHashTable *tickets;    /* Session Ticket to master secret. */
    GHashTable *crandom;    /* Client Random to master secret */
    GHashTable *pre_master; /* First 8 bytes of encrypted pre-master secret to
                               pre-master secret */
    GHashTable *pms;        /* Client Random to unencrypted pre-master secret */

    /* For TLS 1.3: maps Client Random to derived secret. */
    GHashTable *tls13_client_early;
    GHashTable *tls13_client_handshake;
    GHashTable *tls13_server_handshake;
    GHashTable *tls13_client_appdata;
    GHashTable *tls13_server_appdata;
    GHashTable *tls13_early_exporter;
    GHashTable *tls13_exporter;
} ssl_master_key_map_t;

gint ssl_get_keyex_alg(gint cipher);

void quic_transport_parameter_id_base_custom(gchar *result, guint64 parameter_id);

gboolean ssldecrypt_uat_fld_ip_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
gboolean ssldecrypt_uat_fld_port_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
gboolean ssldecrypt_uat_fld_fileopen_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
gboolean ssldecrypt_uat_fld_password_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
gchar* ssl_association_info(const char* dissector_table_name, const char* table_protocol);

/** Initialize the list of sessions with connection ID */
void ssl_init_cid_list(void);

/** Release resource allocated for the list of sessions with connection ID */
void ssl_cleanup_cid_list(void);

/** Add a session to the list of sessions using connection ID */
void ssl_add_session_by_cid(SslDecryptSession *ssl);

/**
 * Return a session with a matching connection ID
 * @param tvb a buffer containing a connection ID
 * @param offset offset of the connection ID in tvb
 */
SslDecryptSession *ssl_get_session_by_cid(tvbuff_t *tvb, guint32 offset);

/** Retrieve a SslSession, creating it if it did not already exist.
 * @param conversation The SSL conversation.
 * @param tls_handle The dissector handle for SSL or DTLS.
 */
extern SslDecryptSession *
ssl_get_session(conversation_t *conversation, dissector_handle_t tls_handle);

/** Resets the decryption parameters for the next decoder. */
extern void
ssl_reset_session(SslSession *session, SslDecryptSession *ssl, gboolean is_client);

/** Set server address and port */
extern void
ssl_set_server(SslSession *session, address *addr, port_type ptype, guint32 port);

/** Sets the application data protocol dissector. Intended to be called by
 * protocols that encapsulate TLS instead of switching to it using STARTTLS.
 * @param tls_handle The dissector handle for TLS or DTLS.
 * @param pinfo Packet Info.
 * @param app_handle Dissector handle for the protocol inside the decrypted
 * Application Data record.
 */
WS_DLL_PUBLIC void
tls_set_appdata_dissector(dissector_handle_t tls_handle, packet_info *pinfo,
                 dissector_handle_t app_handle);

/** Marks this packet as the last one before switching to SSL that is supposed
 * to encapsulate this protocol.
 * @param tls_handle The dissector handle for SSL or DTLS.
 * @param pinfo Packet Info.
 * @param app_handle Dissector handle for the protocol inside the decrypted
 * Application Data record.
 * @return 0 for the first STARTTLS acknowledgement (success) or if tls_handle
 * is NULL. >0 if STARTTLS was started before.
 */
WS_DLL_PUBLIC guint32
ssl_starttls_ack(dissector_handle_t tls_handle, packet_info *pinfo,
                 dissector_handle_t app_handle);

/** Marks this packet as belonging to an SSL conversation started with STARTTLS.
 * @param tls_handle The dissector handle for SSL or DTLS.
 * @param pinfo Packet Info.
 * @param app_handle Dissector handle for the protocol inside the decrypted
 * Application Data record.
 * @return 0 for the first STARTTLS acknowledgement (success) or if tls_handle
 * is NULL. >0 if STARTTLS was started before.
 */
WS_DLL_PUBLIC guint32
ssl_starttls_post_ack(dissector_handle_t tls_handle, packet_info *pinfo,
                 dissector_handle_t app_handle);

extern dissector_handle_t
ssl_find_appdata_dissector(const char *name);

/** set the data and len for the stringInfo buffer. buf should be big enough to
 * contain the provided data
 @param buf the buffer to update
 @param src the data source
 @param len the source data len */
extern void
ssl_data_set(StringInfo* buf, const guchar* src, guint len);

/** alloc the data with the specified len for the stringInfo buffer.
 @param str the data source
 @param len the source data len */
extern gint
ssl_data_alloc(StringInfo* str, size_t len);

extern gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, guchar* iv, gint iv_len);

/** Search for the specified cipher suite id
 @param num the id of the cipher suite to be searched
 @return pointer to the cipher suite struct (or NULL if not found). */
extern const SslCipherSuite *
ssl_find_cipher(int num);


/** Returns the Libgcrypt cipher identifier or 0 if unavailable. */
int
ssl_get_cipher_algo(const SslCipherSuite *cipher_suite);

/** Obtains the block size for a CBC block cipher.
 * @param cipher_suite a cipher suite as returned by ssl_find_cipher().
 * @return the block size of a cipher or 0 if unavailable.
 */
guint
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite);

gboolean
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session,
                               guint32 length, tvbuff_t *tvb, guint32 offset,
                               const gchar *ssl_psk,
#ifdef HAVE_LIBGNUTLS
                               GHashTable *key_hash,
#endif
                               const ssl_master_key_map_t *mk_map);

/** Expand the pre_master_secret to generate all the session information
 * (master secret, session keys, ivs)
 @param ssl_session the store for all the session data
 @return 0 on success */
extern gint
ssl_generate_keyring_material(SslDecryptSession*ssl_session);

extern void
ssl_change_cipher(SslDecryptSession *ssl_session, gboolean server);

/** Try to decrypt an ssl record
 @param ssl ssl_session the store all the session data
 @param decoder the stream decoder to be used
 @param ct the content type of this ssl record
 @param record_version the version as contained in the record
 @param ignore_mac_failed whether to ignore MAC or authenticity failures
 @param in a pointer to the ssl record to be decrypted
 @param inl the record length
 @param cid a pointer to the connection ID to use in AEAD or NULL
 @param cidl the connection ID length or 0 if cid is NULL
 @param comp_str a pointer to the store the compression data
 @param out_str a pointer to the store for the decrypted data
 @param outl the decrypted data len
 @return 0 on success */
extern gint
ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, guint8 ct, guint16 record_version,
        gboolean ignore_mac_failed,
        const guchar *in, guint16 inl, const guchar *cid, guint8 cidl,
        StringInfo *comp_str, StringInfo *out_str, guint *outl);

/**
 * Given a cipher algorithm and its mode, a hash algorithm and the secret (with
 * the same length as the hash algorithm), try to build a cipher. The algorithms
 * and mode are Libgcrypt identifiers.
 */
tls13_cipher *
tls13_cipher_create(const char *label_prefix, int cipher_algo, int cipher_mode, int hash_algo, const StringInfo *secret, const gchar **error);


/* Common part between TLS and DTLS dissectors */

/* handling of association between tls/dtls ports and clear text protocol */
extern void
ssl_association_add(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, guint port, gboolean tcp);

extern void
ssl_association_remove(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, guint port, gboolean tcp);

extern gint
ssl_packet_from_server(SslSession *session, dissector_table_t table, packet_info *pinfo);

/* Obtain information about the current TLS layer. */
SslPacketInfo *
tls_add_packet_info(gint proto, packet_info *pinfo, guint8 curr_layer_num_ssl);

/* add to packet data a copy of the specified real data */
extern void
ssl_add_record_info(gint proto, packet_info *pinfo, const guchar *data, gint data_len, gint record_id, SslFlow *flow, ContentType type, guint8 curr_layer_num_ssl);

/* search in packet data for the specified id; return a newly created tvb for the associated data */
extern tvbuff_t*
ssl_get_record_info(tvbuff_t *parent_tvb, gint proto, packet_info *pinfo, gint record_id, guint8 curr_layer_num_ssl, SslRecordInfo **matched_record);

/* initialize/reset per capture state data (ssl sessions cache) */
extern void
ssl_common_init(ssl_master_key_map_t *master_key_map,
                StringInfo *decrypted_data, StringInfo *compressed_data);
extern void
ssl_common_cleanup(ssl_master_key_map_t *master_key_map, FILE **ssl_keylog_file,
                   StringInfo *decrypted_data, StringInfo *compressed_data);

/**
 * Access to the keys in the TLS dissector, for use by the DTLS dissector.
 * (This is a transition function, it would be nice if the static keylog file
 * contents was separated from keys derived at runtime.)
 */
extern ssl_master_key_map_t *
tls_get_master_key_map(gboolean load_secrets);

/* Process lines from the TLS key log and populate the secrets map. */
extern void
tls_keylog_process_lines(const ssl_master_key_map_t *mk_map, const guint8 *data, guint len);

/* tries to update the secrets cache from the given filename */
extern void
ssl_load_keyfile(const gchar *ssl_keylog_filename, FILE **keylog_file,
                 const ssl_master_key_map_t *mk_map);

#ifdef HAVE_LIBGNUTLS
/* parse ssl related preferences (private keys and ports association strings) */
extern void
ssl_parse_key_list(const ssldecrypt_assoc_t * uats, GHashTable *key_hash, const char* dissector_table_name, dissector_handle_t main_handle, gboolean tcp);
#endif

/* store master secret into session data cache */
extern void
ssl_save_session(SslDecryptSession* ssl, GHashTable *session_hash);

extern void
ssl_finalize_decryption(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map);

extern gboolean
tls13_generate_keys(SslDecryptSession *ssl_session, const StringInfo *secret, gboolean is_from_server);

extern StringInfo *
tls13_load_secret(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                  gboolean is_from_server, TLSRecordType type);

extern void
tls13_change_key(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                 gboolean is_from_server, TLSRecordType type);

extern void
tls13_key_update(SslDecryptSession *ssl, gboolean is_from_server);

extern gboolean
ssl_is_valid_content_type(guint8 type);

extern gboolean
ssl_is_valid_handshake_type(guint8 hs_type, gboolean is_dtls);

extern void
tls_scan_server_hello(tvbuff_t *tvb, guint32 offset, guint32 offset_end,
                      guint16 *server_version, gboolean *is_hrr);

extern void
ssl_try_set_version(SslSession *session, SslDecryptSession *ssl,
                    guint8 content_type, guint8 handshake_type,
                    gboolean is_dtls, guint16 version);

extern void
ssl_calculate_handshake_hash(SslDecryptSession *ssl_session, tvbuff_t *tvb, guint32 offset, guint32 length);

/* common header fields, subtrees and expert info for SSL and DTLS dissectors */
typedef struct ssl_common_dissect {
    struct {
        gint change_cipher_spec;
        gint hs_exts_len;
        gint hs_ext_alpn_len;
        gint hs_ext_alpn_list;
        gint hs_ext_alpn_str;
        gint hs_ext_alpn_str_len;
        gint hs_ext_cert_url_item;
        gint hs_ext_cert_url_padding;
        gint hs_ext_cert_url_sha1;
        gint hs_ext_cert_url_type;
        gint hs_ext_cert_url_url;
        gint hs_ext_cert_url_url_hash_list_len;
        gint hs_ext_cert_url_url_len;
        gint hs_ext_cert_status_type;
        gint hs_ext_cert_status_request_len;
        gint hs_ext_cert_status_responder_id_list_len;
        gint hs_ext_cert_status_request_extensions_len;
        gint hs_ext_cert_status_request_list_len;
        gint hs_ocsp_response_list_len;
        gint hs_ocsp_response_len;
        gint hs_ext_cert_type;
        gint hs_ext_cert_types;
        gint hs_ext_cert_types_len;
        gint hs_ext_data;
        gint hs_ext_ec_point_format;
        gint hs_ext_ec_point_formats;
        gint hs_ext_ec_point_formats_len;
        gint hs_ext_srp_len;
        gint hs_ext_srp_username;
        gint hs_ext_supported_group;
        gint hs_ext_supported_groups;
        gint hs_ext_supported_groups_len;
        gint hs_ext_heartbeat_mode;
        gint hs_ext_len;
        gint hs_ext_npn_str;
        gint hs_ext_npn_str_len;
        gint hs_ext_reneg_info_len;
        gint hs_ext_reneg_info;
        gint hs_ext_key_share_client_length;
        gint hs_ext_key_share_group;
        gint hs_ext_key_share_key_exchange_length;
        gint hs_ext_key_share_key_exchange;
        gint hs_ext_key_share_selected_group;
        gint hs_ext_psk_identities_length;
        gint hs_ext_psk_identity_identity_length;
        gint hs_ext_psk_identity_identity;
        gint hs_ext_psk_identity_obfuscated_ticket_age;
        gint hs_ext_psk_binders_length;
        gint hs_ext_psk_binders;
        gint hs_ext_psk_identity_selected;
        gint hs_ext_supported_versions_len;
        gint hs_ext_supported_version;
        gint hs_ext_cookie_len;
        gint hs_ext_cookie;
        gint hs_ext_server_name;
        gint hs_ext_server_name_len;
        gint hs_ext_server_name_list_len;
        gint hs_ext_server_name_type;
        gint hs_ext_max_fragment_length;
        gint hs_ext_padding_data;
        gint hs_ext_type;
        gint hs_ext_connection_id_length;
        gint hs_ext_connection_id;
        gint hs_sig_hash_alg;
        gint hs_sig_hash_alg_len;
        gint hs_sig_hash_algs;
        gint hs_sig_hash_hash;
        gint hs_sig_hash_sig;
        gint hs_client_keyex_epms_len;
        gint hs_client_keyex_epms;
        gint hs_server_keyex_modulus_len;
        gint hs_server_keyex_exponent_len;
        gint hs_server_keyex_sig_len;
        gint hs_server_keyex_p_len;
        gint hs_server_keyex_g_len;
        gint hs_server_keyex_ys_len;
        gint hs_client_keyex_yc_len;
        gint hs_client_keyex_point_len;
        gint hs_server_keyex_point_len;
        gint hs_server_keyex_p;
        gint hs_server_keyex_g;
        gint hs_server_keyex_curve_type;
        gint hs_server_keyex_named_curve;
        gint hs_server_keyex_ys;
        gint hs_client_keyex_yc;
        gint hs_server_keyex_point;
        gint hs_client_keyex_point;
        gint hs_server_keyex_xs_len;
        gint hs_client_keyex_xc_len;
        gint hs_server_keyex_xs;
        gint hs_client_keyex_xc;
        gint hs_server_keyex_vs_len;
        gint hs_client_keyex_vc_len;
        gint hs_server_keyex_vs;
        gint hs_client_keyex_vc;
        gint hs_server_keyex_rs_len;
        gint hs_client_keyex_rc_len;
        gint hs_server_keyex_rs;
        gint hs_client_keyex_rc;
        gint hs_server_keyex_modulus;
        gint hs_server_keyex_exponent;
        gint hs_server_keyex_sig;
        gint hs_server_keyex_hint_len;
        gint hs_server_keyex_hint;
        gint hs_client_keyex_identity_len;
        gint hs_client_keyex_identity;
        gint hs_certificates_len;
        gint hs_certificates;
        gint hs_certificate_len;
        gint hs_certificate;
        gint hs_cert_types_count;
        gint hs_cert_types;
        gint hs_cert_type;
        gint hs_dnames_len;
        gint hs_dnames;
        gint hs_dnames_truncated;
        gint hs_dname_len;
        gint hs_dname;
        gint hs_random;
        gint hs_random_time;
        gint hs_random_bytes;
        gint hs_session_id;
        gint hs_session_id_len;
        gint hs_client_version;
        gint hs_server_version;
        gint hs_cipher_suites_len;
        gint hs_cipher_suites;
        gint hs_cipher_suite;
        gint hs_comp_methods_len;
        gint hs_comp_methods;
        gint hs_comp_method;
        gint hs_session_ticket_lifetime_hint;
        gint hs_session_ticket_age_add;
        gint hs_session_ticket_nonce_len;
        gint hs_session_ticket_nonce;
        gint hs_session_ticket_len;
        gint hs_session_ticket;
        gint hs_finished;
        gint hs_client_cert_vrfy_sig_len;
        gint hs_client_cert_vrfy_sig;
        gint hs_ja3_full;
        gint hs_ja3_hash;
        gint hs_ja3s_full;
        gint hs_ja3s_hash;

        /* TLS 1.3 */
        gint hs_ext_psk_ke_modes_length;
        gint hs_ext_psk_ke_mode;
        gint hs_certificate_request_context_length;
        gint hs_certificate_request_context;
        gint hs_key_update_request_update;
        gint sct_scts_length;
        gint sct_sct_length;
        gint sct_sct_version;
        gint sct_sct_logid;
        gint sct_sct_timestamp;
        gint sct_sct_extensions_length;
        gint sct_sct_extensions;
        gint sct_sct_signature;
        gint sct_sct_signature_length;
        gint hs_ext_max_early_data_size;
        gint hs_ext_oid_filters_length;
        gint hs_ext_oid_filters_oid_length;
        gint hs_ext_oid_filters_oid;
        gint hs_ext_oid_filters_values_length;
        gint hs_cred_valid_time;
        gint hs_cred_pubkey;
        gint hs_cred_pubkey_len;
        gint hs_cred_signature;
        gint hs_cred_signature_len;

        /* compress_certificate */
        gint hs_ext_compress_certificate_algorithms_length;
        gint hs_ext_compress_certificate_algorithm;
        gint hs_ext_compress_certificate_uncompressed_length;
        gint hs_ext_compress_certificate_compressed_certificate_message_length;
        gint hs_ext_compress_certificate_compressed_certificate_message;

        gint hs_ext_record_size_limit;

        /* QUIC Transport Parameters */
        gint hs_ext_quictp_len;
        gint hs_ext_quictp_parameter;
        gint hs_ext_quictp_parameter_type;
        gint hs_ext_quictp_parameter_len;
        gint hs_ext_quictp_parameter_len_old;
        gint hs_ext_quictp_parameter_value;
        gint hs_ext_quictp_parameter_original_destination_connection_id;
        gint hs_ext_quictp_parameter_max_idle_timeout;
        gint hs_ext_quictp_parameter_stateless_reset_token;
        gint hs_ext_quictp_parameter_initial_max_data;
        gint hs_ext_quictp_parameter_initial_max_stream_data_bidi_local;
        gint hs_ext_quictp_parameter_initial_max_stream_data_bidi_remote;
        gint hs_ext_quictp_parameter_initial_max_stream_data_uni;
        gint hs_ext_quictp_parameter_initial_max_streams_bidi;
        gint hs_ext_quictp_parameter_initial_max_streams_uni;
        gint hs_ext_quictp_parameter_ack_delay_exponent;
        gint hs_ext_quictp_parameter_max_ack_delay;
        gint hs_ext_quictp_parameter_max_udp_payload_size;
        gint hs_ext_quictp_parameter_pa_ipv4address;
        gint hs_ext_quictp_parameter_pa_ipv6address;
        gint hs_ext_quictp_parameter_pa_ipv4port;
        gint hs_ext_quictp_parameter_pa_ipv6port;
        gint hs_ext_quictp_parameter_pa_connectionid_length;
        gint hs_ext_quictp_parameter_pa_connectionid;
        gint hs_ext_quictp_parameter_pa_statelessresettoken;
        gint hs_ext_quictp_parameter_active_connection_id_limit;
        gint hs_ext_quictp_parameter_initial_source_connection_id;
        gint hs_ext_quictp_parameter_retry_source_connection_id;
        gint hs_ext_quictp_parameter_max_datagram_frame_size;
        gint hs_ext_quictp_parameter_cibir_encoding_length;
        gint hs_ext_quictp_parameter_cibir_encoding_offset;
        gint hs_ext_quictp_parameter_loss_bits;
        gint hs_ext_quictp_parameter_enable_time_stamp_v2;
        gint hs_ext_quictp_parameter_min_ack_delay;
        gint hs_ext_quictp_parameter_google_user_agent_id;
        gint hs_ext_quictp_parameter_google_key_update_not_yet_supported;
        gint hs_ext_quictp_parameter_google_quic_version;
        gint hs_ext_quictp_parameter_google_initial_rtt;
        gint hs_ext_quictp_parameter_google_support_handshake_done;
        gint hs_ext_quictp_parameter_google_quic_params;
        gint hs_ext_quictp_parameter_google_quic_params_unknown_field;
        gint hs_ext_quictp_parameter_google_connection_options;
        gint hs_ext_quictp_parameter_google_supported_versions_length;
        gint hs_ext_quictp_parameter_google_supported_version;
        gint hs_ext_quictp_parameter_facebook_partial_reliability;
        gint hs_ext_quictp_parameter_chosen_version;
        gint hs_ext_quictp_parameter_other_version;

        gint esni_suite;
        gint esni_record_digest_length;
        gint esni_record_digest;
        gint esni_encrypted_sni_length;
        gint esni_encrypted_sni;
        gint esni_nonce;

        gint hs_ext_alps_len;
        gint hs_ext_alps_alpn_list;
        gint hs_ext_alps_alpn_str;
        gint hs_ext_alps_alpn_str_len;
        gint hs_ext_alps_settings;

        /* do not forget to update SSL_COMMON_LIST_T and SSL_COMMON_HF_LIST! */
    } hf;
    struct {
        gint hs_ext;
        gint hs_ext_alpn;
        gint hs_ext_cert_types;
        gint hs_ext_groups;
        gint hs_ext_curves_point_formats;
        gint hs_ext_npn;
        gint hs_ext_reneg_info;
        gint hs_ext_key_share;
        gint hs_ext_key_share_ks;
        gint hs_ext_pre_shared_key;
        gint hs_ext_psk_identity;
        gint hs_ext_server_name;
        gint hs_ext_oid_filter;
        gint hs_ext_quictp_parameter;
        gint hs_sig_hash_alg;
        gint hs_sig_hash_algs;
        gint urlhash;
        gint keyex_params;
        gint certificates;
        gint cert_types;
        gint dnames;
        gint hs_random;
        gint cipher_suites;
        gint comp_methods;
        gint session_ticket;
        gint sct;
        gint cert_status;
        gint ocsp_response;
        gint uncompressed_certificates;
        gint hs_ext_alps;

        /* do not forget to update SSL_COMMON_LIST_T and SSL_COMMON_ETT_LIST! */
    } ett;
    struct {
        /* Generic expert info for malformed packets. */
        expert_field malformed_vector_length;
        expert_field malformed_buffer_too_small;
        expert_field malformed_trailing_data;

        expert_field hs_ext_cert_status_undecoded;
        expert_field resumed;
        expert_field record_length_invalid;
        expert_field decompression_error;

        /* do not forget to update SSL_COMMON_LIST_T and SSL_COMMON_EI_LIST! */
    } ei;
} ssl_common_dissect_t;

/* Header fields specific to DTLS. See packet-dtls.c */
typedef struct {
    gint hf_dtls_handshake_cookie_len;
    gint hf_dtls_handshake_cookie;

    /* Do not forget to initialize dtls_hfs to -1 in packet-dtls.c! */
} dtls_hfs_t;

/* Header fields specific to SSL. See packet-tls.c */
typedef struct {
    gint hs_md5_hash;
    gint hs_sha_hash;

    /* Do not forget to initialize ssl_hfs to -1 in packet-tls.c! */
} ssl_hfs_t;


/* Helpers for dissecting Variable-Length Vectors. {{{ */
/* Largest value that fits in a 24-bit number (2^24-1). */
#define G_MAXUINT24     ((1U << 24) - 1)

/**
 * Helper for dissection of variable-length vectors (RFC 5246, section 4.3). It
 * adds a length field to the tree and writes the validated length value into
 * "ret_length" (which is truncated if it exceeds "offset_end").
 *
 * The size of the field is derived from "max_value" (for example, 8 and 255
 * require one byte while 400 needs two bytes). Expert info is added if the
 * length field from the tvb is outside the (min_value, max_value) range.
 *
 * Returns TRUE if there is enough space for the length field and data elements
 * and FALSE otherwise.
 */
extern gboolean
ssl_add_vector(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               guint offset, guint offset_end, guint32 *ret_length,
               int hf_length, guint32 min_value, guint32 max_value);

/**
 * Helper to check whether the data in a vector with multiple elements is
 * correctly dissected. If the current "offset" (normally the value after
 * adding all kinds of fields) does not match "offset_end" (the end of the
 * vector), expert info is added.
 *
 * Returns TRUE if the offset matches the end of the vector and FALSE otherwise.
 */
extern gboolean
ssl_end_vector(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               guint offset, guint offset_end);
/* }}} */


extern void
ssl_check_record_length(ssl_common_dissect_t *hf, packet_info *pinfo,
                        ContentType content_type,
                        guint record_length, proto_item *length_pi,
                        guint16 version, tvbuff_t *decrypted_tvb);

void
ssl_dissect_change_cipher_spec(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               guint32 offset, SslSession *session,
                               gboolean is_from_server,
                               const SslDecryptSession *ssl);

extern void
ssl_dissect_hnd_cli_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *tree, guint32 offset,
                          guint32 offset_end, SslSession *session,
                          SslDecryptSession *ssl,
                          dtls_hfs_t *dtls_hfs);

extern void
ssl_dissect_hnd_srv_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info* pinfo,
                          proto_tree *tree, guint32 offset, guint32 offset_end,
                          SslSession *session, SslDecryptSession *ssl,
                          gboolean is_dtls, gboolean is_hrr);

extern void
ssl_dissect_hnd_hello_retry_request(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info* pinfo,
                                    proto_tree *tree, guint32 offset, guint32 offset_end,
                                    SslSession *session, SslDecryptSession *ssl,
                                    gboolean is_dtls);

extern void
ssl_dissect_hnd_encrypted_extensions(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info* pinfo,
                                     proto_tree *tree, guint32 offset, guint32 offset_end,
                                     SslSession *session, SslDecryptSession *ssl,
                                     gboolean is_dtls);

extern void
ssl_dissect_hnd_new_ses_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset, guint32 offset_end,
                               SslSession *session, SslDecryptSession *ssl,
                               gboolean is_dtls, GHashTable *session_hash);

extern void
ssl_dissect_hnd_cert(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                     guint32 offset, guint32 offset_end, packet_info *pinfo,
                     SslSession *session, SslDecryptSession *ssl,
                     gboolean is_from_server, gboolean is_dtls);

extern void
ssl_dissect_hnd_cert_req(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, guint32 offset, guint32 offset_end,
                         SslSession *session, gboolean is_dtls);

extern void
ssl_dissect_hnd_cli_cert_verify(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset, guint32 offset_end, guint16 version);

extern void
ssl_dissect_hnd_finished(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                         proto_tree *tree, guint32 offset, guint32 offset_end,
                         const SslSession *session, ssl_hfs_t *ssl_hfs);

extern void
ssl_dissect_hnd_cert_url(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, guint32 offset);

extern guint32
tls_dissect_hnd_certificate_status(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset, guint32 offset_end);

extern void
ssl_dissect_hnd_cli_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session);

extern void
ssl_dissect_hnd_srv_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, guint32 offset, guint32 offset_end,
                          const SslSession *session);

extern void
tls13_dissect_hnd_key_update(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, guint32 offset);

extern guint32
tls_dissect_sct_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint32 offset, guint32 offset_end, guint16 version);

extern gboolean
tls13_hkdf_expand_label_context(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        const guint8 *context, guint8 context_length,
                        guint16 out_len, guchar **out);

extern gboolean
tls13_hkdf_expand_label(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        guint16 out_len, guchar **out);

extern void
ssl_dissect_hnd_compress_certificate(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                                     guint32 offset, guint32 offset_end, packet_info *pinfo,
                                     SslSession *session _U_, SslDecryptSession *ssl _U_,
                                     gboolean is_from_server _U_, gboolean is_dtls _U_);
/* {{{ */
#define SSL_COMMON_LIST_T(name) \
ssl_common_dissect_t name = {   \
    /* hf */ {                  \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1                                  \
    },                                                                  \
    /* ett */ {                                                         \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1          \
    },                                                                  \
    /* ei */ {                                                          \
        EI_INIT, EI_INIT, EI_INIT, EI_INIT, EI_INIT, EI_INIT, EI_INIT   \
    },                                                                  \
}
/* }}} */

/* {{{ */
#define SSL_COMMON_HF_LIST(name, prefix)                                \
    { & name .hf.change_cipher_spec,                                    \
      { "Change Cipher Spec Message", prefix ".change_cipher_spec",     \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "Signals a change in cipher specifications", HFILL }            \
    },                                                                  \
    { & name .hf.hs_exts_len,                                           \
      { "Extensions Length", prefix ".handshake.extensions_length",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of hello extensions", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_ext_type,                                           \
      { "Type", prefix ".handshake.extension.type",                     \
        FT_UINT16, BASE_DEC, VALS(tls_hello_extension_types), 0x0,      \
        "Hello extension type", HFILL }                                 \
    },                                                                  \
    { & name .hf.hs_ext_len,                                            \
      { "Length", prefix ".handshake.extension.len",                    \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of a hello extension", HFILL }                          \
    },                                                                  \
    { & name .hf.hs_ext_data,                                           \
      { "Data", prefix ".handshake.extension.data",                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Hello Extension data", HFILL }                                 \
    },                                                                  \
    { & name .hf.hs_ext_supported_groups_len,                           \
      { "Supported Groups List Length", prefix ".handshake.extensions_supported_groups_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_supported_groups,                               \
      { "Supported Groups List", prefix ".handshake.extensions_supported_groups", \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of supported groups (formerly Supported Elliptic Curves)", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_supported_group,                                \
      { "Supported Group", prefix ".handshake.extensions_supported_group", \
        FT_UINT16, BASE_HEX, VALS(ssl_extension_curves), 0x0,           \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_ec_point_formats_len,                           \
      { "EC point formats Length", prefix ".handshake.extensions_ec_point_formats_length",     \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of elliptic curves point formats field", HFILL }        \
    },                                                                  \
    { & name .hf.hs_ext_ec_point_formats,                               \
      { "EC point formats", prefix ".handshake.extensions_ec_point_formats", \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of elliptic curves point format", HFILL }                 \
    },                                                                  \
    { & name .hf.hs_ext_ec_point_format,                                \
      { "EC point format", prefix ".handshake.extensions_ec_point_format",             \
        FT_UINT8, BASE_DEC, VALS(ssl_extension_ec_point_formats), 0x0,  \
        "Elliptic curves point format", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_ext_srp_len,                                        \
      { "SRP username length", prefix ".handshake.extensions_srp_len",  \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of Secure Remote Password username field", HFILL }      \
    },                                                                  \
    { & name .hf.hs_ext_srp_username,                                   \
      { "SRP username", prefix ".handshake.extensions_srp_username",    \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        "Secure Remote Password username", HFILL }                      \
    },                                                                  \
    { & name .hf.hs_ext_alpn_len,                                       \
      { "ALPN Extension Length", prefix ".handshake.extensions_alpn_len",              \
      FT_UINT16, BASE_DEC, NULL, 0x0,                                   \
      "Length of the ALPN Extension", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_ext_alpn_list,                                      \
      { "ALPN Protocol", prefix ".handshake.extensions_alpn_list",      \
      FT_NONE, BASE_NONE, NULL, 0x0,                                    \
      NULL, HFILL }                                                     \
    },                                                                  \
    { & name .hf.hs_ext_alpn_str_len,                                   \
      { "ALPN string length", prefix ".handshake.extensions_alpn_str_len",             \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of ALPN string", HFILL }                                \
    },                                                                  \
    { & name .hf.hs_ext_alpn_str,                                       \
      { "ALPN Next Protocol", prefix ".handshake.extensions_alpn_str",  \
        FT_STRING, BASE_NONE, NULL, 0x00,                               \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_npn_str_len,                                    \
      { "Protocol string length", prefix ".handshake.extensions_npn_str_len",          \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of next protocol string", HFILL }                       \
    },                                                                  \
    { & name .hf.hs_ext_npn_str,                                        \
      { "Next Protocol", prefix ".handshake.extensions_npn",            \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_reneg_info_len,                                 \
      { "Renegotiation info extension length", prefix ".handshake.extensions_reneg_info_len",  \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_reneg_info,                                     \
      { "Renegotiation info", prefix ".handshake.extensions_reneg_info",\
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_key_share_client_length,                        \
      { "Client Key Share Length", prefix ".handshake.extensions_key_share_client_length",  \
         FT_UINT16, BASE_DEC, NULL, 0x00,                               \
         NULL, HFILL }                                                  \
    },                                                                  \
    { & name .hf.hs_ext_key_share_group,                                \
      { "Group", prefix ".handshake.extensions_key_share_group",        \
         FT_UINT16, BASE_DEC, VALS(ssl_extension_curves), 0x00,         \
         NULL, HFILL }                                                  \
    },                                                                  \
    { & name .hf.hs_ext_key_share_key_exchange_length,                  \
      { "Key Exchange Length", prefix ".handshake.extensions_key_share_key_exchange_length",   \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_key_share_key_exchange,                         \
      { "Key Exchange", prefix ".handshake.extensions_key_share_key_exchange",  \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_key_share_selected_group,                       \
      { "Selected Group", prefix ".handshake.extensions_key_share_selected_group",  \
         FT_UINT16, BASE_DEC, VALS(ssl_extension_curves), 0x00,         \
         NULL, HFILL }                                                  \
    },                                                                  \
    { & name .hf.hs_ext_psk_identities_length,                          \
      { "Identities Length", prefix ".handshake.extensions.psk.identities.length",  \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_identity_identity_length,                   \
      { "Identity Length", prefix ".handshake.extensions.psk.identity.identity_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_identity_identity,                          \
      { "Identity", prefix ".handshake.extensions.psk.identity.identity", \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_identity_obfuscated_ticket_age,             \
      { "Obfuscated Ticket Age", prefix ".handshake.extensions.psk.identity.obfuscated_ticket_age", \
        FT_UINT32, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_binders_length,                             \
      { "PSK Binders length", prefix ".handshake.extensions.psk.binders_len", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_binders,                                    \
      { "PSK Binders", prefix ".handshake.extensions.psk.binders",      \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_identity_selected,                          \
      { "Selected Identity", prefix ".handshake.extensions.psk.identity.selected", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_supported_versions_len,                         \
      { "Supported Versions length", prefix ".handshake.extensions.supported_versions_len", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_supported_version,                              \
      { "Supported Version", prefix ".handshake.extensions.supported_version", \
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,                   \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cookie_len,                                     \
      { "Cookie length", prefix ".handshake.extensions.cookie_len",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cookie,                                         \
      { "Cookie", prefix ".handshake.extensions.cookie",                \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_server_name_list_len,                           \
      { "Server Name list length", prefix ".handshake.extensions_server_name_list_len",    \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of server name list", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_ext_server_name_len,                                \
      { "Server Name length", prefix ".handshake.extensions_server_name_len",          \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of server name string", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_ext_server_name_type,                               \
      { "Server Name Type", prefix ".handshake.extensions_server_name_type",           \
        FT_UINT8, BASE_DEC, VALS(tls_hello_ext_server_name_type_vs), 0x0,               \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_server_name,                                    \
      { "Server Name", prefix ".handshake.extensions_server_name",      \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_max_fragment_length,                            \
      { "Maximum Fragment Length", prefix ".handshake.max_fragment_length", \
        FT_UINT8, BASE_DEC, VALS(tls_hello_ext_max_fragment_length), 0x00, \
        "Maximum fragment length that an endpoint is willing to receive", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_padding_data,                                   \
      { "Padding Data", prefix ".handshake.extensions_padding_data",    \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Must be zero", HFILL }                                         \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_type,                                  \
      { "Certificate Chain Type", prefix ".handshake.cert_url_type",    \
        FT_UINT8, BASE_DEC, VALS(tls_cert_chain_type), 0x0,             \
        "Certificate Chain Type for Client Certificate URL", HFILL }    \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_url_hash_list_len,                     \
      { "URL and Hash list Length", prefix ".handshake.cert_url.url_hash_len",         \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_item,                                  \
      { "URL and Hash", prefix ".handshake.cert_url.url_hash",          \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_url_len,                               \
      { "URL Length", prefix ".handshake.cert_url.url_len",             \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_type,                                      \
      { "Certificate Type", prefix ".handshake.cert_type.type",         \
        FT_UINT8, BASE_HEX, VALS(tls_certificate_type), 0x0,            \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_types,                                     \
      { "Certificate Type List", prefix ".handshake.cert_type.types",   \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_types_len,                                 \
      { "Certificate Type List Length", prefix ".handshake.cert_type.types_len",       \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_url,                                   \
      { "URL", prefix ".handshake.cert_url.url",                        \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        "URL used to fetch the certificate(s)", HFILL }                 \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_padding,                               \
      { "Padding", prefix ".handshake.cert_url.padding",                \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "Padding that MUST be 0x01 for backwards compatibility", HFILL }                \
    },                                                                  \
    { & name .hf.hs_ext_cert_url_sha1,                                  \
      { "SHA1 Hash", prefix ".handshake.cert_url.sha1",                 \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "SHA1 Hash of the certificate", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_ext_cert_status_type,                               \
      { "Certificate Status Type", prefix ".handshake.extensions_status_request_type", \
        FT_UINT8, BASE_DEC, VALS(tls_cert_status_type), 0x0,            \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_status_request_len,                        \
      { "Certificate Status Length", prefix ".handshake.extensions_status_request_len",    \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_status_responder_id_list_len,              \
      { "Responder ID list Length", prefix ".handshake.extensions_status_request_responder_ids_len",   \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_status_request_extensions_len,             \
      { "Request Extensions Length", prefix ".handshake.extensions_status_request_exts_len",   \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_cert_status_request_list_len,                   \
      { "Certificate Status List Length", prefix ".handshake.extensions_status_request_list_len", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "CertificateStatusRequestItemV2 list length", HFILL }           \
    },                                                                  \
    { & name .hf.hs_ocsp_response_list_len,                             \
      { "OCSP Response List Length", prefix ".handshake.ocsp_response_list_len", \
        FT_UINT24, BASE_DEC, NULL, 0x0,                                 \
        "OCSPResponseList length", HFILL }                              \
    },                                                                  \
    { & name .hf.hs_ocsp_response_len,                                  \
      { "OCSP Response Length", prefix ".handshake.ocsp_response_len",  \
        FT_UINT24, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_sig_hash_alg_len,                                   \
      { "Signature Hash Algorithms Length", prefix ".handshake.sig_hash_alg_len",      \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of Signature Hash Algorithms", HFILL }                  \
    },                                                                  \
    { & name .hf.hs_sig_hash_algs,                                      \
      { "Signature Algorithms", prefix ".handshake.sig_hash_algs",      \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of supported Signature Algorithms", HFILL }               \
    },                                                                  \
    { & name .hf.hs_sig_hash_alg,                                       \
      { "Signature Algorithm", prefix ".handshake.sig_hash_alg",        \
        FT_UINT16, BASE_HEX, VALS(tls13_signature_algorithm), 0x0,      \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_sig_hash_hash,                                      \
      { "Signature Hash Algorithm Hash", prefix ".handshake.sig_hash_hash",            \
        FT_UINT8, BASE_DEC, VALS(tls_hash_algorithm), 0x0,              \
        "Hash algorithm (TLS 1.2)", HFILL }                             \
    },                                                                  \
    { & name .hf.hs_sig_hash_sig,                                       \
      { "Signature Hash Algorithm Signature", prefix ".handshake.sig_hash_sig",        \
        FT_UINT8, BASE_DEC, VALS(tls_signature_algorithm), 0x0,         \
        "Signature algorithm (TLS 1.2)", HFILL }                        \
    },                                                                  \
    { & name .hf.hs_client_keyex_epms_len,                              \
      { "Encrypted PreMaster length", prefix ".handshake.epms_len",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of encrypted PreMaster secret", HFILL }                 \
    },                                                                  \
    { & name .hf.hs_client_keyex_epms,                                  \
      { "Encrypted PreMaster", prefix ".handshake.epms",                \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Encrypted PreMaster secret", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_server_keyex_modulus_len,                           \
      { "Modulus Length", prefix ".handshake.modulus_len",              \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of RSA-EXPORT modulus", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_server_keyex_exponent_len,                          \
      { "Exponent Length", prefix ".handshake.exponent_len",            \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of RSA-EXPORT exponent", HFILL }                        \
    },                                                                  \
    { & name .hf.hs_server_keyex_sig_len,                               \
      { "Signature Length", prefix ".handshake.sig_len",                \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of Signature", HFILL }                                  \
    },                                                                  \
    { & name .hf.hs_server_keyex_p_len,                                 \
      { "p Length", prefix ".handshake.p_len",                          \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of p", HFILL }                                          \
    },                                                                  \
    { & name .hf.hs_server_keyex_g_len,                                 \
      { "g Length", prefix ".handshake.g_len",                          \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of g", HFILL }                                          \
    },                                                                  \
    { & name .hf.hs_server_keyex_ys_len,                                \
      { "Pubkey Length", prefix ".handshake.ys_len",                    \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of server's Diffie-Hellman public key", HFILL }         \
    },                                                                  \
    { & name .hf.hs_client_keyex_yc_len,                                \
      { "Pubkey Length", prefix ".handshake.yc_len",                    \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of client's Diffie-Hellman public key", HFILL }         \
    },                                                                  \
    { & name .hf.hs_client_keyex_point_len,                             \
      { "Pubkey Length", prefix ".handshake.client_point_len",          \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of client's EC Diffie-Hellman public key", HFILL }      \
    },                                                                  \
    { & name .hf.hs_server_keyex_point_len,                             \
      { "Pubkey Length", prefix ".handshake.server_point_len",          \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of server's EC Diffie-Hellman public key", HFILL }      \
    },                                                                  \
    { & name .hf.hs_server_keyex_p,                                     \
      { "p", prefix ".handshake.p",                                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Diffie-Hellman p", HFILL }                                     \
    },                                                                  \
    { & name .hf.hs_server_keyex_g,                                     \
      { "g", prefix ".handshake.g",                                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Diffie-Hellman g", HFILL }                                     \
    },                                                                  \
    { & name .hf.hs_server_keyex_curve_type,                            \
      { "Curve Type", prefix ".handshake.server_curve_type",            \
        FT_UINT8, BASE_HEX, VALS(ssl_curve_types), 0x0,                 \
        "Server curve_type", HFILL }                                    \
    },                                                                  \
    { & name .hf.hs_server_keyex_named_curve,                           \
      { "Named Curve", prefix ".handshake.server_named_curve",          \
        FT_UINT16, BASE_HEX, VALS(ssl_extension_curves), 0x0,           \
        "Server named_curve", HFILL }                                   \
    },                                                                  \
    { & name .hf.hs_server_keyex_ys,                                    \
      { "Pubkey", prefix ".handshake.ys",                               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Diffie-Hellman server pubkey", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_client_keyex_yc,                                    \
      { "Pubkey", prefix ".handshake.yc",                               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Diffie-Hellman client pubkey", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_server_keyex_point,                                 \
      { "Pubkey", prefix ".handshake.server_point",                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC Diffie-Hellman server pubkey", HFILL }                      \
    },                                                                  \
    { & name .hf.hs_client_keyex_point,                                 \
      { "Pubkey", prefix ".handshake.client_point",                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC Diffie-Hellman client pubkey", HFILL }                      \
    },                                                                  \
    { & name .hf.hs_server_keyex_xs_len,                                \
      { "Pubkey Length", prefix ".handshake.xs_len",                    \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of EC J-PAKE server public key", HFILL }                \
    },                                                                  \
    { & name .hf.hs_client_keyex_xc_len,                                \
      { "Pubkey Length", prefix ".handshake.xc_len",                    \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of EC J-PAKE client public key", HFILL }                \
    },                                                                  \
    { & name .hf.hs_server_keyex_xs,                                    \
      { "Pubkey", prefix ".handshake.xs",                               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC J-PAKE server public key", HFILL }                          \
    },                                                                  \
    { & name .hf.hs_client_keyex_xc,                                    \
      { "Pubkey", prefix ".handshake.xc",                               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC J-PAKE client public key", HFILL }                          \
    },                                                                  \
    { & name .hf.hs_server_keyex_vs_len,                                \
      { "Ephemeral Pubkey Length", prefix ".handshake.vs_len",          \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of EC J-PAKE server ephemeral public key", HFILL }      \
    },                                                                  \
    { & name .hf.hs_client_keyex_vc_len,                                \
      { "Ephemeral Pubkey Length", prefix ".handshake.vc_len",          \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of EC J-PAKE client ephemeral public key", HFILL }      \
    },                                                                  \
    { & name .hf.hs_server_keyex_vs,                                    \
      { "Ephemeral Pubkey", prefix ".handshake.vs",                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC J-PAKE server ephemeral public key", HFILL }                \
    },                                                                  \
    { & name .hf.hs_client_keyex_vc,                                    \
      { "Ephemeral Pubkey", prefix ".handshake.vc",                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC J-PAKE client ephemeral public key", HFILL }                \
    },                                                                  \
    { & name .hf.hs_server_keyex_rs_len,                                \
      { "Schnorr signature Length", prefix ".handshake.rs_len",         \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of EC J-PAKE server Schnorr signature", HFILL }         \
    },                                                                  \
    { & name .hf.hs_client_keyex_rc_len,                                \
      { "Schnorr signature Length", prefix ".handshake.rc_len",         \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of EC J-PAKE client Schnorr signature", HFILL }         \
    },                                                                  \
    { & name .hf.hs_server_keyex_rs,                                    \
      { "Schnorr signature", prefix ".handshake.rs",                    \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC J-PAKE server Schnorr signature", HFILL }                   \
    },                                                                  \
    { & name .hf.hs_client_keyex_rc,                                    \
      { "Schnorr signature", prefix ".handshake.rc",                    \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "EC J-PAKE client Schnorr signature", HFILL }                   \
    },                                                                  \
    { & name .hf.hs_server_keyex_modulus,                               \
      { "Modulus", prefix ".handshake.modulus",                         \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "RSA-EXPORT modulus", HFILL }                                   \
    },                                                                  \
    { & name .hf.hs_server_keyex_exponent,                              \
      { "Exponent", prefix ".handshake.exponent",                       \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "RSA-EXPORT exponent", HFILL }                                  \
    },                                                                  \
    { & name .hf.hs_server_keyex_sig,                                   \
      { "Signature", prefix ".handshake.sig",                           \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Diffie-Hellman server signature", HFILL }                      \
    },                                                                  \
    { & name .hf.hs_server_keyex_hint_len,                              \
      { "Hint Length", prefix ".handshake.hint_len",                    \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of PSK Hint", HFILL }                                   \
    },                                                                  \
    { & name .hf.hs_server_keyex_hint,                                  \
      { "Hint", prefix ".handshake.hint",                               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "PSK Hint", HFILL }                                             \
    },                                                                  \
    { & name .hf.hs_client_keyex_identity_len,                          \
      { "Identity Length", prefix ".handshake.identity_len",            \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of PSK Identity", HFILL }                               \
    },                                                                  \
    { & name .hf.hs_client_keyex_identity,                              \
      { "Identity", prefix ".handshake.identity",                       \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "PSK Identity", HFILL }                                         \
    },                                                                  \
    { & name .hf.hs_ext_heartbeat_mode,                                 \
      { "Mode", prefix ".handshake.extension.heartbeat.mode",           \
        FT_UINT8, BASE_DEC, VALS(tls_heartbeat_mode), 0x0,              \
        "Heartbeat extension mode", HFILL }                             \
    },                                                                  \
    { & name .hf.hs_certificates_len,                                   \
      { "Certificates Length", prefix ".handshake.certificates_length", \
        FT_UINT24, BASE_DEC, NULL, 0x0,                                 \
        "Length of certificates field", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_certificates,                                       \
      { "Certificates", prefix ".handshake.certificates",               \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of certificates", HFILL }                                 \
    },                                                                  \
    { & name .hf.hs_certificate,                                        \
      { "Certificate", prefix ".handshake.certificate",                 \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_certificate_len,                                    \
      { "Certificate Length", prefix ".handshake.certificate_length",   \
        FT_UINT24, BASE_DEC, NULL, 0x0,                                 \
        "Length of certificate", HFILL }                                \
    },                                                                  \
    { & name .hf.hs_cert_types_count,                                   \
      { "Certificate types count", prefix ".handshake.cert_types_count",\
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Count of certificate types", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_cert_types,                                         \
      { "Certificate types", prefix ".handshake.cert_types",            \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of certificate types", HFILL }                            \
    },                                                                  \
    { & name .hf.hs_cert_type,                                          \
      { "Certificate type", prefix ".handshake.cert_type",              \
        FT_UINT8, BASE_DEC, VALS(ssl_31_client_certificate_type), 0x0,  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_dnames_len,                                         \
      { "Distinguished Names Length", prefix ".handshake.dnames_len",   \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of list of CAs that server trusts", HFILL }             \
    },                                                                  \
    { & name .hf.hs_dnames,                                             \
      { "Distinguished Names", prefix ".handshake.dnames",              \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of CAs that server trusts", HFILL }                       \
    },                                                                  \
    { & name .hf.hs_dname_len,                                          \
      { "Distinguished Name Length", prefix ".handshake.dname_len",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of distinguished name", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_dnames_truncated,                                   \
      { "Tree view truncated", prefix ".handshake.dnames_truncated",    \
         FT_NONE, BASE_NONE, NULL, 0x00,                                \
         "Some Distinguished Names are not added to tree pane to limit resources", HFILL } \
    },                                                                  \
    { & name .hf.hs_dname,                                              \
      { "Distinguished Name", prefix ".handshake.dname",                \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "Distinguished name of a CA that server trusts", HFILL }        \
    },                                                                  \
    { & name .hf.hs_random,                                             \
      { "Random", prefix ".handshake.random",                           \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Random values used for deriving keys", HFILL }                 \
    },                                                                  \
    { & name .hf.hs_random_time,                                        \
      { "GMT Unix Time", prefix ".handshake.random_time",               \
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,               \
        "Unix time field of random structure", HFILL }                  \
    },                                                                  \
    { & name .hf.hs_random_bytes,                                       \
      { "Random Bytes", prefix ".handshake.random_bytes",               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Random values used for deriving keys", HFILL }                 \
    },                                                                  \
    { & name .hf.hs_session_id,                                         \
      { "Session ID", prefix ".handshake.session_id",                   \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Identifies the SSL session, allowing later resumption", HFILL }\
    },                                                                  \
    { & name .hf.hs_session_id_len,                                     \
      { "Session ID Length", prefix ".handshake.session_id_length",     \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of Session ID field", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_client_version,                                     \
      { "Version", prefix ".handshake.version",                         \
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,                   \
        "Maximum version supported by client", HFILL }                  \
    },                                                                  \
    { & name .hf.hs_server_version,                                     \
      { "Version", prefix ".handshake.version",                         \
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,                   \
        "Version selected by server", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_cipher_suites_len,                                  \
      { "Cipher Suites Length", prefix ".handshake.cipher_suites_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of cipher suites field", HFILL }                        \
    },                                                                  \
    { & name .hf.hs_cipher_suites,                                      \
      { "Cipher Suites", prefix ".handshake.ciphersuites",              \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of cipher suites supported by client", HFILL }            \
    },                                                                  \
    { & name .hf.hs_cipher_suite,                                       \
      { "Cipher Suite", prefix ".handshake.ciphersuite",                \
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ssl_31_ciphersuite_ext, 0x0, \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_comp_methods_len,                                   \
      { "Compression Methods Length", prefix ".handshake.comp_methods_length", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of compression methods field", HFILL }                  \
    },                                                                  \
    { & name .hf.hs_comp_methods,                                       \
      { "Compression Methods", prefix ".handshake.comp_methods",        \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of compression methods supported by client", HFILL }      \
    },                                                                  \
    { & name .hf.hs_comp_method,                                        \
      { "Compression Method", prefix ".handshake.comp_method",          \
        FT_UINT8, BASE_DEC, VALS(ssl_31_compression_method), 0x0,       \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_session_ticket_lifetime_hint,                       \
      { "Session Ticket Lifetime Hint",                                 \
        prefix ".handshake.session_ticket_lifetime_hint",               \
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_second_seconds, 0x0, \
        "New Session Ticket Lifetime Hint", HFILL }                     \
    },                                                                  \
    { & name .hf.hs_session_ticket_age_add,                             \
      { "Session Ticket Age Add",                                       \
        prefix ".handshake.session_ticket_age_add",                     \
        FT_UINT32, BASE_DEC, NULL, 0x0,                                 \
        "Random 32-bit value to obscure age of ticket", HFILL }         \
    },                                                                  \
    { & name .hf.hs_session_ticket_nonce_len,                           \
      { "Session Ticket Nonce Length", prefix ".handshake.session_ticket_nonce_length", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_session_ticket_nonce,                               \
      { "Session Ticket Nonce", prefix ".handshake.session_ticket_nonce",   \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "A unique per-ticket value", HFILL }                            \
    },                                                                  \
    { & name .hf.hs_session_ticket_len,                                 \
      { "Session Ticket Length", prefix ".handshake.session_ticket_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "New Session Ticket Length", HFILL }                            \
    },                                                                  \
    { & name .hf.hs_session_ticket,                                     \
      { "Session Ticket", prefix ".handshake.session_ticket",           \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "New Session Ticket", HFILL }                                   \
    },                                                                  \
    { & name .hf.hs_finished,                                           \
      { "Verify Data", prefix ".handshake.verify_data",                 \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "Opaque verification data", HFILL }                             \
    },                                                                  \
    { & name .hf.hs_client_cert_vrfy_sig_len,                           \
      { "Signature length", prefix ".handshake.client_cert_vrfy.sig_len", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of CertificateVerify's signature", HFILL }              \
    },                                                                  \
    { & name .hf.hs_client_cert_vrfy_sig,                               \
      { "Signature", prefix ".handshake.client_cert_vrfy.sig",          \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "CertificateVerify's signature", HFILL }                        \
    },                                                                  \
    { & name .hf.hs_ja3_full,                                           \
      { "JA3 Fullstring", prefix ".handshake.ja3_full",                 \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ja3_hash,                                           \
      { "JA3", prefix ".handshake.ja3",                                 \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ja3s_full,                                          \
      { "JA3S Fullstring", prefix ".handshake.ja3s_full",               \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ja3s_hash,                                          \
      { "JA3S", prefix ".handshake.ja3s",                               \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_ke_modes_length,                            \
      { "PSK Key Exchange Modes Length", prefix ".extension.psk_ke_modes_length", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_psk_ke_mode,                                    \
      { "PSK Key Exchange Mode", prefix ".extension.psk_ke_mode",       \
        FT_UINT8, BASE_DEC, VALS(tls_hello_ext_psk_ke_mode), 0x0,       \
        "Key exchange modes where the client supports use of PSKs", HFILL } \
    },                                                                  \
    { & name .hf.hs_certificate_request_context_length,                 \
      { "Certificate Request Context Length", prefix ".handshake.certificate_request_context_length", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_certificate_request_context,                        \
      { "Certificate Request Context", prefix ".handshake.certificate_request_context", \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Value from CertificateRequest or empty for server auth", HFILL } \
    },                                                                  \
    { & name .hf.hs_key_update_request_update,                          \
      { "Key Update Request", prefix ".handshake.key_update.request_update", \
        FT_UINT8, BASE_DEC, VALS(tls13_key_update_request), 0x00,       \
        "Whether the receiver should also update its keys", HFILL }     \
    },                                                                  \
    { & name .hf.sct_scts_length,                                       \
      { "Serialized SCT List Length", prefix ".sct.scts_length",        \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.sct_sct_length,                                        \
      { "Serialized SCT Length", prefix ".sct.sct_length",              \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.sct_sct_version,                                       \
      { "SCT Version", prefix ".sct.sct_version",                       \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        "SCT Protocol version (v1 (0) is defined in RFC 6962)", HFILL } \
    },                                                                  \
    { & name .hf.sct_sct_logid,                                         \
      { "Log ID", prefix ".sct.sct_logid",                              \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "SHA-256 hash of log's public key", HFILL }                     \
    },                                                                  \
    { & name .hf.sct_sct_timestamp,                                     \
      { "Timestamp", prefix ".sct.sct_timestamp",                       \
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,                \
        "Timestamp of issuance", HFILL }                                \
    },                                                                  \
    { & name .hf.sct_sct_extensions_length,                             \
      { "Extensions length", prefix ".sct.sct_extensions_length",       \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        "Length of future extensions to this protocol (currently none)", HFILL } \
    },                                                                  \
    { & name .hf.sct_sct_extensions,                                    \
      { "Extensions", prefix ".sct.sct_extensions",                     \
        FT_NONE, BASE_NONE, NULL, 0x00,                                 \
        "Future extensions to this protocol (currently none)", HFILL }  \
    },                                                                  \
    { & name .hf.sct_sct_signature_length,                              \
      { "Signature Length", prefix ".sct.sct_signature_length",         \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.sct_sct_signature,                                     \
      { "Signature", prefix ".sct.sct_signature",                       \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_max_early_data_size,                            \
      { "Maximum Early Data Size", prefix ".early_data.max_early_data_size", \
        FT_UINT32, BASE_DEC, NULL, 0x00,                                \
        "Maximum amount of 0-RTT data that the client may send", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_oid_filters_length,                             \
      { "OID Filters Length", prefix ".extension.oid_filters_length",   \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_oid_filters_oid_length,                         \
      { "Certificate Extension OID Length", prefix ".extension.oid_filters.oid_length", \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_oid_filters_oid,                                \
      { "Certificate Extension OID", prefix ".extension.oid_filters.oid", \
        FT_OID, BASE_NONE, NULL, 0x00,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_oid_filters_values_length,                      \
      { "Certificate Extension Values Length", prefix ".extension.oid_filters.values_length", \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_cred_valid_time,                                    \
      { "Valid Time", prefix ".handshake.cred.valid_time",              \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Delegated Credentials Valid Time", HFILL }                     \
    },                                                                  \
    { & name .hf.hs_cred_pubkey,                                        \
      { "Subject Public Key Info", prefix ".handshake.cred.pubkey",     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Delegated Credentials Subject Public Key Info", HFILL }        \
    },                                                                  \
    { & name .hf.hs_cred_pubkey_len,                                    \
      { "Subject Public Key Info Length", prefix ".handshake.cred.pubkey_len", \
        FT_UINT24, BASE_DEC, NULL, 0x0,                                 \
        "Delegated Credentials Subject Public Key Info Length", HFILL } \
    },                                                                  \
    { & name .hf.hs_cred_signature,                                     \
      { "Signature", prefix ".handshake.cred.signature",                \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Delegated Credentials Signature", HFILL }                      \
    },                                                                  \
    { & name .hf.hs_cred_signature_len,                                 \
      { "Signature Length", prefix ".handshake.cred.signature_len",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Delegated Credentials Signature Length", HFILL }               \
    },                                                                  \
    { & name .hf.hs_ext_compress_certificate_algorithms_length,         \
      { "Algorithms Length", prefix ".compress_certificate.algorithms_length", \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_compress_certificate_algorithm,                 \
      { "Algorithm", prefix ".compress_certificate.algorithm",          \
        FT_UINT16, BASE_DEC, VALS(compress_certificate_algorithm_vals), 0x00, \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_compress_certificate_uncompressed_length,       \
      { "Uncompressed Length", prefix ".compress_certificate.uncompressed_length", \
        FT_UINT24, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_compress_certificate_compressed_certificate_message_length, \
      { "Length", prefix ".compress_certificate.compressed_certificate_message.length", \
        FT_UINT24, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_compress_certificate_compressed_certificate_message, \
      { "Compressed Certificate Message", prefix ".compress_certificate.compressed_certificate_message", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_record_size_limit,                              \
      { "Record Size Limit", prefix ".record_size_limit",               \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        "Maximum record size that an endpoint is willing to receive", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_quictp_len,                                     \
      { "Parameters Length", prefix ".quic.len",                        \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter,                               \
      { "Parameter", prefix ".quic.parameter",                          \
        FT_NONE, BASE_NONE, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_type,                          \
      { "Type", prefix ".quic.parameter.type",                          \
        FT_UINT64, BASE_CUSTOM, CF_FUNC(quic_transport_parameter_id_base_custom), 0x00,    \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_len,                           \
      { "Length", prefix ".quic.parameter.length",                      \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_len_old,                       \
      { "Length", prefix ".quic.parameter.lengt.old",                   \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_value,                         \
      { "Value", prefix ".quic.parameter.value",                        \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_original_destination_connection_id, \
      { "original_destination_connection_id", prefix ".quic.parameter.original_destination_connection_id", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "Destination Connection ID from the first Initial packet sent by the client", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_max_idle_timeout,              \
      { "max_idle_timeout", prefix ".quic.parameter.max_idle_timeout",  \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "In milliseconds", HFILL }                                      \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_stateless_reset_token,         \
      { "stateless_reset_token", prefix ".quic.parameter.stateless_reset_token",    \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "Used in verifying a stateless reset", HFILL }                  \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_max_udp_payload_size,          \
      { "max_udp_payload_size", prefix ".quic.parameter.max_udp_payload_size", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Maximum UDP payload size that the endpoint is willing to receive", HFILL }    \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_data,              \
      { "initial_max_data", prefix ".quic.parameter.initial_max_data",  \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Contains the initial value for the maximum amount of data that can be sent on the connection", HFILL }                                                                 \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_stream_data_bidi_local, \
      { "initial_max_stream_data_bidi_local", prefix ".quic.parameter.initial_max_stream_data_bidi_local", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Initial stream maximum data for bidirectional, locally-initiated streams", HFILL }                                                                 \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_stream_data_bidi_remote, \
      { "initial_max_stream_data_bidi_remote", prefix ".quic.parameter.initial_max_stream_data_bidi_remote", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Initial stream maximum data for bidirectional, peer-initiated streams", HFILL }                                                                 \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_stream_data_uni,   \
      { "initial_max_stream_data_uni", prefix ".quic.parameter.initial_max_stream_data_uni", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Initial stream maximum data for unidirectional streams parameter", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_streams_bidi,      \
      { "initial_max_streams_bidi", prefix ".quic.parameter.initial_max_streams_bidi",  \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Initial maximum number of application-owned bidirectional streams", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_streams_uni,       \
      { "initial_max_streams_uni", prefix ".quic.parameter.initial_max_streams_uni",    \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Initial maximum number of application-owned unidirectional streams", HFILL }   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_ack_delay_exponent,            \
      { "ack_delay_exponent", prefix ".quic.parameter.ack_delay_exponent",  \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Indicating an exponent used to decode the ACK Delay field in the ACK frame,", HFILL }  \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_max_ack_delay,                 \
      { "max_ack_delay", prefix ".quic.parameter.max_ack_delay",        \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        "Indicating the maximum amount of time in milliseconds by which it will delay sending of acknowledgments", HFILL } \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_ipv4address,                \
      { "ipv4Address", prefix ".quic.parameter.preferred_address.ipv4address",  \
        FT_IPv4, BASE_NONE, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_ipv6address,                \
      { "ipv6Address", prefix ".quic.parameter.preferred_address.ipv6address",  \
        FT_IPv6, BASE_NONE, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_ipv4port,                   \
      { "ipv4Port", prefix ".quic.parameter.preferred_address.ipv4port", \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_ipv6port,                   \
      { "ipv6Port", prefix ".quic.parameter.preferred_address.ipv6port", \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_connectionid_length,        \
      { "Length", prefix ".quic.parameter.preferred_address.connectionid.length",   \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        "Length of connectionId Field", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_connectionid,               \
      { "connectionId", prefix ".quic.parameter.preferred_address.connectionid",    \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_pa_statelessresettoken,        \
      { "statelessResetToken", prefix ".quic.parameter.preferred_address.statelessresettoken",  \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_active_connection_id_limit,    \
      { "Active Connection ID Limit", prefix ".quic.parameter.active_connection_id_limit", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_source_connection_id,  \
      { "Initial Source Connection ID", prefix ".quic.parameter.initial_source_connection_id", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_retry_source_connection_id,    \
      { "Retry Source Connection ID", prefix ".quic.parameter.retry_source_connection_id", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_max_datagram_frame_size,       \
      { "max_datagram_frame_size", prefix ".quic.parameter.max_datagram_frame_size", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_cibir_encoding_length,         \
      { "length", prefix ".quic.parameter.cibir_encoding.length",       \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_cibir_encoding_offset,         \
      { "offset", prefix ".quic.parameter.cibir_encoding.offset",       \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_loss_bits,                     \
      { "loss_bits", prefix ".quic.parameter.loss_bits",                \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_enable_time_stamp_v2,          \
      { "Enable TimestampV2", prefix ".quic.parameter.enable_time_stamp_v2", \
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(quic_enable_time_stamp_v2_vals), 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_min_ack_delay,                 \
      { "min_ack_delay", prefix ".quic.parameter.min_ack_delay",        \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_user_agent_id,          \
      { "Google UserAgent", prefix ".quic.parameter.google.user_agent", \
        FT_STRING, BASE_NONE, NULL, 0x00,                               \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_key_update_not_yet_supported, \
      { "Google Key Update not yet supported", prefix ".quic.parameter.google.key_update_not_yet_supported", \
        FT_NONE, BASE_NONE, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_quic_version,           \
      { "Google QUIC version", prefix ".quic.parameter.google.quic_version", \
        FT_UINT32, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_version_vals), 0x00, \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_initial_rtt,            \
      { "Google Initial RTT", prefix ".quic.parameter.google.initial_rtt", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_support_handshake_done, \
      { "Google Support Handshake Done", prefix ".quic.parameter.google.support_handshake_done", \
        FT_NONE, BASE_NONE, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_quic_params,            \
      { "Google QUIC parameters", prefix ".quic.parameter.google.quic_params", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_quic_params_unknown_field, \
      { "Google Unknown Field", prefix ".quic.parameter.google.quic_params_unknown_field", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_connection_options,     \
      { "Google Connection options", prefix ".quic.parameter.google.connection_options", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_supported_versions_length, \
      { "Google Supported Versions Length", prefix ".quic.parameter.google.supported_versions_length", \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_google_supported_version,      \
      { "Google Supported Version", prefix ".quic.parameter.google.supported_version", \
        FT_UINT32, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_version_vals), 0x00, \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_facebook_partial_reliability,     \
      { "Facebook Partial Reliability", prefix ".quic.parameter.facebook.partial_reliability", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_chosen_version,                \
      { "Chosen Version", prefix ".quic.parameter.vi.chosen_version",   \
        FT_UINT32, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_version_vals), 0x00, \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_other_version,                 \
      { "Other Version", prefix ".quic.parameter.vi.other_version",     \
        FT_UINT32, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_version_vals), 0x00, \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_connection_id_length,                           \
      { "Connection ID length", prefix ".connection_id_length",         \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_connection_id,                                  \
      { "Connection ID", prefix ".connection_id",                       \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.esni_suite,                                            \
      { "Cipher Suite", prefix ".esni.suite",                           \
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ssl_31_ciphersuite_ext, 0x0, \
        "Cipher suite used to encrypt the SNI", HFILL }                 \
    },                                                                  \
    { & name .hf.esni_record_digest_length,                             \
      { "Record Digest Length", prefix ".esni.record_digest_length",    \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.esni_record_digest,                                    \
      { "Record Digest", prefix ".esni.record_digest",                  \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "Cryptographic hash of the ESNIKeys from which the ESNI key was obtained", HFILL } \
    },                                                                  \
    { & name .hf.esni_encrypted_sni_length,                             \
      { "Encrypted SNI Length", prefix ".esni.encrypted_sni_length",    \
        FT_UINT16, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.esni_encrypted_sni,                                    \
      { "Encrypted SNI", prefix ".esni.encrypted_sni",                  \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "The encrypted ClientESNIInner structure", HFILL }              \
    },                                                                  \
    { & name .hf.esni_nonce,                                            \
      { "Nonce", prefix ".esni.nonce",                                  \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "Contents of ClientESNIInner.nonce", HFILL }                    \
    },                                                                  \
    { & name .hf.hs_ext_alps_len,                                       \
      { "ALPS Extension Length", prefix ".handshake.extensions_alps_len", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of the ALPS Extension", HFILL }                         \
    },                                                                  \
    { & name .hf.hs_ext_alps_alpn_list,                                 \
      { "Supported ALPN List", prefix ".handshake.extensions_alps_alpn_list", \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of supported ALPN by ALPS", HFILL }                       \
    },                                                                  \
    { & name .hf.hs_ext_alps_alpn_str_len,                              \
      { "Supported ALPN Length", prefix ".handshake.extensions_alps_alpn_str_len", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of ALPN string", HFILL }                                \
    },                                                                  \
    { & name .hf.hs_ext_alps_alpn_str,                                  \
      { "Supported ALPN", prefix ".handshake.extensions_alps_alpn_str", \
        FT_STRING, BASE_NONE, NULL, 0x00,                               \
        "ALPN supported by ALPS", HFILL }                               \
    },                                                                  \
    { & name .hf.hs_ext_alps_settings,                                  \
      { "ALPN Opaque Settings", prefix ".handshake.extensions_alps.settings", \
        FT_BYTES, BASE_NONE, NULL, 0x00,                                \
        "ALPN Opaque Settings", HFILL }                                 \
    }
/* }}} */

/* {{{ */
#define SSL_COMMON_ETT_LIST(name)                   \
        & name .ett.hs_ext,                         \
        & name .ett.hs_ext_alpn,                    \
        & name .ett.hs_ext_cert_types,              \
        & name .ett.hs_ext_groups,                  \
        & name .ett.hs_ext_curves_point_formats,    \
        & name .ett.hs_ext_npn,                     \
        & name .ett.hs_ext_reneg_info,              \
        & name .ett.hs_ext_key_share,               \
        & name .ett.hs_ext_key_share_ks,            \
        & name .ett.hs_ext_pre_shared_key,          \
        & name .ett.hs_ext_psk_identity,            \
        & name .ett.hs_ext_server_name,             \
        & name .ett.hs_ext_oid_filter,              \
        & name .ett.hs_ext_quictp_parameter,        \
        & name .ett.hs_sig_hash_alg,                \
        & name .ett.hs_sig_hash_algs,               \
        & name .ett.urlhash,                        \
        & name .ett.keyex_params,                   \
        & name .ett.certificates,                   \
        & name .ett.cert_types,                     \
        & name .ett.dnames,                         \
        & name .ett.hs_random,                      \
        & name .ett.cipher_suites,                  \
        & name .ett.comp_methods,                   \
        & name .ett.session_ticket,                 \
        & name .ett.sct,                            \
        & name .ett.cert_status,                    \
        & name .ett.ocsp_response,                  \
        & name .ett.uncompressed_certificates,      \
        & name .ett.hs_ext_alps,                    \
/* }}} */

/* {{{ */
#define SSL_COMMON_EI_LIST(name, prefix)                       \
    { & name .ei.malformed_vector_length, \
        { prefix ".malformed.vector_length", PI_PROTOCOL, PI_WARN, \
        "Variable vector length is outside the permitted range", EXPFILL } \
    }, \
    { & name .ei.malformed_buffer_too_small, \
        { prefix ".malformed.buffer_too_small", PI_MALFORMED, PI_ERROR, \
        "Malformed message, not enough data is available", EXPFILL } \
    }, \
    { & name .ei.malformed_trailing_data, \
        { prefix ".malformed.trailing_data", PI_PROTOCOL, PI_WARN, \
        "Undecoded trailing data is present", EXPFILL } \
    }, \
    { & name .ei.hs_ext_cert_status_undecoded, \
        { prefix ".handshake.status_request.undecoded", PI_UNDECODED, PI_NOTE, \
        "Responder ID list or Request Extensions are not implemented, contact Wireshark developers if you want this to be supported", EXPFILL } \
    }, \
    { & name .ei.resumed, \
        { prefix ".resumed", PI_SEQUENCE, PI_NOTE, \
        "This session reuses previously negotiated keys (Session resumption)", EXPFILL } \
    }, \
    { & name .ei.record_length_invalid, \
        { prefix ".record.length.invalid", PI_PROTOCOL, PI_ERROR, \
        "Record fragment length is too small or too large", EXPFILL } \
    }, \
    { & name .ei.decompression_error, \
        { prefix ".decompression_error", PI_PROTOCOL, PI_ERROR, \
        "Decompression error", EXPFILL } \
    }
/* }}} */

extern void
ssl_common_register_ssl_alpn_dissector_table(const char *name,
    const char *ui_name, const int proto);

extern void
ssl_common_register_dtls_alpn_dissector_table(const char *name,
    const char *ui_name, const int proto);

extern void
ssl_common_register_options(module_t *module, ssl_common_options_t *options, gboolean is_dtls);

#ifdef SSL_DECRYPT_DEBUG
extern void
ssl_debug_printf(const gchar* fmt,...) G_GNUC_PRINTF(1,2);
extern void
ssl_print_data(const gchar* name, const guchar* data, size_t len);
extern void
ssl_print_string(const gchar* name, const StringInfo* data);
extern void
ssl_set_debug(const gchar* name);
extern void
ssl_debug_flush(void);
#else

/* No debug: nullify debug operation*/
static inline void G_GNUC_PRINTF(1,2)
ssl_debug_printf(const gchar* fmt _U_,...)
{
}
#define ssl_print_data(a, b, c)
#define ssl_print_string(a, b)
#define ssl_set_debug(name)
#define ssl_debug_flush()

#endif /* SSL_DECRYPT_DEBUG */

#endif /* __PACKET_TLS_UTILS_H__ */

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
