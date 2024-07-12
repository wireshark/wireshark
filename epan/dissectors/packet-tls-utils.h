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
    SSL_ID_TLS12_CID               = 0x19,
    SSL_ID_DTLS13_ACK              = 0x1A,
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
#define SSL_HND_HELLO_EXT_ENCRYPTED_CLIENT_HELLO        65037 /* 0xfe0d draft-ietf-tls-esni-16 */
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
#define SSL_HND_QUIC_TP_VERSION_INFORMATION                 0x11 /* https://tools.ietf.org/html/draft-ietf-quic-version-negotiation-14 */
#define SSL_HND_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE             0x20 /* https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram-06 */
#define SSL_HND_QUIC_TP_CIBIR_ENCODING                      0x1000 /* https://datatracker.ietf.org/doc/html/draft-banks-quic-cibir-01 */
#define SSL_HND_QUIC_TP_LOSS_BITS                           0x1057 /* https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03 */
#define SSL_HND_QUIC_TP_GREASE_QUIC_BIT                     0x2ab2 /* RFC 9287 */
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
#define SSL_HND_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1              0xFF03DE1A /* https://tools.ietf.org/html/draft-ietf-quic-ack-frequency-01 */
#define SSL_HND_QUIC_TP_MIN_ACK_DELAY_DRAFT05               0xff04de1a /* https://tools.ietf.org/html/draft-ietf-quic-ack-frequency-04 / draft-05 */
#define SSL_HND_QUIC_TP_MIN_ACK_DELAY                       0xff04de1b /* https://tools.ietf.org/html/draft-ietf-quic-ack-frequency-07 */
#define SSL_HND_QUIC_TP_ENABLE_MULTIPATH_DRAFT04            0x0f739bbc1b666d04 /* https://tools.ietf.org/html/draft-ietf-quic-multipath-04 */
#define SSL_HND_QUIC_TP_ENABLE_MULTIPATH_DRAFT05            0x0f739bbc1b666d05 /* https://tools.ietf.org/html/draft-ietf-quic-multipath-05 */
#define SSL_HND_QUIC_TP_ENABLE_MULTIPATH                    0x0f739bbc1b666d06 /* https://tools.ietf.org/html/draft-ietf-quic-multipath-06 */
#define SSL_HND_QUIC_TP_INITIAL_MAX_PATHS                   0x0f739bbc1b666d07 /* https://tools.ietf.org/html/draft-ietf-quic-multipath-07 */
#define SSL_HND_QUIC_TP_INITIAL_MAX_PATH_ID                 0x0f739bbc1b666d09 /* https://tools.ietf.org/html/draft-ietf-quic-multipath-09 */

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
extern const val64_string quic_transport_parameter_id[];
extern const range_string quic_version_vals[];
extern const val64_string quic_enable_time_stamp_v2_vals[];
extern const val64_string quic_enable_multipath_vals[];
extern const value_string tls_hello_ext_ech_clienthello_types[];
extern const value_string kem_id_type_vals[];
extern const value_string kdf_id_type_vals[];
extern const value_string aead_id_type_vals[];
extern const value_string token_binding_key_parameter_vals[];

/* XXX Should we use GByteArray instead? */
typedef struct _StringInfo {
    unsigned char  *data;      /* Backing storage which may be larger than data_len */
    unsigned data_len;  /* Length of the meaningful part of data */
} StringInfo;

#define SSL_WRITE_KEY           1

#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLCPV1_VERSION         0x101
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd
#define DTLSV1DOT3_VERSION     0xfefc

/* Returns the TLS 1.3 draft version or 0 if not applicable. */
static inline uint8_t extract_tls13_draft_version(uint32_t version) {
    if ((version & 0xff00) == 0x7f00) {
        return (uint8_t) version;
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
    MODE_ECB, /* ECB: used to perform record seq number encryption in DTLSv1.3 */
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
    int number;
    int kex;
    int enc;
    int dig;
    ssl_cipher_mode_t mode;
} SslCipherSuite;

typedef struct _SslFlow {
    uint32_t byte_seq;
    uint16_t flags;
    wmem_tree_t *multisegment_pdus;
} SslFlow;

typedef struct _SslDecompress SslDecompress;

typedef struct _SslDecoder {
    const SslCipherSuite *cipher_suite;
    int compression;
    unsigned char _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX sn_evp; /* used to decrypt serial number in DTLSv1.3 */
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    uint64_t dtls13_epoch;
    uint64_t seq;    /**< Implicit (TLS) or explicit (DTLS) record sequence number. */
    StringInfo dtls13_aad;  /**< Additional Authenticated Data for DTLS 1.3. */
    uint16_t epoch;
    SslFlow *flow;
    StringInfo app_traffic_secret;  /**< TLS 1.3 application traffic secret (if applicable), wmem file scope. */
} SslDecoder;

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
    const char *name;
    unsigned len;
} SslDigestAlgo;

typedef struct _SslRecordInfo {
    unsigned char *plain_data;     /**< Decrypted data. */
    unsigned   data_len;       /**< Length of decrypted data. */
    int     id;             /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    ContentType type;       /**< Content type of the decrypted record data. */
    SslFlow *flow;          /**< Flow where this record fragment is a part of.
                                 Can be NULL if this record type may not be fragmented. */
    uint32_t seq;            /**< Data offset within the flow. */
    uint16_t dtls13_seq_suffix;   /* < decrypted dtlsv1.3 record number suffix */
    struct _SslRecordInfo* next;
} SslRecordInfo;

/**
 * Stored information about a part of a reassembled handshake message. A single
 * handshake record is uniquely identified by (record_id, reassembly_id).
 */
typedef struct _TlsHsFragment {
    unsigned   record_id;      /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    unsigned   reassembly_id;  /**< Identifies the reassembly that this fragment is part of. */
    uint32_t offset;         /**< Offset within a reassembly. */
    uint8_t type;           /**< Handshake type (first byte of the buffer). */
    int     is_last : 1;    /**< Whether this fragment completes the message. */
    struct _TlsHsFragment *next;
} TlsHsFragment;

typedef struct {
    SslRecordInfo *records; /**< Decrypted records within this frame. */
    TlsHsFragment *hs_fragments;    /**< Handshake records that are part of a reassembly. */
    uint32_t srcport;        /**< Used for Decode As */
    uint32_t destport;
    int cipher;            /**< Cipher at time of Key Exchange handshake message.
                                 Session cipher can change in renegotiation. */
} SslPacketInfo;

typedef struct _SslSession {
    int cipher;
    int compression;
    uint16_t version;
    unsigned char tls13_draft_version;
    int8_t client_cert_type;
    int8_t server_cert_type;
    uint32_t client_ccs_frame;
    uint32_t server_ccs_frame;

    /* The address/proto/port of the server as determined from heuristics
     * (e.g. ClientHello) or set externally (via ssl_set_master_secret()). */
    address srv_addr;
    port_type srv_ptype;
    unsigned srv_port;

    /* The Application layer protocol if known (for STARTTLS support) */
    dissector_handle_t   app_handle;
    const char          *alpn_name;
    /* The ALPN the client requested, not necessarily the one chosen */
    const char          *client_alpn_name;
    uint32_t             last_nontls_frame;
    bool                 is_session_resumed;

    /* First pass only: track an in-progress handshake reassembly (>0) */
    uint32_t    client_hs_reassembly_id;
    uint32_t    server_hs_reassembly_id;

    /* Connection ID extension

    struct {
        opaque cid<0..2^8-1>;
    } ConnectionId;
    */

    uint8_t *client_cid;
    uint8_t *server_cid;
    uint8_t client_cid_len;
    bool client_cid_len_present;
    uint8_t server_cid_len;
    bool server_cid_len_present;
    bool deprecated_cid; /* Set when handshake is using the deprecated CID extension type */
    uint64_t dtls13_current_epoch[2]; /* max epoch (for server and client respectively) */
    uint64_t dtls13_next_seq_num[2]; /* DTLSv1.3 next expected seq number (for server and client respectively) */
} SslSession;

/* RFC 5246, section 8.1 says that the master secret is always 48 bytes */
#define SSL_MASTER_SECRET_LENGTH        48

struct cert_key_id; /* defined in epan/secrets.h */

/* This holds state information for a SSL conversation */
typedef struct _SslDecryptSession {
    unsigned char _master_secret[SSL_MASTER_SECRET_LENGTH];
    unsigned char _session_id[256];
    unsigned char _client_random[32];
    unsigned char _server_random[32];
    StringInfo session_id;
    StringInfo session_ticket;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    StringInfo handshake_data;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    unsigned char _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    unsigned char _client_data_for_iv[24];
    StringInfo client_data_for_iv;

    int state;
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
    bool       has_early_data;

} SslDecryptSession;

/* RecordNumber - RFC 9147 section 4 */
typedef struct {
    uint64_t epoch;
    uint64_t sequence_number;
} SslRecordNumber;

/* User Access Table */
typedef struct _ssldecrypt_assoc_t {
    char* ipaddr;
    char* port;
    char* protocol;
    char* keyfile;
    char* password;
} ssldecrypt_assoc_t;

typedef struct ssl_common_options {
    const char         *psk;
    const char         *keylog_filename;
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

    /* The hash tables above store the static keylog file contents and secrets
     * from any DSB, not all of which may be used, in addition to any master
     * secrets derived at runtime ([D]TLS < 1.3). These store the used
     * Client Random for exporting master secrets and derived secrets in
     * TLS Export Sessions or adding a DSB.
     */
    GHashTable *used_crandom;
} ssl_master_key_map_t;

int ssl_get_keyex_alg(int cipher);

void quic_transport_parameter_id_base_custom(char *result, uint64_t parameter_id);

bool ssldecrypt_uat_fld_ip_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
bool ssldecrypt_uat_fld_port_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
bool ssldecrypt_uat_fld_fileopen_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
bool ssldecrypt_uat_fld_password_chk_cb(void*, const char*, unsigned, const void*, const void*, char** err);
char* ssl_association_info(const char* dissector_table_name, const char* table_protocol);

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
SslDecryptSession *ssl_get_session_by_cid(tvbuff_t *tvb, uint32_t offset);

/** Retrieve a SslSession, creating it if it did not already exist.
 * @param conversation The SSL conversation.
 * @param tls_handle The dissector handle for SSL or DTLS.
 */
extern SslDecryptSession *
ssl_get_session(conversation_t *conversation, dissector_handle_t tls_handle);

/** Resets the decryption parameters for the next decoder. */
extern void
ssl_reset_session(SslSession *session, SslDecryptSession *ssl, bool is_client);

/** Set server address and port */
extern void
ssl_set_server(SslSession *session, address *addr, port_type ptype, uint32_t port);

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
WS_DLL_PUBLIC uint32_t
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
WS_DLL_PUBLIC uint32_t
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
ssl_data_set(StringInfo* buf, const unsigned char* src, unsigned len);

/** alloc the data with the specified len for the stringInfo buffer.
 @param str the data source
 @param len the source data len */
extern int
ssl_data_alloc(StringInfo* str, size_t len);

extern int
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, unsigned char* iv, int iv_len);

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
unsigned
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite);

bool
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session,
                               uint32_t length, tvbuff_t *tvb, uint32_t offset,
                               const char *ssl_psk, packet_info *pinfo,
#ifdef HAVE_LIBGNUTLS
                               GHashTable *key_hash,
#endif
                               const ssl_master_key_map_t *mk_map);

/** Expand the pre_master_secret to generate all the session information
 * (master secret, session keys, ivs)
 @param ssl_session the store for all the session data
 @return 0 on success */
extern int
ssl_generate_keyring_material(SslDecryptSession*ssl_session);

extern void
ssl_change_cipher(SslDecryptSession *ssl_session, bool server);

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
extern int
ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, uint8_t ct, uint16_t record_version,
        bool ignore_mac_failed,
        const unsigned char *in, uint16_t inl, const unsigned char *cid, uint8_t cidl,
        StringInfo *comp_str, StringInfo *out_str, unsigned *outl);


/* Common part between TLS and DTLS dissectors */

/* handling of association between tls/dtls ports and clear text protocol */
extern void
ssl_association_add(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, unsigned port, bool tcp);

extern void
ssl_association_remove(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, unsigned port, bool tcp);

extern int
ssl_packet_from_server(SslSession *session, dissector_table_t table, const packet_info *pinfo);

/* Obtain information about the current TLS layer. */
SslPacketInfo *
tls_add_packet_info(int proto, packet_info *pinfo, uint8_t curr_layer_num_ssl);

/* add to packet data a copy of the specified real data */
extern void
ssl_add_record_info(int proto, packet_info *pinfo, const unsigned char *data, int data_len, int record_id, SslFlow *flow, ContentType type, uint8_t curr_layer_num_ssl);

/* search in packet data for the specified id; return a newly created tvb for the associated data */
extern tvbuff_t*
ssl_get_record_info(tvbuff_t *parent_tvb, int proto, packet_info *pinfo, int record_id, uint8_t curr_layer_num_ssl, SslRecordInfo **matched_record);

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
WS_DLL_PUBLIC ssl_master_key_map_t *
tls_get_master_key_map(bool load_secrets);

/* Process lines from the TLS key log and populate the secrets map. */
extern void
tls_keylog_process_lines(const ssl_master_key_map_t *mk_map, const uint8_t *data, unsigned len);

/* tries to update the secrets cache from the given filename */
extern void
ssl_load_keyfile(const char *ssl_keylog_filename, FILE **keylog_file,
                 const ssl_master_key_map_t *mk_map);

#ifdef HAVE_LIBGNUTLS
/* parse ssl related preferences (private keys and ports association strings) */
extern void
ssl_parse_key_list(const ssldecrypt_assoc_t * uats, GHashTable *key_hash, const char* dissector_table_name, dissector_handle_t main_handle, bool tcp);
#endif

extern void
ssl_finalize_decryption(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map);

/**
 * Mark a Client Random as used (not just present in the keylog file),
 * to enable "Export TLS Sessions Keys" or "Inject Secrets"
 */
extern void
tls_save_crandom(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map);

extern bool
tls13_generate_keys(SslDecryptSession *ssl_session, const StringInfo *secret, bool is_from_server);

extern StringInfo *
tls13_load_secret(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                  bool is_from_server, TLSRecordType type);

extern void
tls13_change_key(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                 bool is_from_server, TLSRecordType type);

extern void
tls13_key_update(SslDecryptSession *ssl, bool is_from_server);

extern bool
ssl_is_valid_content_type(uint8_t type);

extern bool
ssl_is_valid_handshake_type(uint8_t hs_type, bool is_dtls);

extern bool
tls_scan_server_hello(tvbuff_t *tvb, uint32_t offset, uint32_t offset_end,
                      uint16_t *server_version, bool *is_hrr);

extern void
ssl_try_set_version(SslSession *session, SslDecryptSession *ssl,
                    uint8_t content_type, uint8_t handshake_type,
                    bool is_dtls, uint16_t version);

extern void
ssl_calculate_handshake_hash(SslDecryptSession *ssl_session, tvbuff_t *tvb, uint32_t offset, uint32_t length);

/* common header fields, subtrees and expert info for SSL and DTLS dissectors */
typedef struct ssl_common_dissect {
    struct {
        int change_cipher_spec;
        int hs_exts_len;
        int hs_ext_alpn_len;
        int hs_ext_alpn_list;
        int hs_ext_alpn_str;
        int hs_ext_alpn_str_len;
        int hs_ext_cert_url_item;
        int hs_ext_cert_url_padding;
        int hs_ext_cert_url_sha1;
        int hs_ext_cert_url_type;
        int hs_ext_cert_url_url;
        int hs_ext_cert_url_url_hash_list_len;
        int hs_ext_cert_url_url_len;
        int hs_ext_cert_status_type;
        int hs_ext_cert_status_request_len;
        int hs_ext_cert_status_responder_id_list_len;
        int hs_ext_cert_status_request_extensions_len;
        int hs_ext_cert_status_request_list_len;
        int hs_ocsp_response_list_len;
        int hs_ocsp_response_len;
        int hs_ext_cert_type;
        int hs_ext_cert_types;
        int hs_ext_cert_types_len;
        int hs_ext_data;
        int hs_ext_ec_point_format;
        int hs_ext_ec_point_formats;
        int hs_ext_ec_point_formats_len;
        int hs_ext_srp_len;
        int hs_ext_srp_username;
        int hs_ext_supported_group;
        int hs_ext_supported_groups;
        int hs_ext_supported_groups_len;
        int hs_ext_heartbeat_mode;
        int hs_ext_len;
        int hs_ext_npn_str;
        int hs_ext_npn_str_len;
        int hs_ext_reneg_info_len;
        int hs_ext_reneg_info;
        int hs_ext_key_share_client_length;
        int hs_ext_key_share_group;
        int hs_ext_key_share_key_exchange_length;
        int hs_ext_key_share_key_exchange;
        int hs_ext_key_share_selected_group;
        int hs_ext_psk_identities_length;
        int hs_ext_psk_identity_identity_length;
        int hs_ext_psk_identity_identity;
        int hs_ext_psk_identity_obfuscated_ticket_age;
        int hs_ext_psk_binders_length;
        int hs_ext_psk_binders;
        int hs_ext_psk_identity_selected;
        int hs_ext_session_ticket;
        int hs_ext_supported_versions_len;
        int hs_ext_supported_version;
        int hs_ext_cookie_len;
        int hs_ext_cookie;
        int hs_ext_server_name;
        int hs_ext_server_name_len;
        int hs_ext_server_name_list_len;
        int hs_ext_server_name_type;
        int hs_ext_max_fragment_length;
        int hs_ext_padding_data;
        int hs_ext_type;
        int hs_ext_connection_id_length;
        int hs_ext_connection_id;
        int hs_sig_hash_alg;
        int hs_sig_hash_alg_len;
        int hs_sig_hash_algs;
        int hs_sig_hash_hash;
        int hs_sig_hash_sig;
        int hs_client_keyex_epms_len;
        int hs_client_keyex_epms;
        int hs_server_keyex_modulus_len;
        int hs_server_keyex_exponent_len;
        int hs_server_keyex_sig_len;
        int hs_server_keyex_p_len;
        int hs_server_keyex_g_len;
        int hs_server_keyex_ys_len;
        int hs_client_keyex_yc_len;
        int hs_client_keyex_point_len;
        int hs_server_keyex_point_len;
        int hs_server_keyex_p;
        int hs_server_keyex_g;
        int hs_server_keyex_curve_type;
        int hs_server_keyex_named_curve;
        int hs_server_keyex_ys;
        int hs_client_keyex_yc;
        int hs_server_keyex_point;
        int hs_client_keyex_point;
        int hs_server_keyex_xs_len;
        int hs_client_keyex_xc_len;
        int hs_server_keyex_xs;
        int hs_client_keyex_xc;
        int hs_server_keyex_vs_len;
        int hs_client_keyex_vc_len;
        int hs_server_keyex_vs;
        int hs_client_keyex_vc;
        int hs_server_keyex_rs_len;
        int hs_client_keyex_rc_len;
        int hs_server_keyex_rs;
        int hs_client_keyex_rc;
        int hs_server_keyex_modulus;
        int hs_server_keyex_exponent;
        int hs_server_keyex_sig;
        int hs_server_keyex_hint_len;
        int hs_server_keyex_hint;
        int hs_client_keyex_identity_len;
        int hs_client_keyex_identity;
        int hs_certificates_len;
        int hs_certificates;
        int hs_certificate_len;
        int hs_certificate;
        int hs_cert_types_count;
        int hs_cert_types;
        int hs_cert_type;
        int hs_dnames_len;
        int hs_dnames;
        int hs_dnames_truncated;
        int hs_dname_len;
        int hs_dname;
        int hs_random;
        int hs_random_time;
        int hs_random_bytes;
        int hs_session_id;
        int hs_session_id_len;
        int hs_client_version;
        int hs_server_version;
        int hs_cipher_suites_len;
        int hs_cipher_suites;
        int hs_cipher_suite;
        int hs_comp_methods_len;
        int hs_comp_methods;
        int hs_comp_method;
        int hs_session_ticket_lifetime_hint;
        int hs_session_ticket_age_add;
        int hs_session_ticket_nonce_len;
        int hs_session_ticket_nonce;
        int hs_session_ticket_len;
        int hs_session_ticket;
        int hs_finished;
        int hs_client_cert_vrfy_sig_len;
        int hs_client_cert_vrfy_sig;
        int hs_ja3_full;
        int hs_ja3_hash;
        int hs_ja3s_full;
        int hs_ja3s_hash;
        int hs_ja4;
        int hs_ja4_r;

        /* TLS 1.3 */
        int hs_ext_psk_ke_modes_length;
        int hs_ext_psk_ke_mode;
        int hs_certificate_request_context_length;
        int hs_certificate_request_context;
        int hs_key_update_request_update;
        int sct_scts_length;
        int sct_sct_length;
        int sct_sct_version;
        int sct_sct_logid;
        int sct_sct_timestamp;
        int sct_sct_extensions_length;
        int sct_sct_extensions;
        int sct_sct_signature;
        int sct_sct_signature_length;
        int hs_ext_max_early_data_size;
        int hs_ext_oid_filters_length;
        int hs_ext_oid_filters_oid_length;
        int hs_ext_oid_filters_oid;
        int hs_ext_oid_filters_values_length;
        int hs_cred_valid_time;
        int hs_cred_pubkey;
        int hs_cred_pubkey_len;
        int hs_cred_signature;
        int hs_cred_signature_len;

        /* compress_certificate */
        int hs_ext_compress_certificate_algorithms_length;
        int hs_ext_compress_certificate_algorithm;
        int hs_ext_compress_certificate_uncompressed_length;
        int hs_ext_compress_certificate_compressed_certificate_message_length;
        int hs_ext_compress_certificate_compressed_certificate_message;

        /* Token Binding Negotiation */
        int hs_ext_token_binding_version_major;
        int hs_ext_token_binding_version_minor;
        int hs_ext_token_binding_key_parameters;
        int hs_ext_token_binding_key_parameters_length;
        int hs_ext_token_binding_key_parameter;

        int hs_ext_record_size_limit;

        /* QUIC Transport Parameters */
        int hs_ext_quictp_len;
        int hs_ext_quictp_parameter;
        int hs_ext_quictp_parameter_type;
        int hs_ext_quictp_parameter_len;
        int hs_ext_quictp_parameter_len_old;
        int hs_ext_quictp_parameter_value;
        int hs_ext_quictp_parameter_original_destination_connection_id;
        int hs_ext_quictp_parameter_max_idle_timeout;
        int hs_ext_quictp_parameter_stateless_reset_token;
        int hs_ext_quictp_parameter_initial_max_data;
        int hs_ext_quictp_parameter_initial_max_stream_data_bidi_local;
        int hs_ext_quictp_parameter_initial_max_stream_data_bidi_remote;
        int hs_ext_quictp_parameter_initial_max_stream_data_uni;
        int hs_ext_quictp_parameter_initial_max_streams_bidi;
        int hs_ext_quictp_parameter_initial_max_streams_uni;
        int hs_ext_quictp_parameter_ack_delay_exponent;
        int hs_ext_quictp_parameter_max_ack_delay;
        int hs_ext_quictp_parameter_max_udp_payload_size;
        int hs_ext_quictp_parameter_pa_ipv4address;
        int hs_ext_quictp_parameter_pa_ipv6address;
        int hs_ext_quictp_parameter_pa_ipv4port;
        int hs_ext_quictp_parameter_pa_ipv6port;
        int hs_ext_quictp_parameter_pa_connectionid_length;
        int hs_ext_quictp_parameter_pa_connectionid;
        int hs_ext_quictp_parameter_pa_statelessresettoken;
        int hs_ext_quictp_parameter_active_connection_id_limit;
        int hs_ext_quictp_parameter_initial_source_connection_id;
        int hs_ext_quictp_parameter_retry_source_connection_id;
        int hs_ext_quictp_parameter_max_datagram_frame_size;
        int hs_ext_quictp_parameter_cibir_encoding_length;
        int hs_ext_quictp_parameter_cibir_encoding_offset;
        int hs_ext_quictp_parameter_loss_bits;
        int hs_ext_quictp_parameter_enable_time_stamp_v2;
        int hs_ext_quictp_parameter_min_ack_delay;
        int hs_ext_quictp_parameter_google_user_agent_id;
        int hs_ext_quictp_parameter_google_key_update_not_yet_supported;
        int hs_ext_quictp_parameter_google_quic_version;
        int hs_ext_quictp_parameter_google_initial_rtt;
        int hs_ext_quictp_parameter_google_support_handshake_done;
        int hs_ext_quictp_parameter_google_quic_params;
        int hs_ext_quictp_parameter_google_quic_params_unknown_field;
        int hs_ext_quictp_parameter_google_connection_options;
        int hs_ext_quictp_parameter_google_supported_versions_length;
        int hs_ext_quictp_parameter_google_supported_version;
        int hs_ext_quictp_parameter_facebook_partial_reliability;
        int hs_ext_quictp_parameter_chosen_version;
        int hs_ext_quictp_parameter_other_version;
        int hs_ext_quictp_parameter_enable_multipath;
        int hs_ext_quictp_parameter_initial_max_paths;
        int hs_ext_quictp_parameter_initial_max_path_id;

        int esni_suite;
        int esni_record_digest_length;
        int esni_record_digest;
        int esni_encrypted_sni_length;
        int esni_encrypted_sni;
        int esni_nonce;

        int ech_echconfiglist_length;
        int ech_echconfiglist;
        int ech_echconfig;
        int ech_echconfig_version;
        int ech_echconfig_length;
        int ech_echconfigcontents_maximum_name_length;
        int ech_echconfigcontents_public_name_length;
        int ech_echconfigcontents_public_name;
        int ech_echconfigcontents_extensions_length;
        int ech_echconfigcontents_extensions;
        int ech_hpke_keyconfig;
        int ech_hpke_keyconfig_config_id;
        int ech_hpke_keyconfig_kem_id;
        int ech_hpke_keyconfig_public_key_length;
        int ech_hpke_keyconfig_public_key;
        int ech_hpke_keyconfig_cipher_suites;
        int ech_hpke_keyconfig_cipher_suites_length;
        int ech_hpke_keyconfig_cipher_suite;
        int ech_hpke_keyconfig_cipher_suite_kdf_id;
        int ech_hpke_keyconfig_cipher_suite_aead_id;
        int ech_clienthello_type;
        int ech_cipher_suite;
        int ech_config_id;
        int ech_enc_length;
        int ech_enc;
        int ech_payload_length;
        int ech_payload;
        int ech_confirmation;
        int ech_retry_configs;

        int hs_ext_alps_len;
        int hs_ext_alps_alpn_list;
        int hs_ext_alps_alpn_str;
        int hs_ext_alps_alpn_str_len;
        int hs_ext_alps_settings;

        /* do not forget to update SSL_COMMON_HF_LIST! */
    } hf;
    struct {
        int hs_ext;
        int hs_ext_alpn;
        int hs_ext_cert_types;
        int hs_ext_groups;
        int hs_ext_curves_point_formats;
        int hs_ext_npn;
        int hs_ext_reneg_info;
        int hs_ext_key_share;
        int hs_ext_key_share_ks;
        int hs_ext_pre_shared_key;
        int hs_ext_psk_identity;
        int hs_ext_server_name;
        int hs_ext_oid_filter;
        int hs_ext_quictp_parameter;
        int hs_sig_hash_alg;
        int hs_sig_hash_algs;
        int urlhash;
        int keyex_params;
        int certificates;
        int cert_types;
        int dnames;
        int hs_random;
        int cipher_suites;
        int comp_methods;
        int session_ticket;
        int sct;
        int cert_status;
        int ocsp_response;
        int uncompressed_certificates;
        int hs_ext_alps;
        int ech_echconfiglist;
        int ech_echconfig;
        int ech_retry_configs;
        int ech_hpke_keyconfig;
        int ech_hpke_cipher_suites;
        int ech_hpke_cipher_suite;
        int hs_ext_token_binding_key_parameters;

        /* do not forget to update SSL_COMMON_ETT_LIST! */
    } ett;
    struct {
        /* Generic expert info for malformed packets. */
        expert_field client_version_error;
        expert_field server_version_error;
        expert_field legacy_version;
        expert_field malformed_vector_length;
        expert_field malformed_buffer_too_small;
        expert_field malformed_trailing_data;

        expert_field hs_ext_cert_status_undecoded;
        expert_field hs_ciphersuite_undecoded;
        expert_field hs_srv_keyex_illegal;
        expert_field resumed;
        expert_field record_length_invalid;
        expert_field decompression_error;

        expert_field ech_echconfig_invalid_version;

        /* do not forget to update SSL_COMMON_EI_LIST! */
    } ei;
} ssl_common_dissect_t;

/* Header fields specific to DTLS. See packet-dtls.c */
typedef struct {
    int hf_dtls_handshake_cookie_len;
    int hf_dtls_handshake_cookie;

    /* Do not forget to initialize dtls_hfs to -1 in packet-dtls.c! */
} dtls_hfs_t;

/* Header fields specific to SSL. See packet-tls.c */
typedef struct {
    int hs_md5_hash;
    int hs_sha_hash;

    /* Do not forget to initialize ssl_hfs to -1 in packet-tls.c! */
} ssl_hfs_t;

typedef struct {
    uint32_t       max_version;
    bool           server_name_present;
    int            num_cipher_suites;
    int            num_extensions;
    wmem_strbuf_t *alpn;
    wmem_list_t   *cipher_list;
    wmem_list_t   *extension_list;
    wmem_list_t   *sighash_list;
} ja4_data_t;


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
 * Returns true if there is enough space for the length field and data elements
 * and false otherwise.
 */
extern bool
ssl_add_vector(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               unsigned offset, unsigned offset_end, uint32_t *ret_length,
               int hf_length, uint32_t min_value, uint32_t max_value);

/**
 * Helper to check whether the data in a vector with multiple elements is
 * correctly dissected. If the current "offset" (normally the value after
 * adding all kinds of fields) does not match "offset_end" (the end of the
 * vector), expert info is added.
 *
 * Returns true if the offset matches the end of the vector and false otherwise.
 */
extern bool
ssl_end_vector(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               unsigned offset, unsigned offset_end);
/* }}} */


extern void
ssl_check_record_length(ssl_common_dissect_t *hf, packet_info *pinfo,
                        ContentType content_type,
                        unsigned record_length, proto_item *length_pi,
                        uint16_t version, tvbuff_t *decrypted_tvb);

void
ssl_dissect_change_cipher_spec(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               uint32_t offset, SslSession *session,
                               bool is_from_server,
                               const SslDecryptSession *ssl);

extern void
ssl_dissect_hnd_cli_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *tree, uint32_t offset,
                          uint32_t offset_end, SslSession *session,
                          SslDecryptSession *ssl,
                          dtls_hfs_t *dtls_hfs);

extern void
ssl_dissect_hnd_srv_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info* pinfo,
                          proto_tree *tree, uint32_t offset, uint32_t offset_end,
                          SslSession *session, SslDecryptSession *ssl,
                          bool is_dtls, bool is_hrr);

extern void
ssl_dissect_hnd_hello_retry_request(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info* pinfo,
                                    proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                    SslSession *session, SslDecryptSession *ssl,
                                    bool is_dtls);

extern void
ssl_dissect_hnd_encrypted_extensions(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info* pinfo,
                                     proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                     SslSession *session, SslDecryptSession *ssl,
                                     bool is_dtls);

extern void
ssl_dissect_hnd_new_ses_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               SslSession *session, SslDecryptSession *ssl,
                               bool is_dtls, GHashTable *session_hash);

extern void
ssl_dissect_hnd_cert(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                     uint32_t offset, uint32_t offset_end, packet_info *pinfo,
                     SslSession *session, SslDecryptSession *ssl,
                     bool is_from_server, bool is_dtls);

extern void
ssl_dissect_hnd_cert_req(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, uint32_t offset, uint32_t offset_end,
                         SslSession *session, bool is_dtls);

extern void
ssl_dissect_hnd_cli_cert_verify(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, uint32_t offset, uint32_t offset_end, uint16_t version);

extern void
ssl_dissect_hnd_finished(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                         proto_tree *tree, uint32_t offset, uint32_t offset_end,
                         const SslSession *session, ssl_hfs_t *ssl_hfs);

extern void
ssl_dissect_hnd_cert_url(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, uint32_t offset);

extern uint32_t
tls_dissect_hnd_certificate_status(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, uint32_t offset, uint32_t offset_end);

extern void
ssl_dissect_hnd_cli_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, uint32_t offset, uint32_t length,
                          const SslSession *session);

extern void
ssl_dissect_hnd_srv_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, uint32_t offset, uint32_t offset_end,
                          const SslSession *session);

extern void
tls13_dissect_hnd_key_update(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, uint32_t offset);

extern uint32_t
tls_dissect_sct_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     uint32_t offset, uint32_t offset_end, uint16_t version);

extern bool
tls13_hkdf_expand_label_context(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        const uint8_t *context, uint8_t context_length,
                        uint16_t out_len, unsigned char **out);

extern bool
tls13_hkdf_expand_label(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        uint16_t out_len, unsigned char **out);

extern void
ssl_dissect_hnd_compress_certificate(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                                     uint32_t offset, uint32_t offset_end, packet_info *pinfo,
                                     SslSession *session _U_, SslDecryptSession *ssl _U_,
                                     bool is_from_server _U_, bool is_dtls _U_);
/* {{{ */
#define SSL_COMMON_LIST_T(name) \
ssl_common_dissect_t name;
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
    { & name .hf.hs_ext_session_ticket,                                 \
      { "Session Ticket", prefix ".handshake.extensions.session_ticket", \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
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
        "Maximum version supported by client [legacy_version if supported_versions ext is present]", HFILL } \
    },                                                                  \
    { & name .hf.hs_server_version,                                     \
      { "Version", prefix ".handshake.version",                         \
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,                   \
        "Version selected by server [legacy_version if supported_versions ext is present]", HFILL } \
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
    { & name .hf.hs_ja4,                                                \
      { "JA4", prefix ".handshake.ja4",                                 \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ja4_r,                                              \
      { "JA4_r", prefix ".handshake.ja4_r",                             \
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
    { & name .hf.hs_ext_token_binding_version_major,                    \
      { "Protocol Major Version", prefix ".token_binding.version_major", \
        FT_UINT8, BASE_HEX, NULL, 0x00,                                 \
        "Major version of the Token Binding protocol", HFILL }          \
    },                                                                  \
    { & name .hf.hs_ext_token_binding_version_minor,                    \
      { "Protocol Minor Version", prefix ".token_binding.version_minor", \
        FT_UINT8, BASE_HEX, NULL, 0x00,                                 \
        "Minor version of the Token Binding protocol", HFILL }          \
    },                                                                  \
    { & name .hf.hs_ext_token_binding_key_parameters,                   \
      { "Key Parameters", prefix ".token_binding.key_parameters",       \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_token_binding_key_parameters_length,            \
      { "Key Parameters Length", prefix ".token_binding.key_parameters_length", \
        FT_UINT8, BASE_DEC, NULL, 0x00,                                 \
        "Length of the key parameters list", HFILL }                    \
    },                                                                  \
    { & name .hf.hs_ext_token_binding_key_parameter,                    \
      { "Key Parameter", prefix ".token_binding.key_parameter",         \
        FT_UINT8, BASE_DEC, VALS(token_binding_key_parameter_vals), 0x00, \
        "Identifier of the Token Binding key parameter", HFILL }         \
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
      { "Length", prefix ".quic.parameter.length.old",                  \
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
    { & name .hf.hs_ext_quictp_parameter_enable_multipath,              \
      { "Enable Multipath", prefix ".quic.parameter.enable_multipath", \
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(quic_enable_multipath_vals), 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_paths,             \
      { "Initial Max Paths", prefix ".quic.parameter.initial_max_paths", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_quictp_parameter_initial_max_path_id,           \
      { "Initial Max Path ID", prefix ".quic.parameter.initial_max_path_id", \
        FT_UINT64, BASE_DEC, NULL, 0x00,                                \
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
    { & name .hf.ech_echconfiglist_length,                              \
      { "ECHConfigList length", prefix ".ech.echconfiglist_length",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Encrypted ClientHello (ECH) Configurations length", HFILL }    \
    },                                                                  \
    { & name .hf.ech_echconfiglist,                                     \
      { "ECHConfigList", prefix ".ech.echconfiglist",                   \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "Encrypted ClientHello (ECH) Configurations", HFILL }           \
    },                                                                  \
    { & name .hf.ech_echconfig,                                         \
      { "ECHConfig", prefix ".ech.echconfig",                           \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "Encrypted ClientHello (ECH) Configuration", HFILL }            \
    },                                                                  \
    { & name .hf.ech_echconfig_version,                                 \
      { "Version", prefix ".ech.echconfig.version",                     \
        FT_UINT16, BASE_HEX, NULL, 0x0,                                 \
        "Encrypted ClientHello: ECHConfig version", HFILL }             \
    },                                                                  \
    { & name .hf.ech_echconfig_length,                                  \
      { "Length", prefix ".ech.echconfig.length",                       \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Encrypted ClientHello: ECHConfig length", HFILL }              \
    },                                                                  \
    { & name .hf.ech_echconfigcontents_maximum_name_length,             \
      { "Maximum Name Length", prefix ".ech.echconfigcontents.maximum_name_length", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "The longest name of a backend server, if known", HFILL }       \
    },                                                                  \
    { & name .hf.ech_echconfigcontents_public_name_length,              \
      { "Public Name length", prefix ".ech.echconfigcontents.public_name_length", \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of the Public Name field", HFILL }                      \
    },                                                                  \
    { & name .hf.ech_echconfigcontents_public_name,                     \
      { "Public Name", prefix ".ech.echconfigcontents.public_name",     \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        "The DNS name of the client-facing server, i.e., the entity trusted to update the ECH configuration", HFILL } \
    },                                                                  \
    { & name .hf.ech_echconfigcontents_extensions_length,               \
      { "Extensions length", prefix ".ech.echconfigcontents.extensions_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of the Extensions field", HFILL }                       \
    },                                                                  \
    { & name .hf.ech_echconfigcontents_extensions,                      \
      { "Extensions", prefix ".ech.echconfigcontents.extensions",       \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "A list of extensions that the client must take into consideration when generating a ClientHello message", HFILL } \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig,                                    \
      { "HPKE Key Config", prefix ".ech.hpke.keyconfig",                \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "HPKE Key Config", HFILL }                                      \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_config_id,                          \
      { "Config Id", prefix ".ech.hpke.keyconfig.config_id",            \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "HPKE Config Id", HFILL }                                       \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_kem_id,                             \
      { "KEM Id", prefix ".ech.hpke.keyconfig.kem_id",                  \
        FT_UINT16, BASE_DEC, VALS(kem_id_type_vals), 0x0,               \
        "HPKE KEM Id", HFILL }                                          \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_public_key_length,                  \
      { "Public Key length", prefix ".ech.hpke.keyconfig.public_key_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "HPKE Public Key length", HFILL }                               \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_public_key,                         \
      { "Public Key", prefix ".ech.hpke.keyconfig.public_key",          \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "HPKE Public Key", HFILL }                                      \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_cipher_suites,                      \
      { "Cipher Suites", prefix ".ech.hpke.keyconfig.cipher_suites",    \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "HPKE Cipher Suites", HFILL }                                   \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_cipher_suites_length,               \
      { "Cipher Suites length", prefix ".ech.hpke.keyconfig.cipher_suites_length", \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "HPKE Cipher Suites length", HFILL }                            \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_cipher_suite,                       \
      { "Cipher Suite", prefix ".ech.hpke.keyconfig.cipher_suite",      \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "HPKE Cipher Suite", HFILL }                                    \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_cipher_suite_kdf_id,                \
      { "KDF Id", prefix ".ech.hpke.keyconfig.cipher_suite.kdf_id",     \
        FT_UINT16, BASE_DEC, VALS(kdf_id_type_vals), 0x0,               \
        "HPKE KDF Id", HFILL }                                          \
    },                                                                  \
    { & name .hf.ech_hpke_keyconfig_cipher_suite_aead_id,               \
      { "AEAD Id", prefix ".ech.hpke.keyconfig.cipher_suite.aead_id",   \
        FT_UINT16, BASE_DEC, VALS(aead_id_type_vals), 0x0,              \
        "HPKE AEAD Id", HFILL }                                         \
    },                                                                  \
    { & name .hf.ech_clienthello_type,                                  \
      { "Client Hello type", prefix ".ech.client_hello_type",           \
        FT_UINT8, BASE_DEC, VALS(tls_hello_ext_ech_clienthello_types), 0x0, \
        "Client Hello type", HFILL }                                     \
    },                                                                  \
    { & name .hf.ech_cipher_suite,                                      \
      { "Cipher Suite", prefix ".ech.cipher_suite",                     \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "The cipher suite used to encrypt ClientHelloInner", HFILL }    \
    },                                                                  \
    { & name .hf.ech_config_id,                                         \
      { "Config Id", prefix ".ech.config_id",                           \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "The ECHConfigContents.key_config.config_id for the chosen ECHConfig", HFILL } \
    },                                                                  \
    { & name .hf.ech_enc_length,                                        \
      { "Enc length", prefix ".ech.enc_length",                         \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.ech_enc,                                               \
      { "Enc", prefix ".ech.enc",                                       \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "The HPKE encapsulated key, used by servers to decrypt the corresponding payload field", HFILL } \
    },                                                                  \
    { & name .hf.ech_payload_length,                                    \
      { "Payload length", prefix ".ech.payload_length",                 \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Payload Length", HFILL }                                       \
    },                                                                  \
    { & name .hf.ech_payload,                                           \
      { "Payload", prefix ".ech.payload",                               \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "The serialized and encrypted ClientHelloInner structure", HFILL } \
    },                                                                  \
    { & name .hf.ech_confirmation,                                      \
      { "Confirmation", prefix ".ech.confirmation",                     \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Confirmation of ECH acceptance in a HelloRetryRequest", HFILL } \
    },                                                                  \
    { & name .hf.ech_retry_configs,                                     \
      { "Retry Configs", prefix ".ech.retry_configs",                   \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "ECHConfig structures for one-time use by the client in a retry connection", HFILL } \
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
        & name .ett.ech_echconfiglist,              \
        & name .ett.ech_echconfig,                  \
        & name .ett.ech_retry_configs,              \
        & name .ett.ech_hpke_keyconfig,             \
        & name .ett.ech_hpke_cipher_suites,         \
        & name .ett.ech_hpke_cipher_suite,          \
        & name .ett.hs_ext_token_binding_key_parameters, \

/* }}} */

/* {{{ */
#define SSL_COMMON_EI_LIST(name, prefix)                       \
    { & name .ei.client_version_error, \
        { prefix ".handshake.client_version_error", PI_PROTOCOL, PI_WARN, \
        "Client Hello legacy version field specifies version 1.3, not version 1.2; some servers may not be able to handle that.", EXPFILL } \
    }, \
    { & name .ei.server_version_error, \
        { prefix ".handshake.server_version_error", PI_PROTOCOL, PI_WARN, \
        "Server Hello legacy version field specifies version 1.3, not version 1.2; some middleboxes may not be able to handle that.", EXPFILL } \
    }, \
    { & name .ei.legacy_version, \
        { prefix ".handshake.legacy_version", PI_DEPRECATED, PI_CHAT, \
        "This legacy_version field MUST be ignored. The supported_versions extension is present and MUST be used instead.", EXPFILL } \
    }, \
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
    { & name .ei.hs_ciphersuite_undecoded, \
        { prefix ".handshake.ciphersuite.undecoded", PI_UNDECODED, PI_NOTE, \
        "Ciphersuite not implemented, contact Wireshark developers if you want this to be supported", EXPFILL } \
    }, \
    { & name .ei.hs_srv_keyex_illegal, \
        { prefix ".handshake.server_keyex_illegal", PI_PROTOCOL, PI_WARN, \
        "It is not legal to send the ServerKeyExchange message for this ciphersuite", EXPFILL } \
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
    }, \
    { & name .ei.ech_echconfig_invalid_version, \
        { prefix ".ech_echconfig_invalid_version", PI_PROTOCOL, PI_ERROR, \
        "Invalid/unknown ECHConfig version", EXPFILL } \
    }
/* }}} */

extern void
ssl_common_register_ssl_alpn_dissector_table(const char *name,
    const char *ui_name, const int proto);

extern void
ssl_common_register_dtls_alpn_dissector_table(const char *name,
    const char *ui_name, const int proto);

extern void
ssl_common_register_options(module_t *module, ssl_common_options_t *options, bool is_dtls);

#ifdef SSL_DECRYPT_DEBUG
extern void
ssl_debug_printf(const char* fmt,...) G_GNUC_PRINTF(1,2);
extern void
ssl_print_data(const char* name, const unsigned char* data, size_t len);
extern void
ssl_print_string(const char* name, const StringInfo* data);
extern void
ssl_set_debug(const char* name);
extern void
ssl_debug_flush(void);
#else

/* No debug: nullify debug operation*/
static inline void G_GNUC_PRINTF(1,2)
ssl_debug_printf(const char* fmt _U_,...)
{
}
#define ssl_print_data(a, b, c)
#define ssl_print_string(a, b)
#define ssl_set_debug(name)
#define ssl_debug_flush()

#endif /* SSL_DECRYPT_DEBUG */


uint32_t
ssl_dissect_ext_ech_echconfiglist(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, uint32_t offset, uint32_t offset_end);

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
