/* packet-ssl-utils.h
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __SSL_UTILS_H_
#define __SSL_UTILS_H_

#include <stdio.h>      /* some APIs we declare take a stdio stream as an argument */

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <wsutil/wsgcrypt.h>

#ifdef HAVE_LIBGNUTLS
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

#include <epan/conversation.h>
#include "ws_symbol_export.h"

/* #define SSL_FAST 1 */
#define SSL_DECRYPT_DEBUG
#endif /* HAVE_LIBGNUTLS */

#ifdef HAVE_LIBGCRYPT
#define SSL_CIPHER_CTX gcry_cipher_hd_t
#ifdef SSL_FAST
#define SSL_PRIVATE_KEY gcry_mpi_t
#else /* SSL_FAST */
#define SSL_PRIVATE_KEY struct gcry_sexp
#endif /* SSL_FAST */
#else  /* HAVE_LIBGCRYPT */
#define SSL_CIPHER_CTX void*
#define SSL_PRIVATE_KEY void
#endif /* HAVE_LIBGCRYPT */


/* version state tables */
#define SSL_VER_UNKNOWN                   0
#define SSL_VER_SSLv2                     1
#define SSL_VER_SSLv3                     2
#define SSL_VER_TLS                       3
#define SSL_VER_TLSv1DOT1                 4
#define SSL_VER_DTLS                      5
#define SSL_VER_DTLS1DOT2                 8
#define SSL_VER_DTLS_OPENSSL              9
#define SSL_VER_PCT                       6
#define SSL_VER_TLSv1DOT2                 7

/* other defines */
#define SSL_ID_CHG_CIPHER_SPEC         0x14
#define SSL_ID_ALERT                   0x15
#define SSL_ID_HANDSHAKE               0x16
#define SSL_ID_APP_DATA                0x17
#define SSL_ID_HEARTBEAT               0x18

#define SSL_HND_HELLO_REQUEST          0
#define SSL_HND_CLIENT_HELLO           1
#define SSL_HND_SERVER_HELLO           2
#define SSL_HND_HELLO_VERIFY_REQUEST   3
#define SSL_HND_NEWSESSION_TICKET      4
#define SSL_HND_CERTIFICATE            11
#define SSL_HND_SERVER_KEY_EXCHG       12
#define SSL_HND_CERT_REQUEST           13
#define SSL_HND_SVR_HELLO_DONE         14
#define SSL_HND_CERT_VERIFY            15
#define SSL_HND_CLIENT_KEY_EXCHG       16
#define SSL_HND_FINISHED               20
#define SSL_HND_CERT_URL               21
#define SSL_HND_CERT_STATUS            22
#define SSL_HND_SUPPLEMENTAL_DATA      23
/* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03 and
 * changed in draft 04 */
#define SSL_HND_ENCRYPTED_EXTS         67

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define PCT_VERSION_1                  0x8001

#define PCT_MSG_CLIENT_HELLO           0x01
#define PCT_MSG_SERVER_HELLO           0x02
#define PCT_MSG_CLIENT_MASTER_KEY      0x03
#define PCT_MSG_SERVER_VERIFY          0x04
#define PCT_MSG_ERROR                  0x05

#define PCT_CH_OFFSET_V1               0xa

#define PCT_CIPHER_DES                 0x01
#define PCT_CIPHER_IDEA                0x02
#define PCT_CIPHER_RC2                 0x03
#define PCT_CIPHER_RC4                 0x04
#define PCT_CIPHER_DES_112             0x05
#define PCT_CIPHER_DES_168             0x06

#define PCT_HASH_MD5                   0x0001
#define PCT_HASH_MD5_TRUNC_64          0x0002
#define PCT_HASH_SHA                   0x0003
#define PCT_HASH_SHA_TRUNC_80          0x0004
#define PCT_HASH_DES_DM                0x0005

#define PCT_CERT_NONE                  0x00
#define PCT_CERT_X509                  0x01
#define PCT_CERT_PKCS7                 0x02

#define PCT_SIG_NONE                   0x0000
#define PCT_SIG_RSA_MD5                0x0001
#define PCT_SIG_RSA_SHA                0x0002
#define PCT_SIG_DSA_SHA                0x0003

#define PCT_EXCH_RSA_PKCS1             0x01
#define PCT_EXCH_RSA_PKCS1_TOKEN_DES   0x02
#define PCT_EXCH_RSA_PKCS1_TOKEN_DES3  0x03
#define PCT_EXCH_RSA_PKCS1_TOKEN_RC2   0x04
#define PCT_EXCH_RSA_PKCS1_TOKEN_RC4   0x05
#define PCT_EXCH_DH_PKCS3              0x06
#define PCT_EXCH_DH_PKCS3_TOKEN_DES    0x07
#define PCT_EXCH_DH_PKCS3_TOKEN_DES3   0x08
#define PCT_EXCH_FORTEZZA_TOKEN        0x09

#define PCT_ERR_BAD_CERTIFICATE        0x01
#define PCT_ERR_CLIENT_AUTH_FAILED     0x02
#define PCT_ERR_ILLEGAL_MESSAGE        0x03
#define PCT_ERR_INTEGRITY_CHECK_FAILED 0x04
#define PCT_ERR_SERVER_AUTH_FAILED     0x05
#define PCT_ERR_SPECS_MISMATCH         0x06

#define SSL_HND_HELLO_EXT_SERVER_NAME        0x0
#define SSL_HND_HELLO_EXT_STATUS_REQUEST     0x0005
#define SSL_HND_HELLO_EXT_CERT_TYPE          0x0009
#define SSL_HND_HELLO_EXT_ELLIPTIC_CURVES    0x000a
#define SSL_HND_HELLO_EXT_EC_POINT_FORMATS   0x000b
#define SSL_HND_HELLO_EXT_SIG_HASH_ALGS      0x000d
#define SSL_HND_HELLO_EXT_HEARTBEAT          0x000f
#define SSL_HND_HELLO_EXT_ALPN               0x0010
#define SSL_HND_HELLO_EXT_STATUS_REQUEST_V2  0x0011
#define SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE   0x0013
#define SSL_HND_HELLO_EXT_SERVER_CERT_TYPE   0x0014
#define SSL_HND_HELLO_EXT_PADDING            0x0015
#define SSL_HND_HELLO_EXT_SESSION_TICKET     0x0023
#define SSL_HND_HELLO_EXT_RENEG_INFO         0xff01
#define SSL_HND_HELLO_EXT_NPN                0x3374
#define SSL_HND_HELLO_EXT_CHANNEL_ID_OLD     0x754f
#define SSL_HND_HELLO_EXT_CHANNEL_ID         0x7550
#define SSL_HND_CERT_URL_TYPE_INDIVIDUAL_CERT       1
#define SSL_HND_CERT_URL_TYPE_PKIPATH               2
#define SSL_HND_CERT_STATUS_TYPE_OCSP        1
#define SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI  2
#define SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY     2

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
extern const value_string pct_msg_types[];
extern const value_string pct_cipher_type[];
extern const value_string pct_hash_type[];
extern const value_string pct_cert_type[];
extern const value_string pct_sig_type[];
extern const value_string pct_exch_type[];
extern const value_string pct_error_code[];
extern const value_string tls_hello_extension_types[];
extern const value_string tls_hash_algorithm[];
extern const value_string tls_signature_algorithm[];
extern const value_string tls_certificate_type[];
extern const value_string tls_cert_chain_type[];
extern const value_string tls_cert_status_type[];
extern const value_string ssl_extension_curves[];
extern const value_string ssl_extension_ec_point_formats[];
extern const value_string ssl_curve_types[];
extern const value_string tls_hello_ext_server_name_type_vs[];

/* XXX Should we use GByteArray instead? */
typedef struct _StringInfo {
    guchar* data;
    guint data_len;
} StringInfo;

#define SSL_WRITE_KEY           1

#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_VERSION_NOT 0x100
#define DTLSV1DOT2_VERSION     0xfefd

#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)

/* SSL Cipher Suite modes */
typedef enum {
    MODE_STREAM,    /* GenericStreamCipher */
    MODE_CBC,       /* GenericBlockCipher */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_CCM,       /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
    MODE_CCM_8      /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
} ssl_cipher_mode_t;

/* Explicit nonce length */
#define SSL_EX_NONCE_LEN_GCM    8 /* RFC 5288 - section 3 */

#define SSL_DEBUG_USE_STDERR "-"

#define SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES 16

typedef struct _SslCipherSuite {
    gint number;
    gint kex;
    gint enc;
    gint block; /* IV block size */
    gint bits;
    gint eff_bits;
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
    SslCipherSuite* cipher_suite;
    gint compression;
    guchar _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    guint32 seq;
    guint16 epoch;
    SslFlow *flow;
} SslDecoder;

#define KEX_RSA         0x10
#define KEX_DH          0x11
#define KEX_PSK         0x12
#define KEX_ECDH        0x13
#define KEX_RSA_PSK     0x14

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
#define ENC_NULL        0x3A

#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_NA          0x44 /* Not Applicable */

typedef struct {
    const gchar *name;
    gint len;
} SslDigestAlgo;

typedef struct _SslRecordInfo {
    guchar *real_data;
    gint data_len;
    gint id;
    struct _SslRecordInfo* next;
} SslRecordInfo;

typedef struct _SslDataInfo {
    gint key;
    StringInfo plain_data;
    guint32 seq;
    guint32 nxtseq;
    SslFlow *flow;
    struct _SslDataInfo *next;
} SslDataInfo;

typedef struct {
    SslDataInfo *appl_data;
    SslRecordInfo* handshake_data;
} SslPacketInfo;

typedef struct _SslSession {
    gint cipher;
    gint compression;
    guint32 version;
    gint8 client_cert_type;
    gint8 server_cert_type;
} SslSession;

typedef struct _SslDecryptSession {
    guchar _master_secret[48];
    guchar _session_id[256];
    guchar _client_random[32];
    guchar _server_random[32];
    StringInfo session_id;
    StringInfo session_ticket;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    guchar _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    guchar _client_data_for_iv[24];
    StringInfo client_data_for_iv;

    gint state;
    SslCipherSuite cipher_suite;
    SslDecoder *server;
    SslDecoder *client;
    SslDecoder *server_new;
    SslDecoder *client_new;
    SSL_PRIVATE_KEY* private_key;
    StringInfo psk;
    guint16 version_netorder;
    StringInfo app_data_segment;
    SslSession session;

    address srv_addr;
    port_type srv_ptype;
    guint srv_port;

} SslDecryptSession;

typedef struct _SslAssociation {
    gboolean tcp;
    guint ssl_port;
    dissector_handle_t handle;
    gchar* info;
    gboolean from_key_list;
} SslAssociation;

typedef struct _SslService {
    address addr;
    guint port;
} SslService;

typedef struct _Ssl_private_key {
#ifdef HAVE_LIBGNUTLS
    gnutls_x509_crt_t     x509_cert;
    gnutls_x509_privkey_t x509_pkey;
#endif
    SSL_PRIVATE_KEY       *sexp_pkey;
} Ssl_private_key_t;

/* User Access Table */
typedef struct _ssldecrypt_assoc_t {
    char* ipaddr;
    char* port;
    char* protocol;
    char* keyfile;
    char* password;
} ssldecrypt_assoc_t;

gint ssl_get_keyex_alg(gint cipher);

gboolean ssldecrypt_uat_fld_ip_chk_cb(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean ssldecrypt_uat_fld_port_chk_cb(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean ssldecrypt_uat_fld_protocol_chk_cb(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean ssldecrypt_uat_fld_fileopen_chk_cb(void*, const char*, unsigned, const void*, const void*, const char** err);
gboolean ssldecrypt_uat_fld_password_chk_cb(void*, const char*, unsigned, const void*, const void*, const char** err);

/** Initialize decryption engine/ssl layer. To be called once per execution */
extern void
ssl_lib_init(void);

/** Initialize an ssl session struct
 @param ssl pointer to ssl session struct to be initialized */
extern void
ssl_session_init(SslDecryptSession* ssl);

/** Set server address and port */
extern void
ssl_set_server(SslDecryptSession* ssl, address *addr, port_type ptype, guint32 port);

/** set the data and len for the stringInfo buffer. buf should be big enough to
 * contain the provided data
 @param buf the buffer to update
 @param src the data source
 @param len the source data len */
extern void
ssl_data_set(StringInfo* buf, const guchar* src, guint len);

extern gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, guchar* iv, gint iv_len);

/** Load an RSA private key from specified file
 @param fp the file that contain the key data
 @return a pointer to the loaded key on success, or NULL */
extern Ssl_private_key_t *
ssl_load_key(FILE* fp);

/** Deallocate the memory used for specified key
 @param key pointer to the key to be freed */
void
ssl_free_key(Ssl_private_key_t* key);

/* Find private key in associations */
extern void
ssl_find_private_key(SslDecryptSession *ssl_session, GHashTable *key_hash, GTree* associations, packet_info *pinfo);

/** Search for the specified cipher suite id
 @param num the id of the cipher suite to be searched
 @param cs pointer to the cipher suite struct to be filled
 @return 0 if the cipher suite is found, -1 elsewhere */
extern gint
ssl_find_cipher(int num,SslCipherSuite* cs);

int
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session,
                               guint32 length, tvbuff_t *tvb, guint32 offset,
                               const gchar *ssl_psk, const gchar *keylog_filename);

/** Expand the pre_master_secret to generate all the session information
 * (master secret, session keys, ivs)
 @param ssl_session the store for all the session data
 @return 0 on success */
extern gint
ssl_generate_keyring_material(SslDecryptSession*ssl_session);

extern void
ssl_change_cipher(SslDecryptSession *ssl_session, gboolean server);

/** Try to find the pre-master secret for the given encrypted pre-master secret
    from a log of secrets.
 @param ssl_session the store for the decrypted pre_master_secret
 @param ssl_keylog_filename a file that contains a log of secrets (may be NULL)
 @param encrypted_pre_master the rsa encrypted pre_master_secret (may be NULL)
 @return 0 on success */
int
ssl_keylog_lookup(SslDecryptSession* ssl_session,
                  const gchar* ssl_keylog_filename,
                  StringInfo* encrypted_pre_master);

/** Try to decrypt in place the encrypted pre_master_secret
 @param ssl_session the store for the decrypted pre_master_secret
 @param encrypted_pre_master the rsa encrypted pre_master_secret
 @param pk the private key to be used for decryption
 @return 0 on success */
extern gint
ssl_decrypt_pre_master_secret(SslDecryptSession*ssl_session,
    StringInfo* encrypted_pre_master, SSL_PRIVATE_KEY *pk);

/** Try to decrypt an ssl record
 @param ssl ssl_session the store all the session data
 @param decoder the stream decoder to be used
 @param ct the content type of this ssl record
 @param in a pointer to the ssl record to be decrypted
 @param inl the record length
 @param comp_str a pointer to the store the compression data
 @param out_str a pointer to the store for the decrypted data
 @param outl the decrypted data len
 @return 0 on success */
extern gint
ssl_decrypt_record(SslDecryptSession* ssl,SslDecoder* decoder, gint ct,
        const guchar* in, guint inl, StringInfo* comp_str, StringInfo* out_str, guint* outl);


/* Common part bitween SSL and DTLS dissectors */
/* Hash Functions for TLS/DTLS sessions table and private keys table */
extern gint
ssl_equal (gconstpointer v, gconstpointer v2);

extern guint
ssl_hash  (gconstpointer v);

extern gint
ssl_private_key_equal (gconstpointer v, gconstpointer v2);

extern guint
ssl_private_key_hash  (gconstpointer v);

/* private key table entries have a scope 'larger' then packet capture,
 * so we can't relay on se_alloc** function */
extern void
ssl_private_key_free(gpointer id, gpointer key, gpointer dummy _U_);

/* handling of association between tls/dtls ports and clear text protocol */
extern void
ssl_association_add(GTree* associations, dissector_handle_t handle, guint port, const gchar *protocol, gboolean tcp, gboolean from_key_list);

extern void
ssl_association_remove(GTree* associations, SslAssociation *assoc);

extern gint
ssl_association_cmp(gconstpointer a, gconstpointer b);

extern SslAssociation*
ssl_association_find(GTree * associations, guint port, gboolean tcp);

extern gint
ssl_assoc_from_key_list(gpointer key _U_, gpointer data, gpointer user_data);

extern gint
ssl_packet_from_server(SslDecryptSession* ssl, GTree* associations, packet_info *pinfo);

/* add to packet data a copy of the specified real data */
extern void
ssl_add_record_info(gint proto, packet_info *pinfo, guchar* data, gint data_len, gint record_id);

/* search in packet data for the specified id; return a newly created tvb for the associated data */
extern tvbuff_t*
ssl_get_record_info(tvbuff_t *parent_tvb, gint proto, packet_info *pinfo, gint record_id);

void
ssl_add_data_info(gint proto, packet_info *pinfo, guchar* data, gint data_len, gint key, SslFlow *flow);

SslDataInfo*
ssl_get_data_info(int proto, packet_info *pinfo, gint key);

/* initialize/reset per capture state data (ssl sessions cache) */
extern void
ssl_common_init(GHashTable **session_hash, StringInfo *decrypted_data, StringInfo *compressed_data);

/* parse ssl related preferences (private keys and ports association strings) */
extern void
ssl_parse_key_list(const ssldecrypt_assoc_t * uats, GHashTable *key_hash, GTree* associations, dissector_handle_t handle, gboolean tcp);

/* store master secret into session data cache */
extern void
ssl_save_session(SslDecryptSession* ssl, GHashTable *session_hash);

extern gboolean
ssl_restore_session(SslDecryptSession* ssl, GHashTable *session_hash);

extern void
ssl_save_session_ticket(SslDecryptSession* ssl, GHashTable *session_hash);

extern gboolean
ssl_restore_session_ticket(SslDecryptSession* ssl, GHashTable *session_hash);

extern gint
ssl_is_valid_content_type(guint8 type);

typedef struct ssl_common_dissect {
    struct {
        gint hs_exts_len;
        gint hs_ext_alpn_len;
        gint hs_ext_alpn_list;
        gint hs_ext_alpn_str;
        gint hs_ext_alpn_str_len;
        gint hs_ext_cert_status_request_extensions_len;
        gint hs_ext_cert_status_request_len;
        gint hs_ext_cert_status_responder_id_list_len;
        gint hs_ext_cert_status_type;
        gint hs_ext_cert_url_item;
        gint hs_ext_cert_url_padding;
        gint hs_ext_cert_url_sha1;
        gint hs_ext_cert_url_type;
        gint hs_ext_cert_url_url;
        gint hs_ext_cert_url_url_hash_list_len;
        gint hs_ext_cert_url_url_len;
        gint hs_ext_cert_type;
        gint hs_ext_cert_types;
        gint hs_ext_cert_types_len;
        gint hs_ext_data;
        gint hs_ext_ec_point_format;
        gint hs_ext_ec_point_formats_len;
        gint hs_ext_elliptic_curve;
        gint hs_ext_elliptic_curves;
        gint hs_ext_elliptic_curves_len;
        gint hs_ext_heartbeat_mode;
        gint hs_ext_len;
        gint hs_ext_npn_str;
        gint hs_ext_npn_str_len;
        gint hs_ext_reneg_info_len;
        gint hs_ext_server_name;
        gint hs_ext_server_name_len;
        gint hs_ext_server_name_list_len;
        gint hs_ext_server_name_type;
        gint hs_ext_padding;
        gint hs_ext_padding_len;
        gint hs_ext_padding_data;
        gint hs_ext_type;
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
        gint hs_server_keyex_modulus;
        gint hs_server_keyex_exponent;
        gint hs_server_keyex_sig;
        gint hs_server_keyex_hint_len;
        gint hs_server_keyex_hint;
        gint hs_client_keyex_identity_len;
        gint hs_client_keyex_identity;
    } hf;
    struct {
        gint hs_ext;
        gint hs_ext_alpn;
        gint hs_ext_cert_types;
        gint hs_ext_curves;
        gint hs_ext_curves_point_formats;
        gint hs_ext_npn;
        gint hs_ext_reneg_info;
        gint hs_ext_server_name;
        gint hs_ext_padding;
        gint hs_sig_hash_alg;
        gint hs_sig_hash_algs;
        gint urlhash;
        gint keyex_params;
    } ett;
    struct {
        expert_field hs_ext_cert_status_undecoded;
    } ei;
} ssl_common_dissect_t;

extern gint
ssl_dissect_hnd_hello_ext(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          guint32 offset, guint32 left, gboolean is_client,
                          SslSession *session, SslDecryptSession *ssl);

extern gint
ssl_dissect_hash_alg_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          guint32 offset, guint16 len);

extern void
ssl_dissect_hnd_cert_url(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, guint32 offset);

extern void
ssl_dissect_hnd_cli_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session);

extern void
ssl_dissect_hnd_srv_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session);

#define SSL_COMMON_LIST_T(name) \
ssl_common_dissect_t name = {   \
    /* hf */ {                  \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, \
        -1, -1, -1, -1, -1,                                             \
    },                                                                  \
    /* ett */ {                                                         \
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,             \
    },                                                                  \
    /* ei */ {                                                          \
        EI_INIT,                                                        \
    },                                                                  \
}

#define SSL_COMMON_HF_LIST(name, prefix)                                \
    { & name .hf.hs_exts_len,                                           \
      { "Extensions Length", prefix ".handshake.extensions_length",     \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of hello extensions", HFILL }                           \
    },                                                                  \
    { & name .hf.hs_ext_type,                                           \
      { "Type", prefix ".handshake.extension.type",                     \
        FT_UINT16, BASE_HEX, VALS(tls_hello_extension_types), 0x0,      \
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
    { & name .hf.hs_ext_elliptic_curves_len,                            \
      { "Elliptic Curves Length", prefix ".handshake.extensions_elliptic_curves_length",   \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of elliptic curves field", HFILL }                      \
    },                                                                  \
    { & name .hf.hs_ext_elliptic_curves,                                \
      { "Elliptic Curves List", prefix ".handshake.extensions_elliptic_curves",        \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of elliptic curves supported", HFILL }                    \
    },                                                                  \
    { & name .hf.hs_ext_elliptic_curve,                                 \
      { "Elliptic curve", prefix ".handshake.extensions_elliptic_curve",\
        FT_UINT16, BASE_HEX, VALS(ssl_extension_curves), 0x0,           \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_ec_point_formats_len,                           \
      { "EC point formats Length", prefix ".handshake.extensions_ec_point_formats_length",     \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        "Length of elliptic curves point formats field", HFILL }        \
    },                                                                  \
    { & name .hf.hs_ext_ec_point_format,                                \
      { "EC point format", prefix ".handshake.extensions_ec_point_format",             \
        FT_UINT8, BASE_DEC, VALS(ssl_extension_ec_point_formats), 0x0,  \
        "Elliptic curves point format", HFILL }                         \
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
    { & name .hf.hs_ext_padding,                                        \
      { "Padding", prefix ".handshake.extensions_padding",              \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_ext_padding_len,                                    \
      { "Padding length", prefix ".handshake.extensions_padding_len",   \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of Padding", HFILL }                                    \
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
      { "URL", prefix ".handshake.cert_url.url_hash_len",               \
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
    { & name .hf.hs_sig_hash_alg_len,                                   \
      { "Signature Hash Algorithms Length", prefix ".handshake.sig_hash_alg_len",      \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Length of Signature Hash Algorithms", HFILL }                  \
    },                                                                  \
    { & name .hf.hs_sig_hash_algs,                                      \
      { "Signature Hash Algorithms", prefix ".handshake.sig_hash_algs", \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        "List of Signature Hash Algorithms", HFILL }                    \
    },                                                                  \
    { & name .hf.hs_sig_hash_alg,                                       \
      { "Signature Hash Algorithm", prefix ".handshake.sig_hash_alg",   \
        FT_UINT16, BASE_HEX, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_sig_hash_hash,                                      \
      { "Signature Hash Algorithm Hash", prefix ".handshake.sig_hash_hash",            \
        FT_UINT8, BASE_DEC, VALS(tls_hash_algorithm), 0x0,              \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.hs_sig_hash_sig,                                       \
      { "Signature Hash Algorithm Signature", prefix ".handshake.sig_hash_sig",        \
        FT_UINT8, BASE_DEC, VALS(tls_signature_algorithm), 0x0,         \
        NULL, HFILL }                                                   \
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
      { "Curve Type", prefix ".handshake.server_curve_type",          \
        FT_UINT8, BASE_HEX, VALS(ssl_curve_types), 0x0,               \
        "Server curve_type", HFILL }                                  \
    },                                                                  \
    { & name .hf.hs_server_keyex_named_curve,                           \
      { "Named Curve", prefix ".handshake.server_named_curve",        \
        FT_UINT16, BASE_HEX, VALS(ssl_extension_curves), 0x0,         \
        "Server named_curve", HFILL }                                 \
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
    }


#define SSL_COMMON_ETT_LIST(name)                   \
        & name .ett.hs_ext,                         \
        & name .ett.hs_ext_alpn,                    \
        & name .ett.hs_ext_cert_types,              \
        & name .ett.hs_ext_curves,                  \
        & name .ett.hs_ext_curves_point_formats,    \
        & name .ett.hs_ext_npn,                     \
        & name .ett.hs_ext_reneg_info,              \
        & name .ett.hs_ext_server_name,             \
        & name .ett.hs_sig_hash_alg,                \
        & name .ett.hs_sig_hash_algs,               \
        & name .ett.urlhash,                        \
        & name .ett.keyex_params


#define SSL_COMMON_EI_LIST(name, prefix)                       \
        { & name .ei.hs_ext_cert_status_undecoded, { prefix ".handshake.status_request.undecoded", PI_UNDECODED, PI_NOTE,   \
          "Responder ID list or Request Extensions are not implemented, contact Wireshark developers if you want this to be supported", EXPFILL }}

typedef struct ssl_common_options {
    const gchar        *psk;
    const gchar        *keylog_filename;
} ssl_common_options_t;

extern void
ssl_common_register_options(module_t *module, ssl_common_options_t *options);

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

#endif /* SSL_UTILS_H */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
