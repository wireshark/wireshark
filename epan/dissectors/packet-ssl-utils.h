/* packet-ssl-utils.h
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __SSL_UTILS_H_
#define __SSL_UTILS_H_

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/value_string.h>

#include <stdio.h>

#ifdef HAVE_LIBGNUTLS
#include <gcrypt.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

#include <epan/conversation.h>

/* #define SSL_FAST 1 */
#define SSL_DECRYPT_DEBUG

#define SSL_CIPHER_CTX gcry_cipher_hd_t
#define SSL_PSK_KEY guchar
#ifdef SSL_FAST
#define SSL_PRIVATE_KEY gcry_mpi_t
#else /* SSL_FAST */
#define SSL_PRIVATE_KEY struct gcry_sexp
#endif /* SSL_FAST */
#else  /* HAVE_LIBGNUTLS */
#define SSL_CIPHER_CTX void*
#define SSL_PRIVATE_KEY void
#define SSL_PSK_KEY void
#endif /* HAVE_LIBGNUTLS */


/* version state tables */
#define SSL_VER_UNKNOWN                   0
#define SSL_VER_SSLv2                     1
#define SSL_VER_SSLv3                     2
#define SSL_VER_TLS                       3
#define SSL_VER_TLSv1DOT1                 4
#define SSL_VER_DTLS                      5
#define SSL_VER_PCT                       6
#define SSL_VER_TLSv1DOT2                 7

/* other defines */
#define SSL_ID_CHG_CIPHER_SPEC         0x14
#define SSL_ID_ALERT                   0x15
#define SSL_ID_HANDSHAKE               0x16
#define SSL_ID_APP_DATA                0x17

#define SSL_HND_HELLO_REQUEST          0
#define SSL_HND_CLIENT_HELLO           1
#define SSL_HND_SERVER_HELLO           2
#define SSL_HND_HELLO_VERIFY_REQUEST   3
#define SSL_HND_CERTIFICATE            11
#define SSL_HND_SERVER_KEY_EXCHG       12
#define SSL_HND_CERT_REQUEST           13
#define SSL_HND_SVR_HELLO_DONE         14
#define SSL_HND_CERT_VERIFY            15
#define SSL_HND_CLIENT_KEY_EXCHG       16
#define SSL_HND_FINISHED               20
#define SSL_HND_CERT_STATUS            22

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

#define SSL_HND_HELLO_EXT_ELLIPTIC_CURVES    0x000a
#define SSL_HND_HELLO_EXT_EC_POINT_FORMATS   0x000b

#define SSL_HND_CERT_STATUS_TYPE_OCSP  1

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
extern const value_string tls_cert_status_type[];
extern const value_string ssl_extension_curves[];
extern const value_string ssl_extension_ec_point_formats[];

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

#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)

#define SSL_CIPHER_MODE_STREAM  0
#define SSL_CIPHER_MODE_CBC     1

#define SSL_DEBUG_USE_STDERR "-"

#define SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES 16

typedef struct _SslCipherSuite {
     gint number;
     gint kex;
     gint sig;
     gint enc;
     gint block;
     gint bits;
     gint eff_bits;
     gint dig;
     gint dig_len;
     gint export;
     gint mode;
} SslCipherSuite;

typedef struct _SslFlow {
    guint32 byte_seq;
    guint16 flags;
    emem_tree_t *multisegment_pdus;
} SslFlow;

typedef struct _SslDecompress SslDecompress;

typedef struct _SslDecoder {
    SslCipherSuite* cipher_suite;
    gint compression;
    guchar _mac_key[20];
    StringInfo mac_key;
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    guint32 seq;
    guint16 epoch;
    SslFlow *flow;
} SslDecoder;

#define KEX_RSA         0x10
#define KEX_DH          0x11
#define KEX_PSK         0x12

#define SIG_RSA         0x20
#define SIG_DSS         0x21
#define SIG_NONE        0x22

#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_NULL        0x37

#define DIG_MD5         0x40
#define DIG_SHA         0x41

struct tvbuff;

typedef struct _SslRecordInfo {
    struct tvbuff* tvb;
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

typedef struct _SslDecryptSession {
    guchar _master_secret[48];
    guchar _session_id[256];
    guchar _client_random[32];
    guchar _server_random[32];
    StringInfo session_id;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    guchar _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    guchar _client_data_for_iv[24];
    StringInfo client_data_for_iv;

    gint cipher;
    gint compression;
    gint state;
    SslCipherSuite cipher_suite;
    SslDecoder *server;
    SslDecoder *client;
    SslDecoder *server_new;
    SslDecoder *client_new;
    SSL_PRIVATE_KEY* private_key;
    SSL_PSK_KEY* psk;
    guint32 version;
    guint16 version_netorder;
    StringInfo app_data_segment;

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

extern Ssl_private_key_t *
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd);

/** Deallocate the memory used for specified key
 @param key pointer to the key to be freed */
extern void
ssl_free_key(Ssl_private_key_t* key);

/* Find private key in associations */
extern gint
ssl_find_private_key(SslDecryptSession *ssl_session, GHashTable *key_hash, GTree* associations, packet_info *pinfo);

/** Search for the specified cipher souite id
 @param num the id of the cipher suite to be searched
 @param cs pointer to the cipher suite struct to be filled
 @return 0 if the cipher suite is found, -1 elsewhere */
extern gint
ssl_find_cipher(int num,SslCipherSuite* cs);

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
 @param ssl_keylog_filename a file that contains a log of pre-master secrets
 @param encrypted_pre_master the rsa encrypted pre_master_secret
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
 @param in a pinter to the ssl record to be decrypted
 @param inl the record length
 @param comp_str
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

/* add to packet data a newly allocated tvb with the specified real data*/
extern void
ssl_add_record_info(gint proto, packet_info *pinfo, guchar* data, gint data_len, gint record_id);

/* search in packet data the tvbuff associated to the specified id */
extern tvbuff_t*
ssl_get_record_info(gint proto, packet_info *pinfo, gint record_id);

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

extern void
ssl_restore_session(SslDecryptSession* ssl, GHashTable *session_hash);

extern gint
ssl_is_valid_content_type(guint8 type);

#ifdef SSL_DECRYPT_DEBUG
extern void
ssl_debug_printf(const gchar* fmt,...) G_GNUC_PRINTF(1,2);
extern void
ssl_print_data(const gchar* name, const guchar* data, size_t len);
extern void
ssl_print_string(const gchar* name, const StringInfo* data);
extern void
ssl_print_text_data(const gchar* name, const guchar* data, size_t len);
extern void
ssl_set_debug(gchar* name);
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
#define ssl_print_text_data(a, b, c)
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
 * vi: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */
