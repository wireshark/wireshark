/* packet-ssl-utils.h
 *
 * $Id$
 *
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
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
#include <epan/gnuc_format_check.h>

#ifdef HAVE_LIBGNUTLS
#ifdef _WIN32
#include <winposixtype.h>
#endif /* _WIN32 */

#include <stdio.h>
#include <gcrypt.h>
#include <gnutls/x509.h>
#include <gnutls/openssl.h>

/* #define SSL_FAST 1 */
#define SSL_DECRYPT_DEBUG

#define SSL_CIPHER_CTX gcry_cipher_hd_t
#ifdef SSL_FAST
#define SSL_PRIVATE_KEY gcry_mpi_t
#else /* SSL_FAST */
#define SSL_PRIVATE_KEY struct gcry_sexp
#endif /* SSL_FAST */
#else  /* HAVE_LIBGNUTLS */
#define SSL_CIPHER_CTX void*
#define SSL_PRIVATE_KEY void
#endif /* HAVE_LIBGNUTLS */

typedef struct _StringInfo {
    unsigned char* data;
    unsigned int data_len;
} StringInfo;

#define SSL_WRITE_KEY           1

#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301

#define SSL_CLIENT_RANDOM       1
#define SSL_SERVER_RANDOM       2
#define SSL_CIPHER              4
#define SSL_HAVE_SESSION_KEY    8    
#define SSL_VERSION             0x10
#define SSL_MASTER_SECRET       0x20

#define SSL_CIPHER_MODE_STREAM  0
#define SSL_CIPHER_MODE_CBC     1

#define SSL_DEBUG_USE_STDERR "-"

typedef struct _SslCipherSuite {
     int number;
     int kex;
     int sig;
     int enc;
     int block;
     int bits;
     int eff_bits;
     int dig;
     int dig_len;
     int export;
     int mode;
} SslCipherSuite;

typedef struct _SslDecoder {
    SslCipherSuite* cipher_suite;
    unsigned char _mac_key[20];
    StringInfo mac_key;
    SSL_CIPHER_CTX evp;    
    guint32 seq;
} SslDecoder;

#define KEX_RSA         0x10
#define KEX_DH          0x11

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
    int id;
    struct _SslRecordInfo* next;
} SslRecordInfo;

typedef struct {
    StringInfo app_data;
    SslRecordInfo* handshake_data; 
} SslPacketInfo;

typedef struct _SslDecryptSession {
    unsigned char _master_secret[48];
    unsigned char _session_id[256];
    unsigned char _client_random[32];
    unsigned char _server_random[32];
    StringInfo session_id;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    StringInfo pre_master_secret;
    
    int cipher;
    int state;
    SslCipherSuite cipher_suite;
    SslDecoder server;
    SslDecoder client;
    SSL_PRIVATE_KEY* private_key;
    guint32 version;
    guint16 version_netorder;  

} SslDecryptSession;

/** Initialize decryption engine/ssl layer. To be called once per execution */
extern void 
ssl_lib_init(void);

/** Initialize an ssl session struct
 @param ssl pointer to ssl session struct to be initialized */
extern void 
ssl_session_init(SslDecryptSession* ssl);

/** set the data and len for the stringInfo buffer. buf should be big enough to
 * contain the provided data
 @param buf the buffer to update
 @param src the data source 
 @param len the source data len */
extern void 
ssl_data_set(StringInfo* buf, unsigned char* src, unsigned int len);

/** Load an RSA private key from specified file
 @param fp the file that contain the key data
 @return a pointer to the loaded key on success, or NULL */
extern SSL_PRIVATE_KEY* 
ssl_load_key(FILE* fp);

/** Deallocate the memory used for specified key 
 @param pointer to the key to be freed */
extern void 
ssl_free_key(SSL_PRIVATE_KEY* key);

/* Search for the specified cipher souite id 
 @param num the id of the cipher suite to be searched 
 @param cs pointer to the cipher suite struct to be filled 
 @return 0 if the cipher suite is found, -1 elsewhere */
extern int 
ssl_find_cipher(int num,SslCipherSuite* cs);

/* Expand the pre_master_secret to generate all the session information 
 * (master secret, session keys, ivs)
 @param ssl_session the store for all the session data
 @return 0 on success */
extern int 
ssl_generate_keyring_material(SslDecryptSession*ssl_session);

/* Try to decrypt in place the encrypted pre_master_secret
 @param ssl_session the store for the decrypted pre_master_secret
 @param entrypted_pre_master the rsa encrypted pre_master_secret
 @param pk the private key to be used for decryption
 @return 0 on success */
extern int 
ssl_decrypt_pre_master_secret(SslDecryptSession*ssl_session, 
    StringInfo* entrypted_pre_master, SSL_PRIVATE_KEY *pk);

/* Try to decrypt an ssl record
 @param ssl_session the store all the session data
 @param decoder the stream decoder to be used
 @param ct the content type of this ssl record
 @param in a pinter to the ssl record to be decrypted
 @param inl the record lenght
 @param out a pointer to the store for the decrypted data
 @param outl the decrypted data len 
 @return 0 on success */
extern int 
ssl_decrypt_record(SslDecryptSession*ssl,SslDecoder* decoder, int ct, 
        const unsigned char* in, int inl,unsigned char*out,int* outl);

#ifdef SSL_DECRYPT_DEBUG
extern void 
ssl_debug_printf(const char* fmt,...) GNUC_FORMAT_CHECK(printf,1,2);
extern void 
ssl_print_data(const char* name, const unsigned char* data, int len);
extern void 
ssl_print_string(const char* name, const StringInfo* data);
extern void 
ssl_print_text_data(const char* name, const unsigned char* data, int len);
extern void 
ssl_set_debug(char* name);
#else

/* No debug: nullify debug operation*/
static inline void GNUC_FORMAT_CHECK(printf,1,2)
ssl_debug_printf(const char* fmt _U_,...)
{ 
}
#define ssl_print_data(a, b, c)
#define ssl_print_string(a, b)
#define ssl_print_text_data(a, b, c)
#define ssl_set_debug(name)

#endif

#endif
