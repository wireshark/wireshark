/* packet-ss-utils.c
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

#ifdef HAVE_LIBGNUTLS

#ifdef _WIN32
/* #include <gnutls_conf.h> */
#include <gcrypt_conf.h>
#endif

#include <stdio.h>
#include <gcrypt.h>
#include <gnutls/x509.h>
#include <gnutls/openssl.h>

/* #define SSL_FAST 1 */
#define SSL_DECRYPT_DEBUG

#define SSL_CIPHER_CTX gcry_cipher_hd_t
#ifdef SSL_FAST
#define SSL_PRIVATE_KEY gcry_mpi_t
#else
#define SSL_PRIVATE_KEY struct gcry_sexp
#endif
#else 
#define SSL_CIPHER_CTX void*
#define SSL_PRIVATE_KEY void
#endif

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

/*typedef struct _SslService {
    address addr;
    guint port;
} SslService;*/

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

void ssl_lib_init(void);
void ssl_session_init(SslDecryptSession*);
int ssl_data_alloc(StringInfo* str, unsigned int len);
int ssl_data_set(StringInfo* data, unsigned char* src, unsigned int len);

SSL_PRIVATE_KEY* ssl_load_key(FILE* fp);
void ssl_free_key(SSL_PRIVATE_KEY*);

int ssl_find_cipher(int num,SslCipherSuite* cs);

int ssl_generate_keyring_material(SslDecryptSession*ssl_session);

int ssl_decrypt_pre_master_secret(SslDecryptSession*ssl_session, 
    StringInfo* entrypted_pre_master, SSL_PRIVATE_KEY *pk);

int ssl_decrypt_record(SslDecryptSession*ssl,SslDecoder* decoder, int ct, 
        const unsigned char* in, int inl,unsigned char*out,int* outl);

#ifdef SSL_DECRYPT_DEBUG
void ssl_debug_printf(const char* fmt,...);
void ssl_print_data(const char* name, const unsigned char* data, int len);
void ssl_print_string(const char* name, const StringInfo* data);
void ssl_print_text_data(const char* name, const unsigned char* data, int len);
#else
static inline char* ssl_debug_printf(const char* fmt,...) { return fmt; }
#define ssl_print_data(a, b, c)
#define ssl_print_string(a, b)
#define ssl_print_text_data(a, b, c)
#endif

#endif
