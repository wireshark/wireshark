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
#include <epan/value_string.h>

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

 /* The TCP port to associate with by default */
#define TCP_PORT_SSL                    443
#define TCP_PORT_SSL_LDAP               636
#define TCP_PORT_SSL_IMAP               993
#define TCP_PORT_SSL_POP                995

/* version state tables */
#define SSL_VER_UNKNOWN                   0
#define SSL_VER_SSLv2                     1
#define SSL_VER_SSLv3                     2
#define SSL_VER_TLS                       3
#define SSL_VER_TLSv1DOT1                 4
#define SSL_VER_DTLS     		  5
#define SSL_VER_PCT                       6

/* corresponds to the #defines above */

static const gchar* ssl_version_short_names[] = {
    "SSL",
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLSv1.1",
    "DTLSv1.0",
    "PCT"
};

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

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define PCT_VERSION_1					0x8001

#define PCT_MSG_CLIENT_HELLO			0x01
#define PCT_MSG_SERVER_HELLO			0x02
#define PCT_MSG_CLIENT_MASTER_KEY		0x03
#define PCT_MSG_SERVER_VERIFY			0x04
#define PCT_MSG_ERROR					0x05

#define PCT_CH_OFFSET_V1				0xa

#define PCT_CIPHER_DES					0x01
#define PCT_CIPHER_IDEA					0x02
#define PCT_CIPHER_RC2					0x03
#define PCT_CIPHER_RC4					0x04
#define PCT_CIPHER_DES_112				0x05
#define PCT_CIPHER_DES_168				0x06

#define PCT_HASH_MD5					0x0001
#define PCT_HASH_MD5_TRUNC_64			0x0002
#define PCT_HASH_SHA					0x0003
#define PCT_HASH_SHA_TRUNC_80			0x0004
#define PCT_HASH_DES_DM					0x0005

#define PCT_CERT_NONE					0x00
#define PCT_CERT_X509					0x01
#define PCT_CERT_PKCS7					0x02

#define PCT_SIG_NONE					0x0000
#define PCT_SIG_RSA_MD5					0x0001
#define PCT_SIG_RSA_SHA					0x0002
#define PCT_SIG_DSA_SHA					0x0003

#define PCT_EXCH_RSA_PKCS1				0x01
#define PCT_EXCH_RSA_PKCS1_TOKEN_DES	0x02
#define PCT_EXCH_RSA_PKCS1_TOKEN_DES3	0x03
#define PCT_EXCH_RSA_PKCS1_TOKEN_RC2	0x04
#define PCT_EXCH_RSA_PKCS1_TOKEN_RC4	0x05
#define PCT_EXCH_DH_PKCS3				0x06
#define PCT_EXCH_DH_PKCS3_TOKEN_DES		0x07
#define PCT_EXCH_DH_PKCS3_TOKEN_DES3	0x08
#define PCT_EXCH_FORTEZZA_TOKEN			0x09

#define PCT_ERR_BAD_CERTIFICATE			0x01
#define PCT_ERR_CLIENT_AUTH_FAILED		0x02
#define PCT_ERR_ILLEGAL_MESSAGE			0x03
#define PCT_ERR_INTEGRITY_CHECK_FAILED	0x04
#define PCT_ERR_SERVER_AUTH_FAILED		0x05
#define PCT_ERR_SPECS_MISMATCH			0x06

/*
 * Lookup tables
 *
 */
static const value_string ssl_20_msg_types[] = {
    { SSL2_HND_ERROR,               "Error" },
    { SSL2_HND_CLIENT_HELLO,        "Client Hello" },
    { SSL2_HND_CLIENT_MASTER_KEY,   "Client Master Key" },
    { SSL2_HND_CLIENT_FINISHED,     "Client Finished" },
    { SSL2_HND_SERVER_HELLO,        "Server Hello" },
    { SSL2_HND_SERVER_VERIFY,       "Server Verify" },
    { SSL2_HND_SERVER_FINISHED,     "Server Finished" },
    { SSL2_HND_REQUEST_CERTIFICATE, "Request Certificate" },
    { SSL2_HND_CLIENT_CERTIFICATE,  "Client Certificate" },
    { 0x00, NULL },
};

static const value_string ssl_20_cipher_suites[] = {
    { 0x010080, "SSL2_RC4_128_WITH_MD5" },
    { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
    { 0x030080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
    { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
    { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
    { 0x080080, "SSL2_RC4_64_WITH_MD5" },
    { 0x000000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x000001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x000002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x000003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x000004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x000005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x000006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x000007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x000008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x00000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x00000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x000010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x000013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x000016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x000018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x000019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x00001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x00001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
    { 0x00001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
    { 0x00002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x000035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x000041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x000048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x000049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x00004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x000060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x000061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x000062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x000084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0x00fefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0x00feff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* Microsoft's old PCT protocol. These are from Eric Rescorla's
       book "SSL and TLS" */
    { 0x8f8001, "PCT_SSL_COMPAT | PCT_VERSION_1" },
    { 0x800003, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN" },
    { 0x800001, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509" },
    { 0x810001, "PCT_SSL_HASH_TYPE | PCT1_HASH_MD5" },
    { 0x810003, "PCT_SSL_HASH_TYPE | PCT1_HASH_SHA" },
    { 0x820001, "PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1" },
    { 0x830004, "PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4" },
    { 0x848040, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128" },
    { 0x842840, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128" },
    /* note that ciphersuites of {0x00????} are TLS cipher suites in
     * a sslv2 client hello message; the ???? above is the two-byte
     * tls cipher suite id
     */
    { 0x00, NULL }
};

static const value_string ssl_20_certificate_type[] = {
    { 0x00, "N/A" },
    { 0x01, "X.509 Certificate" },
    { 0x00, NULL },
};

static const value_string ssl_31_content_type[] = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" },
    { 0x00, NULL }
};

static const value_string ssl_versions[] = {
    { 0x0100, "DTLS 1.0" },
    { 0x0302, "TLS 1.1" },
    { 0x0301, "TLS 1.0" },
    { 0x0300, "SSL 3.0" },
    { 0x0002, "SSL 2.0" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected the body of a Change Cipher Spec
   message. */
static const value_string ssl_31_change_cipher_spec[] = {
    { 1, "Change Cipher Spec" },
    { 0x00, NULL },
};
#endif

static const value_string ssl_31_alert_level[] = {
    { 1, "Warning" },
    { 2, "Fatal" },
    { 0x00, NULL }
};

static const value_string ssl_31_alert_description[] = {
    {  0,  "Close Notify" },
    { 10,  "Unexpected Message" },
    { 20,  "Bad Record MAC" },
    { 21,  "Decryption Failed" },
    { 22,  "Record Overflow" },
    { 30,  "Decompression Failure" },
    { 40,  "Handshake Failure" },
    { 42,  "Bad Certificate" },
    { 43,  "Unsupported Certificate" },
    { 44,  "Certificate Revoked" },
    { 45,  "Certificate Expired" },
    { 46,  "Certificate Unknown" },
    { 47,  "Illegal Parameter" },
    { 48,  "Unknown CA" },
    { 49,  "Access Denied" },
    { 50,  "Decode Error" },
    { 51,  "Decrypt Error" },
    { 60,  "Export Restriction" },
    { 70,  "Protocol Version" },
    { 71,  "Insufficient Security" },
    { 80,  "Internal Error" },
    { 90,  "User Canceled" },
    { 100, "No Renegotiation" },
    { 0x00, NULL }
};

static const value_string ssl_31_handshake_type[] = {
    { SSL_HND_HELLO_REQUEST,     "Hello Request" },
    { SSL_HND_CLIENT_HELLO,      "Client Hello" },
    { SSL_HND_SERVER_HELLO,      "Server Hello" },
    { SSL_HND_HELLO_VERIFY_REQUEST, "Hello Verify Request"},
    { SSL_HND_CERTIFICATE,       "Certificate" },
    { SSL_HND_SERVER_KEY_EXCHG,  "Server Key Exchange" },
    { SSL_HND_CERT_REQUEST,      "Certificate Request" },
    { SSL_HND_SVR_HELLO_DONE,    "Server Hello Done" },
    { SSL_HND_CERT_VERIFY,       "Certificate Verify" },
    { SSL_HND_CLIENT_KEY_EXCHG,  "Client Key Exchange" },
    { SSL_HND_FINISHED,          "Finished" },
    { 0x00, NULL }
};

static const value_string ssl_31_compression_method[] = {
    { 0, "null" },
    { 1, "ZLIB" },
    { 64, "LZS" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected a Signature, as would be
   seen in a server key exchange or certificate verify message. */
static const value_string ssl_31_key_exchange_algorithm[] = {
    { 0, "RSA" },
    { 1, "Diffie Hellman" },
    { 0x00, NULL }
};

static const value_string ssl_31_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 0x00, NULL }
};
#endif

static const value_string ssl_31_client_certificate_type[] = {
    { 1, "RSA Sign" },
    { 2, "DSS Sign" },
    { 3, "RSA Fixed DH" },
    { 4, "DSS Fixed DH" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected exchange keys, as would be
   seen in a client key exchange message. */
static const value_string ssl_31_public_value_encoding[] = {
    { 0, "Implicit" },
    { 1, "Explicit" },
    { 0x00, NULL }
};
#endif

static const value_string ssl_31_ciphersuite[] = {
    { 0x0000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
    { 0x001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
    { 0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x0048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x0049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites 0xff00 - 0xffff are private */
    { 0x00, NULL }
};

static const value_string pct_msg_types[] = {
    { PCT_MSG_CLIENT_HELLO,         "Client Hello" },
    { PCT_MSG_SERVER_HELLO,         "Server Hello" },
    { PCT_MSG_CLIENT_MASTER_KEY,    "Client Master Key" },
    { PCT_MSG_SERVER_VERIFY,        "Server Verify" },
    { PCT_MSG_ERROR,                "Error" },
    { 0x00, NULL },
};

static const value_string pct_cipher_type[] = {
	{ PCT_CIPHER_DES, "DES" },
	{ PCT_CIPHER_IDEA, "IDEA" },
	{ PCT_CIPHER_RC2, "RC2" },
	{ PCT_CIPHER_RC4, "RC4" },
	{ PCT_CIPHER_DES_112, "DES 112 bit" },
	{ PCT_CIPHER_DES_168, "DES 168 bit" },
	{ 0x00, NULL },
};

static const value_string pct_hash_type[] = {
	{ PCT_HASH_MD5, "MD5" },
	{ PCT_HASH_MD5_TRUNC_64, "MD5_TRUNC_64"},
	{ PCT_HASH_SHA, "SHA"},
	{ PCT_HASH_SHA_TRUNC_80, "SHA_TRUNC_80"},
	{ PCT_HASH_DES_DM, "DES_DM"},
	{ 0x00, NULL },
};

static const value_string pct_cert_type[] = {
	{ PCT_CERT_NONE, "None" },
	{ PCT_CERT_X509, "X.509" },
	{ PCT_CERT_PKCS7, "PKCS #7" },
	{ 0x00, NULL },
};
static const value_string pct_sig_type[]  = {
	{ PCT_SIG_NONE, "None" },
	{ PCT_SIG_RSA_MD5, "MD5" },
	{ PCT_SIG_RSA_SHA, "RSA SHA" },
	{ PCT_SIG_DSA_SHA, "DSA SHA" },
	{ 0x00, NULL },
};

static const value_string pct_exch_type[] = {
	{ PCT_EXCH_RSA_PKCS1, "RSA PKCS#1" },
	{ PCT_EXCH_RSA_PKCS1_TOKEN_DES, "RSA PKCS#1 Token DES" },
	{ PCT_EXCH_RSA_PKCS1_TOKEN_DES3, "RSA PKCS#1 Token 3DES" },	
	{ PCT_EXCH_RSA_PKCS1_TOKEN_RC2, "RSA PKCS#1 Token RC-2" },
	{ PCT_EXCH_RSA_PKCS1_TOKEN_RC4, "RSA PKCS#1 Token RC-4" },
	{ PCT_EXCH_DH_PKCS3, "DH PKCS#3" },
	{ PCT_EXCH_DH_PKCS3_TOKEN_DES, "DH PKCS#3 Token DES" },
	{ PCT_EXCH_DH_PKCS3_TOKEN_DES3, "DH PKCS#3 Token 3DES" },
	{ PCT_EXCH_FORTEZZA_TOKEN, "Fortezza" },
	{ 0x00, NULL },
};

static const value_string pct_error_code[] = {
	{ PCT_ERR_BAD_CERTIFICATE, "PCT_ERR_BAD_CERTIFICATE" },
	{ PCT_ERR_CLIENT_AUTH_FAILED, "PCT_ERR_CLIENT_AUTH_FAILE" },
	{ PCT_ERR_ILLEGAL_MESSAGE, "PCT_ERR_ILLEGAL_MESSAGE" },
	{ PCT_ERR_INTEGRITY_CHECK_FAILED, "PCT_ERR_INTEGRITY_CHECK_FAILED" },
	{ PCT_ERR_SERVER_AUTH_FAILED, "PCT_ERR_SERVER_AUTH_FAILED" },
	{ PCT_ERR_SPECS_MISMATCH, "PCT_ERR_SPECS_MISMATCH" },
	{ 0x00, NULL },
};

/* RFC 3546 */
static const value_string tls_hello_extension_types[] = {
	{ 0, "server_name" },
	{ 1, "max_fragment_length" },
	{ 2, "client_certificate_url" },
	{ 3, "trusted_ca_keys" },
	{ 4, "truncated_hmac" },
	{ 5, "status_request" },
	{ 35, "EAP-FAST PAC-Opaque" /* draft-cam-winget-eap-fast-00.txt */ },
	{ 0, NULL }
};

typedef struct _StringInfo {
    unsigned char* data;
    unsigned int data_len;
} StringInfo;

#define SSL_WRITE_KEY           1

#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define DTLSV1DOT0_VERSION     0x100

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
    guint16 epoch;
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
    StringInfo app_data_segment; 
  
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
