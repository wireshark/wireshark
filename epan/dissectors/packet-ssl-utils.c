/* packet-ssl-utils.c
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Copyright (c) 2013, Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright (c) 2014, Peter Wu <peter@lekensteyn.nl>
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

#include "config.h"

#ifdef HAVE_ZLIB
#define ZLIB_CONST
#include <zlib.h>
#endif

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/ipv6.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>
#include <wsutil/report_err.h>
#include <wsutil/pint.h>
#include <wsutil/strtoi.h>
#include <ws_version_info.h>
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-ssl-utils.h"
#include "packet-ssl.h"
#include "packet-dtls.h"
#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
#include <gnutls/abstract.h>
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
/* Whether to provide support for authentication in addition to decryption. */
#define HAVE_LIBGCRYPT_AEAD
#endif

/* Lookup tables {{{ */
const value_string ssl_version_short_names[] = {
    { SSL_VER_UNKNOWN,      "SSL" },
    { SSLV2_VERSION,        "SSLv2" },
    { SSLV3_VERSION,        "SSLv3" },
    { TLSV1_VERSION,        "TLSv1" },
    { TLSV1DOT1_VERSION,    "TLSv1.1" },
    { TLSV1DOT2_VERSION,    "TLSv1.2" },
    { TLSV1DOT3_VERSION,    "TLSv1.3" },
    { DTLSV1DOT0_VERSION,   "DTLSv1.0" },
    { DTLSV1DOT2_VERSION,   "DTLSv1.2" },
    { DTLSV1DOT0_OPENSSL_VERSION, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { PCT_VERSION,          "PCT" },
    { 0x00, NULL }
};

const value_string ssl_versions[] = {
    { SSLV2_VERSION,        "SSL 2.0" },
    { SSLV3_VERSION,        "SSL 3.0" },
    { TLSV1_VERSION,        "TLS 1.0" },
    { TLSV1DOT1_VERSION,    "TLS 1.1" },
    { TLSV1DOT2_VERSION,    "TLS 1.2" },
    { TLSV1DOT3_VERSION,    "TLS 1.3" },
    { 0x7F0E,               "TLS 1.3 (draft 14)" },
    { 0x7F0F,               "TLS 1.3 (draft 15)" },
    { 0x7F10,               "TLS 1.3 (draft 16)" },
    { 0x7F11,               "TLS 1.3 (draft 17)" },
    { 0x7F12,               "TLS 1.3 (draft 18)" },
    { DTLSV1DOT0_OPENSSL_VERSION, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { DTLSV1DOT0_VERSION,   "DTLS 1.0" },
    { DTLSV1DOT2_VERSION,   "DTLS 1.2" },
    { 0x00, NULL }
};

const value_string ssl_20_msg_types[] = {
    { SSL2_HND_ERROR,               "Error" },
    { SSL2_HND_CLIENT_HELLO,        "Client Hello" },
    { SSL2_HND_CLIENT_MASTER_KEY,   "Client Master Key" },
    { SSL2_HND_CLIENT_FINISHED,     "Client Finished" },
    { SSL2_HND_SERVER_HELLO,        "Server Hello" },
    { SSL2_HND_SERVER_VERIFY,       "Server Verify" },
    { SSL2_HND_SERVER_FINISHED,     "Server Finished" },
    { SSL2_HND_REQUEST_CERTIFICATE, "Request Certificate" },
    { SSL2_HND_CLIENT_CERTIFICATE,  "Client Certificate" },
    { 0x00, NULL }
};
/* http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
/* Note: sorted by ascending value so value_string-ext can do a binary search */
static const value_string ssl_20_cipher_suites[] = {
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
#if 0
    { 0x00001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif
    /* RFC 2712 */
    { 0x00001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x00001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x000020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x000021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x000022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x000023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x000024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x000025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x000026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x000027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x000028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x000029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x00002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x00002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    /* RFC 4785 */
    { 0x00002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x00002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x00002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    /* RFC 5246 */
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
    { 0x00003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x00003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x00003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
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
    { 0x000067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x000069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x00006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x00006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    /* 0x00,0x6E-83 Unassigned  */
    { 0x000084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* RFC 4279 */
    { 0x00008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x00008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x00008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x000092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x000093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    /* RFC 4162 */
    { 0x000096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x000097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x000098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x000099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x00009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x00009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    /* RFC 5288 */
    { 0x00009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x0000A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x0000A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    /* RFC 5487 */
    { 0x0000A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x0000B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x0000B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x0000B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x0000B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x0000B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    /* From RFC 5932 */
    { 0x0000BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* 0x00,0xC6-FE Unassigned  */
    { 0x0000FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* 0x01-BF,* Unassigned  */
    /* From RFC 4492 */
    { 0x00c001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x00c002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0x00c007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0x00c00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0x00c00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0x00c011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0x00c012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0x00c016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0x00c017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0x00c019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    /* RFC 5054 */
    { 0x00C01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0x00C01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00C01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0x00C020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0x00C021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00C022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    /* RFC 5589 */
    { 0x00C023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    /* RFC 5489 */
    { 0x00C033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0x00C034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00C036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00C037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00C038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00C039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0x00C03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0x00C03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    /* 0xC0,0x3C-FF Unassigned
            0xC1-FD,* Unassigned
            0xFE,0x00-FD Unassigned
            0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
            0xFF,0x00-FF Reserved for Private Use [RFC5246]
            */

    /* old numbers used in the beginning
     * http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0x00CC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },

    /* http://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */
    { 0x00CCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },

    /* http://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    { 0x00E410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E411, "TLS_RSA_WITH_SALSA20_SHA1" },
    { 0x00E412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1" },
    { 0x00E414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1" },
    { 0x00E416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E417, "TLS_PSK_WITH_SALSA20_SHA1" },
    { 0x00E418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1" },

    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0x00fefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0x00feff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites of {0x00????} are TLS cipher suites in
     * a sslv2 client hello message; the ???? above is the two-byte
     * tls cipher suite id
     */

    { 0x010080, "SSL2_RC4_128_WITH_MD5" },
    { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
    { 0x030080, "SSL2_RC2_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5" },
    { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
    { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
    { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
    { 0x080080, "SSL2_RC4_64_WITH_MD5" },

    /* Microsoft's old PCT protocol. These are from Eric Rescorla's
       book "SSL and TLS" */
    { 0x800001, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509" },
    { 0x800003, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN" },
    { 0x810001, "PCT_SSL_HASH_TYPE | PCT1_HASH_MD5" },
    { 0x810003, "PCT_SSL_HASH_TYPE | PCT1_HASH_SHA" },
    { 0x820001, "PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1" },
    { 0x830004, "PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4" },
    { 0x842840, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128" },
    { 0x848040, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128" },
    { 0x8f8001, "PCT_SSL_COMPAT | PCT_VERSION_1" },
    { 0x00, NULL }
};

value_string_ext ssl_20_cipher_suites_ext = VALUE_STRING_EXT_INIT(ssl_20_cipher_suites);


const value_string ssl_extension_curves[] = {
    {  1, "sect163k1" },
    {  2, "sect163r1" },
    {  3, "sect163r2" },
    {  4, "sect193r1" },
    {  5, "sect193r2" },
    {  6, "sect233k1" },
    {  7, "sect233r1" },
    {  8, "sect239k1" },
    {  9, "sect283k1" },
    { 10, "sect283r1" },
    { 11, "sect409k1" },
    { 12, "sect409r1" },
    { 13, "sect571k1" },
    { 14, "sect571r1" },
    { 15, "secp160k1" },
    { 16, "secp160r1" },
    { 17, "secp160r2" },
    { 18, "secp192k1" },
    { 19, "secp192r1" },
    { 20, "secp224k1" },
    { 21, "secp224r1" },
    { 22, "secp256k1" },
    { 23, "secp256r1" },
    { 24, "secp384r1" },
    { 25, "secp521r1" },
    { 26, "brainpoolP256r1" }, /* RFC 7027 */
    { 27, "brainpoolP384r1" }, /* RFC 7027 */
    { 28, "brainpoolP512r1" }, /* RFC 7027 */
    { 29, "ecdh_x25519" }, /* https://tools.ietf.org/html/draft-ietf-tls-rfc4492bis */
    { 30, "ecdh_x448" }, /* https://tools.ietf.org/html/draft-ietf-tls-rfc4492bis */
    { 256, "ffdhe2048" }, /* https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe */
    { 257, "ffdhe3072" }, /* https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe */
    { 258, "ffdhe4096" }, /* https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe */
    { 259, "ffdhe6144" }, /* https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe */
    { 260, "ffdhe8192" }, /* https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe */
    { 0xFF01, "arbitrary_explicit_prime_curves" },
    { 0xFF02, "arbitrary_explicit_char2_curves" },
    { 0x00, NULL }
};

const value_string ssl_curve_types[] = {
    { 1, "explicit_prime" },
    { 2, "explicit_char2" },
    { 3, "named_curve" },
    { 0x00, NULL }
};

const value_string ssl_extension_ec_point_formats[] = {
    { 0, "uncompressed" },
    { 1, "ansiX962_compressed_prime" },
    { 2, "ansiX962_compressed_char2" },
    { 0x00, NULL }
};

const value_string ssl_20_certificate_type[] = {
    { 0x00, "N/A" },
    { 0x01, "X.509 Certificate" },
    { 0x00, NULL }
};

const value_string ssl_31_content_type[] = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" },
    { 24, "Heartbeat" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected the body of a Change Cipher Spec
   message. */
const value_string ssl_31_change_cipher_spec[] = {
    { 1, "Change Cipher Spec" },
    { 0x00, NULL }
};
#endif

const value_string ssl_31_alert_level[] = {
    { 1, "Warning" },
    { 2, "Fatal" },
    { 0x00, NULL }
};

const value_string ssl_31_alert_description[] = {
    {   0,  "Close Notify" },
    {   1,  "End of Early Data" },
    {  10,  "Unexpected Message" },
    {  20,  "Bad Record MAC" },
    {  21,  "Decryption Failed" },
    {  22,  "Record Overflow" },
    {  30,  "Decompression Failure" },
    {  40,  "Handshake Failure" },
    {  41,  "No Certificate" },
    {  42,  "Bad Certificate" },
    {  43,  "Unsupported Certificate" },
    {  44,  "Certificate Revoked" },
    {  45,  "Certificate Expired" },
    {  46,  "Certificate Unknown" },
    {  47,  "Illegal Parameter" },
    {  48,  "Unknown CA" },
    {  49,  "Access Denied" },
    {  50,  "Decode Error" },
    {  51,  "Decrypt Error" },
    {  60,  "Export Restriction" },
    {  70,  "Protocol Version" },
    {  71,  "Insufficient Security" },
    {  80,  "Internal Error" },
    {  86,  "Inappropriate Fallback" },
    {  90,  "User Canceled" },
    { 100, "No Renegotiation" },
    { 109, "Missing Extension" },
    { 110, "Unsupported Extension" },
    { 111, "Certificate Unobtainable" },
    { 112, "Unrecognized Name" },
    { 113, "Bad Certificate Status Response" },
    { 114, "Bad Certificate Hash Value" },
    { 115, "Unknown PSK Identity" },
    { 116, "Certificate Required" },
    { 120, "No application Protocol" },
    { 0x00, NULL }
};

const value_string ssl_31_handshake_type[] = {
    { SSL_HND_HELLO_REQUEST,     "Hello Request" },
    { SSL_HND_CLIENT_HELLO,      "Client Hello" },
    { SSL_HND_SERVER_HELLO,      "Server Hello" },
    { SSL_HND_HELLO_VERIFY_REQUEST, "Hello Verify Request"},
    { SSL_HND_NEWSESSION_TICKET, "New Session Ticket" },
    { SSL_HND_HELLO_RETRY_REQUEST, "Hello Retry Request" },
    { SSL_HND_ENCRYPTED_EXTENSIONS, "Encrypted Extensions" },
    { SSL_HND_CERTIFICATE,       "Certificate" },
    { SSL_HND_SERVER_KEY_EXCHG,  "Server Key Exchange" },
    { SSL_HND_CERT_REQUEST,      "Certificate Request" },
    { SSL_HND_SVR_HELLO_DONE,    "Server Hello Done" },
    { SSL_HND_CERT_VERIFY,       "Certificate Verify" },
    { SSL_HND_CLIENT_KEY_EXCHG,  "Client Key Exchange" },
    { SSL_HND_FINISHED,          "Finished" },
    { SSL_HND_CERT_URL,          "Client Certificate URL" },
    { SSL_HND_CERT_STATUS,       "Certificate Status" },
    { SSL_HND_SUPPLEMENTAL_DATA, "Supplemental Data" },
    { SSL_HND_ENCRYPTED_EXTS,    "Encrypted Extensions" },
    { 0x00, NULL }
};

const value_string tls_heartbeat_type[] = {
    { 1, "Request" },
    { 2, "Response" },
    { 0x00, NULL }
};

const value_string tls_heartbeat_mode[] = {
    { 1, "Peer allowed to send requests" },
    { 2, "Peer not allowed to send requests" },
    { 0x00, NULL }
};

const value_string ssl_31_compression_method[] = {
    {  0, "null" },
    {  1, "DEFLATE" },
    { 64, "LZS" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected a Signature, as would be
   seen in a server key exchange or certificate verify message. */
const value_string ssl_31_key_exchange_algorithm[] = {
    { 0, "RSA" },
    { 1, "Diffie Hellman" },
    { 0x00, NULL }
};

const value_string ssl_31_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 0x00, NULL }
};
#endif

const value_string ssl_31_client_certificate_type[] = {
    { 1, "RSA Sign" },
    { 2, "DSS Sign" },
    { 3, "RSA Fixed DH" },
    { 4, "DSS Fixed DH" },
    /* GOST certificate types */
    /* Section 3.5 of draft-chudov-cryptopro-cptls-04 */
    { 21, "GOST R 34.10-94" },
    { 22, "GOST R 34.10-2001" },
    /* END GOST certificate types */
    { 64, "ECDSA Sign" },
    { 65, "RSA Fixed ECDH" },
    { 66, "ECDSA Fixed ECDH" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected exchange keys, as would be
   seen in a client key exchange message. */
const value_string ssl_31_public_value_encoding[] = {
    { 0, "Implicit" },
    { 1, "Explicit" },
    { 0x00, NULL }
};
#endif

/* http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
/* Note: sorted by ascending value so value_string_ext fcns can do a binary search */
static const value_string ssl_31_ciphersuite[] = {
    /* RFC 2246, RFC 4346, RFC 5246 */
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
#if 0 /* Because it clashes with KRB5, is never used any more, and is safe
         to remove according to David Hopwood <david.hopwood@zetnet.co.uk>
         of the ietf-tls list */
    { 0x001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif

    /* RFC 2712 */
    { 0x001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },

    /* RFC 4785 */
    { 0x002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x002E, "TLS_RSA_PSK_WITH_NULL_SHA" },

    /* RFC 5246 */
    { 0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA" },
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
    { 0x003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },

    /* RFC 4132 */
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },

    /* 0x00,0x60-66 Reserved to avoid conflicts with widely deployed implementations  */
    /* --- ??? --- */
    { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    /* draft-ietf-tls-56-bit-ciphersuites-01.txt */
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    /* --- ??? ---*/

    { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },

    /* draft-chudov-cryptopro-cptls-04.txt */
    { 0x0080,  "TLS_GOSTR341094_WITH_28147_CNT_IMIT" },
    { 0x0081,  "TLS_GOSTR341001_WITH_28147_CNT_IMIT" },
    { 0x0082,  "TLS_GOSTR341094_WITH_NULL_GOSTR3411" },
    { 0x0083,  "TLS_GOSTR341001_WITH_NULL_GOSTR3411" },

    /* RFC 4132 */
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },

    /* RFC 4279 */
    { 0x008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },

    /* RFC 4162 */
    { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },

    /* RFC 5288 */
    { 0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },

    /* RFC 5487 */
    { 0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x00B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },

    /* From RFC 5932 */
    { 0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* 0x00,0xC6-FE Unassigned  */
    /* From RFC 5746 */
    { 0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { 0x1301, "TLS_AES_128_GCM_SHA256" },
    { 0x1302, "TLS_AES_256_GCM_SHA384" },
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" },
    { 0x1304, "TLS_AES_128_CCM_SHA256" },
    { 0x1305, "TLS_AES_128_CCM_8_SHA256" },
    /* From RFC 7507 */
    { 0x5600, "TLS_FALLBACK_SCSV" },
    /* From RFC 4492 */
    { 0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0xc015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },

    /* RFC 5054 */
    { 0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },

    /* RFC 5589 */
    { 0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },

    /* RFC 5489 */
    { 0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },

    /* RFC 6209 */
    { 0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256" },
    { 0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384" },
    { 0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" },

    /* RFC 6367 */
    { 0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },

    /* RFC 6655 */
    { 0xC09C, "TLS_RSA_WITH_AES_128_CCM" },
    { 0xC09D, "TLS_RSA_WITH_AES_256_CCM" },
    { 0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM" },
    { 0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM" },
    { 0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A4, "TLS_PSK_WITH_AES_128_CCM" },
    { 0xC0A5, "TLS_PSK_WITH_AES_256_CCM" },
    { 0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM" },
    { 0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM" },
    { 0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8" },
    { 0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8" },
    { 0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8" },
    { 0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8" },

    /* RFC 7251 */
    { 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
    { 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
    { 0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" },
    { 0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" },
/*
0xC0,0xAB-FF Unassigned
0xC1-FD,* Unassigned
0xFE,0x00-FD Unassigned
0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
0xFF,0x00-FF Reserved for Private Use [RFC5246]
*/

    /* old numbers used in the beginning
     * http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0xCC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },

    /* http://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */
    { 0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },

    /* http://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    { 0xE410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE411, "TLS_RSA_WITH_SALSA20_SHA1" },
    { 0xE412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1" },
    { 0xE414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1" },
    { 0xE416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE417, "TLS_PSK_WITH_SALSA20_SHA1" },
    { 0xE418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1" },
    { 0xE41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1" },
    { 0xE41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1" },
    { 0xE41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1" },

    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites 0xff00 - 0xffff are private */
    { 0x00, NULL }
};

value_string_ext ssl_31_ciphersuite_ext = VALUE_STRING_EXT_INIT(ssl_31_ciphersuite);


const value_string pct_msg_types[] = {
    { PCT_MSG_CLIENT_HELLO,         "Client Hello" },
    { PCT_MSG_SERVER_HELLO,         "Server Hello" },
    { PCT_MSG_CLIENT_MASTER_KEY,    "Client Master Key" },
    { PCT_MSG_SERVER_VERIFY,        "Server Verify" },
    { PCT_MSG_ERROR,                "Error" },
    { 0x00, NULL }
};

const value_string pct_cipher_type[] = {
    { PCT_CIPHER_DES, "DES" },
    { PCT_CIPHER_IDEA, "IDEA" },
    { PCT_CIPHER_RC2, "RC2" },
    { PCT_CIPHER_RC4, "RC4" },
    { PCT_CIPHER_DES_112, "DES 112 bit" },
    { PCT_CIPHER_DES_168, "DES 168 bit" },
    { 0x00, NULL }
};

const value_string pct_hash_type[] = {
    { PCT_HASH_MD5, "MD5" },
    { PCT_HASH_MD5_TRUNC_64, "MD5_TRUNC_64"},
    { PCT_HASH_SHA, "SHA"},
    { PCT_HASH_SHA_TRUNC_80, "SHA_TRUNC_80"},
    { PCT_HASH_DES_DM, "DES_DM"},
    { 0x00, NULL }
};

const value_string pct_cert_type[] = {
    { PCT_CERT_NONE, "None" },
    { PCT_CERT_X509, "X.509" },
    { PCT_CERT_PKCS7, "PKCS #7" },
    { 0x00, NULL }
};
const value_string pct_sig_type[] = {
    { PCT_SIG_NONE, "None" },
    { PCT_SIG_RSA_MD5, "MD5" },
    { PCT_SIG_RSA_SHA, "RSA SHA" },
    { PCT_SIG_DSA_SHA, "DSA SHA" },
    { 0x00, NULL }
};

const value_string pct_exch_type[] = {
    { PCT_EXCH_RSA_PKCS1, "RSA PKCS#1" },
    { PCT_EXCH_RSA_PKCS1_TOKEN_DES, "RSA PKCS#1 Token DES" },
    { PCT_EXCH_RSA_PKCS1_TOKEN_DES3, "RSA PKCS#1 Token 3DES" },
    { PCT_EXCH_RSA_PKCS1_TOKEN_RC2, "RSA PKCS#1 Token RC-2" },
    { PCT_EXCH_RSA_PKCS1_TOKEN_RC4, "RSA PKCS#1 Token RC-4" },
    { PCT_EXCH_DH_PKCS3, "DH PKCS#3" },
    { PCT_EXCH_DH_PKCS3_TOKEN_DES, "DH PKCS#3 Token DES" },
    { PCT_EXCH_DH_PKCS3_TOKEN_DES3, "DH PKCS#3 Token 3DES" },
    { PCT_EXCH_FORTEZZA_TOKEN, "Fortezza" },
    { 0x00, NULL }
};

const value_string pct_error_code[] = {
    { PCT_ERR_BAD_CERTIFICATE, "PCT_ERR_BAD_CERTIFICATE" },
    { PCT_ERR_CLIENT_AUTH_FAILED, "PCT_ERR_CLIENT_AUTH_FAILE" },
    { PCT_ERR_ILLEGAL_MESSAGE, "PCT_ERR_ILLEGAL_MESSAGE" },
    { PCT_ERR_INTEGRITY_CHECK_FAILED, "PCT_ERR_INTEGRITY_CHECK_FAILED" },
    { PCT_ERR_SERVER_AUTH_FAILED, "PCT_ERR_SERVER_AUTH_FAILED" },
    { PCT_ERR_SPECS_MISMATCH, "PCT_ERR_SPECS_MISMATCH" },
    { 0x00, NULL }
};

/* http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1 */
const value_string tls_hello_extension_types[] = {
    { SSL_HND_HELLO_EXT_SERVER_NAME, "server_name" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH, "max_fragment_length" },/* RFC 6066 */
    { SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL, "client_certificate_url" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS, "trusted_ca_keys" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_TRUNCATED_HMAC, "truncated_hmac" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST, "status_request" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_USER_MAPPING, "user_mapping" }, /* RFC 4681 */
    { SSL_HND_HELLO_EXT_CLIENT_AUTHZ, "client_authz" }, /* RFC 5878 */
    { SSL_HND_HELLO_EXT_SERVER_AUTHZ, "server_authz" }, /* RFC 5878 */
    { SSL_HND_HELLO_EXT_CERT_TYPE, "cert_type" }, /* RFC 6091 */
    { SSL_HND_HELLO_EXT_SUPPORTED_GROUPS, "elliptic_curves" }, /* RFC 4492 */
    { SSL_HND_HELLO_EXT_EC_POINT_FORMATS, "ec_point_formats" }, /* RFC 4492 */
    { SSL_HND_HELLO_EXT_SRP, "srp" }, /* RFC 5054 */
    { SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS, "signature_algorithms" }, /* RFC 5246 */
    { SSL_HND_HELLO_EXT_USE_SRTP, "use_srtp" }, /* RFC 5764 */
    { SSL_HND_HELLO_EXT_HEARTBEAT, "heartbeat" }, /* RFC 6520 */
    { SSL_HND_HELLO_EXT_ALPN, "application_layer_protocol_negotiation" }, /* RFC 7301 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST_V2, "status_request_v2" }, /* RFC 6961 */
    { SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP, "signed_certificate_timestamp" }, /* RFC 6962 */
    { SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE, "client_certificate_type" }, /* RFC 7250 */
    { SSL_HND_HELLO_EXT_SERVER_CERT_TYPE, "server_certificate_type" }, /* RFC 7250 */
    { SSL_HND_HELLO_EXT_PADDING, "padding" }, /* RFC 7685 */
    { SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC, "encrypt_then_mac" }, /* RFC 7366 */
    { SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET, "extended_master_secret" }, /* RFC 7627 */
    { SSL_HND_HELLO_EXT_TOKEN_BINDING, "token_binding" }, /* https://tools.ietf.org/html/draft-ietf-tokbind-negotiation */
    { SSL_HND_HELLO_EXT_CACHED_INFO, "cached_info" }, /* RFC 7924 */
    { SSL_HND_HELLO_EXT_SESSION_TICKET_TLS, "SessionTicket TLS" }, /* RFC 4507 */
    { SSL_HND_HELLO_EXT_KEY_SHARE, "key_share" }, /* TLS 1.3 https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { SSL_HND_HELLO_EXT_PRE_SHARED_KEY, "pre_shared_key" }, /* TLS 1.3 https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { SSL_HND_HELLO_EXT_EARLY_DATA, "early_data" }, /* TLS 1.3 https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS, "supported_versions" }, /* TLS 1.3 https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { SSL_HND_HELLO_EXT_COOKIE, "cookie" }, /* TLS 1.3 https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES, "psk_key_exchange_modes" }, /* TLS 1.3 https://tools.ietf.org/html/draft-ietf-tls-tls13 */
    { SSL_HND_HELLO_EXT_NPN, "next_protocol_negotiation"}, /* https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html */
    { SSL_HND_HELLO_EXT_CHANNEL_ID_OLD, "channel_id_old" }, /* http://tools.ietf.org/html/draft-balfanz-tls-channelid-00
       https://twitter.com/ericlaw/status/274237352531083264 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID, "channel_id" }, /* http://tools.ietf.org/html/draft-balfanz-tls-channelid-01
       https://code.google.com/p/chromium/codesearch#chromium/src/net/third_party/nss/ssl/sslt.h&l=209 */
    { SSL_HND_HELLO_EXT_RENEGOTIATION_INFO, "renegotiation_info" }, /* RFC 5746 */
    { SSL_HND_HELLO_EXT_DRAFT_VERSION_TLS13, "Draft version of TLS 1.3" }, /* for experimentation only  https://www.ietf.org/mail-archive/web/tls/current/msg20853.html */
    { 0, NULL }
};

const value_string tls_hello_ext_server_name_type_vs[] = {
    { 0, "host_name" },
    { 0, NULL }
};

/* draft-ietf-tls-tls13-18 4.2.7 */
const value_string tls_hello_ext_psk_ke_mode[] = {
    { 0, "PSK-only key establishment (psk_ke)" },
    { 1, "PSK key establishment with (EC)DHE key establishment (psk_dhe_ke)" },
    { 0, NULL }
};

/* RFC 5246 7.4.1.4.1 */
const value_string tls_hash_algorithm[] = {
    { 0, "None" },
    { 1, "MD5" },
    { 2, "SHA1" },
    { 3, "SHA224" },
    { 4, "SHA256" },
    { 5, "SHA384" },
    { 6, "SHA512" },
    { 0, NULL }
};

const value_string tls_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 3, "ECDSA" },
    { 0, NULL }
};

/* RFC 6091 3.1 */
const value_string tls_certificate_type[] = {
    { 0, "X.509" },
    { 1, "OpenPGP" },
    { SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY, "Raw Public Key" }, /* RFC 7250 */
    { 0, NULL }
};

const value_string tls_cert_chain_type[] = {
    { SSL_HND_CERT_URL_TYPE_INDIVIDUAL_CERT,    "Individual Certificates" },
    { SSL_HND_CERT_URL_TYPE_PKIPATH,            "PKI Path" },
    { 0, NULL }
};

const value_string tls_cert_status_type[] = {
    { SSL_HND_CERT_STATUS_TYPE_OCSP,            "OCSP" },
    { SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI,      "OCSP Multi" },
    { 0, NULL }
};

/* string_string is inappropriate as it compares strings while
 * "byte strings MUST NOT be truncated" (RFC 7301) */
typedef struct ssl_alpn_protocol {
    const char      *proto_name;
    gboolean         match_exact;
    const char      *dissector_name;
} ssl_alpn_protocol_t;
/* http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
static const ssl_alpn_protocol_t ssl_alpn_protocols[] = {
    { "http/1.1",           TRUE,   "http" },
    /* SPDY moves so fast, just 1, 2 and 3 are registered with IANA but there
     * already exists 3.1 as of this writing... match the prefix. */
    { "spdy/",              FALSE,  "spdy" },
    { "stun.turn",          TRUE,   "turnchannel" },
    { "stun.nat-discovery", TRUE,   "stun" },
    /* draft-ietf-httpbis-http2-16 */
    { "h2-",                FALSE,  "http2" }, /* draft versions */
    { "h2",                 TRUE,   "http2" }, /* final version */
};

/* Lookup tables }}} */

/* we keep this internal to packet-ssl-utils, as there should be
   no need to access it any other way.

   This also allows us to hide the dependency on zlib.
*/
struct _SslDecompress {
    gint compression;
#ifdef HAVE_ZLIB
    z_stream istream;
#endif
};

/* To assist in parsing client/server key exchange messages
   0 indicates unknown */
gint ssl_get_keyex_alg(gint cipher)
{
    /* Map Cipher suite number to Key Exchange algorithm {{{ */
    switch(cipher) {
    case 0x0017:
    case 0x0018:
    case 0x0019:
    case 0x001a:
    case 0x001b:
    case 0x0034:
    case 0x003a:
    case 0x0046:
    case 0x006c:
    case 0x006d:
    case 0x0089:
    case 0x009b:
    case 0x00a6:
    case 0x00a7:
    case 0x00bf:
    case 0x00c5:
    case 0xc084:
    case 0xc085:
        return KEX_DH_ANON;
    case 0x000b:
    case 0x000c:
    case 0x000d:
    case 0x0030:
    case 0x0036:
    case 0x003e:
    case 0x0042:
    case 0x0068:
    case 0x0085:
    case 0x0097:
    case 0x00a4:
    case 0x00a5:
    case 0x00bb:
    case 0x00c1:
    case 0xc082:
    case 0xc083:
        return KEX_DH_DSS;
    case 0x000e:
    case 0x000f:
    case 0x0010:
    case 0x0031:
    case 0x0037:
    case 0x003f:
    case 0x0043:
    case 0x0069:
    case 0x0086:
    case 0x0098:
    case 0x00a0:
    case 0x00a1:
    case 0x00bc:
    case 0x00c2:
    case 0xc07e:
    case 0xc07f:
        return KEX_DH_RSA;
    case 0x0011:
    case 0x0012:
    case 0x0013:
    case 0x0032:
    case 0x0038:
    case 0x0040:
    case 0x0044:
    case 0x0063:
    case 0x0065:
    case 0x0066:
    case 0x006a:
    case 0x0087:
    case 0x0099:
    case 0x00a2:
    case 0x00a3:
    case 0x00bd:
    case 0x00c3:
    case 0xc080:
    case 0xc081:
        return KEX_DHE_DSS;
    case 0x002d:
    case 0x008e:
    case 0x008f:
    case 0x0090:
    case 0x0091:
    case 0x00aa:
    case 0x00ab:
    case 0x00b2:
    case 0x00b3:
    case 0x00b4:
    case 0x00b5:
    case 0xc090:
    case 0xc091:
    case 0xc096:
    case 0xc097:
    case 0xc0a6:
    case 0xc0a7:
    case 0xc0aa:
    case 0xc0ab:
    case 0xe41c:
    case 0xe41d:
        return KEX_DHE_PSK;
    case 0x0014:
    case 0x0015:
    case 0x0016:
    case 0x0033:
    case 0x0039:
    case 0x0045:
    case 0x0067:
    case 0x006b:
    case 0x0088:
    case 0x009a:
    case 0x009e:
    case 0x009f:
    case 0x00be:
    case 0x00c4:
    case 0xc07c:
    case 0xc07d:
    case 0xc09e:
    case 0xc09f:
    case 0xc0a2:
    case 0xc0a3:
    case 0xe41e:
    case 0xe41f:
        return KEX_DHE_RSA;
    case 0xc015:
    case 0xc016:
    case 0xc017:
    case 0xc018:
    case 0xc019:
        return KEX_ECDH_ANON;
    case 0xc001:
    case 0xc002:
    case 0xc003:
    case 0xc004:
    case 0xc005:
    case 0xc025:
    case 0xc026:
    case 0xc02d:
    case 0xc02e:
    case 0xc074:
    case 0xc075:
    case 0xc088:
    case 0xc089:
        return KEX_ECDH_ECDSA;
    case 0xc00b:
    case 0xc00c:
    case 0xc00d:
    case 0xc00e:
    case 0xc00f:
    case 0xc029:
    case 0xc02a:
    case 0xc031:
    case 0xc032:
    case 0xc078:
    case 0xc079:
    case 0xc08c:
    case 0xc08d:
        return KEX_ECDH_RSA;
    case 0xc006:
    case 0xc007:
    case 0xc008:
    case 0xc009:
    case 0xc00a:
    case 0xc023:
    case 0xc024:
    case 0xc02b:
    case 0xc02c:
    case 0xc072:
    case 0xc073:
    case 0xc086:
    case 0xc087:
    case 0xc0ac:
    case 0xc0ad:
    case 0xc0ae:
    case 0xc0af:
    case 0xe414:
    case 0xe415:
        return KEX_ECDHE_ECDSA;
    case 0xc033:
    case 0xc034:
    case 0xc035:
    case 0xc036:
    case 0xc037:
    case 0xc038:
    case 0xc039:
    case 0xc03a:
    case 0xc03b:
    case 0xc09a:
    case 0xc09b:
    case 0xe418:
    case 0xe419:
        return KEX_ECDHE_PSK;
    case 0xc010:
    case 0xc011:
    case 0xc012:
    case 0xc013:
    case 0xc014:
    case 0xc027:
    case 0xc028:
    case 0xc02f:
    case 0xc030:
    case 0xc076:
    case 0xc077:
    case 0xc08a:
    case 0xc08b:
    case 0xe412:
    case 0xe413:
        return KEX_ECDHE_RSA;
    case 0x001e:
    case 0x001f:
    case 0x0020:
    case 0x0021:
    case 0x0022:
    case 0x0023:
    case 0x0024:
    case 0x0025:
    case 0x0026:
    case 0x0027:
    case 0x0028:
    case 0x0029:
    case 0x002a:
    case 0x002b:
        return KEX_KRB5;
    case 0x002c:
    case 0x008a:
    case 0x008b:
    case 0x008c:
    case 0x008d:
    case 0x00a8:
    case 0x00a9:
    case 0x00ae:
    case 0x00af:
    case 0x00b0:
    case 0x00b1:
    case 0xc064:
    case 0xc065:
    case 0xc08e:
    case 0xc08f:
    case 0xc094:
    case 0xc095:
    case 0xc0a4:
    case 0xc0a5:
    case 0xc0a8:
    case 0xc0a9:
    case 0xe416:
    case 0xe417:
        return KEX_PSK;
    case 0x0001:
    case 0x0002:
    case 0x0003:
    case 0x0004:
    case 0x0005:
    case 0x0006:
    case 0x0007:
    case 0x0008:
    case 0x0009:
    case 0x000a:
    case 0x002f:
    case 0x0035:
    case 0x003b:
    case 0x003c:
    case 0x003d:
    case 0x0041:
    case 0x0060:
    case 0x0061:
    case 0x0062:
    case 0x0064:
    case 0x0084:
    case 0x0096:
    case 0x009c:
    case 0x009d:
    case 0x00ba:
    case 0x00c0:
    case 0xc07a:
    case 0xc07b:
    case 0xc09c:
    case 0xc09d:
    case 0xc0a0:
    case 0xc0a1:
    case 0xe410:
    case 0xe411:
    case 0xfefe:
    case 0xfeff:
    case 0xffe0:
    case 0xffe1:
        return KEX_RSA;
    case 0x002e:
    case 0x0092:
    case 0x0093:
    case 0x0094:
    case 0x0095:
    case 0x00ac:
    case 0x00ad:
    case 0x00b6:
    case 0x00b7:
    case 0x00b8:
    case 0x00b9:
    case 0xc092:
    case 0xc093:
    case 0xc098:
    case 0xc099:
    case 0xe41a:
    case 0xe41b:
        return KEX_RSA_PSK;
    case 0xc01a:
    case 0xc01d:
    case 0xc020:
        return KEX_SRP_SHA;
    case 0xc01c:
    case 0xc01f:
    case 0xc022:
        return KEX_SRP_SHA_DSS;
    case 0xc01b:
    case 0xc01e:
    case 0xc021:
        return KEX_SRP_SHA_RSA;
    default:
        break;
    }

    return 0;
    /* }}} */
}


/* StringInfo structure (len + data) functions {{{ */

static gint
ssl_data_alloc(StringInfo* str, size_t len)
{
    str->data = (guchar *)g_malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (guint) len;
    return 0;
}

void
ssl_data_set(StringInfo* str, const guchar* data, guint len)
{
    DISSECTOR_ASSERT(data);
    memcpy(str->data, data, len);
    str->data_len = len;
}

#ifdef HAVE_LIBGCRYPT
static gint
ssl_data_realloc(StringInfo* str, guint len)
{
    str->data = (guchar *)g_realloc(str->data, len);
    if (!str->data)
        return -1;
    str->data_len = len;
    return 0;
}

static StringInfo *
ssl_data_clone(StringInfo *str)
{
    StringInfo *cloned_str;
    cloned_str = (StringInfo *) wmem_alloc0(wmem_file_scope(),
            sizeof(StringInfo) + str->data_len);
    cloned_str->data = (guchar *) (cloned_str + 1);
    ssl_data_set(cloned_str, str->data, str->data_len);
    return cloned_str;
}

static gint
ssl_data_copy(StringInfo* dst, StringInfo* src)
{
    if (dst->data_len < src->data_len) {
      if (ssl_data_realloc(dst, src->data_len))
        return -1;
    }
    memcpy(dst->data, src->data, src->data_len);
    dst->data_len = src->data_len;
    return 0;
}
#endif

/* from_hex converts |hex_len| bytes of hex data from |in| and sets |*out| to
 * the result. |out->data| will be allocated using wmem_file_scope. Returns TRUE on
 * success. */
static gboolean from_hex(StringInfo* out, const char* in, gsize hex_len) {
    gsize i;

    if (hex_len & 1)
        return FALSE;

    out->data = (guchar *)wmem_alloc(wmem_file_scope(), hex_len / 2);
    for (i = 0; i < hex_len / 2; i++) {
        int a = ws_xton(in[i*2]);
        int b = ws_xton(in[i*2 + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        out->data[i] = a << 4 | b;
    }
    out->data_len = (guint)hex_len / 2;
    return TRUE;
}
/* StringInfo structure (len + data) functions }}} */


#ifdef HAVE_LIBGCRYPT

/* libgcrypt wrappers for HMAC/message digest operations {{{ */
/* hmac abstraction layer */
#define SSL_HMAC gcry_md_hd_t

static inline gint
ssl_hmac_init(SSL_HMAC* md, const void * key, gint len, gint algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    gcry_md_setkey (*(md), key, len);
    return 0;
}
static inline void
ssl_hmac_update(SSL_HMAC* md, const void* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_hmac_final(SSL_HMAC* md, guchar* data, guint* datalen)
{
    gint  algo;
    guint len;

    algo = gcry_md_get_algo (*(md));
    len  = gcry_md_get_algo_dlen(algo);
    DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}
static inline void
ssl_hmac_cleanup(SSL_HMAC* md)
{
    gcry_md_close(*(md));
}

/* message digest abstraction layer*/
#define SSL_MD gcry_md_hd_t

static inline gint
ssl_md_init(SSL_MD* md, gint algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,algo, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_md_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}
static inline void
ssl_md_update(SSL_MD* md, guchar* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md_final(SSL_MD* md, guchar* data, guint* datalen)
{
    gint algo;
    gint len;
    algo = gcry_md_get_algo (*(md));
    len = gcry_md_get_algo_dlen (algo);
    memcpy(data, gcry_md_read(*(md),  algo), len);
    *datalen = len;
}
static inline void
ssl_md_cleanup(SSL_MD* md)
{
    gcry_md_close(*(md));
}

/* md5 /sha abstraction layer */
#define SSL_SHA_CTX gcry_md_hd_t
#define SSL_MD5_CTX gcry_md_hd_t

static inline void
ssl_sha_init(SSL_SHA_CTX* md)
{
    gcry_md_open(md,GCRY_MD_SHA1, 0);
}
static inline void
ssl_sha_update(SSL_SHA_CTX* md, guchar* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_sha_final(guchar* buf, SSL_SHA_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_SHA1),
           gcry_md_get_algo_dlen(GCRY_MD_SHA1));
}
static inline void
ssl_sha_cleanup(SSL_SHA_CTX* md)
{
    gcry_md_close(*(md));
}

static inline gint
ssl_md5_init(SSL_MD5_CTX* md)
{
    return gcry_md_open(md,GCRY_MD_MD5, 0);
}
static inline void
ssl_md5_update(SSL_MD5_CTX* md, guchar* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md5_final(guchar* buf, SSL_MD5_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_MD5),
           gcry_md_get_algo_dlen(GCRY_MD_MD5));
}
static inline void
ssl_md5_cleanup(SSL_MD5_CTX* md)
{
    gcry_md_close(*(md));
}
/* libgcrypt wrappers for HMAC/message digest operations }}} */

/* libgcrypt wrappers for Cipher state manipulation {{{ */
gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, guchar* iv, gint iv_len)
{
    gint ret;
#if 0
    guchar *ivp;
    gint i;
    gcry_cipher_hd_t c;
    c=(gcry_cipher_hd_t)*cipher;
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    ret = gcry_cipher_setiv(*(cipher), iv, iv_len);
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    return ret;
}
/* stream cipher abstraction layer*/
static gint
ssl_cipher_init(gcry_cipher_hd_t *cipher, gint algo, guchar* sk,
        guchar* iv, gint mode)
{
    gint gcry_modes[] = {
        GCRY_CIPHER_MODE_STREAM,
        GCRY_CIPHER_MODE_CBC,
#ifdef HAVE_LIBGCRYPT_AEAD
        GCRY_CIPHER_MODE_GCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_CCM
#else
        GCRY_CIPHER_MODE_CTR,
        GCRY_CIPHER_MODE_CTR,
        GCRY_CIPHER_MODE_CTR,
#endif
    };
    gint err;
    if (algo == -1) {
        /* NULL mode */
        *(cipher) = (gcry_cipher_hd_t)-1;
        return 0;
    }
    err = gcry_cipher_open(cipher, algo, gcry_modes[mode], 0);
    if (err !=0)
        return  -1;
    err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen (algo));
    if (err != 0)
        return -1;
    /* AEAD cipher suites will set the nonce later. */
    if (mode == MODE_CBC) {
        err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen(algo));
        if (err != 0)
            return -1;
    }
    return 0;
}
static inline gint
ssl_cipher_decrypt(gcry_cipher_hd_t *cipher, guchar * out, gint outl,
                   const guchar * in, gint inl)
{
    if ((*cipher) == (gcry_cipher_hd_t)-1)
    {
        if (in && inl)
            memcpy(out, in, outl < inl ? outl : inl);
        return 0;
    }
    return gcry_cipher_decrypt ( *(cipher), out, outl, in, inl);
}
static inline gint
ssl_get_digest_by_name(const gchar*name)
{
    return gcry_md_map_name(name);
}
static inline gint
ssl_get_cipher_by_name(const gchar* name)
{
    return gcry_cipher_map_name(name);
}

static inline void
ssl_cipher_cleanup(gcry_cipher_hd_t *cipher)
{
    if ((*cipher) != (gcry_cipher_hd_t)-1)
        gcry_cipher_close(*cipher);
    *cipher = NULL;
}
/* libgcrypt wrappers for Cipher state manipulation }}} */

#ifdef HAVE_LIBGNUTLS
/* libgcrypt wrapper to decrypt using a RSA private key {{{ */
/* decrypt data with private key. Store decrypted data directly into input
 * buffer */
static int
ssl_private_decrypt(const guint len, guchar* data, gcry_sexp_t pk)
{
    gint        rc = 0;
    size_t      decr_len = 0, i = 0;
    gcry_sexp_t s_data = NULL, s_plain = NULL;
    gcry_mpi_t  encr_mpi = NULL, text = NULL;

    /* create mpi representation of encrypted data */
    rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG, data, len, NULL);
    if (rc != 0 ) {
        ssl_debug_printf("pcry_private_decrypt: can't convert data to mpi (size %d):%s\n",
            len, gcry_strerror(rc));
        return 0;
    }

    /* put the data into a simple list */
    rc = gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", encr_mpi);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't build encr_sexp:%s\n",
             gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* pass it to libgcrypt */
    rc = gcry_pk_decrypt(&s_plain, s_data, pk);
    if (rc != 0)
    {
        ssl_debug_printf("pcry_private_decrypt: can't decrypt key:%s\n",
            gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* convert plain text sexp to mpi format */
    text = gcry_sexp_nth_mpi(s_plain, 0, 0);
    if (! text) {
        ssl_debug_printf("pcry_private_decrypt: can't convert sexp to mpi\n");
        decr_len = 0;
        goto out;
    }

    /* compute size requested for plaintext buffer */
    rc = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &decr_len, text);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't compute decr size:%s\n",
            gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* sanity check on out buffer */
    if (decr_len > len) {
        ssl_debug_printf("pcry_private_decrypt: decrypted data is too long ?!? (%" G_GSIZE_MODIFIER "u max %d)\n", decr_len, len);
        decr_len = 0;
        goto out;
    }

    /* write plain text to newly allocated buffer */
    rc = gcry_mpi_print(GCRYMPI_FMT_USG, data, len, &decr_len, text);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't print decr data to mpi (size %" G_GSIZE_MODIFIER "u):%s\n", decr_len, gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    ssl_print_data("decrypted_unstrip_pre_master", data, decr_len);

    /* strip the padding*/
    rc = 0;
    for (i = 1; i < decr_len; i++) {
        if (data[i] == 0) {
            rc = (gint) i+1;
            break;
        }
    }

    ssl_debug_printf("pcry_private_decrypt: stripping %d bytes, decr_len %" G_GSIZE_MODIFIER "u\n", rc, decr_len);
    decr_len -= rc;
    memmove(data, data+rc, decr_len);

out:
    gcry_sexp_release(s_data);
    gcry_sexp_release(s_plain);
    gcry_mpi_release(encr_mpi);
    gcry_mpi_release(text);
    return (int) decr_len;
} /* }}} */
#endif /* HAVE_LIBGNUTLS */

#else /* ! HAVE_LIBGCRYPT */

gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher _U_, guchar* iv _U_, gint iv_len _U_)
{
    ssl_debug_printf("ssl_cipher_setiv: impossible without gnutls.\n");
    return 0;
}
#endif /* ! HAVE_LIBGCRYPT */


#ifdef HAVE_LIBGCRYPT /* Save space if decryption is not enabled. */

/* Digests, Ciphers and Cipher Suites registry {{{ */
static const SslDigestAlgo digests[]={
    {"MD5",     16},
    {"SHA1",    20},
    {"SHA256",  32},
    {"SHA384",  48},
    {"Not Applicable",  0},
};

#define DIGEST_MAX_SIZE 48

/* get index digest index */
static const SslDigestAlgo *
ssl_cipher_suite_dig(const SslCipherSuite *cs) {
    return &digests[cs->dig - DIG_MD5];
}

static const gchar *ciphers[]={
    "DES",
    "3DES",
    "ARCFOUR", /* libgcrypt does not support rc4, but this should be 100% compatible*/
    "RFC2268_128", /* libgcrypt name for RC2 with a 128-bit key */
    "IDEA",
    "AES",
    "AES256",
    "CAMELLIA128",
    "CAMELLIA256",
    "SEED",
    "*UNKNOWN*"
};

static const SslCipherSuite cipher_suites[]={
    {0x0001,KEX_RSA,            ENC_NULL,       DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
    {0x0002,KEX_RSA,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
    {0x0003,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    {0x0004,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
    {0x0005,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
    {0x0006,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    {0x0007,KEX_RSA,            ENC_IDEA,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_IDEA_CBC_SHA */
    {0x0008,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0009,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_DES_CBC_SHA */
    {0x000A,KEX_RSA,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x000B,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x000C,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    {0x000D,KEX_DH_DSS,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x000E,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x000F,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    {0x0010,KEX_DH_RSA,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0011,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x0012,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    {0x0013,KEX_DHE_DSS,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x0014,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0015,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    {0x0016,KEX_DHE_RSA,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0017,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    {0x0018,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
    {0x0019,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    {0x001A,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_DES_CBC_SHA */
    {0x001B,KEX_DH_ANON,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    {0x002C,KEX_PSK,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
    {0x002D,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
    {0x002E,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
    {0x002F,KEX_RSA,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA */
    {0x0030,KEX_DH_DSS,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    {0x0031,KEX_DH_RSA,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    {0x0032,KEX_DHE_DSS,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    {0x0033,KEX_DHE_RSA,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    {0x0034,KEX_DH_ANON,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    {0x0035,KEX_RSA,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA */
    {0x0036,KEX_DH_DSS,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    {0x0037,KEX_DH_RSA,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    {0x0038,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    {0x0039,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    {0x003A,KEX_DH_ANON,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    {0x003B,KEX_RSA,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
    {0x003C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    {0x003D,KEX_RSA,            ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    {0x003E,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
    {0x003F,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0040,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    {0x0041,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0042,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0043,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0044,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0045,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0046,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    {0x0060,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    {0x0061,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
    {0x0062,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0063,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0064,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    {0x0065,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
    {0x0066,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
    {0x0067,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0068,KEX_DH_DSS,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
    {0x0069,KEX_DH_RSA,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006A,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
    {0x006B,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006C,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
    {0x006D,KEX_DH_ANON,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
    {0x0084,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0085,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0086,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0087,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0088,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0089,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    {0x008A,KEX_PSK,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
    {0x008B,KEX_PSK,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x008C,KEX_PSK,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA */
    {0x008D,KEX_PSK,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA */
    {0x008E,KEX_DHE_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
    {0x008F,KEX_DHE_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0090,KEX_DHE_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
    {0x0091,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
    {0x0092,KEX_RSA_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    {0x0093,KEX_RSA_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0094,KEX_RSA_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    {0x0095,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    {0x0096,KEX_RSA,            ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_SEED_CBC_SHA */
    {0x0097,KEX_DH_DSS,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    {0x0098,KEX_DH_RSA,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    {0x0099,KEX_DHE_DSS,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    {0x009A,KEX_DHE_RSA,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
    {0x009B,KEX_DH_ANON,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
    {0x009C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009D,KEX_RSA,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    {0x009E,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009F,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A0,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
    {0x00A1,KEX_DH_RSA,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A2,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A3,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A4,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A5,KEX_DH_DSS,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A6,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
    {0x00A7,KEX_DH_ANON,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
    {0x00A8,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00A9,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AA,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AB,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AC,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AD,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AE,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00AF,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B0,KEX_PSK,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
    {0x00B1,KEX_PSK,            ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
    {0x00B2,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B3,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B4,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    {0x00B5,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    {0x00B6,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B7,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B8,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    {0x00B9,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    {0x00BA,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BB,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BC,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BD,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BE,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BF,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00C0,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C1,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C2,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C3,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C4,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C5,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */

    /* NOTE: TLS 1.3 cipher suites are incompatible with TLS 1.2. */
    {0x1301,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_AES_128_GCM_SHA256 */
    {0x1302,KEX_TLS13,          ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_AES_256_GCM_SHA384 */
    /* TODO TLS_CHACHA20_POLY1305_SHA256 */
    {0x1304,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM   },   /* TLS_AES_128_CCM_SHA256 */
    {0x1305,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM_8 },   /* TLS_AES_128_CCM_8_SHA256 */

    {0xC001,KEX_ECDH_ECDSA,     ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    {0xC002,KEX_ECDH_ECDSA,     ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    {0xC003,KEX_ECDH_ECDSA,     ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC004,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC005,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC006,KEX_ECDHE_ECDSA,    ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    {0xC007,KEX_ECDHE_ECDSA,    ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    {0xC008,KEX_ECDHE_ECDSA,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC009,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC00A,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC00B,KEX_ECDH_RSA,       ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
    {0xC00C,KEX_ECDH_RSA,       ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    {0xC00D,KEX_ECDH_RSA,       ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC00E,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    {0xC00F,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    {0xC010,KEX_ECDHE_RSA,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    {0xC011,KEX_ECDHE_RSA,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    {0xC012,KEX_ECDHE_RSA,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC013,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    {0xC014,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    {0xC015,KEX_ECDH_ANON,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
    {0xC016,KEX_ECDH_ANON,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    {0xC017,KEX_ECDH_ANON,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    {0xC018,KEX_ECDH_ANON,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    {0xC019,KEX_ECDH_ANON,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    {0xC023,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC024,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC025,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC026,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC027,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC028,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC029,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC02A,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC02B,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02C,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02D,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02E,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02F,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC030,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC031,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC032,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC033,KEX_ECDHE_PSK,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
    {0xC034,KEX_ECDHE_PSK,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0xC035,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
    {0xC036,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
    {0xC037,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0xC038,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0xC039,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    {0xC03A,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    {0xC03B,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
    {0xC072,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC073,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC074,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC075,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC076,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC077,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC078,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC079,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC07A,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07B,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07C,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07D,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07E,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07F,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC080,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC081,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC082,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC083,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC084,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC085,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC086,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC087,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC088,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC089,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08A,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08B,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08C,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08D,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08E,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08F,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC090,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC091,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC092,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC093,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC094,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC095,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC096,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC097,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC098,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC099,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09A,KEX_ECDHE_PSK,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC09B,KEX_ECDHE_PSK,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09C,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_128_CCM */
    {0xC09D,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_256_CCM */
    {0xC09E,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_128_CCM */
    {0xC09F,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_256_CCM */
    {0xC0A0,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_128_CCM_8 */
    {0xC0A1,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_256_CCM_8 */
    {0xC0A2,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
    {0xC0A3,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
    {0xC0A4,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_128_CCM */
    {0xC0A5,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_256_CCM */
    {0xC0A6,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_128_CCM */
    {0xC0A7,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_256_CCM */
    {0xC0A8,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_128_CCM_8 */
    {0xC0A9,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_256_CCM_8 */
    {0xC0AA,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
    {0xC0AB,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
    {0xC0AC,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    {0xC0AD,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
    {0xC0AE,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
    {0xC0AF,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
    {-1,    0,                  0,              0,          MODE_STREAM}
};

#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32

const SslCipherSuite *
ssl_find_cipher(int num)
{
    const SslCipherSuite *c;
    for(c=cipher_suites;c->number!=-1;c++){
        if(c->number==num){
            return c;
        }
    }

    return NULL;
}

guint
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite)
{
    gint cipher_algo;
    if (cipher_suite->mode != MODE_CBC) return 0;
    cipher_algo = ssl_get_cipher_by_name(ciphers[cipher_suite->enc - 0x30]);
    return (guint)gcry_cipher_get_algo_blklen(cipher_algo);
}

static guint
ssl_get_cipher_export_keymat_size(int cipher_suite_num)
{
    switch (cipher_suite_num) {
    /* See RFC 6101 (SSL 3.0), Table 2, column Key Material. */
    case 0x0003:    /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    case 0x0006:    /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    case 0x0008:    /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x000B:    /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    case 0x000E:    /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0011:    /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0014:    /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0017:    /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    case 0x0019:    /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
        return 5;

    /* not defined in below draft, but "implemented by several vendors",
     * https://www.ietf.org/mail-archive/web/tls/current/msg00036.html */
    case 0x0060:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    case 0x0061:    /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
        return 7;

    /* Note: the draft states that DES_CBC needs 8 bytes, but Wireshark always
     * used 7. Until a pcap proves 8, let's use the old value. Link:
     * https://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01 */
    case 0x0062:    /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    case 0x0063:    /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    case 0x0064:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    case 0x0065:    /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
        return 7;

    default:
        return 0;
    }
}
#else /* ! HAVE_LIBGCRYPT */
const SslCipherSuite *
ssl_find_cipher(int num)
{
    ssl_debug_printf("ssl_find_cipher: dummy without gnutls. num %d\n",
        num);
    return NULL;
}

guint
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite _U_)
{
    return 0;
}
#endif /* ! HAVE_LIBGCRYPT */

/* Digests, Ciphers and Cipher Suites registry }}} */


#ifdef HAVE_LIBGCRYPT

/* HMAC and the Pseudorandom function {{{ */
static void
tls_hash(StringInfo *secret, StringInfo *seed, gint md,
         StringInfo *out, guint out_len)
{
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    guint8   *ptr;
    guint     left, tocpy;
    guint8   *A;
    guint8    _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    guint     A_l, tmp_l;
    SSL_HMAC  hm;

    ptr  = out->data;
    left = out_len;

    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    /* A(0) = seed */
    A = seed->data;
    A_l = seed->data_len;

    while (left) {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        ssl_hmac_init(&hm, secret->data, secret->data_len, md);
        ssl_hmac_update(&hm, A, A_l);
        A_l = sizeof(_A); /* upper bound len for hash output */
        ssl_hmac_final(&hm, _A, &A_l);
        ssl_hmac_cleanup(&hm);
        A = _A;

        /* HMAC_hash(secret, A(i) + seed) */
        ssl_hmac_init(&hm, secret->data, secret->data_len, md);
        ssl_hmac_update(&hm, A, A_l);
        ssl_hmac_update(&hm, seed->data, seed->data_len);
        tmp_l = sizeof(tmp); /* upper bound len for hash output */
        ssl_hmac_final(&hm, tmp, &tmp_l);
        ssl_hmac_cleanup(&hm);

        /* ssl_hmac_final puts the actual digest output size in tmp_l */
        tocpy = MIN(left, tmp_l);
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }
    out->data_len = out_len;

    ssl_print_string("hash out", out);
}

static gboolean
tls_prf(StringInfo* secret, const gchar *usage,
        StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
    StringInfo  seed, sha_out, md5_out;
    guint8     *ptr;
    StringInfo  s1, s2;
    guint       i,s_l;
    size_t      usage_len, rnd2_len;
    gboolean    success = FALSE;
    usage_len = strlen(usage);
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    /* initalize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, MAX(out_len, 20)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
        return FALSE;
    }
    if (ssl_data_alloc(&md5_out, MAX(out_len, 16)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls_prf: can't allocate rnd %d\n",
                         (int) (usage_len+rnd1->data_len+rnd2_len));
        goto free_md5;
    }

    ptr=seed.data;
    memcpy(ptr,usage,usage_len);
    ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len);
    if (rnd2_len > 0) {
        ptr+=rnd1->data_len;
        memcpy(ptr,rnd2->data,rnd2->data_len);
        /*ptr+=rnd2->data_len;*/
    }

    /* initalize buffer for client/server seeds*/
    s_l=secret->data_len/2 + secret->data_len%2;
    if (ssl_data_alloc(&s1, s_l) < 0) {
        ssl_debug_printf("tls_prf: can't allocate secret %d\n", s_l);
        goto free_seed;
    }
    if (ssl_data_alloc(&s2, s_l) < 0) {
        ssl_debug_printf("tls_prf: can't allocate secret(2) %d\n", s_l);
        goto free_s1;
    }

    memcpy(s1.data,secret->data,s_l);
    memcpy(s2.data,secret->data + (secret->data_len - s_l),s_l);

    ssl_debug_printf("tls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len, seed.data_len);
    tls_hash(&s1, &seed, ssl_get_digest_by_name("MD5"), &md5_out, out_len);
    ssl_debug_printf("tls_prf: tls_hash(sha)\n");
    tls_hash(&s2, &seed, ssl_get_digest_by_name("SHA1"), &sha_out, out_len);

    for (i = 0; i < out_len; i++)
        out->data[i] = md5_out.data[i] ^ sha_out.data[i];
    /* success, now store the new meaningful data length */
    out->data_len = out_len;
    success = TRUE;

    ssl_print_string("PRF out",out);
    g_free(s2.data);
free_s1:
    g_free(s1.data);
free_seed:
    g_free(seed.data);
free_md5:
    g_free(md5_out.data);
free_sha:
    g_free(sha_out.data);
    return success;
}

static gboolean
tls12_prf(gint md, StringInfo* secret, const gchar* usage,
          StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
    StringInfo label_seed;
    size_t     usage_len, rnd2_len;
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls12_prf: can't allocate label_seed\n");
        return FALSE;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0)
        memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    ssl_debug_printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);
    tls_hash(secret, &label_seed, md, out, out_len);
    g_free(label_seed.data);
    ssl_print_string("PRF out", out);
    return TRUE;
}

static void
ssl3_generate_export_iv(StringInfo *r1, StringInfo *r2,
                        StringInfo *out, guint out_len)
{
    SSL_MD5_CTX md5;
    guint8      tmp[16];

    ssl_md5_init(&md5);
    ssl_md5_update(&md5,r1->data,r1->data_len);
    ssl_md5_update(&md5,r2->data,r2->data_len);
    ssl_md5_final(tmp,&md5);
    ssl_md5_cleanup(&md5);

    DISSECTOR_ASSERT(out_len <= sizeof(tmp));
    ssl_data_set(out, tmp, out_len);
    ssl_print_string("export iv", out);
}

static gboolean
ssl3_prf(StringInfo* secret, const gchar* usage,
         StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;
    guint        off;
    gint         i = 0,j;
    guint8       buf[20];

    for (off = 0; off < out_len; off += 16) {
        guchar outbuf[16];
        i++;

        ssl_debug_printf("ssl3_prf: sha1_hash(%d)\n",i);
        /* A, BB, CCC,  ... */
        for(j=0;j<i;j++){
            buf[j]=64+i;
        }

        ssl_sha_init(&sha);
        ssl_sha_update(&sha,buf,i);
        ssl_sha_update(&sha,secret->data,secret->data_len);

        if(!strcmp(usage,"client write key") || !strcmp(usage,"server write key")){
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
        }
        else{
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
        }

        ssl_sha_final(buf,&sha);
        ssl_sha_cleanup(&sha);

        ssl_debug_printf("ssl3_prf: md5_hash(%d) datalen %d\n",i,
            secret->data_len);
        ssl_md5_init(&md5);
        ssl_md5_update(&md5,secret->data,secret->data_len);
        ssl_md5_update(&md5,buf,20);
        ssl_md5_final(outbuf,&md5);
        ssl_md5_cleanup(&md5);

        memcpy(out->data + off, outbuf, MIN(out_len - off, 16));
    }
    out->data_len = out_len;

    return TRUE;
}

/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static gboolean
prf(SslDecryptSession *ssl, StringInfo *secret, const gchar *usage,
    StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len)
{
    switch (ssl->session.version) {
    case SSLV3_VERSION:
        return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

    default: /* TLSv1.2 */
        switch (ssl->cipher_suite->dig) {
        case DIG_SHA384:
            return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
                             out, out_len);
        default:
            return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2,
                             out, out_len);
        }
    }
}

static gint tls_handshake_hash(SslDecryptSession* ssl, StringInfo* out)
{
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;

    if (ssl_data_alloc(out, 36) < 0)
        return -1;

    ssl_md5_init(&md5);
    ssl_md5_update(&md5,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_md5_final(out->data,&md5);
    ssl_md5_cleanup(&md5);

    ssl_sha_init(&sha);
    ssl_sha_update(&sha,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_sha_final(out->data+16,&sha);
    ssl_sha_cleanup(&sha);
    return 0;
}

static gint tls12_handshake_hash(SslDecryptSession* ssl, gint md, StringInfo* out)
{
    SSL_MD  mc;
    guint8 tmp[48];
    guint  len;

    ssl_md_init(&mc, md);
    ssl_md_update(&mc,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_md_final(&mc, tmp, &len);
    ssl_md_cleanup(&mc);

    if (ssl_data_alloc(out, len) < 0)
        return -1;
    memcpy(out->data, tmp, len);
    return 0;
}

static gboolean
tls13_hkdf_expand_label(int md, const StringInfo *secret, const char *label, const char *hash_value,
                        guint16 out_len, guchar **out)
{
    /* draft-ietf-tls-tls13-18:
     * HKDF-Expand-Label(Secret, Label, HashValue, Length) =
     *      HKDF-Expand(Secret, HkdfLabel, Length)
     * struct {
     *     uint16 length = Length;
     *     opaque label<9..255> = "TLS 1.3, " + Label;
     *     opaque hash_value<0..255> = HashValue;
     * } HkdfLabel;
     *
     * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
     * HKDF-Expand(PRK, info, L) -> OKM
     */
    guchar  lastoutput[DIGEST_MAX_SIZE];
    gcry_md_hd_t h;
    gcry_error_t err;
    const guint label_length = (guint) strlen(label);
    const guint hash_value_length = (guint) strlen(hash_value);
    const guint hash_len = gcry_md_get_algo_dlen(md);

    /* Some sanity checks */
    DISSECTOR_ASSERT(out_len > 0 && out_len <= 255 * hash_len);
    DISSECTOR_ASSERT(label_length <= 255 - 9);
    DISSECTOR_ASSERT(hash_value_length <= 255);
    DISSECTOR_ASSERT(hash_len > 0 && hash_len <= DIGEST_MAX_SIZE);

    err = gcry_md_open(&h, md, GCRY_MD_FLAG_HMAC);
    if (err) {
        ssl_debug_printf("%s failed to invoke hash func %d: %s\n", G_STRFUNC, md, gcry_strerror(err));
        return FALSE;
    }

    *out = (guchar *)wmem_alloc(NULL, out_len);

    for (guint offset = 0; offset < out_len; offset += hash_len) {
        gcry_md_reset(h);
        gcry_md_setkey(h, secret->data, secret->data_len);  /* Set PRK */

        if (offset > 0) {
            gcry_md_write(h, lastoutput, hash_len);         /* T(1..N) */
        }

        /* info = HkdfLabel { length, label, hash_value } */
        gcry_md_putc(h, out_len >> 8);                      /* length */
        gcry_md_putc(h, (guint8) out_len);
        gcry_md_putc(h, 9 + label_length);                  /* label */
        gcry_md_write(h, "TLS 1.3, ", 9);
        gcry_md_write(h, label, label_length);
        gcry_md_putc(h, hash_value_length);                 /* hash_value */
        gcry_md_write(h, hash_value, hash_value_length);

        gcry_md_putc(h, (guint8) (offset / hash_len + 1));  /* constant 0x01..N */

        memcpy(lastoutput, gcry_md_read(h, md), hash_len);
        memcpy(*out + offset, lastoutput, MIN(hash_len, out_len - offset));
    }

    gcry_md_close(h);
    return TRUE;
}
/* HMAC and the Pseudorandom function }}} */

#else /* ! HAVE_LIBGCRYPT */
/* Stub code when decryption support is not available. {{{ */
gboolean
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session _U_,
        guint32 length _U_, tvbuff_t *tvb _U_, guint32 offset _U_,
        const gchar *ssl_psk _U_, const ssl_master_key_map_t *mk_map _U_)
{
    ssl_debug_printf("%s: impossible without gnutls.\n", G_STRFUNC);
    return FALSE;
}
int
ssl_generate_keyring_material(SslDecryptSession*ssl)
{
    ssl_debug_printf("ssl_generate_keyring_material: impossible without gnutls. ssl %p\n",
        ssl);
    /* We cannot determine whether the cipher suite is valid. Fail such that
     * ssl_set_master_secret bails out. */
    return -1;
}
void
ssl_change_cipher(SslDecryptSession *ssl_session, gboolean server)
{
    ssl_debug_printf("ssl_change_cipher %s: makes no sense without gnutls. ssl %p\n",
        (server)?"SERVER":"CLIENT", ssl_session);
}

int
ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, guint8 ct, guint16 record_version,
        const guchar *in, guint16 inl, StringInfo *comp_str _U_, StringInfo *out_str, guint *outl)
{
    ssl_debug_printf("ssl_decrypt_record: impossible without gnutls. ssl %p"
        "decoder %p ct %d version %d in %p inl %d out %p outl %p\n", ssl, decoder, ct,
        record_version, in, inl, out_str, outl);
    return 0;
}
/* }}} */
#endif /* ! HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGCRYPT
/* Record Decompression (after decryption) {{{ */
#ifdef HAVE_ZLIB
/* memory allocation functions for zlib initialization */
static void* ssl_zalloc(void* opaque _U_, unsigned int no, unsigned int size)
{
    return g_malloc0(no*size);
}
static void ssl_zfree(void* opaque _U_, void* addr)
{
    g_free(addr);
}
#endif

static SslDecompress*
ssl_create_decompressor(gint compression)
{
    SslDecompress *decomp;
#ifdef HAVE_ZLIB
    int err;
#endif

    if (compression == 0) return NULL;
    ssl_debug_printf("ssl_create_decompressor: compression method %d\n", compression);
    decomp = (SslDecompress *)wmem_alloc(wmem_file_scope(), sizeof(SslDecompress));
    decomp->compression = compression;
    switch (decomp->compression) {
#ifdef HAVE_ZLIB
        case 1:  /* DEFLATE */
            decomp->istream.zalloc = ssl_zalloc;
            decomp->istream.zfree = ssl_zfree;
            decomp->istream.opaque = Z_NULL;
            decomp->istream.next_in = Z_NULL;
            decomp->istream.next_out = Z_NULL;
            decomp->istream.avail_in = 0;
            decomp->istream.avail_out = 0;
            err = inflateInit(&decomp->istream);
            if (err != Z_OK) {
                ssl_debug_printf("ssl_create_decompressor: inflateInit_() failed - %d\n", err);
                return NULL;
            }
            break;
#endif
        default:
            ssl_debug_printf("ssl_create_decompressor: unsupported compression method %d\n", decomp->compression);
            return NULL;
    }
    return decomp;
}

#ifdef HAVE_ZLIB
static int
ssl_decompress_record(SslDecompress* decomp, const guchar* in, guint inl, StringInfo* out_str, guint* outl)
{
    gint err;

    switch (decomp->compression) {
        case 1:  /* DEFLATE */
            err = Z_OK;
            if (out_str->data_len < 16384) {  /* maximal plain length */
                ssl_data_realloc(out_str, 16384);
            }
#ifdef z_const
            decomp->istream.next_in = in;
#else
DIAG_OFF(cast-qual)
            decomp->istream.next_in = (Bytef *)in;
DIAG_ON(cast-qual)
#endif
            decomp->istream.avail_in = inl;
            decomp->istream.next_out = out_str->data;
            decomp->istream.avail_out = out_str->data_len;
            if (inl > 0)
                err = inflate(&decomp->istream, Z_SYNC_FLUSH);
            if (err != Z_OK) {
                ssl_debug_printf("ssl_decompress_record: inflate() failed - %d\n", err);
                return -1;
            }
            *outl = out_str->data_len - decomp->istream.avail_out;
            break;
        default:
            ssl_debug_printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
            return -1;
    }
    return 0;
}
#else
int
ssl_decompress_record(SslDecompress* decomp _U_, const guchar* in _U_, guint inl _U_, StringInfo* out_str _U_, guint* outl _U_)
{
    ssl_debug_printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
    return -1;
}
#endif
/* Record Decompression (after decryption) }}} */
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGCRYPT
/* Create a new structure to store decrypted chunks. {{{ */
static SslFlow*
ssl_create_flow(void)
{
  SslFlow *flow;

  flow = (SslFlow *)wmem_alloc(wmem_file_scope(), sizeof(SslFlow));
  flow->byte_seq = 0;
  flow->flags = 0;
  flow->multisegment_pdus = wmem_tree_new(wmem_file_scope());
  return flow;
}
/* }}} */

/* Use the negotiated security parameters for decryption. {{{ */
void
ssl_change_cipher(SslDecryptSession *ssl_session, gboolean server)
{
    ssl_debug_printf("ssl_change_cipher %s\n", (server)?"SERVER":"CLIENT");
    if (server) {
        ssl_session->server = ssl_session->server_new;
        ssl_session->server_new = NULL;
    } else {
        ssl_session->client = ssl_session->client_new;
        ssl_session->client_new = NULL;
    }
}
/* }}} */

/* Init cipher state given some security parameters. {{{ */
static gboolean
ssl_decoder_destroy_cb(wmem_allocator_t *, wmem_cb_event_t, void *);

static SslDecoder*
ssl_create_decoder(const SslCipherSuite *cipher_suite, gint cipher_algo,
        gint compression, guint8 *mk, guint8 *sk, guint8 *iv, guint iv_length)
{
    SslDecoder *dec;
    ssl_cipher_mode_t mode = cipher_suite->mode;

    dec = (SslDecoder *)wmem_alloc0(wmem_file_scope(), sizeof(SslDecoder));
    /* init mac buffer: mac storage is embedded into decoder struct to save a
     memory allocation and waste samo more memory*/
    dec->cipher_suite=cipher_suite;
    dec->compression = compression;
    if ((mode == MODE_STREAM && mk != NULL) || mode == MODE_CBC) {
        // AEAD ciphers use no MAC key, but stream and block ciphers do. Note
        // the special case for NULL ciphers, even if there is insufficieny
        // keying material (including MAC key), we will can still create
        // decoders since "decryption" is easy for such ciphers.
        dec->mac_key.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->mac_key, mk, ssl_cipher_suite_dig(cipher_suite)->len);
    } else if (mode == MODE_GCM || mode == MODE_CCM || mode == MODE_CCM_8) {
        // Input for the nonce, to be used with AEAD ciphers.
        DISSECTOR_ASSERT(iv_length <= sizeof(dec->_mac_key_or_write_iv));
        dec->write_iv.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->write_iv, iv, iv_length);
    }
    dec->seq = 0;
    dec->decomp = ssl_create_decompressor(compression);
    wmem_register_callback(wmem_file_scope(), ssl_decoder_destroy_cb, dec);

    if (ssl_cipher_init(&dec->evp,cipher_algo,sk,iv,cipher_suite->mode) < 0) {
        ssl_debug_printf("%s: can't create cipher id:%d mode:%d\n", G_STRFUNC,
            cipher_algo, cipher_suite->mode);
        return NULL;
    }

    ssl_debug_printf("decoder initialized (digest len %d)\n", ssl_cipher_suite_dig(cipher_suite)->len);
    return dec;
}

static gboolean
ssl_decoder_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    SslDecoder *dec = (SslDecoder *) user_data;

    if (dec->evp)
        ssl_cipher_cleanup(&dec->evp);

#ifdef HAVE_ZLIB
    if (dec->decomp != NULL && dec->decomp->compression == 1 /* DEFLATE */)
        inflateEnd(&dec->decomp->istream);
#endif

    return FALSE;
}
/* }}} */

/* (Pre-)master secrets calculations {{{ */
#ifdef HAVE_LIBGNUTLS
static int
ssl_decrypt_pre_master_secret(SslDecryptSession *ssl_session,
                              StringInfo *encrypted_pre_master,
                              gcry_sexp_t pk);
#endif /* HAVE_LIBGNUTLS */

static gboolean
ssl_restore_master_key(SslDecryptSession *ssl, const char *label,
                       gboolean is_pre_master, GHashTable *ht, StringInfo *key);

gboolean
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session,
                               guint32 length, tvbuff_t *tvb, guint32 offset,
                               const gchar *ssl_psk,
                               const ssl_master_key_map_t *mk_map)
{
    /* check for required session data */
    ssl_debug_printf("%s: found SSL_HND_CLIENT_KEY_EXCHG, state %X\n",
                     G_STRFUNC, ssl_session->state);
    if ((ssl_session->state & (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) !=
        (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) {
        ssl_debug_printf("%s: not enough data to generate key (required state %X)\n", G_STRFUNC,
                         (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION));
        return FALSE;
    }

    if (ssl_session->session.version == TLSV1DOT3_VERSION) {
        ssl_debug_printf("%s: detected TLS 1.3 which has no pre-master secrets\n", G_STRFUNC);
        return FALSE;
    }

    /* check to see if the PMS was provided to us*/
    if (ssl_restore_master_key(ssl_session, "Unencrypted pre-master secret", TRUE,
           mk_map->pms, &ssl_session->client_random)) {
        return TRUE;
    }

    if (ssl_session->cipher_suite->kex == KEX_PSK)
    {
        /* calculate pre master secret*/
        StringInfo pre_master_secret;
        guint psk_len, pre_master_len;

        if (!ssl_psk || (ssl_psk[0] == 0)) {
            ssl_debug_printf("%s: can't find pre-shared-key\n", G_STRFUNC);
            return FALSE;
        }

        /* convert hex string into char*/
        if (!from_hex(&ssl_session->psk, ssl_psk, strlen(ssl_psk))) {
            ssl_debug_printf("%s: ssl.psk/dtls.psk contains invalid hex\n",
                             G_STRFUNC);
            return FALSE;
        }

        psk_len = ssl_session->psk.data_len;
        if (psk_len >= (2 << 15)) {
            ssl_debug_printf("%s: ssl.psk/dtls.psk must not be larger than 2^15 - 1\n",
                             G_STRFUNC);
            return FALSE;
        }


        pre_master_len = psk_len * 2 + 4;

        pre_master_secret.data = (guchar *)wmem_alloc(wmem_file_scope(), pre_master_len);
        pre_master_secret.data_len = pre_master_len;
        /* 2 bytes psk_len*/
        pre_master_secret.data[0] = psk_len >> 8;
        pre_master_secret.data[1] = psk_len & 0xFF;
        /* psk_len bytes times 0*/
        memset(&pre_master_secret.data[2], 0, psk_len);
        /* 2 bytes psk_len*/
        pre_master_secret.data[psk_len + 2] = psk_len >> 8;
        pre_master_secret.data[psk_len + 3] = psk_len & 0xFF;
        /* psk*/
        memcpy(&pre_master_secret.data[psk_len + 4], ssl_session->psk.data, psk_len);

        ssl_session->pre_master_secret.data = pre_master_secret.data;
        ssl_session->pre_master_secret.data_len = pre_master_len;
        /*ssl_debug_printf("pre master secret",&ssl->pre_master_secret);*/

        /* Remove the master secret if it was there.
           This forces keying material regeneration in
           case we're renegotiating */
        ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
        ssl_session->state |= SSL_PRE_MASTER_SECRET;
        return TRUE;
    }
    else
    {
        StringInfo encrypted_pre_master;
        guint encrlen, skip;
        encrlen = length;
        skip = 0;

        /* get encrypted data, on tls1 we have to skip two bytes
         * (it's the encrypted len and should be equal to record len - 2)
         * in case of rsa1024 that would be 128 + 2 = 130; for psk not necessary
         */
        if (ssl_session->cipher_suite->kex == KEX_RSA &&
           (ssl_session->session.version == TLSV1_VERSION ||
            ssl_session->session.version == TLSV1DOT1_VERSION ||
            ssl_session->session.version == TLSV1DOT2_VERSION ||
            ssl_session->session.version == DTLSV1DOT0_VERSION ||
            ssl_session->session.version == DTLSV1DOT2_VERSION))
        {
            encrlen  = tvb_get_ntohs(tvb, offset);
            skip = 2;
            if (encrlen > length - 2)
            {
                ssl_debug_printf("%s: wrong encrypted length (%d max %d)\n",
                                 G_STRFUNC, encrlen, length);
                return FALSE;
            }
        }
        /* the valid lower bound is higher than 8, but it is sufficient for the
         * ssl keylog file below */
        if (encrlen < 8) {
            ssl_debug_printf("%s: invalid encrypted pre-master key length %d\n",
                             G_STRFUNC, encrlen);
            return FALSE;
        }

        encrypted_pre_master.data = (guchar *)wmem_alloc(wmem_file_scope(), encrlen);
        encrypted_pre_master.data_len = encrlen;
        tvb_memcpy(tvb, encrypted_pre_master.data, offset+skip, encrlen);

#ifdef HAVE_LIBGNUTLS
        if (ssl_session->private_key) {
            /* try to decrypt encrypted pre-master with RSA key */
            if (ssl_decrypt_pre_master_secret(ssl_session,
                &encrypted_pre_master, ssl_session->private_key))
                return TRUE;

            ssl_debug_printf("%s: can't decrypt pre-master secret\n",
                             G_STRFUNC);
        }
#endif /* HAVE_LIBGNUTLS */

        /* try to find the pre-master secret from the encrypted one. The
         * ssl key logfile stores only the first 8 bytes, so truncate it */
        encrypted_pre_master.data_len = 8;
        if (ssl_restore_master_key(ssl_session, "Encrypted pre-master secret",
            TRUE, mk_map->pre_master, &encrypted_pre_master))
            return TRUE;
    }
    return FALSE;
}

/* Used for (D)TLS 1.2 and earlier versions (not with TLS 1.3). */
int
ssl_generate_keyring_material(SslDecryptSession*ssl_session)
{
    StringInfo  key_block = { NULL, 0 };
    guint8      _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];
    guint8      _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    gint        needed;
    gint        cipher_algo = -1;   /* special value (-1) for NULL encryption */
    guint       encr_key_len, write_iv_len = 0;
    gboolean    is_export_cipher;
    guint8     *ptr, *c_iv = NULL, *s_iv = NULL;
    guint8     *c_wk = NULL, *s_wk = NULL, *c_mk = NULL, *s_mk = NULL;
    const SslCipherSuite *cipher_suite = ssl_session->cipher_suite;

    /* TLS 1.3 is handled directly in tls13_change_key. */
    if (ssl_session->session.version == TLSV1DOT3_VERSION) {
        ssl_debug_printf("%s: detected TLS 1.3. Should not have been called!\n", G_STRFUNC);
        return -1;
    }

    /* check for enough info to proced */
    guint need_all = SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION;
    guint need_any = SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;
    if (((ssl_session->state & need_all) != need_all) || ((ssl_session->state & need_any) == 0)) {
        ssl_debug_printf("ssl_generate_keyring_material not enough data to generate key "
                         "(0x%02X required 0x%02X or 0x%02X)\n", ssl_session->state,
                         need_all|SSL_MASTER_SECRET, need_all|SSL_PRE_MASTER_SECRET);
        /* Special case: for NULL encryption, allow dissection of data even if
         * the Client Hello is missing (MAC keys are now skipped though). */
        need_all = SSL_CIPHER|SSL_VERSION;
        if ((ssl_session->state & need_all) == need_all &&
                cipher_suite->enc == ENC_NULL) {
            ssl_debug_printf("%s NULL cipher found, will create a decoder but "
                    "skip MAC validation as keys are missing.\n", G_STRFUNC);
            goto create_decoders;
        }

        return -1;
    }

    /* if master key is not available, generate is from the pre-master secret */
    if (!(ssl_session->state & SSL_MASTER_SECRET)) {
        if ((ssl_session->state & SSL_EXTENDED_MASTER_SECRET_MASK) == SSL_EXTENDED_MASTER_SECRET_MASK) {
            StringInfo handshake_hashed_data;
            gint ret;

            handshake_hashed_data.data = NULL;
            handshake_hashed_data.data_len = 0;

            ssl_debug_printf("%s:PRF(pre_master_secret_extended)\n", G_STRFUNC);
            ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
            DISSECTOR_ASSERT(ssl_session->handshake_data.data_len > 0);

            switch(ssl_session->session.version) {
            case TLSV1_VERSION:
            case TLSV1DOT1_VERSION:
            case DTLSV1DOT0_VERSION:
            case DTLSV1DOT0_OPENSSL_VERSION:
                ret = tls_handshake_hash(ssl_session, &handshake_hashed_data);
                break;
            default:
                switch (cipher_suite->dig) {
                case DIG_SHA384:
                    ret = tls12_handshake_hash(ssl_session, GCRY_MD_SHA384, &handshake_hashed_data);
                    break;
                default:
                    ret = tls12_handshake_hash(ssl_session, GCRY_MD_SHA256, &handshake_hashed_data);
                    break;
                }
                break;
            }
            if (ret) {
                ssl_debug_printf("%s can't generate handshake hash\n", G_STRFUNC);
                return -1;
            }

            wmem_free(wmem_file_scope(), ssl_session->handshake_data.data);
            ssl_session->handshake_data.data = NULL;
            ssl_session->handshake_data.data_len = 0;

            if (!prf(ssl_session, &ssl_session->pre_master_secret, "extended master secret",
                     &handshake_hashed_data,
                     NULL, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                g_free(handshake_hashed_data.data);
                return -1;
            }
            g_free(handshake_hashed_data.data);
        } else {
            ssl_debug_printf("%s:PRF(pre_master_secret)\n", G_STRFUNC);
            ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
            ssl_print_string("client random",&ssl_session->client_random);
            ssl_print_string("server random",&ssl_session->server_random);
            if (!prf(ssl_session, &ssl_session->pre_master_secret, "master secret",
                     &ssl_session->client_random,
                     &ssl_session->server_random, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                return -1;
            }
        }
        ssl_print_string("master secret",&ssl_session->master_secret);

        /* the pre-master secret has been 'consumend' so we must clear it now */
        ssl_session->state &= ~SSL_PRE_MASTER_SECRET;
        ssl_session->state |= SSL_MASTER_SECRET;
    }

    /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
    if (cipher_suite->enc != ENC_NULL) {
        const char *cipher_name = ciphers[cipher_suite->enc-0x30];
        ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
        cipher_algo = ssl_get_cipher_by_name(cipher_name);
        if (cipher_algo == 0) {
            ssl_debug_printf("%s can't find cipher %s\n", G_STRFUNC, cipher_name);
            return -1;
        }
    }

    /* Export ciphers consume less material from the key block. */
    encr_key_len = ssl_get_cipher_export_keymat_size(cipher_suite->number);
    is_export_cipher = encr_key_len > 0;
    if (!is_export_cipher && cipher_suite->enc != ENC_NULL) {
        encr_key_len = (guint)gcry_cipher_get_algo_keylen(cipher_algo);
    }

    if (cipher_suite->mode == MODE_CBC) {
        write_iv_len = (guint)gcry_cipher_get_algo_blklen(cipher_algo);
    } else if (cipher_suite->mode == MODE_GCM || cipher_suite->mode == MODE_CCM || cipher_suite->mode == MODE_CCM_8) {
        /* account for a four-byte salt for client and server side (from
         * client_write_IV and server_write_IV), see GCMNonce (RFC 5288) */
        write_iv_len = 4;
    }

    /* Compute the key block. First figure out how much data we need */
    needed = ssl_cipher_suite_dig(cipher_suite)->len*2;     /* MAC key  */
    needed += 2 * encr_key_len;                             /* encryption key */
    needed += 2 * write_iv_len;                             /* write IV */

    key_block.data = (guchar *)g_malloc(needed);
    ssl_debug_printf("%s sess key generation\n", G_STRFUNC);
    if (!prf(ssl_session, &ssl_session->master_secret, "key expansion",
            &ssl_session->server_random,&ssl_session->client_random,
            &key_block, needed)) {
        ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
        goto fail;
    }
    ssl_print_string("key expansion", &key_block);

    ptr=key_block.data;
    /* client/server write MAC key (for non-AEAD ciphers) */
    if (cipher_suite->mode == MODE_STREAM || cipher_suite->mode == MODE_CBC) {
        c_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
        s_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
    }
    /* client/server write encryption key */
    c_wk=ptr; ptr += encr_key_len;
    s_wk=ptr; ptr += encr_key_len;
    /* client/server write IV (used as IV (for CBC) or salt (for AEAD)) */
    if (write_iv_len > 0) {
        c_iv=ptr; ptr += write_iv_len;
        s_iv=ptr; /* ptr += write_iv_len; */
    }

    /* export ciphers work with a smaller key length */
    if (is_export_cipher) {
        if (cipher_suite->mode == MODE_CBC) {

            /* We only have room for MAX_BLOCK_SIZE bytes IVs, but that's
             all we should need. This is a sanity check */
            if (write_iv_len > MAX_BLOCK_SIZE) {
                ssl_debug_printf("%s cipher suite block must be at most %d nut is %d\n",
                        G_STRFUNC, MAX_BLOCK_SIZE, write_iv_len);
                goto fail;
            }

            if(ssl_session->session.version==SSLV3_VERSION){
                /* The length of these fields are ignored by this caller */
                StringInfo iv_c, iv_s;
                iv_c.data = _iv_c;
                iv_s.data = _iv_s;

                ssl_debug_printf("%s ssl3_generate_export_iv\n", G_STRFUNC);
                ssl3_generate_export_iv(&ssl_session->client_random,
                        &ssl_session->server_random, &iv_c, write_iv_len);
                ssl_debug_printf("%s ssl3_generate_export_iv(2)\n", G_STRFUNC);
                ssl3_generate_export_iv(&ssl_session->server_random,
                        &ssl_session->client_random, &iv_s, write_iv_len);
            }
            else{
                guint8 _iv_block[MAX_BLOCK_SIZE * 2];
                StringInfo iv_block;
                StringInfo key_null;
                guint8 _key_null;

                key_null.data = &_key_null;
                key_null.data_len = 0;

                iv_block.data = _iv_block;

                ssl_debug_printf("%s prf(iv_block)\n", G_STRFUNC);
                if (!prf(ssl_session, &key_null, "IV block",
                        &ssl_session->client_random,
                        &ssl_session->server_random, &iv_block,
                        write_iv_len * 2)) {
                    ssl_debug_printf("%s can't generate tls31 iv block\n", G_STRFUNC);
                    goto fail;
                }

                memcpy(_iv_c, iv_block.data, write_iv_len);
                memcpy(_iv_s, iv_block.data + write_iv_len, write_iv_len);
            }

            c_iv=_iv_c;
            s_iv=_iv_s;
        }

        if (ssl_session->session.version==SSLV3_VERSION){

            SSL_MD5_CTX md5;
            ssl_debug_printf("%s MD5(client_random)\n", G_STRFUNC);

            ssl_md5_init(&md5);
            ssl_md5_update(&md5,c_wk,encr_key_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                ssl_session->client_random.data_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                ssl_session->server_random.data_len);
            ssl_md5_final(_key_c,&md5);
            ssl_md5_cleanup(&md5);
            c_wk=_key_c;

            ssl_md5_init(&md5);
            ssl_debug_printf("%s MD5(server_random)\n", G_STRFUNC);
            ssl_md5_update(&md5,s_wk,encr_key_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                ssl_session->server_random.data_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                ssl_session->client_random.data_len);
            ssl_md5_final(_key_s,&md5);
            ssl_md5_cleanup(&md5);
            s_wk=_key_s;
        }
        else{
            StringInfo key_c, key_s, k;
            key_c.data = _key_c;
            key_s.data = _key_s;

            k.data = c_wk;
            k.data_len = encr_key_len;
            ssl_debug_printf("%s PRF(key_c)\n", G_STRFUNC);
            if (!prf(ssl_session, &k, "client write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_c, sizeof(_key_c))) {
                ssl_debug_printf("%s can't generate tll31 server key \n", G_STRFUNC);
                goto fail;
            }
            c_wk=_key_c;

            k.data = s_wk;
            k.data_len = encr_key_len;
            ssl_debug_printf("%s PRF(key_s)\n", G_STRFUNC);
            if (!prf(ssl_session, &k, "server write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_s, sizeof(_key_s))) {
                ssl_debug_printf("%s can't generate tll31 client key \n", G_STRFUNC);
                goto fail;
            }
            s_wk=_key_s;
        }
    }

    /* show key material info */
    if (c_mk != NULL) {
        ssl_print_data("Client MAC key",c_mk,ssl_cipher_suite_dig(cipher_suite)->len);
        ssl_print_data("Server MAC key",s_mk,ssl_cipher_suite_dig(cipher_suite)->len);
    }
    ssl_print_data("Client Write key", c_wk, encr_key_len);
    ssl_print_data("Server Write key", s_wk, encr_key_len);
    /* used as IV for CBC mode and the AEAD implicit nonce (salt) */
    if (write_iv_len > 0) {
        ssl_print_data("Client Write IV", c_iv, write_iv_len);
        ssl_print_data("Server Write IV", s_iv, write_iv_len);
    }

create_decoders:
    /* create both client and server ciphers*/
    ssl_debug_printf("%s ssl_create_decoder(client)\n", G_STRFUNC);
    ssl_session->client_new = ssl_create_decoder(cipher_suite, cipher_algo, ssl_session->session.compression, c_mk, c_wk, c_iv, write_iv_len);
    if (!ssl_session->client_new) {
        ssl_debug_printf("%s can't init client decoder\n", G_STRFUNC);
        goto fail;
    }
    ssl_debug_printf("%s ssl_create_decoder(server)\n", G_STRFUNC);
    ssl_session->server_new = ssl_create_decoder(cipher_suite, cipher_algo, ssl_session->session.compression, s_mk, s_wk, s_iv, write_iv_len);
    if (!ssl_session->server_new) {
        ssl_debug_printf("%s can't init client decoder\n", G_STRFUNC);
        goto fail;
    }

    /* Continue the SSL stream after renegotiation with new keys. */
    ssl_session->client_new->flow = ssl_session->client ? ssl_session->client->flow : ssl_create_flow();
    ssl_session->server_new->flow = ssl_session->server ? ssl_session->server->flow : ssl_create_flow();

    ssl_debug_printf("%s: client seq %" G_GUINT64_FORMAT ", server seq %" G_GUINT64_FORMAT "\n",
        G_STRFUNC, ssl_session->client_new->seq, ssl_session->server_new->seq);
    g_free(key_block.data);
    ssl_session->state |= SSL_HAVE_SESSION_KEY;
    return 0;

fail:
    g_free(key_block.data);
    return -1;
}

/* Generated the key material based on the given secret. */
static gboolean
tls13_generate_keys(SslDecryptSession *ssl_session, const StringInfo *secret, gboolean is_from_server)
{
    gboolean    success = FALSE;
    guchar     *write_key = NULL, *write_iv = NULL;
    SslDecoder *decoder;
    guint       key_length, iv_length;
    int         hash_algo;
    const SslCipherSuite *cipher_suite = ssl_session->cipher_suite;
    int         cipher_algo;

    if (ssl_session->session.version != TLSV1DOT3_VERSION) {
        ssl_debug_printf("%s only usable for TLS 1.3, not %#x!\n", G_STRFUNC,
                ssl_session->session.version);
        return FALSE;
    }

    if (cipher_suite == NULL) {
        ssl_debug_printf("%s Unknown cipher\n", G_STRFUNC);
        return FALSE;
    }

    if (cipher_suite->kex != KEX_TLS13) {
        ssl_debug_printf("%s Invalid cipher suite 0x%04x spotted!\n", G_STRFUNC, cipher_suite->number);
        return FALSE;
    }

    /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
    const char *cipher_name = ciphers[cipher_suite->enc-0x30];
    ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
    cipher_algo = ssl_get_cipher_by_name(cipher_name);
    if (cipher_algo == 0) {
        ssl_debug_printf("%s can't find cipher %s\n", G_STRFUNC, cipher_name);
        return FALSE;
    }

    const char *hash_name = ssl_cipher_suite_dig(cipher_suite)->name;
    hash_algo = ssl_get_digest_by_name(hash_name);
    if (!hash_algo) {
        ssl_debug_printf("%s can't find hash function %s\n", G_STRFUNC, hash_name);
        return FALSE;
    }

    key_length = (guint) gcry_cipher_get_algo_blklen(cipher_algo);
    /* AES-GCM/AES-CCM/Poly1305-ChaCha20 all have N_MIN=N_MAX = 12. */
    iv_length = 12;
    ssl_debug_printf("%s key_length %u iv_length %u\n", G_STRFUNC, key_length, iv_length);

    if (!tls13_hkdf_expand_label(hash_algo, secret, "key", "", key_length, &write_key)) {
        ssl_debug_printf("%s write_key expansion failed\n", G_STRFUNC);
        return FALSE;
    }
    if (!tls13_hkdf_expand_label(hash_algo, secret, "iv", "", iv_length, &write_iv)) {
        ssl_debug_printf("%s write_iv expansion failed\n", G_STRFUNC);
        goto end;
    }

    ssl_print_data(is_from_server ? "Server Write Key" : "Client Write Key", write_key, key_length);
    ssl_print_data(is_from_server ? "Server Write IV" : "Client Write IV", write_iv, iv_length);

    ssl_debug_printf("%s ssl_create_decoder(%s)\n", G_STRFUNC, is_from_server ? "server" : "client");
    decoder = ssl_create_decoder(cipher_suite, cipher_algo, 0, NULL, write_key, write_iv, iv_length);
    if (!decoder) {
        ssl_debug_printf("%s can't init %s decoder\n", G_STRFUNC, is_from_server ? "server" : "client");
        goto end;
    }

    /* Continue the TLS session with new keys, but reuse old flow to keep things
     * like "Follow SSL" working (by linking application data records). */
    if (is_from_server) {
        decoder->flow = ssl_session->server ? ssl_session->server->flow : ssl_create_flow();
        ssl_session->server = decoder;
    } else {
        decoder->flow = ssl_session->client ? ssl_session->client->flow : ssl_create_flow();
        ssl_session->client = decoder;
    }
    ssl_debug_printf("%s %s ready using cipher suite 0x%04x (cipher %s hash %s)\n", G_STRFUNC,
                     is_from_server ? "Server" : "Client", cipher_suite->number, cipher_name, hash_name);
    success = TRUE;

end:
    wmem_free(NULL, write_key);
    wmem_free(NULL, write_iv);
    return success;
}
/* (Pre-)master secrets calculations }}} */

#ifdef HAVE_LIBGNUTLS
/* Decrypt RSA pre-master secret using RSA private key. {{{ */
static gboolean
ssl_decrypt_pre_master_secret(SslDecryptSession*ssl_session,
    StringInfo* encrypted_pre_master, gcry_sexp_t pk)
{
    gint i;

    if (!encrypted_pre_master)
        return FALSE;

    if (KEX_IS_DH(ssl_session->cipher_suite->kex)) {
        ssl_debug_printf("%s: session uses Diffie-Hellman key exchange "
                         "(cipher suite 0x%04X %s) and cannot be decrypted "
                         "using a RSA private key file.\n",
                         G_STRFUNC, ssl_session->session.cipher,
                         val_to_str_ext_const(ssl_session->session.cipher,
                             &ssl_31_ciphersuite_ext, "unknown"));
        return FALSE;
    } else if(ssl_session->cipher_suite->kex != KEX_RSA) {
         ssl_debug_printf("%s key exchange %d different from KEX_RSA (%d)\n",
                          G_STRFUNC, ssl_session->cipher_suite->kex, KEX_RSA);
        return FALSE;
    }

    /* with tls key loading will fail if not rsa type, so no need to check*/
    ssl_print_string("pre master encrypted",encrypted_pre_master);
    ssl_debug_printf("%s: RSA_private_decrypt\n", G_STRFUNC);
    i=ssl_private_decrypt(encrypted_pre_master->data_len,
        encrypted_pre_master->data, pk);

    if (i!=48) {
        ssl_debug_printf("%s wrong pre_master_secret length (%d, expected "
                         "%d)\n", G_STRFUNC, i, 48);
        return FALSE;
    }

    /* the decrypted data has been written into the pre_master key buffer */
    ssl_session->pre_master_secret.data = encrypted_pre_master->data;
    ssl_session->pre_master_secret.data_len=48;
    ssl_print_string("pre master secret",&ssl_session->pre_master_secret);

    /* Remove the master secret if it was there.
       This forces keying material regeneration in
       case we're renegotiating */
    ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
    ssl_session->state |= SSL_PRE_MASTER_SECRET;
    return TRUE;
} /* }}} */
#endif /* HAVE_LIBGNUTLS */

/* Decryption integrity check {{{ */

static gint
tls_check_mac(SslDecoder*decoder, gint ct, gint ver, guint8* data,
        guint32 datalen, guint8* mac)
{
    SSL_HMAC hm;
    gint     md;
    guint32  len;
    guint8   buf[DIGEST_MAX_SIZE];
    gint16   temp;

    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    ssl_debug_printf("tls_check_mac mac type:%s md %d\n",
        ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    if (ssl_hmac_init(&hm,decoder->mac_key.data,decoder->mac_key.data_len,md) != 0)
        return -1;

    /* hash sequence number */
    phton64(buf, decoder->seq);

    decoder->seq++;

    ssl_hmac_update(&hm,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_hmac_update(&hm,buf,1);

    /* hash version,data length and data*/
    /* *((gint16*)buf) = g_htons(ver); */
    temp = g_htons(ver);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);

    /* *((gint16*)buf) = g_htons(datalen); */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);

    /* get digest and digest len*/
    len = sizeof(buf);
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return 0;
}

static int
ssl3_check_mac(SslDecoder*decoder,int ct,guint8* data,
        guint32 datalen, guint8* mac)
{
    SSL_MD  mc;
    gint    md;
    guint32 len;
    guint8  buf[64],dgst[20];
    gint    pad_ct;
    gint16  temp;

    pad_ct=(decoder->cipher_suite->dig==DIG_SHA)?40:48;

    /* get cipher used for digest comptuation */
    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    if (ssl_md_init(&mc,md) !=0)
        return -1;

    /* do hash computation on data && padding */
    ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

    /* hash padding*/
    memset(buf,0x36,pad_ct);
    ssl_md_update(&mc,buf,pad_ct);

    /* hash sequence number */
    phton64(buf, decoder->seq);
    decoder->seq++;
    ssl_md_update(&mc,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_md_update(&mc,buf,1);

    /* hash data length in network byte order and data*/
    /* *((gint16* )buf) = g_htons(datalen); */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_md_update(&mc,buf,2);
    ssl_md_update(&mc,data,datalen);

    /* get partial digest */
    ssl_md_final(&mc,dgst,&len);
    ssl_md_cleanup(&mc);

    ssl_md_init(&mc,md);

    /* hash mac key */
    ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

    /* hash padding and partial digest*/
    memset(buf,0x5c,pad_ct);
    ssl_md_update(&mc,buf,pad_ct);
    ssl_md_update(&mc,dgst,len);

    ssl_md_final(&mc,dgst,&len);
    ssl_md_cleanup(&mc);

    if(memcmp(mac,dgst,len))
        return -1;

    return(0);
}

static gint
dtls_check_mac(SslDecoder*decoder, gint ct,int ver, guint8* data,
        guint32 datalen, guint8* mac)
{
    SSL_HMAC hm;
    gint     md;
    guint32  len;
    guint8   buf[DIGEST_MAX_SIZE];
    gint16   temp;

    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    ssl_debug_printf("dtls_check_mac mac type:%s md %d\n",
        ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    if (ssl_hmac_init(&hm,decoder->mac_key.data,decoder->mac_key.data_len,md) != 0)
        return -1;
    ssl_debug_printf("dtls_check_mac seq: %" G_GUINT64_FORMAT " epoch: %d\n",decoder->seq,decoder->epoch);
    /* hash sequence number */
    phton64(buf, decoder->seq);
    buf[0]=decoder->epoch>>8;
    buf[1]=(guint8)decoder->epoch;

    ssl_hmac_update(&hm,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_hmac_update(&hm,buf,1);

    /* hash version,data length and data */
    temp = g_htons(ver);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);

    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);
    /* get digest and digest len */
    len = sizeof(buf);
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return(0);
}
/* Decryption integrity check }}} */


static gboolean
tls_decrypt_aead_record(SslDecryptSession *ssl, SslDecoder *decoder,
#ifdef HAVE_LIBGCRYPT_AEAD
        guint8 ct, guint16 record_version,
#else
        guint8 ct _U_, guint16 record_version _U_,
#endif
        const guchar *in, guint16 inl, StringInfo *out_str, guint *outl)
{
    /* RFC 5246 (TLS 1.2) 6.2.3.3 defines the TLSCipherText.fragment as:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * In TLS 1.3 this explicit nonce is gone.
     * With AES GCM/CCM, "[content]" is actually the concatenation of the
     * ciphertext and authentication tag.
     */
    const guint16   version = ssl->session.version;
    const gboolean  is_v12 = version == TLSV1DOT2_VERSION || version == DTLSV1DOT2_VERSION;
    gcry_error_t    err;
    const guchar   *explicit_nonce = NULL, *ciphertext;
    guint           ciphertext_len, auth_tag_len;
    guchar          nonce[12];
#ifdef HAVE_LIBGCRYPT_AEAD
    const guchar   *auth_tag_wire;
    guchar          auth_tag_calc[16];
#else
    guchar          nonce_with_counter[16] = { 0 };
#endif

    switch (decoder->cipher_suite->mode) {
    case MODE_GCM:
    case MODE_CCM:
        auth_tag_len = 16;
        break;
    case MODE_CCM_8:
        auth_tag_len = 8;
        break;
    default:
        ssl_debug_printf("%s unsupported cipher!\n", G_STRFUNC);
        return FALSE;
    }

    /* Parse input into explicit nonce (TLS 1.2 only), ciphertext and tag. */
    if (is_v12) {
        if (inl < EXPLICIT_NONCE_LEN + auth_tag_len) {
            ssl_debug_printf("%s input %d is too small for explicit nonce %d and auth tag %d\n",
                    G_STRFUNC, inl, EXPLICIT_NONCE_LEN, auth_tag_len);
            return FALSE;
        }
        explicit_nonce = in;
        ciphertext = explicit_nonce + EXPLICIT_NONCE_LEN;
        ciphertext_len = inl - EXPLICIT_NONCE_LEN - auth_tag_len;
    } else if (version == TLSV1DOT3_VERSION) {
        if (inl < auth_tag_len) {
            ssl_debug_printf("%s input %d has no space for auth tag %d\n", G_STRFUNC, inl, auth_tag_len);
            return FALSE;
        }
        ciphertext = in;
        ciphertext_len = inl - auth_tag_len;
    } else {
        ssl_debug_printf("%s Unexpected TLS version %#x\n", G_STRFUNC, version);
        return FALSE;
    }
#ifdef HAVE_LIBGCRYPT_AEAD
    auth_tag_wire = ciphertext + ciphertext_len;
#endif

    /* Nonce construction is version-specific. */
    if (is_v12) {
        DISSECTOR_ASSERT(decoder->write_iv.data_len == IMPLICIT_NONCE_LEN);
        /* Implicit (4) and explicit (8) part of nonce. */
        memcpy(nonce, decoder->write_iv.data, IMPLICIT_NONCE_LEN);
        memcpy(nonce + IMPLICIT_NONCE_LEN, explicit_nonce, EXPLICIT_NONCE_LEN);

#ifndef HAVE_LIBGCRYPT_AEAD
        if (decoder->cipher_suite->mode == MODE_GCM) {
            /* NIST SP 800-38D, sect. 7.2 says that the 32-bit counter part starts
             * at 1, and gets incremented before passing to the block cipher. */
            memcpy(nonce_with_counter, nonce, IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN);
            nonce_with_counter[IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN + 3] = 2;
        } else { /* MODE_CCM and MODE_CCM_8 */
            /* The nonce for CCM and GCM are the same, but the nonce is used as input
             * in the CCM algorithm described in RFC 3610. The nonce generated here is
             * the one from RFC 3610 sect 2.3. Encryption. */
            /* Flags: (L-1) ; L = 16 - 1 - nonceSize */
            nonce_with_counter[0] = 3 - 1;
            memcpy(nonce_with_counter + 1, nonce, IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN);
            /* struct { opaque salt[4]; opaque nonce_explicit[8] } CCMNonce (RFC 6655) */
            nonce_with_counter[IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN + 3] = 1;
        }
#endif
    } else if (version == TLSV1DOT3_VERSION) {
        /*
         * Technically the nonce length must be at least 8 bytes, but for
         * AES-GCM, AES-CCM and Poly1305-ChaCha20 the nonce length is exact 12.
         */
        const guint nonce_len = 12;
        DISSECTOR_ASSERT(decoder->write_iv.data_len == nonce_len);
        memcpy(nonce, decoder->write_iv.data, decoder->write_iv.data_len);
        /* Sequence number is left-padded with zeroes and XORed with write_iv */
        phton64(nonce + nonce_len - 8, pntoh64(nonce + nonce_len - 8) ^ decoder->seq);
        ssl_debug_printf("%s seq %" G_GUINT64_FORMAT "\n", G_STRFUNC, decoder->seq);
        decoder->seq++;             /* Implicit sequence number for TLS 1.3. */
    }

    /* Set nonce and additional authentication data */
#ifdef HAVE_LIBGCRYPT_AEAD
    gcry_cipher_reset(decoder->evp);
    ssl_print_data("nonce", nonce, 12);
    err = gcry_cipher_setiv(decoder->evp, nonce, 12);
    if (err) {
        ssl_debug_printf("%s failed to set nonce: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }

    if (decoder->cipher_suite->mode == MODE_CCM || decoder->cipher_suite->mode == MODE_CCM_8) {
        /* size of plaintext, additional authenticated data and auth tag. */
        guint64 lengths[3] = { ciphertext_len, is_v12 ? 13 : 0, auth_tag_len };
        gcry_cipher_ctl(decoder->evp, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths));
    }

    /* (D)TLS 1.2 needs specific AAD, TLS 1.3 uses empty AAD. */
    if (is_v12) {
        guchar aad[13];
        phton64(aad, decoder->seq);         /* record sequence number */
        if (version == TLSV1DOT2_VERSION) {
            decoder->seq++;                 /* Implicit sequence number for TLS 1.2. */
        } else {
            phton16(aad, decoder->epoch);   /* DTLS 1.2 includes epoch. */
        }
        aad[8] = ct;                        /* TLSCompressed.type */
        phton16(aad + 9, record_version);   /* TLSCompressed.version */
        phton16(aad + 11, ciphertext_len);  /* TLSCompressed.length */
        ssl_print_data("AAD", aad, sizeof(aad));
        err = gcry_cipher_authenticate(decoder->evp, aad, sizeof(aad));
        if (err) {
            ssl_debug_printf("%s failed to set AAD: %s\n", G_STRFUNC, gcry_strerror(err));
            return FALSE;
        }
    }
#else
    err = gcry_cipher_setctr(decoder->evp, nonce_with_counter, 16);
    if (err) {
        ssl_debug_printf("%s failed: failed to set CTR: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }
#endif

    /* Decrypt now that nonce and AAD are set. */
    err = gcry_cipher_decrypt(decoder->evp, out_str->data, out_str->data_len, ciphertext, ciphertext_len);
    if (err) {
        ssl_debug_printf("%s decrypt failed: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }

    /* Check authentication tag for authenticity (replaces MAC) */
#ifdef HAVE_LIBGCRYPT_AEAD
    err = gcry_cipher_gettag(decoder->evp, auth_tag_calc, auth_tag_len);
    if (err == 0 && !memcmp(auth_tag_calc, auth_tag_wire, auth_tag_len)) {
        ssl_print_data("auth_tag(OK)", auth_tag_calc, auth_tag_len);
    } else {
        if (err) {
            ssl_debug_printf("%s cannot obtain tag: %s\n", G_STRFUNC, gcry_strerror(err));
        } else {
            ssl_debug_printf("%s auth tag mismatch\n", G_STRFUNC);
            ssl_print_data("auth_tag(expect)", auth_tag_calc, auth_tag_len);
            ssl_print_data("auth_tag(actual)", auth_tag_wire, auth_tag_len);
        }
        if (ssl_ignore_mac_failed) {
            ssl_debug_printf("%s: auth check failed, but ignored for troubleshooting ;-)\n", G_STRFUNC);
        } else {
            return FALSE;
        }
    }
#else
    ssl_debug_printf("Libgcrypt is older than 1.6, unable to verify auth tag!\n");
#endif

    ssl_print_data("Plaintext", out_str->data, ciphertext_len);
    *outl = ciphertext_len;
    return TRUE;
}

/* Record decryption glue based on security parameters {{{ */
/* Assume that we are called only for a non-NULL decoder which also means that
 * we have a non-NULL decoder->cipher_suite. */
int
ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, guint8 ct, guint16 record_version,
        const guchar *in, guint16 inl, StringInfo *comp_str, StringInfo *out_str, guint *outl)
{
    guint   pad, worklen, uncomplen;
    guint8 *mac;

    ssl_debug_printf("ssl_decrypt_record ciphertext len %d\n", inl);
    ssl_print_data("Ciphertext",in, inl);

    if ((ssl->session.version == TLSV1DOT3_VERSION) != (decoder->cipher_suite->kex == KEX_TLS13)) {
        ssl_debug_printf("%s Invalid cipher suite for the protocol version!\n", G_STRFUNC);
        return -1;
    }

    /* ensure we have enough storage space for decrypted data */
    if (inl > out_str->data_len)
    {
        ssl_debug_printf("ssl_decrypt_record: allocating %d bytes for decrypt data (old len %d)\n",
                inl + 32, out_str->data_len);
        ssl_data_realloc(out_str, inl + 32);
    }

    /* AEAD ciphers (GenericAEADCipher in TLS 1.2; TLS 1.3) have no padding nor
     * a separate MAC, so use a different routine for simplicity. */
    if (decoder->cipher_suite->mode == MODE_GCM ||
        decoder->cipher_suite->mode == MODE_CCM ||
        decoder->cipher_suite->mode == MODE_CCM_8 ||
        ssl->session.version == TLSV1DOT3_VERSION) {

        if (!tls_decrypt_aead_record(ssl, decoder, ct, record_version, in, inl, out_str, &worklen)) {
            /* decryption failed */
            return -1;
        }

        goto skip_mac;
    }

    /* RFC 6101/2246: SSLCipherText/TLSCipherText has two structures for types:
     * (notation: { unencrypted, [ encrypted ] })
     * GenericStreamCipher: { [content, mac] }
     * GenericBlockCipher: { IV (TLS 1.1+), [content, mac, padding, padding_len] }
     * RFC 5426 (TLS 1.2): TLSCipherText has additionally:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * RFC 4347 (DTLS): based on TLS 1.1, only GenericBlockCipher is supported.
     * RFC 6347 (DTLS 1.2): based on TLS 1.2, includes GenericAEADCipher too.
     */

    /* (TLS 1.1 and later, DTLS) Extract explicit IV for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
        guint blocksize;

        switch (ssl->session.version) {
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
        case DTLSV1DOT0_VERSION:
        case DTLSV1DOT2_VERSION:
        case DTLSV1DOT0_OPENSSL_VERSION:
            blocksize = ssl_get_cipher_blocksize(decoder->cipher_suite);
            if (inl < blocksize) {
                ssl_debug_printf("ssl_decrypt_record failed: input %d has no space for IV %d\n",
                        inl, blocksize);
                return -1;
            }
            pad = gcry_cipher_setiv(decoder->evp, in, blocksize);
            if (pad != 0) {
                ssl_debug_printf("ssl_decrypt_record failed: failed to set IV: %s %s\n",
                        gcry_strsource (pad), gcry_strerror (pad));
            }

            inl -= blocksize;
            in += blocksize;
            break;
        }
    }

    /* First decrypt*/
    if ((pad = ssl_cipher_decrypt(&decoder->evp, out_str->data, out_str->data_len, in, inl)) != 0) {
        ssl_debug_printf("ssl_decrypt_record failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
                    gcry_strerror (pad));
        return -1;
    }

    ssl_print_data("Plaintext", out_str->data, inl);
    worklen=inl;


    /* strip padding for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
        if (inl < 1) { /* Should this check happen earlier? */
            ssl_debug_printf("ssl_decrypt_record failed: input length %d too small\n", inl);
            return -1;
        }
        pad=out_str->data[inl-1];
        if (worklen <= pad) {
            ssl_debug_printf("ssl_decrypt_record failed: padding %d too large for work %d\n",
                pad, worklen);
            return -1;
        }
        worklen-=(pad+1);
        ssl_debug_printf("ssl_decrypt_record found padding %d final len %d\n",
            pad, worklen);
    }

    /* MAC for GenericStreamCipher and GenericBlockCipher */
    if (ssl_cipher_suite_dig(decoder->cipher_suite)->len > (gint)worklen) {
        ssl_debug_printf("ssl_decrypt_record wrong record len/padding outlen %d\n work %d\n",*outl, worklen);
        return -1;
    }
    worklen -= ssl_cipher_suite_dig(decoder->cipher_suite)->len;
    mac = out_str->data + worklen;

    /* If NULL encryption active and no keys are available, do not bother
     * checking the MAC. We do not have keys for that. */
    if (decoder->cipher_suite->mode == MODE_STREAM &&
            decoder->cipher_suite->enc == ENC_NULL &&
            !(ssl->state & SSL_MASTER_SECRET)) {
        ssl_debug_printf("MAC check skipped due to missing keys\n");
        goto skip_mac;
    }

    /* Now check the MAC */
    ssl_debug_printf("checking mac (len %d, version %X, ct %d seq %" G_GUINT64_FORMAT ")\n",
        worklen, ssl->session.version, ct, decoder->seq);
    if(ssl->session.version==SSLV3_VERSION){
        if(ssl3_check_mac(decoder,ct,out_str->data,worklen,mac) < 0) {
            if(ssl_ignore_mac_failed) {
                ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
            }
            else{
                ssl_debug_printf("ssl_decrypt_record: mac failed\n");
                return -1;
            }
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
    }
    else if(ssl->session.version==TLSV1_VERSION || ssl->session.version==TLSV1DOT1_VERSION || ssl->session.version==TLSV1DOT2_VERSION){
        if(tls_check_mac(decoder,ct,ssl->session.version,out_str->data,worklen,mac)< 0) {
            if(ssl_ignore_mac_failed) {
                ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
            }
            else{
                ssl_debug_printf("ssl_decrypt_record: mac failed\n");
                return -1;
            }
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
    }
    else if(ssl->session.version==DTLSV1DOT0_VERSION ||
        ssl->session.version==DTLSV1DOT2_VERSION ||
        ssl->session.version==DTLSV1DOT0_OPENSSL_VERSION){
        /* Try rfc-compliant mac first, and if failed, try old openssl's non-rfc-compliant mac */
        if(dtls_check_mac(decoder,ct,ssl->session.version,out_str->data,worklen,mac)>= 0) {
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
        else if(tls_check_mac(decoder,ct,TLSV1_VERSION,out_str->data,worklen,mac)>= 0) {
            ssl_debug_printf("ssl_decrypt_record: dtls rfc-compliant mac failed, but old openssl's non-rfc-compliant mac ok\n");
        }
        else if(ssl_ignore_mac_failed) {
            ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac failed\n");
            return -1;
        }
    }
skip_mac:

    *outl = worklen;

    if (decoder->compression > 0) {
        ssl_debug_printf("ssl_decrypt_record: compression method %d\n", decoder->compression);
        ssl_data_copy(comp_str, out_str);
        ssl_print_data("Plaintext compressed", comp_str->data, worklen);
        if (!decoder->decomp) {
            ssl_debug_printf("decrypt_ssl3_record: no decoder available\n");
            return -1;
        }
        if (ssl_decompress_record(decoder->decomp, comp_str->data, worklen, out_str, &uncomplen) < 0) return -1;
        ssl_print_data("Plaintext uncompressed", out_str->data, uncomplen);
        *outl = uncomplen;
    }

    return 0;
}
/* Record decryption glue based on security parameters }}} */

#endif /* HAVE_LIBGCRYPT */


#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
/* RSA private key file processing {{{ */
#define RSA_PARS 6
static gcry_sexp_t
ssl_privkey_to_sexp(gnutls_x509_privkey_t priv_key)
{
    gnutls_datum_t rsa_datum[RSA_PARS]; /* m, e, d, p, q, u */
    size_t         tmp_size;
    gcry_error_t   gret;
    gcry_sexp_t    rsa_priv_key = NULL;
    gint           i;
    gcry_mpi_t     rsa_params[RSA_PARS];

    /* RSA get parameter */
    if (gnutls_x509_privkey_export_rsa_raw(priv_key,
                                           &rsa_datum[0],
                                           &rsa_datum[1],
                                           &rsa_datum[2],
                                           &rsa_datum[3],
                                           &rsa_datum[4],
                                           &rsa_datum[5])  != 0) {
        ssl_debug_printf("ssl_load_key: can't export rsa param (is a rsa private key file ?!?)\n");
        return NULL;
    }

    /* convert each rsa parameter to mpi format*/
    for(i=0; i<RSA_PARS; i++) {
      gret = gcry_mpi_scan(&rsa_params[i], GCRYMPI_FMT_USG, rsa_datum[i].data, rsa_datum[i].size,&tmp_size);
      /* these buffers were allocated by gnutls_x509_privkey_export_rsa_raw() */
      g_free(rsa_datum[i].data);
      if (gret != 0) {
        ssl_debug_printf("ssl_load_key: can't convert m rsa param to int (size %d)\n", rsa_datum[i].size);
        return NULL;
      }
    }

    /* libgcrypt expects p < q, and gnutls might not return it as such, depending on gnutls version and its crypto backend */
    if (gcry_mpi_cmp(rsa_params[3], rsa_params[4]) > 0)
    {
        ssl_debug_printf("ssl_load_key: swapping p and q parameters and recomputing u\n");
        /* p, q = q, p */
        gcry_mpi_swap(rsa_params[3], rsa_params[4]);
        /* due to swapping p and q, u = p^-1 mod p which happens to be needed. */
    }
    /* libgcrypt expects u = p^-1 mod q (for OpenPGP), but the u parameter
     * says u = q^-1 mod p. Recompute u = p^-1 mod q. Do this unconditionally as
     * at least GnuTLS 2.12.23 computes an invalid value. */
    gcry_mpi_invm(rsa_params[5], rsa_params[3], rsa_params[4]);

    if  (gcry_sexp_build( &rsa_priv_key, NULL,
            "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))", rsa_params[0],
            rsa_params[1], rsa_params[2], rsa_params[3], rsa_params[4],
            rsa_params[5]) != 0) {
        ssl_debug_printf("ssl_load_key: can't build rsa private key s-exp\n");
        return NULL;
    }

    for (i=0; i< 6; i++)
        gcry_mpi_release(rsa_params[i]);
    return rsa_priv_key;
}

/** Load an RSA private key from specified file
 @param fp the file that contain the key data
 @return a pointer to the loaded key on success, or NULL */
static gnutls_x509_privkey_t
ssl_load_key(FILE* fp)
{
    /* gnutls makes our work much harder, since we have to work internally with
     * s-exp formatted data, but PEM loader exports only in "gnutls_datum_t"
     * format, and a datum -> s-exp convertion function does not exist.
     */
    gnutls_x509_privkey_t priv_key;
    gnutls_datum_t        key;
    ws_statb64            statbuf;
    gint                  ret;
    guint                 bytes;

    if (ws_fstat64(ws_fileno(fp), &statbuf) == -1) {
        ssl_debug_printf("ssl_load_key: can't ws_fstat64 file\n");
        return NULL;
    }
    if (S_ISDIR(statbuf.st_mode)) {
        ssl_debug_printf("ssl_load_key: file is a directory\n");
        errno = EISDIR;
        return NULL;
    }
    if (S_ISFIFO(statbuf.st_mode)) {
        ssl_debug_printf("ssl_load_key: file is a named pipe\n");
        errno = EINVAL;
        return NULL;
    }
    if (!S_ISREG(statbuf.st_mode)) {
        ssl_debug_printf("ssl_load_key: file is not a regular file\n");
        errno = EINVAL;
        return NULL;
    }
    /* XXX - check for a too-big size */
    /* load all file contents into a datum buffer*/
    key.data = (unsigned char *)g_malloc((size_t)statbuf.st_size);
    key.size = (int)statbuf.st_size;
    bytes = (guint) fread(key.data, 1, key.size, fp);
    if (bytes < key.size) {
        ssl_debug_printf("ssl_load_key: can't read from file %d bytes, got %d\n",
            key.size, bytes);
        g_free(key.data);
        return NULL;
    }

    /* init private key data*/
    gnutls_x509_privkey_init(&priv_key);

    /* import PEM data*/
    if ((ret = gnutls_x509_privkey_import(priv_key, &key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
        ssl_debug_printf("ssl_load_key: can't import pem data: %s\n", gnutls_strerror(ret));
        g_free(key.data);
        return NULL;
    }

    if (gnutls_x509_privkey_get_pk_algorithm(priv_key) != GNUTLS_PK_RSA) {
        ssl_debug_printf("ssl_load_key: private key public key algorithm isn't RSA\n");
        g_free(key.data);
        return NULL;
    }

    g_free(key.data);

    return priv_key;
}

static const char *
BAGTYPE(gnutls_pkcs12_bag_type_t x) {
    switch (x) {
        case GNUTLS_BAG_EMPTY:               return "Empty";
        case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY: return "PKCS#8 Encrypted key";
        case GNUTLS_BAG_PKCS8_KEY:           return "PKCS#8 Key";
        case GNUTLS_BAG_CERTIFICATE:         return "Certificate";
        case GNUTLS_BAG_CRL:                 return "CRL";
        case GNUTLS_BAG_ENCRYPTED:           return "Encrypted";
        case GNUTLS_BAG_UNKNOWN:             return "Unknown";
        default:                             return "<undefined>";
    }
}

/**
 * Load a RSA private key from a PKCS#12 file.
 * @param fp the file that contains the key data.
 * @param cert_passwd password to decrypt the PKCS#12 file.
 * @param[out] err error message upon failure; NULL upon success.
 * @return a pointer to the loaded key on success; NULL upon failure.
 */
static gnutls_x509_privkey_t
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd, char** err) {

    int                       i, j, ret;
    int                       rest;
    unsigned char            *p;
    gnutls_datum_t            data;
    gnutls_pkcs12_bag_t       bag = NULL;
    gnutls_pkcs12_bag_type_t  bag_type;
    size_t                    len;

    gnutls_pkcs12_t       ssl_p12  = NULL;
    gnutls_x509_privkey_t ssl_pkey = NULL;

    gnutls_x509_privkey_t     priv_key = NULL;
    *err = NULL;

    rest = 4096;
    data.data = (unsigned char *)g_malloc(rest);
    data.size = rest;
    p = data.data;
    while ((len = fread(p, 1, rest, fp)) > 0) {
        p += len;
        rest -= (int) len;
        if (!rest) {
            rest = 1024;
            data.data = (unsigned char *)g_realloc(data.data, data.size + rest);
            p = data.data + data.size;
            data.size += rest;
        }
    }
    data.size -= rest;
    ssl_debug_printf("%d bytes read\n", data.size);
    if (!feof(fp)) {
        *err = g_strdup("Error during certificate reading.");
        ssl_debug_printf("%s\n", *err);
        g_free(data.data);
        return 0;
    }

    ret = gnutls_pkcs12_init(&ssl_p12);
    if (ret < 0) {
        *err = g_strdup_printf("gnutls_pkcs12_init(&st_p12) - %s", gnutls_strerror(ret));
        ssl_debug_printf("%s\n", *err);
        g_free(data.data);
        return 0;
    }

    /* load PKCS#12 in DER or PEM format */
    ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_DER, 0);
    if (ret < 0) {
        *err = g_strdup_printf("could not load PKCS#12 in DER format: %s", gnutls_strerror(ret));
        ssl_debug_printf("%s\n", *err);
        g_free(*err);

        ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_PEM, 0);
        if (ret < 0) {
            *err = g_strdup_printf("could not load PKCS#12 in PEM format: %s", gnutls_strerror(ret));
            ssl_debug_printf("%s\n", *err);
        } else {
            *err = NULL;
        }
    }
    g_free(data.data);
    if (ret < 0) {
        return 0;
    }

    ssl_debug_printf( "PKCS#12 imported\n");

    /* TODO: Use gnutls_pkcs12_simple_parse, since 3.1.0 (August 2012) */
    for (i=0; ; i++) {

        ret = gnutls_pkcs12_bag_init(&bag);
        if (ret < 0) break;

        ret = gnutls_pkcs12_get_bag(ssl_p12, i, bag);
        if (ret < 0) break;

        for (j=0; j<gnutls_pkcs12_bag_get_count(bag); j++) {

            ret = gnutls_pkcs12_bag_get_type(bag, j);
            if (ret < 0) goto done;
            bag_type = (gnutls_pkcs12_bag_type_t)ret;
            if (bag_type >= GNUTLS_BAG_UNKNOWN) goto done;
            ssl_debug_printf( "Bag %d/%d: %s\n", i, j, BAGTYPE(bag_type));
            if (bag_type == GNUTLS_BAG_ENCRYPTED) {
                ret = gnutls_pkcs12_bag_decrypt(bag, cert_passwd);
                if (ret == 0) {
                    ret = gnutls_pkcs12_bag_get_type(bag, j);
                    if (ret < 0) goto done;
                    bag_type = (gnutls_pkcs12_bag_type_t)ret;
                    if (bag_type >= GNUTLS_BAG_UNKNOWN) goto done;
                    ssl_debug_printf( "Bag %d/%d decrypted: %s\n", i, j, BAGTYPE(bag_type));
                }
            }

            ret = gnutls_pkcs12_bag_get_data(bag, j, &data);
            if (ret < 0) goto done;

            switch (bag_type) {

                case GNUTLS_BAG_PKCS8_KEY:
                case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:

                    ret = gnutls_x509_privkey_init(&ssl_pkey);
                    if (ret < 0) {
                        *err = g_strdup_printf("gnutls_x509_privkey_init(&ssl_pkey) - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        goto done;
                    }
                    ret = gnutls_x509_privkey_import_pkcs8(ssl_pkey, &data, GNUTLS_X509_FMT_DER, cert_passwd,
                                                           (bag_type==GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
                    if (ret < 0) {
                        *err = g_strdup_printf("Can not decrypt private key - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        goto done;
                    }

                    if (gnutls_x509_privkey_get_pk_algorithm(ssl_pkey) != GNUTLS_PK_RSA) {
                        *err = g_strdup("ssl_load_pkcs12: private key public key algorithm isn't RSA");
                        ssl_debug_printf("%s\n", *err);
                        goto done;
                    }

                    /* Private key found, return it. */
                    priv_key = ssl_pkey;
                    goto done;

                default: ;
            }
        }  /* j */
        if (bag) { gnutls_pkcs12_bag_deinit(bag); bag = NULL; }
    }  /* i */

done:
    if (!priv_key && ssl_pkey)
        gnutls_x509_privkey_deinit(ssl_pkey);
    if (bag)
        gnutls_pkcs12_bag_deinit(bag);

    return priv_key;
}


void
ssl_private_key_free(gpointer key)
{
    gcry_sexp_release((gcry_sexp_t) key);
}

static void
ssl_find_private_key_by_pubkey(SslDecryptSession *ssl, GHashTable *key_hash,
                               gnutls_datum_t *subjectPublicKeyInfo)
{
    gnutls_pubkey_t pubkey = NULL;
    guchar key_id[20];
    size_t key_id_len = sizeof(key_id);
    int r;

    if (!subjectPublicKeyInfo->size) {
        ssl_debug_printf("%s: could not find SubjectPublicKeyInfo\n", G_STRFUNC);
        return;
    }

    r = gnutls_pubkey_init(&pubkey);
    if (r < 0) {
        ssl_debug_printf("%s: failed to init pubkey: %s\n",
                G_STRFUNC, gnutls_strerror(r));
        return;
    }

    r = gnutls_pubkey_import(pubkey, subjectPublicKeyInfo, GNUTLS_X509_FMT_DER);
    if (r < 0) {
        ssl_debug_printf("%s: failed to import pubkey from handshake: %s\n",
                G_STRFUNC, gnutls_strerror(r));
        goto end;
    }

    /* Generate a 20-byte SHA-1 hash. */
    r = gnutls_pubkey_get_key_id(pubkey, 0, key_id, &key_id_len);
    if (r < 0) {
        ssl_debug_printf("%s: failed to extract key id from pubkey: %s\n",
                G_STRFUNC, gnutls_strerror(r));
        goto end;
    }

    ssl_print_data("lookup(KeyID)", key_id, key_id_len);
    ssl->private_key = (gcry_sexp_t)g_hash_table_lookup(key_hash, key_id);
    ssl_debug_printf("%s: lookup result: %p\n", G_STRFUNC, (void *) ssl->private_key);

end:
    gnutls_pubkey_deinit(pubkey);
}

/* RSA private key file processing }}} */

#else /* ! (defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)) */
void
ssl_private_key_free(gpointer key _U_)
{
}
#endif /* ! (defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)) */


/*--- Start of dissector-related code below ---*/

/* get ssl data for this session. if no ssl data is found allocate a new one*/
SslDecryptSession *
ssl_get_session(conversation_t *conversation, dissector_handle_t ssl_handle)
{
    void               *conv_data;
    SslDecryptSession  *ssl_session;
    int                 proto_ssl;

    proto_ssl = dissector_handle_get_protocol_index(ssl_handle);
    conv_data = conversation_get_proto_data(conversation, proto_ssl);
    if (conv_data != NULL)
        return (SslDecryptSession *)conv_data;

    /* no previous SSL conversation info, initialize it. */
    ssl_session = wmem_new0(wmem_file_scope(), SslDecryptSession);

    /* data_len is the part that is meaningful, not the allocated length */
    ssl_session->master_secret.data_len = 0;
    ssl_session->master_secret.data = ssl_session->_master_secret;
    ssl_session->session_id.data_len = 0;
    ssl_session->session_id.data = ssl_session->_session_id;
    ssl_session->client_random.data_len = 0;
    ssl_session->client_random.data = ssl_session->_client_random;
    ssl_session->server_random.data_len = 0;
    ssl_session->server_random.data = ssl_session->_server_random;
    ssl_session->session_ticket.data_len = 0;
    ssl_session->session_ticket.data = NULL; /* will be re-alloced as needed */
    ssl_session->server_data_for_iv.data_len = 0;
    ssl_session->server_data_for_iv.data = ssl_session->_server_data_for_iv;
    ssl_session->client_data_for_iv.data_len = 0;
    ssl_session->client_data_for_iv.data = ssl_session->_client_data_for_iv;
    ssl_session->app_data_segment.data = NULL;
    ssl_session->app_data_segment.data_len = 0;
    ssl_session->handshake_data.data=NULL;
    ssl_session->handshake_data.data_len=0;

    /* Initialize parameters which are not necessary specific to decryption. */
    ssl_session->session.version = SSL_VER_UNKNOWN;
    clear_address(&ssl_session->session.srv_addr);
    ssl_session->session.srv_ptype = PT_NONE;
    ssl_session->session.srv_port = 0;

    conversation_add_proto_data(conversation, proto_ssl, ssl_session);
    return ssl_session;
}

/* Resets the decryption parameters for the next decoder. */
static void ssl_reset_session(SslSession *session, SslDecryptSession *ssl, gboolean is_client)
{
    if (ssl) {
        /* Ensure that secrets are not restored using stale identifiers. Split
         * between client and server in case the packets somehow got out of order. */
        gint clear_flags = SSL_HAVE_SESSION_KEY | SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;

        if (is_client) {
            clear_flags |= SSL_CLIENT_EXTENDED_MASTER_SECRET;
            ssl->session_id.data_len = 0;
            ssl->session_ticket.data_len = 0;
            ssl->master_secret.data_len = 0;
            ssl->client_random.data_len = 0;
        } else {
            clear_flags |= SSL_SERVER_EXTENDED_MASTER_SECRET | SSL_NEW_SESSION_TICKET;
            ssl->server_random.data_len = 0;
            ssl->pre_master_secret.data_len = 0;
#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
            ssl->private_key = NULL;
#endif
            ssl->psk.data_len = 0;
        }

        if (ssl->state & clear_flags) {
            ssl_debug_printf("%s detected renegotiation, clearing 0x%02x (%s side)\n",
                    G_STRFUNC, ssl->state & clear_flags, is_client ? "client" : "server");
            ssl->state &= ~clear_flags;
        }
    }

    /* These flags might be used for non-decryption purposes and may affect the
     * dissection, so reset them as well. */
    if (is_client) {
        session->client_cert_type = 0;
    } else {
        session->compression = 0;
        session->server_cert_type = 0;
        /* session->is_session_resumed is already handled in the ServerHello dissection. */
    }
}

static guint32
ssl_starttls(dissector_handle_t ssl_handle, packet_info *pinfo,
                 dissector_handle_t app_handle, guint32 last_nontls_frame)
{
    conversation_t  *conversation;
    SslSession      *session;

    /* Ignore if the SSL dissector is disabled. */
    if (!ssl_handle)
        return 0;
    /* The caller should always pass a valid handle to its own dissector. */
    DISSECTOR_ASSERT(app_handle);

    conversation = find_or_create_conversation(pinfo);
    session = &ssl_get_session(conversation, ssl_handle)->session;

    ssl_debug_printf("%s: old frame %d, app_handle=%p (%s)\n", G_STRFUNC,
                     session->last_nontls_frame,
                     (void *)session->app_handle,
                     dissector_handle_get_dissector_name(session->app_handle));
    ssl_debug_printf("%s: current frame %d, app_handle=%p (%s)\n", G_STRFUNC,
                     pinfo->num, (void *)app_handle,
                     dissector_handle_get_dissector_name(app_handle));

    /* Do not switch again if a dissector did it before. */
    if (session->last_nontls_frame) {
        ssl_debug_printf("%s: not overriding previous app handle!\n", G_STRFUNC);
        return session->last_nontls_frame;
    }

    session->app_handle = app_handle;
    /* The SSL dissector should be called first for this conversation. */
    conversation_set_dissector(conversation, ssl_handle);
    /* SSL starts after this frame. */
    session->last_nontls_frame = last_nontls_frame;
    return 0;
} /* }}} */

/* ssl_starttls_ack: mark future frames as encrypted. {{{ */
guint32
ssl_starttls_ack(dissector_handle_t ssl_handle, packet_info *pinfo,
                 dissector_handle_t app_handle)
{
    return ssl_starttls(ssl_handle, pinfo, app_handle, pinfo->num);
}

guint32
ssl_starttls_post_ack(dissector_handle_t ssl_handle, packet_info *pinfo,
                 dissector_handle_t app_handle)
{
    return ssl_starttls(ssl_handle, pinfo, app_handle, pinfo->num - 1);
}

dissector_handle_t
ssl_find_appdata_dissector(const char *name)
{
    /* Accept 'http' for backwards compatibility and sanity. */
    if (!strcmp(name, "http"))
        name = "http-over-tls";
    return find_dissector(name);
}

/* Functions for TLS/DTLS sessions and RSA private keys hashtables. {{{ */
static gint
ssl_equal (gconstpointer v, gconstpointer v2)
{
    const StringInfo *val1;
    const StringInfo *val2;
    val1 = (const StringInfo *)v;
    val2 = (const StringInfo *)v2;

    if (val1->data_len == val2->data_len &&
        !memcmp(val1->data, val2->data, val2->data_len)) {
        return 1;
    }
    return 0;
}

static guint
ssl_hash  (gconstpointer v)
{
    guint l,hash;
    const StringInfo* id;
    const guint* cur;
    hash = 0;
    id = (const StringInfo*) v;

    /*  id and id->data are mallocated in ssl_save_master_key().  As such 'data'
     *  should be aligned for any kind of access (for example as a guint as
     *  is done below).  The intermediate void* cast is to prevent "cast
     *  increases required alignment of target type" warnings on CPUs (such
     *  as SPARCs) that do not allow misaligned memory accesses.
     */
    cur = (const guint*)(void*) id->data;

    for (l=4; (l < id->data_len); l+=4, cur++)
        hash = hash ^ (*cur);

    return hash;
}

gboolean
ssl_private_key_equal (gconstpointer v, gconstpointer v2)
{
    /* key ID length (SHA-1 hash, per GNUTLS_KEYID_USE_SHA1) */
    return !memcmp(v, v2, 20);
}

guint
ssl_private_key_hash (gconstpointer v)
{
    guint        l, hash = 0;
    const guint8 *cur = (const guint8 *)v;

    /* The public key' SHA-1 hash (which maps to a private key) has a uniform
     * distribution, hence simply xor'ing them should be sufficient. */
    for (l = 0; l < 20; l += 4, cur += 4)
        hash ^= pntoh32(cur);

    return hash;
}
/* Functions for TLS/DTLS sessions and RSA private keys hashtables. }}} */

/* Handling of association between tls/dtls ports and clear text protocol. {{{ */
void
ssl_association_add(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, guint port, gboolean tcp)
{
    DISSECTOR_ASSERT(main_handle);
    DISSECTOR_ASSERT(subdissector_handle);
    /* Registration is required for Export PDU feature to work properly. */
    DISSECTOR_ASSERT_HINT(dissector_handle_get_dissector_name(subdissector_handle),
            "SSL appdata dissectors must register with register_dissector()!");
    ssl_debug_printf("association_add %s port %d handle %p\n", dissector_table_name, port, (void *)subdissector_handle);

    if (port) {
        dissector_add_uint(dissector_table_name, port, subdissector_handle);
        if (tcp)
            dissector_add_uint("tcp.port", port, main_handle);
        else
            dissector_add_uint("udp.port", port, main_handle);
        dissector_add_uint("sctp.port", port, main_handle);
    } else {
        dissector_add_for_decode_as(dissector_table_name, subdissector_handle);
    }
}

void
ssl_association_remove(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, guint port, gboolean tcp)
{
    ssl_debug_printf("ssl_association_remove removing %s %u - handle %p\n",
                     tcp?"TCP":"UDP", port, (void *)subdissector_handle);
    if (main_handle) {
        dissector_delete_uint(tcp?"tcp.port":"udp.port", port, main_handle);
        dissector_delete_uint("sctp.port", port, main_handle);
    }

    if (port) {
        dissector_delete_uint(dissector_table_name, port, subdissector_handle);
    }
}

void
ssl_set_server(SslSession *session, address *addr, port_type ptype, guint32 port)
{
    copy_address_wmem(wmem_file_scope(), &session->srv_addr, addr);
    session->srv_ptype = ptype;
    session->srv_port = port;
}

int
ssl_packet_from_server(SslSession *session, dissector_table_t table, packet_info *pinfo)
{
    gint ret;
    if (session->srv_addr.type != AT_NONE) {
        ret = (session->srv_ptype == pinfo->ptype) &&
              (session->srv_port == pinfo->srcport) &&
              addresses_equal(&session->srv_addr, &pinfo->src);
    } else {
        ret = (dissector_get_uint_handle(table, pinfo->srcport) != 0);
    }

    ssl_debug_printf("packet_from_server: is from server - %s\n", (ret)?"TRUE":"FALSE");
    return ret;
}
/* Handling of association between tls/dtls ports and clear text protocol. }}} */


/* Links SSL records with the real packet data. {{{ */
/**
 * Remembers the decrypted TLS record fragment (TLSInnerPlaintext in TLS 1.3) to
 * avoid the need for a decoder in the second pass. Additionally, it remembers
 * sequence numbers (for reassembly and Follow SSL Stream).
 *
 * @param proto The protocol identifier (proto_ssl or proto_dtls).
 * @param pinfo The packet where the record originates from.
 * @param data Decrypted data to store in the record.
 * @param data_len Length of decrypted record data.
 * @param record_id The identifier for this record within the current packet.
 * @param flow Information about sequence numbers, etc.
 * @param type TLS Content Type (such as handshake or application_data).
 */
void
ssl_add_record_info(gint proto, packet_info *pinfo, const guchar *data, gint data_len, gint record_id, SslFlow *flow, ContentType type)
{
    SslRecordInfo* rec, **prec;
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, 0);
    if (!pi)
    {
        pi = wmem_new0(wmem_file_scope(), SslPacketInfo);
        p_add_proto_data(wmem_file_scope(), pinfo, proto, 0, pi);
    }

    rec = wmem_new(wmem_file_scope(), SslRecordInfo);
    rec->plain_data = (guchar *)wmem_memdup(wmem_file_scope(), data, data_len);
    rec->data_len = data_len;
    rec->id = record_id;
    rec->type = type;
    rec->next = NULL;

    /* TODO allow Handshake records also to be reassembled. There needs to be
     * one "flow" for each record type (appdata, handshake). "seq" for the
     * record should then be relative within this flow. */
    if (flow && type == SSL_ID_APP_DATA) {
        rec->seq = flow->byte_seq;
        rec->flow = flow;
        flow->byte_seq += data_len;
        ssl_debug_printf("%s stored decrypted record seq=%d nxtseq=%d flow=%p\n",
                         G_STRFUNC, rec->seq, rec->seq + data_len, (void*)flow);
    }

    /* Remember decrypted records. */
    prec = &pi->records;
    while (*prec) prec = &(*prec)->next;
    *prec = rec;
}

/* search in packet data for the specified id; return a newly created tvb for the associated data */
tvbuff_t*
ssl_get_record_info(tvbuff_t *parent_tvb, int proto, packet_info *pinfo, gint record_id, SslRecordInfo **matched_record)
{
    SslRecordInfo* rec;
    SslPacketInfo* pi;
    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, 0);

    if (!pi)
        return NULL;

    for (rec = pi->records; rec; rec = rec->next)
        if (rec->id == record_id) {
            *matched_record = rec;
            /* link new real_data_tvb with a parent tvb so it is freed when frame dissection is complete */
            return tvb_new_child_real_data(parent_tvb, rec->plain_data, rec->data_len, rec->data_len);
        }

    return NULL;
}
/* Links SSL records with the real packet data. }}} */

/* initialize/reset per capture state data (ssl sessions cache). {{{ */
void
ssl_common_init(ssl_master_key_map_t *mk_map,
                StringInfo *decrypted_data, StringInfo *compressed_data)
{
    mk_map->session = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tickets = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->crandom = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->pre_master = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->pms = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_client_handshake = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_server_handshake = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_client_appdata = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_server_appdata = g_hash_table_new(ssl_hash, ssl_equal);
    ssl_data_alloc(decrypted_data, 32);
    ssl_data_alloc(compressed_data, 32);
}

void
ssl_common_cleanup(ssl_master_key_map_t *mk_map, FILE **ssl_keylog_file,
                   StringInfo *decrypted_data, StringInfo *compressed_data)
{
    g_hash_table_destroy(mk_map->session);
    g_hash_table_destroy(mk_map->tickets);
    g_hash_table_destroy(mk_map->crandom);
    g_hash_table_destroy(mk_map->pre_master);
    g_hash_table_destroy(mk_map->pms);
    g_hash_table_destroy(mk_map->tls13_client_handshake);
    g_hash_table_destroy(mk_map->tls13_server_handshake);
    g_hash_table_destroy(mk_map->tls13_client_appdata);
    g_hash_table_destroy(mk_map->tls13_server_appdata);

    g_free(decrypted_data->data);
    g_free(compressed_data->data);

    /* close the previous keylog file now that the cache are cleared, this
     * allows the cache to be filled with the full keylog file contents. */
    if (*ssl_keylog_file) {
        fclose(*ssl_keylog_file);
        *ssl_keylog_file = NULL;
    }
}
/* }}} */

/* parse ssl related preferences (private keys and ports association strings) */
#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
/* Load a single RSA key file item from preferences. {{{ */
void
ssl_parse_key_list(const ssldecrypt_assoc_t *uats, GHashTable *key_hash, const char* dissector_table_name, dissector_handle_t main_handle, gboolean tcp)
{
    gnutls_x509_privkey_t priv_key;
    gcry_sexp_t        private_key;
    FILE*              fp     = NULL;
    int                ret;
    size_t             key_id_len = 20;
    guchar            *key_id = NULL;
    dissector_handle_t handle;
    /* try to load keys file first */
    fp = ws_fopen(uats->keyfile, "rb");
    if (!fp) {
        report_open_failure(uats->keyfile, errno, FALSE);
        return;
    }

    if ((gint)strlen(uats->password) == 0) {
        priv_key = ssl_load_key(fp);
    } else {
        char *err = NULL;
        priv_key = ssl_load_pkcs12(fp, uats->password, &err);
        if (err) {
            report_failure("%s\n", err);
            g_free(err);
        }
    }
    fclose(fp);

    if (!priv_key) {
        report_failure("Can't load private key from %s\n", uats->keyfile);
        return;
    }

    key_id = (guchar *) g_malloc0(key_id_len);
    ret = gnutls_x509_privkey_get_key_id(priv_key, 0, key_id, &key_id_len);
    if (ret < 0) {
        report_failure("Can't calculate public key ID for %s: %s",
                uats->keyfile, gnutls_strerror(ret));
        goto end;
    }
    ssl_print_data("KeyID", key_id, key_id_len);

    private_key = ssl_privkey_to_sexp(priv_key);
    if (!private_key) {
        report_failure("Can't extract private key parameters for %s", uats->keyfile);
        goto end;
    }

    g_hash_table_replace(key_hash, key_id, private_key);
    key_id = NULL; /* used in key_hash, do not free. */
    ssl_debug_printf("ssl_init private key file %s successfully loaded.\n", uats->keyfile);

    handle = ssl_find_appdata_dissector(uats->protocol);
    if (handle) {
        /* Port to subprotocol mapping */
        guint16 port = 0;
        if (ws_strtou16(uats->port, NULL, &port)) {
            if (port > 0) {
                ssl_debug_printf("ssl_init port '%d' filename '%s' password(only for p12 file) '%s'\n",
                    port, uats->keyfile, uats->password);

                ssl_association_add(dissector_table_name, main_handle, handle, port, tcp);
            }
        } else {
            if (strcmp(uats->port, "start_tls"))
                ssl_debug_printf("invalid ssl_init_port: %s\n", uats->port);
        }
    }

end:
    gnutls_x509_privkey_deinit(priv_key);
    g_free(key_id);
}
/* }}} */
#else
void
ssl_parse_key_list(const ssldecrypt_assoc_t *uats _U_, GHashTable *key_hash _U_, const char* dissector_table_name _U_, dissector_handle_t main_handle _U_, gboolean tcp _U_)
{
    report_failure("Can't load private key files, support is not compiled in.");
}
#endif


#ifdef HAVE_LIBGCRYPT /* useless without decryption support. */
/* Store/load a known (pre-)master secret from/for this SSL session. {{{ */
/** store a known (pre-)master secret into cache */
static void
ssl_save_master_key(const char *label, GHashTable *ht, StringInfo *key,
                    StringInfo *mk)
{
    StringInfo *ht_key, *master_secret;

    if (key->data_len == 0) {
        ssl_debug_printf("%s: not saving empty %s!\n", G_STRFUNC, label);
        return;
    }

    if (mk->data_len == 0) {
        ssl_debug_printf("%s not saving empty (pre-)master secret for %s!\n",
                         G_STRFUNC, label);
        return;
    }

    /* ssl_hash() depends on session_ticket->data being aligned for guint access
     * so be careful in changing how it is allocated. */
    ht_key = ssl_data_clone(key);
    master_secret = ssl_data_clone(mk);
    g_hash_table_insert(ht, ht_key, master_secret);

    ssl_debug_printf("%s inserted (pre-)master secret for %s\n", G_STRFUNC, label);
    ssl_print_string("stored key", ht_key);
    ssl_print_string("stored (pre-)master secret", master_secret);
}

/** restore a (pre-)master secret given some key in the cache */
static gboolean
ssl_restore_master_key(SslDecryptSession *ssl, const char *label,
                       gboolean is_pre_master, GHashTable *ht, StringInfo *key)
{
    StringInfo *ms;

    if (key->data_len == 0) {
        ssl_debug_printf("%s can't restore %smaster secret using an empty %s\n",
                         G_STRFUNC, is_pre_master ? "pre-" : "", label);
        return FALSE;
    }

    ms = (StringInfo *)g_hash_table_lookup(ht, key);
    if (!ms) {
        ssl_debug_printf("%s can't find %smaster secret by %s\n", G_STRFUNC,
                         is_pre_master ? "pre-" : "", label);
        return FALSE;
    }

    /* (pre)master secret found, clear knowledge of other keys and set it in the
     * current conversation */
    ssl->state &= ~(SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET |
                    SSL_HAVE_SESSION_KEY);
    if (is_pre_master) {
        /* unlike master secret, pre-master secret has a variable size (48 for
         * RSA, varying for PSK) and is therefore not statically allocated */
        ssl->pre_master_secret.data = (guchar *) wmem_alloc(wmem_file_scope(),
                                                            ms->data_len);
        ssl_data_set(&ssl->pre_master_secret, ms->data, ms->data_len);
        ssl->state |= SSL_PRE_MASTER_SECRET;
    } else {
        ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
        ssl->state |= SSL_MASTER_SECRET;
    }
    ssl_debug_printf("%s %smaster secret retrieved using %s\n", G_STRFUNC,
                     is_pre_master ? "pre-" : "", label);
    ssl_print_string(label, key);
    ssl_print_string("(pre-)master secret", ms);
    return TRUE;
}
/* Store/load a known (pre-)master secret from/for this SSL session. }}} */

/* Should be called when all parameters are ready (after ChangeCipherSpec), and
 * the decoder should be attempted to be initialized. {{{*/
void
ssl_finalize_decryption(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map)
{
    if (ssl->session.version == TLSV1DOT3_VERSION) {
        /* TLS 1.3 implementations only provide secrets derived from the master
         * secret which are loaded in tls13_change_key. No master secrets can be
         * loaded here, so just return. */
        return;
    }
    ssl_debug_printf("%s state = 0x%02X\n", G_STRFUNC, ssl->state);
    if (ssl->state & SSL_HAVE_SESSION_KEY) {
        ssl_debug_printf("  session key already available, nothing to do.\n");
        return;
    }
    if (!(ssl->state & SSL_CIPHER)) {
        ssl_debug_printf("  Cipher suite (Server Hello) is missing!\n");
        return;
    }

    /* for decryption, there needs to be a master secret (which can be derived
     * from pre-master secret). If missing, try to pick a master key from cache
     * (an earlier packet in the capture or key logfile). */
    if (!(ssl->state & (SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET)) &&
        !ssl_restore_master_key(ssl, "Session ID", FALSE,
                                mk_map->session, &ssl->session_id) &&
        (!ssl->session.is_session_resumed ||
         !ssl_restore_master_key(ssl, "Session Ticket", FALSE,
                                 mk_map->tickets, &ssl->session_ticket)) &&
        !ssl_restore_master_key(ssl, "Client Random", FALSE,
                                mk_map->crandom, &ssl->client_random)) {
        if (ssl->cipher_suite->enc != ENC_NULL) {
            /* how unfortunate, the master secret could not be found */
            ssl_debug_printf("  Cannot find master secret\n");
            return;
        } else {
            ssl_debug_printf(" Cannot find master secret, continuing anyway "
                    "because of a NULL cipher\n");
        }
    }

    if (ssl_generate_keyring_material(ssl) < 0) {
        ssl_debug_printf("%s can't generate keyring material\n", G_STRFUNC);
        return;
    }
    /* Save Client Random/ Session ID for "SSL Export Session keys" */
    ssl_save_master_key("Client Random", mk_map->crandom,
                        &ssl->client_random, &ssl->master_secret);
    ssl_save_master_key("Session ID", mk_map->session,
                        &ssl->session_id, &ssl->master_secret);
    /* Only save the new secrets if the server sent the ticket. The client
     * ticket might have become stale. */
    if (ssl->state & SSL_NEW_SESSION_TICKET) {
        ssl_save_master_key("Session Ticket", mk_map->tickets,
                            &ssl->session_ticket, &ssl->master_secret);
    }
} /* }}} */

/* Load the new key. */
void
tls13_change_key(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                 gboolean is_from_server, TLSRecordType type)
{
    GHashTable *key_map;
    const char *label;

    if (ssl->session.version != TLSV1DOT3_VERSION) {
        ssl_debug_printf("%s TLS version %#x is not 1.3\n", G_STRFUNC, ssl->session.version);
        return;
    }

    if (ssl->client_random.data_len == 0) {
        /* May happen if Hello message is missing and Finished is found. */
        ssl_debug_printf("%s missing Client Random\n", G_STRFUNC);
        return;
    }

    switch (type) {
    case TLS_SECRET_0RTT_APP:
        /* TODO 0-RTT decryption is not implemented yet */
        return;
    case TLS_SECRET_HANDSHAKE:
        if (is_from_server) {
            label = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
            key_map = mk_map->tls13_server_handshake;
        } else {
            label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
            key_map = mk_map->tls13_client_handshake;
        }
        break;
    case TLS_SECRET_APP:
        if (is_from_server) {
            label = "SERVER_TRAFFIC_SECRET_0";
            key_map = mk_map->tls13_server_appdata;
        } else {
            label = "CLIENT_TRAFFIC_SECRET_0";
            key_map = mk_map->tls13_client_appdata;
        }
        break;
    default:
        g_assert_not_reached();
    }

    /* Transitioning to new keys, mark old ones as unusable. */
    ssl_debug_printf("%s transitioning to new key, old state 0x%02x\n", G_STRFUNC, ssl->state);
    ssl->state &= ~(SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET | SSL_HAVE_SESSION_KEY);

    StringInfo *secret = (StringInfo *)g_hash_table_lookup(key_map, &ssl->client_random);
    if (!secret) {
        ssl_debug_printf("%s Cannot find %s, decryption impossible\n", G_STRFUNC, label);
        /* Disable decryption, the keys are invalid. */
        if (is_from_server) {
            ssl->server = NULL;
        } else {
            ssl->client = NULL;
        }
        return;
    }

    /* TLS 1.3 secret found, set new keys. */
    ssl->traffic_secret.data = (guchar *) wmem_realloc(wmem_file_scope(),
            ssl->traffic_secret.data, secret->data_len);
    ssl_data_set(&ssl->traffic_secret, secret->data, secret->data_len);
    ssl_debug_printf("%s Retrieved TLS 1.3 traffic secret.\n", G_STRFUNC);
    ssl_print_string("Client Random", &ssl->client_random);
    ssl_print_string(label, secret);
    tls13_generate_keys(ssl, secret, is_from_server);
}
#endif /* HAVE_LIBGCRYPT */

/** SSL keylog file handling. {{{ */

static GRegex *
ssl_compile_keyfile_regex(void)
{
#define OCTET "(?:[[:xdigit:]]{2})"
    const gchar *pattern =
        "(?:"
        /* Matches Client Hellos having this Client Random */
        "PMS_CLIENT_RANDOM (?<client_random_pms>" OCTET "{32}) "
        /* Matches first part of encrypted RSA pre-master secret */
        "|RSA (?<encrypted_pmk>" OCTET "{8}) "
        /* Pre-Master-Secret is given, it is 48 bytes for RSA,
           but it can be of any length for DHE */
        ")(?<pms>" OCTET "+)"
        "|(?:"
        /* Matches Server Hellos having a Session ID */
        "RSA Session-ID:(?<session_id>" OCTET "+) Master-Key:"
        /* Matches Client Hellos having this Client Random */
        "|CLIENT_RANDOM (?<client_random>" OCTET "{32}) "
        /* Master-Secret is given, its length is fixed */
        ")(?<master_secret>" OCTET "{" G_STRINGIFY(SSL_MASTER_SECRET_LENGTH) "})"
        "|(?"
        /* TLS 1.3 Client Random to Derived Secrets mapping. */
        ":CLIENT_HANDSHAKE_TRAFFIC_SECRET (?<client_handshake>" OCTET "{32})"
        "|SERVER_HANDSHAKE_TRAFFIC_SECRET (?<server_handshake>" OCTET "{32})"
        "|CLIENT_TRAFFIC_SECRET_0 (?<client_appdata>" OCTET "{32})"
        "|SERVER_TRAFFIC_SECRET_0 (?<server_appdata>" OCTET "{32})"
        ") (?<derived_secret>" OCTET "+)";
#undef OCTET
    static GRegex *regex = NULL;
    GError *gerr = NULL;

    if (!regex) {
        regex = g_regex_new(pattern,
                (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_ANCHORED),
                G_REGEX_MATCH_ANCHORED, &gerr);
        if (gerr) {
            ssl_debug_printf("%s failed to compile regex: %s\n", G_STRFUNC,
                             gerr->message);
            g_error_free(gerr);
            regex = NULL;
        }
    }

    return regex;
}

static gboolean
file_needs_reopen(FILE *fp, const char *filename)
{
    ws_statb64 open_stat, current_stat;

    /* consider a file deleted when stat fails for either file,
     * or when the residing device / inode has changed. */
    if (0 != ws_fstat64(ws_fileno(fp), &open_stat))
        return TRUE;
    if (0 != ws_stat64(filename, &current_stat))
        return TRUE;

    /* Note: on Windows, ino may be 0. Existing files cannot be deleted on
     * Windows, but hopefully the size is a good indicator when a file got
     * removed and recreated */
    return  open_stat.st_dev != current_stat.st_dev ||
            open_stat.st_ino != current_stat.st_ino ||
            open_stat.st_size > current_stat.st_size;
}

typedef struct ssl_master_key_match_group {
    const char *re_group_name;
    GHashTable *master_key_ht;
} ssl_master_key_match_group_t;

void
ssl_load_keyfile(const gchar *ssl_keylog_filename, FILE **keylog_file,
                 const ssl_master_key_map_t *mk_map)
{
    unsigned i;
    GRegex *regex;
    ssl_master_key_match_group_t mk_groups[] = {
        { "encrypted_pmk",  mk_map->pre_master },
        { "session_id",     mk_map->session },
        { "client_random",  mk_map->crandom },
        { "client_random_pms",  mk_map->pms },
        /* TLS 1.3 map from Client Random to derived secret. */
        { "client_handshake",   mk_map->tls13_client_handshake },
        { "server_handshake",   mk_map->tls13_server_handshake },
        { "client_appdata",     mk_map->tls13_client_appdata },
        { "server_appdata",     mk_map->tls13_server_appdata },
    };
    /* no need to try if no key log file is configured. */
    if (!ssl_keylog_filename || !*ssl_keylog_filename) {
        ssl_debug_printf("%s dtls/ssl.keylog_file is not configured!\n",
                         G_STRFUNC);
        return;
    }

    /* The format of the file is a series of records with one of the following formats:
     *   - "RSA xxxx yyyy"
     *     Where xxxx are the first 8 bytes of the encrypted pre-master secret (hex-encoded)
     *     Where yyyy is the cleartext pre-master secret (hex-encoded)
     *     (this is the original format introduced with bug 4349)
     *
     *   - "RSA Session-ID:xxxx Master-Key:yyyy"
     *     Where xxxx is the SSL session ID (hex-encoded)
     *     Where yyyy is the cleartext master secret (hex-encoded)
     *     (added to support openssl s_client Master-Key output)
     *     This is somewhat is a misnomer because there's nothing RSA specific
     *     about this.
     *
     *   - "PMS_CLIENT_RANDOM xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyyy is the cleartext pre-master secret (hex-encoded)
     *     (This format allows SSL connections to be decrypted, if a user can
     *     capture the PMS but could not recover the MS for a specific session
     *     with a SSL Server.)
     *
     *   - "CLIENT_RANDOM xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyyy is the cleartext master secret (hex-encoded)
     *     (This format allows non-RSA SSL connections to be decrypted, i.e.
     *     ECDHE-RSA.)
     *
     *   - "CLIENT_HANDSHAKE_TRAFFIC_SECRET xxxx yyyy"
     *   - "SERVER_HANDSHAKE_TRAFFIC_SECRET xxxx yyyy"
     *   - "CLIENT_TRAFFIC_SECRET_0 xxxx yyyy"
     *   - "SERVER_TRAFFIC_SECRET_0 xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyyy is the secret (hex-encoded) derived from the handshake or
     *     master secrets. (This format is introduced with TLS 1.3 and supported
     *     by BoringSSL, OpenSSL, etc. See bug 12779.)
     */
    regex = ssl_compile_keyfile_regex();
    if (!regex)
        return;

    ssl_debug_printf("trying to use SSL keylog in %s\n", ssl_keylog_filename);

    /* if the keylog file was deleted, re-open it */
    if (*keylog_file && file_needs_reopen(*keylog_file, ssl_keylog_filename)) {
        ssl_debug_printf("%s file got deleted, trying to re-open\n", G_STRFUNC);
        fclose(*keylog_file);
        *keylog_file = NULL;
    }

    if (*keylog_file == NULL) {
        *keylog_file = ws_fopen(ssl_keylog_filename, "r");
        if (!*keylog_file) {
            ssl_debug_printf("%s failed to open SSL keylog\n", G_STRFUNC);
            return;
        }
    }

    for (;;) {
        char buf[512], *line;
        gsize bytes_read;
        GMatchInfo *mi;

        line = fgets(buf, sizeof(buf), *keylog_file);
        if (!line)
            break;

        bytes_read = strlen(line);
        /* fgets includes the \n at the end of the line. */
        if (bytes_read > 0 && line[bytes_read - 1] == '\n') {
            line[bytes_read - 1] = 0;
            bytes_read--;
        }
        if (bytes_read > 0 && line[bytes_read - 1] == '\r') {
            line[bytes_read - 1] = 0;
            bytes_read--;
        }

        ssl_debug_printf("  checking keylog line: %s\n", line);
        if (g_regex_match(regex, line, G_REGEX_MATCH_ANCHORED, &mi)) {
            gchar *hex_key, *hex_pre_ms_or_ms;
            StringInfo *key = wmem_new(wmem_file_scope(), StringInfo);
            StringInfo *pre_ms_or_ms = NULL;
            GHashTable *ht = NULL;

            /* Is the PMS being supplied with the PMS_CLIENT_RANDOM
             * otherwise we will use the Master Secret
             */
            hex_pre_ms_or_ms = g_match_info_fetch_named(mi, "master_secret");
            if (hex_pre_ms_or_ms == NULL || !*hex_pre_ms_or_ms) {
                g_free(hex_pre_ms_or_ms);
                hex_pre_ms_or_ms = g_match_info_fetch_named(mi, "pms");
            }
            if (hex_pre_ms_or_ms == NULL || !*hex_pre_ms_or_ms) {
                g_free(hex_pre_ms_or_ms);
                hex_pre_ms_or_ms = g_match_info_fetch_named(mi, "derived_secret");
            }
            /* There is always a match, otherwise the regex is wrong. */
            DISSECTOR_ASSERT(hex_pre_ms_or_ms && strlen(hex_pre_ms_or_ms));

            /* convert from hex to bytes and save to hashtable */
            pre_ms_or_ms = wmem_new(wmem_file_scope(), StringInfo);
            from_hex(pre_ms_or_ms, hex_pre_ms_or_ms, strlen(hex_pre_ms_or_ms));
            g_free(hex_pre_ms_or_ms);

            /* Find a master key from any format (CLIENT_RANDOM, SID, ...) */
            for (i = 0; i < G_N_ELEMENTS(mk_groups); i++) {
                ssl_master_key_match_group_t *g = &mk_groups[i];
                hex_key = g_match_info_fetch_named(mi, g->re_group_name);
                if (hex_key && *hex_key) {
                    ssl_debug_printf("    matched %s\n", g->re_group_name);
                    ht = g->master_key_ht;
                    from_hex(key, hex_key, strlen(hex_key));
                    g_free(hex_key);
                    break;
                }
                g_free(hex_key);
            }
            DISSECTOR_ASSERT(ht); /* Cannot be reached, or regex is wrong. */

            g_hash_table_insert(ht, key, pre_ms_or_ms);

        } else {
            ssl_debug_printf("    unrecognized line\n");
        }
        /* always free match info even if there is no match. */
        g_match_info_free(mi);
    }
}
/** SSL keylog file handling. }}} */

#ifdef SSL_DECRYPT_DEBUG /* {{{ */

static FILE* ssl_debug_file=NULL;

void
ssl_set_debug(const gchar* name)
{
    static gint debug_file_must_be_closed;
    gint        use_stderr;

    use_stderr                = name?(strcmp(name, SSL_DEBUG_USE_STDERR) == 0):0;

    if (debug_file_must_be_closed)
        fclose(ssl_debug_file);

    if (use_stderr)
        ssl_debug_file = stderr;
    else if (!name || (strcmp(name, "") ==0))
        ssl_debug_file = NULL;
    else
        ssl_debug_file = ws_fopen(name, "w");

    if (!use_stderr && ssl_debug_file)
        debug_file_must_be_closed = 1;
    else
        debug_file_must_be_closed = 0;

    ssl_debug_printf("Wireshark SSL debug log \n\n");
    ssl_debug_printf("Wireshark version: %s\n", get_ws_vcs_version_info());
#ifdef HAVE_LIBGNUTLS
    ssl_debug_printf("GnuTLS version:    %s\n", gnutls_check_version(NULL));
#endif
#ifdef HAVE_LIBGCRYPT
    ssl_debug_printf("Libgcrypt version: %s\n", gcry_check_version(NULL));
#endif
    ssl_debug_printf("\n");
}

void
ssl_debug_flush(void)
{
    if (ssl_debug_file)
        fflush(ssl_debug_file);
}

void
ssl_debug_printf(const gchar* fmt, ...)
{
    va_list ap;

    if (!ssl_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssl_debug_file, fmt, ap);
    va_end(ap);
}

void
ssl_print_data(const gchar* name, const guchar* data, size_t len)
{
    size_t i, j, k;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i<len; i+=16) {
        fprintf(ssl_debug_file,"| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssl_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssl_debug_file,"   ");
        fputc('|', ssl_debug_file);
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            guchar c = data[j];
            if (!g_ascii_isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssl_debug_file);
        }
        for (; k<16; ++k)
            fputc(' ', ssl_debug_file);
        fprintf(ssl_debug_file,"|\n");
    }
}

void
ssl_print_string(const gchar* name, const StringInfo* data)
{
    ssl_print_data(name, data->data, data->data_len);
}
#endif /* SSL_DECRYPT_DEBUG }}} */

/* UAT preferences callbacks. {{{ */
/* checks for SSL and DTLS UAT key list fields */

gboolean
ssldecrypt_uat_fld_ip_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = g_strdup("No IP address given.");
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_port_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = g_strdup("No Port given.");
        return FALSE;
    }

    if (strcmp(p, "start_tls") != 0){
        guint16 port;
        if (!ws_strtou16(p, NULL, &port)) {
            *err = g_strdup("Invalid port given.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_fileopen_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    ws_statb64 st;

    if (!p || strlen(p) == 0u) {
        *err = g_strdup("No filename given.");
        return FALSE;
    } else {
        if (ws_stat64(p, &st) != 0) {
            *err = g_strdup_printf("File '%s' does not exist or access is denied.", p);
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_password_chk_cb(void *r _U_, const char *p _U_, guint len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
    ssldecrypt_assoc_t*  f  = (ssldecrypt_assoc_t *)r;
    FILE                *fp = NULL;

    if (p && (strlen(p) > 0u)) {
        fp = ws_fopen(f->keyfile, "rb");
        if (fp) {
            char *msg = NULL;
            gnutls_x509_privkey_t priv_key = ssl_load_pkcs12(fp, p, &msg);
            if (!priv_key) {
                fclose(fp);
                *err = g_strdup_printf("Could not load PKCS#12 key file: %s", msg);
                g_free(msg);
                return FALSE;
            }
            g_free(msg);
            gnutls_x509_privkey_deinit(priv_key);
            fclose(fp);
        } else {
            *err = g_strdup_printf("Leave this field blank if the keyfile is not PKCS#12.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
#else
    *err = g_strdup("Cannot load key files, support is not compiled in.");
    return FALSE;
#endif
}
/* UAT preferences callbacks. }}} */

/** maximum size of ssl_association_info() string */
#define SSL_ASSOC_MAX_LEN 8192

typedef struct ssl_association_info_callback_data
{
    gchar *str;
    const char *table_protocol;
} ssl_association_info_callback_data_t;

/**
 * callback function used by ssl_association_info() to traverse the SSL associations.
 */
static void
ssl_association_info_(const gchar *table _U_, gpointer handle, gpointer user_data)
{
    ssl_association_info_callback_data_t* data = (ssl_association_info_callback_data_t*)user_data;
    const int l = (const int)strlen(data->str);
    g_snprintf(data->str+l, SSL_ASSOC_MAX_LEN-l, "'%s' %s\n", dissector_handle_get_short_name((dissector_handle_t)handle), data->table_protocol);
}

/**
 * @return an information string on the SSL protocol associations. The string has ephemeral lifetime/scope.
 */
gchar*
ssl_association_info(const char* dissector_table_name, const char* table_protocol)
{
    ssl_association_info_callback_data_t data;

    data.str = (gchar *)g_malloc0(SSL_ASSOC_MAX_LEN);
    data.table_protocol = table_protocol;
    dissector_table_foreach_handle(dissector_table_name, ssl_association_info_, &data);
    return data.str;
}


/** Begin of code related to dissection of wire data. */

/* change_cipher_spec(20) dissection */
void
ssl_dissect_change_cipher_spec(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               guint32 offset, SslSession *session,
                               gboolean is_from_server,
                               const SslDecryptSession *ssl)
{
    /*
     * struct {
     *     enum { change_cipher_spec(1), (255) } type;
     * } ChangeCipherSpec;
     */
    proto_item *ti;
    proto_item_set_text(tree,
            "%s Record Layer: %s Protocol: Change Cipher Spec",
            val_to_str_const(session->version, ssl_version_short_names, "SSL"),
            val_to_str_const(SSL_ID_CHG_CIPHER_SPEC, ssl_31_content_type, "unknown"));
    ti = proto_tree_add_item(tree, hf->hf.change_cipher_spec, tvb, offset, 1, ENC_NA);

    /* Use heuristics to detect an abbreviated handshake, assume that missing
     * ServerHelloDone implies reusing previously negotiating keys. Then when
     * a Session ID or ticket is present, it must be a resumed session.
     * Normally this should be done at the Finished message, but that may be
     * encrypted so we do it here, at the last cleartext message. */
    if (is_from_server && ssl) {
        if (session->is_session_resumed) {
            const char *resumed = NULL;
            if (ssl->session_ticket.data_len) {
                resumed = "Session Ticket";
            } else if (ssl->session_id.data_len) {
                resumed = "Session ID";
            }
            if (resumed) {
                ssl_debug_printf("%s Session resumption using %s\n", G_STRFUNC, resumed);
            } else {
                /* Can happen if the capture somehow starts in the middle */
                ssl_debug_printf("%s No Session resumption, missing packets?\n", G_STRFUNC);
            }
        } else {
            ssl_debug_printf("%s Not using Session resumption\n", G_STRFUNC);
        }
    }
    if (is_from_server && session->is_session_resumed)
        expert_add_info(pinfo, ti, &hf->ei.resumed);
}

/** Begin of handshake(22) record dissections */
/* dissect a list of hash algorithms, return the number of bytes dissected
   this is used for the signature algorithms extension and for the
   TLS1.2 certificate request. {{{ */
static gint
ssl_dissect_hash_alg_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          packet_info* pinfo, guint32 offset, guint16 len)
{
    guint32     offset_start;
    proto_tree *subtree, *alg_tree;
    proto_item *ti;

    offset_start = offset;
    if (len==0)
        return 0;

    ti = proto_tree_add_none_format(tree, hf->hf.hs_sig_hash_algs, tvb,
                                    offset, len,
                                    "Signature Hash Algorithms (%u algorithm%s)",
                                    len / 2, plurality(len / 2, "", "s"));
    subtree = proto_item_add_subtree(ti, hf->ett.hs_sig_hash_algs);

    if (len % 2) {
        expert_add_info_format(pinfo, ti, &hf->ei.hs_sig_hash_algs_bad,
                            "Invalid Signature Hash Algorithm length: %d", len);
        return offset-offset_start;
    }

    while (len > 0) {
        ti = proto_tree_add_item(subtree, hf->hf.hs_sig_hash_alg,
                                 tvb, offset, 2, ENC_BIG_ENDIAN);
        alg_tree = proto_item_add_subtree(ti, hf->ett.hs_sig_hash_alg);

        proto_tree_add_item(alg_tree, hf->hf.hs_sig_hash_hash,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(alg_tree, hf->hf.hs_sig_hash_sig,
                            tvb, offset+1, 1, ENC_BIG_ENDIAN);

        offset += 2;
        len -= 2;
    }
    return offset-offset_start;
} /* }}} */

/** TLS Extensions (in Client Hello and Server Hello). {{{ */
static gint
ssl_dissect_hnd_hello_ext_sig_hash_algs(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                        proto_tree *tree, packet_info* pinfo, guint32 offset, guint32 ext_len)
{
    guint16  sh_alg_length;
    gint     ret;

    sh_alg_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf->hf.hs_sig_hash_alg_len,
                        tvb, offset, 2, sh_alg_length);
    offset += 2;
    if (ext_len < 2 || sh_alg_length != ext_len - 2) {
        /* ERROR: sh_alg_length must be 2 less than ext_len */
        return offset;
    }

    ret = ssl_dissect_hash_alg_list(hf, tvb, tree, pinfo, offset, sh_alg_length);
    if (ret >= 0)
        offset += ret;

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_alpn(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 ext_len,
                               guint8 hnd_type, SslSession *session)
{
    guint16 alpn_length;
    guint8 name_length;
    proto_tree *alpn_tree;
    proto_item *ti;

    alpn_length = tvb_get_ntohs(tvb, offset);
    if (ext_len < 2 || alpn_length != ext_len - 2) {
        /* ERROR: alpn_length must be 2 less than ext_len */
        return offset;
    }
    proto_tree_add_item(tree, hf->hf.hs_ext_alpn_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ti = proto_tree_add_item(tree, hf->hf.hs_ext_alpn_list,
                             tvb, offset, alpn_length, ENC_NA);
    alpn_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_alpn);

    /* If ALPN is given in ServerHello, then ProtocolNameList MUST contain
     * exactly one "ProtocolName". */
    if (hnd_type == SSL_HND_SERVER_HELLO) {
        guint8 *proto_name;
        size_t i;

        name_length = tvb_get_guint8(tvb, offset);
        /* '\0'-terminated string for prefix/full string comparison purposes. */
        proto_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1,
                                        name_length, ENC_ASCII);
        for (i = 0; i < G_N_ELEMENTS(ssl_alpn_protocols); i++) {
            const ssl_alpn_protocol_t *alpn_proto = &ssl_alpn_protocols[i];

            if ((alpn_proto->match_exact &&
                        name_length == strlen(alpn_proto->proto_name) &&
                        !strcmp(proto_name, alpn_proto->proto_name)) ||
                (!alpn_proto->match_exact && g_str_has_prefix(proto_name, alpn_proto->proto_name))) {

                dissector_handle_t handle;
                /* ProtocolName match, so set the App data dissector handle.
                 * This may override protocols given via the UAT dialog, but
                 * since the ALPN hint is precise, do it anyway. */
                handle = ssl_find_appdata_dissector(alpn_proto->dissector_name);
                ssl_debug_printf("%s: changing handle %p to %p (%s)", G_STRFUNC,
                                 (void *)session->app_handle,
                                 (void *)handle, alpn_proto->dissector_name);
                /* if dissector is disabled, do not overwrite previous one */
                if (handle)
                    session->app_handle = handle;
                break;
            }
        }
    }

    while (alpn_length > 0) {
        name_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(alpn_tree, hf->hf.hs_ext_alpn_str_len,
                            tvb, offset, 1, ENC_NA);
        offset++;
        alpn_length--;
        proto_tree_add_item(alpn_tree, hf->hf.hs_ext_alpn_str,
                            tvb, offset, name_length, ENC_ASCII|ENC_NA);
        offset += name_length;
        alpn_length -= name_length;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_npn(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint8      npn_length;
    proto_tree *npn_tree;

    if (ext_len == 0) {
        return offset;
    }

    npn_tree = proto_tree_add_subtree(tree, tvb, offset, ext_len, hf->ett.hs_ext_npn, NULL, "Next Protocol Negotiation");

    while (ext_len > 0) {
        npn_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(npn_tree, hf->hf.hs_ext_npn_str_len,
                            tvb, offset, 1, ENC_NA);
        offset++;
        ext_len--;

        if (npn_length > 0) {
            proto_tree_add_item(npn_tree, hf->hf.hs_ext_npn_str,
                                tvb, offset, npn_length, ENC_ASCII|ENC_NA);
            offset += npn_length;
            ext_len -= npn_length;
        }
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_reneg_info(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                     proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint8      reneg_info_length;
    proto_tree *reneg_info_tree;

    if (ext_len == 0) {
        return offset;
    }

    reneg_info_tree = proto_tree_add_subtree(tree, tvb, offset, ext_len, hf->ett.hs_ext_reneg_info, NULL, "Renegotiation Info extension");

    reneg_info_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(reneg_info_tree, hf->hf.hs_ext_reneg_info_len,
              tvb, offset, 1, ENC_NA);
    offset += 1;

    if (reneg_info_length > 0) {
        proto_tree_add_item(reneg_info_tree, hf->hf.hs_ext_reneg_info, tvb, offset, reneg_info_length, ENC_NA);
        offset += reneg_info_length;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_key_share_entry(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                          proto_tree *tree, guint32 offset, guint32 offset_end)
{
    guint32 key_exchange_length, group;
    proto_tree *ks_tree;

    ks_tree = proto_tree_add_subtree(tree, tvb, offset, 4, hf->ett.hs_ext_key_share_ks, NULL, "Key Share Entry");

    proto_tree_add_item_ret_uint(ks_tree, hf->hf.hs_ext_key_share_group, tvb, offset, 2, ENC_BIG_ENDIAN, &group);
    offset += 2;

    proto_tree_add_item_ret_uint(ks_tree, hf->hf.hs_ext_key_share_key_exchange_length, tvb, offset, 2, ENC_BIG_ENDIAN, &key_exchange_length);
    offset += 2;

    proto_item_set_len(ks_tree, 2 + 2 + key_exchange_length);
    proto_item_append_text(ks_tree, ": Group: %s, Key Exchange length: %u", val_to_str(group, ssl_extension_curves, "Unknown (%u)"), key_exchange_length);

    if (key_exchange_length > offset_end - offset) {
        offset = offset_end;
        return offset; /* XXX expert info? */
    }

    proto_tree_add_item(ks_tree, hf->hf.hs_ext_key_share_key_exchange, tvb, offset, key_exchange_length, ENC_NA);
    offset += key_exchange_length;

    return offset;
}
static gint
ssl_dissect_hnd_hello_ext_key_share(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                    proto_tree *tree, guint32 offset, guint32 ext_len,
                                    guint8 hnd_type)
{
    proto_tree *key_share_tree;
    guint32 offset_end = offset + ext_len;

    if (offset_end <= offset) {  /* Check if ext_len == 0 and "overflow" (offset + ext_len) > guint32) */
        return offset;
    }

    key_share_tree = proto_tree_add_subtree(tree, tvb, offset, ext_len, hf->ett.hs_ext_key_share, NULL, "Key Share extension");

    switch(hnd_type){
        case SSL_HND_CLIENT_HELLO:
            proto_tree_add_item(key_share_tree, hf->hf.hs_ext_key_share_client_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            while (offset + 4 <= offset_end) { /* (NamedGroup (2 bytes), key_exchange (1 byte for length, 1 byte minimum data) */
                offset = ssl_dissect_hnd_hello_ext_key_share_entry(hf, tvb, key_share_tree, offset, offset_end);
            }
        break;
        case SSL_HND_SERVER_HELLO:
            offset = ssl_dissect_hnd_hello_ext_key_share_entry(hf, tvb, key_share_tree, offset, offset_end);
        break;
        case SSL_HND_HELLO_RETRY_REQUEST:
            proto_tree_add_item(key_share_tree, hf->hf.hs_ext_key_share_selected_group, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset += 2;
        break;
        default: /* no default */
        break;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_pre_shared_key(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                         proto_tree *tree, guint32 offset, guint32 ext_len,
                                         guint8 hnd_type)
{
    /*  struct {
     *      opaque identity<0..2^16-1>;
     *      uint32 obfuscated_ticket_age;
     *  } PskIdentity;
     *  opaque PskBinderEntry<32..255>;
     *  struct {
     *      select (Handshake.msg_type) {
     *          case client_hello:
     *              PskIdentity identities<6..2^16-1>;
     *              PskBinderEntry binders<33..2^16-1>;
     *          case server_hello:
     *              uint16 selected_identity;
     *      };
     *  } PreSharedKeyExtension;
     */

    proto_tree *psk_tree;
    guint32 offset_end = offset + ext_len;

    if (offset_end <= offset) { /* Check if ext_len == 0 and "overflow" (offset + ext_len) > guint32) */
        return offset;
    }

    psk_tree = proto_tree_add_subtree(tree, tvb, offset, ext_len, hf->ett.hs_ext_pre_shared_key, NULL, "Pre-Shared Key extension");

    switch (hnd_type){
        case SSL_HND_CLIENT_HELLO: {
            guint32 identities_length, identities_end, binders_length;

            proto_tree_add_item_ret_uint(psk_tree, hf->hf.hs_ext_psk_identities_length, tvb, offset, 2, ENC_BIG_ENDIAN, &identities_length);
            offset += 2;

            if (offset_end - offset < identities_length) {
                /* XXX expert info */
                return offset;
            }

            identities_end = offset + identities_length;
            while (offset < identities_end) {
                guint32 identity_length;
                proto_tree *identity_tree;

                identity_tree = proto_tree_add_subtree(psk_tree, tvb, offset, 4, hf->ett.hs_ext_psk_identity, NULL, "PSK Identity (");

                proto_tree_add_item_ret_uint(identity_tree, hf->hf.hs_ext_psk_identity_identity_length, tvb, offset, 2, ENC_BIG_ENDIAN, &identity_length);
                offset += 2;
                proto_item_append_text(identity_tree, "length: %u)", identity_length);

                if (identity_length > identities_end - offset) {
                    /* XXX expert info */
                    return offset;
                }

                proto_tree_add_item(identity_tree, hf->hf.hs_ext_psk_identity_identity, tvb, offset, identity_length, ENC_BIG_ENDIAN);
                offset += identity_length;

                proto_tree_add_item(identity_tree, hf->hf.hs_ext_psk_identity_obfuscated_ticket_age, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_item_set_len(identity_tree, 2 + identity_length + 4);
            }

            proto_tree_add_item_ret_uint(psk_tree, hf->hf.hs_ext_psk_binders_length, tvb, offset, 2, ENC_BIG_ENDIAN, &binders_length);
            offset += 2;

            if (binders_length > offset_end - offset) {
                /* XXX expert info */
                return offset;
            }

            proto_tree_add_item(psk_tree, hf->hf.hs_ext_psk_binders, tvb, offset, binders_length, ENC_NA);
            offset += binders_length;
        }
        break;
        case SSL_HND_SERVER_HELLO: {
            proto_tree_add_item(psk_tree, hf->hf.hs_ext_psk_identity_selected, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        break;
        default:
        break;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_early_data(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                         proto_tree *tree, guint32 offset, guint32 ext_len _U_,
                                         guint8 hnd_type)
{

    switch (hnd_type){
        case SSL_HND_CLIENT_HELLO:
            proto_tree_add_item(tree, hf->hf.hs_ext_early_data_obfuscated_ticket_age, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case SSL_HND_SERVER_HELLO: /* empty extension_data */
            break;
        default: /* no default */
        break;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_supported_versions(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                             proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint32 offset_end = offset + ext_len;

    if (ext_len < 1) {
        return offset;
    }

    proto_tree_add_item(tree, hf->hf.hs_ext_supported_versions_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    while(offset_end - offset >= 2){
        proto_tree_add_item(tree, hf->hf.hs_ext_supported_versions, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_cookie(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                 proto_tree *tree, guint32 offset, guint32 ext_len)
{

    if (ext_len < 2) {
        return offset;
    }

    proto_tree_add_item(tree, hf->hf.hs_ext_cookie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ext_len -= 2;

    proto_tree_add_item(tree, hf->hf.hs_ext_cookie, tvb, offset, ext_len, ENC_NA);
    offset += ext_len;

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_psk_key_exchange_modes(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                                 proto_tree *tree, guint32 offset, guint32 ext_len)
{
    /*
     * enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
     *
     * struct {
     *     PskKeyExchangeMode ke_modes<1..255>;
     * } PskKeyExchangeModes;
     */
    guint32 offset_end = offset + ext_len;
    guint32 ke_modes_length, i;

    if (ext_len < 1) {
        /* XXX expert info, there must be at least 1 ke mode */
        return offset;
    }

    proto_tree_add_item_ret_uint(tree, hf->hf.hs_ext_psk_ke_modes_len, tvb, offset, 1, ENC_NA, &ke_modes_length);
    offset += 1;

    if (ke_modes_length > offset_end - offset) {
        ke_modes_length = offset_end - offset;
        /* XXX expert info: size too large */
    }

    for (i = 0; i < ke_modes_length; i++) {
        proto_tree_add_item(tree, hf->hf.hs_ext_psk_ke_mode, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_server_name(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint16     server_name_length;
    proto_tree *server_name_tree;


    if (ext_len == 0) {
        return offset;
    }

    server_name_tree = proto_tree_add_subtree(tree, tvb, offset, ext_len, hf->ett.hs_ext_server_name, NULL, "Server Name Indication extension");

    proto_tree_add_item(server_name_tree, hf->hf.hs_ext_server_name_list_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ext_len -= 2;

    while (ext_len > 0) {
        proto_tree_add_item(server_name_tree, hf->hf.hs_ext_server_name_type,
                            tvb, offset, 1, ENC_NA);
        offset += 1;
        ext_len -= 1;

        server_name_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(server_name_tree, hf->hf.hs_ext_server_name_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        ext_len -= 2;

        if (server_name_length > 0) {
            proto_tree_add_item(server_name_tree, hf->hf.hs_ext_server_name,
                                tvb, offset, server_name_length, ENC_ASCII|ENC_NA);
            offset += server_name_length;
            ext_len -= server_name_length;
        }
    }
    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_session_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      proto_tree *tree, guint32 offset, guint32 ext_len, guint8 hnd_type, SslDecryptSession *ssl)
{
    if (hnd_type == SSL_HND_CLIENT_HELLO && ssl && ext_len != 0) {
        tvb_ensure_bytes_exist(tvb, offset, ext_len);
        /* Save the Session Ticket such that it can be used as identifier for
         * restoring a previous Master Secret (in ChangeCipherSpec) */
        ssl->session_ticket.data = (guchar*)wmem_realloc(wmem_file_scope(),
                                    ssl->session_ticket.data, ext_len);
        ssl->session_ticket.data_len = ext_len;
        tvb_memcpy(tvb,ssl->session_ticket.data, offset, ext_len);
    }
    proto_tree_add_bytes_format(tree, hf->hf.hs_ext_data,
                                tvb, offset, ext_len, NULL,
                                "Data (%u byte%s)",
                                ext_len, plurality(ext_len, "", "s"));
    return offset + ext_len;
}

static gint
ssl_dissect_hnd_hello_ext_cert_type(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                    proto_tree *tree, guint32 offset, guint32 ext_len,
                                    guint8 hnd_type, guint16 ext_type, SslSession *session)
{
    guint8      cert_list_length;
    guint8      cert_type;
    proto_tree *cert_list_tree;
    proto_item *ti;

    switch(hnd_type){
    case SSL_HND_CLIENT_HELLO:
        cert_list_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_types_len,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (ext_len != (guint32)cert_list_length + 1)
            return offset;

        ti = proto_tree_add_item(tree, hf->hf.hs_ext_cert_types, tvb, offset,
                                 cert_list_length, cert_list_length);
        proto_item_append_text(ti, " (%d)", cert_list_length);

        /* make this a subtree */
        cert_list_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_cert_types);

        /* loop over all point formats */
        while (cert_list_length > 0)
        {
            proto_tree_add_item(cert_list_tree, hf->hf.hs_ext_cert_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            cert_list_length--;
        }
    break;
    case SSL_HND_SERVER_HELLO:
        cert_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (ext_type == SSL_HND_HELLO_EXT_CERT_TYPE || ext_type == SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE) {
            session->client_cert_type = cert_type;
        }
        if (ext_type == SSL_HND_HELLO_EXT_CERT_TYPE || ext_type == SSL_HND_HELLO_EXT_SERVER_CERT_TYPE) {
           session->server_cert_type = cert_type;
        }
    break;
    default: /* no default */
    break;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_common(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, guint32 offset,
                             SslSession *session, SslDecryptSession *ssl,
                             gboolean from_server)
{
    nstime_t     gmt_unix_time;
    guint8       sessid_length;
    proto_tree  *rnd_tree;
    proto_tree  *ti_rnd;

    /* Prepare for renegotiation by resetting the state. */
    ssl_reset_session(session, ssl, !from_server);

    if (ssl) {
        StringInfo *rnd;
        if (from_server)
            rnd = &ssl->server_random;
        else
            rnd = &ssl->client_random;

        /* save provided random for later keyring generation */
        tvb_memcpy(tvb, rnd->data, offset, 32);
        rnd->data_len = 32;
        if (from_server)
            ssl->state |= SSL_SERVER_RANDOM;
        else
            ssl->state |= SSL_CLIENT_RANDOM;
        ssl_debug_printf("%s found %s RANDOM -> state 0x%02X\n", G_STRFUNC,
                from_server ? "SERVER" : "CLIENT", ssl->state);
    }

    ti_rnd = proto_tree_add_item(tree, hf->hf.hs_random, tvb, offset, 32, ENC_NA);

    if (session->version != TLSV1DOT3_VERSION) { /* No time on first bytes random with TLS 1.3 */

        rnd_tree = proto_item_add_subtree(ti_rnd, hf->ett.hs_random);
        /* show the time */
        gmt_unix_time.secs  = tvb_get_ntohl(tvb, offset);
        gmt_unix_time.nsecs = 0;
        proto_tree_add_time(rnd_tree, hf->hf.hs_random_time,
                tvb, offset, 4, &gmt_unix_time);
        offset += 4;

        /* show the random bytes */
        proto_tree_add_item(rnd_tree, hf->hf.hs_random_bytes,
                tvb, offset, 28, ENC_NA);
        offset += 28;
    } else {
        offset += 32;
    }

    if (from_server == 0 || session->version != TLSV1DOT3_VERSION) { /* No Session ID with TLS 1.3 on Server Hello */
        /* show the session id (length followed by actual Session ID) */
        sessid_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_session_id_len,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (ssl) {
            /* save the authorative SID for later use in ChangeCipherSpec.
             * (D)TLS restricts the SID to 32 chars, it does not make sense to
             * save more, so ignore larger ones. */
            if (from_server && sessid_length <= 32) {
                tvb_memcpy(tvb, ssl->session_id.data, offset, sessid_length);
                ssl->session_id.data_len = sessid_length;
            }
        }
        if (sessid_length > 0) {
            proto_tree_add_item(tree, hf->hf.hs_session_id,
                    tvb, offset, sessid_length, ENC_NA);
            offset += sessid_length;
        }
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_status_request(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                                         guint32 offset, gboolean has_length)
{
    guint    cert_status_type;

    cert_status_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_cert_status_type,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (has_length) {
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_status_request_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    switch (cert_status_type) {
    case SSL_HND_CERT_STATUS_TYPE_OCSP:
    case SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI:
        {
            guint16      responder_id_list_len;
            guint16      request_extensions_len;
            proto_item  *responder_id;
            proto_item  *request_extensions;

            responder_id_list_len = tvb_get_ntohs(tvb, offset);
            responder_id =
                proto_tree_add_item(tree,
                                    hf->hf.hs_ext_cert_status_responder_id_list_len,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (responder_id_list_len != 0) {
                expert_add_info_format(NULL, responder_id,
                                       &hf->ei.hs_ext_cert_status_undecoded,
                                       "Responder ID list is not implemented, contact Wireshark"
                                       " developers if you want this to be supported");
                /* Non-empty responder ID list would mess with extensions. */
                break;
            }

            request_extensions_len = tvb_get_ntohs(tvb, offset);
            request_extensions =
                proto_tree_add_item(tree,
                                    hf->hf.hs_ext_cert_status_request_extensions_len, tvb, offset,
                                    2, ENC_BIG_ENDIAN);
            offset += 2;
            if (request_extensions_len != 0)
                expert_add_info_format(NULL, request_extensions,
                                       &hf->ei.hs_ext_cert_status_undecoded,
                                       "Request Extensions are not implemented, contact"
                                       " Wireshark developers if you want this to be supported");
            break;
        }
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_status_request_v2(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                                            guint32 offset)
{
    gint32   list_len;

    list_len = tvb_get_ntohs(tvb, offset);
    offset += 2;

    while (list_len > 0) {
        guint32 prev_offset = offset;
        offset = ssl_dissect_hnd_hello_ext_status_request(hf, tvb, tree, offset, TRUE);
        list_len -= (offset - prev_offset);
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_elliptic_curves(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                          proto_tree *tree, guint32 offset)
{
    guint16     curves_length;
    proto_tree *curves_tree;
    proto_item *ti;

    curves_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_elliptic_curves_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 2;
    ti = proto_tree_add_none_format(tree,
                                    hf->hf.hs_ext_elliptic_curves,
                                    tvb, offset, curves_length,
                                    "Elliptic curves (%d curve%s)",
                                    curves_length / 2,
                                    plurality(curves_length/2, "", "s"));

    /* make this a subtree */
    curves_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_curves);

    /* loop over all curves */
    while (curves_length > 0)
    {
        proto_tree_add_item(curves_tree, hf->hf.hs_ext_elliptic_curve, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        curves_length -= 2;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_ec_point_formats(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                           proto_tree *tree, guint32 offset)
{
    guint8      ecpf_length;
    proto_tree *ecpf_tree;
    proto_item *ti;

    ecpf_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_ec_point_formats_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    ti = proto_tree_add_none_format(tree,
                                    hf->hf.hs_ext_elliptic_curves,
                                    tvb, offset, ecpf_length,
                                    "Elliptic curves point formats (%d)",
                                    ecpf_length);

    /* make this a subtree */
    ecpf_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_curves_point_formats);

    /* loop over all point formats */
    while (ecpf_length > 0)
    {
        proto_tree_add_item(ecpf_tree, hf->hf.hs_ext_ec_point_format, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        ecpf_length--;
    }

    return offset;
}
/** TLS Extensions (in Client Hello and Server Hello). }}} */

/* Whether the Content and Handshake Types are valid; handle Protocol Version. {{{ */
gboolean
ssl_is_valid_content_type(guint8 type)
{
    switch ((ContentType) type) {
    case SSL_ID_CHG_CIPHER_SPEC:
    case SSL_ID_ALERT:
    case SSL_ID_HANDSHAKE:
    case SSL_ID_APP_DATA:
    case SSL_ID_HEARTBEAT:
        return TRUE;
    }
    return FALSE;
}

gboolean
ssl_is_valid_handshake_type(guint8 hs_type, gboolean is_dtls)
{
    switch ((HandshakeType) hs_type) {
    case SSL_HND_HELLO_VERIFY_REQUEST:
        /* hello_verify_request is DTLS-only */
        return is_dtls;

    case SSL_HND_HELLO_REQUEST:
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_SERVER_HELLO:
    case SSL_HND_NEWSESSION_TICKET:
    case SSL_HND_HELLO_RETRY_REQUEST:
    case SSL_HND_ENCRYPTED_EXTENSIONS:
    case SSL_HND_CERTIFICATE:
    case SSL_HND_SERVER_KEY_EXCHG:
    case SSL_HND_CERT_REQUEST:
    case SSL_HND_SVR_HELLO_DONE:
    case SSL_HND_CERT_VERIFY:
    case SSL_HND_CLIENT_KEY_EXCHG:
    case SSL_HND_FINISHED:
    case SSL_HND_CERT_URL:
    case SSL_HND_CERT_STATUS:
    case SSL_HND_SUPPLEMENTAL_DATA:
    case SSL_HND_ENCRYPTED_EXTS:
        return TRUE;
    }
    return FALSE;
}

static gboolean
ssl_is_authoritative_version_message(guint8 content_type, guint8 handshake_type,
                                     gboolean is_dtls)
{
    /* Consider all valid Handshake messages (except for Client Hello) and
     * all other valid record types (other than Handshake) */
    return (content_type == SSL_ID_HANDSHAKE &&
            ssl_is_valid_handshake_type(handshake_type, is_dtls) &&
            handshake_type != SSL_HND_CLIENT_HELLO) ||
           (content_type != SSL_ID_HANDSHAKE &&
            ssl_is_valid_content_type(content_type));
}

void
ssl_try_set_version(SslSession *session, SslDecryptSession *ssl,
                    guint8 content_type, guint8 handshake_type,
                    gboolean is_dtls, guint16 version)
{
    if (!ssl_is_authoritative_version_message(content_type, handshake_type,
                is_dtls))
        return;

    switch (version) {
    case SSLV3_VERSION:
    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case TLSV1DOT2_VERSION:
    case TLSV1DOT3_VERSION:
        if (is_dtls)
            return;
        break;

    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
    case DTLSV1DOT2_VERSION:
        if (!is_dtls)
            return;
        break;

    default: /* invalid version number */
        return;
    }

    session->version = version;
    if (ssl) {
        ssl->state |= SSL_VERSION;
        ssl_debug_printf("%s found version 0x%04X -> state 0x%02X\n", G_STRFUNC, version, ssl->state);
    }
}
/* }}} */


/* Client Hello and Server Hello dissections. {{{ */
static gint
ssl_dissect_hnd_hello_ext(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          packet_info* pinfo, guint32 offset, guint32 left, guint8 hnd_type,
                          SslSession *session, SslDecryptSession *ssl,
                          gboolean is_dtls);
void
ssl_dissect_hnd_cli_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *tree, guint32 offset,
                          guint32 length, SslSession *session,
                          SslDecryptSession *ssl, dtls_hfs_t *dtls_hfs)
{
    /* struct {
     *     ProtocolVersion client_version;
     *     Random random;
     *     SessionID session_id;
     *     opaque cookie<0..32>;                   //new field for DTLS
     *     CipherSuite cipher_suites<2..2^16-1>;
     *     CompressionMethod compression_methods<1..2^8-1>;
     *     Extension client_hello_extension_list<0..2^16-1>;
     * } ClientHello;
     *
     */
    proto_item *ti;
    proto_tree *cs_tree;
    guint16     cipher_suite_length;
    guint8      compression_methods_length;
    guint8      compression_method;
    guint16     start_offset = offset;

    /* show the client version */
    proto_tree_add_item(tree, hf->hf.hs_client_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* dissect fields that are also present in ClientHello */
    offset = ssl_dissect_hnd_hello_common(hf, tvb, tree, offset, session, ssl, FALSE);

    /* fields specific for DTLS (cookie_len, cookie) */
    if (dtls_hfs != NULL) {
        /* look for a cookie */
        guint8 cookie_length = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(tree, dtls_hfs->hf_dtls_handshake_cookie_len,
                            tvb, offset, 1, cookie_length);
        offset++;
        if (cookie_length > 0) {
            proto_tree_add_item(tree, dtls_hfs->hf_dtls_handshake_cookie,
                                tvb, offset, cookie_length, ENC_NA);
            offset += cookie_length;
        }
    }

    /* tell the user how many cipher suites there are */
    cipher_suite_length = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(tree, hf->hf.hs_cipher_suites_len,
                             tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (cipher_suite_length > 0) {
        if (cipher_suite_length % 2) {
            expert_add_info_format(pinfo, ti, &hf->ei.hs_cipher_suites_len_bad,
                "Cipher suite length (%d) must be a multiple of 2",
                cipher_suite_length);
            return;
        }
        ti = proto_tree_add_none_format(tree,
                                        hf->hf.hs_cipher_suites,
                                        tvb, offset, cipher_suite_length,
                                        "Cipher Suites (%d suite%s)",
                                        cipher_suite_length / 2,
                                        plurality(cipher_suite_length/2, "", "s"));

        /* make this a subtree */
        cs_tree = proto_item_add_subtree(ti, hf->ett.cipher_suites);

        while (cipher_suite_length > 0) {
            proto_tree_add_item(cs_tree, hf->hf.hs_cipher_suite,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            cipher_suite_length -= 2;
        }
    }
    /* tell the user how many compression methods there are */
    compression_methods_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf->hf.hs_comp_methods_len,
                        tvb, offset, 1, compression_methods_length);
    offset += 1;
    if (compression_methods_length > 0) {
        ti = proto_tree_add_none_format(tree,
                                        hf->hf.hs_comp_methods,
                                        tvb, offset, compression_methods_length,
                                        "Compression Methods (%u method%s)",
                                        compression_methods_length,
                                        plurality(compression_methods_length,
                                          "", "s"));

        /* make this a subtree */
        cs_tree = proto_item_add_subtree(ti, hf->ett.comp_methods);

        while (compression_methods_length > 0) {
            compression_method = tvb_get_guint8(tvb, offset);
            /* TODO: make reserved/private comp meth. fields selectable */
            if (compression_method < 64)
                proto_tree_add_uint(cs_tree, hf->hf.hs_comp_method,
                                    tvb, offset, 1, compression_method);
            else if (compression_method > 63 && compression_method < 193)
                proto_tree_add_uint_format_value(cs_tree, hf->hf.hs_comp_method, tvb, offset, 1,
                                    compression_method, "Reserved - to be assigned by IANA (%u)",
                                    compression_method);
            else
                proto_tree_add_uint_format_value(cs_tree, hf->hf.hs_comp_method, tvb, offset, 1,
                                    compression_method, "Private use range (%u)",
                                    compression_method);
            offset++;
            compression_methods_length--;
        }
    }
    if (length > offset - start_offset) {
        ssl_dissect_hnd_hello_ext(hf, tvb, tree, pinfo, offset,
                                  length - (offset - start_offset), SSL_HND_CLIENT_HELLO,
                                  session, ssl, dtls_hfs != NULL);
    }
}

void
ssl_dissect_hnd_srv_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          packet_info* pinfo, proto_tree *tree, guint32 offset, guint32 length,
                          SslSession *session, SslDecryptSession *ssl,
                          gboolean is_dtls)
{
    /* struct {
     *     ProtocolVersion server_version;
     *     Random random;
     *     SessionID session_id;
     *     CipherSuite cipher_suite;
     *     CompressionMethod compression_method;
     *     Extension server_hello_extension_list<0..2^16-1>;
     * } ServerHello;
     */
    guint16 server_version;
    guint16 start_offset = offset;

    /* This version is always better than the guess at the Record Layer */
    server_version = tvb_get_ntohs(tvb, offset);
    if((server_version & 0xFF00) == 0x7f00) { /* if server_version start with 0x7f, it is (and force) TLS 1.3 */
        server_version = TLSV1DOT3_VERSION;
    }
    ssl_try_set_version(session, ssl, SSL_ID_HANDSHAKE, SSL_HND_SERVER_HELLO,
            is_dtls, server_version);
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                val_to_str_const(server_version, ssl_version_short_names, "SSL"));

    /* Initially assume that the session is resumed. If this is not the case, a
     * ServerHelloDone will be observed before the ChangeCipherSpec message
     * which will reset this flag. */
    session->is_session_resumed = TRUE;

    /* show the server version */
    proto_tree_add_item(tree, hf->hf.hs_server_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* dissect fields that are also present in ClientHello */
    offset = ssl_dissect_hnd_hello_common(hf, tvb, tree, offset, session, ssl, TRUE);

    if (ssl) {
        /* store selected cipher suite for decryption */
        ssl->session.cipher = tvb_get_ntohs(tvb, offset);

        if (!(ssl->cipher_suite = ssl_find_cipher(ssl->session.cipher))) {
            ssl->state &= ~SSL_CIPHER;
            ssl_debug_printf("%s can't find cipher suite 0x%04X\n",
                             G_STRFUNC, ssl->session.cipher);
        } else {
            /* Cipher found, save this for the delayed decoder init */
            ssl->state |= SSL_CIPHER;
            ssl_debug_printf("%s found CIPHER 0x%04X %s -> state 0x%02X\n",
                             G_STRFUNC, ssl->session.cipher,
                             val_to_str_ext_const(ssl->session.cipher,
                                 &ssl_31_ciphersuite_ext, "unknown"),
                             ssl->state);
        }
    }

    /* now the server-selected cipher suite */
    proto_tree_add_item(tree, hf->hf.hs_cipher_suite,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (session->version != TLSV1DOT3_VERSION) { /* No compression with TLS 1.3 */
        if (ssl) {
            /* store selected compression method for decryption */
            ssl->session.compression = tvb_get_guint8(tvb, offset);
        }
        /* and the server-selected compression method */
        proto_tree_add_item(tree, hf->hf.hs_comp_method,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    /* remaining data are extensions */
    if (length > offset - start_offset) {
        ssl_dissect_hnd_hello_ext(hf, tvb, tree, pinfo, offset,
                                  length - (offset - start_offset), SSL_HND_SERVER_HELLO,
                                  session, ssl, is_dtls);
    }
}
/* Client Hello and Server Hello dissections. }}} */

/* New Session Ticket dissection. {{{ */
void
ssl_dissect_hnd_new_ses_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset,
                               SslDecryptSession *ssl _U_,
                               GHashTable *session_hash _U_)
{
    proto_tree  *subtree;
    guint16      ticket_len;

    /* length of session ticket, may be 0 if the server has sent the
     * SessionTicket extension, but decides not to use one. */
    ticket_len = tvb_get_ntohs(tvb, offset + 4);
    subtree = proto_tree_add_subtree(tree, tvb, offset, 6 + ticket_len,
                                     hf->ett.session_ticket, NULL,
                                     "TLS Session Ticket");

    /* ticket lifetime hint */
    proto_tree_add_item(subtree, hf->hf.hs_session_ticket_lifetime_hint,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* opaque ticket (length, data) */
    proto_tree_add_item(subtree, hf->hf.hs_session_ticket_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Content depends on implementation, so just show data! */
    proto_tree_add_item(subtree, hf->hf.hs_session_ticket,
                        tvb, offset, ticket_len, ENC_NA);
    /* save the session ticket to cache for ssl_finalize_decryption */
#ifdef HAVE_LIBGCRYPT
    if (ssl) {
        tvb_ensure_bytes_exist(tvb, offset, ticket_len);
        ssl->session_ticket.data = (guchar*)wmem_realloc(wmem_file_scope(),
                                    ssl->session_ticket.data, ticket_len);
        ssl->session_ticket.data_len = ticket_len;
        tvb_memcpy(tvb, ssl->session_ticket.data, offset, ticket_len);
        /* NewSessionTicket is received after the first (client)
         * ChangeCipherSpec, and before the second (server) ChangeCipherSpec.
         * Since the second CCS has already the session key available it will
         * just return. To ensure that the session ticket is mapped to a
         * master key (from the first CCS), save the ticket here too. */
        ssl_save_master_key("Session Ticket", session_hash,
                            &ssl->session_ticket, &ssl->master_secret);
        ssl->state |= SSL_NEW_SESSION_TICKET;
    }
#endif
} /* }}} */

void
ssl_dissect_hnd_hello_retry_request(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                    packet_info* pinfo, proto_tree *tree, guint32 offset, guint32 length,
                                    SslSession *session, SslDecryptSession *ssl,
                                    gboolean is_dtls)
{
    /* struct {
     *     ProtocolVersion server_version;
     *     Extension extensions<2..2^16-1>;
     * } HelloRetryRequest;
     */
    guint16 start_offset = offset;

    proto_tree_add_item(tree, hf->hf.hs_server_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* remaining data are extensions */
    if (length > offset - start_offset) {
        ssl_dissect_hnd_hello_ext(hf, tvb, tree, pinfo, offset,
                                  length - (offset - start_offset), SSL_HND_HELLO_RETRY_REQUEST,
                                  session, ssl, is_dtls);
    }
}

void
ssl_dissect_hnd_encrypted_extensions(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                     packet_info* pinfo, proto_tree *tree, guint32 offset, guint32 length,
                                     SslSession *session, SslDecryptSession *ssl,
                                     gboolean is_dtls)
{
    /* struct {
     *     Extension extensions<0..2^16-1>;
     * } EncryptedExtensions;
     */
    ssl_dissect_hnd_hello_ext(hf, tvb, tree, pinfo, offset,
                              length, SSL_HND_ENCRYPTED_EXTENSIONS,
                              session, ssl, is_dtls);
}

/* Certificate and Certificate Request dissections. {{{ */
void
ssl_dissect_hnd_cert(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                     guint32 offset, packet_info *pinfo,
                     const SslSession *session, SslDecryptSession *ssl _U_,
                     GHashTable *key_hash _U_, gint is_from_server)
{
    /* opaque ASN.1Cert<1..2^24-1>;
     *
     * struct {
     *     select(certificate_type) {
     *
     *         // certificate type defined in RFC 7250
     *         case RawPublicKey:
     *           opaque ASN.1_subjectPublicKeyInfo<1..2^24-1>;
     *
     *         // X.509 certificate defined in RFC 5246
     *         case X.509:
     *           ASN.1Cert certificate_list<0..2^24-1>;
     *     };
     * } Certificate;
     *
     * draft-ietf-tls-tls13-18:
     *     opaque ASN1Cert<1..2^24-1>;
     *     struct {
     *         ASN1Cert cert_data;
     *         Extension extensions<0..2^16-1>;
     *     } CertificateEntry;
     *     struct {
     *         opaque certificate_request_context<0..2^8-1>;
     *         CertificateEntry certificate_list<0..2^24-1>;
     *     } Certificate;
     */
    enum { CERT_X509, CERT_RPK } cert_type;
    asn1_ctx_t  asn1_ctx;
#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
    gnutls_datum_t subjectPublicKeyInfo = { NULL, 0 };
#endif

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    if ((is_from_server && session->server_cert_type == SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY) ||
        (!is_from_server && session->client_cert_type == SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY)) {
        cert_type = CERT_RPK;
    } else {
        cert_type = CERT_X509;
    }

#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
    /* Ask the pkcs1 dissector to return the public key details */
    if (ssl)
        asn1_ctx.private_data = &subjectPublicKeyInfo;
#endif

    switch (cert_type) {
    case CERT_RPK:
        {
            proto_tree_add_item(tree, hf->hf.hs_certificate_len,
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            dissect_x509af_SubjectPublicKeyInfo(FALSE, tvb, offset, &asn1_ctx, tree, hf->hf.hs_certificate);

            break;
        }
    case CERT_X509:
        {
            guint32     certificate_list_length;
            proto_item *ti;
            proto_tree *subtree;

            /* TLS 1.3: opaque certificate_request_context<0..2^8-1> */
            if (session->version == TLSV1DOT3_VERSION) {
                guint32 context_length;
                proto_tree_add_item_ret_uint(tree, hf->hf.hs_certificate_request_context_length,
                                             tvb, offset, 1, ENC_NA, &context_length);
                offset++;
                if (context_length > 0) {
                    proto_tree_add_item(tree, hf->hf.hs_certificate_request_context,
                                        tvb, offset, context_length, ENC_NA);
                    offset += context_length;
                }
            }

            proto_tree_add_item_ret_uint(tree, hf->hf.hs_certificates_len,
                                         tvb, offset, 3, ENC_BIG_ENDIAN, &certificate_list_length);
            offset += 3;            /* 24-bit length value */

            if (certificate_list_length > 0) {
                ti = proto_tree_add_none_format(tree,
                                                hf->hf.hs_certificates,
                                                tvb, offset, certificate_list_length,
                                                "Certificates (%u bytes)",
                                                certificate_list_length);

                /* make it a subtree */
                subtree = proto_item_add_subtree(ti, hf->ett.certificates);

                /* iterate through each certificate */
                while (certificate_list_length > 0) {
                    /* get the length of the current certificate */
                    guint32 cert_length;
                    proto_tree_add_item_ret_uint(subtree, hf->hf.hs_certificate_len,
                                                 tvb, offset, 3, ENC_BIG_ENDIAN, &cert_length);
                    offset += 3;
                    certificate_list_length -= 3 + cert_length;

                    dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, subtree, hf->hf.hs_certificate);
#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
                    /* Only attempt to get the RSA modulus for the first cert. */
                    asn1_ctx.private_data = NULL;
#endif

                    offset += cert_length;

                    /* TLS 1.3: Extension extensions<0..2^16-1> */
                    if (session->version == TLSV1DOT3_VERSION) {
                        guint32 extensions_length;
                        proto_tree_add_item_ret_uint(subtree, hf->hf.hs_exts_len,
                                                     tvb, offset, 2, ENC_BIG_ENDIAN, &extensions_length);
                        offset += 2;

                        // XXX dissect OCSP and SCT extensions
                        // https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.4.1.1
                        offset += extensions_length;
                        certificate_list_length -= 2 + extensions_length;
                    }
                }
            }
            break;
        }
    }

#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
    if (is_from_server && ssl)
        ssl_find_private_key_by_pubkey(ssl, key_hash, &subjectPublicKeyInfo);
#endif
}

void
ssl_dissect_hnd_cert_req(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, packet_info *pinfo,
                          const SslSession *session)
{
    /*
     *    enum {
     *        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
     *        (255)
     *    } ClientCertificateType;
     *
     *    opaque DistinguishedName<1..2^16-1>;
     *
     *    struct {
     *        ClientCertificateType certificate_types<1..2^8-1>;
     *        DistinguishedName certificate_authorities<3..2^16-1>;
     *    } CertificateRequest;
     *
     *
     * As per TLSv1.2 (RFC 5246) the format has changed to:
     *
     *    enum {
     *        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
     *        rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
     *        fortezza_dms_RESERVED(20), (255)
     *    } ClientCertificateType;
     *
     *    enum {
     *        none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
     *        sha512(6), (255)
     *    } HashAlgorithm;
     *
     *    enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
     *      SignatureAlgorithm;
     *
     *    struct {
     *          HashAlgorithm hash;
     *          SignatureAlgorithm signature;
     *    } SignatureAndHashAlgorithm;
     *
     *    SignatureAndHashAlgorithm
     *      supported_signature_algorithms<2..2^16-2>;
     *
     *    opaque DistinguishedName<1..2^16-1>;
     *
     *    struct {
     *        ClientCertificateType certificate_types<1..2^8-1>;
     *        SignatureAndHashAlgorithm
     *          supported_signature_algorithms<2^16-1>;
     *        DistinguishedName certificate_authorities<0..2^16-1>;
     *    } CertificateRequest;
     *
     * draft-ietf-tls-tls13-18 (soon obsolete!):
     * Note: certificate_extensions is not dissected since it is removed in next
     * draft.
     *
     *    struct {
     *        opaque certificate_request_context<0..2^8-1>;
     *        SignatureScheme supported_signature_algorithms<2..2^16-2>;
     *        DistinguishedName certificate_authorities<0..2^16-1>;
     *        CertificateExtension certificate_extensions<0..2^16-1>;
     *    } CertificateRequest;
     *
     * draft-ietf-tls-tls13 (between -18 and -19, 2017-01-30):
     *
     *    struct {
     *        opaque certificate_request_context<0..2^8-1>;
     *        Extension extensions<2..2^16-1>;
     *    } CertificateRequest;
     */
    proto_item *ti;
    proto_tree *subtree;
    guint8      cert_types_count;
    gint        sh_alg_length;
    gint        dnames_length;
    asn1_ctx_t  asn1_ctx;
    gint        ret;

    if (!tree)
        return;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    if (session->version == TLSV1DOT3_VERSION) {
        guint32 context_length;
        proto_tree_add_item_ret_uint(tree, hf->hf.hs_certificate_request_context_length,
                                     tvb, offset, 1, ENC_NA, &context_length);
        offset++;
        if (context_length > 0) {
            proto_tree_add_item(tree, hf->hf.hs_certificate_request_context,
                                tvb, offset, context_length, ENC_NA);
            offset += context_length;
        }
    } else {
        cert_types_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf->hf.hs_cert_types_count,
                tvb, offset, 1, cert_types_count);
        offset++;

        if (cert_types_count > 0) {
            ti = proto_tree_add_none_format(tree,
                    hf->hf.hs_cert_types,
                    tvb, offset, cert_types_count,
                    "Certificate types (%u type%s)",
                    cert_types_count,
                    plurality(cert_types_count, "", "s"));
            subtree = proto_item_add_subtree(ti, hf->ett.cert_types);

            while (cert_types_count > 0) {
                proto_tree_add_item(subtree, hf->hf.hs_cert_type,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                cert_types_count--;
            }
        }
    }

    switch (session->version) {
        case TLSV1DOT2_VERSION:
        case DTLSV1DOT2_VERSION:
        case TLSV1DOT3_VERSION: /* XXX draft -18 only, remove for next version */
            sh_alg_length = tvb_get_ntohs(tvb, offset);
            if (sh_alg_length % 2) {
                expert_add_info_format(pinfo, NULL,
                        &hf->ei.hs_sig_hash_alg_len_bad,
                        "Signature Hash Algorithm length (%d) must be a multiple of 2",
                        sh_alg_length);
                return;
            }

            proto_tree_add_uint(tree, hf->hf.hs_sig_hash_alg_len,
                    tvb, offset, 2, sh_alg_length);
            offset += 2;

            ret = ssl_dissect_hash_alg_list(hf, tvb, tree, pinfo, offset, sh_alg_length);
            if (ret >= 0)
                offset += ret;
            break;

        default:
            break;
    }

    dnames_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf->hf.hs_dnames_len,
            tvb, offset, 2, dnames_length);
    offset += 2;

    if (dnames_length > 0) {
        ti = proto_tree_add_none_format(tree,
                hf->hf.hs_dnames,
                tvb, offset, dnames_length,
                "Distinguished Names (%d byte%s)",
                dnames_length,
                plurality(dnames_length, "", "s"));
        subtree = proto_item_add_subtree(ti, hf->ett.dnames);

        while (dnames_length > 0) {
            /* get the length of the current certificate */
            guint16 name_length;
            name_length = tvb_get_ntohs(tvb, offset);
            dnames_length -= 2 + name_length;

            proto_tree_add_item(subtree, hf->hf.hs_dname_len,
                    tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            dissect_x509if_DistinguishedName(FALSE, tvb, offset, &asn1_ctx,
                                             subtree, hf->hf.hs_dname);
            offset += name_length;
        }
    }
}
/* Certificate and Certificate Request dissections. }}} */

static void
ssl_dissect_digitally_signed(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, guint32 offset,
                             const SslSession *session,
                             gint hf_sig_len, gint hf_sig);

void
ssl_dissect_hnd_cli_cert_verify(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                const SslSession *session)
{
    ssl_dissect_digitally_signed(hf, tvb, tree, offset, session,
                                 hf->hf.hs_client_cert_vrfy_sig_len,
                                 hf->hf.hs_client_cert_vrfy_sig);
}

/* Finished dissection. {{{ */
void
ssl_dissect_hnd_finished(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                         proto_tree *tree, guint32 offset,
                         const SslSession *session, ssl_hfs_t *ssl_hfs)
{
    /* For SSLv3:
     *     struct {
     *         opaque md5_hash[16];
     *         opaque sha_hash[20];
     *     } Finished;
     *
     * For (D)TLS:
     *     struct {
     *         opaque verify_data[12];
     *     } Finished;
     */
    if (!tree)
        return;

    if (session->version == SSLV3_VERSION) {
        if (ssl_hfs != NULL) {
            proto_tree_add_item(tree, ssl_hfs->hs_md5_hash,
                                tvb, offset, 16, ENC_NA);
            proto_tree_add_item(tree, ssl_hfs->hs_sha_hash,
                                tvb, offset + 16, 20, ENC_NA);
        }
    } else {
        proto_tree_add_item(tree, hf->hf.hs_finished,
                            tvb, offset, 12, ENC_NA);
    }
} /* }}} */

/* RFC 6066 Certificate URL handshake message dissection. {{{ */
void
ssl_dissect_hnd_cert_url(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint16  url_hash_len;

    /* enum {
     *     individual_certs(0), pkipath(1), (255)
     * } CertChainType;
     *
     * struct {
     *     CertChainType type;
     *     URLAndHash url_and_hash_list<1..2^16-1>;
     * } CertificateURL;
     *
     * struct {
     *     opaque url<1..2^16-1>;
     *     unint8 padding;
     *     opaque SHA1Hash[20];
     * } URLAndHash;
     */

    proto_tree_add_item(tree, hf->hf.hs_ext_cert_url_type,
                        tvb, offset, 1, ENC_NA);
    offset++;

    url_hash_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_cert_url_url_hash_list_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while (url_hash_len-- > 0) {
        proto_item  *urlhash_item;
        proto_tree  *urlhash_tree;
        guint16      url_len;

        urlhash_item = proto_tree_add_item(tree, hf->hf.hs_ext_cert_url_item,
                                           tvb, offset, -1, ENC_NA);
        urlhash_tree = proto_item_add_subtree(urlhash_item, hf->ett.urlhash);

        url_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_url_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_url,
                            tvb, offset, url_len, ENC_ASCII|ENC_NA);
        offset += url_len;

        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_padding,
                            tvb, offset, 1, ENC_NA);
        offset++;
        /* Note: RFC 6066 says that padding must be 0x01 */

        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_sha1,
                            tvb, offset, 20, ENC_NA);
        offset += 20;
    }
} /* }}} */

/* Client Hello and Server Hello TLS extensions dissection. {{{ */
static gint
ssl_dissect_hnd_hello_ext(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          packet_info* pinfo, guint32 offset, guint32 left, guint8 hnd_type,
                          SslSession *session, SslDecryptSession *ssl,
                          gboolean is_dtls)
{
    guint16     extension_length;
    guint16     ext_type;
    guint16     ext_len;
    proto_tree *ext_tree;

    if (left < 2)
        return offset;

    extension_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf->hf.hs_exts_len,
                        tvb, offset, 2, extension_length);
    offset += 2;
    left   -= 2;

    while (left >= 4)
    {
        ext_type = tvb_get_ntohs(tvb, offset);
        ext_len  = tvb_get_ntohs(tvb, offset + 2);

        ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + ext_len, hf->ett.hs_ext, NULL,
                                  "Extension: %s (len=%u)", val_to_str(ext_type,
                                            tls_hello_extension_types,
                                            "Unknown type %u"), ext_len);

        proto_tree_add_uint(ext_tree, hf->hf.hs_ext_type,
                            tvb, offset, 2, ext_type);
        offset += 2;

        proto_tree_add_uint(ext_tree, hf->hf.hs_ext_len,
                            tvb, offset, 2, ext_len);
        offset += 2;

        switch (ext_type) {
        case SSL_HND_HELLO_EXT_STATUS_REQUEST:
            if (hnd_type == SSL_HND_CLIENT_HELLO)
                offset = ssl_dissect_hnd_hello_ext_status_request(hf, tvb, ext_tree, offset, FALSE);
            else
                offset += ext_len; /* server must return empty extension_data */
            break;
        case SSL_HND_HELLO_EXT_STATUS_REQUEST_V2:
            if (hnd_type == SSL_HND_CLIENT_HELLO)
                offset = ssl_dissect_hnd_hello_ext_status_request_v2(hf, tvb, ext_tree, offset);
            else
                offset += ext_len; /* server must return empty extension_data */
            break;
        case SSL_HND_HELLO_EXT_SUPPORTED_GROUPS:
            offset = ssl_dissect_hnd_hello_ext_elliptic_curves(hf, tvb, ext_tree, offset);
            break;
        case SSL_HND_HELLO_EXT_EC_POINT_FORMATS:
            offset = ssl_dissect_hnd_hello_ext_ec_point_formats(hf, tvb, ext_tree, offset);
            break;
        case SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS:
            offset = ssl_dissect_hnd_hello_ext_sig_hash_algs(hf, tvb, ext_tree, pinfo, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_ALPN:
            offset = ssl_dissect_hnd_hello_ext_alpn(hf, tvb, ext_tree, offset, ext_len, hnd_type, session);
            break;
        case SSL_HND_HELLO_EXT_NPN:
            offset = ssl_dissect_hnd_hello_ext_npn(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_RENEGOTIATION_INFO:
            offset = ssl_dissect_hnd_hello_ext_reneg_info(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_KEY_SHARE:
            offset = ssl_dissect_hnd_hello_ext_key_share(hf, tvb, ext_tree, offset, ext_len, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_PRE_SHARED_KEY:
            offset = ssl_dissect_hnd_hello_ext_pre_shared_key(hf, tvb, ext_tree, offset, ext_len, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_EARLY_DATA:
            offset = ssl_dissect_hnd_hello_ext_early_data(hf, tvb, ext_tree, offset, ext_len, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS:
            offset = ssl_dissect_hnd_hello_ext_supported_versions(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_COOKIE:
            offset = ssl_dissect_hnd_hello_ext_cookie(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES:
            offset = ssl_dissect_hnd_hello_ext_psk_key_exchange_modes(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_DRAFT_VERSION_TLS13:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_draft_version_tls13,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += ext_len;
            break;
        case SSL_HND_HELLO_EXT_SERVER_NAME:
            offset = ssl_dissect_hnd_hello_ext_server_name(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_USE_SRTP:
            if (is_dtls) {
                offset = dtls_dissect_hnd_hello_ext_use_srtp(tvb, ext_tree, offset, ext_len);
            } else {
                // XXX expert info: This extension MUST only be used with DTLS, and not with TLS.
                offset += ext_len;
            }
            break;
        case SSL_HND_HELLO_EXT_HEARTBEAT:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_heartbeat_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += ext_len;
            break;
        case SSL_HND_HELLO_EXT_PADDING:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_padding_data, tvb, offset, ext_len, ENC_NA);
            offset += ext_len;
            break;
        case SSL_HND_HELLO_EXT_SESSION_TICKET_TLS:
            offset = ssl_dissect_hnd_hello_ext_session_ticket(hf, tvb, ext_tree, offset, ext_len, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_CERT_TYPE:
        case SSL_HND_HELLO_EXT_SERVER_CERT_TYPE:
        case SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE:
            offset = ssl_dissect_hnd_hello_ext_cert_type(hf, tvb, ext_tree,
                                                         offset, ext_len,
                                                         hnd_type, ext_type,
                                                         session);
            break;
        case SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET:
            if (ssl){
                switch(hnd_type){
                    case SSL_HND_CLIENT_HELLO:
                        ssl->state |= SSL_CLIENT_EXTENDED_MASTER_SECRET;
                    break;
                    case SSL_HND_SERVER_HELLO:
                        ssl->state |= SSL_SERVER_EXTENDED_MASTER_SECRET;
                    break;
                    default: /* no default */
                    break;
                }
            }
            break;
        default:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_data,
                                        tvb, offset, ext_len, ENC_NA);
            offset += ext_len;
            break;
        }

        left -= 2 + 2 + ext_len;
    }

    return offset;
} /* }}} */


/* ClientKeyExchange algo-specific dissectors. {{{ */

static void
dissect_ssl3_hnd_cli_keyex_ecdh(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint32 length)
{
    gint        point_len;
    proto_tree *ssl_ecdh_tree;

    ssl_ecdh_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                  hf->ett.keyex_params, NULL, "EC Diffie-Hellman Client Params");

    /* point */
    point_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_client_keyex_point_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_client_keyex_point, tvb,
                        offset + 1, point_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cli_keyex_dh(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset, guint32 length)
{
    gint        yc_len;
    proto_tree *ssl_dh_tree;

    ssl_dh_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                hf->ett.keyex_params, NULL, "Diffie-Hellman Client Params");

    /* ClientDiffieHellmanPublic.dh_public (explicit) */
    yc_len  = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_client_keyex_yc_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_client_keyex_yc, tvb,
                        offset + 2, yc_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cli_keyex_rsa(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset,
                               guint32 length, const SslSession *session)
{
    gint        epms_len;
    proto_tree *ssl_rsa_tree;

    ssl_rsa_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "RSA Encrypted PreMaster Secret");

    /* EncryptedPreMasterSecret.pre_master_secret */
    switch (session->version) {
    case SSLV2_VERSION:
    case SSLV3_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        /* OpenSSL pre-0.9.8f DTLS and pre-TLS quirk: 2-octet length vector is
         * not present. The handshake contents represents the EPMS, see:
         * https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=10222 */
        epms_len = length;
        break;

    default:
        /* TLS and DTLS include vector length before EPMS */
        epms_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_client_keyex_epms_len, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;
    }
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_client_keyex_epms, tvb,
                        offset, epms_len, ENC_NA);
}

/* Used in PSK cipher suites */
static void
dissect_ssl3_hnd_cli_keyex_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 length)
{
    guint        identity_len;
    proto_tree *ssl_psk_tree;

    ssl_psk_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "PSK Client Params");
    /* identity */
    identity_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity, tvb,
                        offset + 2, identity_len, ENC_NA);
}

/* Used in RSA PSK cipher suites */
static void
dissect_ssl3_hnd_cli_keyex_rsa_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                   proto_tree *tree, guint32 offset,
                                   guint32 length)
{
    gint        identity_len, epms_len;
    proto_tree *ssl_psk_tree;

    ssl_psk_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "RSA PSK Client Params");

    /* identity */
    identity_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity,
                        tvb, offset + 2, identity_len, ENC_NA);
    offset += 2 + identity_len;

    /* Yc */
    epms_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_epms_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_epms, tvb,
                        offset + 2, epms_len, ENC_NA);
}
/* ClientKeyExchange algo-specific dissectors. }}} */


/* Dissects DigitallySigned (see RFC 5246 4.7 Cryptographic Attributes). {{{ */
static void
ssl_dissect_digitally_signed(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, guint32 offset,
                             const SslSession *session,
                             gint hf_sig_len, gint hf_sig)
{
    gint        sig_len;
    proto_item *ti_algo;
    proto_tree *ssl_algo_tree;

    switch (session->version) {
    case TLSV1DOT2_VERSION:
    case DTLSV1DOT2_VERSION:
    case TLSV1DOT3_VERSION: /* XXX merge both fields into one SignatureScheme? */
        ti_algo = proto_tree_add_item(tree, hf->hf.hs_sig_hash_alg, tvb,
                                      offset, 2, ENC_BIG_ENDIAN);
        ssl_algo_tree = proto_item_add_subtree(ti_algo, hf->ett.hs_sig_hash_alg);

        /* SignatureAndHashAlgorithm { hash, signature } */
        proto_tree_add_item(ssl_algo_tree, hf->hf.hs_sig_hash_hash, tvb,
                            offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ssl_algo_tree, hf->hf.hs_sig_hash_sig, tvb,
                            offset + 1, 1, ENC_BIG_ENDIAN);
        offset += 2;
        break;

    default:
        break;
    }

    /* Sig */
    sig_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_sig_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_sig, tvb, offset + 2, sig_len, ENC_NA);
} /* }}} */

/* ServerKeyExchange algo-specific dissectors. {{{ */

/* dissects signed_params inside a ServerKeyExchange for some keyex algos */
static void
dissect_ssl3_hnd_srv_keyex_sig(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset,
                               const SslSession *session)
{
    /*
     * TLSv1.2 (RFC 5246 sec 7.4.8)
     *  struct {
     *      digitally-signed struct {
     *          opaque handshake_messages[handshake_messages_length];
     *      }
     *  } CertificateVerify;
     *
     * TLSv1.0/TLSv1.1 (RFC 5436 sec 7.4.8 and 7.4.3) works essentially the same
     * as TLSv1.2, but the hash algorithms are not explicit in digitally-signed.
     *
     * SSLv3 (RFC 6101 sec 5.6.8) esseentially works the same as TLSv1.0 but it
     * does more hashing including the master secret and padding.
     */
    ssl_dissect_digitally_signed(hf, tvb, tree, offset, session,
                                 hf->hf.hs_server_keyex_sig_len,
                                 hf->hf.hs_server_keyex_sig);
}

static void
dissect_ssl3_hnd_srv_keyex_ecdh(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint32 length, const SslSession *session,
                                gboolean anon)
{
    /*
     * RFC 4492 ECC cipher suites for TLS
     *
     *  struct {
     *      ECCurveType    curve_type;
     *      select (curve_type) {
     *          case explicit_prime:
     *              ...
     *          case explicit_char2:
     *              ...
     *          case named_curve:
     *              NamedCurve namedcurve;
     *      };
     *  } ECParameters;
     *
     *  struct {
     *      opaque point <1..2^8-1>;
     *  } ECPoint;
     *
     *  struct {
     *      ECParameters    curve_params;
     *      ECPoint         public;
     *  } ServerECDHParams;
     *
     *  select (KeyExchangeAlgorithm) {
     *      case ec_diffie_hellman:
     *          ServerECDHParams    params;
     *          Signature           signed_params;
     *  } ServerKeyExchange;
     */

    gint        curve_type;
    gint        point_len;
    proto_tree *ssl_ecdh_tree;

    ssl_ecdh_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                  hf->ett.keyex_params, NULL, "EC Diffie-Hellman Server Params");

    /* ECParameters.curve_type */
    curve_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_server_keyex_curve_type, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset++;
    if (curve_type != 3)
        return; /* only named_curves are supported */

    /* case curve_type == named_curve; ECParameters.namedcurve */
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_server_keyex_named_curve, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* ECPoint.point */
    point_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_server_keyex_point_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_server_keyex_point, tvb,
                        offset + 1, point_len, ENC_NA);
    offset += 1 + point_len;

    /* Signature (if non-anonymous KEX) */
    if (!anon) {
        dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, ssl_ecdh_tree, offset, session);
    }
}

static void
dissect_ssl3_hnd_srv_keyex_dhe(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 length,
                               const SslSession *session, gboolean anon)
{
    gint        p_len, g_len, ys_len;
    proto_tree *ssl_dh_tree;

    ssl_dh_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                hf->ett.keyex_params, NULL, "Diffie-Hellman Server Params");

    /* p */
    p_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_p_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_p, tvb,
                        offset + 2, p_len, ENC_NA);
    offset += 2 + p_len;

    /* g */
    g_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_g_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_g, tvb,
                        offset + 2, g_len, ENC_NA);
    offset += 2 + g_len;

    /* Ys */
    ys_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(ssl_dh_tree, hf->hf.hs_server_keyex_ys_len, tvb,
                        offset, 2, ys_len);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_ys, tvb,
                        offset + 2, ys_len, ENC_NA);
    offset += 2 + ys_len;

    /* Signature (if non-anonymous KEX) */
    if (!anon) {
        dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, ssl_dh_tree, offset, session);
    }
}

/* Only used in RSA-EXPORT cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_rsa(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 length,
                               const SslSession *session)
{
    gint        modulus_len, exponent_len;
    proto_tree *ssl_rsa_tree;

    ssl_rsa_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "RSA-EXPORT Server Params");

    /* modulus */
    modulus_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_modulus_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_modulus, tvb,
                        offset + 2, modulus_len, ENC_NA);
    offset += 2 + modulus_len;

    /* exponent */
    exponent_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_exponent_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_exponent,
                        tvb, offset + 2, exponent_len, ENC_NA);
    offset += 2 + exponent_len;

    /* Signature */
    dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, ssl_rsa_tree, offset, session);
}

/* Used in RSA PSK and PSK cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 length)
{
    guint        hint_len;
    proto_tree *ssl_psk_tree;

    hint_len = tvb_get_ntohs(tvb, offset);
    if ((2 + hint_len) != length) {
        /* Lengths don't line up (wasn't what we expected?) */
        return;
    }

    ssl_psk_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "PSK Server Params");

    /* hint */
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_server_keyex_hint_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_server_keyex_hint, tvb,
                        offset + 2, hint_len, ENC_NA);
}
/* ServerKeyExchange algo-specific dissectors. }}} */

/* Client Key Exchange and Server Key Exchange handshake dissections. {{{ */
void
ssl_dissect_hnd_cli_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session)
{
    switch (ssl_get_keyex_alg(session->cipher)) {
    case KEX_DH_ANON: /* RFC 5246; DHE_DSS, DHE_RSA, DH_DSS, DH_RSA, DH_ANON: ClientDiffieHellmanPublic */
    case KEX_DH_DSS:
    case KEX_DH_RSA:
    case KEX_DHE_DSS:
    case KEX_DHE_RSA:
        dissect_ssl3_hnd_cli_keyex_dh(hf, tvb, tree, offset, length);
        break;
    case KEX_DHE_PSK: /* RFC 4279; diffie_hellman_psk: psk_identity, ClientDiffieHellmanPublic */
        /* XXX: implement support for DHE_PSK */
        break;
    case KEX_ECDH_ANON: /* RFC 4492; ec_diffie_hellman: ClientECDiffieHellmanPublic */
    case KEX_ECDH_ECDSA:
    case KEX_ECDH_RSA:
    case KEX_ECDHE_ECDSA:
    case KEX_ECDHE_RSA:
        dissect_ssl3_hnd_cli_keyex_ecdh(hf, tvb, tree, offset, length);
        break;
    case KEX_ECDHE_PSK: /* RFC 5489; ec_diffie_hellman_psk: psk_identity, ClientECDiffieHellmanPublic */
        /* XXX: implement support for ECDHE_PSK */
        break;
    case KEX_KRB5: /* RFC 2712; krb5: KerberosWrapper */
        /* XXX: implement support for KRB5 */
        break;
    case KEX_PSK: /* RFC 4279; psk: psk_identity */
        dissect_ssl3_hnd_cli_keyex_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_RSA: /* RFC 5246; rsa: EncryptedPreMasterSecret */
        dissect_ssl3_hnd_cli_keyex_rsa(hf, tvb, tree, offset, length, session);
        break;
    case KEX_RSA_PSK: /* RFC 4279; rsa_psk: psk_identity, EncryptedPreMasterSecret */
        dissect_ssl3_hnd_cli_keyex_rsa_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_SRP_SHA: /* RFC 5054; srp: ClientSRPPublic */
    case KEX_SRP_SHA_DSS:
    case KEX_SRP_SHA_RSA:
        /* XXX: implement support for SRP_SHA* */
        break;
    default:
        /* XXX: add info message for not supported KEX algo */
        break;
    }
}

void
ssl_dissect_hnd_srv_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session)
{
    switch (ssl_get_keyex_alg(session->cipher)) {
    case KEX_DH_ANON: /* RFC 5246; ServerDHParams */
        dissect_ssl3_hnd_srv_keyex_dhe(hf, tvb, tree, offset, length, session, TRUE);
        break;
    case KEX_DH_DSS: /* RFC 5246; not allowed */
    case KEX_DH_RSA:
        /* XXX: add error on not allowed KEX */
        break;
    case KEX_DHE_DSS: /* RFC 5246; dhe_dss, dhe_rsa: ServerDHParams, Signature */
    case KEX_DHE_RSA:
        dissect_ssl3_hnd_srv_keyex_dhe(hf, tvb, tree, offset, length, session, FALSE);
        break;
    case KEX_DHE_PSK: /* RFC 4279; diffie_hellman_psk: psk_identity_hint, ServerDHParams */
        /* XXX: implement support for DHE_PSK */
        break;
    case KEX_ECDH_ANON: /* RFC 4492; ec_diffie_hellman: ServerECDHParams (without signature for anon) */
        dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, tree, offset, length, session, TRUE);
        break;
    case KEX_ECDHE_PSK: /* RFC 5489; psk_identity_hint, ServerECDHParams */
        /* XXX: implement support for ECDHE_PSK */
        break;
    case KEX_ECDH_ECDSA: /* RFC 4492; ec_diffie_hellman: ServerECDHParams, Signature */
    case KEX_ECDH_RSA:
    case KEX_ECDHE_ECDSA:
    case KEX_ECDHE_RSA:
        dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, tree, offset, length, session, FALSE);
        break;
    case KEX_KRB5: /* RFC 2712; not allowed */
        /* XXX: add error on not allowed KEX */
        break;
    case KEX_PSK: /* RFC 4279; psk, rsa: psk_identity*/
    case KEX_RSA_PSK:
        dissect_ssl3_hnd_srv_keyex_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_RSA: /* only allowed if the public key in the server certificate is longer than 512 bits*/
        dissect_ssl3_hnd_srv_keyex_rsa(hf, tvb, tree, offset, length, session);
        break;
    case KEX_SRP_SHA: /* RFC 5054; srp: ServerSRPParams, Signature */
    case KEX_SRP_SHA_DSS:
    case KEX_SRP_SHA_RSA:
        /* XXX: implement support for SRP_SHA* */
        break;
    default:
        /* XXX: add info message for not supported KEX algo */
        break;
    }
}
/* Client Key Exchange and Server Key Exchange handshake dissections. }}} */

#ifdef HAVE_LIBGCRYPT
void
ssl_common_register_options(module_t *module, ssl_common_options_t *options)
{
        prefs_register_string_preference(module, "psk", "Pre-Shared-Key",
             "Pre-Shared-Key as HEX string. Should be 0 to 16 bytes.",
             &(options->psk));

        prefs_register_filename_preference(module, "keylog_file", "(Pre)-Master-Secret log filename",
             "The name of a file which contains a list of \n"
             "(pre-)master secrets in one of the following formats:\n"
             "\n"
             "RSA <EPMS> <PMS>\n"
             "RSA Session-ID:<SSLID> Master-Key:<MS>\n"
             "CLIENT_RANDOM <CRAND> <MS>\n"
             "PMS_CLIENT_RANDOM <CRAND> <PMS>\n"
             "\n"
             "Where:\n"
             "<EPMS> = First 8 bytes of the Encrypted PMS\n"
             "<PMS> = The Pre-Master-Secret (PMS) used to derive the MS\n"
             "<SSLID> = The SSL Session ID\n"
             "<MS> = The Master-Secret (MS)\n"
             "<CRAND> = The Client's random number from the ClientHello message\n"
             "\n"
             "(All fields are in hex notation)",
             &(options->keylog_filename));
}
#else
void
ssl_common_register_options(module_t *module _U_, ssl_common_options_t *options _U_)
{
}
#endif

void
ssl_calculate_handshake_hash(SslDecryptSession *ssl_session, tvbuff_t *tvb, guint32 offset, guint32 length)
{
    if (ssl_session && ssl_session->session.version != TLSV1DOT3_VERSION && !(ssl_session->state & SSL_MASTER_SECRET)) {
        guint32 old_length = ssl_session->handshake_data.data_len;
        ssl_debug_printf("Calculating hash with offset %d %d\n", offset, length);
        ssl_session->handshake_data.data = (guchar *)wmem_realloc(wmem_file_scope(), ssl_session->handshake_data.data, old_length + length);
        tvb_memcpy(tvb, ssl_session->handshake_data.data + old_length, offset, length);
        ssl_session->handshake_data.data_len += length;
    }
}


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
