/* packet-ssl-utils.c
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Copyright (c) 2013, Hauke Mehrtens <hauke@hauke-m.de>
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

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include "packet-ssl-utils.h"
#include "packet-ssl.h"

#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/ipv6-utils.h>
#include <epan/expert.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>

/*
 * Lookup tables
 */
const value_string ssl_version_short_names[] = {
    { SSL_VER_UNKNOWN,    "SSL" },
    { SSL_VER_SSLv2,      "SSLv2" },
    { SSL_VER_SSLv3,      "SSLv3" },
    { SSL_VER_TLS,        "TLSv1" },
    { SSL_VER_TLSv1DOT1,  "TLSv1.1" },
    { SSL_VER_DTLS,       "DTLSv1.0" },
    { SSL_VER_DTLS1DOT2,  "DTLSv1.2" },
    { SSL_VER_DTLS_OPENSSL, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { SSL_VER_PCT,        "PCT" },
    { SSL_VER_TLSv1DOT2,  "TLSv1.2" },
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

    /* http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0x00CC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },

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
    { 0x030080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
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

const value_string ssl_versions[] = {
    { 0xfefd, "DTLS 1.2" },
    { 0xfeff, "DTLS 1.0" },
    { 0x0100, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { 0x0303, "TLS 1.2" },
    { 0x0302, "TLS 1.1" },
    { 0x0301, "TLS 1.0" },
    { 0x0300, "SSL 3.0" },
    { 0x0002, "SSL 2.0" },
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
    {  90,  "User Canceled" },
    { 100, "No Renegotiation" },
    { 110, "Unsupported Extension" },
    { 111, "Certificate Unobtainable" },
    { 112, "Unrecognized Name" },
    { 113, "Bad Certificate Status Response" },
    { 114, "Bad Certificate Hash Value" },
    { 115, "Unknown PSK Identity" },
    { 0x00, NULL }
};

const value_string ssl_31_handshake_type[] = {
    { SSL_HND_HELLO_REQUEST,     "Hello Request" },
    { SSL_HND_CLIENT_HELLO,      "Client Hello" },
    { SSL_HND_SERVER_HELLO,      "Server Hello" },
    { SSL_HND_HELLO_VERIFY_REQUEST, "Hello Verify Request"},
    { SSL_HND_NEWSESSION_TICKET, "New Session Ticket" },
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
    { 0x0000FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* 0x01-BF,* Unassigned */
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

    /* http://www.iana.org/go/draft-mcgrew-tls-aes-ccm-ecc-08 */
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

    /* http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0xCC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },

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
    { SSL_HND_HELLO_EXT_SERVER_NAME, "server_name" }, /* RFC 3546 */
    { 1, "max_fragment_length" },
    { 2, "client_certificate_url" },
    { 3, "trusted_ca_keys" },
    { 4, "truncated_hmac" },
    { SSL_HND_HELLO_EXT_STATUS_REQUEST, "status_request" }, /* RFC 6066 */
    { 6, "user_mapping" },  /* RFC 4681 */
    { 7, "client_authz" },
    { 8, "server_authz" },
    { SSL_HND_HELLO_EXT_CERT_TYPE, "cert_type" },  /* RFC 5081 */
    { SSL_HND_HELLO_EXT_ELLIPTIC_CURVES, "elliptic_curves" },  /* RFC 4492 */
    { SSL_HND_HELLO_EXT_EC_POINT_FORMATS, "ec_point_formats" },  /* RFC 4492 */
    { 12, "srp" },  /* RFC 5054 */
    { 13, "signature_algorithms" },  /* RFC 5246 */
    { 14, "use_srtp" },
    { SSL_HND_HELLO_EXT_HEARTBEAT, "Heartbeat" },  /* RFC 6520 */
    { SSL_HND_HELLO_EXT_ALPN, "Application Layer Protocol Negotiation" }, /* draft-ietf-tls-applayerprotoneg-01 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST_V2, "status_request_v2" }, /* RFC 6961 */
    { 18, "signed_certificate_timestamp" }, /* RFC 6962 */
    { SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE, "client_certificate_type" }, /* http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-11 */
    { SSL_HND_HELLO_EXT_SERVER_CERT_TYPE, "server_certificate_type" }, /* http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-11 */
    { SSL_HND_HELLO_EXT_PADDING, "Padding" }, /* http://tools.ietf.org/html/draft-agl-tls-padding */
    { SSL_HND_HELLO_EXT_SESSION_TICKET, "SessionTicket TLS" },  /* RFC 4507 */
    { SSL_HND_HELLO_EXT_NPN, "next_protocol_negotiation"}, /* http://technotes.googlecode.com/git/nextprotoneg.html */
    { SSL_HND_HELLO_EXT_RENEG_INFO, "renegotiation_info" }, /* RFC 5746 */
    /* http://tools.ietf.org/html/draft-balfanz-tls-channelid-00
       https://twitter.com/ericlaw/status/274237352531083264 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID_OLD, "channel_id_old" },
    /* http://tools.ietf.org/html/draft-balfanz-tls-channelid-01
       https://code.google.com/p/chromium/codesearch#chromium/src/net/third_party/nss/ssl/sslt.h&l=209 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID, "channel_id" },
    { 0, NULL }
};

const value_string tls_hello_ext_server_name_type_vs[] = {
    { 0, "host_name" },
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
    { SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY, "Raw Public Key" }, /* http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-11 */
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

/* we keep this internal to packet-ssl-utils, as there should be
   no need to access it any other way.

   This also allows us to hide the dependency on zlib.
*/
struct _SslDecompress {
    gint compression;
#ifdef HAVE_LIBZ
    z_stream istream;
#endif
};

/* To assist in parsing client/server key exchange messages
   0 indicates unknown */
gint ssl_get_keyex_alg(gint cipher)
{
    switch(cipher) {
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
    case 0xfefe:
    case 0xfeff:
    case 0xffe0:
    case 0xffe1:
        return KEX_RSA;
    case 0x000b:
    case 0x000c:
    case 0x000d:
    case 0x000e:
    case 0x000f:
    case 0x0010:
    case 0x0011:
    case 0x0012:
    case 0x0013:
    case 0x0014:
    case 0x0015:
    case 0x0016:
    case 0x0017:
    case 0x0018:
    case 0x0019:
    case 0x001a:
    case 0x001b:
    case 0x002d:
    case 0x0030:
    case 0x0031:
    case 0x0032:
    case 0x0033:
    case 0x0034:
    case 0x0036:
    case 0x0037:
    case 0x0038:
    case 0x0039:
    case 0x003a:
    case 0x003e:
    case 0x003f:
    case 0x0040:
    case 0x0042:
    case 0x0043:
    case 0x0044:
    case 0x0045:
    case 0x0046:
    case 0x0063:
    case 0x0065:
    case 0x0066:
    case 0x0067:
    case 0x0068:
    case 0x0069:
    case 0x006a:
    case 0x006b:
    case 0x006c:
    case 0x006d:
    case 0x0085:
    case 0x0086:
    case 0x0087:
    case 0x0088:
    case 0x0089:
    case 0x008e:
    case 0x008f:
    case 0x0090:
    case 0x0091:
    case 0x0097:
    case 0x0098:
    case 0x0099:
    case 0x009a:
    case 0x009b:
    case 0x009e:
    case 0x009f:
    case 0x00a0:
    case 0x00a1:
    case 0x00a2:
    case 0x00a3:
    case 0x00a4:
    case 0x00a5:
    case 0x00a6:
    case 0x00a7:
    case 0x00aa:
    case 0x00ab:
    case 0x00b2:
    case 0x00b3:
    case 0x00b4:
    case 0x00b5:
    case 0x00bb:
    case 0x00bc:
    case 0x00bd:
    case 0x00be:
    case 0x00bf:
    case 0x00c1:
    case 0x00c2:
    case 0x00c3:
    case 0x00c4:
    case 0x00c5:
        return KEX_DH;
    case 0xc001:
    case 0xc002:
    case 0xc003:
    case 0xc004:
    case 0xc005:
    case 0xc006:
    case 0xc007:
    case 0xc008:
    case 0xc009:
    case 0xc00a:
    case 0xc00b:
    case 0xc00c:
    case 0xc00d:
    case 0xc00e:
    case 0xc00f:
    case 0xc010:
    case 0xc011:
    case 0xc012:
    case 0xc013:
    case 0xc014:
    case 0xc015:
    case 0xc016:
    case 0xc017:
    case 0xc018:
    case 0xc019:
    case 0xc023:
    case 0xc024:
    case 0xc025:
    case 0xc026:
    case 0xc027:
    case 0xc028:
    case 0xc029:
    case 0xc02a:
    case 0xc02b:
    case 0xc02c:
    case 0xc02d:
    case 0xc02e:
    case 0xc02f:
    case 0xc030:
    case 0xc031:
    case 0xc032:
    case 0xc033:
    case 0xc034:
    case 0xc035:
    case 0xc036:
    case 0xc037:
    case 0xc038:
    case 0xc039:
    case 0xc03a:
    case 0xc03b:
    case 0xc0ac:
    case 0xc0ad:
    case 0xc0ae:
    case 0xc0af:
        return KEX_ECDH;
    case 0x002C:
    case 0x008A:
    case 0x008B:
    case 0x008C:
    case 0x008D:
    case 0x00A8:
    case 0x00A9:
    case 0x00AE:
    case 0x00AF:
    case 0x00B0:
    case 0x00B1:
    case 0xC064:
    case 0xC065:
    case 0xC06A:
    case 0xC06B:
    case 0xC08E:
    case 0xC08F:
    case 0xC094:
    case 0xC095:
    case 0xC0A4:
    case 0xC0A5:
    case 0xC0A8:
    case 0xC0A9:
    case 0xC0AA:
    case 0xC0AB:
        return KEX_PSK;
    case 0x002E:
    case 0x0092:
    case 0x0093:
    case 0x0094:
    case 0x0095:
    case 0x00AC:
    case 0x00AD:
    case 0x00B6:
    case 0x00B7:
    case 0x00B8:
    case 0x00B9:
    case 0xC068:
    case 0xC069:
    case 0xC06E:
    case 0xC06F:
    case 0xC092:
    case 0xC093:
    case 0xC098:
    case 0xC099:
        return KEX_RSA_PSK;
    default:
        break;
    }

    return 0;
}




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


static guint8
from_hex_char(gchar c) {
    /* XXX, ws_xton() */
    if ((c >= '0') && (c <= '9'))
        return c - '0';
    if ((c >= 'A') && (c <= 'F'))
        return c - 'A' + 10;
    if ((c >= 'a') && (c <= 'f'))
        return c - 'a' + 10;
    return 16;
}

/* from_hex converts |hex_len| bytes of hex data from |in| and sets |*out| to
 * the result. |out->data| will be allocated using se_alloc. Returns TRUE on
 * success. */
static gboolean from_hex(StringInfo* out, const char* in, gsize hex_len) {
    gsize i;

    if (hex_len & 1)
        return FALSE;

    out->data_len = (guint)hex_len/2;
    out->data = (guchar *)wmem_alloc(wmem_file_scope(), out->data_len);
    for (i = 0; i < out->data_len; i++) {
        int a = ws_xton(in[i*2]);
        int b = ws_xton(in[i*2 + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        out->data[i] = a << 4 | b;
    }
    return TRUE;
}


#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)

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

/* memory digest abstraction layer*/
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
    gint gcry_modes[]={GCRY_CIPHER_MODE_STREAM,GCRY_CIPHER_MODE_CBC,GCRY_CIPHER_MODE_CTR,GCRY_CIPHER_MODE_CTR,GCRY_CIPHER_MODE_CTR};
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
    err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen (algo));
    if (err != 0)
        return -1;
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

gcry_err_code_t
_gcry_rsa_decrypt (int algo, gcry_mpi_t *result, gcry_mpi_t *data,
                   gcry_mpi_t *skey, gint flags);

/* decrypt data with private key. Store decrypted data directly into input
 * buffer */
static int
ssl_private_decrypt(const guint len, guchar* data, SSL_PRIVATE_KEY* pk)
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

#ifndef SSL_FAST
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

#else /* SSL_FAST */
    rc = _gcry_rsa_decrypt(0, &text,  &encr_mpi, pk,0);
    gcry_mpi_print( GCRYMPI_FMT_USG, 0, 0, &decr_len, text);
#endif /* SSL_FAST */

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
}

/* stringinfo interface */
static gint
ssl_data_realloc(StringInfo* str, guint len)
{
    str->data = (guchar *)g_realloc(str->data, len);
    if (!str->data)
        return -1;
    str->data_len = len;
    return 0;
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
ssl_cipher_suite_dig(SslCipherSuite *cs) {
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

static SslCipherSuite cipher_suites[]={
    {0x0001,KEX_RSA,    ENC_NULL,        1,  0,  0,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
    {0x0002,KEX_RSA,    ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
    {0x0003,KEX_RSA,    ENC_RC4,         1,128, 40,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    {0x0004,KEX_RSA,    ENC_RC4,         1,128,128,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
    {0x0005,KEX_RSA,    ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
    {0x0006,KEX_RSA,    ENC_RC2,         8,128, 40,DIG_MD5,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    {0x0007,KEX_RSA,    ENC_IDEA,        8,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_IDEA_CBC_SHA */
    {0x0008,KEX_RSA,    ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0009,KEX_RSA,    ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_DES_CBC_SHA */
    {0x000A,KEX_RSA,    ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x000B,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x000C,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    {0x000D,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x000E,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x000F,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    {0x0010,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0011,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x0012,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    {0x0013,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x0014,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0015,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    {0x0016,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0017,KEX_DH,     ENC_RC4,         1,128, 40,DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    {0x0018,KEX_DH,     ENC_RC4,         1,128,128,DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
    {0x0019,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    {0x001A,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_DES_CBC_SHA */
    {0x001B,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    {0x002C,KEX_PSK,    ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
    {0x002D,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
    {0x002E,KEX_RSA_PSK,ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
    {0x002F,KEX_RSA,    ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA */
    {0x0030,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    {0x0031,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    {0x0032,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    {0x0033,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    {0x0034,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    {0x0035,KEX_RSA,    ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA */
    {0x0036,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    {0x0037,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    {0x0038,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    {0x0039,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    {0x003A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    {0x003B,KEX_RSA,    ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
    {0x003C,KEX_RSA,    ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    {0x003D,KEX_RSA,    ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    {0x003E,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
    {0x003F,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0040,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    {0x0041,KEX_RSA,    ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0042,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0043,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0044,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0045,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0046,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    {0x0060,KEX_RSA,    ENC_RC4,         1,128, 56,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    {0x0061,KEX_RSA,    ENC_RC2,         1,128, 56,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
    {0x0062,KEX_RSA,    ENC_DES,         8, 64, 56,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0063,KEX_DH,     ENC_DES,         8, 64, 56,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0064,KEX_RSA,    ENC_RC4,         1,128, 56,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    {0x0065,KEX_DH,     ENC_RC4,         1,128, 56,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
    {0x0066,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
    {0x0067,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0068,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
    {0x0069,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
    {0x006B,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006C,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
    {0x006D,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
    {0x0084,KEX_RSA,    ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0085,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0086,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0087,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0088,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0089,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    {0x008A,KEX_PSK,    ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
    {0x008B,KEX_PSK,    ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x008C,KEX_PSK,    ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA */
    {0x008D,KEX_PSK,    ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA */
    {0x008E,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
    {0x008F,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0090,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
    {0x0091,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
    {0x0092,KEX_RSA_PSK,ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    {0x0093,KEX_RSA_PSK,ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0094,KEX_RSA_PSK,ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    {0x0095,KEX_RSA_PSK,ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    {0x0096,KEX_RSA,    ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_SEED_CBC_SHA */
    {0x0097,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    {0x0098,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    {0x0099,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    {0x009A,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
    {0x009B,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
    {0x009C,KEX_RSA,    ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009D,KEX_RSA,    ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    {0x009E,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009F,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A0,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
    {0x00A1,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A2,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A3,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A4,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A5,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A6,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
    {0x00A7,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
    {0x00A8,KEX_PSK,    ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00A9,KEX_PSK,    ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AA,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AB,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AC,KEX_RSA_PSK,ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AD,KEX_RSA_PSK,ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AE,KEX_PSK,    ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00AF,KEX_PSK,    ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B0,KEX_PSK,    ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
    {0x00B1,KEX_PSK,    ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
    {0x00B2,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B3,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B4,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    {0x00B5,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    {0x00B6,KEX_RSA_PSK,ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B7,KEX_RSA_PSK,ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B8,KEX_RSA_PSK,ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    {0x00B9,KEX_RSA_PSK,ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    {0x00BA,KEX_RSA,    ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BB,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BC,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BD,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BE,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BF,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00C0,KEX_RSA,    ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C1,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C2,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C3,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C4,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C5,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */
    {0xC001,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    {0xC002,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    {0xC003,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC004,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC005,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC006,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    {0xC007,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    {0xC008,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC009,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC00A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC00B,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
    {0xC00C,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    {0xC00D,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC00E,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    {0xC00F,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    {0xC010,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    {0xC011,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    {0xC012,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC013,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    {0xC014,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    {0xC015,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
    {0xC016,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    {0xC017,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    {0xC018,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    {0xC019,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    {0xC023,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC024,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC025,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC026,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC027,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC028,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC029,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC02A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC02B,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02C,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02D,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02E,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02F,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC030,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC031,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC032,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC033,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
    {0xC034,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0xC035,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
    {0xC036,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
    {0xC037,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0xC038,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0xC039,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    {0xC03A,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    {0xC03B,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
    {0xC072,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC073,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC074,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC075,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC076,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC077,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC078,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC079,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC07A,KEX_RSA,    ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07B,KEX_RSA,    ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07C,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07D,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07E,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07F,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC080,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC081,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC082,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC083,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC084,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC085,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC086,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC087,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC088,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC089,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08A,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08B,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08C,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08D,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08E,KEX_PSK,    ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08F,KEX_PSK,    ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC090,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC091,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC092,KEX_RSA_PSK,ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC093,KEX_RSA_PSK,ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC094,KEX_PSK,    ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC095,KEX_PSK,    ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC096,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC097,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC098,KEX_RSA_PSK,ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC099,KEX_RSA_PSK,ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09A,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC09B,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09C,KEX_RSA,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_128_CCM */
    {0xC09D,KEX_RSA,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_256_CCM */
    {0xC09E,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_128_CCM */
    {0xC09F,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_256_CCM */
    {0xC0A0,KEX_RSA,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_128_CCM_8 */
    {0xC0A1,KEX_RSA,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_256_CCM_8 */
    {0xC0A2,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
    {0xC0A3,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
    {0xC0A4,KEX_PSK,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_128_CCM */
    {0xC0A5,KEX_PSK,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_256_CCM */
    {0xC0A6,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_128_CCM */
    {0xC0A7,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_256_CCM */
    {0xC0A8,KEX_PSK,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_128_CCM_8 */
    {0xC0A9,KEX_PSK,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_256_CCM_8 */
    {0xC0AA,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
    {0xC0AB,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
    {0xC0AC,KEX_ECDH,   ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    {0xC0AD,KEX_ECDH,   ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
    {0xC0AE,KEX_ECDH,   ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
    {0xC0AF,KEX_ECDH,   ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
    {-1,    0,          0,               0,  0,  0,0,          MODE_STREAM}
};

#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32

int
ssl_find_cipher(int num,SslCipherSuite* cs)
{
    SslCipherSuite *c;

    for(c=cipher_suites;c->number!=-1;c++){
        if(c->number==num){
            *cs=*c;
            return 0;
        }
    }

    return -1;
}

static gint
tls_hash(StringInfo* secret, StringInfo* seed, gint md, StringInfo* out)
{
    guint8   *ptr;
    guint     left;
    gint      tocpy;
    guint8   *A;
    guint8    _A[DIGEST_MAX_SIZE],tmp[DIGEST_MAX_SIZE];
    guint     A_l,tmp_l;
    SSL_HMAC  hm;
    ptr  = out->data;
    left = out->data_len;


    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    A=seed->data;
    A_l=seed->data_len;

    while(left){
        ssl_hmac_init(&hm,secret->data,secret->data_len,md);
        ssl_hmac_update(&hm,A,A_l);
        A_l = sizeof(_A);
        ssl_hmac_final(&hm,_A,&A_l);
        ssl_hmac_cleanup(&hm);
        A=_A;

        ssl_hmac_init(&hm,secret->data,secret->data_len,md);
        ssl_hmac_update(&hm,A,A_l);
        ssl_hmac_update(&hm,seed->data,seed->data_len);
        tmp_l = sizeof(tmp);
        ssl_hmac_final(&hm,tmp,&tmp_l);
        ssl_hmac_cleanup(&hm);

        tocpy=MIN(left,tmp_l);
        memcpy(ptr,tmp,tocpy);
        ptr+=tocpy;
        left-=tocpy;
    }

    ssl_print_string("hash out", out);
    return (0);
}

static gint
tls_prf(StringInfo* secret, const gchar *usage,
        StringInfo* rnd1, StringInfo* rnd2, StringInfo* out)
{
    StringInfo  seed, sha_out, md5_out;
    guint8     *ptr;
    StringInfo  s1, s2;
    guint       i,s_l, r;
    size_t      usage_len;
    r         = -1;
    usage_len = strlen(usage);

    /* initalize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, MAX(out->data_len,20)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
        return -1;
    }
    if (ssl_data_alloc(&md5_out, MAX(out->data_len,16)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2->data_len) < 0) {
        ssl_debug_printf("tls_prf: can't allocate rnd %d\n",
                         (int) (usage_len+rnd1->data_len+rnd2->data_len));
        goto free_md5;
    }

    ptr=seed.data;
    memcpy(ptr,usage,usage_len);
    ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len);
    ptr+=rnd1->data_len;
    memcpy(ptr,rnd2->data,rnd2->data_len);
    /*ptr+=rnd2->data_len;*/

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
    if(tls_hash(&s1,&seed,ssl_get_digest_by_name("MD5"),&md5_out) != 0)
        goto free_all;
    ssl_debug_printf("tls_prf: tls_hash(sha)\n");
    if(tls_hash(&s2,&seed,ssl_get_digest_by_name("SHA1"),&sha_out) != 0)
        goto free_all;

    for(i=0;i<out->data_len;i++)
      out->data[i]=md5_out.data[i] ^ sha_out.data[i];
    r =0;

    ssl_print_string("PRF out",out);
free_all:
    g_free(s2.data);
free_s1:
    g_free(s1.data);
free_seed:
    g_free(seed.data);
free_md5:
    g_free(md5_out.data);
free_sha:
    g_free(sha_out.data);
    return r;
}

static gint
tls12_prf(gint md, StringInfo* secret, const gchar* usage, StringInfo* rnd1, StringInfo* rnd2, StringInfo* out)
{
    StringInfo label_seed;
    size_t     usage_len;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2->data_len) < 0) {
        ssl_debug_printf("tls12_prf: can't allocate label_seed\n");
        return -1;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    ssl_debug_printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);
    if (tls_hash(secret, &label_seed, md, out) != 0){
        g_free(label_seed.data);
        return -1;
    }
    ssl_print_string("PRF out", out);
    return 0;
}

static gint
ssl3_generate_export_iv(StringInfo* r1,
        StringInfo* r2, StringInfo* out)
{
    SSL_MD5_CTX md5;
    guint8      tmp[16];

    ssl_md5_init(&md5);
    ssl_md5_update(&md5,r1->data,r1->data_len);
    ssl_md5_update(&md5,r2->data,r2->data_len);
    ssl_md5_final(tmp,&md5);
    ssl_md5_cleanup(&md5);

    memcpy(out->data,tmp,out->data_len);
    ssl_print_string("export iv", out);

    return(0);
}

static gint
ssl3_prf(StringInfo* secret, const gchar* usage,
        StringInfo* r1,
        StringInfo* r2,StringInfo* out)
{
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;
    StringInfo  *rnd1,*rnd2;
    guint        off;
    gint         i = 0,j;
    guint8       buf[20];

    rnd1=r1; rnd2=r2;

    for(off=0;off<out->data_len;off+=16){
        guchar outbuf[16];
        gint tocpy;
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
            ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
        }
        else{
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
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

        tocpy=MIN(out->data_len-off,16);
        memcpy(out->data+off,outbuf,tocpy);
    }

    return(0);
}

static gint prf(SslDecryptSession* ssl,StringInfo* secret,const gchar* usage,StringInfo* rnd1,StringInfo* rnd2,StringInfo* out)
{
    gint ret;
    if (ssl->version_netorder==SSLV3_VERSION){
        ret = ssl3_prf(secret,usage,rnd1,rnd2,out);
    }else if (ssl->version_netorder==TLSV1_VERSION || ssl->version_netorder==TLSV1DOT1_VERSION ||
            ssl->version_netorder==DTLSV1DOT0_VERSION || ssl->version_netorder==DTLSV1DOT0_VERSION_NOT){
        ret = tls_prf(secret,usage,rnd1,rnd2,out);
    }else{
        if (ssl->cipher_suite.dig == DIG_SHA384){
            ret = tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2, out);
        }else{
            ret = tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2, out);
        }
    }
    return ret;
}

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

#ifdef HAVE_LIBZ
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
#ifdef HAVE_LIBZ
    int err;
#endif

    if (compression == 0) return NULL;
    ssl_debug_printf("ssl_create_decompressor: compression method %d\n", compression);
    decomp = (SslDecompress *)wmem_alloc(wmem_file_scope(), sizeof(SslDecompress));
    decomp->compression = compression;
    switch (decomp->compression) {
#ifdef HAVE_LIBZ
        case 1:  /* DEFLATE */
            decomp->istream.zalloc = ssl_zalloc;
            decomp->istream.zfree = ssl_zfree;
            decomp->istream.opaque = Z_NULL;
            decomp->istream.next_in = Z_NULL;
            decomp->istream.next_out = Z_NULL;
            decomp->istream.avail_in = 0;
            decomp->istream.avail_out = 0;
            err = inflateInit_(&decomp->istream, ZLIB_VERSION, sizeof(z_stream));
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

static SslDecoder*
ssl_create_decoder(SslCipherSuite *cipher_suite, gint compression,
        guint8 *mk, guint8 *sk, guint8 *iv)
{
    SslDecoder *dec;
    gint        ciph;

    dec = (SslDecoder *)wmem_alloc0(wmem_file_scope(), sizeof(SslDecoder));
    /* Find the SSLeay cipher */
    if(cipher_suite->enc!=ENC_NULL) {
        ssl_debug_printf("ssl_create_decoder CIPHER: %s\n", ciphers[cipher_suite->enc-0x30]);
        ciph=ssl_get_cipher_by_name(ciphers[cipher_suite->enc-0x30]);
    } else {
        ssl_debug_printf("ssl_create_decoder CIPHER: %s\n", "NULL");
        ciph = -1;
    }
    if (ciph == 0) {
        ssl_debug_printf("ssl_create_decoder can't find cipher %s\n",
            ciphers[cipher_suite->enc > ENC_NULL ? ENC_NULL-0x30 : (cipher_suite->enc-0x30)]);
        return NULL;
    }

    /* init mac buffer: mac storage is embedded into decoder struct to save a
     memory allocation and waste samo more memory*/
    dec->cipher_suite=cipher_suite;
    dec->compression = compression;
    /* AEED ciphers don't have a MAC but need to keep the write IV instead */
    if (mk == NULL) {
        dec->write_iv.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->write_iv, iv, cipher_suite->block);
    } else {
        dec->mac_key.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->mac_key, mk, ssl_cipher_suite_dig(cipher_suite)->len);
    }
    dec->seq = 0;
    dec->decomp = ssl_create_decompressor(compression);
    dec->flow = ssl_create_flow();

    if (dec->evp)
        ssl_cipher_cleanup(&dec->evp);

    if (ssl_cipher_init(&dec->evp,ciph,sk,iv,cipher_suite->mode) < 0) {
        ssl_debug_printf("ssl_create_decoder: can't create cipher id:%d mode:%d\n",
            ciph, cipher_suite->mode);
        return NULL;
    }

    ssl_debug_printf("decoder initialized (digest len %d)\n", ssl_cipher_suite_dig(cipher_suite)->len);
    return dec;
}


int
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session,
                               guint32 length, tvbuff_t *tvb, guint32 offset,
                               const gchar *ssl_psk, const gchar *keylog_filename)
{
    /* check for required session data */
    ssl_debug_printf("ssl_generate_pre_master_secret: found SSL_HND_CLIENT_KEY_EXCHG, state %X\n",
                     ssl_session->state);
    if ((ssl_session->state & (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) !=
        (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) {
        ssl_debug_printf("ssl_generate_pre_master_secret: not enough data to generate key (required state %X)\n",
                         (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION));
        return -1;
    }

    if (ssl_session->cipher_suite.kex == KEX_PSK)
    {
        /* calculate pre master secret*/
        StringInfo pre_master_secret;
        guint psk_len, pre_master_len;

        if (!ssl_psk || (ssl_psk[0] == 0)) {
            ssl_debug_printf("ssl_generate_pre_master_secret: can't find pre-shared-key\n");
            return -1;
        }

        /* convert hex string into char*/
        if (!from_hex(&ssl_session->psk, ssl_psk, strlen(ssl_psk))) {
            ssl_debug_printf("ssl_generate_pre_master_secret: ssl.psk/dtls.psk contains invalid hex\n");
            return -1;
        }

        psk_len = ssl_session->psk.data_len;
        if (psk_len >= (2 << 15)) {
            ssl_debug_printf("ssl_generate_pre_master_secret: ssl.psk/dtls.psk must not be larger than 2^15 - 1\n");
            return -1;
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
        return 0;
    }
    else
    {
        StringInfo encrypted_pre_master;
        gint ret;
        guint encrlen, skip;
        encrlen = length;
        skip = 0;

        /* get encrypted data, on tls1 we have to skip two bytes
         * (it's the encrypted len and should be equal to record len - 2)
         * in case of rsa1024 that would be 128 + 2 = 130; for psk not necessary
         */
        if (ssl_session->cipher_suite.kex == KEX_RSA &&
           (ssl_session->session.version == SSL_VER_TLS || ssl_session->session.version == SSL_VER_TLSv1DOT1 ||
            ssl_session->session.version == SSL_VER_TLSv1DOT2 || ssl_session->session.version == SSL_VER_DTLS ||
            ssl_session->session.version == SSL_VER_DTLS1DOT2))
        {
            encrlen  = tvb_get_ntohs(tvb, offset);
            skip = 2;
            if (encrlen > length - 2)
            {
                ssl_debug_printf("ssl_generate_pre_master_secret: wrong encrypted length (%d max %d)\n",
                    encrlen, length);
                return -1;
            }
        }
        encrypted_pre_master.data = (guchar *)wmem_alloc(wmem_file_scope(), encrlen);
        encrypted_pre_master.data_len = encrlen;
        tvb_memcpy(tvb, encrypted_pre_master.data, offset+skip, encrlen);

        if (ssl_session->private_key) {
            /* go with ssl key processessing; encrypted_pre_master
             * will be used for master secret store*/
            ret = ssl_decrypt_pre_master_secret(ssl_session, &encrypted_pre_master, ssl_session->private_key);
            if (ret>=0)
                return 0;

            ssl_debug_printf("ssl_generate_pre_master_secret: can't decrypt pre master secret\n");
        }

        if (keylog_filename != NULL) {
            /* try to find the key in the key log */
            ret = ssl_keylog_lookup(ssl_session, keylog_filename, &encrypted_pre_master);
            if (ret>=0)
                return 0;
        }
    }
    return -1;
}

int
ssl_generate_keyring_material(SslDecryptSession*ssl_session)
{
    StringInfo  key_block;
    guint8      _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];
    guint8      _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    gint        needed;
    guint8     *ptr,*c_wk,*s_wk,*c_mk,*s_mk,*c_iv = _iv_c,*s_iv = _iv_s;

    /* check for enough info to proced */
    guint need_all = SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION;
    guint need_any = SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;
    if (((ssl_session->state & need_all) != need_all) || ((ssl_session->state & need_any) == 0)) {
        ssl_debug_printf("ssl_generate_keyring_material not enough data to generate key "
                         "(0x%02X required 0x%02X or 0x%02X)\n", ssl_session->state,
                         need_all|SSL_MASTER_SECRET, need_all|SSL_PRE_MASTER_SECRET);
        return -1;
    }

    /* if master_key is not yet generate, create it now*/
    if (!(ssl_session->state & SSL_MASTER_SECRET)) {
        ssl_debug_printf("ssl_generate_keyring_material:PRF(pre_master_secret)\n");
        ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
        ssl_print_string("client random",&ssl_session->client_random);
        ssl_print_string("server random",&ssl_session->server_random);
        if (prf(ssl_session,&ssl_session->pre_master_secret,"master secret",
                &ssl_session->client_random,
                &ssl_session->server_random, &ssl_session->master_secret)) {
            ssl_debug_printf("ssl_generate_keyring_material can't generate master_secret\n");
            return -1;
        }
        ssl_print_string("master secret",&ssl_session->master_secret);

        /* the pre-master secret has been 'consumend' so we must clear it now */
        ssl_session->state &= ~SSL_PRE_MASTER_SECRET;
        ssl_session->state |= SSL_MASTER_SECRET;
    }

    /* Compute the key block. First figure out how much data we need*/
    needed=ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len*2;
    needed+=ssl_session->cipher_suite.bits / 4;
    if(ssl_session->cipher_suite.block>1)
        needed+=ssl_session->cipher_suite.block*2;

    key_block.data_len = needed;
    key_block.data = (guchar *)g_malloc(needed);
    ssl_debug_printf("ssl_generate_keyring_material sess key generation\n");
    if (prf(ssl_session,&ssl_session->master_secret,"key expansion",
            &ssl_session->server_random,&ssl_session->client_random,
            &key_block)) {
        ssl_debug_printf("ssl_generate_keyring_material can't generate key_block\n");
        goto fail;
    }
    ssl_print_string("key expansion", &key_block);

    ptr=key_block.data;
    /* AEAD ciphers do not have a separate MAC */
    if (ssl_session->cipher_suite.mode == MODE_GCM ||
        ssl_session->cipher_suite.mode == MODE_CCM ||
        ssl_session->cipher_suite.mode == MODE_CCM_8) {
        c_mk = s_mk = NULL;
    } else {
        c_mk=ptr; ptr+=ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len;
        s_mk=ptr; ptr+=ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len;
    }

    c_wk=ptr; ptr+=ssl_session->cipher_suite.eff_bits/8;
    s_wk=ptr; ptr+=ssl_session->cipher_suite.eff_bits/8;

    if(ssl_session->cipher_suite.block>1){
        c_iv=ptr; ptr+=ssl_session->cipher_suite.block;
        s_iv=ptr; /*ptr+=ssl_session->cipher_suite.block;*/
    }

    /* export ciphers work with a smaller key length */
    if (ssl_session->cipher_suite.eff_bits < ssl_session->cipher_suite.bits) {
        StringInfo iv_c,iv_s;
        StringInfo key_c,key_s;
        StringInfo k;

        if(ssl_session->cipher_suite.block>1){

            /* We only have room for MAX_BLOCK_SIZE bytes IVs, but that's
             all we should need. This is a sanity check */
            if(ssl_session->cipher_suite.block>MAX_BLOCK_SIZE) {
                ssl_debug_printf("ssl_generate_keyring_material cipher suite block must be at most %d nut is %d\n",
                    MAX_BLOCK_SIZE, ssl_session->cipher_suite.block);
                goto fail;
            }

            iv_c.data = _iv_c;
            iv_c.data_len = ssl_session->cipher_suite.block;
            iv_s.data = _iv_s;
            iv_s.data_len = ssl_session->cipher_suite.block;

            if(ssl_session->version_netorder==SSLV3_VERSION){
                ssl_debug_printf("ssl_generate_keyring_material ssl3_generate_export_iv\n");
                if (ssl3_generate_export_iv(&ssl_session->client_random,
                        &ssl_session->server_random,&iv_c)) {
                    ssl_debug_printf("ssl_generate_keyring_material can't generate sslv3 client iv\n");
                    goto fail;
                }
                ssl_debug_printf("ssl_generate_keyring_material ssl3_generate_export_iv(2)\n");
                if (ssl3_generate_export_iv(&ssl_session->server_random,
                        &ssl_session->client_random,&iv_s)) {
                    ssl_debug_printf("ssl_generate_keyring_material can't generate sslv3 server iv\n");
                    goto fail;
                }
            }
            else{
                guint8 _iv_block[MAX_BLOCK_SIZE * 2];
                StringInfo iv_block;
                StringInfo key_null;
                guint8 _key_null;

                key_null.data = &_key_null;
                key_null.data_len = 0;

                iv_block.data = _iv_block;
                iv_block.data_len = ssl_session->cipher_suite.block*2;

                ssl_debug_printf("ssl_generate_keyring_material prf(iv_block)\n");
                if(prf(ssl_session,&key_null, "IV block",
                        &ssl_session->client_random,
                        &ssl_session->server_random,&iv_block)) {
                    ssl_debug_printf("ssl_generate_keyring_material can't generate tls31 iv block\n");
                    goto fail;
                }

                memcpy(_iv_c,iv_block.data,ssl_session->cipher_suite.block);
                memcpy(_iv_s,iv_block.data+ssl_session->cipher_suite.block,
                    ssl_session->cipher_suite.block);
            }

            c_iv=_iv_c;
            s_iv=_iv_s;
        }

        if (ssl_session->version_netorder==SSLV3_VERSION){

            SSL_MD5_CTX md5;
            ssl_debug_printf("ssl_generate_keyring_material MD5(client_random)\n");

            ssl_md5_init(&md5);
            ssl_md5_update(&md5,c_wk,ssl_session->cipher_suite.eff_bits/8);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                ssl_session->client_random.data_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                ssl_session->server_random.data_len);
            ssl_md5_final(_key_c,&md5);
            ssl_md5_cleanup(&md5);
            c_wk=_key_c;

            ssl_md5_init(&md5);
            ssl_debug_printf("ssl_generate_keyring_material MD5(server_random)\n");
            ssl_md5_update(&md5,s_wk,ssl_session->cipher_suite.eff_bits/8);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                ssl_session->server_random.data_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                ssl_session->client_random.data_len);
            ssl_md5_final(_key_s,&md5);
            ssl_md5_cleanup(&md5);
            s_wk=_key_s;
        }
        else{
            key_c.data = _key_c;
            key_c.data_len = sizeof(_key_c);
            key_s.data = _key_s;
            key_s.data_len = sizeof(_key_s);

            k.data = c_wk;
            k.data_len = ssl_session->cipher_suite.eff_bits/8;
            ssl_debug_printf("ssl_generate_keyring_material PRF(key_c)\n");
            if (prf(ssl_session,&k,"client write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_c)) {
                ssl_debug_printf("ssl_generate_keyring_material can't generate tll31 server key \n");
                goto fail;
            }
            c_wk=_key_c;

            k.data = s_wk;
            k.data_len = ssl_session->cipher_suite.eff_bits/8;
            ssl_debug_printf("ssl_generate_keyring_material PRF(key_s)\n");
            if(prf(ssl_session,&k,"server write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_s)) {
                ssl_debug_printf("ssl_generate_keyring_material can't generate tll31 client key \n");
                goto fail;
            }
            s_wk=_key_s;
        }
    }

    /* show key material info */
    if (c_mk != NULL) {
        ssl_print_data("Client MAC key",c_mk,ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len);
        ssl_print_data("Server MAC key",s_mk,ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len);
    }
    ssl_print_data("Client Write key",c_wk,ssl_session->cipher_suite.bits/8);
    ssl_print_data("Server Write key",s_wk,ssl_session->cipher_suite.bits/8);

    if(ssl_session->cipher_suite.block>1) {
        ssl_print_data("Client Write IV",c_iv,ssl_session->cipher_suite.block);
        ssl_print_data("Server Write IV",s_iv,ssl_session->cipher_suite.block);
    }
    else {
        ssl_print_data("Client Write IV",c_iv,8);
        ssl_print_data("Server Write IV",s_iv,8);
    }

    /* create both client and server ciphers*/
    ssl_debug_printf("ssl_generate_keyring_material ssl_create_decoder(client)\n");
    ssl_session->client_new = ssl_create_decoder(&ssl_session->cipher_suite, ssl_session->session.compression, c_mk, c_wk, c_iv);
    if (!ssl_session->client_new) {
        ssl_debug_printf("ssl_generate_keyring_material can't init client decoder\n");
        goto fail;
    }
    ssl_debug_printf("ssl_generate_keyring_material ssl_create_decoder(server)\n");
    ssl_session->server_new = ssl_create_decoder(&ssl_session->cipher_suite, ssl_session->session.compression, s_mk, s_wk, s_iv);
    if (!ssl_session->server_new) {
        ssl_debug_printf("ssl_generate_keyring_material can't init client decoder\n");
        goto fail;
    }

    ssl_debug_printf("ssl_generate_keyring_material: client seq %d, server seq %d\n",
        ssl_session->client_new->seq, ssl_session->server_new->seq);
    g_free(key_block.data);
    ssl_session->state |= SSL_HAVE_SESSION_KEY;
    return 0;

fail:
    g_free(key_block.data);
    return -1;
}

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

int
ssl_decrypt_pre_master_secret(SslDecryptSession*ssl_session,
    StringInfo* encrypted_pre_master, SSL_PRIVATE_KEY *pk)
{
    gint i;

    if (!encrypted_pre_master)
        return -1;

    if(ssl_session->cipher_suite.kex == KEX_DH) {
        ssl_debug_printf("ssl_decrypt_pre_master_secret session uses DH (%d) key exchange, which is impossible to decrypt\n",
            KEX_DH);
        return -1;
    } else if(ssl_session->cipher_suite.kex != KEX_RSA) {
         ssl_debug_printf("ssl_decrypt_pre_master_secret key exchange %d different from KEX_RSA (%d)\n",
            ssl_session->cipher_suite.kex, KEX_RSA);
        return -1;
    }

    /* with tls key loading will fail if not rsa type, so no need to check*/
    ssl_print_string("pre master encrypted",encrypted_pre_master);
    ssl_debug_printf("ssl_decrypt_pre_master_secret:RSA_private_decrypt\n");
    i=ssl_private_decrypt(encrypted_pre_master->data_len,
        encrypted_pre_master->data, pk);

    if (i!=48) {
        ssl_debug_printf("ssl_decrypt_pre_master_secret wrong "
            "pre_master_secret length (%d, expected %d)\n", i, 48);
        return -1;
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
    return 0;
}

/* convert network byte order 32 byte number to right-aligned host byte order *
 * 8 bytes buffer */
static gint fmt_seq(guint32 num, guint8* buf)
{
    guint32 netnum;

    memset(buf,0,8);
    netnum=g_htonl(num);
    memcpy(buf+4,&netnum,4);

    return(0);
}

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
    fmt_seq(decoder->seq,buf);

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
    fmt_seq(decoder->seq,buf);
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
    ssl_debug_printf("dtls_check_mac seq: %d epoch: %d\n",decoder->seq,decoder->epoch);
    /* hash sequence number */
    fmt_seq(decoder->seq,buf);
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

#ifdef HAVE_LIBZ
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
            decomp->istream.next_in = (guchar*)in;
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

int
ssl_decrypt_record(SslDecryptSession*ssl,SslDecoder* decoder, gint ct,
        const guchar* in, guint inl, StringInfo* comp_str, StringInfo* out_str, guint* outl)
{
    guint   pad, worklen, uncomplen;
    guint8 *mac;

    ssl_debug_printf("ssl_decrypt_record ciphertext len %d\n", inl);
    ssl_print_data("Ciphertext",in, inl);

    /* ensure we have enough storage space for decrypted data */
    if (inl > out_str->data_len)
    {
        ssl_debug_printf("ssl_decrypt_record: allocating %d bytes for decrypt data (old len %d)\n",
                inl + 32, out_str->data_len);
        ssl_data_realloc(out_str, inl + 32);
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
        switch (ssl->version_netorder) {
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
        case DTLSV1DOT0_VERSION:
        case DTLSV1DOT2_VERSION:
        case DTLSV1DOT0_VERSION_NOT:
            if ((gint)inl < decoder->cipher_suite->block) {
                ssl_debug_printf("ssl_decrypt_record failed: input %d has no space for IV %d\n",
                        inl, decoder->cipher_suite->block);
                return -1;
            }
            pad = gcry_cipher_setiv(decoder->evp, in, decoder->cipher_suite->block);
            if (pad != 0) {
                ssl_debug_printf("ssl_decrypt_record failed: failed to set IV: %s %s\n",
                        gcry_strsource (pad), gcry_strerror (pad));
            }

            inl -= decoder->cipher_suite->block;
            in += decoder->cipher_suite->block;
            break;
        }
    }

    /* Nonce for GenericAEADCipher */
    if (decoder->cipher_suite->mode == MODE_GCM ||
        decoder->cipher_suite->mode == MODE_CCM ||
        decoder->cipher_suite->mode == MODE_CCM_8) {
        /* 4 bytes write_iv, 8 bytes explicit_nonce, 4 bytes counter */
        guchar gcm_nonce[16] = { 0 };

        if ((gint)inl < SSL_EX_NONCE_LEN_GCM) {
            ssl_debug_printf("ssl_decrypt_record failed: input %d has no space for nonce %d\n",
                inl, SSL_EX_NONCE_LEN_GCM);
            return -1;
        }

        if (decoder->cipher_suite->mode == MODE_GCM) {
            memcpy(gcm_nonce, decoder->write_iv.data, decoder->write_iv.data_len); /* salt */
            memcpy(gcm_nonce + decoder->write_iv.data_len, in, SSL_EX_NONCE_LEN_GCM);
            /* NIST SP 800-38D, sect. 7.2 says that the 32-bit counter part starts
             * at 1, and gets incremented before passing to the block cipher. */
            gcm_nonce[4 + SSL_EX_NONCE_LEN_GCM + 3] = 2;
        } else { /* MODE_CCM and MODE_CCM_8 */
            /* The nonce for CCM and GCM are the same, but the nonce is used as input
             * in the CCM algorithm described in RFC 3610. The nonce generated here is
             * the one from RFC 3610 sect 2.3. Encryption. */
            /* Flags: (L-1) ; L = 16 - 1 - nonceSize */
            gcm_nonce[0] = 3 - 1;

            memcpy(gcm_nonce + 1, decoder->write_iv.data, decoder->write_iv.data_len); /* salt */
            memcpy(gcm_nonce + 1 + decoder->write_iv.data_len, in, SSL_EX_NONCE_LEN_GCM);
            gcm_nonce[4 + SSL_EX_NONCE_LEN_GCM + 3] = 1;
        }

        pad = gcry_cipher_setctr (decoder->evp, gcm_nonce, sizeof (gcm_nonce));
        if (pad != 0) {
            ssl_debug_printf("ssl_decrypt_record failed: failed to set CTR: %s %s\n",
                    gcry_strsource (pad), gcry_strerror (pad));
            return -1;
        }
        inl -= SSL_EX_NONCE_LEN_GCM;
        in += SSL_EX_NONCE_LEN_GCM;
    }

    /* First decrypt*/
    if ((pad = ssl_cipher_decrypt(&decoder->evp, out_str->data, out_str->data_len, in, inl))!= 0) {
        ssl_debug_printf("ssl_decrypt_record failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
                    gcry_strerror (pad));
        return -1;
    }

    ssl_print_data("Plaintext", out_str->data, inl);
    worklen=inl;

    /* RFC 5116 sect 5.1/5.3: AES128/256 GCM/CCM uses 16 bytes for auth tag
     * RFC 6655 sect 6.1: AEAD_AES_128_CCM uses 16 bytes for auth tag */
    if (decoder->cipher_suite->mode == MODE_GCM ||
        decoder->cipher_suite->mode == MODE_CCM) {
        if (worklen < 16) {
            ssl_debug_printf("ssl_decrypt_record failed: missing tag, work %d\n", worklen);
            return -1;
        }
        /* XXX - validate auth tag */
        worklen -= 16;
    }
    /* RFC 6655 sect 6.1: AEAD_AES_128_CCM_8 uses 8 bytes for auth tag */
    if (decoder->cipher_suite->mode == MODE_CCM_8) {
        if (worklen < 8) {
            ssl_debug_printf("ssl_decrypt_record failed: missing tag, work %d\n", worklen);
            return -1;
        }
        /* XXX - validate auth tag */
        worklen -= 8;
    }

    /* strip padding for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
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
    if (decoder->cipher_suite->mode == MODE_STREAM ||
        decoder->cipher_suite->mode == MODE_CBC) {
        if (ssl_cipher_suite_dig(decoder->cipher_suite)->len > (gint)worklen) {
            ssl_debug_printf("ssl_decrypt_record wrong record len/padding outlen %d\n work %d\n",*outl, worklen);
            return -1;
        }
        worklen-=ssl_cipher_suite_dig(decoder->cipher_suite)->len;
        mac = out_str->data + worklen;
    } else /* if (decoder->cipher_suite->mode == MODE_GCM) */ {
        /* GenericAEADCipher has no MAC */
        goto skip_mac;
    }

    /* Now check the MAC */
    ssl_debug_printf("checking mac (len %d, version %X, ct %d seq %d)\n",
        worklen, ssl->version_netorder, ct, decoder->seq);
    if(ssl->version_netorder==SSLV3_VERSION){
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
    else if(ssl->version_netorder==TLSV1_VERSION || ssl->version_netorder==TLSV1DOT1_VERSION || ssl->version_netorder==TLSV1DOT2_VERSION){
        if(tls_check_mac(decoder,ct,ssl->version_netorder,out_str->data,worklen,mac)< 0) {
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
    else if(ssl->version_netorder==DTLSV1DOT0_VERSION ||
        ssl->version_netorder==DTLSV1DOT2_VERSION ||
        ssl->version_netorder==DTLSV1DOT0_VERSION_NOT){
        /* Try rfc-compliant mac first, and if failed, try old openssl's non-rfc-compliant mac */
        if(dtls_check_mac(decoder,ct,ssl->version_netorder,out_str->data,worklen,mac)>= 0) {
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

#define RSA_PARS 6
static SSL_PRIVATE_KEY*
ssl_privkey_to_sexp(struct gnutls_x509_privkey_int* priv_key)
{
    gnutls_datum_t rsa_datum[RSA_PARS]; /* m, e, d, p, q, u */
    size_t         tmp_size;
    gcry_sexp_t    rsa_priv_key = NULL;
    gint           i;
    int            ret;
    size_t         buf_len;
    unsigned char  buf_keyid[32];

#ifdef SSL_FAST
    gcry_mpi_t* rsa_params = g_malloc(sizeof(gcry_mpi_t)*RSA_PARS);
#else
    gcry_mpi_t rsa_params[RSA_PARS];
#endif

    buf_len = sizeof(buf_keyid);
    ret = gnutls_x509_privkey_get_key_id(priv_key, 0, buf_keyid, &buf_len);
    if (ret != 0) {
        ssl_debug_printf( "gnutls_x509_privkey_get_key_id(ssl_pkey, 0, buf_keyid, &buf_len) - %s\n", gnutls_strerror(ret));
    } else {
        ssl_debug_printf( "Private key imported: KeyID %s\n", bytes_to_ep_str_punct(buf_keyid, (int) buf_len, ':'));
    }

    /* RSA get parameter */
    if (gnutls_x509_privkey_export_rsa_raw(priv_key,
                                           &rsa_datum[0],
                                           &rsa_datum[1],
                                           &rsa_datum[2],
                                           &rsa_datum[3],
                                           &rsa_datum[4],
                                           &rsa_datum[5])  != 0) {
        ssl_debug_printf("ssl_load_key: can't export rsa param (is a rsa private key file ?!?)\n");
#ifdef SSL_FAST
        g_free(rsa_params);
#endif
        return NULL;
    }

    /* convert each rsa parameter to mpi format*/
    for(i=0; i<RSA_PARS; i++) {
      if (gcry_mpi_scan(&rsa_params[i], GCRYMPI_FMT_USG, rsa_datum[i].data, rsa_datum[i].size,&tmp_size) != 0) {
        ssl_debug_printf("ssl_load_key: can't convert m rsa param to int (size %d)\n", rsa_datum[i].size);
#ifdef SSL_FAST
        g_free(rsa_params);
#endif
        return NULL;
      }
    }

    /* libgcrypt expects p < q, and gnutls might not return it as such, depending on gnutls version and its crypto backend */
    if (gcry_mpi_cmp(rsa_params[3], rsa_params[4]) > 0)
    {
        ssl_debug_printf("ssl_load_key: swapping p and q parameters and recomputing u\n");
        gcry_mpi_swap(rsa_params[3], rsa_params[4]);
        gcry_mpi_invm(rsa_params[5], rsa_params[3], rsa_params[4]);
    }

    if  (gcry_sexp_build( &rsa_priv_key, NULL,
            "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))", rsa_params[0],
            rsa_params[1], rsa_params[2], rsa_params[3], rsa_params[4],
            rsa_params[5]) != 0) {
        ssl_debug_printf("ssl_load_key: can't build rsa private key s-exp\n");
#ifdef SSL_FAST
        g_free(rsa_params);
#endif
        return NULL;
    }

#ifdef SSL_FAST
    return rsa_params;
#else
    for (i=0; i< 6; i++)
        gcry_mpi_release(rsa_params[i]);
    return rsa_priv_key;
#endif

}

Ssl_private_key_t *
ssl_load_key(FILE* fp)
{
    /* gnutls makes our work much harder, since we have to work internally with
     * s-exp formatted data, but PEM loader exports only in "gnutls_datum_t"
     * format, and a datum -> s-exp convertion function does not exist.
     */
    gnutls_x509_privkey_t priv_key;
    gnutls_datum_t        key;
    long                  size;
    gint                  ret;
    guint                 bytes;

    Ssl_private_key_t *private_key = (Ssl_private_key_t *)g_malloc0(sizeof(Ssl_private_key_t));

    /* init private key data*/
    gnutls_x509_privkey_init(&priv_key);

    /* compute file size and load all file contents into a datum buffer*/
    if (fseek(fp, 0, SEEK_END) < 0) {
        ssl_debug_printf("ssl_load_key: can't fseek file\n");
        g_free(private_key);
        return NULL;
    }
    if ((size = ftell(fp)) < 0) {
        ssl_debug_printf("ssl_load_key: can't ftell file\n");
        g_free(private_key);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) < 0) {
        ssl_debug_printf("ssl_load_key: can't re-fseek file\n");
        g_free(private_key);
        return NULL;
    }
    key.data = (unsigned char *)g_malloc(size);
    key.size = (int)size;
    bytes = (guint) fread(key.data, 1, key.size, fp);
    if (bytes < key.size) {
        ssl_debug_printf("ssl_load_key: can't read from file %d bytes, got %d\n",
            key.size, bytes);
        g_free(private_key);
        g_free(key.data);
        return NULL;
    }

    /* import PEM data*/
    if ((ret = gnutls_x509_privkey_import(priv_key, &key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
        ssl_debug_printf("ssl_load_key: can't import pem data: %s\n", gnutls_strerror(ret));
        g_free(private_key);
        g_free(key.data);
        return NULL;
    }

    if (gnutls_x509_privkey_get_pk_algorithm(priv_key) != GNUTLS_PK_RSA) {
        ssl_debug_printf("ssl_load_key: private key public key algorithm isn't RSA\n");
        g_free(private_key);
        g_free(key.data);
        return NULL;
    }

    g_free(key.data);

    private_key->x509_pkey = priv_key;
    private_key->sexp_pkey = ssl_privkey_to_sexp(priv_key);
    if ( !private_key->sexp_pkey ) {
        g_free(private_key);
        return NULL;
    }
    return private_key;
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
static Ssl_private_key_t *
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd, char** err) {

    int                       i, j, ret;
    int                       rest;
    unsigned char            *p;
    gnutls_datum_t            data;
    gnutls_pkcs12_bag_t       bag = NULL;
    gnutls_pkcs12_bag_type_t  bag_type;
    size_t                    len, buf_len;
    static char               buf_name[256];
    static char               buf_email[128];
    unsigned char             buf_keyid[32];

    gnutls_pkcs12_t       ssl_p12  = NULL;
    gnutls_x509_crt_t     ssl_cert = NULL;
    gnutls_x509_privkey_t ssl_pkey = NULL;

    Ssl_private_key_t *private_key = (Ssl_private_key_t *)g_malloc0(sizeof(Ssl_private_key_t));
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
        g_free(private_key);
        g_free(data.data);
        return 0;
    }

    ret = gnutls_pkcs12_init(&ssl_p12);
    if (ret < 0) {
        *err = g_strdup_printf("gnutls_pkcs12_init(&st_p12) - %s", gnutls_strerror(ret));
        ssl_debug_printf("%s\n", *err);
        g_free(private_key);
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
        g_free(private_key);
        return 0;
    }

    ssl_debug_printf( "PKCS#12 imported\n");

    for (i=0; ret==0; i++) {

        if (bag) { gnutls_pkcs12_bag_deinit(bag); bag = NULL; }

        ret = gnutls_pkcs12_bag_init(&bag);
        if (ret < 0) continue;

        ret = gnutls_pkcs12_get_bag(ssl_p12, i, bag);
        if (ret < 0) continue;

        for (j=0; ret==0 && j<gnutls_pkcs12_bag_get_count(bag); j++) {

            bag_type = gnutls_pkcs12_bag_get_type(bag, j);
            if (bag_type >= GNUTLS_BAG_UNKNOWN) continue;
            ssl_debug_printf( "Bag %d/%d: %s\n", i, j, BAGTYPE(bag_type));
            if (bag_type == GNUTLS_BAG_ENCRYPTED) {
                ret = gnutls_pkcs12_bag_decrypt(bag, cert_passwd);
                if (ret == 0) {
                    bag_type = gnutls_pkcs12_bag_get_type(bag, j);
                    if (bag_type >= GNUTLS_BAG_UNKNOWN) continue;
                    ssl_debug_printf( "Bag %d/%d decrypted: %s\n", i, j, BAGTYPE(bag_type));
                }
            }

            ret = gnutls_pkcs12_bag_get_data(bag, j, &data);
            if (ret < 0) continue;

            switch (bag_type) {

                case GNUTLS_BAG_CERTIFICATE:

                    ret = gnutls_x509_crt_init(&ssl_cert);
                    if (ret < 0) {
                        *err = g_strdup_printf("gnutls_x509_crt_init(&ssl_cert) - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        g_free(private_key);
                        return 0;
                    }

                    ret = gnutls_x509_crt_import(ssl_cert, &data, GNUTLS_X509_FMT_DER);
                    if (ret < 0) {
                        *err = g_strdup_printf("gnutls_x509_crt_import(ssl_cert, &data, GNUTLS_X509_FMT_DER) - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        g_free(private_key);
                        return 0;
                    }

                    buf_len = sizeof(buf_name);
                    ret = gnutls_x509_crt_get_dn_by_oid(ssl_cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf_name, &buf_len);
                    if (ret < 0) { g_strlcpy(buf_name, "<ERROR>", 256); }
                    buf_len = sizeof(buf_email);
                    ret = gnutls_x509_crt_get_dn_by_oid(ssl_cert, GNUTLS_OID_PKCS9_EMAIL, 0, 0, buf_email, &buf_len);
                    if (ret < 0) { g_strlcpy(buf_email, "<ERROR>", 128); }

                    buf_len = sizeof(buf_keyid);
                    ret = gnutls_x509_crt_get_key_id(ssl_cert, 0, buf_keyid, &buf_len);
                    if (ret < 0) { g_strlcpy(buf_keyid, "<ERROR>", 32); }

                    private_key->x509_cert = ssl_cert;
                    ssl_debug_printf( "Certificate imported: %s <%s>, KeyID %s\n", buf_name, buf_email, bytes_to_ep_str(buf_keyid, (int) buf_len));
                    break;

                case GNUTLS_BAG_PKCS8_KEY:
                case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:

                    ret = gnutls_x509_privkey_init(&ssl_pkey);
                    if (ret < 0) {
                        *err = g_strdup_printf("gnutls_x509_privkey_init(&ssl_pkey) - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        g_free(private_key);
                        return 0;
                    }
                    ret = gnutls_x509_privkey_import_pkcs8(ssl_pkey, &data, GNUTLS_X509_FMT_DER, cert_passwd,
                                                           (bag_type==GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
                    if (ret < 0) {
                        *err = g_strdup_printf("Can not decrypt private key - %s", gnutls_strerror(ret));
                        ssl_debug_printf("%s\n", *err);
                        g_free(private_key);
                        return 0;
                    }

                    if (gnutls_x509_privkey_get_pk_algorithm(ssl_pkey) != GNUTLS_PK_RSA) {
                        *err = g_strdup("ssl_load_pkcs12: private key public key algorithm isn't RSA");
                        ssl_debug_printf("%s\n", *err);
                        g_free(private_key);
                        return 0;
                    }

                    private_key->x509_pkey = ssl_pkey;
                    private_key->sexp_pkey = ssl_privkey_to_sexp(ssl_pkey);
                    if ( !private_key->sexp_pkey ) {
                        *err = g_strdup("ssl_load_pkcs12: could not create sexp_pkey");
                        ssl_debug_printf("%s\n", *err);
                        g_free(private_key);
                        return NULL;
                    }
                    break;

                default: ;
            }
        }  /* j */
    }  /* i */

    return private_key;
}


void ssl_free_key(Ssl_private_key_t* key)
{
#ifdef SSL_FAST
    gint i;
    for (i=0; i< 6; i++)
        gcry_mpi_release(key->sexp_pkey[i]);
#else
    gcry_sexp_release(key->sexp_pkey);
#endif

    if (!key->x509_cert)
        gnutls_x509_crt_deinit (key->x509_cert);

    if (!key->x509_pkey)
        gnutls_x509_privkey_deinit(key->x509_pkey);

    g_free((Ssl_private_key_t*)key);
}

void
ssl_find_private_key(SslDecryptSession *ssl_session, GHashTable *key_hash, GTree* associations, packet_info *pinfo) {
    SslService dummy;
    char       ip_addr_any[] = {0,0,0,0};
    guint32    port    = 0;
    gchar     *addr_string;
    Ssl_private_key_t * private_key;

    if (!ssl_session) {
        return;
    }

    /* we need to know which side of the conversation is speaking */
    if (ssl_packet_from_server(ssl_session, associations, pinfo)) {
        dummy.addr = pinfo->src;
        dummy.port = port = pinfo->srcport;
    } else {
        dummy.addr = pinfo->dst;
        dummy.port = port = pinfo->destport;
    }
    addr_string = address_to_str(NULL, &dummy.addr);
    ssl_debug_printf("ssl_find_private_key server %s:%u\n",
                     addr_string, dummy.port);
    wmem_free(NULL, addr_string);

    if (g_hash_table_size(key_hash) == 0) {
        ssl_debug_printf("ssl_find_private_key: no keys found\n");
        return;
    } else {
        ssl_debug_printf("ssl_find_private_key: testing %i keys\n",
            g_hash_table_size(key_hash));
    }

    /* try to retrieve private key for this service. Do it now 'cause pinfo
     * is not always available
     * Note that with HAVE_LIBGNUTLS undefined private_key is allways 0
     * and thus decryption never engaged*/


    ssl_session->private_key = 0;
    private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find private key for this server! Try it again with universal port 0\n");

        dummy.port = 0;
        private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);
    }

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find private key for this server (universal port)! Try it again with universal address 0.0.0.0\n");

        dummy.addr.type = AT_IPv4;
        dummy.addr.len = 4;
        dummy.addr.data = ip_addr_any;

        dummy.port = port;
        private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);
    }

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find private key for this server! Try it again with universal address 0.0.0.0 and universal port 0\n");

        dummy.port = 0;
        private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);
    }

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find any private key!\n");
    } else {
        ssl_session->private_key = private_key->sexp_pkey;
    }
}

void
ssl_lib_init(void)
{
    ssl_debug_printf("gnutls version: %s\n", gnutls_check_version(NULL));
}

#else /* defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT) */
/* no libgnutl: dummy operation to keep interface consistent*/
void
ssl_lib_init(void)
{
}

Ssl_private_key_t *
ssl_load_key(FILE* fp)
{
    ssl_debug_printf("ssl_load_key: impossible without gnutls. fp %p\n",fp);
    return NULL;
}

Ssl_private_key_t *
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd _U_, char** err) {
    *err = NULL;
    ssl_debug_printf("ssl_load_pkcs12: impossible without gnutls. fp %p\n",fp);
    return NULL;
}

void
ssl_free_key(Ssl_private_key_t* key _U_)
{
}

void
ssl_find_private_key(SslDecryptSession *ssl_session _U_, GHashTable *key_hash _U_, GTree* associations _U_, packet_info *pinfo _U_)
{
}

int
ssl_find_cipher(int num,SslCipherSuite* cs)
{
    ssl_debug_printf("ssl_find_cipher: dummy without gnutls. num %d cs %p\n",
        num,cs);
    return 0;
}
int
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session _U_,
        guint32 length _U_, tvbuff_t *tvb _U_, guint32 offset _U_,
        const gchar *ssl_psk _U_, const gchar *keylog_filename _U_)
{
    ssl_debug_printf("ssl_generate_pre_master_secret: impossible without gnutls.\n");
    return 0;
}
int
ssl_generate_keyring_material(SslDecryptSession*ssl)
{
    ssl_debug_printf("ssl_generate_keyring_material: impossible without gnutls. ssl %p\n",
        ssl);
    return 0;
}
void
ssl_change_cipher(SslDecryptSession *ssl_session, gboolean server)
{
    ssl_debug_printf("ssl_change_cipher %s: makes no sense without gnutls. ssl %p\n",
        (server)?"SERVER":"CLIENT", ssl_session);
}

int
ssl_decrypt_pre_master_secret(SslDecryptSession* ssl_session,
    StringInfo* encrypted_pre_master, SSL_PRIVATE_KEY *pk)
{
    ssl_debug_printf("ssl_decrypt_pre_master_secret: impossible without gnutls."
        " ssl %p encrypted_pre_master %p pk %p\n", ssl_session,
        encrypted_pre_master, pk);
    return 0;
}

int
ssl_decrypt_record(SslDecryptSession*ssl, SslDecoder* decoder, gint ct,
        const guchar* in, guint inl, StringInfo* comp_str _U_, StringInfo* out, guint* outl)
{
    ssl_debug_printf("ssl_decrypt_record: impossible without gnutls. ssl %p"
        "decoder %p ct %d, in %p inl %d out %p outl %p\n", ssl, decoder, ct,
        in, inl, out, outl);
    return 0;
}

gint
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher _U_, guchar* iv _U_, gint iv_len _U_)
{
    ssl_debug_printf("ssl_cipher_setiv: impossible without gnutls.\n");
    return 0;
}

#endif /* defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT) */

/* get ssl data for this session. if no ssl data is found allocate a new one*/
void
ssl_session_init(SslDecryptSession* ssl_session)
{
    ssl_debug_printf("ssl_session_init: initializing ptr %p size %" G_GSIZE_MODIFIER "u\n",
                     (void *)ssl_session, sizeof(SslDecryptSession));

    ssl_session->master_secret.data = ssl_session->_master_secret;
    ssl_session->session_id.data = ssl_session->_session_id;
    ssl_session->client_random.data = ssl_session->_client_random;
    ssl_session->server_random.data = ssl_session->_server_random;
    ssl_session->session_ticket.data = NULL;
    ssl_session->session_ticket.data_len = 0;
    ssl_session->master_secret.data_len = 48;
    ssl_session->server_data_for_iv.data_len = 0;
    ssl_session->server_data_for_iv.data = ssl_session->_server_data_for_iv;
    ssl_session->client_data_for_iv.data_len = 0;
    ssl_session->client_data_for_iv.data = ssl_session->_client_data_for_iv;
    ssl_session->app_data_segment.data=NULL;
    ssl_session->app_data_segment.data_len=0;
    SET_ADDRESS(&ssl_session->srv_addr, AT_NONE, 0, NULL);
    ssl_session->srv_ptype = PT_NONE;
    ssl_session->srv_port = 0;
}

void
ssl_set_server(SslDecryptSession* ssl, address *addr, port_type ptype, guint32 port)
{
    SE_COPY_ADDRESS(&ssl->srv_addr, addr);
    ssl->srv_ptype = ptype;
    ssl->srv_port = port;
}

/* Hash Functions for TLS/DTLS sessions table and private keys table*/
gint
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

guint
ssl_hash  (gconstpointer v)
{
    guint l,hash;
    const StringInfo* id;
    const guint* cur;
    hash = 0;
    id = (const StringInfo*) v;

    /*  id and id->data are mallocated in ssl_save_session().  As such 'data'
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

gint
ssl_private_key_equal (gconstpointer v, gconstpointer v2)
{
    const SslService *val1;
    const SslService *val2;
    val1 = (const SslService *)v;
    val2 = (const SslService *)v2;

    if ((val1->port == val2->port) &&
        ! CMP_ADDRESS(&val1->addr, &val2->addr)) {
        return 1;
    }
    return 0;
}

guint
ssl_private_key_hash  (gconstpointer v)
{
    const SslService *key;
    guint        l, hash, len ;
    const guint* cur;

    key  = (const SslService *)v;
    hash = key->port;
    len  = key->addr.len;
    hash |= len << 16;
    cur  = (const guint*) key->addr.data;

    for (l=4; (l<len); l+=4, cur++)
        hash = hash ^ (*cur);

    return hash;
}

/* private key table entries have a scope 'larger' then packet capture,
 * so we can't relay on se_alloc** function */
void
ssl_private_key_free(gpointer id, gpointer key, gpointer dummy _U_)
{
    if (id != NULL) {
        g_free(id);
        ssl_free_key((Ssl_private_key_t*) key);
    }
}

/* handling of association between tls/dtls ports and clear text protocol */
void
ssl_association_add(GTree* associations, dissector_handle_t handle, guint port, const gchar *protocol, gboolean tcp, gboolean from_key_list)
{

    SslAssociation* assoc;
    assoc = (SslAssociation *)g_malloc(sizeof(SslAssociation));

    assoc->tcp = tcp;
    assoc->ssl_port = port;
    assoc->info=g_strdup(protocol);
    assoc->handle = find_dissector(protocol);
    assoc->from_key_list = from_key_list;

    ssl_debug_printf("association_add %s port %d protocol %s handle %p\n",
                     (assoc->tcp)?"TCP":"UDP", port, protocol, (void *)(assoc->handle));


    if (!assoc->handle) {
        ssl_debug_printf("association_add could not find handle for protocol '%s', try to find 'data' dissector\n", protocol);
        assoc->handle = find_dissector("data");
    }

    if (!assoc->handle) {
        fprintf(stderr, "association_add() could not find handle for protocol:%s\n",protocol);
    } else {
        if (port) {
            if (tcp)
                dissector_add_uint("tcp.port", port, handle);
            else
                dissector_add_uint("udp.port", port, handle);
        }
        g_tree_insert(associations, assoc, assoc);

        dissector_add_uint("sctp.port", port, handle);
    }
}

void
ssl_association_remove(GTree* associations, SslAssociation *assoc)
{
    ssl_debug_printf("ssl_association_remove removing %s %u - %s handle %p\n",
                     (assoc->tcp)?"TCP":"UDP", assoc->ssl_port, assoc->info, (void *)(assoc->handle));
    if (assoc->handle)
        dissector_delete_uint((assoc->tcp)?"tcp.port":"udp.port", assoc->ssl_port, assoc->handle);

    g_free(assoc->info);

    g_tree_remove(associations, assoc);
    g_free(assoc);
}

gint
ssl_association_cmp(gconstpointer a, gconstpointer b)
{
    const SslAssociation *assoc_a=(const SslAssociation *)a, *assoc_b=(const SslAssociation *)b;
    if (assoc_a->tcp != assoc_b->tcp) return (assoc_a->tcp)?1:-1;
    return assoc_a->ssl_port - assoc_b->ssl_port;
}

SslAssociation*
ssl_association_find(GTree * associations, guint port, gboolean tcp)
{
    register SslAssociation* ret;
    SslAssociation           assoc_tmp;

    assoc_tmp.tcp = tcp;
    assoc_tmp.ssl_port = port;
    ret = (SslAssociation *)g_tree_lookup(associations, &assoc_tmp);

    ssl_debug_printf("association_find: %s port %d found %p\n", (tcp)?"TCP":"UDP", port, (void *)ret);
    return ret;
}

gint
ssl_assoc_from_key_list(gpointer key _U_, gpointer data, gpointer user_data)
{
    if (((SslAssociation*)data)->from_key_list)
        wmem_stack_push((wmem_stack_t*)user_data, data);
    return FALSE;
}

int
ssl_packet_from_server(SslDecryptSession* ssl, GTree* associations, packet_info *pinfo)
{
    gint ret;
    if (ssl && (ssl->srv_ptype != PT_NONE)) {
        ret = (ssl->srv_ptype == pinfo->ptype) && (ssl->srv_port == pinfo->srcport) && ADDRESSES_EQUAL(&ssl->srv_addr, &pinfo->src);
    } else {
        ret = ssl_association_find(associations, pinfo->srcport, pinfo->ptype == PT_TCP) != 0;
    }

    ssl_debug_printf("packet_from_server: is from server - %s\n", (ret)?"TRUE":"FALSE");
    return ret;
}

/* add to packet data a copy of the specified real data */
void
ssl_add_record_info(gint proto, packet_info *pinfo, guchar* data, gint data_len, gint record_id)
{
    guchar*        real_data;
    SslRecordInfo* rec;
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, 0);
    if (!pi)
    {
        pi = (SslPacketInfo *)wmem_alloc0(wmem_file_scope(), sizeof(SslPacketInfo));
        p_add_proto_data(wmem_file_scope(), pinfo, proto, 0, pi);
    }

    real_data = (guchar *)wmem_alloc(wmem_file_scope(), data_len);
    memcpy(real_data, data, data_len);

    rec = (SslRecordInfo *)wmem_alloc(wmem_file_scope(), sizeof(SslRecordInfo));
    rec->id = record_id;
    rec->real_data = real_data;
    rec->data_len = data_len;

    /* head insertion */
    rec->next= pi->handshake_data;
    pi->handshake_data = rec;
}

/* search in packet data for the specified id; return a newly created tvb for the associated data */
tvbuff_t*
ssl_get_record_info(tvbuff_t *parent_tvb, int proto, packet_info *pinfo, gint record_id)
{
    SslRecordInfo* rec;
    SslPacketInfo* pi;
    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, 0);

    if (!pi)
        return NULL;

    for (rec = pi->handshake_data; rec; rec = rec->next)
        if (rec->id == record_id)
            /* link new real_data_tvb with a parent tvb so it is freed when frame dissection is complete */
            return tvb_new_child_real_data(parent_tvb, rec->real_data, rec->data_len, rec->data_len);

    return NULL;
}

void
ssl_add_data_info(gint proto, packet_info *pinfo, guchar* data, gint data_len, gint key, SslFlow *flow)
{
    SslDataInfo   *rec, **prec;
    SslPacketInfo *pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, 0);
    if (!pi)
    {
        pi = (SslPacketInfo *)wmem_alloc0(wmem_file_scope(), sizeof(SslPacketInfo));
        p_add_proto_data(wmem_file_scope(), pinfo, proto, 0, pi);
    }

    rec = (SslDataInfo *)wmem_alloc(wmem_file_scope(), sizeof(SslDataInfo)+data_len);
    rec->key = key;
    rec->plain_data.data = (guchar*)(rec + 1);
    memcpy(rec->plain_data.data, data, data_len);
    rec->plain_data.data_len = data_len;
    if (flow)
    {
        rec->seq = flow->byte_seq;
        rec->nxtseq = flow->byte_seq + data_len;
        rec->flow = flow;
        flow->byte_seq += data_len;
    }
    rec->next = NULL;

    /* insertion */
    prec = &pi->appl_data;
    while (*prec) prec = &(*prec)->next;
    *prec = rec;

    ssl_debug_printf("ssl_add_data_info: new data inserted data_len = %d, seq = %u, nxtseq = %u\n",
                     rec->plain_data.data_len, rec->seq, rec->nxtseq);
}

SslDataInfo*
ssl_get_data_info(int proto, packet_info *pinfo, gint key)
{
    SslDataInfo*   rec;
    SslPacketInfo* pi;
    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, 0);

    if (!pi) return NULL;

    rec = pi->appl_data;
    while (rec) {
        if (rec->key == key) return rec;
        rec = rec->next;
    }

    return NULL;
}

/* initialize/reset per capture state data (ssl sessions cache) */
void
ssl_common_init(GHashTable **session_hash, StringInfo *decrypted_data, StringInfo *compressed_data)
{
    if (*session_hash)
        g_hash_table_destroy(*session_hash);
    *session_hash = g_hash_table_new(ssl_hash, ssl_equal);

    g_free(decrypted_data->data);
    ssl_data_alloc(decrypted_data, 32);

    g_free(compressed_data->data);
    ssl_data_alloc(compressed_data, 32);
}

/* parse ssl related preferences (private keys and ports association strings) */
void
ssl_parse_key_list(const ssldecrypt_assoc_t * uats, GHashTable *key_hash, GTree* associations, dissector_handle_t handle, gboolean tcp)
{
    SslService*        service;
    Ssl_private_key_t* private_key, *tmp_private_key;
    FILE*              fp     = NULL;
    guint32            addr_data[4];
    int                addr_len, at;
    address_type addr_type[2] = { AT_IPv4, AT_IPv6 };
    gchar*             address_string;

    /* try to load keys file first */
    fp = ws_fopen(uats->keyfile, "rb");
    if (!fp) {
        fprintf(stderr, "Can't open file %s\n",uats->keyfile);
        return;
    }

    for (at = 0; at < 2; at++) {
        memset(addr_data, 0, sizeof(addr_data));
        addr_len = 0;

        /* any: IPv4 or IPv6 wildcard */
        /* anyipv4: IPv4 wildcard */
        /* anyipv6: IPv6 wildcard */

        if(addr_type[at] == AT_IPv4) {
            if (strcmp(uats->ipaddr, "any") == 0 || strcmp(uats->ipaddr, "anyipv4") == 0 ||
                    get_host_ipaddr(uats->ipaddr, &addr_data[0])) {
                addr_len = 4;
            }
        } else { /* AT_IPv6 */
            if(strcmp(uats->ipaddr, "any") == 0 || strcmp(uats->ipaddr, "anyipv6") == 0 ||
                    get_host_ipaddr6(uats->ipaddr, (struct e_in6_addr *) addr_data)) {
                addr_len = 16;
            }
        }

        if (! addr_len) {
            continue;
        }

        /* reset the data pointer for the second iteration */
        rewind(fp);

        if ((gint)strlen(uats->password) == 0) {
            private_key = ssl_load_key(fp);
        } else {
            char *err = NULL;
            private_key = ssl_load_pkcs12(fp, uats->password, &err);
            if (err) {
                fprintf(stderr, "%s\n", err);
                g_free(err);
            }
        }

        if (!private_key) {
            fprintf(stderr,"Can't load private key from %s\n", uats->keyfile);
            fclose(fp);
            return;
        }

        service = (SslService *)g_malloc(sizeof(SslService) + addr_len);
        service->addr.type = addr_type[at];
        service->addr.len = addr_len;
        service->addr.data = ((guchar*)service) + sizeof(SslService);
        memcpy((void*)service->addr.data, addr_data, addr_len);

        if(strcmp(uats->port,"start_tls")==0) {
            service->port = 0;
        } else {
            service->port = atoi(uats->port);
        }

        /*
         * This gets called outside any dissection scope, so we have to
         * use a NULL scope and free it ourselves.
         */
        address_string = address_to_str(NULL, &service->addr);
        ssl_debug_printf("ssl_init %s addr '%s' (%s) port '%d' filename '%s' password(only for p12 file) '%s'\n",
            (addr_type[at] == AT_IPv4) ? "IPv4" : "IPv6", uats->ipaddr, address_string,
            service->port, uats->keyfile, uats->password);
        wmem_free(NULL, address_string);

        ssl_debug_printf("ssl_init private key file %s successfully loaded.\n", uats->keyfile);

        /* if item exists, remove first */
        tmp_private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, service);
        if (tmp_private_key) {
            g_hash_table_remove(key_hash, service);
            ssl_free_key(tmp_private_key);
        }

        g_hash_table_insert(key_hash, service, private_key);

        ssl_association_add(associations, handle, service->port, uats->protocol, tcp, TRUE);
    }

    fclose(fp);
}

/* store master secret into session data cache */
void
ssl_save_session(SslDecryptSession* ssl, GHashTable *session_hash)
{
    /* allocate stringinfo chunks for session id and master secret data*/
    StringInfo* session_id;
    StringInfo* master_secret;

    if (ssl->session_id.data_len == 0) {
        ssl_debug_printf("ssl_save_session SessionID is empty!\n");
        return;
    }

    session_id = (StringInfo *)wmem_alloc0(wmem_file_scope(), sizeof(StringInfo) + ssl->session_id.data_len);
    master_secret = (StringInfo *)wmem_alloc0(wmem_file_scope(), 48 + sizeof(StringInfo));

    master_secret->data = ((guchar*)master_secret+sizeof(StringInfo));

    /*  ssl_hash() depends on session_id->data being aligned for guint access
     *  so be careful in changing how it is allocated.
     */
    session_id->data = ((guchar*)session_id+sizeof(StringInfo));

    ssl_data_set(session_id, ssl->session_id.data, ssl->session_id.data_len);
    ssl_data_set(master_secret, ssl->master_secret.data, ssl->master_secret.data_len);
    g_hash_table_insert(session_hash, session_id, master_secret);
    ssl_print_string("ssl_save_session stored session id", session_id);
    ssl_print_string("ssl_save_session stored master secret", master_secret);
}

gboolean
ssl_restore_session(SslDecryptSession* ssl, GHashTable *session_hash)
{
    StringInfo* ms;

    if (ssl->session_id.data_len == 0) {
        ssl_debug_printf("ssl_restore_session Cannot restore using an empty SessionID\n");
        return FALSE;
    }

    ms = (StringInfo *)g_hash_table_lookup(session_hash, &ssl->session_id);

    if (!ms) {
        ssl_debug_printf("ssl_restore_session can't find stored session\n");
        return FALSE;
    }
    ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
    ssl->state |= SSL_MASTER_SECRET;
    ssl_debug_printf("ssl_restore_session master key retrieved\n");
    return TRUE;
}

/* store master secret into session data cache */
void
ssl_save_session_ticket(SslDecryptSession* ssl, GHashTable *session_hash)
{
    /* allocate stringinfo chunks for session id and master secret data*/
    StringInfo* session_ticket;
    StringInfo* master_secret;

    if (ssl->session_ticket.data_len == 0) {
        ssl_debug_printf("ssl_save_session_ticket - session ticket is empty!\n");
        return;
    }

    session_ticket = (StringInfo *)wmem_alloc0(wmem_file_scope(), sizeof(StringInfo) + ssl->session_ticket.data_len);
    master_secret = (StringInfo *)wmem_alloc0(wmem_file_scope(), 48 + sizeof(StringInfo));

    master_secret->data = ((guchar*)master_secret+sizeof(StringInfo));

    /*  ssl_hash() depends on session_id->data being aligned for guint access
     *  so be careful in changing how it is allocated.
     */
    session_ticket->data = ((guchar*)session_ticket+sizeof(StringInfo));

    ssl_data_set(session_ticket, ssl->session_ticket.data, ssl->session_ticket.data_len);
    ssl_data_set(master_secret, ssl->master_secret.data, ssl->master_secret.data_len);
    g_hash_table_insert(session_hash, session_ticket, master_secret);
    ssl_print_string("ssl_save_session_ticket stored session_ticket", session_ticket);
    ssl_print_string("ssl_save_session_ticket stored master secret", master_secret);
}

gboolean
ssl_restore_session_ticket(SslDecryptSession* ssl, GHashTable *session_hash)
{
    StringInfo* ms;

    if (ssl->session_ticket.data_len == 0) {
        ssl_debug_printf("ssl_restore_session_ticket Cannot restore using an empty session ticket\n");
        return FALSE;
    }

    ms = (StringInfo *)g_hash_table_lookup(session_hash, &ssl->session_ticket);

    if (!ms) {
        ssl_debug_printf("ssl_restore_session_ticket can't find stored session ticket\n");
        return FALSE;
    }
    ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
    ssl->state |= SSL_MASTER_SECRET;
    ssl_debug_printf("ssl_restore_session_ticket master key retrieved\n");
    return TRUE;
}

int
ssl_is_valid_content_type(guint8 type)
{
    if ((type >= 0x14) && (type <= 0x18))
    {
        return 1;
    }

    return 0;
}

static const unsigned int kRSAMasterSecretLength = 48; /* RFC5246 8.1 */

/* ssl_keylog_parse_session_id parses, from |line|, a string that looks like:
 *   RSA Session-ID:<hex session id> Master-Key:<hex TLS master secret>.
 *
 * It returns TRUE iff the session id matches |ssl_session| and the master
 * secret is correctly extracted. */
static gboolean
ssl_keylog_parse_session_id(const char* line,
                            SslDecryptSession* ssl_session)
{
    gsize len = strlen(line);
    unsigned int i;

    if (ssl_session->session_id.data_len == 0)
        return FALSE;

    if (len < 15 || memcmp(line, "RSA Session-ID:", 15) != 0)
        return FALSE;
    line += 15;
    len -= 15;

    if (len < ssl_session->session_id.data_len*2)
        return FALSE;

    for (i = 0; i < ssl_session->session_id.data_len; i++) {
        if (from_hex_char(line[2*i]) != (ssl_session->session_id.data[i] >> 4) ||
            from_hex_char(line[2*i+1]) != (ssl_session->session_id.data[i] & 15)) {
            ssl_debug_printf("    line does not match session id\n");
            return FALSE;
        }
    }

    line += 2*i;
    len -= 2*i;

    if (len != 12 + kRSAMasterSecretLength*2 ||
        memcmp(line, " Master-Key:", 12) != 0) {
        return FALSE;
    }
    line += 12;
    len -= 12;

    if (!from_hex(&ssl_session->master_secret, line, len))
        return FALSE;
    ssl_session->state &= ~(SSL_PRE_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
    ssl_session->state |= SSL_MASTER_SECRET;
    ssl_debug_printf("found master secret in key log\n");
    return TRUE;
}

/* ssl_keylog_parse_client_random parses, from |line|, a string that looks like:
 *   CLIENT_RANDOM <hex client_random> <hex TLS master secret>.
 *
 * It returns TRUE iff the client_random matches |ssl_session| and the master
 * secret is correctly extracted. */
static gboolean
ssl_keylog_parse_client_random(const char* line,
                               SslDecryptSession* ssl_session)
{
    static const unsigned int kTLSRandomSize = 32; /* RFC5246 A.6 */
    gsize len = strlen(line);
    unsigned int i;

    if (len < 14 || memcmp(line, "CLIENT_RANDOM ", 14) != 0)
        return FALSE;
    line += 14;
    len -= 14;

    if (len < kTLSRandomSize*2 ||
        ssl_session->client_random.data_len != kTLSRandomSize) {
        return FALSE;
    }

    for (i = 0; i < kTLSRandomSize; i++) {
        if (from_hex_char(line[2*i]) != (ssl_session->client_random.data[i] >> 4) ||
            from_hex_char(line[2*i+1]) != (ssl_session->client_random.data[i] & 15)) {
            ssl_debug_printf("    line does not match client random\n");
            return FALSE;
        }
    }

    line += 2*kTLSRandomSize;
    len -= 2*kTLSRandomSize;

    if (len != 1 + kRSAMasterSecretLength*2 || line[0] != ' ')
        return FALSE;
    line++;
    len--;

    if (!from_hex(&ssl_session->master_secret, line, len))
        return FALSE;
    ssl_session->state &= ~(SSL_PRE_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
    ssl_session->state |= SSL_MASTER_SECRET;
    ssl_debug_printf("found master secret in key log\n");
    return TRUE;
}

/* ssl_keylog_parse_session_id parses, from |line|, a string that looks like:
 *   RSA <hex, 8-bytes of encrypted pre-master secret> <hex pre-master secret>.
 *
 * It returns TRUE iff the session id matches |ssl_session| and the master
 * secret is correctly extracted. */
static gboolean
ssl_keylog_parse_rsa_premaster(const char* line,
                               SslDecryptSession* ssl_session,
                               StringInfo* encrypted_pre_master)
{
    static const unsigned int kRSAPremasterLength = 48; /* RFC5246 7.4.7.1 */
    gsize len = strlen(line);
    unsigned int i;

    if (encrypted_pre_master == NULL)
        return FALSE;

    if (encrypted_pre_master->data_len < 8)
        return FALSE;

    if (len < 4 || memcmp(line, "RSA ", 4) != 0)
        return FALSE;
    line += 4;
    len -= 4;

    if (len < 16)
        return FALSE;

    for (i = 0; i < 8; i++) {
        if (from_hex_char(line[2*i]) != (encrypted_pre_master->data[i] >> 4) ||
            from_hex_char(line[2*i+1]) != (encrypted_pre_master->data[i] & 15)) {
            ssl_debug_printf("    line does not match encrypted pre-master secret");
            return FALSE;
        }
    }

    line += 16;
    len -= 16;

    if (len != 1 + kRSAPremasterLength*2 || line[0] != ' ')
        return FALSE;
    line++;
    len--;

    if (!from_hex(&ssl_session->pre_master_secret, line, len))
        return FALSE;
    ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
    ssl_session->state |= SSL_PRE_MASTER_SECRET;
    ssl_debug_printf("found pre-master secret in key log\n");

    return TRUE;
}

int
ssl_keylog_lookup(SslDecryptSession* ssl_session,
                  const gchar* ssl_keylog_filename,
                  StringInfo* encrypted_pre_master) {
    FILE* ssl_keylog;
    int ret = -1;

    if (!ssl_keylog_filename)
        return -1;

    ssl_debug_printf("trying to use SSL keylog in %s\n", ssl_keylog_filename);

    ssl_keylog = ws_fopen(ssl_keylog_filename, "r");
    if (!ssl_keylog) {
        ssl_debug_printf("failed to open SSL keylog\n");
        return -1;
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
     *   - "CLIENT_RANDOM xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyy is the cleartext master secret (hex-encoded)
     *     (This format allows non-RSA SSL connections to be decrypted, i.e.
     *     ECDHE-RSA.)
     */
    for (;;) {
        char buf[512], *line;
        gsize bytes_read;

        line = fgets(buf, sizeof(buf), ssl_keylog);
        if (!line)
            break;

        bytes_read = strlen(line);
        /* fgets includes the \n at the end of the line. */
        if (bytes_read > 0) {
            line[bytes_read - 1] = 0;
            bytes_read--;
        }
        if (bytes_read > 0 && line[bytes_read - 1] == '\r') {
            line[bytes_read - 1] = 0;
            bytes_read--;
        }

        ssl_debug_printf("  checking keylog line: %s\n", line);

        if (ssl_keylog_parse_session_id(line, ssl_session) ||
            ssl_keylog_parse_rsa_premaster(line, ssl_session,
                                           encrypted_pre_master) ||
            ssl_keylog_parse_client_random(line, ssl_session)) {
            ret = 1;
            break;
        } else {
            ssl_debug_printf("    line does not match\n");
        }
    }

    fclose(ssl_keylog);
    return ret;
}

#ifdef SSL_DECRYPT_DEBUG

static FILE* ssl_debug_file=NULL;

void
ssl_set_debug(const gchar* name)
{
    static gint debug_file_must_be_closed;
    gint        use_stderr;

    debug_file_must_be_closed = 0;
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

    ssl_debug_printf("Wireshark SSL debug log \n\n");
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
#endif /* SSL_DECRYPT_DEBUG */

/* checks for SSL and DTLS UAT key list fields */

gboolean
ssldecrypt_uat_fld_ip_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No IP address given.");
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_port_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No Port given.");
        return FALSE;
    }

    if (strcmp(p, "start_tls") != 0){
        const gint i = atoi(p);
        if (i < 0 || i > 65535) {
            *err = ep_strdup_printf("Invalid port given.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_protocol_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No protocol given.");
        return FALSE;
    }

    if (!find_dissector(p)) {
        *err = ep_strdup_printf("Could not find dissector for: '%s'\nValid dissectors are:\n%s", p, ssl_association_info());
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_fileopen_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    ws_statb64 st;

    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No filename given.");
        return FALSE;
    } else {
        if (ws_stat64(p, &st) != 0) {
            *err = ep_strdup_printf("File '%s' does not exist or access is denied.", p);
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_password_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, const char ** err)
{
    ssldecrypt_assoc_t*  f  = (ssldecrypt_assoc_t *)r;
    FILE                *fp = NULL;

    if (p && (strlen(p) > 0u)) {
        fp = ws_fopen(f->keyfile, "rb");
        if (fp) {
            char *msg = NULL;
            if (!ssl_load_pkcs12(fp, p, &msg)) {
                fclose(fp);
                *err = ep_strdup_printf("Could not load PKCS#12 key file: %s", msg);
                g_free(msg);
                return FALSE;
            }
            g_free(msg);
            fclose(fp);
        } else {
            *err = ep_strdup_printf("Leave this field blank if the keyfile is not PKCS#12.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}


/* dissect a list of hash algorithms, return the number of bytes dissected
   this is used for the signature algorithms extension and for the
   TLS1.2 certificate request */
gint
ssl_dissect_hash_alg_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          guint32 offset, guint16 len)
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
        proto_tree_add_text(tree, tvb, offset, 2,
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
}

static gint
ssl_dissect_hnd_hello_ext_sig_hash_algs(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                        proto_tree *tree, guint32 offset, guint32 ext_len)
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

    ret = ssl_dissect_hash_alg_list(hf, tvb, tree, offset, sh_alg_length);
    if (ret >= 0)
        offset += ret;

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_alpn(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 ext_len)
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
    proto_item *ti;

    if (ext_len == 0) {
        return offset;
    }

    ti = proto_tree_add_text(tree, tvb, offset, ext_len, "Next Protocol Negotiation");
    npn_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_npn);

    while (ext_len > 0) {
        npn_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(npn_tree, hf->hf.hs_ext_npn_str_len,
                            tvb, offset, 1, ENC_NA);
        offset++;
        ext_len--;

        if (npn_length > 0) {
            tvb_ensure_bytes_exist(tvb, offset, npn_length);
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
    proto_item *ti;

    if (ext_len == 0) {
        return offset;
    }

    ti = proto_tree_add_text(tree, tvb, offset, ext_len, "Renegotiation Info extension");
    reneg_info_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_reneg_info);

    reneg_info_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(reneg_info_tree, hf->hf.hs_ext_reneg_info_len,
              tvb, offset, 1, ENC_NA);
    offset += 1;

    if (reneg_info_length > 0) {
        tvb_ensure_bytes_exist(tvb, offset, reneg_info_length);
        proto_tree_add_text(reneg_info_tree, tvb, offset, reneg_info_length, "Renegotiation Info");
        offset += reneg_info_length;
    }

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_server_name(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint16     server_name_length;
    proto_tree *server_name_tree;
    proto_item *ti;


   if (ext_len == 0) {
       return offset;
   }

   ti = proto_tree_add_text(tree, tvb, offset, ext_len, "Server Name Indication extension");
   server_name_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_server_name);

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
           tvb_ensure_bytes_exist(tvb, offset, server_name_length);
           proto_tree_add_item(server_name_tree, hf->hf.hs_ext_server_name,
                               tvb, offset, server_name_length, ENC_ASCII|ENC_NA);
           offset += server_name_length;
           ext_len -= server_name_length;
       }
   }
   return offset;
}

static gint
ssl_dissect_hnd_hello_ext_padding(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                     proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint8      padding_length;
    proto_tree *padding_tree;
    proto_item *ti;

    if (ext_len == 0) {
        return offset;
    }

    ti = proto_tree_add_item(tree, hf->hf.hs_ext_padding_data, tvb, offset, ext_len, ENC_NA);
    padding_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_padding);


    proto_tree_add_item(padding_tree, hf->hf.hs_ext_padding_len, tvb, offset, 2, ENC_NA);
    padding_length = tvb_get_guint8(tvb, offset);
    offset += 2;

    proto_tree_add_item(padding_tree, hf->hf.hs_ext_padding_data, tvb, offset, padding_length, ENC_NA);
    offset += padding_length;

    return offset;
}

static gint
ssl_dissect_hnd_hello_ext_session_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      proto_tree *tree, guint32 offset, guint32 ext_len, gboolean is_client, SslDecryptSession *ssl)
{
    if(is_client && ssl && ext_len != 0)
    {
        /*save the ticket on the ssl opaque so that we can use it as key on server hello */
        ssl->session_ticket.data = (guchar*)wmem_realloc(wmem_file_scope(),
                                    ssl->session_ticket.data, ext_len);
        tvb_memcpy(tvb,ssl->session_ticket.data, offset, ext_len);
        ssl->session_ticket.data_len = ext_len;
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
                                    gboolean is_client, guint16 ext_type, SslSession *session)
{
    guint8      cert_list_length;
    guint8      cert_type;
    proto_tree *cert_list_tree;
    proto_item *ti;

    if (is_client) {
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
    } else {
        cert_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (ext_type == SSL_HND_HELLO_EXT_CERT_TYPE || ext_type == SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE) {
            session->client_cert_type = cert_type;
        }
        if (ext_type == SSL_HND_HELLO_EXT_CERT_TYPE || ext_type == SSL_HND_HELLO_EXT_SERVER_CERT_TYPE) {
            session->server_cert_type = cert_type;
        }
    }

    return offset;
}

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
    guint   list_len;

    list_len = tvb_get_ntoh24(tvb, offset);
    offset += 3;

    while (list_len-- > 0)
        offset = ssl_dissect_hnd_hello_ext_status_request(hf, tvb, tree, offset, TRUE);

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
    tvb_ensure_bytes_exist(tvb, offset, curves_length);
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
    tvb_ensure_bytes_exist(tvb, offset, ecpf_length);
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

gint
ssl_dissect_hnd_hello_ext(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          guint32 offset, guint32 left, gboolean is_client,
                          SslSession *session, SslDecryptSession *ssl)
{
    guint16     extension_length;
    guint16     ext_type;
    guint16     ext_len;
    proto_item *pi;
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

        pi = proto_tree_add_text(tree, tvb, offset, 4 + ext_len,  "Extension: %s",
                                 val_to_str(ext_type,
                                            tls_hello_extension_types,
                                            "Unknown %u"));
        ext_tree = proto_item_add_subtree(pi, hf->ett.hs_ext);
        if (!ext_tree)
            ext_tree = tree;

        proto_tree_add_uint(ext_tree, hf->hf.hs_ext_type,
                            tvb, offset, 2, ext_type);
        offset += 2;

        proto_tree_add_uint(ext_tree, hf->hf.hs_ext_len,
                            tvb, offset, 2, ext_len);
        offset += 2;

        switch (ext_type) {
        case SSL_HND_HELLO_EXT_STATUS_REQUEST:
            if (is_client)
                offset = ssl_dissect_hnd_hello_ext_status_request(hf, tvb, ext_tree, offset, FALSE);
            else
                offset += ext_len; /* server must return empty extension_data */
            break;
        case SSL_HND_HELLO_EXT_STATUS_REQUEST_V2:
            if (is_client)
                offset = ssl_dissect_hnd_hello_ext_status_request_v2(hf, tvb, ext_tree, offset);
            else
                offset += ext_len; /* server must return empty extension_data */
            break;
        case SSL_HND_HELLO_EXT_ELLIPTIC_CURVES:
            offset = ssl_dissect_hnd_hello_ext_elliptic_curves(hf, tvb, ext_tree, offset);
            break;
        case SSL_HND_HELLO_EXT_EC_POINT_FORMATS:
            offset = ssl_dissect_hnd_hello_ext_ec_point_formats(hf, tvb, ext_tree, offset);
            break;
        case SSL_HND_HELLO_EXT_SIG_HASH_ALGS:
            offset = ssl_dissect_hnd_hello_ext_sig_hash_algs(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_ALPN:
            offset = ssl_dissect_hnd_hello_ext_alpn(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_NPN:
            offset = ssl_dissect_hnd_hello_ext_npn(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_RENEG_INFO:
            offset = ssl_dissect_hnd_hello_ext_reneg_info(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_SERVER_NAME:
            offset = ssl_dissect_hnd_hello_ext_server_name(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_HEARTBEAT:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_heartbeat_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += ext_len;
            break;
        case SSL_HND_HELLO_EXT_PADDING:
            offset = ssl_dissect_hnd_hello_ext_padding(hf, tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_SESSION_TICKET:
            offset = ssl_dissect_hnd_hello_ext_session_ticket(hf, tvb, ext_tree, offset, ext_len, is_client, ssl);
            break;
        case SSL_HND_HELLO_EXT_CERT_TYPE:
        case SSL_HND_HELLO_EXT_SERVER_CERT_TYPE:
        case SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE:
            offset = ssl_dissect_hnd_hello_ext_cert_type(hf, tvb, ext_tree, offset, ext_len, is_client, ext_type, session);
            break;
        default:
            proto_tree_add_bytes_format(ext_tree, hf->hf.hs_ext_data,
                                        tvb, offset, ext_len, NULL,
                                        "Data (%u byte%s)",
                                        ext_len, plurality(ext_len, "", "s"));
            offset += ext_len;
            break;
        }

        left -= 2 + 2 + ext_len;
    }

    return offset;
}


/* ClientKeyExchange algo-specific dissectors */

static void
dissect_ssl3_hnd_cli_keyex_ecdh(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint32 length)
{
    gint        point_len;
    proto_item *ti_ecdh;
    proto_tree *ssl_ecdh_tree;

    ti_ecdh = proto_tree_add_text(tree, tvb, offset, length,
                                  "EC Diffie-Hellman Client Params");
    ssl_ecdh_tree = proto_item_add_subtree(ti_ecdh, hf->ett.keyex_params);

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
    proto_item *ti_dh;
    proto_tree *ssl_dh_tree;

    ti_dh = proto_tree_add_text(tree, tvb, offset, length,
                                "Diffie-Hellman Client Params");
    ssl_dh_tree = proto_item_add_subtree(ti_dh, hf->ett.keyex_params);

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
    proto_item *ti_rsa;
    proto_tree *ssl_rsa_tree;

    ti_rsa = proto_tree_add_text(tree, tvb, offset, length,
                                 "RSA Encrypted PreMaster Secret");
    ssl_rsa_tree = proto_item_add_subtree(ti_rsa, hf->ett.keyex_params);

    /* EncryptedPreMasterSecret.pre_master_secret */
    switch (session->version) {
    case SSL_VER_SSLv2:
    case SSL_VER_SSLv3:
    case SSL_VER_DTLS_OPENSSL:
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
    proto_item *ti_psk;
    proto_tree *ssl_psk_tree;

    ti_psk = proto_tree_add_text(tree, tvb, offset, length,
                                 "PSK Client Params");
    ssl_psk_tree = proto_item_add_subtree(ti_psk, hf->ett.keyex_params);

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
    proto_item *ti_psk;
    proto_tree *ssl_psk_tree;

    ti_psk = proto_tree_add_text(tree, tvb, offset, length,
                                 "RSA PSK Client Params");
    ssl_psk_tree = proto_item_add_subtree(ti_psk, hf->ett.keyex_params);

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


/* ServerKeyExchange algo-specific dissectors */

/* dissects signed_params inside a ServerKeyExchange for some keyex algos */
static void
dissect_ssl3_hnd_srv_keyex_sig(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset,
                               const SslSession *session)
{
    gint        sig_len;
    proto_item *ti_algo;
    proto_tree *ssl_algo_tree;

    switch (session->version) {
    case SSL_VER_TLSv1DOT2:
    case SSL_VER_DTLS1DOT2:
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
    proto_tree_add_item(tree, hf->hf.hs_server_keyex_sig_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf->hf.hs_server_keyex_sig, tvb,
                        offset + 2, sig_len, ENC_NA);
}

static void
dissect_ssl3_hnd_srv_keyex_ecdh(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint32 length, const SslSession *session)
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
    proto_item *ti_ecdh;
    proto_tree *ssl_ecdh_tree;

    ti_ecdh = proto_tree_add_text(tree, tvb, offset, length,
                                  "EC Diffie-Hellman Server Params");
    ssl_ecdh_tree = proto_item_add_subtree(ti_ecdh, hf->ett.keyex_params);

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

    /* Signature */
    dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, ssl_ecdh_tree, offset, session);
}

static void
dissect_ssl3_hnd_srv_keyex_dhe(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 length,
                               const SslSession *session)
{
    gint        p_len, g_len, ys_len;
    proto_item *ti_dh;
    proto_tree *ssl_dh_tree;

    ti_dh = proto_tree_add_text(tree, tvb, offset, length,
                                "Diffie-Hellman Server Params");
    ssl_dh_tree = proto_item_add_subtree(ti_dh, hf->ett.keyex_params);

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

    /* Signature */
    dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, ssl_dh_tree, offset, session);
}

/* Only used in RSA-EXPORT cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_rsa(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 length,
                               const SslSession *session)
{
    gint        modulus_len, exponent_len;
    proto_item *ti_rsa;
    proto_tree *ssl_rsa_tree;

    ti_rsa = proto_tree_add_text(tree, tvb, offset, length,
                                 "RSA-EXPORT Server Params");
    ssl_rsa_tree = proto_item_add_subtree(ti_rsa, hf->ett.keyex_params);

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
    proto_item *ti_psk;
    proto_tree *ssl_psk_tree;

    hint_len = tvb_get_ntohs(tvb, offset);
    if ((2 + hint_len) != length) {
        /* Lengths don't line up (wasn't what we expected?) */
        return;
    }

    ti_psk = proto_tree_add_text(tree, tvb, offset, length,
                                 "PSK Server Params");
    ssl_psk_tree = proto_item_add_subtree(ti_psk, hf->ett.keyex_params);

    /* hint */
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_server_keyex_hint_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_server_keyex_hint, tvb,
                        offset + 2, hint_len, ENC_NA);
}


void
ssl_dissect_hnd_cli_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session)
{
    switch (ssl_get_keyex_alg(session->cipher)) {
    case KEX_RSA: /* rsa: EncryptedPreMasterSecret */
        dissect_ssl3_hnd_cli_keyex_rsa(hf, tvb, tree, offset, length, session);
        break;
    case KEX_DH: /* DHE_RSA: ClientDiffieHellmanPublic */
        /* XXX: DHE_DSS, DH_DSS, DH_RSA, DH_ANON; same format */
        dissect_ssl3_hnd_cli_keyex_dh(hf, tvb, tree, offset, length);
        break;
    case KEX_ECDH: /* ec_diffie_hellman: ClientECDiffieHellmanPublic */
        dissect_ssl3_hnd_cli_keyex_ecdh(hf, tvb, tree, offset, length);
        break;
    case KEX_PSK:
        dissect_ssl3_hnd_cli_keyex_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_RSA_PSK:
        dissect_ssl3_hnd_cli_keyex_rsa_psk(hf, tvb, tree, offset, length);
        break;
    }
}

void
ssl_dissect_hnd_srv_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, guint32 length,
                          const SslSession *session)
{
    switch (ssl_get_keyex_alg(session->cipher)) {
    case KEX_DH: /* DHE_RSA: ServerDHParams + signature */
        /* XXX: DHE_DSS, same format */
        /* XXX: DHE_ANON, almost the same, but without signed_params */
        dissect_ssl3_hnd_srv_keyex_dhe(hf, tvb, tree, offset, length, session);
        break;
    case KEX_RSA: /* TLSv1.0 and older: RSA_EXPORT cipher suites */
        dissect_ssl3_hnd_srv_keyex_rsa(hf, tvb, tree, offset, length, session);
        break;
    case KEX_ECDH: /* ec_diffie_hellman: ServerECDHParams + signature */
        dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, tree, offset, length, session);
        break;
    case KEX_RSA_PSK:
    case KEX_PSK:
        dissect_ssl3_hnd_srv_keyex_psk(hf, tvb, tree, offset, length);
        break;
    }
}

#ifdef HAVE_LIBGNUTLS
void
ssl_common_register_options(module_t *module, ssl_common_options_t *options)
{
        prefs_register_string_preference(module, "psk", "Pre-Shared-Key",
             "Pre-Shared-Key as HEX string, should be 0 to 16 bytes",
             &(options->psk));

        prefs_register_filename_preference(module, "keylog_file", "(Pre)-Master-Secret log filename",
             "The filename of a file which contains a list of \n"
             "(pre-)master secrets in one of the following formats:\n"
             "\n"
             "RSA <EPMS> <PMS>\n"
             "RSA Session-ID:<SSLID> Master-Key:<MS>\n"
             "CLIENT_RANDOM <CRAND> <MS>\n"
             "\n"
             "Where:\n"
             "<EPMS> = First 8 bytes of the Encrypted PMS\n"
             "<PMS> = The Pre-Master-Secret (PMS)\n"
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
