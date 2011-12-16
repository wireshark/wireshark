/* packet-ssl-utils.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include "packet-ssl-utils.h"

#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/ipv6-utils.h>
#include <wsutil/file_util.h>

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
    { 1, "sect163k1" },
    { 2, "sect163r1" },
    { 3, "sect163r2" },
    { 4, "sect193r1" },
    { 5, "sect193r2" },
    { 6, "sect233k1" },
    { 7, "sect233r1" },
    { 8, "sect239k1" },
    { 9, "sect283k1" },
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
    { 0xFF01, "arbitrary_explicit_prime_curves" },
    { 0xFF02, "arbitrary_explicit_char2_curves" },
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
    { 0x00, NULL }
};

const value_string ssl_versions[] = {
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
    {  0,  "Close Notify" },
    { 10,  "Unexpected Message" },
    { 20,  "Bad Record MAC" },
    { 21,  "Decryption Failed" },
    { 22,  "Record Overflow" },
    { 30,  "Decompression Failure" },
    { 40,  "Handshake Failure" },
    { 41,  "No Certificate" },
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
    { SSL_HND_CERTIFICATE,       "Certificate" },
    { SSL_HND_SERVER_KEY_EXCHG,  "Server Key Exchange" },
    { SSL_HND_CERT_REQUEST,      "Certificate Request" },
    { SSL_HND_SVR_HELLO_DONE,    "Server Hello Done" },
    { SSL_HND_CERT_VERIFY,       "Certificate Verify" },
    { SSL_HND_CLIENT_KEY_EXCHG,  "Client Key Exchange" },
    { SSL_HND_FINISHED,          "Finished" },
    { SSL_HND_CERT_STATUS,       "Certificate Status" },
    { 0x00, NULL }
};

const value_string ssl_31_compression_method[] = {
    { 0, "null" },
    { 1, "DEFLATE" },
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
/*
0xC0,0x3C-FF Unassigned
0xC1-FD,* Unassigned
0xFE,0x00-FD Unassigned
0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
0xFF,0x00-FF Reserved for Private Use [RFC5246]
*/
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

/* RFC 4366 */
const value_string tls_hello_extension_types[] = {
    { 0, "server_name" },
    { 1, "max_fragment_length" },
    { 2, "client_certificate_url" },
    { 3, "trusted_ca_keys" },
    { 4, "truncated_hmac" },
    { 5, "status_request" },
    { 6, "user_mapping" },  /* RFC 4681 */
    { 7, "client_authz" },
    { 8, "server_authz" },
    { 9, "cert_type" },  /* RFC 5081 */
    { SSL_HND_HELLO_EXT_ELLIPTIC_CURVES, "elliptic_curves" },  /* RFC 4492 */
    { SSL_HND_HELLO_EXT_EC_POINT_FORMATS, "ec_point_formats" },  /* RFC 4492 */
    { 12, "srp" },  /* RFC 5054 */
    { 13, "signature_algorithms" },  /* RFC 5246 */
    { 14, "use_srtp" },
    { 35, "SessionTicket TLS" },  /* RFC 4507 */
    { 65281, "renegotiation_info" },
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
    { 0, NULL }
};

const value_string tls_cert_status_type[] = {
    { SSL_HND_CERT_STATUS_TYPE_OCSP, "OCSP" },
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

static gint
ssl_data_alloc(StringInfo* str, size_t len)
{
    str->data = g_malloc(len);
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
    memcpy(str->data, data, len);
    str->data_len = len;
}

#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)

static gint ver_major, ver_minor, ver_patch;

/* hmac abstraction layer */
#define SSL_HMAC gcry_md_hd_t

static inline gint
ssl_hmac_init(SSL_HMAC* md, const void * key, gint len, gint algo)
{
    gcry_error_t err;
    const char *err_str, *err_src;
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
    gint algo;
    guint len;
    algo = gcry_md_get_algo (*(md));
    len = gcry_md_get_algo_dlen(algo);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen =len;
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
    gcry_error_t err;
    const char *err_str, *err_src;
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
    /* guchar * ivp; */
    gint ret;
    /* gint i; */
    /* gcry_cipher_hd_t c; */
    ret=0;
    /*c=(gcry_cipher_hd_t)*cipher;*/

    ssl_debug_printf("--------------------------------------------------------------------");
    /*for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
    */
    ssl_debug_printf("--------------------------------------------------------------------");
    ret = gcry_cipher_setiv(*(cipher), iv, iv_len);
    /*for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
    */
    ssl_debug_printf("--------------------------------------------------------------------");
    return ret;
}
/* stream cipher abstraction layer*/
static gint
ssl_cipher_init(gcry_cipher_hd_t *cipher, gint algo, guchar* sk,
        guchar* iv, gint mode)
{
    gint gcry_modes[]={GCRY_CIPHER_MODE_STREAM,GCRY_CIPHER_MODE_CBC};
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

/* private key abstraction layer */
static inline gint
ssl_get_key_len(SSL_PRIVATE_KEY* pk) {return gcry_pk_get_nbits (pk); }

gcry_err_code_t
_gcry_rsa_decrypt (int algo, gcry_mpi_t *result, gcry_mpi_t *data,
                   gcry_mpi_t *skey, gint flags);

#define PUBKEY_FLAG_NO_BLINDING (1 << 0)

const gchar*
ssl_private_key_to_str(SSL_PRIVATE_KEY* pk)
{
    const gchar *str="NULL";
    size_t n;
    gchar *buf;

    if (!pk) return str;
#ifndef SSL_FAST
    n = gcry_sexp_sprint(pk, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = ep_alloc(n);
    n = gcry_sexp_sprint(pk, GCRYSEXP_FMT_ADVANCED, buf, n);
    str = buf;
#else /* SSL_FAST */
    str = "TO DO: dump mpi gcry_mpi_print()";
#endif /* SSL_FAST */

    return str;
}

/* decrypt data with private key. Store decrypted data directly into input
 * buffer */
int
ssl_private_decrypt(guint len, guchar* encr_data, SSL_PRIVATE_KEY* pk)
{
    gint rc;
    size_t decr_len;
    gcry_sexp_t  s_data, s_plain;
    gcry_mpi_t encr_mpi;
    size_t i, encr_len;
    guchar* decr_data_ptr;
    gcry_mpi_t text;
    decr_len = 0;
    encr_len = len;
    text=NULL;

    /* build up a mpi rappresentation for encrypted data */
    rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG,encr_data, encr_len, &encr_len);
    if (rc != 0 ) {
        ssl_debug_printf("pcry_private_decrypt: can't convert encr_data to mpi (size %d):%s\n",
            len, gcry_strerror(rc));
        return 0;
    }

    /*ssl_debug_printf("pcry_private_decrypt: pk=%s\n", ssl_private_key_to_str(pk));*/

#ifndef SSL_FAST
    /* put the data into a simple list */
    rc = gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", encr_mpi);
    if (rc != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't build encr_sexp:%s \n",
             gcry_strerror(rc));
        return 0;
    }

    /* pass it to libgcrypt */
    rc = gcry_pk_decrypt(&s_plain, s_data, pk);
    gcry_sexp_release(s_data);
    if (rc != 0)
    {
        ssl_debug_printf("pcry_private_decrypt: can't decrypt key:%s\n",
            gcry_strerror(rc));
        goto out;
    }

    /* convert plain text sexp to mpi format */
    text = gcry_sexp_nth_mpi(s_plain, 0, 0);

    /* compute size requested for plaintext buffer */
    decr_len = len;
    if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, decr_len, &decr_len, text) != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't compute decr size:%s\n",
            gcry_strerror(rc));
        decr_len = 0;
        goto out;
    }

    /* sanity check on out buffer */
    if (decr_len > len) {
        ssl_debug_printf("pcry_private_decrypt: decrypted data is too long ?!? (%" G_GSIZE_MODIFIER "u max %d)\n",
            decr_len, len);
        return 0;
    }

    /* write plain text to encrypted data buffer */
    decr_data_ptr = encr_data;
    if (gcry_mpi_print( GCRYMPI_FMT_USG, decr_data_ptr, decr_len, &decr_len,
            text) != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't print decr data to mpi (size %" G_GSIZE_MODIFIER "u):%s\n",
            decr_len, gcry_strerror(rc));
        g_free(decr_data_ptr);
        decr_len = 0;
        goto out;
    }

    /* strip the padding*/
    rc = 0;
    for (i = 1; i < decr_len; i++) {
        if (decr_data_ptr[i] == 0) {
            rc = (gint) i+1;
            break;
        }
    }

    ssl_debug_printf("pcry_private_decrypt: stripping %d bytes, decr_len %" G_GSIZE_MODIFIER "u\n",
        rc, decr_len);
    ssl_print_data("decrypted_unstrip_pre_master", decr_data_ptr, decr_len);
    g_memmove(decr_data_ptr, &decr_data_ptr[rc], decr_len - rc);
    decr_len -= rc;

out:
    gcry_sexp_release(s_plain);
#else /* SSL_FAST */
    rc = _gcry_rsa_decrypt(0, &text,  &encr_mpi, pk,0);
    gcry_mpi_print( GCRYMPI_FMT_USG, 0, 0, &decr_len, text);

    /* sanity check on out buffer */
    if (decr_len > len) {
        ssl_debug_printf("pcry_private_decrypt: decrypted data is too long ?!? (%d max %d)\n",
            decr_len, len);
        return 0;
    }

    /* write plain text to newly allocated buffer */
    decr_data_ptr = encr_data;
    if (gcry_mpi_print( GCRYMPI_FMT_USG, decr_data_ptr, decr_len, &decr_len,
            text) != 0) {
        ssl_debug_printf("pcry_private_decrypt: can't print decr data to mpi (size %d):%s\n",
            decr_len, gcry_strerror(rc));
        return 0;
    }

    /* strip the padding*/
    rc = 0;
    for (i = 1; i < decr_len; i++) {
        if (decr_data_ptr[i] == 0) {
            rc = i+1;
            break;
        }
    }

    ssl_debug_printf("pcry_private_decrypt: stripping %d bytes, decr_len %d\n",
        rc, decr_len);
    ssl_print_data("decrypted_unstrip_pre_master", decr_data_ptr, decr_len);
    g_memmove(decr_data_ptr, &decr_data_ptr[rc], decr_len - rc);
    decr_len -= rc;
#endif /* SSL_FAST */
    gcry_mpi_release(text);
    return (int) decr_len;
}

/* stringinfo interface */
static gint
ssl_data_realloc(StringInfo* str, guint len)
{
    str->data = g_realloc(str->data, len);
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

#define PRF(ssl,secret,usage,rnd1,rnd2,out) ((ssl->version_netorder==SSLV3_VERSION)? \
        ssl3_prf(secret,usage,rnd1,rnd2,out): \
        tls_prf(secret,usage,rnd1,rnd2,out))

static const gchar *digests[]={
    "MD5",
    "SHA1"
};

static const gchar *ciphers[]={
    "DES",
    "3DES",
    "ARCFOUR", /* gnutls does not support rc4, but this should be 100% compatible*/
    "RC2",
    "IDEA",
    "AES",
    "AES256",
    "*UNKNOWN*"
};

static SslCipherSuite cipher_suites[]={
    {1,KEX_RSA,SIG_RSA,ENC_NULL,1,0,0,DIG_MD5,16,0, SSL_CIPHER_MODE_STREAM},
    {2,KEX_RSA,SIG_RSA,ENC_NULL,1,0,0,DIG_SHA,20,0, SSL_CIPHER_MODE_STREAM},
    {3,KEX_RSA,SIG_RSA,ENC_RC4,1,128,40,DIG_MD5,16,1, SSL_CIPHER_MODE_STREAM},
    {4,KEX_RSA,SIG_RSA,ENC_RC4,1,128,128,DIG_MD5,16,0, SSL_CIPHER_MODE_STREAM},
    {5,KEX_RSA,SIG_RSA,ENC_RC4,1,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_STREAM},
    {6,KEX_RSA,SIG_RSA,ENC_RC2,8,128,40,DIG_SHA,20,1, SSL_CIPHER_MODE_STREAM},
    {7,KEX_RSA,SIG_RSA,ENC_IDEA,8,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_STREAM},
    {8,KEX_RSA,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1, SSL_CIPHER_MODE_CBC},
    {9,KEX_RSA,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {10,KEX_RSA,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {11,KEX_DH,SIG_DSS,ENC_DES,8,64,40,DIG_SHA,20,1, SSL_CIPHER_MODE_CBC},
    {12,KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {13,KEX_DH,SIG_DSS,ENC_3DES,8,192,192,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {14,KEX_DH,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1, SSL_CIPHER_MODE_CBC},
    {15,KEX_DH,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {16,KEX_DH,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {17,KEX_DH,SIG_DSS,ENC_DES,8,64,40,DIG_SHA,20,1, SSL_CIPHER_MODE_CBC},
    {18,KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {19,KEX_DH,SIG_DSS,ENC_3DES,8,192,192,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {20,KEX_DH,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1, SSL_CIPHER_MODE_CBC},
    {21,KEX_DH,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {22,KEX_DH,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {23,KEX_DH,SIG_NONE,ENC_RC4,1,128,40,DIG_MD5,16,1, SSL_CIPHER_MODE_STREAM},
    {24,KEX_DH,SIG_NONE,ENC_RC4,1,128,128,DIG_MD5,16,0, SSL_CIPHER_MODE_STREAM},
    {25,KEX_DH,SIG_NONE,ENC_DES,8,64,40,DIG_MD5,16,1, SSL_CIPHER_MODE_CBC},
    {26,KEX_DH,SIG_NONE,ENC_DES,8,64,64,DIG_MD5,16,0, SSL_CIPHER_MODE_CBC},
    {27,KEX_DH,SIG_NONE,ENC_3DES,8,192,192,DIG_MD5,16,0, SSL_CIPHER_MODE_CBC},
    {47,KEX_RSA,SIG_RSA,ENC_AES,16,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {51,KEX_DH, SIG_RSA,ENC_AES,16,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {53,KEX_RSA,SIG_RSA,ENC_AES256,16,256,256,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {96,KEX_RSA,SIG_RSA,ENC_RC4,1,128,56,DIG_MD5,16,1, SSL_CIPHER_MODE_STREAM},
    {97,KEX_RSA,SIG_RSA,ENC_RC2,1,128,56,DIG_MD5,16,1, SSL_CIPHER_MODE_STREAM},
    {98,KEX_RSA,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,1, SSL_CIPHER_MODE_STREAM},
    {99,KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,16,1, SSL_CIPHER_MODE_CBC},
    {100,KEX_RSA,SIG_RSA,ENC_RC4,1,128,56,DIG_SHA,20,1, SSL_CIPHER_MODE_STREAM},
    {101,KEX_DH,SIG_DSS,ENC_RC4,1,128,56,DIG_SHA,20,1, SSL_CIPHER_MODE_STREAM},
    {102,KEX_DH,SIG_DSS,ENC_RC4,1,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_STREAM},
    /*{138,KEX_PSK,SIG_RSA,ENC_RC4,16,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},*/
    {139,KEX_PSK,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {140,KEX_PSK,SIG_RSA,ENC_AES,16,128,128,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {141,KEX_PSK,SIG_RSA,ENC_AES256,16,256,256,DIG_SHA,20,0, SSL_CIPHER_MODE_CBC},
    {-1, 0,0,0,0,0,0,0,0,0, 0}
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
    guint8 *ptr;
    guint left;
    gint tocpy;
    guint8 *A;
    guint8 _A[20],tmp[20];
    guint A_l,tmp_l;
    SSL_HMAC hm;
    ptr=out->data;
    left=out->data_len;


    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    A=seed->data;
    A_l=seed->data_len;

    while(left){
        ssl_hmac_init(&hm,secret->data,secret->data_len,md);
        ssl_hmac_update(&hm,A,A_l);
        ssl_hmac_final(&hm,_A,&A_l);
        ssl_hmac_cleanup(&hm);
        A=_A;

        ssl_hmac_init(&hm,secret->data,secret->data_len,md);
        ssl_hmac_update(&hm,A,A_l);
        ssl_hmac_update(&hm,seed->data,seed->data_len);
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
    StringInfo seed, sha_out, md5_out;
    guint8 *ptr;
    StringInfo s1, s2;
    guint i,s_l, r;
    size_t usage_len;
    r=-1;
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
    memcpy(ptr,usage,usage_len); ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len); ptr+=rnd1->data_len;
    memcpy(ptr,rnd2->data,rnd2->data_len); ptr+=rnd2->data_len;

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
ssl3_generate_export_iv(StringInfo* r1,
        StringInfo* r2, StringInfo* out)
{
    SSL_MD5_CTX md5;
    guint8 tmp[16];

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
    SSL_MD5_CTX md5;
    SSL_SHA_CTX sha;
    StringInfo *rnd1,*rnd2;
    guint off;
    gint i=0,j;
    guint8 buf[20];

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

static SslFlow*
ssl_create_flow(void)
{
  SslFlow *flow;

  flow = se_alloc(sizeof(SslFlow));
  flow->byte_seq = 0;
  flow->flags = 0;
  flow->multisegment_pdus = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "ssl_multisegment_pdus");
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
    decomp = se_alloc(sizeof(SslDecompress));
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
    gint ciph;
    ciph=0;

    dec = se_alloc0(sizeof(SslDecoder));
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
            ciphers[(cipher_suite->enc-0x30) > 7 ? 7 : (cipher_suite->enc-0x30)]);
        return NULL;
    }

    /* init mac buffer: mac storage is embedded into decoder struct to save a
     memory allocation and waste samo more memory*/
    dec->cipher_suite=cipher_suite;
    dec->compression = compression;
    dec->mac_key.data = dec->_mac_key;
    ssl_data_set(&dec->mac_key, mk, cipher_suite->dig_len);
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

    ssl_debug_printf("decoder initialized (digest len %d)\n", cipher_suite->dig_len);
    return dec;
}

int
ssl_generate_keyring_material(SslDecryptSession*ssl_session)
{
    StringInfo key_block;
    guint8 _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];
    guint8 _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    gint needed;
    guint8 *ptr,*c_wk,*s_wk,*c_mk,*s_mk,*c_iv = _iv_c,*s_iv = _iv_s;

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
        if (PRF(ssl_session,&ssl_session->pre_master_secret,"master secret",
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
    needed=ssl_session->cipher_suite.dig_len*2;
    needed+=ssl_session->cipher_suite.bits / 4;
    if(ssl_session->cipher_suite.block>1)
        needed+=ssl_session->cipher_suite.block*2;

    key_block.data_len = needed;
    key_block.data = g_malloc(needed);
    ssl_debug_printf("ssl_generate_keyring_material sess key generation\n");
    if (PRF(ssl_session,&ssl_session->master_secret,"key expansion",
            &ssl_session->server_random,&ssl_session->client_random,
            &key_block)) {
        ssl_debug_printf("ssl_generate_keyring_material can't generate key_block\n");
        goto fail;
    }
    ssl_print_string("key expansion", &key_block);

    ptr=key_block.data;
    c_mk=ptr; ptr+=ssl_session->cipher_suite.dig_len;
    s_mk=ptr; ptr+=ssl_session->cipher_suite.dig_len;

    c_wk=ptr; ptr+=ssl_session->cipher_suite.eff_bits/8;
    s_wk=ptr; ptr+=ssl_session->cipher_suite.eff_bits/8;

    if(ssl_session->cipher_suite.block>1){
        c_iv=ptr; ptr+=ssl_session->cipher_suite.block;
        s_iv=ptr; ptr+=ssl_session->cipher_suite.block;
    }

    if(ssl_session->cipher_suite.export){
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
                if(PRF(ssl_session,&key_null, "IV block",
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
            if (PRF(ssl_session,&k,"client write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_c)) {
                ssl_debug_printf("ssl_generate_keyring_material can't generate tll31 server key \n");
                goto fail;
            }
            c_wk=_key_c;

            k.data = s_wk;
            k.data_len = ssl_session->cipher_suite.eff_bits/8;
            ssl_debug_printf("ssl_generate_keyring_material PRF(key_s)\n");
            if(PRF(ssl_session,&k,"server write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_s)) {
                ssl_debug_printf("ssl_generate_keyring_material can't generate tll31 client key \n");
                goto fail;
            }
            s_wk=_key_s;
        }
    }

    /* show key material info */
    ssl_print_data("Client MAC key",c_mk,ssl_session->cipher_suite.dig_len);
    ssl_print_data("Server MAC key",s_mk,ssl_session->cipher_suite.dig_len);
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
    ssl_session->client_new = ssl_create_decoder(&ssl_session->cipher_suite, ssl_session->compression, c_mk, c_wk, c_iv);
    if (!ssl_session->client_new) {
        ssl_debug_printf("ssl_generate_keyring_material can't init client decoder\n");
        goto fail;
    }
    ssl_debug_printf("ssl_generate_keyring_material ssl_create_decoder(server)\n");
    ssl_session->server_new = ssl_create_decoder(&ssl_session->cipher_suite, ssl_session->compression, s_mk, s_wk, s_iv);
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
    gint md;
    guint32 len;
    guint8 buf[20];
    gint16 temp;

    md=ssl_get_digest_by_name(digests[decoder->cipher_suite->dig-0x40]);
    ssl_debug_printf("tls_check_mac mac type:%s md %d\n",
        digests[decoder->cipher_suite->dig-0x40], md);

    if (ssl_hmac_init(&hm,decoder->mac_key.data,decoder->mac_key.data_len,md) != 0)
        return -1;;

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
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return 0;
}

int
ssl3_check_mac(SslDecoder*decoder,int ct,guint8* data,
        guint32 datalen, guint8* mac)
{
    SSL_MD mc;
    gint md;
    guint32 len;
    guint8 buf[64],dgst[20];
    gint pad_ct;
    gint16 temp;

    pad_ct=(decoder->cipher_suite->dig==DIG_SHA)?40:48;

    /* get cipher used for digest comptuation */
    md=ssl_get_digest_by_name(digests[decoder->cipher_suite->dig-0x40]);
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

#if 0
static gint
dtls_check_mac(SslDecoder*decoder, gint ct,int ver, guint8* data,
        guint32 datalen, guint8* mac)
{
    SSL_HMAC hm;
    gint md;
    guint32 len;
    guint8 buf[20];
    guint32 netnum;
    md=ssl_get_digest_by_name(digests[decoder->cipher_suite->dig-0x40]);
    ssl_debug_printf("dtls_check_mac mac type:%s md %d\n",
        digests[decoder->cipher_suite->dig-0x40], md);

    if (ssl_hmac_init(&hm,decoder->mac_key.data,decoder->mac_key.data_len,md) != 0)
        return -1;
    ssl_debug_printf("dtls_check_mac seq: %d epoch: %d\n",decoder->seq,decoder->epoch);
    /* hash sequence number */
    fmt_seq(decoder->seq,buf);
    buf[0]=decoder->epoch>>8;
    buf[1]=decoder->epoch;

    ssl_hmac_update(&hm,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_hmac_update(&hm,buf,1);

    /* hash version,data length and data */
    *((gint16*)buf) = g_htons(ver);
    ssl_hmac_update(&hm,buf,2);

    *((gint16*)buf) = g_htons(datalen);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);
    /* get digest and digest len */
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return(0);
}
#endif

#ifdef HAVE_LIBZ
int
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
    guint pad, worklen, uncomplen;
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

    /* First decrypt*/
    if ((pad = ssl_cipher_decrypt(&decoder->evp, out_str->data, out_str->data_len, in, inl))!= 0) {
        ssl_debug_printf("ssl_decrypt_record failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
                    gcry_strerror (pad));
        return -1;
    }

    ssl_print_data("Plaintext", out_str->data, inl);
    worklen=inl;

    /* Now strip off the padding*/
    if(decoder->cipher_suite->block!=1) {
        pad=out_str->data[inl-1];
        worklen-=(pad+1);
        ssl_debug_printf("ssl_decrypt_record found padding %d final len %d\n",
            pad, worklen);
    }

    /* And the MAC */
    if (decoder->cipher_suite->dig_len > (gint)worklen)
    {
        ssl_debug_printf("ssl_decrypt_record wrong record len/padding outlen %d\n work %d\n",*outl, worklen);
        return -1;
    }
    worklen-=decoder->cipher_suite->dig_len;
    mac = out_str->data + worklen;

    /* if TLS 1.1 we use the transmitted IV and remove it after (to not modify dissector in others parts)*/
    if(ssl->version_netorder==TLSV1DOT1_VERSION){
        worklen=worklen-decoder->cipher_suite->block;
        memcpy(out_str->data,out_str->data+decoder->cipher_suite->block,worklen);
    }
    if(ssl->version_netorder==DTLSV1DOT0_VERSION ||
      ssl->version_netorder==DTLSV1DOT0_VERSION_NOT){
        worklen=worklen-decoder->cipher_suite->block;
        memcpy(out_str->data,out_str->data+decoder->cipher_suite->block,worklen);
    }
    /* Now check the MAC */
    ssl_debug_printf("checking mac (len %d, version %X, ct %d seq %d)\n",
        worklen, ssl->version_netorder, ct, decoder->seq);
    if(ssl->version_netorder==SSLV3_VERSION){
        if(ssl3_check_mac(decoder,ct,out_str->data,worklen,mac) < 0) {
            ssl_debug_printf("ssl_decrypt_record: mac failed\n");
            return -1;
        }
    }
    else if(ssl->version_netorder==TLSV1_VERSION || ssl->version_netorder==TLSV1DOT1_VERSION){
        if(tls_check_mac(decoder,ct,ssl->version_netorder,out_str->data,worklen,mac)< 0) {
            ssl_debug_printf("ssl_decrypt_record: mac failed\n");
            return -1;
        }
    }
    else if(ssl->version_netorder==DTLSV1DOT0_VERSION ||
        ssl->version_netorder==DTLSV1DOT0_VERSION_NOT){
        /* following the openssl dtls errors the right test is:
        if(dtls_check_mac(decoder,ct,ssl->version_netorder,out_str->data,worklen,mac)< 0) { */
        if(tls_check_mac(decoder,ct,TLSV1_VERSION,out_str->data,worklen,mac)< 0) {
            ssl_debug_printf("ssl_decrypt_record: mac failed\n");
            return -1;
        }
    }
    ssl_debug_printf("ssl_decrypt_record: mac ok\n");
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

static void
ssl_get_version(gint* major, gint* minor, gint* patch)
{
  *major = ver_major;
  *minor = ver_minor;
  *patch = ver_patch;
}

#define RSA_PARS 6
SSL_PRIVATE_KEY*
ssl_privkey_to_sexp(struct gnutls_x509_privkey_int* priv_key)
{
    gnutls_datum_t rsa_datum[RSA_PARS]; /* m, e, d, p, q, u */
    size_t tmp_size;
    gcry_sexp_t rsa_priv_key;
    gint major, minor, patch;
    gint i, p_idx, q_idx;
    int ret;
    size_t buf_len;
    unsigned char buf_keyid[32];

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
        ssl_debug_printf( "Private key imported: KeyID %s\n", bytes_to_str_punct(buf_keyid, (int) buf_len, ':'));
    }

    /*
     * note: openssl and gnutls use 'p' and 'q' with opposite meaning:
     * our 'p' must be equal to 'q' as provided from openssl and viceversa
     */

#if (LIBGNUTLS_VERSION_MAJOR>2)||((LIBGNUTLS_VERSION_MAJOR==2)&&(LIBGNUTLS_VERSION_MINOR>=5))
    p_idx = 3; q_idx = 4;
#else /* versions 2.4.x and older need 'p' and 'q' swapped */
    p_idx = 4; q_idx = 3;
#endif

    /* RSA get parameter */
    if (gnutls_x509_privkey_export_rsa_raw(priv_key,
                                           &rsa_datum[0],
                                           &rsa_datum[1],
                                           &rsa_datum[2],
                                           &rsa_datum[p_idx],
                                           &rsa_datum[q_idx],
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

    ssl_get_version(&major, &minor, &patch);

    /* certain versions of gnutls require swap of rsa params 'p' and 'q' */
    if ((major <= 1) && (minor <= 0) && (patch <=13))
    {
        gcry_mpi_t tmp;
        ssl_debug_printf("ssl_load_key: swapping p and q parameters\n");
        tmp = rsa_params[4];
        rsa_params[4] = rsa_params[3];
        rsa_params[3] = tmp;
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

#if SSL_FAST
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
    /* gnutls make our work much harded, since we have to work internally with
     * s-exp formatted data, but PEM loader export only in "gnutls_datum"
     * format, and a datum -> s-exp convertion function does not exist.
     */
    gnutls_x509_privkey_t priv_key;
    gnutls_datum key;
    gint size;
    guint bytes;

    Ssl_private_key_t *private_key = g_malloc(sizeof(Ssl_private_key_t));
    private_key->x509_cert = 0;
    private_key->x509_pkey = 0;
    private_key->sexp_pkey = 0;

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
    key.data = g_malloc(size);
    key.size = size;
    bytes = (guint) fread(key.data, 1, key.size, fp);
    if (bytes < key.size) {
        ssl_debug_printf("ssl_load_key: can't read from file %d bytes, got %d\n",
            key.size, bytes);
        g_free(private_key);
        g_free(key.data);
        return NULL;
    }

    /* import PEM data*/
    if (gnutls_x509_privkey_import(priv_key, &key, GNUTLS_X509_FMT_PEM)!=0) {
        ssl_debug_printf("ssl_load_key: can't import pem data\n");
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

Ssl_private_key_t *
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd) {

    int i, j, ret;
    int rest;
    unsigned char *p;
    gnutls_datum_t data;
    gnutls_pkcs12_bag_t bag = NULL;
    gnutls_pkcs12_bag_type_t bag_type;
    size_t len, buf_len;
    static char buf_name[256];
    static char buf_email[128];
    unsigned char buf_keyid[32];

    gnutls_pkcs12_t       ssl_p12  = NULL;
    gnutls_x509_crt_t     ssl_cert = NULL;
    gnutls_x509_privkey_t ssl_pkey = NULL;

    Ssl_private_key_t *private_key = g_malloc(sizeof(Ssl_private_key_t));
    private_key->x509_cert = 0;
    private_key->x509_pkey = 0;
    private_key->sexp_pkey = 0;

    rest = 4096;
    data.data = g_malloc(rest);
    data.size = rest;
    p = data.data;
    while ((len = fread(p, 1, rest, fp)) > 0) {
        p += len;
        rest -= (int) len;
        if (!rest) {
            rest = 1024;
            data.data = g_realloc(data.data, data.size + rest);
            p = data.data + data.size;
            data.size += rest;
        }
    }
    data.size -= rest;
    ssl_debug_printf("%d bytes read\n", data.size);
    if (!feof(fp)) {
        ssl_debug_printf( "Error during certificate reading.\n");
        g_free(private_key);
        return 0;
    }

    ret = gnutls_pkcs12_init(&ssl_p12);
    if (ret < 0) {
        ssl_debug_printf("gnutls_pkcs12_init(&st_p12) - %s", gnutls_strerror(ret));
        g_free(private_key);
        return 0;
    }
    ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_DER, 0);
    g_free(data.data);
    if (ret < 0) {
        ssl_debug_printf("gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_DER, 0) - %s\n", gnutls_strerror(ret));
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
                ret = 0;
            }

            ret = gnutls_pkcs12_bag_get_data(bag, j, &data);
            if (ret < 0) continue;

            switch (bag_type) {

                case GNUTLS_BAG_CERTIFICATE:

                    ret = gnutls_x509_crt_init(&ssl_cert);
                    if (ret < 0) {
                        ssl_debug_printf( "gnutls_x509_crt_init(&ssl_cert) - %s\n", gnutls_strerror(ret));
                        g_free(private_key);
                        return 0;
                    }

                    ret = gnutls_x509_crt_import(ssl_cert, &data, GNUTLS_X509_FMT_DER);
                    if (ret < 0) {
                        ssl_debug_printf( "gnutls_x509_crt_import(ssl_cert, &data, GNUTLS_X509_FMT_DER) - %s\n", gnutls_strerror(ret));
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
                    ssl_debug_printf( "Certificate imported: %s <%s>, KeyID %s\n", buf_name, buf_email, bytes_to_str(buf_keyid, (int) buf_len));
                    break;

                case GNUTLS_BAG_PKCS8_KEY:
                case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:

                    ret = gnutls_x509_privkey_init(&ssl_pkey);
                    if (ret < 0) {
                        ssl_debug_printf( "gnutls_x509_privkey_init(&ssl_pkey) - %s\n", gnutls_strerror(ret));
                        g_free(private_key);
                        return 0;
                    }
                    ret = gnutls_x509_privkey_import_pkcs8(ssl_pkey, &data, GNUTLS_X509_FMT_DER, cert_passwd,
                                                           (bag_type==GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
                    if (ret < 0) {
                        ssl_debug_printf( "Can not decrypt private key - %s\n", gnutls_strerror(ret));
                        g_free(private_key);
                        return 0;
                    }

                    if (gnutls_x509_privkey_get_pk_algorithm(ssl_pkey) != GNUTLS_PK_RSA) {
                        ssl_debug_printf("ssl_load_pkcs12: private key public key algorithm isn't RSA\n");
                        g_free(private_key);
                        return 0;
                    }

                    private_key->x509_pkey = ssl_pkey;
                    private_key->sexp_pkey = ssl_privkey_to_sexp(ssl_pkey);
                    if ( !private_key->sexp_pkey ) {
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
#if SSL_FAST
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

gint
ssl_find_private_key(SslDecryptSession *ssl_session, GHashTable *key_hash, GTree* associations, packet_info *pinfo) {
    SslService dummy;
    char ip_addr_any[] = {0,0,0,0};
    guint32 port = 0;
    Ssl_private_key_t * private_key;

    /* we need to know which side of the conversation is speaking */
    if (ssl_packet_from_server(ssl_session, associations, pinfo)) {
        dummy.addr = pinfo->src;
        dummy.port = port = pinfo->srcport;
    } else {
        dummy.addr = pinfo->dst;
        dummy.port = port = pinfo->destport;
    }
    ssl_debug_printf("ssl_find_private_key server %s:%u\n",
                     ep_address_to_str(&dummy.addr),dummy.port);

    /* try to retrieve private key for this service. Do it now 'cause pinfo
     * is not always available
     * Note that with HAVE_LIBGNUTLS undefined private_key is allways 0
     * and thus decryption never engaged*/


    ssl_session->private_key = 0;
    private_key = g_hash_table_lookup(key_hash, &dummy);

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find private key for this server! Try it again with universal port 0\n");

        dummy.port = 0;
        private_key = g_hash_table_lookup(key_hash, &dummy);
    }

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find private key for this server (universal port)! Try it again with universal address 0.0.0.0\n");

        dummy.addr.type = AT_IPv4;
        dummy.addr.len = 4;
        dummy.addr.data = ip_addr_any;

        dummy.port = port;
        private_key = g_hash_table_lookup(key_hash, &dummy);
    }

    if (!private_key) {
        ssl_debug_printf("ssl_find_private_key can't find any private key!\n");
    } else {
        ssl_session->private_key = private_key->sexp_pkey;
    }

    return 0;
}

void
ssl_lib_init(void)
{
    const gchar* str = gnutls_check_version(NULL);

    /* get library version */
    /* old relase of gnutls does not define the appropriate macros, so get
     * them from the string*/
    ssl_debug_printf("gnutls version: %s\n", str);
    sscanf(str, "%d.%d.%d", &ver_major, &ver_minor, &ver_patch);
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
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd _U_) {
    ssl_debug_printf("ssl_load_pkcs12: impossible without gnutls. fp %p\n",fp);
    return NULL;
}

void
ssl_free_key(Ssl_private_key_t* key _U_)
{
}

gint
ssl_find_private_key(SslDecryptSession *ssl_session _U_, GHashTable *key_hash _U_, GTree* associations _U_, packet_info *pinfo _U_)
{
    return 0;
}

int
ssl_find_cipher(int num,SslCipherSuite* cs)
{
    ssl_debug_printf("ssl_find_cipher: dummy without gnutls. num %d cs %p\n",
        num,cs);
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

#endif /* HAVE_LIBGNUTLS */

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
    guint l, hash, len ;
    const guint* cur;
    key = (const SslService *)v;
    hash = key->port;
    len = key->addr.len;
    cur = (const guint*) key->addr.data;

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
    assoc = g_malloc(sizeof(SslAssociation));

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

    if(!assoc->handle) {
        fprintf(stderr, "association_add() could not find handle for protocol:%s\n",protocol);
    } else {
        if(port) {
            if(tcp)
                dissector_add_uint("tcp.port", port, handle);
            else
                dissector_add_uint("udp.port", port, handle);
        }
        g_tree_insert(associations, assoc, assoc);
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
    const SslAssociation *assoc_a=a, *assoc_b=b;
    if (assoc_a->tcp != assoc_b->tcp) return (assoc_a->tcp)?1:-1;
    return assoc_a->ssl_port - assoc_b->ssl_port;
}

SslAssociation*
ssl_association_find(GTree * associations, guint port, gboolean tcp)
{
    register SslAssociation* ret;
    SslAssociation assoc_tmp;

    assoc_tmp.tcp = tcp;
    assoc_tmp.ssl_port = port;
    ret = g_tree_lookup(associations, &assoc_tmp);

    ssl_debug_printf("association_find: %s port %d found %p\n", (tcp)?"TCP":"UDP", port, (void *)ret);
    return ret;
}

gint
ssl_assoc_from_key_list(gpointer key _U_, gpointer data, gpointer user_data)
{
    if (((SslAssociation*)data)->from_key_list)
        ep_stack_push((ep_stack_t)user_data, data);
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
    guchar* real_data;
    SslRecordInfo* rec;
    SslPacketInfo* pi;

    pi = p_get_proto_data(pinfo->fd, proto);
    if (!pi)
    {
        pi = se_alloc0(sizeof(SslPacketInfo));
        p_add_proto_data(pinfo->fd, proto, pi);
    }

    real_data = se_alloc(data_len);
    memcpy(real_data, data, data_len);

    rec = se_alloc(sizeof(SslRecordInfo));
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
    pi = p_get_proto_data(pinfo->fd, proto);

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
    SslDataInfo *rec, **prec;
    SslPacketInfo *pi;

    pi = p_get_proto_data(pinfo->fd, proto);
    if (!pi)
    {
        pi = se_alloc0(sizeof(SslPacketInfo));
        p_add_proto_data(pinfo->fd, proto,pi);
    }

    rec = se_alloc(sizeof(SslDataInfo)+data_len);
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
    SslDataInfo* rec;
    SslPacketInfo* pi;
    pi = p_get_proto_data(pinfo->fd, proto);

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
    SslService* service;
    Ssl_private_key_t * private_key, *tmp_private_key;
    FILE* fp = NULL;
    guint32 addr_data[4];
    int addr_len, at;
    address_type addr_type[2] = { AT_IPv4, AT_IPv6 };

    /* try to load keys file first */
    fp = ws_fopen(uats->keyfile, "rb");
    if (!fp) {
        fprintf(stderr, "Can't open file %s\n",uats->keyfile);
        return;
    }

    if ((gint)strlen(uats->password) == 0) {
         private_key = ssl_load_key(fp);
    } else {
        private_key = ssl_load_pkcs12(fp, uats->password);
    }

    fclose(fp);

    if (!private_key) {
        fprintf(stderr,"Can't load private key from %s\n", uats->keyfile);
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

        service = g_malloc(sizeof(SslService) + addr_len);
        service->addr.type = addr_type[at];
        service->addr.len = addr_len;
        service->addr.data = ((guchar*)service) + sizeof(SslService);
        memcpy((void*)service->addr.data, addr_data, addr_len);

        if(strcmp(uats->port,"start_tls")==0) {
            service->port = 0;
        } else {
            service->port = atoi(uats->port);
        }

        ssl_debug_printf("ssl_init %s addr '%s' (%s) port '%d' filename '%s' password(only for p12 file) '%s'\n",
            (addr_type[at] == AT_IPv4) ? "IPv4" : "IPv6", uats->ipaddr, ep_address_to_str(&service->addr),
            service->port, uats->keyfile, uats->password);

        ssl_debug_printf("ssl_init private key file %s successfully loaded.\n", uats->keyfile);

        /* if item exists, remove first */
        tmp_private_key = g_hash_table_lookup(key_hash, service);
        if (tmp_private_key) {
            g_hash_table_remove(key_hash, service);
            ssl_free_key(tmp_private_key);
        }

        g_hash_table_insert(key_hash, service, private_key);

        ssl_association_add(associations, handle, service->port, uats->protocol, tcp, TRUE);
    }
}

/* store master secret into session data cache */
void
ssl_save_session(SslDecryptSession* ssl, GHashTable *session_hash)
{
    /* allocate stringinfo chunks for session id and master secret data*/
    StringInfo* session_id;
    StringInfo* master_secret;
    session_id = se_alloc0(sizeof(StringInfo) + ssl->session_id.data_len);
    master_secret = se_alloc0(48 + sizeof(StringInfo));

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

void
ssl_restore_session(SslDecryptSession* ssl, GHashTable *session_hash)
{
    StringInfo* ms;
    ms = g_hash_table_lookup(session_hash, &ssl->session_id);

    if (!ms) {
        ssl_debug_printf("ssl_restore_session can't find stored session\n");
        return;
    }
    ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
    ssl->state |= SSL_MASTER_SECRET;
    ssl_debug_printf("ssl_restore_session master key retrieved\n");
}

int
ssl_is_valid_content_type(guint8 type)
{
    if (type >= 0x14 && type <= 0x17)
    {
        return 1;
    }

    return 0;
}

static guint8
from_hex_char(gchar c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return 16;
}

int
ssl_keylog_lookup(SslDecryptSession* ssl_session,
                  const gchar* ssl_keylog_filename,
                  StringInfo* encrypted_pre_master) {
    static const unsigned int kRSAPremasterLength = 48; /* RFC5246 7.4.7.1 */
    FILE* ssl_keylog;
    gsize bytes_read;
    int ret = -1;

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
     *   - "RSA Sesion-ID:xxxx Master-Key:yyyy"
     *     Where xxxx is the SSL session ID (hex-encoded)
     *     Where yyyy is the cleartext master secret (hex-encoded)
     *     (added to support openssl s_client Master-Key output)
     */
    for (;;) {
        char buf[512], *line;
        unsigned int i;
        unsigned int offset;

        line = fgets(buf, sizeof(buf), ssl_keylog);
        if (!line)
                break;

        bytes_read = strlen(line);
        /* fgets includes the \n at the end of the line. */
        if (bytes_read > 0) {
            line[bytes_read - 1] = 0;
            bytes_read--;
        }

        ssl_debug_printf("  checking keylog line: %s\n", line);

        if ( memcmp(line, "RSA ", 4) != 0) {
            ssl_debug_printf("    rejecting line due to bad format\n");
            continue;
        }

        offset = 4;

        if ( ssl_session->session_id.data_len>0 && memcmp(line+offset,"Session-ID:",11) == 0 ) {
            offset += 11;
            for (i = 0; i < ssl_session->session_id.data_len; i++) {
                if (from_hex_char(line[offset + i*2]) != (ssl_session->session_id.data[i] >> 4) ||
                    from_hex_char(line[offset + i*2 + 1]) != (ssl_session->session_id.data[i] & 15)) {
                    line = NULL;
                    break;
                }
            }

            if (line == NULL) {
                ssl_debug_printf("    line does not match SSL-ID\n");
                continue;
            }

            offset += 2*ssl_session->session_id.data_len;
            offset++;

        } else if( line[offset+16] == ' ' ) {
            for (i = 0; i < 8; i++) {
                if (from_hex_char(line[offset + i*2]) != (encrypted_pre_master->data[i] >> 4) ||
                    from_hex_char(line[offset + i*2 + 1]) != (encrypted_pre_master->data[i] & 15)) {
                    line = NULL;
                    break;
                }
            }

            if (line == NULL) {
                ssl_debug_printf("    line does not match encrypted pre-master secret\n");
                continue;
            }

            offset += 17;

        } else {
            ssl_debug_printf("    rejecting line due to bad format\n");
            continue;
        }


        /* This record seems to match. */
        if (memcmp(line+offset, "Master-Key:", 11) == 0) {
            /* Key is a MasterSecret */
            offset += 11;
            ssl_session->master_secret.data = se_alloc(kRSAPremasterLength);
            for (i = 0; i < kRSAPremasterLength; i++) {
                guint8 a = from_hex_char(line[offset + i*2]);
                guint8 b = from_hex_char(line[offset + i*2 + 1]);
                if (a == 16 || b == 16) {
                    line = NULL;
                    break;
                }
                ssl_session->master_secret.data[i] = a << 4 | b;
            }

            if (line == NULL) {
                ssl_debug_printf("    line contains non-hex chars in master secret\n");
                continue;
            }

            ssl_session->master_secret.data_len = kRSAPremasterLength;
            ssl_session->state &= ~(SSL_PRE_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
            ssl_session->state |= SSL_MASTER_SECRET;
            ssl_debug_printf("found master secret in key log\n");
            ret = 0;
            break;

        } else {
            /* Key is a PreMasterSecret */
            ssl_session->pre_master_secret.data = se_alloc(kRSAPremasterLength);
            for (i = 0; i < kRSAPremasterLength; i++) {
                guint8 a = from_hex_char(line[offset + i*2]);
                guint8 b = from_hex_char(line[offset + i*2 + 1]);
                if (a == 16 || b == 16) {
                    line = NULL;
                    break;
                }
                ssl_session->pre_master_secret.data[i] = a << 4 | b;
            }

            if (line == NULL) {
                ssl_debug_printf("    line contains non-hex chars in pre-master secret\n");
                continue;
            }

            ssl_session->pre_master_secret.data_len = kRSAPremasterLength;
            ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
            ssl_session->state |= SSL_PRE_MASTER_SECRET;
            ssl_debug_printf("found pre-master secret in key log\n");
            ret = 0;
            break;
        }
    }

    fclose(ssl_keylog);
    return ret;
}

#ifdef SSL_DECRYPT_DEBUG

static FILE* ssl_debug_file=NULL;

void
ssl_set_debug(char* name)
{
    static gint debug_file_must_be_closed;
    gint use_stderr;
    debug_file_must_be_closed = 0;
    use_stderr = name?(strcmp(name, SSL_DEBUG_USE_STDERR) == 0):0;

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
    gint ret;
    ret=0;

    if (!ssl_debug_file)
        return;

    va_start(ap, fmt);
    ret += vfprintf(ssl_debug_file, fmt, ap);
    va_end(ap);
}

void
ssl_print_text_data(const gchar* name, const guchar* data, size_t len)
{
    size_t i;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s: ",name);
    for (i=0; i< len; i++) {
      fprintf(ssl_debug_file,"%c",data[i]);
    }
    fprintf(ssl_debug_file,"\n");
}

void
ssl_print_data(const gchar* name, const guchar* data, size_t len)
{
    size_t i;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i< len; i++) {
        if ((i>0) && (i%16 == 0))
            fprintf(ssl_debug_file,"\n");
        fprintf(ssl_debug_file,"%.2x ",data[i]&255);
    }
    fprintf(ssl_debug_file,"\n");
}

void
ssl_print_string(const gchar* name, const StringInfo* data)
{
    ssl_print_data(name, data->data, data->data_len);
}
#endif /* SSL_DECRYPT_DEBUG */

/* checks for SSL and DTLS UAT key list fields */

gboolean
ssldecrypt_uat_fld_ip_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No IP address given.");
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_port_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No Port given.");
        return FALSE;
    }

    if (strcmp(p, "start_tls") != 0){
        const gint i = atoi(p);
        if (i <= 0 || i > 65535) {
            *err = ep_strdup_printf("Invalid port given.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_protocol_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = ep_strdup_printf("No protocol given.");
        return FALSE;
    }

    if (!find_dissector(p)) {
        *err = ep_strdup_printf("Could not find dissector for: '%s'", p);
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

gboolean
ssldecrypt_uat_fld_fileopen_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
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
ssldecrypt_uat_fld_password_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, const char** err)
{
    ssldecrypt_assoc_t* f = r;
    FILE *fp = NULL;

    if (p && strlen(p) > 0u) {
        fp = ws_fopen(f->keyfile, "rb");
        if (fp) {
            if (!ssl_load_pkcs12(fp, p)) {
                fclose(fp);
                *err = ep_strdup_printf("Invalid. Password is necessary only if you use PKCS#12 key file.");
                return FALSE;
            }
            fclose(fp);
        } else {
            *err = ep_strdup_printf("Leave this field blank if the keyfile is not PKCS#12.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
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
