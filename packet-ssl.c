/* packet-ssl.c
 * Routines for ssl dissection
 * Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
 *
 * $Id: packet-ssl.c,v 1.6 2001/09/03 10:33:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Notes:
 *
 *   - Uses conversations in a no-malloc fashion.  Since we just want to
 *     remember the version of the conversation, we store the version
 *     integer directly in the void *data member of the conversation
 *     structure.  This means that we don't have to manage any memory,
 *     but will cause problems if anyone assumes that all data pointers
 *     are actually pointers to memory allocated by g_mem_chunk_alloc.
 *
 *   - Does not support decryption of encrypted frames, nor dissection
 *     of frames that would require state maintained between frames
 *     (e.g., single ssl records spread across multiple tcp frames)
 *
 *   - Identifies, but does not fully dissect the following messages:
 *
 *     - SSLv3/TLS (These need more state from previous handshake msgs)
 *       - Server Key Exchange
 *       - Client Key Exchange
 *       - Certificate Verify
 *
 *     - SSLv2 (These don't appear in the clear)
 *       - Error
 *       - Client Finished
 *       - Server Verify
 *       - Server Finished
 *       - Request Certificate
 *       - Client Certificate
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "conversation.h"

/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* Initialize the protocol and registered fields */
static int proto_ssl                         = -1;
static int hf_ssl_record                     = -1;
static int hf_ssl_record_content_type        = -1;
static int hf_ssl_record_version             = -1;
static int hf_ssl_record_length              = -1;
static int hf_ssl_record_appdata             = -1;
static int hf_ssl2_record                    = -1;
static int hf_ssl2_record_is_escape          = -1;
static int hf_ssl2_record_padding_length     = -1;
static int hf_ssl2_msg_type                  = -1;
static int hf_ssl_change_cipher_spec         = -1;
static int hf_ssl_alert_message              = -1;
static int hf_ssl_alert_message_level        = -1;
static int hf_ssl_alert_message_description  = -1;
static int hf_ssl_handshake_protocol         = -1;
static int hf_ssl_handshake_type             = -1;
static int hf_ssl_handshake_length           = -1;
static int hf_ssl_handshake_client_version   = -1;
static int hf_ssl_handshake_server_version   = -1;
static int hf_ssl_handshake_random_time      = -1;
static int hf_ssl_handshake_random_bytes     = -1;
static int hf_ssl_handshake_cipher_suites_len = -1;
static int hf_ssl_handshake_cipher_suites    = -1;
static int hf_ssl_handshake_cipher_suite     = -1;
static int hf_ssl_handshake_session_id       = -1;
static int hf_ssl_handshake_comp_methods_len = -1;
static int hf_ssl_handshake_comp_methods     = -1;
static int hf_ssl_handshake_comp_method      = -1;
static int hf_ssl_handshake_certificates_len = -1;
static int hf_ssl_handshake_certificates     = -1;
static int hf_ssl_handshake_certificate      = -1;
static int hf_ssl_handshake_certificate_len  = -1;
static int hf_ssl_handshake_cert_types_count = -1;
static int hf_ssl_handshake_cert_types       = -1;
static int hf_ssl_handshake_cert_type        = -1;
static int hf_ssl_handshake_finished         = -1;
static int hf_ssl_handshake_md5_hash         = -1;
static int hf_ssl_handshake_sha_hash         = -1;
static int hf_ssl_handshake_session_id_len   = -1;
static int hf_ssl_handshake_dnames_len       = -1;
static int hf_ssl_handshake_dnames           = -1;
static int hf_ssl_handshake_dname_len        = -1;
static int hf_ssl_handshake_dname            = -1;
static int hf_ssl2_handshake_cipher_spec_len = -1;
static int hf_ssl2_handshake_session_id_len  = -1;
static int hf_ssl2_handshake_challenge_len   = -1;
static int hf_ssl2_handshake_cipher_spec     = -1;
static int hf_ssl2_handshake_challenge       = -1;
static int hf_ssl2_handshake_clear_key_len   = -1;
static int hf_ssl2_handshake_enc_key_len     = -1;
static int hf_ssl2_handshake_key_arg_len     = -1;
static int hf_ssl2_handshake_clear_key       = -1;
static int hf_ssl2_handshake_enc_key         = -1;
static int hf_ssl2_handshake_key_arg         = -1;
static int hf_ssl2_handshake_session_id_hit  = -1;
static int hf_ssl2_handshake_cert_type       = -1;
static int hf_ssl2_handshake_connection_id_len = -1;
static int hf_ssl2_handshake_connection_id   = -1;

/* Initialize the subtree pointers */
static gint ett_ssl                   = -1;
static gint ett_ssl_record            = -1;
static gint ett_ssl_alert             = -1;
static gint ett_ssl_handshake         = -1;
static gint ett_ssl_cipher_suites     = -1;
static gint ett_ssl_comp_methods      = -1;
static gint ett_ssl_certs             = -1;
static gint ett_ssl_cert_types        = -1;
static gint ett_ssl_dnames            = -1;

/* The TCP port to associate with by default */
#define TCP_PORT_SSL                    443

/* version state tables */
#define SSL_VER_UNKNOWN                   0
#define SSL_VER_SSLv2                     1
#define SSL_VER_SSLv3                     2
#define SSL_VER_TLS                       3

/* corresponds to the #defines above */
static gchar* ssl_version_short_names[] = {
    "SSL",
    "SSLv2",
    "SSLv3",
    "TLS",
};

/* other defines */
#define SSL_ID_CHG_CIPHER_SPEC         0x14
#define SSL_ID_ALERT                   0x15
#define SSL_ID_HANDSHAKE               0x16
#define SSL_ID_APP_DATA                0x17

#define SSL_HND_HELLO_REQUEST          0x00
#define SSL_HND_CLIENT_HELLO           0x01
#define SSL_HND_SERVER_HELLO           0x02
#define SSL_HND_CERTIFICATE            0x0b
#define SSL_HND_SERVER_KEY_EXCHG       0x0c
#define SSL_HND_CERT_REQUEST           0x0d
#define SSL_HND_SVR_HELLO_DONE         0x0e
#define SSL_HND_CERT_VERIFY            0x0f
#define SSL_HND_CLIENT_KEY_EXCHG       0x10
#define SSL_HND_FINISHED               0x14

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

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
    { 0x000062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
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
    { 0x0301, "TLS 1.0" },
    { 0x0300, "SSL 3.0" },
    { 0x0002, "SSL 2.0" },
    { 0x00, NULL }
};

static const value_string ssl_31_change_cipher_spec[] = {
    { 1, "Change Cipher Spec" },
    { 0x00, NULL },
};

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
    { 0x00, NULL }
};

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

static const value_string ssl_31_client_certificate_type[] = {
    { 1, "RSA Sign" },
    { 2, "DSS Sign" },
    { 3, "RSA Fixed DH" },
    { 4, "DSS Fixed DH" },
    { 0x00, NULL }
};

static const value_string ssl_31_public_value_encoding[] = {
    { 0, "Implicit" },
    { 1, "Explicit" },
    { 0x00, NULL }
};

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
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    /* note that ciphersuites 0xff00 - 0xffff are private */
    { 0x00, NULL }
};

/*********************************************************************
 *
 * Forward Declarations
 *
 *********************************************************************/

/*
 * SSL version 3 and TLS dissectors
 *
 */
/* record layer dissector */
static int dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version);

/* change cipher spec dissector */
static void dissect_ssl3_change_cipher_spec(tvbuff_t *tvb, packet_info *pinfo,
                                            proto_tree *tree,
                                            guint32 offset,
                                            guint *conv_version);

/* alert message dissector */
static void dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version);

/* handshake protocol dissector */
static void dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint32 record_length,
                                   guint *conv_version);


static void dissect_ssl3_hnd_cli_hello(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree,
                                       guint32 offset);

static void dissect_ssl3_hnd_srv_hello(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree,
                                       guint32 offset);

static void dissect_ssl3_hnd_cert(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, guint32 offset);

static void dissect_ssl3_hnd_cert_req(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree,
                                      guint32 offset);

static void dissect_ssl3_hnd_finished(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree,
                                      guint32 offset,
                                      guint *conv_version);


/*
 * SSL version 2 dissectors
 *
 */

/* record layer dissector */
static int dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version);

/* client hello dissector */
static void dissect_ssl2_hnd_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree,
                                          guint32 offset);

/* client master key dissector */
static void dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb,
                                               packet_info *pinfo,
                                               proto_tree *tree,
                                               guint32 offset);

/* server hello dissector */
static void dissect_ssl2_hnd_server_hello(tvbuff_t *tvb,
                                          packet_info *pinfo,
                                          proto_tree *tree,
                                          guint32 offset);

/*
 * Support Functions
 *
 */
static void ssl_set_conv_version(packet_info *pinfo, guint version);
static int  ssl_is_valid_handshake_type(guint8 type);
static int  ssl_is_valid_content_type(guint8 type);
static int  ssl_is_valid_ssl_version(guint16 version);
static int  ssl_is_authoritative_version_message(guint8 content_type,
                                                guint8 next_byte);
static int  ssl_is_v2_client_hello(tvbuff_t *tvb, guint32 offset);
static int  ssl_looks_like_sslv2(tvbuff_t *tvb, guint32 offset);
static int  ssl_looks_like_sslv3(tvbuff_t *tvb, guint32 offset);
static int  ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb,
                                              guint32 offset,
                                              guint32 record_length);

/*********************************************************************
 *
 * Main dissector
 *
 *********************************************************************/
/*
 * Code to actually dissect the packets
 */
static void
dissect_ssl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    conversation_t *conversation;
    void *conv_data;
    guint conv_version     = SSL_VER_UNKNOWN;
    proto_item *ti         = NULL;
    proto_tree *ssl_tree   = NULL;
    guint32 offset         = 0;
    gboolean first_record_in_frame = TRUE;

    /* Track the version using conversations to reduce the
     * chance that a packet that simply *looks* like a v2 or
     * v3 packet is dissected improperly.  This also allows
     * us to more frequently set the protocol column properly
     * for continuation data frames.
     *
     * Also: We use the copy in conv_version as our cached copy,
     *       so that we don't have to search the conversation
     *       table every time we want the version; when setting
     *       the conv_version, must set the copy in the conversation
     *       in addition to conv_version
     */
    conversation = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype,
                                     pinfo->srcport, pinfo->destport, 0);
    if (!conversation)
    {
        /* create a new conversation */
        conversation = conversation_new(&pinfo->src, &pinfo->dst, pinfo->ptype,
                                        pinfo->srcport, pinfo->destport, 0);
    }
    conv_data = conversation_get_proto_data(conversation, proto_ssl);
    if (conv_data != NULL)
    {
        conv_version = (guint)conv_data;
    }

    /* Initialize the protocol column; we'll set it later when we
     * figure out what flavor of SSL it is (assuming we don't
     * throw an exception before we get the chance to do so). */
    if (check_col(pinfo->fd, COL_PROTOCOL))
    {
        col_set_str(pinfo->fd, COL_PROTOCOL, "SSL");
    }

    /* clear the the info column */
    if (check_col(pinfo->fd, COL_INFO))
        col_clear(pinfo->fd, COL_INFO);

    /* TCP packets and SSL records are orthogonal.
     * A tcp packet may contain multiple ssl records and an ssl
     * record may be spread across multiple tcp packets.
     *
     * This loop accounts for multiple ssl records in a single
     * frame, but not a single ssl record across multiple tcp
     * packets.
     *
     * Handling the single ssl record across multiple packets
     * may be possible using ethereal conversations, but
     * probably not cleanly.  May have to wait for tcp stream
     * reassembly.
     */

    /* Create display subtree for SSL as a whole */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_ssl, tvb,
                                 0, tvb_length(tvb), FALSE);
        ssl_tree = proto_item_add_subtree(ti, ett_ssl);
    }

    /* iterate through the records in this frame */
    while (offset < tvb_length(tvb)-1)
    {
        /* on second and subsequent records per frame
         * add a delimiter on info column
         */
        if (!first_record_in_frame
            && check_col(pinfo->fd, COL_INFO))
        {
            col_append_str(pinfo->fd, COL_INFO, ", ");
        }

        /* first try to dispatch off the cached version
         * known to be associated with the conversation
         */
        switch(conv_version) {
        case SSL_VER_SSLv2:
            offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                         offset, &conv_version);
            break;

        case SSL_VER_SSLv3:
        case SSL_VER_TLS:
            /* the version tracking code works too well ;-)
             * at times, we may visit a v2 client hello after
             * we already know the version of the connection;
             * work around that here by detecting and calling
             * the v2 dissector instead
             */
            if (ssl_is_v2_client_hello(tvb, offset))
            {
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, &conv_version);
            }
            else
            {
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, &conv_version);
            }
            break;

            /* that failed, so apply some heuristics based
             * on this individual packet
             */
        default:
            if (ssl_looks_like_sslv2(tvb, offset))
            {
                /* looks like sslv2 client hello */
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, &conv_version);
            }
            else if (ssl_looks_like_sslv3(tvb, offset))
            {
                /* looks like sslv3 or tls */
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, &conv_version);
            }
            else
            {
                /* looks like something unknown, so lump into
                 * continuation data
                 */
                offset = tvb_length(tvb);
                if (check_col(pinfo->fd, COL_INFO))
                    col_append_str(pinfo->fd, COL_INFO,
                                   "Continuation Data");

                /* Set the protocol column */
                if (check_col(pinfo->fd, COL_PROTOCOL))
                {
                    col_set_str(pinfo->fd, COL_PROTOCOL,
                         ssl_version_short_names[conv_version]);
                }
            }
            break;
        }

        /* If we haven't already set the version information for
         * this conversation, do so. */
        if (conv_data == NULL)
        {
            conv_data = (void *)conv_version;
            conversation_add_proto_data(conversation, proto_ssl, conv_data);
        }

        /* set up for next record in frame, if any */
        first_record_in_frame = FALSE;
    }

}


/*********************************************************************
 *
 * SSL version 3 and TLS Dissection Routines
 *
 *********************************************************************/
static int
dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, guint32 offset,
                    guint *conv_version)
{

    /*
     *    struct {
     *        uint8 major, minor;
     *    } ProtocolVersion;
     *
     *
     *    enum {
     *        change_cipher_spec(20), alert(21), handshake(22),
     *        application_data(23), (255)
     *    } ContentType;
     *
     *    struct {
     *        ContentType type;
     *        ProtocolVersion version;
     *        uint16 length;
     *        opaque fragment[TLSPlaintext.length];
     *    } TLSPlaintext;
     */
    guint32 record_length;
    guint16 version;
    guint8 content_type;
    guint8 next_byte;
    proto_tree *ti              = NULL;
    proto_tree *ssl_record_tree = NULL;

    /*
     * Get the record layer fields of interest
     */
    content_type  = tvb_get_guint8(tvb, offset);
    version       = tvb_get_ntohs(tvb, offset + 1);
    record_length = tvb_get_ntohs(tvb, offset + 3);

    /* if we don't have a valid content_type, there's no sense
     * continuing any further
     */
    if (!ssl_is_valid_content_type(content_type))
    {
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, "Continuation Data");

        /* Set the protocol column */
        if (check_col(pinfo->fd, COL_PROTOCOL))
        {
            col_set_str(pinfo->fd, COL_PROTOCOL,
                        ssl_version_short_names[*conv_version]);
        }
        return offset + 5 + record_length;
    }

    /*
     * If GUI, fill in record layer part of tree
     */
    if (tree)
    {

        /* add the record layer subtree header */
        ti = proto_tree_add_item(tree, hf_ssl_record, tvb,
                                 offset, 5 + record_length, 0);
        ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);
    }
    if (ssl_record_tree)
    {

        /* show the one-byte content type */
        proto_tree_add_item(ssl_record_tree, hf_ssl_record_content_type,
                            tvb, offset, 1, 0);
        offset++;

        /* add the version */
        proto_tree_add_item(ssl_record_tree, hf_ssl_record_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        /* add the length */
        proto_tree_add_uint(ssl_record_tree, hf_ssl_record_length, tvb,
                            offset, 2, record_length);
        offset += 2;    /* move past length field itself */
    }
    else
    {
        /* if no GUI tree, then just skip over those fields */
        offset += 5;
    }


    /*
     * if we don't already have a version set for this conversation,
     * but this message's version is authoritative (i.e., it's
     * not client_hello, then save the version to to conversation
     * structure and print the column version
     */
    next_byte = tvb_get_guint8(tvb, offset);
    if (*conv_version == SSL_VER_UNKNOWN
        && ssl_is_authoritative_version_message(content_type, next_byte))
    {
        if (version == 0x0300)
        {
            *conv_version = SSL_VER_SSLv3;
            ssl_set_conv_version(pinfo, *conv_version);
        }
        else if (version == 0x0301)
        {
            *conv_version = SSL_VER_TLS;
            ssl_set_conv_version(pinfo, *conv_version);
        }
    }
    if (check_col(pinfo->fd, COL_PROTOCOL))
    {
        if (version == 0x0300)
        {
            col_set_str(pinfo->fd, COL_PROTOCOL,
                        ssl_version_short_names[SSL_VER_SSLv3]);
        }
        else if (version == 0x0301)
        {
            col_set_str(pinfo->fd, COL_PROTOCOL,
                        ssl_version_short_names[SSL_VER_TLS]);
        }
        else
        {
            col_set_str(pinfo->fd, COL_PROTOCOL,
                        ssl_version_short_names[*conv_version]);
        }
    }

    /*
     * now dissect the next layer
     */
    switch (content_type) {
    case SSL_ID_CHG_CIPHER_SPEC:
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, "Change Cipher Spec");
        dissect_ssl3_change_cipher_spec(tvb, pinfo, ssl_record_tree,
                                        offset, conv_version);
        break;
    case SSL_ID_ALERT:
        dissect_ssl3_alert(tvb, pinfo, ssl_record_tree, offset,
                           conv_version);
        break;
    case SSL_ID_HANDSHAKE:
        dissect_ssl3_handshake(tvb, pinfo, ssl_record_tree, offset,
                               record_length, conv_version);
        break;
    case SSL_ID_APP_DATA:
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, "Application Data");
        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree,
                                "%s Record Layer: Application Data",
                                ssl_version_short_names[*conv_version]);
            proto_tree_add_item(ssl_record_tree, hf_ssl_record_appdata, tvb,
                                offset, record_length, 0);
        }
        break;

    default:
        /* shouldn't get here since we check above for valid types */
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, "Bad SSLv3 Content Type");
        break;
    }
    offset += record_length; /* skip to end of record */

    return offset;
}

/* dissects the change cipher spec procotol, filling in the tree */
static void
dissect_ssl3_change_cipher_spec(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset,
                                guint *conv_version)
{
    /*
     * struct {
     *     enum { change_cipher_spec(1), (255) } type;
     * } ChangeCipherSpec;
     *
     */
    if (tree)
    {
        proto_item_set_text(tree,
                            "%s Record Layer: Change Cipher Spec",
                            ssl_version_short_names[*conv_version]);
        proto_tree_add_item(tree, hf_ssl_change_cipher_spec, tvb,
                            offset++, 1, FALSE);
    }
}

/* dissects the alert message, filling in the tree */
static void
dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, guint32 offset,
                   guint *conv_version)
{
    /*     struct {
     *         AlertLevel level;
     *         AlertDescription description;
     *     } Alert;
     */
    proto_tree *ti;
    proto_tree *ssl_alert_tree = NULL;
    gchar *level;
    gchar *desc;
    guint8 byte;
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_ssl_alert_message, tvb,
                                 offset, 2, 0);
        ssl_alert_tree = proto_item_add_subtree(ti, ett_ssl_alert);
    }

    /*
     * set the record layer label
     */

    /* first lookup the names for the alert level and description */
    byte = tvb_get_guint8(tvb, offset); /* grab the level byte */
    level = match_strval(byte, ssl_31_alert_level);

    byte = tvb_get_guint8(tvb, offset+1); /* grab the desc byte */
    desc = match_strval(byte, ssl_31_alert_description);

    /* now set the text in the record layer line */
    if (level && desc)
    {
        if (check_col(pinfo->fd, COL_INFO))
            col_append_fstr(pinfo->fd, COL_INFO,
                            "Alert (Level: %s, Description: %s)",
                            level, desc);
    }
    else
    {
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, "Encrypted Alert");
    }

    if (tree)
    {
        if (level && desc)
        {
            proto_item_set_text(tree, "%s Record Layer: Alert "
                                "(Level: %s, Description: %s)",
                                ssl_version_short_names[*conv_version],
                                level, desc);
            proto_tree_add_item(ssl_alert_tree, hf_ssl_alert_message_level,
                                tvb, offset++, 1, FALSE);

            proto_tree_add_item(ssl_alert_tree, hf_ssl_alert_message_description,
                                tvb, offset++, 1, FALSE);
        }
        else
        {
            proto_item_set_text(tree,
                                "%s Record Layer: Encrypted Alert",
                                ssl_version_short_names[*conv_version]);
            proto_item_set_text(ssl_alert_tree,
                                "Alert Message: Encrypted Alert");
        }
    }
}


/* dissects the handshake protocol, filling the tree */
static void
dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 record_length, guint *conv_version)
{
    /*     struct {
     *         HandshakeType msg_type;
     *         uint24 length;
     *         select (HandshakeType) {
     *             case hello_request:       HelloRequest;
     *             case client_hello:        ClientHello;
     *             case server_hello:        ServerHello;
     *             case certificate:         Certificate;
     *             case server_key_exchange: ServerKeyExchange;
     *             case certificate_request: CertificateRequest;
     *             case server_hello_done:   ServerHelloDone;
     *             case certificate_verify:  CertificateVerify;
     *             case client_key_exchange: ClientKeyExchange;
     *             case finished:            Finished;
     *         } body;
     *     } Handshake;
     */
    proto_tree *ti            = NULL;
    proto_tree *ssl_hand_tree = NULL;
    gchar *msg_type_str       = NULL;
    guint8 msg_type;
    guint32 length;
    gboolean first_iteration  = TRUE;


    /* just as there can be multiple records per packet, there
     * can be multiple messages per record as long as they have
     * the same content type
     *
     * we really only care about this for handshake messages
     */

    /* set record_length to the max offset */
    record_length += offset;
    while (offset < record_length)
    {
        msg_type = tvb_get_guint8(tvb, offset);
        msg_type_str = match_strval(msg_type, ssl_31_handshake_type);
        length   = tvb_get_ntoh24(tvb, offset + 1);

        if (!msg_type_str && !first_iteration)
        {
            /* only dissect / report messages if they're
             * either the first message in this record
             * or they're a valid message type
             */
            return;
        }

        /* on second and later iterations, add comma to info col */
        if (!first_iteration)
        {
            if (check_col(pinfo->fd, COL_INFO))
                col_append_fstr(pinfo->fd, COL_INFO, ", ");
        }

        /*
         * Update our info string
         */
        if (check_col(pinfo->fd, COL_INFO))
            col_append_fstr(pinfo->fd, COL_INFO, "%s", (msg_type_str != NULL)
                            ? msg_type_str : "Encrypted Handshake Message");

        if (tree)
        {
            /* set the label text on the record layer expanding node */
            if (first_iteration)
            {
                proto_item_set_text(tree, "%s Record Layer: %s",
                                    ssl_version_short_names[*conv_version],
                                    (msg_type_str!=NULL) ? msg_type_str :
                                    "Encrypted Handshake Message");
            }
            else
            {
                proto_item_set_text(tree, "%s Record Layer: %s",
                                    ssl_version_short_names[*conv_version],
                                    "Multiple Handshake Messages");
            }

            /* add a subtree for the handshake protocol */
            ti = proto_tree_add_item(tree, hf_ssl_handshake_protocol, tvb,
                                     offset, length + 4, 0);
            ssl_hand_tree = proto_item_add_subtree(ti, ett_ssl_handshake);

            if (ssl_hand_tree)
            {
                /* set the text label on the subtree node */
                proto_item_set_text(ssl_hand_tree, "Handshake Protocol: %s",
                                    (msg_type_str != NULL) ? msg_type_str :
                                    "Encrypted Handshake Message");
            }
        }

        /* if we don't have a valid handshake type, just quit dissecting */
        if (!msg_type_str)
        {
            return;
        }

        if (ssl_hand_tree)
        {
            /* add nodes for the message type and message length */
            proto_tree_add_item(ssl_hand_tree, hf_ssl_handshake_type,
                                tvb, offset, 1, msg_type);
            offset++;
            proto_tree_add_uint(ssl_hand_tree, hf_ssl_handshake_length,
                                tvb, offset, 3, length);
            offset += 3;

            /* now dissect the handshake message, if necessary */
            switch (msg_type) {
            case SSL_HND_HELLO_REQUEST:
                /* hello_request has no fields, so nothing to do! */
                break;

            case SSL_HND_CLIENT_HELLO:
                dissect_ssl3_hnd_cli_hello(tvb, pinfo, ssl_hand_tree, offset);
            break;

            case SSL_HND_SERVER_HELLO:
                dissect_ssl3_hnd_srv_hello(tvb, pinfo, ssl_hand_tree, offset);
                break;

            case SSL_HND_CERTIFICATE:
                dissect_ssl3_hnd_cert(tvb, pinfo, ssl_hand_tree, offset);
                break;

            case SSL_HND_CERT_REQUEST:
                dissect_ssl3_hnd_cert_req(tvb, pinfo, ssl_hand_tree, offset);
                break;

            case SSL_HND_SVR_HELLO_DONE:
                /* server_hello_done has no fields, so nothing to do! */
                break;

            case SSL_HND_FINISHED:
                dissect_ssl3_hnd_finished(tvb, pinfo, ssl_hand_tree,
                                          offset, conv_version);
                break;

            case SSL_HND_SERVER_KEY_EXCHG:
            case SSL_HND_CERT_VERIFY:
            case SSL_HND_CLIENT_KEY_EXCHG:
                /* unimplemented */
                break;
            }

        }
        else
        {
            offset += 4;        /* skip the handshake header */
        }
        offset += length;
        first_iteration = FALSE; /* set up for next pass, if any */
    }
}

static int
dissect_ssl3_hnd_hello_common(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset)
{
    /* show the client's random challenge */
    guint32 initial_offset = offset;
    struct timeval gmt_unix_time;
    guint8  session_id_length = 0;

    if (tree)
    {
        /* show the time */
        gmt_unix_time.tv_sec = tvb_get_ntohl(tvb, offset);
        gmt_unix_time.tv_usec = 0;
        proto_tree_add_time(tree, hf_ssl_handshake_random_time,
                                     tvb, offset, 4, &gmt_unix_time);
        offset += 4;

        /* show the random bytes */
        proto_tree_add_item(tree, hf_ssl_handshake_random_bytes,
                            tvb, offset, 28, 0);
        offset += 28;

        /* show the session id */
        session_id_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ssl_handshake_session_id_len,
                            tvb, offset++, 1, 0);
        if (session_id_length > 0)
        {
            proto_tree_add_bytes_format(tree, hf_ssl_handshake_session_id,
                                         tvb, offset, session_id_length,
                                         tvb_get_ptr(tvb, offset, session_id_length),
                                         "Session ID (%u byte%s)",
                                         session_id_length,
                                         plurality(session_id_length, "", "s"));
            offset += session_id_length;
        }

    }
    return offset - initial_offset;
}

static void
dissect_ssl3_hnd_cli_hello(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, guint32 offset)
{
    /* struct {
     *     ProtocolVersion client_version;
     *     Random random;
     *     SessionID session_id;
     *     CipherSuite cipher_suites<2..2^16-1>;
     *     CompressionMethod compression_methods<1..2^8-1>;
     * } ClientHello;
     *
     */
    proto_tree *ti;
    proto_tree *cs_tree;
    guint16 cipher_suite_length = 0;
    guint8  compression_methods_length = 0;

    if (tree)
    {
        /* show the client version */
        proto_tree_add_item(tree, hf_ssl_handshake_client_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        /* show the fields in common with server hello */
        offset += dissect_ssl3_hnd_hello_common(tvb, tree, offset);

        /* tell the user how many cipher suites there are */
        cipher_suite_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_cipher_suites_len,
                            tvb, offset, 2, cipher_suite_length);
        offset += 2;            /* skip opaque length */

        if (cipher_suite_length > 0)
        {
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_cipher_suites,
                                            tvb, offset, cipher_suite_length,
                                            "Cipher Suites (%u suite%s)",
                                            cipher_suite_length / 2,
                                            plurality(cipher_suite_length/2, "", "s"));

            /* make this a subtree */
            cs_tree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
            if (!cs_tree)
            {
                cs_tree = tree; /* failsafe */
            }

            while (cipher_suite_length > 0)
            {
                proto_tree_add_item(cs_tree, hf_ssl_handshake_cipher_suite,
                                    tvb, offset, 2, FALSE);
                offset += 2;
                cipher_suite_length -= 2;
            }
        }

        /* tell the user how man compression methods there are */
        compression_methods_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_comp_methods_len,
                            tvb, offset, 1, compression_methods_length);
        offset++;

        if (compression_methods_length > 0)
        {
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_comp_methods,
                                            tvb, offset, compression_methods_length,
                                            "Compression Methods (%u method%s)",
                                            compression_methods_length,
                                            plurality(compression_methods_length,
                                              "", "s"));

            /* make this a subtree */
            cs_tree = proto_item_add_subtree(ti, ett_ssl_comp_methods);
            if (!cs_tree)
            {
                cs_tree = tree; /* failsafe */
            }

            while (compression_methods_length > 0)
            {
                proto_tree_add_item(cs_tree, hf_ssl_handshake_comp_method,
                                    tvb, offset, 1, FALSE);
                offset++;
                compression_methods_length--;
            }
        }
    }
}

static void
dissect_ssl3_hnd_srv_hello(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, guint32 offset)
{
    /* struct {
     *     ProtocolVersion server_version;
     *     Random random;
     *     SessionID session_id;
     *     CipherSuite cipher_suite;
     *     CompressionMethod compression_method;
     * } ServerHello;
     */

    if (tree)
    {
        /* show the server version */
        proto_tree_add_item(tree, hf_ssl_handshake_server_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        /* first display the elements conveniently in
         * common with client hello
         */
        offset += dissect_ssl3_hnd_hello_common(tvb, tree, offset);

        /* now the server-selected cipher suite */
        proto_tree_add_item(tree, hf_ssl_handshake_cipher_suite,
                            tvb, offset, 2, FALSE);
        offset += 2;

        /* and the server-selected compression method */
        proto_tree_add_item(tree, hf_ssl_handshake_comp_method,
                            tvb, offset, 1, FALSE);
    }
}

static void
dissect_ssl3_hnd_cert(tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *tree, guint32 offset)
{

    /* opaque ASN.1Cert<2^24-1>;
     *
     * struct {
     *     ASN.1Cert certificate_list<1..2^24-1>;
     * } Certificate;
     */
    guint32 certificate_list_length;
    proto_tree *ti;
    proto_tree *subtree;

    if (tree)
    {
        certificate_list_length = tvb_get_ntoh24(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_certificates_len,
                            tvb, offset, 3, certificate_list_length);
        offset += 3;            /* 24-bit length value */

        if (certificate_list_length > 0)
        {
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_certificates,
                                            tvb, offset, certificate_list_length,
                                            "Certificates (%u byte%s)",
                                            certificate_list_length,
                                            plurality(certificate_list_length,
                                              "", "s"));

            /* make it a subtree */
            subtree = proto_item_add_subtree(ti, ett_ssl_certs);
            if (!subtree)
            {
                subtree = tree; /* failsafe */
            }

            /* iterate through each certificate */
            while (certificate_list_length > 0)
            {
                /* get the length of the current certificate */
                guint32 cert_length = tvb_get_ntoh24(tvb, offset);
                certificate_list_length -= 3 + cert_length;

                proto_tree_add_item(subtree, hf_ssl_handshake_certificate_len,
                                    tvb, offset, 3, FALSE);
                offset += 3;

                proto_tree_add_bytes_format(subtree,
                                            hf_ssl_handshake_certificate,
                                            tvb, offset, cert_length,
                                            tvb_get_ptr(tvb, offset, cert_length),
                                            "Certificate (%u byte%s)",
                                            cert_length,
                                            plurality(cert_length, "", "s"));
                offset += cert_length;
            }
        }

    }
}

static void
dissect_ssl3_hnd_cert_req(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, guint32 offset)
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
     */
    proto_tree *ti;
    proto_tree *subtree;
    guint8      cert_types_count = 0;
    int         dnames_length = 0;

    if (tree)
    {
        cert_types_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_cert_types_count,
                            tvb, offset, 1, cert_types_count);
        offset++;

        if (cert_types_count > 0)
        {
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_cert_types,
                                            tvb, offset, cert_types_count,
                                            "Certificate types (%u type%s)",
                                            cert_types_count,
                                            plurality(cert_types_count, "", "s"));
            subtree = proto_item_add_subtree(ti, ett_ssl_cert_types);
            if (!subtree)
            {
                subtree = tree;
            }

            while (cert_types_count > 0)
            {
                proto_tree_add_item(subtree, hf_ssl_handshake_cert_type,
                                    tvb, offset, 1, FALSE);
                offset++;
                cert_types_count--;
            }
        }

        dnames_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_dnames_len,
                            tvb, offset, 2, dnames_length);
        offset += 2;

        if (dnames_length > 0)
        {
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_dnames,
                                            tvb, offset, dnames_length,
                                            "Distinguished Names (%d byte%s)",
                                            dnames_length,
                                            plurality(dnames_length, "", "s"));
            subtree = proto_item_add_subtree(ti, ett_ssl_dnames);
            if (!subtree)
            {
                subtree = tree;
            }

            while (dnames_length > 0)
            {
                /* get the length of the current certificate */
                guint16 name_length = tvb_get_ntohs(tvb, offset);
                dnames_length -= 2 + name_length;

                proto_tree_add_item(subtree, hf_ssl_handshake_dname_len,
                                    tvb, offset, 2, FALSE);
                offset += 2;

                proto_tree_add_bytes_format(subtree,
                                            hf_ssl_handshake_dname,
                                            tvb, offset, name_length,
                                            tvb_get_ptr(tvb, offset, name_length),
                                            "Distinguished Name (%u byte%s)",
                                            name_length,
                                            plurality(name_length, "", "s"));
                offset += name_length;
            }
        }
    }

}

static void
dissect_ssl3_hnd_finished(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, guint32 offset,
                          guint *conv_version)
{
    /* For TLS:
     *     struct {
     *         opaque verify_data[12];
     *     } Finished;
     *
     * For SSLv3:
     *     struct {
     *         opaque md5_hash[16];
     *         opaque sha_hash[20];
     *     } Finished;
     */

    /* this all needs a tree, so bail if we don't have one */
    if (!tree)
    {
        return;
    }

    switch(*conv_version) {
    case SSL_VER_TLS:
        proto_tree_add_item(tree, hf_ssl_handshake_finished,
                            tvb, offset, 12, FALSE);
        break;

    case SSL_VER_SSLv3:
        proto_tree_add_item(tree, hf_ssl_handshake_md5_hash,
                            tvb, offset, 16, FALSE);
        offset += 16;
        proto_tree_add_item(tree, hf_ssl_handshake_sha_hash,
                            tvb, offset, 20, FALSE);
        offset += 20;
        break;
    }
}

/*********************************************************************
 *
 * SSL version 2 Dissectors
 *
 *********************************************************************/


/* record layer dissector */
static int
dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree
                    *tree, guint32 offset, guint *conv_version)
{
    guint32 initial_offset       = offset;
    guint8  byte                 = 0;
    guint8  record_length_length = 0;
    gint32  record_length        = -1;
    gint    is_escape            = -1;
    gint16  padding_length       = -1;
    guint8  msg_type             = 0;
    gchar   *msg_type_str        = NULL;

    proto_tree *ti;
    proto_tree *ssl_record_tree = NULL;

    /* if we get here, but don't have a version set for the
     * conversation, then set a version for just this frame
     * (e.g., on a client hello)
     */
    if (check_col(pinfo->fd, COL_PROTOCOL))
    {
        col_set_str(pinfo->fd, COL_PROTOCOL, "SSLv2");
    }

    /* pull first byte; if high bit is set, then record
     * length is three bytes due to padding; otherwise
     * record length is two bytes
     */
    byte = tvb_get_guint8(tvb, offset++);
    record_length_length = (byte & 0x80) ? 2 : 3;

    /* parse out the record length */
    switch(record_length_length) {
    case 2:                     /* two-byte record length */
        record_length = (byte & 0x7f) << 8;
        byte = tvb_get_guint8(tvb, offset++);
        record_length += byte;
        break;
    case 3:                     /* three-byte record length */
        is_escape = (byte & 0x40) ? TRUE : FALSE;
        record_length = (byte & 0x3f) << 8;
        byte = tvb_get_guint8(tvb, offset++);
        record_length += byte;
        byte = tvb_get_guint8(tvb, offset++);
        padding_length = byte;
    }

    /* add the record layer subtree header */
    ti = proto_tree_add_item(tree, hf_ssl2_record, tvb, initial_offset,
                             record_length_length + record_length, 0);
    ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);

    /* pull the msg_type so we can bail if it's unknown */
    msg_type = tvb_get_guint8(tvb, initial_offset + record_length_length);

    /* if we get a server_hello or later handshake in v2, then set
     * this to sslv2
     */
    if (*conv_version == SSL_VER_UNKNOWN
        && msg_type >= 2 && msg_type <= 8)
    {
        *conv_version = SSL_VER_SSLv2;
        ssl_set_conv_version(pinfo, *conv_version);
    }

    /* see if the msg_type is valid; if not the payload is
     * probably encrypted, so note that fact and bail
     */
    msg_type_str = match_strval(msg_type, ssl_20_msg_types);
    if (!msg_type_str
        || !ssl_looks_like_valid_v2_handshake(tvb, initial_offset
                                              + record_length_length,
                                              record_length))
    {
        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "SSLv2 Record Layer: %s",
                                "Encrypted Data");
        }
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, "Encrypted Data");
        return initial_offset + record_length_length + record_length;
    }
    else
    {
        if (check_col(pinfo->fd, COL_INFO))
            col_append_str(pinfo->fd, COL_INFO, msg_type_str);

        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "SSLv2 Record Layer: %s",
                                msg_type_str);
        }
    }

    /* We have a valid message type, so move foward, filling in the
     * tree by adding the length, is_escape boolean and padding_length,
     * if present in the original packet
     */
    if (ssl_record_tree && record_length != -1)
    {
        /* add the record length */
        ti = proto_tree_add_uint (ssl_record_tree,
                                  hf_ssl_record_length, tvb,
                                  initial_offset, record_length_length,
                                  record_length);
    }
    if (ssl_record_tree && is_escape != -1)
    {
        proto_tree_add_boolean(ssl_record_tree,
                               hf_ssl2_record_is_escape, tvb,
                               initial_offset, 1, is_escape);
    }
    if (ssl_record_tree && padding_length != -1)
    {
        proto_tree_add_uint(ssl_record_tree,
                            hf_ssl2_record_padding_length, tvb,
                            initial_offset + 2, 1, padding_length);
    }

    /*
     * dissect the record data
     */

    /* jump forward to the start of the record data */
    offset = initial_offset + record_length_length;

    /* add the message type */
    if (ssl_record_tree)
    {
        proto_tree_add_item(ssl_record_tree, hf_ssl2_msg_type, tvb,
                            offset, 1, 0);
    }
    offset++;                   /* move past msg_type byte */


    /* dissect the message (only handle client hello right now) */
    switch (msg_type) {
    case SSL2_HND_CLIENT_HELLO:
        dissect_ssl2_hnd_client_hello(tvb, pinfo, ssl_record_tree, offset);
        break;

    case SSL2_HND_CLIENT_MASTER_KEY:
        dissect_ssl2_hnd_client_master_key(tvb, pinfo, ssl_record_tree, offset);
        break;

    case SSL2_HND_SERVER_HELLO:
        dissect_ssl2_hnd_server_hello(tvb, pinfo, ssl_record_tree, offset);
        break;

    case SSL2_HND_ERROR:
    case SSL2_HND_CLIENT_FINISHED:
    case SSL2_HND_SERVER_VERIFY:
    case SSL2_HND_SERVER_FINISHED:
    case SSL2_HND_REQUEST_CERTIFICATE:
    case SSL2_HND_CLIENT_CERTIFICATE:
        /* unimplemented */
        break;

    default:                    /* unknown */
        break;
    }


    return (initial_offset + record_length_length + record_length);
}

static void
dissect_ssl2_hnd_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, guint32 offset)
{
    /* struct {
     *    uint8 msg_type;
     *     Version version;
     *     uint16 cipher_spec_length;
     *     uint16 session_id_length;
     *     uint16 challenge_length;
     *     V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];
     *     opaque session_id[V2ClientHello.session_id_length];
     *     Random challenge;
     * } V2ClientHello;
     *
     * Note: when we get here, offset's already pointing at Version
     *
     */
    guint16 version;
    guint16 cipher_spec_length;
    guint16 session_id_length;
    guint16 challenge_length;

    proto_tree *ti;
    proto_tree *cs_tree;

    version = tvb_get_ntohs(tvb, offset);
    if (!ssl_is_valid_ssl_version(version))
    {
        /* invalid version; probably encrypted data */
        return;
    }

    if (tree)
    {
        /* show the version */
        proto_tree_add_item(tree, hf_ssl_record_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        cipher_spec_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_ssl2_handshake_cipher_spec_len,
                            tvb, offset, 2, FALSE);
        offset += 2;

        session_id_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_ssl2_handshake_session_id_len,
                            tvb, offset, 2, FALSE);
        offset += 2;

        challenge_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_ssl2_handshake_challenge_len,
                            tvb, offset, 2, FALSE);
        offset += 2;

        /* tell the user how many cipher specs they've won */
        ti = proto_tree_add_none_format(tree, hf_ssl_handshake_cipher_suites,
                                        tvb, offset, cipher_spec_length,
                                        "Cipher Specs (%u specs)",
                                        cipher_spec_length/3);

        /* make this a subtree and expand the actual specs below */
        cs_tree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
        if (!cs_tree)
        {
            cs_tree = tree;     /* failsafe */
        }

        /* iterate through the cipher specs, showing them */
        while (cipher_spec_length > 0)
        {
            proto_tree_add_item(cs_tree, hf_ssl2_handshake_cipher_spec,
                                tvb, offset, 3, FALSE);
            offset += 3;        /* length of one cipher spec */
            cipher_spec_length -= 3;
        }

        /* if there's a session id, show it */
        if (session_id_length > 0)
        {
            proto_tree_add_bytes_format(tree,
                                         hf_ssl_handshake_session_id,
                                         tvb, offset, session_id_length,
                                         tvb_get_ptr(tvb, offset, session_id_length),
                                         "Session ID (%u byte%s)",
                                         session_id_length,
                                         plurality(session_id_length, "", "s"));

            offset += session_id_length;
        }

        /* if there's a challenge, show it */
        if (challenge_length > 0)
        {
            proto_tree_add_item(tree, hf_ssl2_handshake_challenge,
                                tvb, offset, challenge_length, 0);
            offset += challenge_length;
        }
    }
}

static void
dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset)
{
    /* struct {
     *    uint8 msg_type;
     *    V2Cipherspec cipher;
     *    uint16 clear_key_length;
     *    uint16 encrypted_key_length;
     *    uint16 key_arg_length;
     *    opaque clear_key_data[V2ClientMasterKey.clear_key_length];
     *    opaque encrypted_key_data[V2ClientMasterKey.encrypted_key_length];
     *    opaque key_arg_data[V2ClientMasterKey.key_arg_length];
     * } V2ClientMasterKey;
     *
     * Note: when we get here, offset's already pointing at cipher
     */
    guint16 clear_key_length;
    guint16 encrypted_key_length;
    guint16 key_arg_length;

    /* at this point, everything we do involves the tree,
     * so quit now if we don't have one ;-)
     */
    if (!tree)
    {
        return;
    }

    /* show the selected cipher */
    proto_tree_add_item(tree, hf_ssl2_handshake_cipher_spec,
                        tvb, offset, 3, FALSE);
    offset += 3;

    /* get the fixed fields */
    clear_key_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_clear_key_len,
                        tvb, offset, 2, FALSE);
    offset += 2;

    encrypted_key_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_enc_key_len,
                        tvb, offset, 2, FALSE);
    offset += 2;

    key_arg_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_key_arg_len,
                        tvb, offset, 2, FALSE);
    offset += 2;

    /* show the variable length fields */
    if (clear_key_length > 0)
    {
        proto_tree_add_item(tree, hf_ssl2_handshake_clear_key,
                            tvb, offset, clear_key_length, FALSE);
        offset += clear_key_length;
    }

    if (encrypted_key_length > 0)
    {
        proto_tree_add_item(tree, hf_ssl2_handshake_enc_key,
                            tvb, offset, encrypted_key_length, FALSE);
        offset += encrypted_key_length;
    }

    if (key_arg_length > 0)
    {
        proto_tree_add_item(tree, hf_ssl2_handshake_key_arg,
                            tvb, offset, key_arg_length, FALSE);
        offset += key_arg_length;
    }

}

static void
dissect_ssl2_hnd_server_hello(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, guint32 offset)
{
    /* struct {
     *    uint8  msg_type;
     *    uint8  session_id_hit;
     *    uint8  certificate_type;
     *    uint16 server_version;
     *    uint16 certificate_length;
     *    uint16 cipher_specs_length;
     *    uint16 connection_id_length;
     *    opaque certificate_data[V2ServerHello.certificate_length];
     *    opaque cipher_specs_data[V2ServerHello.cipher_specs_length];
     *    opaque connection_id_data[V2ServerHello.connection_id_length];
     * } V2ServerHello;
     *
     * Note: when we get here, offset's already pointing at session_id_hit
     */
    guint16 certificate_length;
    guint16 cipher_spec_length;
    guint16 connection_id_length;
    guint16 version;
    proto_tree *ti;
    proto_tree *subtree;

    /* everything we do only makes sense with a tree, so
     * quit now if we don't have one
     */
    if (!tree)
    {
        return;
    }

    version = tvb_get_ntohs(tvb, offset + 2);
    if (!ssl_is_valid_ssl_version(version))
    {
        /* invalid version; probably encrypted data */
        return;
    }


    /* is there a hit? */
    proto_tree_add_item(tree, hf_ssl2_handshake_session_id_hit,
                        tvb, offset, 1, FALSE);
    offset++;

    /* what type of certificate is this? */
    proto_tree_add_item(tree, hf_ssl2_handshake_cert_type,
                        tvb, offset, 1, FALSE);
    offset++;

    /* now the server version */
    proto_tree_add_item(tree, hf_ssl_handshake_server_version,
                        tvb, offset, 2, FALSE);
    offset += 2;

    /* get the fixed fields */
    certificate_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl_handshake_certificate_len,
                        tvb, offset, 2, certificate_length);
    offset += 2;

    cipher_spec_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl2_handshake_cipher_spec_len,
                        tvb, offset, 2, cipher_spec_length);
    offset += 2;

    connection_id_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl2_handshake_connection_id_len,
                        tvb, offset, 2, connection_id_length);
    offset += 2;

    /* now the variable length fields */
    if (certificate_length > 0)
    {
        proto_tree_add_bytes_format(tree, hf_ssl_handshake_certificate,
                                    tvb, offset, certificate_length,
                                    tvb_get_ptr(tvb, offset, certificate_length),
                                    "Certificate (%u byte%s)",
                                    certificate_length,
                                    plurality(certificate_length, "", "s"));
        offset += certificate_length;
    }

    if (cipher_spec_length > 0)
    {
        /* provide a collapsing node for the cipher specs */
        ti = proto_tree_add_none_format(tree, 
                                        hf_ssl_handshake_cipher_suites,
                                        tvb, offset, cipher_spec_length,
                                        "Cipher Specs (%u spec%s)",
                                        cipher_spec_length/3,
                                        plurality(cipher_spec_length/3, "", "s"));
        subtree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
        if (!subtree)
        {
            subtree = tree;
        }

        /* iterate through the cipher specs */
        while (cipher_spec_length > 0)
        {
            proto_tree_add_item(subtree, hf_ssl2_handshake_cipher_spec,
                                tvb, offset, 3, FALSE);
            offset += 3;
            cipher_spec_length -= 3;
        }
    }

    if (connection_id_length > 0)
    {
        proto_tree_add_item(tree, hf_ssl2_handshake_connection_id,
                            tvb, offset, connection_id_length, FALSE);
        offset += connection_id_length;
    }

}




/*********************************************************************
 *
 * Support Functions
 *
 *********************************************************************/

static void
ssl_set_conv_version(packet_info *pinfo, guint version)
{
    conversation_t *conversation;
    void *conv_data;

    if (pinfo->fd->flags.visited)
    {
        /* We've already processed this frame; no need to do any more
         * work on it.
         */
        return;
    }

    conversation = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype,
                                     pinfo->srcport, pinfo->destport, 0);

    if (conversation == NULL)
    {
        /* create a new conversation */
        conversation = conversation_new(&pinfo->src, &pinfo->dst, pinfo->ptype,
                                        pinfo->srcport, pinfo->destport, 0);
    }

    if (conversation_get_proto_data(conversation, proto_ssl) != NULL)
    {
        /* get rid of the current data */
        conversation_delete_proto_data(conversation, proto_ssl);
    }
    conversation_add_proto_data(conversation, proto_ssl, (void *)version);
}

static int
ssl_is_valid_handshake_type(guint8 type)
{

    switch (type) {
    case SSL_HND_HELLO_REQUEST:
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_SERVER_HELLO:
    case SSL_HND_CERTIFICATE:
    case SSL_HND_SERVER_KEY_EXCHG:
    case SSL_HND_CERT_REQUEST:
    case SSL_HND_SVR_HELLO_DONE:
    case SSL_HND_CERT_VERIFY:
    case SSL_HND_CLIENT_KEY_EXCHG:
    case SSL_HND_FINISHED:
        return 1;
    }
    return 0;
}

static int
ssl_is_valid_content_type(guint8 type)
{
    if (type >= 0x14 && type <= 0x17)
    {
        return 1;
    }

    return 0;
}

static int
ssl_is_valid_ssl_version(guint16 version)
{
    gchar *version_str = match_strval(version, ssl_versions);
    return version_str != NULL;
}

static int
ssl_is_authoritative_version_message(guint8 content_type,
                                     guint8 next_byte)
{
    if (content_type == SSL_ID_HANDSHAKE
        && ssl_is_valid_handshake_type(next_byte))
    {
        return (next_byte != SSL_HND_CLIENT_HELLO);
    }
    else if (ssl_is_valid_content_type(content_type)
             && content_type != SSL_ID_HANDSHAKE)
    {
        return 1;
    }
    return 0;
}

static int
ssl_is_v2_client_hello(tvbuff_t *tvb, guint32 offset)
{
    guint8 byte;

    byte = tvb_get_guint8(tvb, offset);
    if (byte != 0x80)           /* v2 client hello should start this way */
    {
        return 0;
    }

    byte = tvb_get_guint8(tvb, offset+2);
    if (byte != 0x01)           /* v2 client hello msg type */
    {
        return 0;
    }

    /* 1 in 2^16 of being right; improve later if necessary */
    return 1;
}

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv2 record.  this isn't really possible,
 * but we'll try to do a reasonable job anyway.
 */
static int
ssl_looks_like_sslv2(tvbuff_t *tvb, guint32 offset)
{
    /* here's the current approach:
     *
     * we only try to catch unencrypted handshake messages, so we can
     * assume that there is not padding.  This means that the
     * first byte must be >= 0x80 and there must be a valid sslv2
     * msg_type in the third byte
     */

    /* get the first byte; must have high bit set */
    guint8 byte = tvb_get_guint8(tvb, offset);
    if (byte < 0x80)
    {
        return 0;
    }

    /* get the supposed msg_type byte; since we only care about
     * unencrypted handshake messages (we can't tell the type for
     * encrypted messages), we just check against that list
     */
    byte = tvb_get_guint8(tvb, offset + 2);
    switch(byte) {
    case SSL2_HND_ERROR:
    case SSL2_HND_CLIENT_HELLO:
    case SSL2_HND_CLIENT_MASTER_KEY:
    case SSL2_HND_SERVER_HELLO:
        return 1;
    }
    return 0;
}

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv3 record.  this is somewhat more reliable
 * than sslv2 due to the structure of the v3 protocol
 */
static int
ssl_looks_like_sslv3(tvbuff_t *tvb, guint32 offset)
{
    /* have to have a valid content type followed by a valid
     * protocol version
     */
    guint8 byte;
    guint16 version;

    /* see if the first byte is a valid content type */
    byte = tvb_get_guint8(tvb, offset);
    if (!ssl_is_valid_content_type(byte))
    {
        return 0;
    }

    /* now check to see if the version byte appears valid */
    version = tvb_get_ntohs(tvb, offset + 1);
    if (version != 0x0300 && version != 0x0301)
    {
        return 0;
    }

    return 1;
}

/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted v2 handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.
 */
static int
ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb, guint32 offset,
                                  guint32 record_length)
{
    /* first byte should be a msg_type.
     *
     *   - we know we only see client_hello, client_master_key,
     *     and server_hello in the clear, so check to see if
     *     msg_type is one of those (this gives us a 3 in 2^8
     *     chance of saying yes with random payload)
     *
     *   - for those three types that we know about, do some
     *     further validation to reduce the chance of an error
     */
    guint8 msg_type;
    guint16 version;
    guint32 sum;

    /* fetch the msg_type */
    msg_type = tvb_get_guint8(tvb, offset);

    switch (msg_type) {
    case SSL2_HND_CLIENT_HELLO:
        /* version follows msg byte, so verify that this is valid */
        version = tvb_get_ntohs(tvb, offset+1);
        return ssl_is_valid_ssl_version(version);
        break;

    case SSL2_HND_SERVER_HELLO:
        /* version is three bytes after msg_type */
        version = tvb_get_ntohs(tvb, offset+3);
        return ssl_is_valid_ssl_version(version);
        break;

    case SSL2_HND_CLIENT_MASTER_KEY:
        /* sum of clear_key_length, encrypted_key_length, and key_arg_length
         * must be less than record length
         */
        sum  = tvb_get_ntohs(tvb, offset + 4); /* clear_key_length */
        sum += tvb_get_ntohs(tvb, offset + 6); /* encrypted_key_length */
        sum += tvb_get_ntohs(tvb, offset + 8); /* key_arg_length */
        if (sum > record_length)
        {
            return 0;
        }
        return 1;
        break;

    default:
        return 0;
    }
    return 0;
}

/*********************************************************************
 *
 * Standard Ethereal Protocol Registration and housekeeping
 *
 *********************************************************************/
void
proto_register_ssl(void)
{

    /* Setup list of header fields See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_ssl_record,
          { "Record Layer", "ssl.record",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Record layer", HFILL }
        },
        { &hf_ssl_record_content_type,
          { "Content Type", "ssl.record.content_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
            "Content type", HFILL}
        },
        { &hf_ssl2_msg_type,
          { "Handshake Message Type", "ssl.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_msg_types), 0x0,
            "SSLv2 handshake message type", HFILL}
        },
        { &hf_ssl_record_version,
          { "Version", "ssl.record.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Record layer version.", HFILL }
        },
        { &hf_ssl_record_length,
          { "Length", "ssl.record.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of SSL record data", HFILL }
        },
        { &hf_ssl_record_appdata,
          { "Application Data", "ssl.app_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Payload is application data", HFILL }
        },
        { & hf_ssl2_record,
          { "SSLv2 Record Header", "ssl.record",
            FT_NONE, BASE_DEC, NULL, 0x0,
            "SSLv2 record data", HFILL }
        },
        { &hf_ssl2_record_is_escape,
          { "Is Escape", "ssl.record.is_escape",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Indicates a security escape", HFILL}
        },
        { &hf_ssl2_record_padding_length,
          { "Padding Length", "ssl.record.padding_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of padding at end of record", HFILL }
        },
        { &hf_ssl_change_cipher_spec,
          { "Change Cipher Spec Message", "ssl.change_cipher_spec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Signals a change in cipher specifications", HFILL }
        },
        { & hf_ssl_alert_message,
          { "Alert Message", "ssl.alert_message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Alert message", HFILL }
        },
        { & hf_ssl_alert_message_level,
          { "Level", "ssl.alert_message.level",
            FT_UINT8, BASE_DEC, VALS(ssl_31_alert_level), 0x0,
            "Alert message level", HFILL }
        },
        { &hf_ssl_alert_message_description,
          { "Description", "ssl.alert_message.desc",
            FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
            "Alert message description", HFILL }
        },
        { &hf_ssl_handshake_protocol,
          { "Handshake Protocol", "ssl.handshake",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Handshake protocol message", HFILL}
        },
        { &hf_ssl_handshake_type,
          { "Handshake Type", "ssl.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_handshake_type), 0x0,
            "Type of handshake message", HFILL}
        },
        { &hf_ssl_handshake_length,
          { "Length", "ssl.handshake.length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of handshake message", HFILL }
        },
        { &hf_ssl_handshake_client_version,
          { "Version", "ssl.handshake.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Maximum version supported by client", HFILL }
        },
        { &hf_ssl_handshake_server_version,
          { "Version", "ssl.handshake.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Version selected by server", HFILL }
        },
        { &hf_ssl_handshake_random_time,
          { "Random.gmt_unix_time", "ssl.handshake.random_time",
            FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
            "Unix time field of random structure", HFILL }
        },
        { &hf_ssl_handshake_random_bytes,
          { "Random.bytes", "ssl.handshake.random",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Random challenge used to authenticate server", HFILL }
        },
        { &hf_ssl_handshake_cipher_suites_len,
          { "Cipher Suites Length", "ssl.handshake.cipher_suites_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of cipher suites field", HFILL }
        },
        { &hf_ssl_handshake_cipher_suites,
          { "Cipher Suites", "ssl.handshake.ciphersuites",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of cipher suites supported by client", HFILL }
        },
        { &hf_ssl_handshake_cipher_suite,
          { "Cipher Suite", "ssl.handshake.ciphersuite",
            FT_UINT16, BASE_HEX, VALS(ssl_31_ciphersuite), 0x0,
            "Cipher suite", HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec,
          { "Cipher Spec", "ssl.handshake.cipherspec",
            FT_UINT24, BASE_HEX, VALS(ssl_20_cipher_suites), 0x0,
            "Cipher specification", HFILL }
        },
        { &hf_ssl_handshake_session_id,
          { "Session ID", "ssl.handshake.session_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Identifies the SSL session, allowing later resumption", HFILL }
        },
        { &hf_ssl_handshake_comp_methods_len,
          { "Compression Methods Length", "ssl.handshake.comp_methods_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of compression methods field", HFILL }
        },
        { &hf_ssl_handshake_comp_methods,
          { "Compression Methods", "ssl.handshake.comp_methods",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of compression methods supported by client", HFILL }
        },
        { &hf_ssl_handshake_comp_method,
          { "Compression Method", "ssl.handshake.comp_method",
            FT_UINT8, BASE_DEC, VALS(ssl_31_compression_method), 0x0,
            "Compression Method", HFILL }
        },
        { &hf_ssl_handshake_certificates_len,
          { "Certificates Length", "ssl.handshake.certificates_length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of certificates field", HFILL }
        },
        { &hf_ssl_handshake_certificates,
          { "Certificates", "ssl.handshake.certificates",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of certificates", HFILL }
        },
        { &hf_ssl_handshake_certificate,
          { "Certificate", "ssl.handshake.certificate",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Certificate", HFILL }
        },
        { &hf_ssl_handshake_certificate_len,
          { "Certificate Length", "ssl.handshake.certificate_length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of certificate", HFILL }
        },
        { &hf_ssl_handshake_cert_types_count,
          { "Certificate types count", "ssl.handshake.cert_types_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Count of certificate types", HFILL }
        },
        { &hf_ssl_handshake_cert_types,
          { "Certificate types", "ssl.handshake.cert_types",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of certificate types", HFILL }
        },
        { &hf_ssl_handshake_cert_type,
          { "Certificate type", "ssl.handshake.cert_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_client_certificate_type), 0x0,
            "Certificate type", HFILL }
        },
        { &hf_ssl_handshake_finished,
          { "Verify Data", "ssl.handshake.verify_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Opaque verification data", HFILL }
        },
        { &hf_ssl_handshake_md5_hash,
          { "MD5 Hash", "ssl.handshake.md5_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &hf_ssl_handshake_sha_hash,
          { "SHA-1 Hash", "ssl.handshake.sha_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &hf_ssl_handshake_session_id_len,
          { "Session ID Length", "ssl.handshake.session_id_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of session ID field", HFILL }
        },
        { &hf_ssl_handshake_dnames_len,
          { "Distinguished Names Length", "ssl.handshake.dnames_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of list of CAs that server trusts", HFILL }
        },
        { &hf_ssl_handshake_dnames,
          { "Distinguished Names", "ssl.handshake.dnames",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of CAs that server trusts", HFILL }
        },
        { &hf_ssl_handshake_dname_len,
          { "Distinguished Name Length", "ssl.handshake.dname_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of distinguished name", HFILL }
        },
        { &hf_ssl_handshake_dname,
          { "Distinguished Name", "ssl.handshake.dname",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Distinguished name of a CA that server trusts", HFILL }
        },
        { &hf_ssl2_handshake_challenge,
          { "Challenge", "ssl.handshake.challenge",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Challenge data used to authenticate server", HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec_len,
          { "Cipher Spec Length", "ssl.handshake.cipher_spec_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of cipher specs field", HFILL }
        },
        { &hf_ssl2_handshake_session_id_len,
          { "Session ID Length", "ssl.handshake.session_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of session ID field", HFILL }
        },
        { &hf_ssl2_handshake_challenge_len,
          { "Challenge Length", "ssl.handshake.challenge_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of challenge field", HFILL }
        },
        { &hf_ssl2_handshake_clear_key_len,
          { "Clear Key Data Length", "ssl.handshake.clear_key_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of clear key data", HFILL }
        },
        { &hf_ssl2_handshake_enc_key_len,
          { "Encrypted Key Data Length", "ssl.handshake.encrypted_key_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of encrypted key data", HFILL }
        },
        { &hf_ssl2_handshake_key_arg_len,
          { "Key Argument Length", "ssl.handshake.key_arg_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of key argument", HFILL }
        },
        { &hf_ssl2_handshake_clear_key,
          { "Clear Key Data", "ssl.handshake.clear_key_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Clear portion of MASTER-KEY", HFILL }
        },
        { &hf_ssl2_handshake_enc_key,
          { "Encrypted Key", "ssl.handshake.encrypted_key",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Secret portion of MASTER-KEY encrypted to server", HFILL }
        },
        { &hf_ssl2_handshake_key_arg,
          { "Key Argument", "ssl.handshake.key_arg",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Key Argument (e.g., Initialization Vector)", HFILL }
        },
        { &hf_ssl2_handshake_session_id_hit,
          { "Session ID Hit", "ssl.handshake.session_id_hit",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Did the server find the client's Session ID?", HFILL }
        },
        { &hf_ssl2_handshake_cert_type,
          { "Certificate Type", "ssl.handshake.cert_type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_certificate_type), 0x0,
            "Certificate Type", HFILL }
        },
        { &hf_ssl2_handshake_connection_id_len,
          { "Connection ID Length", "ssl.handshake.connection_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of connection ID", HFILL }
        },
        { &hf_ssl2_handshake_connection_id,
          { "Connection ID", "ssl.handshake.connection_id",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Server's challenge to client", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ssl,
        &ett_ssl_record,
        &ett_ssl_alert,
        &ett_ssl_handshake,
        &ett_ssl_cipher_suites,
        &ett_ssl_comp_methods,
        &ett_ssl_certs,
        &ett_ssl_cert_types,
        &ett_ssl_dnames,
    };

    /* Register the protocol name and description */
    proto_ssl = proto_register_protocol("Secure Socket Layer",
                                        "SSL", "ssl");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_ssl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_ssl(void)
{
    dissector_add("tcp.port", TCP_PORT_SSL, dissect_ssl, proto_ssl);
}
