/* packet-ssl.c
 * Routines for ssl dissection
 * Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * See
 *
 *    http://www.mozilla.org/projects/security/pki/nss/ssl/draft02.html
 *
 * for SSL 2.0 specs.
 *
 * See
 *
 *    http://www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt
 *
 * for SSL 3.0 specs.
 *
 * See RFC 2246 for SSL 3.1/TLS 1.0 specs.
 *
 * See (among other places)
 *
 *    http://www.graphcomp.com/info/specs/ms/pct.htm
 *
 * for PCT 1 draft specs.
 *
 * See
 *
 *    http://research.sun.com/projects/crypto/draft-ietf-tls-ecc-05.txt
 *
 * for Elliptic Curve Cryptography cipher suites.
 *
 * See
 *
 *    http://www.ietf.org/internet-drafts/draft-ietf-tls-camellia-04.txt
 *
 * for Camellia-based cipher suites.
 *
 * Notes:
 *
 *   - Does not support dissection
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
 *    - Decryption is supported only for session that use RSA key exchange,
 *      if the host private key is provided via preference.
 *
 *    - Decryption needs to be performed 'sequentially', so it's done
 *      at packet reception time. This may cause a significant packet capture
 *      slow down. This also causes dissection of some ssl info that in previous
 *      dissector versions was dissected only when a proto_tree context was
 *      available
 *
 *     We are at Packet reception if time pinfo->fd->flags.visited == 0
 *
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/dissectors/packet-ocsp.h>
#include <epan/tap.h>
#include <epan/filesystem.h>
#include <epan/report_err.h>
#include <epan/expert.h>
#include "packet-x509if.h"
#include "packet-ssl.h"
#include "packet-ssl-utils.h"
#include <wsutil/file_util.h>
#include <epan/uat.h>

static ssldecrypt_assoc_t *sslkeylist_uats = NULL;
static guint nssldecrypt = 0;

static gboolean ssl_desegment          = TRUE;
static gboolean ssl_desegment_app_data = TRUE;

gboolean ssl_ignore_mac_failed = FALSE;


/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* Initialize the protocol and registered fields */
static gint ssl_tap                           = -1;
static gint proto_ssl                         = -1;
static gint hf_ssl_record                     = -1;
static gint hf_ssl_record_content_type        = -1;
static gint hf_ssl_record_version             = -1;
static gint hf_ssl_record_length              = -1;
static gint hf_ssl_record_appdata             = -1;
static gint hf_ssl2_record                    = -1;
static gint hf_ssl2_record_is_escape          = -1;
static gint hf_ssl2_record_padding_length     = -1;
static gint hf_ssl2_msg_type                  = -1;
static gint hf_pct_msg_type                   = -1;
static gint hf_ssl_change_cipher_spec         = -1;
static gint hf_ssl_alert_message              = -1;
static gint hf_ssl_alert_message_level        = -1;
static gint hf_ssl_alert_message_description  = -1;
static gint hf_ssl_handshake_protocol         = -1;
static gint hf_ssl_handshake_type             = -1;
static gint hf_ssl_handshake_length           = -1;
static gint hf_ssl_handshake_client_version   = -1;
static gint hf_ssl_handshake_server_version   = -1;
static gint hf_ssl_handshake_random_time      = -1;
static gint hf_ssl_handshake_random_bytes     = -1;
static gint hf_ssl_handshake_cipher_suites_len = -1;
static gint hf_ssl_handshake_cipher_suites    = -1;
static gint hf_ssl_handshake_cipher_suite     = -1;
static gint hf_ssl_handshake_session_id       = -1;
static gint hf_ssl_handshake_comp_methods_len = -1;
static gint hf_ssl_handshake_comp_methods     = -1;
static gint hf_ssl_handshake_comp_method      = -1;
static gint hf_ssl_handshake_extensions_len   = -1;
static gint hf_ssl_handshake_extension_type   = -1;
static gint hf_ssl_handshake_extension_len    = -1;
static gint hf_ssl_handshake_extension_data   = -1;
static gint hf_ssl_handshake_extension_elliptic_curves_len  = -1;
static gint hf_ssl_handshake_extension_elliptic_curves      = -1;
static gint hf_ssl_handshake_extension_elliptic_curve       = -1;
static gint hf_ssl_handshake_extension_ec_point_formats_len = -1;
static gint hf_ssl_handshake_extension_ec_point_format      = -1;
static gint hf_ssl_handshake_extension_npn_str_len = -1;
static gint hf_ssl_handshake_extension_npn_str = -1;
static gint hf_ssl_handshake_extension_reneg_info_len = -1;
static gint hf_ssl_handshake_extension_server_name_len = -1;
static gint hf_ssl_handshake_extension_server_name_list_len = -1;
static gint hf_ssl_handshake_extension_server_name_type = -1;
static gint hf_ssl_handshake_extension_server_name = -1;
static gint hf_ssl_handshake_session_ticket_lifetime_hint = -1;
static gint hf_ssl_handshake_session_ticket_len = -1;
static gint hf_ssl_handshake_session_ticket = -1;
static gint hf_ssl_handshake_certificates_len = -1;
static gint hf_ssl_handshake_certificates     = -1;
static gint hf_ssl_handshake_certificate      = -1;
static gint hf_ssl_handshake_certificate_len  = -1;
static gint hf_ssl_handshake_cert_types_count = -1;
static gint hf_ssl_handshake_cert_types       = -1;
static gint hf_ssl_handshake_cert_type        = -1;
static gint hf_ssl_handshake_server_keyex_p_len     = -1;
static gint hf_ssl_handshake_server_keyex_g_len     = -1;
static gint hf_ssl_handshake_server_keyex_ys_len    = -1;
static gint hf_ssl_handshake_server_keyex_point_len = -1;
static gint hf_ssl_handshake_client_keyex_yc_len    = -1;
static gint hf_ssl_handshake_client_keyex_point_len = -1;
static gint hf_ssl_handshake_client_keyex_epms_len  = -1;
static gint hf_ssl_handshake_server_keyex_modulus_len = -1;
static gint hf_ssl_handshake_server_keyex_exponent_len = -1;
static gint hf_ssl_handshake_server_keyex_sig_len   = -1;
static gint hf_ssl_handshake_server_keyex_p         = -1;
static gint hf_ssl_handshake_server_keyex_g         = -1;
static gint hf_ssl_handshake_server_keyex_ys        = -1;
static gint hf_ssl_handshake_client_keyex_yc        = -1;
static gint hf_ssl_handshake_server_keyex_curve_type = -1;
static gint hf_ssl_handshake_server_keyex_named_curve = -1;
static gint hf_ssl_handshake_server_keyex_point     = -1;
static gint hf_ssl_handshake_client_keyex_epms      = -1;
static gint hf_ssl_handshake_client_keyex_point     = -1;
static gint hf_ssl_handshake_server_keyex_modulus   = -1;
static gint hf_ssl_handshake_server_keyex_exponent  = -1;
static gint hf_ssl_handshake_server_keyex_sig       = -1;
static gint hf_ssl_handshake_sig_hash_alg_len = -1;
static gint hf_ssl_handshake_sig_hash_algs    = -1;
static gint hf_ssl_handshake_sig_hash_alg     = -1;
static gint hf_ssl_handshake_sig_hash_hash    = -1;
static gint hf_ssl_handshake_sig_hash_sig     = -1;
static gint hf_ssl_handshake_cert_status      = -1;
static gint hf_ssl_handshake_cert_status_type = -1;
static gint hf_ssl_handshake_cert_status_len  = -1;
static gint hf_ssl_handshake_finished         = -1;
static gint hf_ssl_handshake_md5_hash         = -1;
static gint hf_ssl_handshake_sha_hash         = -1;
static gint hf_ssl_handshake_session_id_len   = -1;
static gint hf_ssl_handshake_dnames_len       = -1;
static gint hf_ssl_handshake_dnames           = -1;
static gint hf_ssl_handshake_dname_len        = -1;
static gint hf_ssl_handshake_dname            = -1;
static gint hf_ssl2_handshake_cipher_spec_len = -1;
static gint hf_ssl2_handshake_session_id_len  = -1;
static gint hf_ssl2_handshake_challenge_len   = -1;
static gint hf_ssl2_handshake_cipher_spec     = -1;
static gint hf_ssl2_handshake_challenge       = -1;
static gint hf_ssl2_handshake_clear_key_len   = -1;
static gint hf_ssl2_handshake_enc_key_len     = -1;
static gint hf_ssl2_handshake_key_arg_len     = -1;
static gint hf_ssl2_handshake_clear_key       = -1;
static gint hf_ssl2_handshake_enc_key         = -1;
static gint hf_ssl2_handshake_key_arg         = -1;
static gint hf_ssl2_handshake_session_id_hit  = -1;
static gint hf_ssl2_handshake_cert_type       = -1;
static gint hf_ssl2_handshake_connection_id_len = -1;
static gint hf_ssl2_handshake_connection_id   = -1;
static gint hf_pct_handshake_cipher_spec      = -1;
static gint hf_pct_handshake_hash_spec        = -1;
static gint hf_pct_handshake_cert_spec        = -1;
static gint hf_pct_handshake_cert             = -1;
static gint hf_pct_handshake_server_cert      = -1;
static gint hf_pct_handshake_exch_spec        = -1;
static gint hf_pct_handshake_hash             = -1;
static gint hf_pct_handshake_cipher           = -1;
static gint hf_pct_handshake_exch             = -1;
static gint hf_pct_handshake_sig              = -1;
static gint hf_pct_msg_error_type             = -1;
static int hf_ssl_reassembled_in              = -1;
static int hf_ssl_reassembled_length          = -1;
static int hf_ssl_segments                    = -1;
static int hf_ssl_segment                     = -1;
static int hf_ssl_segment_overlap             = -1;
static int hf_ssl_segment_overlap_conflict    = -1;
static int hf_ssl_segment_multiple_tails      = -1;
static int hf_ssl_segment_too_long_fragment   = -1;
static int hf_ssl_segment_error               = -1;
static int hf_ssl_segment_count               = -1;

static gint hf_ssl_heartbeat_extension_mode          = -1;
static gint hf_ssl_heartbeat_message                 = -1;
static gint hf_ssl_heartbeat_message_type            = -1;
static gint hf_ssl_heartbeat_message_payload_length  = -1;
static gint hf_ssl_heartbeat_message_payload         = -1;
static gint hf_ssl_heartbeat_message_padding         = -1;

/* Initialize the subtree pointers */
static gint ett_ssl                   = -1;
static gint ett_ssl_record            = -1;
static gint ett_ssl_alert             = -1;
static gint ett_ssl_handshake         = -1;
static gint ett_ssl_heartbeat         = -1;
static gint ett_ssl_cipher_suites     = -1;
static gint ett_ssl_comp_methods      = -1;
static gint ett_ssl_extension         = -1;
static gint ett_ssl_extension_curves  = -1;
static gint ett_ssl_extension_curves_point_formats = -1;
static gint ett_ssl_extension_npn     = -1;
static gint ett_ssl_extension_reneg_info = -1;
static gint ett_ssl_extension_server_name = -1;
static gint ett_ssl_certs             = -1;
static gint ett_ssl_cert_types        = -1;
static gint ett_ssl_sig_hash_algs     = -1;
static gint ett_ssl_sig_hash_alg      = -1;
static gint ett_ssl_dnames            = -1;
static gint ett_ssl_random            = -1;
static gint ett_ssl_new_ses_ticket    = -1;
static gint ett_ssl_keyex_params      = -1;
static gint ett_ssl_cert_status       = -1;
static gint ett_ssl_ocsp_resp         = -1;
static gint ett_pct_cipher_suites     = -1;
static gint ett_pct_hash_suites       = -1;
static gint ett_pct_cert_suites       = -1;
static gint ett_pct_exch_suites       = -1;
static gint ett_ssl_segments          = -1;
static gint ett_ssl_segment           = -1;


/* not all of the hf_fields below make sense for SSL but we have to provide
   them anyways to comply with the api (which was aimed for ip fragment
   reassembly) */
static const fragment_items ssl_segment_items = {
    &ett_ssl_segment,
    &ett_ssl_segments,
    &hf_ssl_segments,
    &hf_ssl_segment,
    &hf_ssl_segment_overlap,
    &hf_ssl_segment_overlap_conflict,
    &hf_ssl_segment_multiple_tails,
    &hf_ssl_segment_too_long_fragment,
    &hf_ssl_segment_error,
    &hf_ssl_segment_count,
    &hf_ssl_reassembled_in,
    &hf_ssl_reassembled_length,
    /* Reassembled data field */
    NULL,
    "Segments"
};

/* ssl_session_hash is used by "Export SSL Session Keys" */
GHashTable *ssl_session_hash   = NULL;

static GHashTable *ssl_key_hash       = NULL;
static GTree* ssl_associations        = NULL;
static dissector_handle_t ssl_handle  = NULL;
static StringInfo ssl_compressed_data = {NULL, 0};
static StringInfo ssl_decrypted_data  = {NULL, 0};
static gint ssl_decrypted_data_avail  = 0;

static uat_t *ssldecrypt_uat = NULL;
static const gchar* ssl_keys_list = NULL;
static const gchar* ssl_psk = NULL;
static const gchar* ssl_keylog_filename = NULL;

/* List of dissectors to call for SSL data */
static heur_dissector_list_t ssl_heur_subdissector_list;

#if defined(SSL_DECRYPT_DEBUG) || defined(HAVE_LIBGNUTLS)
static const gchar* ssl_debug_file_name     = NULL;
#endif


/* Forward declaration we need below */
void proto_reg_handoff_ssl(void);

/* Desegmentation of SSL streams */
/* table to hold defragmented SSL streams */
static GHashTable *ssl_fragment_table = NULL;
static void
ssl_fragment_init(void)
{
    fragment_table_init(&ssl_fragment_table);
}

/* initialize/reset per capture state data (ssl sessions cache) */
static void
ssl_init(void)
{
    module_t *ssl_module = prefs_find_module("ssl");
    pref_t *keys_list_pref;

    ssl_common_init(&ssl_session_hash, &ssl_decrypted_data, &ssl_compressed_data);
    ssl_fragment_init();
    ssl_debug_flush();

    /* We should have loaded "keys_list" by now. Mark it obsolete */
    if (ssl_module) {
        keys_list_pref = prefs_find_preference(ssl_module, "keys_list");
        if (! prefs_get_preference_obsolete(keys_list_pref)) {
            prefs_set_preference_obsolete(keys_list_pref);
        }
    }
}

/* parse ssl related preferences (private keys and ports association strings) */
static void
ssl_parse_uat(void)
{
    ep_stack_t tmp_stack;
    SslAssociation *tmp_assoc;
    guint i;

    ssl_set_debug(ssl_debug_file_name);

    if (ssl_key_hash)
    {
        g_hash_table_foreach(ssl_key_hash, ssl_private_key_free, NULL);
        g_hash_table_destroy(ssl_key_hash);
    }

    /* remove only associations created from key list */
    tmp_stack = ep_stack_new();
    g_tree_foreach(ssl_associations, ssl_assoc_from_key_list, tmp_stack);
    while ((tmp_assoc = ep_stack_pop(tmp_stack)) != NULL) {
        ssl_association_remove(ssl_associations, tmp_assoc);
    }

    /* parse private keys string, load available keys and put them in key hash*/
    ssl_key_hash = g_hash_table_new(ssl_private_key_hash,ssl_private_key_equal);


    if (nssldecrypt > 0) {
        for (i = 0; i < nssldecrypt; i++) {
            ssldecrypt_assoc_t *ssl_uat = &(sslkeylist_uats[i]);
            ssl_parse_key_list(ssl_uat, ssl_key_hash, ssl_associations, ssl_handle, TRUE);
        }
    }

    ssl_debug_flush();
}

static void
ssl_parse_old_keys(void)
{
    gchar **old_keys, **parts, *err;
    gchar *uat_entry;
    guint i;

    /* Import old-style keys */
    if (ssldecrypt_uat && ssl_keys_list && ssl_keys_list[0]) {
        old_keys = ep_strsplit(ssl_keys_list, ";", 0);
        for (i = 0; old_keys[i] != NULL; i++) {
            parts = ep_strsplit(old_keys[i], ",", 4);
            if (parts[0] && parts[1] && parts[2] && parts[3]) {
                uat_entry = ep_strdup_printf("\"%s\",\"%s\",\"%s\",\"%s\",\"\"",
                                parts[0], parts[1], parts[2], parts[3]);
                if (!uat_load_str(ssldecrypt_uat, uat_entry, &err)) {
                    ssl_debug_printf("ssl_parse_old_keys: Can't load UAT string %s: %s\n",
                                     uat_entry, err);
                }
            }
        }
    }
}

/*********************************************************************
 *
 * SSL Associations tree
 *
 *********************************************************************/

/** maximum size of ssl_association_info() string */
#define SSL_ASSOC_MAX_LEN 8192

/**
 * callback function used by ssl_association_info() to traverse the SSL associations.
 */
static gboolean
ssl_association_info_(gpointer key_ _U_, gpointer value_, gpointer s_)
{
    SslAssociation *value = value_;
    gchar *s = s_;
    const int l = (const int)strlen(s);
    g_snprintf(s+l, SSL_ASSOC_MAX_LEN-l, "'%s' %s %i\n", value->info, value->tcp ? "TCP":"UDP", value->ssl_port);
    return FALSE;
}

extern GTree* ssl_associations;

/**
 * @return an information string on the SSL protocol associations. The string has ephemeral lifetime/scope.
 */
gchar*
ssl_association_info(void)
{
    gchar *s = ep_alloc0(SSL_ASSOC_MAX_LEN);
    g_tree_foreach(ssl_associations, ssl_association_info_, s);
    return s;
}

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
static gint dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset,
                                guint *conv_version, guint conv_cipher,
                                gboolean *need_desegmentation,
                                SslDecryptSession *conv_data,
                                const gboolean first_record_in_frame);

/* change cipher spec dissector */
static void dissect_ssl3_change_cipher_spec(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            guint32 offset,
                                            guint *conv_version, const guint8 content_type);

/* alert message dissector */
static void dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version);

/* handshake protocol dissector */
static void dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint32 record_length,
                                   guint *conv_version, guint conv_cipher,
                                   SslDecryptSession *conv_data, const guint8 content_type);

/* heartbeat message dissector */
static void dissect_ssl3_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint *conv_version, guint32 record_length);

/* hello extension dissector */
static gint dissect_ssl3_hnd_hello_ext_elliptic_curves(tvbuff_t *tvb,
                                                       proto_tree *tree, guint32 offset);

static gint dissect_ssl3_hnd_hello_ext_ec_point_formats(tvbuff_t *tvb,
                                                        proto_tree *tree, guint32 offset);

static gint dissect_ssl3_hnd_hello_ext_npn(tvbuff_t *tvb,
                                           proto_tree *tree, guint32 offset, guint32 ext_len);

static gint dissect_ssl3_hnd_hello_ext_reneg_info(tvbuff_t *tvb,
                                           proto_tree *tree, guint32 offset, guint32 ext_len);

static gint dissect_ssl3_hnd_hello_ext_server_name(tvbuff_t *tvb,
                                           proto_tree *tree, guint32 offset, guint32 ext_len);

static void dissect_ssl3_hnd_cli_hello(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length,
                                       SslDecryptSession* ssl);

static void dissect_ssl3_hnd_srv_hello(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length,
                                       SslDecryptSession* ssl);

static void dissect_ssl3_hnd_new_ses_ticket(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length);

static void dissect_ssl3_hnd_cert(tvbuff_t *tvb,
                                  proto_tree *tree, guint32 offset, packet_info *pinfo);

static void dissect_ssl3_hnd_cert_req(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset, packet_info *pinfo,
                                      const guint* conv_version);

static void dissect_ssl3_hnd_srv_keyex_ecdh(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, guint32 length);


static void dissect_ssl3_hnd_srv_keyex_dh(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, guint32 length);

static void dissect_ssl3_hnd_srv_keyex_rsa(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, guint32 length);

static void dissect_ssl3_hnd_cli_keyex_ecdh(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, guint32 length);

static void dissect_ssl3_hnd_cli_keyex_dh(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, guint32 length);

static void dissect_ssl3_hnd_cli_keyex_rsa(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, guint32 length);


static void dissect_ssl3_hnd_finished(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      const guint32 offset,
                                      const guint* conv_version);

static void dissect_ssl3_hnd_cert_status(tvbuff_t *tvb,
                                         proto_tree *tree,
                                         guint32 offset,
                                         packet_info *pinfo);

/*
 * SSL version 2 dissectors
 *
 */

/* record layer dissector */
static gint dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset,
                                guint *conv_version,
                                gboolean *need_desegmentation,
                                SslDecryptSession* ssl, gboolean first_record_in_frame);

/* client hello dissector */
static void dissect_ssl2_hnd_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree,
                                          guint32 offset,
                                          SslDecryptSession* ssl);

static void dissect_pct_msg_client_hello(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset);

/* client master key dissector */
static void dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb,
                                               proto_tree *tree,
                                               guint32 offset);
static void dissect_pct_msg_client_master_key(tvbuff_t *tvb,
                                              proto_tree *tree,
                                              guint32 offset);

/* server hello dissector */
static void dissect_ssl2_hnd_server_hello(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, packet_info *pinfo);
static void dissect_pct_msg_server_hello(tvbuff_t *tvb,
                                         proto_tree *tree,
                                         guint32 offset, packet_info *pinfo);


static void dissect_pct_msg_server_verify(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset);

static void dissect_pct_msg_error(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 offset);

/*
 * Support Functions
 *
 */
/*static void ssl_set_conv_version(packet_info *pinfo, guint version);*/
static gint  ssl_is_valid_handshake_type(const guint8 type);
static gint  ssl_is_valid_ssl_version(const guint16 version);
static gint  ssl_is_authoritative_version_message(const guint8 content_type,
                                                  const guint8 next_byte);
static gint  ssl_is_v2_client_hello(tvbuff_t *tvb, const guint32 offset);
static gint  ssl_looks_like_sslv2(tvbuff_t *tvb, const guint32 offset);
static gint  ssl_looks_like_sslv3(tvbuff_t *tvb, const guint32 offset);
static gint  ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb,
                                               const guint32 offset,
                                               const guint32 record_length);
static gint  ssl_looks_like_valid_pct_handshake(tvbuff_t *tvb,
                                                const guint32 offset,
                                                const guint32 record_length);
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
    proto_item *ti;
    proto_tree *ssl_tree;
    guint32 offset;
    gboolean first_record_in_frame;
    gboolean need_desegmentation;
    SslDecryptSession* ssl_session;
    guint* conv_version;
    guint conv_cipher;

    ti = NULL;
    ssl_tree   = NULL;
    offset = 0;
    first_record_in_frame = TRUE;
    ssl_session = NULL;


    ssl_debug_printf("\ndissect_ssl enter frame #%u (%s)\n", pinfo->fd->num, (pinfo->fd->flags.visited)?"already visited":"first time");

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
    conversation = find_or_create_conversation(pinfo);

    conv_data = conversation_get_proto_data(conversation, proto_ssl);

    /* PAOLO: manage ssl decryption data */
    /*get a valid ssl session pointer*/
    if (conv_data != NULL)
        ssl_session = conv_data;
    else {
        ssl_session = se_alloc0(sizeof(SslDecryptSession));
        ssl_session_init(ssl_session);
        ssl_session->version = SSL_VER_UNKNOWN;
        conversation_add_proto_data(conversation, proto_ssl, ssl_session);
    }
    conv_version =& ssl_session->version;
    conv_cipher  =  ssl_session->cipher;

    /* try decryption only the first time we see this packet
     * (to keep cipher synchronized) */
    if (pinfo->fd->flags.visited)
         ssl_session = NULL;

    ssl_debug_printf("  conversation = %p, ssl_session = %p\n", (void *)conversation, (void *)ssl_session);

    /* Initialize the protocol column; we'll set it later when we
     * figure out what flavor of SSL it is (assuming we don't
     * throw an exception before we get the chance to do so). */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSL");
    /* clear the the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* TCP packets and SSL records are orthogonal.
     * A tcp packet may contain multiple ssl records and an ssl
     * record may be spread across multiple tcp packets.
     *
     * This loop accounts for multiple ssl records in a single
     * frame, but not a single ssl record across multiple tcp
     * packets.
     *
     * Handling the single ssl record across multiple packets
     * may be possible using wireshark conversations, but
     * probably not cleanly.  May have to wait for tcp stream
     * reassembly.
     */

    /* Create display subtree for SSL as a whole */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_ssl, tvb, 0, -1, ENC_NA);
        ssl_tree = proto_item_add_subtree(ti, ett_ssl);
    }
    /* iterate through the records in this tvbuff */
    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        ssl_debug_printf("  record: offset = %d, reported_length_remaining = %d\n", offset, tvb_reported_length_remaining(tvb, offset));

        /*
         * Assume, for now, that this doesn't need desegmentation.
         */
        need_desegmentation = FALSE;

        /* first try to dispatch off the cached version
         * known to be associated with the conversation
         */
        switch(*conv_version) {
        case SSL_VER_SSLv2:
        case SSL_VER_PCT:
            offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                         offset, conv_version,
                                         &need_desegmentation,
                                         ssl_session,
                                         first_record_in_frame);
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
                                             offset, conv_version,
                                             &need_desegmentation,
                                             ssl_session,
                                             first_record_in_frame);
            }
            else
            {
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             conv_cipher,
                                             &need_desegmentation,
                                             ssl_session,
                                             first_record_in_frame);
            }
            break;

            /* that failed, so apply some heuristics based
             * on this individual packet
             */
        default:
            if (ssl_looks_like_sslv2(tvb, offset))
            {
                /* looks like sslv2 or pct client hello */
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             &need_desegmentation,
                                             ssl_session,
                                             first_record_in_frame);
            }
            else if (ssl_looks_like_sslv3(tvb, offset))
            {
                /* looks like sslv3 or tls */
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             conv_cipher,
                                             &need_desegmentation,
                                             ssl_session,
                                             first_record_in_frame);
            }
            else
            {
                /* on second and subsequent records per frame
                 * add a delimiter on info column
                 */
                if (!first_record_in_frame) {
                    col_append_str(pinfo->cinfo, COL_INFO, ", ");
                }

                /* looks like something unknown, so lump into
                 * continuation data
                 */
                offset = tvb_length(tvb);
                col_append_str(pinfo->cinfo, COL_INFO,
                                   "Continuation Data");

                /* Set the protocol column */
                col_set_str(pinfo->cinfo, COL_PROTOCOL,
                         val_to_str_const(*conv_version, ssl_version_short_names, "SSL"));
            }
            break;
        }

        /* Desegmentation return check */
        if (need_desegmentation) {
          ssl_debug_printf("  need_desegmentation: offset = %d, reported_length_remaining = %d\n", offset, tvb_reported_length_remaining(tvb, offset));
          return;
        }

        /* set up for next record in frame, if any */
        first_record_in_frame = FALSE;
    }

    col_set_fence(pinfo->cinfo, COL_INFO);

    ssl_debug_flush();

    tap_queue_packet(ssl_tap, pinfo, GINT_TO_POINTER(proto_ssl));
}

static gint
decrypt_ssl3_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset,
        guint32 record_length, guint8 content_type, SslDecryptSession* ssl,
        gboolean save_plaintext)
{
    gint ret;
    gint direction;
    StringInfo* data_for_iv;
    gint data_for_iv_len;
    SslDecoder* decoder;
    ret = 0;
    /* if we can decrypt and decryption was a success
     * add decrypted data to this packet info */
    ssl_debug_printf("decrypt_ssl3_record: app_data len %d, ssl state 0x%02X\n",
        record_length, ssl->state);
    direction = ssl_packet_from_server(ssl, ssl_associations, pinfo);

    /* retrieve decoder for this packet direction */
    if (direction != 0) {
        ssl_debug_printf("decrypt_ssl3_record: using server decoder\n");
        decoder = ssl->server;
    }
    else {
        ssl_debug_printf("decrypt_ssl3_record: using client decoder\n");
        decoder = ssl->client;
    }

    /* save data to update IV if decoder is available or updated later */
    data_for_iv = (direction != 0) ? &ssl->server_data_for_iv : &ssl->client_data_for_iv;
    data_for_iv_len = (record_length < 24) ? record_length : 24;
    ssl_data_set(data_for_iv, (guchar*)tvb_get_ptr(tvb, offset + record_length - data_for_iv_len, data_for_iv_len), data_for_iv_len);

    if (!decoder) {
        ssl_debug_printf("decrypt_ssl3_record: no decoder available\n");
        return ret;
    }

    /* run decryption and add decrypted payload to protocol data, if decryption
     * is successful*/
    ssl_decrypted_data_avail = ssl_decrypted_data.data_len;
    if (ssl_decrypt_record(ssl, decoder,
                           content_type, tvb_get_ptr(tvb, offset, record_length),
                           record_length, &ssl_compressed_data, &ssl_decrypted_data, &ssl_decrypted_data_avail) == 0)
        ret = 1;
    /*  */
    if (!ret) {
        /* save data to update IV if valid session key is obtained later */
        data_for_iv = (direction != 0) ? &ssl->server_data_for_iv : &ssl->client_data_for_iv;
        data_for_iv_len = (record_length < 24) ? record_length : 24;
        ssl_data_set(data_for_iv, (guchar*)tvb_get_ptr(tvb, offset + record_length - data_for_iv_len, data_for_iv_len), data_for_iv_len);
    }
    if (ret && save_plaintext) {
      ssl_add_data_info(proto_ssl, pinfo, ssl_decrypted_data.data, ssl_decrypted_data_avail,  tvb_raw_offset(tvb)+offset, decoder->flow);
    }
    return ret;
}

static void
process_ssl_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
                    proto_tree *tree, SslAssociation* association);

static void
desegment_ssl(tvbuff_t *tvb, packet_info *pinfo, int offset,
              guint32 seq, guint32 nxtseq,
              SslAssociation* association,
              proto_tree *root_tree, proto_tree *tree,
              SslFlow *flow)
{
    fragment_data *ipfd_head;
    gboolean must_desegment;
    gboolean called_dissector;
    int another_pdu_follows;
    int deseg_offset;
    guint32 deseg_seq;
    gint nbytes;
    proto_item *item;
    proto_item *frag_tree_item;
    proto_item *ssl_tree_item;
    struct tcp_multisegment_pdu *msp;

again:
    ipfd_head = NULL;
    must_desegment = FALSE;
    called_dissector = FALSE;
    another_pdu_follows = 0;
    msp = NULL;

    /*
     * Initialize these to assume no desegmentation.
     * If that's not the case, these will be set appropriately
     * by the subdissector.
     */
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    /*
     * Initialize this to assume that this segment will just be
     * added to the middle of a desegmented chunk of data, so
     * that we should show it all as data.
     * If that's not the case, it will be set appropriately.
     */
    deseg_offset = offset;

    /* If we've seen this segment before (e.g., it's a retransmission),
     * there's nothing for us to do.  Certainly, don't add it to the list
     * of multisegment_pdus (that would cause subsequent lookups to find
     * the retransmission instead of the original transmission, breaking
     * dissection of the desegmented pdu if we'd already seen the end of
     * the pdu).
     */
    if ((msp = se_tree_lookup32(flow->multisegment_pdus, seq))) {
        const char* str;

        if (msp->first_frame == PINFO_FD_NUM(pinfo)) {
            str = "";
            col_set_str(pinfo->cinfo, COL_INFO, "[SSL segment of a reassembled PDU]");
        } else {
            str = "Retransmitted ";
        }

        nbytes = tvb_reported_length_remaining(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, nbytes,
                            "%sSSL segment data (%u byte%s)",
                            str, nbytes, plurality(nbytes, "", "s"));
        return;
    }

    /* Else, find the most previous PDU starting before this sequence number */
    msp = se_tree_lookup32_le(flow->multisegment_pdus, seq-1);
    if (msp && msp->seq <= seq && msp->nxtpdu > seq) {
        int len;

        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame = pinfo->fd->num;
            msp->last_frame_time = pinfo->fd->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        if (msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /* The dissector asked for the entire segment */
            len = MAX(0, tvb_length_remaining(tvb, offset));
        } else {
            len = MIN(nxtseq, msp->nxtpdu) - seq;
        }

        ipfd_head = fragment_add(tvb, offset, pinfo, msp->first_frame,
                                 ssl_fragment_table, seq - msp->seq,
                                 len, (LT_SEQ (nxtseq,msp->nxtpdu)));

        if (msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            msp->flags &= (~MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT);

            /* If we consumed the entire segment there is no
             * other pdu starting anywhere inside this segment.
             * So update nxtpdu to point at least to the start
             * of the next segment.
             * (If the subdissector asks for even more data we
             * will advance nxtpdu even furhter later down in
             * the code.)
             */
            msp->nxtpdu = nxtseq;
        }

        if ( (msp->nxtpdu < nxtseq)
        &&  (msp->nxtpdu >= seq)
        &&  (len > 0)) {
            another_pdu_follows = msp->nxtpdu - seq;
        }
    } else {
        /* This segment was not found in our table, so it doesn't
         * contain a continuation of a higher-level PDU.
         * Call the normal subdissector.
         */
        process_ssl_payload(tvb, offset, pinfo, tree, association);
        called_dissector = TRUE;

        /* Did the subdissector ask us to desegment some more data
         * before it could handle the packet?
         * If so we have to create some structures in our table but
         * this is something we only do the first time we see this
         * packet.
         */
        if (pinfo->desegment_len) {
            if (!PINFO_FD_VISITED(pinfo))
                must_desegment = TRUE;

            /*
             * Set "deseg_offset" to the offset in "tvb"
             * of the first byte of data that the
             * subdissector didn't process.
             */
            deseg_offset = offset + pinfo->desegment_offset;
        }

        /* Either no desegmentation is necessary, or this is
         * segment contains the beginning but not the end of
         * a higher-level PDU and thus isn't completely
         * desegmented.
         */
        ipfd_head = NULL;
    }


    /* is it completely desegmented? */
    if (ipfd_head) {
        /*
         * Yes, we think it is.
         * We only call subdissector for the last segment.
         * Note that the last segment may include more than what
         * we needed.
         */
        if (ipfd_head->reassembled_in == pinfo->fd->num) {
            /*
             * OK, this is the last segment.
             * Let's call the subdissector with the desegmented
             * data.
             */
            tvbuff_t *next_tvb;
            int old_len;

            /* create a new TVB structure for desegmented data */
            next_tvb = tvb_new_child_real_data(tvb, ipfd_head->data,
                                               ipfd_head->datalen,
                                               ipfd_head->datalen);

            /* add desegmented data to the data source list */
            add_new_data_source(pinfo, next_tvb, "Reassembled SSL");

            /* call subdissector */
            process_ssl_payload(next_tvb, 0, pinfo, tree, association);
            called_dissector = TRUE;

            /*
             * OK, did the subdissector think it was completely
             * desegmented, or does it think we need even more
             * data?
             */
            old_len = (int)(tvb_reported_length(next_tvb) - tvb_reported_length_remaining(tvb, offset));
            if (pinfo->desegment_len && pinfo->desegment_offset <= old_len) {
                /*
                 * "desegment_len" isn't 0, so it needs more
                 * data for something - and "desegment_offset"
                 * is before "old_len", so it needs more data
                 * to dissect the stuff we thought was
                 * completely desegmented (as opposed to the
                 * stuff at the beginning being completely
                 * desegmented, but the stuff at the end
                 * being a new higher-level PDU that also
                 * needs desegmentation).
                 */
                fragment_set_partial_reassembly(pinfo, msp->first_frame, ssl_fragment_table);
                /* Update msp->nxtpdu to point to the new next
                 * pdu boundary.
                 */
                if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                    /* We want reassembly of at least one
                     * more segment so set the nxtpdu
                     * boundary to one byte into the next
                     * segment.
                     * This means that the next segment
                     * will complete reassembly even if it
                     * is only one single byte in length.
                     */
                    msp->nxtpdu = seq + tvb_reported_length_remaining(tvb, offset) + 1;
                    msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
                } else {
                    msp->nxtpdu = seq + tvb_reported_length_remaining(tvb, offset) + pinfo->desegment_len;
                }
                /* Since we need at least some more data
                 * there can be no pdu following in the
                 * tail of this segment.
                 */
                another_pdu_follows = 0;
            } else {
                /*
                 * Show the stuff in this TCP segment as
                 * just raw TCP segment data.
                 */
                nbytes = tvb_reported_length_remaining(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, -1,
                                    "SSL segment data (%u byte%s)", nbytes,
                                    plurality(nbytes, "", "s"));

                /*
                 * The subdissector thought it was completely
                 * desegmented (although the stuff at the
                 * end may, in turn, require desegmentation),
                 * so we show a tree with all segments.
                 */
                show_fragment_tree(ipfd_head, &ssl_segment_items,
                                   root_tree, pinfo, next_tvb, &frag_tree_item);
                /*
                 * The toplevel fragment subtree is now
                 * behind all desegmented data; move it
                 * right behind the TCP tree.
                 */
                ssl_tree_item = proto_tree_get_parent(tree);
                if (frag_tree_item && ssl_tree_item) {
                    proto_tree_move_item(root_tree, ssl_tree_item, frag_tree_item);
                }

                /* Did the subdissector ask us to desegment
                 * some more data?  This means that the data
                 * at the beginning of this segment completed
                 * a higher-level PDU, but the data at the
                 * end of this segment started a higher-level
                 * PDU but didn't complete it.
                 *
                 * If so, we have to create some structures
                 * in our table, but this is something we
                 * only do the first time we see this packet.
                 */
                if (pinfo->desegment_len) {
                    if (!PINFO_FD_VISITED(pinfo))
                        must_desegment = TRUE;

                    /* The stuff we couldn't dissect
                     * must have come from this segment,
                     * so it's all in "tvb".
                     *
                     * "pinfo->desegment_offset" is
                     * relative to the beginning of
                     * "next_tvb"; we want an offset
                     * relative to the beginning of "tvb".
                     *
                     * First, compute the offset relative
                     * to the *end* of "next_tvb" - i.e.,
                     * the number of bytes before the end
                     * of "next_tvb" at which the
                     * subdissector stopped.  That's the
                     * length of "next_tvb" minus the
                     * offset, relative to the beginning
                     * of "next_tvb, at which the
                     * subdissector stopped.
                     */
                    deseg_offset = ipfd_head->datalen - pinfo->desegment_offset;

                    /* "tvb" and "next_tvb" end at the
                     * same byte of data, so the offset
                     * relative to the end of "next_tvb"
                     * of the byte at which we stopped
                     * is also the offset relative to
                     * the end of "tvb" of the byte at
                     * which we stopped.
                     *
                     * Convert that back into an offset
                     * relative to the beginninng of
                     * "tvb", by taking the length of
                     * "tvb" and subtracting the offset
                     * relative to the end.
                     */
                    deseg_offset = tvb_reported_length(tvb) - deseg_offset;
                }
            }
        }
    }

    if (must_desegment) {
        /* If the dissector requested "reassemble until FIN"
         * just set this flag for the flow and let reassembly
         * proceed at normal.  We will check/pick up these
         * reassembled PDUs later down in dissect_tcp() when checking
         * for the FIN flag.
         */
        if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
            flow->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
        }
        /*
         * The sequence number at which the stuff to be desegmented
         * starts is the sequence number of the byte at an offset
         * of "deseg_offset" into "tvb".
         *
         * The sequence number of the byte at an offset of "offset"
         * is "seq", i.e. the starting sequence number of this
         * segment, so the sequence number of the byte at
         * "deseg_offset" is "seq + (deseg_offset - offset)".
         */
        deseg_seq = seq + (deseg_offset - offset);

        if (((nxtseq - deseg_seq) <= 1024*1024)
            &&  (!PINFO_FD_VISITED(pinfo))) {
            if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                /* The subdissector asked to reassemble using the
                 * entire next segment.
                 * Just ask reassembly for one more byte
                 * but set this msp flag so we can pick it up
                 * above.
                 */
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+1, flow->multisegment_pdus);
                msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
            } else {
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+pinfo->desegment_len, flow->multisegment_pdus);
            }

            /* add this segment as the first one for this new pdu */
            fragment_add(tvb, deseg_offset, pinfo, msp->first_frame,
                         ssl_fragment_table, 0, nxtseq - deseg_seq,
                         LT_SEQ(nxtseq, msp->nxtpdu));
        }
    }

    if (!called_dissector || pinfo->desegment_len != 0) {
        if (ipfd_head != NULL && ipfd_head->reassembled_in != 0 &&
            !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
            /*
             * We know what frame this PDU is reassembled in;
             * let the user know.
             */
            item=proto_tree_add_uint(tree, *ssl_segment_items.hf_reassembled_in,
                                     tvb, 0, 0, ipfd_head->reassembled_in);
            PROTO_ITEM_SET_GENERATED(item);
        }

        /*
         * Either we didn't call the subdissector at all (i.e.,
         * this is a segment that contains the middle of a
         * higher-level PDU, but contains neither the beginning
         * nor the end), or the subdissector couldn't dissect it
         * all, as some data was missing (i.e., it set
         * "pinfo->desegment_len" to the amount of additional
         * data it needs).
         */
        if (pinfo->desegment_offset == 0) {
            /*
             * It couldn't, in fact, dissect any of it (the
             * first byte it couldn't dissect is at an offset
             * of "pinfo->desegment_offset" from the beginning
             * of the payload, and that's 0).
             * Just mark this as SSL.
             */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSL");
            col_set_str(pinfo->cinfo, COL_INFO, "[SSL segment of a reassembled PDU]");
        }

        /*
         * Show what's left in the packet as just raw TCP segment
         * data.
         * XXX - remember what protocol the last subdissector
         * was, and report it as a continuation of that, instead?
         */
        nbytes = tvb_reported_length_remaining(tvb, deseg_offset);
        proto_tree_add_text(tree, tvb, deseg_offset, -1,
                            "SSL segment data (%u byte%s)", nbytes,
                            plurality(nbytes, "", "s"));
    }
    pinfo->can_desegment = 0;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    if (another_pdu_follows) {
        /* there was another pdu following this one. */
        pinfo->can_desegment=2;
        /* we also have to prevent the dissector from changing the
         * PROTOCOL and INFO colums since what follows may be an
         * incomplete PDU and we dont want it be changed back from
         *  <Protocol>   to <TCP>
         * XXX There is no good way to block the PROTOCOL column
         * from being changed yet so we set the entire row unwritable.
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, FALSE);
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    }
}

static void
process_ssl_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
                    proto_tree *tree, SslAssociation* association)
{
    tvbuff_t *next_tvb;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if (association && association->handle) {
        ssl_debug_printf("dissect_ssl3_record found association %p\n", (void *)association);

        if (dissector_try_heuristic(ssl_heur_subdissector_list, next_tvb,
                                    pinfo, proto_tree_get_root(tree), NULL)) {
        } else {
            call_dissector(association->handle, next_tvb, pinfo, proto_tree_get_root(tree));
        }
    }
}

static void
dissect_ssl_payload(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, SslAssociation* association)
{
    gboolean save_fragmented;
    guint16 save_can_desegment;
    SslDataInfo *appl_data;
    tvbuff_t *next_tvb;

    /* Preserve current desegmentation ability to prevent the subdissector
     * from messing up the ssl desegmentation */
    save_can_desegment = pinfo->can_desegment;

    /* show decrypted data info, if available */
    appl_data = ssl_get_data_info(proto_ssl, pinfo, tvb_raw_offset(tvb)+offset);
    if (!appl_data || !appl_data->plain_data.data_len) return;

    /* try to dissect decrypted data*/
    ssl_debug_printf("dissect_ssl3_record decrypted len %d\n", appl_data->plain_data.data_len);
    ssl_print_data("decrypted app data fragment", appl_data->plain_data.data, appl_data->plain_data.data_len);

    /* create a new TVB structure for desegmented data */
    next_tvb = tvb_new_child_real_data(tvb, appl_data->plain_data.data, appl_data->plain_data.data_len, appl_data->plain_data.data_len);

    /* add desegmented data to the data source list */
    add_new_data_source(pinfo, next_tvb, "Decrypted SSL data");

    /* Can we desegment this segment? */
    if (ssl_desegment_app_data) {
        /* Yes. */
        pinfo->can_desegment = 2;
        desegment_ssl(next_tvb, pinfo, 0, appl_data->seq, appl_data->nxtseq, association, proto_tree_get_root(tree), tree, appl_data->flow);
    } else if (association && association->handle) {
        /* No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame. */
        pinfo->can_desegment = 0;
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        process_ssl_payload(next_tvb, 0, pinfo, tree, association);
        pinfo->fragmented = save_fragmented;
    }

    /* restore desegmentation ability */
    pinfo->can_desegment = save_can_desegment;
}


/*********************************************************************
 *
 * SSL version 3 and TLS Dissection Routines
 *
 *********************************************************************/
static gint
dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, guint32 offset,
                    guint *conv_version, guint conv_cipher,
                    gboolean *need_desegmentation,
                    SslDecryptSession* ssl, const gboolean first_record_in_frame)
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
    proto_tree *ti;
    proto_tree *ssl_record_tree;
    SslAssociation* association;
    guint32 available_bytes;
    ti = NULL;
    ssl_record_tree = NULL;

    available_bytes = tvb_length_remaining(tvb, offset);

    /* TLS 1.0/1.1 just ignores unknown records - RFC 2246 chapter 6. The TLS Record Protocol */
    if ((*conv_version==SSL_VER_TLS || *conv_version==SSL_VER_TLSv1DOT1 || *conv_version==SSL_VER_TLSv1DOT2) &&
        (available_bytes >=1 ) && !ssl_is_valid_content_type(tvb_get_guint8(tvb, offset))) {
        proto_tree_add_text(tree, tvb, offset, available_bytes, "Ignored Unknown Record");
        /* on second and subsequent records per frame
         * add a delimiter on info column
         */
        if (!first_record_in_frame) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }
        col_append_str(pinfo->cinfo, COL_INFO, "Ignored Unknown Record");
        col_set_str(pinfo->cinfo, COL_PROTOCOL, val_to_str_const(*conv_version, ssl_version_short_names, "SSL"));
        return offset + available_bytes;
    }

    /*
     * Is the record header split across segment boundaries?
     */
    if (available_bytes < 5) {
        /*
         * Yes - can we do reassembly?
         */
        if (ssl_desegment && pinfo->can_desegment) {
            /*
             * Yes.  Tell the TCP dissector where the data for this
             * message starts in the data it handed us, and that we need
             * "some more data."  Don't tell it exactly how many bytes we
             * need because if/when we ask for even more (after the header)
             * that will break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        } else {
            /* Not enough bytes available. Stop here. */
            return offset + available_bytes;
        }
    }

    /*
     * Get the record layer fields of interest
     */
    content_type  = tvb_get_guint8(tvb, offset);
    version       = tvb_get_ntohs(tvb, offset + 1);
    record_length = tvb_get_ntohs(tvb, offset + 3);

    if (ssl_is_valid_content_type(content_type)) {

        /*
         * Is the record split across segment boundaries?
         */
        if (available_bytes < record_length + 5) {
            /*
             * Yes - can we do reassembly?
             */
            if (ssl_desegment && pinfo->can_desegment) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and how many
                 * more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;

                /* Don't use:
                 * pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                 * it avoids some minor display glitches when a frame contains
                 * the continuation of a previous PDU together with a full new
                 * PDU, but it completely breaks dissection for jumbo SSL frames
                 */

                pinfo->desegment_len = (record_length + 5) - available_bytes;
                *need_desegmentation = TRUE;
                return offset;
            } else {
                /* Not enough bytes available. Stop here. */
                return offset + available_bytes;
            }
        }

    } else {

        /* on second and subsequent records per frame
         * add a delimiter on info column
         */
        if (!first_record_in_frame) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

        /* if we don't have a valid content_type, there's no sense
         * continuing any further
         */
        col_append_str(pinfo->cinfo, COL_INFO, "Continuation Data");

        /* Set the protocol column */
        col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        val_to_str_const(*conv_version, ssl_version_short_names, "SSL"));

        return offset + 5 + record_length;
    }

    /*
     * If building a protocol tree, fill in record layer part of tree
     */
    if (tree)
    {

        /* add the record layer subtree header */
        tvb_ensure_bytes_exist(tvb, offset, 5 + record_length);
        ti = proto_tree_add_item(tree, hf_ssl_record, tvb,
                                 offset, 5 + record_length, ENC_NA);
        ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);

        /* show the one-byte content type */
        proto_tree_add_item(ssl_record_tree, hf_ssl_record_content_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;;

        /* add the version */
        proto_tree_add_item(ssl_record_tree, hf_ssl_record_version, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* add the length */
        proto_tree_add_uint(ssl_record_tree, hf_ssl_record_length, tvb,
                            offset, 2, record_length);
        offset += 2;    /* move past length field itself */
    }
    else
    {
        /* if no protocol tree, then just skip over those fields */
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
        if (version == SSLV3_VERSION)
        {
            *conv_version = SSL_VER_SSLv3;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
                ssl_debug_printf("dissect_ssl3_record found version 0x%04X -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (version == TLSV1_VERSION)
        {

            *conv_version = SSL_VER_TLS;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
                ssl_debug_printf("dissect_ssl3_record found version 0x%04X(TLS 1.0) -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (version == TLSV1DOT1_VERSION)
        {

            *conv_version = SSL_VER_TLSv1DOT1;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
                ssl_debug_printf("dissect_ssl3_record found version 0x%04X(TLS 1.1) -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (version == TLSV1DOT2_VERSION)
        {

            *conv_version = SSL_VER_TLSv1DOT2;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
                ssl_debug_printf("dissect_ssl3_record found version 0x%04X(TLS 1.2) -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
    }

    /* on second and subsequent records per frame
     * add a delimiter on info column
     */
    if (!first_record_in_frame) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        val_to_str_const(*conv_version, ssl_version_short_names, "SSL"));

    /*
     * now dissect the next layer
     */
    ssl_debug_printf("dissect_ssl3_record: content_type %d %s\n",content_type, val_to_str_const(content_type, ssl_31_content_type, "unknown"));

    /* PAOLO try to decrypt each record (we must keep ciphers "in sync")
     * store plain text only for app data */

    switch (content_type) {
    case SSL_ID_CHG_CIPHER_SPEC:
        ssl_debug_printf("dissect_ssl3_change_cipher_spec\n");
        col_append_str(pinfo->cinfo, COL_INFO, "Change Cipher Spec");
        dissect_ssl3_change_cipher_spec(tvb, ssl_record_tree,
                                        offset, conv_version, content_type);
        if (ssl) ssl_change_cipher(ssl, ssl_packet_from_server(ssl, ssl_associations, pinfo));
        break;
    case SSL_ID_ALERT:
    {
        tvbuff_t* decrypted;

        if (ssl&&decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
          ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                  ssl_decrypted_data_avail, offset);

        /* try to retrieve and use decrypted alert record, if any. */
        decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, offset);
        if (decrypted) {
            add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_alert(decrypted, pinfo, ssl_record_tree, 0, conv_version);
        } else {
            dissect_ssl3_alert(tvb, pinfo, ssl_record_tree, offset, conv_version);
        }
        break;
    }
    case SSL_ID_HANDSHAKE:
    {
        tvbuff_t* decrypted;

        /* try to decrypt handshake record, if possible. Store decrypted
         * record for later usage. The offset is used as 'key' to identify
         * this record in the packet (we can have multiple handshake records
         * in the same frame) */
        if (ssl && decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
            ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                ssl_decrypted_data_avail, offset);

        /* try to retrieve and use decrypted handshake record, if any. */
        decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, offset);
        if (decrypted) {
            /* add desegmented data to the data source list */
            add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_handshake(decrypted, pinfo, ssl_record_tree, 0,
                 tvb_length(decrypted), conv_version, conv_cipher, ssl, content_type);
        } else {
            dissect_ssl3_handshake(tvb, pinfo, ssl_record_tree, offset,
                               record_length, conv_version, conv_cipher, ssl, content_type);
        }
        break;
    }
    case SSL_ID_APP_DATA:
        if (ssl){
            decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, TRUE);
            /* if application data desegmentation is allowed and needed */
            /* if (ssl_desegment_app_data && *need_desegmentation)
                   ssl_desegment_ssl_app_data(ssl,pinfo);
             */
        }

        /* show on info colum what we are decoding */
        col_append_str(pinfo->cinfo, COL_INFO, "Application Data");

        /* we need dissector information when the selected packet is shown.
         * ssl session pointer is NULL at that time, so we can't access
         * info cached there*/
        association = ssl_association_find(ssl_associations, pinfo->srcport, pinfo->ptype == PT_TCP);
        association = association ? association: ssl_association_find(ssl_associations, pinfo->destport, pinfo->ptype == PT_TCP);
        association = association ? association: ssl_association_find(ssl_associations, 0, pinfo->ptype == PT_TCP);

        proto_item_set_text(ssl_record_tree,
           "%s Record Layer: %s Protocol: %s",
            val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
            val_to_str_const(content_type, ssl_31_content_type, "unknown"),
            association?association->info:"Application Data");

        proto_tree_add_item(ssl_record_tree, hf_ssl_record_appdata, tvb,
                       offset, record_length, ENC_NA);

        dissect_ssl_payload(tvb, pinfo, offset, tree, association);

        break;
    case SSL_ID_HEARTBEAT:
    {
        tvbuff_t* decrypted;

        if (ssl && decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
            ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                                ssl_decrypted_data_avail, offset);

        /* try to retrieve and use decrypted handshake record, if any. */
        decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, offset);
        if (decrypted) {
            add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_heartbeat(decrypted, pinfo, ssl_record_tree, 0, conv_version, record_length);
        } else {
            dissect_ssl3_heartbeat(tvb, pinfo, ssl_record_tree, offset, conv_version, record_length);
        }
        break;
    }

    default:
        /* shouldn't get here since we check above for valid types */
        col_append_str(pinfo->cinfo, COL_INFO, "Bad SSLv3 Content Type");
        break;
    }
    offset += record_length; /* skip to end of record */

    return offset;
}

/* dissects the change cipher spec procotol, filling in the tree */
static void
dissect_ssl3_change_cipher_spec(tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint* conv_version, const guint8 content_type)
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
                            "%s Record Layer: %s Protocol: Change Cipher Spec",
                            val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                            val_to_str_const(content_type, ssl_31_content_type, "unknown"));
        proto_tree_add_item(tree, hf_ssl_change_cipher_spec, tvb,
                            offset++, 1, ENC_NA);
    }
}

/* dissects the alert message, filling in the tree */
static void
dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, guint32 offset,
                   guint* conv_version)
{
    /*     struct {
     *         AlertLevel level;
     *         AlertDescription description;
     *     } Alert;
     */
    proto_tree *ti;
    proto_tree *ssl_alert_tree;
    const gchar *level;
    const gchar *desc;
    guint8 byte;
    ssl_alert_tree = NULL;
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_ssl_alert_message, tvb,
                                 offset, 2, ENC_NA);
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
        col_append_fstr(pinfo->cinfo, COL_INFO,
                            "Alert (Level: %s, Description: %s)",
                            level, desc);
    }
    else
    {
        col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Alert");
    }

    if (tree)
    {
        if (level && desc)
        {
            proto_item_set_text(tree, "%s Record Layer: Alert "
                                "(Level: %s, Description: %s)",
                                val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                                level, desc);
            proto_tree_add_item(ssl_alert_tree, hf_ssl_alert_message_level,
                                tvb, offset++, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(ssl_alert_tree, hf_ssl_alert_message_description,
                                tvb, offset++, 1, ENC_BIG_ENDIAN);
        }
        else
        {
            proto_item_set_text(tree,
                                "%s Record Layer: Encrypted Alert",
                                val_to_str_const(*conv_version, ssl_version_short_names, "SSL"));
            proto_item_set_text(ssl_alert_tree,
                                "Alert Message: Encrypted Alert");
        }
    }
}


/* dissects the handshake protocol, filling the tree */
static void
dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 record_length, guint *conv_version, guint conv_cipher,
                       SslDecryptSession* ssl, const guint8 content_type)
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
    proto_tree *ti;
    proto_tree *ssl_hand_tree;
    const gchar *msg_type_str;
    guint8 msg_type;
    guint32 length;
    gboolean first_iteration;
    ti = NULL;
    ssl_hand_tree = NULL;
    msg_type_str = NULL;
    first_iteration = TRUE;

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
        length   = tvb_get_ntoh24(tvb, offset + 1);

        /* Check the length in the handshake message. Assume it's an
         * encrypted handshake message if the message would pass
         * the record_length boundary. This is a workaround for the
         * situation where the first octet of the encrypted handshake
         * message is actually a known handshake message type.
         */
        if (offset + length <= record_length)
            msg_type_str = match_strval(msg_type, ssl_31_handshake_type);
        else
            msg_type_str = NULL;

        ssl_debug_printf("dissect_ssl3_handshake iteration %d type %d offset %d length %d "
            "bytes, remaining %d \n", first_iteration, msg_type, offset, length, record_length);
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
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

        /*
         * Update our info string
         */
        col_append_str(pinfo->cinfo, COL_INFO, (msg_type_str != NULL)
                            ? msg_type_str : "Encrypted Handshake Message");

        if (tree)
        {
            /* set the label text on the record layer expanding node */
            if (first_iteration)
            {
                proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s",
                                    val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                                    val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                                    (msg_type_str!=NULL) ? msg_type_str :
                                        "Encrypted Handshake Message");
            }
            else
            {
                proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s",
                                    val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                                    val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                                    "Multiple Handshake Messages");
            }

            /* add a subtree for the handshake protocol */
            ti = proto_tree_add_item(tree, hf_ssl_handshake_protocol, tvb,
                                     offset, length + 4, ENC_NA);
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
            return;

        /* PAOLO: if we are doing ssl decryption we must dissect some requests type */
        if (ssl_hand_tree || ssl)
        {
            /* add nodes for the message type and message length */
            if (ssl_hand_tree)
                proto_tree_add_uint(ssl_hand_tree, hf_ssl_handshake_type,
                                    tvb, offset, 1, msg_type);
            offset += 1;
            if (ssl_hand_tree)
                proto_tree_add_uint(ssl_hand_tree, hf_ssl_handshake_length,
                                tvb, offset, 3, length);
            offset += 3;

            /* now dissect the handshake message, if necessary */
            switch (msg_type) {
            case SSL_HND_HELLO_REQUEST:
                /* hello_request has no fields, so nothing to do! */
                break;

            case SSL_HND_CLIENT_HELLO:
                dissect_ssl3_hnd_cli_hello(tvb, pinfo, ssl_hand_tree, offset, length, ssl);
                break;

            case SSL_HND_SERVER_HELLO:
                dissect_ssl3_hnd_srv_hello(tvb, ssl_hand_tree, offset, length, ssl);
                break;

            case SSL_HND_NEWSESSION_TICKET:
                dissect_ssl3_hnd_new_ses_ticket(tvb, ssl_hand_tree, offset, length);
                break;

            case SSL_HND_CERTIFICATE:
                dissect_ssl3_hnd_cert(tvb, ssl_hand_tree, offset, pinfo);
                break;

            case SSL_HND_SERVER_KEY_EXCHG: {
                switch(ssl_get_keyex_alg(conv_cipher)) {
                case KEX_DH:
                    dissect_ssl3_hnd_srv_keyex_dh(tvb, ssl_hand_tree, offset, length);
                    break;
                case KEX_RSA:
                    dissect_ssl3_hnd_srv_keyex_rsa(tvb, ssl_hand_tree, offset, length);
                    break;
                case KEX_ECDH:
                    dissect_ssl3_hnd_srv_keyex_ecdh(tvb, ssl_hand_tree, offset, length);
                    break;
                default:
                    break;
                }
            }
                break;

            case SSL_HND_CERT_REQUEST:
                dissect_ssl3_hnd_cert_req(tvb, ssl_hand_tree, offset, pinfo, conv_version);
                break;

            case SSL_HND_SVR_HELLO_DONE:
                /* server_hello_done has no fields, so nothing to do! */
                break;

            case SSL_HND_CERT_VERIFY:
                /* unimplemented */
                break;

            case SSL_HND_CLIENT_KEY_EXCHG:
                switch(ssl_get_keyex_alg(conv_cipher)) {
                case KEX_DH:
                        dissect_ssl3_hnd_cli_keyex_dh(tvb, ssl_hand_tree, offset, length);
                        break;
                case KEX_RSA:
                        dissect_ssl3_hnd_cli_keyex_rsa(tvb, ssl_hand_tree, offset, length);
                        break;
                case KEX_ECDH:
                        dissect_ssl3_hnd_cli_keyex_ecdh(tvb, ssl_hand_tree, offset, length);
                        break;
                default:
                        break;
                }
                {
                    /* PAOLO: here we can have all the data to build session key*/

                    gint cipher_num;

                    if (!ssl)
                        break;

                    cipher_num = ssl->cipher;

                    if (cipher_num == 0x8a || cipher_num == 0x8b || cipher_num == 0x8c || cipher_num == 0x8d)
                    {
                        /* calculate pre master secret*/
                        StringInfo pre_master_secret;
                        guint psk_len, pre_master_len;

                        int size;
                        unsigned char *out;
                        int i,j = 0;
                        char input[2];

                        if (!ssl_psk || (ssl_psk[0] == 0)) {
                            ssl_debug_printf("dissect_ssl3_handshake can't find pre-shared-key\n");
                            break;
                        }

                        size = (int)strlen(ssl_psk);

                        /* psk must be 0 to 16 bytes*/
                        if (size < 0 || size > 32 || size % 2 != 0)
                        {
                            break;
                        }

                        /* convert hex string into char*/
                        out = (unsigned char*) ep_alloc(size > 0 ? size / 2 : 0);

                        for (i = 0; i < size; i+=2)
                        {
                            input[0] = ssl_psk[0 + i];
                            input[1] = ssl_psk[1 + i];
                            out[j++] = (unsigned int) strtoul((const char*)&input, NULL, 16);
                        }

                        ssl->psk = (guchar*) out;

                        psk_len = size > 0 ? size / 2 : 0;
                        pre_master_len = psk_len * 2 + 4;

                        pre_master_secret.data = se_alloc(pre_master_len);
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
                        memcpy(&pre_master_secret.data[psk_len + 4], ssl->psk, psk_len);

                        ssl->pre_master_secret.data = pre_master_secret.data;
                        ssl->pre_master_secret.data_len = pre_master_len;
                        /*ssl_debug_printf("pre master secret",&ssl->pre_master_secret);*/

                        /* Remove the master secret if it was there.
                           This forces keying material regeneration in
                           case we're renegotiating */
                        ssl->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
                        ssl->state |= SSL_PRE_MASTER_SECRET;
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
                         * in case of rsa1024 that would be 128 + 2 = 130; for psk not neccessary
                         */
                        if (ssl->cipher_suite.kex==KEX_RSA && (ssl->version == SSL_VER_TLS||ssl->version == SSL_VER_TLSv1DOT1||ssl->version == SSL_VER_TLSv1DOT2))
                        {
                            encrlen  = tvb_get_ntohs(tvb, offset);
                            skip = 2;
                            if (encrlen > length - 2)
                            {
                                ssl_debug_printf("dissect_ssl3_handshake wrong encrypted length (%d max %d)\n",
                                    encrlen, length);
                                break;
                            }
                        }
                        encrypted_pre_master.data = se_alloc(encrlen);
                        encrypted_pre_master.data_len = encrlen;
                        tvb_memcpy(tvb, encrypted_pre_master.data, offset+skip, encrlen);

                        if (ssl->private_key) {
                            /* go with ssl key processessing; encrypted_pre_master
                             * will be used for master secret store*/
                            ret = ssl_decrypt_pre_master_secret(ssl, &encrypted_pre_master, ssl->private_key);
                            if (ret < 0) {
                                ssl_debug_printf("dissect_ssl3_handshake can't decrypt pre master secret\n");
                                break;
                            }
                        } else {
                            /* try to find the key in the key log */
                            if (ssl_keylog_lookup(ssl, ssl_keylog_filename, &encrypted_pre_master)<0)
                                break;
                        }
                    }
                    if (ssl_generate_keyring_material(ssl)<0) {
                        ssl_debug_printf("dissect_ssl3_handshake can't generate keyring material\n");
                        break;
                    }

                    ssl_save_session(ssl, ssl_session_hash);
                    ssl_debug_printf("dissect_ssl3_handshake session keys successfully generated\n");
                }
                break;

            case SSL_HND_FINISHED:
                dissect_ssl3_hnd_finished(tvb, ssl_hand_tree,
                                          offset, conv_version);
                break;

            case SSL_HND_CERT_STATUS:
                dissect_ssl3_hnd_cert_status(tvb, ssl_hand_tree, offset, pinfo);
                break;
            }

        }
        else
            offset += 4;        /* skip the handshake header when handshake is not processed*/

        offset += length;
        first_iteration = FALSE; /* set up for next pass, if any */
    }
}

/* dissects the heartbeat message, filling in the tree */
static void
dissect_ssl3_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint* conv_version, guint32 record_length)
{
    /*     struct {
     *         HeartbeatMessageType type;
     *         uint16 payload_length;
     *         opaque payload;
     *         opaque padding;
     *     } HeartbeatMessage;
     */

    proto_tree  *ti;
    proto_tree  *tls_heartbeat_tree;
    const gchar *type;
    guint8       byte;
    guint16      payload_length;
    guint16      padding_length;

    tls_heartbeat_tree = NULL;

    if (tree) {
        ti = proto_tree_add_item(tree, hf_ssl_heartbeat_message, tvb,
                                 offset, record_length - 32, ENC_NA);
        tls_heartbeat_tree = proto_item_add_subtree(ti, ett_ssl_heartbeat);
    }

    /*
     * set the record layer label
     */

    /* first lookup the names for the message type and the payload length */
    byte = tvb_get_guint8(tvb, offset);
    type = match_strval(byte, tls_heartbeat_type);

    payload_length = tvb_get_ntohs(tvb, offset + 1);
    padding_length = record_length - 3 - payload_length;

    /* now set the text in the record layer line */
    if (type && (payload_length <= record_length - 16 - 3)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat %s", type);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Heartbeat");
    }

    if (tree) {
        if (type && (payload_length <= record_length - 16 - 3)) {
            proto_item_set_text(tree, "%s Record Layer: Heartbeat "
                                "%s",
                                val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                                type);
            proto_tree_add_item(tls_heartbeat_tree, hf_ssl_heartbeat_message_type,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_uint(tls_heartbeat_tree, hf_ssl_heartbeat_message_payload_length,
                                tvb, offset, 2, payload_length);
            offset += 2;
            proto_tree_add_bytes_format(tls_heartbeat_tree, hf_ssl_heartbeat_message_payload,
                                        tvb, offset, payload_length,
                                        NULL, "Payload (%u byte%s)",
                                        payload_length,
                                        plurality(payload_length, "", "s"));
            offset += payload_length;
            proto_tree_add_bytes_format(tls_heartbeat_tree, hf_ssl_heartbeat_message_padding,
                                        tvb, offset, padding_length,
                                        NULL, "Padding and HMAC (%u byte%s)",
                                        padding_length,
                                        plurality(padding_length, "", "s"));
        } else {
            proto_item_set_text(tree,
                                "%s Record Layer: Encrypted Heartbeat",
                                val_to_str_const(*conv_version, ssl_version_short_names, "SSL"));
            proto_item_set_text(tls_heartbeat_tree,
                                "Encrypted Heartbeat Message");
        }
    }
}

static gint
dissect_ssl3_hnd_hello_common(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, SslDecryptSession* ssl, gint from_server)
{
    /* show the client's random challenge */
    nstime_t gmt_unix_time;
    guint8  session_id_length;
    proto_item *ti_rnd;
    proto_tree *ssl_rnd_tree;

    session_id_length = 0;

    if (ssl)
    {
        /* PAOLO: get proper peer information*/
        StringInfo* rnd;
        if (from_server)
            rnd = &ssl->server_random;
        else
            rnd = &ssl->client_random;

        /* get provided random for keyring generation*/
        tvb_memcpy(tvb, rnd->data, offset, 32);
        rnd->data_len = 32;
        if (from_server)
            ssl->state |= SSL_SERVER_RANDOM;
        else
            ssl->state |= SSL_CLIENT_RANDOM;
        ssl_debug_printf("dissect_ssl3_hnd_hello_common found %s RANDOM -> state 0x%02X\n",
            (from_server)?"SERVER":"CLIENT", ssl->state);

        session_id_length = tvb_get_guint8(tvb, offset + 32);
        /* check stored session id info */
        if (from_server && (session_id_length == ssl->session_id.data_len) &&
                 (tvb_memeql(tvb, offset+33, ssl->session_id.data, session_id_length) == 0))
        {
            /* client/server id match: try to restore a previous cached session*/
            if (!ssl_restore_session(ssl, ssl_session_hash)) {
                /* If we failed to find the previous session, we may still have
                 * the master secret in the key log. */
                if (ssl_keylog_lookup(ssl, ssl_keylog_filename, NULL)) {
                    ssl_debug_printf("  cannot find master secret in keylog file either\n");
                } else {
                    ssl_debug_printf("  found master secret in keylog file\n");
                }
            }
        } else {
            tvb_memcpy(tvb,ssl->session_id.data, offset+33, session_id_length);
            ssl->session_id.data_len = session_id_length;
        }
    }

    if (tree)
    {
        ti_rnd = proto_tree_add_text(tree, tvb, offset, 32, "Random");
        ssl_rnd_tree = proto_item_add_subtree(ti_rnd, ett_ssl_random);

        /* show the time */
        gmt_unix_time.secs = tvb_get_ntohl(tvb, offset);
        gmt_unix_time.nsecs = 0;
        proto_tree_add_time(ssl_rnd_tree, hf_ssl_handshake_random_time,
                                     tvb, offset, 4, &gmt_unix_time);
        offset += 4;

        /* show the random bytes */
        proto_tree_add_item(ssl_rnd_tree, hf_ssl_handshake_random_bytes,
                            tvb, offset, 28, ENC_NA);
        offset += 28;

        /* show the session id */
        session_id_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ssl_handshake_session_id_len,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
        if (session_id_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, session_id_length);
            proto_tree_add_item(tree, hf_ssl_handshake_session_id,
                                tvb, offset, session_id_length, ENC_NA);
        }

    }

    /* XXXX */
    return session_id_length+33;
}

static gint
dissect_ssl3_hnd_hello_ext(tvbuff_t *tvb,
                           proto_tree *tree, guint32 offset, guint32 left)
{
    guint16 extension_length;
    guint16 ext_type;
    guint16 ext_len;
    proto_item *pi;
    proto_tree *ext_tree;

    if (left < 2)
        return offset;

    extension_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl_handshake_extensions_len,
        tvb, offset, 2, extension_length);
    offset += 2;
    left -= 2;

    while (left >= 4)
    {
        ext_type = tvb_get_ntohs(tvb, offset);
        ext_len = tvb_get_ntohs(tvb, offset + 2);

        pi = proto_tree_add_text(tree, tvb, offset, 4 + ext_len,
            "Extension: %s",
            val_to_str(ext_type,
            tls_hello_extension_types,
            "Unknown %u"));
        ext_tree = proto_item_add_subtree(pi, ett_ssl_extension);
        if (!ext_tree)
            ext_tree = tree;

        proto_tree_add_uint(ext_tree, hf_ssl_handshake_extension_type,
            tvb, offset, 2, ext_type);
        offset += 2;

        proto_tree_add_uint(ext_tree, hf_ssl_handshake_extension_len,
            tvb, offset, 2, ext_len);
        offset += 2;

        switch (ext_type) {
        case SSL_HND_HELLO_EXT_ELLIPTIC_CURVES:
            offset = dissect_ssl3_hnd_hello_ext_elliptic_curves(tvb, ext_tree, offset);
            break;
        case SSL_HND_HELLO_EXT_EC_POINT_FORMATS:
            offset = dissect_ssl3_hnd_hello_ext_ec_point_formats(tvb, ext_tree, offset);
            break;
        case SSL_HND_HELLO_EXT_NPN:
            offset = dissect_ssl3_hnd_hello_ext_npn(tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_RENEG_INFO:
            offset = dissect_ssl3_hnd_hello_ext_reneg_info(tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_SERVER_NAME:
            offset = dissect_ssl3_hnd_hello_ext_server_name(tvb, ext_tree, offset, ext_len);
            break;
        case SSL_HND_HELLO_EXT_HEARTBEAT:
            proto_tree_add_item(ext_tree, hf_ssl_heartbeat_extension_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += ext_len;
            break;
        default:
            proto_tree_add_bytes_format(ext_tree, hf_ssl_handshake_extension_data,
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

static gint
dissect_ssl3_hnd_hello_ext_npn(tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint8 npn_length;
    proto_tree *npn_tree, *ti;

    if (ext_len == 0) {
        return offset;
    }

    ti = proto_tree_add_text(tree, tvb, offset, ext_len, "Next Protocol Negotiation");
    npn_tree = proto_item_add_subtree(ti, ett_ssl_extension_npn);

    while (ext_len > 0) {
        npn_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(npn_tree, hf_ssl_handshake_extension_npn_str_len,
                            tvb, offset, 1, ENC_NA);
        offset++;
        ext_len--;

        if (npn_length > 0) {
            tvb_ensure_bytes_exist(tvb, offset, npn_length);
            proto_tree_add_item(npn_tree, hf_ssl_handshake_extension_npn_str,
                                tvb, offset, npn_length, ENC_ASCII|ENC_NA);
            offset += npn_length;
            ext_len -= npn_length;
        }
    }

    return offset;
}

static gint
dissect_ssl3_hnd_hello_ext_reneg_info(tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint8 reneg_info_length;
    proto_tree *reneg_info_tree, *ti;

    if (ext_len == 0) {
        return offset;
    }

    ti = proto_tree_add_text(tree, tvb, offset, ext_len, "Renegotiation Info extension");
    reneg_info_tree = proto_item_add_subtree(ti, ett_ssl_extension_reneg_info);

    reneg_info_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(reneg_info_tree, hf_ssl_handshake_extension_reneg_info_len,
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
dissect_ssl3_hnd_hello_ext_server_name(tvbuff_t *tvb,
                               proto_tree *tree, guint32 offset, guint32 ext_len)
{
    guint16 server_name_length;
    proto_tree *server_name_tree, *ti;


   if (ext_len == 0) {
       return offset;
   }

   ti = proto_tree_add_text(tree, tvb, offset, ext_len, "Server Name Indication extension");
   server_name_tree = proto_item_add_subtree(ti, ett_ssl_extension_server_name);

   proto_tree_add_item(server_name_tree, hf_ssl_handshake_extension_server_name_list_len,
                       tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   ext_len -= 2;

   while (ext_len > 0) {
       proto_tree_add_item(server_name_tree, hf_ssl_handshake_extension_server_name_type,
                           tvb, offset, 1, ENC_NA);
       offset += 1;
       ext_len -= 1;

       server_name_length = tvb_get_ntohs(tvb, offset);
       proto_tree_add_item(server_name_tree, hf_ssl_handshake_extension_server_name_len,
                           tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       ext_len -= 2;

       if (server_name_length > 0) {
           tvb_ensure_bytes_exist(tvb, offset, server_name_length);
           proto_tree_add_item(server_name_tree, hf_ssl_handshake_extension_server_name,
                               tvb, offset, server_name_length, ENC_ASCII|ENC_NA);
           offset += server_name_length;
           ext_len -= server_name_length;
       }
   }
   return offset;
}

static gint
dissect_ssl3_hnd_hello_ext_elliptic_curves(tvbuff_t *tvb,
                                           proto_tree *tree, guint32 offset)
{
    guint16 curves_length;
    proto_tree *curves_tree;
    proto_tree *ti;

    curves_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_handshake_extension_elliptic_curves_len,
        tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 2;
    tvb_ensure_bytes_exist(tvb, offset, curves_length);
    ti = proto_tree_add_none_format(tree,
                                    hf_ssl_handshake_extension_elliptic_curves,
                                    tvb, offset, curves_length,
                                    "Elliptic curves (%d curve%s)",
                                    curves_length / 2,
                                    plurality(curves_length/2, "", "s"));

    /* make this a subtree */
    curves_tree = proto_item_add_subtree(ti, ett_ssl_extension_curves);

    /* loop over all curves */
    while (curves_length > 0)
    {
        proto_tree_add_item(curves_tree, hf_ssl_handshake_extension_elliptic_curve, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        curves_length -= 2;
    }

    return offset;
}

static gint
dissect_ssl3_hnd_hello_ext_ec_point_formats(tvbuff_t *tvb,
                                            proto_tree *tree, guint32 offset)
{
    guint8 ecpf_length;
    proto_tree *ecpf_tree;
    proto_tree *ti;

    ecpf_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_handshake_extension_ec_point_formats_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    tvb_ensure_bytes_exist(tvb, offset, ecpf_length);
    ti = proto_tree_add_none_format(tree,
                                    hf_ssl_handshake_extension_elliptic_curves,
                                    tvb, offset, ecpf_length,
                                    "Elliptic curves point formats (%d)",
                                    ecpf_length);

    /* make this a subtree */
    ecpf_tree = proto_item_add_subtree(ti, ett_ssl_extension_curves_point_formats);

    /* loop over all point formats */
    while (ecpf_length > 0)
    {
        proto_tree_add_item(ecpf_tree, hf_ssl_handshake_extension_ec_point_format, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        ecpf_length--;
    }

    return offset;
}

static void
dissect_ssl3_hnd_cli_hello(tvbuff_t *tvb, packet_info *pinfo,
       proto_tree *tree, guint32 offset, guint32 length,
       SslDecryptSession*ssl)
{
    /* struct {
     *     ProtocolVersion client_version;
     *     Random random;
     *     SessionID session_id;
     *     CipherSuite cipher_suites<2..2^16-1>;
     *     CompressionMethod compression_methods<1..2^8-1>;
     *     Extension client_hello_extension_list<0..2^16-1>;
     * } ClientHello;
     *
     */
    proto_tree *ti;
    proto_tree *cs_tree;
    gint cipher_suite_length;
    guint8  compression_methods_length;
    guint8  compression_method;
    guint16 start_offset;

    start_offset = offset;

    if (ssl) {
        ssl_set_server(ssl, &pinfo->dst, pinfo->ptype, pinfo->destport);
        ssl_find_private_key(ssl, ssl_key_hash, ssl_associations, pinfo);
    }

    if (tree || ssl)
    {
        /* show the client version */
        if (tree)
            proto_tree_add_item(tree, hf_ssl_handshake_client_version, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* show the fields in common with server hello */
        offset += dissect_ssl3_hnd_hello_common(tvb, tree, offset, ssl, 0);

        /* tell the user how many cipher suites there are */
        cipher_suite_length = tvb_get_ntohs(tvb, offset);
        if (!tree)
            return;
        proto_tree_add_uint(tree, hf_ssl_handshake_cipher_suites_len,
                        tvb, offset, 2, cipher_suite_length);
        offset += 2;            /* skip opaque length */

        if (cipher_suite_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, cipher_suite_length);
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_cipher_suites,
                                            tvb, offset, cipher_suite_length,
                                            "Cipher Suites (%d suite%s)",
                                            cipher_suite_length / 2,
                                            plurality(cipher_suite_length/2, "", "s"));
            if (cipher_suite_length % 2) {
                proto_tree_add_text(tree, tvb, offset, 2,
                    "Invalid cipher suite length: %d", cipher_suite_length);
                expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR,
                    "Cipher suite length (%d) must be a multiple of 2",
                    cipher_suite_length);
                return;
            }

            /* make this a subtree */
            cs_tree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
            if (!cs_tree)
            {
                cs_tree = tree; /* failsafe */
            }

            while (cipher_suite_length > 0)
            {
                proto_tree_add_item(cs_tree, hf_ssl_handshake_cipher_suite,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                cipher_suite_length -= 2;
            }
        }

        /* tell the user how many compression methods there are */
        compression_methods_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_comp_methods_len,
                            tvb, offset, 1, compression_methods_length);
        offset += 1;

        if (compression_methods_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, compression_methods_length);
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
                compression_method = tvb_get_guint8(tvb, offset);
                if (compression_method < 64)
                    proto_tree_add_uint(cs_tree, hf_ssl_handshake_comp_method,
                                        tvb, offset, 1, compression_method);
                else if (compression_method > 63 && compression_method < 193)
                    proto_tree_add_text(cs_tree, tvb, offset, 1,
                                        "Compression Method: Reserved - to be assigned by IANA (%u)",
                                        compression_method);
                else
                    proto_tree_add_text(cs_tree, tvb, offset, 1,
                                        "Compression Method: Private use range (%u)",
                                        compression_method);
                offset++;
                compression_methods_length--;
            }
        }

        if (length > offset - start_offset)
        {
            dissect_ssl3_hnd_hello_ext(tvb, tree, offset,
                                       length - (offset - start_offset));
        }
    }
}

static void
dissect_ssl3_hnd_srv_hello(tvbuff_t *tvb,
                           proto_tree *tree, guint32 offset, guint32 length, SslDecryptSession* ssl)
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
    guint16 start_offset;
    start_offset = offset;

    if (tree || ssl)
    {
        /* show the server version */
        if (tree)
            proto_tree_add_item(tree, hf_ssl_handshake_server_version, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* first display the elements conveniently in
         * common with client hello
         */
        offset += dissect_ssl3_hnd_hello_common(tvb, tree, offset, ssl, 1);

        /* PAOLO: handle session cipher suite  */
        if (ssl) {
            /* store selected cipher suite for decryption */
            ssl->cipher = tvb_get_ntohs(tvb, offset);
            if (ssl_find_cipher(ssl->cipher,&ssl->cipher_suite) < 0) {
                ssl_debug_printf("dissect_ssl3_hnd_srv_hello can't find cipher suite 0x%X\n", ssl->cipher);
                goto no_cipher;
            }

            ssl->state |= SSL_CIPHER;
            ssl_debug_printf("dissect_ssl3_hnd_srv_hello found CIPHER 0x%04X -> state 0x%02X\n",
                ssl->cipher, ssl->state);

            /* if we have restored a session now we can have enough material
             * to build session key, check it out*/
            ssl_debug_printf("dissect_ssl3_hnd_srv_hello trying to generate keys\n");
            if (ssl_generate_keyring_material(ssl)<0) {
                ssl_debug_printf("dissect_ssl3_hnd_srv_hello can't generate keyring material\n");
                goto no_cipher;
            }
        }
no_cipher:

        /* now the server-selected cipher suite */
        proto_tree_add_item(tree, hf_ssl_handshake_cipher_suite,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (ssl) {
            /* store selected compression method for decryption */
            ssl->compression = tvb_get_guint8(tvb, offset);
        }
        /* and the server-selected compression method */
        proto_tree_add_item(tree, hf_ssl_handshake_comp_method,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (length > offset - start_offset)
        {
            dissect_ssl3_hnd_hello_ext(tvb, tree, offset,
                                       length - (offset - start_offset));
        }
    }
}

static void
dissect_ssl3_hnd_new_ses_ticket(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    guint nst_len;
    proto_item *ti;
    proto_tree *subtree;


    nst_len = tvb_get_ntohs(tvb, offset+4);
    if (6 + nst_len != length) {
        return;
    }

    ti = proto_tree_add_text(tree, tvb, offset, 6+nst_len, "TLS Session Ticket");
    subtree = proto_item_add_subtree(ti, ett_ssl_new_ses_ticket);

    proto_tree_add_item(subtree, hf_ssl_handshake_session_ticket_lifetime_hint,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_uint(subtree, hf_ssl_handshake_session_ticket_len,
        tvb, offset, 2, nst_len);
    /* Content depends on implementation, so just show data! */
    proto_tree_add_item(subtree, hf_ssl_handshake_session_ticket,
            tvb, offset + 2, nst_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cert(tvbuff_t *tvb,
                      proto_tree *tree, guint32 offset, packet_info *pinfo)
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
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    if (tree)
    {
        certificate_list_length = tvb_get_ntoh24(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_certificates_len,
                            tvb, offset, 3, certificate_list_length);
        offset += 3;            /* 24-bit length value */

        if (certificate_list_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, certificate_list_length);
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_certificates,
                                            tvb, offset, certificate_list_length,
                                            "Certificates (%u byte%s)",
                                            certificate_list_length,
                                            plurality(certificate_list_length, "", "s"));

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
                guint32 cert_length;
                cert_length = tvb_get_ntoh24(tvb, offset);
                certificate_list_length -= 3 + cert_length;

                proto_tree_add_item(subtree, hf_ssl_handshake_certificate_len,
                                    tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;

                (void)dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, subtree, hf_ssl_handshake_certificate);
                offset += cert_length;
            }
        }

    }
}

static void
dissect_ssl3_hnd_cert_req(tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset, packet_info *pinfo,
                          const guint* conv_version)
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
     */
    proto_tree *ti;
    proto_tree *subtree;
    proto_tree *saved_subtree;
    guint8      cert_types_count;
    gint        sh_alg_length;
    guint16     sig_hash_alg;
    gint        dnames_length;
    asn1_ctx_t  asn1_ctx;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    if (tree)
    {
        cert_types_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_cert_types_count,
                            tvb, offset, 1, cert_types_count);
        offset += 1;

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
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                cert_types_count--;
            }
        }

        switch(*conv_version) {
        case SSL_VER_TLSv1DOT2:
            sh_alg_length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(tree, hf_ssl_handshake_sig_hash_alg_len,
                                tvb, offset, 2, sh_alg_length);
            offset += 2;

            if (sh_alg_length > 0)
            {
                ti = proto_tree_add_none_format(tree,
                                                hf_ssl_handshake_sig_hash_algs,
                                                tvb, offset, sh_alg_length,
                                                "Signature Hash Algorithms (%u algorithm%s)",
                                                sh_alg_length/2,
                                                plurality(sh_alg_length/2, "", "s"));
                subtree = proto_item_add_subtree(ti, ett_ssl_sig_hash_algs);
                if (!subtree)
                {
                    subtree = tree;
                }

                if (sh_alg_length % 2) {
                    proto_tree_add_text(tree, tvb, offset, 2,
                        "Invalid Signature Hash Algorithm length: %d", sh_alg_length);
                    expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR,
                        "Signature Hash Algorithm length (%d) must be a multiple of 2",
                        sh_alg_length);
                    return;
                }


                while (sh_alg_length > 0)
                {
                    saved_subtree = subtree;

                    sig_hash_alg = tvb_get_ntohs(tvb, offset);
                    ti = proto_tree_add_uint(subtree, hf_ssl_handshake_sig_hash_alg,
                                        tvb, offset, 2, sig_hash_alg);
                    subtree = proto_item_add_subtree(ti, ett_ssl_sig_hash_alg);
                    if (!subtree)
                    {
                        subtree = saved_subtree;
                    }

                    proto_tree_add_item(subtree, hf_ssl_handshake_sig_hash_hash,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree, hf_ssl_handshake_sig_hash_sig,
                                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

                    subtree = saved_subtree;

                    offset += 2;
                    sh_alg_length -= 2;
                }
            }
            break;

        default:
            break;
        }

        dnames_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_dnames_len,
                            tvb, offset, 2, dnames_length);
        offset += 2;

        if (dnames_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, dnames_length);
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
                guint16 name_length;
                name_length = tvb_get_ntohs(tvb, offset);
                dnames_length -= 2 + name_length;

                proto_tree_add_item(subtree, hf_ssl_handshake_dname_len,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                tvb_ensure_bytes_exist(tvb, offset, name_length);

                (void)dissect_x509if_DistinguishedName(FALSE, tvb, offset, &asn1_ctx, subtree, hf_ssl_handshake_dname);

                offset += name_length;
            }
        }
    }

}

static void
dissect_ssl3_hnd_srv_keyex_ecdh(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    gint curve_type, curve_type_offset;
    gint named_curve, named_curve_offset;
    gint point_len, point_len_offset;
    gint sig_len, sig_len_offset;
    proto_item *ti_ecdh;
    proto_tree *ssl_ecdh_tree;
    guint32 orig_offset;

    orig_offset = offset;

    curve_type_offset = offset;
    curve_type = tvb_get_guint8(tvb, offset);
    if (curve_type != 3)
        return; /* only named_curves are supported */
    offset += 1;
    if ((offset - orig_offset) > length) {
        return;
    }

    named_curve_offset = offset;
    named_curve = tvb_get_ntohs(tvb, offset);
    offset += 2;
    if ((offset - orig_offset) > length) {
        return;
    }

    point_len_offset = offset;
    point_len = tvb_get_guint8(tvb, offset);
    if ((offset + point_len - orig_offset) > length) {
        return;
    }
    offset += 1 + point_len;

    sig_len_offset = offset;
    sig_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + sig_len;
    if ((offset - orig_offset) != length) {
        /* Lengths don't line up (wasn't what we expected?) */
        return;
    }

    ti_ecdh = proto_tree_add_text(tree, tvb, orig_offset,
                (offset - orig_offset), "EC Diffie-Hellman Server Params");
    ssl_ecdh_tree = proto_item_add_subtree(ti_ecdh, ett_ssl_keyex_params);

    /* curve_type */
    proto_tree_add_uint(ssl_ecdh_tree, hf_ssl_handshake_server_keyex_curve_type,
        tvb, curve_type_offset, 1, curve_type);

    /* named_curve */
    proto_tree_add_uint(ssl_ecdh_tree, hf_ssl_handshake_server_keyex_named_curve,
        tvb, named_curve_offset, 2, named_curve);

    /* point */
    proto_tree_add_uint(ssl_ecdh_tree, hf_ssl_handshake_server_keyex_point_len,
        tvb, point_len_offset, 1, point_len);
    proto_tree_add_item(ssl_ecdh_tree, hf_ssl_handshake_server_keyex_point,
            tvb, point_len_offset+1, point_len, ENC_NA);

    /* Sig */
    proto_tree_add_uint(ssl_ecdh_tree, hf_ssl_handshake_server_keyex_sig_len,
        tvb, sig_len_offset, 2, sig_len);
    proto_tree_add_item(ssl_ecdh_tree, hf_ssl_handshake_server_keyex_sig,
            tvb, sig_len_offset + 2, sig_len, ENC_NA);

}

static void
dissect_ssl3_hnd_cli_keyex_ecdh(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    gint point_len, point_len_offset;
    proto_item *ti_ecdh;
    proto_tree *ssl_ecdh_tree;
    guint32 orig_offset;

    orig_offset = offset;

    point_len_offset = offset;
    point_len = tvb_get_guint8(tvb, offset);
    if ((offset + point_len - orig_offset) > length) {
        return;
    }
    offset += 1 + point_len;

    ti_ecdh = proto_tree_add_text(tree, tvb, orig_offset,
                (offset - orig_offset), "EC Diffie-Hellman Client Params");
    ssl_ecdh_tree = proto_item_add_subtree(ti_ecdh, ett_ssl_keyex_params);

    /* point */
    proto_tree_add_uint(ssl_ecdh_tree, hf_ssl_handshake_client_keyex_point_len,
        tvb, point_len_offset, 1, point_len);
    proto_tree_add_item(ssl_ecdh_tree, hf_ssl_handshake_client_keyex_point,
            tvb, point_len_offset+1, point_len, ENC_NA);

}

static void
dissect_ssl3_hnd_srv_keyex_dh(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    gint p_len, p_len_offset;
    gint g_len, g_len_offset;
    gint ys_len, ys_len_offset;
    gint sig_len, sig_len_offset;
    proto_item *ti_dh;
    proto_tree *ssl_dh_tree;
    guint32 orig_offset;

    orig_offset = offset;

    p_len_offset = offset;
    p_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + p_len;
    if ((offset - orig_offset) > length) {
        return;
    }

    g_len_offset = offset;
    g_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + g_len;
    if ((offset - orig_offset) > length) {
        return;
    }

    ys_len_offset = offset;
    ys_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + ys_len;
    if ((offset - orig_offset) > length) {
        return;
    }

    sig_len_offset = offset;
    sig_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + sig_len;
    if ((offset - orig_offset) != length) {
        /* Lengths don't line up (wasn't what we expected?) */
        return;
    }

    ti_dh = proto_tree_add_text(tree, tvb, orig_offset,
                (offset - orig_offset), "Diffie-Hellman Server Params");
    ssl_dh_tree = proto_item_add_subtree(ti_dh, ett_ssl_keyex_params);

    /* p */
    proto_tree_add_uint(ssl_dh_tree, hf_ssl_handshake_server_keyex_p_len,
        tvb, p_len_offset, 2, p_len);
    proto_tree_add_item(ssl_dh_tree, hf_ssl_handshake_server_keyex_p,
            tvb, p_len_offset + 2, p_len, ENC_NA);

    /* g */
    proto_tree_add_uint(ssl_dh_tree, hf_ssl_handshake_server_keyex_g_len,
        tvb, g_len_offset, 2, g_len);
    proto_tree_add_item(ssl_dh_tree, hf_ssl_handshake_server_keyex_g,
            tvb, g_len_offset + 2, g_len, ENC_NA);

    /* Ys */
    proto_tree_add_uint(ssl_dh_tree, hf_ssl_handshake_server_keyex_ys_len,
        tvb, ys_len_offset, 2, ys_len);
    proto_tree_add_item(ssl_dh_tree, hf_ssl_handshake_server_keyex_ys,
            tvb, ys_len_offset + 2, ys_len, ENC_NA);

    /* Sig */
    proto_tree_add_uint(ssl_dh_tree, hf_ssl_handshake_server_keyex_sig_len,
        tvb, sig_len_offset, 2, sig_len);
    proto_tree_add_item(ssl_dh_tree, hf_ssl_handshake_server_keyex_sig,
            tvb, sig_len_offset + 2, sig_len, ENC_NA);

}

/* Only used in RSA-EXPORT cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_rsa(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    gint modulus_len, modulus_len_offset;
    gint exponent_len, exponent_len_offset;
    gint sig_len, sig_len_offset;
    proto_item *ti_rsa;
    proto_tree *ssl_rsa_tree;
    guint32 orig_offset;

    orig_offset = offset;

    modulus_len_offset = offset;
    modulus_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + modulus_len;
    if ((offset - orig_offset) > length) {
        return;
    }

    exponent_len_offset = offset;
    exponent_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + exponent_len;
    if ((offset - orig_offset) > length) {
        return;
    }

    sig_len_offset = offset;
    sig_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + sig_len;
    if ((offset - orig_offset) != length) {
        /* Lengths don't line up (wasn't what we expected?) */
        return;
    }

    ti_rsa = proto_tree_add_text(tree, tvb, orig_offset,
                (offset - orig_offset), "RSA-EXPORT Server Params");
    ssl_rsa_tree = proto_item_add_subtree(ti_rsa, ett_ssl_keyex_params);

    /* modulus */
    proto_tree_add_uint(ssl_rsa_tree, hf_ssl_handshake_server_keyex_modulus_len,
        tvb, modulus_len_offset, 2, modulus_len);
    proto_tree_add_item(ssl_rsa_tree, hf_ssl_handshake_server_keyex_modulus,
            tvb, modulus_len_offset + 2, modulus_len, ENC_NA);

    /* exponent */
    proto_tree_add_uint(ssl_rsa_tree, hf_ssl_handshake_server_keyex_exponent_len,
        tvb, exponent_len_offset, 2, exponent_len);
    proto_tree_add_item(ssl_rsa_tree, hf_ssl_handshake_server_keyex_exponent,
            tvb, exponent_len_offset + 2, exponent_len, ENC_NA);

    /* Sig */
    proto_tree_add_uint(ssl_rsa_tree, hf_ssl_handshake_server_keyex_sig_len,
        tvb, sig_len_offset, 2, sig_len);
    proto_tree_add_item(ssl_rsa_tree, hf_ssl_handshake_server_keyex_sig,
            tvb, sig_len_offset + 2, sig_len, ENC_NA);

}


static void
dissect_ssl3_hnd_cli_keyex_dh(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    gint yc_len, yc_len_offset;
    proto_item *ti_dh;
    proto_tree *ssl_dh_tree;
    guint32 orig_offset;

    orig_offset = offset;

    yc_len_offset = offset;
    yc_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + yc_len;
    if ((offset - orig_offset) != length) {
        return;
    }

    ti_dh = proto_tree_add_text(tree, tvb, orig_offset,
                (offset - orig_offset), "Diffie-Hellman Client Params");
    ssl_dh_tree = proto_item_add_subtree(ti_dh, ett_ssl_keyex_params);

    /* encrypted PreMaster secret */
    proto_tree_add_uint(ssl_dh_tree, hf_ssl_handshake_client_keyex_yc_len,
        tvb, yc_len_offset, 2, yc_len);
    proto_tree_add_item(ssl_dh_tree, hf_ssl_handshake_client_keyex_yc,
            tvb, yc_len_offset + 2, yc_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cli_keyex_rsa(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, guint32 length)
{
    gint epms_len, epms_len_offset;
    proto_item *ti_rsa;
    proto_tree *ssl_rsa_tree;
    guint32 orig_offset;

    orig_offset = offset;

    epms_len_offset = offset;
    epms_len = tvb_get_ntohs(tvb, offset);
    offset += 2 + epms_len;
    if ((offset - orig_offset) != length) {
        return;
    }

    ti_rsa = proto_tree_add_text(tree, tvb, orig_offset,
                (offset - orig_offset), "RSA Encrypted PreMaster Secret");
    ssl_rsa_tree = proto_item_add_subtree(ti_rsa, ett_ssl_keyex_params);

    /* Yc */
    proto_tree_add_uint(ssl_rsa_tree, hf_ssl_handshake_client_keyex_epms_len,
        tvb, epms_len_offset, 2, epms_len);
    proto_tree_add_item(ssl_rsa_tree, hf_ssl_handshake_client_keyex_epms,
            tvb, epms_len_offset + 2, epms_len, ENC_NA);
}




static void
dissect_ssl3_hnd_finished(tvbuff_t *tvb,
                          proto_tree *tree, const guint32 offset,
                          const guint* conv_version)
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
    case SSL_VER_TLSv1DOT1:
    case SSL_VER_TLSv1DOT2:
        proto_tree_add_item(tree, hf_ssl_handshake_finished,
                            tvb, offset, 12, ENC_NA);
        break;

    case SSL_VER_SSLv3:
        proto_tree_add_item(tree, hf_ssl_handshake_md5_hash,
                            tvb, offset, 16, ENC_NA);
        proto_tree_add_item(tree, hf_ssl_handshake_sha_hash,
                            tvb, offset + 16, 20, ENC_NA);
        break;
    }
}

static void
dissect_ssl3_hnd_cert_status(tvbuff_t *tvb, proto_tree *tree,
                             guint32 offset, packet_info *pinfo)
{
    guint8 cert_status_type;
    guint cert_status_len;
    proto_tree *ti;
    proto_tree *cert_status_tree;

    if (tree)
    {
        cert_status_type = tvb_get_guint8(tvb, offset);
        cert_status_len  = tvb_get_ntoh24(tvb, offset+1);
        tvb_ensure_bytes_exist(tvb, offset, cert_status_len+4);
        ti = proto_tree_add_none_format(tree, hf_ssl_handshake_cert_status,
                                        tvb, offset, cert_status_len+4,
                                        "Certificate Status (%u byte%s)",
                                        cert_status_len+4,
                                        plurality(cert_status_len+4, "", "s"));
        cert_status_tree = proto_item_add_subtree(ti, ett_ssl_cert_status);
        proto_tree_add_item(cert_status_tree, hf_ssl_handshake_cert_status_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_uint(cert_status_tree, hf_ssl_handshake_cert_status_len,
                            tvb, offset, 3, cert_status_len);
        offset += 3;
        if (cert_status_len > 0)
        {
            switch (cert_status_type) {
            case SSL_HND_CERT_STATUS_TYPE_OCSP:
                {
                    proto_item *ocsp_resp;
                    proto_tree *ocsp_resp_tree;
                    asn1_ctx_t asn1_ctx;

                    ocsp_resp = proto_tree_add_item(cert_status_tree,
                                                    proto_ocsp, tvb, offset,
                                                    cert_status_len, ENC_BIG_ENDIAN);
                    proto_item_set_text(ocsp_resp, "OCSP Response");
                    ocsp_resp_tree = proto_item_add_subtree(ocsp_resp,
                                                            ett_ssl_ocsp_resp);
                    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
                    dissect_ocsp_OCSPResponse(FALSE, tvb, offset, &asn1_ctx,
                                              ocsp_resp_tree, -1);
                    break;
                }
            default:
                break;
            }
        }
    }
}

/*********************************************************************
 *
 * SSL version 2 Dissectors
 *
 *********************************************************************/


/* record layer dissector */
static gint
dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint32 offset, guint* conv_version,
                    gboolean *need_desegmentation,
                    SslDecryptSession* ssl, gboolean first_record_in_frame)
{
    guint32 initial_offset;
    guint8  byte;
    guint8  record_length_length;
    guint32 record_length;
    gint    is_escape;
    gint16  padding_length;
    guint8  msg_type;
    const gchar *msg_type_str;
    guint32 available_bytes;
    proto_tree *ti;
    proto_tree *ssl_record_tree;

    initial_offset  = offset;
    record_length   = 0;
    is_escape       = -1;
    padding_length  = -1;
    msg_type_str    = NULL;
    ssl_record_tree = NULL;

    /* pull first byte; if high bit is unset, then record
     * length is three bytes due to padding; otherwise
     * record length is two bytes
     */
    byte = tvb_get_guint8(tvb, offset);
    record_length_length = (byte & 0x80) ? 2 : 3;

    available_bytes = tvb_length_remaining(tvb, offset);

    /*
     * Is the record header split across segment boundaries?
     */
    if (available_bytes < record_length_length) {
        /*
         * Yes - can we do reassembly?
         */
        if (ssl_desegment && pinfo->can_desegment) {
            /*
             * Yes.  Tell the TCP dissector where the data for this
             * message starts in the data it handed us, and that we need
             * "some more data."  Don't tell it exactly how many bytes we
             * need because if/when we ask for even more (after the header)
             * that will break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        } else {
            /* Not enough bytes available. Stop here. */
            return offset + available_bytes;
        }
    }

    /* parse out the record length */
    switch(record_length_length) {
    case 2:                     /* two-byte record length */
        record_length = (byte & 0x7f) << 8;
        byte = tvb_get_guint8(tvb, offset + 1);
        record_length += byte;
        break;
    case 3:                     /* three-byte record length */
        is_escape = (byte & 0x40) ? TRUE : FALSE;
        record_length = (byte & 0x3f) << 8;
        byte = tvb_get_guint8(tvb, offset + 1);
        record_length += byte;
        byte = tvb_get_guint8(tvb, offset + 2);
        padding_length = byte;
    }

    /*
     * Is the record split across segment boundaries?
     */
    if (available_bytes < (record_length_length + record_length)) {
        /*
         * Yes - Can we do reassembly?
         */
        if (ssl_desegment && pinfo->can_desegment) {
            /*
             * Yes.  Tell the TCP dissector where the data for this
             * message starts in the data it handed us, and how many
             * more bytes we need, and return.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = (record_length_length + record_length)
                                   - available_bytes;
            *need_desegmentation = TRUE;
            return offset;
        } else {
            /* Not enough bytes available. Stop here. */
            return offset + available_bytes;
        }
    }
    offset += record_length_length;

    /* on second and subsequent records per frame
     * add a delimiter on info column
     */
    if (!first_record_in_frame) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }

    /* add the record layer subtree header */
    ti = proto_tree_add_item(tree, hf_ssl2_record, tvb, initial_offset,
                             record_length_length + record_length, ENC_NA);
    ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);

    /* pull the msg_type so we can bail if it's unknown */
    msg_type = tvb_get_guint8(tvb, initial_offset + record_length_length);

    /* if we get a server_hello or later handshake in v2, then set
     * this to sslv2
     */
    if (*conv_version == SSL_VER_UNKNOWN)
    {
        if (ssl_looks_like_valid_pct_handshake(tvb,
                                               (initial_offset +
                                                record_length_length),
                                               record_length)) {
            *conv_version = SSL_VER_PCT;
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (msg_type >= 2 && msg_type <= 8)
        {
            *conv_version = SSL_VER_SSLv2;
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
    }

    /* if we get here, but don't have a version set for the
     * conversation, then set a version for just this frame
     * (e.g., on a client hello)
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                    (*conv_version == SSL_VER_PCT) ? "PCT" : "SSLv2");

    /* see if the msg_type is valid; if not the payload is
     * probably encrypted, so note that fact and bail
     */
    msg_type_str = match_strval(msg_type,
                                (*conv_version == SSL_VER_PCT)
                                ? pct_msg_types : ssl_20_msg_types);
    if (!msg_type_str
        || ((*conv_version != SSL_VER_PCT) &&
            !ssl_looks_like_valid_v2_handshake(tvb, initial_offset
                               + record_length_length,
                               record_length))
        || ((*conv_version == SSL_VER_PCT) &&
            !ssl_looks_like_valid_pct_handshake(tvb, initial_offset
                               + record_length_length,
                               record_length)))
    {
        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                (*conv_version == SSL_VER_PCT)
                                ? "PCT" : "SSLv2",
                                "Encrypted Data");

            /* Unlike SSLv3, the SSLv2 record layer does not have a
             * version field. To make it possible to filter on record
             * layer version we create a generated field with ssl
             * record layer version 0x0002
             */
            ti = proto_tree_add_uint(ssl_record_tree,
                    hf_ssl_record_version, tvb,
                    initial_offset, 0, 0x0002);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Data");
        return initial_offset + record_length_length + record_length;
    }
    else
    {
        col_append_str(pinfo->cinfo, COL_INFO, msg_type_str);

        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                (*conv_version == SSL_VER_PCT)
                                ? "PCT" : "SSLv2",
                                msg_type_str);
        }
    }

    /* We have a valid message type, so move foward, filling in the
     * tree by adding the length, is_escape boolean and padding_length,
     * if present in the original packet
     */
    if (ssl_record_tree)
    {
        /* Unlike SSLv3, the SSLv2 record layer does not have a
         * version field. To make it possible to filter on record
         * layer version we create a generated field with ssl
         * record layer version 0x0002
         */
        ti = proto_tree_add_uint(ssl_record_tree,
                                 hf_ssl_record_version, tvb,
                                 initial_offset, 0, 0x0002);
        PROTO_ITEM_SET_GENERATED(ti);

        /* add the record length */
        tvb_ensure_bytes_exist(tvb, offset, record_length_length);
        proto_tree_add_uint (ssl_record_tree,
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
        proto_tree_add_item(ssl_record_tree,
                            (*conv_version == SSL_VER_PCT)
                            ? hf_pct_msg_type : hf_ssl2_msg_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;                   /* move past msg_type byte */

    if (*conv_version != SSL_VER_PCT)
    {
        /* dissect the message (only handle client hello right now) */
        switch (msg_type) {
        case SSL2_HND_CLIENT_HELLO:
            dissect_ssl2_hnd_client_hello(tvb, pinfo, ssl_record_tree, offset, ssl);
            break;

        case SSL2_HND_CLIENT_MASTER_KEY:
            dissect_ssl2_hnd_client_master_key(tvb, ssl_record_tree, offset);
            break;

        case SSL2_HND_SERVER_HELLO:
            dissect_ssl2_hnd_server_hello(tvb, ssl_record_tree, offset, pinfo);
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
    }
    else
    {
        /* dissect the message */
        switch (msg_type) {
        case PCT_MSG_CLIENT_HELLO:
            dissect_pct_msg_client_hello(tvb, ssl_record_tree, offset);
            break;
        case PCT_MSG_SERVER_HELLO:
            dissect_pct_msg_server_hello(tvb, ssl_record_tree, offset, pinfo);
            break;
        case PCT_MSG_CLIENT_MASTER_KEY:
            dissect_pct_msg_client_master_key(tvb, ssl_record_tree, offset);
            break;
        case PCT_MSG_SERVER_VERIFY:
            dissect_pct_msg_server_verify(tvb, ssl_record_tree, offset);
            break;
        case PCT_MSG_ERROR:
            dissect_pct_msg_error(tvb, ssl_record_tree, offset);
            break;

        default:                    /* unknown */
            break;
        }
    }
    return (initial_offset + record_length_length + record_length);
}

static void
dissect_ssl2_hnd_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, guint32 offset,
                              SslDecryptSession* ssl)
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
    cs_tree=0;

    version = tvb_get_ntohs(tvb, offset);
    if (!ssl_is_valid_ssl_version(version))
    {
        /* invalid version; probably encrypted data */
        return;
    }

    if (ssl) {
      ssl_set_server(ssl, &pinfo->dst, pinfo->ptype, pinfo->destport);
      ssl_find_private_key(ssl, ssl_key_hash, ssl_associations, pinfo);
    }

    if (tree || ssl)
    {
        /* show the version */
        if (tree)
            proto_tree_add_item(tree, hf_ssl_handshake_client_version, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        cipher_spec_length = tvb_get_ntohs(tvb, offset);
        if (tree)
            proto_tree_add_item(tree, hf_ssl2_handshake_cipher_spec_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        session_id_length = tvb_get_ntohs(tvb, offset);
        if (tree)
            proto_tree_add_item(tree, hf_ssl2_handshake_session_id_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        if (session_id_length > SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES) {
            proto_tree_add_text(tree, tvb, offset, 2,
                                "Invalid session ID length: %d", session_id_length);
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR,
                                   "Session ID length (%u) must be less than %u.",
                                   session_id_length, SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES);
            return;
        }
        offset += 2;

        challenge_length = tvb_get_ntohs(tvb, offset);
        if (tree)
            proto_tree_add_item(tree, hf_ssl2_handshake_challenge_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (tree)
        {
            /* tell the user how many cipher specs they've won */
            tvb_ensure_bytes_exist(tvb, offset, cipher_spec_length);
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
        }

        /* iterate through the cipher specs, showing them */
        while (cipher_spec_length > 0)
        {
            if (cs_tree)
                proto_tree_add_item(cs_tree, hf_ssl2_handshake_cipher_spec,
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;        /* length of one cipher spec */
            cipher_spec_length -= 3;
        }

        /* if there's a session id, show it */
        if (session_id_length > 0)
        {
            if (tree)
            {
                tvb_ensure_bytes_exist(tvb, offset, session_id_length);
                proto_tree_add_bytes_format(tree,
                                            hf_ssl_handshake_session_id,
                                            tvb, offset, session_id_length,
                                            NULL, "Session ID (%u byte%s)",
                                            session_id_length,
                                            plurality(session_id_length, "", "s"));
            }

            /* PAOLO: get session id and reset session state for key [re]negotiation */
            if (ssl)
            {
                tvb_memcpy(tvb,ssl->session_id.data, offset, session_id_length);
                ssl->session_id.data_len = session_id_length;
                ssl->state &= ~(SSL_HAVE_SESSION_KEY|SSL_MASTER_SECRET|SSL_PRE_MASTER_SECRET|
                        SSL_CIPHER|SSL_SERVER_RANDOM);
            }
            offset += session_id_length;
        }

        /* if there's a challenge, show it */
        if (challenge_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, challenge_length);

            if (tree)
                proto_tree_add_item(tree, hf_ssl2_handshake_challenge,
                                tvb, offset, challenge_length, ENC_NA);
            if (ssl)
            {
                /* PAOLO: get client random data; we get at most 32 bytes from
                 challenge */
                gint max;
                max = challenge_length > 32? 32: challenge_length;

                ssl_debug_printf("client random len: %d padded to 32\n", challenge_length);

                /* client random is padded with zero and 'right' aligned */
                memset(ssl->client_random.data, 0, 32 - max);
                tvb_memcpy(tvb, &ssl->client_random.data[32 - max], offset, max);
                ssl->client_random.data_len = 32;
                ssl->state |= SSL_CLIENT_RANDOM;
                ssl_debug_printf("dissect_ssl2_hnd_client_hello found CLIENT RANDOM -> state 0x%02X\n", ssl->state);
            }
        }
    }
}

static void
dissect_pct_msg_client_hello(tvbuff_t *tvb,
                             proto_tree *tree, guint32 offset)
{
    guint16 CH_CLIENT_VERSION, CH_OFFSET, CH_CIPHER_SPECS_LENGTH, CH_HASH_SPECS_LENGTH, CH_CERT_SPECS_LENGTH, CH_EXCH_SPECS_LENGTH, CH_KEY_ARG_LENGTH;
    proto_item *CH_CIPHER_SPECS_ti, *CH_HASH_SPECS_ti, *CH_CERT_SPECS_ti, *CH_EXCH_SPECS_ti;
    proto_tree *CH_CIPHER_SPECS_tree, *CH_HASH_SPECS_tree, *CH_CERT_SPECS_tree, *CH_EXCH_SPECS_tree;
    gint i;

    CH_CLIENT_VERSION = tvb_get_ntohs(tvb, offset);
    if (CH_CLIENT_VERSION != PCT_VERSION_1)
        proto_tree_add_text(tree, tvb, offset, 2, "Client Version, should be %x in PCT version 1", PCT_VERSION_1);
    else
        proto_tree_add_text(tree, tvb, offset, 2, "Client Version (%x)", PCT_VERSION_1);
    offset += 2;

    proto_tree_add_text(tree, tvb, offset, 1, "PAD");
    offset += 1;

    proto_tree_add_text(tree, tvb, offset, 32, "Client Session ID Data (32 bytes)");
    offset += 32;

    proto_tree_add_text(tree, tvb, offset, 32, "Challenge Data(32 bytes)");
    offset += 32;

    CH_OFFSET = tvb_get_ntohs(tvb, offset);
    if (CH_OFFSET != PCT_CH_OFFSET_V1)
        proto_tree_add_text(tree, tvb, offset, 2, "CH_OFFSET: %d, should be %d in PCT version 1", CH_OFFSET, PCT_CH_OFFSET_V1);
    else
        proto_tree_add_text(tree, tvb, offset, 2, "CH_OFFSET: %d", CH_OFFSET);
    offset += 2;

    CH_CIPHER_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "CIPHER_SPECS Length: %d", CH_CIPHER_SPECS_LENGTH);
    offset += 2;

    CH_HASH_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "HASH_SPECS Length: %d", CH_HASH_SPECS_LENGTH);
    offset += 2;

    CH_CERT_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "CERT_SPECS Length: %d", CH_CERT_SPECS_LENGTH);
    offset += 2;

    CH_EXCH_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "EXCH_SPECS Length: %d", CH_EXCH_SPECS_LENGTH);
    offset += 2;

    CH_KEY_ARG_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "IV Length: %d", CH_KEY_ARG_LENGTH);
    offset += 2;

    if (CH_CIPHER_SPECS_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CH_CIPHER_SPECS_LENGTH);
        CH_CIPHER_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_cipher_spec, tvb, offset, CH_CIPHER_SPECS_LENGTH, ENC_NA);
        CH_CIPHER_SPECS_tree = proto_item_add_subtree(CH_CIPHER_SPECS_ti, ett_pct_cipher_suites);

        for(i=0; i<(CH_CIPHER_SPECS_LENGTH/4); i++) {
            proto_tree_add_item(CH_CIPHER_SPECS_tree, hf_pct_handshake_cipher, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_text(CH_CIPHER_SPECS_tree, tvb, offset, 1, "Encryption key length: %d", tvb_get_guint8(tvb, offset));
            offset += 1;
            proto_tree_add_text(CH_CIPHER_SPECS_tree, tvb, offset, 1, "MAC key length in bits: %d", tvb_get_guint8(tvb, offset) + 64);
            offset += 1;
        }
    }

    if (CH_HASH_SPECS_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CH_HASH_SPECS_LENGTH);
        CH_HASH_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_hash_spec, tvb, offset, CH_HASH_SPECS_LENGTH, ENC_NA);
        CH_HASH_SPECS_tree = proto_item_add_subtree(CH_HASH_SPECS_ti, ett_pct_hash_suites);

        for(i=0; i<(CH_HASH_SPECS_LENGTH/2); i++) {
            proto_tree_add_item(CH_HASH_SPECS_tree, hf_pct_handshake_hash, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (CH_CERT_SPECS_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CH_CERT_SPECS_LENGTH);
        CH_CERT_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_cert_spec, tvb, offset, CH_CERT_SPECS_LENGTH, ENC_NA);
        CH_CERT_SPECS_tree = proto_item_add_subtree(CH_CERT_SPECS_ti, ett_pct_cert_suites);

        for(i=0; i< (CH_CERT_SPECS_LENGTH/2); i++) {
            proto_tree_add_item(CH_CERT_SPECS_tree, hf_pct_handshake_cert, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (CH_EXCH_SPECS_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CH_EXCH_SPECS_LENGTH);
        CH_EXCH_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_exch_spec, tvb, offset, CH_EXCH_SPECS_LENGTH, ENC_NA);
        CH_EXCH_SPECS_tree = proto_item_add_subtree(CH_EXCH_SPECS_ti, ett_pct_exch_suites);

        for(i=0; i<(CH_EXCH_SPECS_LENGTH/2); i++) {
            proto_tree_add_item(CH_EXCH_SPECS_tree, hf_pct_handshake_exch, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (CH_KEY_ARG_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CH_KEY_ARG_LENGTH);
        proto_tree_add_text(tree, tvb, offset, CH_KEY_ARG_LENGTH, "IV data (%d bytes)", CH_KEY_ARG_LENGTH);
    }
}

static void
dissect_pct_msg_server_hello(tvbuff_t *tvb, proto_tree *tree, guint32 offset, packet_info *pinfo)
{
/* structure:
   char SH_MSG_SERVER_HELLO
   char SH_PAD
   char SH_SERVER_VERSION_MSB
   char SH_SERVER_VERSION_LSB
   char SH_RESTART_SESSION_OK
   char SH_CLIENT_AUTH_REQ
   char SH_CIPHER_SPECS_DATA[4]
   char SH_HASH_SPECS_DATA[2]
   char SH_CERT_SPECS_DATA[2]
   char SH_EXCH_SPECS_DATA[2]
   char SH_CONNECTION_ID_DATA[32]
   char SH_CERTIFICATE_LENGTH_MSB
   char SH_CERTIFICATE_LENGTH_LSB
   char SH_CLIENT_CERT_SPECS_LENGTH_MSB
   char SH_CLIENT_CERT_SPECS_LENGTH_LSB
   char SH_CLIENT_SIG_SPECS_LENGTH_MSB
   char SH_CLIENT_SIG_SPECS_LENGTH_LSB
   char SH_RESPONSE_LENGTH_MSB
   char SH_RESPONSE_LENGTH_LSB
   char SH_CERTIFICATE_DATA[MSB<<8|LSB]
   char SH_CLIENT_CERT_SPECS_DATA[MSB<<8|LSB]
   char SH_CLIENT_SIG_SPECS_DATA[MSB<<8|LSB]
   char SH_RESPONSE_DATA[MSB<<8|LSB]

*/

    guint16 SH_SERVER_VERSION, SH_CERT_LENGTH, SH_CERT_SPECS_LENGTH, SH_CLIENT_SIG_LENGTH, SH_RESPONSE_LENGTH;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    proto_tree_add_text(tree, tvb, offset, 1, "PAD");
    offset += 1;

    SH_SERVER_VERSION = tvb_get_ntohs(tvb, offset);
    if (SH_SERVER_VERSION != PCT_VERSION_1)
        proto_tree_add_text(tree, tvb, offset, 2, "Server Version, should be %x in PCT version 1", PCT_VERSION_1);
    else
        proto_tree_add_text(tree, tvb, offset, 2, "Server Version (%x)", PCT_VERSION_1);
    offset += 2;

    proto_tree_add_text(tree, tvb, offset, 1, "SH_RESTART_SESSION_OK flag");
    offset += 1;

    proto_tree_add_text(tree, tvb, offset, 1, "SH_CLIENT_AUTH_REQ flag");
    offset += 1;

    proto_tree_add_item(tree, hf_pct_handshake_cipher, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_text(tree, tvb, offset, 1, "Encryption key length: %d", tvb_get_guint8(tvb, offset));
    offset += 1;
    proto_tree_add_text(tree, tvb, offset, 1, "MAC key length in bits: %d", tvb_get_guint8(tvb, offset) + 64);
    offset += 1;

    proto_tree_add_item(tree, hf_pct_handshake_hash, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pct_handshake_cert, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pct_handshake_exch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_text(tree, tvb, offset, 32, "Connection ID Data (32 bytes)");
    offset += 32;

    SH_CERT_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Server Certificate Length: %d", SH_CERT_LENGTH);
    offset += 2;

    SH_CERT_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Client CERT_SPECS Length: %d", SH_CERT_SPECS_LENGTH);
    offset += 2;

    SH_CLIENT_SIG_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Client SIG_SPECS Length: %d", SH_CLIENT_SIG_LENGTH);
    offset += 2;

    SH_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Response Length: %d", SH_RESPONSE_LENGTH);
    offset += 2;

    if (SH_CERT_LENGTH) {
        dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_pct_handshake_server_cert);
        offset += SH_CERT_LENGTH;
    }

    if (SH_CERT_SPECS_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, SH_CERT_SPECS_LENGTH);
        proto_tree_add_text(tree, tvb, offset, SH_CERT_SPECS_LENGTH, "Client CERT_SPECS (%d bytes)", SH_CERT_SPECS_LENGTH);
        offset += SH_CERT_SPECS_LENGTH;
    }

    if (SH_CLIENT_SIG_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, SH_CLIENT_SIG_LENGTH);
        proto_tree_add_text(tree, tvb, offset, SH_CLIENT_SIG_LENGTH, "Client Signature (%d bytes)", SH_CLIENT_SIG_LENGTH);
        offset += SH_CLIENT_SIG_LENGTH;
    }

    if (SH_RESPONSE_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, SH_RESPONSE_LENGTH);
        proto_tree_add_text(tree, tvb, offset, SH_RESPONSE_LENGTH, "Server Response (%d bytes)", SH_RESPONSE_LENGTH);
    }

}

static void
dissect_pct_msg_client_master_key(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint16 CMK_CLEAR_KEY_LENGTH, CMK_ENCRYPTED_KEY_LENGTH, CMK_KEY_ARG_LENGTH, CMK_VERIFY_PRELUDE, CMK_CLIENT_CERT_LENGTH, CMK_RESPONSE_LENGTH;

    proto_tree_add_text(tree, tvb, offset, 1, "PAD");
    offset += 1;

    proto_tree_add_item(tree, hf_pct_handshake_cert, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pct_handshake_sig, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_CLEAR_KEY_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Clear Key Length: %d",CMK_CLEAR_KEY_LENGTH);
    offset += 2;

    CMK_ENCRYPTED_KEY_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Encrypted Key Length: %d",CMK_ENCRYPTED_KEY_LENGTH);
    offset += 2;

    CMK_KEY_ARG_LENGTH= tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "IV Length: %d",CMK_KEY_ARG_LENGTH);
    offset += 2;

    CMK_VERIFY_PRELUDE = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Verify Prelude Length: %d",CMK_VERIFY_PRELUDE);
    offset += 2;

    CMK_CLIENT_CERT_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Client Cert Length: %d",CMK_CLIENT_CERT_LENGTH);
    offset += 2;

    CMK_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Response Length: %d",CMK_RESPONSE_LENGTH);
    offset += 2;

    if (CMK_CLEAR_KEY_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CMK_CLEAR_KEY_LENGTH);
        proto_tree_add_text(tree, tvb, offset, CMK_CLEAR_KEY_LENGTH, "Clear Key data (%d bytes)", CMK_CLEAR_KEY_LENGTH);
        offset += CMK_CLEAR_KEY_LENGTH;
    }
    if (CMK_ENCRYPTED_KEY_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CMK_ENCRYPTED_KEY_LENGTH);
        proto_tree_add_text(tree, tvb, offset, CMK_ENCRYPTED_KEY_LENGTH, "Encrypted Key data (%d bytes)", CMK_ENCRYPTED_KEY_LENGTH);
        offset += CMK_ENCRYPTED_KEY_LENGTH;
    }
    if (CMK_KEY_ARG_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CMK_KEY_ARG_LENGTH);
        proto_tree_add_text(tree, tvb, offset, CMK_KEY_ARG_LENGTH, "IV data (%d bytes)", CMK_KEY_ARG_LENGTH);
        offset += CMK_KEY_ARG_LENGTH;
    }
    if (CMK_VERIFY_PRELUDE) {
        tvb_ensure_bytes_exist(tvb, offset, CMK_VERIFY_PRELUDE);
        proto_tree_add_text(tree, tvb, offset, CMK_VERIFY_PRELUDE, "Verify Prelude data (%d bytes)", CMK_VERIFY_PRELUDE);
        offset += CMK_VERIFY_PRELUDE;
    }
    if (CMK_CLIENT_CERT_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CMK_CLIENT_CERT_LENGTH);
        proto_tree_add_text(tree, tvb, offset, CMK_CLIENT_CERT_LENGTH, "Client Certificate data (%d bytes)", CMK_CLIENT_CERT_LENGTH);
        offset += CMK_CLIENT_CERT_LENGTH;
    }
    if (CMK_RESPONSE_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, CMK_RESPONSE_LENGTH);
        proto_tree_add_text(tree, tvb, offset, CMK_RESPONSE_LENGTH, "Response data (%d bytes)", CMK_RESPONSE_LENGTH);
    }
}

static void
dissect_pct_msg_server_verify(tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset)
{
    guint16 SV_RESPONSE_LENGTH;

    proto_tree_add_text(tree, tvb, offset, 1, "PAD");
    offset += 1;

    proto_tree_add_text(tree, tvb, offset, 32, "Server Session ID data (32 bytes)");
    offset += 32;

    SV_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Server Response Length: %d", SV_RESPONSE_LENGTH);
    offset += 2;

    if (SV_RESPONSE_LENGTH) {
        tvb_ensure_bytes_exist(tvb, offset, SV_RESPONSE_LENGTH);
        proto_tree_add_text(tree, tvb, offset, SV_RESPONSE_LENGTH, "Server Response (%d bytes)", SV_RESPONSE_LENGTH);
    }
}

static void
dissect_pct_msg_error(tvbuff_t *tvb,
                      proto_tree *tree, guint32 offset)
{
    guint16 ERROR_CODE, INFO_LEN;

    ERROR_CODE = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_pct_msg_error_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    INFO_LEN = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Error Information Length: %d", INFO_LEN);
    offset += 2;
    if (ERROR_CODE == PCT_ERR_SPECS_MISMATCH && INFO_LEN == 6)
    {
        proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CIPHER");
        offset += 1;
        proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_HASH");
        offset += 1;
        proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CERT");
        offset += 1;
        proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_EXCH");
        offset += 1;
        proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CLIENT_CERT");
        offset += 1;
        proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CLIENT_SIG");
    }
    else if (INFO_LEN) {
        proto_tree_add_text(tree, tvb, offset, INFO_LEN, "Error Information data (%d bytes)", INFO_LEN);
    }
}

static void
dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb,
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
                        tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* get the fixed fields */
    clear_key_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_clear_key_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    encrypted_key_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_enc_key_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    key_arg_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_key_arg_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* show the variable length fields */
    if (clear_key_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, clear_key_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_clear_key,
                            tvb, offset, clear_key_length, ENC_NA);
        offset += clear_key_length;
    }

    if (encrypted_key_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, encrypted_key_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_enc_key,
                            tvb, offset, encrypted_key_length, ENC_NA);
        offset += encrypted_key_length;
    }

    if (key_arg_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, key_arg_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_key_arg,
                            tvb, offset, key_arg_length, ENC_NA);
    }

}

static void
dissect_ssl2_hnd_server_hello(tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset, packet_info *pinfo)
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
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* what type of certificate is this? */
    proto_tree_add_item(tree, hf_ssl2_handshake_cert_type,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* now the server version */
    proto_tree_add_item(tree, hf_ssl_handshake_server_version,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
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
        (void)dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_ssl_handshake_certificate);
        offset += certificate_length;
    }

    if (cipher_spec_length > 0)
    {
        /* provide a collapsing node for the cipher specs */
        tvb_ensure_bytes_exist(tvb, offset, cipher_spec_length);
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
                                tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            cipher_spec_length -= 3;
        }
    }

    if (connection_id_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, connection_id_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_connection_id,
                            tvb, offset, connection_id_length, ENC_NA);
    }

}


void ssl_set_master_secret(guint32 frame_num, address *addr_srv, address *addr_cli,
                           port_type ptype, guint32 port_srv, guint32 port_cli,
                           guint32 version, gint cipher, const guchar *_master_secret,
                           const guchar *_client_random, const guchar *_server_random,
                           guint32 client_seq, guint32 server_seq)
{
    conversation_t *conversation = NULL;
    void *conv_data = NULL;
    SslDecryptSession *ssl = NULL;
    guint iv_len;

    ssl_debug_printf("\nssl_set_master_secret enter frame #%u\n", frame_num);

    conversation = find_conversation(frame_num, addr_srv, addr_cli, ptype, port_srv, port_cli, 0);

    if (!conversation) {
        /* create a new conversation */
        conversation = conversation_new(frame_num, addr_srv, addr_cli, ptype, port_srv, port_cli, 0);
        ssl_debug_printf("  new conversation = %p created\n", (void *)conversation);
    }
    conv_data = conversation_get_proto_data(conversation, proto_ssl);

    if (conv_data) {
        ssl = conv_data;
    } else {
        ssl = se_alloc0(sizeof(SslDecryptSession));
        ssl_session_init(ssl);
        ssl->version = SSL_VER_UNKNOWN;
        conversation_add_proto_data(conversation, proto_ssl, ssl);
    }

    ssl_debug_printf("  conversation = %p, ssl_session = %p\n", (void *)conversation, (void *)ssl);

    ssl_set_server(ssl, addr_srv, ptype, port_srv);

    /* version */
    if ((ssl->version==SSL_VER_UNKNOWN) && (version!=SSL_VER_UNKNOWN)) {
        switch (version) {
        case SSL_VER_SSLv3:
            ssl->version = SSL_VER_SSLv3;
            ssl->version_netorder = SSLV3_VERSION;
            ssl->state |= SSL_VERSION;
            ssl_debug_printf("ssl_set_master_secret set version 0x%04X -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            break;

        case SSL_VER_TLS:
            ssl->version = SSL_VER_TLS;
            ssl->version_netorder = TLSV1_VERSION;
            ssl->state |= SSL_VERSION;
            ssl_debug_printf("ssl_set_master_secret set version 0x%04X -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            break;

        case SSL_VER_TLSv1DOT1:
            ssl->version = SSL_VER_TLSv1DOT1;
            ssl->version_netorder = TLSV1DOT1_VERSION;
            ssl->state |= SSL_VERSION;
            ssl_debug_printf("ssl_set_master_secret set version 0x%04X -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            break;

        case SSL_VER_TLSv1DOT2:
            ssl->version = SSL_VER_TLSv1DOT2;
            ssl->version_netorder = TLSV1DOT2_VERSION;
            ssl->state |= SSL_VERSION;
            ssl_debug_printf("ssl_set_master_secret set version 0x%04X -> state 0x%02X\n", ssl->version_netorder, ssl->state);
            break;
        }
    }

    /* cipher */
    if (cipher > 0) {
        ssl->cipher = cipher;
        if (ssl_find_cipher(ssl->cipher,&ssl->cipher_suite) < 0) {
            ssl_debug_printf("ssl_set_master_secret can't find cipher suite 0x%X\n", ssl->cipher);
        } else {
            ssl->state |= SSL_CIPHER;
            ssl_debug_printf("ssl_set_master_secret set CIPHER 0x%04X -> state 0x%02X\n", ssl->cipher, ssl->state);
        }
    }

    /* client random */
    if (_client_random) {
        ssl_data_set(&ssl->client_random, _client_random, 32);
        ssl->state |= SSL_CLIENT_RANDOM;
        ssl_debug_printf("ssl_set_master_secret set CLIENT RANDOM -> state 0x%02X\n", ssl->state);
    }

    /* server random */
    if (_server_random) {
        ssl_data_set(&ssl->server_random, _server_random, 32);
        ssl->state |= SSL_SERVER_RANDOM;
        ssl_debug_printf("ssl_set_master_secret set SERVER RANDOM -> state 0x%02X\n", ssl->state);
    }

    /* master secret */
    if (_master_secret) {
        ssl_data_set(&ssl->master_secret, _master_secret, 48);
        ssl->state |= SSL_MASTER_SECRET;
        ssl_debug_printf("ssl_set_master_secret set MASTER SECRET -> state 0x%02X\n", ssl->state);
    }

    ssl_debug_printf("ssl_set_master_secret trying to generate keys\n");
    if (ssl_generate_keyring_material(ssl)<0) {
        ssl_debug_printf("ssl_set_master_secret can't generate keyring material\n");
        return;
    }

    /* change ciphers immediately */
    ssl_change_cipher(ssl, TRUE);
    ssl_change_cipher(ssl, FALSE);

    /* update seq numbers if available */
    if (ssl->client && (client_seq != (guint32)-1)) {
        ssl->client->seq = client_seq;
        ssl_debug_printf("ssl_set_master_secret client->seq updated to %u\n", ssl->client->seq);
    }
    if (ssl->server && (server_seq != (guint32)-1)) {
        ssl->server->seq = server_seq;
        ssl_debug_printf("ssl_set_master_secret server->seq updated to %u\n", ssl->server->seq);
    }

    /* update IV from last data */
    iv_len = (ssl->cipher_suite.block>1) ? ssl->cipher_suite.block : 8;
    if (ssl->client && ((ssl->client->seq > 0) || (ssl->client_data_for_iv.data_len > iv_len))) {
        ssl_cipher_setiv(&ssl->client->evp, ssl->client_data_for_iv.data + ssl->client_data_for_iv.data_len - iv_len, iv_len);
        ssl_print_data("ssl_set_master_secret client IV updated",ssl->client_data_for_iv.data + ssl->client_data_for_iv.data_len - iv_len, iv_len);
    }
    if (ssl->server && ((ssl->server->seq > 0) || (ssl->server_data_for_iv.data_len > iv_len))) {
        ssl_cipher_setiv(&ssl->server->evp, ssl->server_data_for_iv.data + ssl->server_data_for_iv.data_len - iv_len, iv_len);
        ssl_print_data("ssl_set_master_secret server IV updated",ssl->server_data_for_iv.data + ssl->server_data_for_iv.data_len - iv_len, iv_len);
    }
}


/*********************************************************************
 *
 * Support Functions
 *
 *********************************************************************/
#if 0
static void
ssl_set_conv_version(packet_info *pinfo, guint version)
{
    conversation_t *conversation;

    if (pinfo->fd->flags.visited)
    {
        /* We've already processed this frame; no need to do any more
         * work on it.
         */
        return;
    }

    conversation = find_or_create_conversation(pinfo);

    if (conversation_get_proto_data(conversation, proto_ssl) != NULL)
    {
        /* get rid of the current data */
        conversation_delete_proto_data(conversation, proto_ssl);
    }
    conversation_add_proto_data(conversation, proto_ssl, GINT_TO_POINTER(version));
}
#endif

static gint
ssl_is_valid_handshake_type(const guint8 type)
{

    switch (type) {
    case SSL_HND_HELLO_REQUEST:
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_SERVER_HELLO:
    case SSL_HND_NEWSESSION_TICKET:
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

static gint
ssl_is_valid_ssl_version(const guint16 version)
{
    const gchar *version_str;
    version_str = match_strval(version, ssl_versions);
    return version_str != NULL;
}

static gint
ssl_is_authoritative_version_message(const guint8 content_type,
                                     const guint8 next_byte)
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

static gint
ssl_is_v2_client_hello(tvbuff_t *tvb, const guint32 offset)
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
static gint
ssl_looks_like_sslv2(tvbuff_t *tvb, const guint32 offset)
{
    /* here's the current approach:
     *
     * we only try to catch unencrypted handshake messages, so we can
     * assume that there is not padding.  This means that the
     * first byte must be >= 0x80 and there must be a valid sslv2
     * msg_type in the third byte
     */

    /* get the first byte; must have high bit set */
    guint8 byte;
    byte = tvb_get_guint8(tvb, offset);

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
    case PCT_MSG_CLIENT_MASTER_KEY:
    case PCT_MSG_ERROR:
        return 1;
    }
    return 0;
}

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv3 record.  this is somewhat more reliable
 * than sslv2 due to the structure of the v3 protocol
 */
static gint
ssl_looks_like_sslv3(tvbuff_t *tvb, const guint32 offset)
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
    switch(version) {
    case SSLV3_VERSION:
    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case TLSV1DOT2_VERSION:
        return 1;
    }
    return 0;
}

/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted v2 handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.
 */
static gint
ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb, const guint32 offset,
                                  const guint32 record_length)
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
    gint ret = 0;

    /* fetch the msg_type */
    msg_type = tvb_get_guint8(tvb, offset);

    switch (msg_type) {
    case SSL2_HND_CLIENT_HELLO:
        /* version follows msg byte, so verify that this is valid */
        version = tvb_get_ntohs(tvb, offset+1);
        ret = ssl_is_valid_ssl_version(version);
        break;

    case SSL2_HND_SERVER_HELLO:
        /* version is three bytes after msg_type */
        version = tvb_get_ntohs(tvb, offset+3);
        ret = ssl_is_valid_ssl_version(version);
        break;

    case SSL2_HND_CLIENT_MASTER_KEY:
        /* sum of clear_key_length, encrypted_key_length, and key_arg_length
         * must be less than record length
         */
        sum  = tvb_get_ntohs(tvb, offset + 4); /* clear_key_length */
        sum += tvb_get_ntohs(tvb, offset + 6); /* encrypted_key_length */
        sum += tvb_get_ntohs(tvb, offset + 8); /* key_arg_length */
        if (sum <= record_length) {
            ret = 1;
        }
        break;

    default:
        break;
    }

    return ret;
}

/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted pct handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.
 */
static gint
ssl_looks_like_valid_pct_handshake(tvbuff_t *tvb, const guint32 offset,
                   const guint32 record_length)
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
    gint ret = 0;

    /* fetch the msg_type */
    msg_type = tvb_get_guint8(tvb, offset);

    switch (msg_type) {
    case PCT_MSG_CLIENT_HELLO:
        /* version follows msg byte, so verify that this is valid */
        version = tvb_get_ntohs(tvb, offset+1);
        ret = (version == PCT_VERSION_1);
        break;

    case PCT_MSG_SERVER_HELLO:
        /* version is one byte after msg_type */
        version = tvb_get_ntohs(tvb, offset+2);
        ret = (version == PCT_VERSION_1);
        break;

    case PCT_MSG_CLIENT_MASTER_KEY:
        /* sum of various length fields must be less than record length */
        sum  = tvb_get_ntohs(tvb, offset + 6); /* clear_key_length */
        sum += tvb_get_ntohs(tvb, offset + 8); /* encrypted_key_length */
        sum += tvb_get_ntohs(tvb, offset + 10); /* key_arg_length */
        sum += tvb_get_ntohs(tvb, offset + 12); /* verify_prelude_length */
        sum += tvb_get_ntohs(tvb, offset + 14); /* client_cert_length */
        sum += tvb_get_ntohs(tvb, offset + 16); /* response_length */
        if (sum <= record_length) {
            ret = 1;
        }
        break;

    case PCT_MSG_SERVER_VERIFY:
        /* record is 36 bytes longer than response_length */
        sum = tvb_get_ntohs(tvb, offset + 34); /* response_length */
        if ((sum + 36) == record_length) {
            ret = 1;
        }
        break;

    default:
        break;
    }

    return ret;
}

/* UAT */

#ifdef HAVE_LIBGNUTLS
static void
ssldecrypt_free_cb(void* r)
{
    ssldecrypt_assoc_t* h = r;

    g_free(h->ipaddr);
    g_free(h->port);
    g_free(h->protocol);
    g_free(h->keyfile);
    g_free(h->password);
}

static void
ssldecrypt_update_cb(void* r _U_, const char** err)
{
    if (err)
            *err = NULL;
    return;
}

static void*
ssldecrypt_copy_cb(void* dest, const void* orig, size_t len _U_)
{
    const ssldecrypt_assoc_t* o = orig;
    ssldecrypt_assoc_t* d = dest;

    d->ipaddr    = g_strdup(o->ipaddr);
    d->port      = g_strdup(o->port);
    d->protocol  = g_strdup(o->protocol);
    d->keyfile   = g_strdup(o->keyfile);
    d->password  = g_strdup(o->password);

    return d;
}

UAT_CSTRING_CB_DEF(sslkeylist_uats,ipaddr,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,port,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,protocol,ssldecrypt_assoc_t)
UAT_FILENAME_CB_DEF(sslkeylist_uats,keyfile,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,password,ssldecrypt_assoc_t)
#endif

/*********************************************************************
 *
 * Standard Wireshark Protocol Registration and housekeeping
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
            NULL, HFILL }
        },
        { &hf_ssl_record_content_type,
          { "Content Type", "ssl.record.content_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
            NULL, HFILL}
        },
        { &hf_ssl2_msg_type,
          { "Handshake Message Type", "ssl.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_msg_types), 0x0,
            "SSLv2 handshake message type", HFILL}
        },
        { &hf_pct_msg_type,
          { "Handshake Message Type", "ssl.pct_handshake.type",
            FT_UINT8, BASE_DEC, VALS(pct_msg_types), 0x0,
            "PCT handshake message type", HFILL}
        },
        { &hf_ssl_record_version,
          { "Version", "ssl.record.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Record layer version", HFILL }
        },
        { &hf_ssl_record_length,
          { "Length", "ssl.record.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of SSL record data", HFILL }
        },
        { &hf_ssl_record_appdata,
          { "Encrypted Application Data", "ssl.app_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Payload is encrypted application data", HFILL }
        },

        { &hf_ssl2_record,
          { "SSLv2/PCT Record Header", "ssl.record",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "SSLv2/PCT record data", HFILL }
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
        { &hf_ssl_alert_message,
          { "Alert Message", "ssl.alert_message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_alert_message_level,
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
          { "gmt_unix_time", "ssl.handshake.random_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "Unix time field of random structure", HFILL }
        },
        { &hf_ssl_handshake_random_bytes,
          { "random_bytes", "ssl.handshake.random_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
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
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ssl_31_ciphersuite_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec,
          { "Cipher Spec", "ssl.handshake.cipherspec",
            FT_UINT24, BASE_HEX|BASE_EXT_STRING, &ssl_20_cipher_suites_ext, 0x0,
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
            NULL, HFILL }
        },
        { &hf_ssl_handshake_extensions_len,
          { "Extensions Length", "ssl.handshake.extensions_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of hello extensions", HFILL }
        },
        { &hf_ssl_handshake_extension_type,
          { "Type", "ssl.handshake.extension.type",
            FT_UINT16, BASE_HEX, VALS(tls_hello_extension_types), 0x0,
            "Hello extension type", HFILL }
        },
        { &hf_ssl_handshake_extension_len,
          { "Length", "ssl.handshake.extension.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of a hello extension", HFILL }
        },
        { &hf_ssl_handshake_extension_data,
          { "Data", "ssl.handshake.extension.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Hello Extension data", HFILL }
        },
        { &hf_ssl_handshake_extension_elliptic_curves_len,
          { "Elliptic Curves Length", "ssl.handshake.extensions_elliptic_curves_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of elliptic curves field", HFILL }
        },
        { &hf_ssl_handshake_extension_elliptic_curves,
          { "Elliptic Curves List", "ssl.handshake.extensions_elliptic_curves",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of elliptic curves supported", HFILL }
        },
        { &hf_ssl_handshake_extension_elliptic_curve,
          { "Elliptic curve", "ssl.handshake.extensions_elliptic_curve",
            FT_UINT16, BASE_HEX, VALS(ssl_extension_curves), 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_extension_ec_point_formats_len,
          { "EC point formats Length", "ssl.handshake.extensions_ec_point_formats_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of elliptic curves point formats field", HFILL }
        },
        { &hf_ssl_handshake_extension_ec_point_format,
          { "EC point format", "ssl.handshake.extensions_ec_point_format",
            FT_UINT8, BASE_DEC, VALS(ssl_extension_ec_point_formats), 0x0,
            "Elliptic curves point format", HFILL }
        },
        { &hf_ssl_handshake_extension_npn_str_len,
          { "Protocol string length", "ssl.handshake.extensions_npn_str_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of next protocol string", HFILL }
        },
        { &hf_ssl_handshake_extension_npn_str,
          { "Next Protocol", "ssl.handshake.extensions_npn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_extension_reneg_info_len,
          { "Renegotiation info extension length", "ssl.handshake.extensions_reneg_info_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_extension_server_name_list_len,
          { "Server Name list length", "ssl.handshake.extensions_server_name_list_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of server name list", HFILL }
        },
        { &hf_ssl_handshake_extension_server_name_len,
          { "Server Name length", "ssl.handshake.extensions_server_name_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of server name string", HFILL }
        },
        { &hf_ssl_handshake_extension_server_name_type,
          { "Server Name Type", "ssl.handshake.extensions_server_name_type",
            FT_UINT8, BASE_DEC, VALS(tls_hello_ext_server_name_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_extension_server_name,
          { "Server Name", "ssl.handshake.extensions_server_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_session_ticket_lifetime_hint,
          { "Session Ticket Lifetime Hint", "ssl.handshake.session_ticket_lifetime_hint",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "New TLS Session Ticket Lifetime Hint", HFILL }
        },
        { &hf_ssl_handshake_session_ticket_len,
          { "Session Ticket Length", "ssl.handshake.session_ticket_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "New TLS Session Ticket Length", HFILL }
        },
        { &hf_ssl_handshake_session_ticket,
          { "Session Ticket", "ssl.handshake.session_ticket",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "New TLS Session Ticket", HFILL }
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
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
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
            NULL, HFILL }
        },
        { &hf_ssl_handshake_server_keyex_p_len,
          { "p Length", "ssl.handshake.p_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of p", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_g_len,
          { "g Length", "ssl.handshake.g_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of g", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_ys_len,
          { "Pubkey Length", "ssl.handshake.ys_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of server's Diffie-Hellman public key", HFILL }
        },
        { &hf_ssl_handshake_client_keyex_yc_len,
          { "Pubkey Length", "ssl.handshake.yc_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of client's Diffie-Hellman public key", HFILL }
        },
        { &hf_ssl_handshake_client_keyex_point_len,
          { "Pubkey Length", "ssl.handshake.client_point_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of client's EC Diffie-Hellman public key", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_point_len,
          { "Pubkey Length", "ssl.handshake.server_point_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of server's EC Diffie-Hellman public key", HFILL }
        },
        { &hf_ssl_handshake_client_keyex_epms_len,
          { "Encrypted PreMaster length", "ssl.handshake.epms_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of encrypted PreMaster secret", HFILL }
        },
        { &hf_ssl_handshake_client_keyex_epms,
          { "Encrypted PreMaster", "ssl.handshake.epms",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Encrypted PreMaster secret", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_modulus_len,
          { "modulus Length", "ssl.handshake.modulus_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of RSA-EXPORT modulus", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_exponent_len,
          { "exponent Length", "ssl.handshake.exponent_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of RSA-EXPORT exponent", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_sig_len,
          { "Signature Length", "ssl.handshake.sig_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of Signature", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_p,
          { "p", "ssl.handshake.p",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Diffie-Hellman p", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_g,
          { "g", "ssl.handshake.g",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Diffie-Hellman g", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_curve_type,
            { "curve_type", "ssl.handshake.server_curve_type",
              FT_UINT8, BASE_HEX, VALS(ssl_curve_types), 0x0,
              "Server curve_type", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_named_curve,
            { "named_curve", "ssl.handshake.server_named_curve",
              FT_UINT16, BASE_HEX, VALS(ssl_extension_curves), 0x0,
              "Server named_curve", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_ys,
          { "pubkey", "ssl.handshake.ys",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Diffie-Hellman server pubkey", HFILL }
        },
        { &hf_ssl_handshake_client_keyex_yc,
          { "pubkey", "ssl.handshake.yc",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Diffie-Hellman client pubkey", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_point,
          { "pubkey", "ssl.handshake.server_point",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "EC Diffie-Hellman server pubkey", HFILL }
        },
        { &hf_ssl_handshake_client_keyex_point,
          { "pubkey", "ssl.handshake.client_point",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "EC Diffie-Hellman client pubkey", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_modulus,
          { "modulus", "ssl.handshake.modulus",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "RSA-EXPORT modulus", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_exponent,
          { "exponent", "ssl.handshake.exponent",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "RSA-EXPORT exponent", HFILL }
        },
        { &hf_ssl_handshake_server_keyex_sig,
          { "signature", "ssl.handshake.sig",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Diffie-Hellman server signature", HFILL }
        },
        { &hf_ssl_handshake_sig_hash_alg_len,
          { "Signature Hash Algorithms Length", "ssl.handshake.sig_hash_alg_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of Signature Hash Algorithms", HFILL }
        },
        { &hf_ssl_handshake_sig_hash_algs,
          { "Signature Hash Algorithms", "ssl.handshake.sig_hash_algs",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of Signature Hash Algorithms", HFILL }
        },
        { &hf_ssl_handshake_sig_hash_alg,
          { "Signature Hash Algorithm", "ssl.handshake.sig_hash_alg",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_sig_hash_hash,
          { "Signature Hash Algorithm Hash", "ssl.handshake.sig_hash_hash",
            FT_UINT8, BASE_DEC, VALS(tls_hash_algorithm), 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_sig_hash_sig,
          { "Signature Hash Algorithm Signature", "ssl.handshake.sig_hash_sig",
            FT_UINT8, BASE_DEC, VALS(tls_signature_algorithm), 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_cert_status,
          { "Certificate Status", "ssl.handshake.cert_status",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Certificate Status Data", HFILL }
        },
        { &hf_ssl_handshake_cert_status_type,
          { "Certificate Status Type", "ssl.handshake.cert_status_type",
            FT_UINT8, BASE_DEC, VALS(tls_cert_status_type), 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_cert_status_len,
          { "Certificate Status Length", "ssl.handshake.cert_status_len",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of certificate status", HFILL }
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
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Distinguished name of a CA that server trusts", HFILL }
        },
        { &hf_ssl_heartbeat_extension_mode,
          { "Mode", "ssl.handshake.extension.heartbeat.mode",
            FT_UINT8, BASE_DEC, VALS(tls_heartbeat_mode), 0x0,
            "Heartbeat extension mode", HFILL }
        },
        { &hf_ssl_heartbeat_message,
          { "Heartbeat Message", "ssl.heartbeat_message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_heartbeat_message_type,
          { "Type", "ssl.heartbeat_message.type",
            FT_UINT8, BASE_DEC, VALS(tls_heartbeat_type), 0x0,
            "Heartbeat message type", HFILL }
        },
        { &hf_ssl_heartbeat_message_payload_length,
          { "Payload Length", "ssl.heartbeat_message.payload_length",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ssl_heartbeat_message_payload,
          { "Payload Length", "ssl.heartbeat_message.payload",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ssl_heartbeat_message_padding,
          { "Payload Length", "ssl.heartbeat_message.padding",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
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
            NULL, HFILL }
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
        { &hf_pct_handshake_cipher_spec,
          { "Cipher Spec", "pct.handshake.cipherspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Cipher specification", HFILL }
        },
        { &hf_pct_handshake_cipher,
          { "Cipher", "pct.handshake.cipher",
            FT_UINT16, BASE_HEX, VALS(pct_cipher_type), 0x0,
            "PCT Ciper", HFILL }
        },
        { &hf_pct_handshake_hash_spec,
          { "Hash Spec", "pct.handshake.hashspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Hash specification", HFILL }
        },
        { &hf_pct_handshake_hash,
          { "Hash", "pct.handshake.hash",
            FT_UINT16, BASE_HEX, VALS(pct_hash_type), 0x0,
            "PCT Hash", HFILL }
        },
        { &hf_pct_handshake_cert_spec,
          { "Cert Spec", "pct.handshake.certspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Certificate specification", HFILL }
        },
        { &hf_pct_handshake_cert,
          { "Cert", "pct.handshake.cert",
            FT_UINT16, BASE_HEX, VALS(pct_cert_type), 0x0,
            "PCT Certificate", HFILL }
        },
        { &hf_pct_handshake_exch_spec,
          { "Exchange Spec", "pct.handshake.exchspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Exchange specification", HFILL }
        },
        { &hf_pct_handshake_exch,
          { "Exchange", "pct.handshake.exch",
            FT_UINT16, BASE_HEX, VALS(pct_exch_type), 0x0,
            "PCT Exchange", HFILL }
        },
        { &hf_pct_handshake_sig,
          { "Sig Spec", "pct.handshake.sig",
            FT_UINT16, BASE_HEX, VALS(pct_sig_type), 0x0,
            "PCT Signature", HFILL }
        },
        { &hf_pct_msg_error_type,
          { "PCT Error Code", "pct.msg_error_code",
            FT_UINT16, BASE_HEX, VALS(pct_error_code), 0x0,
            NULL, HFILL }
        },
        { &hf_pct_handshake_server_cert,
          { "Server Cert", "pct.handshake.server_cert",
            FT_NONE, BASE_NONE, NULL , 0x0,
            "PCT Server Certificate", HFILL }
        },
        { &hf_ssl_segment_overlap,
          { "Segment overlap", "ssl.segment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }},

        { &hf_ssl_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "ssl.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL }},

        { &hf_ssl_segment_multiple_tails,
          { "Multiple tail segments found", "ssl.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the pdu", HFILL }},

        { &hf_ssl_segment_too_long_fragment,
          { "Segment too long", "ssl.segment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of the pdu", HFILL }},

        { &hf_ssl_segment_error,
          { "Reassembling error", "ssl.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembling error due to illegal segments", HFILL }},

        { &hf_ssl_segment_count,
          { "Segment count", "ssl.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssl_segment,
          { "SSL Segment", "ssl.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssl_segments,
          { "Reassembled SSL Segments", "ssl.segments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "SSL Segments", HFILL }},

        { &hf_ssl_reassembled_in,
          { "Reassembled PDU in frame", "ssl.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

        { &hf_ssl_reassembled_length,
          { "Reassembled PDU length", "ssl.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ssl,
        &ett_ssl_record,
        &ett_ssl_alert,
        &ett_ssl_handshake,
        &ett_ssl_heartbeat,
        &ett_ssl_cipher_suites,
        &ett_ssl_comp_methods,
        &ett_ssl_extension,
        &ett_ssl_extension_curves,
        &ett_ssl_extension_curves_point_formats,
        &ett_ssl_extension_npn,
        &ett_ssl_extension_reneg_info,
        &ett_ssl_extension_server_name,
        &ett_ssl_certs,
        &ett_ssl_cert_types,
        &ett_ssl_sig_hash_algs,
        &ett_ssl_sig_hash_alg,
        &ett_ssl_dnames,
        &ett_ssl_random,
        &ett_ssl_new_ses_ticket,
        &ett_ssl_keyex_params,
        &ett_ssl_cert_status,
        &ett_ssl_ocsp_resp,
        &ett_pct_cipher_suites,
        &ett_pct_hash_suites,
        &ett_pct_cert_suites,
        &ett_pct_exch_suites,
        &ett_ssl_segments,
        &ett_ssl_segment
    };

    /* Register the protocol name and description */
    proto_ssl = proto_register_protocol("Secure Sockets Layer",
                                        "SSL", "ssl");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_ssl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    {
        module_t *ssl_module = prefs_register_protocol(proto_ssl, proto_reg_handoff_ssl);

#ifdef HAVE_LIBGNUTLS

        static uat_field_t sslkeylist_uats_flds[] = {
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, ipaddr, "IP address", ssldecrypt_uat_fld_ip_chk_cb, "IPv4 or IPv6 address"),
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, port, "Port", ssldecrypt_uat_fld_port_chk_cb, "Port Number"),
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, protocol, "Protocol", ssldecrypt_uat_fld_protocol_chk_cb, "Protocol"),
            UAT_FLD_FILENAME_OTHER(sslkeylist_uats, keyfile, "Key File", ssldecrypt_uat_fld_fileopen_chk_cb, "Private keyfile."),
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, password,"Password", ssldecrypt_uat_fld_password_chk_cb, "Password (for PCKS#12 keyfile)"),
            UAT_END_FIELDS
        };

        ssldecrypt_uat = uat_new("SSL Decrypt",
            sizeof(ssldecrypt_assoc_t),
            "ssl_keys",                     /* filename */
            TRUE,                           /* from_profile */
            (void*) &sslkeylist_uats,       /* data_ptr */
            &nssldecrypt,                   /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* Help section (currently a wiki page) */
            ssldecrypt_copy_cb,
            ssldecrypt_update_cb,
            ssldecrypt_free_cb,
            ssl_parse_uat,
            sslkeylist_uats_flds);

        prefs_register_uat_preference(ssl_module, "key_table",
            "RSA keys list",
            "A table of RSA keys for SSL decryption",
            ssldecrypt_uat);

        prefs_register_filename_preference(ssl_module, "debug_file", "SSL debug file",
            "Redirect SSL debug to file name; leave empty to disable debugging, "
            "or use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr\n",
            &ssl_debug_file_name);

        prefs_register_string_preference(ssl_module, "keys_list", "RSA keys list (deprecated)",
             "Semicolon-separated list of private RSA keys used for SSL decryption. "
             "Used by versions of Wireshark prior to 1.6",
             &ssl_keys_list);
#endif

        prefs_register_bool_preference(ssl_module,
             "desegment_ssl_records",
             "Reassemble SSL records spanning multiple TCP segments",
             "Whether the SSL dissector should reassemble SSL records spanning multiple TCP segments. "
             "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
             &ssl_desegment);
        prefs_register_bool_preference(ssl_module,
             "desegment_ssl_application_data",
             "Reassemble SSL Application Data spanning multiple SSL records",
             "Whether the SSL dissector should reassemble SSL Application Data spanning multiple SSL records. ",
             &ssl_desegment_app_data);
        prefs_register_bool_preference(ssl_module,
             "ignore_ssl_mac_failed",
             "Message Authentication Code (MAC), ignore \"mac failed\"",
             "For troubleshooting ignore the mac check result and decrypt also if the Message Authentication Code (MAC) fails.",
             &ssl_ignore_mac_failed);
#ifdef HAVE_LIBGNUTLS
        prefs_register_string_preference(ssl_module, "psk", "Pre-Shared-Key",
             "Pre-Shared-Key as HEX string, should be 0 to 16 bytes",
             &ssl_psk);

        prefs_register_filename_preference(ssl_module, "keylog_file", "(Pre)-Master-Secret log filename",
             "The filename of a file which contains a list of \n"
             "(pre-)master secrets in one of the following formats:\n"
             "\n"
             "RSA <EPMS> <PMS>\n"
             "RSA Session-ID:<SSLID> Master-Key:<MS>\n"
             "\n"
             "Where:\n"
             "<EPMS> = First 8 bytes of the Encrypted PMS\n"
             "<PMS> = The Pre-Master-Secret (PMS)\n"
             "<SSLID> = The SSL Session ID\n"
             "<MS> = The Master-Secret (MS)\n"
             "\n"
             "(All fields are in hex notation)",
             &ssl_keylog_filename);
#endif
    }

    /* heuristic dissectors for any premable e.g. CredSSP before RDP */
    register_heur_dissector_list("ssl", &ssl_heur_subdissector_list);

    register_dissector("ssl", dissect_ssl, proto_ssl);
    ssl_handle = find_dissector("ssl");

    ssl_associations = g_tree_new(ssl_association_cmp);

    register_init_routine(ssl_init);
    ssl_lib_init();
    ssl_tap = register_tap("ssl");
    ssl_debug_printf("proto_register_ssl: registered tap %s:%d\n",
        "ssl", ssl_tap);
}

/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_ssl(void)
{

    /* parse key list */
    ssl_parse_uat();
    ssl_parse_old_keys();
}

void
ssl_dissector_add(guint port, const gchar *protocol, gboolean tcp)
{
    SslAssociation *assoc;

    assoc = ssl_association_find(ssl_associations, port, tcp);
    if (assoc) {
        ssl_association_remove(ssl_associations, assoc);
    }

    ssl_association_add(ssl_associations, ssl_handle, port, protocol, tcp, FALSE);
}

void
ssl_dissector_delete(guint port, const gchar *protocol, gboolean tcp)
{
    SslAssociation *assoc;

    assoc = ssl_association_find(ssl_associations, port, tcp);
    if (assoc && (assoc->handle == find_dissector(protocol))) {
        ssl_association_remove(ssl_associations, assoc);
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
