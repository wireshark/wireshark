/* packet-ssl.c
 * Routines for ssl dissection
 * Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
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

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/uat.h>
#include <epan/addr_resolv.h>
#include <epan/follow.h>
#include <epan/exported_pdu.h>
#include <epan/proto_data.h>
#include <epan/decode_as.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/str_util.h>
#include "packet-tcp.h"
#include "packet-x509af.h"
#include "packet-ocsp.h"
#include "packet-ssl.h"
#include "packet-ssl-utils.h"

void proto_register_ssl(void);

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
static gint exported_pdu_tap                  = -1;
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
static gint hf_ssl_alert_message              = -1;
static gint hf_ssl_alert_message_level        = -1;
static gint hf_ssl_alert_message_description  = -1;
static gint hf_ssl_handshake_protocol         = -1;
static gint hf_ssl_handshake_type             = -1;
static gint hf_ssl_handshake_length           = -1;
static gint hf_ssl_handshake_cert_status      = -1;
static gint hf_ssl_handshake_cert_status_type = -1;
static gint hf_ssl_handshake_cert_status_len  = -1;
static gint hf_ssl_handshake_npn_selected_protocol_len = -1;
static gint hf_ssl_handshake_npn_selected_protocol = -1;
static gint hf_ssl_handshake_npn_padding_len = -1;
static gint hf_ssl_handshake_npn_padding = -1;
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

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ssl_pct_client_version = -1;
static int hf_ssl_pct_pad = -1;
static int hf_ssl_pct_client_session_id_data = -1;
static int hf_ssl_pct_challenge_data = -1;
static int hf_ssl_pct_ch_offset = -1;
static int hf_ssl_pct_cipher_specs_length = -1;
static int hf_ssl_pct_hash_specs_length = -1;
static int hf_ssl_pct_cert_specs_length = -1;
static int hf_ssl_pct_exch_specs_length = -1;
static int hf_ssl_pct_iv_length = -1;
static int hf_ssl_pct_encryption_key_length = -1;
static int hf_ssl_pct_mac_key_length_in_bits = -1;
static int hf_ssl_pct_iv_data = -1;
static int hf_ssl_pct_server_version = -1;
static int hf_ssl_pct_sh_restart_session_ok_flag = -1;
static int hf_ssl_pct_sh_client_auth_req_flag = -1;
static int hf_ssl_pct_connection_id_data = -1;
static int hf_ssl_pct_server_certificate_length = -1;
static int hf_ssl_pct_client_cert_specs_length = -1;
static int hf_ssl_pct_client_sig_specs_length = -1;
static int hf_ssl_pct_response_length = -1;
static int hf_ssl_pct_client_cert_specs = -1;
static int hf_ssl_pct_client_signature = -1;
static int hf_ssl_pct_server_response = -1;
static int hf_ssl_pct_clear_key_length = -1;
static int hf_ssl_pct_encrypted_key_length = -1;
static int hf_ssl_pct_verify_prelude_length = -1;
static int hf_ssl_pct_client_cert_length = -1;
static int hf_ssl_pct_clear_key_data = -1;
static int hf_ssl_pct_encrypted_key_data = -1;
static int hf_ssl_pct_verify_prelude_data = -1;
static int hf_ssl_pct_client_certificate_data = -1;
static int hf_ssl_pct_response_data = -1;
static int hf_ssl_pct_server_session_id_data = -1;
static int hf_ssl_pct_server_response_length = -1;
static int hf_ssl_pct_error_information_length = -1;
static int hf_ssl_pct_specs_mismatch_cipher = -1;
static int hf_ssl_pct_specs_mismatch_hash = -1;
static int hf_ssl_pct_specs_mismatch_cert = -1;
static int hf_ssl_pct_specs_mismatch_exch = -1;
static int hf_ssl_pct_specs_mismatch_client_cert = -1;
static int hf_ssl_pct_specs_mismatch_client_sig = -1;
static int hf_ssl_pct_error_information_data = -1;

static int hf_ssl_reassembled_in              = -1;
static int hf_ssl_reassembled_length          = -1;
static int hf_ssl_reassembled_data            = -1;
static int hf_ssl_segments                    = -1;
static int hf_ssl_segment                     = -1;
static int hf_ssl_segment_overlap             = -1;
static int hf_ssl_segment_overlap_conflict    = -1;
static int hf_ssl_segment_multiple_tails      = -1;
static int hf_ssl_segment_too_long_fragment   = -1;
static int hf_ssl_segment_error               = -1;
static int hf_ssl_segment_count               = -1;
static int hf_ssl_segment_data                = -1;

static gint hf_ssl_heartbeat_message                 = -1;
static gint hf_ssl_heartbeat_message_type            = -1;
static gint hf_ssl_heartbeat_message_payload_length  = -1;
static gint hf_ssl_heartbeat_message_payload         = -1;
static gint hf_ssl_heartbeat_message_padding         = -1;

static ssl_hfs_t ssl_hfs = { -1, -1 };

/* Initialize the subtree pointers */
static gint ett_ssl                   = -1;
static gint ett_ssl_record            = -1;
static gint ett_ssl_alert             = -1;
static gint ett_ssl_handshake         = -1;
static gint ett_ssl_heartbeat         = -1;
static gint ett_ssl_certs             = -1;
static gint ett_ssl_cert_status       = -1;
static gint ett_ssl_ocsp_resp         = -1;
static gint ett_pct_cipher_suites     = -1;
static gint ett_pct_hash_suites       = -1;
static gint ett_pct_cert_suites       = -1;
static gint ett_pct_exch_suites       = -1;
static gint ett_ssl_segments          = -1;
static gint ett_ssl_segment           = -1;

static expert_field ei_ssl2_handshake_session_id_len_error = EI_INIT;
static expert_field ei_ssl3_heartbeat_payload_length = EI_INIT;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_ssl_pct_ch_offset = EI_INIT;
static expert_field ei_ssl_pct_server_version = EI_INIT;
static expert_field ei_ssl_ignored_unknown_record = EI_INIT;
static expert_field ei_ssl_pct_client_version = EI_INIT;

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
    &hf_ssl_reassembled_data,
    "Segments"
};

static SSL_COMMON_LIST_T(dissect_ssl3_hf);

static void
ssl_proto_tree_add_segment_data(
    proto_tree  *tree,
    tvbuff_t    *tvb,
    gint         offset,
    gint         length,
    const gchar *prefix)
{
    proto_tree_add_bytes_format(
        tree,
        hf_ssl_segment_data,
        tvb,
        offset,
        length,
        NULL,
        "%sSSL segment data (%u %s)",
        prefix != NULL ? prefix : "",
        length,
        plurality(length, "byte", "bytes"));
}


static ssl_master_key_map_t       ssl_master_key_map;
/* used by "Export SSL Session Keys" */
GHashTable *ssl_session_hash;
GHashTable *ssl_crandom_hash;

static GHashTable         *ssl_key_hash             = NULL;
static wmem_stack_t       *key_list_stack            = NULL;
static dissector_table_t   ssl_associations         = NULL;
static dissector_handle_t  ssl_handle               = NULL;
static StringInfo          ssl_compressed_data      = {NULL, 0};
static StringInfo          ssl_decrypted_data       = {NULL, 0};
static gint                ssl_decrypted_data_avail = 0;
static FILE               *ssl_keylog_file          = NULL;

static uat_t              *ssldecrypt_uat           = NULL;
static const gchar        *ssl_keys_list            = NULL;
static ssl_common_options_t ssl_options = { NULL, NULL};

/* List of dissectors to call for SSL data */
static heur_dissector_list_t ssl_heur_subdissector_list;

#ifdef HAVE_LIBGCRYPT
static const gchar *ssl_debug_file_name     = NULL;
#endif


/* Forward declaration we need below */
void proto_reg_handoff_ssl(void);

/* Desegmentation of SSL streams */
/* table to hold defragmented SSL streams */
static reassembly_table ssl_reassembly_table;

/* initialize/reset per capture state data (ssl sessions cache) */
static void
ssl_init(void)
{
    module_t *ssl_module = prefs_find_module("ssl");
    pref_t   *keys_list_pref;

    ssl_common_init(&ssl_master_key_map,
                    &ssl_decrypted_data, &ssl_compressed_data);
    reassembly_table_init(&ssl_reassembly_table,
                          &addresses_ports_reassembly_table_functions);
    ssl_debug_flush();

    /* for "Export SSL Session Keys" */
    ssl_session_hash = ssl_master_key_map.session;
    ssl_crandom_hash = ssl_master_key_map.crandom;

    /* We should have loaded "keys_list" by now. Mark it obsolete */
    if (ssl_module) {
        keys_list_pref = prefs_find_preference(ssl_module, "keys_list");
        if (! prefs_get_preference_obsolete(keys_list_pref)) {
            prefs_set_preference_obsolete(keys_list_pref);
        }
    }
}

static void
ssl_cleanup(void)
{
    if (key_list_stack != NULL) {
        wmem_destroy_stack(key_list_stack);
        key_list_stack = NULL;
    }
    reassembly_table_destroy(&ssl_reassembly_table);
    ssl_common_cleanup(&ssl_master_key_map, &ssl_keylog_file,
                       &ssl_decrypted_data, &ssl_compressed_data);

    /* should not be needed since the UI code prevents this from being accessed
     * when no file is open. Clear it anyway just to be sure. */
    ssl_session_hash = NULL;
    ssl_crandom_hash = NULL;
}

/* parse ssl related preferences (private keys and ports association strings) */
static void
ssl_parse_uat(void)
{
    guint            i, port;
    dissector_handle_t handle;

    ssl_set_debug(ssl_debug_file_name);

    if (ssl_key_hash)
    {
        g_hash_table_destroy(ssl_key_hash);
    }

    /* remove only associations created from key list */
    if (key_list_stack != NULL) {
        while (wmem_stack_count(key_list_stack) > 0) {
          port = GPOINTER_TO_UINT(wmem_stack_pop(key_list_stack));
          handle = dissector_get_uint_handle(ssl_associations, port);
          if (handle != NULL)
              ssl_association_remove("ssl.port", ssl_handle, handle, port, FALSE);
        }
    }
    /* parse private keys string, load available keys and put them in key hash*/
    ssl_key_hash = g_hash_table_new_full(ssl_private_key_hash,
            ssl_private_key_equal, g_free, ssl_private_key_free);


    if (nssldecrypt > 0) {
        if (key_list_stack == NULL)
            key_list_stack = wmem_stack_new(NULL);
        for (i = 0; i < nssldecrypt; i++) {
            ssldecrypt_assoc_t *ssl_uat = &(sslkeylist_uats[i]);
            ssl_parse_key_list(ssl_uat, ssl_key_hash, "ssl.port", ssl_handle, TRUE);
            if (key_list_stack)
                wmem_stack_push(key_list_stack, GUINT_TO_POINTER(atoi(ssl_uat->port)));
        }
    }

    ssl_debug_flush();
}

static void
ssl_parse_old_keys(void)
{
    gchar **old_keys, **parts, *err;
    gchar  *uat_entry;
    guint   i;

    /* Import old-style keys */
    if (ssldecrypt_uat && ssl_keys_list && ssl_keys_list[0]) {
        old_keys = wmem_strsplit(NULL, ssl_keys_list, ";", 0);
        for (i = 0; old_keys[i] != NULL; i++) {
            parts = wmem_strsplit(NULL, old_keys[i], ",", 5);
            if (parts[0] && parts[1] && parts[2] && parts[3]) {
                gchar *path = uat_esc(parts[3], (guint)strlen(parts[3]));
                const gchar *password = parts[4] ? parts[4] : "";
                uat_entry = wmem_strdup_printf(NULL, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
                                parts[0], parts[1], parts[2], path, password);
                g_free(path);
                if (!uat_load_str(ssldecrypt_uat, uat_entry, &err)) {
                    ssl_debug_printf("ssl_parse_old_keys: Can't load UAT string %s: %s\n",
                                     uat_entry, err);
                    g_free(err);
                }
                wmem_free(NULL, uat_entry);
            }
            wmem_free(NULL, parts);
        }
        wmem_free(NULL, old_keys);
    }
}


static gboolean
ssl_follow_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *ssl)
{
    follow_info_t *      follow_info = (follow_info_t*) tapdata;
    follow_record_t * follow_record = NULL;
    const SslDataInfo *        appl_data = NULL;
    const SslPacketInfo *      pi = (const SslPacketInfo*)ssl;
    show_stream_t        from = FROM_CLIENT;

    /* Skip packets without decrypted payload data. */
    if (!pi || !pi->appl_data) return FALSE;

    /* Compute the packet's sender. */
    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        copy_address(&follow_info->client_ip, &pinfo->src);
    }
    if (addresses_equal(&follow_info->client_ip, &pinfo->src) &&
            follow_info->client_port == pinfo->srcport) {
        from = FROM_CLIENT;
    } else {
        from = FROM_SERVER;
    }

    for (appl_data = pi->appl_data; appl_data != NULL; appl_data = appl_data->next) {

        /* TCP segments that contain the end of two or more SSL PDUs will be
           queued to SSL taps for each of those PDUs. Therefore a single
           packet could be processed by this SSL tap listener multiple times.
           The following test handles that scenario by treating the
           follow_info->bytes_written[] values as the next expected
           appl_data->seq. Any appl_data instances that fall below that have
           already been processed and must be skipped. */
        if (appl_data->seq < follow_info->bytes_written[from]) continue;

        /* Allocate a follow_record_t to hold the current appl_data
           instance's decrypted data. Even though it would be possible to
           consolidate multiple appl_data instances into a single record, it is
           beneficial to use a one-to-one mapping. This affords the Follow
           Stream dialog view modes (ASCII, EBCDIC, Hex Dump, C Arrays, Raw)
           the opportunity to accurately reflect SSL PDU boundaries. Currently
           the Hex Dump view does by starting a new line, and the C Arrays
           view does by starting a new array declaration. */
        follow_record = g_new(follow_record_t,1);

        follow_record->is_server = (from == FROM_SERVER);
        follow_record->packet_num = pinfo->num;

        follow_record->data = g_byte_array_sized_new(appl_data->plain_data.data_len);
        follow_record->data = g_byte_array_append(follow_record->data,
                                              appl_data->plain_data.data,
                                              appl_data->plain_data.data_len);

        /* Append the record to the follow_info structure. */
        follow_info->payload = g_list_append(follow_info->payload, follow_record);
        follow_info->bytes_written[from] += appl_data->plain_data.data_len;
    }

    return FALSE;
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
                                SslSession *session, gint is_from_server,
                                gboolean *need_desegmentation,
                                SslDecryptSession *conv_data,
                                const gboolean first_record_in_frame);

/* alert message dissector */
static void dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               const SslSession *session);

/* handshake protocol dissector */
static void dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint32 record_length,
                                   SslSession *session, gint is_from_server,
                                   SslDecryptSession *conv_data, const guint8 content_type);

/* heartbeat message dissector */
static void dissect_ssl3_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   const SslSession *session, guint32 record_length,
                                   gboolean decrypted);

static void dissect_ssl3_hnd_cert_status(tvbuff_t *tvb,
                                         proto_tree *tree,
                                         guint32 offset,
                                         packet_info *pinfo);

static void dissect_ssl3_hnd_encrypted_exts(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            guint32 offset);

/*
 * SSL version 2 dissectors
 *
 */

/* record layer dissector */
static gint dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset,
                                SslSession *session,
                                gboolean *need_desegmentation,
                                SslDecryptSession *ssl, gboolean first_record_in_frame);

/* client hello dissector */
static void dissect_ssl2_hnd_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree,
                                          guint32 offset,
                                          SslDecryptSession *ssl);

static void dissect_pct_msg_client_hello(tvbuff_t *tvb, packet_info *pinfo,
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
static gint  ssl_is_valid_ssl_version(const guint16 version);
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
static int
dissect_ssl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    conversation_t    *conversation;
    proto_item        *ti;
    proto_tree        *ssl_tree;
    guint32            offset;
    gboolean           first_record_in_frame;
    gboolean           need_desegmentation;
    SslDecryptSession *ssl_session;
    SslSession        *session;
    gint               is_from_server;

    ti = NULL;
    ssl_tree   = NULL;
    offset = 0;
    first_record_in_frame = TRUE;
    ssl_session = NULL;


    if (tvb_captured_length(tvb) > 4) {
        const guint8 *tmp = tvb_get_ptr(tvb, 0, 4);
        if (g_ascii_isprint(tmp[0]) &&
                g_ascii_isprint(tmp[1]) &&
                g_ascii_isprint(tmp[2]) &&
                g_ascii_isprint(tmp[3])) {
            /* it is extremely unlikely that real SSL traffic starts with four
             * printable ascii characters; this looks like it's unencrypted
             * text, so assume it's not ours (SSL does have some unencrypted
             * text fields in certain packets, but you'd have to get very
             * unlucky with TCP fragmentation to have one of those fields at the
             * beginning of a TCP payload at the beginning of the capture where
             * reassembly hasn't started yet) */
            return 0;
        }
    }

    ssl_debug_printf("\ndissect_ssl enter frame #%u (%s)\n", pinfo->num, (pinfo->fd->flags.visited)?"already visited":"first time");

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
    ssl_session = ssl_get_session(conversation, ssl_handle);
    session = &ssl_session->session;
    is_from_server = ssl_packet_from_server(session, ssl_associations, pinfo);

    if (session->last_nontls_frame != 0 &&
        session->last_nontls_frame >= pinfo->num) {
        /* This conversation started at a different protocol and STARTTLS was
         * used, but this packet comes too early. */
        return 0;
    }

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
        switch (session->version) {
        case SSLV2_VERSION:
        case PCT_VERSION:
            offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                         offset, session,
                                         &need_desegmentation,
                                         ssl_session,
                                         first_record_in_frame);
            break;

        case SSLV3_VERSION:
        case TLSV1_VERSION:
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
            /* SSLv3/TLS record headers need at least 1+2+2 = 5 bytes. */
            if (tvb_reported_length_remaining(tvb, offset) < 5) {
                if (ssl_desegment && pinfo->can_desegment) {
                    pinfo->desegment_offset = offset;
                    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                    need_desegmentation = TRUE;
                } else {
                    /* Not enough bytes available. Stop here. */
                    offset = tvb_reported_length(tvb);
                }
                break;
            }

            /* the version tracking code works too well ;-)
             * at times, we may visit a v2 client hello after
             * we already know the version of the connection;
             * work around that here by detecting and calling
             * the v2 dissector instead
             */
            if (ssl_is_v2_client_hello(tvb, offset))
            {
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, session,
                                             &need_desegmentation,
                                             ssl_session,
                                             first_record_in_frame);
            }
            else
            {
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, session, is_from_server,
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
                                             offset, session,
                                             &need_desegmentation,
                                             ssl_session,
                                             first_record_in_frame);
            }
            else if (ssl_looks_like_sslv3(tvb, offset))
            {
                /* looks like sslv3 or tls */
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, session, is_from_server,
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
                offset = tvb_reported_length(tvb);
                col_append_str(pinfo->cinfo, COL_INFO,
                                   "Continuation Data");

                /* Set the protocol column */
                col_set_str(pinfo->cinfo, COL_PROTOCOL,
                         val_to_str_const(session->version, ssl_version_short_names, "SSL"));
            }
            break;
        }

        /* Desegmentation return check */
        if (need_desegmentation) {
          ssl_debug_printf("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                           offset, tvb_reported_length_remaining(tvb, offset));
          tap_queue_packet(ssl_tap, pinfo, p_get_proto_data(wmem_file_scope(), pinfo, proto_ssl, 0));
          return tvb_captured_length(tvb);
        }

        /* set up for next record in frame, if any */
        first_record_in_frame = FALSE;
    }

    col_set_fence(pinfo->cinfo, COL_INFO);

    ssl_debug_flush();

    tap_queue_packet(ssl_tap, pinfo, p_get_proto_data(wmem_file_scope(), pinfo, proto_ssl, 0));

    return tvb_captured_length(tvb);
}

static gint
decrypt_ssl3_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset,
        guint32 record_length, guint8 content_type, SslDecryptSession *ssl,
        gboolean save_plaintext)
{
    gint        ret;
    gint        direction;
    StringInfo *data_for_iv;
    gint        data_for_iv_len;
    SslDecoder *decoder;

    ret = 0;
    /* if we can decrypt and decryption was a success
     * add decrypted data to this packet info */
    ssl_debug_printf("decrypt_ssl3_record: app_data len %d, ssl state 0x%02X\n",
        record_length, ssl->state);
    direction = ssl_packet_from_server(&ssl->session, ssl_associations, pinfo);

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
    ssl_data_set(data_for_iv, (const guchar*)tvb_get_ptr(tvb, offset + record_length - data_for_iv_len, data_for_iv_len), data_for_iv_len);

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
        ssl_data_set(data_for_iv, (const guchar*)tvb_get_ptr(tvb, offset + record_length - data_for_iv_len, data_for_iv_len), data_for_iv_len);
    }
    if (ret && save_plaintext) {
      ssl_add_data_info(proto_ssl, pinfo, ssl_decrypted_data.data, ssl_decrypted_data_avail,  tvb_raw_offset(tvb)+offset, decoder->flow);
    }
    return ret;
}

static void
process_ssl_payload(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, SslSession *session,
                    dissector_handle_t app_handle_port);

static void
desegment_ssl(tvbuff_t *tvb, packet_info *pinfo, int offset,
              guint32 seq, guint32 nxtseq,
              SslSession *session,
              proto_tree *root_tree, proto_tree *tree,
              SslFlow *flow, dissector_handle_t app_handle_port)
{
    fragment_head *ipfd_head;
    gboolean       must_desegment;
    gboolean       called_dissector;
    int            another_pdu_follows;
    gboolean       another_segment_in_frame = FALSE;
    int            deseg_offset;
    guint32        deseg_seq;
    gint           nbytes;
    proto_item    *item;
    proto_item    *frag_tree_item;
    proto_item    *ssl_tree_item;
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
    if ((msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32(flow->multisegment_pdus, seq))) {
        const char *prefix;

        if (msp->first_frame == pinfo->num) {
            prefix = "";
            col_set_str(pinfo->cinfo, COL_INFO, "[SSL segment of a reassembled PDU]");
        } else {
            prefix = "Retransmitted ";
        }

        nbytes = tvb_reported_length_remaining(tvb, offset);
        ssl_proto_tree_add_segment_data(tree, tvb, offset, nbytes, prefix);
        return;
    }

    /* Else, find the most previous PDU starting before this sequence number */
    msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(flow->multisegment_pdus, seq-1);
    if (msp && msp->seq <= seq && msp->nxtpdu > seq) {
        int len;

        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame = pinfo->num;
            msp->last_frame_time = pinfo->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        if (msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /* The dissector asked for the entire segment */
            len = MAX(0, tvb_reported_length_remaining(tvb, offset));
        } else {
            len = MIN(nxtseq, msp->nxtpdu) - seq;
        }

        ipfd_head = fragment_add(&ssl_reassembly_table, tvb, offset,
                                 pinfo, msp->first_frame, NULL,
                                 seq - msp->seq,
                                 len, (LT_SEQ (nxtseq,msp->nxtpdu)));

        if (msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            msp->flags &= (~MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT);

            /* If we consumed the entire segment there is no
             * other pdu starting anywhere inside this segment.
             * So update nxtpdu to point at least to the start
             * of the next segment.
             * (If the subdissector asks for even more data we
             * will advance nxtpdu even further later down in
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
        process_ssl_payload(tvb, offset, pinfo, tree, session, app_handle_port);
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
        if (ipfd_head->reassembled_in == pinfo->num &&
            nxtseq < ipfd_head->datalen) {
            /*
             * This is *not* the last segment. It is part of a PDU in the same
             * frame, so no another PDU can follow this one.
             * Do not reassemble SSL yet, it will be done in the final segment.
             * Clear the Info column and avoid displaying [SSL segment of a
             * reassembled PDU], the payload dissector will typically set it.
             * (This is needed here for the second pass.)
             */
            another_pdu_follows = 0;
            col_clear(pinfo->cinfo, COL_INFO);
            another_segment_in_frame = TRUE;
        } else if (ipfd_head->reassembled_in == pinfo->num) {
            /*
             * OK, this is the last segment of the PDU and also the
             * last segment in this frame.
             * Let's call the subdissector with the desegmented
             * data.
             */
            tvbuff_t *next_tvb;
            int old_len;

            /*
             * Reset column in case multiple SSL segments form the
             * PDU and this last SSL segment is not in the first TCP segment of
             * this frame.
             * XXX prevent clearing the column if the last layer is not SSL?
             */
            /* Clear column during the first pass. */
            col_clear(pinfo->cinfo, COL_INFO);

            /* create a new TVB structure for desegmented data */
            next_tvb = tvb_new_chain(tvb, ipfd_head->tvb_data);

            /* add desegmented data to the data source list */
            add_new_data_source(pinfo, next_tvb, "Reassembled SSL");

            /* call subdissector */
            process_ssl_payload(next_tvb, 0, pinfo, tree, session, app_handle_port);
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
                fragment_set_partial_reassembly(&ssl_reassembly_table,
                                                pinfo, msp->first_frame, NULL);
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
                ssl_proto_tree_add_segment_data(tree, tvb, offset, nbytes, NULL);

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
                     * relative to the beginning of
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
            fragment_add(&ssl_reassembly_table, tvb, deseg_offset,
                         pinfo, msp->first_frame, NULL,
                         0, nxtseq - deseg_seq,
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
        if (!another_segment_in_frame && pinfo->desegment_offset == 0) {
            /*
             * It couldn't, in fact, dissect any of it (the
             * first byte it couldn't dissect is at an offset
             * of "pinfo->desegment_offset" from the beginning
             * of the payload, and that's 0).
             * Just mark this as SSL.
             */
            col_set_str(pinfo->cinfo, COL_PROTOCOL,
                    val_to_str_const(session->version, ssl_version_short_names, "SSL"));
            col_set_str(pinfo->cinfo, COL_INFO, "[SSL segment of a reassembled PDU]");
        }

        /*
         * Show what's left in the packet as just raw TCP segment
         * data.
         * XXX - remember what protocol the last subdissector
         * was, and report it as a continuation of that, instead?
         */
        nbytes = tvb_reported_length_remaining(tvb, deseg_offset);
        ssl_proto_tree_add_segment_data(tree, tvb, deseg_offset, nbytes, NULL);
    }
    pinfo->can_desegment = 0;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    if (another_pdu_follows) {
        /* there was another pdu following this one. */
        pinfo->can_desegment=2;
        /* we also have to prevent the dissector from changing the
         * PROTOCOL and INFO colums since what follows may be an
         * incomplete PDU and we don't want it be changed back from
         *  <Protocol>   to <TCP>
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    }
}

static void
export_pdu_packet(tvbuff_t *tvb, packet_info *pinfo, guint8 tag, const gchar *name)
{
    exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, name, tag);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;

    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
}

static void
process_ssl_payload(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, SslSession *session,
                    dissector_handle_t app_handle_port)
{
    tvbuff_t *next_tvb;
    heur_dtbl_entry_t *hdtbl_entry;
    guint16 saved_match_port;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /* If the appdata proto is not yet known (no STARTTLS), try heuristics
     * first, then ports-based dissectors. Port 443 is too overloaded... */
    if (!session->app_handle) {
        /* The heuristics dissector should set the app_handle if it wants to be
         * called in the future. */
        if (dissector_try_heuristic(ssl_heur_subdissector_list, next_tvb,
                                    pinfo, proto_tree_get_root(tree), &hdtbl_entry,
                                    &session->app_handle)) {
            ssl_debug_printf("%s: found heuristics dissector %s, app_handle is %p (%s)\n",
                             G_STRFUNC, hdtbl_entry->short_name,
                             (void *)session->app_handle,
                             dissector_handle_get_dissector_name(session->app_handle));
            if (have_tap_listener(exported_pdu_tap)) {
                export_pdu_packet(next_tvb, pinfo, EXP_PDU_TAG_HEUR_PROTO_NAME, hdtbl_entry->short_name);
            }
            return;
        }
        if (app_handle_port) {
            /* Heuristics failed, just try the port-based dissector. */
            ssl_debug_printf("%s: no heuristics dissector, falling back to "
                             "handle %p (%s)\n", G_STRFUNC,
                             (void *)app_handle_port,
                             dissector_handle_get_dissector_name(app_handle_port));
            session->app_handle = app_handle_port;
        } else {
            /* No heuristics, no port-based proto, unknown protocol. */
            ssl_debug_printf("%s: no appdata dissector found\n", G_STRFUNC);
            return;
        }
    }

    ssl_debug_printf("%s: found handle %p (%s)\n", G_STRFUNC,
                     (void *)session->app_handle,
                     dissector_handle_get_dissector_name(session->app_handle));

    if (have_tap_listener(exported_pdu_tap)) {
        export_pdu_packet(next_tvb, pinfo, EXP_PDU_TAG_PROTO_NAME,
                          dissector_handle_get_dissector_name(session->app_handle));
    }
    saved_match_port = pinfo->match_uint;
    if (ssl_packet_from_server(session, ssl_associations, pinfo)) {
        pinfo->match_uint = pinfo->srcport;
    } else {
        pinfo->match_uint = pinfo->destport;
    }
    call_dissector(session->app_handle, next_tvb, pinfo, proto_tree_get_root(tree));
    pinfo->match_uint = saved_match_port;
}

static void
dissect_ssl_payload(tvbuff_t *tvb, packet_info *pinfo, int offset,
                    proto_tree *tree, SslSession *session,
                    dissector_handle_t app_handle_port)
{
    gboolean     save_fragmented;
    guint16      save_can_desegment;
    SslDataInfo *appl_data;
    tvbuff_t    *next_tvb;

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
        desegment_ssl(next_tvb, pinfo, 0, appl_data->seq, appl_data->nxtseq,
                      session, proto_tree_get_root(tree), tree,
                      appl_data->flow, app_handle_port);
    } else if (session->app_handle || app_handle_port) {
        /* No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame. */
        pinfo->can_desegment = 0;
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        process_ssl_payload(next_tvb, 0, pinfo, tree, session, app_handle_port);
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
                    SslSession *session, gint is_from_server,
                    gboolean *need_desegmentation,
                    SslDecryptSession *ssl, const gboolean first_record_in_frame)
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
    guint32         record_length;
    guint16         version;
    guint8          content_type;
    guint8          next_byte;
    proto_tree     *ti;
    proto_tree     *ssl_record_tree;
    guint32         available_bytes;

    ti = NULL;
    ssl_record_tree = NULL;

    available_bytes = tvb_reported_length_remaining(tvb, offset);

    /* TLS 1.0/1.1 just ignores unknown records - RFC 2246 chapter 6. The TLS Record Protocol */
    if ((session->version==TLSV1_VERSION ||
         session->version==TLSV1DOT1_VERSION ||
         session->version==TLSV1DOT2_VERSION) &&
        (available_bytes >=1 ) && !ssl_is_valid_content_type(tvb_get_guint8(tvb, offset))) {
        proto_tree_add_expert(tree, pinfo, &ei_ssl_ignored_unknown_record, tvb, offset, available_bytes);
        /* on second and subsequent records per frame
         * add a delimiter on info column
         */
        if (!first_record_in_frame) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }
        col_append_str(pinfo->cinfo, COL_INFO, "Ignored Unknown Record");
        col_set_str(pinfo->cinfo, COL_PROTOCOL, val_to_str_const(session->version, ssl_version_short_names, "SSL"));
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
                        val_to_str_const(session->version, ssl_version_short_names, "SSL"));

        return offset + 5 + record_length;
    }

    /* add the record layer subtree header */
    ti = proto_tree_add_item(tree, hf_ssl_record, tvb,
                             offset, 5 + record_length, ENC_NA);
    ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);

    /* show the one-byte content type */
    proto_tree_add_item(ssl_record_tree, hf_ssl_record_content_type,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* add the version */
    proto_tree_add_item(ssl_record_tree, hf_ssl_record_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* add the length */
    proto_tree_add_uint(ssl_record_tree, hf_ssl_record_length, tvb,
                        offset, 2, record_length);
    offset += 2;    /* move past length field itself */

    /*
     * if we don't already have a version set for this conversation,
     * but this message's version is authoritative (i.e., it's
     * not client_hello, then save the version to to conversation
     * structure and print the column version
     */
    next_byte = tvb_get_guint8(tvb, offset);
    if (session->version == SSL_VER_UNKNOWN)
        ssl_try_set_version(session, ssl, content_type, next_byte, FALSE, version);

    /* on second and subsequent records per frame
     * add a delimiter on info column
     */
    if (!first_record_in_frame) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        val_to_str_const(session->version, ssl_version_short_names, "SSL"));

    /*
     * now dissect the next layer
     */
    ssl_debug_printf("dissect_ssl3_record: content_type %d %s\n",content_type, val_to_str_const(content_type, ssl_31_content_type, "unknown"));

    /* PAOLO try to decrypt each record (we must keep ciphers "in sync")
     * store plain text only for app data */

    switch ((ContentType) content_type) {
    case SSL_ID_CHG_CIPHER_SPEC:
        col_append_str(pinfo->cinfo, COL_INFO, "Change Cipher Spec");
        ssl_dissect_change_cipher_spec(&dissect_ssl3_hf, tvb, pinfo,
                                       ssl_record_tree, offset, session,
                                       is_from_server, ssl);
        if (ssl) {
            ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file,
                             &ssl_master_key_map);
            ssl_finalize_decryption(ssl, &ssl_master_key_map);
            ssl_change_cipher(ssl, ssl_packet_from_server(session, ssl_associations, pinfo));
        }
        break;
    case SSL_ID_ALERT:
    {
        tvbuff_t *decrypted;

        if (ssl&&decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
          ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                  ssl_decrypted_data_avail, tvb_raw_offset(tvb)+offset);

        /* try to retrieve and use decrypted alert record, if any. */
        decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, tvb_raw_offset(tvb)+offset);
        if (decrypted) {
            add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_alert(decrypted, pinfo, ssl_record_tree, 0, session);
        } else {
            dissect_ssl3_alert(tvb, pinfo, ssl_record_tree, offset, session);
        }
        break;
    }
    case SSL_ID_HANDSHAKE:
    {
        tvbuff_t *decrypted;

        ssl_calculate_handshake_hash(ssl, tvb, offset, record_length);

        /* try to decrypt handshake record, if possible. Store decrypted
         * record for later usage. The offset is used as 'key' to identify
         * this record in the packet (we can have multiple handshake records
         * in the same frame) */
        if (ssl && decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
            ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                ssl_decrypted_data_avail, tvb_raw_offset(tvb)+offset);

        /* try to retrieve and use decrypted handshake record, if any. */
        decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, tvb_raw_offset(tvb)+offset);
        if (decrypted) {
            /* add desegmented data to the data source list */
            add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_handshake(decrypted, pinfo, ssl_record_tree, 0,
                                   tvb_reported_length(decrypted), session,
                                   is_from_server, ssl, content_type);
        } else {
            dissect_ssl3_handshake(tvb, pinfo, ssl_record_tree, offset,
                                   record_length, session, is_from_server, ssl,
                                   content_type);
        }
        break;
    }
    case SSL_ID_APP_DATA:
    {
        dissector_handle_t app_handle;

        if (ssl){
            decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, TRUE);
            /* if application data desegmentation is allowed and needed */
            /* if (ssl_desegment_app_data && *need_desegmentation)
                   ssl_desegment_ssl_app_data(ssl,pinfo);
             */
        }

        /* show on info column what we are decoding */
        col_append_str(pinfo->cinfo, COL_INFO, "Application Data");

        /* app_handle discovery is done here instead of dissect_ssl_payload()
         * because the protocol name needs to be displayed below. */
        app_handle = session->app_handle;
        if (!app_handle) {
            /* Unknown protocol handle, ssl_starttls_ack was not called before.
             * Try to find a port-based protocol and use it if there is no
             * heuristics dissector (see process_ssl_payload). */
            app_handle = dissector_get_uint_handle(ssl_associations, pinfo->srcport);
            if (!app_handle) app_handle = dissector_get_uint_handle(ssl_associations, pinfo->destport);
        }

        proto_item_set_text(ssl_record_tree,
           "%s Record Layer: %s Protocol: %s",
            val_to_str_const(session->version, ssl_version_short_names, "SSL"),
            val_to_str_const(content_type, ssl_31_content_type, "unknown"),
            app_handle ? dissector_handle_get_dissector_name(app_handle)
            : "Application Data");

        proto_tree_add_item(ssl_record_tree, hf_ssl_record_appdata, tvb,
                       offset, record_length, ENC_NA);

        dissect_ssl_payload(tvb, pinfo, offset, tree, session, app_handle);

        /* Set app proto again in case the heuristics found a different proto. */
        if (session->app_handle && session->app_handle != app_handle)
            proto_item_set_text(ssl_record_tree,
               "%s Record Layer: %s Protocol: %s",
                val_to_str_const(session->version, ssl_version_short_names, "SSL"),
                val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                dissector_handle_get_dissector_name(session->app_handle));

        break;
    }
    case SSL_ID_HEARTBEAT:
      {
        tvbuff_t *decrypted;

        if (ssl && decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
            ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                                ssl_decrypted_data_avail, tvb_raw_offset(tvb)+offset);

        /* try to retrieve and use decrypted handshake record, if any. */
        decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, tvb_raw_offset(tvb)+offset);
        if (decrypted) {
            add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_heartbeat(decrypted, pinfo, ssl_record_tree, 0, session, tvb_reported_length (decrypted), TRUE);
        } else {
            gboolean plaintext = TRUE;
            /* heartbeats before ChangeCipherSpec are unencrypted */
            if (ssl) {
                if (ssl_packet_from_server(session, ssl_associations, pinfo)) {
                    plaintext = ssl->server == NULL;
                } else {
                    plaintext = ssl->client == NULL;
                }
            }
            dissect_ssl3_heartbeat(tvb, pinfo, ssl_record_tree, offset, session, record_length, plaintext);
        }
        break;
      }
    }
    offset += record_length; /* skip to end of record */

    return offset;
}

/* dissects the alert message, filling in the tree */
static void
dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, guint32 offset,
                   const SslSession *session)
{
    /*     struct {
     *         AlertLevel level;
     *         AlertDescription description;
     *     } Alert;
     */
    proto_tree  *ti;
    proto_tree  *ssl_alert_tree;
    const gchar *level;
    const gchar *desc;
    guint8       byte;

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
    level = try_val_to_str(byte, ssl_31_alert_level);

    byte = tvb_get_guint8(tvb, offset+1); /* grab the desc byte */
    desc = try_val_to_str(byte, ssl_31_alert_description);

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
                                val_to_str_const(session->version, ssl_version_short_names, "SSL"),
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
                                val_to_str_const(session->version, ssl_version_short_names, "SSL"));
            proto_item_set_text(ssl_alert_tree,
                                "Alert Message: Encrypted Alert");
        }
    }
}


/* dissects the handshake protocol, filling the tree */
static void
dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 record_length, SslSession *session,
                       gint is_from_server,
                       SslDecryptSession *ssl, const guint8 content_type)
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
     *             case certificate_url:     CertificateURL;
     *             case certificate_status:  CertificateStatus;
     *             case encrypted_extensions:NextProtocolNegotiationEncryptedExtension;
     *         } body;
     *     } Handshake;
     */
    proto_tree  *ssl_hand_tree;
    const gchar *msg_type_str;
    guint8       msg_type;
    guint32      length;
    gboolean     first_iteration;
    proto_item  *ti;

    ssl_hand_tree   = NULL;
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
            msg_type_str = try_val_to_str(msg_type, ssl_31_handshake_type);
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

        /* set the label text on the record layer expanding node */
        if (first_iteration)
        {
            proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s",
                    val_to_str_const(session->version, ssl_version_short_names, "SSL"),
                    val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                    (msg_type_str!=NULL) ? msg_type_str :
                    "Encrypted Handshake Message");
        }
        else
        {
            proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s",
                    val_to_str_const(session->version, ssl_version_short_names, "SSL"),
                    val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                    "Multiple Handshake Messages");
        }

        /* add a subtree for the handshake protocol */
        ti = proto_tree_add_item(tree, hf_ssl_handshake_protocol, tvb,
                offset, length + 4, ENC_NA);
        ssl_hand_tree = proto_item_add_subtree(ti, ett_ssl_handshake);

        /* set the text label on the subtree node */
        proto_item_set_text(ssl_hand_tree, "Handshake Protocol: %s",
                (msg_type_str != NULL) ? msg_type_str :
                "Encrypted Handshake Message");

        /* if we don't have a valid handshake type, just quit dissecting */
        if (!msg_type_str)
            return;

        /* add nodes for the message type and message length */
        proto_tree_add_uint(ssl_hand_tree, hf_ssl_handshake_type,
                tvb, offset, 1, msg_type);
        offset += 1;
        proto_tree_add_uint(ssl_hand_tree, hf_ssl_handshake_length,
                tvb, offset, 3, length);
        offset += 3;

        /* now dissect the handshake message, if necessary */
        switch ((HandshakeType) msg_type) {
            case SSL_HND_HELLO_REQUEST:
                /* hello_request has no fields, so nothing to do! */
                break;

            case SSL_HND_CLIENT_HELLO:
                if (ssl) {
                    /* ClientHello is first packet so set direction */
                    ssl_set_server(session, &pinfo->dst, pinfo->ptype, pinfo->destport);
                }
                ssl_dissect_hnd_cli_hello(&dissect_ssl3_hf, tvb, pinfo,
                        ssl_hand_tree, offset, length, session, ssl,
                        NULL);
                break;

            case SSL_HND_SERVER_HELLO:
                ssl_dissect_hnd_srv_hello(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree,
                        offset, length, session, ssl, FALSE);
                break;

            case SSL_HND_HELLO_VERIFY_REQUEST:
                /* only valid for DTLS */
                break;

            case SSL_HND_NEWSESSION_TICKET:
                /* no need to load keylog file here as it only links a previous
                 * master key with this Session Ticket */
                ssl_dissect_hnd_new_ses_ticket(&dissect_ssl3_hf, tvb,
                        ssl_hand_tree, offset, ssl,
                        ssl_master_key_map.tickets);
                break;

            case SSL_HND_CERTIFICATE:
                ssl_dissect_hnd_cert(&dissect_ssl3_hf, tvb, ssl_hand_tree,
                        offset, pinfo, session, ssl, ssl_key_hash, is_from_server);
                break;

            case SSL_HND_SERVER_KEY_EXCHG:
                ssl_dissect_hnd_srv_keyex(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, length, session);
                break;

            case SSL_HND_CERT_REQUEST:
                ssl_dissect_hnd_cert_req(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, pinfo, session);
                break;

            case SSL_HND_SVR_HELLO_DONE:
                if (ssl)
                    ssl->state |= SSL_SERVER_HELLO_DONE;
                break;

            case SSL_HND_CERT_VERIFY:
                ssl_dissect_hnd_cli_cert_verify(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, session);
                break;

            case SSL_HND_CLIENT_KEY_EXCHG:
                ssl_dissect_hnd_cli_keyex(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, length, session);

                if (!ssl)
                    break;

                ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file,
                        &ssl_master_key_map);
                /* try to find master key from pre-master key */
                if (!ssl_generate_pre_master_secret(ssl, length, tvb, offset,
                            ssl_options.psk,
                            &ssl_master_key_map)) {
                    ssl_debug_printf("dissect_ssl3_handshake can't generate pre master secret\n");
                }
                break;

            case SSL_HND_FINISHED:
                ssl_dissect_hnd_finished(&dissect_ssl3_hf, tvb, ssl_hand_tree,
                        offset, session, &ssl_hfs);
                break;

            case SSL_HND_CERT_URL:
                ssl_dissect_hnd_cert_url(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset);
                break;

            case SSL_HND_CERT_STATUS:
                dissect_ssl3_hnd_cert_status(tvb, ssl_hand_tree, offset, pinfo);
                break;

            case SSL_HND_SUPPLEMENTAL_DATA:
                /* TODO: dissect this? */
                break;

            case SSL_HND_ENCRYPTED_EXTS:
                dissect_ssl3_hnd_encrypted_exts(tvb, ssl_hand_tree, offset);
                break;
        }

        offset += length;
        first_iteration = FALSE; /* set up for next pass, if any */
    }
}

/* dissects the heartbeat message, filling in the tree */
static void
dissect_ssl3_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       const SslSession *session, guint32 record_length,
                       gboolean decrypted)
{
    /*     struct {
     *         HeartbeatMessageType type;
     *         uint16 payload_length;
     *         opaque payload;
     *         opaque padding;
     *     } HeartbeatMessage;
     */

    proto_item  *ti;
    proto_tree  *tls_heartbeat_tree;
    const gchar *type;
    guint8       byte;
    guint16      payload_length;
    guint16      padding_length;

    tls_heartbeat_tree = NULL;

    if (tree) {
        ti = proto_tree_add_item(tree, hf_ssl_heartbeat_message, tvb,
                                 offset, record_length, ENC_NA);
        tls_heartbeat_tree = proto_item_add_subtree(ti, ett_ssl_heartbeat);
    }

    /*
     * set the record layer label
     */

    /* first lookup the names for the message type and the payload length */
    byte = tvb_get_guint8(tvb, offset);
    type = try_val_to_str(byte, tls_heartbeat_type);

    payload_length = tvb_get_ntohs(tvb, offset + 1);
    padding_length = record_length - 3 - payload_length;

    /* assume plaintext if the (expected) record size is smaller than the type
     * (1), length (2)[, payload] and padding (16) fields combined */
    if (record_length <= 19u || 3u + payload_length + 16 <= record_length) {
        decrypted = TRUE;
    }

    /* now set the text in the record layer line */
    if (type && decrypted) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat %s", type);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Heartbeat");
    }

    if (type && decrypted) {
        proto_item_set_text(tree, "%s Record Layer: Heartbeat "
                            "%s",
                            val_to_str_const(session->version, ssl_version_short_names, "SSL"),
                            type);
        proto_tree_add_item(tls_heartbeat_tree, hf_ssl_heartbeat_message_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        ti = proto_tree_add_uint(tls_heartbeat_tree, hf_ssl_heartbeat_message_payload_length,
                                 tvb, offset, 2, payload_length);
        offset += 2;
        if (3u + payload_length + 16 > record_length) {
            expert_add_info_format(pinfo, ti, &ei_ssl3_heartbeat_payload_length,
                                   "Invalid heartbeat payload length (%d)", payload_length);
            /* There is no room for padding... truncate the payload such that
             * the field can be selected (for the interested). */
            payload_length = record_length - 3;
            padding_length = 0;
            proto_item_append_text (ti, " (invalid, using %u to decode payload)", payload_length);
        }
        proto_tree_add_bytes_format(tls_heartbeat_tree, hf_ssl_heartbeat_message_payload,
                                    tvb, offset, payload_length,
                                    NULL, "Payload (%u byte%s)",
                                    payload_length,
                                    plurality(payload_length, "", "s"));
        offset += payload_length;
        if (padding_length)
            proto_tree_add_bytes_format(tls_heartbeat_tree, hf_ssl_heartbeat_message_padding,
                                        tvb, offset, padding_length,
                                        NULL, "Padding and HMAC (%u byte%s)",
                                        padding_length,
                                        plurality(padding_length, "", "s"));
    } else {
        proto_item_set_text(tree,
                            "%s Record Layer: Encrypted Heartbeat",
                            val_to_str_const(session->version, ssl_version_short_names, "SSL"));
        proto_item_set_text(tls_heartbeat_tree,
                            "Encrypted Heartbeat Message");
    }
}

static guint
dissect_ssl3_ocsp_response(tvbuff_t *tvb, proto_tree *tree,
                           guint32 offset, packet_info *pinfo)
{
    guint       cert_status_len;
    proto_item *ti;
    proto_tree *cert_status_tree;

    cert_status_len  = tvb_get_ntoh24(tvb, offset);
    ti = proto_tree_add_item(tree, hf_ssl_handshake_cert_status,
                                    tvb, offset, cert_status_len + 3,
                                    ENC_NA);
    cert_status_tree = proto_item_add_subtree(ti, ett_ssl_cert_status);

    proto_tree_add_item(cert_status_tree, hf_ssl_handshake_cert_status_len,
                        tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    if (cert_status_len > 0) {
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
        offset += cert_status_len;
    }

    return offset;
}

static void
dissect_ssl3_hnd_cert_status(tvbuff_t *tvb, proto_tree *tree,
                             guint32 offset, packet_info *pinfo)
{
    guint8      cert_status_type;

    cert_status_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_handshake_cert_status_type,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (cert_status_type) {
    case SSL_HND_CERT_STATUS_TYPE_OCSP:
        dissect_ssl3_ocsp_response(tvb, tree, offset, pinfo);
        break;
    case SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI:
        {
            gint32 list_len;

            list_len = tvb_get_ntoh24(tvb, offset);
            offset += 3;

            while (list_len > 0) {
                guint32 prev_offset = offset;
                offset = dissect_ssl3_ocsp_response(tvb, tree, offset, pinfo);
                list_len -= offset - prev_offset;
            }
            break;
        }
    }
}

/* based on https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04 */
static void
dissect_ssl3_hnd_encrypted_exts(tvbuff_t *tvb, proto_tree *tree,
                                guint32 offset)
{
    guint8       selected_protocol_len;
    guint8       padding_len;

    selected_protocol_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_handshake_npn_selected_protocol_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_ssl_handshake_npn_selected_protocol,
        tvb, offset, selected_protocol_len, ENC_ASCII|ENC_NA);
    offset += selected_protocol_len;

    padding_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_handshake_npn_padding_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_ssl_handshake_npn_padding,
        tvb, offset, padding_len, ENC_NA);
}

/*********************************************************************
 *
 * SSL version 2 Dissectors
 *
 *********************************************************************/


/* record layer dissector */
static gint
dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint32 offset, SslSession *session,
                    gboolean *need_desegmentation,
                    SslDecryptSession *ssl, gboolean first_record_in_frame)
{
    guint32      initial_offset;
    guint8       byte;
    guint8       record_length_length;
    guint32      record_length;
    gint         is_escape;
    gint16       padding_length;
    guint8       msg_type;
    const gchar *msg_type_str;
    guint32      available_bytes;
    proto_item  *ti;
    proto_tree  *ssl_record_tree;

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

    available_bytes = tvb_reported_length_remaining(tvb, offset);

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
    switch (record_length_length) {
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
    if (session->version == SSL_VER_UNKNOWN)
    {
        if (ssl_looks_like_valid_pct_handshake(tvb,
                                               (initial_offset +
                                                record_length_length),
                                               record_length)) {
            session->version = PCT_VERSION;
        }
        else if (msg_type >= 2 && msg_type <= 8)
        {
            session->version = SSLV2_VERSION;
        }
    }

    /* if we get here, but don't have a version set for the
     * conversation, then set a version for just this frame
     * (e.g., on a client hello)
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                    (session->version == PCT_VERSION) ? "PCT" : "SSLv2");

    /* see if the msg_type is valid; if not the payload is
     * probably encrypted, so note that fact and bail
     */
    msg_type_str = try_val_to_str(msg_type,
                                (session->version == PCT_VERSION)
                                ? pct_msg_types : ssl_20_msg_types);
    if (!msg_type_str
        || ((session->version != PCT_VERSION) &&
            !ssl_looks_like_valid_v2_handshake(tvb, initial_offset
                               + record_length_length,
                               record_length))
        || ((session->version == PCT_VERSION) &&
            !ssl_looks_like_valid_pct_handshake(tvb, initial_offset
                               + record_length_length,
                               record_length)))
    {
        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                (session->version == PCT_VERSION)
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
                                (session->version == PCT_VERSION)
                                ? "PCT" : "SSLv2",
                                msg_type_str);
        }
    }

    /* We have a valid message type, so move forward, filling in the
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
                            (session->version == PCT_VERSION)
                            ? hf_pct_msg_type : hf_ssl2_msg_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;                   /* move past msg_type byte */

    if (session->version != PCT_VERSION)
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
            dissect_pct_msg_client_hello(tvb, pinfo, ssl_record_tree, offset);
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
                              SslDecryptSession *ssl)
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

    proto_item *ti;
    proto_tree *cs_tree;
    cs_tree=0;

    version = tvb_get_ntohs(tvb, offset);
    if (!ssl_is_valid_ssl_version(version))
    {
        /* invalid version; probably encrypted data */
        return;
    }

    if (ssl) {
      ssl_set_server(&ssl->session, &pinfo->dst, pinfo->ptype, pinfo->destport);
    }

    /* show the version */
    proto_tree_add_item(tree, dissect_ssl3_hf.hf.hs_client_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    cipher_spec_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_cipher_spec_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    session_id_length = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(tree, hf_ssl2_handshake_session_id_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    if (session_id_length > SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES) {
        expert_add_info_format(pinfo, ti, &ei_ssl2_handshake_session_id_len_error,
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
        ti = proto_tree_add_none_format(tree, dissect_ssl3_hf.hf.hs_cipher_suites,
                                        tvb, offset, cipher_spec_length,
                                        "Cipher Specs (%u specs)",
                                        cipher_spec_length/3);

        /* make this a subtree and expand the actual specs below */
        cs_tree = proto_item_add_subtree(ti, dissect_ssl3_hf.ett.cipher_suites);
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
        proto_tree_add_bytes_format(tree,
                                        dissect_ssl3_hf.hf.hs_session_id,
                                        tvb, offset, session_id_length,
                                        NULL, "Session ID (%u byte%s)",
                                        session_id_length,
                                        plurality(session_id_length, "", "s"));

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

static void
dissect_pct_msg_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, guint32 offset)
{
    guint16 CH_CLIENT_VERSION, CH_OFFSET, CH_CIPHER_SPECS_LENGTH, CH_HASH_SPECS_LENGTH, CH_CERT_SPECS_LENGTH, CH_EXCH_SPECS_LENGTH, CH_KEY_ARG_LENGTH;
    proto_item *CH_CIPHER_SPECS_ti, *CH_HASH_SPECS_ti, *CH_CERT_SPECS_ti, *CH_EXCH_SPECS_ti, *ti;
    proto_tree *CH_CIPHER_SPECS_tree, *CH_HASH_SPECS_tree, *CH_CERT_SPECS_tree, *CH_EXCH_SPECS_tree;
    gint i;

    CH_CLIENT_VERSION = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(tree, hf_ssl_pct_client_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (CH_CLIENT_VERSION != PCT_VERSION_1)
        expert_add_info_format(pinfo, ti, &ei_ssl_pct_client_version, "Client Version, should be %x in PCT version 1", PCT_VERSION_1);
    offset += 2;

    proto_tree_add_item(tree, hf_ssl_pct_pad, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ssl_pct_client_session_id_data, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(tree, hf_ssl_pct_challenge_data, tvb, offset, 32, ENC_NA);
    offset += 32;

    CH_OFFSET = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(tree, hf_ssl_pct_ch_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (CH_OFFSET != PCT_CH_OFFSET_V1)
        expert_add_info_format(pinfo, ti, &ei_ssl_pct_ch_offset, "should be %d in PCT version 1", PCT_CH_OFFSET_V1);
    offset += 2;

    CH_CIPHER_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_cipher_specs_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CH_HASH_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_hash_specs_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CH_CERT_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_cert_specs_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CH_EXCH_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_exch_specs_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CH_KEY_ARG_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_iv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (CH_CIPHER_SPECS_LENGTH) {
        CH_CIPHER_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_cipher_spec, tvb, offset, CH_CIPHER_SPECS_LENGTH, ENC_NA);
        CH_CIPHER_SPECS_tree = proto_item_add_subtree(CH_CIPHER_SPECS_ti, ett_pct_cipher_suites);

        for(i=0; i<(CH_CIPHER_SPECS_LENGTH/4); i++) {
            proto_tree_add_item(CH_CIPHER_SPECS_tree, hf_pct_handshake_cipher, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(CH_CIPHER_SPECS_tree, hf_ssl_pct_encryption_key_length, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_uint(CH_CIPHER_SPECS_tree, hf_ssl_pct_mac_key_length_in_bits, tvb, offset, 1, tvb_get_guint8(tvb, offset) + 64);
            offset += 1;
        }
    }

    if (CH_HASH_SPECS_LENGTH) {
        CH_HASH_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_hash_spec, tvb, offset, CH_HASH_SPECS_LENGTH, ENC_NA);
        CH_HASH_SPECS_tree = proto_item_add_subtree(CH_HASH_SPECS_ti, ett_pct_hash_suites);

        for(i=0; i<(CH_HASH_SPECS_LENGTH/2); i++) {
            proto_tree_add_item(CH_HASH_SPECS_tree, hf_pct_handshake_hash, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (CH_CERT_SPECS_LENGTH) {
        CH_CERT_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_cert_spec, tvb, offset, CH_CERT_SPECS_LENGTH, ENC_NA);
        CH_CERT_SPECS_tree = proto_item_add_subtree(CH_CERT_SPECS_ti, ett_pct_cert_suites);

        for(i=0; i< (CH_CERT_SPECS_LENGTH/2); i++) {
            proto_tree_add_item(CH_CERT_SPECS_tree, hf_pct_handshake_cert, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (CH_EXCH_SPECS_LENGTH) {
        CH_EXCH_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_exch_spec, tvb, offset, CH_EXCH_SPECS_LENGTH, ENC_NA);
        CH_EXCH_SPECS_tree = proto_item_add_subtree(CH_EXCH_SPECS_ti, ett_pct_exch_suites);

        for(i=0; i<(CH_EXCH_SPECS_LENGTH/2); i++) {
            proto_tree_add_item(CH_EXCH_SPECS_tree, hf_pct_handshake_exch, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    if (CH_KEY_ARG_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_iv_data, tvb, offset, CH_KEY_ARG_LENGTH, ENC_NA);
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
    proto_item* ti;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    proto_tree_add_item(tree, hf_ssl_pct_pad, tvb, offset, 1, ENC_NA);
    offset += 1;

    SH_SERVER_VERSION = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_item(tree, hf_ssl_pct_server_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (SH_SERVER_VERSION != PCT_VERSION_1)
        expert_add_info_format(pinfo, ti, &ei_ssl_pct_server_version, "Server Version, should be %x in PCT version 1", PCT_VERSION_1);
    offset += 2;

    proto_tree_add_item(tree, hf_ssl_pct_sh_restart_session_ok_flag, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ssl_pct_sh_client_auth_req_flag, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_pct_handshake_cipher, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_ssl_pct_encryption_key_length, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_uint(tree, hf_ssl_pct_mac_key_length_in_bits, tvb, offset, 1, tvb_get_guint8(tvb, offset) + 64);
    offset += 1;

    proto_tree_add_item(tree, hf_pct_handshake_hash, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pct_handshake_cert, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pct_handshake_exch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ssl_pct_connection_id_data, tvb, offset, 32, ENC_NA);
    offset += 32;

    SH_CERT_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_server_certificate_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    SH_CERT_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_client_cert_specs_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    SH_CLIENT_SIG_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_client_sig_specs_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    SH_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_response_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (SH_CERT_LENGTH) {
        dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_pct_handshake_server_cert);
        offset += SH_CERT_LENGTH;
    }

    if (SH_CERT_SPECS_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_client_cert_specs, tvb, offset, SH_CERT_SPECS_LENGTH, ENC_NA);
        offset += SH_CERT_SPECS_LENGTH;
    }

    if (SH_CLIENT_SIG_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_client_signature, tvb, offset, SH_CLIENT_SIG_LENGTH, ENC_NA);
        offset += SH_CLIENT_SIG_LENGTH;
    }

    if (SH_RESPONSE_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_server_response, tvb, offset, SH_RESPONSE_LENGTH, ENC_NA);
    }

}

static void
dissect_pct_msg_client_master_key(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint16 CMK_CLEAR_KEY_LENGTH, CMK_ENCRYPTED_KEY_LENGTH, CMK_KEY_ARG_LENGTH, CMK_VERIFY_PRELUDE, CMK_CLIENT_CERT_LENGTH, CMK_RESPONSE_LENGTH;

    proto_tree_add_item(tree, hf_ssl_pct_pad, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_pct_handshake_cert, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_pct_handshake_sig, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_CLEAR_KEY_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_clear_key_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_ENCRYPTED_KEY_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_encrypted_key_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_KEY_ARG_LENGTH= tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_iv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_VERIFY_PRELUDE = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_verify_prelude_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_CLIENT_CERT_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_client_cert_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    CMK_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_response_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (CMK_CLEAR_KEY_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_clear_key_data, tvb, offset, CMK_CLEAR_KEY_LENGTH, ENC_NA);
        offset += CMK_CLEAR_KEY_LENGTH;
    }
    if (CMK_ENCRYPTED_KEY_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_encrypted_key_data, tvb, offset, CMK_ENCRYPTED_KEY_LENGTH, ENC_NA);
        offset += CMK_ENCRYPTED_KEY_LENGTH;
    }
    if (CMK_KEY_ARG_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_iv_data, tvb, offset, CMK_KEY_ARG_LENGTH, ENC_NA);
        offset += CMK_KEY_ARG_LENGTH;
    }
    if (CMK_VERIFY_PRELUDE) {
        proto_tree_add_item(tree, hf_ssl_pct_verify_prelude_data, tvb, offset, CMK_VERIFY_PRELUDE, ENC_NA);
        offset += CMK_VERIFY_PRELUDE;
    }
    if (CMK_CLIENT_CERT_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_client_certificate_data, tvb, offset, CMK_CLIENT_CERT_LENGTH, ENC_NA);
        offset += CMK_CLIENT_CERT_LENGTH;
    }
    if (CMK_RESPONSE_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_response_data, tvb, offset, CMK_RESPONSE_LENGTH, ENC_NA);
    }
}

static void
dissect_pct_msg_server_verify(tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset)
{
    guint16 SV_RESPONSE_LENGTH;

    proto_tree_add_item(tree, hf_ssl_pct_pad, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_ssl_pct_server_session_id_data, tvb, offset, 32, ENC_NA);
    offset += 32;

    SV_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl_pct_server_response_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (SV_RESPONSE_LENGTH) {
        proto_tree_add_item(tree, hf_ssl_pct_server_response, tvb, offset, SV_RESPONSE_LENGTH, ENC_NA);
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
    proto_tree_add_item(tree, hf_ssl_pct_error_information_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (ERROR_CODE == PCT_ERR_SPECS_MISMATCH && INFO_LEN == 6)
    {
        proto_tree_add_item(tree, hf_ssl_pct_specs_mismatch_cipher, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_ssl_pct_specs_mismatch_hash, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_ssl_pct_specs_mismatch_cert, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_ssl_pct_specs_mismatch_exch, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_ssl_pct_specs_mismatch_client_cert, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_ssl_pct_specs_mismatch_client_sig, tvb, offset, 1, ENC_NA);
    }
    else if (INFO_LEN) {
        proto_tree_add_item(tree, hf_ssl_pct_error_information_data, tvb, offset, INFO_LEN, ENC_NA);
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
        proto_tree_add_item(tree, hf_ssl2_handshake_clear_key,
                            tvb, offset, clear_key_length, ENC_NA);
        offset += clear_key_length;
    }

    if (encrypted_key_length > 0)
    {
        proto_tree_add_item(tree, hf_ssl2_handshake_enc_key,
                            tvb, offset, encrypted_key_length, ENC_NA);
        offset += encrypted_key_length;
    }

    if (key_arg_length > 0)
    {
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
    guint16     certificate_length;
    guint16     cipher_spec_length;
    guint16     connection_id_length;
    guint16     version;
    proto_item *ti;
    proto_tree *subtree;
    asn1_ctx_t  asn1_ctx;

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
    proto_tree_add_item(tree, dissect_ssl3_hf.hf.hs_server_version,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* get the fixed fields */
    certificate_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, dissect_ssl3_hf.hf.hs_certificate_len,
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
        (void)dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, dissect_ssl3_hf.hf.hs_certificate);
        offset += certificate_length;
    }

    if (cipher_spec_length > 0)
    {
        /* provide a collapsing node for the cipher specs */
        ti = proto_tree_add_none_format(tree,
                                        dissect_ssl3_hf.hf.hs_cipher_suites,
                                        tvb, offset, cipher_spec_length,
                                        "Cipher Specs (%u spec%s)",
                                        cipher_spec_length/3,
                                        plurality(cipher_spec_length/3, "", "s"));
        subtree = proto_item_add_subtree(ti, dissect_ssl3_hf.ett.cipher_suites);
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
    conversation_t    *conversation;
    SslDecryptSession *ssl;
    guint              iv_len;

    ssl_debug_printf("\nssl_set_master_secret enter frame #%u\n", frame_num);

    conversation = find_conversation(frame_num, addr_srv, addr_cli, ptype, port_srv, port_cli, 0);

    if (!conversation) {
        /* create a new conversation */
        conversation = conversation_new(frame_num, addr_srv, addr_cli, ptype, port_srv, port_cli, 0);
        ssl_debug_printf("  new conversation = %p created\n", (void *)conversation);
    }
    ssl = ssl_get_session(conversation, ssl_handle);

    ssl_debug_printf("  conversation = %p, ssl_session = %p\n", (void *)conversation, (void *)ssl);

    ssl_set_server(&ssl->session, addr_srv, ptype, port_srv);

    /* version */
    if ((ssl->session.version==SSL_VER_UNKNOWN) && (version!=SSL_VER_UNKNOWN)) {
        switch (version) {
        case SSLV3_VERSION:
        case TLSV1_VERSION:
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
            ssl->session.version = version;
            ssl->state |= SSL_VERSION;
            ssl_debug_printf("%s set version 0x%04X -> state 0x%02X\n", G_STRFUNC, ssl->session.version, ssl->state);
            break;
        default:
            /* API change: version number is no longer an internal value
             * (SSL_VER_*) but the ProtocolVersion from wire (*_VERSION) */
            ssl_debug_printf("%s WARNING must pass ProtocolVersion, not 0x%04x!\n", G_STRFUNC, version);
            break;
        }
    }

    /* cipher */
    if (cipher > 0) {
        ssl->session.cipher = cipher;
        if (!(ssl->cipher_suite = ssl_find_cipher(ssl->session.cipher))) {
            ssl->state &= ~SSL_CIPHER;
            ssl_debug_printf("ssl_set_master_secret can't find cipher suite 0x%X\n", ssl->session.cipher);
        } else {
            ssl->state |= SSL_CIPHER;
            ssl_debug_printf("ssl_set_master_secret set CIPHER 0x%04X -> state 0x%02X\n", ssl->session.cipher, ssl->state);
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
    iv_len = (ssl->cipher_suite->block>1) ? ssl->cipher_suite->block : 8;
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
static gint
ssl_is_valid_ssl_version(const guint16 version)
{
    const gchar *version_str;

    version_str = try_val_to_str(version, ssl_versions);
    return version_str != NULL;
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
    switch (byte) {
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
    switch (version) {
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
    guint8  msg_type;
    guint16 version;
    guint32 sum;
    gint    ret = 0;

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
    guint8  msg_type;
    guint16 version;
    guint32 sum;
    gint    ret = 0;

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
        sum  = tvb_get_ntohs(tvb, offset +  6); /* clear_key_length */
        sum += tvb_get_ntohs(tvb, offset +  8); /* encrypted_key_length */
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

#if defined(HAVE_LIBGNUTLS) && defined(HAVE_LIBGCRYPT)
static void
ssldecrypt_free_cb(void *r)
{
    ssldecrypt_assoc_t *h = (ssldecrypt_assoc_t *)r;

    g_free(h->ipaddr);
    g_free(h->port);
    g_free(h->protocol);
    g_free(h->keyfile);
    g_free(h->password);
}

static void*
ssldecrypt_copy_cb(void *dest, const void *orig, size_t len _U_)
{
    const ssldecrypt_assoc_t *o = (const ssldecrypt_assoc_t *)orig;
    ssldecrypt_assoc_t       *d = (ssldecrypt_assoc_t *)dest;

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

static gboolean
ssldecrypt_uat_fld_protocol_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        *err = g_strdup("No protocol given.");
        return FALSE;
    }

    if (!ssl_find_appdata_dissector(p)) {
        if (proto_get_id_by_filter_name(p) != -1) {
            *err = g_strdup_printf("While '%s' is a valid dissector filter name, that dissector is not configured"
                                   " to support SSL decryption.\n\n"
                                   "If you need to decrypt '%s' over SSL, please contact the Wireshark development team.", p, p);
        } else {
            char* ssl_str = ssl_association_info("ssl.port", "TCP");
            *err = g_strdup_printf("Could not find dissector for: '%s'\nCommonly used SSL dissectors include:\n%s", p, ssl_str);
            g_free(ssl_str);
        }
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}
#endif

static void
ssl_src_prompt(packet_info *pinfo, gchar *result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", pinfo->srcport, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
ssl_src_value(packet_info *pinfo)
{
    return GUINT_TO_POINTER(pinfo->srcport);
}

static void
ssl_dst_prompt(packet_info *pinfo, gchar *result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, pinfo->destport);
}

static gpointer
ssl_dst_value(packet_info *pinfo)
{
    return GUINT_TO_POINTER(pinfo->destport);
}

static void
ssl_both_prompt(packet_info *pinfo, gchar *result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "both (%u%s%u)", pinfo->srcport, UTF8_LEFT_RIGHT_ARROW, pinfo->destport);
}

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
        { &hf_ssl2_handshake_cipher_spec,
          { "Cipher Spec", "ssl.handshake.cipherspec",
            FT_UINT24, BASE_HEX|BASE_EXT_STRING, &ssl_20_cipher_suites_ext, 0x0,
            "Cipher specification", HFILL }
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
        { &hf_ssl_handshake_npn_selected_protocol_len,
          { "Selected Protocol Length", "ssl.handshake.npn_selected_protocol_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_npn_selected_protocol,
          { "Selected Protocol", "ssl.handshake.npn_selected_protocol",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Protocol to be used for connection", HFILL }
        },
        { &hf_ssl_handshake_npn_padding_len,
          { "Padding Length", "ssl.handshake.npn_padding_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl_handshake_npn_padding,
          { "Padding", "ssl.handshake.npn_padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &ssl_hfs.hs_md5_hash,
          { "MD5 Hash", "ssl.handshake.md5_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &ssl_hfs.hs_sha_hash,
          { "SHA-1 Hash", "ssl.handshake.sha_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
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
          { "Cipher Spec", "ssl.pct.handshake.cipherspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Cipher specification", HFILL }
        },
        { &hf_pct_handshake_cipher,
          { "Cipher", "ssl.pct.handshake.cipher",
            FT_UINT16, BASE_HEX, VALS(pct_cipher_type), 0x0,
            "PCT Ciper", HFILL }
        },
        { &hf_pct_handshake_hash_spec,
          { "Hash Spec", "ssl.pct.handshake.hashspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Hash specification", HFILL }
        },
        { &hf_pct_handshake_hash,
          { "Hash", "ssl.pct.handshake.hash",
            FT_UINT16, BASE_HEX, VALS(pct_hash_type), 0x0,
            "PCT Hash", HFILL }
        },
        { &hf_pct_handshake_cert_spec,
          { "Cert Spec", "ssl.pct.handshake.certspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Certificate specification", HFILL }
        },
        { &hf_pct_handshake_cert,
          { "Cert", "ssl.pct.handshake.cert",
            FT_UINT16, BASE_HEX, VALS(pct_cert_type), 0x0,
            "PCT Certificate", HFILL }
        },
        { &hf_pct_handshake_exch_spec,
          { "Exchange Spec", "ssl.pct.handshake.exchspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "PCT Exchange specification", HFILL }
        },
        { &hf_pct_handshake_exch,
          { "Exchange", "ssl.pct.handshake.exch",
            FT_UINT16, BASE_HEX, VALS(pct_exch_type), 0x0,
            "PCT Exchange", HFILL }
        },
        { &hf_pct_handshake_sig,
          { "Sig Spec", "ssl.pct.handshake.sig",
            FT_UINT16, BASE_HEX, VALS(pct_sig_type), 0x0,
            "PCT Signature", HFILL }
        },
        { &hf_pct_msg_error_type,
          { "PCT Error Code", "ssl.pct.msg_error_code",
            FT_UINT16, BASE_HEX, VALS(pct_error_code), 0x0,
            NULL, HFILL }
        },
        { &hf_pct_handshake_server_cert,
          { "Server Cert", "ssl.pct.handshake.server_cert",
            FT_BYTES, BASE_NONE, NULL , 0x0,
            "PCT Server Certificate", HFILL }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ssl_pct_client_version, { "Client Version", "ssl.pct.client_version", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_pad, { "PAD", "ssl.pct.pad", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_session_id_data, { "Client Session ID Data", "ssl.pct.client_session_id_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_challenge_data, { "Challenge Data", "ssl.pct.challenge_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_ch_offset, { "CH_OFFSET", "ssl.pct.ch_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_cipher_specs_length, { "CIPHER_SPECS Length", "ssl.pct.cipher_specs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_hash_specs_length, { "HASH_SPECS Length", "ssl.pct.hash_specs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_cert_specs_length, { "CERT_SPECS Length", "ssl.pct.cert_specs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_exch_specs_length, { "EXCH_SPECS Length", "ssl.pct.exch_specs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_iv_length, { "IV Length", "ssl.pct.iv_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_encryption_key_length, { "Encryption key length", "ssl.pct.encryption_key_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_mac_key_length_in_bits, { "MAC key length in bits", "ssl.pct.mac_key_length_in_bits", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_iv_data, { "IV data", "ssl.pct.iv_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_server_version, { "Server Version", "ssl.pct.server_version", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_sh_restart_session_ok_flag, { "SH_RESTART_SESSION_OK flag", "ssl.pct.sh_restart_session_ok_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_sh_client_auth_req_flag, { "SH_CLIENT_AUTH_REQ flag", "ssl.pct.sh_client_auth_req_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_connection_id_data, { "Connection ID Data", "ssl.connection_id_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_server_certificate_length, { "Server Certificate Length", "ssl.pct.server_certificate_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_cert_specs_length, { "Client CERT_SPECS Length", "ssl.pct.client_cert_specs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_sig_specs_length, { "Client SIG_SPECS Length", "ssl.pct.client_sig_specs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_response_length, { "Response Length", "ssl.pct.response_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_cert_specs, { "Client CERT_SPECS", "ssl.pct.client_cert_specs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_signature, { "Client Signature", "ssl.pct.client_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_server_response, { "Server Response", "ssl.pct.server_response", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_clear_key_length, { "Clear Key Length", "ssl.pct.clear_key_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_encrypted_key_length, { "Encrypted Key Length", "ssl.pct.encrypted_key_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_verify_prelude_length, { "Verify Prelude Length", "ssl.pct.verify_prelude_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_cert_length, { "Client Cert Length", "ssl.pct.client_cert_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_clear_key_data, { "Clear Key data", "ssl.pct.clear_key_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_encrypted_key_data, { "Encrypted Key data", "ssl.pct.encrypted_key_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_verify_prelude_data, { "Verify Prelude data", "ssl.pct.verify_prelude_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_client_certificate_data, { "Client Certificate data", "ssl.pct.client_certificate_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_response_data, { "Response data", "ssl.pct.response_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_server_session_id_data, { "Server Session ID data", "ssl.pct.server_session_id_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_server_response_length, { "Server Response Length", "ssl.pct.server_response_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_error_information_length, { "Error Information Length", "ssl.pct.error_information_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_specs_mismatch_cipher, { "SPECS_MISMATCH_CIPHER", "ssl.pct.specs_mismatch_cipher", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_specs_mismatch_hash, { "SPECS_MISMATCH_HASH", "ssl.pct.specs_mismatch_hash", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_specs_mismatch_cert, { "SPECS_MISMATCH_CERT", "ssl.pct.specs_mismatch_cert", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_specs_mismatch_exch, { "SPECS_MISMATCH_EXCH", "ssl.pct.specs_mismatch_exch", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_specs_mismatch_client_cert, { "SPECS_MISMATCH_CLIENT_CERT", "ssl.pct.specs_mismatch_client_cert", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_specs_mismatch_client_sig, { "SPECS_MISMATCH_CLIENT_SIG", "ssl.pct.specs_mismatch_client_sig", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ssl_pct_error_information_data, { "Error Information data", "ssl.pct.error_information_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},


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
          { "SSL segment", "ssl.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssl_segments,
          { "Reassembled SSL segments", "ssl.segments",
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

        { &hf_ssl_reassembled_data,
          { "Reassembled PDU data", "ssl.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "The payload of multiple reassembled SSL segments", HFILL }},

        { &hf_ssl_segment_data,
          { "SSL segment data", "ssl.segment.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "The payload of a single SSL segment", HFILL }
        },
        SSL_COMMON_HF_LIST(dissect_ssl3_hf, "ssl")
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ssl,
        &ett_ssl_record,
        &ett_ssl_alert,
        &ett_ssl_handshake,
        &ett_ssl_heartbeat,
        &ett_ssl_certs,
        &ett_ssl_cert_status,
        &ett_ssl_ocsp_resp,
        &ett_pct_cipher_suites,
        &ett_pct_hash_suites,
        &ett_pct_cert_suites,
        &ett_pct_exch_suites,
        &ett_ssl_segments,
        &ett_ssl_segment,
        SSL_COMMON_ETT_LIST(dissect_ssl3_hf)
    };

    static ei_register_info ei[] = {
        { &ei_ssl2_handshake_session_id_len_error, { "ssl.handshake.session_id_length.error", PI_MALFORMED, PI_ERROR, "Session ID length error", EXPFILL }},
        { &ei_ssl3_heartbeat_payload_length, { "ssl.heartbeat_message.payload_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid heartbeat payload length", EXPFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &ei_ssl_ignored_unknown_record, { "ssl.ignored_unknown_record", PI_PROTOCOL, PI_WARN, "Ignored Unknown Record", EXPFILL }},
      { &ei_ssl_pct_client_version, { "ssl.pct.client_version.invalid", PI_PROTOCOL, PI_WARN, "Client Version invalid", EXPFILL }},
      { &ei_ssl_pct_ch_offset, { "ssl.pct.ch_offset.invalid", PI_PROTOCOL, PI_WARN, "CH_OFFSET invalid", EXPFILL }},
      { &ei_ssl_pct_server_version, { "ssl.pct.server_version.invalid", PI_PROTOCOL, PI_WARN, "Server Version invalid", EXPFILL }},

        SSL_COMMON_EI_LIST(dissect_ssl3_hf, "ssl")
    };

    static build_valid_func ssl_da_src_values[1] = {ssl_src_value};
    static build_valid_func ssl_da_dst_values[1] = {ssl_dst_value};
    static build_valid_func ssl_da_both_values[2] = {ssl_src_value, ssl_dst_value};
    static decode_as_value_t ssl_da_values[3] = {{ssl_src_prompt, 1, ssl_da_src_values}, {ssl_dst_prompt, 1, ssl_da_dst_values}, {ssl_both_prompt, 2, ssl_da_both_values}};
    static decode_as_t ssl_da = {"ssl", "Transport", "ssl.port", 3, 2, ssl_da_values, "TCP", "port(s) as",
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    expert_module_t* expert_ssl;

    /* Register the protocol name and description */
    proto_ssl = proto_register_protocol("Secure Sockets Layer",
                                        "SSL", "ssl");

    ssl_associations = register_dissector_table("ssl.port", "SSL TCP Dissector", proto_ssl, FT_UINT16, BASE_DEC);

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_ssl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ssl = expert_register_protocol(proto_ssl);
    expert_register_field_array(expert_ssl, ei, array_length(ei));

    {
        module_t *ssl_module = prefs_register_protocol(proto_ssl, proto_reg_handoff_ssl);

#ifdef HAVE_LIBGCRYPT
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
            &sslkeylist_uats,               /* data_ptr */
            &nssldecrypt,                   /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* Help section (currently a wiki page) */
            ssldecrypt_copy_cb,
            NULL,
            ssldecrypt_free_cb,
            ssl_parse_uat,
            sslkeylist_uats_flds);

        prefs_register_uat_preference(ssl_module, "key_table",
            "RSA keys list",
            "A table of RSA keys for SSL decryption",
            ssldecrypt_uat);
#endif /* HAVE_LIBGNUTLS */

        prefs_register_filename_preference(ssl_module, "debug_file", "SSL debug file",
            "Redirect SSL debug to the file specified. Leave empty to disable debugging "
            "or use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr.",
            &ssl_debug_file_name);

        prefs_register_string_preference(ssl_module, "keys_list", "RSA keys list (deprecated)",
             "Semicolon-separated list of private RSA keys used for SSL decryption. "
             "Used by versions of Wireshark prior to 1.6",
             &ssl_keys_list);
#endif /* HAVE_LIBGCRYPT */

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
        ssl_common_register_options(ssl_module, &ssl_options);
    }

    /* heuristic dissectors for any premable e.g. CredSSP before RDP */
    ssl_heur_subdissector_list = register_heur_dissector_list("ssl", proto_ssl);

    register_dissector("ssl", dissect_ssl, proto_ssl);
    ssl_handle = find_dissector("ssl");

    register_init_routine(ssl_init);
    register_cleanup_routine(ssl_cleanup);
    register_decode_as(&ssl_da);

    ssl_tap = register_tap("ssl");
    ssl_debug_printf("proto_register_ssl: registered tap %s:%d\n",
        "ssl", ssl_tap);

    register_follow_stream(proto_ssl, "ssl", tcp_follow_conv_filter, tcp_follow_index_filter, tcp_follow_address_filter,
                            tcp_port_to_display, ssl_follow_tap_listener);
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
    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);
}

void
ssl_dissector_add(guint port, dissector_handle_t handle)
{
    ssl_association_add("ssl.port", ssl_handle, handle, port, TRUE);
}

void
ssl_dissector_delete(guint port, dissector_handle_t handle)
{
    ssl_association_remove("ssl.port", ssl_handle, handle, port, TRUE);
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
