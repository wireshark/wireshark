/* packet-tls.c
 * Routines for TLS dissection
 * Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
 * Copyright 2013-2019, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Supported protocol versions:
 *
 *  TLS 1.3, 1.2, 1.0, and SSL 3.0. SSL 2.0 is no longer supported, except for
 *  the SSL 2.0-compatible Client Hello.
 *
 * Primary protocol specifications:
 *
 *  https://tools.ietf.org/html/draft-hickman-netscape-ssl-00 - SSL 2.0
 *  https://tools.ietf.org/html/rfc6101 - SSL 3.0
 *  https://tools.ietf.org/html/rfc2246 - TLS 1.0
 *  https://tools.ietf.org/html/rfc4346 - TLS 1.1
 *  https://tools.ietf.org/html/rfc5246 - TLS 1.2
 *  https://tools.ietf.org/html/rfc8446 - TLS 1.3
 *
 * Important IANA registries:
 *
 *  https://www.iana.org/assignments/tls-parameters/
 *  https://www.iana.org/assignments/tls-extensiontype-values/
 *
 * Notes:
 *
 *    - Decryption needs to be performed 'sequentially', so it's done
 *      at packet reception time. This may cause a significant packet capture
 *      slow down. This also causes dissection of some ssl info that in previous
 *      dissector versions was dissected only when a proto_tree context was
 *      available
 *
 *     We are at Packet reception if time pinfo->fd->visited == 0
 *
 *    - Many dissection and decryption operations are implemented in
 *      epan/dissectors/packet-tls-utils.c and
 *      epan/dissectors/packet-tls-utils.h due to an overlap of functionality
 *      with DTLS (epan/dissectors/packet-dtls.c).
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
#include <epan/secrets.h>
#include <wiretap/secrets-types.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/rsa.h>
#include <wsutil/ws_assert.h>
#include "packet-tcp.h"
#include "packet-x509af.h"
#include "packet-tls.h"
#include "packet-tls-utils.h"
#include "packet-ber.h"

void proto_register_tls(void);

#ifdef HAVE_LIBGNUTLS
static ssldecrypt_assoc_t *tlskeylist_uats = NULL;
static guint ntlsdecrypt = 0;
#endif

static gboolean tls_desegment          = TRUE;
static gboolean tls_desegment_app_data = TRUE;
static gboolean tls_ignore_mac_failed  = FALSE;


/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* Initialize the protocol and registered fields */
static gint tls_tap                           = -1;
static gint exported_pdu_tap                  = -1;
static gint proto_tls                         = -1;
static gint hf_tls_record                     = -1;
static gint hf_tls_record_content_type        = -1;
static gint hf_tls_record_opaque_type         = -1;
static gint hf_tls_record_version             = -1;
static gint hf_tls_record_length              = -1;
static gint hf_tls_record_appdata             = -1;
static gint hf_tls_record_appdata_proto       = -1;
static gint hf_ssl2_record                    = -1;
static gint hf_ssl2_record_is_escape          = -1;
static gint hf_ssl2_record_padding_length     = -1;
static gint hf_ssl2_msg_type                  = -1;
static gint hf_tls_alert_message              = -1;
static gint hf_tls_alert_message_level        = -1;
static gint hf_tls_alert_message_description  = -1;
static gint hf_tls_handshake_protocol         = -1;
static gint hf_tls_handshake_type             = -1;
static gint hf_tls_handshake_length           = -1;
static gint hf_tls_handshake_npn_selected_protocol_len = -1;
static gint hf_tls_handshake_npn_selected_protocol = -1;
static gint hf_tls_handshake_npn_padding_len = -1;
static gint hf_tls_handshake_npn_padding = -1;
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

static int hf_tls_reassembled_in              = -1;
static int hf_tls_reassembled_length          = -1;
static int hf_tls_reassembled_data            = -1;
static int hf_tls_segments                    = -1;
static int hf_tls_segment                     = -1;
static int hf_tls_segment_overlap             = -1;
static int hf_tls_segment_overlap_conflict    = -1;
static int hf_tls_segment_multiple_tails      = -1;
static int hf_tls_segment_too_long_fragment   = -1;
static int hf_tls_segment_error               = -1;
static int hf_tls_segment_count               = -1;
static int hf_tls_segment_data                = -1;

static int hf_tls_handshake_reassembled_in    = -1;
static int hf_tls_handshake_fragments         = -1;
static int hf_tls_handshake_fragment          = -1;
static int hf_tls_handshake_fragment_count    = -1;

static gint hf_tls_heartbeat_message                 = -1;
static gint hf_tls_heartbeat_message_type            = -1;
static gint hf_tls_heartbeat_message_payload_length  = -1;
static gint hf_tls_heartbeat_message_payload         = -1;
static gint hf_tls_heartbeat_message_padding         = -1;

static ssl_hfs_t ssl_hfs = { -1, -1 };

/* Initialize the subtree pointers */
static gint ett_tls                   = -1;
static gint ett_tls_record            = -1;
static gint ett_tls_alert             = -1;
static gint ett_tls_handshake         = -1;
static gint ett_tls_heartbeat         = -1;
static gint ett_tls_certs             = -1;
static gint ett_tls_segments          = -1;
static gint ett_tls_segment           = -1;
static gint ett_tls_hs_fragments       = -1;
static gint ett_tls_hs_fragment        = -1;

static expert_field ei_ssl2_handshake_session_id_len_error = EI_INIT;
static expert_field ei_ssl3_heartbeat_payload_length = EI_INIT;
static expert_field ei_tls_unexpected_message = EI_INIT;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_tls_ignored_unknown_record = EI_INIT;

/* not all of the hf_fields below make sense for TLS but we have to provide
   them anyways to comply with the api (which was aimed for ip fragment
   reassembly) */
static const fragment_items ssl_segment_items = {
    &ett_tls_segment,
    &ett_tls_segments,
    &hf_tls_segments,
    &hf_tls_segment,
    &hf_tls_segment_overlap,
    &hf_tls_segment_overlap_conflict,
    &hf_tls_segment_multiple_tails,
    &hf_tls_segment_too_long_fragment,
    &hf_tls_segment_error,
    &hf_tls_segment_count,
    &hf_tls_reassembled_in,
    &hf_tls_reassembled_length,
    &hf_tls_reassembled_data,
    "Segments"
};

/* Fragmented handshake messages. */
static const fragment_items tls_hs_fragment_items = {
    &ett_tls_hs_fragment,
    &ett_tls_hs_fragments,
    &hf_tls_handshake_fragments,
    &hf_tls_handshake_fragment,
    &hf_tls_segment_overlap,    // Do not care about the errors, should not happen.
    &hf_tls_segment_overlap_conflict,
    &hf_tls_segment_multiple_tails,
    &hf_tls_segment_too_long_fragment,
    &hf_tls_segment_error,
    &hf_tls_handshake_fragment_count,
    NULL,                           /* unused - &hf_tls_handshake_reassembled_in, */
    NULL,                           /* do not display redundant length */
    NULL,                           /* do not display redundant data */
    "Fragments"
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
        hf_tls_segment_data,
        tvb,
        offset,
        length,
        NULL,
        "%sTLS segment data (%u %s)",
        prefix != NULL ? prefix : "",
        length,
        plurality(length, "byte", "bytes"));
}


static ssl_master_key_map_t       ssl_master_key_map;
/* used by "Export TLS Session Keys" */
GHashTable *ssl_session_hash;
GHashTable *ssl_crandom_hash;

#ifdef HAVE_LIBGNUTLS
static GHashTable         *ssl_key_hash             = NULL;
static wmem_stack_t       *key_list_stack            = NULL;
static uat_t              *ssldecrypt_uat           = NULL;
static const gchar        *ssl_keys_list            = NULL;
#endif
static dissector_table_t   ssl_associations         = NULL;
static dissector_handle_t  tls_handle               = NULL;
static StringInfo          ssl_compressed_data      = {NULL, 0};
static StringInfo          ssl_decrypted_data       = {NULL, 0};
static gint                ssl_decrypted_data_avail = 0;
static FILE               *ssl_keylog_file          = NULL;
static ssl_common_options_t ssl_options = { NULL, NULL};

/* List of dissectors to call for TLS data */
static heur_dissector_list_t ssl_heur_subdissector_list;

static const gchar *ssl_debug_file_name     = NULL;


/* Forward declaration we need below */
void proto_reg_handoff_ssl(void);

/* Desegmentation of TLS streams */
/* table to hold defragmented TLS streams */
static reassembly_table ssl_reassembly_table;

/* Table to hold fragmented TLS handshake records. */
static reassembly_table tls_hs_reassembly_table;
static guint32 hs_reassembly_id_count;

/* initialize/reset per capture state data (ssl sessions cache) */
static void
ssl_init(void)
{
    module_t *ssl_module = prefs_find_module("tls");
    pref_t   *keys_list_pref;

    ssl_common_init(&ssl_master_key_map,
                    &ssl_decrypted_data, &ssl_compressed_data);
    ssl_debug_flush();

    /* for "Export TLS Session Keys" */
    ssl_session_hash = ssl_master_key_map.session;
    ssl_crandom_hash = ssl_master_key_map.crandom;

    /* We should have loaded "keys_list" by now. Mark it obsolete */
    if (ssl_module) {
        keys_list_pref = prefs_find_preference(ssl_module, "keys_list");
        if (! prefs_get_preference_obsolete(keys_list_pref)) {
            prefs_set_preference_obsolete(keys_list_pref);
        }
    }

    /* Reset the identifier for a group of handshake fragments. */
    hs_reassembly_id_count = 0;
}

static void
ssl_cleanup(void)
{
#ifdef HAVE_LIBGNUTLS
    if (key_list_stack != NULL) {
        wmem_destroy_stack(key_list_stack);
        key_list_stack = NULL;
    }
#endif
    ssl_common_cleanup(&ssl_master_key_map, &ssl_keylog_file,
                       &ssl_decrypted_data, &ssl_compressed_data);

    /* should not be needed since the UI code prevents this from being accessed
     * when no file is open. Clear it anyway just to be sure. */
    ssl_session_hash = NULL;
    ssl_crandom_hash = NULL;
}

ssl_master_key_map_t *
tls_get_master_key_map(gboolean load_secrets)
{
    // Try to load new keys.
    if (load_secrets) {
        ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
    }
    return &ssl_master_key_map;
}

#ifdef HAVE_LIBGNUTLS
/* parse ssl related preferences (private keys and ports association strings) */
static void
ssl_parse_uat(void)
{
    guint              i;
    guint16            port;
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
              ssl_association_remove("tls.port", tls_handle, handle, port, FALSE);
        }
    }
    /* parse private keys string, load available keys and put them in key hash*/
    ssl_key_hash = privkey_hash_table_new();


    if (ntlsdecrypt > 0) {
        if (key_list_stack == NULL)
            key_list_stack = wmem_stack_new(NULL);
        for (i = 0; i < ntlsdecrypt; i++) {
            ssldecrypt_assoc_t *ssl_uat = &(tlskeylist_uats[i]);
            ssl_parse_key_list(ssl_uat, ssl_key_hash, "tls.port", tls_handle, TRUE);
            if (key_list_stack && ws_strtou16(ssl_uat->port, NULL, &port) && port > 0)
                wmem_stack_push(key_list_stack, GUINT_TO_POINTER(port));
        }
    }

    ssl_debug_flush();
}

static void
ssl_reset_uat(void)
{
    g_hash_table_destroy(ssl_key_hash);
    ssl_key_hash = NULL;
}

static void
ssl_parse_old_keys(void)
{
    gchar **old_keys, **parts, *err;
    gchar  *uat_entry;
    guint   i;

    /* Import old-style keys */
    if (ssldecrypt_uat && ssl_keys_list && ssl_keys_list[0]) {
        old_keys = g_strsplit(ssl_keys_list, ";", 0);
        for (i = 0; old_keys[i] != NULL; i++) {
            parts = g_strsplit(old_keys[i], ",", 5);
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
            g_strfreev(parts);
        }
        g_strfreev(old_keys);
    }
}
#endif  /* HAVE_LIBGNUTLS */


static tap_packet_status
ssl_follow_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *ssl, tap_flags_t flags _U_)
{
    follow_info_t *      follow_info = (follow_info_t*) tapdata;
    follow_record_t * follow_record = NULL;
    const SslRecordInfo *appl_data = NULL;
    const SslPacketInfo *pi = (const SslPacketInfo*)ssl;
    show_stream_t        from = FROM_CLIENT;

    /* Skip packets without decrypted payload data. */
    if (!pi || !pi->records) return TAP_PACKET_DONT_REDRAW;

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

    for (appl_data = pi->records; appl_data != NULL; appl_data = appl_data->next) {

        /* Include only application data in the record, skipping things like
         * Handshake messages and alerts. */
        if (appl_data->type != SSL_ID_APP_DATA) continue;

        /* TCP segments that contain the end of two or more TLS PDUs will be
           queued to TLS taps for each of those PDUs. Therefore a single
           packet could be processed by this TLS tap listener multiple times.
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
           the opportunity to accurately reflect TLS PDU boundaries. Currently
           the Hex Dump view does by starting a new line, and the C Arrays
           view does by starting a new array declaration. */
        follow_record = g_new(follow_record_t,1);

        follow_record->is_server = (from == FROM_SERVER);
        follow_record->packet_num = pinfo->num;
        follow_record->abs_ts = pinfo->abs_ts;

        follow_record->data = g_byte_array_sized_new(appl_data->data_len);
        follow_record->data = g_byte_array_append(follow_record->data,
                                              appl_data->plain_data,
                                              appl_data->data_len);

        /* Add the record to the follow_info structure. */
        follow_info->payload = g_list_prepend(follow_info->payload, follow_record);
        follow_info->bytes_written[from] += appl_data->data_len;
    }

    return TAP_PACKET_DONT_REDRAW;
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
                                guint8 curr_layer_num_ssl);

/* alert message dissector */
static void dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint32 record_length, const SslSession *session);

/* handshake protocol dissector */
static void dissect_tls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 offset_end, gboolean maybe_encrypted,
                       guint record_id, guint8 curr_layer_num_tls,
                       SslSession *session, gint is_from_server,
                       SslDecryptSession *ssl,
                       const guint16 version);

static void dissect_tls_handshake_full(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, guint32 offset,
                                  SslSession *session, gint is_from_server,
                                  SslDecryptSession *conv_data,
                                  const guint16 version,
                                  gboolean is_first_msg);

/* heartbeat message dissector */
static void dissect_ssl3_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   const SslSession *session, guint32 record_length,
                                   gboolean decrypted);

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
                                SslDecryptSession *ssl);

/* client hello dissector */
static void dissect_ssl2_hnd_client_hello(tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree,
                                          guint32 offset,
                                          SslDecryptSession *ssl);

/* client master key dissector */
static void dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb,
                                               proto_tree *tree,
                                               guint32 offset);

/* server hello dissector */
static void dissect_ssl2_hnd_server_hello(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, packet_info *pinfo);


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
    gboolean           need_desegmentation;
    SslDecryptSession *ssl_session;
    SslSession        *session;
    gint               is_from_server;
    /*
     * A single packet may contain multiple TLS records. Two possible scenarios:
     *
     * - Multiple TLS records belonging to the same TLS session.
     * - TLS within a different encrypted TLS tunnel.
     *
     * To support the second case, 'curr_layer_num_ssl' is used as identifier
     * for the current TLS layer. It is however not a stable identifier for the
     * second pass (Bug 16109). If the first decrypted record requests
     * reassembly for HTTP, then the second pass will skip calling the dissector
     * for the first record. That means that 'pinfo->curr_layer_num' will
     * actually be lower the second time.
     *
     * Since this cannot be easily fixed, we will just break the (hopefully less
     * common) case of TLS tunneled within TLS.
     */
    guint8             curr_layer_num_ssl = 0; // pinfo->curr_layer_num;

    ti = NULL;
    ssl_tree   = NULL;
    offset = 0;
    ssl_session = NULL;


    if (tvb_captured_length(tvb) > 4) {
        const guint8 *tmp = tvb_get_ptr(tvb, 0, 4);
        if (g_ascii_isprint(tmp[0]) &&
                g_ascii_isprint(tmp[1]) &&
                g_ascii_isprint(tmp[2]) &&
                g_ascii_isprint(tmp[3])) {
            /* it is extremely unlikely that real TLS traffic starts with four
             * printable ascii characters; this looks like it's unencrypted
             * text, so assume it's not ours (SSL does have some unencrypted
             * text fields in certain packets, but you'd have to get very
             * unlucky with TCP fragmentation to have one of those fields at the
             * beginning of a TCP payload at the beginning of the capture where
             * reassembly hasn't started yet) */
            return 0;
        }
    }

    ssl_debug_printf("\ndissect_ssl enter frame #%u (%s)\n", pinfo->num, (pinfo->fd->visited)?"already visited":"first time");

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
    ssl_session = ssl_get_session(conversation, tls_handle);
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
    if (pinfo->fd->visited)
         ssl_session = NULL;

    ssl_debug_printf("  conversation = %p, ssl_session = %p\n", (void *)conversation, (void *)ssl_session);

    /* Initialize the protocol column; we'll override it later when we
     * detect a different version or flavor of TLS (assuming we don't
     * throw an exception before we get the chance to do so). */
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
             val_to_str_const(session->version, ssl_version_short_names, "SSL"));
    /* clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* TCP packets and TLS records are orthogonal.
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

    /* Create display subtree for TLS as a whole */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_tls, tvb, 0, -1, ENC_NA);
        ssl_tree = proto_item_add_subtree(ti, ett_tls);
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
            offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                         offset, session,
                                         &need_desegmentation,
                                         ssl_session);
            break;

        case SSLV3_VERSION:
        case TLSV1_VERSION:
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
        case GMTLSV1_VERSION:
            /* SSLv3/TLS record headers need at least 1+2+2 = 5 bytes. */
            if (tvb_reported_length_remaining(tvb, offset) < 5) {
                if (tls_desegment && pinfo->can_desegment) {
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
                                             ssl_session);
            }
            else
            {
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, session, is_from_server,
                                             &need_desegmentation,
                                             ssl_session,
                                             curr_layer_num_ssl);
            }
            break;

            /* that failed, so apply some heuristics based
             * on this individual packet
             */
        default:
            /*
             * If the version is unknown, assume SSLv3/TLS which has a record
             * size of at least 5 bytes (SSLv2 record header is two or three
             * bytes, but the data will hopefully be larger than three bytes).
             */
            if (tvb_reported_length_remaining(tvb, offset) < 5) {
                if (tls_desegment && pinfo->can_desegment) {
                    pinfo->desegment_offset = offset;
                    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                    need_desegmentation = TRUE;
                } else {
                    /* Not enough bytes available. Stop here. */
                    offset = tvb_reported_length(tvb);
                }
                break;
            }

            if (ssl_looks_like_sslv2(tvb, offset))
            {
                /* looks like sslv2 client hello */
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, session,
                                             &need_desegmentation,
                                             ssl_session);
            }
            else if (ssl_looks_like_sslv3(tvb, offset))
            {
                /* looks like sslv3 or tls */
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, session, is_from_server,
                                             &need_desegmentation,
                                             ssl_session,
                                             curr_layer_num_ssl);
            }
            else
            {
                /* looks like something unknown, so lump into
                 * continuation data
                 */
                offset = tvb_reported_length(tvb);
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Continuation Data");
            }
            break;
        }

        /* Desegmentation return check */
        if (need_desegmentation) {
          ssl_debug_printf("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                           offset, tvb_reported_length_remaining(tvb, offset));
          /* Make data available to ssl_follow_tap_listener */
          tap_queue_packet(tls_tap, pinfo, p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, curr_layer_num_ssl));
          return tvb_captured_length(tvb);
        }
    }

    col_set_fence(pinfo->cinfo, COL_INFO);

    ssl_debug_flush();

    /* Make data available to ssl_follow_tap_listener */
    tap_queue_packet(tls_tap, pinfo, p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, curr_layer_num_ssl));

    return tvb_captured_length(tvb);
}

/*
 * Dissect TLS 1.3 handshake messages (without the record layer).
 * For use by QUIC (draft -13).
 */
static int
dissect_tls13_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    conversation_t    *conversation;
    SslDecryptSession *ssl_session;
    SslSession        *session;
    gint               is_from_server;
    proto_item        *ti;
    proto_tree        *ssl_tree;
    /**
     * A value that uniquely identifies this fragment in this frame.
     */
    guint              record_id = GPOINTER_TO_UINT(data);

    ssl_debug_printf("\n%s enter frame #%u (%s)\n", G_STRFUNC, pinfo->num, (pinfo->fd->visited)?"already visited":"first time");

    conversation = find_or_create_conversation(pinfo);
    ssl_session = ssl_get_session(conversation, tls_handle);
    session = &ssl_session->session;
    is_from_server = ssl_packet_from_server(session, ssl_associations, pinfo);
    if (session->version == SSL_VER_UNKNOWN) {
        session->version = TLSV1DOT3_VERSION;
        ssl_session->state |= SSL_VERSION;
        ssl_session->state |= SSL_QUIC_RECORD_LAYER;
    }

    /*
     * First pass: collect state (including Client Random for key matching).
     * Second pass: dissection only, no need to collect state.
     */
    if (PINFO_FD_VISITED(pinfo)) {
         ssl_session = NULL;
    }

    ssl_debug_printf("  conversation = %p, ssl_session = %p, from_server = %d\n",
                     (void *)conversation, (void *)ssl_session, is_from_server);

    /* Add a proto_tls item to allow simple "tls" display filter */
    ti = proto_tree_add_item(tree, proto_tls, tvb, 0, -1, ENC_NA);
    ssl_tree = proto_item_add_subtree(ti, ett_tls);

    dissect_tls_handshake(tvb, pinfo, ssl_tree, 0,
                          tvb_reported_length(tvb), FALSE, record_id, pinfo->curr_layer_num, session,
                          is_from_server, ssl_session, TLSV1DOT3_VERSION);

    ssl_debug_flush();

    return tvb_captured_length(tvb);
}

static gboolean
is_sslv3_or_tls(tvbuff_t *tvb)
{
    guint8              content_type;
    guint16             protocol_version, record_length;

    /*
     * Heuristics should match the TLS record header.
     * ContentType (1), ProtocolVersion (2), Length (2)
     *
     * We do not check for an actual payload, IBM WebSphere is known
     * to separate the record header and payload over two separate packets.
     */
    if (tvb_captured_length(tvb) < 5) {
        return FALSE;
    }

    content_type = tvb_get_guint8(tvb, 0);
    protocol_version = tvb_get_ntohs(tvb, 1);
    record_length = tvb_get_ntohs(tvb, 3);

    /* These are the common types. */
    if (content_type != SSL_ID_HANDSHAKE && content_type != SSL_ID_APP_DATA) {
        return FALSE;
    }

    /*
     * Match SSLv3, TLS 1.0/1.1/1.2 (TLS 1.3 uses same value as TLS 1.0). Most
     * likely you'll see 0x300 (SSLv3) or 0x301 (TLS 1.1) for interoperability
     * reasons. Per RFC 5246 we should accept any 0x3xx value, but this is just
     * a heuristic that catches common/likely cases.
     */
    if (protocol_version != SSLV3_VERSION &&
        protocol_version != TLSV1_VERSION &&
        protocol_version != TLSV1DOT1_VERSION &&
        protocol_version != TLSV1DOT2_VERSION &&
        protocol_version != GMTLSV1_VERSION ) {
        return FALSE;
    }

    /* Check for sane length, see also ssl_check_record_length in packet-tls-utils.c */
    if (record_length == 0 || record_length >= TLS_MAX_RECORD_LENGTH + 2048) {
        return FALSE;
    }

    return TRUE;
}

static gboolean
is_sslv2_clienthello(tvbuff_t *tvb)
{
    /*
     * Detect SSL 2.0 compatible Client Hello as used in SSLv3 and TLS.
     *
     * https://tools.ietf.org/html/rfc5246#appendix-E.2
     *  uint8 V2CipherSpec[3];
     *  struct {
     *      uint16 msg_length;          // 0: highest bit must be 1
     *      uint8 msg_type;             // 2: 1 for Client Hello
     *      Version version;            // 3: equal to ClientHello.client_version
     *      uint16 cipher_spec_length;  // 5: cannot be 0, must be multiple of 3
     *      uint16 session_id_length;   // 7: zero or 16 (in TLS 1.0)
     *      uint16 challenge_length;    // 9: must be 32
     *      // length so far: 2 + 1 + 2 + 2 + 2 + 2 = 11
     *      V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];    // len: min 3
     *      opaque session_id[V2ClientHello.session_id_length];             // len: zero or 16
     *      opaque challenge[V2ClientHello.challenge_length;                // len: 32
     *      // min. length: 11 + 3 + (0 or 16) + 32 = 46 or 62
     *  } V2ClientHello;
     */
    if (tvb_captured_length(tvb) < 46) {
        return FALSE;
    }

    /* Assume that message length is less than 256 (at most 64 cipherspecs). */
    if (tvb_get_guint8(tvb, 0) != 0x80) {
        return FALSE;
    }

    /* msg_type must be 1 for Client Hello */
    if (tvb_get_guint8(tvb, 2) != 1) {
        return FALSE;
    }

    /* cipher spec length must be a non-zero multiple of 3 */
    guint16 cipher_spec_length = tvb_get_ntohs(tvb, 5);
    if (cipher_spec_length == 0 || cipher_spec_length % 3 != 0) {
        return FALSE;
    }

    /* session ID length must be 0 or 16 in TLS 1.0 */
    guint16 session_id_length = tvb_get_ntohs(tvb, 7);
    if (session_id_length != 0 && session_id_length != 16) {
        return FALSE;
    }

    /* Challenge Length must be 32 */
    if (tvb_get_ntohs(tvb, 9) != 32) {
        return FALSE;
    }

    return TRUE;
}

static int
dissect_ssl_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t     *conversation;

    if (!is_sslv3_or_tls(tvb) && !is_sslv2_clienthello(tvb)) {
        return 0;
    }

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, tls_handle);
    return dissect_ssl(tvb, pinfo, tree, data);
}

static void
tls_save_decrypted_record(packet_info *pinfo, gint record_id, SslDecryptSession *ssl, guint8 content_type,
                          SslDecoder *decoder, gboolean allow_fragments, guint8 curr_layer_num_ssl)
{
    const guchar *data = ssl_decrypted_data.data;
    guint datalen = ssl_decrypted_data_avail;

    if (datalen == 0) {
        return;
    }

    if (ssl->session.version == TLSV1DOT3_VERSION) {
        /*
         * The actual data is followed by the content type and then zero or
         * more padding. Scan backwards for content type, skipping padding.
         */
        while (datalen > 0 && data[datalen - 1] == 0) {
            datalen--;
        }
        ssl_debug_printf("%s found %d padding bytes\n", G_STRFUNC, ssl_decrypted_data_avail - datalen);
        if (datalen == 0) {
            ssl_debug_printf("%s there is no room for content type!\n", G_STRFUNC);
            return;
        }
        content_type = data[--datalen];
        if (datalen == 0) {
            /*
             * XXX zero-length Handshake fragments are forbidden by RFC 8446,
             * Section 5.1. Empty Application Data fragments are allowed though.
             */
            return;
        }
    }

    /* In TLS 1.3 only Handshake and Application Data can be fragmented.
     * Alert messages MUST NOT be fragmented across records, so do not
     * bother maintaining a flow for those. */
    ssl_add_record_info(proto_tls, pinfo, data, datalen, record_id,
            allow_fragments ? decoder->flow : NULL, (ContentType)content_type, curr_layer_num_ssl);
}

/**
 * Try to decrypt the record and update the internal cipher state.
 * On success, the decrypted data will be available in "ssl_decrypted_data" of
 * length "ssl_decrypted_data_avail".
 */
static gboolean
decrypt_ssl3_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset, SslDecryptSession *ssl,
        guint8 content_type, guint16 record_version, guint16 record_length,
        gboolean allow_fragments, guint8 curr_layer_num_ssl)
{
    gboolean    success;
    gint        direction;
    StringInfo *data_for_iv;
    gint        data_for_iv_len;
    SslDecoder *decoder;

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
        return FALSE;
    }

    /* run decryption and add decrypted payload to protocol data, if decryption
     * is successful*/
    ssl_decrypted_data_avail = ssl_decrypted_data.data_len;
    success = ssl_decrypt_record(ssl, decoder, content_type, record_version, tls_ignore_mac_failed,
                           tvb_get_ptr(tvb, offset, record_length), record_length, NULL, 0,
                           &ssl_compressed_data, &ssl_decrypted_data, &ssl_decrypted_data_avail) == 0;
    /*  */
    if (!success) {
        /* save data to update IV if valid session key is obtained later */
        data_for_iv = (direction != 0) ? &ssl->server_data_for_iv : &ssl->client_data_for_iv;
        data_for_iv_len = (record_length < 24) ? record_length : 24;
        ssl_data_set(data_for_iv, (const guchar*)tvb_get_ptr(tvb, offset + record_length - data_for_iv_len, data_for_iv_len), data_for_iv_len);
    }
    if (success) {
        tls_save_decrypted_record(pinfo, tvb_raw_offset(tvb)+offset, ssl, content_type, decoder, allow_fragments, curr_layer_num_ssl);
    }
    return success;
}

/**
 * Try to guess the early data cipher using trial decryption.
 * Requires Libgcrypt 1.6 or newer for verifying that decryption is successful.
 */
static gboolean
decrypt_tls13_early_data(tvbuff_t *tvb, packet_info *pinfo, guint32 offset,
                         guint16 record_length, SslDecryptSession *ssl,
                         guint8 curr_layer_num_ssl)

{
    gboolean        success = FALSE;

    ssl_debug_printf("Trying early data encryption, first record / trial decryption: %s\n",
                    !(ssl->state & SSL_SEEN_0RTT_APPDATA) ? "true" : "false");

    /* Only try trial decryption for the first record. */
    if (ssl->state & SSL_SEEN_0RTT_APPDATA) {
        if (!ssl->client) {
            return FALSE;       // sanity check, should not happen in valid captures.
        }

        ssl_decrypted_data_avail = ssl_decrypted_data.data_len;
        success = ssl_decrypt_record(ssl, ssl->client, SSL_ID_APP_DATA, 0x303, FALSE,
                                     tvb_get_ptr(tvb, offset, record_length), record_length, NULL, 0,
                                     &ssl_compressed_data, &ssl_decrypted_data, &ssl_decrypted_data_avail) == 0;
        if (success) {
            tls_save_decrypted_record(pinfo, tvb_raw_offset(tvb)+offset, ssl, SSL_ID_APP_DATA, ssl->client, TRUE, curr_layer_num_ssl);
        } else {
            ssl_debug_printf("early data decryption failed, end of early data?\n");
        }
        return success;
    }
    ssl->state |= SSL_SEEN_0RTT_APPDATA;

    ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
    StringInfo *secret = tls13_load_secret(ssl, &ssl_master_key_map, FALSE, TLS_SECRET_0RTT_APP);
    if (!secret) {
        ssl_debug_printf("Missing secrets, early data decryption not possible!\n");
        return FALSE;
    }

    const guint16 tls13_ciphers[] = {
        0x1301, /* TLS_AES_128_GCM_SHA256 */
        0x1302, /* TLS_AES_256_GCM_SHA384 */
        0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
        0x1304, /* TLS_AES_128_CCM_SHA256 */
        0x1305, /* TLS_AES_128_CCM_8_SHA256 */
    };
    const guchar   *record = tvb_get_ptr(tvb, offset, record_length);
    for (guint i = 0; i < G_N_ELEMENTS(tls13_ciphers); i++) {
        guint16 cipher = tls13_ciphers[i];

        ssl_debug_printf("Performing early data trial decryption, cipher = %#x\n", cipher);
        ssl->session.cipher = cipher;
        ssl->cipher_suite = ssl_find_cipher(cipher);
        if (!tls13_generate_keys(ssl, secret, FALSE)) {
            /* Unable to create cipher (old Libgcrypt) */
            continue;
        }

        ssl_decrypted_data_avail = ssl_decrypted_data.data_len;
        success = ssl_decrypt_record(ssl, ssl->client, SSL_ID_APP_DATA, 0x303, FALSE, record, record_length, NULL, 0,
                                     &ssl_compressed_data, &ssl_decrypted_data, &ssl_decrypted_data_avail) == 0;
        if (success) {
            ssl_debug_printf("Early data decryption succeeded, cipher = %#x\n", cipher);
            tls_save_decrypted_record(pinfo, tvb_raw_offset(tvb)+offset, ssl, SSL_ID_APP_DATA, ssl->client, TRUE, curr_layer_num_ssl);
            break;
        }
    }
    if (!success) {
        ssl_debug_printf("Trial decryption of early data failed!\n");
    }
    return success;
}

static void
process_ssl_payload(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, SslSession *session,
                    dissector_handle_t app_handle_port);

static guint32
tls_msp_fragment_id(struct tcp_multisegment_pdu *msp)
{
    /*
     * If a frame contains multiple appdata PDUs, then "first_frame" is not
     * sufficient to uniquely identify groups of fragments. Therefore we use
     * the tcp reassembly functions that also test msp->seq (the position of
     * the initial fragment in the TLS stream).
     * As a frame most likely does not have multiple PDUs (except maybe for
     * HTTP2), just check 'seq' at the end instead of using it in the hash.
     */
    guint32 id = msp->first_frame;
#if 0
    id ^= (msp->seq & 0xff) << 24;
    id ^= (msp->seq & 0xff00) << 16;
#endif
    return id;
}

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
            /* This must be after the first pass. */
            prefix = "";
            if (msp->last_frame == pinfo->num) {
                col_clear(pinfo->cinfo, COL_INFO);
            } else {
                col_set_str(pinfo->cinfo, COL_INFO, "[TLS segment of a reassembled PDU]");
            }
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
                                 pinfo, tls_msp_fragment_id(msp), msp,
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
    if (ipfd_head && ipfd_head->reassembled_in == pinfo->num) {
        /*
         * Yes, we think it is.
         * We only call subdissector for the last segment.
         * Note that the last segment may include more than what
         * we needed.
         */
        if (nxtseq < msp->nxtpdu) {
            /*
             * This is *not* the last segment. It is part of a PDU in the same
             * frame, so no another PDU can follow this one.
             * Do not reassemble TLS yet, it will be done in the final segment.
             * Clear the Info column and avoid displaying [TLS segment of a
             * reassembled PDU], the payload dissector will typically set it.
             * (This is needed here for the second pass.)
             */
            another_pdu_follows = 0;
            col_clear(pinfo->cinfo, COL_INFO);
            another_segment_in_frame = TRUE;
        } else {
            /*
             * OK, this is the last segment of the PDU and also the
             * last segment in this frame.
             * Let's call the subdissector with the desegmented
             * data.
             */
            tvbuff_t *next_tvb;
            int old_len;

            /*
             * Reset column in case multiple TLS segments form the
             * PDU and this last TLS segment is not in the first TCP segment of
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
                                                pinfo, tls_msp_fragment_id(msp), msp);
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
                         pinfo, tls_msp_fragment_id(msp), msp,
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
            proto_item_set_generated(item);
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
            col_set_str(pinfo->cinfo, COL_INFO, "[TLS segment of a reassembled PDU]");
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
            call_data_dissector(next_tvb, pinfo, proto_tree_get_root(tree));
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
dissect_ssl_payload(tvbuff_t *decrypted, packet_info *pinfo,
                    proto_tree *tree, SslSession *session,
                    SslRecordInfo *record,
                    dissector_handle_t app_handle_port)
{
    gboolean     save_fragmented;
    guint16      save_can_desegment;

    /* Preserve current desegmentation ability to prevent the subdissector
     * from messing up the ssl desegmentation */
    save_can_desegment = pinfo->can_desegment;

    /* try to dissect decrypted data*/
    ssl_debug_printf("%s decrypted len %d\n", G_STRFUNC, record->data_len);
    ssl_print_data("decrypted app data fragment", record->plain_data, record->data_len);

    /* Can we desegment this segment? */
    if (tls_desegment_app_data) {
        /* Yes. */
        pinfo->can_desegment = 2;
        desegment_ssl(decrypted, pinfo, 0, record->seq, record->seq + record->data_len,
                      session, proto_tree_get_root(tree), tree,
                      record->flow, app_handle_port);
    } else if (session->app_handle || app_handle_port) {
        /* No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame. */
        pinfo->can_desegment = 0;
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        process_ssl_payload(decrypted, 0, pinfo, tree, session, app_handle_port);
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
                    SslDecryptSession *ssl,
                    guint8 curr_layer_num_ssl)
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
    guint16         record_version, version;
    guint8          content_type;
    guint8          next_byte;
    proto_tree     *ti;
    proto_tree     *ssl_record_tree;
    proto_item     *length_pi, *ct_pi;
    guint           content_type_offset;
    guint32         available_bytes;
    tvbuff_t       *decrypted;
    SslRecordInfo  *record = NULL;

    ti = NULL;
    ssl_record_tree = NULL;

    available_bytes = tvb_reported_length_remaining(tvb, offset);

    /* TLS 1.0/1.1 just ignores unknown records - RFC 2246 chapter 6. The TLS Record Protocol */
    if ((session->version==TLSV1_VERSION ||
         session->version==TLSV1DOT1_VERSION ||
         session->version==TLSV1DOT2_VERSION ||
         session->version==GMTLSV1_VERSION ) &&
        (available_bytes >=1 ) && !ssl_is_valid_content_type(tvb_get_guint8(tvb, offset))) {
        proto_tree_add_expert(tree, pinfo, &ei_tls_ignored_unknown_record, tvb, offset, available_bytes);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Ignored Unknown Record");
        return offset + available_bytes;
    }

    /*
     * Is the record header split across segment boundaries?
     */
    if (available_bytes < 5) {
        /*
         * Yes - can we do reassembly?
         */
        if (tls_desegment && pinfo->can_desegment) {
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
    record_version = version;
    record_length = tvb_get_ntohs(tvb, offset + 3);

    if (ssl_is_valid_content_type(content_type)) {

        /*
         * Is the record split across segment boundaries?
         */
        if (available_bytes < record_length + 5) {
            /*
             * Yes - can we do reassembly?
             */
            if (tls_desegment && pinfo->can_desegment) {
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
                 * PDU, but it completely breaks dissection for jumbo TLS frames
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
        /* if we don't have a valid content_type, there's no sense
         * continuing any further
         */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Continuation Data");

        return offset + 5 + record_length;
    }

    /* add the record layer subtree header */
    ti = proto_tree_add_item(tree, hf_tls_record, tvb,
                             offset, 5 + record_length, ENC_NA);
    ssl_record_tree = proto_item_add_subtree(ti, ett_tls_record);

    /* show the one-byte content type */
    if (session->version == TLSV1DOT3_VERSION && content_type == SSL_ID_APP_DATA) {
        ct_pi = proto_tree_add_item(ssl_record_tree, hf_tls_record_opaque_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        ct_pi = proto_tree_add_item(ssl_record_tree, hf_tls_record_content_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    content_type_offset = offset;
    offset++;

    /* add the version */
    proto_tree_add_item(ssl_record_tree, hf_tls_record_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* add the length */
    length_pi = proto_tree_add_uint(ssl_record_tree, hf_tls_record_length, tvb,
                        offset, 2, record_length);
    offset += 2;    /* move past length field itself */

    /*
     * if we don't already have a version set for this conversation,
     * but this message's version is authoritative (i.e., it's
     * not client_hello, then save the version to the conversation
     * structure and print the column version. If the message is not authorative
     * (i.e. it is a Client Hello), then this version will still be used for
     * display purposes only (it will not be stored in the conversation).
     */
    next_byte = tvb_get_guint8(tvb, offset);
    if (session->version == SSL_VER_UNKNOWN) {
        ssl_try_set_version(session, ssl, content_type, next_byte, FALSE, version);
        /* Version has possibly changed, adjust the column accordingly. */
        col_set_str(pinfo->cinfo, COL_PROTOCOL,
                            val_to_str_const(version, ssl_version_short_names, "SSL"));
    } else {
        version = session->version;
    }

    /*
     * now dissect the next layer
     */
    ssl_debug_printf("dissect_ssl3_record: content_type %d %s\n",content_type, val_to_str_const(content_type, ssl_31_content_type, "unknown"));

    /* try to decrypt record on the first pass, if possible. Store decrypted
     * record for later usage (without having to decrypt again). The offset is
     * used as 'key' to identify this record in the packet (we can have multiple
     * handshake records in the same frame).
     * In TLS 1.3, only "Application Data" records are encrypted.
     */
    if (ssl && record_length && (session->version != TLSV1DOT3_VERSION || content_type == SSL_ID_APP_DATA)) {
        gboolean    decrypt_ok = FALSE;

        /* Try to decrypt TLS 1.3 early data first */
        if (session->version == TLSV1DOT3_VERSION && content_type == SSL_ID_APP_DATA &&
            ssl->has_early_data && !ssl_packet_from_server(session, ssl_associations, pinfo)) {
            decrypt_ok = decrypt_tls13_early_data(tvb, pinfo, offset, record_length, ssl, curr_layer_num_ssl);
            if (!decrypt_ok) {
                /* Either trial decryption failed (e.g. missing key) or end of
                 * early data is reached. Switch to HS secrets if available. */
                if (ssl->state & SSL_SERVER_RANDOM) {
                    tls13_change_key(ssl, &ssl_master_key_map, FALSE, TLS_SECRET_HANDSHAKE);
                }
                ssl->has_early_data = FALSE;
            }
        }

        if (!decrypt_ok) {
            decrypt_ssl3_record(tvb, pinfo, offset, ssl,
                content_type, record_version, record_length,
                content_type == SSL_ID_APP_DATA ||
                content_type == SSL_ID_HANDSHAKE, curr_layer_num_ssl);
        }
    }

    /* try to retrieve and use decrypted alert/handshake/appdata record, if any. */
    decrypted = ssl_get_record_info(tvb, proto_tls, pinfo, tvb_raw_offset(tvb)+offset, curr_layer_num_ssl, &record);
    if (decrypted) {
        add_new_data_source(pinfo, decrypted, "Decrypted TLS");
        if (session->version == TLSV1DOT3_VERSION) {
            content_type = record->type;
            ti = proto_tree_add_uint(ssl_record_tree, hf_tls_record_content_type,
                                     tvb, content_type_offset, 1, record->type);
            proto_item_set_generated(ti);
        }
    }
    ssl_check_record_length(&dissect_ssl3_hf, pinfo, (ContentType)content_type, record_length, length_pi, version, decrypted);

    switch ((ContentType) content_type) {
    case SSL_ID_CHG_CIPHER_SPEC:
        if (version == TLSV1DOT3_VERSION && session->tls13_draft_version > 0 && session->tls13_draft_version < 22) {
            /* CCS was reintroduced in TLS 1.3 draft -22 */
            expert_add_info_format(pinfo, ct_pi, &ei_tls_unexpected_message,
                                   "Record type is not allowed in TLS 1.3");
            break;
        }
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Change Cipher Spec");
        ssl_dissect_change_cipher_spec(&dissect_ssl3_hf, tvb, pinfo,
                                       ssl_record_tree, offset, session,
                                       is_from_server, ssl);
        if (version == TLSV1DOT3_VERSION) {
            /* CCS is a dummy message in TLS 1.3, do not try to load keys. */
            break;
        }
        if (ssl) {
            ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file,
                             &ssl_master_key_map);
            ssl_finalize_decryption(ssl, &ssl_master_key_map);
            ssl_change_cipher(ssl, ssl_packet_from_server(session, ssl_associations, pinfo));
        }
        /* Heuristic: any later ChangeCipherSpec is not a resumption of this
         * session. Set the flag after ssl_finalize_decryption such that it has
         * a chance to use resume using Session Tickets. */
        if (is_from_server)
          session->is_session_resumed = FALSE;
        break;
    case SSL_ID_ALERT:
        if (decrypted) {
            dissect_ssl3_alert(decrypted, pinfo, ssl_record_tree, 0, 2, session);
        } else {
            dissect_ssl3_alert(tvb, pinfo, ssl_record_tree, offset, record_length, session);
        }
        break;
    case SSL_ID_HANDSHAKE:
        if (decrypted) {
            guint record_id = record->id;
            dissect_tls_handshake(decrypted, pinfo, ssl_record_tree, 0,
                                  tvb_reported_length(decrypted), FALSE, record_id, curr_layer_num_ssl, session,
                                  is_from_server, ssl, version);
        } else {
            // Combine both the offset within this TCP segment and the layer
            // number in case a record consists of multiple reassembled TCP
            // segments. The exact value does not matter, but it should be
            // unique per frame.
            guint record_id = tvb_raw_offset(tvb) + offset + curr_layer_num_ssl;
            dissect_tls_handshake(tvb, pinfo, ssl_record_tree, offset,
                                  offset + record_length, TRUE, record_id, curr_layer_num_ssl, session,
                                  is_from_server, ssl, version);
        }
        break;
    case SSL_ID_APP_DATA:
    {
        dissector_handle_t app_handle;

        /* show on info column what we are decoding */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Application Data");

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
            val_to_str_const(version, ssl_version_short_names, "SSL"),
            val_to_str_const(content_type, ssl_31_content_type, "unknown"),
            app_handle ? dissector_handle_get_dissector_name(app_handle)
            : "Application Data");

        proto_tree_add_item(ssl_record_tree, hf_tls_record_appdata, tvb,
                       offset, record_length, ENC_NA);

        if (app_handle) {
            ti = proto_tree_add_string(ssl_record_tree, hf_tls_record_appdata_proto, tvb, 0, 0, dissector_handle_get_dissector_name(app_handle));
            proto_item_set_generated(ti);
        }

        if (decrypted) {
            dissect_ssl_payload(decrypted, pinfo, tree, session, record, app_handle);
        }

        /* Set app proto again in case the heuristics found a different proto. */
        if (session->app_handle && session->app_handle != app_handle)
            proto_item_set_text(ssl_record_tree,
               "%s Record Layer: %s Protocol: %s",
                val_to_str_const(version, ssl_version_short_names, "SSL"),
                val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                dissector_handle_get_dissector_name(session->app_handle));

        break;
    }
    case SSL_ID_HEARTBEAT:
        if (version == TLSV1DOT3_VERSION) {
            expert_add_info_format(pinfo, ct_pi, &ei_tls_unexpected_message,
                                   "Record type is not allowed in TLS 1.3");
            break;
        }
        if (decrypted) {
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
    case SSL_ID_TLS12_CID:
        break;
    }
    offset += record_length; /* skip to end of record */

    return offset;
}

/* dissects the alert message, filling in the tree */
static void
dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, guint32 offset, guint32 record_length,
                   const SslSession *session)
{
    /*     struct {
     *         AlertLevel level;
     *         AlertDescription description;
     *     } Alert;
     */
    proto_tree  *ti;
    proto_tree  *alert_tree = NULL;
    const gchar *level;
    const gchar *desc;
    guint8       level_byte, desc_byte;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_tls_alert_message, tvb,
                                 offset, record_length, ENC_NA);
        alert_tree = proto_item_add_subtree(ti, ett_tls_alert);
    }

    /*
     * Assume that TLS alert records are not fragmented. Any larger message is
     * assumed to be encrypted.
     */
    if (record_length != 2) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Alert");
        proto_item_set_text(tree,
                            "%s Record Layer: Encrypted Alert",
                            val_to_str_const(session->version, ssl_version_short_names, "TLS"));
        proto_item_set_text(alert_tree,
                            "Alert Message: Encrypted Alert");
        return;
    }

    /*
     * set the record layer label
     */

    /* first lookup the names for the alert level and description */
    level_byte = tvb_get_guint8(tvb, offset); /* grab the level byte */
    level = val_to_str_const(level_byte, ssl_31_alert_level, "Unknown");

    desc_byte = tvb_get_guint8(tvb, offset+1); /* grab the desc byte */
    desc = val_to_str_const(desc_byte, ssl_31_alert_description, "Unknown");

    /* now set the text in the record layer line */
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        "Alert (Level: %s, Description: %s)",
                        level, desc);

    if (tree)
    {
        proto_item_set_text(tree, "%s Record Layer: Alert "
                            "(Level: %s, Description: %s)",
                            val_to_str_const(session->version, ssl_version_short_names, "TLS"),
                            level, desc);
        proto_tree_add_item(alert_tree, hf_tls_alert_message_level,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(alert_tree, hf_tls_alert_message_description,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
    }
}


/**
 * Checks whether a handshake message seems encrypted and cannot be dissected.
 */
static gboolean
is_encrypted_handshake_message(tvbuff_t *tvb, packet_info *pinfo, guint32 offset, guint32 offset_end,
                               gboolean maybe_encrypted, SslSession *session, gboolean is_from_server)
{
    guint record_length = offset_end - offset;

    if (record_length < 16) {
        /*
         * Encrypted data has additional overhead. For TLS 1.0/1.1 with stream
         * and block ciphers, there is at least a MAC which is at minimum 16
         * bytes for MD5. In TLS 1.2, AEAD adds an explicit nonce and auth tag.
         * For AES-GCM/CCM the auth tag is 16 bytes. AES_CCM_8 (RFC 6655) uses 8
         * byte auth tags, but the explicit nonce is also 8 (sums up to 16).
         *
         * So anything smaller than 16 bytes is assumed to be plaintext.
         */
        return FALSE;
    }

    /*
     * If this is not a decrypted buffer, then perhaps it is still in plaintext.
     * Heuristics: if the buffer is too small, it is likely not encrypted.
     * Otherwise assume that the Handshake does not contain two successive
     * HelloRequest messages (type=0x00 length=0x000000, type=0x00). If this
     * occurs, then we have possibly found the explicit nonce preceding the
     * encrypted contents for GCM/CCM cipher suites as used in TLS 1.2.
     */
    if (maybe_encrypted) {
        maybe_encrypted = tvb_get_ntoh40(tvb, offset) == 0;
        /*
         * Everything after the ChangeCipherSpec message is encrypted.
         * TODO handle Finished message after CCS in the same frame and remove the
         * above nonce-based heuristic.
         */
        if (!maybe_encrypted) {
            guint32 ccs_frame = is_from_server ? session->server_ccs_frame : session->client_ccs_frame;
            maybe_encrypted = ccs_frame != 0 && pinfo->num > ccs_frame;
        }
    }

    if (!maybe_encrypted) {
        /*
         * Assume encrypted if the message type makes no sense. If this still
         * leads to false positives (detecting plaintext while it should mark
         * stuff as encrypted), some other ideas include:
         * - Perform additional validation based on the message type.
         * - Disallow handshake fragmentation except for some common cases like
         *   Certificate messages (due to large certificates).
         */
        guint8 msg_type = tvb_get_guint8(tvb, offset);
        maybe_encrypted = try_val_to_str(msg_type, ssl_31_handshake_type) == NULL;
        if (!maybe_encrypted) {
            guint msg_length = tvb_get_ntoh24(tvb, offset + 1);
            // Assume handshake messages are below 64K.
            maybe_encrypted = msg_length >= 0x010000;
        }
    }
    return maybe_encrypted;
}

static TlsHsFragment *
save_tls_handshake_fragment(packet_info *pinfo, guint8 curr_layer_num_tls,
                            guint record_id, guint reassembly_id,
                            tvbuff_t *tvb, guint32 offset, guint frag_len,
                            guint frag_offset, guint8 msg_type, gboolean is_last)
{
    // Full handshake messages should not be saved.
    DISSECTOR_ASSERT(!(frag_offset == 0 && is_last));
    // Fragment data must be non-empty.
    DISSECTOR_ASSERT(frag_len != 0);
    // 0 is a special value indicating no reassembly in progress.
    DISSECTOR_ASSERT(reassembly_id != 0);

    if (tvb_reported_length(tvb) > tvb_captured_length(tvb)) {
        // The reassembly API will refuse to add fragments when not all
        // available data has been captured. Since we were given a tvb with at
        // least 'frag_len' data, we must always succeed in obtaining a subset.
        tvb = tvb_new_subset_length(tvb, 0, offset + frag_len);
    }

    SslPacketInfo *pi = tls_add_packet_info(proto_tls, pinfo, curr_layer_num_tls);
    TlsHsFragment *frag_info = wmem_new0(wmem_file_scope(), TlsHsFragment);
    frag_info->record_id = record_id;
    frag_info->reassembly_id = reassembly_id;
    frag_info->is_last = is_last;
    frag_info->offset = frag_offset;
    frag_info->type = msg_type;

    TlsHsFragment **p = &pi->hs_fragments;
    while (*p) p = &(*p)->next;
    *p = frag_info;

    // Add (subset of) record data.
    fragment_add_check(&tls_hs_reassembly_table, tvb, offset,
                       pinfo, reassembly_id, NULL, frag_offset, frag_len, !is_last);

    return frag_info;
}

/**
 * Populate the Info column and record layer tree item based on the message type.
 *
 * @param pinfo Packet info.
 * @param record_tree The Record layer tree item.
 * @param version Record version.
 * @param msg_type The message type (not necessarily the same as the first byte
 * of the buffer in case of HRR in TLS 1.3).
 * @param is_first_msg TRUE if this is the first message in this record.
 * @param complete TRUE if the buffer describes the full (encrypted) message.
 * @param tvb Buffer that covers the start of this handshake fragment.
 * @param offset Position within the record data.
 * @param length Length of the record fragment that is part of the handshake
 * message. May be smaller than the record length if this is a fragment.
 */
static proto_item *
tls_show_handshake_details(packet_info *pinfo, proto_tree *record_tree, guint version,
        guint8 msg_type, gboolean is_encrypted, gboolean is_first_msg, gboolean complete,
        tvbuff_t *tvb, guint32 offset, guint32 length)
{
    const char *msg_type_str = "Encrypted Handshake Message";
    if (!is_encrypted) {
        msg_type_str = val_to_str_const(msg_type, ssl_31_handshake_type, msg_type_str);
    }

    /*
     * Update our info string if this is the first message (possibly a fragment
     * of a handshake message), or if this is a complete (reassembled) message.
     */
    if (complete) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_type_str);
    } else if (is_first_msg) {
        /*
         * Only mark the first message to avoid an empty Info column. If another
         * message came before this one, do not bother mentioning this fragment.
         */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "[%s Fragment]", msg_type_str);
    }

    /* set the label text on the record layer expanding node */
    if (is_first_msg) {
        proto_item_set_text(record_tree, "%s Record Layer: Handshake Protocol: %s",
                val_to_str_const(version, ssl_version_short_names, "TLS"),
                msg_type_str);
        if (!complete && !is_encrypted) {
            proto_item_append_text(record_tree, " (fragment)");
        }
    } else {
        proto_item_set_text(record_tree, "%s Record Layer: Handshake Protocol: %s",
                val_to_str_const(version, ssl_version_short_names, "TLS"),
                "Multiple Handshake Messages");
    }

    proto_item *ti = proto_tree_add_item(record_tree, hf_tls_handshake_protocol,
            tvb, offset, length, ENC_NA);
    proto_item_set_text(ti, "Handshake Protocol: %s", msg_type_str);
    if (!complete && !is_encrypted) {
        proto_item_append_text(ti, " (fragment)");
    }
    return ti;
}

/* dissects the handshake protocol, filling the tree */
static void
dissect_tls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *tree, guint32 offset,
                      guint32 offset_end, gboolean maybe_encrypted,
                      guint record_id, guint8 curr_layer_num_tls,
                      SslSession *session, gint is_from_server,
                      SslDecryptSession *ssl,
                      const guint16 version)
{
    // Handshake fragment processing:
    // 1. (First pass:) If a previous handshake message needed reasembly, add
    //    (a subset of) the new data for reassembly.
    // 2. Did this fragment complete reasembly in the previous step?
    //    - Yes: dissect message and continue.
    //    - No: show details and stop.
    // 3. Not part of a reassembly, so this is a new handshake message. Does it
    //    look like encrypted data?
    //    - Yes: show details and stop.
    // 4. Loop through remaining handshake messages. Is there sufficient data?
    //    - Yes: dissect message and continue with next message.
    //    - No (first pass): Add all data for reassembly, show details and stop.
    //    - No (second pass): Show details and stop.

    fragment_head  *fh = NULL;
    guint           subset_len;
    guint32         msg_len = 0;
    TlsHsFragment  *frag_info = NULL;
    gboolean        is_first_msg = TRUE;
    proto_item     *frag_tree_item;
    guint          *hs_reassembly_id_p = is_from_server ? &session->server_hs_reassembly_id : &session->client_hs_reassembly_id;

    if (!PINFO_FD_VISITED(pinfo)) {
        // 1. (First pass:) If a previous handshake message needed reasembly.
        if (*hs_reassembly_id_p) {
            // Continuation, so a previous fragment *must* exist.
            fh = fragment_get(&tls_hs_reassembly_table, pinfo, *hs_reassembly_id_p, NULL);
            DISSECTOR_ASSERT(fh);
            // We expect that reassembly has not completed yet.
            DISSECTOR_ASSERT(fh->tvb_data == NULL);

            // Combine all previous segments plus data from the current record
            // in order to find the length.
            tvbuff_t *len_tvb = tvb_new_composite();
            guint frags_len = 0;
            for (fragment_item *fd = fh->next; fd; fd = fd->next) {
                if (frags_len < 4) {
                    tvb_composite_append(len_tvb, fd->tvb_data);
                }
                frags_len += tvb_reported_length(fd->tvb_data);
            }
            if (frags_len < 4) {
                tvbuff_t *remaining_tvb = tvb_new_subset_remaining(tvb, offset);
                tvb_composite_append(len_tvb, remaining_tvb);
            }
            tvb_composite_finalize(len_tvb);

            // Extract the actual handshake message length (0 means unknown) and
            // check whether only a subset of the current record is needed.
            subset_len = offset_end - offset;
            if (tvb_reported_length(len_tvb) >= 4) {
                msg_len = 4 + tvb_get_ntoh24(len_tvb, 1);
                if (subset_len > msg_len - frags_len) {
                    subset_len = msg_len - frags_len;
                }
            }

            if (tvb_captured_length(tvb) < offset + subset_len) {
                // Not all data has been captured. As we are missing data, the
                // reassembly cannot be completed nor do we know the boundary
                // where the next handshake message starts. Stop reassembly.
                *hs_reassembly_id_p = 0;
            } else {
                // Check if the handshake message is complete.
                guint8 msg_type = tvb_get_guint8(len_tvb, 0);
                gboolean is_last = frags_len + subset_len == msg_len;
                frag_info = save_tls_handshake_fragment(pinfo, curr_layer_num_tls, record_id, *hs_reassembly_id_p,
                        tvb, offset, subset_len, frags_len, msg_type, is_last);
                if (is_last) {
                    // Reassembly finished, next message should not continue this message.
                    *hs_reassembly_id_p = 0;
                }
            }
        }
    } else {
        // Lookup the reassembled handshake matching this frame (if any).
        SslPacketInfo *pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, curr_layer_num_tls);
        if (pi) {
            for (TlsHsFragment *rec = pi->hs_fragments; rec; rec = rec->next) {
                if (rec->record_id == record_id) {
                    frag_info = rec;
                    break;
                }
            }
        }
    }

    // 2. Did this fragment complete reasembly in the previous step?
    if (frag_info && frag_info->offset != 0) {
        fh = fragment_get_reassembled_id(&tls_hs_reassembly_table, pinfo, frag_info->reassembly_id);
        if (frag_info->is_last) {
            // This is the last fragment of the handshake message.
            // Skip a subset of the bytes of this buffer.
            subset_len = tvb_reported_length_remaining(fh->tvb_data, frag_info->offset);

            // Add a tree item to mark the handshake fragment.
            proto_item *ti = proto_tree_add_item(tree,
                    hf_tls_handshake_protocol, tvb, offset, subset_len, ENC_NA);
            offset += subset_len;
            proto_item_set_text(ti, "Handshake Protocol: %s (last fragment)",
                    val_to_str_const(frag_info->type, ssl_31_handshake_type,
                        "Encrypted Handshake Message"));

            // Now display the full, reassembled handshake message.
            tvbuff_t *next_tvb = tvb_new_chain(tvb, fh->tvb_data);
            add_new_data_source(pinfo, next_tvb, "Reassembled TLS Handshake");
            show_fragment_tree(fh, &tls_hs_fragment_items, tree, pinfo, next_tvb, &frag_tree_item);
            dissect_tls_handshake_full(next_tvb, pinfo, tree, 0, session, is_from_server, ssl, version, TRUE);
            is_first_msg = FALSE;

            // Skip to the next fragment in case this records ends with another
            // fragment for which information is presented below.
            frag_info = frag_info->next;
            if (frag_info && frag_info->record_id != record_id) {
                frag_info = NULL;
            }
        } else if (frag_info->offset != 0) {
            // The full TVB is in the middle of a handshake message and needs more data.
            tls_show_handshake_details(pinfo, tree, version, frag_info->type, FALSE, FALSE, FALSE,
                    tvb, offset, offset_end - offset);
            if (fh) {
                proto_tree_add_uint(tree, hf_tls_handshake_reassembled_in, tvb, 0, 0, fh->reassembled_in);
            }
            return;
        }
    } else if (!frag_info) {
        // 3. Not part of a reassembly, so this is a new handshake message. Does it
        //    look like encrypted data?
        if (is_encrypted_handshake_message(tvb, pinfo, offset, offset_end, maybe_encrypted, session, is_from_server)) {
            // Update Info column and record tree.
            tls_show_handshake_details(pinfo, tree, version, 0, TRUE, TRUE, TRUE,
                    tvb, offset, offset_end - offset);
            return;
        }
    }

    // 4. Loop through remaining handshake messages.
    // The previous reassembly has been handled, so at this point, offset should
    // start a new, valid handshake message.
    while (offset < offset_end) {
        msg_len = 0;
        subset_len = offset_end - offset;
        if (subset_len >= 4) {
            msg_len = 4 + tvb_get_ntoh24(tvb, offset + 1);
        }
        if (msg_len == 0 || subset_len < msg_len) {
            // Need more data to find the message length or complete it.
            if (!PINFO_FD_VISITED(pinfo)) {
                guint8 msg_type = tvb_get_guint8(tvb, offset);
                *hs_reassembly_id_p = ++hs_reassembly_id_count;
                frag_info = save_tls_handshake_fragment(pinfo, curr_layer_num_tls, record_id, *hs_reassembly_id_p,
                        tvb, offset, subset_len, 0, msg_type, FALSE);
            } else {
                // The first pass must have created a new fragment.
                DISSECTOR_ASSERT(frag_info && frag_info->offset == 0);
            }

            tls_show_handshake_details(pinfo, tree, version, frag_info->type, FALSE, is_first_msg, FALSE,
                    tvb, offset, subset_len);
            fh = fragment_get_reassembled_id(&tls_hs_reassembly_table, pinfo, frag_info->reassembly_id);
            if (fh) {
                proto_tree_add_uint(tree, hf_tls_handshake_reassembled_in, tvb, 0, 0, fh->reassembled_in);
            }
            break;
        }

        dissect_tls_handshake_full(tvb, pinfo, tree, offset, session, is_from_server, ssl, version, is_first_msg);
        offset += msg_len;
        is_first_msg = FALSE;
    }
}

/* Dissects a single (reassembled) Handshake message. */
static void
dissect_tls_handshake_full(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, guint32 offset,
                           SslSession *session, gint is_from_server,
                           SslDecryptSession *ssl,
                           const guint16 version,
                           gboolean is_first_msg)
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
    proto_tree  *ssl_hand_tree = NULL;
    const gchar *msg_type_str;
    guint8       msg_type;
    guint32      length;
    proto_item  *ti;

    {
        guint32 hs_offset = offset;
        gboolean is_hrr = FALSE;

        msg_type = tvb_get_guint8(tvb, offset);
        length   = tvb_get_ntoh24(tvb, offset + 1);
        // The caller should have given us a fully reassembled record.
        DISSECTOR_ASSERT((guint)tvb_reported_length_remaining(tvb, offset + 4) >= length);

        msg_type_str = try_val_to_str(msg_type, ssl_31_handshake_type);

        ssl_debug_printf("dissect_ssl3_handshake iteration %d type %d offset %d length %d "
            "bytes\n", is_first_msg, msg_type, offset, length);
        if (!msg_type_str && !is_first_msg)
        {
            /* only dissect / report messages if they're
             * either the first message in this record
             * or they're a valid message type
             */
            return;
        }

        if (is_first_msg && msg_type == SSL_HND_SERVER_HELLO && length > 2) {
            guint16 server_version;

            tls_scan_server_hello(tvb, offset + 4, offset + 4 + length, &server_version, &is_hrr);
            ssl_try_set_version(session, ssl, SSL_ID_HANDSHAKE, SSL_HND_SERVER_HELLO, FALSE, server_version);
            if (is_hrr) {
                msg_type_str = "Hello Retry Request";
            }
        }

        /* Populate Info column and set record layer text. */
        ti = tls_show_handshake_details(pinfo, tree, version,
                is_hrr ? SSL_HND_HELLO_RETRY_REQUEST : msg_type, FALSE, is_first_msg, TRUE,
                tvb, offset, length + 4);

        /* if we don't have a valid handshake type, just quit dissecting */
        if (!msg_type_str)
            return;

        /* add a subtree for the handshake protocol */
        ssl_hand_tree = proto_item_add_subtree(ti, ett_tls_handshake);

        /* add nodes for the message type and message length */
        proto_tree_add_uint(ssl_hand_tree, hf_tls_handshake_type,
                tvb, offset, 1, msg_type);
        offset += 1;
        proto_tree_add_uint(ssl_hand_tree, hf_tls_handshake_length,
                tvb, offset, 3, length);
        offset += 3;

        if ((msg_type == SSL_HND_CLIENT_HELLO || msg_type == SSL_HND_SERVER_HELLO)) {
            /* Prepare for renegotiation by resetting the state. */
            ssl_reset_session(session, ssl, msg_type == SSL_HND_CLIENT_HELLO);
        }

        /*
         * Add handshake message (including type, length, etc.) to hash (for
         * Extended Master Secret).
         * Hash ClientHello up to and including ClientKeyExchange. As the
         * premaster secret is looked up during ChangeCipherSpec processing (an
         * implementation detail), we must skip the CertificateVerify message
         * which can appear between CKE and CCS when mutual auth is enabled.
         */
        if (msg_type != SSL_HND_CERT_VERIFY) {
            ssl_calculate_handshake_hash(ssl, tvb, hs_offset, 4 + length);
        }

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
                        ssl_hand_tree, offset, offset + length, session, ssl,
                        NULL);
                /*
                 * Cannot call tls13_change_key here with TLS_SECRET_HANDSHAKE
                 * since the server may not agree on using TLS 1.3. If
                 * early_data is advertised, it must be TLS 1.3 though.
                 */
                if (ssl && ssl->has_early_data) {
                    session->version = TLSV1DOT3_VERSION;
                    ssl->state |= SSL_VERSION;
                    ssl_debug_printf("%s forcing version 0x%04X -> state 0x%02X\n", G_STRFUNC, version, ssl->state);
                }
                break;

            case SSL_HND_SERVER_HELLO:
                ssl_dissect_hnd_srv_hello(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree,
                        offset, offset + length, session, ssl, FALSE, is_hrr);
                if (ssl) {
                    ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
                    /* Create client and server decoders for TLS 1.3.
                     * Create client decoder based on HS secret only if there is
                     * no early data, or if there is no decryptable early data. */
                    if (!ssl->has_early_data ||
                        ((ssl->state & SSL_SEEN_0RTT_APPDATA) && !ssl->client)) {
                        tls13_change_key(ssl, &ssl_master_key_map, FALSE, TLS_SECRET_HANDSHAKE);
                    }
                    tls13_change_key(ssl, &ssl_master_key_map, TRUE, TLS_SECRET_HANDSHAKE);
                }
                break;

            case SSL_HND_HELLO_VERIFY_REQUEST:
                /* only valid for DTLS */
                break;

            case SSL_HND_NEWSESSION_TICKET:
                /* no need to load keylog file here as it only links a previous
                 * master key with this Session Ticket */
                ssl_dissect_hnd_new_ses_ticket(&dissect_ssl3_hf, tvb, pinfo,
                        ssl_hand_tree, offset, offset + length, session, ssl, FALSE,
                        ssl_master_key_map.tickets);
                break;

            case SSL_HND_END_OF_EARLY_DATA:
                /* RFC 8446 Section 4.5 */
                if (!is_from_server && ssl) {
                    ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
                    tls13_change_key(ssl, &ssl_master_key_map, FALSE, TLS_SECRET_HANDSHAKE);
                    ssl->has_early_data = FALSE;
                }
                break;

            case SSL_HND_HELLO_RETRY_REQUEST: /* TLS 1.3 draft -21 and before */
                ssl_dissect_hnd_hello_retry_request(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree,
                                                    offset, offset + length, session, ssl, FALSE);
                break;

            case SSL_HND_ENCRYPTED_EXTENSIONS:
                /* XXX expert info if used with non-TLS 1.3? */
                ssl_dissect_hnd_encrypted_extensions(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree,
                                                     offset, offset + length, session, ssl, FALSE);

                break;

            case SSL_HND_CERTIFICATE:
                ssl_dissect_hnd_cert(&dissect_ssl3_hf, tvb, ssl_hand_tree,
                        offset, offset + length, pinfo, session, ssl, is_from_server, FALSE);
                break;

            case SSL_HND_SERVER_KEY_EXCHG:
                ssl_dissect_hnd_srv_keyex(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree, offset, offset + length, session);
                break;

            case SSL_HND_CERT_REQUEST:
                ssl_dissect_hnd_cert_req(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree, offset, offset + length, session, FALSE);
                break;

            case SSL_HND_SVR_HELLO_DONE:
                /* This is not an abbreviated handshake, it is certainly not resumed. */
                session->is_session_resumed = FALSE;
                break;

            case SSL_HND_CERT_VERIFY:
                ssl_dissect_hnd_cli_cert_verify(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree, offset, offset + length, session->version);
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
#ifdef HAVE_LIBGNUTLS
                            ssl_key_hash,
#endif
                            &ssl_master_key_map)) {
                    ssl_debug_printf("dissect_ssl3_handshake can't generate pre master secret\n");
                }
                break;

            case SSL_HND_FINISHED:
                ssl_dissect_hnd_finished(&dissect_ssl3_hf, tvb, ssl_hand_tree,
                        offset, offset + length, session, &ssl_hfs);
                if (ssl) {
                    ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
                    tls13_change_key(ssl, &ssl_master_key_map, is_from_server, TLS_SECRET_APP);
                }
                break;

            case SSL_HND_CERT_URL:
                ssl_dissect_hnd_cert_url(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset);
                break;

            case SSL_HND_CERT_STATUS:
                tls_dissect_hnd_certificate_status(&dissect_ssl3_hf, tvb, pinfo, ssl_hand_tree, offset, offset + length);
                break;

            case SSL_HND_SUPPLEMENTAL_DATA:
                /* TODO: dissect this? */
                break;

            case SSL_HND_KEY_UPDATE:
                tls13_dissect_hnd_key_update(&dissect_ssl3_hf, tvb, tree, offset);
                if (ssl) {
                    tls13_key_update(ssl, is_from_server);
                }
                break;

            case SSL_HND_COMPRESSED_CERTIFICATE:
                ssl_dissect_hnd_compress_certificate(&dissect_ssl3_hf, tvb, ssl_hand_tree,
                                                     offset, offset + length, pinfo, session,
                                                     ssl, is_from_server, FALSE);
                break;

            case SSL_HND_ENCRYPTED_EXTS:
                dissect_ssl3_hnd_encrypted_exts(tvb, ssl_hand_tree, offset);
                break;
        }
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
        ti = proto_tree_add_item(tree, hf_tls_heartbeat_message, tvb,
                                 offset, record_length, ENC_NA);
        tls_heartbeat_tree = proto_item_add_subtree(ti, ett_tls_heartbeat);
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
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Heartbeat %s", type);
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Heartbeat");
    }

    if (type && decrypted) {
        proto_item_set_text(tree, "%s Record Layer: Heartbeat "
                            "%s",
                            val_to_str_const(session->version, ssl_version_short_names, "SSL"),
                            type);
        proto_tree_add_item(tls_heartbeat_tree, hf_tls_heartbeat_message_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        ti = proto_tree_add_uint(tls_heartbeat_tree, hf_tls_heartbeat_message_payload_length,
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
        proto_tree_add_bytes_format(tls_heartbeat_tree, hf_tls_heartbeat_message_payload,
                                    tvb, offset, payload_length,
                                    NULL, "Payload (%u byte%s)",
                                    payload_length,
                                    plurality(payload_length, "", "s"));
        offset += payload_length;
        if (padding_length)
            proto_tree_add_bytes_format(tls_heartbeat_tree, hf_tls_heartbeat_message_padding,
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

/* based on https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04 */
static void
dissect_ssl3_hnd_encrypted_exts(tvbuff_t *tvb, proto_tree *tree,
                                guint32 offset)
{
    guint8       selected_protocol_len;
    guint8       padding_len;

    selected_protocol_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_tls_handshake_npn_selected_protocol_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_tls_handshake_npn_selected_protocol,
        tvb, offset, selected_protocol_len, ENC_ASCII);
    offset += selected_protocol_len;

    padding_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_tls_handshake_npn_padding_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_tls_handshake_npn_padding,
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
                    SslDecryptSession *ssl)
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
        if (tls_desegment && pinfo->can_desegment) {
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
        if (tls_desegment && pinfo->can_desegment) {
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

    /* add the record layer subtree header */
    ti = proto_tree_add_item(tree, hf_ssl2_record, tvb, initial_offset,
                             record_length_length + record_length, ENC_NA);
    ssl_record_tree = proto_item_add_subtree(ti, ett_tls_record);

    /* pull the msg_type so we can bail if it's unknown */
    msg_type = tvb_get_guint8(tvb, initial_offset + record_length_length);

    /* if we get a server_hello or later handshake in v2, then set
     * this to sslv2
     */
    if (session->version == SSL_VER_UNKNOWN)
    {
        if (msg_type >= 2 && msg_type <= 8)
        {
            session->version = SSLV2_VERSION;
        }
    }

    /* if we get here, but don't have a version set for the
     * conversation, then set a version for just this frame
     * (e.g., on a client hello)
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSLv2");

    /* see if the msg_type is valid; if not the payload is
     * probably encrypted, so note that fact and bail
     */
    msg_type_str = try_val_to_str(msg_type, ssl_20_msg_types);
    if (!msg_type_str
        || (!ssl_looks_like_valid_v2_handshake(tvb, initial_offset
                               + record_length_length,
                               record_length)))
    {
        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                "SSLv2",
                                "Encrypted Data");

            /* Unlike SSLv3, the SSLv2 record layer does not have a
             * version field. To make it possible to filter on record
             * layer version we create a generated field with ssl
             * record layer version 0x0002
             */
            ti = proto_tree_add_uint(ssl_record_tree,
                    hf_tls_record_version, tvb,
                    initial_offset, 0, 0x0002);
            proto_item_set_generated(ti);
        }

        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Data");
        return initial_offset + record_length_length + record_length;
    }
    else
    {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_type_str);

        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                "SSLv2",
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
                                 hf_tls_record_version, tvb,
                                 initial_offset, 0, 0x0002);
        proto_item_set_generated(ti);

        /* add the record length */
        tvb_ensure_bytes_exist(tvb, offset, record_length_length);
        proto_tree_add_uint (ssl_record_tree,
                             hf_tls_record_length, tvb,
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
        proto_tree_add_item(ssl_record_tree, hf_ssl2_msg_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;                   /* move past msg_type byte */

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

    conversation = find_conversation(frame_num, addr_srv, addr_cli, conversation_pt_to_endpoint_type(ptype), port_srv, port_cli, 0);

    if (!conversation) {
        /* create a new conversation */
        conversation = conversation_new(frame_num, addr_srv, addr_cli, conversation_pt_to_endpoint_type(ptype), port_srv, port_cli, 0);
        ssl_debug_printf("  new conversation = %p created\n", (void *)conversation);
    }
    ssl = ssl_get_session(conversation, tls_handle);

    ssl_debug_printf("  conversation = %p, ssl_session = %p\n", (void *)conversation, (void *)ssl);

    ssl_set_server(&ssl->session, addr_srv, ptype, port_srv);

    /* version */
    if ((ssl->session.version==SSL_VER_UNKNOWN) && (version!=SSL_VER_UNKNOWN)) {
        switch (version) {
        case SSLV3_VERSION:
        case TLSV1_VERSION:
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
        case GMTLSV1_VERSION:
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
    /* TODO change API to accept 64-bit sequence numbers. */
    if (ssl->client && (client_seq != (guint32)-1)) {
        ssl->client->seq = client_seq;
        ssl_debug_printf("ssl_set_master_secret client->seq updated to %" PRIu64 "\n", ssl->client->seq);
    }
    if (ssl->server && (server_seq != (guint32)-1)) {
        ssl->server->seq = server_seq;
        ssl_debug_printf("ssl_set_master_secret server->seq updated to %" PRIu64 "\n", ssl->server->seq);
    }

    /* update IV from last data */
    iv_len = ssl_get_cipher_blocksize(ssl->cipher_suite);
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
    case GMTLSV1_VERSION:
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

gboolean
tls_get_cipher_info(packet_info *pinfo, guint16 cipher_suite, int *cipher_algo, int *cipher_mode, int *hash_algo)
{
    if (cipher_suite == 0) {
        conversation_t *conv = find_conversation_pinfo(pinfo, 0);
        if (!conv) {
            return FALSE;
        }

        void *conv_data = conversation_get_proto_data(conv, proto_tls);
        if (conv_data == NULL) {
            return FALSE;
        }

        SslDecryptSession *ssl_session = (SslDecryptSession *)conv_data;
        cipher_suite = ssl_session->session.cipher;
    }
    const SslCipherSuite *suite = ssl_find_cipher(cipher_suite);
    if (!suite) {
        return FALSE;
    }

    /* adapted from ssl_cipher_init in packet-tls-utils.c */
    static const gint gcry_modes[] = {
        GCRY_CIPHER_MODE_STREAM,
        GCRY_CIPHER_MODE_CBC,
        GCRY_CIPHER_MODE_GCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_POLY1305,
    };
    static const int gcry_mds[] = {
        GCRY_MD_MD5,
        GCRY_MD_SHA1,
        GCRY_MD_SHA256,
        GCRY_MD_SHA384,
        -1,
    };
    int mode = gcry_modes[suite->mode];
    int cipher_algo_id = ssl_get_cipher_algo(suite);
    int hash_algo_id = gcry_mds[suite->dig-DIG_MD5];
    if (mode == -1 || cipher_algo_id == 0 || hash_algo_id == -1) {
        /* Identifiers are unusable, fail. */
        return FALSE;
    }
    if (cipher_algo) {
        *cipher_algo = cipher_algo_id;
    }
    if (cipher_mode) {
        *cipher_mode = mode;
    }
    if (hash_algo) {
        *hash_algo = hash_algo_id;
    }

    return TRUE;
}

/**
 * Load the QUIC traffic secret from the keylog file.
 * Returns the secret length (at most 'secret_max_len') and the secret into
 * 'secret' if a secret was found, or zero otherwise.
 */
gint
tls13_get_quic_secret(packet_info *pinfo, gboolean is_from_server, int type, guint secret_min_len, guint secret_max_len, guint8 *secret_out)
{
    GHashTable *key_map;
    const char *label;
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);
    if (!conv) {
        return 0;
    }

    SslDecryptSession *ssl = (SslDecryptSession *)conversation_get_proto_data(conv, proto_tls);
    if (ssl == NULL) {
        return 0;
    }

    gboolean is_quic = !!(ssl->state & SSL_QUIC_RECORD_LAYER);
    ssl_debug_printf("%s frame %d is_quic=%d\n", G_STRFUNC, pinfo->num, is_quic);
    if (!is_quic) {
        return 0;
    }

    if (ssl->client_random.data_len == 0) {
        /* May happen if Hello message is missing and Finished is found. */
        ssl_debug_printf("%s missing Client Random\n", G_STRFUNC);
        return 0;
    }

    // Not strictly necessary as QUIC CRYPTO frames have just been processed
    // which also calls ssl_load_keyfile for key transitions.
    ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);

    switch ((TLSRecordType)type) {
    case TLS_SECRET_0RTT_APP:
        DISSECTOR_ASSERT(!is_from_server);
        label = "CLIENT_EARLY_TRAFFIC_SECRET";
        key_map = ssl_master_key_map.tls13_client_early;
        break;
    case TLS_SECRET_HANDSHAKE:
        if (is_from_server) {
            label = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
            key_map = ssl_master_key_map.tls13_server_handshake;
        } else {
            label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
            key_map = ssl_master_key_map.tls13_client_handshake;
        }
        break;
    case TLS_SECRET_APP:
        if (is_from_server) {
            label = "SERVER_TRAFFIC_SECRET_0";
            key_map = ssl_master_key_map.tls13_server_appdata;
        } else {
            label = "CLIENT_TRAFFIC_SECRET_0";
            key_map = ssl_master_key_map.tls13_client_appdata;
        }
        break;
    default:
        ws_assert_not_reached();
    }

    StringInfo *secret = (StringInfo *)g_hash_table_lookup(key_map, &ssl->client_random);
    if (!secret || secret->data_len < secret_min_len || secret->data_len > secret_max_len) {
        ssl_debug_printf("%s Cannot find QUIC %s of size %d..%d, found bad size %d!\n",
                         G_STRFUNC, label, secret_min_len, secret_max_len, secret ? secret->data_len : 0);
        return 0;
    }

    ssl_debug_printf("%s Retrieved QUIC traffic secret.\n", G_STRFUNC);
    ssl_print_string("Client Random", &ssl->client_random);
    ssl_print_string(label, secret);
    memcpy(secret_out, secret->data, secret->data_len);
    return secret->data_len;
}

const char *
tls_get_alpn(packet_info *pinfo)
{
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);
    if (!conv) {
        return NULL;
    }

    SslDecryptSession *session = (SslDecryptSession *)conversation_get_proto_data(conv, proto_tls);
    if (session == NULL) {
        return NULL;
    }

    return session->session.alpn_name;
}

/* TLS Exporters {{{ */
/**
 * Computes the TLS 1.3 Exporter value (RFC 8446 Section 7.5).
 *
 * "secret" is the [early_]exporter_master_secret. On success, TRUE is returned
 * and the key is returned via "out" (free with "wmem_free(NULL, out)").
 */
static gboolean
tls13_exporter_common(int algo, const StringInfo *secret, const char *label, guint8 *context,
                      guint context_length, guint key_length, guchar **out)
{
    /*  TLS-Exporter(label, context_value, key_length) =
     *      HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
     *                        "exporter", Hash(context_value), key_length)
     *
     *  Derive-Secret(Secret, Label, Messages) =
     *      HKDF-Expand-Label(Secret, Label,
     *                        Transcript-Hash(Messages), Hash.length)
     */
    gcry_error_t    err;
    gcry_md_hd_t    hd;
    const char     *hash_value;
    StringInfo      derived_secret = { NULL, 0 };
    // QUIC -09 currently uses draft 23, so no need to support older TLS drafts
    const char *label_prefix = "tls13 ";

    err = gcry_md_open(&hd, algo, 0);
    if (err) {
        return FALSE;
    }

    /* Calculate Derive-Secret(Secret, label, ""). */
    hash_value = gcry_md_read(hd, 0);   /* Empty Messages */
    guint8 hash_len = (guint8) gcry_md_get_algo_dlen(algo);
    derived_secret.data_len = hash_len;
    if (!tls13_hkdf_expand_label_context(algo, secret, label_prefix, label, hash_value, hash_len, derived_secret.data_len, &derived_secret.data)) {
        gcry_md_close(hd);
        return FALSE;
    }

    /* HKDF-Expand-Label(..., "exporter", Hash(context_value), key_length) */
    gcry_md_write(hd, context, context_length);
    hash_value = gcry_md_read(hd, 0);
    tls13_hkdf_expand_label_context(algo, &derived_secret, label_prefix, "exporter", hash_value, hash_len, key_length, out);
    wmem_free(NULL, derived_secret.data);
    gcry_md_close(hd);

    return TRUE;
}

/**
 * Exports keying material using "[early_]exporter_master_secret". See
 * tls13_exporter_common for more details.
 */
gboolean
tls13_exporter(packet_info *pinfo, gboolean is_early,
               const char *label, guint8 *context,
               guint context_length, guint key_length, guchar **out)
{
    int hash_algo = 0;
    GHashTable *key_map;
    const StringInfo *secret;

    if (!tls_get_cipher_info(pinfo, 0, NULL, NULL, &hash_algo)) {
        return FALSE;
    }

    /* Lookup EXPORTER_SECRET based on client_random from conversation */
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);
    if (!conv) {
        return FALSE;
    }

    void *conv_data = conversation_get_proto_data(conv, proto_tls);
    if (conv_data == NULL) {
        return FALSE;
    }

    SslDecryptSession *ssl_session = (SslDecryptSession *)conv_data;
    ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
    key_map = is_early ? ssl_master_key_map.tls13_early_exporter
                       : ssl_master_key_map.tls13_exporter;
    secret = (StringInfo *)g_hash_table_lookup(key_map, &ssl_session->client_random);
    if (!secret) {
        return FALSE;
    }

    return tls13_exporter_common(hash_algo, secret, label, context, context_length, key_length, out);
}
/* }}} */


/* UAT */

#ifdef HAVE_LIBGNUTLS
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
        // This should be removed in favor of Decode As. Make it optional.
        *err = NULL;
        return TRUE;
    }

    if (!ssl_find_appdata_dissector(p)) {
        if (proto_get_id_by_filter_name(p) != -1) {
            *err = ws_strdup_printf("While '%s' is a valid dissector filter name, that dissector is not configured"
                                   " to support TLS decryption.\n\n"
                                   "If you need to decrypt '%s' over TLS, please contact the Wireshark development team.", p, p);
        } else {
            char* ssl_str = ssl_association_info("tls.port", "TCP");
            *err = ws_strdup_printf("Could not find dissector for: '%s'\nCommonly used TLS dissectors include:\n%s", p, ssl_str);
            g_free(ssl_str);
        }
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}
#endif  /* HAVE_LIBGNUTLS */

static void
ssl_src_prompt(packet_info *pinfo, gchar *result)
{
    SslPacketInfo* pi;
    guint32 srcport = pinfo->srcport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, pinfo->curr_layer_num);
    if (pi != NULL)
        srcport = pi->srcport;

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", srcport, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
ssl_src_value(packet_info *pinfo)
{
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, pinfo->curr_layer_num);
    if (pi == NULL)
        return GUINT_TO_POINTER(pinfo->srcport);

    return GUINT_TO_POINTER(pi->srcport);
}

static void
ssl_dst_prompt(packet_info *pinfo, gchar *result)
{
    SslPacketInfo* pi;
    guint32 destport = pinfo->destport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, pinfo->curr_layer_num);
    if (pi != NULL)
        destport = pi->destport;

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, destport);
}

static gpointer
ssl_dst_value(packet_info *pinfo)
{
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, pinfo->curr_layer_num);
    if (pi == NULL)
        return GUINT_TO_POINTER(pinfo->destport);

    return GUINT_TO_POINTER(pi->destport);
}

static void
ssl_both_prompt(packet_info *pinfo, gchar *result)
{
    SslPacketInfo* pi;
    guint32 srcport = pinfo->srcport,
            destport = pinfo->destport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_tls, pinfo->curr_layer_num);
    if (pi != NULL)
    {
        srcport = pi->srcport;
        destport = pi->destport;
    }

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "both (%u%s%u)", srcport, UTF8_LEFT_RIGHT_ARROW, destport);
}

static void
tls_secrets_block_callback(const void *secrets, guint size)
{
    tls_keylog_process_lines(&ssl_master_key_map, (const guint8 *)secrets, size);
}

/*********************************************************************
 *
 * Standard Wireshark Protocol Registration and housekeeping
 *
 *********************************************************************/
void
proto_register_tls(void)
{

    /* Setup list of header fields See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_tls_record,
          { "Record Layer", "tls.record",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tls_record_content_type,
          { "Content Type", "tls.record.content_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
            NULL, HFILL}
        },
        { &hf_tls_record_opaque_type,
          { "Opaque Type", "tls.record.opaque_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
            "Always set to value 23, actual content type is known after decryption", HFILL}
        },
        { &hf_ssl2_msg_type,
          { "Handshake Message Type", "tls.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_msg_types), 0x0,
            "SSLv2 handshake message type", HFILL}
        },
        { &hf_tls_record_version,
          { "Version", "tls.record.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Record layer version", HFILL }
        },
        { &hf_tls_record_length,
          { "Length", "tls.record.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of TLS record data", HFILL }
        },
        { &hf_tls_record_appdata,
          { "Encrypted Application Data", "tls.app_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Payload is encrypted application data", HFILL }
        },
        { &hf_tls_record_appdata_proto,
          { "Application Data Protocol", "tls.app_data_proto",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ssl2_record,
          { "SSLv2 Record Header", "tls.record",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "SSLv2 record data", HFILL }
        },
        { &hf_ssl2_record_is_escape,
          { "Is Escape", "tls.record.is_escape",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Indicates a security escape", HFILL}
        },
        { &hf_ssl2_record_padding_length,
          { "Padding Length", "tls.record.padding_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of padding at end of record", HFILL }
        },
        { &hf_tls_alert_message,
          { "Alert Message", "tls.alert_message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tls_alert_message_level,
          { "Level", "tls.alert_message.level",
            FT_UINT8, BASE_DEC, VALS(ssl_31_alert_level), 0x0,
            "Alert message level", HFILL }
        },
        { &hf_tls_alert_message_description,
          { "Description", "tls.alert_message.desc",
            FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
            "Alert message description", HFILL }
        },
        { &hf_tls_handshake_protocol,
          { "Handshake Protocol", "tls.handshake",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Handshake protocol message", HFILL}
        },
        { &hf_tls_handshake_type,
          { "Handshake Type", "tls.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_handshake_type), 0x0,
            "Type of handshake message", HFILL}
        },
        { &hf_tls_handshake_length,
          { "Length", "tls.handshake.length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of handshake message", HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec,
          { "Cipher Spec", "tls.handshake.cipherspec",
            FT_UINT24, BASE_HEX|BASE_EXT_STRING, &ssl_20_cipher_suites_ext, 0x0,
            "Cipher specification", HFILL }
        },
        { &hf_tls_handshake_npn_selected_protocol_len,
          { "Selected Protocol Length", "tls.handshake.npn_selected_protocol_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tls_handshake_npn_selected_protocol,
          { "Selected Protocol", "tls.handshake.npn_selected_protocol",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Protocol to be used for connection", HFILL }
        },
        { &hf_tls_handshake_npn_padding_len,
          { "Padding Length", "tls.handshake.npn_padding_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tls_handshake_npn_padding,
          { "Padding", "tls.handshake.npn_padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &ssl_hfs.hs_md5_hash,
          { "MD5 Hash", "tls.handshake.md5_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &ssl_hfs.hs_sha_hash,
          { "SHA-1 Hash", "tls.handshake.sha_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &hf_tls_heartbeat_message,
          { "Heartbeat Message", "tls.heartbeat_message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tls_heartbeat_message_type,
          { "Type", "tls.heartbeat_message.type",
            FT_UINT8, BASE_DEC, VALS(tls_heartbeat_type), 0x0,
            "Heartbeat message type", HFILL }
        },
        { &hf_tls_heartbeat_message_payload_length,
          { "Payload Length", "tls.heartbeat_message.payload_length",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_tls_heartbeat_message_payload,
          { "Payload Length", "tls.heartbeat_message.payload",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_tls_heartbeat_message_padding,
          { "Payload Length", "tls.heartbeat_message.padding",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_ssl2_handshake_challenge,
          { "Challenge", "tls.handshake.challenge",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Challenge data used to authenticate server", HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec_len,
          { "Cipher Spec Length", "tls.handshake.cipher_spec_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of cipher specs field", HFILL }
        },
        { &hf_ssl2_handshake_session_id_len,
          { "Session ID Length", "tls.handshake.session_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of session ID field", HFILL }
        },
        { &hf_ssl2_handshake_challenge_len,
          { "Challenge Length", "tls.handshake.challenge_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of challenge field", HFILL }
        },
        { &hf_ssl2_handshake_clear_key_len,
          { "Clear Key Data Length", "tls.handshake.clear_key_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of clear key data", HFILL }
        },
        { &hf_ssl2_handshake_enc_key_len,
          { "Encrypted Key Data Length", "tls.handshake.encrypted_key_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of encrypted key data", HFILL }
        },
        { &hf_ssl2_handshake_key_arg_len,
          { "Key Argument Length", "tls.handshake.key_arg_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of key argument", HFILL }
        },
        { &hf_ssl2_handshake_clear_key,
          { "Clear Key Data", "tls.handshake.clear_key_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Clear portion of MASTER-KEY", HFILL }
        },
        { &hf_ssl2_handshake_enc_key,
          { "Encrypted Key", "tls.handshake.encrypted_key",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Secret portion of MASTER-KEY encrypted to server", HFILL }
        },
        { &hf_ssl2_handshake_key_arg,
          { "Key Argument", "tls.handshake.key_arg",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Key Argument (e.g., Initialization Vector)", HFILL }
        },
        { &hf_ssl2_handshake_session_id_hit,
          { "Session ID Hit", "tls.handshake.session_id_hit",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Did the server find the client's Session ID?", HFILL }
        },
        { &hf_ssl2_handshake_cert_type,
          { "Certificate Type", "tls.handshake.cert_type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_certificate_type), 0x0,
            NULL, HFILL }
        },
        { &hf_ssl2_handshake_connection_id_len,
          { "Connection ID Length", "tls.handshake.connection_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of connection ID", HFILL }
        },
        { &hf_ssl2_handshake_connection_id,
          { "Connection ID", "tls.handshake.connection_id",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Server's challenge to client", HFILL }
        },

        { &hf_tls_segment_overlap,
          { "Segment overlap", "tls.segment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }},

        { &hf_tls_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "tls.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL }},

        { &hf_tls_segment_multiple_tails,
          { "Multiple tail segments found", "tls.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the pdu", HFILL }},

        { &hf_tls_segment_too_long_fragment,
          { "Segment too long", "tls.segment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of the pdu", HFILL }},

        { &hf_tls_segment_error,
          { "Reassembling error", "tls.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembling error due to illegal segments", HFILL }},

        { &hf_tls_segment_count,
          { "Segment count", "tls.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tls_segment,
          { "TLS segment", "tls.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tls_segments,
          { "Reassembled TLS segments", "tls.segments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "TLS Segments", HFILL }},

        { &hf_tls_reassembled_in,
          { "Reassembled PDU in frame", "tls.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

        { &hf_tls_reassembled_length,
          { "Reassembled PDU length", "tls.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        { &hf_tls_reassembled_data,
          { "Reassembled PDU data", "tls.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "The payload of multiple reassembled TLS segments", HFILL }},

        { &hf_tls_segment_data,
          { "TLS segment data", "tls.segment.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "The payload of a single TLS segment", HFILL }
        },

        { &hf_tls_handshake_fragment_count,
          { "Handshake Fragment count", "tls.handshake.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tls_handshake_fragment,
          { "Handshake Fragment", "tls.handshake.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tls_handshake_fragments,
          { "Reassembled Handshake Fragments", "tls.handshake.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tls_handshake_reassembled_in,
          { "Reassembled Handshake Message in frame", "tls.handshake.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The handshake message is fully reassembled in this frame", HFILL }},

        SSL_COMMON_HF_LIST(dissect_ssl3_hf, "tls")
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tls,
        &ett_tls_record,
        &ett_tls_alert,
        &ett_tls_handshake,
        &ett_tls_heartbeat,
        &ett_tls_certs,
        &ett_tls_segments,
        &ett_tls_segment,
        &ett_tls_hs_fragments,
        &ett_tls_hs_fragment,
        SSL_COMMON_ETT_LIST(dissect_ssl3_hf)
    };

    static ei_register_info ei[] = {
        { &ei_ssl2_handshake_session_id_len_error, { "tls.handshake.session_id_length.error", PI_MALFORMED, PI_ERROR, "Session ID length error", EXPFILL }},
        { &ei_ssl3_heartbeat_payload_length, { "tls.heartbeat_message.payload_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid heartbeat payload length", EXPFILL }},
        { &ei_tls_unexpected_message, { "tls.unexpected_message", PI_PROTOCOL, PI_ERROR, "Unexpected message", EXPFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &ei_tls_ignored_unknown_record, { "tls.ignored_unknown_record", PI_PROTOCOL, PI_WARN, "Ignored Unknown Record", EXPFILL }},

        SSL_COMMON_EI_LIST(dissect_ssl3_hf, "tls")
    };

    static build_valid_func ssl_da_src_values[1] = {ssl_src_value};
    static build_valid_func ssl_da_dst_values[1] = {ssl_dst_value};
    static build_valid_func ssl_da_both_values[2] = {ssl_src_value, ssl_dst_value};
    static decode_as_value_t ssl_da_values[3] = {{ssl_src_prompt, 1, ssl_da_src_values}, {ssl_dst_prompt, 1, ssl_da_dst_values}, {ssl_both_prompt, 2, ssl_da_both_values}};
    static decode_as_t ssl_da = {"tls", "tls.port", 3, 2, ssl_da_values, "TCP", "port(s) as",
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    expert_module_t* expert_ssl;

    /* Register the protocol name and description */
    proto_tls = proto_register_protocol("Transport Layer Security",
                                        "TLS", "tls");

    ssl_associations = register_dissector_table("tls.port", "TLS Port", proto_tls, FT_UINT16, BASE_DEC);
    register_dissector_table_alias(ssl_associations, "ssl.port");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_tls, hf, array_length(hf));
    proto_register_alias(proto_tls, "ssl");
    proto_register_subtree_array(ett, array_length(ett));
    expert_ssl = expert_register_protocol(proto_tls);
    expert_register_field_array(expert_ssl, ei, array_length(ei));

    {
        module_t *ssl_module = prefs_register_protocol(proto_tls, proto_reg_handoff_ssl);

#ifdef HAVE_LIBGNUTLS
        static uat_field_t sslkeylist_uats_flds[] = {
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, ipaddr, "IP address", ssldecrypt_uat_fld_ip_chk_cb, "IPv4 or IPv6 address (unused)"),
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, port, "Port", ssldecrypt_uat_fld_port_chk_cb, "Port Number (optional)"),
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, protocol, "Protocol", ssldecrypt_uat_fld_protocol_chk_cb, "Application Layer Protocol (optional)"),
            UAT_FLD_FILENAME_OTHER(sslkeylist_uats, keyfile, "Key File", ssldecrypt_uat_fld_fileopen_chk_cb, "Private keyfile."),
            UAT_FLD_CSTRING_OTHER(sslkeylist_uats, password,"Password", ssldecrypt_uat_fld_password_chk_cb, "Password (for PCKS#12 keyfile)"),
            UAT_END_FIELDS
        };

        ssldecrypt_uat = uat_new("TLS Decrypt",
            sizeof(ssldecrypt_assoc_t),
            "ssl_keys",                     /* filename */
            TRUE,                           /* from_profile */
            &tlskeylist_uats,               /* data_ptr */
            &ntlsdecrypt,                   /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* Help section (currently a wiki page) */
            ssldecrypt_copy_cb,
            NULL,
            ssldecrypt_free_cb,
            ssl_parse_uat,
            ssl_reset_uat,
            sslkeylist_uats_flds);

        prefs_register_uat_preference(ssl_module, "key_table",
            "RSA keys list",
            "A table of RSA keys for TLS decryption",
            ssldecrypt_uat);

        prefs_register_string_preference(ssl_module, "keys_list", "RSA keys list (deprecated)",
             "Semicolon-separated list of private RSA keys used for TLS decryption. "
             "Used by versions of Wireshark prior to 1.6",
             &ssl_keys_list);
#endif  /* HAVE_LIBGNUTLS */

        prefs_register_filename_preference(ssl_module, "debug_file", "TLS debug file",
            "Redirect TLS debug to the file specified. Leave empty to disable debugging "
            "or use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr.",
            &ssl_debug_file_name, TRUE);

        prefs_register_bool_preference(ssl_module,
             "desegment_ssl_records",
             "Reassemble TLS records spanning multiple TCP segments",
             "Whether the TLS dissector should reassemble TLS records spanning multiple TCP segments. "
             "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
             &tls_desegment);
        prefs_register_bool_preference(ssl_module,
             "desegment_ssl_application_data",
             "Reassemble TLS Application Data spanning multiple TLS records",
             "Whether the TLS dissector should reassemble TLS Application Data spanning multiple TLS records. ",
             &tls_desegment_app_data);
        prefs_register_bool_preference(ssl_module,
             "ignore_ssl_mac_failed",
             "Message Authentication Code (MAC), ignore \"mac failed\"",
             "For troubleshooting ignore the mac check result and decrypt also if the Message Authentication Code (MAC) fails.",
             &tls_ignore_mac_failed);
        ssl_common_register_options(ssl_module, &ssl_options, FALSE);
    }

    /* heuristic dissectors for any premable e.g. CredSSP before RDP */
    ssl_heur_subdissector_list = register_heur_dissector_list("tls", proto_tls);

    ssl_common_register_ssl_alpn_dissector_table("tls.alpn",
        "SSL/TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs",
        proto_tls);

    tls_handle = register_dissector("tls", dissect_ssl, proto_tls);
    register_dissector("tls13-handshake", dissect_tls13_handshake, proto_tls);

    register_init_routine(ssl_init);
    register_cleanup_routine(ssl_cleanup);
    reassembly_table_register(&ssl_reassembly_table,
                          &tcp_reassembly_table_functions);
    reassembly_table_register(&tls_hs_reassembly_table,
                          &addresses_ports_reassembly_table_functions);
    register_decode_as(&ssl_da);

    /* XXX: this seems unused due to new "Follow TLS" method, remove? */
    tls_tap = register_tap("tls");
    ssl_debug_printf("proto_register_ssl: registered tap %s:%d\n",
        "tls", tls_tap);

    register_follow_stream(proto_tls, "tls", tcp_follow_conv_filter, tcp_follow_index_filter, tcp_follow_address_filter,
                            tcp_port_to_display, ssl_follow_tap_listener);
    secrets_register_type(SECRETS_TYPE_TLS, tls_secrets_block_callback);
}

static int dissect_tls_sct_ber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint32 offset = 0;
    /* Skip through tag and length for OCTET STRING encoding. */
    offset = dissect_ber_identifier(pinfo, tree, tvb, offset, NULL, NULL, NULL);
    offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
    /*
     * RFC 6962 (Certificate Transparency) refers to RFC 5246 (TLS 1.2) for the
     * DigitallySigned format, so asssume that version.
     */
    return tls_dissect_sct_list(&dissect_ssl3_hf, tvb, pinfo, tree, offset, tvb_captured_length(tvb), TLSV1DOT2_VERSION);
}

/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_ssl(void)
{

#ifdef HAVE_LIBGNUTLS
    /* parse key list */
    ssl_parse_uat();
    ssl_parse_old_keys();
#endif

    /*
     * XXX the port preferences should probably be removed in favor of Decode
     * As. Then proto_reg_handoff_ssl can be removed from
     * prefs_register_protocol.
     */
    static gboolean initialized = FALSE;
    if (initialized) {
        return;
    }
    initialized = TRUE;

    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);

    /* Certificate Transparency extensions: 2 (Certificate), 5 (OCSP Response) */
    register_ber_oid_dissector("1.3.6.1.4.1.11129.2.4.2", dissect_tls_sct_ber, proto_tls, "SignedCertificateTimestampList");
    register_ber_oid_dissector("1.3.6.1.4.1.11129.2.4.5", dissect_tls_sct_ber, proto_tls, "SignedCertificateTimestampList");

    heur_dissector_add("tcp", dissect_ssl_heur, "SSL/TLS over TCP", "tls_tcp", proto_tls, HEURISTIC_ENABLE);
}

void
ssl_dissector_add(guint port, dissector_handle_t handle)
{
    ssl_association_add("tls.port", tls_handle, handle, port, TRUE);
}

void
ssl_dissector_delete(guint port, dissector_handle_t handle)
{
    ssl_association_remove("tls.port", tls_handle, handle, port, TRUE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
