/* packet-dtls.c
 * Routines for dtls dissection
 * Copyright (c) 2006, Authesserre Samuel <sauthess@gmail.com>
 * Copyright (c) 2007, Mikael Magnusson <mikma@users.sourceforge.net>
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
 *
 *
 * DTLS dissection and decryption.
 * See RFC 4347 for details about DTLS specs.
 *
 * Notes :
 * This dissector is based on the TLS dissector (packet-ssl.c); Because of the similarity
 *   of DTLS and TLS, decryption works like TLS with RSA key exchange.
 * This dissector uses the sames things (file, libraries) as the SSL dissector (gnutls, packet-ssl-utils.h)
 *  to make it easily maintainable.
 *
 * It was developed to dissect and decrypt the OpenSSL v 0.9.8f DTLS implementation.
 * It is limited to this implementation; there is no complete implementation.
 *
 * Implemented :
 *  - DTLS dissection
 *  - DTLS decryption (openssl one)
 *
 * Todo :
 *  - activate correct Mac calculation when openssl will be corrected
 *    (or if an other implementation works),
 *    corrected code is ready and commented in packet-ssl-utils.h file.
 *  - add missing things (desegmentation, reordering... that aren't present in actual OpenSSL implementation)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/reassemble.h>
#include <epan/uat.h>
#include <epan/sctpppids.h>
#include <epan/exported_pdu.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/utf8_entities.h>
#include "packet-ssl-utils.h"
#include "packet-dtls.h"

void proto_register_dtls(void);

/* DTLS User Access Table */
static ssldecrypt_assoc_t *dtlskeylist_uats = NULL;
static guint ndtlsdecrypt = 0;

/* we need to remember the top tree so that subdissectors we call are created
 * at the root and not deep down inside the DTLS decode
 */
static proto_tree *top_tree;

/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml */
static const value_string srtp_protection_profile_vals[] = {
  { 0x0001, "SRTP_AES128_CM_HMAC_SHA1_80" }, /* RFC 5764 */
  { 0x0002, "SRTP_AES128_CM_HMAC_SHA1_32" },
  { 0x0005, "SRTP_NULL_HMAC_SHA1_80" },
  { 0x0006, "SRTP_NULL_HMAC_SHA1_32" },
  { 0x0007, "SRTP_AEAD_AES_128_GCM" }, /* RFC 7714 */
  { 0x0008, "SRTP_AEAD_AES_256_GCM" },
  { 0x00, NULL },
};

/* Initialize the protocol and registered fields */
static gint dtls_tap                            = -1;
static gint exported_pdu_tap                    = -1;
static gint proto_dtls                          = -1;
static gint hf_dtls_record                      = -1;
static gint hf_dtls_record_content_type         = -1;
static gint hf_dtls_record_version              = -1;
static gint hf_dtls_record_epoch                = -1;
static gint hf_dtls_record_sequence_number      = -1;
static gint hf_dtls_record_length               = -1;
static gint hf_dtls_record_appdata              = -1;
static gint hf_dtls_alert_message               = -1;
static gint hf_dtls_alert_message_level         = -1;
static gint hf_dtls_alert_message_description   = -1;
static gint hf_dtls_handshake_protocol          = -1;
static gint hf_dtls_handshake_type              = -1;
static gint hf_dtls_handshake_length            = -1;
static gint hf_dtls_handshake_message_seq       = -1;
static gint hf_dtls_handshake_fragment_offset   = -1;
static gint hf_dtls_handshake_fragment_length   = -1;

static gint hf_dtls_heartbeat_message                 = -1;
static gint hf_dtls_heartbeat_message_type            = -1;
static gint hf_dtls_heartbeat_message_payload_length  = -1;
static gint hf_dtls_heartbeat_message_payload         = -1;
static gint hf_dtls_heartbeat_message_padding         = -1;

static gint hf_dtls_fragments                   = -1;
static gint hf_dtls_fragment                    = -1;
static gint hf_dtls_fragment_overlap            = -1;
static gint hf_dtls_fragment_overlap_conflicts  = -1;
static gint hf_dtls_fragment_multiple_tails     = -1;
static gint hf_dtls_fragment_too_long_fragment  = -1;
static gint hf_dtls_fragment_error              = -1;
static gint hf_dtls_fragment_count              = -1;
static gint hf_dtls_reassembled_in              = -1;
static gint hf_dtls_reassembled_length          = -1;

static gint hf_dtls_hs_ext_use_srtp_protection_profiles_length  = -1;
static gint hf_dtls_hs_ext_use_srtp_protection_profile          = -1;
static gint hf_dtls_hs_ext_use_srtp_mki_length                  = -1;
static gint hf_dtls_hs_ext_use_srtp_mki                         = -1;

/* header fields used in ssl-utils, but defined here. */
static dtls_hfs_t dtls_hfs = { -1, -1 };

/* Initialize the subtree pointers */
static gint ett_dtls                   = -1;
static gint ett_dtls_record            = -1;
static gint ett_dtls_alert             = -1;
static gint ett_dtls_handshake         = -1;
static gint ett_dtls_heartbeat         = -1;
static gint ett_dtls_certs             = -1;

static gint ett_dtls_fragment          = -1;
static gint ett_dtls_fragments         = -1;

static expert_field ei_dtls_handshake_fragment_length_too_long = EI_INIT;
static expert_field ei_dtls_handshake_fragment_length_zero = EI_INIT;
static expert_field ei_dtls_handshake_fragment_past_end_msg = EI_INIT;
static expert_field ei_dtls_msg_len_diff_fragment = EI_INIT;
static expert_field ei_dtls_heartbeat_payload_length = EI_INIT;

static ssl_master_key_map_t dtls_master_key_map;
static GHashTable         *dtls_key_hash             = NULL;
static wmem_stack_t       *key_list_stack            = NULL;
static reassembly_table    dtls_reassembly_table;
static dissector_table_t   dtls_associations         = NULL;
static dissector_handle_t  dtls_handle               = NULL;
static StringInfo          dtls_compressed_data      = {NULL, 0};
static StringInfo          dtls_decrypted_data       = {NULL, 0};
static gint                dtls_decrypted_data_avail = 0;
static FILE               *dtls_keylog_file          = NULL;

static uat_t *dtlsdecrypt_uat      = NULL;
static const gchar *dtls_keys_list = NULL;
static ssl_common_options_t dtls_options = { NULL, NULL};
static const gchar *dtls_debug_file_name = NULL;

static heur_dissector_list_t heur_subdissector_list;

static const fragment_items dtls_frag_items = {
  /* Fragment subtrees */
  &ett_dtls_fragment,
  &ett_dtls_fragments,
  /* Fragment fields */
  &hf_dtls_fragments,
  &hf_dtls_fragment,
  &hf_dtls_fragment_overlap,
  &hf_dtls_fragment_overlap_conflicts,
  &hf_dtls_fragment_multiple_tails,
  &hf_dtls_fragment_too_long_fragment,
  &hf_dtls_fragment_error,
  &hf_dtls_fragment_count,
  /* Reassembled in field */
  &hf_dtls_reassembled_in,
  /* Reassembled length field */
  &hf_dtls_reassembled_length,
  /* Reassembled data field */
  NULL,
  /* Tag */
  "Message fragments"
};

static SSL_COMMON_LIST_T(dissect_dtls_hf);

/* initialize/reset per capture state data (dtls sessions cache) */
static void
dtls_init(void)
{
  module_t *dtls_module = prefs_find_module("dtls");
  pref_t   *keys_list_pref;

  ssl_common_init(&dtls_master_key_map,
                  &dtls_decrypted_data, &dtls_compressed_data);

  /* We should have loaded "keys_list" by now. Mark it obsolete */
  if (dtls_module) {
    keys_list_pref = prefs_find_preference(dtls_module, "keys_list");
    if (! prefs_get_preference_obsolete(keys_list_pref)) {
      prefs_set_preference_obsolete(keys_list_pref);
    }
  }
}

static void
dtls_cleanup(void)
{
  if (key_list_stack != NULL) {
    wmem_destroy_stack(key_list_stack);
    key_list_stack = NULL;
  }
  ssl_common_cleanup(&dtls_master_key_map, &dtls_keylog_file,
                     &dtls_decrypted_data, &dtls_compressed_data);
}

/* parse dtls related preferences (private keys and ports association strings) */
static void
dtls_parse_uat(void)
{
  guint            i, port;
  dissector_handle_t handle;

  if (dtls_key_hash)
  {
      g_hash_table_destroy(dtls_key_hash);
  }

  /* remove only associations created from key list */
  if (key_list_stack != NULL) {
    while (wmem_stack_count(key_list_stack) > 0) {
      port = GPOINTER_TO_UINT(wmem_stack_pop(key_list_stack));
      handle = dissector_get_uint_handle(dtls_associations, port);
      if (handle != NULL)
        ssl_association_remove("dtls.port", dtls_handle, handle, port, FALSE);
    }
  }

  /* parse private keys string, load available keys and put them in key hash*/
  dtls_key_hash = g_hash_table_new_full(ssl_private_key_hash,
      ssl_private_key_equal, g_free, ssl_private_key_free);

  ssl_set_debug(dtls_debug_file_name);

  if (ndtlsdecrypt > 0)
  {
    if (key_list_stack == NULL)
      key_list_stack = wmem_stack_new(NULL);

    for (i = 0; i < ndtlsdecrypt; i++)
    {
      ssldecrypt_assoc_t *d = &(dtlskeylist_uats[i]);
      ssl_parse_key_list(d, dtls_key_hash, "dtls.port", dtls_handle, FALSE);
      if (key_list_stack && ws_strtou32(d->port, NULL, &port))
        wmem_stack_push(key_list_stack, GUINT_TO_POINTER(port));
    }
  }

  dissector_add_for_decode_as("sctp.port", dtls_handle);
  dissector_add_for_decode_as("udp.port", dtls_handle);
}

#if defined(HAVE_LIBGNUTLS)
static void
dtls_reset_uat(void)
{
  g_hash_table_destroy(dtls_key_hash);
  dtls_key_hash = NULL;
}
#endif

static void
dtls_parse_old_keys(void)
{
  gchar          **old_keys, **parts, *err;
  guint            i;
  gchar          *uat_entry;

  /* Import old-style keys */
  if (dtlsdecrypt_uat && dtls_keys_list && dtls_keys_list[0]) {
    old_keys = wmem_strsplit(NULL, dtls_keys_list, ";", 0);
    for (i = 0; old_keys[i] != NULL; i++) {
      parts = wmem_strsplit(NULL, old_keys[i], ",", 4);
      if (parts[0] && parts[1] && parts[2] && parts[3]) {
        gchar *path = uat_esc(parts[3], (guint)strlen(parts[3]));
        uat_entry = wmem_strdup_printf(NULL, "\"%s\",\"%s\",\"%s\",\"%s\",\"\"",
                        parts[0], parts[1], parts[2], path);
        g_free(path);
        if (!uat_load_str(dtlsdecrypt_uat, uat_entry, &err)) {
          ssl_debug_printf("dtls_parse: Can't load UAT string %s: %s\n",
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

/*
 * DTLS Dissection Routines
 *
 */

/* record layer dissector */
static gint dissect_dtls_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset,
                                SslSession *session, gint is_from_server,
                                SslDecryptSession *conv_data,
                                guint8 curr_layer_num_ssl);

/* alert message dissector */
static void dissect_dtls_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               const SslSession *session);

/* handshake protocol dissector */
static void dissect_dtls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint32 record_length,
                                   SslSession *session, gint is_from_server,
                                   SslDecryptSession *conv_data, guint8 content_type);

/* heartbeat message dissector */
static void dissect_dtls_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   const SslSession *session, guint32 record_length,
                                   gboolean decrypted);

static int dissect_dtls_hnd_hello_verify_request(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                                 packet_info *pinfo, proto_tree *tree,
                                                 guint32 offset, guint32 offset_end);

/*
 * Support Functions
 *
 */

static gint  looks_like_dtls(tvbuff_t *tvb, guint32 offset);

/*********************************************************************
 *
 * Main dissector
 *
 *********************************************************************/
/*
 * Code to actually dissect the packets
 */
static int
dissect_dtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

  conversation_t    *conversation;
  proto_item        *ti;
  proto_tree        *dtls_tree;
  guint32            offset;
  gboolean           first_record_in_frame;
  SslDecryptSession *ssl_session;
  SslSession        *session;
  gint               is_from_server;
  guint8             curr_layer_num_ssl = pinfo->curr_layer_num;

  ti                    = NULL;
  dtls_tree             = NULL;
  offset                = 0;
  first_record_in_frame = TRUE;
  ssl_session           = NULL;
  top_tree              = tree;

  /* Track the version using conversations allows
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
  ssl_session = ssl_get_session(conversation, dtls_handle);
  session = &ssl_session->session;
  is_from_server = ssl_packet_from_server(session, dtls_associations, pinfo);

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

  /* Initialize the protocol column; we'll set it later when we
   * figure out what flavor of DTLS it is */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTLS");

  /* clear the the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  /* Create display subtree for SSL as a whole */
  ti = proto_tree_add_item(tree, proto_dtls, tvb, 0, -1, ENC_NA);
  dtls_tree = proto_item_add_subtree(ti, ett_dtls);

  /* iterate through the records in this tvbuff */
  while (tvb_reported_length_remaining(tvb, offset) != 0)
    {
      /* on second and subsequent records per frame
       * add a delimiter on info column
       */
      if (!first_record_in_frame)
        {
          col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

      /* first try to dispatch off the cached version
       * known to be associated with the conversation
       */
      switch(session->version) {
      case DTLSV1DOT0_VERSION:
      case DTLSV1DOT0_OPENSSL_VERSION:
      case DTLSV1DOT2_VERSION:
        offset = dissect_dtls_record(tvb, pinfo, dtls_tree,
                                     offset, session, is_from_server,
                                     ssl_session, curr_layer_num_ssl);
        break;

        /* that failed, so apply some heuristics based
         * on this individual packet
         */
      default:
        if (looks_like_dtls(tvb, offset))
          {
            /* looks like dtls */
            offset = dissect_dtls_record(tvb, pinfo, dtls_tree,
                                         offset, session, is_from_server,
                                         ssl_session, curr_layer_num_ssl);
          }
        else
          {
            /* looks like something unknown, so lump into
             * continuation data
             */
            offset = tvb_reported_length(tvb);
            col_append_str(pinfo->cinfo, COL_INFO,
                             "Continuation Data");

            /* Set the protocol column */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTLS");
          }
        break;
      }

      /* set up for next record in frame, if any */
      first_record_in_frame = FALSE;
    }

  // XXX there is no Follow DTLS Stream, is this tap needed?
  tap_queue_packet(dtls_tap, pinfo, NULL);
  return tvb_captured_length(tvb);
}

static gboolean
dissect_dtls_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)

{
  /* Stronger confirmation of DTLS packet is provided by verifying the
   * captured payload length against the remainder of the UDP packet size. */
  guint length = tvb_captured_length(tvb);
  guint offset = 0;

  if (tvb_reported_length(tvb) == length) {
    /* The entire payload was captured. */
    while (offset + 13 <= length && looks_like_dtls(tvb, offset)) {
      /* Advance offset to the end of the current DTLS record */
      offset += tvb_get_ntohs(tvb, offset + 11) + 13;
      if (offset == length) {
        dissect_dtls(tvb, pinfo, tree, data);
        return TRUE;
      }
    }

    if (pinfo->fragmented && offset >= 13) {
      dissect_dtls(tvb, pinfo, tree, data);
      return TRUE;
    }
    return FALSE;
  }

  /* This packet was truncated by the capture process due to a snapshot
   * length - do our best with what we've got. */
  while (tvb_captured_length_remaining(tvb, offset) >= 3) {
    if (!looks_like_dtls(tvb, offset))
      return FALSE;

    offset += 3;
    if (tvb_captured_length_remaining(tvb, offset) >= 10 ) {
      offset += tvb_get_ntohs(tvb, offset + 8) + 10;
    } else {
      /* Dissect what we've got, which might be as little as 3 bytes. */
      dissect_dtls(tvb, pinfo, tree, data);
      return TRUE;
    }
    if (offset == length) {
      /* Can this ever happen?  Well, just in case ... */
      dissect_dtls(tvb, pinfo, tree, data);
      return TRUE;
    }
  }

  /* One last check to see if the current offset is at least less than the
   * original number of bytes present before truncation or we're dealing with
   * a packet fragment that's also been truncated. */
  if ((length >= 3) && (offset <= tvb_reported_length(tvb) || pinfo->fragmented)) {
    dissect_dtls(tvb, pinfo, tree, data);
    return TRUE;
  }
  return FALSE;
}

static gboolean
dtls_is_null_cipher(guint cipher )
{
  switch(cipher) {
  case 0x0000:
  case 0x0001:
  case 0x0002:
  case 0x002c:
  case 0x002d:
  case 0x002e:
  case 0x003b:
  case 0x00b0:
  case 0x00b1:
  case 0x00b4:
  case 0x00b5:
  case 0x00b8:
  case 0x00b9:
  case 0xc001:
  case 0xc006:
  case 0xc00b:
  case 0xc010:
  case 0xc015:
  case 0xc039:
  case 0xc03a:
  case 0xc03b:
    return TRUE;
  default:
    return FALSE;
  }
}

static gboolean
decrypt_dtls_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset, SslDecryptSession *ssl,
                    guint8 content_type, guint16 record_version, guint16 record_length, guint8 curr_layer_num_ssl)
{
  gboolean    success;
  SslDecoder *decoder;

  /* if we can decrypt and decryption have success
   * add decrypted data to this packet info */
  if (!ssl || !(ssl->state & SSL_HAVE_SESSION_KEY)) {
    ssl_debug_printf("decrypt_dtls_record: no session key\n");
    return FALSE;
  }
  ssl_debug_printf("decrypt_dtls_record: app_data len %d, ssl state %X\n",
                   record_length, ssl->state);

  /* retrieve decoder for this packet direction */
  if (ssl_packet_from_server(&ssl->session, dtls_associations, pinfo) != 0) {
    ssl_debug_printf("decrypt_dtls_record: using server decoder\n");
    decoder = ssl->server;
  }
  else {
    ssl_debug_printf("decrypt_dtls_record: using client decoder\n");
    decoder = ssl->client;
  }

  if (!decoder && !dtls_is_null_cipher(ssl->session.cipher)) {
    ssl_debug_printf("decrypt_dtls_record: no decoder available\n");
    return FALSE;
  }

  /* ensure we have enough storage space for decrypted data */
  if (record_length > dtls_decrypted_data.data_len)
    {
      ssl_debug_printf("decrypt_dtls_record: allocating %d bytes"
                       " for decrypt data (old len %d)\n",
                       record_length + 32, dtls_decrypted_data.data_len);
      dtls_decrypted_data.data = (guchar *)g_realloc(dtls_decrypted_data.data,
                                           record_length + 32);
      dtls_decrypted_data.data_len = record_length + 32;
    }

  /* run decryption and add decrypted payload to protocol data, if decryption
   * is successful*/
  dtls_decrypted_data_avail = dtls_decrypted_data.data_len;
  if (ssl->state & SSL_HAVE_SESSION_KEY) {
    if (!decoder) {
      ssl_debug_printf("decrypt_dtls_record: no decoder available\n");
      return FALSE;
    }
    success = ssl_decrypt_record(ssl, decoder, content_type, record_version,
                           tvb_get_ptr(tvb, offset, record_length), record_length,
                           &dtls_compressed_data, &dtls_decrypted_data, &dtls_decrypted_data_avail) == 0;
  }
  else if (dtls_is_null_cipher(ssl->session.cipher)) {
    /* Non-encrypting cipher NULL-XXX */
    tvb_memcpy(tvb, dtls_decrypted_data.data, offset, record_length);
    dtls_decrypted_data_avail = dtls_decrypted_data.data_len = record_length;
    success = TRUE;
  } else {
    success = FALSE;
  }

  if (success && dtls_decrypted_data_avail > 0) {
    const guchar *data = dtls_decrypted_data.data;
    guint datalen = dtls_decrypted_data_avail;

    ssl_add_record_info(proto_dtls, pinfo, data, datalen,
        tvb_raw_offset(tvb)+offset,
        NULL, (ContentType)content_type, curr_layer_num_ssl);
  }
  return success;
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


/*********************************************************************
 *
 * DTLS Dissection Routines
 *
 *********************************************************************/
static gint
dissect_dtls_record(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, guint32 offset,
                    SslSession *session, gint is_from_server,
                    SslDecryptSession* ssl,
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
   *        uint16 epoch;               // New field
   *        uint48 sequence_number;     // New field
   *        uint16 length;
   *        opaque fragment[TLSPlaintext.length];
   *    } DTLSPlaintext;
   */

  guint32         record_length;
  guint16         version;
  guint16         epoch;
  guint64         sequence_number;
  guint8          content_type;
  guint8          next_byte;
  proto_tree     *ti;
  proto_tree     *dtls_record_tree;
  proto_item     *length_pi;
  tvbuff_t       *decrypted;
  SslRecordInfo  *record = NULL;
  heur_dtbl_entry_t *hdtbl_entry;

  /*
   * Get the record layer fields of interest
   */
  content_type          = tvb_get_guint8(tvb, offset);
  version               = tvb_get_ntohs(tvb, offset + 1);
  epoch                 = tvb_get_ntohs(tvb, offset + 3);
  sequence_number       = tvb_get_ntoh48(tvb, offset + 5);
  record_length         = tvb_get_ntohs(tvb, offset + 11);

  if(ssl){
    if(ssl_packet_from_server(session, dtls_associations, pinfo)){
     if (ssl->server) {
      ssl->server->seq=sequence_number;
      ssl->server->epoch=epoch;
     }
    }
    else{
     if (ssl->client) {
      ssl->client->seq=sequence_number;
      ssl->client->epoch=epoch;
     }
    }
  }
  if (!ssl_is_valid_content_type(content_type)) {

    /* if we don't have a valid content_type, there's no sense
     * continuing any further
     */
    col_append_str(pinfo->cinfo, COL_INFO, "Continuation Data");

    /* Set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTLS");
    return offset + 13 + record_length;
  }

  /*
   * If GUI, fill in record layer part of tree
   */

  /* add the record layer subtree header */
  ti = proto_tree_add_item(tree, hf_dtls_record, tvb,
                               offset, 13 + record_length, ENC_NA);
  dtls_record_tree = proto_item_add_subtree(ti, ett_dtls_record);

  /* show the one-byte content type */
  proto_tree_add_item(dtls_record_tree, hf_dtls_record_content_type,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* add the version */
  proto_tree_add_item(dtls_record_tree, hf_dtls_record_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* show epoch */
  proto_tree_add_uint(dtls_record_tree, hf_dtls_record_epoch, tvb, offset, 2, epoch);
  offset += 2;

  /* add sequence_number */
  proto_tree_add_uint64(dtls_record_tree, hf_dtls_record_sequence_number, tvb, offset, 6, sequence_number);
  offset += 6;

  /* add the length */
  length_pi = proto_tree_add_uint(dtls_record_tree, hf_dtls_record_length, tvb,
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
    ssl_try_set_version(session, ssl, content_type, next_byte, TRUE, version);
  col_set_str(pinfo->cinfo, COL_PROTOCOL,
      val_to_str_const(session->version, ssl_version_short_names, "DTLS"));

  /*
   * now dissect the next layer
   */
  ssl_debug_printf("dissect_dtls_record: content_type %d\n",content_type);

  /* try to decrypt record on the first pass, if possible. Store decrypted
   * record for later usage (without having to decrypt again). */
  if (ssl) {
    decrypt_dtls_record(tvb, pinfo, offset, ssl, content_type, version, record_length, curr_layer_num_ssl);
  }
  decrypted = ssl_get_record_info(tvb, proto_dtls, pinfo, tvb_raw_offset(tvb)+offset, curr_layer_num_ssl, &record);
  if (decrypted) {
    add_new_data_source(pinfo, decrypted, "Decrypted DTLS");
  }
  ssl_check_record_length(&dissect_dtls_hf, pinfo, record_length, length_pi, session->version, decrypted);


  switch ((ContentType) content_type) {
  case SSL_ID_CHG_CIPHER_SPEC:
    col_append_str(pinfo->cinfo, COL_INFO, "Change Cipher Spec");
    ssl_dissect_change_cipher_spec(&dissect_dtls_hf, tvb, pinfo,
                                   dtls_record_tree, offset, session,
                                   is_from_server, ssl);
    if (ssl) {
        ssl_load_keyfile(dtls_options.keylog_filename, &dtls_keylog_file,
                         &dtls_master_key_map);
        ssl_finalize_decryption(ssl, &dtls_master_key_map);
        ssl_change_cipher(ssl, ssl_packet_from_server(session, dtls_associations, pinfo));
    }
    /* Heuristic: any later ChangeCipherSpec is not a resumption of this
     * session. Set the flag after ssl_finalize_decryption such that it has
     * a chance to use resume using Session Tickets. */
    if (is_from_server)
      session->is_session_resumed = FALSE;
    break;
  case SSL_ID_ALERT:
    {
      /* try to retrieve and use decrypted alert record, if any. */
      if (decrypted) {
        dissect_dtls_alert(decrypted, pinfo, dtls_record_tree, 0,
                           session);
      } else {
        dissect_dtls_alert(tvb, pinfo, dtls_record_tree, offset,
                           session);
      }
      break;
    }
  case SSL_ID_HANDSHAKE:
    {
      /* try to retrieve and use decrypted handshake record, if any. */
      if (decrypted) {
        dissect_dtls_handshake(decrypted, pinfo, dtls_record_tree, 0,
                               tvb_reported_length(decrypted), session, is_from_server,
                               ssl, content_type);
      } else {
        dissect_dtls_handshake(tvb, pinfo, dtls_record_tree, offset,
                               record_length, session, is_from_server, ssl,
                               content_type);
      }
      break;
    }
  case SSL_ID_APP_DATA:
    /* show on info column what we are decoding */
    col_append_str(pinfo->cinfo, COL_INFO, "Application Data");

    /* app_handle discovery is done here instead of dissect_dtls_payload()
     * because the protocol name needs to be displayed below. */
    if (!session->app_handle) {
      /* Unknown protocol handle, ssl_starttls_ack was not called before.
       * Try to find an appropriate dissection handle and cache it. */
      dissector_handle_t handle;
      handle = dissector_get_uint_handle(dtls_associations, pinfo->srcport);
      handle = handle ? handle : dissector_get_uint_handle(dtls_associations, pinfo->destport);
      if (handle) session->app_handle = handle;
    }

    proto_item_set_text(dtls_record_tree,
                        "%s Record Layer: %s Protocol: %s",
                        val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                        val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                        session->app_handle
                        ? dissector_handle_get_dissector_name(session->app_handle)
                        : "Application Data");

    proto_tree_add_item(dtls_record_tree, hf_dtls_record_appdata, tvb,
                        offset, record_length, ENC_NA);

    /* show decrypted data info, if available */
    if (decrypted)
      {
        gboolean  dissected;
        guint16   saved_match_port;
        /* try to dissect decrypted data*/
        ssl_debug_printf("%s decrypted len %d\n", G_STRFUNC, record->data_len);

        saved_match_port = pinfo->match_uint;
        if (ssl_packet_from_server(session, dtls_associations, pinfo)) {
          pinfo->match_uint = pinfo->srcport;
        } else {
          pinfo->match_uint = pinfo->destport;
        }

        /* find out a dissector using server port*/
        if (session->app_handle) {
          ssl_debug_printf("%s: found handle %p (%s)\n", G_STRFUNC,
                           (void *)session->app_handle,
                           dissector_handle_get_dissector_name(session->app_handle));
          ssl_print_data("decrypted app data", record->plain_data, record->data_len);

          if (have_tap_listener(exported_pdu_tap)) {
            export_pdu_packet(decrypted, pinfo, EXP_PDU_TAG_PROTO_NAME,
                              dissector_handle_get_dissector_name(session->app_handle));
          }

          dissected = call_dissector_only(session->app_handle, decrypted, pinfo, top_tree, NULL);
        }
        else {
          /* try heuristic subdissectors */
          dissected = dissector_try_heuristic(heur_subdissector_list, decrypted, pinfo, top_tree, &hdtbl_entry, NULL);
          if (dissected && have_tap_listener(exported_pdu_tap)) {
            export_pdu_packet(decrypted, pinfo, EXP_PDU_TAG_HEUR_PROTO_NAME, hdtbl_entry->short_name);
          }
        }
        pinfo->match_uint = saved_match_port;
        /* fallback to data dissector */
        if (!dissected)
          call_data_dissector(decrypted, pinfo, top_tree);
      }
    break;
  case SSL_ID_HEARTBEAT:
    /* try to retrieve and use decrypted alert record, if any. */
    if (decrypted) {
      dissect_dtls_heartbeat(decrypted, pinfo, dtls_record_tree, 0,
                             session, tvb_reported_length (decrypted), TRUE);
    } else {
      dissect_dtls_heartbeat(tvb, pinfo, dtls_record_tree, offset,
                             session, record_length, FALSE);
    }
    break;
  }
  offset += record_length; /* skip to end of record */

  return offset;
}

/* dissects the alert message, filling in the tree */
static void
dissect_dtls_alert(tvbuff_t *tvb, packet_info *pinfo,
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

   ti = proto_tree_add_item(tree, hf_dtls_alert_message, tvb,
                               offset, 2, ENC_NA);
   ssl_alert_tree = proto_item_add_subtree(ti, ett_dtls_alert);

  /*
   * set the record layer label
   */

  /* first lookup the names for the alert level and description */
  byte  = tvb_get_guint8(tvb, offset); /* grab the level byte */
  level = try_val_to_str(byte, ssl_31_alert_level);

  byte  = tvb_get_guint8(tvb, offset+1); /* grab the desc byte */
  desc  = try_val_to_str(byte, ssl_31_alert_description);

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
                              val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                              level, desc);
          proto_tree_add_item(ssl_alert_tree, hf_dtls_alert_message_level,
                              tvb, offset++, 1, ENC_BIG_ENDIAN);

          proto_tree_add_item(ssl_alert_tree, hf_dtls_alert_message_description,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
        }
      else
        {
          proto_item_set_text(tree,
                              "%s Record Layer: Encrypted Alert",
                              val_to_str_const(session->version, ssl_version_short_names, "DTLS"));
          proto_item_set_text(ssl_alert_tree,
                              "Alert Message: Encrypted Alert");
        }
    }
}


/* dissects the handshake protocol, filling the tree */
static void
dissect_dtls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 record_length, SslSession *session,
                       gint is_from_server,
                       SslDecryptSession* ssl, guint8 content_type)
{
  /*     struct {
   *         HandshakeType msg_type;
   *         uint24 length;
   *         uint16 message_seq;          //new field
   *         uint24 fragment_offset;      //new field
   *         uint24 fragment_length;      //new field
   *         select (HandshakeType) {
   *             case hello_request:       HelloRequest;
   *             case client_hello:        ClientHello;
   *             case server_hello:        ServerHello;
   *             case hello_verify_request: HelloVerifyRequest;     //new field
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

  proto_tree  *ti, *length_item = NULL, *fragment_length_item = NULL;
  proto_tree  *ssl_hand_tree;
  const gchar *msg_type_str;
  guint8       msg_type;
  guint32      length;
  guint16      message_seq;
  guint32      fragment_offset;
  guint32      fragment_length;
  gboolean     first_iteration;
  guint32      reassembled_length;
  tvbuff_t     *sub_tvb;

  msg_type_str    = NULL;
  first_iteration = TRUE;

  /* just as there can be multiple records per packet, there
   * can be multiple messages per record as long as they have
   * the same content type
   *
   * we really only care about this for handshake messages
   */

  /* set record_length to the max offset */
  record_length += offset;
  for (; offset < record_length; offset += fragment_length,
         first_iteration = FALSE) /* set up for next pass, if any */
    {
      fragment_head *frag_msg = NULL;
      tvbuff_t      *new_tvb  = NULL;
      const gchar   *frag_str = NULL;
      gboolean       fragmented;
      guint32        hs_offset = offset;

      /* add a subtree for the handshake protocol */
      ti = proto_tree_add_item(tree, hf_dtls_handshake_protocol, tvb, offset, -1, ENC_NA);
      ssl_hand_tree = proto_item_add_subtree(ti, ett_dtls_handshake);

      msg_type = tvb_get_guint8(tvb, offset);
      fragment_length = tvb_get_ntoh24(tvb, offset + 9);

      /* Check the fragment length in the handshake message. Assume it's an
       * encrypted handshake message if the message would pass
       * the record_length boundary. This is a workaround for the
       * situation where the first octet of the encrypted handshake
       * message is actually a known handshake message type.
       */
      if (offset + fragment_length <= record_length)
          msg_type_str = try_val_to_str(msg_type, ssl_31_handshake_type);

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
      if (msg_type_str)
        {
          col_append_str(pinfo->cinfo, COL_INFO, msg_type_str);
        }
      else
        {
          /* if we don't have a valid handshake type, just quit dissecting */
          col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Handshake Message");
          return;
        }

      proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_type,
                            tvb, offset, 1, msg_type);
      offset++;

      length = tvb_get_ntoh24(tvb, offset);
      length_item = proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_length,
                                          tvb, offset, 3, length);
      offset += 3;

      message_seq = tvb_get_ntohs(tvb,offset);
      proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_message_seq,
                            tvb, offset, 2, message_seq);
      offset += 2;

      fragment_offset = tvb_get_ntoh24(tvb, offset);
      proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_fragment_offset,
                            tvb, offset, 3, fragment_offset);
      offset += 3;

      fragment_length_item = proto_tree_add_uint(ssl_hand_tree,
                                                   hf_dtls_handshake_fragment_length,
                                                   tvb, offset, 3,
                                                   fragment_length);
      offset += 3;
      proto_item_set_len(ti, fragment_length + 12);

      fragmented = FALSE;
      if (fragment_length + fragment_offset > length)
        {
          if (fragment_offset == 0)
            {
              expert_add_info(pinfo, fragment_length_item, &ei_dtls_handshake_fragment_length_too_long);
            }
          else
            {
              fragmented = TRUE;
              expert_add_info(pinfo, fragment_length_item, &ei_dtls_handshake_fragment_past_end_msg);
            }
        }
      else if (fragment_offset > 0 && fragment_length == 0)
        {
          /* Fragmented message, but no actual fragment... Note that if a
           * fragment was previously completed (reassembled_length == length),
           * it is already dissected. */
          expert_add_info(pinfo, fragment_length_item, &ei_dtls_handshake_fragment_length_zero);
          continue;
        }
      else if (fragment_length < length)
        {
          fragmented = TRUE;

          /* Handle fragments of known message type, ignore others */
          if (ssl_is_valid_handshake_type(msg_type, TRUE))
            {
              /* Fragmented handshake message */
              pinfo->fragmented = TRUE;

              /* Don't pass the reassembly code data that doesn't exist */
              tvb_ensure_bytes_exist(tvb, offset, fragment_length);

              frag_msg = fragment_add(&dtls_reassembly_table,
                                      tvb, offset, pinfo, message_seq, NULL,
                                      fragment_offset, fragment_length, TRUE);
              /*
               * Do we already have a length for this reassembly?
               */
              reassembled_length = fragment_get_tot_len(&dtls_reassembly_table,
                                                        pinfo, message_seq, NULL);
              if (reassembled_length == 0)
                {
                  /* No - set it to the length specified by this packet. */
                  fragment_set_tot_len(&dtls_reassembly_table,
                                       pinfo, message_seq, NULL, length);
                }
              else
                {
                  /* Yes - if this packet specifies a different length,
                     report an error. */
                  if (reassembled_length != length)
                    {
                      expert_add_info(pinfo, length_item, &ei_dtls_msg_len_diff_fragment);
                    }
                }

              if (frag_msg && (fragment_length + fragment_offset) == reassembled_length)
                {
                  /* Reassembled */
                  new_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                     "Reassembled DTLS",
                                                     frag_msg,
                                                     &dtls_frag_items,
                                                     NULL, tree);
                  frag_str = " (Reassembled)";
                }
              else
                {
                  frag_str = " (Fragment)";
                }

              col_append_str(pinfo->cinfo, COL_INFO, frag_str);
            }
        }

      if (tree)
        {
          /* set the label text on the record layer expanding node */
          if (first_iteration)
            {
              proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s%s",
                                  val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                                  val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                                  msg_type_str, (frag_str!=NULL) ? frag_str : "");
            }
          else
            {
              proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s%s",
                                  val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                                  val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                                  "Multiple Handshake Messages",
                                  (frag_str!=NULL) ? frag_str : "");
            }

          if (ssl_hand_tree)
            {
              /* set the text label on the subtree node */
              proto_item_set_text(ssl_hand_tree, "Handshake Protocol: %s%s",
                                  msg_type_str, (frag_str!=NULL) ? frag_str : "");
            }
        }

        if (fragmented && !new_tvb)
        {
          /* Skip fragmented messages not reassembled yet */
          continue;
        }

        if (new_tvb)
        {
          sub_tvb = new_tvb;
        }
        else
        {
          sub_tvb = tvb_new_subset_length(tvb, offset, fragment_length);
        }

        /*
         * Add handshake message (including type, length, etc.) to hash (for
         * Extended Master Secret). The computation must however happen as if
         * the message was sent in a single fragment (RFC 6347, section 4.2.6).
         */
        if (fragment_offset == 0) {
          /* Unfragmented packet. */
          ssl_calculate_handshake_hash(ssl, tvb, hs_offset, 12 + fragment_length);
        } else {
          /*
           * Handshake message was fragmented over multiple messages, fake a
           * single fragment and add reassembled data.
           */
          /* msg_type (1), length (3), message_seq (2) */
          ssl_calculate_handshake_hash(ssl, tvb, hs_offset, 6);
          /* fragment_offset (3) equals to zero. */
          ssl_calculate_handshake_hash(ssl, NULL, 0, 3);
          /* fragment_length (3) equals to length. */
          ssl_calculate_handshake_hash(ssl, tvb, hs_offset + 1, 3);
          /* actual handshake data */
          ssl_calculate_handshake_hash(ssl, sub_tvb, 0, length);
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
            ssl_dissect_hnd_cli_hello(&dissect_dtls_hf, sub_tvb, pinfo,
                                      ssl_hand_tree, 0, length, session, ssl,
                                      &dtls_hfs);
            break;

          case SSL_HND_SERVER_HELLO:
            ssl_dissect_hnd_srv_hello(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree,
                                      0, length, session, ssl, TRUE);
            break;

          case SSL_HND_HELLO_VERIFY_REQUEST:
            /*
             * The initial ClientHello and HelloVerifyRequest are not included
             * in the calculation of the handshake_messages
             * (https://tools.ietf.org/html/rfc6347#page-18). This is also
             * important for correct calculation of Extended Master Secret.
             */
            if (ssl && ssl->handshake_data.data_len) {
              ssl_debug_printf("%s erasing previous handshake_messages: %d\n", G_STRFUNC, ssl->handshake_data.data_len);
              wmem_free(wmem_file_scope(), ssl->handshake_data.data);
              ssl->handshake_data.data = NULL;
              ssl->handshake_data.data_len = 0;
            }
            dissect_dtls_hnd_hello_verify_request(&dissect_dtls_hf, sub_tvb, pinfo,
                                                  ssl_hand_tree, 0, length);
            break;

          case SSL_HND_NEWSESSION_TICKET:
            /* no need to load keylog file here as it only links a previous
             * master key with this Session Ticket */
            ssl_dissect_hnd_new_ses_ticket(&dissect_dtls_hf, sub_tvb, pinfo,
                                           ssl_hand_tree, 0, length, session, ssl, TRUE,
                                           dtls_master_key_map.tickets);
            break;

          case SSL_HND_HELLO_RETRY_REQUEST:
            ssl_dissect_hnd_hello_retry_request(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree,
                                                0, length, session, ssl, TRUE);
            break;

          case SSL_HND_CERTIFICATE:
            ssl_dissect_hnd_cert(&dissect_dtls_hf, sub_tvb, ssl_hand_tree, 0, length,
                pinfo, session, ssl, dtls_key_hash, is_from_server, TRUE);
            break;

          case SSL_HND_SERVER_KEY_EXCHG:
            ssl_dissect_hnd_srv_keyex(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session);
            break;

          case SSL_HND_CERT_REQUEST:
            ssl_dissect_hnd_cert_req(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session, TRUE);
            break;

          case SSL_HND_SVR_HELLO_DONE:
            /* This is not an abbreviated handshake, it is certainly not resumed. */
            session->is_session_resumed = FALSE;
            break;

          case SSL_HND_CERT_VERIFY:
            ssl_dissect_hnd_cli_cert_verify(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session->version);
            break;

          case SSL_HND_CLIENT_KEY_EXCHG:
            ssl_dissect_hnd_cli_keyex(&dissect_dtls_hf, sub_tvb, ssl_hand_tree, 0, length, session);
            if (!ssl)
                break;

            ssl_load_keyfile(dtls_options.keylog_filename, &dtls_keylog_file,
                             &dtls_master_key_map);
            /* try to find master key from pre-master key */
            if (!ssl_generate_pre_master_secret(ssl, length, sub_tvb, 0,
                                                dtls_options.psk,
                                                &dtls_master_key_map)) {
                ssl_debug_printf("dissect_dtls_handshake can't generate pre master secret\n");
            }
            break;

          case SSL_HND_FINISHED:
            ssl_dissect_hnd_finished(&dissect_dtls_hf, sub_tvb, ssl_hand_tree,
                                     0, length, session, NULL);
            break;

          case SSL_HND_CERT_URL:
          case SSL_HND_CERT_STATUS:
          case SSL_HND_SUPPLEMENTAL_DATA:
          case SSL_HND_KEY_UPDATE:
          case SSL_HND_ENCRYPTED_EXTS:
          case SSL_HND_END_OF_EARLY_DATA: /* TLS 1.3 */
          case SSL_HND_ENCRYPTED_EXTENSIONS: /* TLS 1.3 */
            /* TODO: does this need further dissection? */
            break;
        }
    }
}

/* dissects the heartbeat message, filling in the tree */
static void
dissect_dtls_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
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

  proto_tree  *ti;
  proto_tree  *dtls_heartbeat_tree;
  const gchar *type;
  guint8       byte;
  guint16      payload_length;
  guint16      padding_length;

  ti = proto_tree_add_item(tree, hf_dtls_heartbeat_message, tvb,
                             offset, record_length - 32, ENC_NA);
  dtls_heartbeat_tree = proto_item_add_subtree(ti, ett_dtls_heartbeat);

  /*
   * set the record layer label
   */

  /* first lookup the names for the message type and the payload length */
  byte = tvb_get_guint8(tvb, offset);
  type = try_val_to_str(byte, tls_heartbeat_type);

  payload_length = tvb_get_ntohs(tvb, offset + 1);
  padding_length = record_length - 3 - payload_length;

  /* now set the text in the record layer line */
  if (type && (payload_length <= record_length - 16 - 3)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat %s", type);
  } else {
    col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Heartbeat");
  }

  if (tree) {
    if (type && ((payload_length <= record_length - 16 - 3) || decrypted)) {
      proto_item_set_text(tree, "%s Record Layer: Heartbeat "
                                "%s",
                                val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                                type);
      proto_tree_add_item(dtls_heartbeat_tree, hf_dtls_heartbeat_message_type,
                          tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      ti = proto_tree_add_uint(dtls_heartbeat_tree, hf_dtls_heartbeat_message_payload_length,
                               tvb, offset, 2, payload_length);
      offset += 2;
      if (payload_length > record_length - 16 - 3) {
        expert_add_info_format(pinfo, ti, &ei_dtls_heartbeat_payload_length,
                               "Invalid heartbeat payload length (%d)", payload_length);
        /* Invalid heartbeat payload length, adjust to try decoding */
        payload_length = record_length - 16 - 3;
        padding_length = 16;
        proto_item_append_text (ti, " (invalid, using %u to decode payload)", payload_length);

      }
      proto_tree_add_bytes_format(dtls_heartbeat_tree, hf_dtls_heartbeat_message_payload,
                                  tvb, offset, payload_length,
                                  NULL, "Payload (%u byte%s)",
                                  payload_length,
                                  plurality(payload_length, "", "s"));
      offset += payload_length;
      proto_tree_add_bytes_format(dtls_heartbeat_tree, hf_dtls_heartbeat_message_padding,
                                  tvb, offset, padding_length,
                                  NULL, "Padding and HMAC (%u byte%s)",
                                  padding_length,
                                  plurality(padding_length, "", "s"));
    } else {
      proto_item_set_text(tree,
                         "%s Record Layer: Encrypted Heartbeat",
                         val_to_str_const(session->version, ssl_version_short_names, "DTLS"));
      proto_item_set_text(dtls_heartbeat_tree,
                          "Encrypted Heartbeat Message");
    }
  }
}

static int
dissect_dtls_hnd_hello_verify_request(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      packet_info *pinfo, proto_tree *tree,
                                      guint32 offset, guint32 offset_end)
{
  /*
   * struct {
   *    ProtocolVersion server_version;
   *    opaque cookie<0..32>;
   * } HelloVerifyRequest;
   */

  guint32 cookie_length;

  /* show the client version */
  proto_tree_add_item(tree, dissect_dtls_hf.hf.hs_server_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cookie_length,
                      dtls_hfs.hf_dtls_handshake_cookie_len, 0, 32)) {
      return offset;
  }
  offset++;

  if (cookie_length > 0)
  {
    proto_tree_add_item(tree, dtls_hfs.hf_dtls_handshake_cookie,
                        tvb, offset, cookie_length, ENC_NA);
    offset += cookie_length;
  }

  return offset;
}

gint
dtls_dissect_hnd_hello_ext_use_srtp(tvbuff_t *tvb, proto_tree *tree,
                                    guint32 offset, guint32 ext_len)
{
  /* From https://tools.ietf.org/html/rfc5764#section-4.1.1
   *
   * uint8 SRTPProtectionProfile[2];
   *
   * struct {
   *    SRTPProtectionProfiles SRTPProtectionProfiles;
   *    opaque srtp_mki<0..255>;
   * } UseSRTPData;
   *
   * SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;
   */

  guint32 profiles_length, profiles_end, mki_length;

  if (ext_len < 2) {
    /* XXX expert info, record too small */
    return offset + ext_len;
  }

  /* SRTPProtectionProfiles list length */
  proto_tree_add_item_ret_uint(tree, hf_dtls_hs_ext_use_srtp_protection_profiles_length,
      tvb, offset, 2, ENC_BIG_ENDIAN, &profiles_length);
  if (profiles_length > ext_len - 2) {
    /* XXX expert info because length exceeds extension_data field */
    profiles_length = ext_len - 2;
  }
  offset += 2;

  /* SRTPProtectionProfiles list items */
  profiles_end = offset + profiles_length;
  while (offset < profiles_end) {
    proto_tree_add_item(tree, hf_dtls_hs_ext_use_srtp_protection_profile,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  }

  /* MKI */
  proto_tree_add_item_ret_uint(tree, hf_dtls_hs_ext_use_srtp_mki_length,
      tvb, offset, 1, ENC_NA, &mki_length);
  offset++;
  if (mki_length > 0) {
    proto_tree_add_item(tree, hf_dtls_hs_ext_use_srtp_mki,
        tvb, offset, mki_length, ENC_NA);
    offset += mki_length;
  }

  return offset;
}

/*********************************************************************
 *
 * Support Functions
 *
 *********************************************************************/

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid dtls record.
 */
static gint
looks_like_dtls(tvbuff_t *tvb, guint32 offset)
{
  /* have to have a valid content type followed by a valid
   * protocol version
   */
  guint8  byte;
  guint16 version;

  /* see if the first byte is a valid content type */
  byte = tvb_get_guint8(tvb, offset);
  if (!ssl_is_valid_content_type(byte))
    {
      return 0;
    }

  /* now check to see if the version byte appears valid */
  version = tvb_get_ntohs(tvb, offset + 1);
  if (version != DTLSV1DOT0_VERSION && version != DTLSV1DOT2_VERSION &&
      version != DTLSV1DOT0_OPENSSL_VERSION)
    {
      return 0;
    }

  return 1;
}

/* UAT */

#if defined(HAVE_LIBGNUTLS)
static void
dtlsdecrypt_free_cb(void* r)
{
  ssldecrypt_assoc_t* h = (ssldecrypt_assoc_t*)r;

  g_free(h->ipaddr);
  g_free(h->port);
  g_free(h->protocol);
  g_free(h->keyfile);
  g_free(h->password);
}
#endif

#if 0
static void
dtlsdecrypt_update_cb(void* r _U_, const char** err _U_)
{
  return;
}
#endif

#if defined(HAVE_LIBGNUTLS)
static void *
dtlsdecrypt_copy_cb(void* dest, const void* orig, size_t len _U_)
{
  const ssldecrypt_assoc_t* o = (const ssldecrypt_assoc_t*)orig;
  ssldecrypt_assoc_t*       d = (ssldecrypt_assoc_t*)dest;

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
dtlsdecrypt_uat_fld_protocol_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        // This should be removed in favor of Decode As. Make it optional.
        *err = NULL;
        return TRUE;
    }

    if (!find_dissector(p)) {
        if (proto_get_id_by_filter_name(p) != -1) {
            *err = g_strdup_printf("While '%s' is a valid dissector filter name, that dissector is not configured"
                                   " to support DTLS decryption.\n\n"
                                   "If you need to decrypt '%s' over DTLS, please contact the Wireshark development team.", p, p);
        } else {
            char* ssl_str = ssl_association_info("dtls.port", "UDP");
            *err = g_strdup_printf("Could not find dissector for: '%s'\nCommonly used DTLS dissectors include:\n%s", p, ssl_str);
            g_free(ssl_str);
        }
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}
#endif

static void
dtls_src_prompt(packet_info *pinfo, gchar *result)
{
    SslPacketInfo* pi;
    guint32 srcport = pinfo->srcport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi != NULL)
        srcport = pi->srcport;

    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", srcport, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
dtls_src_value(packet_info *pinfo)
{
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi == NULL)
        return GUINT_TO_POINTER(pinfo->srcport);

    return GUINT_TO_POINTER(pi->srcport);
}

static void
dtls_dst_prompt(packet_info *pinfo, gchar *result)
{
    SslPacketInfo* pi;
    guint32 destport = pinfo->destport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi != NULL)
        destport = pi->destport;

    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, destport);
}

static gpointer
dtls_dst_value(packet_info *pinfo)
{
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi == NULL)
        return GUINT_TO_POINTER(pinfo->destport);

    return GUINT_TO_POINTER(pi->destport);
}

static void
dtls_both_prompt(packet_info *pinfo, gchar *result)
{
    SslPacketInfo* pi;
    guint32 srcport = pinfo->srcport,
            destport = pinfo->destport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi != NULL)
    {
        srcport = pi->srcport;
        destport = pi->destport;
    }

    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "both (%u%s%u)", srcport, UTF8_LEFT_RIGHT_ARROW, destport);
}

void proto_reg_handoff_dtls(void);

/*********************************************************************
 *
 * Standard Wireshark Protocol Registration and housekeeping
 *
 *********************************************************************/
void
proto_register_dtls(void)
{

  /* Setup list of header fields See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_dtls_record,
      { "Record Layer", "dtls.record",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_content_type,
      { "Content Type", "dtls.record.content_type",
        FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
        NULL, HFILL}
    },
    { &hf_dtls_record_version,
      { "Version", "dtls.record.version",
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
        "Record layer version.", HFILL }
    },
    { &hf_dtls_record_epoch,
      { "Epoch", "dtls.record.epoch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_sequence_number,
      { "Sequence Number", "dtls.record.sequence_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_length,
      { "Length", "dtls.record.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of DTLS record data", HFILL }
    },
    { &hf_dtls_record_appdata,
      { "Encrypted Application Data", "dtls.app_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Payload is encrypted application data", HFILL }
    },
    { & hf_dtls_alert_message,
      { "Alert Message", "dtls.alert_message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_dtls_alert_message_level,
      { "Level", "dtls.alert_message.level",
        FT_UINT8, BASE_DEC, VALS(ssl_31_alert_level), 0x0,
        "Alert message level", HFILL }
    },
    { &hf_dtls_alert_message_description,
      { "Description", "dtls.alert_message.desc",
        FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
        "Alert message description", HFILL }
    },
    { &hf_dtls_handshake_protocol,
      { "Handshake Protocol", "dtls.handshake",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Handshake protocol message", HFILL}
    },
    { &hf_dtls_handshake_type,
      { "Handshake Type", "dtls.handshake.type",
        FT_UINT8, BASE_DEC, VALS(ssl_31_handshake_type), 0x0,
        "Type of handshake message", HFILL}
    },
    { &hf_dtls_handshake_length,
      { "Length", "dtls.handshake.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Length of handshake message", HFILL }
    },
    { &hf_dtls_handshake_message_seq,
      { "Message Sequence", "dtls.handshake.message_seq",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Message sequence of handshake message", HFILL }
    },
    { &hf_dtls_handshake_fragment_offset,
      { "Fragment Offset", "dtls.handshake.fragment_offset",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Fragment offset of handshake message", HFILL }
    },
    { &hf_dtls_handshake_fragment_length,
      { "Fragment Length", "dtls.handshake.fragment_length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Fragment length of handshake message", HFILL }
    },
    { &dtls_hfs.hf_dtls_handshake_cookie_len,
      { "Cookie Length", "dtls.handshake.cookie_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of the cookie field", HFILL }
    },
    { &dtls_hfs.hf_dtls_handshake_cookie,
      { "Cookie", "dtls.handshake.cookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message,
      { "Heartbeat Message", "dtls.heartbeat_message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message_type,
      { "Type", "dtls.heartbeat_message.type",
        FT_UINT8, BASE_DEC, VALS(tls_heartbeat_type), 0x0,
        "Heartbeat message type", HFILL }
    },
    { &hf_dtls_heartbeat_message_payload_length,
      { "Payload Length", "dtls.heartbeat_message.payload_length",
        FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message_payload,
      { "Payload Length", "dtls.heartbeat_message.payload",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message_padding,
      { "Payload Length", "dtls.heartbeat_message.padding",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_fragments,
      { "Message fragments", "dtls.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_fragment,
      { "Message fragment", "dtls.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_fragment_overlap,
      { "Message fragment overlap", "dtls.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data",
        "dtls.fragment.overlap.conflicts",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_multiple_tails,
      { "Message has multiple tail fragments",
        "dtls.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_too_long_fragment,
      { "Message fragment too long", "dtls.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_error,
      { "Message defragmentation error", "dtls.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_fragment_count,
      { "Message fragment count", "dtls.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_reassembled_in,
      { "Reassembled in", "dtls.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_reassembled_length,
      { "Reassembled DTLS length", "dtls.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_protection_profiles_length,
      { "SRTP Protection Profiles Length", "dtls.use_srtp.protection_profiles_length",
        FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_protection_profile,
      { "SRTP Protection Profile", "dtls.use_srtp.protection_profile",
        FT_UINT16, BASE_HEX, VALS(srtp_protection_profile_vals), 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_mki_length,
      { "MKI Length", "dtls.use_srtp.mki_length",
        FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_mki,
      { "MKI", "dtls.use_srtp.mki",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    SSL_COMMON_HF_LIST(dissect_dtls_hf, "dtls")
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_dtls,
    &ett_dtls_record,
    &ett_dtls_alert,
    &ett_dtls_handshake,
    &ett_dtls_heartbeat,
    &ett_dtls_certs,
    &ett_dtls_fragment,
    &ett_dtls_fragments,
    SSL_COMMON_ETT_LIST(dissect_dtls_hf)
  };

  static ei_register_info ei[] = {
     { &ei_dtls_handshake_fragment_length_zero, { "dtls.handshake.fragment_length.zero", PI_PROTOCOL, PI_WARN, "Zero-length fragment length for fragmented message", EXPFILL }},
     { &ei_dtls_handshake_fragment_length_too_long, { "dtls.handshake.fragment_length.too_long", PI_PROTOCOL, PI_ERROR, "Fragment length is larger than message length", EXPFILL }},
     { &ei_dtls_handshake_fragment_past_end_msg, { "dtls.handshake.fragment_past_end_msg", PI_PROTOCOL, PI_ERROR, "Fragment runs past the end of the message", EXPFILL }},
     { &ei_dtls_msg_len_diff_fragment, { "dtls.msg_len_diff_fragment", PI_PROTOCOL, PI_ERROR, "Message length differs from value in earlier fragment", EXPFILL }},
     { &ei_dtls_heartbeat_payload_length, { "dtls.heartbeat_message.payload_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid heartbeat payload length", EXPFILL }},

     SSL_COMMON_EI_LIST(dissect_dtls_hf, "dtls")
  };

  static build_valid_func dtls_da_src_values[1] = {dtls_src_value};
  static build_valid_func dtls_da_dst_values[1] = {dtls_dst_value};
  static build_valid_func dtls_da_both_values[2] = {dtls_src_value, dtls_dst_value};
  static decode_as_value_t dtls_da_values[3] = {{dtls_src_prompt, 1, dtls_da_src_values}, {dtls_dst_prompt, 1, dtls_da_dst_values}, {dtls_both_prompt, 2, dtls_da_both_values}};
  static decode_as_t dtls_da = {"dtls", "Transport", "dtls.port", 3, 2, dtls_da_values, "UDP", "port(s) as",
                               decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

  expert_module_t* expert_dtls;

  /* Register the protocol name and description */
  proto_dtls = proto_register_protocol("Datagram Transport Layer Security",
                                       "DTLS", "dtls");

  dtls_associations = register_dissector_table("dtls.port", "DTLS Port", proto_dtls, FT_UINT16, BASE_DEC);

  /* Required function calls to register the header fields and
   * subtrees used */
  proto_register_field_array(proto_dtls, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dtls = expert_register_protocol(proto_dtls);
  expert_register_field_array(expert_dtls, ei, array_length(ei));

  {
    module_t *dtls_module = prefs_register_protocol(proto_dtls, proto_reg_handoff_dtls);

#ifdef HAVE_LIBGNUTLS
    static uat_field_t dtlskeylist_uats_flds[] = {
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, ipaddr, "IP address", ssldecrypt_uat_fld_ip_chk_cb, "IPv4 or IPv6 address (unused)"),
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, port, "Port", ssldecrypt_uat_fld_port_chk_cb, "Port Number (optional)"),
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, protocol, "Protocol", dtlsdecrypt_uat_fld_protocol_chk_cb, "Application Layer Protocol (optional)"),
      UAT_FLD_FILENAME_OTHER(sslkeylist_uats, keyfile, "Key File", ssldecrypt_uat_fld_fileopen_chk_cb, "Path to the keyfile."),
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, password," Password (p12 file)", ssldecrypt_uat_fld_password_chk_cb, "Password"),
      UAT_END_FIELDS
    };

    dtlsdecrypt_uat = uat_new("DTLS RSA Keylist",
                              sizeof(ssldecrypt_assoc_t),
                              "dtlsdecrypttablefile",         /* filename */
                              TRUE,                           /* from_profile */
                              &dtlskeylist_uats,              /* data_ptr */
                              &ndtlsdecrypt,                  /* numitems_ptr */
                              UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
                              "ChK12ProtocolsSection",        /* TODO, need revision - help */
                              dtlsdecrypt_copy_cb,
                              NULL, /* dtlsdecrypt_update_cb? */
                              dtlsdecrypt_free_cb,
                              dtls_parse_uat,
                              dtls_reset_uat,
                              dtlskeylist_uats_flds);

    prefs_register_uat_preference(dtls_module, "cfg",
                                  "RSA keys list",
                                  "A table of RSA keys for DTLS decryption",
                                  dtlsdecrypt_uat);
#endif /* HAVE_LIBGNUTLS */

    prefs_register_filename_preference(dtls_module, "debug_file", "DTLS debug file",
                                       "redirect dtls debug to file name; leave empty to disable debug, "
                                       "use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr\n",
                                       &dtls_debug_file_name, TRUE);

    prefs_register_string_preference(dtls_module, "keys_list", "RSA keys list (deprecated)",
                                     "Semicolon-separated list of private RSA keys used for DTLS decryption. "
                                     "Used by versions of Wireshark prior to 1.6",
                                     &dtls_keys_list);
    ssl_common_register_options(dtls_module, &dtls_options);
  }

  dtls_handle = register_dissector("dtls", dissect_dtls, proto_dtls);

  register_init_routine(dtls_init);
  register_cleanup_routine(dtls_cleanup);
  reassembly_table_register (&dtls_reassembly_table, &addresses_ports_reassembly_table_functions);
  register_decode_as(&dtls_da);

  dtls_tap = register_tap("dtls");
  ssl_debug_printf("proto_register_dtls: registered tap %s:%d\n",
                   "dtls", dtls_tap);

  heur_subdissector_list = register_heur_dissector_list("dtls", proto_dtls);
}


/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_dtls(void)
{
  static gboolean initialized = FALSE;

  /* add now dissector to default ports.*/
  dtls_parse_uat();
  dtls_parse_old_keys();
  exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);

  if (initialized == FALSE) {
    heur_dissector_add("udp", dissect_dtls_heur, "DTLS over UDP", "dtls_udp", proto_dtls, HEURISTIC_ENABLE);
    dissector_add_uint("sctp.ppi", DIAMETER_DTLS_PROTOCOL_ID, dtls_handle);
  }

  initialized = TRUE;
}

void
dtls_dissector_add(guint port, dissector_handle_t handle)
{
  ssl_association_add("dtls.port", dtls_handle, handle, port, FALSE);
}

void
dtls_dissector_delete(guint port, dissector_handle_t handle)
{
  ssl_association_remove("dtls.port", dtls_handle, handle, port, FALSE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
