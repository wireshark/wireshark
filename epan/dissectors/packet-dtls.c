/* packet-dtls.c
 * Routines for dtls dissection
 * Copyright (c) 2006, Authesserre Samuel <sauthess@gmail.com>
 * Copyright (c) 2007, Mikael Magnusson <mikma@users.sourceforge.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * DTLS dissection and decryption.
 * See RFC 4347 for details about DTLS specs.
 *
 * Notes :
 * This dissector is based on TLS one (packet-ssl.c) because of the proximity of DTLS and TLS, decryption works like him with RSA key exchange.
 * It uses the sames things (file, libraries) that SSL one (gnutls, packet-ssl-utils.h) to make it easily maintenable.
 *
 * It was developped to dissect and decrypt OpenSSL v 0.9.8f DTLS implementation.
 * It is limited to this implementation  while there is no complete implementation.
 *
 * Implemented :
 *  - DTLS dissection
 *  - DTLS decryption (openssl one)
 *
 * Todo :
 *  - activate correct Mac calculation when openssl will be corrected
 *    (or if an other implementation works),
 *    corrected code is ready and commented in packet-ssl-utils.h file.
 *  - add missings things (desegmentation, reordering... that aren't present in actual OpenSSL implementation)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <glib.h>

#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include <epan/reassemble.h>
#ifdef NEED_INET_V6DEFS_H
#include "wsutil/inet_v6defs.h"
#endif
#include "packet-ssl-utils.h"
#include <wsutil/file_util.h>
#include <epan/uat.h>

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

/* Initialize the protocol and registered fields */
static gint dtls_tap                           = -1;
static gint proto_dtls                         = -1;
static gint hf_dtls_record                     = -1;
static gint hf_dtls_record_content_type        = -1;
static gint hf_dtls_record_version             = -1;
static gint hf_dtls_record_epoch               = -1;
static gint hf_dtls_record_sequence_number     = -1;
static gint hf_dtls_record_length              = -1;
static gint hf_dtls_record_appdata             = -1;
static gint hf_dtls_change_cipher_spec         = -1;
static gint hf_dtls_alert_message              = -1;
static gint hf_dtls_alert_message_level        = -1;
static gint hf_dtls_alert_message_description  = -1;
static gint hf_dtls_handshake_protocol         = -1;
static gint hf_dtls_handshake_type             = -1;
static gint hf_dtls_handshake_length           = -1;
static gint hf_dtls_handshake_message_seq      = -1;
static gint hf_dtls_handshake_fragment_offset  = -1;
static gint hf_dtls_handshake_fragment_length  = -1;
static gint hf_dtls_handshake_client_version   = -1;
static gint hf_dtls_handshake_server_version   = -1;
static gint hf_dtls_handshake_random_time      = -1;
static gint hf_dtls_handshake_random_bytes     = -1;
static gint hf_dtls_handshake_cookie_len       = -1;
static gint hf_dtls_handshake_cookie           = -1;
static gint hf_dtls_handshake_cipher_suites_len = -1;
static gint hf_dtls_handshake_cipher_suites    = -1;
static gint hf_dtls_handshake_cipher_suite     = -1;
static gint hf_dtls_handshake_session_id       = -1;
static gint hf_dtls_handshake_comp_methods_len = -1;
static gint hf_dtls_handshake_comp_methods     = -1;
static gint hf_dtls_handshake_comp_method      = -1;
static gint hf_dtls_handshake_extensions_len   = -1;
static gint hf_dtls_handshake_extension_type   = -1;
static gint hf_dtls_handshake_extension_len    = -1;
static gint hf_dtls_handshake_extension_data   = -1;
static gint hf_dtls_handshake_certificates_len = -1;
static gint hf_dtls_handshake_certificates     = -1;
static gint hf_dtls_handshake_certificate      = -1;
static gint hf_dtls_handshake_certificate_len  = -1;
static gint hf_dtls_handshake_cert_types_count = -1;
static gint hf_dtls_handshake_cert_types       = -1;
static gint hf_dtls_handshake_cert_type        = -1;
static gint hf_dtls_handshake_finished         = -1;
static gint hf_dtls_handshake_md5_hash         = -1;
static gint hf_dtls_handshake_sha_hash         = -1;
static gint hf_dtls_handshake_session_id_len   = -1;
static gint hf_dtls_handshake_dnames_len       = -1;
static gint hf_dtls_handshake_dnames           = -1;
static gint hf_dtls_handshake_dname_len        = -1;
static gint hf_dtls_handshake_dname            = -1;

static gint hf_dtls_fragments                  = -1;
static gint hf_dtls_fragment                   = -1;
static gint hf_dtls_fragment_overlap           = -1;
static gint hf_dtls_fragment_overlap_conflicts = -1;
static gint hf_dtls_fragment_multiple_tails    = -1;
static gint hf_dtls_fragment_too_long_fragment = -1;
static gint hf_dtls_fragment_error             = -1;
static gint hf_dtls_fragment_count             = -1;
static gint hf_dtls_reassembled_in             = -1;
static gint hf_dtls_reassembled_length         = -1;

/* Initialize the subtree pointers */
static gint ett_dtls                   = -1;
static gint ett_dtls_record            = -1;
static gint ett_dtls_alert             = -1;
static gint ett_dtls_handshake         = -1;
static gint ett_dtls_cipher_suites     = -1;
static gint ett_dtls_comp_methods      = -1;
static gint ett_dtls_extension         = -1;
static gint ett_dtls_certs             = -1;
static gint ett_dtls_cert_types        = -1;
static gint ett_dtls_dnames            = -1;

static gint ett_dtls_fragment          = -1;
static gint ett_dtls_fragments         = -1;

static GHashTable *dtls_session_hash   = NULL;
static GHashTable *dtls_key_hash       = NULL;
static GHashTable *dtls_fragment_table = NULL;
static GTree* dtls_associations = NULL;
static dissector_handle_t dtls_handle  = NULL;
static StringInfo dtls_compressed_data = {NULL, 0};
static StringInfo dtls_decrypted_data  = {NULL, 0};
static gint dtls_decrypted_data_avail  = 0;

static uat_t *dtlsdecrypt_uat = NULL;
static gchar* dtls_keys_list = NULL;
#ifdef HAVE_LIBGNUTLS
static gchar* dtls_debug_file_name = NULL;
#endif

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
  /* Tag */
  "Message fragments"
};

/* initialize/reset per capture state data (dtls sessions cache) */
static void
dtls_init(void)
{
  module_t *dtls_module = prefs_find_module("dtls");
  pref_t *keys_list_pref;

  ssl_common_init(&dtls_session_hash, &dtls_decrypted_data, &dtls_compressed_data);
  fragment_table_init (&dtls_fragment_table);

  /* We should have loaded "keys_list" by now. Mark it obsolete */
  if (dtls_module) {
    keys_list_pref = prefs_find_preference(dtls_module, "keys_list");
    if (! prefs_get_preference_obsolete(keys_list_pref)) {
      prefs_set_preference_obsolete(keys_list_pref);
    }
  }
}

/* parse dtls related preferences (private keys and ports association strings) */
static void
dtls_parse(void)
{
  ep_stack_t tmp_stack;
  SslAssociation *tmp_assoc;
  guint i;
  gchar **old_keys, **parts, *err;
  GString *uat_entry = g_string_new("");

  if (dtls_key_hash)
    {
      g_hash_table_foreach(dtls_key_hash, ssl_private_key_free, NULL);
      g_hash_table_destroy(dtls_key_hash);
    }

  /* remove only associations created from key list */
  tmp_stack = ep_stack_new();
  g_tree_foreach(dtls_associations, ssl_assoc_from_key_list, tmp_stack);
  while ((tmp_assoc = ep_stack_pop(tmp_stack)) != NULL) {
    ssl_association_remove(dtls_associations, tmp_assoc);
  }

  /* Import old-style keys */
  if (dtlsdecrypt_uat && dtls_keys_list && dtls_keys_list[0]) {
    old_keys = g_strsplit(dtls_keys_list, ";", 0);
    for (i = 0; old_keys[i] != NULL; i++) {
      parts = g_strsplit(old_keys[i], ",", 4);
      if (parts[0] && parts[1] && parts[2] && parts[3]) {
	g_string_printf(uat_entry, "\"%s\",\"%s\",\"%s\",\"%s\",\"\"",
			parts[0], parts[1], parts[2], parts[3]);
	if (!uat_load_str(dtlsdecrypt_uat, uat_entry->str, &err)) {
	  ssl_debug_printf("dtls_parse: Can't load UAT string %s: %s\n",
                           uat_entry->str, err);
	}
      }
      g_strfreev(parts);
    }
    g_strfreev(old_keys);
  }
  g_string_free(uat_entry, TRUE);


  /* parse private keys string, load available keys and put them in key hash*/
  dtls_key_hash = g_hash_table_new(ssl_private_key_hash, ssl_private_key_equal);

  if (ndtlsdecrypt > 0)
  {
	  for (i = 0; i < ndtlsdecrypt; i++)
	  {
		  ssldecrypt_assoc_t *d = &(dtlskeylist_uats[i]);
		  ssl_parse_key_list(d, dtls_key_hash, dtls_associations, dtls_handle, FALSE);
	  }
  }

  ssl_set_debug(dtls_debug_file_name);

  dissector_add_handle("sctp.port", dtls_handle);
  dissector_add_handle("udp.port", dtls_handle);
}

/*
 * DTLS Dissection Routines
 *
 */

/* record layer dissector */
static gint dissect_dtls_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, guint32 offset,
                                guint *conv_version,
                                SslDecryptSession *conv_data);

/* change cipher spec dissector */
static void dissect_dtls_change_cipher_spec(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            guint32 offset,
                                            guint *conv_version, guint8 content_type);

/* alert message dissector */
static void dissect_dtls_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version);

/* handshake protocol dissector */
static void dissect_dtls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint32 record_length,
                                   guint *conv_version,
                                   SslDecryptSession *conv_data, guint8 content_type);


static void dissect_dtls_hnd_cli_hello(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length,
                                       SslDecryptSession* ssl);

static void dissect_dtls_hnd_hello_verify_request(tvbuff_t *tvb,
                                                  proto_tree *tree,
                                                  guint32 offset,
                                                  SslDecryptSession* ssl);

static void dissect_dtls_hnd_srv_hello(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length,
                                       SslDecryptSession* ssl);

static void dissect_dtls_hnd_cert(tvbuff_t *tvb,
                                  proto_tree *tree, guint32 offset, packet_info *pinfo);

static void dissect_dtls_hnd_cert_req(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset);

static void dissect_dtls_hnd_finished(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset,
                                      guint* conv_version);

/*
 * Support Functions
 *
 */
/*static void ssl_set_conv_version(packet_info *pinfo, guint version);*/
static gint  dtls_is_valid_handshake_type(guint8 type);

static gint  dtls_is_authoritative_version_message(guint8 content_type,
                                                   guint8 next_byte);
static gint  looks_like_dtls(tvbuff_t *tvb, guint32 offset);

/*********************************************************************
 *
 * Main dissector
 *
 *********************************************************************/
/*
 * Code to actually dissect the packets
 */
static void
dissect_dtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  conversation_t *conversation;
  void *conv_data;
  proto_item *ti;
  proto_tree *dtls_tree;
  guint32 offset;
  gboolean first_record_in_frame;
  SslDecryptSession* ssl_session;
  guint* conv_version;
  ti = NULL;
  dtls_tree = NULL;
  offset = 0;
  first_record_in_frame = TRUE;
  ssl_session = NULL;
  top_tree=tree;

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
  conv_data = conversation_get_proto_data(conversation, proto_dtls);

  /* manage dtls decryption data */
  /*get a valid ssl session pointer*/
  if (conv_data != NULL)
    ssl_session = conv_data;
  else {
    SslService dummy;

    ssl_session = se_alloc0(sizeof(SslDecryptSession));
    ssl_session_init(ssl_session);
    ssl_session->version = SSL_VER_UNKNOWN;
    conversation_add_proto_data(conversation, proto_dtls, ssl_session);

    /* we need to know witch side of conversation is speaking */
    if (ssl_packet_from_server(ssl_session, dtls_associations, pinfo)) {
      dummy.addr = pinfo->src;
      dummy.port = pinfo->srcport;
    }
    else {
      dummy.addr = pinfo->dst;
      dummy.port = pinfo->destport;
    }
    ssl_debug_printf("dissect_dtls server %s:%d\n",
                     ep_address_to_str(&dummy.addr),dummy.port);

    /* try to retrive private key for this service. Do it now 'cause pinfo
     * is not always available
     * Note that with HAVE_LIBGNUTLS undefined private_key is allways 0
     * and thus decryption never engaged*/
    ssl_session->private_key = g_hash_table_lookup(dtls_key_hash, &dummy);
    if (!ssl_session->private_key)
      ssl_debug_printf("dissect_dtls can't find private key for this server!\n");
  }
  conv_version= & ssl_session->version;

  /* try decryption only the first time we see this packet
   * (to keep cipher synchronized)and only if we have
   * the server private key*/
  if (!ssl_session->private_key || pinfo->fd->flags.visited)
    ssl_session = NULL;

  /* Initialize the protocol column; we'll set it later when we
   * figure out what flavor of DTLS it is (actually only one
   version exists). */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTLS");

  /* clear the the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  /* Create display subtree for SSL as a whole */
  if (tree)
    {
      ti = proto_tree_add_item(tree, proto_dtls, tvb, 0, -1, FALSE);
      dtls_tree = proto_item_add_subtree(ti, ett_dtls);
    }

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
      switch(*conv_version) {
      case SSL_VER_DTLS:
        offset = dissect_dtls_record(tvb, pinfo, dtls_tree,
                                     offset, conv_version,
                                     ssl_session);
        break;

        /* that failed, so apply some heuristics based
         * on this individual packet
         */
      default:
        if (looks_like_dtls(tvb, offset))
          {
            /* looks like dtls */
            offset = dissect_dtls_record(tvb, pinfo, dtls_tree,
                                         offset, conv_version,
                                         ssl_session);
          }
        else
          {
            /* looks like something unknown, so lump into
             * continuation data
             */
            offset = tvb_length(tvb);
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

  tap_queue_packet(dtls_tap, pinfo, NULL);
}

static gint
decrypt_dtls_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset,
                    guint32 record_length, guint8 content_type, SslDecryptSession* ssl,
                    gboolean save_plaintext)
{
  gint ret;
  SslDecoder* decoder;
  ret = 0;

  /* if we can decrypt and decryption have success
   * add decrypted data to this packet info */
  ssl_debug_printf("decrypt_dtls_record: app_data len %d, ssl state %X\n",
                   record_length, ssl->state);
  if (!(ssl->state & SSL_HAVE_SESSION_KEY)) {
    ssl_debug_printf("decrypt_dtls_record: no session key\n");
    return ret;
  }

  /* retrive decoder for this packet direction */
  if (ssl_packet_from_server(ssl, dtls_associations, pinfo) != 0) {
    ssl_debug_printf("decrypt_dtls_record: using server decoder\n");
    decoder = ssl->server;
  }
  else {
    ssl_debug_printf("decrypt_dtls_record: using client decoder\n");
    decoder = ssl->client;
  }

  /* ensure we have enough storage space for decrypted data */
  if (record_length > dtls_decrypted_data.data_len)
    {
      ssl_debug_printf("decrypt_dtls_record: allocating %d bytes"
                       " for decrypt data (old len %d)\n",
                       record_length + 32, dtls_decrypted_data.data_len);
      dtls_decrypted_data.data = g_realloc(dtls_decrypted_data.data,
                                           record_length + 32);
      dtls_decrypted_data.data_len = record_length + 32;
    }

  /* run decryption and add decrypted payload to protocol data, if decryption
   * is successful*/
  dtls_decrypted_data_avail = dtls_decrypted_data.data_len;
  if (ssl_decrypt_record(ssl, decoder,
                         content_type, tvb_get_ptr(tvb, offset, record_length),
                         record_length, &dtls_compressed_data, &dtls_decrypted_data, &dtls_decrypted_data_avail) == 0)
    ret = 1;

    if (ret && save_plaintext) {
      ssl_add_data_info(proto_dtls, pinfo, dtls_decrypted_data.data, dtls_decrypted_data_avail,  TVB_RAW_OFFSET(tvb)+offset, 0);
    }

  return ret;
}





/*********************************************************************
 *
 * DTLS Dissection Routines
 *
 *********************************************************************/
static gint
dissect_dtls_record(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, guint32 offset,
                    guint *conv_version,
                    SslDecryptSession* ssl)
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
   *       uint16 epoch;               // New field
   *       uint48 sequence_number;       // New field
   *        uint16 length;
   *        opaque fragment[TLSPlaintext.length];
   *    } DTLSPlaintext;
   */
  guint32 record_length;
  guint16 version;
  guint16 epoch;
  gdouble sequence_number;
  gint64 sequence_number_temp;
  guint8 content_type;
  guint8 next_byte;
  proto_tree *ti;
  proto_tree *dtls_record_tree;
  guint32 available_bytes;
  SslAssociation* association;
  SslDataInfo *appl_data;
  ti              = NULL;
  dtls_record_tree = NULL;
  available_bytes = tvb_length_remaining(tvb, offset);

  /*
   * Get the record layer fields of interest
   */
  content_type  = tvb_get_guint8(tvb, offset);
  version       = tvb_get_ntohs(tvb, offset + 1);
  epoch       = tvb_get_ntohs(tvb, offset + 3);
  sequence_number  = tvb_get_ntohl(tvb, offset + 7);
  sequence_number_temp=tvb_get_ntohs(tvb, offset + 5);
  sequence_number_temp=sequence_number_temp<<32;
  sequence_number+=sequence_number_temp;
  record_length = tvb_get_ntohs(tvb, offset + 11);

  if(ssl){
    if(ssl_packet_from_server(ssl, dtls_associations, pinfo)){
     if (ssl->server) {
      ssl->server->seq=(guint32)sequence_number;
      ssl->server->epoch=epoch;
     }
    }
    else{
     if (ssl->client) {
      ssl->client->seq=(guint32)sequence_number;
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

  if (tree)
    {
      /* add the record layer subtree header */
      tvb_ensure_bytes_exist(tvb, offset, 13 + record_length);
      ti = proto_tree_add_item(tree, hf_dtls_record, tvb,
                               offset, 13 + record_length, 0);
      dtls_record_tree = proto_item_add_subtree(ti, ett_dtls_record);
    }

  if (dtls_record_tree)
    {

      /* show the one-byte content type */
      proto_tree_add_item(dtls_record_tree, hf_dtls_record_content_type,
                          tvb, offset, 1, FALSE);
      offset++;

      /* add the version */
      proto_tree_add_item(dtls_record_tree, hf_dtls_record_version, tvb,
                          offset, 2, FALSE);
      offset += 2;

      /* show epoch */
      proto_tree_add_uint(dtls_record_tree, hf_dtls_record_epoch, tvb, offset, 2, epoch);

      offset += 2;

      /* add sequence_number */

      proto_tree_add_double(dtls_record_tree, hf_dtls_record_sequence_number, tvb, offset, 6, sequence_number);

      offset += 6;

      /* add the length */
      proto_tree_add_uint(dtls_record_tree, hf_dtls_record_length, tvb,
                          offset, 2, record_length);
      offset += 2;    /* move past length field itself */

    }
  else
    {
      /* if no GUI tree, then just skip over those fields */
      offset += 13;
    }


  /*
   * if we don't already have a version set for this conversation,
   * but this message's version is authoritative (i.e., it's
   * not client_hello, then save the version to to conversation
   * structure and print the column version
   */
  next_byte = tvb_get_guint8(tvb, offset);
  if (*conv_version == SSL_VER_UNKNOWN
      && dtls_is_authoritative_version_message(content_type, next_byte))
    {
      if (version == DTLSV1DOT0_VERSION ||
          version == DTLSV1DOT0_VERSION_NOT)
        {

          *conv_version = SSL_VER_DTLS;
          if (ssl) {
            ssl->version_netorder = version;
            ssl->state |= SSL_VERSION;
          }
          /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
    }
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
      if (version == DTLSV1DOT0_VERSION)
        {
          col_set_str(pinfo->cinfo, COL_PROTOCOL,
                      val_to_str_const(SSL_VER_DTLS, ssl_version_short_names, "SSL"));
        }
      else
        {
          col_set_str(pinfo->cinfo, COL_PROTOCOL,"DTLS");
        }
    }

  /*
   * now dissect the next layer
   */
  ssl_debug_printf("dissect_dtls_record: content_type %d\n",content_type);

  /* PAOLO try to decrypt each record (we must keep ciphers "in sync")
   * store plain text only for app data */

  switch (content_type) {
  case SSL_ID_CHG_CIPHER_SPEC:
    col_append_str(pinfo->cinfo, COL_INFO, "Change Cipher Spec");
    dissect_dtls_change_cipher_spec(tvb, dtls_record_tree,
                                    offset, conv_version, content_type);
    break;
  case SSL_ID_ALERT:
    {
      tvbuff_t* decrypted;
      decrypted = 0;
      if (ssl&&decrypt_dtls_record(tvb, pinfo, offset,
                                   record_length, content_type, ssl, FALSE))
        ssl_add_record_info(proto_dtls, pinfo, dtls_decrypted_data.data,
                            dtls_decrypted_data_avail, offset);

      /* try to retrive and use decrypted alert record, if any. */
      decrypted = ssl_get_record_info(proto_dtls, pinfo, offset);
      if (decrypted)
        dissect_dtls_alert(decrypted, pinfo, dtls_record_tree, 0,
                           conv_version);
      else
        dissect_dtls_alert(tvb, pinfo, dtls_record_tree, offset,
                           conv_version);
      break;
    }
  case SSL_ID_HANDSHAKE:
    {
      tvbuff_t* decrypted;
      decrypted = 0;
      /* try to decrypt handshake record, if possible. Store decrypted
       * record for later usage. The offset is used as 'key' to itentify
       * this record into the packet (we can have multiple handshake records
       * in the same frame) */
      if (ssl && decrypt_dtls_record(tvb, pinfo, offset,
                                     record_length, content_type, ssl, FALSE))
        ssl_add_record_info(proto_dtls, pinfo, dtls_decrypted_data.data,
                            dtls_decrypted_data_avail, offset);

      /* try to retrive and use decrypted handshake record, if any. */
      decrypted = ssl_get_record_info(proto_dtls, pinfo, offset);
      if (decrypted)
        dissect_dtls_handshake(decrypted, pinfo, dtls_record_tree, 0,
                               decrypted->length, conv_version, ssl, content_type);
      else
        dissect_dtls_handshake(tvb, pinfo, dtls_record_tree, offset,
                               record_length, conv_version, ssl, content_type);
      break;
    }
  case SSL_ID_APP_DATA:
    if (ssl)
      decrypt_dtls_record(tvb, pinfo, offset,
                          record_length, content_type, ssl, TRUE);

    /* show on info colum what we are decoding */
    col_append_str(pinfo->cinfo, COL_INFO, "Application Data");

    if (!dtls_record_tree)
      break;

    /* we need dissector information when the selected packet is shown.
     * ssl session pointer is NULL at that time, so we can't access
     * info cached there*/
    association = ssl_association_find(dtls_associations, pinfo->srcport, pinfo->ptype == PT_TCP);
    association = association ? association: ssl_association_find(dtls_associations, pinfo->destport, pinfo->ptype == PT_TCP);

    proto_item_set_text(dtls_record_tree,
                        "%s Record Layer: %s Protocol: %s",
                        val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                        val_to_str(content_type, ssl_31_content_type, "unknown"),
                        association?association->info:"Application Data");

    proto_tree_add_item(dtls_record_tree, hf_dtls_record_appdata, tvb,
                        offset, record_length, 0);

    /* show decrypted data info, if available */
    appl_data = ssl_get_data_info(proto_dtls, pinfo, TVB_RAW_OFFSET(tvb)+offset);
    if (appl_data && (appl_data->plain_data.data_len > 0))
      {
        tvbuff_t *next_tvb;
        /* try to dissect decrypted data*/
        ssl_debug_printf("dissect_dtls_record decrypted len %d\n",
                         appl_data->plain_data.data_len);

        /* create a new TVB structure for desegmented data */
        next_tvb = tvb_new_child_real_data(tvb, appl_data->plain_data.data, appl_data->plain_data.data_len, appl_data->plain_data.data_len);

        add_new_data_source(pinfo, next_tvb, "Decrypted DTLS data");

        /* find out a dissector using server port*/
        if (association && association->handle) {
          ssl_debug_printf("dissect_dtls_record found association %p\n", (void *)association);
          ssl_print_text_data("decrypted app data",appl_data->plain_data.data, appl_data->plain_data.data_len);

          call_dissector(association->handle, next_tvb, pinfo, top_tree);
        }
      }
    break;

  default:
    /* shouldn't get here since we check above for valid types */
    col_append_str(pinfo->cinfo, COL_INFO, "Bad DTLS Content Type");
    break;
  }
  offset += record_length; /* skip to end of record */

  return offset;
}

/* dissects the change cipher spec procotol, filling in the tree */
static void
dissect_dtls_change_cipher_spec(tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint* conv_version, guint8 content_type)
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
                          val_to_str(content_type, ssl_31_content_type, "unknown"));
      proto_tree_add_item(tree, hf_dtls_change_cipher_spec, tvb,
                          offset++, 1, FALSE);
    }
}

/* dissects the alert message, filling in the tree */
static void
dissect_dtls_alert(tvbuff_t *tvb, packet_info *pinfo,
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
      ti = proto_tree_add_item(tree, hf_dtls_alert_message, tvb,
                               offset, 2, 0);
      ssl_alert_tree = proto_item_add_subtree(ti, ett_dtls_alert);
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
      if (check_col(pinfo->cinfo, COL_INFO))
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
          proto_tree_add_item(ssl_alert_tree, hf_dtls_alert_message_level,
                              tvb, offset++, 1, FALSE);

          proto_tree_add_item(ssl_alert_tree, hf_dtls_alert_message_description,
                              tvb, offset++, 1, FALSE);
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
dissect_dtls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 record_length, guint *conv_version,
                       SslDecryptSession* ssl, guint8 content_type)
{
  /*     struct {
   *         HandshakeType msg_type;
   *         uint24 length;
   *         uint16 message_seq;          //new field
   *         uint24 fragment_offset;       //new field
   *         uint24 fragment_length;        //new field
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
  proto_tree *ti;
  proto_tree *ssl_hand_tree;
  const gchar *msg_type_str;
  guint8 msg_type;
  guint32 length;
  guint16 message_seq;
  guint32 fragment_offset;
  guint32 fragment_length;
  gboolean first_iteration;
  ti               = NULL;
  ssl_hand_tree    = NULL;
  msg_type_str     = NULL;
  first_iteration  = TRUE;

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
      fragment_data *frag_msg = NULL;
      tvbuff_t *new_tvb = NULL;
      const gchar *frag_str = NULL;
      gboolean fragmented;

      msg_type = tvb_get_guint8(tvb, offset);
      msg_type_str = match_strval(msg_type, ssl_31_handshake_type);
      length   = tvb_get_ntoh24(tvb, offset + 1);
      message_seq = tvb_get_ntohs(tvb,offset + 4);
      fragment_offset = tvb_get_ntoh24(tvb, offset + 6);
      fragment_length = tvb_get_ntoh24(tvb, offset + 9);
      fragmented = fragment_length != length;

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
      if (check_col(pinfo->cinfo, COL_INFO))
        col_append_str(pinfo->cinfo, COL_INFO, (msg_type_str != NULL)
                        ? msg_type_str : "Encrypted Handshake Message");

      /* Handle fragments of known message type */
      if (fragmented)
        {
          gboolean frag_hand;

          switch (msg_type) {
          case SSL_HND_HELLO_REQUEST:
          case SSL_HND_CLIENT_HELLO:
          case SSL_HND_HELLO_VERIFY_REQUEST:
          case SSL_HND_SERVER_HELLO:
          case SSL_HND_CERTIFICATE:
          case SSL_HND_SERVER_KEY_EXCHG:
          case SSL_HND_CERT_REQUEST:
          case SSL_HND_SVR_HELLO_DONE:
          case SSL_HND_CERT_VERIFY:
          case SSL_HND_CLIENT_KEY_EXCHG:
          case SSL_HND_FINISHED:
            frag_hand = TRUE;
            break;
          default:
            /* Ignore encrypted handshake messages */
            frag_hand = FALSE;
            break;
          }

          if (frag_hand) {
            /* Fragmented handshake message */
            pinfo->fragmented = TRUE;

	    /* Don't pass the reassembly code data that doesn't exist */
	    tvb_ensure_bytes_exist(tvb, fragment_offset, fragment_length);

            frag_msg = fragment_add(tvb, offset+12, pinfo, message_seq,
                                    dtls_fragment_table,
                                    fragment_offset, fragment_length, TRUE);
            fragment_set_tot_len(pinfo, message_seq, dtls_fragment_table,
                                 length);

            if (frag_msg && (fragment_length + fragment_offset) == length)
              {
                /* Reassembled */
                new_tvb = process_reassembled_data(tvb, offset+12, pinfo,
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

            if (check_col(pinfo->cinfo, COL_INFO))
              col_append_str(pinfo->cinfo, COL_INFO, frag_str);
          }
        }

      if (tree)
        {
          /* set the label text on the record layer expanding node */
          if (first_iteration)
            {
              proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s%s",
                                  val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                                  val_to_str(content_type, ssl_31_content_type, "unknown"),
                                  (msg_type_str!=NULL) ? msg_type_str :
                                  "Encrypted Handshake Message",
                                  (frag_str!=NULL) ? frag_str : "");
            }
          else
            {
              proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s%s",
                                  val_to_str_const(*conv_version, ssl_version_short_names, "SSL"),
                                  val_to_str(content_type, ssl_31_content_type, "unknown"),
                                  "Multiple Handshake Messages",
                                  (frag_str!=NULL) ? frag_str : "");
            }

          /* add a subtree for the handshake protocol */
          ti = proto_tree_add_item(tree, hf_dtls_handshake_protocol, tvb,
                                   offset, fragment_length + 12, 0);
          ssl_hand_tree = proto_item_add_subtree(ti, ett_dtls_handshake);

          if (ssl_hand_tree)
            {
              /* set the text label on the subtree node */
              proto_item_set_text(ssl_hand_tree, "Handshake Protocol: %s%s",
                                  (msg_type_str != NULL) ? msg_type_str :
                                  "Encrypted Handshake Message",
                                  (frag_str!=NULL) ? frag_str : "");
            }
        }

      /* if we don't have a valid handshake type, just quit dissecting */
      if (!msg_type_str)
        return;

      /* if we are doing ssl decryption we must dissect some requests type */
      if (ssl_hand_tree || ssl)
        {
          tvbuff_t *sub_tvb = NULL;

          /* add nodes for the message type and message length */
          if (ssl_hand_tree)
            proto_tree_add_item(ssl_hand_tree, hf_dtls_handshake_type,
                                tvb, offset, 1, msg_type);
          offset++;
          if (ssl_hand_tree)
            proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_length,
                                tvb, offset, 3, length);
          offset += 3;

          if (ssl_hand_tree)
            proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_message_seq,
                                tvb, offset, 2, message_seq);
          offset += 2;
          if (ssl_hand_tree)
            proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_fragment_offset,
                                tvb, offset, 3, fragment_offset);
          offset += 3;
          if (ssl_hand_tree)
            proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_fragment_length,
                                tvb, offset, 3, fragment_length);
          offset += 3;

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
              sub_tvb = tvb_new_subset(tvb, offset, fragment_length,
                                        fragment_length);
            }

          /* now dissect the handshake message, if necessary */
          switch (msg_type) {
          case SSL_HND_HELLO_REQUEST:
            /* hello_request has no fields, so nothing to do! */
            break;

          case SSL_HND_CLIENT_HELLO:
            dissect_dtls_hnd_cli_hello(sub_tvb, ssl_hand_tree, 0, length, ssl);
            break;

          case SSL_HND_HELLO_VERIFY_REQUEST:
            dissect_dtls_hnd_hello_verify_request(sub_tvb, ssl_hand_tree, 0,  ssl);
            break;

          case SSL_HND_SERVER_HELLO:
            dissect_dtls_hnd_srv_hello(sub_tvb, ssl_hand_tree, 0, length, ssl);
            break;

          case SSL_HND_CERTIFICATE:
            dissect_dtls_hnd_cert(sub_tvb, ssl_hand_tree, 0, pinfo);
            break;

          case SSL_HND_SERVER_KEY_EXCHG:
            /* unimplemented */
            break;

          case SSL_HND_CERT_REQUEST:
            dissect_dtls_hnd_cert_req(sub_tvb, ssl_hand_tree, 0);
            break;

          case SSL_HND_SVR_HELLO_DONE:
            /* server_hello_done has no fields, so nothing to do! */
            break;

          case SSL_HND_CERT_VERIFY:
            /* unimplemented */
            break;

          case SSL_HND_CLIENT_KEY_EXCHG:
            {
              /* here we can have all the data to build session key */
              StringInfo encrypted_pre_master;
              gint ret;
              guint encrlen = length, skip;
              skip = 0;

              if (!ssl)
                break;

              /* check for required session data */
              ssl_debug_printf("dissect_dtls_handshake found SSL_HND_CLIENT_KEY_EXCHG, state %X\n",
                               ssl->state);
              if ((ssl->state & (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) !=
                  (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) {
                ssl_debug_printf("dissect_dtls_handshake not enough data to generate key (required state %X)\n",
                                 (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION));
                break;
              }

              encrypted_pre_master.data = se_alloc(encrlen);
              encrypted_pre_master.data_len = encrlen;
              tvb_memcpy(tvb, encrypted_pre_master.data, offset+skip, encrlen);

              if (!ssl->private_key) {
                ssl_debug_printf("dissect_dtls_handshake can't find private key\n");
                break;
              }

              /* go with ssl key processessing; encrypted_pre_master
               * will be used for master secret store*/
              ret = ssl_decrypt_pre_master_secret(ssl, &encrypted_pre_master, ssl->private_key);
              if (ret < 0) {
                ssl_debug_printf("dissect_dtls_handshake can't decrypt pre master secret\n");
                break;
              }
              if (ssl_generate_keyring_material(ssl)<0) {
                ssl_debug_printf("dissect_dtls_handshake can't generate keyring material\n");
                break;
              }
              ssl->state |= SSL_HAVE_SESSION_KEY;
              ssl_save_session(ssl, dtls_session_hash);
              ssl_debug_printf("dissect_dtls_handshake session keys successfully generated\n");
            }
            break;

          case SSL_HND_FINISHED:
            dissect_dtls_hnd_finished(sub_tvb, ssl_hand_tree,
                                      0, conv_version);
            break;
          }

        }
      else{
        offset += 12;        /* skip the handshake header when handshake is not processed*/
      }
    }
}

static gint
dissect_dtls_hnd_hello_common(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, SslDecryptSession* ssl, gint from_server)
{
  /* show the client's random challenge */
  nstime_t gmt_unix_time;
  guint8  session_id_length;
  session_id_length = 0;
  if (ssl)
    {
      /* get proper peer information*/
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
      ssl_debug_printf("dissect_dtls_hnd_hello_common found random state %X\n",
                       ssl->state);

      session_id_length = tvb_get_guint8(tvb, offset + 32);
      /* check stored session id info */
      if (from_server && (session_id_length == ssl->session_id.data_len) &&
          (tvb_memeql(tvb, offset+33, ssl->session_id.data, session_id_length) == 0))
        {
          /* clinet/server id match: try to restore a previous cached session*/
          ssl_restore_session(ssl, dtls_session_hash);
        }
      else {
        tvb_memcpy(tvb,ssl->session_id.data, offset+33, session_id_length);
        ssl->session_id.data_len = session_id_length;
      }
    }

  if (tree)
    {
      /* show the time */
      gmt_unix_time.secs = tvb_get_ntohl(tvb, offset);
      gmt_unix_time.nsecs = 0;
      proto_tree_add_time(tree, hf_dtls_handshake_random_time,
                          tvb, offset, 4, &gmt_unix_time);
      offset += 4;

      /* show the random bytes */
      proto_tree_add_item(tree, hf_dtls_handshake_random_bytes,
                          tvb, offset, 28, 0);
      offset += 28;

      /* show the session id */
      session_id_length = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_dtls_handshake_session_id_len,
                          tvb, offset++, 1, 0);
      if (session_id_length > 0)
        {
          proto_tree_add_bytes_format(tree, hf_dtls_handshake_session_id,
                                      tvb, offset, session_id_length,
                                      NULL, "Session ID (%u byte%s)",
                                      session_id_length,
                                      plurality(session_id_length, "", "s"));
          offset += session_id_length;
        }

    }

  /* XXXX */
  return session_id_length+33;
}

static gint
dissect_dtls_hnd_hello_ext(tvbuff_t *tvb,
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
  proto_tree_add_uint(tree, hf_dtls_handshake_extensions_len,
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
      ext_tree = proto_item_add_subtree(pi, ett_dtls_extension);
      if (!ext_tree)
        ext_tree = tree;

      proto_tree_add_uint(ext_tree, hf_dtls_handshake_extension_type,
                          tvb, offset, 2, ext_type);
      offset += 2;

      proto_tree_add_uint(ext_tree, hf_dtls_handshake_extension_len,
                          tvb, offset, 2, ext_len);
      offset += 2;

      proto_tree_add_bytes_format(ext_tree, hf_dtls_handshake_extension_data,
                                  tvb, offset, ext_len, NULL,
                                  "Data (%u byte%s)", ext_len,
				  plurality(ext_len, "", "s"));
      offset += ext_len;
      left -= 2 + 2 + ext_len;
    }

  return offset;
}

static void
dissect_dtls_hnd_cli_hello(tvbuff_t *tvb,
                           proto_tree *tree, guint32 offset, guint32 length,
                           SslDecryptSession*ssl)
{
  /* struct {
   *     ProtocolVersion client_version;
   *     Random random;
   *     SessionID session_id;
   *     opaque cookie<0..32>;                   //new field
   *     CipherSuite cipher_suites<2..2^16-1>;
   *     CompressionMethod compression_methods<1..2^8-1>;
   *     Extension client_hello_extension_list<0..2^16-1>;
   * } ClientHello;
   *
   */
  proto_tree *ti;
  proto_tree *cs_tree;
  guint16 cipher_suite_length;
  guint8  compression_methods_length;
  guint8  compression_method;
  guint16 start_offset = offset;
  guint8 cookie_length;
  cipher_suite_length = 0;
  compression_methods_length = 0;
  cookie_length = 0;

  if (tree || ssl)
    {
      /* show the client version */
      if (tree)
        proto_tree_add_item(tree, hf_dtls_handshake_client_version, tvb,
                            offset, 2, FALSE);
      offset += 2;

      /* show the fields in common with server hello */
      offset += dissect_dtls_hnd_hello_common(tvb, tree, offset, ssl, 0);

      /* look for a cookie */
      cookie_length = tvb_get_guint8(tvb, offset);
      if (!tree)
        return;

      proto_tree_add_uint(tree, hf_dtls_handshake_cookie_len,
                          tvb, offset, 1, cookie_length);
      offset ++;            /* skip opaque length */

      if (cookie_length > 0)
        {
          proto_tree_add_bytes_format(tree, hf_dtls_handshake_cookie,
                                      tvb, offset, cookie_length,
                                      NULL, "Cookie (%u byte%s)",
                                      cookie_length,
                                      plurality(cookie_length, "", "s"));
          offset += cookie_length;
        }

      /* tell the user how many cipher suites there are */
      cipher_suite_length = tvb_get_ntohs(tvb, offset);

      proto_tree_add_uint(tree, hf_dtls_handshake_cipher_suites_len,
                          tvb, offset, 2, cipher_suite_length);
      offset += 2;            /* skip opaque length */

      if (cipher_suite_length > 0)
        {
          tvb_ensure_bytes_exist(tvb, offset, cipher_suite_length);
          ti = proto_tree_add_none_format(tree,
                                          hf_dtls_handshake_cipher_suites,
                                          tvb, offset, cipher_suite_length,
                                          "Cipher Suites (%u suite%s)",
                                          cipher_suite_length / 2,
                                          plurality(cipher_suite_length/2, "", "s"));

          /* make this a subtree */
          cs_tree = proto_item_add_subtree(ti, ett_dtls_cipher_suites);
          if (!cs_tree)
            {
              cs_tree = tree; /* failsafe */
            }

          while (cipher_suite_length > 0)
            {
              proto_tree_add_item(cs_tree, hf_dtls_handshake_cipher_suite,
                                  tvb, offset, 2, FALSE);
              offset += 2;
              cipher_suite_length -= 2;
            }
        }

      /* tell the user how man compression methods there are */
      compression_methods_length = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(tree, hf_dtls_handshake_comp_methods_len,
                          tvb, offset, 1, compression_methods_length);
      offset++;

      if (compression_methods_length > 0)
        {
          tvb_ensure_bytes_exist(tvb, offset, compression_methods_length);
          ti = proto_tree_add_none_format(tree,
                                          hf_dtls_handshake_comp_methods,
                                          tvb, offset, compression_methods_length,
                                          "Compression Methods (%u method%s)",
                                          compression_methods_length,
                                          plurality(compression_methods_length,
                                                    "", "s"));

          /* make this a subtree */
          cs_tree = proto_item_add_subtree(ti, ett_dtls_comp_methods);
          if (!cs_tree)
            {
              cs_tree = tree; /* failsafe */
            }

          while (compression_methods_length > 0)
            {
              compression_method = tvb_get_guint8(tvb, offset);
              if (compression_method < 64)
                proto_tree_add_uint(cs_tree, hf_dtls_handshake_comp_method,
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
          offset = dissect_dtls_hnd_hello_ext(tvb, tree, offset,
                                              length -
                                              (offset - start_offset));
        }
    }
}


static void
dissect_dtls_hnd_hello_verify_request(tvbuff_t *tvb, proto_tree *tree,
				      guint32 offset, SslDecryptSession* ssl)
{
  /*
   * struct {
   *    ProtocolVersion server_version;
   *    opaque cookie<0..32>;
   * } HelloVerifyRequest;
   */

  guint8 cookie_length;
  cookie_length = 0;

  if (tree || ssl)
    {
      /* show the client version */
      if (tree)
        proto_tree_add_item(tree, hf_dtls_handshake_server_version, tvb,
                            offset, 2, FALSE);
      offset += 2;


      /* look for a cookie */
      cookie_length = tvb_get_guint8(tvb, offset);
      if (!tree)
        return;

      proto_tree_add_uint(tree, hf_dtls_handshake_cookie_len,
                          tvb, offset, 1, cookie_length);
      offset ++;            /* skip opaque length */

      if (cookie_length > 0)
        {
          proto_tree_add_bytes_format(tree, hf_dtls_handshake_cookie,
                                      tvb, offset, cookie_length,
                                      NULL, "Cookie (%u byte%s)",
                                      cookie_length,
                                      plurality(cookie_length, "", "s"));
          offset += cookie_length;
        }
    }

}

static void
dissect_dtls_hnd_srv_hello(tvbuff_t *tvb,
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
        proto_tree_add_item(tree, hf_dtls_handshake_server_version, tvb,
                            offset, 2, FALSE);
      offset += 2;

      /* first display the elements conveniently in
       * common with client hello
       */
      offset += dissect_dtls_hnd_hello_common(tvb, tree, offset, ssl, 1);

      /* PAOLO: handle session cipher suite  */
      if (ssl) {
        /* store selected cipher suite for decryption */
        ssl->cipher = tvb_get_ntohs(tvb, offset);
        if (ssl_find_cipher(ssl->cipher,&ssl->cipher_suite) < 0) {
          ssl_debug_printf("dissect_dtls_hnd_srv_hello can't find cipher suite %X\n", ssl->cipher);
          goto no_cipher;
        }

        ssl->state |= SSL_CIPHER;
        ssl_debug_printf("dissect_dtls_hnd_srv_hello found cipher %X, state %X\n",
                         ssl->cipher, ssl->state);

        /* if we have restored a session now we can have enought material
         * to build session key, check it out*/
        if ((ssl->state &
             (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION|SSL_MASTER_SECRET)) !=
            (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION|SSL_MASTER_SECRET)) {
          ssl_debug_printf("dissect_dtls_hnd_srv_hello not enough data to generate key (required state %X)\n",
                           (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION|SSL_MASTER_SECRET));
          goto no_cipher;
        }

        ssl_debug_printf("dissect_dtls_hnd_srv_hello trying to generate keys\n");
        if (ssl_generate_keyring_material(ssl)<0) {
          ssl_debug_printf("dissect_dtls_hnd_srv_hello can't generate keyring material\n");
          goto no_cipher;
        }
        ssl->state |= SSL_HAVE_SESSION_KEY;
      }
    no_cipher:
      if (!tree)
        return;

      /* now the server-selected cipher suite */
      proto_tree_add_item(tree, hf_dtls_handshake_cipher_suite,
                          tvb, offset, 2, FALSE);
      offset += 2;

      /* and the server-selected compression method */
      proto_tree_add_item(tree, hf_dtls_handshake_comp_method,
                          tvb, offset, 1, FALSE);
      offset++;

      if (length > offset - start_offset)
        {
          offset = dissect_dtls_hnd_hello_ext(tvb, tree, offset,
                                              length -
                                              (offset - start_offset));
        }
    }
}

static void
dissect_dtls_hnd_cert(tvbuff_t *tvb,
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
      proto_tree_add_uint(tree, hf_dtls_handshake_certificates_len,
                          tvb, offset, 3, certificate_list_length);
      offset += 3;            /* 24-bit length value */

      if (certificate_list_length > 0)
        {
          tvb_ensure_bytes_exist(tvb, offset, certificate_list_length);
          ti = proto_tree_add_none_format(tree,
                                          hf_dtls_handshake_certificates,
                                          tvb, offset, certificate_list_length,
                                          "Certificates (%u byte%s)",
                                          certificate_list_length,
                                          plurality(certificate_list_length,
                                                    "", "s"));

          /* make it a subtree */
          subtree = proto_item_add_subtree(ti, ett_dtls_certs);
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

              proto_tree_add_item(subtree, hf_dtls_handshake_certificate_len,
                                  tvb, offset, 3, FALSE);
              offset += 3;

              dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, subtree, hf_dtls_handshake_certificate);
              offset += cert_length;
            }
        }

    }
}

static void
dissect_dtls_hnd_cert_req(tvbuff_t *tvb,
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
  guint8      cert_types_count;
  gint         dnames_length;
  cert_types_count = 0;
  dnames_length = 0;

  if (tree)
    {
      cert_types_count = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(tree, hf_dtls_handshake_cert_types_count,
                          tvb, offset, 1, cert_types_count);
      offset++;

      if (cert_types_count > 0)
        {
          ti = proto_tree_add_none_format(tree,
                                          hf_dtls_handshake_cert_types,
                                          tvb, offset, cert_types_count,
                                          "Certificate types (%u type%s)",
                                          cert_types_count,
                                          plurality(cert_types_count, "", "s"));
          subtree = proto_item_add_subtree(ti, ett_dtls_cert_types);
          if (!subtree)
            {
              subtree = tree;
            }

          while (cert_types_count > 0)
            {
              proto_tree_add_item(subtree, hf_dtls_handshake_cert_type,
                                  tvb, offset, 1, FALSE);
              offset++;
              cert_types_count--;
            }
        }

      dnames_length = tvb_get_ntohs(tvb, offset);
      proto_tree_add_uint(tree, hf_dtls_handshake_dnames_len,
                          tvb, offset, 2, dnames_length);
      offset += 2;

      if (dnames_length > 0)
        {
          tvb_ensure_bytes_exist(tvb, offset, dnames_length);
          ti = proto_tree_add_none_format(tree,
                                          hf_dtls_handshake_dnames,
                                          tvb, offset, dnames_length,
                                          "Distinguished Names (%d byte%s)",
                                          dnames_length,
                                          plurality(dnames_length, "", "s"));
          subtree = proto_item_add_subtree(ti, ett_dtls_dnames);
          if (!subtree)
            {
              subtree = tree;
            }

          while (dnames_length > 0)
            {
              /* get the length of the current certificate */
              guint16 name_length = tvb_get_ntohs(tvb, offset);
              dnames_length -= 2 + name_length;

              proto_tree_add_item(subtree, hf_dtls_handshake_dname_len,
                                  tvb, offset, 2, FALSE);
              offset += 2;

              proto_tree_add_bytes_format(subtree,
                                          hf_dtls_handshake_dname,
                                          tvb, offset, name_length, NULL,
                                          "Distinguished Name (%u byte%s)",
                                          name_length,
                                          plurality(name_length, "", "s"));
              offset += name_length;
            }
        }
    }

}

static void
dissect_dtls_hnd_finished(tvbuff_t *tvb, proto_tree *tree, guint32 offset,
                          guint* conv_version)
{
  /*
   *     struct {
   *         opaque verify_data[12];
   *     } Finished;
   */

  /* this all needs a tree, so bail if we don't have one */
  if (!tree)
    {
      return;
    }

  switch(*conv_version) {
  case SSL_VER_DTLS:
    proto_tree_add_item(tree, hf_dtls_handshake_finished,
                        tvb, offset, 12, FALSE);
    break;
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

  if (conversation_get_proto_data(conversation, proto_dtls) != NULL)
    {
      /* get rid of the current data */
      conversation_delete_proto_data(conversation, proto_dtls);
    }
  conversation_add_proto_data(conversation, proto_dtls, GINT_TO_POINTER(version));
}
#endif

static gint
dtls_is_valid_handshake_type(guint8 type)
{

  switch (type) {
  case SSL_HND_HELLO_REQUEST:
  case SSL_HND_CLIENT_HELLO:
  case SSL_HND_SERVER_HELLO:
  case SSL_HND_HELLO_VERIFY_REQUEST:
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
dtls_is_authoritative_version_message(guint8 content_type, guint8 next_byte)
{
  if (content_type == SSL_ID_HANDSHAKE
      && dtls_is_valid_handshake_type(next_byte))
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
  if (version != DTLSV1DOT0_VERSION && version != DTLSV1DOT0_VERSION_NOT)
    {
      return 0;
    }

  return 1;
}

/* UAT */

#ifdef HAVE_LIBGNUTLS
static void
dtlsdecrypt_free_cb(void* r)
{
	ssldecrypt_assoc_t* h = r;

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

#ifdef HAVE_LIBGNUTLS
static void *
dtlsdecrypt_copy_cb(void* dest, const void* orig, size_t len _U_)
{
	const ssldecrypt_assoc_t* o = orig;
	ssldecrypt_assoc_t* d = dest;

	d->ipaddr    = g_strdup(o->ipaddr);
	d->port		 = g_strdup(o->port);
	d->protocol  = g_strdup(o->protocol);
	d->keyfile   = g_strdup(o->keyfile);
	d->password  = g_strdup(o->password);

	return d;
}

UAT_CSTRING_CB_DEF(sslkeylist_uats,ipaddr,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,port,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,protocol,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,keyfile,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,password,ssldecrypt_assoc_t)
#endif

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
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
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
    { &hf_dtls_change_cipher_spec,
      { "Change Cipher Spec Message", "dtls.change_cipher_spec",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Signals a change in cipher specifications", HFILL }
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
    { &hf_dtls_handshake_client_version,
      { "Version", "dtls.handshake.version",
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
        "Maximum version supported by client", HFILL }
    },
    { &hf_dtls_handshake_server_version,
      { "Version", "dtls.handshake.version",
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
        "Version selected by server", HFILL }
    },
    { &hf_dtls_handshake_random_time,
      { "Random.gmt_unix_time", "dtls.handshake.random_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "Unix time field of random structure", HFILL }
    },
    { &hf_dtls_handshake_random_bytes,
      { "Random.bytes", "dtls.handshake.random",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Random challenge used to authenticate server", HFILL }
    },
    { &hf_dtls_handshake_cipher_suites_len,
      { "Cipher Suites Length", "dtls.handshake.cipher_suites_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of cipher suites field", HFILL }
    },
    { &hf_dtls_handshake_cipher_suites,
      { "Cipher Suites", "dtls.handshake.ciphersuites",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of cipher suites supported by client", HFILL }
    },
    { &hf_dtls_handshake_cipher_suite,
      { "Cipher Suite", "dtls.handshake.ciphersuite",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ssl_31_ciphersuite_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_handshake_cookie_len,
      { "Cookie Length", "dtls.handshake.cookie_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of the cookie field", HFILL }
    },
    { &hf_dtls_handshake_cookie,
      { "Cookie", "dtls.handshake.cookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_handshake_session_id,
      { "Session ID", "dtls.handshake.session_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Identifies the DTLS session, allowing later resumption", HFILL }
    },
    { &hf_dtls_handshake_comp_methods_len,
      { "Compression Methods Length", "dtls.handshake.comp_methods_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of compression methods field", HFILL }
    },
    { &hf_dtls_handshake_comp_methods,
      { "Compression Methods", "dtls.handshake.comp_methods",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of compression methods supported by client", HFILL }
    },
    { &hf_dtls_handshake_comp_method,
      { "Compression Method", "dtls.handshake.comp_method",
        FT_UINT8, BASE_DEC, VALS(ssl_31_compression_method), 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_handshake_extensions_len,
      { "Extensions Length", "dtls.handshake.extensions_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of hello extensions", HFILL }
    },
    { &hf_dtls_handshake_extension_type,
      { "Type", "dtls.handshake.extension.type",
        FT_UINT16, BASE_HEX, VALS(tls_hello_extension_types), 0x0,
        "Hello extension type", HFILL }
    },
    { &hf_dtls_handshake_extension_len,
      { "Length", "dtls.handshake.extension.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of a hello extension", HFILL }
    },
    { &hf_dtls_handshake_extension_data,
      { "Data", "dtls.handshake.extension.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Hello Extension data", HFILL }
    },
    { &hf_dtls_handshake_certificates_len,
      { "Certificates Length", "dtls.handshake.certificates_length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Length of certificates field", HFILL }
    },
    { &hf_dtls_handshake_certificates,
      { "Certificates", "dtls.handshake.certificates",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of certificates", HFILL }
    },
    { &hf_dtls_handshake_certificate,
      { "Certificate", "dtls.handshake.certificate",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_handshake_certificate_len,
      { "Certificate Length", "dtls.handshake.certificate_length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Length of certificate", HFILL }
    },
    { &hf_dtls_handshake_cert_types_count,
      { "Certificate types count", "dtls.handshake.cert_types_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Count of certificate types", HFILL }
    },
    { &hf_dtls_handshake_cert_types,
      { "Certificate types", "dtls.handshake.cert_types",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of certificate types", HFILL }
    },
    { &hf_dtls_handshake_cert_type,
      { "Certificate type", "dtls.handshake.cert_type",
        FT_UINT8, BASE_DEC, VALS(ssl_31_client_certificate_type), 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_handshake_finished,
      { "Verify Data", "dtls.handshake.verify_data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Opaque verification data", HFILL }
    },
    { &hf_dtls_handshake_md5_hash,
      { "MD5 Hash", "dtls.handshake.md5_hash",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Hash of messages, master_secret, etc.", HFILL }
    },
    { &hf_dtls_handshake_sha_hash,
      { "SHA-1 Hash", "dtls.handshake.sha_hash",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Hash of messages, master_secret, etc.", HFILL }
    },
    { &hf_dtls_handshake_session_id_len,
      { "Session ID Length", "dtls.handshake.session_id_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of session ID field", HFILL }
    },
    { &hf_dtls_handshake_dnames_len,
      { "Distinguished Names Length", "dtls.handshake.dnames_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of list of CAs that server trusts", HFILL }
    },
    { &hf_dtls_handshake_dnames,
      { "Distinguished Names", "dtls.handshake.dnames",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of CAs that server trusts", HFILL }
    },
    { &hf_dtls_handshake_dname_len,
      { "Distinguished Name Length", "dtls.handshake.dname_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of distinguished name", HFILL }
    },
    { &hf_dtls_handshake_dname,
      { "Distinguished Name", "dtls.handshake.dname",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Distinguished name of a CA that server trusts", HFILL }
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
      { "Message fragment count", "dtls.fragment.error",
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
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_dtls,
    &ett_dtls_record,
    &ett_dtls_alert,
    &ett_dtls_handshake,
    &ett_dtls_cipher_suites,
    &ett_dtls_comp_methods,
    &ett_dtls_extension,
    &ett_dtls_certs,
    &ett_dtls_cert_types,
    &ett_dtls_dnames,
    &ett_dtls_fragment,
    &ett_dtls_fragments,
  };

  /* Register the protocol name and description */
  proto_dtls = proto_register_protocol("Datagram Transport Layer Security",
                                       "DTLS", "dtls");

  /* Required function calls to register the header fields and
   * subtrees used */
  proto_register_field_array(proto_dtls, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

#ifdef HAVE_LIBGNUTLS
  {
    module_t *dtls_module = prefs_register_protocol(proto_dtls, dtls_parse);

	static uat_field_t dtlskeylist_uats_flds[] = {
		UAT_FLD_CSTRING_OTHER(sslkeylist_uats, ipaddr, "IP address", ssldecrypt_uat_fld_ip_chk_cb, "IPv4 or IPv6 address"),
		UAT_FLD_CSTRING_OTHER(sslkeylist_uats, port, "Port", ssldecrypt_uat_fld_port_chk_cb, "Port Number"),
		UAT_FLD_CSTRING_OTHER(sslkeylist_uats, protocol, "Protocol", ssldecrypt_uat_fld_protocol_chk_cb, "Protocol"),
		UAT_FLD_CSTRING_OTHER(sslkeylist_uats, keyfile, "Key File", ssldecrypt_uat_fld_fileopen_chk_cb, "Path to the keyfile."),
		UAT_FLD_CSTRING_OTHER(sslkeylist_uats, password," Password (p12 file)", ssldecrypt_uat_fld_password_chk_cb, "Password"),
		UAT_END_FIELDS
	};

	dtlsdecrypt_uat = uat_new("DTLS RSA Keylist",
		sizeof(ssldecrypt_assoc_t),
		"dtlsdecrypttablefile",         /* filename */
		TRUE,                     		/* from_profile */
		(void*) &dtlskeylist_uats,      /* data_ptr */
		&ndtlsdecrypt,                  /* numitems_ptr */
		UAT_CAT_FFMT,             		/* category */
		"ChK12ProtocolsSection",  		/* TODO, need revision - help */
		dtlsdecrypt_copy_cb,
		NULL, /* dtlsdecrypt_update_cb? */
		dtlsdecrypt_free_cb,
		NULL,
		dtlskeylist_uats_flds);

	prefs_register_uat_preference(dtls_module, "cfg",
		"RSA keys list",
		"A table of RSA keys for DTLS decryption",
		dtlsdecrypt_uat);

	prefs_register_string_preference(dtls_module, "debug_file", "DTLS debug file",
                                     "redirect dtls debug to file name; leave empty to disable debug, "
                                     "use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr\n",
                                     (const gchar **)&dtls_debug_file_name);

        prefs_register_string_preference(dtls_module, "keys_list", "RSA keys list (deprecated)",
             "Semicolon-separated list of private RSA keys used for DTLS decryption. "
             "Used by versions of Wireshark prior to 1.6",
             (const gchar **)&dtls_keys_list);

  }
#endif

  register_dissector("dtls", dissect_dtls, proto_dtls);
  dtls_handle = find_dissector("dtls");

  dtls_associations = g_tree_new(ssl_association_cmp);

  register_init_routine(dtls_init);
  ssl_lib_init();
  dtls_tap = register_tap("dtls");
  ssl_debug_printf("proto_register_dtls: registered tap %s:%d\n",
                   "dtls", dtls_tap);
}

/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_dtls(void)
{

  /* add now dissector to default ports.*/
  dtls_parse();
}
