/* packet-negoex.c
 * Dissect the NEGOEX security protocol
 * as described here: http://tools.ietf.org/id/draft-zhu-negoex-04.txt
 * Copyright 2012 Richard Sharpe <realrichardsharpe@gmail.com>
 * Routines for SPNEGO Extended Negotiation Security Mechanism
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include "packet-frame.h"
#include "packet-dcerpc.h"
#include "packet-gssapi.h"

static int proto_negoex = -1;
static int hf_negoex_sig = -1;
static int hf_negoex_message_type = -1;
static int hf_negoex_sequence_num = -1;
static int hf_negoex_header_len = -1;
static int hf_negoex_message_len = -1;
static int hf_negoex_conversation_id = -1;
static int hf_negoex_random = -1;
static int hf_negoex_proto_version = -1;
static int hf_negoex_authscheme = -1;
static int hf_negoex_authscheme_vector_offset = -1;
static int hf_negoex_authscheme_vector_count = -1;
static int hf_negoex_authscheme_vector_pad = -1;
static int hf_negoex_extension = -1;
static int hf_negoex_extension_vector_offset = -1;
static int hf_negoex_extension_vector_count = -1;
static int hf_negoex_extension_vector_pad = -1;
static int hf_negoex_exchange_vector_offset = -1;
static int hf_negoex_exchange_vector_count = -1;
static int hf_negoex_exchange_vector_pad = -1;
static int hf_negoex_exchange = -1;
static int hf_negoex_checksum_scheme = -1;
static int hf_negoex_checksum_type = -1;
static int hf_negoex_checksum_vector_offset = -1;
static int hf_negoex_checksum_vector_count = -1;
static int hf_negoex_checksum_vector_pad = -1;
static int hf_negoex_checksum = -1;
static int hf_negoex_errorcode = -1;

static gint ett_negoex = -1;
static gint ett_negoex_msg = -1;
static gint ett_negoex_hdr = -1;
static gint ett_negoex_authscheme_vector = -1;
static gint ett_negoex_extension_vector = -1;
static gint ett_negoex_exchange = -1;
static gint ett_negoex_checksum = -1;
static gint ett_negoex_checksum_vector = -1;
static gint ett_negoex_byte_vector = -1;

/* If you add more message types, add them in sequence and update MAX_MSG */
#define MESSAGE_TYPE_INITIATOR_NEGO      0
#define MESSAGE_TYPE_ACCEPTOR_NEGO       1
#define MESSAGE_TYPE_INITIATOR_META_DATA 2
#define MESSAGE_TYPE_ACCEPTOR_META_DATA  3
#define MESSAGE_TYPE_CHALLENGE           4
#define MESSAGE_TYPE_AP_REQUEST          5
#define MESSAGE_TYPE_VERIFY              6
#define MESSAGE_TYPE_ALERT               7
#define MESSAGE_TYPE_MAX_MSG             MESSAGE_TYPE_ALERT

static const value_string negoex_message_types[] = {
  {MESSAGE_TYPE_INITIATOR_NEGO,      "INITATOR_NEGO"},
  {MESSAGE_TYPE_ACCEPTOR_NEGO,       "ACCEPTOR_NEGO"},
  {MESSAGE_TYPE_INITIATOR_META_DATA, "INITIATOR_META_DATA"},
  {MESSAGE_TYPE_ACCEPTOR_META_DATA,  "ACCEPTOR_META_DATA"},
  {MESSAGE_TYPE_CHALLENGE,           "CHALLENGE"},
  {MESSAGE_TYPE_AP_REQUEST,          "AP_REQUEST"},
  {MESSAGE_TYPE_VERIFY,              "VERIFY"},
  {MESSAGE_TYPE_ALERT,               "ALERT"},
  {0, NULL}
};

static const value_string checksum_schemes[] = {
  {1, "rfc3961"},
  {0, NULL}
};

static const value_string alert_types[] = {
  {1, "ALERT_TYPE_PULSE"},
  {0, NULL}
};

static const value_string alert_reasons[] = {
  {1, "ALERT_VERIFY_NO_KEY"},
  {0, NULL}
};

static void
dissect_negoex_alert_message(tvbuff_t *tvb,
                             packet_info *pinfo _U_,
                             proto_tree *tree,
                             guint32 start_off)
{
  guint32 offset;

  offset = start_off;

  /* AuthScheme */
  proto_tree_add_item(tree, hf_negoex_authscheme, tvb, offset, 16, ENC_LITTLE_ENDIAN);
  offset += 16;

  /* ErrorCode, an NTSTATUS :-) */
  proto_tree_add_item(tree, hf_negoex_errorcode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* The rest */
  proto_tree_add_text(tree, tvb, offset, tvb_length(tvb) - offset,
                      "The rest of the alert message");

}

static void
dissect_negoex_verify_message(tvbuff_t *tvb,
                              packet_info *pinfo _U_,
                              proto_tree *tree,
                              guint32 start_off)
{
  guint32 offset;
  guint32 checksum_vector_offset;
  guint32 checksum_vector_count;
  proto_item *pi;
  proto_tree *checksum;
  proto_item *pi_chk;
  proto_tree *checksum_vector;

  offset = start_off;

  /* AuthScheme */
  proto_tree_add_item(tree, hf_negoex_authscheme, tvb, offset, 16, ENC_LITTLE_ENDIAN);
  offset += 16;

  /* Checksum */
  pi = proto_tree_add_text(tree, tvb, offset, 20, "Checksum");
  checksum = proto_item_add_subtree(pi, ett_negoex_checksum);

  /* cbHeaderLength */
  proto_tree_add_item(checksum, hf_negoex_header_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* ChecksumScheme */
  proto_tree_add_item(checksum, hf_negoex_checksum_scheme, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* ChecksumType */
  proto_tree_add_item(checksum, hf_negoex_checksum_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* Checksum Byte Vector */
  checksum_vector_offset = tvb_get_letohl(tvb, offset);
  checksum_vector_count = tvb_get_letohs(tvb, offset + 4);

  pi_chk = proto_tree_add_text(checksum, tvb, offset, 8,
                               "Checksum Vector: %u at %u",
                               checksum_vector_count,
                               checksum_vector_offset);
  checksum_vector = proto_item_add_subtree(pi_chk, ett_negoex_checksum_vector);

  proto_tree_add_item(checksum_vector, hf_negoex_checksum_vector_offset, tvb,
                      offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(checksum_vector, hf_negoex_checksum_vector_count, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(checksum_vector, hf_negoex_checksum_vector_pad, tvb,
                      offset, 2, ENC_NA);
  /*offset += 2;*/

  proto_tree_add_item(checksum_vector, hf_negoex_checksum, tvb,
                      checksum_vector_offset, checksum_vector_count, ENC_NA);

}

static void
dissect_negoex_exchange_message(tvbuff_t *tvb,
                                packet_info *pinfo _U_,
                                proto_tree *tree,
                                guint32 start_off)
{
  guint32 offset;
  guint32 exchange_vector_offset;
  guint32 exchange_vector_count;
  proto_item *pi;
  proto_tree *exchange_vector;

  offset = start_off;

  /* AuthScheme */
  proto_tree_add_item(tree, hf_negoex_authscheme, tvb, offset, 16, ENC_LITTLE_ENDIAN);
  offset += 16;

  /* Exchange Byte Vector */
  exchange_vector_offset = tvb_get_letohl(tvb, offset);
  exchange_vector_count = tvb_get_letohs(tvb, offset + 4);

  pi = proto_tree_add_text(tree, tvb, offset, 8, "Exchange: %u bytes at %u",
                           exchange_vector_count, exchange_vector_offset);
  exchange_vector = proto_item_add_subtree(pi, ett_negoex_exchange);

  proto_tree_add_item(exchange_vector, hf_negoex_exchange_vector_offset, tvb,
                      offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(exchange_vector, hf_negoex_exchange_vector_count, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(exchange_vector, hf_negoex_exchange_vector_pad, tvb,
                      offset, 2, ENC_NA);
  /*offset += 2;*/

  proto_tree_add_item(exchange_vector, hf_negoex_exchange, tvb,
                      exchange_vector_offset, exchange_vector_count, ENC_NA);
}

/*
 * In each of the subdissectors we are handed the whole message, but the
 * header is already dissected. The offset tells us where in the buffer the
 * actual data starts. This is a bit redundant, but it allows for changes
 * to the header structure ...
 *
 * Eventually we want to treat the header and body differently perhaps.
 */
static void
dissect_negoex_nego_message(tvbuff_t *tvb,
                            packet_info *pinfo _U_,
                            proto_tree *tree,
                            guint32 start_off)
{
  volatile guint32 offset;
  guint32 authscheme_vector_offset;
  guint16 authscheme_vector_count;
  guint32 extension_vector_offset;
  guint32 extension_vector_count;
  proto_item *pi, *ext_pi;
  proto_tree *authscheme_vector;
  proto_tree *extension_vector;
  guint32 i;

  offset = start_off;

  TRY {
    /* The Random field */
    proto_tree_add_item(tree, hf_negoex_random, tvb, offset, 32, ENC_ASCII);
    offset += 32;

    /* Protocol version */
    proto_tree_add_item(tree, hf_negoex_proto_version, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* AuthScheme offset and count */
    authscheme_vector_offset = tvb_get_letohl(tvb, offset);
    authscheme_vector_count = tvb_get_letohs(tvb, offset + 4);

    pi = proto_tree_add_text(tree, tvb, offset, 8, "AuthSchemes: %u at %u",
                             authscheme_vector_count, authscheme_vector_offset);
    authscheme_vector = proto_item_add_subtree(pi, ett_negoex_authscheme_vector);
    proto_tree_add_item(authscheme_vector, hf_negoex_authscheme_vector_offset,
                        tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(authscheme_vector, hf_negoex_authscheme_vector_count,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(authscheme_vector, hf_negoex_authscheme_vector_pad,
                        tvb, offset, 2, ENC_NA);
    offset += 2;

    /* Now, add the various items */
    for (i = 0; i < authscheme_vector_count; i++) {
      proto_tree_add_item(authscheme_vector, hf_negoex_authscheme, tvb,
                          authscheme_vector_offset + i * 16, 16, ENC_LITTLE_ENDIAN);
    }

    extension_vector_offset = tvb_get_letohl(tvb, offset);
    extension_vector_count = tvb_get_letohs(tvb, offset + 4);

    ext_pi = proto_tree_add_text(tree, tvb, offset, 8, "Extensions: %u at %u",
                                 extension_vector_count, extension_vector_count);
    extension_vector = proto_item_add_subtree(ext_pi, ett_negoex_extension_vector);

    proto_tree_add_item(extension_vector, hf_negoex_extension_vector_offset,
                        tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(extension_vector, hf_negoex_extension_vector_count,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(extension_vector, hf_negoex_extension_vector_pad,
                        tvb, offset, 2, ENC_NA);
    offset += 2;

    for (i = 0; i < extension_vector_count; i++) {
      guint32 byte_vector_offset, byte_vector_count;
      proto_item *bv_pi;
      proto_tree *bv_tree;

      /*
       * Dissect these things ... they consist of a byte vector, so we
       * add a subtree and point to the relevant bytes
       */
      byte_vector_offset = tvb_get_letohl(tvb, offset);
      byte_vector_count = tvb_get_letohs(tvb, offset + 4);

      bv_pi = proto_tree_add_text(extension_vector, tvb,
                                  extension_vector_offset + i * 8, 8,
                                  "Extension: %u bytes at %u",
                                  byte_vector_count, byte_vector_offset);
      bv_tree = proto_item_add_subtree(bv_pi, ett_negoex_byte_vector);

      proto_tree_add_item(bv_tree, hf_negoex_extension, tvb,
                          byte_vector_offset, byte_vector_count, ENC_NA);
    }


  } ENDTRY;

}

static void
dissect_negoex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  volatile guint32 offset;
  proto_tree * volatile negoex_tree;
  proto_item *tf;
  volatile gboolean done;
  guint32 payload_len;
  guint32 message_len;
  guint32 message_type;
  guint32 header_len;

  offset = 0;
  negoex_tree = NULL;
  tf = NULL;
  done = FALSE;
  payload_len = tvb_length(tvb);

  /* Set up the initial NEGOEX payload */
  if (tree) {
    tf = proto_tree_add_item(tree, proto_negoex, tvb, offset, -1, ENC_NA);
    negoex_tree = proto_item_add_subtree(tf, ett_negoex);
  }

  /*
   * There can be multiple negoex messages, each with a header with a length.
   * However, the payload might not have been reassembled ...
   */

  while (offset < payload_len && !done) {
    proto_tree *negoex_msg_tree;
    proto_tree *negoex_hdr_tree;
    proto_item *msg;
    proto_item *hdr;
    tvbuff_t *msg_tvb;
    guint32 start_offset;

    start_offset = offset;

    TRY {
     /* Message type, it is after the signature */
      message_type = tvb_get_letohl(tvb, offset + 8);

      /* Add the message type tree ... set its length below */
      msg = proto_tree_add_text(negoex_tree, tvb, offset, -1,
                                "NEGOEX %s",
                                val_to_str_const(message_type,
                                                 negoex_message_types,
                                                 "Unknown NEGOEX message type"));

      /* Add a subtree for the message */
      negoex_msg_tree = proto_item_add_subtree(msg, ett_negoex_msg);

      /* Add a subtree for the header */
      hdr = proto_tree_add_text(negoex_msg_tree, tvb, offset, 40, "Header");
      negoex_hdr_tree = proto_item_add_subtree(hdr, ett_negoex_hdr);

      /* Signature, NEGOEXTS */
      proto_tree_add_item(negoex_hdr_tree, hf_negoex_sig,
                          tvb, offset, 8, ENC_ASCII | ENC_NA);
      offset += 8;

      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s",
                          val_to_str_const(message_type,
                                           negoex_message_types,
                                           "Unknown NEGOEX message type"));
      proto_tree_add_uint(negoex_hdr_tree, hf_negoex_message_type,
                          tvb, offset, 4, message_type);

      /*
       * If this is an unknown message type, we have to punt because anything
       * following cannot be handled
       */
      if (message_type > MESSAGE_TYPE_MAX_MSG) {
        offset = payload_len; /* Can't do any more */
        goto bad_message;
      } else {
        offset += 4;
      }

      /* Sequence Number */
      proto_tree_add_item(negoex_hdr_tree, hf_negoex_sequence_num,
                          tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;

      /* Header Length */
      header_len = tvb_get_letohl(tvb, offset);
      proto_tree_add_uint(negoex_hdr_tree, hf_negoex_header_len,
                          tvb, offset, 4, header_len);
      offset += 4;

      /* Message Length */
      message_len = tvb_get_letohl(tvb, offset);
      proto_tree_add_uint(negoex_hdr_tree, hf_negoex_message_len,
                          tvb, offset, 4, message_len);
      offset += 4;

      /* Set the message len so the tree item has correct len */
      proto_item_set_len(msg, message_len);

      /* Conversation ID */
      proto_tree_add_item(negoex_hdr_tree, hf_negoex_conversation_id,
                          tvb, offset, 16, ENC_LITTLE_ENDIAN);
      offset += 16;

      /*
       * Construct a new TVB covering just this message and pass to the
       * sub-dissector
       */
      msg_tvb = tvb_new_subset(tvb,
                               start_offset,
                               MIN(message_len, tvb_length(tvb)),
                               message_len);

      switch (message_type) {
      case MESSAGE_TYPE_INITIATOR_NEGO:
      case MESSAGE_TYPE_ACCEPTOR_NEGO:
        dissect_negoex_nego_message(msg_tvb,
                                    pinfo,
                                    negoex_msg_tree,
                                    offset - start_offset);
        break;

      case MESSAGE_TYPE_INITIATOR_META_DATA:
      case MESSAGE_TYPE_ACCEPTOR_META_DATA:
      case MESSAGE_TYPE_CHALLENGE:
      case MESSAGE_TYPE_AP_REQUEST:
        dissect_negoex_exchange_message(msg_tvb,
                                        pinfo,
                                        negoex_msg_tree,
                                        offset - start_offset);
        break;

      case MESSAGE_TYPE_VERIFY:
        dissect_negoex_verify_message(msg_tvb,
                                      pinfo,
                                      negoex_msg_tree,
                                      offset - start_offset);
        break;

      case MESSAGE_TYPE_ALERT:
        dissect_negoex_alert_message(msg_tvb,
                                     pinfo,
                                     negoex_msg_tree,
                                     offset - start_offset);
        break;

      default:
        proto_tree_add_text(negoex_msg_tree, tvb, offset, message_len - 40,
                            "The rest of the message");
      }

      offset = start_offset + message_len;

      /* We cannot branch out of the TRY block, but we can branch here */
    bad_message:
        ;

    } CATCH(BoundsError) {
      RETHROW;
    } CATCH(ReportedBoundsError) {
      done = TRUE;
      show_reported_bounds_error(tvb, pinfo, tree);
    } ENDTRY;
  }

}

static void
negoex_init_protocol(void)
{
}

void
proto_register_negoex(void)
{

  static hf_register_info hf[] = {
    { &hf_negoex_sig,
      { "Signature", "negoex.message.sig", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_message_type,
      { "MessageType", "negoex.message.type", FT_UINT32, BASE_HEX,
         VALS(negoex_message_types), 0x00, NULL, HFILL }},
    { &hf_negoex_sequence_num,
      { "SequencNum", "negoex.message.seq_num", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_header_len,
      { "cbHeaderLength", "negoex.header.len", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_message_len,
      { "cbMessageLength", "negoex.message.len", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_conversation_id,
      { "ConversationID", "negoex.message.conv_id", FT_GUID, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_random,
      { "Random", "negoex.message.random", FT_BYTES, BASE_NONE,
        NULL, 0x0, "Random data", HFILL }},
    { &hf_negoex_proto_version,
      { "ProtocolVersion", "negoex.proto_version", FT_UINT64, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_authscheme,
      { "AuthScheme", "negoex.auth_scheme", FT_GUID, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_authscheme_vector_offset,
      { "AuthSchemeArrayOffset", "negoex.auth_scheme_array_offset", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_authscheme_vector_count,
      { "AuthSchemeCount", "negoex.auth_scheme_array_count", FT_UINT16,
        BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_authscheme_vector_pad,
      { "AuthSchemePad", "negoex.auth_scheme_array_pad", FT_BYTES,
        BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_extension,
      { "Extension", "negoex.extension", FT_BYTES, BASE_NONE,
        NULL, 0x0, "Extension data", HFILL }},
    { &hf_negoex_extension_vector_offset,
      { "ExtensionArrayOffset", "negoex.extension_array_offset", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_extension_vector_count,
      { "ExtensionCount", "negoex.extension_array_count", FT_UINT16,
        BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_extension_vector_pad,
      { "ExtensionPad", "negoex.extension_pad", FT_BYTES,
        BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_negoex_exchange_vector_offset,
      { "ExchangeOffset", "negoex.exchange_vec_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_exchange_vector_count,
      { "ExchangeByteCount", "negoex.exchange_vec_byte_count", FT_UINT16,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_exchange_vector_pad,
      { "ExchangePad", "negoex.exchange_vec_pad", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_exchange,
      { "Exchange Bytes", "negoex.exchange", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_checksum_scheme,
      { "ChecksumScheme", "negoex.checksum_scheme", FT_UINT32, BASE_DEC,
        VALS(checksum_schemes), 0x0, NULL, HFILL}},
    { &hf_negoex_checksum_vector_offset,
      { "ChecksumOffset", "negoex.checksum_vec_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_checksum_vector_count,
      { "ChecksumCount", "negoex.checksum_vec_count", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_checksum_vector_pad,
      { "ChecksumPad", "negoex.checksum_pad", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_checksum_type,
      { "ChecksumType", "negoex.checksum_type", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_checksum,
      { "Checksum", "negoex.checksum", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_negoex_errorcode,
      { "ErrorCode", "negoex.errorcode", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_negoex,
    &ett_negoex_msg,
    &ett_negoex_hdr,
    &ett_negoex_authscheme_vector,
    &ett_negoex_extension_vector,
    &ett_negoex_exchange,
    &ett_negoex_checksum,
    &ett_negoex_checksum_vector,
    &ett_negoex_byte_vector,
  };
  /*module_t *negoex_module = NULL; */

  proto_negoex = proto_register_protocol (
    "SPNEGO Extended Negotiation Security Mechanism", /* name */
    "NEGOEX",  /* short name */
    "negoex"   /* abbrev */
    );
  proto_register_field_array(proto_negoex, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&negoex_init_protocol);

  /* negoex_module = prefs_register_protocol(proto_negoex, NULL);*/

  register_dissector("negoex", dissect_negoex, proto_negoex);
}

void
proto_reg_handoff_negoex(void)
{
  dissector_handle_t negoex_handle;

  /* Register protocol with the GSS-API module */

  negoex_handle = find_dissector("negoex");
  gssapi_init_oid("1.3.6.1.4.1.311.2.2.30", proto_negoex, ett_negoex,
                  negoex_handle, NULL,
                  "NEGOEX - SPNEGO Extended Negotiation Security Mechanism");

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
