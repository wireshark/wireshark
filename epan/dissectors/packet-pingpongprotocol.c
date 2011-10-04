/* packet-pingpongprotocol.c
 * Routines for the Ping Pong Protocol, a test application of the
 * rsplib RSerPool implementation
 * http://tdrwww.exp-math.uni-essen.de/dreibholz/rserpool/
 *
 * Copyright 2006 by Thomas Dreibholz <dreibh [AT] exp-math.uni-essen.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/sctpppids.h>


#define PINGPONGPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY 0x29097602


/* Initialize the protocol and registered fields */
static int proto_pingpongprotocol         = -1;
static int hf_message_type                = -1;
static int hf_message_flags               = -1;
static int hf_message_length              = -1;
static int hf_ping_messageno              = -1;
static int hf_ping_data                   = -1;
static int hf_pong_messageno              = -1;
static int hf_pong_replyno                = -1;
static int hf_pong_data                   = -1;


/* Initialize the subtree pointers */
static gint ett_pingpongprotocol = -1;

static void
dissect_pingpongprotocol_message(tvbuff_t *, packet_info *, proto_tree *);


/* Dissectors for messages. This is specific to PingPongProtocol */
#define MESSAGE_TYPE_LENGTH    1
#define MESSAGE_FLAGS_LENGTH   1
#define MESSAGE_LENGTH_LENGTH  2

#define MESSAGE_TYPE_OFFSET    0
#define MESSAGE_FLAGS_OFFSET   (MESSAGE_TYPE_OFFSET    + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_FLAGS_OFFSET   + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_VALUE_OFFSET   (MESSAGE_LENGTH_OFFSET  + MESSAGE_LENGTH_LENGTH)


#define PING_MESSAGENO_LENGTH 8

#define PING_MESSAGENO_OFFSET MESSAGE_VALUE_OFFSET
#define PING_DATA_OFFSET      (PING_MESSAGENO_OFFSET + PING_MESSAGENO_LENGTH)

#define PONG_MESSAGENO_LENGTH 8
#define PONG_REPLYNO_LENGTH   8

#define PONG_MESSAGENO_OFFSET  MESSAGE_VALUE_OFFSET
#define PONG_REPLYNO_OFFSET    (PONG_MESSAGENO_OFFSET + PONG_MESSAGENO_LENGTH)
#define PONG_DATA_OFFSET       (PONG_REPLYNO_OFFSET + PONG_REPLYNO_LENGTH)


#define PINGPONG_PING_MESSAGE_TYPE 0x01
#define PINGPONG_PONG_MESSAGE_TYPE 0x02



static const value_string message_type_values[] = {
  { PINGPONG_PONG_MESSAGE_TYPE, "PingPongProtocol Pong" },
  { PINGPONG_PING_MESSAGE_TYPE, "PingPongProtocol Ping" },
  { 0, NULL }
};


static void
dissect_pingpongprotocol_ping_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint16 ping_data_length;

  proto_tree_add_item(message_tree, hf_ping_messageno, message_tvb, PING_MESSAGENO_OFFSET, PING_MESSAGENO_LENGTH, FALSE);

  ping_data_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - PING_DATA_OFFSET;
  if (ping_data_length > 0)
    proto_tree_add_item(message_tree, hf_ping_data, message_tvb, PING_DATA_OFFSET, ping_data_length, ENC_NA);
}

static void
dissect_pingpongprotocol_pong_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint16 pong_data_length;

  proto_tree_add_item(message_tree, hf_pong_messageno, message_tvb, PONG_MESSAGENO_OFFSET, PONG_MESSAGENO_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_pong_replyno,   message_tvb, PONG_REPLYNO_OFFSET,   PONG_REPLYNO_LENGTH,   FALSE);

  pong_data_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - PONG_DATA_OFFSET;
  if (pong_data_length > 0) {
    proto_tree_add_item(message_tree, hf_pong_data, message_tvb, PONG_DATA_OFFSET, pong_data_length, ENC_NA);
  }
}


static void
dissect_pingpongprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *pingpongprotocol_tree)
{
  guint8 type;

  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  if (pinfo && (check_col(pinfo->cinfo, COL_INFO))) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown PingPongProtocol type"));
  }
  proto_tree_add_item(pingpongprotocol_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   FALSE);
  proto_tree_add_item(pingpongprotocol_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  FALSE);
  proto_tree_add_item(pingpongprotocol_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, FALSE);
  switch (type) {
    case PINGPONG_PING_MESSAGE_TYPE:
      dissect_pingpongprotocol_ping_message(message_tvb, pingpongprotocol_tree);
     break;
    case PINGPONG_PONG_MESSAGE_TYPE:
      dissect_pingpongprotocol_pong_message(message_tvb, pingpongprotocol_tree);
     break;
  }
}

static int
dissect_pingpongprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *pingpongprotocol_item;
  proto_tree *pingpongprotocol_tree;

  /* pinfo is NULL only if dissect_pingpongprotocol_message is called from dissect_error cause */
  if (pinfo)
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PingPongProtocol");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the pingpongprotocol protocol tree */
    pingpongprotocol_item = proto_tree_add_item(tree, proto_pingpongprotocol, message_tvb, 0, -1, FALSE);
    pingpongprotocol_tree = proto_item_add_subtree(pingpongprotocol_item, ett_pingpongprotocol);
  } else {
    pingpongprotocol_tree = NULL;
  };
  /* dissect the message */
  dissect_pingpongprotocol_message(message_tvb, pinfo, pingpongprotocol_tree);
  return(TRUE);
}

/* Register the protocol with Wireshark */
void
proto_register_pingpongprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,     { "Type",      "pingpongprotocol.message_type",   FT_UINT8,  BASE_DEC, VALS(message_type_values), 0x0, NULL, HFILL } },
    { &hf_message_flags,    { "Flags",     "pingpongprotocol.message_flags",  FT_UINT8,  BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_message_length,   { "Length",    "pingpongprotocol.message_length", FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_ping_messageno,   { "MessageNo", "pingpongprotocol.ping_messageno", FT_UINT64, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_ping_data,        { "Ping_Data", "pingpongprotocol.ping_data",      FT_BYTES,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
    { &hf_pong_messageno,   { "MessageNo", "pingpongprotocol.pong_messageno", FT_UINT64, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_pong_replyno,     { "ReplyNo",   "pingpongprotocol.pong_replyno",   FT_UINT64, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_pong_data,        { "Pong_Data", "pingpongprotocol.pong_data",      FT_BYTES,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_pingpongprotocol
  };

  /* Register the protocol name and description */
  proto_pingpongprotocol = proto_register_protocol("Ping Pong Protocol", "PingPongProtocol",  "pingpongprotocol");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_pingpongprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pingpongprotocol(void)
{
  dissector_handle_t pingpongprotocol_handle;

  pingpongprotocol_handle = new_create_dissector_handle(dissect_pingpongprotocol, proto_pingpongprotocol);
  dissector_add_uint("sctp.ppi", PINGPONGPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY, pingpongprotocol_handle);
  dissector_add_uint("sctp.ppi", PPP_PAYLOAD_PROTOCOL_ID, pingpongprotocol_handle);
}
