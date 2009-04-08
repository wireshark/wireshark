/* packet-scriptingservice.c
 * Routines for the Scripting Service Protocol, a load distribution application
 * of the rsplib RSerPool implementation
 * http://tdrwww.iem.uni-due.de/dreibholz/rserpool/
 *
 * Copyright 2008 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>


#define SSPROTOCOL_PAYLOAD_PROTOCOL_ID 0x29097604


/* Initialize the protocol and registered fields */
static int proto_ssprotocol  = -1;
static int hf_message_type   = -1;
static int hf_message_flags  = -1;
static int hf_message_length = -1;
static int hf_message_status = -1;
static int hf_message_data   = -1;

/* Initialize the subtree pointers */
static gint ett_ssprotocol   = -1;

static void
dissect_ssprotocol_message(tvbuff_t *, packet_info *, proto_tree *);


/* Dissectors for messages. This is specific to ScriptingServiceProtocol */
#define MESSAGE_TYPE_LENGTH       1
#define MESSAGE_FLAGS_LENGTH      1
#define MESSAGE_LENGTH_LENGTH     2
#define MESSAGE_STATUS_LENGTH     4

#define MESSAGE_TYPE_OFFSET       0
#define MESSAGE_FLAGS_OFFSET      (MESSAGE_TYPE_OFFSET    + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET     (MESSAGE_FLAGS_OFFSET   + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_STATUS_OFFSET     (MESSAGE_LENGTH_OFFSET  + MESSAGE_LENGTH_LENGTH)
#define MESSAGE_DATA_OFFSET       (MESSAGE_LENGTH_OFFSET  + MESSAGE_LENGTH_LENGTH)


#define SS_READY_TYPE          1
#define SS_UPLOAD_TYPE         2
#define SS_DOWNLOAD_TYPE       3
#define SS_KEEPALIVE_TYPE      4
#define SS_KAEEPALIVE_ACK_TYPE 5
#define SS_STATUS_TYPE         6


static const value_string message_type_values[] = {
  { SS_READY_TYPE,          "Ready" },
  { SS_UPLOAD_TYPE,         "Upload" },
  { SS_DOWNLOAD_TYPE,       "Download" },
  { SS_KEEPALIVE_TYPE,      "Keep-Alive" },
  { SS_KAEEPALIVE_ACK_TYPE, "Keep-Alive Ack" },
  { SS_STATUS_TYPE,         "Status" },
  { 0, NULL }
};


static void
dissect_ssprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *ssprotocol_tree)
{
  guint8  type;
  guint16 data_length;

  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  if (pinfo && (check_col(pinfo->cinfo, COL_INFO))) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown SSP type"));
  }
  proto_tree_add_item(ssprotocol_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   FALSE);
  proto_tree_add_item(ssprotocol_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  FALSE);
  proto_tree_add_item(ssprotocol_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, FALSE);
  switch (type) {
    case SS_KAEEPALIVE_ACK_TYPE:
    case SS_STATUS_TYPE:
      proto_tree_add_item(ssprotocol_tree, hf_message_status, message_tvb, MESSAGE_STATUS_OFFSET, MESSAGE_STATUS_LENGTH, FALSE);
     break;
    case SS_UPLOAD_TYPE:
    case SS_DOWNLOAD_TYPE:
      data_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - 4;
      if (data_length > 0) {
        proto_tree_add_item(ssprotocol_tree, hf_message_data, message_tvb, MESSAGE_DATA_OFFSET, data_length, FALSE);
      }
     break;
  }
}


static int
dissect_ssprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ssprotocol_item;
  proto_tree *ssprotocol_tree;

  /* pinfo is NULL only if dissect_ssprotocol_message is called from dissect_error cause */
  if (pinfo && (check_col(pinfo->cinfo, COL_PROTOCOL)))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSP");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the ssprotocol protocol tree */
    ssprotocol_item = proto_tree_add_item(tree, proto_ssprotocol, message_tvb, 0, -1, FALSE);
    ssprotocol_tree = proto_item_add_subtree(ssprotocol_item, ett_ssprotocol);
  } else {
    ssprotocol_tree = NULL;
  };
  /* dissect the message */
  dissect_ssprotocol_message(message_tvb, pinfo, ssprotocol_tree);
  return(TRUE);
}


/* Register the protocol */
void
proto_register_ssprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,      { "Type",       "ssprotocol.message_type",   FT_UINT8,  BASE_DEC, VALS(message_type_values), 0x0, "", HFILL } },
    { &hf_message_flags,     { "Flags",      "ssprotocol.message_flags",  FT_UINT8,  BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_message_length,    { "Length",     "ssprotocol.message_length", FT_UINT16, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_message_status,    { "Status",     "ssprotocol.message_status", FT_UINT32, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_message_data,      { "Data",       "ssprotocol.message_data",   FT_BYTES,  BASE_HEX, NULL,                      0x0, "", HFILL } }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_ssprotocol
  };

  /* Register the protocol name and description */
  proto_ssprotocol = proto_register_protocol("Scripting Service Protocol", "SSP", "ssp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_ssprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ssprotocol(void)
{
  dissector_handle_t ssprotocol_handle;

  ssprotocol_handle = new_create_dissector_handle(dissect_ssprotocol, proto_ssprotocol);
  dissector_add("sctp.ppi", SSPROTOCOL_PAYLOAD_PROTOCOL_ID, ssprotocol_handle);
}
