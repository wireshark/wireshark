/* packet-scriptingservice.c
 * Routines for the Scripting Service Protocol, a load distribution application
 * of the rsplib RSerPool implementation
 * http://tdrwww.iem.uni-due.de/dreibholz/rserpool/
 *
 * Copyright 2008-2010 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
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
#include <epan/sctpppids.h>


#define SSPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY 0x29097604


/* Initialize the protocol and registered fields */
static int proto_ssprotocol     = -1;
static int hf_message_type      = -1;
static int hf_message_flags     = -1;
static int hf_message_length    = -1;
static int hf_message_status    = -1;
static int hf_message_data      = -1;
static int hf_message_reason    = -1;
static int hf_message_info      = -1;
static int hf_message_hash      = -1;
static int hf_environment_u_bit = -1;

/* Initialize the subtree pointers */
static gint ett_ssprotocol        = -1;
static gint ett_environment_flags = -1;

static guint
dissect_ssprotocol_message(tvbuff_t *, packet_info *, proto_tree *);


/* Dissectors for messages. This is specific to ScriptingServiceProtocol */
#define MESSAGE_TYPE_LENGTH          1
#define MESSAGE_FLAGS_LENGTH         1
#define MESSAGE_LENGTH_LENGTH        2
#define MESSAGE_STATUS_LENGTH        4
#define MESSAGE_NOTRDY_REASON_LENGTH 4
#define MESSAGE_ENVIRON_HASH_LENGTH  20

#define MESSAGE_TYPE_OFFSET          0
#define MESSAGE_FLAGS_OFFSET         (MESSAGE_TYPE_OFFSET   + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET        (MESSAGE_FLAGS_OFFSET  + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_STATUS_OFFSET        (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)
#define MESSAGE_DATA_OFFSET          (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)
#define MESSAGE_RDY_INFO_OFFSET      (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)
#define MESSAGE_NOTRDY_REASON_OFFSET (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)
#define MESSAGE_NOTRDY_INFO_OFFSET   (MESSAGE_NOTRDY_REASON_OFFSET + MESSAGE_NOTRDY_REASON_LENGTH)
#define MESSAGE_ENVIRON_HASH_OFFSET  (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH)


#define SS_NOTREADY_TYPE       0
#define SS_READY_TYPE          1
#define SS_UPLOAD_TYPE         2
#define SS_DOWNLOAD_TYPE       3
#define SS_KEEPALIVE_TYPE      4
#define SS_KEEPALIVE_ACK_TYPE  5
#define SS_STATUS_TYPE         6
#define SS_ENVIRONMENT_TYPE    7


static const value_string message_type_values[] = {
  { SS_NOTREADY_TYPE,       "Not Ready" },
  { SS_READY_TYPE,          "Ready" },
  { SS_UPLOAD_TYPE,         "Upload" },
  { SS_DOWNLOAD_TYPE,       "Download" },
  { SS_KEEPALIVE_TYPE,      "Keep-Alive" },
  { SS_KEEPALIVE_ACK_TYPE,  "Keep-Alive Ack" },
  { SS_STATUS_TYPE,         "Status" },
  { SS_ENVIRONMENT_TYPE,    "Environment" },
  { 0, NULL }
};


static const value_string notrdy_reason_values[] = {
  { 0x00000001, "Fully Loaded" },
  { 0x00000002, "Out of Resources" },
  { 0, NULL }
};


#define SSP_ENVIRONMENT_U_BIT 0x01
static const true_false_string environment_u_bit = {
  "Upload needed",
  "Upload not needed"
};


static guint
dissect_ssprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *ssprotocol_tree)
{
  proto_item* flags_item;
  proto_tree* flags_tree;
  guint8      type;
  guint16     data_length;
  guint16     info_length;
  guint       total_length;

  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  if (pinfo && (check_col(pinfo->cinfo, COL_INFO))) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown SSP type: %u"));
  }
  proto_tree_add_item(ssprotocol_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   FALSE);
  flags_item = proto_tree_add_item(ssprotocol_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  FALSE);
  proto_tree_add_item(ssprotocol_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, FALSE);
  total_length = MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH;
  switch (type) {
    case SS_KEEPALIVE_ACK_TYPE:
    case SS_STATUS_TYPE:
      info_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - MESSAGE_STATUS_OFFSET;
      if (info_length == MESSAGE_STATUS_LENGTH) {
        proto_tree_add_item(ssprotocol_tree, hf_message_status, message_tvb, MESSAGE_STATUS_OFFSET, MESSAGE_STATUS_LENGTH, FALSE);
        total_length += MESSAGE_STATUS_LENGTH;
      }
      break;
    case SS_UPLOAD_TYPE:
    case SS_DOWNLOAD_TYPE:
      data_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - MESSAGE_DATA_OFFSET;
      if (data_length > 0) {
        proto_tree_add_item(ssprotocol_tree, hf_message_data, message_tvb, MESSAGE_DATA_OFFSET, data_length, ENC_NA);
        total_length += data_length;
      }
      break;
    case SS_READY_TYPE:
      info_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - MESSAGE_RDY_INFO_OFFSET;
      if (info_length > 0) {
        proto_tree_add_item(ssprotocol_tree, hf_message_info, message_tvb, MESSAGE_RDY_INFO_OFFSET, info_length, FALSE);
        total_length += info_length;
      }
      break;
    case SS_NOTREADY_TYPE:
      info_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - MESSAGE_NOTRDY_INFO_OFFSET;
      if (info_length > 0) {
        proto_tree_add_item(ssprotocol_tree, hf_message_reason, message_tvb, MESSAGE_NOTRDY_REASON_OFFSET, MESSAGE_NOTRDY_REASON_LENGTH, FALSE);
        proto_tree_add_item(ssprotocol_tree, hf_message_info,   message_tvb, MESSAGE_NOTRDY_INFO_OFFSET, info_length, FALSE);
        total_length += info_length;
      }
      break;
    case SS_ENVIRONMENT_TYPE:
        flags_tree = proto_item_add_subtree(flags_item, ett_environment_flags);
        proto_tree_add_item(flags_tree, hf_environment_u_bit, message_tvb, MESSAGE_FLAGS_OFFSET, MESSAGE_FLAGS_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(ssprotocol_tree, hf_message_hash, message_tvb, MESSAGE_ENVIRON_HASH_OFFSET, MESSAGE_ENVIRON_HASH_LENGTH, ENC_NA);
      break;
    default:
      break;
  }

  return total_length;
}


static int
dissect_ssprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ssprotocol_item;
  proto_tree *ssprotocol_tree;

  /* pinfo is NULL only if dissect_ssprotocol_message is called from dissect_error cause */
  if (pinfo)
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
  return dissect_ssprotocol_message(message_tvb, pinfo, ssprotocol_tree);
}


/* Register the protocol */
void
proto_register_ssprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,      { "Type",   "ssprotocol.message_type",   FT_UINT8,  BASE_DEC,  VALS(message_type_values),  0x0, NULL, HFILL } },
    { &hf_message_flags,     { "Flags",  "ssprotocol.message_flags",  FT_UINT8,  BASE_DEC,  NULL,                       0x0, NULL, HFILL } },
    { &hf_message_length,    { "Length", "ssprotocol.message_length", FT_UINT16, BASE_DEC,  NULL,                       0x0, NULL, HFILL } },
    { &hf_message_status,    { "Status", "ssprotocol.message_status", FT_UINT32, BASE_DEC,  NULL,                       0x0, NULL, HFILL } },
    { &hf_message_reason,    { "Reason", "ssprotocol.message_reason", FT_UINT32, BASE_DEC,  VALS(notrdy_reason_values), 0x0, NULL, HFILL } },
    { &hf_message_info,      { "Info",   "ssprotocol.message_info",   FT_STRING, BASE_NONE, NULL,                       0x0, NULL, HFILL } },
    { &hf_message_data,      { "Data",   "ssprotocol.message_data",   FT_BYTES,  BASE_NONE, NULL,                       0x0, NULL, HFILL } },
    { &hf_message_hash,      { "Hash",   "ssprotocol.message_hash",   FT_BYTES,  BASE_NONE, NULL,                       0x0, NULL, HFILL } },
    { &hf_environment_u_bit, { "U-Bit",  "ssprotocol.environment_u_bit", FT_BOOLEAN, 8,TFS(&environment_u_bit), SSP_ENVIRONMENT_U_BIT, NULL, HFILL } }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_ssprotocol,
    &ett_environment_flags
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
  dissector_add_uint("sctp.ppi", SSPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY, ssprotocol_handle);
  dissector_add_uint("sctp.ppi", SSP_PAYLOAD_PROTOCOL_ID, ssprotocol_handle);
}
