/* packet-componentstatus.c
 * Routines for the Component Status Protocol of the rsplib RSerPool implementation
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


#define CSP_VERSION 0x0200

#define CID_GROUP(id)  (((uint64_t) id >> 56) & (0xffffULL)
#define CID_OBJECT(id) (((uint64_t) id & 0xffffffffffffffULL)

#define CID_GROUP_REGISTRAR 0x0001
#define CID_GROUP_POOLELEMENT 0x0002
#define CID_GROUP_POOLUSER 0x0003

#define CID_COMPOUND(group, object) (((uint64_t) (group & 0xffff) << 56) | CID_OBJECT((uint64_t)object))

#define CSPT_REPORT


/* Initialize the protocol and registered fields */
static int proto_componentstatusprotocol             = -1;
static int hf_message_type                           = -1;
static int hf_message_flags                          = -1;
static int hf_message_length                         = -1;
static int hf_message_version                        = -1;
static int hf_message_senderid                       = -1;
static int hf_message_sendertimestamp                = -1;
static int hf_componentstatusreport_reportinterval   = -1;
static int hf_componentstatusreport_location         = -1;
static int hf_componentstatusreport_status           = -1;
static int hf_componentstatusreport_workload         = -1;
static int hf_componentstatusreport_associations     = -1;
static int hf_componentstatusreport_associationarray = -1;
static int hf_componentassociation_receiverid        = -1;
static int hf_componentassociation_duration          = -1;
static int hf_componentassociation_flags             = -1;
static int hf_componentassociation_protocolid        = -1;
static int hf_componentassociation_ppid              = -1;


/* Initialize the subtree pointers */
static gint ett_componentstatusprotocol = -1;
static gint ett_association             = -1;


static void
dissect_componentstatusprotocol_message(tvbuff_t *, packet_info *, proto_tree *);


#define COMPONENTSTATUSPROTOCOL_PORT    2960
#define COMPONENTSTATUSPROTOCOL_VERSION 0x0200


/* Dissectors for messages. This is specific to ComponentStatusProtocol */
#define MESSAGE_TYPE_LENGTH             1
#define MESSAGE_FLAGS_LENGTH            1
#define MESSAGE_LENGTH_LENGTH           2
#define MESSAGE_VERSION_LENGTH          4
#define MESSAGE_SENDERID_LENGTH         8
#define MESSAGE_SENDERTIMESTAMP_LENGTH  8


#define MESSAGE_TYPE_OFFSET             0
#define MESSAGE_FLAGS_OFFSET            (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET           (MESSAGE_FLAGS_OFFSET + MESSAGE_FLAGS_OFFSET)
#define MESSAGE_VERSION_OFFSET          (MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_OFFSET)
#define MESSAGE_SENDERID_OFFSET         (MESSAGE_VERSION_OFFSET + MESSAGE_VERSION_OFFSET)
#define MESSAGE_SENDERTIMESTAMP_OFFSET  (MESSAGE_SENDERID_OFFSET + MESSAGE_SENDERID_OFFSET)
#define MESSAGE_VALUE_OFFSET            (MESSAGE_SENDERTIMESTAMP_OFFSET + MESSAGE_SENDERTIMESTAMP_LENGTH)


#define COMPONENTSTATUSREPORT_REPORTINTERVAL_LENGTH 4
#define COMPONENTSTATUSREPORT_WORKLOAD_LENGTH  2
#define COMPONENTSTATUSREPORT_ASSOCIATIONS_LENGTH 2
#define COMPONENTSTATUSREPORT_LOCATION_LENGTH 128
#define COMPONENTSTATUSREPORT_STATUS_LENGTH 128


#define COMPONENTSTATUSREPORT_REPORTINTERVAL_OFFSET MESSAGE_VALUE_OFFSET
#define COMPONENTSTATUSREPORT_LOCATION_OFFSET (COMPONENTSTATUSREPORT_REPORTINTERVAL_OFFSET + COMPONENTSTATUSREPORT_REPORTINTERVAL_LENGTH)
#define COMPONENTSTATUSREPORT_STATUS_OFFSET (COMPONENTSTATUSREPORT_LOCATION_OFFSET + COMPONENTSTATUSREPORT_LOCATION_LENGTH)
#define COMPONENTSTATUSREPORT_WORKLOAD_OFFSET (COMPONENTSTATUSREPORT_STATUS_OFFSET + COMPONENTSTATUSREPORT_STATUS_LENGTH)
#define COMPONENTSTATUSREPORT_ASSOCIATIONS_OFFSET (COMPONENTSTATUSREPORT_WORKLOAD_OFFSET + COMPONENTSTATUSREPORT_WORKLOAD_LENGTH)
#define COMPONENTSTATUSREPORT_ASSOCIATIONARRAY_OFFSET (COMPONENTSTATUSREPORT_ASSOCIATIONS_OFFSET + COMPONENTSTATUSREPORT_ASSOCIATIONS_LENGTH)


#define COMPONENTASSOCIATION_RECEIVERID_LENGTH  8
#define COMPONENTASSOCIATION_DURATION_LENGTH    8
#define COMPONENTASSOCIATION_FLAGS_LENGTH       2
#define COMPONENTASSOCIATION_PROTOCOLID_LENGTH  2
#define COMPONENTASSOCIATION_PPID_LENGTH        4

#define COMPONENTASSOCIATION_RECEIVERID_OFFSET  0
#define COMPONENTASSOCIATION_DURATION_OFFSET (COMPONENTASSOCIATION_RECEIVERID_OFFSET + COMPONENTASSOCIATION_RECEIVERID_LENGTH)
#define COMPONENTASSOCIATION_FLAGS_OFFSET (COMPONENTASSOCIATION_DURATION_OFFSET + COMPONENTASSOCIATION_DURATION_LENGTH)
#define COMPONENTASSOCIATION_PROTOCOLID_OFFSET (COMPONENTASSOCIATION_FLAGS_OFFSET + COMPONENTASSOCIATION_FLAGS_LENGTH)
#define COMPONENTASSOCIATION_PPID_OFFSET (COMPONENTASSOCIATION_PROTOCOLID_OFFSET + COMPONENTASSOCIATION_PROTOCOLID_LENGTH)
#define COMPONENTASSOCIATION_LENGTH (COMPONENTASSOCIATION_PPID_OFFSET + COMPONENTASSOCIATION_PPID_LENGTH)


#define COMPONENTSTATUS_COMPONENTSTATUSREPORT_MESSAGE_TYPE       0x01




static const value_string message_type_values[] = {
  { COMPONENTSTATUS_COMPONENTSTATUSREPORT_MESSAGE_TYPE,             "ComponentStatus Report" },
  { 0, NULL }
};


static void
dissect_componentstatusprotocol_componentassociation_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  proto_tree_add_item(message_tree, hf_componentassociation_receiverid,  message_tvb, COMPONENTASSOCIATION_RECEIVERID_OFFSET,  COMPONENTASSOCIATION_RECEIVERID_LENGTH,  FALSE);
  proto_tree_add_item(message_tree, hf_componentassociation_duration, message_tvb, COMPONENTASSOCIATION_DURATION_OFFSET, COMPONENTASSOCIATION_DURATION_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentassociation_flags, message_tvb, COMPONENTASSOCIATION_FLAGS_OFFSET, COMPONENTASSOCIATION_FLAGS_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentassociation_protocolid, message_tvb, COMPONENTASSOCIATION_PROTOCOLID_OFFSET, COMPONENTASSOCIATION_PROTOCOLID_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentassociation_ppid, message_tvb, COMPONENTASSOCIATION_PPID_OFFSET, COMPONENTASSOCIATION_PPID_LENGTH, FALSE);
}


static void
dissect_componentstatusprotocol_componentstatusreport_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  tvbuff_t   *association_tvb;
  proto_item *association_item;
  proto_tree *association_tree;
  gint        associations;
  size_t      i;
  gint        offset;
  gint        remaining_length;
  char        title[64];

  proto_tree_add_item(message_tree, hf_componentstatusreport_reportinterval, message_tvb, COMPONENTSTATUSREPORT_REPORTINTERVAL_OFFSET, COMPONENTSTATUSREPORT_REPORTINTERVAL_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentstatusreport_location, message_tvb,  COMPONENTSTATUSREPORT_LOCATION_OFFSET, COMPONENTSTATUSREPORT_LOCATION_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentstatusreport_status, message_tvb,  COMPONENTSTATUSREPORT_STATUS_OFFSET, COMPONENTSTATUSREPORT_STATUS_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentstatusreport_workload, message_tvb,  COMPONENTSTATUSREPORT_WORKLOAD_OFFSET, COMPONENTSTATUSREPORT_WORKLOAD_LENGTH, FALSE);
  proto_tree_add_item(message_tree, hf_componentstatusreport_associations,  message_tvb, COMPONENTSTATUSREPORT_ASSOCIATIONS_OFFSET, COMPONENTSTATUSREPORT_ASSOCIATIONS_LENGTH, FALSE);

  associations = tvb_get_ntohs(message_tvb, COMPONENTSTATUSREPORT_ASSOCIATIONS_OFFSET);
  offset = COMPONENTSTATUSREPORT_ASSOCIATIONARRAY_OFFSET;
  i = 1;
  while((remaining_length = tvb_length_remaining(message_tvb, offset)) >= COMPONENTASSOCIATION_LENGTH) {
     snprintf((char*)&title, sizeof(title), "Association #%d", i++);
     association_item = proto_tree_add_text(message_tree, message_tvb, offset, COMPONENTASSOCIATION_LENGTH, title);
     association_tree = proto_item_add_subtree(association_item, ett_association);
     association_tvb  = tvb_new_subset(message_tvb, offset, COMPONENTASSOCIATION_LENGTH, COMPONENTASSOCIATION_LENGTH);

     dissect_componentstatusprotocol_componentassociation_message(association_tvb, association_tree);
     offset += COMPONENTASSOCIATION_LENGTH;
  }
}


static void
dissect_componentstatusprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *componentstatusprotocol_tree)
{
  guint8 type;

  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  if (pinfo && (check_col(pinfo->cinfo, COL_INFO))) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, message_type_values, "Unknown ComponentStatusProtocol type"));
  }
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_type,            message_tvb, MESSAGE_TYPE_OFFSET,     MESSAGE_TYPE_LENGTH,     FALSE);
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_flags,           message_tvb, MESSAGE_FLAGS_OFFSET,    MESSAGE_FLAGS_LENGTH,    FALSE);
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_length,          message_tvb, MESSAGE_LENGTH_OFFSET,   MESSAGE_LENGTH_LENGTH,   FALSE);
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_version,         message_tvb, MESSAGE_VERSION_OFFSET,  MESSAGE_VERSION_LENGTH,  FALSE);
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_senderid,        message_tvb, MESSAGE_SENDERID_OFFSET, MESSAGE_SENDERID_LENGTH, FALSE);
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_sendertimestamp, message_tvb, MESSAGE_SENDERTIMESTAMP_OFFSET, MESSAGE_SENDERTIMESTAMP_LENGTH, FALSE);
  switch (type) {
    case COMPONENTSTATUS_COMPONENTSTATUSREPORT_MESSAGE_TYPE:
      dissect_componentstatusprotocol_componentstatusreport_message(message_tvb, componentstatusprotocol_tree);
     break;
  }
}


static int
dissect_componentstatusprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *componentstatusprotocol_item;
  proto_tree *componentstatusprotocol_tree;
  gint8 type;
  gint32 version;

  /* Check, if this packet really contains a ComponentStatusProtocol message */
  type = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  if (type != COMPONENTSTATUS_COMPONENTSTATUSREPORT_MESSAGE_TYPE) {
    return(FALSE);
  }
  version = tvb_get_ntohl(message_tvb, MESSAGE_VERSION_OFFSET);
  if (version != COMPONENTSTATUSPROTOCOL_VERSION) {
    return(FALSE);
  }

  /* pinfo is NULL only if dissect_componentstatusprotocol_message is called from dissect_error cause */
  if (pinfo && (check_col(pinfo->cinfo, COL_PROTOCOL)))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ComponentStatusProtocol");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the componentstatusprotocol protocol tree */
    componentstatusprotocol_item = proto_tree_add_item(tree, proto_componentstatusprotocol, message_tvb, 0, -1, FALSE);
    componentstatusprotocol_tree = proto_item_add_subtree(componentstatusprotocol_item, ett_componentstatusprotocol);
  } else {
    componentstatusprotocol_tree = NULL;
  };
  /* dissect the message */
  dissect_componentstatusprotocol_message(message_tvb, pinfo, componentstatusprotocol_tree);
  return(TRUE);
}


/* Register the protocol with Wireshark */
void
proto_register_componentstatusprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,                           { "Type",             "componentstatusprotocol.message_type",                           FT_UINT8,  BASE_DEC, VALS(message_type_values), 0x0, "", HFILL } },
    { &hf_message_flags,                          { "Flags",            "componentstatusprotocol.message_flags",                          FT_UINT8,  BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_message_length,                         { "Length",           "componentstatusprotocol.message_length",                         FT_UINT16, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_message_version,                        { "Version",          "componentstatusprotocol.message_version",                        FT_UINT32, BASE_HEX, NULL,                      0x0, "", HFILL } },
    { &hf_message_senderid,                       { "SenderID",         "componentstatusprotocol.message_senderid",                       FT_UINT64, BASE_HEX, NULL,                      0x0, "", HFILL } },
    { &hf_message_sendertimestamp,                { "SenderTimeStamp",  "componentstatusprotocol.message_sendertimestamp",                FT_UINT64, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentstatusreport_reportinterval,   { "ReportInterval",   "componentstatusprotocol.componentstatusreport_reportinterval",   FT_UINT32, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentstatusreport_location,         { "Location",         "componentstatusprotocol.componentstatusreport_location",         FT_STRING, 0, NULL,                             0x0, "", HFILL } },
    { &hf_componentstatusreport_status,           { "Status",           "componentstatusprotocol.componentstatusreport_status",           FT_STRING, 0, NULL,                             0x0, "", HFILL } },
    { &hf_componentstatusreport_workload,         { "Workload",         "componentstatusprotocol.componentstatusreport_workload",         FT_UINT16, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentstatusreport_associations,     { "Associations",     "componentstatusprotocol.componentstatusreport_associations",     FT_UINT16, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentstatusreport_associationarray, { "AssociationArray", "componentstatusprotocol.componentstatusreport_AssociationArray", FT_UINT32, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentassociation_receiverid,        { "ReceiverID",       "componentstatusprotocol.componentassociation_receiverid",        FT_UINT64, BASE_HEX, NULL,                      0x0, "", HFILL } },
    { &hf_componentassociation_duration,          { "Duration",         "componentstatusprotocol.componentassociation_duration",          FT_UINT64, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentassociation_flags,             { "Flags",            "componentstatusprotocol.componentassociation_flags",             FT_UINT16, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentassociation_protocolid,        { "ProtocolID",       "componentstatusprotocol.componentassociation_protocolid",        FT_UINT16, BASE_DEC, NULL,                      0x0, "", HFILL } },
    { &hf_componentassociation_ppid,              { "PPID",             "componentstatusprotocol.componentassociation_ppid",              FT_UINT32, BASE_DEC, NULL,                      0x0, "", HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_componentstatusprotocol,
    &ett_association
  };

  /* Register the protocol name and description */
  proto_componentstatusprotocol = proto_register_protocol("Component Status Protocol", "ComponentStatusProtocol", "componentstatusprotocol");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_componentstatusprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_componentstatusprotocol(void)
{
  dissector_handle_t componentstatusprotocol_handle;

  componentstatusprotocol_handle = new_create_dissector_handle(dissect_componentstatusprotocol, proto_componentstatusprotocol);
  dissector_add("udp.port", COMPONENTSTATUSPROTOCOL_PORT, componentstatusprotocol_handle);
}
