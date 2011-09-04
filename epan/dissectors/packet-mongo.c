/* packet-mongo.c
 * Routines for Mongo Wire Protocol dissection
 * Copyright 2010, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * See Mongo Wire Protocol Specification
 * http://www.mongodb.org/display/DOCS/Mongo+Wire+Protocol
 * See also BSON Specification
 * http://bsonspec.org/#/specification
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-tcp.h"

/* This is not IANA assigned nor registered */
#define TCP_PORT_MONGO 27017

#define OP_REPLY           1
#define OP_MSG          1000
#define OP_UPDATE       2001
#define OP_INSERT       2002
#define OP_RESERVED     2003
#define OP_QUERY        2004
#define OP_GET_MORE     2005
#define OP_DELETE       2006
#define OP_KILL_CURSORS 2007

/**************************************************************************/
/*                      OpCode                                            */
/**************************************************************************/
static const value_string opcode_vals[] = {
  { OP_REPLY,  "Reply" },
  { OP_MSG,  "Message" },
  { OP_UPDATE,  "Update document" },
  { OP_INSERT,  "Insert document" },
  { OP_RESERVED,"Reserved" },
  { OP_QUERY,  "Query" },
  { OP_GET_MORE,  "Get More" },
  { OP_DELETE,  "Delete document" },
  { OP_KILL_CURSORS,  "Kill Cursors" },
  { 0,  NULL }
};

void proto_reg_handoff_mongo(void);


static int proto_mongo = -1;
static int hf_mongo_message_length = -1;
static int hf_mongo_request_id = -1;
static int hf_mongo_response_to = -1;
static int hf_mongo_op_code = -1;
static int hf_mongo_fullcollectionname = -1;
static int hf_mongo_database_name = -1;
static int hf_mongo_collection_name = -1;
static int hf_mongo_reply_flags = -1;
static int hf_mongo_reply_flags_cursornotfound = -1;
static int hf_mongo_reply_flags_queryfailure = -1;
static int hf_mongo_reply_flags_sharedconfigstale = -1;
static int hf_mongo_reply_flags_awaitcapable = -1;
static int hf_mongo_cursor_id = -1;
static int hf_mongo_starting_from = -1;
static int hf_mongo_number_returned = -1;
static int hf_mongo_message = -1;
static int hf_mongo_zero = -1;
static int hf_mongo_update_flags = -1;
static int hf_mongo_update_flags_upsert = -1;
static int hf_mongo_update_flags_multiupdate = -1;
static int hf_mongo_selector = -1;
static int hf_mongo_update = -1;
static int hf_mongo_insert_flags = -1;
static int hf_mongo_insert_flags_continueonerror = -1;
static int hf_mongo_query_flags = -1;
static int hf_mongo_query_flags_tailablecursor = -1;
static int hf_mongo_query_flags_slaveok = -1;
static int hf_mongo_query_flags_oplogreplay = -1;
static int hf_mongo_query_flags_nocursortimeout = -1;
static int hf_mongo_query_flags_awaitdata = -1;
static int hf_mongo_query_flags_exhaust = -1;
static int hf_mongo_query_flags_partial = -1;
static int hf_mongo_number_to_skip = -1;
static int hf_mongo_number_to_return = -1;
static int hf_mongo_query = -1;
static int hf_mongo_return_field_selector = -1;
static int hf_mongo_documents = -1;
static int hf_mongo_document_length = -1;
static int hf_mongo_delete_flags = -1;
static int hf_mongo_delete_flags_singleremove = -1;
static int hf_mongo_number_of_cursor_ids = -1;
static int hf_mongo_unknown = -1;

static guint global_mongo_tcp_port = TCP_PORT_MONGO;

static gint ett_mongo = -1;
static gint ett_mongo_doc = -1;
static gint ett_mongo_fcn = -1;
static gint ett_mongo_flags = -1;

static int
dissect_fullcollectionname(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  gint32 fcn_length, dbn_length;
  proto_item *ti;
  proto_tree *fcn_tree;

  ti = proto_tree_add_item(tree, hf_mongo_fullcollectionname, tvb, offset, -1, ENC_NA);
  fcn_length = tvb_strsize(tvb, offset);

  /* If this doesn't find anything, we'll just throw an exception below */
  dbn_length = tvb_find_guint8(tvb, offset, fcn_length, '.') - offset;

  fcn_tree = proto_item_add_subtree(ti, ett_mongo_fcn);

  proto_tree_add_item(fcn_tree, hf_mongo_database_name, tvb, offset, dbn_length, ENC_NA);

  proto_tree_add_item(fcn_tree, hf_mongo_collection_name, tvb, offset + 1 + dbn_length, fcn_length - dbn_length - 2, ENC_NA);

  return fcn_length;
}

static int
dissect_bson_document(tvbuff_t *tvb, guint offset, proto_tree *tree, int hf_mongo_document)
{
  gint32 document_length;
  proto_item *ti;
  proto_tree *doc_tree;

  document_length = tvb_get_letohl(tvb, offset);
  /* TODO Implement BSON spec to correctly see BSON document type and not in Bytes format... */
  ti = proto_tree_add_item(tree, hf_mongo_document, tvb, offset+4, document_length-4, ENC_NA);
  doc_tree = proto_item_add_subtree(ti, ett_mongo_doc);

  proto_tree_add_item(doc_tree, hf_mongo_document_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  return document_length;
}
static int
dissect_mongo_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *flags_tree;
  gint i, number_returned;

  ti = proto_tree_add_item(tree, hf_mongo_reply_flags, tvb, offset, 4, ENC_NA);
  flags_tree = proto_item_add_subtree(ti, ett_mongo_flags);
  proto_tree_add_item(flags_tree, hf_mongo_reply_flags_cursornotfound, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_reply_flags_queryfailure, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_reply_flags_sharedconfigstale, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_reply_flags_awaitcapable, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_mongo_cursor_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  proto_tree_add_item(tree, hf_mongo_starting_from, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_mongo_number_returned, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  number_returned = tvb_get_letohl(tvb, offset);
  offset += 4;

  for (i=1; i <= number_returned; i++)
  {
    offset += dissect_bson_document(tvb, offset, tree, hf_mongo_documents);
  }
  return offset;
}
static int
dissect_mongo_msg(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

  proto_item *ti;

  ti = proto_tree_add_item(tree, hf_mongo_message, tvb, offset, -1, ENC_NA);
  offset += proto_item_get_len(ti);

  return offset;
}

static int
dissect_mongo_update(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *flags_tree;

  proto_tree_add_item(tree, hf_mongo_zero, tvb, offset, 4, ENC_NA);
  offset += 4;

  offset += dissect_fullcollectionname(tvb, offset, tree);

  ti = proto_tree_add_item(tree, hf_mongo_update_flags, tvb, offset, 4, ENC_NA);
  flags_tree = proto_item_add_subtree(ti, ett_mongo_flags);
  proto_tree_add_item(flags_tree, hf_mongo_update_flags_upsert, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_update_flags_multiupdate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  offset += dissect_bson_document(tvb, offset, tree, hf_mongo_selector);

  offset += dissect_bson_document(tvb, offset, tree, hf_mongo_update);

  return offset;
}

static int
dissect_mongo_insert(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *flags_tree;

  ti = proto_tree_add_item(tree, hf_mongo_insert_flags, tvb, offset, 4, ENC_NA);
  flags_tree = proto_item_add_subtree(ti, ett_mongo_flags);
  proto_tree_add_item(flags_tree, hf_mongo_insert_flags_continueonerror, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  offset += dissect_fullcollectionname(tvb, offset, tree);

  while(offset < tvb_reported_length(tvb)) {
    offset += dissect_bson_document(tvb, offset, tree, hf_mongo_documents);
  }

  return offset;
}

static int
dissect_mongo_query(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *flags_tree;

  ti = proto_tree_add_item(tree, hf_mongo_query_flags, tvb, offset, 4, ENC_NA);
  flags_tree = proto_item_add_subtree(ti, ett_mongo_flags);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_tailablecursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_slaveok, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_oplogreplay, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_nocursortimeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_awaitdata, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_exhaust, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(flags_tree, hf_mongo_query_flags_partial, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  offset += dissect_fullcollectionname(tvb, offset, tree);

  proto_tree_add_item(tree, hf_mongo_number_to_skip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_mongo_number_to_return, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset +=4;

  offset += dissect_bson_document(tvb, offset, tree, hf_mongo_query);

  while(offset < tvb_reported_length(tvb)) {
    offset += dissect_bson_document(tvb, offset, tree, hf_mongo_return_field_selector);
  }
  return offset;
}

static int
dissect_mongo_getmore(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

  proto_tree_add_item(tree, hf_mongo_zero, tvb, offset, 4, ENC_NA);
  offset += 4;

  offset += dissect_fullcollectionname(tvb, offset, tree);

  proto_tree_add_item(tree, hf_mongo_number_to_return, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_mongo_cursor_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

static int
dissect_mongo_delete(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *flags_tree;

  proto_tree_add_item(tree, hf_mongo_zero, tvb, offset, 4, ENC_NA);
  offset += 4;

  offset += dissect_fullcollectionname(tvb, offset, tree);

  ti = proto_tree_add_item(tree, hf_mongo_delete_flags, tvb, offset, 4, ENC_NA);
  flags_tree = proto_item_add_subtree(ti, ett_mongo_flags);
  proto_tree_add_item(flags_tree, hf_mongo_delete_flags_singleremove, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  offset += dissect_bson_document(tvb, offset, tree, hf_mongo_selector);

  return offset;
}

static int
dissect_mongo_kill_cursors(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

  proto_tree_add_item(tree, hf_mongo_zero, tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_mongo_number_of_cursor_ids, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  while(offset < tvb_reported_length(tvb)) {
    proto_tree_add_item(tree, hf_mongo_cursor_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset +=8;
  }
  return offset;
}
static void
dissect_mongo_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  proto_item *ti;
  proto_tree *mongo_tree;
  guint offset = 0, opcode;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MONGO");

  if (tree) {

    ti = proto_tree_add_item(tree, proto_mongo, tvb, 0, -1, ENC_NA);

    mongo_tree = proto_item_add_subtree(ti, ett_mongo);

    proto_tree_add_item(mongo_tree, hf_mongo_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(mongo_tree, hf_mongo_request_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(mongo_tree, hf_mongo_response_to, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(mongo_tree, hf_mongo_op_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    opcode = tvb_get_letohl(tvb, offset);
    offset += 4;

    if(opcode == 1)
    {
      col_set_str(pinfo->cinfo, COL_INFO, "Response :");
    }
    else
    {
      col_set_str(pinfo->cinfo, COL_INFO, "Request :");

    }
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(opcode, opcode_vals, "Unknown"));

    switch(opcode){
    case OP_REPLY:
      offset = dissect_mongo_reply(tvb, offset, mongo_tree);
    break;
    case OP_MSG:
      offset = dissect_mongo_msg(tvb, offset, mongo_tree);
    break;
    case OP_UPDATE:
      offset = dissect_mongo_update(tvb, offset, mongo_tree);
    break;
    case OP_INSERT:
      offset = dissect_mongo_insert(tvb, offset, mongo_tree);
    break;
    case OP_QUERY:
      offset = dissect_mongo_query(tvb, offset, mongo_tree);
    break;
    case OP_GET_MORE:
      offset = dissect_mongo_getmore(tvb, offset, mongo_tree);
    break;
    case OP_DELETE:
      offset = dissect_mongo_delete(tvb, offset, mongo_tree);
    break;
    case OP_KILL_CURSORS:
      offset = dissect_mongo_kill_cursors(tvb, offset, mongo_tree);
    break;
    default:
      /* No default Action */
    break;
    }
    if(offset < tvb_reported_length(tvb))
    {
      ti = proto_tree_add_item(mongo_tree, hf_mongo_unknown, tvb, offset, -1, ENC_NA);
      expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, " Unknown Data (not interpreted)");
    }
  }

}
static guint
get_mongo_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 plen;

  /*
  * Get the length of the MONGO packet.
  */
  plen = tvb_get_letohl(tvb, offset);

  return plen;
}

static void
dissect_mongo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, 1, 4, get_mongo_pdu_len, dissect_mongo_pdu);
}

void
proto_register_mongo(void)
{
  module_t *mongo_module;

  static hf_register_info hf[] = {
    { &hf_mongo_message_length,
      { "Message Length", "mongo.message_length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Total message size (include this)", HFILL }
    },
    { &hf_mongo_request_id,
      { "Request ID", "mongo.request_id",
      FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
      "Identifier for this message", HFILL }
    },
    { &hf_mongo_response_to,
      { "Response To", "mongo.response_to",
      FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
      "RequestID from the original request", HFILL }
    },
    { &hf_mongo_op_code,
      { "OpCode", "mongo.opcode",
      FT_INT32, BASE_DEC, VALS(opcode_vals), 0x0,
      "Type of request message", HFILL }
    },
    { &hf_mongo_query_flags,
      { "Query Flags", "mongo.query.flags",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Bit vector of query options.", HFILL }
    },
    { &hf_mongo_fullcollectionname,
      { "fullCollectionName", "mongo.full_collection_name",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "The full collection name is the concatenation of the database name with the collection name, using a dot for the concatenation", HFILL }
    },
    { &hf_mongo_database_name,
      { "Database Name", "mongo.database_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_mongo_collection_name,
      { "Collection Name", "mongo.collection_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_mongo_reply_flags,
      { "Reply Flags", "mongo.reply.flags",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Bit vector of reply options.", HFILL }
    },
    { &hf_mongo_reply_flags_cursornotfound,
      { "Cursor Not Found", "mongo.reply.flags.cursornotfound",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
      "Set when getMore is called but the cursor id is not valid at the server", HFILL }
    },
    { &hf_mongo_reply_flags_queryfailure,
      { "Query Failure", "mongo.reply.flags.queryfailure",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
      "Set when query failed. Results consist of one document containing an $err field describing the failure.", HFILL }
    },
    { &hf_mongo_reply_flags_sharedconfigstale,
      { "Shared Config Stale", "mongo.reply.flags.sharedconfigstale",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
      NULL, HFILL }
    },
    { &hf_mongo_reply_flags_awaitcapable,
      { "Await Capable", "mongo.reply.flags.awaitcapable",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
      "Set when the server supports the AwaitData Query option", HFILL }
    },
    { &hf_mongo_message,
      { "Message", "mongo.message",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      "Message for the database", HFILL }
    },
    { &hf_mongo_cursor_id,
      { "Cursor ID", "mongo.cursor_id",
      FT_INT64, BASE_DEC, NULL, 0x0,
      "Cursor id if client needs to do get more's", HFILL }
    },
    { &hf_mongo_starting_from,
      { "Starting From", "mongo.starting_from",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Where in the cursor this reply is starting", HFILL }
    },
    { &hf_mongo_number_returned,
      { "Number Returned", "mongo.number_returned",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Number of documents in the reply", HFILL }
    },
    { &hf_mongo_documents,
      { "Documents", "mongo.documents",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_mongo_document_length,
      { "Document length", "mongo.document.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Length of BSON Document", HFILL }
    },
    { &hf_mongo_zero,
      { "Zero", "mongo.document.zero",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Reserved (Must be is Zero)", HFILL }
    },
    { &hf_mongo_update_flags,
      { "Update Flags", "mongo.update.flags",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Bit vector of update options.", HFILL }
    },
    { &hf_mongo_update_flags_upsert,
      { "Upsert", "mongo.update.flags.upsert",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
      "If set, the database will insert the supplied object into the collection if no matching document is found", HFILL }
    },
    { &hf_mongo_update_flags_multiupdate,
      { "Multi Update", "mongo.update.flags.multiupdate",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
      "If set, the database will update all matching objects in the collection. Otherwise only updates first matching doc.", HFILL }
    },
    { &hf_mongo_selector,
      { "Selector", "mongo.selector",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "The query to select the document", HFILL }
    },
    { &hf_mongo_update,
      { "Update", "mongo.update",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Specification of the update to perform", HFILL }
    },
    { &hf_mongo_insert_flags,
      { "Insert Flags", "mongo.insert.flags",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Bit vector of insert options.", HFILL }
    },
    { &hf_mongo_insert_flags_continueonerror,
      { "ContinueOnError", "mongo.insert.flags.continueonerror",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
      "If set, the database will not stop processing a bulk insert if one fails (eg due to duplicate IDs)", HFILL }
    },

    { &hf_mongo_query_flags_tailablecursor,
      { "Tailable Cursor", "mongo.query.flags.tailable_cursor",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
      "Tailable means cursor is not closed when the last data is retrieved", HFILL }
    },
    { &hf_mongo_query_flags_slaveok,
      { "Slave OK", "mongo.query.flags.slave_ok",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
      "Allow query of replica slave", HFILL }
    },
    { &hf_mongo_query_flags_oplogreplay,
      { "Op Log Reply", "mongo.query.flags.op_log_reply",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
      "Internal replication use only", HFILL }
    },
    { &hf_mongo_query_flags_nocursortimeout,
      { "No Cursor Timeout", "mongo.query.flags.no_cursor_timeout",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000010,
      "The server normally times out idle cursors after an inactivity period (10 minutes) to prevent excess memory use. Set this option to prevent that", HFILL }
    },
    { &hf_mongo_query_flags_awaitdata,
      { "AwaitData", "mongo.query.flags.awaitdata",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
      "If we are at the end of the data, block for a while rather than returning no data. After a timeout period, we do return as normal", HFILL }
    },
    { &hf_mongo_query_flags_exhaust,
      { "Exhaust", "mongo.query.flags.exhaust",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000040,
      "Stream the data down full blast in multiple more packages, on the assumption that the client will fully read all data queried", HFILL }
    },
    { &hf_mongo_query_flags_partial,
      { "Partial", "mongo.query.flags.partial",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000080,
      "Get partial results from a mongos if some shards are down (instead of throwing an error)", HFILL }
    },
    { &hf_mongo_number_to_skip,
      { "Number To Skip", "mongo.number_to_skip",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Number of documents in the skip", HFILL }
    },
    { &hf_mongo_number_to_return,
      { "Number to Return", "mongo.number_to_return",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Number of documents in the return", HFILL }
    },
    { &hf_mongo_query,
      { "Query", "mongo.query",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Query BSON Document", HFILL }
    },
    { &hf_mongo_return_field_selector,
      { "Return Field Selector", "mongo.return_field_selector",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Return Field Selector BSON Document", HFILL }
    },
    { &hf_mongo_delete_flags,
      { "Delete Flags", "mongo.delete.flags",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Bit vector of delete options.", HFILL }
    },
    { &hf_mongo_delete_flags_singleremove,
      { "Single Remove", "mongo.delete.flags.singleremove",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
      "If set, the database will remove only the first matching document in the collection. Otherwise all matching documents will be removed", HFILL }
    },
    { &hf_mongo_number_of_cursor_ids,
      { "Number of Cursor IDS", "mongo.number_to_cursor_ids",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Number of cursorIDs in message", HFILL }
    },
    { &hf_mongo_unknown,
      { "Unknown", "mongo.unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Unknown Data type", HFILL }
    },
  };

  static gint *ett[] = {
    &ett_mongo,
    &ett_mongo_doc,
    &ett_mongo_fcn,
    &ett_mongo_flags
  };

  proto_mongo = proto_register_protocol("Mongo Wire Protocol", "MONGO", "mongo");

  proto_register_field_array(proto_mongo, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  mongo_module = prefs_register_protocol(proto_mongo,
      proto_reg_handoff_mongo);

  prefs_register_uint_preference(mongo_module, "tcp.port", "MONGO TCP Port",
       "MONGO TCP port if other than the default",
       10, &global_mongo_tcp_port);
}


void
proto_reg_handoff_mongo(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t mongo_handle;
  static int currentPort;

  if (!initialized) {

    mongo_handle = create_dissector_handle(dissect_mongo, proto_mongo);
    initialized = TRUE;
  } else {


    dissector_delete_uint("tcp.port", currentPort, mongo_handle);
  }

  currentPort = global_mongo_tcp_port;

  dissector_add_uint("tcp.port", currentPort, mongo_handle);

}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
