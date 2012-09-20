/* packet-mongo.c
 * Routines for Mongo Wire Protocol dissection
 * Copyright 2010, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 * BSON dissection added 2011, Thomas Buchanan <tom at thomasbuchanan dot com>
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

#include "config.h"

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

/* BSON Element types */
/* See http://bsonspec.org/#/specification for detail */
#define BSON_ELEMENT_TYPE_DOUBLE         1
#define BSON_ELEMENT_TYPE_STRING         2
#define BSON_ELEMENT_TYPE_DOC            3
#define BSON_ELEMENT_TYPE_ARRAY          4
#define BSON_ELEMENT_TYPE_BINARY         5
#define BSON_ELEMENT_TYPE_UNDEF          6  /* Deprecated */
#define BSON_ELEMENT_TYPE_OBJ_ID         7
#define BSON_ELEMENT_TYPE_BOOL           8
#define BSON_ELEMENT_TYPE_DATETIME       9
#define BSON_ELEMENT_TYPE_NULL          10
#define BSON_ELEMENT_TYPE_REGEX         11
#define BSON_ELEMENT_TYPE_DB_PTR        12  /* Deprecated */
#define BSON_ELEMENT_TYPE_JS_CODE       13
#define BSON_ELEMENT_TYPE_SYMBOL        14
#define BSON_ELEMENT_TYPE_JS_CODE_SCOPE 15
#define BSON_ELEMENT_TYPE_INT32         16  /* 0x10 */
#define BSON_ELEMENT_TYPE_TIMESTAMP     17  /* 0x11 */
#define BSON_ELEMENT_TYPE_INT64         18  /* 0x12 */
#define BSON_ELEMENT_TYPE_MIN_KEY      255  /* 0xFF */
#define BSON_ELEMENT_TYPE_MAX_KEY      127  /* 0x7F */

static const value_string element_type_vals[] = {
  { BSON_ELEMENT_TYPE_DOUBLE,         "Double" },
  { BSON_ELEMENT_TYPE_STRING,         "String" },
  { BSON_ELEMENT_TYPE_DOC,            "Document" },
  { BSON_ELEMENT_TYPE_ARRAY,          "Array" },
  { BSON_ELEMENT_TYPE_BINARY,         "Binary" },
  { BSON_ELEMENT_TYPE_UNDEF,          "Undefined" },
  { BSON_ELEMENT_TYPE_OBJ_ID,         "Object ID" },
  { BSON_ELEMENT_TYPE_BOOL,           "Boolean" },
  { BSON_ELEMENT_TYPE_DATETIME,       "Datetime" },
  { BSON_ELEMENT_TYPE_NULL,           "NULL" },
  { BSON_ELEMENT_TYPE_REGEX,          "Regular Expression" },
  { BSON_ELEMENT_TYPE_DB_PTR,         "DBPointer" },
  { BSON_ELEMENT_TYPE_JS_CODE,        "JavaScript Code" },
  { BSON_ELEMENT_TYPE_SYMBOL,         "Symbol" },
  { BSON_ELEMENT_TYPE_JS_CODE_SCOPE,  "JavaScript Code w/Scope" },
  { BSON_ELEMENT_TYPE_INT32,          "Int32" },
  { BSON_ELEMENT_TYPE_TIMESTAMP,      "Timestamp" },
  { BSON_ELEMENT_TYPE_INT64,          "Int64" },
  { BSON_ELEMENT_TYPE_MIN_KEY,        "Min Key" },
  { BSON_ELEMENT_TYPE_MAX_KEY,        "Max Key" },
  { 0, NULL }
};

/* BSON Element Binary subtypes */
#define BSON_ELEMENT_BINARY_TYPE_GENERIC  0
#define BSON_ELEMENT_BINARY_TYPE_FUNCTION 1
#define BSON_ELEMENT_BINARY_TYPE_BINARY   2 /* OLD */
#define BSON_ELEMENT_BINARY_TYPE_UUID     3
#define BSON_ELEMENT_BINARY_TYPE_MD5      4
#define BSON_ELEMENT_BINARY_TYPE_USER   128 /* 0x80 */

static const value_string binary_type_vals[] = {
  { BSON_ELEMENT_BINARY_TYPE_GENERIC,  "Generic" },
  { BSON_ELEMENT_BINARY_TYPE_FUNCTION, "Function" },
  { BSON_ELEMENT_BINARY_TYPE_BINARY,   "Binary" },
  { BSON_ELEMENT_BINARY_TYPE_UUID,     "UUID" },
  { BSON_ELEMENT_BINARY_TYPE_MD5,      "MD5" },
  { BSON_ELEMENT_BINARY_TYPE_USER,     "User" },
  { 0, NULL }
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
static int hf_mongo_document = -1;
static int hf_mongo_document_length = -1;
static int hf_mongo_document_empty = -1;
static int hf_mongo_delete_flags = -1;
static int hf_mongo_delete_flags_singleremove = -1;
static int hf_mongo_number_of_cursor_ids = -1;
static int hf_mongo_elements = -1;
static int hf_mongo_element_name = -1;
static int hf_mongo_element_type = -1;
static int hf_mongo_element_length = -1;
static int hf_mongo_element_value_boolean = -1;
static int hf_mongo_element_value_int32 = -1;
static int hf_mongo_element_value_int64 = -1;
static int hf_mongo_element_value_double = -1;
static int hf_mongo_element_value_string = -1;
static int hf_mongo_element_value_string_length = -1;
static int hf_mongo_element_value_binary = -1;
static int hf_mongo_element_value_binary_length = -1;
static int hf_mongo_element_value_regex_pattern = -1;
static int hf_mongo_element_value_regex_options = -1;
static int hf_mongo_element_value_objectid = -1;
static int hf_mongo_element_value_objectid_time = -1;
static int hf_mongo_element_value_objectid_machine = -1;
static int hf_mongo_element_value_objectid_pid = -1;
static int hf_mongo_element_value_objectid_inc = -1;
static int hf_mongo_element_value_db_ptr = -1;
static int hf_mongo_element_value_js_code = -1;
static int hf_mongo_element_value_js_scope = -1;
static int hf_mongo_unknown = -1;

static guint global_mongo_tcp_port = TCP_PORT_MONGO;

static gint ett_mongo = -1;
static gint ett_mongo_doc = -1;
static gint ett_mongo_elements = -1;
static gint ett_mongo_element = -1;
static gint ett_mongo_objectid = -1;
static gint ett_mongo_code = -1;
static gint ett_mongo_fcn = -1;
static gint ett_mongo_flags = -1;

static int
dissect_fullcollectionname(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  gint32 fcn_length, dbn_length;
  proto_item *ti;
  proto_tree *fcn_tree;

  ti = proto_tree_add_item(tree, hf_mongo_fullcollectionname, tvb, offset, -1, ENC_ASCII|ENC_NA);
  fcn_length = tvb_strsize(tvb, offset);

  /* If this doesn't find anything, we'll just throw an exception below */
  dbn_length = tvb_find_guint8(tvb, offset, fcn_length, '.') - offset;

  fcn_tree = proto_item_add_subtree(ti, ett_mongo_fcn);

  proto_tree_add_item(fcn_tree, hf_mongo_database_name, tvb, offset, dbn_length, ENC_ASCII|ENC_NA);

  proto_tree_add_item(fcn_tree, hf_mongo_collection_name, tvb, offset + 1 + dbn_length, fcn_length - dbn_length - 2, ENC_ASCII|ENC_NA);

  return fcn_length;
}

/* http://docs.mongodb.org/manual/reference/limits/ */
/* http://www.mongodb.org/display/DOCS/Documents */
#define BSON_MAX_NESTING 100
#define BSON_MAX_DOC_SIZE (16 * 1000 * 1000)
static int
dissect_bson_document(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree, int hf_mongo_doc, int nest_level)
{
  gint32 document_length;
  guint final_offset;
  proto_item *ti, *elements, *element, *objectid, *js_code, *js_scope;
  proto_tree *doc_tree, *elements_tree, *element_sub_tree, *objectid_sub_tree, *js_code_sub_tree, *js_scope_sub_tree;

  document_length = tvb_get_letohl(tvb, offset);

  ti = proto_tree_add_item(tree, hf_mongo_doc, tvb, offset, document_length, ENC_NA);
  doc_tree = proto_item_add_subtree(ti, ett_mongo_doc);

  proto_tree_add_item(doc_tree, hf_mongo_document_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  if (nest_level > BSON_MAX_NESTING) {
      expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "BSON document recursion exceeds %u", BSON_MAX_NESTING);
      THROW(ReportedBoundsError);
  }

  if (document_length < 5) {
      expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "BSON document length too short: %u", document_length);
      THROW(ReportedBoundsError);
  }

  if (document_length > BSON_MAX_DOC_SIZE) {
      expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "BSON document length too long: %u", document_length);
      THROW(ReportedBoundsError);
  }

  if (document_length == 5) {
    /* document with length 5 is an empty document */
    /* don't display the element subtree */
    proto_tree_add_item(tree, hf_mongo_document_empty, tvb, offset, document_length, ENC_NA);
    return document_length;
  }

  final_offset = offset + document_length;
  offset += 4;

  elements = proto_tree_add_item(doc_tree, hf_mongo_elements, tvb, offset, document_length-5, ENC_NA);
  elements_tree = proto_item_add_subtree(elements, ett_mongo_elements);

  do {
    /* Read document elements */
    guint8 e_type = -1;  /* Element type */
    gint str_len = -1;   /* String length */
    gint e_len = -1;     /* Element length */
    gint doc_len = -1;   /* Document length */

    e_type = tvb_get_guint8(tvb, offset);
    tvb_get_ephemeral_stringz(tvb, offset+1, &str_len);

    element = proto_tree_add_item(elements_tree, hf_mongo_element_name, tvb, offset+1, str_len-1, ENC_UTF_8|ENC_NA);
    element_sub_tree = proto_item_add_subtree(element, ett_mongo_element);
    proto_tree_add_item(element_sub_tree, hf_mongo_element_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += str_len+1;

    switch(e_type) {
      case BSON_ELEMENT_TYPE_DOUBLE:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
      case BSON_ELEMENT_TYPE_STRING:
      case BSON_ELEMENT_TYPE_JS_CODE:
      case BSON_ELEMENT_TYPE_SYMBOL:
        str_len = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len+4;
        break;
      case BSON_ELEMENT_TYPE_DOC:
      case BSON_ELEMENT_TYPE_ARRAY:
        offset += dissect_bson_document(tvb, pinfo, offset, element_sub_tree, hf_mongo_document, nest_level+1);
        break;
      case BSON_ELEMENT_TYPE_BINARY:
        e_len = tvb_get_letohl(tvb, offset);
        /* TODO - Add functions to decode various binary subtypes */
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_binary_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_binary, tvb, offset+5, e_len, ENC_NA);
        offset += e_len+5;
        break;
      case BSON_ELEMENT_TYPE_UNDEF:
      case BSON_ELEMENT_TYPE_NULL:
      case BSON_ELEMENT_TYPE_MIN_KEY:
      case BSON_ELEMENT_TYPE_MAX_KEY:
        /* Nothing to do, as there is no element content */
        break;
      case BSON_ELEMENT_TYPE_OBJ_ID:
        objectid = proto_tree_add_item(element_sub_tree, hf_mongo_element_value_objectid, tvb, offset, 12, ENC_NA);
        objectid_sub_tree = proto_item_add_subtree(objectid, ett_mongo_objectid);
        /* Unlike most BSON elements, parts of ObjectID are stored Big Endian, so they can be compared bit by bit */
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_machine, tvb, offset+4, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_pid, tvb, offset+7, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_mongo_element_value_objectid_inc, tvb, offset+9, 3, ENC_BIG_ENDIAN);
        offset += 12;
        break;
      case BSON_ELEMENT_TYPE_BOOL:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_boolean, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
      case BSON_ELEMENT_TYPE_REGEX:
        /* regex pattern */
        tvb_get_ephemeral_stringz(tvb, offset, &str_len);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_regex_pattern, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        /* regex options */
        tvb_get_ephemeral_stringz(tvb, offset, &str_len);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_regex_options, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        break;
      case BSON_ELEMENT_TYPE_DB_PTR:
        str_len = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_db_ptr, tvb, offset, 12, ENC_NA);
        offset += 12;
        break;
      case BSON_ELEMENT_TYPE_JS_CODE_SCOPE:
        /* code_w_s ::= int32 string document */
        proto_tree_add_item(element_sub_tree, hf_mongo_element_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        e_len = tvb_get_letohl(tvb, offset);
        offset += 4;
        str_len = tvb_get_letohl(tvb, offset);
        js_code = proto_tree_add_item(element_sub_tree, hf_mongo_element_value_js_code, tvb, offset, str_len+4, ENC_NA);
        js_code_sub_tree = proto_item_add_subtree(js_code, ett_mongo_code);
        proto_tree_add_item(js_code_sub_tree, hf_mongo_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(js_code_sub_tree, hf_mongo_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len+4;
        doc_len = e_len - (str_len + 8);
        js_scope = proto_tree_add_item(element_sub_tree, hf_mongo_element_value_js_scope, tvb, offset, doc_len, ENC_NA);
        js_scope_sub_tree = proto_item_add_subtree(js_scope, ett_mongo_code);
        offset += dissect_bson_document(tvb, pinfo, offset, js_scope_sub_tree, hf_mongo_document, nest_level+1);
        break;
      case BSON_ELEMENT_TYPE_INT32:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_int32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
      case BSON_ELEMENT_TYPE_DATETIME:
      case BSON_ELEMENT_TYPE_TIMESTAMP:
        /* TODO Implement routine to convert datetime & timestamp values to UTC date/time */
        /* for now, simply display the integer value */
      case BSON_ELEMENT_TYPE_INT64:
        proto_tree_add_item(element_sub_tree, hf_mongo_element_value_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
      default:
        break;
    }  /* end switch() */
  } while (offset < final_offset-1);

  return document_length;
}
static int
dissect_mongo_reply(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree)
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
    offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_document, 1);
  }
  return offset;
}
static int
dissect_mongo_msg(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

  proto_item *ti;

  ti = proto_tree_add_item(tree, hf_mongo_message, tvb, offset, -1, ENC_ASCII|ENC_NA);
  offset += proto_item_get_len(ti);

  return offset;
}

static int
dissect_mongo_update(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree)
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

  offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_selector, 1);

  offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_update, 1);

  return offset;
}

static int
dissect_mongo_insert(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *flags_tree;

  ti = proto_tree_add_item(tree, hf_mongo_insert_flags, tvb, offset, 4, ENC_NA);
  flags_tree = proto_item_add_subtree(ti, ett_mongo_flags);
  proto_tree_add_item(flags_tree, hf_mongo_insert_flags_continueonerror, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  offset += dissect_fullcollectionname(tvb, offset, tree);

  while(offset < tvb_reported_length(tvb)) {
    offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_document, 1);
  }

  return offset;
}

static int
dissect_mongo_query(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree)
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

  offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_query, 1);

  while(offset < tvb_reported_length(tvb)) {
    offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_return_field_selector, 1);
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
dissect_mongo_delete(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree)
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

  offset += dissect_bson_document(tvb, pinfo, offset, tree, hf_mongo_selector, 1);

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
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str_const(opcode, opcode_vals, "Unknown"));

    switch(opcode){
    case OP_REPLY:
      offset = dissect_mongo_reply(tvb, pinfo, offset, mongo_tree);
      break;
    case OP_MSG:
      offset = dissect_mongo_msg(tvb, offset, mongo_tree);
      break;
    case OP_UPDATE:
      offset = dissect_mongo_update(tvb, pinfo, offset, mongo_tree);
      break;
    case OP_INSERT:
      offset = dissect_mongo_insert(tvb, pinfo, offset, mongo_tree);
      break;
    case OP_QUERY:
      offset = dissect_mongo_query(tvb, pinfo, offset, mongo_tree);
      break;
    case OP_GET_MORE:
      offset = dissect_mongo_getmore(tvb, offset, mongo_tree);
      break;
    case OP_DELETE:
      offset = dissect_mongo_delete(tvb, pinfo, offset, mongo_tree);
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
      expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown Data (not interpreted)");
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
      "The full collection name is the concatenation of the database name with the"
        " collection name, using a dot for the concatenation", HFILL }
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
      "Set when query failed. Results consist of one document containing an $err"
        " field describing the failure.", HFILL }
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
    { &hf_mongo_document,
      { "Document", "mongo.document",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_mongo_document_length,
      { "Document length", "mongo.document.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Length of BSON Document", HFILL }
    },
    { &hf_mongo_document_empty,
      { "Empty Document", "mongo.document.empty",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Document with no elements", HFILL }
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
      "If set, the database will insert the supplied object into the collection if no"
        " matching document is found", HFILL }
    },
    { &hf_mongo_update_flags_multiupdate,
      { "Multi Update", "mongo.update.flags.multiupdate",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
      "If set, the database will update all matching objects in the collection."
        " Otherwise only updates first matching doc.", HFILL }
    },
    { &hf_mongo_selector,
      { "Selector", "mongo.selector",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "The query to select the document", HFILL }
    },
    { &hf_mongo_update,
      { "Update", "mongo.update",
      FT_NONE, BASE_NONE, NULL, 0x0,
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
      "If set, the database will not stop processing a bulk insert if one fails"
        " (eg due to duplicate IDs)", HFILL }
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
      "The server normally times out idle cursors after an inactivity period (10 minutes)"
        " to prevent excess memory use. Set this option to prevent that", HFILL }
    },
    { &hf_mongo_query_flags_awaitdata,
      { "AwaitData", "mongo.query.flags.awaitdata",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
      "If we are at the end of the data, block for a while rather than returning no data."
        " After a timeout period, we do return as normal", HFILL }
    },
    { &hf_mongo_query_flags_exhaust,
      { "Exhaust", "mongo.query.flags.exhaust",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000040,
      "Stream the data down full blast in multiple more packages, on the assumption"
        " that the client will fully read all data queried", HFILL }
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
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Query BSON Document", HFILL }
    },
    { &hf_mongo_return_field_selector,
      { "Return Field Selector", "mongo.return_field_selector",
      FT_NONE, BASE_NONE, NULL, 0x0,
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
      "If set, the database will remove only the first matching document in the"
        " collection. Otherwise all matching documents will be removed", HFILL }
    },
    { &hf_mongo_number_of_cursor_ids,
      { "Number of Cursor IDS", "mongo.number_to_cursor_ids",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Number of cursorIDs in message", HFILL }
    },
    { &hf_mongo_elements,
      { "Elements", "mongo.elements",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Document Elements", HFILL }
    },
    { &hf_mongo_element_name,
      { "Element", "mongo.element.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Element Name", HFILL }
    },
    { &hf_mongo_element_type,
      { "Type", "mongo.element.type",
      FT_UINT8, BASE_HEX_DEC, VALS(element_type_vals), 0x0,
      "Element Type", HFILL }
    },
    { &hf_mongo_element_length,
      { "Length", "mongo.element.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Element Length", HFILL }
    },
    { &hf_mongo_element_value_boolean,
      { "Value", "mongo.element.value.bool",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_mongo_element_value_int32,
      { "Value", "mongo.element.value.int",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_mongo_element_value_int64,
      { "Value", "mongo.element.value.int64",
      FT_INT64, BASE_DEC, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_mongo_element_value_double,
      { "Value", "mongo.element.value.double",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_mongo_element_value_string,
      { "Value", "mongo.element.value.string",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_mongo_element_value_string_length,
      { "Length", "mongo.element.value.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Element Value Length", HFILL }
    },
    { &hf_mongo_element_value_binary,
      { "Value", "mongo.element.value.bytes",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_mongo_element_value_binary_length,
      { "Length", "mongo.element.value.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Binary Element Length", HFILL }
    },
    { &hf_mongo_element_value_regex_pattern,
      { "Value", "mongo.element.value.regex.pattern",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Regex Pattern", HFILL }
    },
    { &hf_mongo_element_value_regex_options,
      { "Value", "mongo.element.value.regex.options",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Regex Options", HFILL }
    },
    { &hf_mongo_element_value_objectid,
      { "ObjectID", "mongo.element.value.objectid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "ObjectID Value", HFILL }
    },
    { &hf_mongo_element_value_objectid_time,
      { "ObjectID Time", "mongo.element.value.objectid.time",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "ObjectID timestampt", HFILL }
    },
    { &hf_mongo_element_value_objectid_machine,
      { "ObjectID Machine", "mongo.element.value.objectid.machine",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      "ObjectID machine ID", HFILL }
    },
    { &hf_mongo_element_value_objectid_pid,
      { "ObjectID PID", "mongo.element.value.objectid.pid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "ObjectID process ID", HFILL }
    },
    { &hf_mongo_element_value_objectid_inc,
      { "ObjectID inc", "mongo.element.value.objectid.inc",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "ObjectID increment", HFILL }
    },
    { &hf_mongo_element_value_db_ptr,
      { "ObjectID", "mongo.element.value.db_ptr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "DBPointer", HFILL }
    },
    { &hf_mongo_element_value_js_code,
      { "JavaScript code", "mongo.element.value.js_code",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "JavaScript code to be evaluated", HFILL }
    },
    { &hf_mongo_element_value_js_scope,
      { "JavaScript scope", "mongo.element.value.js_scope",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Scope document for JavaScript evaluation", HFILL }
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
    &ett_mongo_elements,
    &ett_mongo_element,
    &ett_mongo_objectid,
    &ett_mongo_code,
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
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
