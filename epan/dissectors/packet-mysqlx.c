/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Dissector for MySQL X Protocol by Daniël van Eeden <wireshark@myname.nl>
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_mysqlx_protocol.html
 */

#include "config.h"
#include "packet-tcp.h"
#include <epan/expert.h>
#include <epan/packet.h>

/* From ClientMessages in mysqlx.proto, but with CLIENT_ prefix added */
#define CLIENT_CON_CAPABILITIES_GET 1
#define CLIENT_CON_CAPABILITIES_SET 2
#define CLIENT_CON_CLOSE 3
#define CLIENT_SESS_AUTHENTICATE_START 4
#define CLIENT_SESS_AUTHENTICATE_CONTINUE 5
#define CLIENT_SESS_RESET 6
#define CLIENT_SESS_CLOSE 7
#define CLIENT_SQL_STMT_EXECUTE 12
#define CLIENT_CRUD_FIND 17
#define CLIENT_CRUD_INSERT 18
#define CLIENT_CRUD_UPDATE 19
#define CLIENT_CRUD_DELETE 20
#define CLIENT_EXPECT_OPEN 24
#define CLIENT_EXPECT_CLOSE 25
#define CLIENT_CRUD_CREATE_VIEW 30
#define CLIENT_CRUD_MODIFY_VIEW 31
#define CLIENT_CRUD_DROP_VIEW 32
#define CLIENT_PREPARE_PREPARE 40
#define CLIENT_PREPARE_EXECUTE 41
#define CLIENT_PREPARE_DEALLOCATE 42
#define CLIENT_CURSOR_OPEN 43
#define CLIENT_CURSOR_CLOSE 44
#define CLIENT_CURSOR_FETCH 45
#define CLIENT_COMPRESSION 46

/* From ServerMessages in mysqlx.proto, but with SERVER_ prefix added */
#define SERVER_OK 0
#define SERVER_ERROR 1
#define SERVER_CONN_CAPABILITIES 2
#define SERVER_SESS_AUTHENTICATE_CONTINUE 3
#define SERVER_SESS_AUTHENTICATE_OK 4
#define SERVER_NOTICE 11
#define SERVER_RESULTSET_COLUMN_META_DATA 12
#define SERVER_RESULTSET_ROW 13
#define SERVER_RESULTSET_FETCH_DONE 14
#define SERVER_RESULTSET_FETCH_SUSPENDED 15
#define SERVER_RESULTSET_FETCH_DONE_MORE_RESULTSETS 16
#define SERVER_SQL_STMT_EXECUTE_OK 17
#define SERVER_RESULTSET_FETCH_DONE_MORE_OUT_PARAMS 18
#define SERVER_COMPRESSION 19

#define MYSQLX_HEADER_LENGTH 5

static const value_string message_type_vals_client[] = {
    {CLIENT_CON_CAPABILITIES_GET, "Mysqlx.Connection.CapabilitiesGet"},
    {CLIENT_CON_CAPABILITIES_SET, "Mysqlx.Connection.CapabilitiesSet"},
    {CLIENT_CON_CLOSE, "Mysqlx.Connection.Close"},
    {CLIENT_SESS_AUTHENTICATE_START, "Mysqlx.Session.AuthenticateStart"},
    {CLIENT_SESS_AUTHENTICATE_CONTINUE, "Mysqlx.Session.AuthenticateContinue"},
    {CLIENT_SESS_RESET, "Mysqlx.Session.Reset"},
    {CLIENT_SESS_CLOSE, "Mysqlx.Session.Close"},
    {CLIENT_SQL_STMT_EXECUTE, "Mysqlx.Sql.StmtExecute"},
    {CLIENT_CRUD_FIND, "Mysqlx.Crud.Find"},
    {CLIENT_CRUD_INSERT, "Mysqlx.Crud.Insert"},
    {CLIENT_CRUD_UPDATE, "Mysqlx.Crud.Update"},
    {CLIENT_CRUD_DELETE, "Mysqlx.Crud.Delete"},
    {CLIENT_EXPECT_OPEN, "Mysqlx.Expect.Open"},
    {CLIENT_EXPECT_CLOSE, "Mysqlx.Expect.Close"},
    {CLIENT_CRUD_CREATE_VIEW, "Mysqlx.Crud.CreateView"},
    {CLIENT_CRUD_MODIFY_VIEW, "Mysqlx.Crud.ModifyView"},
    {CLIENT_CRUD_DROP_VIEW, "Mysqlx.Crud.DropView"},
    {CLIENT_PREPARE_PREPARE, "Mysqlx.Prepare.Prepare"},
    {CLIENT_PREPARE_EXECUTE, "Mysqlx.Prepare.Execute"},
    {CLIENT_PREPARE_DEALLOCATE, "Mysqlx.Prepare.Deallocate"},
    {CLIENT_CURSOR_OPEN, "Mysqlx.Cursor.Open"},
    {CLIENT_CURSOR_CLOSE, "Mysqlx.Cursor.Close"},
    {CLIENT_CURSOR_FETCH, "Mysqlx.Cursor.Fetch"},
    {CLIENT_COMPRESSION, "Mysqlx.Connection.Compression"},
    {0, NULL}};

static const value_string message_type_vals_server[] = {
    {SERVER_OK, "Mysqlx.Ok"},
    {SERVER_ERROR, "Mysqlx.Error"},
    {SERVER_CONN_CAPABILITIES, "Mysqlx.Connection.Capabilities"},
    {SERVER_SESS_AUTHENTICATE_CONTINUE, "Mysqlx.Session.AuthenticateContinue"},
    {SERVER_SESS_AUTHENTICATE_OK, "Mysqlx.Session.AuthenticateOk"},
    {SERVER_NOTICE, "Mysqlx.Notice.Frame"},
    {SERVER_RESULTSET_COLUMN_META_DATA, "Mysqlx.Resultset.ColumnMetaData"},
    {SERVER_RESULTSET_ROW, "Mysqlx.Resultset.Row"},
    {SERVER_RESULTSET_FETCH_DONE, "Mysqlx.Resultset.FetchDone"},
    {SERVER_RESULTSET_FETCH_SUSPENDED, "Mysqlx.Resultset.FetchSuspended"},
    {SERVER_RESULTSET_FETCH_DONE_MORE_RESULTSETS,
     "Mysqlx.Resultset.FetchDoneMoreResultsets"},
    {SERVER_SQL_STMT_EXECUTE_OK, "Mysqlx.Sql.StmtExecuteOk"},
    {SERVER_RESULTSET_FETCH_DONE_MORE_OUT_PARAMS,
     "Mysqlx.Resultset.FetchDoneMoreOutParams"},
    {SERVER_COMPRESSION, "Mysqlx.Connection.Compression"},
    {0, NULL}};

static dissector_handle_t mysqlx_handle, mysqlx_protobuf_handle;

static int ett_mysqlx;
static int hf_mysqlx_packet_length;
static int hf_mysqlx_message_type;
static int proto_mysqlx;
static expert_field ei_mysqlx_unknown_message_type;

static int dissect_mysqlx_pdu(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, void *data _U_) {
  proto_tree *mysqlx_tree = NULL;
  proto_item *ti;
  tvbuff_t *next_tvb;
  int offset = 0;
  uint8_t message_type;
  char *message = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "mysqlx");
  ti = proto_tree_add_item(tree, proto_mysqlx, tvb, offset, -1, ENC_NA);
  mysqlx_tree = proto_item_add_subtree(ti, ett_mysqlx);
  proto_tree_add_item(mysqlx_tree, hf_mysqlx_packet_length, tvb, offset, 4,
                      ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item_ret_uint8(mysqlx_tree, hf_mysqlx_message_type, tvb,
                                offset, 1, ENC_NA, &message_type);
  offset++;

  if (pinfo->destport == pinfo->match_uint) {
    proto_item_append_text(ti, " (%s)",
                           val_to_str(pinfo->pool, message_type,
                                      message_type_vals_client, "Unknown(%u)"));
    switch (message_type) {
    case CLIENT_CON_CAPABILITIES_GET:
      message = "message,Mysqlx.Connection.CapabilitiesGet";
      break;
    case CLIENT_CON_CAPABILITIES_SET:
      message = "message,Mysqlx.Connection.CapabilitiesSet";
      break;
    case CLIENT_CON_CLOSE:
      message = "message,Mysqlx.Connection.Close";
      break;
    case CLIENT_SESS_AUTHENTICATE_START:
      message = "message,Mysqlx.Session.AuthenticateStart";
      break;
    case CLIENT_SESS_AUTHENTICATE_CONTINUE:
      message = "message,Mysqlx.Session.AuthenticateContinue";
      break;
    case CLIENT_SESS_RESET:
      message = "message,Mysqlx.Session.Reset";
      break;
    case CLIENT_SESS_CLOSE:
      message = "message,Mysqlx.Session.Close";
      break;
    case CLIENT_SQL_STMT_EXECUTE:
      message = "message,Mysqlx.Sql.StmtExecute";
      break;
    case CLIENT_CRUD_FIND:
      message = "message,Mysqlx.Crud.Find";
      break;
    case CLIENT_CRUD_INSERT:
      message = "message,Mysqlx.Crud.Insert";
      break;
    case CLIENT_CRUD_UPDATE:
      message = "message,Mysqlx.Crud.Update";
      break;
    case CLIENT_CRUD_DELETE:
      message = "message,Mysqlx.Crud.Delete";
      break;
    case CLIENT_EXPECT_OPEN:
      message = "message,Mysqlx.Expect.Open";
      break;
    case CLIENT_EXPECT_CLOSE:
      message = "message,Mysqlx.Expect.Close";
      break;
    case CLIENT_CRUD_CREATE_VIEW:
      message = "message,Mysqlx.Crud.CreateView";
      break;
    case CLIENT_CRUD_MODIFY_VIEW:
      message = "message,Mysqlx.Crud.ModifyView";
      break;
    case CLIENT_CRUD_DROP_VIEW:
      message = "message,Mysqlx.Crud.DropView";
      break;
    case CLIENT_PREPARE_PREPARE:
      message = "message,Mysqlx.Prepare.Prepare";
      break;
    case CLIENT_PREPARE_EXECUTE:
      message = "message,Mysqlx.Prepare.Execute";
      break;
    case CLIENT_PREPARE_DEALLOCATE:
      message = "message,Mysqlx.Prepare.Deallocate";
      break;
    case CLIENT_CURSOR_OPEN:
      message = "message,Mysqlx.Cursor.Open";
      break;
    case CLIENT_CURSOR_CLOSE:
      message = "message,Mysqlx.Cursor.Close";
      break;
    case CLIENT_CURSOR_FETCH:
      message = "message,Mysqlx.Cursor.Fetch";
      break;
    case CLIENT_COMPRESSION:
      message = "message,Mysqlx.Connection.Compression";
      break;
    }
  } else {
    proto_item_append_text(ti, " (%s)",
                           val_to_str(pinfo->pool, message_type,
                                      message_type_vals_server, "Unknown(%u)"));
    switch (message_type) {
    case SERVER_OK:
      message = "message,Mysqlx.Ok";
      break;
    case SERVER_ERROR:
      message = "message,Mysqlx.Error";
      break;
    case SERVER_CONN_CAPABILITIES:
      message = "message,Mysqlx.Connection.Capabilities";
      break;
    case SERVER_SESS_AUTHENTICATE_CONTINUE:
      message = "message,Mysqlx.Session.AuthenticateContinue";
      break;
    case SERVER_SESS_AUTHENTICATE_OK:
      message = "message,Mysqlx.Session.AuthenticateOk";
      break;
    case SERVER_NOTICE:
      message = "message,Mysqlx.Notice.Frame";
      break;
    case SERVER_RESULTSET_COLUMN_META_DATA:
      message = "message,Mysqlx.Resultset.ColumnMetaData";
      break;
    case SERVER_RESULTSET_ROW:
      message = "message,Mysqlx.Resultset.Row";
      break;
    case SERVER_RESULTSET_FETCH_DONE:
      message = "message,Mysqlx.Resultset.FetchDone";
      break;
    case SERVER_RESULTSET_FETCH_SUSPENDED:
      message = "message,Mysqlx.Resultset.FetchSuspended";
      break;
    case SERVER_RESULTSET_FETCH_DONE_MORE_RESULTSETS:
      message = "message,Mysqlx.Resultset.FetchDoneMoreResultsets";
      break;
    case SERVER_SQL_STMT_EXECUTE_OK:
      message = "message,Mysqlx.Sql.StmtExecuteOk";
      break;
    case SERVER_RESULTSET_FETCH_DONE_MORE_OUT_PARAMS:
      message = "message,Mysqlx.Resultset.FetchDoneMoreOutParams";
      break;
    case SERVER_COMPRESSION:
      message = "message,Mysqlx.Connection.Compression";
      break;
    }
  }
  if (message == NULL) {
    expert_add_info_format(pinfo, mysqlx_tree, &ei_mysqlx_unknown_message_type,
                           "can not link message type %d to a message",
                           message_type);
  } else {
    next_tvb = tvb_new_subset_length(
        tvb, offset, tvb_reported_length_remaining(tvb, offset));
    return offset + call_dissector_with_data(mysqlx_protobuf_handle, next_tvb,
                                             pinfo, mysqlx_tree, message);
  }
  return offset;
}

static unsigned get_mysqlx_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                   int offset, void *data _U_) {
  unsigned len =
      MYSQLX_HEADER_LENGTH + tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) - 1;
  return len;
}

static int dissect_mysqlx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          void *data) {
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MYSQLX_HEADER_LENGTH,
                   get_mysqlx_pdu_len, dissect_mysqlx_pdu, data);
  return tvb_reported_length(tvb);
}

void proto_register_mysqlx(void) {
  static hf_register_info hf[] = {
      {&hf_mysqlx_packet_length,
       {"Packet Length", "mysqlx.packet_length", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_mysqlx_message_type,
       {"Message Type", "mysqlx.message_type", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
  };

  static int *ett[] = {
      &ett_mysqlx,
  };

  static ei_register_info ei[] = {
      {&ei_mysqlx_unknown_message_type,
       {"mysqlx.unknown_message_type", PI_UNDECODED, PI_WARN,
        "unknown message type", EXPFILL}},
  };

  proto_mysqlx =
      proto_register_protocol("MySQL X Protocol", "MySQLX", "mysqlx");
  proto_register_field_array(proto_mysqlx, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_module_t *expert_mysqlx = expert_register_protocol(proto_mysqlx);
  expert_register_field_array(expert_mysqlx, ei, array_length(ei));
  mysqlx_handle = register_dissector("mysqlx", dissect_mysqlx, proto_mysqlx);
}

void proto_reg_handoff_mysqlx(void) {
  mysqlx_protobuf_handle =
      find_dissector_add_dependency("protobuf", proto_mysqlx);
  dissector_add_uint_with_preference("tcp.port", 33060, mysqlx_handle);
}
