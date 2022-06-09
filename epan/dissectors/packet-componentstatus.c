/* packet-componentstatus.c
 * Routines for the Component Status Protocol of the
 * RSPLIB RSerPool implementation
 * https://www.uni-due.de/~be0001/rserpool/
 *
 * Copyright 2006-2021 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/sctpppids.h>
#include <epan/stat_tap_ui.h>


void proto_register_componentstatusprotocol(void);
void proto_reg_handoff_componentstatusprotocol(void);

/* Initialize the protocol and registered fields */
static int proto_componentstatusprotocol = -1;
static int tap_componentstatusprotocol   = -1;

/* Initialize the subtree pointers */
static gint ett_componentstatusprotocol           = -1;
static gint ett_message_flags                     = -1;
static gint ett_message_sender_id                 = -1;
static gint ett_cspreport_association_receiver_id = -1;
static gint ett_association                       = -1;


#define COMPONENTSTATUSPROTOCOL_PORT    2960   /* Not IANA registered */
#define COMPONENTSTATUSPROTOCOL_VERSION 0x0200

static int hf_message_type             = -1;
static int hf_message_flags            = -1;
static int hf_message_flags_final_bit  = -1;
static int hf_message_length           = -1;
static int hf_message_version          = -1;
static int hf_message_sender_id        = -1;
static int hf_message_sender_id_group  = -1;
static int hf_message_sender_id_object = -1;
static int hf_message_sender_timestamp = -1;

static guint64 componentstatusprotocol_total_msgs     = 0;
static guint64 componentstatusprotocol_total_bytes    = 0;


#define COMPONENTSTATUS_REPORT 0x01

static const value_string message_type_values[] = {
  { COMPONENTSTATUS_REPORT, "ComponentStatus Report" },
  { 0, NULL }
};


static int hf_cspreport_report_interval = -1;
static int hf_cspreport_location        = -1;
static int hf_cspreport_status          = -1;
static int hf_cspreport_workload        = -1;
static int hf_cspreport_associations    = -1;

#define CSPF_FINAL (1 << 0)
static const true_false_string message_flags_final_bit = {
  "Final message",
  "Not final message"
};

#define CID_GROUP_UNKNOWN     0x0000
#define CID_GROUP_REGISTRAR   0x0001
#define CID_GROUP_POOLELEMENT 0x0002
#define CID_GROUP_POOLUSER    0x0003
#define CID_GROUP(id)  (((uint64_t) id >> 56) & (0xffffULL)
#define CID_OBJECT(id) (((uint64_t) id & 0xffffffffffffffULL)
static const value_string group_values[] = {
  { CID_GROUP_UNKNOWN,     "Unknown" },
  { CID_GROUP_REGISTRAR,   "Registrar" },
  { CID_GROUP_POOLELEMENT, "Pool Element" },
  { CID_GROUP_POOLUSER,    "Pool User" },
  { 0, NULL }
};

#define CSR_GET_WORKLOAD(w) ((w == 0xffff) ? -1.0 : (float)(w / (float)0xfffe))

static int hf_cspreport_association_receiver_id        = -1;
static int hf_cspreport_association_receiver_id_group  = -1;
static int hf_cspreport_association_receiver_id_object = -1;
static int hf_cspreport_association_duration           = -1;
static int hf_cspreport_association_flags              = -1;
static int hf_cspreport_association_protocolid         = -1;
static int hf_cspreport_association_ppid               = -1;


/* Setup list of header fields */
static hf_register_info hf[] = {
  { &hf_message_type,                             { "Type",            "componentstatusprotocol.message_type",                         FT_UINT8,  BASE_DEC, VALS(message_type_values), 0x0, NULL, HFILL } },
  { &hf_message_flags,                            { "Flags",           "componentstatusprotocol.message_flags",                        FT_UINT8,  BASE_DEC, NULL,                      0x0, NULL, HFILL } },
  { &hf_message_flags_final_bit,                  { "F-Bit",           "componentstatusprotocol.message_final_bit",                    FT_BOOLEAN, 8, TFS(&message_flags_final_bit),   CSPF_FINAL, NULL, HFILL } },
  { &hf_message_length,                           { "Length",          "componentstatusprotocol.message_length",                       FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
  { &hf_message_version,                          { "Version",         "componentstatusprotocol.message_version",                      FT_UINT32, BASE_HEX, NULL,                      0x0, NULL, HFILL } },
  { &hf_message_sender_id,                        { "SenderID",        "componentstatusprotocol.message_sender_id",                    FT_UINT64, BASE_HEX, NULL,                      0x0, NULL, HFILL } },
  { &hf_message_sender_id_group,                  { "Group",           "componentstatusprotocol.message_sender_id.group",              FT_UINT16, BASE_HEX, VALS(group_values),        0x0, NULL, HFILL } },
  { &hf_message_sender_id_object,                 { "Object",          "componentstatusprotocol.message_sender_id.object",             FT_UINT64, BASE_HEX, NULL,                      0x0, NULL, HFILL } },
  { &hf_message_sender_timestamp,                 { "SenderTimeStamp", "componentstatusprotocol.message_sendertimestamp",              FT_RELATIVE_TIME, BASE_NONE, NULL,              0x0, NULL, HFILL } },

  { &hf_cspreport_report_interval,                { "ReportInterval",  "componentstatusprotocol.componentstatusreport_reportinterval", FT_RELATIVE_TIME, BASE_NONE, NULL,              0x0, NULL, HFILL } },
  { &hf_cspreport_location,                       { "Location",        "componentstatusprotocol.componentstatusreport_location",       FT_STRING, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
  { &hf_cspreport_status,                         { "Status",          "componentstatusprotocol.componentstatusreport_status",         FT_STRING, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
  { &hf_cspreport_workload,                       { "Workload",        "componentstatusprotocol.componentstatusreport_workload",       FT_FLOAT,  BASE_NONE, NULL,                     0x0, NULL, HFILL } },
  { &hf_cspreport_associations,                   { "Associations",    "componentstatusprotocol.componentstatusreport_associations",   FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },

  { &hf_cspreport_association_receiver_id,        { "ReceiverID", "componentstatusprotocol.componentassociation_receiver_id",          FT_UINT64, BASE_HEX, NULL,                      0x0, NULL, HFILL } },
  { &hf_cspreport_association_receiver_id_group,  { "Group",      "componentstatusprotocol.componentassociation_receiver_id.group",    FT_UINT16, BASE_HEX, VALS(group_values),        0x0, NULL, HFILL } },
  { &hf_cspreport_association_receiver_id_object, { "Object",     "componentstatusprotocol.componentassociation_receiver_id.object",   FT_UINT64, BASE_HEX, NULL,                      0x0, NULL, HFILL } },
  { &hf_cspreport_association_duration,           { "Duration",   "componentstatusprotocol.componentassociation_duration",             FT_RELATIVE_TIME, BASE_NONE, NULL,              0x0, NULL, HFILL } },
  { &hf_cspreport_association_flags,              { "Flags",      "componentstatusprotocol.componentassociation_flags",                FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
  { &hf_cspreport_association_protocolid,         { "ProtocolID", "componentstatusprotocol.componentassociation_protocolid",           FT_UINT16, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext,  0x0, NULL, HFILL } },
  { &hf_cspreport_association_ppid,               { "PPID",       "componentstatusprotocol.componentassociation_ppid",                 FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sctpppid_val_ext, 0x0, NULL, HFILL } },
};


typedef struct _tap_componentstatusprotocol_rec_t {
  guint8      type;
  guint16     size;
  const char* type_string;
} tap_componentstatusprotocol_rec_t;


static void
dissect_componentstatusprotocol_cspreport_association(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  proto_item* receiver_id_item;
  proto_tree* receiver_id_tree;
  guint64     timestamp;
  nstime_t    t;

  receiver_id_item = proto_tree_add_item(message_tree, hf_cspreport_association_receiver_id, message_tvb, 0, 8, ENC_BIG_ENDIAN);
  receiver_id_tree = proto_item_add_subtree(receiver_id_item, ett_cspreport_association_receiver_id);
  proto_tree_add_item(receiver_id_tree, hf_cspreport_association_receiver_id_group,  message_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(receiver_id_tree, hf_cspreport_association_receiver_id_object, message_tvb, 1, 7, ENC_BIG_ENDIAN);

  timestamp = tvb_get_ntoh64(message_tvb, 8);
  t.secs  = (time_t)(timestamp / 1000000);
  t.nsecs = (int)((timestamp - 1000000 * t.secs) * 1000);
  if(timestamp == 0xffffffffffffffffULL) {
    proto_tree_add_time_format(message_tree, hf_cspreport_association_duration, message_tvb, 8, 8, &t, "Duration: unknown");
  }
  else {
    proto_tree_add_time(message_tree, hf_cspreport_association_duration, message_tvb, 8, 8, &t);
  }

  proto_tree_add_item(message_tree, hf_cspreport_association_flags,      message_tvb, 16, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_cspreport_association_protocolid, message_tvb, 18, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_cspreport_association_ppid,       message_tvb, 20, 4, ENC_BIG_ENDIAN);
}


static void
dissect_componentstatusprotocol_cspreport_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  tvbuff_t   *association_tvb;
  proto_tree *association_tree;
  int         association;
  gint        offset;
  float       workload;
  guint64     interval;
  nstime_t    t;

  interval = tvb_get_ntohl(message_tvb, 24);
  t.secs  = (time_t)(interval / 1000000);
  t.nsecs = (int)((interval - 1000000 * t.secs) * 1000);
  proto_tree_add_time(message_tree, hf_cspreport_report_interval, message_tvb,  24,   4, &t);
  proto_tree_add_item(message_tree, hf_cspreport_location,        message_tvb,  28, 128, ENC_UTF_8);
  proto_tree_add_item(message_tree, hf_cspreport_status,          message_tvb, 156, 128, ENC_UTF_8);

  workload = (float)(100.0 * CSR_GET_WORKLOAD(tvb_get_ntohs(message_tvb, 284)));
  if(workload < 0.0) {   /* Special value 0xffff -> -1.0 means "no load provided"! */
     proto_tree_add_float_format(message_tree, hf_cspreport_workload, message_tvb, 284, 2,
                                workload, "Workload: N/A");
  }
  else {
     proto_tree_add_float_format_value(message_tree, hf_cspreport_workload, message_tvb, 284, 2,
                                       workload, "%1.2f%%", workload);
  }
  proto_tree_add_item(message_tree, hf_cspreport_associations, message_tvb, 286, 2, ENC_BIG_ENDIAN);

  association = 1;
  offset      = 288;
  while(tvb_reported_length_remaining(message_tvb, offset) >= 24) {
     association_tree = proto_tree_add_subtree_format(message_tree, message_tvb, offset, 24,
         ett_association, NULL, "Association #%d", association++);
     association_tvb  = tvb_new_subset_length_caplen(message_tvb, offset,
                           MIN(24, tvb_reported_length_remaining(message_tvb, offset)),
                           24);

     dissect_componentstatusprotocol_cspreport_association(association_tvb, association_tree);
     offset += 24;
  }
}


static void
dissect_componentstatusprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *componentstatusprotocol_tree)
{
  proto_item* flags_item;
  proto_tree* flags_tree;
  proto_item* sender_id_item;
  proto_tree* sender_id_tree;
  guint64     timestamp;
  nstime_t    t;

  tap_componentstatusprotocol_rec_t* tap_rec = wmem_new0(pinfo->pool, tap_componentstatusprotocol_rec_t);
  tap_rec->type        = tvb_get_guint8(message_tvb, 0);
  tap_rec->size        = tvb_get_ntohs(message_tvb, 2);
  tap_rec->type_string = val_to_str_const(tap_rec->type, message_type_values, "Unknown ComponentStatusProtocol message type");
  tap_queue_packet(tap_componentstatusprotocol, pinfo, tap_rec);

  proto_tree_add_item(componentstatusprotocol_tree, hf_message_type, message_tvb, 0, 1, ENC_BIG_ENDIAN);
  flags_item = proto_tree_add_item(componentstatusprotocol_tree, hf_message_flags, message_tvb, 1, 1, ENC_BIG_ENDIAN);
  flags_tree = proto_item_add_subtree(flags_item, ett_message_flags);
  proto_tree_add_item(flags_tree, hf_message_flags_final_bit, message_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(componentstatusprotocol_tree, hf_message_length, message_tvb, 2, 2, ENC_BIG_ENDIAN);

  proto_tree_add_item(componentstatusprotocol_tree, hf_message_version, message_tvb, 4, 4, ENC_BIG_ENDIAN);
  sender_id_item = proto_tree_add_item(componentstatusprotocol_tree, hf_message_sender_id, message_tvb, 8, 8, ENC_BIG_ENDIAN);
  sender_id_tree = proto_item_add_subtree(sender_id_item, ett_message_sender_id);
  proto_tree_add_item(sender_id_tree, hf_message_sender_id_group,  message_tvb, 8, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sender_id_tree, hf_message_sender_id_object, message_tvb, 9, 7, ENC_BIG_ENDIAN);

  timestamp = tvb_get_ntoh64(message_tvb, 16);
  t.secs  = (time_t)(timestamp / 1000000);
  t.nsecs = (int)((timestamp - 1000000 * t.secs) * 1000);
  proto_tree_add_time(componentstatusprotocol_tree, hf_message_sender_timestamp, message_tvb, 16, 8, &t);

  switch (tap_rec->type) {
    case COMPONENTSTATUS_REPORT:
      dissect_componentstatusprotocol_cspreport_message(message_tvb, componentstatusprotocol_tree);
     break;
  }
}


static int
dissect_componentstatusprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *componentstatusprotocol_item;
  proto_tree *componentstatusprotocol_tree;
  gint8 type;
  gint32 version;

  if (tvb_reported_length(message_tvb) < 4 + 4)
    return(0);

  /* Check, if this packet really contains a ComponentStatusProtocol message */
  type = tvb_get_guint8(message_tvb, 0);
  if (type != COMPONENTSTATUS_REPORT) {
    return(0);
  }
  version = tvb_get_ntohl(message_tvb, 4);
  if (version != COMPONENTSTATUSPROTOCOL_VERSION) {
    return(0);
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ComponentStatusProtocol");

  /* create the componentstatusprotocol protocol tree */
  componentstatusprotocol_item = proto_tree_add_item(tree, proto_componentstatusprotocol, message_tvb, 0, -1, ENC_NA);
  componentstatusprotocol_tree = proto_item_add_subtree(componentstatusprotocol_item, ett_componentstatusprotocol);

  /* dissect the message */
  dissect_componentstatusprotocol_message(message_tvb, pinfo, componentstatusprotocol_tree);
  return(tvb_reported_length(message_tvb));
}


/* TAP STAT INFO */
typedef enum
{
  MESSAGE_TYPE_COLUMN = 0,
  MESSAGES_COLUMN,
  MESSAGES_SHARE_COLUMN,
  BYTES_COLUMN,
  BYTES_SHARE_COLUMN,
  FIRST_SEEN_COLUMN,
  LAST_SEEN_COLUMN,
  INTERVAL_COLUMN,
  MESSAGE_RATE_COLUMN,
  BYTE_RATE_COLUMN
} componentstatusprotocol_stat_columns;

static stat_tap_table_item componentstatusprotocol_stat_fields[] = {
  { TABLE_ITEM_STRING, TAP_ALIGN_LEFT,  "ComponentStatusProtocol Message Type", "%-25s" },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Messages ",            "%u"       },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Messages Share (%)"  , "%1.3f %%" },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Bytes (B)",            "%u"       },
  { TABLE_ITEM_UINT,   TAP_ALIGN_RIGHT, "Bytes Share (%) ",     "%1.3f %%" },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "First Seen (s)",       "%1.6f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Last Seen (s)",        "%1.6f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Interval (s)",         "%1.6f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Message Rate (Msg/s)", "%1.2f"    },
  { TABLE_ITEM_FLOAT,  TAP_ALIGN_LEFT,  "Byte Rate (B/s)",      "%1.2f"    }
};

static void componentstatusprotocol_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "ComponentStatusProtocol Statistics";
  int num_fields = sizeof(componentstatusprotocol_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int i = 0;
  stat_tap_table_item_type items[sizeof(componentstatusprotocol_stat_fields)/sizeof(stat_tap_table_item)];

  table = stat_tap_find_table(new_stat, table_name);
  if (table) {
    if (new_stat->stat_tap_reset_table_cb) {
      new_stat->stat_tap_reset_table_cb(table);
    }
    return;
  }

  table = stat_tap_init_table(table_name, num_fields, 0, NULL);
  stat_tap_add_table(new_stat, table);

  memset(items, 0x0, sizeof(items));
  /* Add a row for each value type */
  while (message_type_values[i].strptr) {
    items[MESSAGE_TYPE_COLUMN].type                = TABLE_ITEM_STRING;
    items[MESSAGE_TYPE_COLUMN].value.string_value  = message_type_values[i].strptr;
    items[MESSAGES_COLUMN].type                    = TABLE_ITEM_UINT;
    items[MESSAGES_COLUMN].value.uint_value        = 0;
    items[MESSAGES_SHARE_COLUMN].type              = TABLE_ITEM_NONE;
    items[MESSAGES_SHARE_COLUMN].value.float_value = -1.0;
    items[BYTES_COLUMN].type                       = TABLE_ITEM_UINT;
    items[BYTES_COLUMN].value.uint_value           = 0;
    items[BYTES_SHARE_COLUMN].type                 = TABLE_ITEM_NONE;
    items[BYTES_SHARE_COLUMN].value.float_value    = -1.0;
    items[FIRST_SEEN_COLUMN].type                  = TABLE_ITEM_NONE;
    items[FIRST_SEEN_COLUMN].value.float_value     = DBL_MAX;
    items[LAST_SEEN_COLUMN].type                   = TABLE_ITEM_NONE;
    items[LAST_SEEN_COLUMN].value.float_value      = DBL_MIN;
    items[INTERVAL_COLUMN].type                    = TABLE_ITEM_NONE;
    items[INTERVAL_COLUMN].value.float_value       = -1.0;
    items[MESSAGE_RATE_COLUMN].type                = TABLE_ITEM_NONE;
    items[MESSAGE_RATE_COLUMN].value.float_value   = -1.0;
    items[BYTE_RATE_COLUMN].type                   = TABLE_ITEM_NONE;
    items[BYTE_RATE_COLUMN].value.float_value      = -1.0;
    stat_tap_init_table_row(table, i, num_fields, items);
    i++;
  }
}

static tap_packet_status
componentstatusprotocol_stat_packet(void* tapdata, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* data, tap_flags_t flags _U_)
{
  stat_data_t*              stat_data = (stat_data_t*)tapdata;
  const tap_componentstatusprotocol_rec_t*      tap_rec   = (const tap_componentstatusprotocol_rec_t*)data;
  stat_tap_table*           table;
  stat_tap_table_item_type* msg_data;
  gint                      idx;
  guint64                   messages;
  guint64                   bytes;
  int                       i         = 0;
  double                    firstSeen = -1.0;
  double                    lastSeen  = -1.0;

  idx = str_to_val_idx(tap_rec->type_string, message_type_values);
  if (idx < 0)
    return TAP_PACKET_DONT_REDRAW;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

  /* Update packets counter */
  componentstatusprotocol_total_msgs++;
  msg_data = stat_tap_get_field_data(table, idx, MESSAGES_COLUMN);
  msg_data->value.uint_value++;
  messages = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, MESSAGES_COLUMN, msg_data);

  /* Update bytes counter */
  componentstatusprotocol_total_bytes += tap_rec->size;
  msg_data = stat_tap_get_field_data(table, idx, BYTES_COLUMN);
  msg_data->value.uint_value += tap_rec->size;
  bytes = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, BYTES_COLUMN, msg_data);

  /* Update messages and bytes share */
  while (message_type_values[i].strptr) {
    msg_data = stat_tap_get_field_data(table, i, MESSAGES_COLUMN);
    const guint m = msg_data->value.uint_value;
    msg_data = stat_tap_get_field_data(table, i, BYTES_COLUMN);
    const guint b = msg_data->value.uint_value;

    msg_data = stat_tap_get_field_data(table, i, MESSAGES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * m / (double)componentstatusprotocol_total_msgs;
    stat_tap_set_field_data(table, i, MESSAGES_SHARE_COLUMN, msg_data);

    msg_data = stat_tap_get_field_data(table, i, BYTES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * b / (double)componentstatusprotocol_total_bytes;
    stat_tap_set_field_data(table, i, BYTES_SHARE_COLUMN, msg_data);
    i++;
  }

  /* Update first seen time */
  if (pinfo->presence_flags & PINFO_HAS_TS) {
    msg_data = stat_tap_get_field_data(table, idx, FIRST_SEEN_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = MIN(msg_data->value.float_value, nstime_to_sec(&pinfo->rel_ts));
    firstSeen = msg_data->value.float_value;
    stat_tap_set_field_data(table, idx, FIRST_SEEN_COLUMN, msg_data);
  }

  /* Update last seen time */
  if (pinfo->presence_flags & PINFO_HAS_TS) {
    msg_data = stat_tap_get_field_data(table, idx, LAST_SEEN_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = MAX(msg_data->value.float_value, nstime_to_sec(&pinfo->rel_ts));
    lastSeen = msg_data->value.float_value;
    stat_tap_set_field_data(table, idx, LAST_SEEN_COLUMN, msg_data);
  }

  if ((lastSeen - firstSeen) > 0.0) {
    /* Update interval */
    msg_data = stat_tap_get_field_data(table, idx, INTERVAL_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = lastSeen - firstSeen;
    stat_tap_set_field_data(table, idx, INTERVAL_COLUMN, msg_data);

    /* Update message rate */
    msg_data = stat_tap_get_field_data(table, idx, MESSAGE_RATE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = messages / (lastSeen - firstSeen);
    stat_tap_set_field_data(table, idx, MESSAGE_RATE_COLUMN, msg_data);

    /* Update byte rate */
    msg_data = stat_tap_get_field_data(table, idx, BYTE_RATE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = bytes / (lastSeen - firstSeen);
    stat_tap_set_field_data(table, idx, BYTE_RATE_COLUMN, msg_data);
  }

  return TAP_PACKET_REDRAW;
}

static void
componentstatusprotocol_stat_reset(stat_tap_table* table)
{
  guint element;
  stat_tap_table_item_type* item_data;

  for (element = 0; element < table->num_elements; element++) {
    item_data = stat_tap_get_field_data(table, element, MESSAGES_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, MESSAGES_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, MESSAGES_SHARE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, MESSAGES_SHARE_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, BYTES_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, BYTES_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, BYTES_SHARE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, BYTES_SHARE_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, FIRST_SEEN_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = DBL_MAX;
    stat_tap_set_field_data(table, element, FIRST_SEEN_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, LAST_SEEN_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = DBL_MIN;
    stat_tap_set_field_data(table, element, LAST_SEEN_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, INTERVAL_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, INTERVAL_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, MESSAGE_RATE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, MESSAGE_RATE_COLUMN, item_data);

    item_data = stat_tap_get_field_data(table, element, BYTE_RATE_COLUMN);
    item_data->type = TABLE_ITEM_NONE;
    item_data->value.float_value = -1.0;
    stat_tap_set_field_data(table, element, BYTE_RATE_COLUMN, item_data);
  }
  componentstatusprotocol_total_msgs  = 0;
  componentstatusprotocol_total_bytes = 0;
}


/* Register the protocol with Wireshark */
void
proto_register_componentstatusprotocol(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_componentstatusprotocol,
    &ett_message_flags,
    &ett_message_sender_id,
    &ett_cspreport_association_receiver_id,
    &ett_association
  };

  static tap_param componentstatusprotocol_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui componentstatusprotocol_stat_table = {
    REGISTER_STAT_GROUP_RSERPOOL,
    "ComponentStatusProtocol Statistics",
    "componentstatusprotocol",
    "componentstatusprotocol,stat",
    componentstatusprotocol_stat_init,
    componentstatusprotocol_stat_packet,
    componentstatusprotocol_stat_reset,
    NULL,
    NULL,
    sizeof(componentstatusprotocol_stat_fields)/sizeof(stat_tap_table_item), componentstatusprotocol_stat_fields,
    sizeof(componentstatusprotocol_stat_params)/sizeof(tap_param), componentstatusprotocol_stat_params,
    NULL,
    0
  };

  /* Register the protocol name and description */
  proto_componentstatusprotocol = proto_register_protocol("Component Status Protocol", "ComponentStatusProtocol", "componentstatusprotocol");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_componentstatusprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  tap_componentstatusprotocol = register_tap("componentstatusprotocol");

  register_stat_tap_table_ui(&componentstatusprotocol_stat_table);
}

void
proto_reg_handoff_componentstatusprotocol(void)
{
  dissector_handle_t componentstatusprotocol_handle;

  componentstatusprotocol_handle = create_dissector_handle(dissect_componentstatusprotocol, proto_componentstatusprotocol);
  dissector_add_uint_with_preference("udp.port", COMPONENTSTATUSPROTOCOL_PORT, componentstatusprotocol_handle);
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
