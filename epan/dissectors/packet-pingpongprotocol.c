/* packet-pingpongprotocol.c
 * Routines for the Ping Pong Protocol, a test application of the
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
#include <epan/sctpppids.h>
#include <epan/stat_tap_ui.h>


#define PINGPONGPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY 0x29097602

void proto_register_pingpongprotocol(void);
void proto_reg_handoff_pingpongprotocol(void);

/* Initialize the protocol and registered fields */
static int proto_pingpongprotocol         = -1;
static int tap_pingpongprotocol           = -1;
static int ett_pingpongprotocol           = -1;
static int hf_message_type                = -1;
static int hf_message_flags               = -1;
static int hf_message_length              = -1;
static int hf_ping_messageno              = -1;
static int hf_ping_data                   = -1;
static int hf_pong_messageno              = -1;
static int hf_pong_replyno                = -1;
static int hf_pong_data                   = -1;

static guint64 pingpongprotocol_total_msgs  = 0;
static guint64 pingpongprotocol_total_bytes = 0;

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


typedef struct _tap_pingpongprotocol_rec_t {
  guint8      type;
  guint16     size;
  const char* type_string;
} tap_pingpongprotocol_rec_t;


static void
dissect_pingpongprotocol_ping_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint16 ping_data_length;

  proto_tree_add_item(message_tree, hf_ping_messageno, message_tvb, PING_MESSAGENO_OFFSET, PING_MESSAGENO_LENGTH, ENC_BIG_ENDIAN);

  ping_data_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - PING_DATA_OFFSET;
  if (ping_data_length > 0)
    proto_tree_add_item(message_tree, hf_ping_data, message_tvb, PING_DATA_OFFSET, ping_data_length, ENC_NA);
}

static void
dissect_pingpongprotocol_pong_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint16 pong_data_length;

  proto_tree_add_item(message_tree, hf_pong_messageno, message_tvb, PONG_MESSAGENO_OFFSET, PONG_MESSAGENO_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_pong_replyno,   message_tvb, PONG_REPLYNO_OFFSET,   PONG_REPLYNO_LENGTH,   ENC_BIG_ENDIAN);

  pong_data_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - PONG_DATA_OFFSET;
  if (pong_data_length > 0) {
    proto_tree_add_item(message_tree, hf_pong_data, message_tvb, PONG_DATA_OFFSET, pong_data_length, ENC_NA);
  }
}


static void
dissect_pingpongprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *pingpongprotocol_tree)
{
  tap_pingpongprotocol_rec_t* tap_rec = wmem_new0(pinfo->pool, tap_pingpongprotocol_rec_t);
  tap_rec->type        = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  tap_rec->size        = tvb_get_ntohs(message_tvb,  MESSAGE_LENGTH_OFFSET);
  tap_rec->type_string = val_to_str_const(tap_rec->type, message_type_values, "Unknown PingPongProtocol message type");
  tap_queue_packet(tap_pingpongprotocol, pinfo, tap_rec);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", tap_rec->type_string);

  proto_tree_add_item(pingpongprotocol_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(pingpongprotocol_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(pingpongprotocol_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  switch (tap_rec->type) {
    case PINGPONG_PING_MESSAGE_TYPE:
      dissect_pingpongprotocol_ping_message(message_tvb, pingpongprotocol_tree);
     break;
    case PINGPONG_PONG_MESSAGE_TYPE:
      dissect_pingpongprotocol_pong_message(message_tvb, pingpongprotocol_tree);
     break;
  }
}

static int
dissect_pingpongprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *pingpongprotocol_item;
  proto_tree *pingpongprotocol_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PingPongProtocol");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the pingpongprotocol protocol tree */
    pingpongprotocol_item = proto_tree_add_item(tree, proto_pingpongprotocol, message_tvb, 0, -1, ENC_NA);
    pingpongprotocol_tree = proto_item_add_subtree(pingpongprotocol_item, ett_pingpongprotocol);
  } else {
    pingpongprotocol_tree = NULL;
  };
  /* dissect the message */
  dissect_pingpongprotocol_message(message_tvb, pinfo, pingpongprotocol_tree);
  return(TRUE);
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
} pingpongprotocol_stat_columns;

static stat_tap_table_item pingpongprotocol_stat_fields[] = {
  { TABLE_ITEM_STRING, TAP_ALIGN_LEFT,  "PingPongProtocol Message Type", "%-25s" },
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

static void pingpongprotocol_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "PingPongProtocol Statistics";
  int num_fields = sizeof(pingpongprotocol_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int i = 0;
  stat_tap_table_item_type items[sizeof(pingpongprotocol_stat_fields)/sizeof(stat_tap_table_item)];

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
pingpongprotocol_stat_packet(void* tapdata, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* data, tap_flags_t flags _U_)
{
  stat_data_t*                      stat_data = (stat_data_t*)tapdata;
  const tap_pingpongprotocol_rec_t* tap_rec   = (const tap_pingpongprotocol_rec_t*)data;
  stat_tap_table*                   table;
  stat_tap_table_item_type*         msg_data;
  gint                              idx;
  guint64                           messages;
  guint64                           bytes;
  int                               i         = 0;
  double                            firstSeen = -1.0;
  double                            lastSeen  = -1.0;

  idx = str_to_val_idx(tap_rec->type_string, message_type_values);
  if (idx < 0)
    return TAP_PACKET_DONT_REDRAW;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

  /* Update packets counter */
  pingpongprotocol_total_msgs++;
  msg_data = stat_tap_get_field_data(table, idx, MESSAGES_COLUMN);
  msg_data->value.uint_value++;
  messages = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, MESSAGES_COLUMN, msg_data);

  /* Update bytes counter */
  pingpongprotocol_total_bytes += tap_rec->size;
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
    msg_data->value.float_value = 100.0 * m / (double)pingpongprotocol_total_msgs;
    stat_tap_set_field_data(table, i, MESSAGES_SHARE_COLUMN, msg_data);

    msg_data = stat_tap_get_field_data(table, i, BYTES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * b / (double)pingpongprotocol_total_bytes;
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
pingpongprotocol_stat_reset(stat_tap_table* table)
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
  pingpongprotocol_total_msgs  = 0;
  pingpongprotocol_total_bytes = 0;
}


/* Register the protocol with Wireshark */
void
proto_register_pingpongprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,   { "Type",      "pingpongprotocol.message_type",   FT_UINT8,  BASE_DEC,  VALS(message_type_values), 0x0, NULL, HFILL } },
    { &hf_message_flags,  { "Flags",     "pingpongprotocol.message_flags",  FT_UINT8,  BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
    { &hf_message_length, { "Length",    "pingpongprotocol.message_length", FT_UINT16, BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
    { &hf_ping_messageno, { "MessageNo", "pingpongprotocol.ping_messageno", FT_UINT64, BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
    { &hf_ping_data,      { "Ping_Data", "pingpongprotocol.ping_data",      FT_BYTES,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
    { &hf_pong_messageno, { "MessageNo", "pingpongprotocol.pong_messageno", FT_UINT64, BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
    { &hf_pong_replyno,   { "ReplyNo",   "pingpongprotocol.pong_replyno",   FT_UINT64, BASE_DEC,  NULL,                      0x0, NULL, HFILL } },
    { &hf_pong_data,      { "Pong_Data", "pingpongprotocol.pong_data",      FT_BYTES,  BASE_NONE, NULL,                      0x0, NULL, HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_pingpongprotocol
  };

  static tap_param pingpongprotocol_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui pingpongprotocol_stat_table = {
    REGISTER_STAT_GROUP_RSERPOOL,
    "PingPongProtocol Statistics",
    "pingpongprotocol",
    "pingpongprotocol,stat",
    pingpongprotocol_stat_init,
    pingpongprotocol_stat_packet,
    pingpongprotocol_stat_reset,
    NULL,
    NULL,
    sizeof(pingpongprotocol_stat_fields)/sizeof(stat_tap_table_item), pingpongprotocol_stat_fields,
    sizeof(pingpongprotocol_stat_params)/sizeof(tap_param), pingpongprotocol_stat_params,
    NULL,
    0
  };

  /* Register the protocol name and description */
  proto_pingpongprotocol = proto_register_protocol("Ping Pong Protocol", "PingPongProtocol",  "pingpongprotocol");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_pingpongprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  tap_pingpongprotocol = register_tap("pingpongprotocol");

  register_stat_tap_table_ui(&pingpongprotocol_stat_table);
}

void
proto_reg_handoff_pingpongprotocol(void)
{
  dissector_handle_t pingpongprotocol_handle;

  pingpongprotocol_handle = create_dissector_handle(dissect_pingpongprotocol, proto_pingpongprotocol);
  dissector_add_uint("sctp.ppi", PINGPONGPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY, pingpongprotocol_handle);
  dissector_add_uint("sctp.ppi", PPP_PAYLOAD_PROTOCOL_ID, pingpongprotocol_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
