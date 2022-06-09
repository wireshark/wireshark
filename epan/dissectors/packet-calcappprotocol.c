/* packet-calcappprotocol.c
 * Routines for the Calculation Application Protocol, a test application of the
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

void proto_register_calcappprotocol(void);
void proto_reg_handoff_calcappprotocol(void);

#define CALCAPPPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY 0x29097603


/* Initialize the protocol and registered fields */
static int proto_calcappprotocol = -1;
static int tap_calcappprotocol   = -1;
static int hf_message_type       = -1;
static int hf_message_flags      = -1;
static int hf_message_length     = -1;
static int hf_message_jobid      = -1;
static int hf_message_jobsize    = -1;
static int hf_message_completed  = -1;

static guint64 calcappprotocol_total_msgs     = 0;
static guint64 calcappprotocol_total_bytes    = 0;

/* Initialize the subtree pointers */
static gint ett_calcappprotocol = -1;

/* Dissectors for messages. This is specific to CalcAppProtocol */
#define MESSAGE_TYPE_LENGTH      1
#define MESSAGE_FLAGS_LENGTH     1
#define MESSAGE_LENGTH_LENGTH    2
#define MESSAGE_JOBID_LENGTH     4
#define MESSAGE_JOBSIZE_LENGTH   8
#define MESSAGE_COMPLETED_LENGTH 8

#define MESSAGE_TYPE_OFFSET      0
#define MESSAGE_FLAGS_OFFSET     (MESSAGE_TYPE_OFFSET    + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET    (MESSAGE_FLAGS_OFFSET   + MESSAGE_FLAGS_LENGTH)
#define MESSAGE_JOBID_OFFSET     (MESSAGE_LENGTH_OFFSET  + MESSAGE_LENGTH_LENGTH)
#define MESSAGE_JOBSIZE_OFFSET   (MESSAGE_JOBID_OFFSET   + MESSAGE_JOBID_OFFSET)
#define MESSAGE_COMPLETED_OFFSET (MESSAGE_JOBSIZE_OFFSET + MESSAGE_JOBSIZE_OFFSET)


#define CALCAPP_REQUEST_MESSAGE_TYPE       1
#define CALCAPP_ACCEPT_MESSAGE_TYPE        2
#define CALCAPP_REJECT_MESSAGE_TYPE        3
#define CALCAPP_ABORT_MESSAGE_TYPE         4
#define CALCAPP_COMPLETE_MESSAGE_TYPE      5
#define CALCAPP_KEEPALIVE_MESSAGE_TYPE     6
#define CALCAPP_KEEPALIVE_ACK_MESSAGE_TYPE 7


static const value_string message_type_values[] = {
  { CALCAPP_REQUEST_MESSAGE_TYPE,        "CalcApp Request" },
  { CALCAPP_ACCEPT_MESSAGE_TYPE,         "CalcApp Accept" },
  { CALCAPP_REJECT_MESSAGE_TYPE,         "CalcApp Reject" },
  { CALCAPP_ABORT_MESSAGE_TYPE,          "CalcApp Abort" },
  { CALCAPP_COMPLETE_MESSAGE_TYPE,       "CalcApp Complete" },
  { CALCAPP_KEEPALIVE_MESSAGE_TYPE,      "CalcApp Keep-Alive" },
  { CALCAPP_KEEPALIVE_ACK_MESSAGE_TYPE,  "CalcApp Keep-Alive Ack" },
  { 0, NULL }
};


typedef struct _tap_calcappprotocol_rec_t {
  guint8      type;
  guint16     size;
  const char* type_string;
} tap_calcappprotocol_rec_t;


static void
dissect_calcappprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *calcappprotocol_tree)
{
  tap_calcappprotocol_rec_t* tap_rec = wmem_new0(pinfo->pool, tap_calcappprotocol_rec_t);
  tap_rec->type        = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  tap_rec->size        = tvb_get_ntohs(message_tvb,  MESSAGE_LENGTH_OFFSET);
  tap_rec->type_string = val_to_str_const(tap_rec->type, message_type_values, "Unknown CalcAppProtocol message type");
  tap_queue_packet(tap_calcappprotocol, pinfo, tap_rec);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", tap_rec->type_string);

  proto_tree_add_item(calcappprotocol_tree, hf_message_type,      message_tvb, MESSAGE_TYPE_OFFSET,      MESSAGE_TYPE_LENGTH,      ENC_BIG_ENDIAN);
  proto_tree_add_item(calcappprotocol_tree, hf_message_flags,     message_tvb, MESSAGE_FLAGS_OFFSET,     MESSAGE_FLAGS_LENGTH,     ENC_BIG_ENDIAN);
  proto_tree_add_item(calcappprotocol_tree, hf_message_length,    message_tvb, MESSAGE_LENGTH_OFFSET,    MESSAGE_LENGTH_LENGTH,    ENC_BIG_ENDIAN);
  proto_tree_add_item(calcappprotocol_tree, hf_message_jobid,     message_tvb, MESSAGE_JOBID_OFFSET,     MESSAGE_JOBID_LENGTH,     ENC_BIG_ENDIAN);
  proto_tree_add_item(calcappprotocol_tree, hf_message_jobsize,   message_tvb, MESSAGE_JOBSIZE_OFFSET,   MESSAGE_JOBSIZE_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(calcappprotocol_tree, hf_message_completed, message_tvb, MESSAGE_COMPLETED_OFFSET, MESSAGE_COMPLETED_LENGTH, ENC_BIG_ENDIAN);
}


static int
dissect_calcappprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *calcappprotocol_item;
  proto_tree *calcappprotocol_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CalcAppProtocol");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the calcappprotocol protocol tree */
    calcappprotocol_item = proto_tree_add_item(tree, proto_calcappprotocol, message_tvb, 0, -1, ENC_NA);
    calcappprotocol_tree = proto_item_add_subtree(calcappprotocol_item, ett_calcappprotocol);
  } else {
    calcappprotocol_tree = NULL;
  };
  /* dissect the message */
  dissect_calcappprotocol_message(message_tvb, pinfo, calcappprotocol_tree);
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
} calcappprotocol_stat_columns;

static stat_tap_table_item calcappprotocol_stat_fields[] = {
  { TABLE_ITEM_STRING, TAP_ALIGN_LEFT,  "CalcAppProtocol Message Type", "%-25s" },
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

static void calcappprotocol_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "CalcAppProtocol Statistics";
  int num_fields = sizeof(calcappprotocol_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int i = 0;
  stat_tap_table_item_type items[sizeof(calcappprotocol_stat_fields)/sizeof(stat_tap_table_item)];

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
calcappprotocol_stat_packet(void* tapdata, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* data, tap_flags_t flags _U_)
{
  stat_data_t*                     stat_data = (stat_data_t*)tapdata;
  const tap_calcappprotocol_rec_t* tap_rec   = (const tap_calcappprotocol_rec_t*)data;
  stat_tap_table*                  table;
  stat_tap_table_item_type*        msg_data;
  gint                             idx;
  guint64                          messages;
  guint64                          bytes;
  int                              i         = 0;
  double                           firstSeen = -1.0;
  double                           lastSeen  = -1.0;

  idx = str_to_val_idx(tap_rec->type_string, message_type_values);
  if (idx < 0)
    return TAP_PACKET_DONT_REDRAW;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

  /* Update packets counter */
  calcappprotocol_total_msgs++;
  msg_data = stat_tap_get_field_data(table, idx, MESSAGES_COLUMN);
  msg_data->value.uint_value++;
  messages = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, MESSAGES_COLUMN, msg_data);

  /* Update bytes counter */
  calcappprotocol_total_bytes += tap_rec->size;
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
    msg_data->value.float_value = 100.0 * m / (double)calcappprotocol_total_msgs;
    stat_tap_set_field_data(table, i, MESSAGES_SHARE_COLUMN, msg_data);

    msg_data = stat_tap_get_field_data(table, i, BYTES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * b / (double)calcappprotocol_total_bytes;
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
calcappprotocol_stat_reset(stat_tap_table* table)
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
  calcappprotocol_total_msgs  = 0;
  calcappprotocol_total_bytes = 0;
}


/* Register the protocol with Wireshark */
void
proto_register_calcappprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,      { "Type",      "calcappprotocol.message_type",      FT_UINT8,  BASE_DEC, VALS(message_type_values), 0x0, NULL, HFILL } },
    { &hf_message_flags,     { "Flags",     "calcappprotocol.message_flags",     FT_UINT8,  BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_message_length,    { "Length",    "calcappprotocol.message_length",    FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_message_jobid,     { "JobID",     "calcappprotocol.message_jobid",     FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_message_jobsize,   { "JobSize",   "calcappprotocol.message_jobsize",   FT_UINT64, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_message_completed, { "Completed", "calcappprotocol.message_completed", FT_UINT64, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_calcappprotocol
  };

  static tap_param calcappprotocol_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui calcappprotocol_stat_table = {
    REGISTER_STAT_GROUP_RSERPOOL,
    "CalcAppProtocol Statistics",
    "calcappprotocol",
    "calcappprotocol,stat",
    calcappprotocol_stat_init,
    calcappprotocol_stat_packet,
    calcappprotocol_stat_reset,
    NULL,
    NULL,
    sizeof(calcappprotocol_stat_fields)/sizeof(stat_tap_table_item), calcappprotocol_stat_fields,
    sizeof(calcappprotocol_stat_params)/sizeof(tap_param), calcappprotocol_stat_params,
    NULL,
    0
  };

  /* Register the protocol name and description */
  proto_calcappprotocol = proto_register_protocol("Calculation Application Protocol", "CalcAppProtocol", "calcappprotocol");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_calcappprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  tap_calcappprotocol = register_tap("calcappprotocol");

  register_stat_tap_table_ui(&calcappprotocol_stat_table);
}

void
proto_reg_handoff_calcappprotocol(void)
{
  dissector_handle_t calcappprotocol_handle;

  calcappprotocol_handle = create_dissector_handle(dissect_calcappprotocol, proto_calcappprotocol);
  dissector_add_uint("sctp.ppi", CALCAPPPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY, calcappprotocol_handle);
  dissector_add_uint("sctp.ppi", CALCAPP_PAYLOAD_PROTOCOL_ID, calcappprotocol_handle);
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
