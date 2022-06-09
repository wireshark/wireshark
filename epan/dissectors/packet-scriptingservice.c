/* packet-scriptingservice.c
 * Routines for the Scripting Service Protocol, a load distribution application
 * of the RSPLIB RSerPool implementation
 * https://www.uni-due.de/~be0001/rserpool/
 *
 * Copyright 2006-2021 by Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/stat_tap_ui.h>

void proto_register_ssprotocol(void);
void proto_reg_handoff_ssprotocol(void);

#define SSPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY 0x29097604


/* Initialize the protocol and registered fields */
static int proto_ssprotocol     = -1;
static int tap_ssprotocol       = -1;
static int hf_message_type      = -1;
static int hf_message_flags     = -1;
static int hf_message_length    = -1;
static int hf_message_status    = -1;
static int hf_message_data      = -1;
static int hf_message_reason    = -1;
static int hf_message_info      = -1;
static int hf_message_hash      = -1;
static int hf_environment_u_bit = -1;

static guint64 ssprotocol_total_msgs  = 0;
static guint64 ssprotocol_total_bytes = 0;

/* Initialize the subtree pointers */
static gint ett_ssprotocol        = -1;
static gint ett_environment_flags = -1;

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


typedef struct _tap_ssprotocol_rec_t {
  guint8      type;
  guint16     size;
  const char* type_string;
} tap_ssprotocol_rec_t;


static guint
dissect_ssprotocol_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *ssprotocol_tree)
{
  proto_item* flags_item;
  proto_tree* flags_tree;
  guint16     data_length;
  guint16     info_length;
  guint       total_length;

  tap_ssprotocol_rec_t* tap_rec = wmem_new0(pinfo->pool, tap_ssprotocol_rec_t);
  tap_rec->type        = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  tap_rec->size        = tvb_get_ntohs(message_tvb,  MESSAGE_LENGTH_OFFSET);
  tap_rec->type_string = val_to_str_const(tap_rec->type, message_type_values, "Unknown SSP message type");
  tap_queue_packet(tap_ssprotocol, pinfo, tap_rec);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", tap_rec->type_string);

  proto_tree_add_item(ssprotocol_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   ENC_BIG_ENDIAN);
  flags_item = proto_tree_add_item(ssprotocol_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(ssprotocol_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  total_length = MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH;
  switch (tap_rec->type) {
    case SS_KEEPALIVE_ACK_TYPE:
    case SS_STATUS_TYPE:
      info_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - MESSAGE_STATUS_OFFSET;
      if (info_length == MESSAGE_STATUS_LENGTH) {
        proto_tree_add_item(ssprotocol_tree, hf_message_status, message_tvb, MESSAGE_STATUS_OFFSET, MESSAGE_STATUS_LENGTH, ENC_BIG_ENDIAN);
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
        proto_tree_add_item(ssprotocol_tree, hf_message_info, message_tvb, MESSAGE_RDY_INFO_OFFSET, info_length, ENC_ASCII);
        total_length += info_length;
      }
      break;
    case SS_NOTREADY_TYPE:
      info_length = tvb_get_ntohs(message_tvb, MESSAGE_LENGTH_OFFSET) - MESSAGE_NOTRDY_INFO_OFFSET;
      if (info_length > 0) {
        proto_tree_add_item(ssprotocol_tree, hf_message_reason, message_tvb, MESSAGE_NOTRDY_REASON_OFFSET, MESSAGE_NOTRDY_REASON_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(ssprotocol_tree, hf_message_info,   message_tvb, MESSAGE_NOTRDY_INFO_OFFSET, info_length, ENC_ASCII);
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
dissect_ssprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ssprotocol_item;
  proto_tree *ssprotocol_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSP");

  /* create the ssprotocol protocol tree */
  ssprotocol_item = proto_tree_add_item(tree, proto_ssprotocol, message_tvb, 0, -1, ENC_NA);
  ssprotocol_tree = proto_item_add_subtree(ssprotocol_item, ett_ssprotocol);

  /* dissect the message */
  return dissect_ssprotocol_message(message_tvb, pinfo, ssprotocol_tree);
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
} ssprotocol_stat_columns;

static stat_tap_table_item ssprotocol_stat_fields[] = {
  { TABLE_ITEM_STRING, TAP_ALIGN_LEFT,  "ScriptingServiceProtocol Message Type", "%-25s" },
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

static void ssprotocol_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "ScriptingServiceProtocol Statistics";
  int num_fields = sizeof(ssprotocol_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int i = 0;
  stat_tap_table_item_type items[sizeof(ssprotocol_stat_fields)/sizeof(stat_tap_table_item)];

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
ssprotocol_stat_packet(void* tapdata, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* data, tap_flags_t flags _U_)
{
  stat_data_t*                stat_data = (stat_data_t*)tapdata;
  const tap_ssprotocol_rec_t* tap_rec   = (const tap_ssprotocol_rec_t*)data;
  stat_tap_table*             table;
  stat_tap_table_item_type*   msg_data;
  gint                        idx;
  guint64                     messages;
  guint64                     bytes;
  int                         i         = 0;
  double                      firstSeen = -1.0;
  double                      lastSeen  = -1.0;

  idx = str_to_val_idx(tap_rec->type_string, message_type_values);
  if (idx < 0)
    return TAP_PACKET_DONT_REDRAW;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

  /* Update packets counter */
  ssprotocol_total_msgs++;
  msg_data = stat_tap_get_field_data(table, idx, MESSAGES_COLUMN);
  msg_data->value.uint_value++;
  messages = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, MESSAGES_COLUMN, msg_data);

  /* Update bytes counter */
  ssprotocol_total_bytes += tap_rec->size;
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
    msg_data->value.float_value = 100.0 * m / (double)ssprotocol_total_msgs;
    stat_tap_set_field_data(table, i, MESSAGES_SHARE_COLUMN, msg_data);

    msg_data = stat_tap_get_field_data(table, i, BYTES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * b / (double)ssprotocol_total_bytes;
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
ssprotocol_stat_reset(stat_tap_table* table)
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
  ssprotocol_total_msgs  = 0;
  ssprotocol_total_bytes = 0;
}


/* Register the protocol */
void
proto_register_ssprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,      { "Type",   "ssp.message_type",   FT_UINT8,  BASE_DEC,  VALS(message_type_values),  0x0, NULL, HFILL } },
    { &hf_message_flags,     { "Flags",  "ssp.message_flags",  FT_UINT8,  BASE_DEC,  NULL,                       0x0, NULL, HFILL } },
    { &hf_message_length,    { "Length", "ssp.message_length", FT_UINT16, BASE_DEC,  NULL,                       0x0, NULL, HFILL } },
    { &hf_message_status,    { "Status", "ssp.message_status", FT_UINT32, BASE_DEC,  NULL,                       0x0, NULL, HFILL } },
    { &hf_message_reason,    { "Reason", "ssp.message_reason", FT_UINT32, BASE_DEC,  VALS(notrdy_reason_values), 0x0, NULL, HFILL } },
    { &hf_message_info,      { "Info",   "ssp.message_info",   FT_STRING, BASE_NONE, NULL,                       0x0, NULL, HFILL } },
    { &hf_message_data,      { "Data",   "ssp.message_data",   FT_BYTES,  BASE_NONE, NULL,                       0x0, NULL, HFILL } },
    { &hf_message_hash,      { "Hash",   "ssp.message_hash",   FT_BYTES,  BASE_NONE, NULL,                       0x0, NULL, HFILL } },
    { &hf_environment_u_bit, { "U-Bit",  "ssp.environment_u_bit", FT_BOOLEAN, 8,TFS(&environment_u_bit), SSP_ENVIRONMENT_U_BIT, NULL, HFILL } }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_ssprotocol,
    &ett_environment_flags
  };

  static tap_param ssprotocol_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui ssprotocol_stat_table = {
    REGISTER_STAT_GROUP_RSERPOOL,
    "ScriptingServiceProtocol Statistics",
    "ssprotocol",
    "ssprotocol,stat",
    ssprotocol_stat_init,
    ssprotocol_stat_packet,
    ssprotocol_stat_reset,
    NULL,
    NULL,
    sizeof(ssprotocol_stat_fields)/sizeof(stat_tap_table_item), ssprotocol_stat_fields,
    sizeof(ssprotocol_stat_params)/sizeof(tap_param), ssprotocol_stat_params,
    NULL,
    0
  };

  /* Register the protocol name and description */
  proto_ssprotocol = proto_register_protocol("Scripting Service Protocol", "SSP", "ssp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_ssprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  tap_ssprotocol = register_tap("ssprotocol");

  register_stat_tap_table_ui(&ssprotocol_stat_table);
}

void
proto_reg_handoff_ssprotocol(void)
{
  dissector_handle_t ssprotocol_handle;

  ssprotocol_handle = create_dissector_handle(dissect_ssprotocol, proto_ssprotocol);
  dissector_add_uint("sctp.ppi", SSPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY, ssprotocol_handle);
  dissector_add_uint("sctp.ppi", SSP_PAYLOAD_PROTOCOL_ID, ssprotocol_handle);
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
