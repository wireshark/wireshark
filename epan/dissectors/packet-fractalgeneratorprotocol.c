/* packet-fractalgeneratorprotocol.c
 * Routines for the Fractal Generator Protocol, a test application of the
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


void proto_register_fractalgeneratorprotocol(void);
void proto_reg_handoff_fractalgeneratorprotocol(void);

#define FRACTALGENERATORPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY 0x29097601


/* Initialize the protocol and registered fields */
static int proto_fractalgeneratorprotocol = -1;
static int tap_fractalgeneratorprotocol   = -1;
static int hf_message_type                = -1;
static int hf_message_flags               = -1;
static int hf_message_length              = -1;
static int hf_data_start_x                = -1;
static int hf_data_start_y                = -1;
static int hf_data_points                 = -1;
static int hf_parameter_width             = -1;
static int hf_parameter_height            = -1;
static int hf_parameter_maxiterations     = -1;
static int hf_parameter_algorithmid       = -1;
static int hf_parameter_c1real            = -1;
static int hf_parameter_c1imag            = -1;
static int hf_parameter_c2real            = -1;
static int hf_parameter_c2imag            = -1;
static int hf_parameter_n                 = -1;
static int hf_buffer                      = -1;

static guint64 fgp_total_msgs     = 0;
static guint64 fgp_total_bytes    = 0;

/* Initialize the subtree pointers */
static gint ett_fractalgeneratorprotocol = -1;

/* Dissectors for messages. This is specific to FractalGeneratorProtocol */
#define MESSAGE_TYPE_LENGTH    1
#define MESSAGE_FLAGS_LENGTH   1
#define MESSAGE_LENGTH_LENGTH  2

#define MESSAGE_TYPE_OFFSET    0
#define MESSAGE_FLAGS_OFFSET   (MESSAGE_TYPE_OFFSET    + MESSAGE_TYPE_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_FLAGS_OFFSET   + MESSAGE_FLAGS_OFFSET)
#define MESSAGE_VALUE_OFFSET   (MESSAGE_LENGTH_OFFSET  + MESSAGE_LENGTH_LENGTH)


#define DATA_STARTX_LENGTH 4
#define DATA_STARTY_LENGTH 4
#define DATA_POINTS_LENGTH 4
#define DATA_BUFFER_LENGTH 4

#define DATA_STARTX_OFFSET MESSAGE_VALUE_OFFSET
#define DATA_STARTY_OFFSET (DATA_STARTX_OFFSET + DATA_STARTX_LENGTH)
#define DATA_POINTS_OFFSET (DATA_STARTY_OFFSET + DATA_STARTY_LENGTH)
#define DATA_BUFFER_OFFSET (DATA_POINTS_OFFSET + DATA_POINTS_LENGTH)


#define PARAMETER_WIDTH_LENGTH         4
#define PARAMETER_HEIGHT_LENGTH        4
#define PARAMETER_MAXITERATIONS_LENGTH 4
#define PARAMETER_ALGORITHMID_LENGTH   4
#define PARAMETER_C1REAL_LENGTH        8
#define PARAMETER_C1IMAG_LENGTH        8
#define PARAMETER_C2REAL_LENGTH        8
#define PARAMETER_C2IMAG_LENGTH        8
#define PARAMETER_N_LENGTH             8

#define PARAMETER_WIDTH_OFFSET         MESSAGE_VALUE_OFFSET
#define PARAMETER_HEIGHT_OFFSET        (PARAMETER_WIDTH_OFFSET + PARAMETER_WIDTH_LENGTH)
#define PARAMETER_MAXITERATIONS_OFFSET (PARAMETER_HEIGHT_OFFSET + PARAMETER_HEIGHT_LENGTH)
#define PARAMETER_ALGORITHMID_OFFSET   (PARAMETER_MAXITERATIONS_OFFSET + PARAMETER_MAXITERATIONS_LENGTH)
#define PARAMETER_C1REAL_OFFSET        (PARAMETER_ALGORITHMID_OFFSET + PARAMETER_ALGORITHMID_LENGTH)
#define PARAMETER_C1IMAG_OFFSET        (PARAMETER_C1REAL_OFFSET + PARAMETER_C1REAL_LENGTH)
#define PARAMETER_C2REAL_OFFSET        (PARAMETER_C1IMAG_OFFSET + PARAMETER_C1IMAG_LENGTH)
#define PARAMETER_C2IMAG_OFFSET        (PARAMETER_C2REAL_OFFSET + PARAMETER_C2REAL_LENGTH)
#define PARAMETER_N_OFFSET             (PARAMETER_C2IMAG_OFFSET + PARAMETER_C2IMAG_LENGTH)

#define FRACTALGENERATOR_PARAMETER_MESSAGE_TYPE 0x01
#define FRACTALGENERATOR_DATA_MESSAGE_TYPE      0x02

static const value_string message_type_values[] = {
  { FRACTALGENERATOR_PARAMETER_MESSAGE_TYPE, "FractalGenerator Parameter" },
  { FRACTALGENERATOR_DATA_MESSAGE_TYPE,      "FractalGenerator Data" },
  { 0, NULL }
};

#define FGPA_MANDELBROT  1
#define FGPA_MANDELBROTN 2

static const value_string algorithmid_values[] = {
  { FGPA_MANDELBROT,  "Mandelbrot: z_{n+1} = z_n^2 + c" },
  { FGPA_MANDELBROTN, "Mandelbrot-N: z_{n+1} = z_n^N + c" },
  { 0, NULL }
};


typedef struct _tap_fgp_rec_t {
  guint8      type;
  guint16     size;
  const char* type_string;
} tap_fgp_rec_t;


static void
dissect_fgp_parameter_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  proto_tree_add_item(message_tree, hf_parameter_width,         message_tvb, PARAMETER_WIDTH_OFFSET,         PARAMETER_WIDTH_LENGTH,         ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_height,        message_tvb, PARAMETER_HEIGHT_OFFSET,        PARAMETER_HEIGHT_LENGTH,        ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_maxiterations, message_tvb, PARAMETER_MAXITERATIONS_OFFSET, PARAMETER_MAXITERATIONS_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_algorithmid,   message_tvb, PARAMETER_ALGORITHMID_OFFSET,   PARAMETER_ALGORITHMID_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_c1real,        message_tvb, PARAMETER_C1REAL_OFFSET,        PARAMETER_C1REAL_LENGTH,        ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_c1imag,        message_tvb, PARAMETER_C1IMAG_OFFSET,        PARAMETER_C1IMAG_LENGTH,        ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_c2real,        message_tvb, PARAMETER_C2REAL_OFFSET,        PARAMETER_C2REAL_LENGTH,        ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_c2imag,        message_tvb, PARAMETER_C2IMAG_OFFSET,        PARAMETER_C2IMAG_LENGTH,        ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_parameter_n,             message_tvb, PARAMETER_N_OFFSET,             PARAMETER_N_LENGTH,             ENC_BIG_ENDIAN);
}


static void
dissect_fgp_data_message(tvbuff_t *message_tvb, proto_tree *message_tree)
{
  guint16 buffer_length;

  proto_tree_add_item(message_tree, hf_data_start_x, message_tvb, DATA_STARTX_OFFSET, DATA_STARTX_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_start_y, message_tvb, DATA_STARTY_OFFSET, DATA_STARTY_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(message_tree, hf_data_points,  message_tvb, DATA_POINTS_OFFSET, DATA_POINTS_LENGTH, ENC_BIG_ENDIAN);

  buffer_length = tvb_get_ntohl(message_tvb, DATA_POINTS_OFFSET)*4;
  if (buffer_length > 0) {
    proto_tree_add_item(message_tree, hf_buffer, message_tvb, DATA_BUFFER_OFFSET, buffer_length, ENC_NA);
  }
}


static void
dissect_fgp_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *fgp_tree)
{
  tap_fgp_rec_t* tap_rec = wmem_new0(pinfo->pool, tap_fgp_rec_t);
  tap_rec->type        = tvb_get_guint8(message_tvb, MESSAGE_TYPE_OFFSET);
  tap_rec->size        = tvb_get_ntohs(message_tvb,  MESSAGE_LENGTH_OFFSET);
  tap_rec->type_string = val_to_str_const(tap_rec->type, message_type_values, "Unknown FractalGeneratorProtocol message type");
  tap_queue_packet(tap_fractalgeneratorprotocol, pinfo, tap_rec);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", tap_rec->type_string);

  proto_tree_add_item(fgp_tree, hf_message_type,   message_tvb, MESSAGE_TYPE_OFFSET,   MESSAGE_TYPE_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(fgp_tree, hf_message_flags,  message_tvb, MESSAGE_FLAGS_OFFSET,  MESSAGE_FLAGS_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(fgp_tree, hf_message_length, message_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH, ENC_BIG_ENDIAN);
  switch (tap_rec->type) {
    case FRACTALGENERATOR_PARAMETER_MESSAGE_TYPE:
      dissect_fgp_parameter_message(message_tvb, fgp_tree);
     break;
    case FRACTALGENERATOR_DATA_MESSAGE_TYPE:
      dissect_fgp_data_message(message_tvb, fgp_tree);
     break;
  }
}

static int
dissect_fractalgeneratorprotocol(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *fgp_item;
  proto_tree *fgp_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FractalGeneratorProtocol");

  /* create the fractalgeneratorprotocol protocol tree */
  fgp_item = proto_tree_add_item(tree, proto_fractalgeneratorprotocol, message_tvb, 0, -1, ENC_NA);
  fgp_tree = proto_item_add_subtree(fgp_item, ett_fractalgeneratorprotocol);

  /* dissect the message */
  dissect_fgp_message(message_tvb, pinfo, fgp_tree);
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
} fgp_stat_columns;

static stat_tap_table_item fgp_stat_fields[] = {
  { TABLE_ITEM_STRING, TAP_ALIGN_LEFT,  "FractalGeneratorProtocol Message Type", "%-25s" },
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

static void fgp_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "FractalGeneratorProtocol Statistics";
  int num_fields = sizeof(fgp_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int i = 0;
  stat_tap_table_item_type items[sizeof(fgp_stat_fields)/sizeof(stat_tap_table_item)];

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
fgp_stat_packet(void* tapdata, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* data, tap_flags_t flags _U_)
{
  stat_data_t*              stat_data = (stat_data_t*)tapdata;
  const tap_fgp_rec_t*      tap_rec   = (const tap_fgp_rec_t*)data;
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
  fgp_total_msgs++;
  msg_data = stat_tap_get_field_data(table, idx, MESSAGES_COLUMN);
  msg_data->value.uint_value++;
  messages = msg_data->value.uint_value;
  stat_tap_set_field_data(table, idx, MESSAGES_COLUMN, msg_data);

  /* Update bytes counter */
  fgp_total_bytes += tap_rec->size;
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
    msg_data->value.float_value = 100.0 * m / (double)fgp_total_msgs;
    stat_tap_set_field_data(table, i, MESSAGES_SHARE_COLUMN, msg_data);

    msg_data = stat_tap_get_field_data(table, i, BYTES_SHARE_COLUMN);
    msg_data->type = TABLE_ITEM_FLOAT;
    msg_data->value.float_value = 100.0 * b / (double)fgp_total_bytes;
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
fgp_stat_reset(stat_tap_table* table)
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
  fgp_total_msgs  = 0;
  fgp_total_bytes = 0;
}


/* Register the protocol with Wireshark */
void
proto_register_fractalgeneratorprotocol(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_message_type,            { "Type",          "fractalgeneratorprotocol.message_type",            FT_UINT8,  BASE_DEC, VALS(message_type_values), 0x0, NULL, HFILL } },
    { &hf_message_flags,           { "Flags",         "fractalgeneratorprotocol.message_flags",           FT_UINT8,  BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_message_length,          { "Length",        "fractalgeneratorprotocol.message_length",          FT_UINT16, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_data_start_x,            { "StartX",        "fractalgeneratorprotocol.data_start_x",            FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_data_start_y,            { "StartY",        "fractalgeneratorprotocol.data_start_y",            FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_data_points,             { "Points",        "fractalgeneratorprotocol.data_points",             FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_parameter_width,         { "Width",         "fractalgeneratorprotocol.parameter_width",         FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_parameter_height,        { "Height",        "fractalgeneratorprotocol.parameter_height",        FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_parameter_maxiterations, { "MaxIterations", "fractalgeneratorprotocol.parameter_maxiterations", FT_UINT32, BASE_DEC, NULL,                      0x0, NULL, HFILL } },
    { &hf_parameter_algorithmid,   { "AlgorithmID",   "fractalgeneratorprotocol.parameter_algorithmid",   FT_UINT32, BASE_DEC, VALS(algorithmid_values),  0x0, NULL, HFILL } },
    { &hf_parameter_c1real,        { "C1Real",        "fractalgeneratorprotocol.parameter_c1real",        FT_DOUBLE, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
    { &hf_parameter_c1imag,        { "C1Imag",        "fractalgeneratorprotocol.parameter_c1imag",        FT_DOUBLE, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
    { &hf_parameter_c2real,        { "C2Real",        "fractalgeneratorprotocol.parameter_c2real",        FT_DOUBLE, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
    { &hf_parameter_c2imag,        { "C2Imag",        "fractalgeneratorprotocol.parameter_c2imag",        FT_DOUBLE, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
    { &hf_parameter_n,             { "N",             "fractalgeneratorprotocol.parameter_n",             FT_DOUBLE, BASE_NONE, NULL,                     0x0, NULL, HFILL } },
    { &hf_buffer,                  { "Buffer",        "fractalgeneratorprotocol.buffer",                  FT_BYTES,  BASE_NONE, NULL,                     0x0, NULL, HFILL } },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_fractalgeneratorprotocol
  };

  static tap_param fgp_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui fgp_stat_table = {
    REGISTER_STAT_GROUP_RSERPOOL,
    "FractalGeneratorProtocol Statistics",
    "fractalgeneratorprotocol",
    "fractalgeneratorprotocol,stat",
    fgp_stat_init,
    fgp_stat_packet,
    fgp_stat_reset,
    NULL,
    NULL,
    sizeof(fgp_stat_fields)/sizeof(stat_tap_table_item), fgp_stat_fields,
    sizeof(fgp_stat_params)/sizeof(tap_param), fgp_stat_params,
    NULL,
    0
  };

  /* Register the protocol name and description */
  proto_fractalgeneratorprotocol = proto_register_protocol("Fractal Generator Protocol", "FractalGeneratorProtocol",  "fractalgeneratorprotocol");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_fractalgeneratorprotocol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  tap_fractalgeneratorprotocol = register_tap("fractalgeneratorprotocol");

  register_stat_tap_table_ui(&fgp_stat_table);
}

void
proto_reg_handoff_fractalgeneratorprotocol(void)
{
  dissector_handle_t fgp_handle;

  fgp_handle = create_dissector_handle(dissect_fractalgeneratorprotocol, proto_fractalgeneratorprotocol);
  dissector_add_uint("sctp.ppi", FRACTALGENERATORPROTOCOL_PAYLOAD_PROTOCOL_ID_LEGACY, fgp_handle);
  dissector_add_uint("sctp.ppi", FGP_PAYLOAD_PROTOCOL_ID, fgp_handle);
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
