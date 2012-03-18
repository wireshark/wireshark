/* packet-hartip.c
 * Routines for HART-IP packet dissection
 * Copyright 2012, Bill Schiller <bill.schiller@emerson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mbtcp.c
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>


static dissector_handle_t hartip_handle;


static int proto_hartip = -1;
static int hf_hartip_hdr_version = -1;
static int hf_hartip_hdr_message_id = -1;
static int hf_hartip_hdr_message_type = -1;
static int hf_hartip_hdr_status = -1;
static int hf_hartip_hdr_transaction_id = -1;
static int hf_hartip_hdr_msg_length = -1;

static int hf_hartip_data = -1;
static int hf_hartip_master_type = -1;
static int hf_hartip_inactivity_close_timer = -1;
static int hf_hartip_error_code = -1;

static int hf_hartip_pt_preambles = -1;
static int hf_hartip_pt_delimiter = -1;
static int hf_hartip_pt_short_addr = -1;
static int hf_hartip_pt_long_addr = -1;
static int hf_hartip_pt_command = -1;
static int hf_hartip_pt_length = -1;
static int hf_hartip_pt_response_code = -1;
static int hf_hartip_pt_device_status = -1;
static int hf_hartip_pt_payload = -1;
static int hf_hartip_pt_checksum = -1;

static gint ett_hartip = -1;
static gint ett_hartip_hdr = -1;
static gint ett_hartip_body = -1;

/* Command 0 response */
static int hf_hartip_pt_rsp_expansion_code = -1;
static int hf_hartip_pt_rsp_expanded_device_type = -1;
static int hf_hartip_pt_rsp_req_min_preambles = -1;
static int hf_hartip_pt_rsp_hart_protocol_major_rev = -1;
static int hf_hartip_pt_rsp_device_rev = -1;
static int hf_hartip_pt_rsp_software_rev = -1;
static int hf_hartip_pt_rsp_hardware_rev_physical_signal = -1;
static int hf_hartip_pt_rsp_flage = -1;
static int hf_hartip_pt_rsp_device_id = -1;
static int hf_hartip_pt_rsp_rsp_min_preambles = -1;
static int hf_hartip_pt_rsp_max_device_variables = -1;
static int hf_hartip_pt_rsp_configuration_change_counter = -1;
static int hf_hartip_pt_rsp_extended_device_status = -1;
static int hf_hartip_pt_rsp_manufacturer_Identification_code = -1;
static int hf_hartip_pt_rsp_private_label = -1;
static int hf_hartip_pt_rsp_device_profile = -1;

/* Command 2 response */
static int hf_hartip_pt_rsp_pv_percent_range = -1;

/* Command 3 response */
static int hf_hartip_pt_rsp_pv_loop_current = -1;
static int hf_hartip_pt_rsp_pv_units = -1;
static int hf_hartip_pt_rsp_pv = -1;
static int hf_hartip_pt_rsp_sv_units = -1;
static int hf_hartip_pt_rsp_sv = -1;
static int hf_hartip_pt_rsp_tv_units = -1;
static int hf_hartip_pt_rsp_tv = -1;
static int hf_hartip_pt_rsp_qv_units = -1;
static int hf_hartip_pt_rsp_qv = -1;

/* Command 9 response */
static int hf_hartip_pt_rsp_slot0_device_var = -1;
static int hf_hartip_pt_rsp_slot0_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot0_units = -1;
static int hf_hartip_pt_rsp_slot0_device_var_value = -1;
static int hf_hartip_pt_rsp_slot0_device_var_status = -1;

static int hf_hartip_pt_rsp_slot1_device_var = -1;
static int hf_hartip_pt_rsp_slot1_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot1_units = -1;
static int hf_hartip_pt_rsp_slot1_device_var_value = -1;
static int hf_hartip_pt_rsp_slot1_device_var_status = -1;

static int hf_hartip_pt_rsp_slot2_device_var = -1;
static int hf_hartip_pt_rsp_slot2_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot2_units = -1;
static int hf_hartip_pt_rsp_slot2_device_var_value = -1;
static int hf_hartip_pt_rsp_slot2_device_var_status = -1;

static int hf_hartip_pt_rsp_slot3_device_var = -1;
static int hf_hartip_pt_rsp_slot3_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot3_units = -1;
static int hf_hartip_pt_rsp_slot3_device_var_value = -1;
static int hf_hartip_pt_rsp_slot3_device_var_status = -1;

static int hf_hartip_pt_rsp_slot4_device_var = -1;
static int hf_hartip_pt_rsp_slot4_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot4_units = -1;
static int hf_hartip_pt_rsp_slot4_device_var_value = -1;
static int hf_hartip_pt_rsp_slot4_device_var_status = -1;

static int hf_hartip_pt_rsp_slot5_device_var = -1;
static int hf_hartip_pt_rsp_slot5_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot5_units = -1;
static int hf_hartip_pt_rsp_slot5_device_var_value = -1;
static int hf_hartip_pt_rsp_slot5_device_var_status = -1;

static int hf_hartip_pt_rsp_slot6_device_var = -1;
static int hf_hartip_pt_rsp_slot6_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot6_units = -1;
static int hf_hartip_pt_rsp_slot6_device_var_value = -1;
static int hf_hartip_pt_rsp_slot6_device_var_status = -1;

static int hf_hartip_pt_rsp_slot7_device_var = -1;
static int hf_hartip_pt_rsp_slot7_device_var_classify = -1;
static int hf_hartip_pt_rsp_slot7_units = -1;
static int hf_hartip_pt_rsp_slot7_device_var_value = -1;
static int hf_hartip_pt_rsp_slot7_device_var_status = -1;

static int hf_hartip_pt_rsp_slot0_timestamp = -1;

/* Command 13 response */
static int hf_hartip_pt_rsp_packed_descriptor = -1;
static int hf_hartip_pt_rsp_day = -1;
static int hf_hartip_pt_rsp_month = -1;
static int hf_hartip_pt_rsp_year = -1;

/* response Tag */
static int hf_hartip_pt_rsp_tag = -1;

/* response Message */
static int hf_hartip_pt_rsp_message = -1;

/* Command 48 response */
static int hf_hartip_pt_rsp_device_sp_status = -1;
static int hf_hartip_pt_rsp_device_op_mode = -1;
static int hf_hartip_pt_rsp_standardized_status_0 = -1;
static int hf_hartip_pt_rsp_standardized_status_1 = -1;
static int hf_hartip_pt_rsp_analog_channel_saturated = -1;
static int hf_hartip_pt_rsp_standardized_status_2 = -1;
static int hf_hartip_pt_rsp_standardized_status_3 = -1;
static int hf_hartip_pt_rsp_analog_channel_fixed = -1;

#define HARTIP_HEADER_LENGTH     8
#define HARTIP_PORT           5094

/* HARTIP header */
typedef struct _hartip_hdr {
  guint8   version;
  guint8   message_type;
  guint8   message_id;
  guint8   status;
  guint16  transaction_id;
  guint16  length;
} hartip_hdr;

/* Message IDs */
#define SESSION_INITIATE_ID       0
#define SESSION_CLOSE_ID          1
#define KEEP_ALIVE_ID             2
#define PASS_THROUGH_ID           3

/* Message types */
#define REQUEST_MSG_TYPE       0
#define RESPONSE_MSG_TYPE      1
#define ERROR_MSG_TYPE         2


static const value_string hartip_message_id_values[] = {
  { SESSION_INITIATE_ID,     "Session Initiate" },
  { SESSION_CLOSE_ID,        "Session Close" },
  { KEEP_ALIVE_ID,           "Keep Alive" },
  { PASS_THROUGH_ID,         "Pass Through" },
  { 0, NULL }
};

static const value_string hartip_message_type_values[] = {
  { REQUEST_MSG_TYPE,        "Request" },
  { RESPONSE_MSG_TYPE,       "Response" },
  { ERROR_MSG_TYPE,          "Error" },
  { 0, NULL }
};

/* Host types */
#define SECONDARY_MASTER_TYPE    0
#define PRIMARY_MASTER_TYPE      1

static const value_string hartip_master_type_values[] = {
  { SECONDARY_MASTER_TYPE,      "Secondary Host" },
  { PRIMARY_MASTER_TYPE,        "Primary Host" },
  { 0, NULL }
};


/* Error Codes */
#define SESSION_CLOSED_ERROR                0
#define PRIMARY_SESSION_UNAVAILABLE_ERROR   1
#define SERVICE_UNAVAILABLE_ERROR           2

static const value_string hartip_error_code_values[] = {
  { SESSION_CLOSED_ERROR,              "Session closed" },
  { PRIMARY_SESSION_UNAVAILABLE_ERROR, "Primary session unavailable" },
  { SERVICE_UNAVAILABLE_ERROR,         "Service unavailable" },
  { 0, NULL }
};


/* Handle for statistics tap. */
static int hartip_tap = -1;

/* Structure used for passing data for statistics processing. */
typedef struct _hartip_tap_info {
  gint8  message_type;
  gint8  message_id;
} hartip_tap_info;

/* Names of items in statistics tree. */
static const gchar* st_str_packets   = "Total HART_IP Packets";
static const gchar* st_str_requests  = "Request Packets";
static const gchar* st_str_responses = "Response Packets";
static const gchar* st_str_errors    = "Error Packets";

/* Handles of items in statistics tree. */
static int st_node_packets = -1;
static int st_node_requests = -1;
static int st_node_responses = -1;
static int st_node_errors = -1;

static void
hartip_stats_tree_init(stats_tree* st) {
  st_node_packets   = stats_tree_create_node(st, st_str_packets, 0, TRUE);
  st_node_requests  = stats_tree_create_pivot(st, st_str_requests, st_node_packets);
  st_node_responses = stats_tree_create_node(st, st_str_responses, st_node_packets, TRUE);
  st_node_errors    = stats_tree_create_node(st, st_str_errors, st_node_packets, TRUE);
}

static int
hartip_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p) {

  const hartip_tap_info *tapinfo = p;
  const gchar           *message_type_node_str, *message_id_node_str;
  int                    message_type_node;

  switch (tapinfo->message_type) {
  case REQUEST_MSG_TYPE:
    message_type_node_str = st_str_requests;
    message_type_node     = st_node_requests;
    break;
  case RESPONSE_MSG_TYPE:
    message_type_node_str = st_str_responses;
    message_type_node     = st_node_responses;
    break;
  case ERROR_MSG_TYPE:
    message_type_node_str = st_str_errors;
    message_type_node     = st_node_errors;
    break;
  default:
    return 0;  /* Don't want to track invalid messages for now. */
  }

  message_id_node_str = val_to_str(tapinfo->message_id,
    hartip_message_id_values, "Unknown message %d");

  tick_stat_node(st, (guint8*)st_str_packets, 0, FALSE);
  tick_stat_node(st, (guint8*)message_type_node_str, st_node_packets, FALSE);
  tick_stat_node(st, (guint8*)message_id_node_str, message_type_node, FALSE);

  return 1;
}

static gint
dissect_empty_body(proto_tree *tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  proto_item  *ti;

  ti = proto_tree_add_item(tree, hf_hartip_data, tvb, offset, bodylen, ENC_NA);
  if (bodylen == 0) {
    proto_item_set_text(ti, "No data");
  } else {
    proto_item_set_text(ti, "Unexpected message body");
  }
  return bodylen;
}

static gint
dissect_session_init(proto_tree *body_tree, tvbuff_t *tvb,
  gint8 msg_type_val, gint offset, gint bodylen)
{
  proto_item *ti;
  guint8      master_type;
  const char *master_type_str;

  msg_type_val = msg_type_val;
  if (bodylen == 5) {
    master_type = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint(body_tree, hf_hartip_master_type, tvb, offset, 1,
      master_type);
    offset++;
    master_type_str = val_to_str(master_type, hartip_master_type_values,
      "Unknown host type %d");
    proto_item_set_text(ti, "Host Type: %s", master_type_str);

    proto_tree_add_uint(body_tree, hf_hartip_inactivity_close_timer, tvb, offset, 4,
      tvb_get_ntohl(tvb, offset));
  } else {
    proto_tree_add_item(body_tree, hf_hartip_data, tvb, offset,
      bodylen, ENC_NA);
  }

  return bodylen;
}

static gint
dissect_error(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen == 1) {
    proto_tree_add_uint(body_tree, hf_hartip_error_code, tvb, offset, 1,
      tvb_get_guint8(tvb, offset));
  } else {
    proto_tree_add_item(body_tree, hf_hartip_data, tvb, offset,
      bodylen, ENC_NA);
  }

  return bodylen;
}

static gint
dissect_session_close(proto_tree *body_tree, tvbuff_t *tvb,
  gint8 msg_type_val, gint offset, gint bodylen)
{
  msg_type_val = msg_type_val;
  return dissect_empty_body(body_tree, tvb, offset, bodylen);
}

static gint
dissect_keep_alive(proto_tree *body_tree, tvbuff_t *tvb,
  gint8 msg_type_val, gint offset, gint bodylen)
{
  msg_type_val = msg_type_val;
  return dissect_empty_body(body_tree, tvb, offset, bodylen);
}

static gint
dissect_byte(proto_tree *tree, int hf, tvbuff_t *tvb, gint offset)
{
  proto_tree_add_uint(tree, hf, tvb, offset, 1, tvb_get_guint8(tvb, offset));
  return 1;
}
static gint
dissect_short(proto_tree *tree, int hf, tvbuff_t *tvb, gint offset)
{
  proto_tree_add_uint(tree, hf, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
  return 2;
}

static gint
dissect_float(proto_tree *tree, int hf, tvbuff_t *tvb, gint offset)
{
  proto_tree_add_item(tree, hf, tvb, offset, sizeof(gfloat), ENC_BIG_ENDIAN);
  return 4;
}

static gint
dissect_string(proto_tree *tree, int hf, char *name, int len, tvbuff_t *tvb,
  gint offset)
{
  proto_item *ti;
  char       *str;

  str = ep_alloc(256);

  ti = proto_tree_add_item(tree, hf, tvb, offset, len, ENC_NA);
  if (len < 256) {
    (void) tvb_get_nstringz0(tvb, offset, len + 1, str);
    proto_item_set_text(ti, "%s: %s", name, str);
  }

  return len;
}

static gint
dissect_packAscii(proto_tree *tree, int hf, char *name, int len, tvbuff_t *tvb,
  gint offset)
{
  gushort     usIdx;
  gushort     usGroupCnt;
  gushort     usMaxGroups;      /* Number of 4 byte groups to pack. */
  gushort     usMask;
  gint        iIndex;
  gint        i   = 0;
  proto_item *ti;
  gushort     buf[4];
  guint8     *tmp;
  char       *str = NULL;

  str = ep_alloc(256+1);

  ti = proto_tree_add_item(tree, hf, tvb, offset, len, ENC_NA);

  DISSECTOR_ASSERT(len < 3 * (256/4));
  tmp = ep_alloc0(len);
  tvb_memcpy(tvb, tmp, offset, len);

  iIndex = 0;
  usMaxGroups = (gushort)(len / 3);
  for (usGroupCnt = 0; usGroupCnt < usMaxGroups; usGroupCnt++) {
    /*
     * First unpack 3 bytes into a group of 4 bytes, clearing bits 6 & 7.
     */
    buf[0] = (gushort)(tmp[iIndex] >> 2);
    buf[1] = (gushort)(((tmp[iIndex] << 4) & 0x30) | (tmp[iIndex + 1] >> 4));
    buf[2] = (gushort)(((tmp[iIndex + 1] << 2) & 0x3C) | (tmp[iIndex + 2] >> 6));
    buf[3] = (gushort)(tmp[iIndex + 2] & 0x3F);
    iIndex += 3;

    /*
     * Now transfer to unpacked area, setting bit 6 to complement of bit 5.
     */
    for (usIdx = 0; usIdx < 4; usIdx++)	{
      usMask = (gushort)(((buf[usIdx] & 0x20) << 1) ^ 0x40);
      DISSECTOR_ASSERT(i < 256);
      str[i++] = (gchar)(buf[usIdx] | usMask);
    }
  }
  str[i] = '\0';
  proto_item_set_text(ti, "%s: %s", name, str);

  return len;
}

static gint
dissect_timestamp(proto_tree *tree, int hf, char *name, int len, tvbuff_t *tvb,
  gint offset)
{
  proto_item *ti;
  guint32     t;
  guint32     hrs  = 0;
  guint32     mins = 0;
  guint32     secs = 0;
  guint32     ms   = 0;

  ti = proto_tree_add_item(tree, hf, tvb, offset, len, ENC_NA);
  t  = tvb_get_ntohl(tvb, offset);

  if (t > 0 ) {
    t /= 32;
    ms = t % 1000;
    t /= 1000;
    secs = t % 60;
    t /= 60;
    mins = t % 60;
    hrs = (guint)(t / 60);
  }

  proto_item_set_text(ti, "%s: %02d:%02d:%02d.%03d", name, hrs, mins, secs, ms);
  return len;
}

static gint
dissect_cmd0(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 22) {
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_expansion_code,                   tvb, offset);
    offset += dissect_short(body_tree, hf_hartip_pt_rsp_expanded_device_type,             tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_req_min_preambles,                tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_hart_protocol_major_rev,          tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_device_rev,                       tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_software_rev,                     tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_hardware_rev_physical_signal,     tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_flage,                            tvb, offset);
    proto_tree_add_item(body_tree,     hf_hartip_pt_rsp_device_id,                        tvb, offset, 3, ENC_NA);
    offset += 3;
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_rsp_min_preambles,                tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_max_device_variables,             tvb, offset);
    offset += dissect_short(body_tree, hf_hartip_pt_rsp_configuration_change_counter,     tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_extended_device_status,           tvb, offset);
    offset += dissect_short(body_tree, hf_hartip_pt_rsp_manufacturer_Identification_code, tvb, offset);
    offset += dissect_short(body_tree, hf_hartip_pt_rsp_private_label,                    tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_device_profile,                   tvb, offset);

    return bodylen;
  }

  return 0;
}

static gint
dissect_cmd1(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 5) {
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_pv_units, tvb, offset);
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_pv,       tvb, offset);
    return bodylen;
  }

  return 0;
}

static gint
dissect_cmd2(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 8) {
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_pv_loop_current,  tvb, offset);
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_pv_percent_range, tvb, offset);
    return bodylen;
  }

  return 0;
}

static gint
dissect_cmd3(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 24) {
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_pv_loop_current, tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_pv_units,        tvb, offset);
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_pv,              tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_sv_units,        tvb, offset);
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_sv,              tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_tv_units,        tvb, offset);
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_tv,              tvb, offset);
    offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_qv_units,        tvb, offset);
    offset += dissect_float(body_tree, hf_hartip_pt_rsp_qv,              tvb, offset);

    return bodylen;
  }

  return 0;
}

static gint
dissect_cmd9(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 14) {
    offset += dissect_byte(body_tree,    hf_hartip_pt_rsp_extended_device_status,    tvb, offset);
    offset += dissect_byte(body_tree,    hf_hartip_pt_rsp_slot0_device_var,          tvb, offset);
    offset += dissect_byte(body_tree,    hf_hartip_pt_rsp_slot0_device_var_classify, tvb, offset);
    offset += dissect_byte(body_tree,    hf_hartip_pt_rsp_slot0_units,               tvb, offset);
    offset += dissect_float(body_tree,   hf_hartip_pt_rsp_slot0_device_var_value,    tvb, offset);
    offset += dissect_byte(body_tree,    hf_hartip_pt_rsp_slot0_device_var_status,   tvb, offset);

    if (bodylen >= 22) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot1_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot1_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot1_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot1_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot1_device_var_status,   tvb, offset);
    }

    if (bodylen >= 30) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot2_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot2_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot2_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot2_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot2_device_var_status,   tvb, offset);
    }

    if (bodylen >= 38) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot3_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot3_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot3_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot3_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot3_device_var_status,   tvb, offset);
    }

    if (bodylen >= 46) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot4_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot4_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot4_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot4_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot4_device_var_status,   tvb, offset);
    }

    if (bodylen >= 54) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot5_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot5_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot5_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot5_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot5_device_var_status,   tvb, offset);
    }

    if (bodylen >= 62) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot6_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot6_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot6_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot6_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot6_device_var_status,   tvb, offset);
    }

    if (bodylen >= 70) {
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot7_device_var,          tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot7_device_var_classify, tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot7_units,               tvb, offset);
      offset += dissect_float(body_tree, hf_hartip_pt_rsp_slot7_device_var_value,    tvb, offset);
      offset += dissect_byte(body_tree,  hf_hartip_pt_rsp_slot7_device_var_status,   tvb, offset);
    }

    dissect_timestamp(body_tree, hf_hartip_pt_rsp_slot0_timestamp, "Slot0 Data TimeStamp", 4, tvb, offset);

    return bodylen;
  }

  return 0;
}

static gint
dissect_cmd13(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 21) {
    offset += dissect_packAscii(body_tree, hf_hartip_pt_rsp_tag, "Tag", 6,                       tvb, offset);
    offset += dissect_packAscii(body_tree, hf_hartip_pt_rsp_packed_descriptor, "descriptor", 12, tvb, offset);
    offset += dissect_byte(body_tree,      hf_hartip_pt_rsp_day,                                 tvb, offset);
    offset += dissect_byte(body_tree,      hf_hartip_pt_rsp_month,                               tvb, offset);
    offset += dissect_byte(body_tree,      hf_hartip_pt_rsp_year,                                tvb, offset);

    return bodylen;
  }

  return 0;
}

static gint
dissect_cmd48(proto_tree *body_tree, tvbuff_t *tvb,
  gint offset, gint bodylen)
{
  if (bodylen >= 9) {
    proto_tree_add_item(body_tree,      hf_hartip_pt_rsp_device_sp_status,         tvb, offset, 5, ENC_NA);
    offset += 5;
    offset += dissect_byte(body_tree,   hf_hartip_pt_rsp_extended_device_status,   tvb, offset);
    offset += dissect_byte(body_tree,   hf_hartip_pt_rsp_device_op_mode,           tvb, offset);
    offset += dissect_byte(body_tree,   hf_hartip_pt_rsp_standardized_status_0,    tvb, offset);

    if (bodylen >= 14) {
      offset += dissect_byte(body_tree, hf_hartip_pt_rsp_standardized_status_1,    tvb, offset);
      offset += dissect_byte(body_tree, hf_hartip_pt_rsp_analog_channel_saturated, tvb, offset);
      offset += dissect_byte(body_tree, hf_hartip_pt_rsp_standardized_status_2,    tvb, offset);
      offset += dissect_byte(body_tree, hf_hartip_pt_rsp_standardized_status_3,    tvb, offset);
      offset += dissect_byte(body_tree, hf_hartip_pt_rsp_analog_channel_fixed,     tvb, offset);
    }

    if (bodylen >= 24) {
      proto_tree_add_item(body_tree,    hf_hartip_pt_rsp_device_sp_status,         tvb, offset, 11, ENC_NA);
      offset += 11;
    }
    return bodylen;
  }

  return 0;
}

static gint
dissect_parse_hart_cmds(proto_tree *body_tree, tvbuff_t *tvb,
  guint8 cmd, gint offset, gint bodylen)
{
  if (cmd == 0)
    return dissect_cmd0(body_tree, tvb, offset, bodylen);
  else if (cmd == 1)
    return dissect_cmd1(body_tree, tvb, offset, bodylen);
  else if (cmd == 2)
    return dissect_cmd2(body_tree, tvb, offset, bodylen);
  else if (cmd == 3)
    return dissect_cmd3(body_tree, tvb, offset, bodylen);
  else if (cmd == 9)
    return dissect_cmd9(body_tree, tvb, offset, bodylen);
  else if ((cmd == 12) && (bodylen >= 24))
    return dissect_packAscii(body_tree, hf_hartip_pt_rsp_message, "Message", 24, tvb, offset);
  else if (cmd == 13)
    return dissect_cmd13(body_tree, tvb, offset, bodylen);
  else if ((cmd == 20) && (bodylen >= 32))
    return dissect_string(body_tree, hf_hartip_pt_rsp_tag, "Tag", 32, tvb, offset);
  else if (cmd == 48)
    return dissect_cmd48(body_tree, tvb, offset, bodylen);

  return 0;
}

static gint
dissect_pass_through(proto_tree *body_tree, tvbuff_t *tvb,
  gint8 msg_type_val, gint offset, gint bodylen)
{
  proto_item *ti;
  guint8      delimiter;
  const char *frame_type_str;
  guint8      tmp;
  guint8      cmd           = 0;
  gint        length        = bodylen;
  gint        is_short      = 0;
  gint        is_rsp        = 0;
  gint        num_preambles = 0;
  gint        result;

  msg_type_val = msg_type_val;

  /* find number of preambles */
  while (length > num_preambles) {
    delimiter = tvb_get_guint8(tvb, offset + num_preambles);
    if (delimiter != 0xFF)
      break;

    num_preambles += 1;
  }

  if (num_preambles > 0) {
    proto_tree_add_item(body_tree, hf_hartip_pt_preambles, tvb, offset,
      num_preambles, ENC_NA);
    offset += num_preambles;
    length -= num_preambles;
  }

  if (length > 0) {
    delimiter = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint(body_tree, hf_hartip_pt_delimiter, tvb, offset, 1,
      delimiter);
    offset++;
    length--;

    if ((delimiter & 0x7) == 2) {
      frame_type_str = "STX";
    } else if ((delimiter & 0x7) == 6) {
      frame_type_str = "ACK";
      is_rsp = 1;
    } else {
      frame_type_str = "UNK";
    }

    if ((delimiter & 0x80) == 0) {
      is_short = 1;
      proto_item_set_text(ti, "Short Address, Frame Type: %s", frame_type_str);
    } else {
      proto_item_set_text(ti, "Frame Type: %s", frame_type_str);
    }
  }

  if (is_short == 1) {
    if (length > 0) {
      tmp = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(body_tree, hf_hartip_pt_short_addr, tvb, offset, 1,
        tmp);
      offset++;
      length--;
    }
  } else {
    if (length > 4) {
      proto_tree_add_item(body_tree, hf_hartip_pt_long_addr, tvb, offset,
        5, ENC_NA);
      offset += 5;
      length -= 5;
    } else if (length > 0) {
      proto_tree_add_item(body_tree, hf_hartip_data, tvb, offset,
        length, ENC_NA);
      length = 0;
    }
  }

  if (length > 0) {
    cmd = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(body_tree, hf_hartip_pt_command, tvb, offset, 1,
      cmd);
    offset++;
    length--;
  }
  if (length > 0) {
    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(body_tree, hf_hartip_pt_length, tvb, offset, 1,
      tmp);
    offset++;
    length--;
  }

  if (is_rsp == 1) {
    if (length > 0) {
      tmp = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(body_tree, hf_hartip_pt_response_code, tvb, offset, 1,
        tmp);
      offset++;
      length--;
    }
    if (length > 0) {
      tmp = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(body_tree, hf_hartip_pt_device_status, tvb, offset, 1,
        tmp);
      offset++;
      length--;
    }
  }

  if (length > 1) {
    result = dissect_parse_hart_cmds(body_tree, tvb, cmd, offset, length);
    if (result == 0 ) {
      proto_tree_add_item(body_tree, hf_hartip_pt_payload, tvb, offset,
        (length - 1), ENC_NA);
    }
    offset += (length - 1);
    length = 1;
  }
  if (length > 0) {
    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(body_tree, hf_hartip_pt_checksum, tvb, offset, 1,
      tmp);
  }

  return bodylen;
}

static void
hartip_set_conversation(packet_info *pinfo)
{
  conversation_t *conversation = NULL;

  if (!pinfo->fd->flags.visited &&
      (pinfo->ptype == PT_UDP)) {
    /*
     * This function is called for a session initiate send over UDP.
     * The session initiate is sent to the server on port HARTIP_PORT.
     * The server then responds from a different port.  All subsequent
     * communication for the session between the client and server
     * uses the new server port and the original client port.
     *
     * A new conversation is created here and this dissector is set to
     * be used for it.  This allows the packets to be dissected properly
     * for this protocol.
     */
    conversation = find_conversation(pinfo->fd->num,
				     &pinfo->src, &pinfo->dst, pinfo->ptype,
				     pinfo->srcport, 0, NO_PORT_B);
    if( (conversation == NULL) ||
	(conversation->dissector_handle != hartip_handle) ) {
      conversation = conversation_new(pinfo->fd->num,
				      &pinfo->src, &pinfo->dst, pinfo->ptype,
				      pinfo->srcport, 0, NO_PORT2);
      conversation_set_dissector(conversation, hartip_handle);
    }
  }
}

static void
dissect_hartip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree      *hartip_tree, *hdr_tree, *body_tree;
  proto_item      *ti, *hdr_node, *body_node;
  gint             offset       = 0;
  gint             bodylen;
  gint             packet_count = 0;
  hartip_hdr       hdr;
  const char      *msg_id_str, *msg_type_str;
  hartip_tap_info *tapinfo;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HART_IP");
  col_clear(pinfo->cinfo, COL_INFO);

  while (1) {
    if (tvb_reported_length_remaining(tvb, offset) < HARTIP_HEADER_LENGTH)
      return;

    tvb_memcpy(tvb, (guint8 *)&hdr, offset, sizeof(hartip_hdr));
    hdr.transaction_id = g_ntohs(hdr.transaction_id);
    hdr.length = g_ntohs(hdr.length);

    msg_id_str   = val_to_str(hdr.message_id, hartip_message_id_values, "Unknown message %d");
    msg_type_str = val_to_str(hdr.message_type, hartip_message_type_values,
      "Unknown message type %d");
    bodylen      = hdr.length - HARTIP_HEADER_LENGTH;

    /* Setup statistics for tap. */
    tapinfo = ep_alloc(sizeof(hartip_tap_info));
    tapinfo->message_type = hdr.message_type;
    tapinfo->message_id   = hdr.message_id;

    if (hdr.message_id == SESSION_INITIATE_ID) {
      hartip_set_conversation(pinfo);
    }

    if (packet_count == 0) {
      col_add_fstr(pinfo->cinfo, COL_INFO,
		   "%s %s, Sequence Number %d",
		   msg_id_str,
		   msg_type_str,
		   hdr.transaction_id);
    }
    else if (packet_count == 1) {
      col_add_fstr(pinfo->cinfo, COL_INFO,
		   "Multiple HART_IP Messages");
    }
    packet_count++;

    if (tree) {
      ti = proto_tree_add_protocol_format
        (tree, proto_hartip, tvb, offset, hdr.length,
          "HART_IP Protocol, %s %s, Sequence Number %d",
          msg_id_str,
          msg_type_str,
          hdr.transaction_id);
      hartip_tree = proto_item_add_subtree(ti, ett_hartip);

      /* add header elements. */
      hdr_node = proto_tree_add_text(hartip_tree, tvb, offset, HARTIP_HEADER_LENGTH,
        "HART_IP Header");


      hdr_tree = proto_item_add_subtree(hdr_node, ett_hartip_hdr);

      proto_tree_add_uint(hdr_tree, hf_hartip_hdr_version, tvb, offset++, 1,
        hdr.version);
      ti = proto_tree_add_uint(hdr_tree, hf_hartip_hdr_message_type, tvb, offset++, 1,
        hdr.message_type);
      proto_item_set_text(ti, "Message Type: %s", msg_type_str);
      ti = proto_tree_add_uint(hdr_tree, hf_hartip_hdr_message_id, tvb, offset++, 1,
        hdr.message_id);
      proto_item_set_text(ti, "Message ID: %s", msg_id_str);
      ti = proto_tree_add_uint(hdr_tree, hf_hartip_hdr_status, tvb, offset++, 1,
        hdr.status);

      proto_tree_add_uint(hdr_tree, hf_hartip_hdr_transaction_id, tvb, offset, 2,
        hdr.transaction_id);
      offset += 2;
      proto_tree_add_uint(hdr_tree, hf_hartip_hdr_msg_length, tvb, offset, 2,
        hdr.length);
      offset += 2;

      /* add body elements. */
      if (bodylen < 0) {
        body_node = proto_tree_add_text(hartip_tree, tvb, offset, hdr.length - HARTIP_HEADER_LENGTH,
          "HART_IP Body - Invalid size");
        return;
      } else {
        body_node = proto_tree_add_text
          (hartip_tree, tvb, offset, bodylen, "HART_IP Body, %s, %s",
            msg_id_str,
            msg_type_str);
        body_tree = proto_item_add_subtree(body_node, ett_hartip_body);

        if (hdr.message_type == ERROR_MSG_TYPE) {
          offset += dissect_error(body_tree, tvb, offset, bodylen);
        } else {
          /*  Dissect the various HARTIP messages. */
          switch(hdr.message_id) {
          case SESSION_INITIATE_ID:
            offset += dissect_session_init(body_tree, tvb, hdr.message_type, offset, bodylen);
            break;
          case SESSION_CLOSE_ID:
            offset += dissect_session_close(body_tree, tvb, hdr.message_type, offset, bodylen);
            break;
          case KEEP_ALIVE_ID:
            offset += dissect_keep_alive(body_tree, tvb, hdr.message_type, offset, bodylen);
            break;
          case PASS_THROUGH_ID:
            offset += dissect_pass_through(body_tree, tvb, hdr.message_type, offset, bodylen);
            break;
          default:
            proto_tree_add_item(body_tree, hf_hartip_data, tvb, offset,
              bodylen, ENC_NA);
            offset += bodylen;
            break;
          }
        }
      }
    }
    else {
      offset += hdr.length;
    }

    tap_queue_packet(hartip_tap, pinfo, tapinfo);
  }
}


void
proto_register_hartip(void)
{
  static hf_register_info hf[] = {
    /* HARTIP header elements. */
    { &hf_hartip_hdr_version,
      { "Version",           "hart_ip.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "HART_IP version number", HFILL }
    },
    { &hf_hartip_hdr_message_type,
      { "Message Type",           "hart_ip.message_type",
        FT_UINT8, BASE_DEC, VALS(hartip_message_type_values), 0xFF,
        "HART_IP message type", HFILL }
    },
    { &hf_hartip_hdr_message_id,
      { "Message ID",           "hart_ip.message_id",
        FT_UINT8, BASE_DEC, VALS(hartip_message_id_values), 0xFF,
        "HART_IP message id", HFILL }
    },
    { &hf_hartip_hdr_status,
      { "Status",           "hart_ip.status",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "HART_IP status field", HFILL }
    },
    { &hf_hartip_hdr_transaction_id,
      { "Sequence Number",           "hart_ip.transaction_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "HART_IP Sequence Number", HFILL }
    },
    { &hf_hartip_hdr_msg_length,
      { "Message Length",           "hart_ip.msg_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "HART_IP Message Length", HFILL }
    },

    /* HARTIP Body elements   */
    { &hf_hartip_data,
      { "Message Data",           "hart_ip.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "HART_IP Message Data", HFILL }
    },
    { &hf_hartip_master_type,
      { "Host Type",           "hart_ip.session_init.master_type",
        FT_UINT8, BASE_DEC, VALS(hartip_master_type_values), 0xFF,
        "Session Host Type", HFILL }
    },
    { &hf_hartip_inactivity_close_timer,
      { "Inactivity Close Timer",           "hart_ip.session_init.inactivity_close_timer",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Session Inactivity Close Timer", HFILL }
    },
    { &hf_hartip_error_code,
      { "Error",           "hart_ip.error.error_code",
        FT_UINT8, BASE_DEC, VALS(hartip_error_code_values), 0xFF,
        "Error Code", HFILL }
    },

    /* HARTIP Pass-through commads. */
    { &hf_hartip_pt_preambles,
      { "Preambles",           "hart_ip.pt.preambles",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Pass Through Preambles", HFILL }
    },
    { &hf_hartip_pt_delimiter,
      { "Delimter",           "hart_ip.pt.delimter",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Pass Through Delimiter", HFILL }
    },
    { &hf_hartip_pt_short_addr,
      { "Short Address",           "hart_ip.pt.short_addr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Pass Through Short Address", HFILL }
    },
    { &hf_hartip_pt_long_addr,
      { "Long Address",           "hart_ip.pt.long_address",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Pass Through Long Address", HFILL }
    },
    { &hf_hartip_pt_command,
      { "Command",           "hart_ip.pt.command",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Pass Through Command", HFILL }
    },
    { &hf_hartip_pt_length,
      { "Length",           "hart_ip.pt.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Pass Through Length", HFILL }
    },
    { &hf_hartip_pt_response_code,
      { "Response Code",           "hart_ip.pt.response_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Pass Through Response Code", HFILL }
    },
    { &hf_hartip_pt_device_status,
      { "Device Status",           "hart_ip.pt.device_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Pass Through Device Status", HFILL }
    },
    { &hf_hartip_pt_payload,
      { "Payload",           "hart_ip.pt.payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Pass Through Payload", HFILL }
    },
    { &hf_hartip_pt_checksum,
      { "Checksum",           "hart_ip.pt.checksum",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Pass Through Checksum", HFILL }
    },

    /* add fields for universal commands. */
    /* command 0 */
    { &hf_hartip_pt_rsp_expansion_code,
      { "Expansion Code",           "hart_ip.pt.rsp.expansion_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_expanded_device_type,
      { "Expanded Device Type",           "hart_ip.pt.rsp.expanded_device_type",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_req_min_preambles,
      { "Minimum Number of Request Preambles",           "hart_ip.pt.rsp.req_min_preambles",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_hart_protocol_major_rev,
      { "HART Universal Revision",           "hart_ip.pt.rsp.hart_univ_rev",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_device_rev,
      { "Device Revision",           "hart_ip.pt.rsp.device_rev",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_software_rev,
      { "Device Software Revision",           "hart_ip.pt.rsp.software_rev",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_hardware_rev_physical_signal,
      { "Hardware Rev and Physical Signaling",           "hart_ip.pt.rsp.hardrev_and_physical_signal",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_flage,
      { "Flags",           "hart_ip.pt.rsp.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_device_id,
      { "Device ID",           "hart_ip.pt.rsp.device_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_rsp_min_preambles,
      { "Minimum Number of Response Preambles",           "hart_ip.pt.rsp.rsp_min_preambles",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_max_device_variables,
      { "Maximum Number of Device Variables",           "hart_ip.pt.rsp.device_variables",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_configuration_change_counter,
      { "Configuration Change Counter",           "hart_ip.pt.rsp.configure_change",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_extended_device_status,
      { "Extended Device Status",           "hart_ip.pt.rsp.ext_device_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_manufacturer_Identification_code,
      { "Manufacturer ID",           "hart_ip.pt.rsp.manufacturer_Id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_private_label,
      { "Private Label",           "hart_ip.pt.rsp.private_label",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_device_profile,
      { "Device Profile",           "hart_ip.pt.rsp.device_profile",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    /* command 2 */
    { &hf_hartip_pt_rsp_pv_percent_range,
      { "PV Percent Range",           "hart_ip.pt.rsp.pv_percent_range",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* command 3 */
    { &hf_hartip_pt_rsp_pv_loop_current,
      { "PV Loop Current",           "hart_ip.pt.rsp.pv_loop_current",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_pv_units,
      { "PV Units",           "hart_ip.pt.rsp.pv_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_pv,
      { "PV",           "hart_ip.pt.rsp.pv",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_sv_units,
      { "SV Units",           "hart_ip.pt.rsp.sv_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_sv,
      { "SV",           "hart_ip.pt.rsp.sv",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_tv_units,
      { "TV Units",           "hart_ip.pt.rsp.tv_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_tv,
      { "TV",           "hart_ip.pt.rsp.tv",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_qv_units,
      { "QV Units",           "hart_ip.pt.rsp.qv_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_qv,
      { "QV",           "hart_ip.pt.rsp.qv",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* command 9 */
    { &hf_hartip_pt_rsp_slot0_device_var,
      { "Slot0 Device Variable",           "hart_ip.pt.rsp.slot0_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot0_device_var_classify,
      { "Slot0 Device Variable Classification",           "hart_ip.pt.rsp.slot0_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot0_units,
      { "Slot0 Units",           "hart_ip.pt.rsp.slot0_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot0_device_var_value,
      { "Slot0 Device Variable Value",           "hart_ip.pt.rsp.slot0_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot0_device_var_status,
      { "Slot0 Device Variable Status",           "hart_ip.pt.rsp.slot0_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot1_device_var,
      { "Slot1 Device Variable",           "hart_ip.pt.rsp.slot1_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot1_device_var_classify,
      { "Slot1 Device Variable Classification",           "hart_ip.pt.rsp.slot1_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot1_units,
      { "Slot1 Units",           "hart_ip.pt.rsp.slot1_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot1_device_var_value,
      { "Slot1 Device Variable Value",           "hart_ip.pt.rsp.slot1_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot1_device_var_status,
      { "Slot1 Device Variable Status",           "hart_ip.pt.rsp.slot1_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot2_device_var,
      { "Slot2 Device Variable",           "hart_ip.pt.rsp.slot2_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot2_device_var_classify,
      { "Slot2 Device Variable Classification",           "hart_ip.pt.rsp.slot2_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot2_units,
      { "Slot2 Units",           "hart_ip.pt.rsp.slot2_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot2_device_var_value,
      { "Slot2 Device Variable Value",           "hart_ip.pt.rsp.slot2_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot2_device_var_status,
      { "Slot2 Device Variable Status",           "hart_ip.pt.rsp.slot2_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot3_device_var,
      { "Slot3 Device Variable",           "hart_ip.pt.rsp.slot3_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot3_device_var_classify,
      { "Slot3 Device Variable Classification",           "hart_ip.pt.rsp.slot3_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot3_units,
      { "Slot3 Units",           "hart_ip.pt.rsp.slot3_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot3_device_var_value,
      { "Slot3 Device Variable Value",           "hart_ip.pt.rsp.slot3_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot3_device_var_status,
      { "Slot3 Device Variable Status",           "hart_ip.pt.rsp.slot3_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot4_device_var,
      { "Slot4 Device Variable",           "hart_ip.pt.rsp.slot4_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot4_device_var_classify,
      { "Slot4 Device Variable Classification",           "hart_ip.pt.rsp.slot4_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot4_units,
      { "Slot4 Units",           "hart_ip.pt.rsp.slot4_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot4_device_var_value,
      { "Slot4 Device Variable Value",           "hart_ip.pt.rsp.slot4_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot4_device_var_status,
      { "Slot4 Device Variable Status",           "hart_ip.pt.rsp.slot4_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot5_device_var,
      { "Slot5 Device Variable",           "hart_ip.pt.rsp.slot5_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot5_device_var_classify,
      { "Slot5 Device Variable Classification",           "hart_ip.pt.rsp.slot5_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot5_units,
      { "Slot5 Units",           "hart_ip.pt.rsp.slot5_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot5_device_var_value,
      { "Slot5 Device Variable Value",           "hart_ip.pt.rsp.slot5_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot5_device_var_status,
      { "Slot5 Device Variable Status",           "hart_ip.pt.rsp.slot5_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot6_device_var,
      { "Slot6 Device Variable",           "hart_ip.pt.rsp.slot6_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot6_device_var_classify,
      { "Slot6 Device Variable Classification",           "hart_ip.pt.rsp.slot6_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot6_units,
      { "Slot6 Units",           "hart_ip.pt.rsp.slot6_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot6_device_var_value,
      { "Slot6 Device Variable Value",           "hart_ip.pt.rsp.slot6_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot6_device_var_status,
      { "Slot6 Device Variable Status",           "hart_ip.pt.rsp.slot6_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot7_device_var,
      { "Slot7 Device Variable",           "hart_ip.pt.rsp.slot7_device_var",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot7_device_var_classify,
      { "Slot7 Device Variable Classification",           "hart_ip.pt.rsp.slot7_device_var_classify",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot7_units,
      { "Slot7 Units",           "hart_ip.pt.rsp.slot7_units",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot7_device_var_value,
      { "Slot7 Device Variable Value",           "hart_ip.pt.rsp.slot7_device_var_value",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot7_device_var_status,
      { "Slot7 Device Variable Status",           "hart_ip.pt.rsp.slot7_device_var_status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_slot0_timestamp,
      { "Slot0 Data TimeStamp",           "hart_ip.pt.rsp.slot0_data_timestamp",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* command 13 */
    { &hf_hartip_pt_rsp_packed_descriptor,
      { "Descriptor",           "hart_ip.pt.rsp.descriptor",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_day,
      { "Day",           "hart_ip.pt.rsp.day",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_month,
      { "Month",           "hart_ip.pt.rsp.month",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_year,
      { "Year",           "hart_ip.pt.rsp.year",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    /* Tag */
    { &hf_hartip_pt_rsp_tag,
      { "Tag",           "hart_ip.pt.rsp.tag",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Message */
    { &hf_hartip_pt_rsp_message,
      { "Message",           "hart_ip.pt.rsp.message",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* command 48 */
    { &hf_hartip_pt_rsp_device_sp_status,
      { "Device-Specific Status",           "hart_ip.pt.rsp.device_sp_status",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_device_op_mode,
      { "Device Operating Mode",           "hart_ip.pt.rsp.device_op_mode",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_standardized_status_0,
      { "Standardized Status 0",           "hart_ip.pt.rsp.standardized_status_0",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_standardized_status_1,
      { "Standardized Status 1",           "hart_ip.pt.rsp.standardized_status_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_analog_channel_saturated,
      { "Analog Channel Saturated",           "hart_ip.pt.rsp.analog_channel_saturated",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_standardized_status_2,
      { "Standardized Status 2",           "hart_ip.pt.rsp.standardized_status_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_standardized_status_3,
      { "Standardized Status 3",           "hart_ip.pt.rsp.standardized_status_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_hartip_pt_rsp_analog_channel_fixed,
      { "Analog Channel Fixed",           "hart_ip.pt.rsp.analog_channel_fixed",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }}
  };

  static gint *ett[] = {
    &ett_hartip,
    &ett_hartip_hdr,
    &ett_hartip_body
  };

  proto_hartip = proto_register_protocol("HART_IP", "HART_IP", "hart_ip");
  proto_register_field_array(proto_hartip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  hartip_tap = register_tap("hart_ip");
}

void
proto_reg_handoff_hartip(void)
{
  hartip_handle = create_dissector_handle(dissect_hartip, proto_hartip);
  dissector_add_uint("udp.port", HARTIP_PORT, hartip_handle);
  dissector_add_uint("tcp.port", HARTIP_PORT, hartip_handle);

  stats_tree_register("hart_ip", "hart_ip", "HART-IP", 0,
    hartip_stats_tree_packet, hartip_stats_tree_init, NULL );
}
