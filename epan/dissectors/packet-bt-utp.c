/* packet-bt-utp.c
 * Routines for BT-UTP dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 * Copyright 2021, John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-udp.h"
#include "packet-bt-utp.h"

void proto_register_bt_utp(void);
void proto_reg_handoff_bt_utp(void);

enum {
  ST_DATA  = 0,
  ST_FIN   = 1,
  ST_STATE = 2,
  ST_RESET = 3,
  ST_SYN   = 4,
  ST_NUM_STATES
};

/* V0 hdr: "flags"; V1 hdr: "type" */
static const value_string bt_utp_type_vals[] = {
  { ST_DATA,  "Data"  },
  { ST_FIN,   "Fin"   },
  { ST_STATE, "State" },
  { ST_RESET, "Reset" },
  { ST_SYN,   "Syn"   },
  { 0, NULL }
};

enum {
  EXT_NO_EXTENSION    = 0,
  EXT_SELECTIVE_ACKS  = 1,
  EXT_EXTENSION_BITS  = 2,
  EXT_NUM_EXT
};

static const value_string bt_utp_extension_type_vals[] = {
  { EXT_NO_EXTENSION,   "No Extension" },
  { EXT_SELECTIVE_ACKS, "Selective ACKs" },
  { EXT_EXTENSION_BITS, "Extension bits" },
  { 0, NULL }
};

static int proto_bt_utp = -1;

/* ---  "Original" uTP Header ("version 0" ?) --------------

See utp.cpp source code @ https://github.com/bittorrent/libutp

-- Fixed Header --
0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| connection_id                                                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_seconds                                             |
+---------------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size      | ext           | flags         | seq_nr [ho]   |
+---------------+---------------+---------------+---------------+
| seq_nr [lo]   | ack_nr                        |
+---------------+---------------+---------------+

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....

*/

/* --- Version 1 Header ----------------

Specifications: BEP-0029
http://www.bittorrent.org/beps/bep_0029.html

-- Fixed Header --
Fields Types
0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| type  | ver   | extension     | connection_id                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size                                                      |
+---------------+---------------+---------------+---------------+
| seq_nr                        | ack_nr                        |
+---------------+---------------+---------------+---------------+

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....
*/

#define V0_FIXED_HDR_SIZE 23
#define V1_FIXED_HDR_SIZE 20

/* Very early versions of libutp (still used by Transmission) set the max
 * recv window size to 0x00380000, versions from 2013 and later set it to
 * 0x00100000, and some other clients use 0x00040000. This is one of the
 * few possible sources of heuristics.
 */

#define V1_MAX_WINDOW_SIZE 0x380000U

static dissector_handle_t bt_utp_handle;

static int hf_bt_utp_ver = -1;
static int hf_bt_utp_type = -1;
static int hf_bt_utp_flags = -1;
static int hf_bt_utp_extension = -1;
static int hf_bt_utp_next_extension_type = -1;
static int hf_bt_utp_extension_len = -1;
static int hf_bt_utp_extension_bitmask = -1;
static int hf_bt_utp_extension_unknown = -1;
static int hf_bt_utp_connection_id_v0 = -1;
static int hf_bt_utp_connection_id_v1 = -1;
static int hf_bt_utp_stream = -1;
static int hf_bt_utp_timestamp_sec = -1;
static int hf_bt_utp_timestamp_us = -1;
static int hf_bt_utp_timestamp_diff_us = -1;
static int hf_bt_utp_wnd_size_v0 = -1;
static int hf_bt_utp_wnd_size_v1 = -1;
static int hf_bt_utp_seq_nr = -1;
static int hf_bt_utp_ack_nr = -1;
static int hf_bt_utp_data = -1;

static gint ett_bt_utp = -1;
static gint ett_bt_utp_extension = -1;

static gboolean enable_version0 = FALSE;
static guint max_window_size = V1_MAX_WINDOW_SIZE;

static guint32 bt_utp_stream_count = 0;

typedef struct {
  guint32 stream;

#if 0
  /* XXX: Some other things to add in later. The flow will contain
   * multisegment PDU handling, base sequence numbers, etc. */
  utp_flow_t flow[2];
  nstime_t ts_first;
  nstime_t ts_prev;
  guint8 conversation_completeness;
#endif
} utp_stream_info_t;

/* Per-packet header information. */
typedef struct {
  guint8  type;
  gboolean v0;
  guint32 connection; /* The prelease "V0" version is 32 bit */
  guint32 stream;
  guint16 seq;
  guint16 ack;
  guint32 seglen; /* reported length remaining */
} utp_info_t;

static utp_stream_info_t*
get_utp_stream_info(packet_info *pinfo, utp_info_t *utp_info)
{
  conversation_t* conv;
  utp_stream_info_t *stream_info;
  guint32 id_up, id_down;

  /* Handle connection ID wrapping correctly. (Mainline libutp source
   * does not appear to do this, probably fails to connect if the random
   * connection ID is GMAX_UINT16 and tries again.)
   */
  if (utp_info->v0) {
    id_up = utp_info->connection+1;
    id_down = utp_info->connection-1;
  } else {
    id_up = (guint16)(utp_info->connection+1);
    id_down = (guint16)(utp_info->connection-1);
  }

  if (utp_info->type == ST_SYN) {
    /* SYN packets are special, they have the connection ID for the other
     * side, and allow us to know both.
     */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_BT_UTP,
 id_up, utp_info->connection, 0);
    if (!conv) {
      /* XXX: A SYN for between the same pair of hosts with a duplicate
       * connection ID in the same direction is almost surely a retransmission
       * (unless there's a client that doesn't actually generate random IDs.)
       * We could check to see if we've gotten a FIN or RST on that same
       * connection, and also could do like TCP and see if the initial sequence
       * number matches. (The latter still doesn't help if the client also
       * doesn't start with random sequence numbers.)
       */
      conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_BT_UTP, id_up, utp_info->connection, 0);
    }
  } else {
    /* For non-SYN packets, we know our connection ID, but we don't know if
     * the other side has our ID+1 (src initiated the connection) or our ID-1
     * (dst initiated). We also don't want find_conversation() to accidentally
     * call conversation_set_port2() with the wrong ID. So first we see if
     * we have a wildcarded conversation around (if we've seen previous
     * non-SYN packets from our current direction but none in the other.)
     */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_BT_UTP, utp_info->connection, 0, NO_PORT_B);
    if (!conv) {
      /* Do we have a complete conversation originated by our src, or
       * possibly a wildcarded conversation originated in this direction
       * (but we saw a non-SYN for the non-initiating side first)? */
      conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_BT_UTP, utp_info->connection, id_up, 0);
      if (!conv) {
        /* As above, but dst initiated? */
        conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_BT_UTP, utp_info->connection, id_down, 0);
        if (!conv) {
          /* Didn't find it, so create a new wildcarded conversation. When we
           * get a packet for the other direction, find_conversation() above
           * will set port2 with the other connection ID.
           */
          conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_BT_UTP, utp_info->connection, 0, NO_PORT2);
        }
      }
    }
  }

  stream_info = (utp_stream_info_t *)conversation_get_proto_data(conv, proto_bt_utp);
  if (!stream_info) {
    stream_info = wmem_new0(wmem_file_scope(), utp_stream_info_t);
    stream_info->stream = bt_utp_stream_count++;
    conversation_add_proto_data(conv, proto_bt_utp, stream_info);
  }

  return stream_info;
}

static gint
get_utp_version(tvbuff_t *tvb) {
  guint8  v0_flags;
  guint8  v1_ver_type, ext, ext_len;
  guint32 window;
  guint   len, offset = 0;
  gint    ver = -1;

  /* Simple heuristics inspired by code from utp.cpp */

  len = tvb_captured_length(tvb);

  /* Version 1? */
  if (len < V1_FIXED_HDR_SIZE) {
    return -1;
  }

  v1_ver_type = tvb_get_guint8(tvb, 0);
  ext = tvb_get_guint8(tvb, 1);
  if (((v1_ver_type & 0x0f) == 1) && ((v1_ver_type>>4) < ST_NUM_STATES) &&
      (ext < EXT_NUM_EXT)) {
    window = tvb_get_guint32(tvb, 12, ENC_BIG_ENDIAN);
    if (window > max_window_size) {
      return -1;
    }
    ver = 1;
    offset = V1_FIXED_HDR_SIZE;
  } else if (enable_version0) {
    /* Version 0? */
    if (len < V0_FIXED_HDR_SIZE) {
      return -1;
    }
    v0_flags = tvb_get_guint8(tvb, 18);
    ext = tvb_get_guint8(tvb, 17);
    if ((v0_flags < ST_NUM_STATES) && (ext < EXT_NUM_EXT)) {
      ver = 0;
      offset = V0_FIXED_HDR_SIZE;
    }
  }

  if (ver < 0) {
    return ver;
  }

  /* In V0 we could use the microseconds value as a heuristic, because
   * it was tv_usec, but in the modern V1 we cannot, because it is
   * computed by converting a time_t into a 64 bit quantity of microseconds
   * and then taking the lower 32 bits, so all possible values are likely.
   */
  /* If we have an extension, then check the next two bytes,
   * the first of which is another extension type (likely NO_EXTENSION)
   * and the second of which is a length, which must be at least 4.
   */
  if (ext != EXT_NO_EXTENSION) {
    if (len < offset + 2) {
      return -1;
    }
    ext = tvb_get_guint8(tvb, offset);
    ext_len = tvb_get_guint8(tvb, offset+1);
    if (ext >= EXT_NUM_EXT || ext_len < 4) {
      return -1;
    }
  }

  return ver;
}

static int
dissect_utp_header_v0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  /* "Original" (V0) */
  utp_info_t        *p_utp_info = NULL;
  utp_stream_info_t *stream_info = NULL;

  proto_item     *ti;
  guint32 type, connection, win, seq, ack;

  p_utp_info = wmem_new(pinfo->pool, utp_info_t);
  p_utp_info->v0 = TRUE;
  p_add_proto_data(pinfo->pool, pinfo, proto_bt_utp, 0, p_utp_info);

  proto_tree_add_item_ret_uint(tree, hf_bt_utp_connection_id_v0, tvb, offset, 4, ENC_BIG_ENDIAN, &connection);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_wnd_size_v0, tvb, offset, 1, ENC_BIG_ENDIAN, &win);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_flags, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, "Connection ID:%d [%s]", connection, val_to_str(type, bt_utp_type_vals, "Unknown %d"));
  p_utp_info->type = type;
  p_utp_info->connection = connection;

  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item_ret_uint(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &seq);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Seq", seq, " ");
  p_utp_info->seq = seq;
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &ack);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Ack", ack, " ");
  p_utp_info->ack = ack;
  offset += 2;
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Win", win, " ");

  stream_info = get_utp_stream_info(pinfo, p_utp_info);
  ti = proto_tree_add_uint(tree, hf_bt_utp_stream, tvb, offset, 0, stream_info->stream);
  p_utp_info->stream = stream_info->stream;
  proto_item_set_generated(ti);

  return offset;
}

static int
dissect_utp_header_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  /* V1 */
  utp_info_t        *p_utp_info = NULL;
  utp_stream_info_t *stream_info = NULL;

  proto_item     *ti;

  guint32 type, connection, win, seq, ack;

  p_utp_info = wmem_new(pinfo->pool, utp_info_t);
  p_utp_info->v0 = FALSE;
  p_add_proto_data(pinfo->pool, pinfo, proto_bt_utp, 0, p_utp_info);

  proto_tree_add_item(tree, hf_bt_utp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_connection_id_v1, tvb, offset, 2, ENC_BIG_ENDIAN, &connection);
  offset += 2;

  col_append_fstr(pinfo->cinfo, COL_INFO, "Connection ID:%d [%s]", connection, val_to_str(type, bt_utp_type_vals, "Unknown %d"));
  p_utp_info->type = type;
  p_utp_info->connection = connection;

  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_wnd_size_v1, tvb, offset, 4, ENC_BIG_ENDIAN, &win);
  offset += 4;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &seq);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Seq", seq, " ");
  p_utp_info->seq = seq;
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN, &ack);
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Ack", ack, " ");
  p_utp_info->ack = ack;
  offset += 2;
  col_append_str_uint(pinfo->cinfo, COL_INFO, "Win", win, " ");

  stream_info = get_utp_stream_info(pinfo, p_utp_info);
  ti = proto_tree_add_uint(tree, hf_bt_utp_stream, tvb, offset, 0, stream_info->stream);
  p_utp_info->stream = stream_info->stream;
  proto_item_set_generated(ti);

  /* XXX: Multisegment PDUs are the top priority to add, but a number of
   * other features in the TCP dissector would be useful- relative sequence
   * numbers, conversation completeness, maybe even tracking SACKs.
   */
  return offset;
}

static int
dissect_utp_extension(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  proto_item *ti;
  proto_tree *ext_tree;
  guint8 extension_length;
  /* display the extension tree */

  while(*extension_type != EXT_NO_EXTENSION && offset < (int)tvb_reported_length(tvb))
  {
    switch(*extension_type){
      case EXT_SELECTIVE_ACKS: /* 1 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Selective ACKs, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, ENC_NA);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
        break;
      }
      case EXT_EXTENSION_BITS: /* 2 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Extension Bits, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, ENC_NA);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
        break;
      }
      default:
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Unknown, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_unknown, tvb, offset, extension_length, ENC_NA);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
      break;
    }
  }

  return offset;
}

static int
dissect_bt_utp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint version;
  version = get_utp_version(tvb);

  /* try dissecting */
  if (version >= 0)
  {
    guint len_tvb;
    proto_tree *sub_tree = NULL;
    proto_item *ti;
    gint offset = 0;
    guint8 extension_type;

    /* set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-uTP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Determine header version */

    if (version == 0) {
      ti = proto_tree_add_protocol_format(tree, proto_bt_utp, tvb, 0, -1,
                                          "uTorrent Transport Protocol V0");
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
      offset = dissect_utp_header_v0(tvb, pinfo, sub_tree, offset, &extension_type);
    } else {
      ti = proto_tree_add_item(tree, proto_bt_utp, tvb, 0, -1, ENC_NA);
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
      offset = dissect_utp_header_v1(tvb, pinfo, sub_tree, offset, &extension_type);
    }

    offset = dissect_utp_extension(tvb, pinfo, sub_tree, offset, &extension_type);

    len_tvb = tvb_reported_length_remaining(tvb, offset);
    if(len_tvb > 0) {
      col_append_str_uint(pinfo->cinfo, COL_INFO, "Len", len_tvb, " ");
      proto_tree_add_item(sub_tree, hf_bt_utp_data, tvb, offset, len_tvb, ENC_NA);
      utp_info_t *p_utp_info = (utp_info_t *)p_get_proto_data(pinfo->pool, pinfo, proto_bt_utp, 0);
      p_utp_info->seglen = len_tvb;
    }

    return offset+len_tvb;
  }
  return 0;
}

static gboolean
dissect_bt_utp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint version;
  version = get_utp_version(tvb);

  if (version >= 0)
  {
    conversation_t *conversation;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector_from_frame_number(conversation, pinfo->num, bt_utp_handle);

    dissect_bt_utp(tvb, pinfo, tree, data);
    return TRUE;
  }

  return FALSE;
}

static void
utp_init(void)
{
  bt_utp_stream_count = 0;
}

void
proto_register_bt_utp(void)
{
  static hf_register_info hf[] = {
    { &hf_bt_utp_ver,
      { "Version", "bt-utp.ver",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL }
    },
    { &hf_bt_utp_flags,
      { "Flags", "bt-utp.flags",
      FT_UINT8, BASE_DEC,  VALS(bt_utp_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_type,
      { "Type", "bt-utp.type",
      FT_UINT8, BASE_DEC,  VALS(bt_utp_type_vals), 0xF0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension,
      { "Extension", "bt-utp.extension",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_next_extension_type,
      { "Next Extension Type", "bt-utp.next_extension_type",
      FT_UINT8, BASE_DEC, VALS(bt_utp_extension_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_len,
      { "Extension Length", "bt-utp.extension_len",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_bitmask,
      { "Extension Bitmask", "bt-utp.extension_bitmask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_unknown,
      { "Extension Unknown", "bt-utp.extension_unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_connection_id_v0,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_connection_id_v1,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_stream,
      { "Stream index", "bt-utp.stream",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_sec,
      { "Timestamp seconds", "bt-utp.timestamp_sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_us,
      { "Timestamp Microseconds", "bt-utp.timestamp_us",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_diff_us,
      { "Timestamp Difference Microseconds", "bt-utp.timestamp_diff_us",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_wnd_size_v0,
      { "Window Size", "bt-utp.wnd_size",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "V0 receive window size, in multiples of 350 bytes", HFILL }
    },
    { &hf_bt_utp_wnd_size_v1,
      { "Window Size", "bt-utp.wnd_size",
      FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_seq_nr,
      { "Sequence number", "bt-utp.seq_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_ack_nr,
      { "ACK number", "bt-utp.ack_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_data,
      { "Data", "bt-utp.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_bt_utp, &ett_bt_utp_extension };

  module_t *bt_utp_module;

  /* Register protocol */
  proto_bt_utp = proto_register_protocol ("uTorrent Transport Protocol", "BT-uTP", "bt-utp");

  bt_utp_module = prefs_register_protocol(proto_bt_utp, NULL);
  prefs_register_obsolete_preference(bt_utp_module, "enable");
  prefs_register_bool_preference(bt_utp_module,
      "enable_version0",
      "Dissect prerelease (version 0) packets",
      "Whether the dissector should attempt to dissect packets with the "
      "obsolete format (version 0) that predates BEP 29 (22-Jun-2009)",
      &enable_version0);
  prefs_register_uint_preference(bt_utp_module,
      "max_window_size",
      "Maximum window size (in hex)",
      "Maximum receive window size allowed by the dissector. Early clients "
      "(and a few modern ones) set this value to 0x380000 (the default), "
      "later ones use smaller values like 0x100000 and 0x40000. A higher "
      "value can detect nonstandard packets, but at the cost of false "
      "positives.",
      16, &max_window_size);

  proto_register_field_array(proto_bt_utp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_init_routine(utp_init);
}

void
proto_reg_handoff_bt_utp(void)
{
  /* disabled by default since heuristic is weak */
  /* XXX: The heuristic is stronger now, but might still get false positives
   * on packets with lots of zero bytes. Needs more testing before enabling
   * by default.
   */
  heur_dissector_add("udp", dissect_bt_utp_heur, "BitTorrent UTP over UDP", "bt_utp_udp", proto_bt_utp, HEURISTIC_DISABLE);

  bt_utp_handle = create_dissector_handle(dissect_bt_utp, proto_bt_utp);
  dissector_add_for_decode_as_with_preference("udp.port", bt_utp_handle);
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

