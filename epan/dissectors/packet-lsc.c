/* packet-lsc.c
 * Routines for Pegasus LSC packet disassembly
 * Copyright 2006, Sean Sheedy <seansh@users.sourceforge.net>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include <packet-tcp.h>

/* Forward declaration we need below */
void proto_reg_handoff_lsc(void);

#define LSC_PAUSE        0x01
#define LSC_RESUME       0x02
#define LSC_STATUS       0x03
#define LSC_RESET        0x04
#define LSC_JUMP         0x05
#define LSC_PLAY         0x06
#define LSC_DONE         0x40
#define LSC_PAUSE_REPLY  0x81
#define LSC_RESUME_REPLY 0x82
#define LSC_STATUS_REPLY 0x83
#define LSC_RESET_REPLY  0x84
#define LSC_JUMP_REPLY   0x85
#define LSC_PLAY_REPLY   0x86

#define isReply(o) ((o) & 0x80)

static const value_string op_code_vals[] = {
  { LSC_PAUSE,          "LSC_PAUSE" },
  { LSC_RESUME,         "LSC_RESUME" },
  { LSC_STATUS,         "LSC_STATUS" },
  { LSC_RESET,          "LSC_RESET" },
  { LSC_JUMP,           "LSC_JUMP" },
  { LSC_PLAY,           "LSC_PLAY" },
  { LSC_DONE,           "LSC_DONE" },
  { LSC_PAUSE_REPLY,    "LSC_PAUSE_REPLY" },
  { LSC_RESUME_REPLY,   "LSC_RESUME_REPLY" },
  { LSC_STATUS_REPLY,   "LSC_STATUS_REPLY" },
  { LSC_RESET_REPLY,    "LSC_RESET_REPLY" },
  { LSC_JUMP_REPLY,     "LSC_JUMP_REPLY" },
  { LSC_PLAY_REPLY,     "LSC_PLAY_REPLY" },
  { 0,                  NULL }
};

#define LSC_OPCODE_LEN   3              /* Length to find op code */
#define LSC_MIN_LEN      8              /* Minimum packet length */
/* Length of each packet type */
#define LSC_PAUSE_LEN   12
#define LSC_RESUME_LEN  16
#define LSC_STATUS_LEN   8
#define LSC_RESET_LEN    8
#define LSC_JUMP_LEN    20
#define LSC_PLAY_LEN    20
#define LSC_REPLY_LEN   17

static const value_string status_code_vals[] = {
  { 0x00,       "LSC_OK" },
  { 0x10,       "LSC_BAD_REQUEST" },
  { 0x11,       "LSC_BAD_STREAM" },
  { 0x12,       "LSC_WRONG_STATE" },
  { 0x13,       "LSC_UNKNOWN" },
  { 0x14,       "LSC_NO_PERMISSION" },
  { 0x15,       "LSC_BAD_PARAM" },
  { 0x16,       "LSC_NO_IMPLEMENT" },
  { 0x17,       "LSC_NO_MEMORY" },
  { 0x18,       "LSC_IMP_LIMIT" },
  { 0x19,       "LSC_TRANSIENT" },
  { 0x1a,       "LSC_NO_RESOURCES" },
  { 0x20,       "LSC_SERVER_ERROR" },
  { 0x21,       "LSC_SERVER_FAILURE" },
  { 0x30,       "LSC_BAD_SCALE" },
  { 0x31,       "LSC_BAD_START" },
  { 0x32,       "LSC_BAD_STOP" },
  { 0x40,       "LSC_MPEG_DELIVERY" },
  { 0,          NULL }
};

static const value_string mode_vals[] = {
  { 0x00,       "O   - Open Mode" },
  { 0x01,       "P   - Pause Mode" },
  { 0x02,       "ST  - Search Transport" },
  { 0x03,       "T   - Transport" },
  { 0x04,       "TP  - Transport Pause" },
  { 0x05,       "STP - Search Transport Pause" },
  { 0x06,       "PST - Pause Search Transport" },
  { 0x07,       "EOS - End of Stream" },
  { 0,          NULL }
};

/* Initialize the protocol and registered fields */
static int proto_lsc = -1;
static int hf_lsc_version = -1;
static int hf_lsc_trans_id = -1;
static int hf_lsc_op_code = -1;
static int hf_lsc_status_code = -1;
static int hf_lsc_stream_handle = -1;
static int hf_lsc_start_npt = -1;
static int hf_lsc_stop_npt = -1;
static int hf_lsc_current_npt = -1;
static int hf_lsc_scale_num = -1;
static int hf_lsc_scale_denom = -1;
static int hf_lsc_mode = -1;

/* Preferences */
static guint global_lsc_port = 0;

/* Initialize the subtree pointers */
static gint ett_lsc = -1;

/* Code to actually dissect the packets */
static void
dissect_lsc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lsc_tree;
  guint8 op_code;
  guint32 stream;
  guint expected_len;

  /* Protocol is LSC, packet summary is not yet known */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LSC");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Too little data? */
  if (tvb_length(tvb) < LSC_MIN_LEN)
  {
    col_set_str(pinfo->cinfo, COL_INFO, "[Too short]");
    return;
  }

  /* Get the op code */
  op_code = tvb_get_guint8(tvb, 2);
  /* And the stream handle */
  stream = tvb_get_ntohl(tvb, 4);

  /* Check the data length against what we actually received */
  switch (op_code)
    {
      case LSC_PAUSE:
        expected_len = LSC_PAUSE_LEN;
        break;
      case LSC_RESUME:
        expected_len = LSC_RESUME_LEN;
        break;
      case LSC_STATUS:
        expected_len = LSC_STATUS_LEN;
        break;
      case LSC_RESET:
        expected_len = LSC_RESET_LEN;
        break;
      case LSC_JUMP:
        expected_len = LSC_JUMP_LEN;
        break;
      case LSC_PLAY:
        expected_len = LSC_PLAY_LEN;
        break;
      case LSC_DONE:
      case LSC_PAUSE_REPLY:
      case LSC_RESUME_REPLY:
      case LSC_STATUS_REPLY:
      case LSC_RESET_REPLY:
      case LSC_JUMP_REPLY:
      case LSC_PLAY_REPLY:
        expected_len = LSC_REPLY_LEN;
        break;
      default:
        /* Unrecognized op code */
        expected_len = LSC_MIN_LEN;
        break;
    }

  /* Display the op code in the summary */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, session %.8u",
                 val_to_str(op_code, op_code_vals, "Unknown op code (0x%x)"),
                 stream);

    if (tvb_length(tvb) < expected_len)
      col_append_str(pinfo->cinfo, COL_INFO, " [Too short]");
    else if (tvb_length(tvb) > expected_len)
      col_append_str(pinfo->cinfo, COL_INFO, " [Too long]");
  }

  if (tree) {
    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_lsc, tvb, 0, -1, FALSE);
    lsc_tree = proto_item_add_subtree(ti, ett_lsc);

    /* Add already fetched items to the tree */
    proto_tree_add_uint(lsc_tree, hf_lsc_op_code, tvb, 2, 1, op_code);
    proto_tree_add_uint_format_value(lsc_tree, hf_lsc_stream_handle, tvb, 4, 4,
                                     stream, "%.8u", stream);

    /* Add rest of LSC header */
    proto_tree_add_uint(lsc_tree, hf_lsc_version, tvb, 0, 1,
                        tvb_get_guint8(tvb, 0));
    proto_tree_add_uint(lsc_tree, hf_lsc_trans_id, tvb, 1, 1,
                        tvb_get_guint8(tvb, 1));

    /* Only replies contain a status code */
    if (isReply(op_code))
      proto_tree_add_uint(lsc_tree, hf_lsc_status_code, tvb, 3, 1,
                          tvb_get_guint8(tvb, 3));

    /* Add op code specific parts */
    switch (op_code)
      {
        case LSC_PAUSE:
          proto_tree_add_int(lsc_tree, hf_lsc_stop_npt, tvb, 8, 4,
                             tvb_get_ntohl(tvb, 8));
          break;
        case LSC_RESUME:
          proto_tree_add_int(lsc_tree, hf_lsc_start_npt, tvb, 8, 4,
                             tvb_get_ntohl(tvb, 8));
          proto_tree_add_int(lsc_tree, hf_lsc_scale_num, tvb, 12, 2,
                             tvb_get_ntohs(tvb, 12));
          proto_tree_add_uint(lsc_tree, hf_lsc_scale_denom, tvb, 14, 2,
                              tvb_get_ntohs(tvb, 14));
          break;
        case LSC_JUMP:
        case LSC_PLAY:
          proto_tree_add_int(lsc_tree, hf_lsc_start_npt, tvb, 8, 4,
                             tvb_get_ntohl(tvb, 8));
          proto_tree_add_int(lsc_tree, hf_lsc_stop_npt, tvb, 12, 4,
                             tvb_get_ntohl(tvb, 12));
          proto_tree_add_int(lsc_tree, hf_lsc_scale_num, tvb, 16, 2,
                             tvb_get_ntohs(tvb, 16));
          proto_tree_add_uint(lsc_tree, hf_lsc_scale_denom, tvb, 18, 2,
                              tvb_get_ntohs(tvb, 18));
          break;
        case LSC_DONE:
        case LSC_PAUSE_REPLY:
        case LSC_RESUME_REPLY:
        case LSC_STATUS_REPLY:
        case LSC_RESET_REPLY:
        case LSC_JUMP_REPLY:
        case LSC_PLAY_REPLY:
          proto_tree_add_int(lsc_tree, hf_lsc_current_npt, tvb, 8, 4,
                             tvb_get_ntohl(tvb, 8));
          proto_tree_add_int(lsc_tree, hf_lsc_scale_num, tvb, 12, 2,
                             tvb_get_ntohs(tvb, 12));
          proto_tree_add_uint(lsc_tree, hf_lsc_scale_denom, tvb, 14, 2,
                              tvb_get_ntohs(tvb, 14));
          proto_tree_add_uint(lsc_tree, hf_lsc_mode, tvb, 16, 1,
                              tvb_get_guint8(tvb, 16));
          break;
        default:
          break;
      }
  }
}

/* Decode LSC over UDP */
static void
dissect_lsc_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_lsc_common(tvb, pinfo, tree);
}

/* Determine length of LSC message */
static guint
get_lsc_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint8 op_code;
  guint pdu_len;

  /* Get the op code */
  op_code = tvb_get_guint8(tvb, offset + 2);

  switch (op_code)
    {
      case LSC_PAUSE:
        pdu_len = LSC_PAUSE_LEN;
        break;
      case LSC_RESUME:
        pdu_len = LSC_RESUME_LEN;
        break;
      case LSC_STATUS:
        pdu_len = LSC_STATUS_LEN;
        break;
      case LSC_RESET:
        pdu_len = LSC_RESET_LEN;
        break;
      case LSC_JUMP:
        pdu_len = LSC_JUMP_LEN;
        break;
      case LSC_PLAY:
        pdu_len = LSC_PLAY_LEN;
        break;
      case LSC_DONE:
      case LSC_PAUSE_REPLY:
      case LSC_RESUME_REPLY:
      case LSC_STATUS_REPLY:
      case LSC_RESET_REPLY:
      case LSC_JUMP_REPLY:
      case LSC_PLAY_REPLY:
        pdu_len = LSC_REPLY_LEN;
        break;
      default:
        /* Unrecognized op code */
        pdu_len = LSC_OPCODE_LEN;
        break;
    }

  return pdu_len;
}

/* Decode LSC over TCP */
static void
dissect_lsc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LSC_OPCODE_LEN, get_lsc_pdu_len,
                   dissect_lsc_common);
}

/* Register the protocol with Wireshark */
void
proto_register_lsc(void)
{
  module_t *lsc_module;

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_lsc_version,
      { "Version", "lsc.version",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Version of the Pegasus LSC protocol", HFILL }
    },
    { &hf_lsc_trans_id,
      { "Transaction ID", "lsc.trans_id",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_lsc_op_code,
      { "Op Code", "lsc.op_code",
        FT_UINT8, BASE_HEX, VALS(op_code_vals), 0,
        "Operation Code", HFILL }
    },
    { &hf_lsc_status_code,
      { "Status Code", "lsc.status_code",
        FT_UINT8, BASE_HEX, VALS(status_code_vals), 0,
        NULL, HFILL }
    },
    { &hf_lsc_stream_handle,
      { "Stream Handle", "lsc.stream_handle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Stream identification handle", HFILL }
    },
    { &hf_lsc_start_npt,
      { "Start NPT", "lsc.start_npt",
        FT_INT32, BASE_DEC, NULL, 0,
        "Start Time (milliseconds)", HFILL }
    },
    { &hf_lsc_stop_npt,
      { "Stop NPT", "lsc.stop_npt",
        FT_INT32, BASE_DEC, NULL, 0,
        "Stop Time (milliseconds)", HFILL }
    },
    { &hf_lsc_current_npt,
      { "Current NPT", "lsc.current_npt",
        FT_INT32, BASE_DEC, NULL, 0,
        "Current Time (milliseconds)", HFILL }
    },
    { &hf_lsc_scale_num,
      { "Scale Numerator", "lsc.scale_num",
        FT_INT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_lsc_scale_denom,
      { "Scale Denominator", "lsc.scale_denum",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_lsc_mode,
      { "Server Mode", "lsc.mode",
        FT_UINT8, BASE_HEX, VALS(mode_vals), 0,
        "Current Server Mode", HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_lsc,
  };

  /* Register the protocol name and description */
  proto_lsc = proto_register_protocol("Pegasus Lightweight Stream Control",
                                      "LSC", "lsc");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_lsc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register preferences module */
  lsc_module = prefs_register_protocol(proto_lsc, proto_reg_handoff_lsc);

  /* Register preferences */
  prefs_register_uint_preference(lsc_module, "port",
		            "LSC Port",
		            "Set the TCP or UDP port for Pegasus LSC messages",
		            10, &global_lsc_port);
}

void
proto_reg_handoff_lsc(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t lsc_udp_handle;
  static dissector_handle_t lsc_tcp_handle;
  static guint saved_lsc_port;

  if (!initialized) {
    lsc_udp_handle = create_dissector_handle(dissect_lsc_udp, proto_lsc);
    lsc_tcp_handle = create_dissector_handle(dissect_lsc_tcp, proto_lsc);
    dissector_add_handle("udp.port", lsc_udp_handle);   /* for 'decode-as' */
    dissector_add_handle("tcp.port", lsc_tcp_handle);   /* ...             */
    initialized = TRUE;
  } else {
    if (saved_lsc_port != 0) {
      dissector_delete_uint("udp.port", saved_lsc_port, lsc_udp_handle);
      dissector_delete_uint("tcp.port", saved_lsc_port, lsc_tcp_handle);
    }
  }

  /* Set the port number */
  if (global_lsc_port != 0) {
    dissector_add_uint("udp.port", global_lsc_port, lsc_udp_handle);
    dissector_add_uint("tcp.port", global_lsc_port, lsc_tcp_handle);
  }
  saved_lsc_port = global_lsc_port;
}
