/* packet-bt-utp.c
 * Routines for BT-UTP dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>

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
  EXT_SELECTION_ACKS  = 1,
  EXT_EXTENSION_BITS  = 2,
  EXT_NUM_EXT
};

static const value_string bt_utp_extension_type_vals[] = {
  { EXT_NO_EXTENSION,   "No Extension" },
  { EXT_SELECTION_ACKS, "Selective acks" },
  { EXT_EXTENSION_BITS, "Extension bits" },
  { 0, NULL }
};

static int proto_bt_utp = -1;

/* ---  "Original" utp Header ("version 0" ?) --------------

See utp.cpp source code @ https://github.com/bittorrent/libutp

-- Fixed Header --

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
| ver   | type  | extension     | connection_id                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size                                                      |
+---------------+---------------+---------------+---------------+
| seq_nr                        | ack_nr                        |
+---------------+---------------+---------------+---------------+

XXX: It appears that the above is to be interpreted as indicating
     that 'ver' is in the low-order 4 bits of byte 0 (mask: 0x0f).
     (See utp.cpp @ https://github.com/bittorrent/libutp)

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....
*/

#define V1_FIXED_HDR_SIZE 20

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
static int hf_bt_utp_timestamp_sec = -1;
static int hf_bt_utp_timestamp_us = -1;
static int hf_bt_utp_timestamp_diff_us = -1;
static int hf_bt_utp_wnd_size_v0 = -1;
static int hf_bt_utp_wnd_size_v1 = -1;
static int hf_bt_utp_seq_nr = -1;
static int hf_bt_utp_ack_nr = -1;

static gint ett_bt_utp = -1;
static gint ett_bt_utp_extension = -1;

void proto_reg_handoff_bt_utp(void);

static gboolean
utp_is_v1(tvbuff_t *tvb) {
  guint8 v1_ver_type;
  guint8 v1_ext;
  guint  len;

  v1_ver_type = tvb_get_guint8(tvb, 0);
  v1_ext      = tvb_get_guint8(tvb, 1);

  if (((v1_ver_type & 0x0f) != 1)             ||
      ((v1_ver_type>>4)     >= ST_NUM_STATES) ||
      (v1_ext               >= EXT_NUM_EXT)) {
    return FALSE;  /* Not V1 (or corrupt) */
  }

  /* The simple heuristic above (based upon code from utp.cpp) suggests the header is "V1";
   *  However, based upon a capture seen, the simple heuristic does not appear to be sufficient.
   *  So: Also do some length checking:
   *   The length of "V1" frames should be 20, 26, 30, 34, 36, 38, ...
   *   fixed hdr len:    20
   *   extension(s) len:  6, 10, 14, 16, 18, 20, ...
   *   XXX: this is a hack and should be replaced !!
   *        In fact this heuristic probably fails for some SF_DATA packets since they
   *        presumably can contain a variable number of data bytes after the header.
   */
  len = tvb_reported_length(tvb);
  if (len < V1_FIXED_HDR_SIZE) {
    return TRUE;  /* Invalid ?: pretend V1 anyways */
  }
  len -= V1_FIXED_HDR_SIZE;
  if ((len ==  0) ||
      (len ==  6) ||
      (len == 10) ||
      (len == 14) ||
      ((len > 14) && (len%2 == 0))) {
    return TRUE; /* looks like V1 */
  }
  return FALSE;   /* Not V1 (or corrupt) */
}

static int
dissect_utp_header_v0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
    /* "Original" (V0) */
  proto_tree_add_item(tree, hf_bt_utp_connection_id_v0, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_wnd_size_v0, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);

  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, " Type: %s", val_to_str(tvb_get_guint8(tvb, offset), bt_utp_type_vals, "Unknown %d"));
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

static int
dissect_utp_header_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  /* V1 */
  /* Strange: Contrary to BEP-29, in LibuTP (utp.cpp) the first byte has the following definition:
     packet_type (4 high bits)
     protocol version (4 low bits)
  */
  proto_tree_add_item(tree, hf_bt_utp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_bt_utp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, " Type: %s", val_to_str((tvb_get_guint8(tvb, offset) >> 4), bt_utp_type_vals, "Unknown %d"));
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_connection_id_v1, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_wnd_size_v1, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

static int
dissect_utp_extension(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  proto_item *ti;
  proto_tree *ext_tree;
  guint8 extension_length;
  /* display the extension tree */

  /* XXX: This code loops thru the packet bytes until reaching the end of the PDU
   *      ignoring the "end-of-list" [EXT_NO_EXTENSION] extension type.
   *      Should we just quit when EXT_NO_EXTENSION is encountered ?
   */
  while(offset < (int)tvb_reported_length(tvb))
  {
    switch(*extension_type){
      case EXT_SELECTION_ACKS: /* 1 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Selection Acks, Len=%d", extension_length);
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
  conversation_t *conversation;

  /* try dissecting */
  if( tvb_get_guint8(tvb,0)=='d' )
  {
    proto_tree *sub_tree = NULL;
    int decoded_length = 0;
    guint8 extension_type;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, bt_utp_handle);

    /* set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-uTP");
    /* set the info column */
    col_set_str( pinfo->cinfo, COL_INFO, "uTorrent Transport Protocol" );

    if(tree)
    {
      proto_item *ti;
      ti = proto_tree_add_item(tree, proto_bt_utp, tvb, 0, -1, ENC_NA);
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
    }

    /* Determine header version */

    if (!utp_is_v1(tvb)) {
      decoded_length = dissect_utp_header_v0(tvb, pinfo, sub_tree, decoded_length, &extension_type);
    } else {
      decoded_length = dissect_utp_header_v1(tvb, pinfo, sub_tree,  decoded_length, &extension_type);
    }

    decoded_length = dissect_utp_extension(tvb, pinfo, sub_tree, decoded_length, &extension_type);

    return decoded_length;
  }
  return 0;
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
      FT_UINT8, BASE_DEC, NULL, 0x0,
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
      { "Windows Size", "bt-utp.wnd_size",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_wnd_size_v1,
      { "Windows Size", "bt-utp.wnd_size",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_seq_nr,
      { "Sequence NR", "bt-utp.seq_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_ack_nr,
      { "ACK NR", "bt-utp.ack_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_bt_utp, &ett_bt_utp_extension };

  /* Register protocol */
  proto_bt_utp = proto_register_protocol (
                        "uTorrent Transport Protocol",  /* name */
                        "BT-uTP",               /* short name */
                        "bt-utp"                /* abbrev */
                        );

  proto_register_field_array(proto_bt_utp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bt_utp(void)
{
  heur_dissector_add("udp", dissect_bt_utp, proto_bt_utp);

  bt_utp_handle = new_create_dissector_handle(dissect_bt_utp, proto_bt_utp);
  dissector_add_handle("udp.port", bt_utp_handle);
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

