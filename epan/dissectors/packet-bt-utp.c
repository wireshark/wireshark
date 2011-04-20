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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <epan/packet.h>
#include <epan/prefs.h>

#define DEFAULT_UDP_PORT 55627

static const value_string bt_utp_type_vals[] = {
  { 0, "Data" },
  { 1, "Fin" },
  { 2, "State" },
  { 3, "Reset" },
  { 4, "Syn" },
  { 0, NULL }
};

#define EXT_NO_EXTENSION    0
#define EXT_SELECTION_ACKS  1
#define EXT_EXTENSION_BITS  2

static const value_string bt_utp_extension_type_vals[] = {
  { EXT_NO_EXTENSION, "No Extension" },
  { EXT_SELECTION_ACKS, "Selective acks" },
  { EXT_EXTENSION_BITS, "Extension bits" },
  { 0, NULL }
};

static int proto_bt_utp = -1;

/* Specifications: BEP-0029
http://www.bittorrent.org/beps/bep_0029.html

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

0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....
*/
static int hf_bt_utp_ver = -1;
static int hf_bt_utp_type = -1;
static int hf_bt_utp_extension = -1;
static int hf_bt_utp_next_extension_type = -1;
static int hf_bt_utp_extension_len = -1;
static int hf_bt_utp_extension_bitmask = -1;
static int hf_bt_utp_extension_unknown = -1;
static int hf_bt_utp_connection_id = -1;
static int hf_bt_utp_timestamp_ms = -1;
static int hf_bt_utp_timestamp_diff_ms = -1;
static int hf_bt_utp_wnd_size = -1;
static int hf_bt_utp_seq_nr = -1;
static int hf_bt_utp_ack_nr = -1;

static gint ett_bt_utp = -1;
static gint ett_bt_utp_extension = -1;

static guint global_bt_utp_udp_port = DEFAULT_UDP_PORT;

void proto_reg_handoff_bt_utp(void);

static int
dissect_utp_header(tvbuff_t *tvb, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *ext_tree;
  guint8 extension_type;
  guint8 extension_length;
  int offset = 0;

  /* Strange in LibuTP the first bytes as the following definition
     packet_type (4 high bits)
     protocol version (4 low bits)
  */
  proto_tree_add_item(tree, hf_bt_utp_ver, tvb, offset, 1, FALSE);
  proto_tree_add_item(tree, hf_bt_utp_type, tvb, offset, 1, FALSE);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, FALSE);
  extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_connection_id, tvb, offset, 2, FALSE);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_ms, tvb, offset, 4, FALSE);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_ms, tvb, offset, 4, FALSE);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_wnd_size, tvb, offset, 4, FALSE);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, FALSE);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, FALSE);
  offset += 2;

  /* display the extension tree */

  /* XXX: This code loops thru the packet bytes until reaching the end of the PDU
   *      ignoring the "end-of-list" [EXT_NO_EXTENSION] extension type.
   *      Should we just quit when EXT_NO_EXTENSION is encountered ?
   */
  while(offset < (int)tvb_length(tvb))
  {
    switch(extension_type){
      case EXT_SELECTION_ACKS: /* 1 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, FALSE);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, FALSE);
        extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, FALSE);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Selection Acks, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, FALSE);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
        break;
      }
      case EXT_EXTENSION_BITS: /* 2 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, FALSE);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, FALSE);
        extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, FALSE);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Extension Bits, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, FALSE);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
        break;
      }
      default:
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, FALSE);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, FALSE);
        extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, FALSE);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Unknown, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_unknown, tvb, offset, extension_length, FALSE);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
      break;
    }
  }

  return offset;
}

static int
dissect_bt_utp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *sub_tree = NULL;
  int decoded_length;

  /* set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-uTP");
  /* set the info column */
  col_set_str( pinfo->cinfo, COL_INFO, "uTorrent Transport Protocol" );

  if(tree)
  {
    proto_item *ti;
    ti = proto_tree_add_item(tree, proto_bt_utp, tvb, 0, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
  }

  decoded_length = dissect_utp_header(tvb, sub_tree);

  return decoded_length;
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
    { &hf_bt_utp_connection_id,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_ms,
      { "Timestamp Microseconds", "bt-utp.timestamp_ms",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_diff_ms,
      { "Timestamp Difference Microseconds", "bt-utp.timestamp_diff_ms",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_wnd_size,
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

  module_t *bt_utp_module;

  /* Register protocol */
  proto_bt_utp = proto_register_protocol (
                        "uTorrent Transport Protocol",  /* name */
                        "BT-uTP",               /* short name */
                        "bt-utp"                /* abbrev */
                        );

  proto_register_field_array(proto_bt_utp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  new_register_dissector("bt-utp", dissect_bt_utp, proto_bt_utp);

  /* Register our configuration options */
  bt_utp_module = prefs_register_protocol(proto_bt_utp, proto_reg_handoff_bt_utp);

  prefs_register_uint_preference(bt_utp_module, "udp_port",
                                           "uTorrent Transport Protocol UDP port",
                                           "Set the UDP port for uTorrent Transport Protocol.",
                                           10, &global_bt_utp_udp_port);
}

void
proto_reg_handoff_bt_utp(void)
{
  static gboolean bt_utp_prefs_initialized = FALSE;
  static dissector_handle_t bt_utp_handle;
  static guint bt_utp_udp_port;

  if (!bt_utp_prefs_initialized)
  {
    bt_utp_handle = new_create_dissector_handle(dissect_bt_utp, proto_bt_utp);
    bt_utp_prefs_initialized = TRUE;
  }
  else
  {
    dissector_delete_uint("udp.port", bt_utp_udp_port, bt_utp_handle);
  }

  /* Set our port number for future use */
  bt_utp_udp_port = global_bt_utp_udp_port;
  dissector_add_uint("udp.port", global_bt_utp_udp_port, bt_utp_handle);
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
 * ex: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */

