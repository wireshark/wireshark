/* packet-bjnp.c
 * Routines for Canon BJNP packet disassembly.
 *
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
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
#include "config.h"
#endif

#include <epan/packet.h>

#define PNAME  "Canon BJNP"
#define PSNAME "BJNP"
#define PFNAME "bjnp"

#define BJNP_PORT1         8611
#define BJNP_PORT2         8612
#define BJNP_PORT3         8613
#define BJNP_PORT4         8614

/* dev_type */
#define PRINTER_COMMAND    0x01
#define SCANNER_COMMAND    0x02
#define PRINTER_RESPONSE   0x81
#define SCANNER_RESPONSE   0x82

/* cmd_code */
#define CMD_DISCOVER       0x01
#define CMD_PRINT_JOB_DET  0x10
#define CMD_CLOSE          0x11
#define CMD_GET_STATUS     0x20
#define CMD_PRINT          0x21
#define CMD_GET_ID         0x30
#define CMD_SCAN_JOB       0x32

static int proto_bjnp = -1;

static int hf_bjnp_id = -1;
static int hf_dev_type = -1;
static int hf_cmd_code = -1;
static int hf_seq_no = -1;
static int hf_session_id = -1;
static int hf_payload_len = -1;
static int hf_payload = -1;

static gint ett_bjnp = -1;

static const value_string dev_type_vals[] = {
  { PRINTER_COMMAND,    "Printer Command"       },
  { SCANNER_COMMAND,    "Scanner Command"       },
  { PRINTER_RESPONSE,   "Printer Response"      },
  { SCANNER_RESPONSE,   "Scanner Response"      },
  { 0, NULL }
};

static const value_string cmd_code_vals[] = {
  { CMD_DISCOVER,       "Discover"              },
  { CMD_PRINT_JOB_DET,  "Print Job Details"     },
  { CMD_CLOSE,          "Request Closure"       }, 
  { CMD_GET_STATUS,     "Get Printer Status"    },
  { CMD_PRINT,          "Print"                 },
  { CMD_GET_ID,         "Get Printer Identity"  },
  { CMD_SCAN_JOB,       "Scan Job Details"      },
  { 0, NULL }
};

static void dissect_bjnp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *bjnp_tree;
  proto_item *ti;
  gint        offset = 0;
  guint32     payload_len;
  guint8      dev_type, cmd_code;
  gchar      *info;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item (tree, proto_bjnp, tvb, offset, -1, ENC_BIG_ENDIAN);
  bjnp_tree = proto_item_add_subtree (ti, ett_bjnp);

  proto_tree_add_item (bjnp_tree, hf_bjnp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  dev_type = tvb_get_guint8 (tvb, offset);
  proto_tree_add_item (bjnp_tree, hf_dev_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  cmd_code = tvb_get_guint8 (tvb, offset);
  proto_tree_add_item (bjnp_tree, hf_cmd_code, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  info = g_strdup_printf ("%s: %s",val_to_str (dev_type, dev_type_vals, "Unknown type (%d)"),
                          val_to_str (cmd_code, cmd_code_vals, "Unknown code (%d)"));

  proto_item_append_text (ti, ", %s", info);
  col_add_str (pinfo->cinfo, COL_INFO, info);

  g_free (info);

  proto_tree_add_item (bjnp_tree, hf_seq_no, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item (bjnp_tree, hf_session_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  payload_len = tvb_get_ntohl (tvb, offset);
  proto_tree_add_item (bjnp_tree, hf_payload_len, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  if (payload_len > 0) {
    /* TBD: Dissect various commands */
    proto_tree_add_item (bjnp_tree, hf_payload, tvb, offset, payload_len, ENC_BIG_ENDIAN);
    offset += payload_len;
  }
}

void proto_register_bjnp (void)
{
  static hf_register_info hf[] = {
    { &hf_bjnp_id,
      { "Id", "bjnp.id", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_dev_type,
      { "Type", "bjnp.type", FT_UINT8, BASE_DEC,
        VALS(dev_type_vals), 0x0, NULL, HFILL } },
    { &hf_cmd_code,
      { "Code", "bjnp.code", FT_UINT8, BASE_DEC,
        VALS(cmd_code_vals), 0x0, NULL, HFILL } },
    { &hf_seq_no,
      { "Sequence Number", "bjnp.seq_no", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_session_id,
      { "Session Id", "bjnp.session_id", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_payload_len,
      { "Payload Length", "bjnp.payload_len", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_payload,
      { "Payload", "bjnp.payload", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
  };

  static gint *ett[] = {
    &ett_bjnp
  };

  proto_bjnp = proto_register_protocol (PNAME, PSNAME, PFNAME);
  register_dissector (PFNAME, dissect_bjnp, proto_bjnp);
  
  proto_register_field_array (proto_bjnp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void proto_reg_handoff_bjnp (void)
{
  dissector_handle_t bjnp_handle;

  bjnp_handle = find_dissector (PFNAME);
  dissector_add_uint ("udp.port", BJNP_PORT1, bjnp_handle);
  dissector_add_uint ("udp.port", BJNP_PORT2, bjnp_handle);
  dissector_add_uint ("udp.port", BJNP_PORT3, bjnp_handle);
  dissector_add_uint ("udp.port", BJNP_PORT4, bjnp_handle);
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
