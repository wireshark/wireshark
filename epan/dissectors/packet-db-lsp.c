/* packet-db-lsp.c
 * Routines for Dropbox LAN sync Protocol
 *
 * Copyright 2010, Stig Bjorlykke <stig@bjorlykke.org>
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"
#include "packet-x509af.h"

#define PNAME  "Dropbox LAN sync Protocol"
#define PSNAME "DB-LSP"
#define PFNAME "db-lsp"

#define PNAME_DISC  "Dropbox LAN sync Discovery Protocol"
#define PSNAME_DISC "DB-LSP-DISC"
#define PFNAME_DISC "db-lsp-disc"

#define DB_LSP_PORT  17500

static int proto_db_lsp = -1;
static int proto_db_lsp_disc = -1;

static int hf_type = -1;
static int hf_magic = -1;
static int hf_length = -1;
static int hf_opvalue = -1;
static int hf_data = -1;
static int hf_value = -1;
static int hf_text = -1;

static gint ett_db_lsp = -1;

/* desegmentation of tcp payload */
static gboolean db_lsp_desegment = TRUE;

#define TYPE_CONFIG   0x16
#define TYPE_DATA     0x17

static const value_string type_vals[] = {
  { TYPE_CONFIG,    "Configuration" },
  { TYPE_DATA,      "Data" },
  { 0, NULL }
};

#define OP_CERT       0x0B

static const value_string op_vals[] = {
  { OP_CERT,   "Certificate" },
  { 0, NULL }
};

static void
dissect_db_lsp_pdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *db_lsp_tree;
  proto_item *db_lsp_item;
  gint        offset = 0;
  guint8      type, opvalue;
  guint16     magic, length;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_set_str (pinfo->cinfo, COL_INFO, PNAME);

  db_lsp_item = proto_tree_add_item (tree, proto_db_lsp, tvb, offset, -1, ENC_BIG_ENDIAN);
  db_lsp_tree = proto_item_add_subtree (db_lsp_item, ett_db_lsp);

  type = tvb_get_guint8 (tvb, offset);
  proto_tree_add_item (db_lsp_tree, hf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (type == 0x80) {
    /* Two unknown bytes */
    offset += 2;
  }

  magic = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (db_lsp_tree, hf_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  length = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (db_lsp_tree, hf_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if (magic != 0x0301 || length > tvb_length_remaining (tvb, offset)) {
    /* Probably an unknown packet */
    /* expert_add_info_format (pinfo, db_lsp_item, PI_UNDECODED, PI_WARN, "Unknown packet"); */
    return;
  }

  if (type == TYPE_CONFIG) {
    opvalue = tvb_get_guint8 (tvb, offset);
    proto_tree_add_item (db_lsp_tree, hf_opvalue, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (opvalue == OP_CERT) {
      /* X509 Certificate */
      tvbuff_t *cert_tvb = tvb_new_subset (tvb, offset+10, length-10, length-10);
      dissect_x509af_Certificate_PDU (cert_tvb, pinfo, db_lsp_tree);
    } else {
      proto_tree_add_item (db_lsp_tree, hf_value, tvb, offset, length, ENC_BIG_ENDIAN);
    }
  } else if (type == TYPE_DATA) {
    proto_tree_add_item (db_lsp_tree, hf_data, tvb, offset, length, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_item (db_lsp_tree, hf_value, tvb, offset, length, ENC_BIG_ENDIAN);
  }
  offset += length;

  proto_item_append_text (db_lsp_item, ", Type: %d, Length: %d", type, length);
  proto_item_set_len (db_lsp_item, length + 5);
}

static guint
get_db_lsp_pdu_len (packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  if (tvb_get_ntohs (tvb, offset + 1) != 0x0301) {
    /* Unknown data, eat remaining data for this frame */
    return tvb_length_remaining (tvb, offset);
  }

  return tvb_get_ntohs (tvb, offset + 3) + 5;
}

static void
dissect_db_lsp_tcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus (tvb, pinfo, tree, db_lsp_desegment, 5,
                    get_db_lsp_pdu_len, dissect_db_lsp_pdu);
}

static void
dissect_db_lsp_disc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *db_lsp_tree;
  proto_item *db_lsp_item;
  gint        offset = 0;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME_DISC);
  col_set_str (pinfo->cinfo, COL_INFO, PNAME_DISC);

  db_lsp_item = proto_tree_add_item (tree, proto_db_lsp_disc, tvb, offset, -1, ENC_BIG_ENDIAN);
  db_lsp_tree = proto_item_add_subtree (db_lsp_item, ett_db_lsp);

  proto_tree_add_item (db_lsp_tree, hf_text, tvb, offset, -1, ENC_BIG_ENDIAN);
}

void
proto_register_db_lsp (void)
{
  static hf_register_info hf[] = {
    { &hf_type,
      { "Type", "db-lsp.type",
        FT_UINT8, BASE_DEC_HEX, VALS(type_vals), 0x0,
        NULL, HFILL } },

    { &hf_magic,
      { "Magic", "db-lsp.magic",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Magic number", HFILL } },

    { &hf_length,
      { "Length", "db-lsp.length",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Length in bytes", HFILL } },

    { &hf_opvalue,
      { "OP Value", "db-lsp.op",
        FT_UINT8, BASE_DEC_HEX, VALS(op_vals), 0x0,
        NULL, HFILL } },

    { &hf_value,
      { "Value", "db-lsp.value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_data,
      { "Data", "db-lsp.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_text,
      { "Text", "db-lsp.text",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },
  };

  static gint *ett[] = {
    &ett_db_lsp,
  };

  module_t *db_lsp_module;

  proto_db_lsp = proto_register_protocol (PNAME, PSNAME, PFNAME);
  proto_db_lsp_disc = proto_register_protocol (PNAME_DISC, PSNAME_DISC, PFNAME_DISC);
  register_dissector ("db-lsp.tcp", dissect_db_lsp_tcp, proto_db_lsp);
  register_dissector ("db-lsp.udp", dissect_db_lsp_disc, proto_db_lsp_disc);

  proto_register_field_array (proto_db_lsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  /* Register our configuration options */
  db_lsp_module = prefs_register_protocol (proto_db_lsp, NULL);

  prefs_register_bool_preference (db_lsp_module, "desegment_pdus",
                                  "Reassemble PDUs spanning multiple TCP segments",
                                  "Whether the LAN sync dissector should reassemble PDUs"
                                  " spanning multiple TCP segments."
                                  " To use this option, you must also enable \"Allow subdissectors"
                                  " to reassemble TCP streams\" in the TCP protocol settings.",
                                  &db_lsp_desegment);
}

void
proto_reg_handoff_db_lsp (void)
{
  dissector_handle_t db_lsp_tcp_handle;
  dissector_handle_t db_lsp_udp_handle;

  db_lsp_tcp_handle = find_dissector ("db-lsp.tcp");
  db_lsp_udp_handle = find_dissector ("db-lsp.udp");

  dissector_add_uint ("tcp.port", DB_LSP_PORT, db_lsp_tcp_handle);
  dissector_add_uint ("udp.port", DB_LSP_PORT, db_lsp_udp_handle);
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
