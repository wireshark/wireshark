/* packet-hyperscsi.c
 * Routines for dissassembly of the Hyper SCSI protocol.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * Copyright 2002 Richard Sharpe <rsharpe@richardsharpe.com>
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

#include <glib.h>

#include <epan/packet.h>

void proto_register_hyperscsi(void);
void proto_reg_handoff_hyperscsi(void);

static int proto_hyperscsi;

static int hf_hs_cmd = -1;
static int hf_hs_ver = -1;
static int hf_hs_res = -1;
static int hf_hs_tagno = -1;
static int hf_hs_lastfrag = -1;
static int hf_hs_fragno = -1;

static gint ett_hyperscsi = -1;
static gint ett_hs_hdr = -1;
static gint ett_hs_pdu = -1;

static const true_false_string tfs_lastfrag = {
  "Last Fragment",
  "Not Last Fragment"
};

#define HSCSI_OPCODE_REQUEST                  0x00
#define HSCSI_OPCODE_REPLY                    0x01
#define HSCSI_OPCODE_DEV_DISCOVERY            0x10
#define HSCSI_OPCODE_ADN_REQUEST              0x11
#define HSCSI_OPCODE_ADN_REPLY                0x12
#define HSCSI_OPCODE_DISCONNECT               0x13
#define HSCSI_OPCODE_ACK_SNR                  0x20
#define HSCSI_OPCODE_ACK_REPLY                0x21
#define HSCSI_OPCODE_ADDR_REPORT              0x30
#define HSCSI_OPCODE_ADDR_REPLY               0x31
#define HSCSI_OPCODE_LOCAL_REQUEST            0x32
#define HSCSI_OPCODE_LOCAL_REPLY              0x33
#define HSCSI_OPCODE_REMOTE_REQUEST           0x34
#define HSCSI_OPCODE_REMOTE_REPLY             0x35

static const value_string hscsi_opcodes[] = {
  { HSCSI_OPCODE_REQUEST,         "Command Block Encap Request"},
  { HSCSI_OPCODE_REPLY,           "Command Block Encap Reply"},
  { HSCSI_OPCODE_DEV_DISCOVERY,   "Device Discovery Reply"},
  { HSCSI_OPCODE_ADN_REQUEST,     "Auth/Device Neg Request"},
  { HSCSI_OPCODE_ADN_REPLY,       "Auth/Device Neg Reply"},
  { HSCSI_OPCODE_DISCONNECT,      "Disconnect Request"},
  { HSCSI_OPCODE_ACK_SNR,         "Flow Control Setup/Ack Request"},
  { HSCSI_OPCODE_ACK_REPLY,       "Flow Control Ack Reply"},
  { 0, NULL}
};

#define OPCODE_MASK 0x7F

static void
dissect_hyperscsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint      hs_hdr1, hs_hdr2, hs_hdr3;
  guint8     hs_res;
  guint16    hs_tagno;
  guint16    hs_fragno;
  gint       offset = 0;
  proto_tree *hs_hdr_tree, *hs_pdu_tree;
  proto_tree *hs_tree = NULL;
  proto_item *ti;
  guint8     hs_cmd, hs_ver;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HyperSCSI");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_hyperscsi, tvb, offset, -1, ENC_NA);
    hs_tree = proto_item_add_subtree(ti, ett_hyperscsi);
  }

  hs_hdr1 = tvb_get_guint8(tvb, offset);
  offset++;
  hs_hdr2 = tvb_get_guint8(tvb, offset);
  offset++;
  hs_hdr3 = tvb_get_guint8(tvb, offset);
  offset++;

  hs_res = hs_hdr1 >> 4;
  hs_tagno = ((hs_hdr1 & 0x0F) << 5 ) | (hs_hdr2 >> 3);
  hs_fragno = ((hs_hdr2 &0X03) << 8 ) | hs_hdr3;

  /*
   * Add the header ... three bytes
   */

  if (tree) {
    ti = proto_tree_add_text(hs_tree, tvb, 0, 3, "HyperSCSI Header");
    hs_hdr_tree = proto_item_add_subtree(ti, ett_hs_hdr);

    /*
     * Now, add the header items
     */

    proto_tree_add_uint(hs_hdr_tree, hf_hs_res, tvb, 0, 1, hs_res);
    proto_tree_add_uint(hs_hdr_tree, hf_hs_tagno, tvb, 0, 2, hs_tagno);
    proto_tree_add_item(hs_hdr_tree, hf_hs_lastfrag, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(hs_hdr_tree, hf_hs_fragno, tvb, 1, 2, hs_fragno);

  }

  /*
   * Now, add the PDU
   */

  hs_ver = tvb_get_guint8(tvb, offset++);

  hs_cmd = tvb_get_guint8(tvb, offset);

  hs_cmd &= OPCODE_MASK;

  col_append_str(pinfo->cinfo, COL_INFO,
                   val_to_str(hs_cmd, hscsi_opcodes, "Unknown HyperSCSI Request or Response (%u)"));

  if (tree) {
    ti = proto_tree_add_text(hs_tree, tvb, 3, -1, "HyperSCSI PDU");
    hs_pdu_tree = proto_item_add_subtree(ti, ett_hs_pdu);

    proto_tree_add_uint(hs_pdu_tree, hf_hs_ver, tvb, 3, 1, hs_ver);

    proto_tree_add_uint(hs_pdu_tree, hf_hs_cmd, tvb, 4, 1, hs_cmd);
  }

}

void
proto_register_hyperscsi(void)
{

  static hf_register_info hf[] = {
    { &hf_hs_res,
      { "Reserved", "hyperscsi.reserved", FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},

    { &hf_hs_tagno,
      { "Tag No", "hyperscsi.tagno", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},

    { &hf_hs_lastfrag,
      { "Last Fragment", "hyperscsi.lastfrag", FT_BOOLEAN, 8, TFS(&tfs_lastfrag), 0x04, NULL, HFILL}},

    { &hf_hs_fragno,
      { "Fragment No", "hyperscsi.fragno", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},

    { &hf_hs_ver,
      { "HyperSCSI Version", "hyperscsi.version", FT_UINT8, BASE_DEC, NULL,
	0x0, NULL, HFILL}},

    { &hf_hs_cmd,
      { "HyperSCSI Command", "hyperscsi.cmd", FT_UINT8, BASE_DEC, VALS(hscsi_opcodes), 0x0,
	NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_hyperscsi,
    &ett_hs_hdr,
    &ett_hs_pdu,
  };

  proto_hyperscsi = proto_register_protocol("HyperSCSI", "HyperSCSI", "hyperscsi");
  proto_register_field_array(proto_hyperscsi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("hyperscsi", dissect_hyperscsi, proto_hyperscsi);
}

/* XXX <epan/etypes.h> */
#define ETHERTYPE_HYPERSCSI 0x889A

void
proto_reg_handoff_hyperscsi(void)
{
  dissector_handle_t hs_handle;

  hs_handle = find_dissector("hyperscsi");
  dissector_add_uint("ethertype", ETHERTYPE_HYPERSCSI, hs_handle);

}
