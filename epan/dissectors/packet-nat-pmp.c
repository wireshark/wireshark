/* packet-nat-pmp.c
 * Routines for NAT Port Mapping Protocol packet disassembly.
 * draft-cheshire-nat-pmp-03
 * http://files.dns-sd.org/draft-cheshire-nat-pmp.txt
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
#include <epan/expert.h>

#define PNAME  "NAT Port Mapping Protocol"
#define PSNAME "NAT-PMP"
#define PFNAME "nat-pmp"

#define NAT_PMP_STATUS_PORT  5350
#define NAT_PMP_PORT         5351

/* opcodes */
#define EXTERNAL_ADDRESS_REQUEST      0
#define MAP_UDP_REQUEST               1
#define MAP_TCP_REQUEST               2
#define EXTERNAL_ADDRESS_RESPONSE   128
#define MAP_UDP_RESPONSE            129
#define MAP_TCP_RESPONSE            130

static int proto_nat_pmp = -1;

static int hf_version = -1;
static int hf_opcode = -1;
static int hf_result_code = -1;
static int hf_sssoe = -1;
static int hf_external_ip = -1;
static int hf_reserved = -1;
static int hf_internal_port = -1;
static int hf_external_port_requested = -1;
static int hf_external_port_mapped = -1;
static int hf_rpmlis = -1;
static int hf_pmlis = -1;

static gint ett_nat_pmp = -1;

static const value_string opcode_vals[] = {
  { EXTERNAL_ADDRESS_REQUEST,  "External Address Request"   },
  { EXTERNAL_ADDRESS_RESPONSE, "External Address Response"  },
  { MAP_UDP_REQUEST,           "Map UDP Request"            },
  { MAP_UDP_RESPONSE,          "Map UDP Response"           },
  { MAP_TCP_REQUEST,           "Map TCP Request"            },
  { MAP_TCP_RESPONSE,          "Map TCP Response"           },
  { 0, NULL }
};

static const value_string result_vals[] = {
  { 0, "Success"                },
  { 1, "Unsupported Version"    },
  { 2, "Not Authorized/Refused" },
  { 3, "Network Failure"        },
  { 4, "Out of resources"       },
  { 5, "Unsupported opcode"     },
  { 0, NULL }
};

static void dissect_nat_pmp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *nat_pmp_tree;
  proto_item *ti, *op_ti;
  gint offset = 0;
  guint8 opcode;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item (tree, proto_nat_pmp, tvb, offset, -1, ENC_NA);
  nat_pmp_tree = proto_item_add_subtree (ti, ett_nat_pmp);

  proto_tree_add_item (nat_pmp_tree, hf_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  opcode = tvb_get_guint8 (tvb, offset);
  proto_item_append_text (ti, ", %s", val_to_str (opcode, opcode_vals, "Unknown opcode: %d"));
  op_ti = proto_tree_add_item (nat_pmp_tree, hf_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  col_add_str (pinfo->cinfo, COL_INFO, val_to_str (opcode, opcode_vals, "Unknown opcode: %d"));

  switch (opcode) {

  case EXTERNAL_ADDRESS_REQUEST:
    /* No more data */
    break;

  case EXTERNAL_ADDRESS_RESPONSE:
    proto_tree_add_item (nat_pmp_tree, hf_result_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item (nat_pmp_tree, hf_sssoe, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item (nat_pmp_tree, hf_external_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  case MAP_UDP_REQUEST:
  case MAP_TCP_REQUEST:
    proto_tree_add_item (nat_pmp_tree, hf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item (nat_pmp_tree, hf_internal_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    
    proto_tree_add_item (nat_pmp_tree, hf_external_port_requested, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item (nat_pmp_tree, hf_rpmlis, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  case MAP_UDP_RESPONSE:
  case MAP_TCP_RESPONSE:
    proto_tree_add_item (nat_pmp_tree, hf_result_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item (nat_pmp_tree, hf_sssoe, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item (nat_pmp_tree, hf_internal_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    
    proto_tree_add_item (nat_pmp_tree, hf_external_port_mapped, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item (nat_pmp_tree, hf_pmlis, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  default:
    /* Unknown OP */
    expert_add_info_format (pinfo, op_ti, PI_RESPONSE_CODE, PI_WARN, "Unknown opcode: %d", opcode);
    break;
  }
}

void proto_register_nat_pmp (void)
{
  static hf_register_info hf[] = {
    { &hf_version,
      { "Version", "nat-pmp.version", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_opcode,
      { "Opcode", "nat-pmp.opcode", FT_UINT8, BASE_DEC,
        VALS(opcode_vals), 0x0, NULL, HFILL } },
    { &hf_result_code,
      { "Result Code", "nat-pmp.result_code", FT_UINT16, BASE_DEC,
        VALS(result_vals), 0x0, NULL, HFILL } },
    { &hf_sssoe,
      { "Seconds Since Start of Epoch", "nat-pmp.sssoe", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_external_ip,
      { "External IP Address", "nat-pmp.external_ip", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_reserved,
      { "Reserved", "nat-pmp.reserved", FT_UINT16, BASE_DEC,
        NULL, 0x0, "Reserved (must be zero)", HFILL } },
    { &hf_internal_port,
      { "Internal Port", "nat-pmp.internal_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_external_port_requested,
      { "Requested External Port", "nat-pmp.external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_external_port_mapped,
      { "Mapped External Port", "nat-pmp.external_port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
    { &hf_rpmlis,
      { "Requested Port Mapping Lifetime", "nat-pmp.pml", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Requested Port Mapping Lifetime in Seconds", HFILL } },
    { &hf_pmlis,
      { "Port Mapping Lifetime", "nat-pmp.pml", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Port Mapping Lifetime in Seconds", HFILL } },
  };

  static gint *ett[] = {
    &ett_nat_pmp,
  };

  proto_nat_pmp = proto_register_protocol (PNAME, PSNAME, PFNAME);
  register_dissector (PFNAME, dissect_nat_pmp, proto_nat_pmp);
  
  proto_register_field_array (proto_nat_pmp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void proto_reg_handoff_nat_pmp (void)
{
  dissector_handle_t nat_pmp_handle;

  nat_pmp_handle = find_dissector (PFNAME);
  dissector_add_uint ("udp.port", NAT_PMP_STATUS_PORT, nat_pmp_handle);
  dissector_add_uint ("udp.port", NAT_PMP_PORT, nat_pmp_handle);
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
