/* packet-gvcp.c
 * Routines for gvcp (GigEVision Control Protocol) dissection
 * Copyright 2010, Adrian Daerr <adrian.daerr@gmx.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */
/*
 * Credits to Falco Hirschenberger for his description of GVCP
 * ( http://gitorious.org/opengigevision )
 *
 * GVCP is part of the GigE-Vision interface (a closed standard) to
 * so-called industrial cameras.
 *
 * see also: http://en.wikipedia.org/wiki/GigE_vision
 *
 * This dissector is based on traffic analysis alone, as the
 * description of the GVCP is accessible only to members of the
 * Automated Imaging Association. The resulting packet description is
 * therefore likely to be incomplete or inaccurate.
 *
 * TODO:
 * - fill holes (missing opcodes / field meanings / ...)
 * - conversation level:
 *   . validity of anwers (is CMD packet properly ACK'ed by follow-up packet?)
 *   . reassemble, unzip, store and parse XML file, so that addresses
 *     may be translated back into register names
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>

#define GVCP_PORT 3956

static int proto_gvcp = -1;
static int hf_gvcp_type = -1;
static int hf_gvcp_opcode = -1;
static int hf_gvcp_payloadsize = -1;
static int hf_gvcp_sequenceno = -1;
static int hf_gvcp_address = -1;
static int hf_gvcp_value = -1;
static int hf_gvcp_address2 = -1;
static int hf_gvcp_value2 = -1;
static int hf_gvcp_remainder = -1;
static int hf_gvcp_nwritten = -1;
static int hf_gvcp_nbytes = -1;
static int hf_gvcp_unknown16 = -1;
static int hf_gvcp_data = -1;
static int hf_gvcp_ip = -1;
static int hf_gvcp_ether = -1;
static int hf_gvcp_netmask = -1;
static gint ett_gvcp = -1;

static const value_string opcode_names[] = {
  { 0x02, "Discovery ping" },
  { 0x03, "Discovery pong" },
  { 0x04, "Assign IP" },
  { 0x05, "Ack IP change" },
  { 0x40, "Resend request" },
  { 0x80, "Register read request" },
  { 0x81, "Register read answer" },
  { 0x82, "Register write request" },
  { 0x83, "Register write answer" },
  { 0x84, "MemBlock read request" },
  { 0x85, "MemBlock read answer" },
  { 0x86, "MemBlock write request" },
  { 0x87, "MemBlock write answer" },
  { 0, NULL }
};

static const value_string opcode_short_names[] = {
  { 0x02, "Disc_Ping" },
  { 0x03, "Disc_Pong" },
  { 0x04, "Assign IP" },
  { 0x05, "Ack IP" },
  { 0x40, "Res_Req" },
  { 0x80, "Reg_Rd_Req" },
  { 0x81, "Reg_Rd_Ans" },
  { 0x82, "Reg_Wr_Req" },
  { 0x83, "Reg_Wr_Ans" },
  { 0x84, "Blk_Rd_Req" },
  { 0x85, "Blk_Rd_Ans" },
  { 0x86, "Blk_Wr_Req" },
  { 0x87, "Blk_Wr_Ans" },
  { 0, NULL }
};

static int
dissect_gvcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 packet_type, packet_opcode, packet_plsize;
  emem_strbuf_t *info;

  /* Check that there's enough data */
  if (tvb_length(tvb) < 8)
    return 0;

  /* Do some tests on what seems to be PDU field to determine if we
     really have a GVCP packet here, otherwise return 0 to give
     another dissector a chance to dissect it. */
  packet_type = tvb_get_ntohs(tvb, 0);

  /* packets from the PC to the camera on GVCP_PORT seem to always
     start with 0x4201 or 0x4200 */
  if ( pinfo->destport == GVCP_PORT &&
       (packet_type != 0x4200 && packet_type != 0x4201) )
    return 0;

  /* packets from the camera GVCP_PORT to the PC seem to start
     with 0x0000, but can be different on error condition (e.g. 0x8005) */
#if 0
  if ( pinfo->srcport == GVCP_PORT && tvb_get_ntohs(tvb, 0) != 0x0 )
    return 0;
#endif

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GVCP");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  /* dissect 8 byte header */
  packet_opcode = tvb_get_ntohs(tvb, 2);
  packet_plsize = tvb_get_ntohs(tvb, 4);

  /* allocate growable info string */
  info = ep_strbuf_new(val_to_str(packet_opcode, opcode_names, "Unknown opcode (0x%04x)"));

  /* check that GVCP header+payload match total packet size */
  if (tvb_reported_length(tvb) < 8+(guint32)packet_plsize) {
    ep_strbuf_append_printf(info, " (truncated? %u bytes missing)",
                            (8 + packet_plsize) - tvb_reported_length(tvb));
    col_add_str(pinfo->cinfo, COL_INFO, info->str);
    return tvb_length(tvb);/* or should we assume this is not GVCP, return 0?*/
  }
  if (tvb_reported_length(tvb) > 8+(guint32)packet_plsize) {
    ep_strbuf_append_printf(info, " (%u excess bytes)",
                            tvb_reported_length(tvb) - (8 + packet_plsize));
    col_add_str(pinfo->cinfo, COL_INFO, info->str);
    return tvb_length(tvb);/* or should we assume this is not GVCP, return 0?*/
  }
  if (packet_plsize & 3) {/* payload is always a multiple of 4 bytes */
    ep_strbuf_append(info, " (payload is not multiple of 4 bytes)");
    col_add_str(pinfo->cinfo, COL_INFO, info->str);
    return tvb_length(tvb);/* or should we assume this is not GVCP, return 0?*/
  }

  /* switch just concerned with building a meaningfull Info column string */

  switch (packet_opcode) {
  case 0x04: /* Assign new temporary IP */
    if (packet_plsize < 24) {/* 56 bytes seem to be normal */
      ep_strbuf_append(info, " <missing args>");
    } else { /* packet contain new network configuration */
      ep_strbuf_append_printf(info, "%d.%d.%d.%d to %s",
                              tvb_get_guint8(tvb, 28), tvb_get_guint8(tvb, 29),
                              tvb_get_guint8(tvb, 30), tvb_get_guint8(tvb, 31),
                              tvb_bytes_to_str_punct(tvb, 10, 6, ':'));
    }
    break;
  case 0x80: /* Register Read Request */
  case 0x81: /* Register Read Answer */
    if (packet_plsize == 0) {
      ep_strbuf_append(info, " <missing arg(s)>");
    } else { /* packet contains address(es) to read from */
      ep_strbuf_append_printf(info, " 0x%08x", tvb_get_ntohl(tvb, 8));
      if (packet_plsize >= 8) {
        ep_strbuf_append_printf(info, ", 0x%08x", tvb_get_ntohl(tvb, 12));
        if (packet_plsize >= 12)
          ep_strbuf_append(info, ", ...");
      }
    }
    break;
  case 0x82: /* Register Write Request */
    if (packet_plsize < 8) {
      ep_strbuf_append(info, " <missing arg(s)>");
    } else { /* packet contains address/value pairs to read from */
      ep_strbuf_append_printf(info, " *0x%08x = 0x%08x", tvb_get_ntohl(tvb, 8),
                              tvb_get_ntohl(tvb, 12));
      if (packet_plsize >= 16) {
        ep_strbuf_append_printf(info, ", *0x%08x = 0x%08x",
                                tvb_get_ntohl(tvb, 16), tvb_get_ntohl(tvb, 20));
        if (packet_plsize >= 24)
          ep_strbuf_append(info, ", ...");
      }
    }
    break;
  case 0x83: /* Register Write Answer */
    if (packet_plsize < 4) {
      ep_strbuf_append(info, " <missing arg>");
    } else {
      ep_strbuf_append_printf(info, " %d register%s written",
                              tvb_get_ntohl(tvb, 8),
                              tvb_get_ntohl(tvb, 8)==1?"":"s");
    }
    break;
  case 0x84: /* Block Read Request */
    if (packet_plsize < 8) {
      ep_strbuf_append(info, " <missing args>");
    } else { /* packet contains address/size pair to read from */
      ep_strbuf_append_printf(info, " 0x%08x (%d bytes, X=0x%04x)",
                              tvb_get_ntohl(tvb, 8), tvb_get_ntohs(tvb, 14),
                              tvb_get_ntohs(tvb, 12));
      if (packet_plsize > 8) {
        ep_strbuf_append(info, "; excess payload");
      }
    }
    break;
  case 0x85: /* Block Read Answer */
    if (packet_plsize < 8) {
      ep_strbuf_append(info, " <missing args>");
    } else { /* packet contains desired data */
      ep_strbuf_append_printf(info, " %d bytes from 0x%08x", packet_plsize - 4,
                              tvb_get_ntohl(tvb, 8));
    }
    break;
  case 0x86: /* Block Write Request */
    if (packet_plsize < 8) {
      ep_strbuf_append(info, " <missing args>");
    } else { /* packet contains desired data */
      ep_strbuf_append_printf(info, " *0x%08x = <%d bytes>",
                              tvb_get_ntohl(tvb, 8), packet_plsize - 4);
    }
    break;
  case 0x87: /* Block Write Answer */
    if (packet_plsize < 4) {
      ep_strbuf_append(info, " <missing arg>");
    } else {
      ep_strbuf_append_printf(info, " %d bytes written", tvb_get_ntohl(tvb, 8));
    }
    break;
  }

  col_add_str(pinfo->cinfo, COL_INFO, info->str);

  if (tree) { /* we are being asked for details */
    proto_item *ti = NULL;
    proto_tree *gvcp_tree = NULL;

    ti = proto_tree_add_item(tree, proto_gvcp, tvb, 0, -1, FALSE);
    gvcp_tree = proto_item_add_subtree(ti, ett_gvcp);
    proto_tree_add_item(gvcp_tree, hf_gvcp_type, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gvcp_tree, hf_gvcp_opcode, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gvcp_tree, hf_gvcp_payloadsize, tvb, 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gvcp_tree, hf_gvcp_sequenceno, tvb, 6, 2, ENC_BIG_ENDIAN);

    /* opcode specific fields */
    switch (packet_opcode) {
    case 0x04: /* Assign new temporary network configuration */
      if (packet_plsize >= 48) {
        proto_tree_add_item(gvcp_tree, hf_gvcp_ether, tvb, 10, 6, ENC_NA);
        proto_tree_add_item(gvcp_tree, hf_gvcp_ip, tvb, 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(gvcp_tree, hf_gvcp_netmask, tvb, 44, 4, ENC_BIG_ENDIAN);
      }
      break;
    case 0x80: /* Register Read Request */
      if (packet_plsize >= 4) {
        proto_tree_add_item(gvcp_tree, hf_gvcp_address, tvb, 8, 4, ENC_BIG_ENDIAN);
        if (packet_plsize >= 8) {
          proto_tree_add_item(gvcp_tree, hf_gvcp_address2, tvb, 12, 4, ENC_BIG_ENDIAN);
          if (packet_plsize >= 12)
            proto_tree_add_item(gvcp_tree, hf_gvcp_remainder, tvb, 16, -1, ENC_NA);
        }
      }
      break;
    case 0x81: /* Register Read Answer */
      if (packet_plsize >= 4) {
        proto_tree_add_item(gvcp_tree, hf_gvcp_value, tvb, 8, 4, ENC_BIG_ENDIAN);
        if (packet_plsize >= 8) {
          proto_tree_add_item(gvcp_tree, hf_gvcp_value2, tvb, 12, 4, ENC_BIG_ENDIAN);
          if (packet_plsize >= 12)
            proto_tree_add_item(gvcp_tree, hf_gvcp_remainder, tvb, 16, -1, ENC_NA);
        }
      }
      break;
    case 0x82: /* Register Write Request */
      if (packet_plsize >= 8) {
        proto_tree_add_item(gvcp_tree, hf_gvcp_address, tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(gvcp_tree, hf_gvcp_value, tvb, 12, 4, ENC_BIG_ENDIAN);
        if (packet_plsize >= 16) {
          proto_tree_add_item(gvcp_tree, hf_gvcp_address2, tvb, 16, 4, ENC_BIG_ENDIAN);
          proto_tree_add_item(gvcp_tree, hf_gvcp_value2, tvb, 20, 4, ENC_BIG_ENDIAN);
          if (packet_plsize >= 24)
            proto_tree_add_item(gvcp_tree, hf_gvcp_remainder, tvb, 24, -1, ENC_NA);
        }
      }
      break;
    case 0x83: /* Register Write Answer */
      if (packet_plsize >= 4)
        proto_tree_add_item(gvcp_tree, hf_gvcp_nwritten, tvb, 8, 4, ENC_BIG_ENDIAN);
      break;
    case 0x84: /* Block Read Request */
      if (packet_plsize >= 8) {
        proto_tree_add_item(gvcp_tree, hf_gvcp_address, tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(gvcp_tree, hf_gvcp_unknown16, tvb, 12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(gvcp_tree, hf_gvcp_nbytes, tvb, 14, 2, ENC_BIG_ENDIAN);
      }
      break;
    case 0x85: /* Block Read Answer */
    case 0x86: /* Block Write Request */
      if (packet_plsize >= 8) {
        proto_tree_add_item(gvcp_tree, hf_gvcp_address, tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(gvcp_tree, hf_gvcp_data, tvb, 12, -1, ENC_NA);
      }
      break;
    case 0x87: /* Block Write Answer */
      if (packet_plsize >= 4)
        proto_tree_add_item(gvcp_tree, hf_gvcp_nbytes, tvb, 10, 2, ENC_BIG_ENDIAN);
      break;
    default:
      if (packet_plsize > 0)
        proto_tree_add_item(gvcp_tree, hf_gvcp_data, tvb, 8, -1, ENC_NA);
      break;
    }

  }

  return tvb_length(tvb);
}

void
proto_register_gvcp(void)
{
  static hf_register_info hf[] = {
    { &hf_gvcp_type,
      { "GVCP Type", "gvcp.type",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_opcode,
      { "GVCP Opcode", "gvcp.opcode",
        FT_UINT16, BASE_HEX,
        VALS(opcode_names), 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_payloadsize,
      { "GVCP Payload bytes", "gvcp.size",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_sequenceno,
      { "GVCP Sequence number", "gvcp.seqn",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_address,
      { "Address", "gvcp.address",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_value,
      { "Value", "gvcp.value",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_address2,
      { "Address 2", "gvcp.address2",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_value2,
      { "Value 2", "gvcp.value2",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_remainder,
      { "Remaining arguments", "gvcp.remainder",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_nwritten,
      { "Number of registers written", "gvcp.nwritten",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_nbytes,
      { "Number of bytes", "gvcp.nbytes",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_unknown16,
      { "2-byte unknown meaning", "gvcp.unknown16",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_data,
      { "Data", "gvcp.data",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_ether,
      { "Link layer address (ethernet)", "gvcp.ether",
        FT_ETHER, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_ip,
      { "IPv4 address", "gvcp.ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gvcp_netmask,
      { "Netmask", "gvcp.netmask",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_gvcp
  };

  proto_gvcp = proto_register_protocol ("GigE Vision Control Protocol",	/*name*/
                                        "GVCP",		/* short name */
                                        "gvcp"		/* abbrev     */);

  proto_register_field_array(proto_gvcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_gvcp(void)
{
  dissector_handle_t gvcp_handle;

  gvcp_handle = new_create_dissector_handle(dissect_gvcp, proto_gvcp);
  dissector_add_uint("udp.port", GVCP_PORT, gvcp_handle);
}

