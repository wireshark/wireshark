/* packet-xdmcp.c
 * Routines for XDMCP message dissection
 * Copyright 2002, Pasi Eronen <pasi.eronen@nixu.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>

#define UDP_PORT_XDMCP 177

#define XDMCP_PROTOCOL_VERSION 1

#define XDMCP_BROADCAST_QUERY 1
#define XDMCP_QUERY 2
#define XDMCP_INDIRECT_QUERY 3
#define XDMCP_FORWARD_QUERY 4
#define XDMCP_WILLING 5
#define XDMCP_UNWILLING 6
#define XDMCP_REQUEST 7
#define XDMCP_ACCEPT 8
#define XDMCP_DECLINE 9
#define XDMCP_MANAGE 10
#define XDMCP_REFUSE 11
#define XDMCP_FAILED 12
#define XDMCP_KEEPALIVE 13
#define XDMCP_ALIVE 14

static const value_string opcode_vals[] = {
  { XDMCP_BROADCAST_QUERY, "Broadcast_query" },
  { XDMCP_QUERY, "Query" },
  { XDMCP_INDIRECT_QUERY, "Indirect_query" },
  { XDMCP_FORWARD_QUERY, "Forward_query" },
  { XDMCP_WILLING, "Willing" },
  { XDMCP_UNWILLING, "Unwilling" },
  { XDMCP_REQUEST, "Request" },
  { XDMCP_ACCEPT, "Accept "},
  { XDMCP_DECLINE, "Decline" },
  { XDMCP_MANAGE, "Manage" },
  { XDMCP_REFUSE, "Refuse" },
  { XDMCP_FAILED, "Failed" },
  { XDMCP_KEEPALIVE, "Keepalive" },
  { XDMCP_ALIVE, "Alive" },
  { 0, NULL }
};

/* Copied from packet-x11.c */
static const value_string family_vals[] = {
  { 0, "Internet" },
  { 1, "DECnet" },
  { 2, "Chaos" },
  { 6, "InternetV6" },
  { 0, NULL }
};

static gint proto_xdmcp = -1;
static gint hf_xdmcp_version = -1;
static gint hf_xdmcp_opcode = -1;
static gint hf_xdmcp_length = -1;
static gint hf_xdmcp_authentication_name = -1;
static gint hf_xdmcp_authorization_name = -1;
static gint hf_xdmcp_hostname = -1;
static gint hf_xdmcp_status = -1;
static gint hf_xdmcp_session_id = -1;
static gint hf_xdmcp_display_number = -1;
static gint hf_xdmcp_manufacturer_display_id = -1;
static gint hf_xdmcp_manufacturer_display_id_len = -1;
static gint hf_xdmcp_display_class = -1;
static gint hf_xdmcp_display_class_len = -1;
static gint hf_xdmcp_client_address_ipv4 = -1;
static gint hf_xdmcp_client_address_ipv6 = -1;
static gint hf_xdmcp_client_address_bytes = -1;
static gint hf_xdmcp_client_address_bytes_len = -1;
static gint hf_xdmcp_client_port_u16 = -1;
static gint hf_xdmcp_client_port_bytes = -1;
static gint hf_xdmcp_client_port_len = -1;
static gint hf_xdmcp_authentication_data = -1;
static gint hf_xdmcp_authentication_data_len = -1;
static gint hf_xdmcp_authorization_data = -1;
static gint hf_xdmcp_authorization_data_len = -1;
static gint hf_xdmcp_connection_type = -1;
static gint hf_xdmcp_connection_address_ipv4 = -1;
static gint hf_xdmcp_connection_address_ipv6 = -1;
static gint hf_xdmcp_connection_address_bytes = -1;
static gint hf_xdmcp_session_running = -1;

static gint ett_xdmcp = -1;
static gint ett_xdmcp_authentication_names = -1;
static gint ett_xdmcp_authorization_names = -1;
static gint ett_xdmcp_connections = -1;
static gint ett_xdmcp_connection = -1;

static gint xdmcp_add_string(proto_tree *tree, gint hf,
			     tvbuff_t *tvb, gint offset)
{
  char *str;
  guint len;

  len = tvb_get_ntohs(tvb, offset);
  str = tvb_get_ephemeral_string(tvb, offset+2, len);
  proto_tree_add_string(tree, hf, tvb, offset, len+2, str);

  return len+2;
}

static gint xdmcp_add_bytes(proto_tree *tree, gint hf_byte, gint hf_length,
		     tvbuff_t *tvb, gint offset)
{
  guint len;
  len = tvb_get_ntohs(tvb, offset);

  proto_tree_add_item(tree, hf_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_byte, tvb, offset, len+2, ENC_NA);
  return len+2;
}

static gint xdmcp_add_authentication_names(proto_tree *tree,
				    tvbuff_t *tvb, gint offset)
{
  proto_tree *anames_tree;
  proto_item *anames_ti;
  gint anames_len, anames_start_offset;

  anames_start_offset = offset;
  anames_len = tvb_get_guint8(tvb, offset);
  anames_ti = proto_tree_add_text(tree, tvb,
				  anames_start_offset, -1,
				  "Authentication names (%d)",
				  anames_len);
  anames_tree = proto_item_add_subtree(anames_ti,
				       ett_xdmcp_authentication_names);

  anames_len = tvb_get_guint8(tvb, offset);
  offset++;
  while (anames_len > 0) {
    offset += xdmcp_add_string(anames_tree, hf_xdmcp_authentication_name,
			       tvb, offset);
    anames_len--;
  }
  proto_item_set_len(anames_ti, offset - anames_start_offset);
  return offset - anames_start_offset;
}

static gint xdmcp_add_authorization_names(proto_tree *tree,
				    tvbuff_t *tvb, gint offset)
{
  proto_tree *anames_tree;
  proto_item *anames_ti;
  gint anames_len, anames_start_offset;

  anames_start_offset = offset;
  anames_len = tvb_get_guint8(tvb, offset);
  anames_ti = proto_tree_add_text(tree, tvb,
				  anames_start_offset, -1,
				  "Authorization names (%d)",
				  anames_len);
  anames_tree = proto_item_add_subtree(anames_ti,
				       ett_xdmcp_authorization_names);

  anames_len = tvb_get_guint8(tvb, offset);
  offset++;
  while (anames_len > 0) {
    offset += xdmcp_add_string(anames_tree, hf_xdmcp_authorization_name,
			       tvb, offset);
    anames_len--;
  }
  proto_item_set_len(anames_ti, offset - anames_start_offset);
  return offset - anames_start_offset;
}

/*
 * I didn't find any documentation for the XDMCP protocol, so
 * this is reverse-engineered from XFree86 source files
 * xc/programs/xdm/xdmcp.c and xc/programs/Xserver/os/xdmcp.c.
 */

static void dissect_xdmcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint version = -1, opcode = -1;
  gint offset = 0;
  proto_item *ti;
  proto_tree *xdmcp_tree = 0;

  version = tvb_get_ntohs(tvb, offset);
  if (version != XDMCP_PROTOCOL_VERSION) {
    /* Only version 1 exists, so this probably is not XDMCP at all... */
    return;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "XDMCP");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_xdmcp, tvb, offset, -1, ENC_NA);
  xdmcp_tree = proto_item_add_subtree(ti, ett_xdmcp);

  proto_tree_add_uint(xdmcp_tree, hf_xdmcp_version, tvb,
			offset, 2, version);

  offset += 2;

  opcode = tvb_get_ntohs(tvb, offset);
  if (tree) {
    proto_tree_add_uint(xdmcp_tree, hf_xdmcp_opcode, tvb,
			offset, 2, opcode);
  }
  offset += 2;
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO,
                 val_to_str(opcode, opcode_vals, "Unknown (0x%04x)"));

  }

  if (tree) {
    proto_tree_add_item(xdmcp_tree, hf_xdmcp_length, tvb,
			offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (opcode) {
      case XDMCP_FORWARD_QUERY:
      {
	gint alen, plen;
	alen = tvb_get_ntohs(tvb, offset);
	/* I have never seen anything except IPv4 addresses here,
	 * but in theory the protocol should support other address
	 * families. */
	if (alen == 4) {
      proto_tree_add_item(xdmcp_tree, hf_xdmcp_client_address_ipv4, tvb, offset+2, alen, ENC_BIG_ENDIAN);
	  offset += 6;
	} else if (alen == 16) {
      proto_tree_add_item(xdmcp_tree, hf_xdmcp_client_address_ipv6, tvb, offset+2, alen, ENC_BIG_ENDIAN);
	  offset += 18;
	} else {
	  offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_client_address_bytes, hf_xdmcp_client_address_bytes_len,
                                tvb, offset);
	}

	plen = tvb_get_ntohs(tvb, offset);
	if (plen == 2) {
      proto_tree_add_item(xdmcp_tree, hf_xdmcp_client_port_u16, tvb, offset+2, plen, ENC_BIG_ENDIAN);
	  offset += 4;
	} else {
	  offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_client_port_bytes, hf_xdmcp_client_port_len,
                    tvb, offset);
	}
      }
      /* fall-through */

      case XDMCP_BROADCAST_QUERY:
      case XDMCP_QUERY:
      case XDMCP_INDIRECT_QUERY:
	offset += xdmcp_add_authentication_names(xdmcp_tree, tvb, offset);
	break;

      case XDMCP_WILLING:
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_authentication_name,
				   tvb, offset);
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_hostname,
				   tvb, offset);
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_status,
				   tvb, offset);
	break;

      case XDMCP_UNWILLING:
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_hostname,
				   tvb, offset);
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_status,
				   tvb, offset);
	break;

      case XDMCP_REQUEST:
      {
	proto_tree *clist_tree;
	proto_item *clist_ti;
	gint ctypes_len, caddrs_len, n;
	gint ctypes_start_offset, caddrs_offset;

	ti = proto_tree_add_item(xdmcp_tree, hf_xdmcp_display_number, tvb,
			    offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	ctypes_len = tvb_get_guint8(tvb, offset);
	ctypes_start_offset = offset;
	caddrs_offset = offset + 1 + 2*ctypes_len;
	caddrs_len = tvb_get_guint8(tvb, caddrs_offset);
	if (ctypes_len != caddrs_len) {
        expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Error: Connection type/address arrays don't match");
	  return;
	}

	clist_ti = proto_tree_add_text(xdmcp_tree,
				       tvb, ctypes_start_offset, -1,
				       "Connections (%d)",
				       ctypes_len);
	clist_tree = proto_item_add_subtree(clist_ti, ett_xdmcp_connections);

	offset++;
	caddrs_offset++;

	n = 1;
	while (ctypes_len > 0) {
	  proto_item *connection_ti;
	  proto_tree *connection_tree;

	  gint alen;
	  gint ctype = tvb_get_ntohs(tvb, offset);
	  offset += 2;
	  alen = tvb_get_ntohs(tvb, caddrs_offset);
	  caddrs_offset += 2;

	  connection_ti = proto_tree_add_text(clist_tree, NULL, 0, 0,
					      "Connection %d", n);
	  connection_tree = proto_item_add_subtree(connection_ti,
						   ett_xdmcp_connection);

      proto_tree_add_item(connection_tree, hf_xdmcp_connection_type, tvb, offset-2, 2, ENC_BIG_ENDIAN);

	  if ((ctype == 0) && (alen == 4)) {
          proto_tree_add_item(connection_tree, hf_xdmcp_connection_address_ipv4, tvb, caddrs_offset, alen, ENC_BIG_ENDIAN);
          proto_item_append_text(connection_ti, ": %s", tvb_ip_to_str(tvb, caddrs_offset));
      } else if ((ctype == 6) && (alen == 16)) {
          proto_tree_add_item(connection_tree, hf_xdmcp_connection_address_ipv6, tvb, caddrs_offset, alen, ENC_BIG_ENDIAN);
          proto_item_append_text(connection_ti, ": %s", tvb_ip6_to_str(tvb, caddrs_offset));
      } else {
          proto_tree_add_item(connection_tree, hf_xdmcp_connection_address_bytes, tvb, caddrs_offset, alen, ENC_NA);
      }

      caddrs_offset += alen;
	  ctypes_len--;
	  n++;
	}
	offset = caddrs_offset;
	proto_item_set_len(clist_ti, offset - ctypes_start_offset);

	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_authentication_name,
				   tvb, offset);
	offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_authentication_data, hf_xdmcp_authentication_data_len, 
				   tvb, offset);

	offset += xdmcp_add_authorization_names(xdmcp_tree, tvb, offset);

	offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_manufacturer_display_id, hf_xdmcp_manufacturer_display_id_len,
				 tvb, offset);
	break;
      }

      case XDMCP_ACCEPT:
	proto_tree_add_item(xdmcp_tree, hf_xdmcp_session_id, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_authentication_name,
				   tvb, offset);
	offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_authentication_data, hf_xdmcp_authentication_data_len, 
				   tvb, offset);
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_authorization_name,
				   tvb, offset);
	offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_authorization_data, hf_xdmcp_authorization_data_len, 
				   tvb, offset);
	break;

      case XDMCP_DECLINE:
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_status,
				   tvb, offset);
	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_authentication_name,
				   tvb, offset);
	offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_authentication_data, hf_xdmcp_authentication_data_len, 
				   tvb, offset);
	break;

      case XDMCP_MANAGE:
	proto_tree_add_item(xdmcp_tree, hf_xdmcp_session_id, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(xdmcp_tree, hf_xdmcp_display_number, tvb,
			    offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	offset += xdmcp_add_bytes(xdmcp_tree, hf_xdmcp_display_class, hf_xdmcp_display_class_len,
				 tvb, offset);
	break;

      case XDMCP_REFUSE:
	proto_tree_add_item(xdmcp_tree, hf_xdmcp_session_id, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	break;

      case XDMCP_FAILED:
	proto_tree_add_item(xdmcp_tree, hf_xdmcp_session_id, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	offset += xdmcp_add_string(xdmcp_tree, hf_xdmcp_status,
				   tvb, offset);
	break;

      case XDMCP_KEEPALIVE:
	proto_tree_add_item(xdmcp_tree, hf_xdmcp_display_number, tvb,
			    offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(xdmcp_tree, hf_xdmcp_session_id, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	break;

      case XDMCP_ALIVE:
      {
    guint8 session_running = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(xdmcp_tree, hf_xdmcp_session_running, tvb,
			    offset, 1, session_running, "Session running: %s", session_running ? "Yes" : "No");
	offset++;

	proto_tree_add_item(xdmcp_tree, hf_xdmcp_session_id, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
      }
	break;
    }
  }
}

/* Register the protocol with Wireshark */
void proto_register_xdmcp(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_xdmcp_version,
      { "Version",           "xdmcp.version",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Protocol version", HFILL }
    },
    { &hf_xdmcp_opcode,
      { "Opcode",              "xdmcp.opcode",
      FT_UINT16, BASE_HEX, VALS(opcode_vals), 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_length,
      { "Message length",     "xdmcp.length",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Length of the remaining message", HFILL }
    },
    { &hf_xdmcp_authentication_name,
      { "Authentication name",     "xdmcp.authentication_name",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_authorization_name,
      { "Authorization name",     "xdmcp.authorization_name",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_hostname,
      { "Hostname",     "xdmcp.hostname",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_status,
      { "Status",     "xdmcp.status",
      FT_STRING, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_session_id,
      { "Session ID",     "xdmcp.session_id",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Session identifier", HFILL }
    },
    { &hf_xdmcp_display_number,
      { "Display number",     "xdmcp.display_number",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_manufacturer_display_id_len,
      { "Manufacturer display ID Length",     "xdmcp.manufacturer_display_id_len",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_manufacturer_display_id,
      { "Manufacturer display ID",     "xdmcp.manufacturer_display_id",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_display_class_len,
      { "Display class Length",     "xdmcp.display_class_len",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_display_class,
      { "Display class",     "xdmcp.display_class",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    /* XXX - the following 3 could be the same filter, but mixed types of the same filter seem to cause issues */
    { &hf_xdmcp_client_address_ipv4,
      { "Client Address",     "xdmcp.client_address_ipv4",
      FT_IPv4, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_client_address_ipv6,
      { "Client Address",     "xdmcp.client_address_ipv6",
      FT_IPv6, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_client_address_bytes,
      { "Client Address",     "xdmcp.client_address_bytes",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_client_address_bytes_len,
      { "Client Address Length",     "xdmcp.client_address_bytes_len",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_client_port_len,
      { "Client port Length",     "xdmcp.client_port_len",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_client_port_bytes,
      { "Client port",     "xdmcp.client_port_bytes",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_client_port_u16,
      { "Client port",     "xdmcp.client_port",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_authentication_data_len,
      { "Authentication data Length",     "xdmcp.authentication_data_len",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_authentication_data,
      { "Authentication data",     "xdmcp.authentication_data",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_authorization_data_len,
      { "Authorization data Length",     "xdmcp.authorization_data_len",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_authorization_data,
      { "Authorization data",     "xdmcp.authorization_data",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    /* XXX - the following 3 could be the same filter, but mixed types of the same filter seem to cause issues */
    { &hf_xdmcp_connection_address_ipv4,
      { "Address",     "xdmcp.connection_address_ipv4",
      FT_IPv4, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_connection_address_ipv6,
      { "Address",     "xdmcp.connection_address_ipv6",
      FT_IPv6, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_connection_address_bytes,
      { "Address",     "xdmcp.connection_address_bytes",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_connection_type,
      { "Type",     "xdmcp.connection_type",
      FT_UINT16, BASE_HEX, VALS(family_vals), 0,
      NULL, HFILL }
    },
    { &hf_xdmcp_session_running,
      { "Session running",     "xdmcp.session_running",
      FT_UINT8, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_xdmcp,
    &ett_xdmcp_authentication_names,
    &ett_xdmcp_authorization_names,
    &ett_xdmcp_connections,
    &ett_xdmcp_connection
  };

  /* Register the protocol name and description */
  proto_xdmcp = proto_register_protocol("X Display Manager Control Protocol",
					"XDMCP", "xdmcp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_xdmcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_xdmcp(void)
{
  dissector_handle_t xdmcp_handle;

  xdmcp_handle = create_dissector_handle(dissect_xdmcp, proto_xdmcp);
  dissector_add_uint("udp.port", UDP_PORT_XDMCP, xdmcp_handle);
}
