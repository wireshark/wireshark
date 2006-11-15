/* packet-omapi.c
 * ISC OMAPI (Object Management API) dissector
 * Copyright 2006, Jaap Keuter <jaap.keuter@xs4all.nl>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * From the description api+protocol.
 * All fields are 32 bit unless stated otherwise.
 *
 * On startup, each side sends a status message indicating what version
 * of the protocol they are speaking. The status message looks like this:
 * +---------+---------+
 * | version | hlength |
 * +---------+---------+
 *
 * The fixed-length header consists of:
 * +--------+----+--------+----+-----+---------+------------+------------+-----+
 * | authid | op | handle | id | rid | authlen | msg values | obj values | sig |
 * +--------+----+--------+----+-----+---------+------v-----+-----v------+--v--+
 * NOTE: real life capture shows order to be: authid, authlen, opcode, handle...
 *
 * The message and object values consists of:
 * +---------+------+----------+-------+
 * | namelen | name | valuelen | value |
 * +---16b---+--v---+----------+---v---+
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/ptvcursor.h>

static int proto_omapi = -1;
static int hf_omapi_version = -1;
static int hf_omapi_hlength = -1;
static int hf_omapi_auth_id = -1;
static int hf_omapi_auth_len = -1;
static int hf_omapi_opcode = -1;
static int hf_omapi_handle = -1;
static int hf_omapi_id = -1;
static int hf_omapi_rid = -1;
static int hf_omapi_msg_name_len = -1; /* 16bit */
static int hf_omapi_msg_name = -1;
static int hf_omapi_msg_value_len = -1;
static int hf_omapi_msg_value = -1;
static int hf_omapi_obj_name_len = -1; /* 16bit */
static int hf_omapi_obj_name = -1;
static int hf_omapi_obj_value_len = -1;
static int hf_omapi_obj_value = -1;
static int hf_omapi_signature = -1;

static gint ett_omapi = -1;

#define OMAPI_PORT 7911

#define OP_OPEN		1
#define OP_REFRESH	2
#define OP_UPDATE	3
#define OP_NOTIFY	4
#define OP_ERROR	5
#define OP_DELETE	6
#define OP_NOTIFY_CANCEL	7
#define OP_NOTIFY_CANCELLED	8

static const value_string omapi_opcode_vals[] = {
  { OP_OPEN,	"Open" },
  { OP_REFRESH,	"Refresh" },
  { OP_UPDATE, 	"Update" },
  { OP_NOTIFY, 	"Notify" },
  { OP_ERROR, 	"Error" },
  { OP_DELETE, 	"Delete" },
  { OP_NOTIFY_CANCEL, 	"Notify cancel" },
  { OP_NOTIFY_CANCELLED,"Notify cancelled" },
  { 0, NULL }
};

static void
dissect_omapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *omapi_tree;
  ptvcursor_t* cursor;

  guint32 authlength;
  guint32 msglength;
  guint32 objlength;


  if (check_col(pinfo->cinfo, COL_PROTOCOL))
  {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OMAPI");
  }

  if (check_col(pinfo->cinfo, COL_INFO)) 
  {
    col_clear(pinfo->cinfo, COL_INFO);
  }

  ti = proto_tree_add_item(tree, proto_omapi, tvb, 0, -1, FALSE);
  omapi_tree = proto_item_add_subtree(ti, ett_omapi);
  cursor = ptvcursor_new(omapi_tree, tvb, 0);

  if (tvb_reported_length_remaining(tvb, 0) < 8)
  {
    /* Payload too small for OMAPI */
    DISSECTOR_ASSERT_NOT_REACHED();
  }
  else if (tvb_reported_length_remaining(tvb, 0) < 24)
  {
    /* This is a startup message */
    ptvcursor_add(cursor, hf_omapi_version, 4, FALSE);
    ptvcursor_add(cursor, hf_omapi_hlength, 4, FALSE);

    if (check_col(pinfo->cinfo, COL_INFO)) 
    {
      col_add_fstr(pinfo->cinfo, COL_INFO, "Status message");
    }
    proto_item_append_text(ti, ", Status message"); 

    return;
  }

  ptvcursor_add(cursor, hf_omapi_auth_id, 4, FALSE);
  authlength = tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_omapi_auth_len, 4, FALSE);

  if (check_col(pinfo->cinfo, COL_INFO)) 
  {
    col_add_fstr(pinfo->cinfo, COL_INFO, 
      val_to_str(tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor)), omapi_opcode_vals, "Unknown opcode (0x%04x)"));
  }
  proto_item_append_text(ti, ", Opcode: %s", 
    val_to_str(tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor)), omapi_opcode_vals, "Unknown opcode (0x%04x)"));

  ptvcursor_add(cursor, hf_omapi_opcode, 4, FALSE);
  ptvcursor_add(cursor, hf_omapi_handle, 4, FALSE);
  ptvcursor_add(cursor, hf_omapi_id, 4, FALSE);
  ptvcursor_add(cursor, hf_omapi_rid, 4, FALSE);

  msglength = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
  while (msglength)
  {
    ptvcursor_add(cursor, hf_omapi_msg_name_len, 2, FALSE);
    ptvcursor_add(cursor, hf_omapi_msg_name, msglength, FALSE);
    msglength = tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_omapi_msg_value_len, 4, FALSE);

    if (msglength == 0)
    {
      proto_tree_add_text(omapi_tree, tvb, 0, 0, "Empty string");
    }
    else if (msglength == (guint32)~0)
    {
      proto_tree_add_text(omapi_tree, tvb, 0, 0, "No value");
    }        
    else
    {
      ptvcursor_add(cursor, hf_omapi_msg_value, msglength, FALSE);
    }

    msglength = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
  }

  proto_tree_add_text(omapi_tree, tvb, ptvcursor_current_offset(cursor), 2, "Message end tag");
  ptvcursor_advance(cursor, 2);

  objlength = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
  while (objlength)
  {
    ptvcursor_add(cursor, hf_omapi_obj_name_len, 2, FALSE);
    ptvcursor_add(cursor, hf_omapi_obj_name, objlength, FALSE);
    objlength = tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_omapi_obj_value_len, 4, FALSE);

    if (objlength == 0)
    {
      proto_tree_add_text(omapi_tree, tvb, 0, 0, "Empty string");
    }
    else if (objlength == (guint32)~0)
    {
      proto_tree_add_text(omapi_tree, tvb, 0, 0, "No value");
    }        
    else
    {
      ptvcursor_add(cursor, hf_omapi_obj_value, objlength, FALSE);
    }

    objlength = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
  }

  proto_tree_add_text(omapi_tree, tvb, ptvcursor_current_offset(cursor), 2, "Object end tag");
  ptvcursor_advance(cursor, 2);

  if (authlength > 0) {
    ptvcursor_add(cursor, hf_omapi_signature, authlength, FALSE);
  }
}

void
proto_register_omapi(void)
{
  static hf_register_info hf[] = {
    { &hf_omapi_version,
      { "Version", "omapi.version",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_hlength,
      { "Header length", "omapi.hlength",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_auth_id,
      { "Authentication ID", "omapi.authid",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_auth_len,
      { "Authentication length", "omapi.authlength",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_opcode,
      { "Opcode", "omapi.opcode",
	FT_UINT32, BASE_DEC, VALS(omapi_opcode_vals), 0x0,
      	NULL, HFILL }},
    { &hf_omapi_handle,
      { "Handle", "omapi.handle",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_id,
      { "ID", "omapi.id",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_rid,
      { "Response ID", "omapi.rid",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_msg_name_len,
      { "Message name length", "omapi.msg_name_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_msg_name,
      { "Message name", "omapi.msg_name",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_msg_value_len,
      { "Message value length", "omapi.msg_value_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_msg_value,
      { "Message value", "omapi.msg_value",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_obj_name_len,
      { "Object name length", "omapi.obj_name_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_obj_name,
      { "Object name", "omapi.obj_name",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_obj_value_len,
      { "Object value length", "omapi.object_value_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_obj_value,
      { "Object value", "omapi.obj_value",
	FT_BYTES, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_omapi_signature,
      { "Signature", "omapi.signature",
	FT_BYTES, BASE_HEX, NULL, 0x0,
      	NULL, HFILL }}
  };

  static gint *ett[] = {
    &ett_omapi
  };

  proto_omapi = proto_register_protocol("ISC Object Management API", "OMAPI", "omapi");
  proto_register_field_array(proto_omapi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_omapi(void)
{
  dissector_handle_t omapi_handle;

  omapi_handle = create_dissector_handle(dissect_omapi, proto_omapi);
  dissector_add("tcp.port", OMAPI_PORT, omapi_handle);
}
