/* packet-dsi.c
 * Routines for dsi packet dissection
 * Copyright 2001, Randy McEoin <rmceoin@pe.com>
 *
 * $Id: packet-dsi.c,v 1.11 2002/04/22 08:50:49 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>

#include "prefs.h"
#include "packet-frame.h"

/* The information in this module (DSI) comes from:

  AFP 2.1 & 2.2.pdf contained in AppleShare_IP_6.3_SDK
  available from http://www.apple.com

  The netatalk source code by Wesley Craig & Adrian Sun

 * What a Data Stream Interface packet looks like:
 * 0                               32
 * |-------------------------------|
 * |flags  |command| requestID     |
 * |-------------------------------|
 * |error code/enclosed data offset|
 * |-------------------------------|
 * |total data length              |
 * |-------------------------------|
 * |reserved field                 |
 * |-------------------------------|
 */

static int proto_dsi = -1;
static int hf_dsi_flags = -1;
static int hf_dsi_command = -1;
static int hf_dsi_requestid = -1;
static int hf_dsi_code = -1;
static int hf_dsi_length = -1;
static int hf_dsi_reserved = -1;

static gint ett_dsi = -1;

/* desegmentation of DSI */
static gboolean dsi_desegment = TRUE;

static dissector_handle_t data_handle;

#define TCP_PORT_DSI			548

/* DSI flags */
#define DSIFL_REQUEST    0x00
#define DSIFL_REPLY      0x01
#define DSIFL_MAX        0x01

/* DSI Commands */
#define DSIFUNC_CLOSE   1       /* DSICloseSession */
#define DSIFUNC_CMD     2       /* DSICommand */
#define DSIFUNC_STAT    3       /* DSIGetStatus */
#define DSIFUNC_OPEN    4       /* DSIOpenSession */
#define DSIFUNC_TICKLE  5       /* DSITickle */
#define DSIFUNC_WRITE   6       /* DSIWrite */
#define DSIFUNC_ATTN    8       /* DSIAttention */
#define DSIFUNC_MAX     8       /* largest command */

static const value_string flag_vals[] = {
  {DSIFL_REQUEST,	"Request" },
  {DSIFL_REPLY,		"Reply" },
  {0,			NULL } };

static const value_string func_vals[] = {
  {DSIFUNC_CLOSE,	"CloseSession" },
  {DSIFUNC_CMD,		"Command" },
  {DSIFUNC_STAT,	"GetStatus" },
  {DSIFUNC_OPEN,	"OpenSession" },
  {DSIFUNC_TICKLE,	"Tickle" },
  {DSIFUNC_WRITE,	"Write" },
  {DSIFUNC_ATTN,	"Attention" },
  {0,			NULL } };

static void
dissect_dsi_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree      *dsi_tree;
	proto_item	*ti;
	guint8		dsi_flags,dsi_command;
	guint16		dsi_requestid;
	gint32		dsi_code;
	guint32		dsi_length;
	guint32		dsi_reserved;
 
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSI");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	dsi_flags = tvb_get_guint8(tvb, 0);
	dsi_command = tvb_get_guint8(tvb, 1);
	dsi_requestid = tvb_get_ntohs(tvb, 2);
	dsi_code = tvb_get_ntohl(tvb, 4);
	dsi_length = tvb_get_ntohl(tvb, 8);
	dsi_reserved = tvb_get_ntohl(tvb, 12);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s (%u)",
			val_to_str(dsi_flags, flag_vals,
				   "Unknown flag (0x%02x)"),
			val_to_str(dsi_command, func_vals,
				   "Unknown function (0x%02x)"),
			dsi_requestid);
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_dsi, tvb, 0, -1, FALSE);
		dsi_tree = proto_item_add_subtree(ti, ett_dsi);

		proto_tree_add_uint(dsi_tree, hf_dsi_flags, tvb,
			0, 1, dsi_flags);
		proto_tree_add_uint(dsi_tree, hf_dsi_command, tvb,
			1, 1, dsi_command);
		proto_tree_add_uint(dsi_tree, hf_dsi_requestid, tvb,
			2, 2, dsi_requestid);
		proto_tree_add_int(dsi_tree, hf_dsi_code, tvb,
			4, 4, dsi_code);
		proto_tree_add_uint_format(dsi_tree, hf_dsi_length, tvb,
			8, 4, dsi_length,
			"Length: %u bytes", dsi_length);
		proto_tree_add_uint(dsi_tree, hf_dsi_reserved, tvb,
			12, 4, dsi_reserved);
		call_dissector(data_handle,tvb_new_subset(tvb, 16,-1,tvb_reported_length_remaining(tvb,16)), pinfo, dsi_tree);
	}
}

static void
dissect_dsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	volatile int offset = 0;
	int length_remaining;
	guint32 plen;
	int length;
	tvbuff_t *next_tvb;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		length_remaining = tvb_length_remaining(tvb, offset);

		/*
		 * Can we do reassembly?
		 */
		if (dsi_desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the DSI header split across segment
			 * boundaries?
			 */
			if (length_remaining < 12) {
				/*
				 * Yes.  Tell the TCP dissector where
				 * the data for this message starts in
				 * the data it handed us, and how many
				 * more bytes we need, and return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 12 - length_remaining;
				return;
			}
		}

		/*
		 * Get the length of the DSI packet.
		 */
		plen = tvb_get_ntohl(tvb, offset+8);

		/*
		 * Can we do reassembly?
		 */
		if (dsi_desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the DSI packet split across segment
			 * boundaries?
			 */
			if ((guint32)length_remaining < plen + 16) {
				/*
				 * Yes.  Tell the TCP dissector where
				 * the data for this message starts in
				 * the data it handed us, and how many
				 * more bytes we need, and return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len =
				    (plen + 16) - length_remaining;
				return;
			}
		}

		/*
		 * Construct a tvbuff containing the amount of the payload
		 * we have available.  Make its reported length the
		 * amount of data in the DSI packet.
		 *
		 * XXX - if reassembly isn't enabled. the subdissector
		 * will throw a BoundsError exception, rather than a
		 * ReportedBoundsError exception.  We really want
		 * a tvbuff where the length is "length", the reported
		 * length is "plen + 16", and the "if the snapshot length
		 * were infinite" length is the minimum of the
		 * reported length of the tvbuff handed to us and "plen+16",
		 * with a new type of exception thrown if the offset is
		 * within the reported length but beyond that third length,
		 * with that exception getting the "Unreassembled Packet"
		 * error.
		 */
		length = length_remaining;
		if ((guint32)length > plen + 16)
			length = plen + 16;
		next_tvb = tvb_new_subset(tvb, offset, length, plen + 16);

		/*
		 * Dissect the DSI packet.
		 *
		 * Catch the ReportedBoundsError exception; if this
		 * particular message happens to get a ReportedBoundsError
		 * exception, that doesn't mean that we should stop
		 * dissecting DSI messages within this frame or chunk
		 * of reassembled data.
		 *
		 * If it gets a BoundsError, we can stop, as there's nothing
		 * more to see, so we just re-throw it.
		 */
		TRY {
			dissect_dsi_packet(next_tvb, pinfo, tree);
		}
		CATCH(BoundsError) {
			RETHROW;
		}
		CATCH(ReportedBoundsError) {
			show_reported_bounds_error(tvb, pinfo, tree);
		}
		ENDTRY;

		/*
		 * Skip the DSI header and the payload.
		 */
		offset += plen + 16;
	}
}

void
proto_register_dsi(void)
{

  static hf_register_info hf[] = {
    { &hf_dsi_flags,
      { "Flags",            "dsi.flags",
	FT_UINT8, BASE_HEX, VALS(flag_vals), 0x0,
      	"Indicates request or reply.", HFILL }},

    { &hf_dsi_command,
      { "Command",           "dsi.command",
	FT_UINT8, BASE_DEC, VALS(func_vals), 0x0,
      	"Represents a DSI command.", HFILL }},

    { &hf_dsi_requestid,
      { "Request ID",           "dsi.requestid",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Keeps track of which request this is.  Replies must match a Request.  IDs must be generated in sequential order.", HFILL }},

    { &hf_dsi_code,
      { "Code",           "dsi.code",
	FT_INT32, BASE_DEC, NULL, 0x0,
      	"In Reply packets this is an error code.  In Request Write packets this is a data offset.", HFILL }},

    { &hf_dsi_length,
      { "Length",           "dsi.length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Total length of the data that follows the DSI header.", HFILL }},

    { &hf_dsi_reserved,
      { "Reserved",           "dsi.reserved",
	FT_UINT32, BASE_HEX, NULL, 0x0,
      	"Reserved for future use.  Should be set to zero.", HFILL }},

  };
  static gint *ett[] = {
    &ett_dsi,
  };
  module_t *dsi_module;

  proto_dsi = proto_register_protocol("Data Stream Interface", "DSI", "dsi");
  proto_register_field_array(proto_dsi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dsi_module = prefs_register_protocol(proto_dsi, NULL);
  prefs_register_bool_preference(dsi_module, "desegment",
    "Desegment all DSI messages spanning multiple TCP segments",
    "Whether the DSI dissector should desegment all messages spanning multiple TCP segments",
    &dsi_desegment);
}

void
proto_reg_handoff_dsi(void)
{
  static dissector_handle_t dsi_handle;

  dsi_handle = create_dissector_handle(dissect_dsi, proto_dsi);
  dissector_add("tcp.port", TCP_PORT_DSI, dsi_handle);

  data_handle = find_dissector("data");
}
