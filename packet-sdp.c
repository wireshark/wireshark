/* packet-sdp.c
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-sdp.c,v 1.22 2001/12/13 21:49:22 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"
#include "strutil.h"

static int proto_sdp = -1;

static int hf_protocol_version = -1;
static int hf_owner = -1;
static int hf_session_name = -1;
static int hf_session_info = -1;
static int hf_uri = -1;
static int hf_email = -1;
static int hf_phone = -1;
static int hf_connection_info = -1;
static int hf_bandwidth = -1;
static int hf_time_zone = -1;
static int hf_encryption_key = -1;
static int hf_session_attribute = -1;
static int hf_media_attribute = -1;
static int hf_time = -1;
static int hf_repeat_time = -1;
static int hf_media = -1;
static int hf_media_title = -1;
static int hf_unknown = -1;
static int hf_misplaced = -1;
static int hf_invalid = -1;

static int ett_sdp = -1;

static void
dissect_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sdp_tree;
	proto_item	*ti;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;
	u_char		section;
	u_char		type;
	u_char          delim;
	int		datalen;
	int             tokenoffset;
	int             hf = -1;

	/*
	 * As RFC 2327 says, "SDP is purely a format for session
	 * description - it does not incorporate a transport protocol,
	 * and is intended to use different transport protocols as
	 * appropriate including the Session Announcement Protocol,
	 * Session Initiation Protocol, Real-Time Streaming Protocol,
	 * electronic mail using the MIME extensions, and the
	 * Hypertext Transport Protocol."
	 *
	 * We therefore don't set the protocol or info columns;
	 * instead, we append to them, so that we don't erase
	 * what the protocol inside which the SDP stuff resides
	 * put there.
	 */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_append_str(pinfo->cinfo, COL_PROTOCOL, "/SDP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* XXX: Needs description. */
		col_append_str(pinfo->cinfo, COL_INFO, ", with session description");
	}

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_sdp, tvb, offset,
	    tvb_length_remaining(tvb, offset), FALSE);
	sdp_tree = proto_item_add_subtree(ti, ett_sdp);

	/*
	 * Show the SDP message a line at a time.
	 */
	section = 0;
	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * Find the end of the line.
		 */
		linelen = tvb_find_line_end_unquoted(tvb, offset, -1,
		    &next_offset);

		/*
		 * Line must contain at least e.g. "v=".
		 */
		if (linelen < 2)
			break;

		type = tvb_get_guint8(tvb,offset);
		delim = tvb_get_guint8(tvb,offset + 1);
		if (delim != '=') {
		        proto_tree_add_string(sdp_tree,hf_invalid,tvb, offset,
					      linelen,
					      tvb_format_text(tvb,
							      offset,linelen));
                        offset = next_offset;
			continue;
		}

		/*
		 * Attributes.
		 */
		switch (type) {
		case 'v':
		        hf = hf_protocol_version;
			section = 'v';
			break;
		case 'o':
		        hf = hf_owner;
			break;
		case 's':
		        hf = hf_session_name;
			break;
		case 'i':
		        if (section == 'v'){
			        hf = hf_session_info;
			}
			else if (section == 'm'){
			        hf = hf_media_title;
			}
			else{
			        hf = hf_misplaced;
			}
			break;
		case 'u':
		        hf = hf_uri;
			break;
		case 'e':
		        hf = hf_email;
			break;
		case 'p':
		        hf = hf_phone;
			break;
		case 'c':
		        hf = hf_connection_info;
			break;
		case 'b':
		        hf = hf_bandwidth;
			break;
		case 't':
		        hf = hf_time;
			section = 't';
			break;
		case 'r':
		        hf = hf_repeat_time;
			break;
		case 'm':
		        hf = hf_media;
			section = 'm';
			break;
		case 'k':
		        hf = hf_encryption_key;
			break;
		case 'a':
		        if (section == 'v'){
			        hf = hf_session_attribute; 
			}
			else if (section == 'm'){
			        hf = hf_media_attribute;
			}
			else{
			        hf = hf_misplaced;
			}
			break;
		case 'z':
		        hf = hf_time_zone;
			break;
		default:
		        hf = hf_unknown;
			break;
		}
		tokenoffset = 2;
		if( hf == hf_unknown || hf == hf_misplaced )
		  tokenoffset = 0;
		proto_tree_add_string(sdp_tree,hf,tvb, offset, 
				      linelen,
				      tvb_format_text(tvb,offset+tokenoffset,
						      linelen - tokenoffset));
		offset = next_offset;
	}

	datalen = tvb_length_remaining(tvb, offset);
	if (datalen > 0) {
		proto_tree_add_text(sdp_tree, tvb, offset, datalen,
		    "Data (%d bytes)", datalen);
	}
}

void
proto_register_sdp(void)
{
  static hf_register_info hf[] = {
    { &hf_protocol_version,
      { "Session Description (v), version",
	"sdp.version", FT_STRING, BASE_NONE,NULL,0x0,
	"Session Description, version", HFILL }},
    { &hf_owner, 
      { "Owner/Creator, Session Id (o)",
	"sdp.owner", FT_STRING, BASE_NONE, NULL, 0x0,
	"Owner/Creator, Session Id", HFILL}},
    { &hf_session_name,
      { "Session Name (s)",
	"sdp.session_name", FT_STRING, BASE_NONE,NULL, 0x0,
	"Session Name", HFILL }},
    { &hf_session_info,
      { "Session Information (i)", 
	"sdp.session_info", FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Information", HFILL }},
    { &hf_uri,
      { "URI of Description (u)",
	"sdp.uri", FT_STRING, BASE_NONE,NULL, 0x0,
	"URI of Description", HFILL }},
    { &hf_email,
      { "E-mail Address (e)", 
	"sdp.email", FT_STRING, BASE_NONE, NULL, 0x0,
	"E-mail Address", HFILL }},
    { &hf_phone,
      { "Phone Number (p)",
	"sdp.phone", FT_STRING, BASE_NONE, NULL, 0x0,
	"Phone Number", HFILL }},
    { &hf_connection_info,
      { "Connection Information (c)",
	"sdp.connection_info", FT_STRING, BASE_NONE, NULL, 0x0,
	"Connection Information", HFILL }},
    { &hf_bandwidth,
      { "Bandwidth Information (b)",
	"sdp.bandwidth", FT_STRING, BASE_NONE, NULL, 0x0,
	"Bandwidth Information", HFILL }},
    { &hf_time_zone,
      { "Time Zone Adjustments (z)",
	"sdp.timezone", FT_STRING, BASE_NONE, NULL, 0x0,
	"Time Zone Adjustments", HFILL }},
    { &hf_encryption_key,
      { "Encryption Key (k)",
	"sdp.encryption_key", FT_STRING, BASE_NONE, NULL, 0x0,
	"Encryption Key", HFILL }},
    { &hf_session_attribute, 
      { "Session Attribute (a)", 
	"sdp.session_attr", FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Attribute", HFILL }},
    { &hf_session_attribute, 
      { "Media Attribute (a)", 
	"sdp.media_attr", FT_STRING, BASE_NONE, NULL, 0x0,
	"Session Attribute", HFILL }},
    { &hf_time,
      { "Time Description, active time (t)",
	"sdp.time", FT_STRING, BASE_NONE, NULL, 0x0,
	"Time Description, active time", HFILL }},
    { &hf_repeat_time,
      { "Repeat Time (r)",
	"sdp.repeat_time", FT_STRING, BASE_NONE, NULL, 0x0,
	"Repeat Time", HFILL }},
    { &hf_media,
      { "Media Description, name and address (m)",
	"sdp.media", FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Description, name and address", HFILL }},
    { &hf_media_title,
      { "Media Title (i)",
	"sdp.media_title",FT_STRING, BASE_NONE, NULL, 0x0,
	"Media Title", HFILL }},
    { &hf_unknown,
      { "Unknown",
	"sdp.unknown",FT_STRING, BASE_NONE, NULL, 0x0,
	"Unknown", HFILL }},
    { &hf_misplaced,
      { "Misplaced",
	"sdp.misplaced",FT_STRING, BASE_NONE, NULL, 0x0,
	"Misplaced", HFILL }},
    { &hf_invalid,
      { "Invalid line",
	"sdp.invalid",FT_STRING, BASE_NONE, NULL, 0x0,
	"Invalid line", HFILL }},
  };
  static gint *ett[] = {
    &ett_sdp,
  };
  
  proto_sdp = proto_register_protocol("Session Description Protocol",
				      "SDP", "sdp");
  proto_register_field_array(proto_sdp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
	
  /*
   * Register the dissector by name, so other dissectors can
   * grab it by name rather than just referring to it directly
   * (you can't refer to it directly from a plugin dissector
   * on Windows without stuffing it into the Big Transfer Vector).
   */
  register_dissector("sdp", dissect_sdp, proto_sdp);
}
