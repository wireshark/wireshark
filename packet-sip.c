/* packet-sip.c
 * Routines for the Session Initiation Protocol (SIP) dissection.
 * RFC 2543
 * 
 * TODO: Pay attention to Content-Type: It might not always be SDP.
 *       Add hf_* fields for filtering support.
 *       Add sip msg body dissection based on Content-Type for:
 *                SDP, MIME, and other types
 *       Align SIP methods with recent Internet Drafts or RFC
 *               (SIP INFO, rfc2976 - done)
 *               (SIP SUBSCRIBE-NOTIFY - done)
 *               (SIP REFER - done)
 *               check for other
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 * Copyright 2001, Jean-Francois Mule <jfm@clarent.com>
 *
 * $Id: packet-sip.c,v 1.22 2002/01/24 09:20:51 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-cops.c
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
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>

#define TCP_PORT_SIP 5060
#define UDP_PORT_SIP 5060

/* Initialize the protocol and registered fields */
static gint proto_sip = -1;
static gint hf_msg_hdr = -1;

/* Initialize the subtree pointers */
static gint ett_sip = -1;
static gint ett_sip_hdr = -1;

static const char *sip_methods[] = {
        "<Invalid method>",      /* Pad so that the real methods start at index 1 */
        "INVITE",
        "ACK",
        "OPTIONS",
        "BYE",
        "CANCEL",
        "REGISTER",
        "INFO",
        "REFER",
        "SUBSCRIBE",
        "NOTIFY"
};

static gboolean sip_is_request(tvbuff_t *tvb, guint32 offset);
static gint sip_get_msg_offset(tvbuff_t *tvb, guint32 offset);
 
static dissector_handle_t sdp_handle;
static dissector_handle_t data_handle;

#define SIP2_HDR "SIP/2.0 "
#define SIP2_HDR_LEN (strlen (SIP2_HDR))

/* Code to actually dissect the packets */
static void dissect_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint32 offset;
        gint eol, next_offset, msg_offset;
        tvbuff_t *next_tvb;
        gboolean is_request;

	/*
	 * Note that "tvb_strneql()" doesn't throw exceptions, so
	 * "sip_is_request()" won't throw an exception.
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" call s below won't throw exceptions.
	 */
        offset = 0;
        eol = tvb_find_line_end(tvb, 0, -1, &next_offset);
        is_request = sip_is_request(tvb, 0);
	/* XXX - Is this case-sensitive?  RFC 2543 didn't explicitly say. */
	if (tvb_strneql(tvb, 0, SIP2_HDR, SIP2_HDR_LEN) != 0 && ! is_request)
		goto bad;
	  
        if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIP");
    

        if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
                             is_request ? "Request" : "Status",
                             is_request ? 
                             tvb_format_text(tvb, 0, eol - SIP2_HDR_LEN) :
                             tvb_format_text(tvb, SIP2_HDR_LEN, eol - SIP2_HDR_LEN));

        msg_offset = sip_get_msg_offset(tvb, offset);
        if (msg_offset < 0) goto bad;

        if (tree) {
                proto_item *ti, *th;
                proto_tree *sip_tree, *hdr_tree;

                ti = proto_tree_add_item(tree, proto_sip, tvb, 0, -1, FALSE);
                sip_tree = proto_item_add_subtree(ti, ett_sip);

                proto_tree_add_text(sip_tree, tvb, 0, next_offset, "%s-Line: %s",
                                    is_request ? "Request" : "Status",
                                    tvb_format_text(tvb, 0, eol));

                offset = next_offset;
                th = proto_tree_add_item(sip_tree, hf_msg_hdr, tvb, offset, msg_offset - offset, FALSE);
                hdr_tree = proto_item_add_subtree(th, ett_sip_hdr);

                /* - 2 since we have a CRLF separating the message-body */
                while (msg_offset - 2 > (int) offset) {
                        eol = tvb_find_line_end(tvb, offset, -1, &next_offset);
                        proto_tree_add_text(hdr_tree, tvb, offset, next_offset - offset, "%s",
                                            tvb_format_text(tvb, offset, eol));
                        offset = next_offset;
                }
                offset += 2;  /* Skip the CRLF mentioned above */
       }

        if (tvb_length_remaining(tvb, msg_offset) > 0) {
                next_tvb = tvb_new_subset(tvb, offset, -1, -1);
                call_dissector(sdp_handle, next_tvb, pinfo, tree);
        }

        return;

  bad:
        next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        call_dissector(data_handle,next_tvb, pinfo, tree);

        return;
}

/* Returns the offset to the start of the optional message-body, or
 * -1 for an error.
 */
static gint sip_get_msg_offset(tvbuff_t *tvb, guint32 offset)
{
        gint eol;

        while ((eol = tvb_find_guint8(tvb, offset, tvb_length_remaining(tvb, offset), '\r')) > 0) {
                        if (tvb_get_guint8(tvb, eol + 1) == '\n' && 
                            tvb_get_guint8(tvb, eol + 2) == '\r' && 
                            tvb_get_guint8(tvb, eol + 3) == '\n')
                                return eol + 4;
                        offset = eol + 2;
        }

        return -1;
}
                
static gboolean sip_is_request(tvbuff_t *tvb, guint32 offset)
{
        u_int i;

        for (i = 1; i < array_length(sip_methods); i++) {
                if (tvb_strneql(tvb, offset, sip_methods[i], strlen(sip_methods[i])) == 0)
                        return TRUE;
        }

        return FALSE;
}

/* Register the protocol with Ethereal */
void proto_register_sip(void)
{                 

        /* Setup list of header fields */
        static hf_register_info hf[] = {

                { &hf_msg_hdr,
                        { "Message Header",           "sip.msg_hdr",
                        FT_NONE, 0, NULL, 0,
                        "Message Header in SIP message", HFILL }
                },
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_sip,
                &ett_sip_hdr,
        };

        /* Register the protocol name and description */
        proto_sip = proto_register_protocol("Session Initiation Protocol",
	    "SIP", "sip");

        /* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_sip, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sip(void)
{
	dissector_handle_t sip_handle;

	sip_handle = create_dissector_handle(dissect_sip, proto_sip);
        dissector_add("tcp.port", TCP_PORT_SIP, sip_handle);
        dissector_add("udp.port", UDP_PORT_SIP, sip_handle);

	/*
	 * Get a handle for the SDP dissector.
	 */
	sdp_handle = find_dissector("sdp");
	data_handle = find_dissector("data");
}
