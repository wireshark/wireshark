/* packet-sip.c
 * Routines for the Session Initiation Protocol (SIP) dissection.
 * RFC 2543
 *
 * TODO: Pay attention to Content-Type: It might not always be SDP.
 *       hf_ display filters for headers of SIP extension RFCs: 
 *		Done for RCF 3265, RFC 3262
 *		Use hash table for list of headers
 *       Add sip msg body dissection based on Content-Type for:
 *                SDP, MIME, and other types
 *       Align SIP methods with recent Internet Drafts or RFC
 *               (SIP INFO, rfc2976 - done)
 *               (SIP SUBSCRIBE-NOTIFY - done)
 *               (SIP REFER - done)
 *               check for other
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 * Copyright 2001, Jean-Francois Mule <jfm@cablelabs.com>
 *
 * $Id: packet-sip.c,v 1.34 2003/03/10 22:33:26 guy Exp $
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
static gint hf_Method = -1;
static gint hf_Status_Code = -1;

/* Initialize the subtree pointers */
static gint ett_sip = -1;
static gint ett_sip_hdr = -1;

static const char *sip_methods[] = {
        "<Invalid method>",      /* Pad so that the real methods start at index 1 */
        "ACK",
        "BYE",
        "CANCEL",
        "DO",
        "INFO",
        "INVITE",
        "MESSAGE",
        "NOTIFY",
        "OPTIONS",
        "PRACK",
        "QAUTH",
        "REFER",
        "REGISTER",
        "SPRACK",
        "SUBSCRIBE"
};

/* from RFC 3261 */
static const char *sip_headers[] = {
		"Unknown-header", /* Pad so that the real headers start at index 1 */
                "Accept",
                "Accept-Encoding",
                "Accept-Language",
                "Alert-Info",
                "Allow",
		"Allow-Events",
                "Authentication-Info",
                "Authorization",
                "Call-ID",
                "Call-Info",
                "Contact",
                "Content-Disposition",
                "Content-Encoding",
                "Content-Language",
                "Content-Length",
                "Content-Type",
                "CSeq",
                "Date",
                "Error-Info",
		"Event",
                "Expires",
                "From",
                "In-Reply-To",
                "Max-Forwards",
                "MIME-Version",
                "Min-Expires",
                "Organization",
                "Priority",
                "Proxy-Authenticate",
                "Proxy-Authorization",
                "Proxy-Require",
		"RAck",
		"RSeq",
                "Record-Route",
                "Reply-To",
                "Require",
                "Retry-After",
                "Route",
                "Server",
                "Subject",
		"Subscription-State",
                "Supported",
                "Timestamp",
                "To",
                "Unsupported",
                "User-Agent",
                "Via",
                "Warning",
                "WWW-Authenticate"
};


const int Pos_Accept 			=1;
const int Pos_Accept_Encoding		=2;
const int Pos_Accept_Language		=3;
const int Pos_Alert_Info		=4;
const int Pos_Allow			=5;
const int Pos_Allow_Events		=6;
const int Pos_Authentication_Info	=7;
const int Pos_Authorization		=8;
const int Pos_Call_ID			=9;
const int Pos_Call_Info			=10;
const int Pos_Contact			=11;
const int Pos_Content_Disposition	=12;
const int Pos_Content_Encoding		=13;
const int Pos_Content_Language		=14;
const int Pos_Content_Length		=15;
const int Pos_Content_Type		=16;
const int Pos_CSeq			=17;
const int Pos_Date			=18;
const int Pos_Error_Info		=19;
const int Pos_Event			=20;
const int Pos_Expires			=21;
const int Pos_From			=22;
const int Pos_In_Reply_To		=23;
const int Pos_Max_Forwards		=24;
const int Pos_MIME_Version		=25;
const int Pos_Min_Expires		=26;
const int Pos_Organization		=27;
const int Pos_Priority			=28;
const int Pos_Proxy_Authenticate	=29;
const int Pos_Proxy_Authorization	=30;
const int Pos_Proxy_Require		=31;
const int Pos_RAck			=32;
const int Pos_RSeq			=33;
const int Pos_Record_Route		=34;
const int Pos_Reply_To			=35;
const int Pos_Require			=36;
const int Pos_Retry_After		=37;
const int Pos_Route			=38;
const int Pos_Server			=39;
const int Pos_Subject			=40;
const int Pos_Subscription_State	=41;
const int Pos_Supported			=42;
const int Pos_Timestamp			=43;
const int Pos_To			=44;
const int Pos_Unsupported		=45;
const int Pos_User_Agent		=46;
const int Pos_Via			=47;
const int Pos_Warning			=48;
const int Pos_WWW_Authenticate		=49;

static gint hf_header_array[] = {
		-1, /* "Unknown-header" - Pad so that the real headers start at index 1 */
                -1, /* "Accept" */
                -1, /* "Accept-Encoding" */
                -1, /* "Accept-Language" */
                -1, /* "Alert-Info" */
                -1, /* "Allow" */
		-1, /* "Allow-Events" - RFC 3265 */
                -1, /* "Authentication-Info" */
                -1, /* "Authorization" */
                -1, /* "Call-ID" */
                -1, /* "Call-Info" */
                -1, /* "Contact" */
                -1, /* "Content-Disposition" */
                -1, /* "Content-Encoding" */
                -1, /* "Content-Language" */
                -1, /* "Content-Length" */
                -1, /* "Content-Type" */
                -1, /* "CSeq" */
                -1, /* "Date" */
                -1, /* "Error-Info" */
                -1, /* "Expires" */
		-1, /* "Event" - RFC 3265 */
                -1, /* "From" */
                -1, /* "In-Reply-To" */
                -1, /* "Max-Forwards" */
                -1, /* "MIME-Version" */
                -1, /* "Min-Expires" */
                -1, /* "Organization" */
                -1, /* "Priority" */
                -1, /* "Proxy-Authenticate" */
                -1, /* "Proxy-Authorization" */
                -1, /* "Proxy-Require" */
		-1, /* "RAck" - RFC 3262 */
		-1, /* "RSeq" - RFC 3261 */
                -1, /* "Record-Route" */
                -1, /* "Reply-To" */
                -1, /* "Require" */
                -1, /* "Retry-After" */
                -1, /* "Route" */
                -1, /* "Server" */
                -1, /* "Subject" */
		-1, /* "Subscription-State" - RFC 3265 */
                -1, /* "Supported" */
                -1, /* "Timestamp" */
                -1, /* "To" */
                -1, /* "Unsupported" */
                -1, /* "User-Agent" */
                -1, /* "Via" */
                -1, /* "Warning" */
                -1  /* "WWW-Authenticate" */
};


static gboolean sip_is_request(tvbuff_t *tvb, gint eol);
static gboolean sip_is_known_request(tvbuff_t *tvb, guint32 offset);
static gint sip_get_msg_offset(tvbuff_t *tvb, guint32 offset);
static gint sip_is_known_sip_header(tvbuff_t *tvb, guint32 offset, guint8* header_len);
void dfilter_sip_message_line(gboolean is_request, tvbuff_t *tvb, proto_tree *tree);

static dissector_handle_t sdp_handle;
static dissector_handle_t data_handle;

#define SIP2_HDR "SIP/2.0"
#define SIP2_HDR_LEN (strlen (SIP2_HDR))

/* Code to actually dissect the packets */
static void dissect_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint32 offset;
        gint eol, next_offset, msg_offset;
        tvbuff_t *next_tvb;
        gboolean is_request, is_known_request;
        char *req_descr;

        /*
         * Note that "tvb_strneql()" doesn't throw exceptions, so
         * "sip_is_request()" won't throw an exception.
         *
         * Note that "tvb_find_line_end()" will return a value that
         * is not longer than what's in the buffer, so the
         * "tvb_get_ptr()" call s below won't throw exceptions.
         */
        offset = 0;
        eol = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);
        /* XXX - Check for a valid status message as well. */
        is_request = sip_is_request(tvb, eol);
        is_known_request = sip_is_known_request(tvb, 0);
        /* XXX - Is this case-sensitive?  RFC 2543 didn't explicitly say. */
        if (tvb_strneql(tvb, 0, SIP2_HDR, SIP2_HDR_LEN) != 0 && ! is_request)
                goto bad;

        if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIP");

        req_descr = is_known_request ? "Request" : "Unknown request";
        if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
                             is_request ? req_descr : "Status",
                             is_request ?
                             tvb_format_text(tvb, 0, eol - SIP2_HDR_LEN - 1) :
                             tvb_format_text(tvb, SIP2_HDR_LEN + 1, eol - SIP2_HDR_LEN - 1));
        msg_offset = sip_get_msg_offset(tvb, offset);
        if (msg_offset < 0) {
                /*
                 * XXX - this may just mean that the entire SIP message
                 * didn't fit in this TCP segment.
                 */
                goto bad;
        }

        if (tree) {
                proto_item *ti, *th;
                proto_tree *sip_tree, *hdr_tree;

                ti = proto_tree_add_item(tree, proto_sip, tvb, 0, -1, FALSE);
                sip_tree = proto_item_add_subtree(ti, ett_sip);

                proto_tree_add_text(sip_tree, tvb, 0, next_offset, "%s line: %s",
                                    is_request ? req_descr : "Status",
                                    tvb_format_text(tvb, 0, eol));

		dfilter_sip_message_line(is_request , tvb, sip_tree);

                offset = next_offset;
                th = proto_tree_add_item(sip_tree, hf_msg_hdr, tvb, offset, msg_offset - offset, FALSE);
                hdr_tree = proto_item_add_subtree(th, ett_sip_hdr);

                /* - 2 since we have a CRLF separating the message-body */
                while (msg_offset - 2 > (int) offset) {
                        gint hf_index;
			guint8 header_len;

                        eol = tvb_find_line_end(tvb, offset, -1, &next_offset,
                            FALSE);
			hf_index = sip_is_known_sip_header(tvb, offset, &header_len);
			
			if (hf_index == -1) {
                         proto_tree_add_text(hdr_tree, tvb, offset , next_offset - offset, "%s",
                                            tvb_format_text(tvb, offset, eol));
			}
			else	{					    
		         proto_tree_add_string(hdr_tree, hf_header_array[hf_index], tvb, offset, next_offset - offset , 
					     tvb_format_text(tvb, offset + header_len + 2, eol - header_len - 2));
			} 
					    
                        offset = next_offset;
                }
                offset += 2;  /* Skip the CRLF mentioned above */
       }

        if (tvb_offset_exists(tvb, msg_offset)) {
                next_tvb = tvb_new_subset(tvb, msg_offset, -1, -1);
                call_dissector(sdp_handle, next_tvb, pinfo, tree);
        }

        return;

  bad:
        next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        call_dissector(data_handle,next_tvb, pinfo, tree);

        return;
}

/* Display filter for SIP-message line */
void dfilter_sip_message_line(gboolean is_request, tvbuff_t *tvb, proto_tree *tree)
{
	char	*string;
        gint	code_len;

	if (is_request) {
	    code_len = tvb_find_guint8(tvb, 0, -1, ' ');
	}
	else	{
	    code_len = tvb_find_guint8(tvb, SIP2_HDR_LEN + 1, -1, ' ');
	}

	string = g_malloc(code_len + 1);
	
	CLEANUP_PUSH(g_free, string);

	if (is_request) {
	    tvb_memcpy(tvb, (guint8 *)string, 0, code_len);
	    string[code_len] = '\0';
	    proto_tree_add_string(tree, hf_Method, tvb, 0, 
		    code_len, string);
	}
	else	{
	    tvb_memcpy(tvb, (guint8 *)string, SIP2_HDR_LEN + 1, code_len - SIP2_HDR_LEN);
	    string[code_len - SIP2_HDR_LEN - 1] = '\0';
	    proto_tree_add_string(tree, hf_Status_Code, 
		    tvb, SIP2_HDR_LEN + 1, code_len - SIP2_HDR_LEN - 1, string);
	}
		
	CLEANUP_CALL_AND_POP;
}

static gboolean
dissect_sip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gint eol, next_offset;

        /*
         * This is a heuristic dissector, which means we get all the
         * UDP and TCP traffic not sent to a known dissector and not
         * claimed by a heuristic dissector called before us!
         * So we first check if the frame is really meant for us.
         */

        /*
         * Check for a response.
         * First, make sure we have enough data to do the check.
         */
        if (!tvb_bytes_exist(tvb, 0, SIP2_HDR_LEN)) {
                /*
                 * We don't.
                 */
                return FALSE;
        }

        /*
         * Now see if we have a response header; they begin with
         * "SIP/2.0".
         */
        if (tvb_strneql(tvb, 0, SIP2_HDR, SIP2_HDR_LEN) != 0)  {
                /*
                 * We don't, so this isn't a response; check for a request.
                 * They *end* with "SIP/2.0".
                 */
                eol = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);
                if (eol <= (gint)SIP2_HDR_LEN) {
                        /*
                         * The line isn't long enough to end with "SIP/2.0".
                         */
                        return FALSE;
                }
                if (!tvb_bytes_exist(tvb, eol - SIP2_HDR_LEN, SIP2_HDR_LEN)) {
                        /*
                         * We don't have enough of the data in the line
                         * to check.
                         */
                        return FALSE;
                }

                if (tvb_strneql(tvb, eol - SIP2_HDR_LEN, SIP2_HDR, SIP2_HDR_LEN - 1) != 0) {
                        /*
                         * Not a request, either.
                         */
                        return FALSE;
                }
        }

        /*
         * The message seems to be a valid SIP message!
         */
        dissect_sip(tvb, pinfo, tree);

        return TRUE;
}

/* Returns the offset to the start of the optional message-body, or
 * -1 if not found.
 */
static gint sip_get_msg_offset(tvbuff_t *tvb, guint32 offset)
{
        gint eol;

        while ((eol = tvb_find_guint8(tvb, offset, -1, '\r')) > 0
            && tvb_bytes_exist(tvb, eol, 4)) {
                if (tvb_get_guint8(tvb, eol + 1) == '\n' &&
                    tvb_get_guint8(tvb, eol + 2) == '\r' &&
                    tvb_get_guint8(tvb, eol + 3) == '\n')
                        return eol + 4;
                offset = eol + 2;
        }

        return -1;
}

/* From section 4.1 of RFC 2543:
 *
 * Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
 */

static gboolean sip_is_request(tvbuff_t *tvb, gint eol)
{
        gint meth_len, req_len, req_colon_pos;
        guint8 req_start, ver_start, ver_len;

        meth_len = tvb_find_guint8(tvb, 0, -1, ' ');
        req_start = meth_len + 1;
        req_len = tvb_find_guint8(tvb, req_start, -1, ' ') - meth_len - 1;
        req_colon_pos = tvb_find_guint8(tvb, req_start + 1, -1, ':');
        ver_start = meth_len + req_len + 2;
        ver_len = eol - req_len - meth_len - 2; /*CRLF, plus two spaces */

        /* Do we have:
         *   A method of at least one character?
         *   A URI consisting of at least three characters?
         *   A version string length matching that of SIP2_HDR?
         */
        if (meth_len <= 0 || req_len <= 3 || ver_len != SIP2_HDR_LEN)
                return FALSE;

        /* Does our method have a colon character? */
        if (req_colon_pos < 0 || req_colon_pos > ver_start)
                return FALSE;
        /* XXX - Check for a proper URI prefix? */

        /* Do we have a proper version string? */
        if (tvb_strneql(tvb, ver_start, SIP2_HDR, SIP2_HDR_LEN))
                return TRUE;

        return TRUE;
}

static gboolean sip_is_known_request(tvbuff_t *tvb, guint32 offset)
{
        guint8 i, meth_len;

        meth_len = tvb_find_guint8(tvb, 0, -1, ' ');

        for (i = 1; i < array_length(sip_methods); i++) {
                if ((meth_len == strlen(sip_methods[i])) && tvb_strneql(tvb, offset, sip_methods[i], strlen(sip_methods[i])) == 0)
                        return TRUE;
        }

        return FALSE;
}

/* Returns index of method in sip_headers */
static gint sip_is_known_sip_header(tvbuff_t *tvb, guint32 offset, guint8* header_len)
{
        guint8 i;

        *header_len = tvb_find_guint8(tvb, offset, -1, ':') - offset;

        for (i = 1; i < array_length(sip_headers); i++) {
                if ((*header_len == strlen(sip_headers[i])) && tvb_strneql(tvb, offset, sip_headers[i], strlen(sip_headers[i])) == 0)
                        return i;
        }

        return -1;
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
                { &hf_Method,
		       { "Method", 		"sip.Method", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"SIP Method", HFILL }
		},
                { &hf_Status_Code,
		       { "Status-Code", 		"sip.Status-Code", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"SIP Status Code", HFILL }
		},
                { &hf_header_array[Pos_Accept],
		       { "Accept", 		"sip.Accept", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept Header", HFILL }
		},
                { &hf_header_array[Pos_Accept_Encoding],
		       { "Accept-Encoding", 		"sip.Accept-Encoding", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept-Encoding Header", HFILL }
		},
                { &hf_header_array[Pos_Accept_Language],
		       { "Accept-Language", 		"sip.Accept-Language", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept-Language Header", HFILL }
		},
                { &hf_header_array[Pos_Alert_Info],
		       { "Alert-Info", 		"sip.Alert-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Alert-Info Header", HFILL }
		},
                { &hf_header_array[Pos_Allow],
		       { "Allow", 		"sip.Allow", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Allow Header", HFILL }
		},
                { &hf_header_array[Pos_Allow_Events],
		       { "Allow-Events", 		"sip.Allow-Events", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Allow-Events Header", HFILL }
		},
                { &hf_header_array[Pos_Authentication_Info],
		       { "Authentication-Info", 		"sip.Authentication-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Authentication-Info Header", HFILL }
		},
                { &hf_header_array[Pos_Authorization],
		       { "Authorization", 		"sip.Authorization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Authorization Header", HFILL }
		},
                { &hf_header_array[Pos_Call_ID],
		       { "Call-ID", 		"sip.Call-ID", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Call-ID Header", HFILL }
		},
                { &hf_header_array[Pos_Call_Info],
		       { "Call-Info", 		"sip.Call-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Call-Info Header", HFILL }
		},
                { &hf_header_array[Pos_Contact],
		       { "Contact", 		"sip.Contact", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Contact Header", HFILL }
		},
                { &hf_header_array[Pos_Content_Disposition],
		       { "Content-Disposition", 		"sip.Content-Disposition", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Disposition Header", HFILL }
		},
                { &hf_header_array[Pos_Content_Encoding],
		       { "Content-Encoding", 		"sip.Content-Encoding", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Encoding Header", HFILL }
		},
                { &hf_header_array[Pos_Content_Language],
		       { "Content-Language", 		"sip.Content-Language", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Language Header", HFILL }
		},
                { &hf_header_array[Pos_Content_Length],
		       { "Content-Length", 		"sip.Content-Length", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Length Header", HFILL }
		},
                { &hf_header_array[Pos_Content_Type],
		       { "Content-Type", 		"sip.Content-Type", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Type Header", HFILL }
		},
                { &hf_header_array[Pos_CSeq],
		       { "CSeq", 		"sip.CSeq", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: CSeq Header", HFILL }
		},
                { &hf_header_array[Pos_Date],
		       { "Date", 		"sip.Date", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Date Header", HFILL }
		},
                { &hf_header_array[Pos_Error_Info],
		       { "Error-Info", 		"sip.Error-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Error-Info Header", HFILL }
		},
                { &hf_header_array[Pos_Event],
		       { "Event", 		"sip.Event", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Event Header", HFILL }
		},
                { &hf_header_array[Pos_Expires],
		       { "Expires", 		"sip.Expires", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Expires Header", HFILL }
		},
                { &hf_header_array[Pos_From],
		       { "From", 		"sip.From", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Header", HFILL }
		},
                { &hf_header_array[Pos_In_Reply_To],
		       { "In-Reply-To", 		"sip.In-Reply-To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: In-Reply-To Header", HFILL }
		},
                { &hf_header_array[Pos_Max_Forwards],
		       { "Max-Forwards", 		"sip.Max-Forwards", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Max-Forwards Header", HFILL }
		},
                { &hf_header_array[Pos_MIME_Version],
		       { "MIME-Version", 		"sip.MIME-Version", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: MIME-Version Header", HFILL }
		},
                { &hf_header_array[Pos_Min_Expires],
		       { "Min-Expires", 		"sip.Min-Expires", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Min-Expires Header", HFILL }
		},
                { &hf_header_array[Pos_Organization],
		       { "Organization", 		"sip.Organization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Organization Header", HFILL }
		},
                { &hf_header_array[Pos_Priority],
		       { "Priority", 		"sip.Priority", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Priority Header", HFILL }
		},
                { &hf_header_array[Pos_Proxy_Authenticate],
		       { "Proxy-Authenticate", 		"sip.Proxy-Authenticate", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Authenticate Header", HFILL }
		},
                { &hf_header_array[Pos_Proxy_Authorization],
		       { "Proxy-Authorization", 		"sip.Proxy-Authorization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Authorization Header", HFILL }
		},
                { &hf_header_array[Pos_RAck],
		       { "RAck", 		"sip.RAck", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3262: RAck Header", HFILL }
		},
                { &hf_header_array[Pos_RSeq],
		       { "RSeq", 		"sip.RSeq", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3262: RSeq Header", HFILL }
		},
                { &hf_header_array[Pos_Proxy_Require],
		       { "Proxy-Require", 		"sip.Proxy-Require", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Require Header", HFILL }
		},
                { &hf_header_array[Pos_Record_Route],
		       { "Record-Route", 		"sip.Record-Route", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Record-Route Header", HFILL }
		},
                { &hf_header_array[Pos_Reply_To],
		       { "Reply-To", 		"sip.Reply-To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Reply-To Header", HFILL }
		},
                { &hf_header_array[Pos_Require],
		       { "Require", 		"sip.Require", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Require Header", HFILL }
		},
                { &hf_header_array[Pos_Retry_After],
		       { "Retry-After", 		"sip.Retry-After", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Retry-After Header", HFILL }
		},
                { &hf_header_array[Pos_Route],
		       { "Route", 		"sip.Route", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Route Header", HFILL }
		},
                { &hf_header_array[Pos_Server],
		       { "Server", 		"sip.Server", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Server Header", HFILL }
		},
                { &hf_header_array[Pos_Subject],
		       { "Subject", 		"sip.Subject", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Subject Header", HFILL }
		},
                { &hf_header_array[Pos_Subscription_State],
		       { "Subscription-State", 		"sip.Subscription-State", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Subscription-State Header", HFILL }
		},
                { &hf_header_array[Pos_Supported],
		       { "Supported", 		"sip.Supported", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Supported Header", HFILL }
		},
                { &hf_header_array[Pos_Timestamp],
		       { "Timestamp", 		"sip.Timestamp", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Timestamp Header", HFILL }
		},
                { &hf_header_array[Pos_To],
		       { "To", 		"sip.To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: To Header", HFILL }
		},
                { &hf_header_array[Pos_Unsupported],
		       { "Unsupported", 		"sip.Unsupported", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Unsupported Header", HFILL }
		},
                { &hf_header_array[Pos_User_Agent],
		       { "User-Agent", 		"sip.User-Agent", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: User-Agent Header", HFILL }
		},
                { &hf_header_array[Pos_Via],
		       { "Via", 		"sip.Via", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Via Header", HFILL }
		},
                { &hf_header_array[Pos_Warning],
		       { "Warning", 		"sip.Warning", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Warning Header", HFILL }
		},
                { &hf_header_array[Pos_WWW_Authenticate],
		       { "WWW-Authenticate", 		"sip.WWW-Authenticate", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: WWW-Authenticate Header", HFILL }
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

        heur_dissector_add( "udp", dissect_sip_heur, proto_sip );
        heur_dissector_add( "tcp", dissect_sip_heur, proto_sip );

        /*
         * Get a handle for the SDP dissector.
         */
        sdp_handle = find_dissector("sdp");
        data_handle = find_dissector("data");
}
