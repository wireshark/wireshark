/* packet-sip.c
 * Routines for the Session Initiation Protocol (SIP) dissection.
 * RFCs 3261-3264
 *
 * TODO: Pay attention to Content-Type: It might not always be SDP.
 *	Content-Type is fixed, mixed/mode is not handled though.
 *       hf_ display filters for headers of SIP extension RFCs: 
 *		Done for RFC 3265, RFC 3262
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
 * $Id: packet-sip.c,v 1.52 2003/12/17 20:52:38 guy Exp $
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
#include <ctype.h>

#include "prefs.h"

#include <glib.h>
#include <epan/packet.h>

#define TCP_PORT_SIP 5060
#define UDP_PORT_SIP 5060

/* Initialize the protocol and registered fields */
static gint proto_sip = -1;
static gint proto_raw_sip = -1;
static gint hf_msg_hdr = -1;
static gint hf_Method = -1;
static gint hf_Status_Code = -1;
static gint hf_sip_to_addr = -1;
static gint hf_sip_from_addr = -1;
static gint hf_sip_tag = -1;

/* Initialize the subtree pointers */
static gint ett_sip 		= -1;
static gint ett_sip_reqresp 	= -1;
static gint ett_sip_hdr 	= -1;
static gint ett_raw_text 	= -1;
static gint ett_sip_element 	= -1;
static gint ett_sip_message_body = -1;

/* PUBLISH method added as per http://www.ietf.org/internet-drafts/draft-ietf-sip-publish-01.txt */
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
        "SUBSCRIBE",
        "UPDATE",
        "PUBLISH"
};

/* from RFC 3261 */
/* Updated with info from http://www.iana.org/assignments/sip-parameters */
/* (last updated 2003-10-31) */
/* Added two headsers ( Etag and If-Match )from http://www.ietf.org/internet-drafts/draft-ietf-sip-publish-01.txt */
typedef struct {
        char *name;
        char *compact_name;
} sip_header_t;
static const sip_header_t sip_headers[] = {
                { "Unknown-header", 		NULL }, /* Pad so that the real headers start at index 1 */
                { "Accept", 			NULL },
                { "Accept-Encoding", 		NULL },
                { "Accept-Language", 		NULL },
                { "Alert-Info", 		NULL },
                { "Allow", 			NULL },
                { "Allow-Events", 		NULL },
                { "Authentication-Info", 	NULL },
                { "Authorization", 		NULL },
                { "Call-ID", 			"i"  },
                { "Call-Info", 			NULL },
                { "Contact", 			"m"  },
                { "Content-Disposition", 	NULL },
                { "Content-Encoding", 		"e"  },
                { "Content-Language", 		NULL },
                { "Content-Length", 		"l"  },
                { "Content-Type", 		"c"  },
                { "CSeq", 			NULL },
                { "Date", 			NULL },
                { "Error-Info", 		NULL },
                { "Event", 			"o"  },
                { "Expires", 			NULL },
                { "From", 			"f"  },
                { "In-Reply-To", 		NULL },
                { "Max-Forwards", 		NULL },
                { "MIME-Version", 		NULL },
                { "Min-Expires", 		NULL },
                { "Organization", 		NULL },
                { "Priority", 			NULL },
                { "Proxy-Authenticate", 	NULL },
                { "Proxy-Authorization", 	NULL },
                { "Proxy-Require", 		NULL },
                { "RAck", 			NULL },
                { "RSeq", 			NULL },
                { "Record-Route", 		NULL },
                { "Reply-To", 			NULL },
                { "Require", 			NULL },
                { "Retry-After", 		NULL },
                { "Route", 			NULL },
                { "Server", 			NULL },
                { "Subject", 			"s"  },
                { "Subscription-State", 	NULL },
                { "Supported", 			"k" },
                { "Timestamp", 			NULL },
                { "To", 			"t"  },
                { "Unsupported", 		NULL },
                { "User-Agent", 		NULL },
                { "Via", 			"v" },
                { "Warning", 			NULL },
                { "WWW-Authenticate", 		NULL },
                { "P-Access-Network-Info",	NULL },  /*  RFC3455  */  
                { "P-Asserted-Identity",        NULL },  /*  RFC3325  */  
                { "P-Associated-URI",           NULL },  /*  RFC3455  */  
                { "P-Called-Party-ID",          NULL },  /*  RFC3455  */  
                { "P-Charging-Function-Addresses",NULL }, /*  RFC3455  */  
                { "P-Charging-Vector",          NULL },  /*  RFC3455  */  
                { "P-DCS-Trace-Party-ID",       NULL },  /*  RFC3603  */  
                { "P-DCS-OSPS",                 NULL },  /*  RFC3603  */  
                { "P-DCS-Billing-Info",         NULL },  /*  RFC3603  */  
                { "P-DCS-LAES",                 NULL },  /*  RFC3603  */  
                { "P-DCS-Redirect",             NULL },  /*  RFC3603  */  
                { "P-Media-Authorization",      NULL },  /*  RFC3313  */  
                { "P-Preferred-Identity",       NULL },  /*  RFC3325  */  
                { "P-Visited-Network-ID",       NULL },  /*  RFC3455  */  
                { "Path",                       NULL },  /*  RFC3327  */  
                { "Privacy",                    NULL },  /*  RFC3323  */  
                { "Reason",                     NULL },  /*  RFC3326  */  
                { "Refer-To",             	"r"  },  /*  RFC3515  */  
                { "Service-Route",              NULL },  /*  RFC3608  */  
                { "ETag",		        NULL },  /*  draft-ietf-sip-publish-01  */  
                { "If-Match",	                NULL },  /*  draft-ietf-sip-publish-01  */  

};


#define POS_ACCEPT 			1
#define POS_ACCEPT_ENCODING		2
#define POS_ACCEPT_LANGUAGE		3
#define POS_ALERT_INFO			4
#define POS_ALLOW			5
#define POS_ALLOW_EVENTS		6
#define POS_AUTHENTICATION_INFO		7
#define POS_AUTHORIZATION		8
#define POS_CALL_ID			9
#define POS_CALL_INFO			10
#define POS_CONTACT			11
#define POS_CONTENT_DISPOSITION		12
#define POS_CONTENT_ENCODING		13
#define POS_CONTENT_LANGUAGE		14
#define POS_CONTENT_LENGTH		15
#define POS_CONTENT_TYPE		16
#define POS_CSEQ			17
#define POS_DATE			18
#define POS_ERROR_INFO			19
#define POS_EVENT			20
#define POS_EXPIRES			21
#define POS_FROM			22
#define POS_IN_REPLY_TO			23
#define POS_MAX_FORWARDS		24
#define POS_MIME_VERSION		25
#define POS_MIN_EXPIRES			26
#define POS_ORGANIZATION		27
#define POS_PRIORITY			28
#define POS_PROXY_AUTHENTICATE		29
#define POS_PROXY_AUTHORIZATION		30
#define POS_PROXY_REQUIRE		31
#define POS_RACK			32
#define POS_RSEQ			33
#define POS_RECORD_ROUTE		34
#define POS_REPLY_TO			35
#define POS_REQUIRE			36
#define POS_RETRY_AFTER			37
#define POS_ROUTE			38
#define POS_SERVER			39
#define POS_SUBJECT			40
#define POS_SUBSCRIPTION_STATE		41
#define POS_SUPPORTED			42
#define POS_TIMESTAMP			43
#define POS_TO				44
#define POS_UNSUPPORTED			45
#define POS_USER_AGENT			46
#define POS_VIA				47
#define POS_WARNING			48
#define POS_WWW_AUTHENTICATE		49

#define POS_P_ACCESS_NETWORK_INFO	50  
#define POS_P_ASSERTED_IDENTITY         51    
#define POS_P_ASSOCIATED_URI            52  
#define POS_P_CALLED_PARTY_ID           53  
#define POS_P_CHARGING_FUNCTION_ADDRESSES 54  
#define POS_P_CHARGING_VECTOR           55
#define POS_P_DCS_TRACE_PARTY_ID        56 
#define POS_P_DCS_OSPS                  57  
#define POS_P_DCS_BILLING_INFO          58  
#define POS_P_DCS_LAES                  59  
#define POS_P_DCS_REDIRECT              60  
#define POS_P_MEDIA_AUTHORIZATION       61  
#define POS_P_PREFERRED_IDENTITY        62  
#define POS_P_VISITED_NETWORK_ID        63  
#define POS_PATH                        64  
#define POS_PRIVACY                     65  
#define POS_REASON                      66 
#define POS_REFER_TO                    67 
#define POS_SERVICE_ROUTE               68 
#define POS_ETAG		        69 
#define POS_IF_MATCH	                70  

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
                -1,  /* "WWW-Authenticate" */
                -1,  /* "P-Access-Network-Info"	-   RFC3455  */  
                -1,  /* "P-Asserted-Identity" 	-   RFC3325  */  
                -1,  /* "P-Associated-URI" 	-   RFC3455  */  
                -1,  /* "P-Called-Party-ID" 	-   RFC3455  */  
                -1,  /* "P-Charging-Function-Addresses" -   RFC3455  */  
                -1,  /* "P-Charging-Vector" 	-   RFC3455  */  
                -1,  /* "P-DCS-Trace-Party-ID" 	-   RFC3603  */  
                -1,  /* "P-DCS-OSPS" 		-   RFC3603  */  
                -1,  /* "P-DCS-Billing-Info" 	-   RFC3603  */  
                -1,  /* "P-DCS-LAES" 		-   RFC3603  */  
                -1,  /* "P-DCS-Redirect" 	-   RFC3603  */  
                -1,  /* "P-Media-Authorization" 	-   RFC3313  */  
                -1,  /* "P-Preferred-Identity" 	-   RFC3325  */  
                -1,  /* "P-Visited-Network-ID" 	-   RFC3455  */  
                -1,  /* "Path" 			-   RFC3327  */  
                -1,  /* "Privacy" 		-   RFC3323  */  
                -1,  /* "Reason" 		-   RFC3326  */  
                -1,  /* "Refer-To" 		-   RFC3515  */  
                -1,  /* "Service-Route" 		-   RFC3608  */  
                -1,  /* "ETag"     draft-ietf-sip-publish-01  */  
                -1,  /* "If-Match  draft-ietf-sip-publish-01  */  

};

/*
 * Type of line.  It's either a SIP Request-Line, a SIP Status-Line, or
 * another type of line.
 */
typedef enum {
	REQUEST_LINE,
	STATUS_LINE,
	OTHER_LINE
} line_type_t;

/* global_sip_raw_text determines whether we are going to display		*/
/* the raw text of the SIP message, much like the MEGACO dissector does.	*/
static gboolean global_sip_raw_text = FALSE;

static gboolean dissect_sip_common(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, gboolean is_heur);
static line_type_t sip_parse_line(tvbuff_t *tvb, gint linelen,
    guint *token_1_len);
static gboolean sip_is_known_request(tvbuff_t *tvb, int meth_offset,
    guint meth_len, guint *meth_idx);
static gint sip_is_known_sip_header(tvbuff_t *tvb, int offset,
    guint header_len);
static void dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree,
    guint meth_len);
static void dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree);
static void tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree);

/* SIP content type and internet media type used by other dissectors are the same */
/* List of nmediatypes from IANA at: http://www.iana.org/assignments/media-types/index.html */
static dissector_table_t media_type_dissector_table;

#define SIP2_HDR "SIP/2.0"
#define SIP2_HDR_LEN (strlen (SIP2_HDR))

/* Code to actually dissect the packets */
static int
dissect_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (!dissect_sip_common(tvb, pinfo, tree, FALSE))
		return 0;
	return tvb_length(tvb);
}

static void
dissect_sip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_sip_common(tvb, pinfo, tree, TRUE);
}

static gboolean
dissect_sip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_sip_common(tvb, pinfo, tree, FALSE);
}

static gboolean
dissect_sip_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean dissect_other_as_continuation)
{
        int offset;
        gint next_offset, linelen;
	line_type_t line_type;
        tvbuff_t *next_tvb;
        gboolean is_known_request;
	gboolean found_match = FALSE;
        char *descr;
        guint token_1_len;
	guint current_method_idx = 0;
        proto_item *ts = NULL, *ti, *th = NULL, *sip_element_item;
        proto_tree *sip_tree = NULL, *reqresp_tree, *hdr_tree = NULL, *sip_element_tree, *message_body_tree;
	guchar contacts = 0, contact_is_star = 0, expires_is_0 = 0;	
	char csec_method[16] = "";
	char *media_type_str = NULL;
	char *content_type_parameter_str = NULL;

        /*
         * Note that "tvb_find_line_end()" will return a value that
         * is not longer than what's in the buffer, so the
         * "tvb_get_ptr()" calls below won't throw exceptions.
         *
         * Note that "tvb_strneql()" doesn't throw exceptions, so
         * "sip_parse_line()" won't throw an exception.
         */
        offset = 0;
        linelen = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);
        line_type = sip_parse_line(tvb, linelen, &token_1_len);
        if (line_type == OTHER_LINE) {
        	/*
        	 * This is neither a SIP request nor response.
        	 */
                if (!dissect_other_as_continuation) {
                        /*
                         * We were asked to reject this.
                         */
                	return FALSE;
                }

                /*
                 * Just dissect it as a continuation.
                 */
        }

        if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIP");

        switch (line_type) {

        case REQUEST_LINE:
                is_known_request = sip_is_known_request(tvb, 0, token_1_len, &current_method_idx);
                descr = is_known_request ? "Request" : "Unknown request";
                if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
                             descr,
                             tvb_format_text(tvb, 0, linelen - SIP2_HDR_LEN - 1));
                }
		break;

        case STATUS_LINE:
                descr = "Status";
                if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "Status: %s",
                             tvb_format_text(tvb, SIP2_HDR_LEN + 1, linelen - SIP2_HDR_LEN - 1));
                }
		break;

	case OTHER_LINE:
	default: /* Squelch compiler complaints */
	        descr = "Continuation";
                if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
                break;
        }
        if (tree) {
                ts = proto_tree_add_item(tree, proto_sip, tvb, 0, -1, FALSE);
                sip_tree = proto_item_add_subtree(ts, ett_sip);

                ti = proto_tree_add_text(sip_tree, tvb, 0, next_offset,
                                         "%s line: %s", descr,
                                         tvb_format_text(tvb, 0, linelen));
                reqresp_tree = proto_item_add_subtree(ti, ett_sip_reqresp);

		switch (line_type) {

                case REQUEST_LINE:
                        dfilter_sip_request_line(tvb, reqresp_tree, token_1_len);
                        break;

                case STATUS_LINE:
                        dfilter_sip_status_line(tvb, reqresp_tree);
                        break;

		case OTHER_LINE:
		        proto_tree_add_text(sip_tree, tvb, 0, -1,
		            "Continuation data");
		        return TRUE;
                }

                offset = next_offset;
                th = proto_tree_add_item(sip_tree, hf_msg_hdr, tvb, offset, -1,
                    FALSE);
                hdr_tree = proto_item_add_subtree(th, ett_sip_hdr);
        }

        /*
         * Process the headers - if we're not building a protocol tree,
         * we just do this to find the blank line separating the
         * headers from the message body.
         */
        next_offset = offset;
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
                gint line_end_offset;
                gint colon_offset;
                gint semicolon_offset;
		gint content_type_len, content_type_parameter_str_len;
                gint header_len;
                gint hf_index;
                gint value_offset,tag_offset;
                guchar c;
		size_t value_len;
                char *value;

                linelen = tvb_find_line_end(tvb, offset, -1, &next_offset,
                    FALSE);
                if (linelen == 0) {
                        /*
                         * This is a blank line separating the
                         * message header from the message body.
                         */
                        break;
                }
                line_end_offset = offset + linelen;
		colon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
		if (colon_offset == -1) {
			/*
			 * Malformed header - no colon after the name.
			 */
			proto_tree_add_text(hdr_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, linelen));
		} else {
			header_len = colon_offset - offset;
			hf_index = sip_is_known_sip_header(tvb,
			    offset, header_len);

			if (hf_index == -1) {
				proto_tree_add_text(hdr_tree, tvb,
				    offset, next_offset - offset, "%s",
				    tvb_format_text(tvb, offset, linelen));
			} else {
				/*
				 * Skip whitespace after the colon.
				 */
				value_offset = colon_offset + 1;
				while (value_offset < line_end_offset
				    && ((c = tvb_get_guint8(tvb,
					    value_offset)) == ' '
				      || c == '\t'))
					value_offset++;
				/*
				 * Fetch the value.
				 */
				value_len = line_end_offset - value_offset;
				value = tvb_get_string(tvb, value_offset,
				    value_len);

				/*
				 * Add it to the protocol tree,
				 * but display the line as is.
				 */
				switch ( hf_index ) {

				case POS_TO :
					sip_element_item = proto_tree_add_string_format(hdr_tree,
					    hf_header_array[hf_index], tvb,
					    offset, next_offset - offset,
					    value, "%s",
					    tvb_format_text(tvb, offset, linelen));
					sip_element_tree = proto_item_add_subtree( sip_element_item,
						 ett_sip_element);
					tag_offset = tvb_find_guint8(tvb, offset,linelen, ';');
					if ( tag_offset != -1){
						tag_offset = tag_offset + 1;
						c = tvb_get_guint8(tvb,tag_offset);
						if ( c == 't' ){/* tag found */
							proto_tree_add_string(sip_element_tree,
							    hf_sip_to_addr, tvb,
							    value_offset, (tag_offset - value_offset - 1),
				    			tvb_format_text(tvb, value_offset,
							( tag_offset - value_offset - 1)));
							tag_offset = tvb_find_guint8(tvb, tag_offset,linelen, '=') + 1;
							proto_tree_add_string(sip_element_tree,
							    hf_sip_tag, tvb,
							    tag_offset, (line_end_offset - tag_offset),
				    			tvb_format_text(tvb, tag_offset, (line_end_offset - tag_offset)));
						
						}
						else {
							proto_tree_add_string_format(sip_element_tree,
							    hf_sip_to_addr, tvb,
							    offset, line_end_offset - offset,
							    value, "%s",
							    tvb_format_text(tvb, offset, linelen));
						}/* if c= t */
					} /* if tag offset */
					break;	

				case POS_FROM :
					sip_element_item = proto_tree_add_string_format(hdr_tree,
					    hf_header_array[hf_index], tvb,
					    offset, next_offset - offset,
					    value, "%s",
					    tvb_format_text(tvb, offset, linelen));
					sip_element_tree = proto_item_add_subtree( sip_element_item, ett_sip_element);
					tag_offset = tvb_find_guint8(tvb, offset,linelen, ';');
					if ( tag_offset != -1){
						tag_offset = tag_offset + 1;
						c = tvb_get_guint8(tvb,tag_offset);
						if ( c == 't' ){/* tag found */
							proto_tree_add_string(sip_element_tree,
							    hf_sip_from_addr, tvb,
							    value_offset, (tag_offset - value_offset - 1),
							    tvb_format_text(tvb, value_offset, ( tag_offset - value_offset - 1)));
							tag_offset = tvb_find_guint8(tvb, offset,linelen, '=') + 1;
							proto_tree_add_string(sip_element_tree,
							    hf_sip_tag, tvb,
							    tag_offset, (line_end_offset - tag_offset),
							    tvb_format_text(tvb, tag_offset, (line_end_offset - tag_offset)));
						}
						else {
							tag_offset = tvb_find_guint8(tvb, tag_offset,linelen, ';');
							if ( tag_offset != -1){
								tag_offset = tag_offset + 1;
								c = tvb_get_guint8(tvb,tag_offset);
								if ( c == 't' ){/* tag found */
									proto_tree_add_string(sip_element_tree,
							 		   hf_sip_from_addr, tvb,
							   		   value_offset, (tag_offset - value_offset - 1),
				    					   tvb_format_text(tvb, value_offset, ( tag_offset - value_offset - 1)));
									tag_offset = tvb_find_guint8(tvb, tag_offset,linelen, '=') + 1;
									proto_tree_add_string(sip_element_tree,
									    hf_sip_tag, tvb,
									    tag_offset, (line_end_offset - tag_offset),
									    tvb_format_text(tvb, tag_offset, (line_end_offset - tag_offset)));
								}
							}
						}/* if c= t */
					} /* if tag offset */
					break;

				case POS_CSEQ :
					/* Extract method name from value */
					for (value_offset = 0; value_offset < (gint)strlen(value); value_offset++)
					{
						if (isalpha(value[value_offset]))
						{
							strcpy(csec_method,value+value_offset);
							break;
						}
					}
					/* Add 'CSeq' string item to tree */
					proto_tree_add_string_format(hdr_tree,
					    hf_header_array[hf_index], tvb,
					    offset, next_offset - offset,
					    value, "%s",
					    tvb_format_text(tvb, offset, linelen));
					break;

				case POS_EXPIRES :
					if (strcmp(value, "0") == 0)
					{
						expires_is_0 = 1;
					}
					/* Add 'Expires' string item to tree */
					proto_tree_add_string_format(hdr_tree,
					    hf_header_array[hf_index], tvb,
					    offset, next_offset - offset,
					    value, "%s",
					    tvb_format_text(tvb, offset, linelen));
					break;

				/*
				 * Content-Type is the same as Internet
				 * media type used by other dissectors,
				 * appropriate dissector found by
				 * lookup in "media_type" dissector table.
				 */
				case POS_CONTENT_TYPE :
					proto_tree_add_string_format(hdr_tree,
					    hf_header_array[hf_index], tvb,
					    offset, next_offset - offset,
					    value, "%s",
					    tvb_format_text(tvb, offset, linelen));
					content_type_len = value_len;
					semicolon_offset = tvb_find_guint8(tvb, value_offset,linelen, ';');
					if ( semicolon_offset != -1) {
						content_type_len = semicolon_offset - value_offset;
						content_type_parameter_str_len = linelen - semicolon_offset; 
						content_type_parameter_str = tvb_get_string(tvb, semicolon_offset + 1, content_type_parameter_str_len);
					}
					media_type_str = tvb_get_string(tvb, value_offset, content_type_len);
					break;

				case POS_CONTACT :
					contacts++;
					if (strcmp(value, "*") == 0)
					{
						contact_is_star = 1;
					}
					/* Fall through to default case to add string to tree */

				default :	
					proto_tree_add_string_format(hdr_tree,
					    hf_header_array[hf_index], tvb,
					    offset, next_offset - offset,
					    value, "%s",
					    tvb_format_text(tvb, offset, linelen));
				break;
				}/* end switch */
				g_free(value);
			}/*if HF_index */
		}/* if colon_offset */ 
                offset = next_offset;
        }/* End while */

        if (tvb_offset_exists(tvb, next_offset)) {

                /*
                 * There's a message body starting at "next_offset".
                 * Set the length of the SIP portion and of the
                 * header item.
                 */
                proto_item_set_end(ts, tvb, next_offset);
                proto_item_set_end(th, tvb, next_offset);
                next_tvb = tvb_new_subset(tvb, next_offset, -1, -1);
               	ti = proto_tree_add_text(sip_tree, next_tvb, 0, -1,
                                         "Message body");
               	message_body_tree = proto_item_add_subtree(ti, ett_sip_message_body);

		/* give the content type parameters to sub dissectors */
		
		if ( media_type_str != NULL ) {
			pinfo->private_data = content_type_parameter_str;
			found_match = dissector_try_string(media_type_dissector_table,
							   media_type_str,
							   next_tvb, pinfo,
							   message_body_tree);
			g_free(media_type_str);
			g_free(content_type_parameter_str);
			/* If no match dump as text */
		}
		if ( found_match != TRUE )
		{
			offset = 0;
	        	while (tvb_offset_exists(next_tvb, offset)) {
	                	tvb_find_line_end(next_tvb, offset, -1, &next_offset, FALSE);
	                	linelen = next_offset - offset;
	                	proto_tree_add_text(message_body_tree, next_tvb, offset, linelen,
	                   		"%s", tvb_format_text(next_tvb, offset, linelen));
 	        		offset = next_offset;
 	 		}/* end while */
		}
        }


	/* Add to info column interesting things learned from header fields. */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		/* Registration requests */
		if (strcmp(sip_methods[current_method_idx], "REGISTER") == 0)
		{
			if (contact_is_star && expires_is_0)
			{
				col_append_str(pinfo->cinfo, COL_INFO, "    (remove all bindings)");
			}
			else
			if (!contacts)
			{
				col_append_str(pinfo->cinfo, COL_INFO, "    (fetch bindings)");
			}
		}

		/* Registration responses */
		if (line_type == STATUS_LINE && (strcmp(csec_method, "REGISTER") == 0))
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "    (%d bindings)", contacts);
		}
	}

        if (global_sip_raw_text)
                tvb_raw_text_add(tvb, tree);

        return TRUE;
}

/* Display filter for SIP Request-Line */
static void
dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree, guint meth_len)
{
	char	*string;

        /*
         * We know we have the entire method; otherwise, "sip_parse_line()"
         * would have returned OTHER_LINE.
         */
        string = tvb_get_string(tvb, 0, meth_len);
        proto_tree_add_string(tree, hf_Method, tvb, 0, meth_len, string);
        g_free(string);
}

/* Display filter for SIP Status-Line */
static void
dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree)
{
	char string[3+1];

        /*
         * We know we have the entire status code; otherwise,
         * "sip_parse_line()" would have returned OTHER_LINE.
         * We also know that we have a version string followed by a
         * space at the beginning of the line, for the same reason.
         */
        tvb_memcpy(tvb, (guint8 *)string, SIP2_HDR_LEN + 1, 3);
        string[3] = '\0';
        proto_tree_add_string(tree, hf_Status_Code, tvb, SIP2_HDR_LEN + 1,
            3, string);
}

/* From section 4.1 of RFC 2543:
 *
 * Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
 *
 * From section 5.1 of RFC 2543:
 *
 * Status-Line  =  SIP-version SP Status-Code SP Reason-Phrase CRLF
 */
static line_type_t
sip_parse_line(tvbuff_t *tvb, gint linelen, guint *token_1_lenp)
{
	gint space_offset;
	guint token_1_len;
	gint token_2_start;
	guint token_2_len;
	gint token_3_start;
	guint token_3_len;
	gint colon_pos;

	space_offset = tvb_find_guint8(tvb, 0, -1, ' ');
	if (space_offset <= 0) {
		/*
		 * Either there's no space in the line (which means
		 * the line is empty or doesn't have a token followed
		 * by a space; neither is valid for a request or status), or
		 * the first character in the line is a space (meaning
		 * the method is empty, which isn't valid for a request,
		 * or the SIP version is empty, which isn't valid for a
		 * status).
		 */
		return OTHER_LINE;
	}
	token_1_len = space_offset;
	token_2_start = space_offset + 1;
	space_offset = tvb_find_guint8(tvb, token_2_start, -1, ' ');
	if (space_offset == -1) {
		/*
		 * There's no space after the second token, so we don't
		 * have a third token.
		 */
		return OTHER_LINE;
	}
	token_2_len = space_offset - token_2_start;
	token_3_start = space_offset + 1;
	token_3_len = linelen - token_3_start;
	
	*token_1_lenp = token_1_len;

	/*
	 * Is the first token a version string?
	 */
	if (token_1_len == SIP2_HDR_LEN &&
	    tvb_strneql(tvb, 0, SIP2_HDR, SIP2_HDR_LEN) == 0) {
		/*
		 * Yes, so this is either a Status-Line or something
		 * else other than a Request-Line.  To be a Status-Line,
		 * the second token must be a 3-digit number.
		 */
		if (token_2_len != 3) {
			/*
			 * We don't have 3-character status code.
			 */
			return OTHER_LINE;
		}
		if (!isdigit(tvb_get_guint8(tvb, token_2_start)) ||
		    !isdigit(tvb_get_guint8(tvb, token_2_start + 1)) ||
		    !isdigit(tvb_get_guint8(tvb, token_2_start + 2))) {
			/*
			 * 3 characters yes, 3 digits no.
			 */
			return OTHER_LINE;
		}
		return STATUS_LINE;
	} else {
		/*
		 * No, so this is either a Request-Line or something
		 * other than a Status-Line.  To be a Request-Line, the
		 * second token must be a URI and the third token must
		 * be a version string.
		 */
		if (token_2_len < 3) {
			/*
			 * We don't have a URI consisting of at least 3
			 * characters.
			 */
			return OTHER_LINE;
		}
		colon_pos = tvb_find_guint8(tvb, token_2_start + 1, -1, ':');
		if (colon_pos == -1) {
			/*
			 * There is no colon after the method, so the URI
			 * doesn't have a colon in it, so it's not valid.
			 */
			return OTHER_LINE;
		}
		if (colon_pos >= token_3_start) {
			/*
			 * The colon is in the version string, not the URI.
			 */
			return OTHER_LINE;
		}
		/* XXX - Check for a proper URI prefix? */
		if (token_3_len != SIP2_HDR_LEN ||
		    tvb_strneql(tvb, token_3_start, SIP2_HDR, SIP2_HDR_LEN) == -1) {
			/*
			 * The version string isn't an SIP version 2.0 version
			 * string.
			 */
			return OTHER_LINE;
		}
		return REQUEST_LINE;
	}
}

static gboolean sip_is_known_request(tvbuff_t *tvb, int meth_offset,
    guint meth_len, guint *meth_idx)
{
        guint i;

        for (i = 1; i < array_length(sip_methods); i++) {
                if (meth_len == strlen(sip_methods[i]) &&
                    tvb_strneql(tvb, meth_offset, sip_methods[i], meth_len) == 0)
                {
                     *meth_idx = i;
                     return TRUE;
                }
        }

        return FALSE;
}

/* Returns index of method in sip_headers */
static gint sip_is_known_sip_header(tvbuff_t *tvb, int offset, guint header_len)
{
        guint i;

        for (i = 1; i < array_length(sip_headers); i++) {
                if (header_len == strlen(sip_headers[i].name) &&
                    tvb_strncaseeql(tvb, offset, sip_headers[i].name, header_len) == 0)
                        return i;
                if (sip_headers[i].compact_name != NULL &&
                    header_len == strlen(sip_headers[i].compact_name) &&
                    tvb_strncaseeql(tvb, offset, sip_headers[i].compact_name, header_len) == 0)
                        return i;
        }

        return -1;
}

/*
 * Display the entire message as raw text.
 */
static void
tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree)
{
        proto_tree *raw_tree;
        proto_item *ti;
        int offset, next_offset, linelen;

        ti = proto_tree_add_item(tree, proto_raw_sip, tvb, 0, -1, FALSE);
        raw_tree = proto_item_add_subtree(ti, ett_raw_text);

        offset = 0;

        while (tvb_offset_exists(tvb, offset)) {
                tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
                linelen = next_offset - offset;
                proto_tree_add_text(raw_tree, tvb, offset, linelen,
                    "%s", tvb_format_text(tvb, offset, linelen));
                offset = next_offset;
        }
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
                { &hf_sip_to_addr,
		       { "SIP to address", 		"sip.from_addr", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: from addr", HFILL }
		},
                { &hf_sip_from_addr,
		       { "SIP from address", 		"sip.to_addr", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: to addr", HFILL }
		},
                { &hf_sip_tag,
		       { "SIP tag", 		"sip.tag", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: tag", HFILL }
		},
                { &hf_header_array[POS_ACCEPT],
		       { "Accept", 		"sip.Accept", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept Header", HFILL }
		},
                { &hf_header_array[POS_ACCEPT_ENCODING],
		       { "Accept-Encoding", 		"sip.Accept-Encoding", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept-Encoding Header", HFILL }
		},
                { &hf_header_array[POS_ACCEPT_LANGUAGE],
		       { "Accept-Language", 		"sip.Accept-Language", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept-Language Header", HFILL }
		},
                { &hf_header_array[POS_ALERT_INFO],
		       { "Alert-Info", 		"sip.Alert-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Alert-Info Header", HFILL }
		},
                { &hf_header_array[POS_ALLOW],
		       { "Allow", 		"sip.Allow", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Allow Header", HFILL }
		},
                { &hf_header_array[POS_ALLOW_EVENTS],
		       { "Allow-Events", 		"sip.Allow-Events", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Allow-Events Header", HFILL }
		},
                { &hf_header_array[POS_AUTHENTICATION_INFO],
		       { "Authentication-Info", 		"sip.Authentication-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Authentication-Info Header", HFILL }
		},
                { &hf_header_array[POS_AUTHORIZATION],
		       { "Authorization", 		"sip.Authorization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Authorization Header", HFILL }
		},
                { &hf_header_array[POS_CALL_ID],
		       { "Call-ID", 		"sip.Call-ID", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Call-ID Header", HFILL }
		},
                { &hf_header_array[POS_CALL_INFO],
		       { "Call-Info", 		"sip.Call-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Call-Info Header", HFILL }
		},
                { &hf_header_array[POS_CONTACT],
		       { "Contact", 		"sip.Contact", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Contact Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_DISPOSITION],
		       { "Content-Disposition", 		"sip.Content-Disposition", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Disposition Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_ENCODING],
		       { "Content-Encoding", 		"sip.Content-Encoding", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Encoding Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_LANGUAGE],
		       { "Content-Language", 		"sip.Content-Language", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Language Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_LENGTH],
		       { "Content-Length", 		"sip.Content-Length", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Length Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_TYPE],
		       { "Content-Type", 		"sip.Content-Type", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Type Header", HFILL }
		},
                { &hf_header_array[POS_CSEQ],
		       { "CSeq", 		"sip.CSeq", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: CSeq Header", HFILL }
		},
                { &hf_header_array[POS_DATE],
		       { "Date", 		"sip.Date", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Date Header", HFILL }
		},
                { &hf_header_array[POS_ERROR_INFO],
		       { "Error-Info", 		"sip.Error-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Error-Info Header", HFILL }
		},
                { &hf_header_array[POS_EVENT],
		       { "Event", 		"sip.Event", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Event Header", HFILL }
		},
                { &hf_header_array[POS_EXPIRES],
		       { "Expires", 		"sip.Expires", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Expires Header", HFILL }
		},
                { &hf_header_array[POS_FROM],
		       { "From", 		"sip.From", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Header", HFILL }
		},
                { &hf_header_array[POS_IN_REPLY_TO],
		       { "In-Reply-To", 		"sip.In-Reply-To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: In-Reply-To Header", HFILL }
		},
                { &hf_header_array[POS_MAX_FORWARDS],
		       { "Max-Forwards", 		"sip.Max-Forwards", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Max-Forwards Header", HFILL }
		},
                { &hf_header_array[POS_MIME_VERSION],
		       { "MIME-Version", 		"sip.MIME-Version", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: MIME-Version Header", HFILL }
		},
                { &hf_header_array[POS_MIN_EXPIRES],
		       { "Min-Expires", 		"sip.Min-Expires", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Min-Expires Header", HFILL }
		},
                { &hf_header_array[POS_ORGANIZATION],
		       { "Organization", 		"sip.Organization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Organization Header", HFILL }
		},
                { &hf_header_array[POS_PRIORITY],
		       { "Priority", 		"sip.Priority", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Priority Header", HFILL }
		},
                { &hf_header_array[POS_PROXY_AUTHENTICATE],
		       { "Proxy-Authenticate", 		"sip.Proxy-Authenticate", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Authenticate Header", HFILL }
		},
                { &hf_header_array[POS_PROXY_AUTHORIZATION],
		       { "Proxy-Authorization", 		"sip.Proxy-Authorization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Authorization Header", HFILL }
		},
                { &hf_header_array[POS_RACK],
		       { "RAck", 		"sip.RAck", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3262: RAck Header", HFILL }
		},
                { &hf_header_array[POS_RSEQ],
		       { "RSeq", 		"sip.RSeq", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3262: RSeq Header", HFILL }
		},
                { &hf_header_array[POS_PROXY_REQUIRE],
		       { "Proxy-Require", 		"sip.Proxy-Require", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Require Header", HFILL }
		},
                { &hf_header_array[POS_RECORD_ROUTE],
		       { "Record-Route", 		"sip.Record-Route", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Record-Route Header", HFILL }
		},
                { &hf_header_array[POS_REPLY_TO],
		       { "Reply-To", 		"sip.Reply-To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Reply-To Header", HFILL }
		},
                { &hf_header_array[POS_REQUIRE],
		       { "Require", 		"sip.Require", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Require Header", HFILL }
		},
                { &hf_header_array[POS_RETRY_AFTER],
		       { "Retry-After", 		"sip.Retry-After", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Retry-After Header", HFILL }
		},
                { &hf_header_array[POS_ROUTE],
		       { "Route", 		"sip.Route", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Route Header", HFILL }
		},
                { &hf_header_array[POS_SERVER],
		       { "Server", 		"sip.Server", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Server Header", HFILL }
		},
                { &hf_header_array[POS_SUBJECT],
		       { "Subject", 		"sip.Subject", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Subject Header", HFILL }
		},
                { &hf_header_array[POS_SUBSCRIPTION_STATE],
		       { "Subscription-State", 		"sip.Subscription-State", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Subscription-State Header", HFILL }
		},
                { &hf_header_array[POS_SUPPORTED],
		       { "Supported", 		"sip.Supported", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Supported Header", HFILL }
		},
                { &hf_header_array[POS_TIMESTAMP],
		       { "Timestamp", 		"sip.Timestamp", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Timestamp Header", HFILL }
		},
                { &hf_header_array[POS_TO],
		       { "To", 		"sip.To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: To Header", HFILL }
		},
                { &hf_header_array[POS_UNSUPPORTED],
		       { "Unsupported", 		"sip.Unsupported", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Unsupported Header", HFILL }
		},
                { &hf_header_array[POS_USER_AGENT],
		       { "User-Agent", 		"sip.User-Agent", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: User-Agent Header", HFILL }
		},
                { &hf_header_array[POS_VIA],
		       { "Via", 		"sip.Via", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Via Header", HFILL }
		},
                { &hf_header_array[POS_WARNING],
		       { "Warning", 		"sip.Warning", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Warning Header", HFILL }
		},
                { &hf_header_array[POS_WWW_AUTHENTICATE],
		       { "WWW-Authenticate", 		"sip.WWW-Authenticate", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: WWW-Authenticate Header", HFILL }
		},
		{ &hf_header_array[POS_P_ACCESS_NETWORK_INFO],  
		       { "P-Access-Network-Info",	"sip.P-Access-Network-Info",  
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Access-Network-Info Header", HFILL }
		},

		{ &hf_header_array[POS_P_ASSERTED_IDENTITY],    
		       { "P-Asserted-Identity",		"sip.P-Asserted-Identity",  
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Asserted-Identity Header", HFILL }
		},

		{ &hf_header_array[POS_P_ASSOCIATED_URI],  
		       { "P-Associated-URI", 		"sip.P-Associated-URI", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Associated-URI Header", HFILL }
		},

		{ &hf_header_array[POS_P_CALLED_PARTY_ID],  
		       { "P-Called-Party-ID", 		"sip.P-Called-Party-ID", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Called-Party-ID Header", HFILL }
		},

		{ &hf_header_array[POS_P_CHARGING_FUNCTION_ADDRESSES],  
		       { "P-Charging-Function-Addresses","sip.P-Charging-Function-Addresses",  
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Charging-Function-Addresses", HFILL }
		},

		{ &hf_header_array[POS_P_CHARGING_VECTOR],
		       { "P-Charging-Vector", 		"sip.P-Charging-Vector", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Charging-Vector Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_TRACE_PARTY_ID], 
		       { "P-DCS-Trace-Party-ID", 	"sip.P-DCS-Trace-Party-ID", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-Trace-Party-ID Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_OSPS],  
		       { "P-DCS-OSPS", 			"sip.P-DCS-OSPS", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-OSPS Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_BILLING_INFO],  
		       { "P-DCS-Billing-Info", 		"sip.P-DCS-Billing-Info", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-Billing-Info Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_LAES],  
		       { "P-DCS-LAES", 			"sip.P-DCS-LAES", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-LAES Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_REDIRECT],  
		       { "P-DCS-Redirect", 		"sip.P-DCS-Redirect", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-Redirect Header", HFILL }
		},

		{ &hf_header_array[POS_P_MEDIA_AUTHORIZATION],  
		       { "P-Media-Authorization", 	"sip.P-Media-Authorization", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Media-Authorization Header", HFILL }
		},

		{ &hf_header_array[POS_P_PREFERRED_IDENTITY],  
		       { "P-Preferred-Identity",  	"sip.P-Preferred-Identity", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Preferred-Identity Header", HFILL }
		},

		{ &hf_header_array[POS_P_VISITED_NETWORK_ID],  
		       { "P-Visited-Network-ID", 	"sip.P-Visited-Network-ID",  
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Visited-Network-ID Header", HFILL }
		},

		{ &hf_header_array[POS_PATH],  
		       { "Path", 			"sip.Path", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Path Header", HFILL }
		},

		{ &hf_header_array[POS_PRIVACY],  
		       { "Privacy", 			"sip.Privacy", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Privacy Header", HFILL }
		},

		{ &hf_header_array[POS_REASON], 
		       { "Reason", 			"sip.Reason", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Reason Header", HFILL }
		},

		{ &hf_header_array[POS_REFER_TO], 
		       { "Refer-To", 			"sip.Refer-To", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Refer-To Header", HFILL }
		},

		{ &hf_header_array[POS_SERVICE_ROUTE],                  
		       { "Service-Route", 		"sip.Service-Route", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Service-Route Header", HFILL }
		},

		{ &hf_header_array[POS_ETAG],                  
		       { "ETag", 		"sip.ETag", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"ETag Header", HFILL }
		},
		{ &hf_header_array[POS_IF_MATCH],                  
		       { "If_Match", 		"sip.If_Match", 
		       FT_STRING, BASE_NONE,NULL,0x0,
			"If-Match Header", HFILL }
		},
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_sip,
                &ett_sip_reqresp,
                &ett_sip_hdr,
		&ett_sip_element,
		&ett_sip_message_body,
        };
        static gint *ett_raw[] = {
                &ett_raw_text,
        };

	module_t *sip_module;

        /* Register the protocol name and description */
        proto_sip = proto_register_protocol("Session Initiation Protocol",
            "SIP", "sip");
        proto_raw_sip = proto_register_protocol("Session Initiation Protocol (SIP as raw text)",
            "Raw_SIP", "raw_sip");

        /* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_sip, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        proto_register_subtree_array(ett_raw, array_length(ett_raw));

	/* SIP content type and internet media type used by other dissectors are the same */

	media_type_dissector_table = find_dissector_table("media_type");


        sip_module = prefs_register_protocol(proto_sip, NULL);

	prefs_register_bool_preference(sip_module, "display_raw_text",
		"Display raw text for SIP message",
		"Specifies that the raw text of the "
		"SIP message should be displayed "
		"in addition to the dissection tree",
		&global_sip_raw_text);
}

void
proto_reg_handoff_sip(void)
{
        dissector_handle_t sip_handle, sip_tcp_handle;

        sip_handle = new_create_dissector_handle(dissect_sip, proto_sip);
        dissector_add("udp.port", UDP_PORT_SIP, sip_handle);

        sip_tcp_handle = create_dissector_handle(dissect_sip_tcp, proto_sip);
        dissector_add("tcp.port", TCP_PORT_SIP, sip_tcp_handle);

        heur_dissector_add("udp", dissect_sip_heur, proto_sip);
        heur_dissector_add("tcp", dissect_sip_heur, proto_sip);
        heur_dissector_add("sctp", dissect_sip_heur, proto_sip);

}
