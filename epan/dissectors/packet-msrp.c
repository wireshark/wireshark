/* packet-msrp.c
 * Routines for Message Session Relay Protocol(MSRP) dissection
 * Copyright 2005, Anders Broman <anders.broman[at]ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References:
 * http://www.ietf.org/internet-drafts/draft-ietf-simple-message-sessions-10.txt
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/conversation.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include "prefs.h"

#include "packet-msrp.h"

#define TCP_PORT_MSRP 0

#define MSRP_HDR "MSRP"
#define MSRP_HDR_LEN (strlen (MSRP_HDR))

/* Initialize the protocol and registered fields */
static int proto_msrp		= -1;

/* Initialize the subtree pointers */
static int ett_msrp					= -1;
static int ett_raw_text				= -1;
static int ett_msrp_reqresp			= -1;
static int ett_msrp_hdr				= -1;
static int ett_msrp_element			= -1;
static int ett_msrp_data			= -1;
static int ett_msrp_end_line		= -1;
static int ett_msrp_setup			= -1;

static int hf_msrp_response_line	= -1;
static int hf_msrp_request_line		= -1;
static int hf_msrp_transactionID	= -1;
static int hf_msrp_method			= -1;
static int hf_msrp_status_code		= -1;
static int hf_msrp_msg_hdr			= -1;
static int hf_msrp_end_line			= -1;
static int hf_msrp_cnt_flg			= -1;

/* MSRP setup fields */
static int hf_msrp_setup        = -1;
static int hf_msrp_setup_frame  = -1;
static int hf_msrp_setup_method = -1;

typedef struct {
        const char *name;
} msrp_header_t;

static const msrp_header_t msrp_headers[] = {
	{ "Unknown-header"},
	{ "From-Path"},				/*  1 */
	{ "To-Path"},				/*  2 */
	{ "Message-ID"},			/*  3 */
	{ "Success-Report"},		/*  4 */
	{ "Failure-Report"},		/*  5 */
	{ "Byte-Range"},			/*  6 */
	{ "Status"},				/*  7 */
	{ "Content-Type"},			/*  8 */
	{ "Content-ID"},			/*  9 */
	{ "Content-Description"},	/*  10 */
	{ "Content-Disposition"},	/*  11 */
	{ "Use-Path"},				/*  12 */
	{ "WWW-Authenticate"},		/*  13 */
	{ "Authorization"},			/*  14 */
	{ "Authentication-Info"},	/*  15 */
};

static gint hf_header_array[] = {
	-1, /* 0"Unknown-header" - Pad so that the real headers start at index 1 */
	-1, /* 1"From-Path														 */
	-1, /* 2"To-Path														 */
	-1, /* 3"Message-ID"													 */
	-1, /* 4"Success-Report"												 */
	-1, /* 5"Failure-Report"												 */
	-1, /* 6"Byte-Range"													 */
	-1, /* 7"Status"														 */
	-1, /* 8"Content-Type"													 */
	-1, /* 9"Content-ID"													 */
	-1, /* 10"Content-Description"											 */
	-1, /* 11"Content-Disposition"											 */
	-1, /* 12"Use-Path"														 */
	-1, /* 13"WWW-Authenticate"												 */
	-1, /* 14"Authorization"												 */
	-1, /* 15"Authentication-Info"											 */
};

#define MSRP_FROM_PATH							1
#define MSRP_TO_PATH							2
#define MSRP_MESSAGE_ID							3
#define MSRP_SUCCESS_REPORT						4
#define MSRP_FAILURE_REPORT						5
#define MSRP_BYTE_RANGE							6
#define MSRP_STATUS								7
#define MSRP_CONTENT_TYPE						8
#define MSRP_CONTENT_ID							9
#define MSRP_CONTENT_DISCRIPTION				10
#define MSRP_CONTENT_DISPOSITION				11
#define MSRP_USE_PATH							12
#define MSRP_WWW_AUTHENTICATE					13
#define MSRP_AUTHORIZATION						14
#define MSRP_AUTHENTICATION_INFO				15

dissector_handle_t msrp_handle;
gboolean global_msrp_raw_text = TRUE;

/* MSRP content type and internet media type used by other dissectors
 * are the same.  List of media types from IANA at:
 * http://www.iana.org/assignments/media-types/index.html */
static dissector_table_t media_type_dissector_table;

static int dissect_msrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/* Displaying conversation setup info */
static gboolean global_msrp_show_setup_info = TRUE;
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Set up an MSRP conversation using the info given */
void msrp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       const gchar *setup_method, guint32 setup_frame_number)
{
	address null_addr;
	conversation_t* p_conv;
	struct _msrp_conversation_info *p_conv_data = NULL;

	/*
	 * If this isn't the first time this packet has been processed,
	 * we've already done this work, so we don't need to do it
	 * again.
	 */
	if (pinfo->fd->flags.visited)
	{
		return;
	}

	SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

	/*
	 * Check if the ip address and port combination is not
	 * already registered as a conversation.
	 */
	p_conv = find_conversation( pinfo->fd->num, addr, &null_addr, PT_TCP, port, 0,
	                            NO_ADDR_B | NO_PORT_B);

	/*
	 * If not, create a new conversation.
	 */
	if (!p_conv) {
		p_conv = conversation_new( pinfo->fd->num, addr, &null_addr, PT_TCP,
		                           (guint32)port, 0,
		                           NO_ADDR2 | NO_PORT2);
	}

	/* Set dissector */
	conversation_set_dissector(p_conv, msrp_handle);

	/*
	 * Check if the conversation has data associated with it.
	 */
	p_conv_data = conversation_get_proto_data(p_conv, proto_msrp);

	/*
	 * If not, add a new data item.
	 */
	if (!p_conv_data) {
		/* Create conversation data */
		p_conv_data = se_alloc(sizeof(struct _msrp_conversation_info));
		if (!p_conv_data)
		{
			return;
		}
		memset(p_conv_data, 0, sizeof(struct _msrp_conversation_info));
		conversation_add_proto_data(p_conv, proto_msrp, p_conv_data);
	}

	/*
	 * Update the conversation data.
	 */
	p_conv_data->setup_method_set = TRUE;
	strncpy(p_conv_data->setup_method, setup_method, MAX_MSRP_SETUP_METHOD_SIZE);
	p_conv_data->setup_method[MAX_MSRP_SETUP_METHOD_SIZE] = '\0';
	p_conv_data->setup_frame_number = setup_frame_number;
}



/* Look for conversation info and display any setup info found */
void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Conversation and current data */
	conversation_t *p_conv = NULL;
	struct _msrp_conversation_info *p_conv_data = NULL;

	/* Use existing packet data if available */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_msrp);

	if (!p_conv_data)
	{
		/* First time, get info from conversation */
		p_conv = find_conversation(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src,
		                           PT_TCP,
		                           pinfo->destport, pinfo->srcport, 0);//NO_ADDR_B | NO_PORT_B);

		if (p_conv)
		{
			/* Look for data in conversation */
			struct _msrp_conversation_info *p_conv_packet_data;
			p_conv_data = conversation_get_proto_data(p_conv, proto_msrp);

			if (p_conv_data)
			{
				/* Save this conversation info into packet info */
				p_conv_packet_data = se_alloc(sizeof(struct _msrp_conversation_info));
				if (!p_conv_packet_data)
				{
					return;
				}
				memcpy(p_conv_packet_data, p_conv_data,
				       sizeof(struct _msrp_conversation_info));

				p_add_proto_data(pinfo->fd, proto_msrp, p_conv_packet_data);
			}
		}                                                           
	}

	/* Create setup info subtree with summary info. */
	if (p_conv_data && p_conv_data->setup_method_set)
	{
		proto_tree *msrp_setup_tree;
		proto_item *ti =  proto_tree_add_string_format(tree, hf_msrp_setup, tvb, 0, 0,
		                                               "",
		                                               "Stream setup by %s (frame %u)",
		                                               p_conv_data->setup_method,
		                                               p_conv_data->setup_frame_number);
		PROTO_ITEM_SET_GENERATED(ti);
		msrp_setup_tree = proto_item_add_subtree(ti, ett_msrp_setup);
		if (msrp_setup_tree)
		{
			/* Add details into subtree */
			proto_item* item = proto_tree_add_uint(msrp_setup_tree, hf_msrp_setup_frame,
			                                       tvb, 0, 0, p_conv_data->setup_frame_number);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_string(msrp_setup_tree, hf_msrp_setup_method,
			                             tvb, 0, 0, p_conv_data->setup_method);
			PROTO_ITEM_SET_GENERATED(item);
		}
	}
}



/* Returns index of headers */
static gint msrp_is_known_msrp_header(tvbuff_t *tvb, int offset, guint header_len)
{
	guint i;

	for (i = 1; i < array_length(msrp_headers); i++) {
		if (header_len == strlen(msrp_headers[i].name) &&
		    tvb_strncaseeql(tvb, offset, msrp_headers[i].name, header_len) == 0)
		{
			return i;
		}
	}

	return -1;
}


/*
 * Display the entire message as raw text.
 */
static void
tvb_raw_text_add(tvbuff_t *tvb, proto_tree *tree)
{
	int offset, next_offset, linelen;
	offset = 0;

	while (tvb_offset_exists(tvb, offset)) {
		/* 'desegment' is FALSE so will set next_offset to beyond the end of
		   the buffer if no line ending is found */
		tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		linelen = next_offset - offset;
		if(tree) {
			proto_tree_add_text(tree, tvb, offset, linelen,
			                    "%s", tvb_format_text(tvb, offset, linelen));
		}
		offset = next_offset;
	}
}

/* This code is modeled on the code in packet-sip.c 
 *  ABNF code for the MSRP header:
 *  The following syntax specification uses the augmented Backus-Naur
 *  Form (BNF) as described in RFC-2234 [6].
 *
 *
 *  msrp-req-or-resp = msrp-request / msrp-response
 *  msrp-request = req-start headers [content-stuff] end-line
 *  msrp-response = resp-start headers end-line
 *
 *  req-start  = pMSRP SP transact-id SP method CRLF
 *  resp-start = pMSRP SP transact-id SP status-code [SP phrase] CRLF
 *  phrase = utf8text
 *
 *  pMSRP = %x4D.53.52.50 ; MSRP in caps
 *  transact-id = ident
 *  method = mSEND / mREPORT / other-method
 *  mSEND = %x53.45.4e.44 ; SEND in caps
 *  mREPORT = %x52.45.50.4f.52.54; REPORT in caps
 *  other-method = 1*UPALPHA
 *  Examples:
 *  "MSRP 1234 SEND(CRLF)"
 *	"MSRP 1234 200 OK(CRLF)
 */	
static gboolean
check_msrp_header(tvbuff_t *tvb)
{	
	gint offset = 0;
	gint linelen;
	gint space_offset;
	gint next_offset = 0;
	guint token_1_len;
	gint token_2_start;

	/*
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" calls below won't throw exceptions.	 *
	 */
	offset = 0;
	linelen = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);
	/* Find the first SP */
	space_offset = tvb_find_guint8(tvb, 0, -1, ' ');

	if (space_offset <= 0) {
		/*
		 * Either there's no space in the line (which means
		 * the line is empty or doesn't have a token followed
		 * by a space; neither is valid for a request or response), or
		 * the first character in the line is a space ( which isn't valid
		 * for a MSRP header.)
		 */
		return FALSE;
	}

	token_1_len = space_offset;
	token_2_start = space_offset + 1;
	space_offset = tvb_find_guint8(tvb, token_2_start, -1, ' ');
	if (space_offset == -1) {
		/*
		 * There's no space after the second token, so we don't
		 * have a third token.
		 */
		return FALSE;
	}
	/*
	 * Is the first token "MSRP"?
	 */
	if (token_1_len == MSRP_HDR_LEN && tvb_strneql(tvb, 0, MSRP_HDR, MSRP_HDR_LEN) == 0){
		/* This check can be made more strict but accept we do have MSRP for now */
		return TRUE;

	}
	return FALSE;
}

/* ABNF of line-end:
 * end-line = "-------" transact-id continuation-flag CRLF
 * This code is modeled on the code in packet-multipart.c
 */
static int
find_end_line(tvbuff_t *tvb, gint start)
{
	gint offset = start, next_offset, linelen;

	while (tvb_length_remaining(tvb, offset) > 0) {
		/* 'desegment' is FALSE so will set next_offset to beyond the end of
		   the buffer if no line ending is found */
		linelen =  tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		if (linelen == -1) {
			return -1;
		}
		if (tvb_strneql(tvb, next_offset, (const guint8 *)"-------", 7) == 0)
			return next_offset;
		offset = next_offset;
	}

	return -1;
}

static gboolean
dissect_msrp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	conversation_t* conversation;

	if ( check_msrp_header(tvb)){
		/*
		 * TODO Set up conversation here
		 */
		if (pinfo->fd->flags.visited){
			/* Look for existing conversation */
			conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
				pinfo->srcport, pinfo->destport, 0);
			/* Create new one if not found */
			if (conversation == NULL){
				conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
				/* Set dissector */
				conversation_set_dissector(conversation, msrp_handle);
			}
		}
		offset = dissect_msrp(tvb, pinfo, tree);
		return TRUE;
	}
	return FALSE;
}

/* Code to actually dissect the packets */
static int
dissect_msrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	gint next_offset = 0;
	proto_item *ti, *th, *msrp_headers_item, *msrp_element_item;
	proto_tree *msrp_tree, *reqresp_tree, *raw_tree, *msrp_hdr_tree, *msrp_end_tree;
	proto_tree *msrp_element_tree, *msrp_data_tree;
	gint linelen;
	gint space_offset;
	gint token_2_start;
	guint token_2_len;
	gint token_3_start;
	guint token_3_len;
	gint token_4_start = 0;
	guint token_4_len = 0;
	gboolean is_msrp_response;
	gint end_line_offset;
	gint end_line_len;
	gint line_end_offset;
	gint message_end_offset;
	gint colon_offset;
	char *transaction_id_str = NULL;
	gint header_len;
	gint hf_index;
	gint value_offset;
	guchar c;
	size_t value_len;
	char *value;
	gboolean have_body = FALSE;
	gboolean found_match = FALSE;
	gint content_type_len, content_type_parameter_str_len;
	char *media_type_str = NULL;
	char *media_type_str_lower_case = NULL;
	char *content_type_parameter_str = NULL;
	tvbuff_t *next_tvb;
	gint parameter_offset;
	gint semi_colon_offset;

	if ( !check_msrp_header(tvb)){
		return 0;
	}
	/* We have a MSRP header with at least three tokens 
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" calls below won't throw exceptions.	 *
	 */
	offset = 0;
	linelen = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);

	/* Find the first SP and skip the first token */
	token_2_start = tvb_find_guint8(tvb, 0, linelen, ' ') + 1;

	/* Work out 2nd token's length by finding next space */
	space_offset = tvb_find_guint8(tvb, token_2_start, linelen-token_2_start, ' ');
	token_2_len = space_offset - token_2_start;

	/* Transaction ID found store it for later use */
	transaction_id_str = tvb_get_ephemeral_string(tvb, token_2_start, token_2_len);

	/* Look for another space in this line to indicate a 4th token */
	token_3_start = space_offset + 1;
	space_offset = tvb_find_guint8(tvb, token_3_start,linelen-token_3_start, ' ');
	if ( space_offset == -1){
		/* 3rd token runs to the end of the line */
		token_3_len = linelen - token_3_start;
	}else{
		/* We have a fourth token */
		token_3_len = space_offset - token_3_start;
		token_4_start = space_offset + 1;
		token_4_len = linelen - token_4_start;
	}

	/*
	 * Yes, so this is either a msrp-request or msrp-response.
	 * To be a msrp-response, the second token must be
	 * a 3-digit number.
	 */
	is_msrp_response = FALSE;
	if (token_3_len == 3) {
			if (isdigit(tvb_get_guint8(tvb, token_3_start)) &&
			    isdigit(tvb_get_guint8(tvb, token_3_start + 1)) &&
			    isdigit(tvb_get_guint8(tvb, token_3_start + 2))) {
				is_msrp_response = TRUE;
			}
	}

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSRP");
	if (is_msrp_response){
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Response: %s ",
					tvb_format_text(tvb, token_3_start, token_3_len));

			if (token_4_len )
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					tvb_format_text(tvb, token_4_start, token_4_len));

			col_append_fstr(pinfo->cinfo, COL_INFO, "Transaction ID: %s",
					tvb_format_text(tvb, token_2_start, token_2_len));
		}
	}else{
		if (check_col(pinfo->cinfo, COL_INFO)) {
			proto_tree_add_text(tree, tvb, token_3_start, token_3_len,
					"Col %s L=%u", tvb_format_text(tvb, token_3_start, token_3_len),token_3_len);

			col_add_fstr(pinfo->cinfo, COL_INFO, "Request: %s ",
					tvb_format_text(tvb, token_3_start, token_3_len));

			col_append_fstr(pinfo->cinfo, COL_INFO, "Transaction ID: %s",
					tvb_format_text(tvb, token_2_start, token_2_len));
		}
	}

	/* Find the end line to be able to process the headers
	 * Note that in case of [content-stuff] headers and [content-stuff] is separated by CRLF
	 */

	offset = next_offset;
	end_line_offset = find_end_line(tvb,offset);
	/* TODO if -1 (No end line found, is returned do something) */
	end_line_len =  tvb_find_line_end(tvb, end_line_offset, -1, &next_offset, FALSE);
	message_end_offset = end_line_offset + end_line_len + 2;


	if (tree) {
		ti = proto_tree_add_item(tree, proto_msrp, tvb, 0, message_end_offset, FALSE);
		msrp_tree = proto_item_add_subtree(ti, ett_msrp);

		if (is_msrp_response){
			th = proto_tree_add_item(msrp_tree,hf_msrp_response_line,tvb,0,linelen,FALSE);
			reqresp_tree = proto_item_add_subtree(th, ett_msrp_reqresp);
			proto_tree_add_item(reqresp_tree,hf_msrp_transactionID,tvb,token_2_start,token_2_len,FALSE);
			proto_tree_add_uint(reqresp_tree,hf_msrp_status_code,tvb,token_3_start,token_3_len,
			                    atoi(tvb_get_string(tvb, token_3_start, token_3_len)));

		}else{
			th = proto_tree_add_item(msrp_tree,hf_msrp_request_line,tvb,0,linelen,FALSE);
			reqresp_tree = proto_item_add_subtree(th, ett_msrp_reqresp);
			proto_tree_add_item(reqresp_tree,hf_msrp_transactionID,tvb,token_2_start,token_2_len,FALSE);
			proto_tree_add_item(reqresp_tree,hf_msrp_method,tvb,token_3_start,token_3_len,FALSE);
		}

		/* Conversation setup info */
		if (global_msrp_show_setup_info)
		{
			show_setup_info(tvb, pinfo, msrp_tree);
		}

		/* Headers */
		msrp_headers_item = proto_tree_add_item(msrp_tree, hf_msrp_msg_hdr, tvb, offset,(end_line_offset - offset), FALSE);
		msrp_hdr_tree = proto_item_add_subtree(msrp_headers_item, ett_msrp_hdr);

		/* 
		 * Process the headers
		 */
		while (tvb_reported_length_remaining(tvb, offset) > 0 && offset < end_line_offset  ) {
			/* 'desegment' is FALSE so will set next_offset to beyond the end of
			   the buffer if no line ending is found */
			linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
			if (linelen == 0) {
				/*
				 * This is a blank line separating the
				 * message header from the message body.
				 */
				have_body = TRUE;
				break;
			}
			line_end_offset = offset + linelen;
			colon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
			if (colon_offset == -1) {
				/*
				 * Malformed header - no colon after the name.
				 */
				proto_tree_add_text(msrp_hdr_tree, tvb, offset,
					                next_offset - offset, "%s",
						            tvb_format_text(tvb, offset, linelen));
			} else {
				header_len = colon_offset - offset;
				hf_index = msrp_is_known_msrp_header(tvb, offset, header_len);

				if (hf_index == -1) {
					proto_tree_add_text(msrp_hdr_tree, tvb,
				                    offset, next_offset - offset, "%s",
				                    tvb_format_text(tvb, offset, linelen));
				} else {
					/*
					 * Skip whitespace after the colon.
					 */
					value_offset = colon_offset + 1;
					while (value_offset < line_end_offset &&
					       ((c = tvb_get_guint8(tvb, value_offset)) == ' ' ||
					         c == '\t'))
						value_offset++;
					/*
					 * Fetch the value.
					 */
					value_len = line_end_offset - value_offset;
					value = tvb_get_ephemeral_string(tvb, value_offset,
				                       value_len);

					/*
					 * Add it to the protocol tree,
					 * but display the line as is.
					 */
					msrp_element_item = proto_tree_add_string_format(msrp_hdr_tree,
				                   hf_header_array[hf_index], tvb,
				                   offset, next_offset - offset,
				                   value, "%s",
				                   tvb_format_text(tvb, offset, linelen));
					msrp_element_tree = proto_item_add_subtree( msrp_element_item, ett_msrp_element);

					switch ( hf_index ) {

						case MSRP_CONTENT_TYPE :
							content_type_len = value_len;
							semi_colon_offset = tvb_find_guint8(tvb, value_offset,linelen, ';');
							if ( semi_colon_offset != -1) {
								parameter_offset = semi_colon_offset +1;
								/*
								 * Skip whitespace after the semicolon.
								 */
								while (parameter_offset < line_end_offset
								       && ((c = tvb_get_guint8(tvb, parameter_offset)) == ' '
								         || c == '\t'))
									parameter_offset++;
								content_type_len = semi_colon_offset - value_offset;
								content_type_parameter_str_len = line_end_offset - parameter_offset;
								content_type_parameter_str = tvb_get_ephemeral_string(tvb, parameter_offset,
							                             content_type_parameter_str_len);
							}
							media_type_str = tvb_get_ephemeral_string(tvb, value_offset, content_type_len);
#if GLIB_MAJOR_VERSION < 2
							media_type_str_lower_case = g_strdup(media_type_str);
							g_strdown(media_type_str_lower_case);
#else
							media_type_str_lower_case = g_ascii_strdown(media_type_str, -1);
#endif
							break;

						default:
							break;
					}
				}
			}
			offset = next_offset;
		}/* End while */

		if ( have_body ){
			/*
			 * There's a message body starting at "next_offset".
			 * Set the length of the header item.
			 */
			proto_item_set_end(msrp_headers_item, tvb, next_offset);
			next_tvb = tvb_new_subset(tvb, next_offset, -1, -1);
			ti = proto_tree_add_text(msrp_tree, next_tvb, 0, -1,
		                         "Data");
			msrp_data_tree = proto_item_add_subtree(ti, ett_msrp_data);

			/* give the content type parameters to sub dissectors */

			if ( media_type_str_lower_case != NULL ) {
				void *save_private_data = pinfo->private_data;
				pinfo->private_data = content_type_parameter_str;
				found_match = dissector_try_string(media_type_dissector_table,
			                                   media_type_str_lower_case,
			                                   next_tvb, pinfo,
			                                   msrp_data_tree);
				g_free(media_type_str_lower_case);
				pinfo->private_data = save_private_data;
				/* If no match dump as text */
			}
			if ( found_match != TRUE )
			{
				offset = 0;
				while (tvb_offset_exists(next_tvb, offset)) {
					tvb_find_line_end(next_tvb, offset, -1, &next_offset, FALSE);
					linelen = next_offset - offset;
					proto_tree_add_text(msrp_data_tree, next_tvb, offset, linelen,
				                    "%s", tvb_format_text(next_tvb, offset, linelen));
					offset = next_offset;
				}/* end while */
			}

		}



		/* End line */
		ti = proto_tree_add_item(msrp_tree,hf_msrp_end_line,tvb,end_line_offset,end_line_len,FALSE);
		msrp_end_tree = proto_item_add_subtree(ti, ett_msrp_end_line);

		proto_tree_add_item(msrp_end_tree,hf_msrp_transactionID,tvb,end_line_offset + 7,token_2_len,FALSE);
		/* continuation-flag */ 
		proto_tree_add_item(msrp_end_tree,hf_msrp_cnt_flg,tvb,end_line_offset+end_line_len-1,1,FALSE);
			
		if (global_msrp_raw_text){
			ti = proto_tree_add_text(tree, tvb, 0, -1,"Message Session Relay Protocol(as raw text)");
			raw_tree = proto_item_add_subtree(ti, ett_msrp);
			tvb_raw_text_add(tvb,raw_tree);
		}

	}/* if tree */
	return message_end_offset;
	/*	return tvb_length(tvb); */

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_msrp(void)
{
	msrp_handle = new_create_dissector_handle(dissect_msrp, proto_msrp);
	dissector_add("tcp.port", 0, msrp_handle);
	heur_dissector_add("tcp", dissect_msrp_heur, proto_msrp);
}

void
proto_register_msrp(void)
{
/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_msrp,
		&ett_raw_text,
		&ett_msrp_reqresp,
		&ett_msrp_hdr,
		&ett_msrp_element,
		&ett_msrp_data,
		&ett_msrp_end_line,
		&ett_msrp_setup
	};

        /* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_msrp_request_line,
			{ "Request Line", 		"msrp.request.line",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Request Line", HFILL }
		},
		{ &hf_msrp_response_line,
			{ "Response Line", 		"msrp.response.line",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Response Line", HFILL }
		},
		{ &hf_msrp_transactionID,
			{ "Transaction Id", 		"msrp.transaction.id",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Transaction Id", HFILL }
		},
		{ &hf_msrp_method,
			{ "Method", 				"msrp.method",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Method", HFILL }
		},
		{ &hf_msrp_status_code,
			{ "Status code", 		"msrp.status.code",
			FT_UINT16, BASE_DEC,NULL,0x0,
			"Status code", HFILL }
		},
		{ &hf_msrp_msg_hdr,
			{ "Message Header", 		"msrp.msg.hdr",
			FT_NONE, 0,NULL,0x0,
			"Message Header", HFILL }
		},
		{ &hf_msrp_end_line,
			{ "End Line", 		"msrp.end.line",
			FT_STRING, BASE_NONE,NULL,0x0,
			"End Line", HFILL }
		},
		{ &hf_msrp_cnt_flg,
			{ "Continuation-flag", 		"msrp.cnt.flg",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Continuation-flag", HFILL }
		},
		{ &hf_header_array[MSRP_FROM_PATH],
			{ "From Path", 		"msrp.from.path",
			FT_STRING, BASE_NONE,NULL,0x0,
			"From Path", HFILL }
		},
		{ &hf_header_array[MSRP_TO_PATH],
			{ "To Path", 		"msrp.to.path",
			FT_STRING, BASE_NONE,NULL,0x0,
			"To Path", HFILL }
		},
		{ &hf_header_array[MSRP_MESSAGE_ID],
			{ "Message ID", 		"msrp.messageid",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Message ID", HFILL }
		},
		{ &hf_header_array[MSRP_SUCCESS_REPORT],
			{ "Success Report", 		"msrp.success.report",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Success Report", HFILL }
		},
		{ &hf_header_array[MSRP_FAILURE_REPORT],
			{ "Failure Report", 		"msrp.failure.report",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Failure Report", HFILL }
		},
		{ &hf_header_array[MSRP_BYTE_RANGE],
			{ "Byte Range", 		"msrp.byte.range",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Byte Range", HFILL }
		},
		{ &hf_header_array[MSRP_STATUS],
			{ "Status", 		"msrp.status",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Status", HFILL }
		},
		{ &hf_header_array[MSRP_CONTENT_TYPE],
			{ "Content-Type", 		"msrp.content.type",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Content-Type", HFILL }
		},
		{ &hf_header_array[MSRP_CONTENT_ID],
			{ "Content-ID", 		"msrp.content.id",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Content-ID", HFILL }
		},
		{ &hf_header_array[MSRP_CONTENT_DISCRIPTION],
			{ "Content-Description", 		"msrp.content.description",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Content-Description", HFILL }
		},
		{ &hf_header_array[MSRP_CONTENT_DISPOSITION],
			{ "Content-Disposition", 		"msrp.content.disposition",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Content-Disposition", HFILL }
		},
		{ &hf_header_array[MSRP_USE_PATH],
			{ "Use-Path", 		"msrp.use.path",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Use-Path", HFILL }
		},
		{ &hf_header_array[MSRP_WWW_AUTHENTICATE],
			{ "WWW-Authenticate", 		"msrp.www.authenticate",
			FT_STRING, BASE_NONE,NULL,0x0,
			"WWW-Authenticate", HFILL }
		},
		{ &hf_header_array[MSRP_AUTHORIZATION],
			{ "Authorization", 		"msrp.authorization",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Authorization", HFILL }
		},
		{ &hf_header_array[MSRP_AUTHENTICATION_INFO],
			{ "Authentication-Info", 		"msrp.authentication.info",
			FT_STRING, BASE_NONE,NULL,0x0,
			"Authentication-Info", HFILL }
		},
		{ &hf_msrp_setup,
			{ "Stream setup", "msrp.setup",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Stream setup, method and frame number", HFILL}
		},
		{ &hf_msrp_setup_frame,
			{ "Setup frame", "msrp.setup-frame",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"Frame that set up this stream", HFILL}
		},
		{ &hf_msrp_setup_method,
			{ "Setup Method", "msrp.setup-method",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Method used to set up this stream", HFILL}
		},
	};

	module_t *msrp_module;
	/* Register the protocol name and description */
	proto_msrp = proto_register_protocol("Message Session Relay Protocol","MSRP", "msrp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_msrp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	media_type_dissector_table = find_dissector_table("media_type");

	msrp_module = prefs_register_protocol(proto_msrp, NULL);

	prefs_register_bool_preference(msrp_module, "display_raw_text",
		"Display raw text for MSRP message",
		"Specifies that the raw text of the "
		"MSRP message should be displayed "
		"in addition to the dissection tree",
		&global_msrp_raw_text);

	prefs_register_bool_preference(msrp_module, "show_setup_info",
		"Show stream setup information",
		"Where available, show which protocol and frame caused "
		"this MSRP stream to be created",
		&global_msrp_show_setup_info);


	/*
	 * Register the dissector by name, so other dissectors can
	 * grab it by name rather than just referring to it directly.
	 */
	new_register_dissector("msrp", dissect_msrp, proto_msrp);
}


