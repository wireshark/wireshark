/* packet-wsp.c (c) 2000 Neil Hunter
 * Based on original work by Ben Fowler
 *
 * Routines to dissect WSP component of WAP traffic.
 * 
 * $Id: packet-wsp.c,v 1.13 2001/01/28 04:21:59 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-wap.h"
#include "packet-wsp.h"

/* File scoped variables for the protocol and registered fields */
static int proto_wsp 							= HF_EMPTY;

/* These fields used by fixed part of header */
static int hf_wsp_header_tid					= HF_EMPTY;
static int hf_wsp_header_pdu_type				= HF_EMPTY;
static int hf_wsp_version_major					= HF_EMPTY;
static int hf_wsp_version_minor					= HF_EMPTY;
static int hf_wsp_capability_length				= HF_EMPTY;
static int hf_wsp_capabilities_section			= HF_EMPTY;
static int hf_wsp_header_uri_len				= HF_EMPTY;
static int hf_wsp_header_uri					= HF_EMPTY;
static int hf_wsp_server_session_id				= HF_EMPTY;
static int hf_wsp_header_status					= HF_EMPTY;
static int hf_wsp_header_length					= HF_EMPTY;
static int hf_wsp_headers_section				= HF_EMPTY;
static int hf_wsp_header						= HF_EMPTY;
static int hf_wsp_content_type					= HF_EMPTY;
static int hf_wsp_parameter_well_known_charset	= HF_EMPTY;
static int hf_wsp_reply_data					= HF_EMPTY;
static int hf_wsp_post_data						= HF_EMPTY;

static int hf_wsp_header_accept					= HF_EMPTY;
static int hf_wsp_header_accept_str				= HF_EMPTY;
static int hf_wsp_header_accept_charset			= HF_EMPTY;
static int hf_wsp_header_accept_language		= HF_EMPTY;
static int hf_wsp_header_accept_ranges			= HF_EMPTY;
static int hf_wsp_header_cache_control			= HF_EMPTY;
static int hf_wsp_header_content_length			= HF_EMPTY;
static int hf_wsp_header_age					= HF_EMPTY;
static int hf_wsp_header_date					= HF_EMPTY;
static int hf_wsp_header_etag					= HF_EMPTY;
static int hf_wsp_header_expires				= HF_EMPTY;
static int hf_wsp_header_last_modified			= HF_EMPTY;
static int hf_wsp_header_location				= HF_EMPTY;
static int hf_wsp_header_if_modified_since		= HF_EMPTY;
static int hf_wsp_header_server					= HF_EMPTY;
static int hf_wsp_header_user_agent				= HF_EMPTY;
static int hf_wsp_header_application_header		= HF_EMPTY;
static int hf_wsp_header_application_value		= HF_EMPTY;
static int hf_wsp_header_x_wap_tod				= HF_EMPTY;

/* Initialize the subtree pointers */
static gint ett_wsp 							= ETT_EMPTY;
static gint ett_header 							= ETT_EMPTY;
static gint ett_headers							= ETT_EMPTY;
static gint ett_capabilities					= ETT_EMPTY;
static gint ett_content_type					= ETT_EMPTY;

static const value_string vals_pdu_type[] = {
	{ 0x00, "Reserved" },
	{ 0x01, "Connect" },
	{ 0x02, "ConnectReply" },
	{ 0x03, "Redirect" },
	{ 0x04, "Reply" },
	{ 0x05, "Disconnect" },
	{ 0x06, "Push" },
	{ 0x07, "ConfirmedPush" },
	{ 0x08, "Suspend" },
	{ 0x09, "Resume" },

	/* 0x10 - 0x3F Unassigned */

	{ 0x40, "Get" },
	{ 0x41, "Options" },
	{ 0x42, "Head" },
	{ 0x43, "Delete" },
	{ 0x44, "Trace" },

	/* 0x45 - 0x4F Unassigned (Get PDU) */
	/* 0x50 - 0x5F Extended method (Get PDU) */

	{ 0x60, "Post" },
	{ 0x61, "Put" },

	/* 0x62 - 0x6F Unassigned (Post PDU) */
	/* 0x70 - 0x7F Extended method (Post PDU) */
	/* 0x80 - 0xFF Reserved */

	{ 0x00, NULL }

};

static const value_string vals_status[] = {
	/* 0x00 - 0x0F Reserved */

	{ 0x10, "Continue" },
	{ 0x11, "Switching Protocols" },

	{ 0x20, "OK" },
	{ 0x21, "Created" },
	{ 0x22, "Accepted" },
	{ 0x23, "Non-Authoritative Information" },
	{ 0x24, "No Content" },
	{ 0x25, "Reset Content" },
	{ 0x26, "Partial Content" },

	{ 0x30, "Multiple Choices" },
	{ 0x31, "Moved Permanently" },
	{ 0x32, "Moved Temporarily" },
	{ 0x33, "See Other" },
	{ 0x34, "Not Modified" },
	{ 0x35, "Use Proxy" },

	{ 0x40, "Bad Request" },
	{ 0x41, "Unauthorised" },
	{ 0x42, "Payment Required" },
	{ 0x43, "Forbidden" },
	{ 0x44, "Not Found" },
	{ 0x45, "Method Not Allowed" },
	{ 0x46, "Not Acceptable" },
	{ 0x47, "Proxy Authentication Required" },
	{ 0x48, "Request Timeout" },
	{ 0x49, "Conflict" },
	{ 0x4A, "Gone" },
	{ 0x4B, "Length Required" },
	{ 0x4C, "Precondition Failed" },
	{ 0x4D, "Request Entity Too Large" },
	{ 0x4E, "Request-URI Too Large" },
	{ 0x4F, "Unsupported Media Type" },

	{ 0x60, "Internal Server Error" },
	{ 0x61, "Not Implemented" },
	{ 0x62, "Bad Gateway" },
	{ 0x63, "Service Unavailable" },
	{ 0x64, "Gateway Timeout" },
	{ 0x65, "HTTP Version Not Supported" },
	{ 0x00, NULL }
};

static const value_string vals_content_types[] = {
	{ 0x00, "*/*" },
	{ 0x01, "text/*" },
	{ 0x02, "text/html" },
	{ 0x03, "text/plain" },
	{ 0x04, "text/x-hdml" },
	{ 0x05, "text/x-ttml" },
	{ 0x06, "text/x-vCalendar" },
	{ 0x07, "text/x-vCard" },
	{ 0x08, "text/vnd.wap.wml" },
	{ 0x09, "text/vnd.wap.wmlscript" },
	{ 0x0A, "text/vnd.wap.channel" },
	{ 0x0B, "Multipart/*" },
	{ 0x0C, "Multipart/mixed" },
	{ 0x0D, "Multipart/form-data" },
	{ 0x0E, "Multipart/byteranges" },
	{ 0x0F, "Multipart/alternative" },
	{ 0x10, "application/*" },
	{ 0x11, "application/java-vm" },
	{ 0x12, "application/x-www-form-urlencoded" },
	{ 0x13, "application/x-hdmlc" },
	{ 0x14, "application/vnd.wap.wmlc" },
	{ 0x15, "application/vnd.wap.wmlscriptc" },
	{ 0x16, "application/vnd.wap.channelc" },
	{ 0x17, "application/vnd.wap.uaprof" },
	{ 0x18, "application/vnd.wap.wtls-ca-certificate" },
	{ 0x19, "application/vnd.wap.wtls-user-certificate" },
	{ 0x1A, "application/x-x509-ca-cert" },
	{ 0x1B, "application/x-x509-user-cert" },
	{ 0x1C, "image/*" },
	{ 0x1D, "image/gif" },
	{ 0x1E, "image/jpeg" },
	{ 0x1F, "image/tiff" },
	{ 0x20, "image/png" },
	{ 0x21, "image/vnd.wap.wbmp" },
	{ 0x22, "application/vnd.wap.multipart.*" },
	{ 0x23, "application/vnd.wap.multipart.mixed" },
	{ 0x24, "application/vnd.wap.multipart.form-data" },
	{ 0x25, "application/vnd.wap.multipart.byteranges" },
	{ 0x26, "application/vnd.wap.multipart.alternative" },
	{ 0x27, "application/xml" },
	{ 0x28, "text/xml" },
	{ 0x29, "application/vnd.wap.wbxml" },
	{ 0x2A, "application/x-x968-cross-cert" },
	{ 0x2B, "application/x-x968-ca-cert" },
	{ 0x2C, "application/x-x968-user-cert" },
	{ 0x2D, "text/vnd.wap.si" },
	{ 0x2E, "application/vnd.wap.sic" },
	{ 0x2F, "text/vnd.wap.sl" },
	{ 0x30, "application/vnd.wap.slc" },
	{ 0x31, "text/vnd.wap.co" },
	{ 0x32, "application/vnd.wap.coc" },
	{ 0x33, "application/vnd.wap.multipart.related" },
	{ 0x34, "application/vnd.wap.sia" },
	{ 0x00, NULL }
};

static const value_string vals_character_sets[] = {
	{ 0x0003, "us-ascii" },
	{ 0x0004, "iso-8859-1" },
	{ 0x0005, "iso-8859-2" },
	{ 0x0006, "iso-8859-3" },
	{ 0x0007, "iso-8859-4" },
	{ 0x0008, "iso-8859-5" },
	{ 0x0009, "iso-8859-6" },
	{ 0x000A, "iso-8859-7" },
	{ 0x000B, "iso-8859-8" },
	{ 0x000C, "iso-8859-9" },
	{ 0x0011, "shift_JIS" },
	{ 0x006A, "utf-8" },
	{ 0x03E8, "iso-10646-ucs-2" },
	{ 0x07EA, "big5" },
	{ 0x00, NULL }
};

static const value_string vals_languages[] = {
	{ 0x19, "English (en)" },
	{ 0x00, NULL }
};

static const value_string vals_accept_ranges[] = {
	{ 0x80, "None" },
	{ 0x81, "Bytes" },
	{ 0x00, NULL }
};

static const value_string vals_cache_control[] = {
	{ 0x80, "No-cache" },
	{ 0x81, "No-store" },
	{ 0x82, "Max-age" },
	{ 0x83, "Max-stale" },
	{ 0x84, "Min-fresh" },
	{ 0x85, "Only-if-cached" },
	{ 0x86, "Public" },
	{ 0x87, "Private" },
	{ 0x88, "No-transform" },
	{ 0x89, "Must-revalidate" },
	{ 0x8A, "Proxy-revalidate" },
	{ 0x00, NULL }
};

/*
 * Windows appears to define DELETE.
 */
#ifdef DELETE
#undef DELETE
#endif

enum {
	RESERVED		= 0x00,
	CONNECT			= 0x01,
	CONNECTREPLY	= 0x02,
	REDIRECT		= 0x03,			/* No sample data */
	REPLY			= 0x04,
	DISCONNECT		= 0x05,
	PUSH			= 0x06,			/* No sample data */
	CONFIRMEDPUSH	= 0x07,			/* No sample data */
	SUSPEND			= 0x08,			/* No sample data */
	RESUME			= 0x09,			/* No sample data */

	GET				= 0x40,
	OPTIONS			= 0x41,			/* No sample data */
	HEAD			= 0x42,			/* No sample data */
	DELETE			= 0x43,			/* No sample data */
	TRACE			= 0x44,			/* No sample data */

	POST			= 0x60,
	PUT				= 0x61,			/* No sample data */
};

static void add_uri (proto_tree *, tvbuff_t *, guint, guint);
static void add_headers (proto_tree *, tvbuff_t *);
static void add_header (proto_tree *, tvbuff_t *, tvbuff_t *);
static guint get_value_length (tvbuff_t *, guint, guint *);
static guint add_content_type (proto_tree *, tvbuff_t *, guint, guint *);
static guint add_parameter (proto_tree *, tvbuff_t *, guint);
static guint add_parameter_charset (proto_tree *, tvbuff_t *, guint, guint);
static void add_post_data (proto_tree *, tvbuff_t *, guint);
static void add_post_variable (proto_tree *, tvbuff_t *, guint, guint, guint, guint);

/* 
 * Accessor to retrieve variable length int as used in WAP protocol.
 * The value is encoded in the lower 7 bits. If the top bit is set, then the
 * value continues into the next byte.
 * The octetCount parameter holds the number of bytes read in order to return
 * the final value. Can be pre-initialised to start at offset+count.
*/
static guint
tvb_get_guintvar (tvbuff_t *tvb, guint offset, guint *octetCount)
{
	guint value = 0;
	guint octet;
	guint counter = 0;
	char cont = 1;
	
	if (octetCount != NULL)
	{
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Starting tvb_get_guintvar at offset %d, count=NULL\n", offset);
#endif
	}
	else
	{
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Starting tvb_get_guintvar at offset %d, count=%d\n", offset, *octetCount);
#endif
		counter = *octetCount;
	}

	while (cont != 0)
	{
		value<<=7;	/* Value only exists in 7 of the 8 bits */
		octet = tvb_get_guint8 (tvb, offset+counter);
		counter++;
		value += (octet & 0x7F);
		cont = (octet & 0x80);
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: octet is %d (0x%02x), count=%d, value=%d, cont=%d\n", octet, octet, counter, value, cont);
#endif
	}

	if (octetCount != NULL)
	{
		*octetCount = counter;
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Leaving tvb_get_guintvar count=%d\n", *octetCount);
#endif
	}

	return (value);
}

/* Code to actually dissect the packets */
static void
dissect_wsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	frame_data *fdata = pinfo->fd;
	int offset = 0;

	guint8 pdut;
	guint count = 0;
	guint value = 0;
	guint uriLength = 0;
	guint uriStart = 0;
	guint capabilityLength = 0;
	guint capabilityStart = 0;
	guint headersLength = 0;
	guint headerLength = 0;
	guint headerStart = 0;
	guint nextOffset = 0;
	guint contentTypeStart = 0;
	guint contentType = 0;
	tvbuff_t *tmp_tvb;

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wsp_tree;
/*	proto_tree *wsp_header_fixed; */
	proto_tree *wsp_capabilities;
	
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. */
    
	/* Display protocol type depending on the port */
	if (check_col(fdata, COL_PROTOCOL)) 
	{
		switch ( pinfo->match_port )
		{
			case UDP_PORT_WSP:
				col_set_str(fdata, COL_PROTOCOL, "WSP" );
				break;
			case UDP_PORT_WTLS_WSP:
				col_set_str(fdata, COL_PROTOCOL, "WTLS+WSP" );
				break;
		}
	}
	if (check_col(fdata, COL_INFO)) {
		col_clear(fdata, COL_INFO);
	};

	/* Connection-less mode has a TID first */
	if ((pinfo->match_port == UDP_PORT_WSP) || (pinfo->match_port == UDP_PORT_WTLS_WSP))
	{
		offset++;
	};

	/* Find the PDU type */
	pdut = tvb_get_guint8 (tvb, offset);

	/* Develop the string to put in the Info column */
	if (check_col(fdata, COL_INFO)) {
		col_add_fstr(fdata, COL_INFO, "WSP %s",
			val_to_str (pdut, vals_pdu_type, "Unknown PDU type (0x%02x)"));
	};

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_wsp, tvb, 0,
		    tvb_length(tvb), bo_little_endian);
	        wsp_tree = proto_item_add_subtree(ti, ett_wsp);

/* Code to process the packet goes here */
/*
			wsp_header_fixed = proto_item_add_subtree(
					ti, 
					ett_header 
				);
*/

			/* Add common items: only TID and PDU Type */

			/* TID Field is always first (if it exists) */
			if ((pinfo->match_port == UDP_PORT_WSP) || (pinfo->match_port == UDP_PORT_WTLS_WSP))
			{
				ti = proto_tree_add_item (wsp_tree, hf_wsp_header_tid,tvb,0,1,bo_little_endian);
			}

			ti = proto_tree_add_item(
					wsp_tree, 		/* tree */
					hf_wsp_header_pdu_type, 	/* id */
					tvb, 
					offset++, 			/* start of high light */
					1,				/* length of high light */
					bo_little_endian				/* value */
			     );

			switch (pdut)
			{
				case CONNECT:
					ti = proto_tree_add_item (wsp_tree, hf_wsp_version_major,tvb,offset,1,bo_little_endian);
					ti = proto_tree_add_item (wsp_tree, hf_wsp_version_minor,tvb,offset,1,bo_little_endian);
					offset++;
					capabilityStart = offset;
					capabilityLength = tvb_get_guintvar (tvb, offset, &count);
					offset += count;
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_capability_length,tvb,capabilityStart,count,capabilityLength);

					headerStart = offset;
					headerLength = tvb_get_guintvar (tvb, offset, &count);
					offset += count;
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,headerLength);
					if (capabilityLength > 0)
					{
						ti = proto_tree_add_item (wsp_tree, hf_wsp_capabilities_section,tvb,offset,capabilityLength,bo_little_endian);
						wsp_capabilities = proto_item_add_subtree( ti, ett_capabilities );
						offset += capabilityLength;
					}

					if (headerLength > 0)
					{
						tmp_tvb = tvb_new_subset (tvb, offset, headerLength, headerLength);
						add_headers (wsp_tree, tmp_tvb);
					}

					break;

				case CONNECTREPLY:
					value = tvb_get_guintvar (tvb, offset, &count);
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
					offset += count;

					capabilityStart = offset;
					capabilityLength = tvb_get_guintvar (tvb, offset, &count);
					offset += count;
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_capability_length,tvb,capabilityStart,count,capabilityLength);

					headerStart = offset;
					headerLength = tvb_get_guintvar (tvb, offset, &count);
					offset += count;
					ti = proto_tree_add_item (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,bo_little_endian);
					if (capabilityLength > 0)
					{
						ti = proto_tree_add_item (wsp_tree, hf_wsp_capabilities_section,tvb,offset,capabilityLength,bo_little_endian);
						wsp_capabilities = proto_item_add_subtree( ti, ett_capabilities );
						offset += capabilityLength;
					}

					if (headerLength > 0)
					{

						/*
						ti = proto_tree_add_item (wsp_tree, hf_wsp_headers_section,tvb,offset,headerLength,bo_little_endian);
						wsp_headers = proto_item_add_subtree( ti, ett_headers );
						*/
						tmp_tvb = tvb_new_subset (tvb, offset, headerLength, headerLength);
						add_headers (wsp_tree, tmp_tvb);
					}

					break;

				case DISCONNECT:
					value = tvb_get_guintvar (tvb, offset, &count);
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
					break;

				case GET:
					/* Length of URI and size of URILen field */
					value = tvb_get_guintvar (tvb, offset, &count);
					nextOffset = offset + count;
					add_uri (wsp_tree, tvb, offset, nextOffset);
					offset += (value+1);
					tmp_tvb = tvb_new_subset (tvb, offset, -1, -1);
					add_headers (wsp_tree, tmp_tvb);
					break;

				case POST:
					uriStart = offset;
					uriLength = tvb_get_guintvar (tvb, offset, &count);
					headerStart = uriStart+count;
					headersLength = tvb_get_guintvar (tvb, headerStart, &count);
					offset = headerStart + count;

					add_uri (wsp_tree, tvb, uriStart, offset);
					offset += uriLength;

					ti = proto_tree_add_item (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,bo_little_endian);

					contentTypeStart = offset;
					nextOffset = add_content_type (wsp_tree, tvb, offset, &contentType);

					/* Add headers subtree that will hold the headers fields */
					/* Runs from nextOffset for value-(length of content-type field)*/
					headerLength = headersLength-(nextOffset-contentTypeStart);
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);

					/* TODO: Post DATA */
					/* Runs from start of headers+headerLength to END_OF_FRAME */
					offset = nextOffset+headerLength;
					tmp_tvb = tvb_new_subset (tvb, offset, tvb_reported_length (tvb)-offset, tvb_reported_length (tvb)-offset);
					add_post_data (wsp_tree, tmp_tvb, contentType);
					break;

				case REPLY:
					ti = proto_tree_add_item (wsp_tree, hf_wsp_header_status,tvb,offset,1,bo_little_endian);
					value = tvb_get_guintvar (tvb, offset+1, &count);
					nextOffset = offset + 1 + count;
					ti = proto_tree_add_item (wsp_tree, hf_wsp_header_length,tvb,offset+1,count,bo_little_endian);

					contentTypeStart = nextOffset;
					nextOffset = add_content_type (wsp_tree, tvb, nextOffset, &contentType);

					/* Add headers subtree that will hold the headers fields */
					/* Runs from nextOffset for value-(length of content-type field)*/
					headerLength = value-(nextOffset-contentTypeStart);
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
					offset += count+value+1;

					/* TODO: Data - decode WMLC */
					/* Runs from offset+1+count+value+1 to END_OF_FRAME */
					if (offset < tvb_reported_length (tvb))
					{
						ti = proto_tree_add_item (wsp_tree, hf_wsp_reply_data,tvb,offset,END_OF_FRAME,bo_little_endian);
					}
					break;
			}
	}
}

static void
add_uri (proto_tree *tree, tvbuff_t *tvb, guint URILenOffset, guint URIOffset)
{
	proto_item *ti;
	guint8 terminator = 0;
	char *newBuffer;

	guint count = 0;
	guint uriLen = tvb_get_guintvar (tvb, URILenOffset, &count);

	ti = proto_tree_add_uint (tree, hf_wsp_header_uri_len,tvb,URILenOffset,count,uriLen);

	/* If string doesn't end with a 0x00, we need to add one to be on the safe side */
	terminator = tvb_get_guint8 (tvb, URIOffset+uriLen-1);
	if (terminator != 0)
	{
		newBuffer = g_malloc (uriLen+1);
		strncpy (newBuffer, tvb_get_ptr (tvb, URIOffset, uriLen), uriLen);
		newBuffer[uriLen] = 0;
		ti = proto_tree_add_string (tree, hf_wsp_header_uri,tvb,URIOffset,uriLen,newBuffer);
		g_free (newBuffer);
	}
	else
	{
		ti = proto_tree_add_item (tree, hf_wsp_header_uri,tvb,URIOffset,uriLen,bo_little_endian);
	}
}

static void
add_headers (proto_tree *tree, tvbuff_t *tvb)
{
	proto_item *ti;
	proto_tree *wsp_headers;
	guint offset = 0;
	guint headersLen = tvb_reported_length (tvb);
	guint8 headerStart = 0;
	guint peek = 0;
	tvbuff_t *header_buff;
	tvbuff_t *value_buff;
	guint count = 0;
	guint valueStart = 0;
	guint valueEnd = 0;

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Offset is %d, size is %d\n", offset, headersLen);
#endif

	/* End of buffer */
	if (headersLen <= 0)
	{
		return;
	}

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Headers to process\n");
#endif

	ti = proto_tree_add_item (tree, hf_wsp_headers_section,tvb,offset,headersLen,bo_little_endian);
	wsp_headers = proto_item_add_subtree( ti, ett_headers );

	/* Parse Headers */

	while (offset < headersLen)
	{
		/* Loop round each header */
		headerStart = offset;
		peek = tvb_get_guint8 (tvb, headerStart);

		if (peek < 32)		/* Short-cut shift delimeter */
		{
			fprintf (stderr, "dissect_wsp: header: short-cut shift %d (0x%02X)\n", peek, peek);
			offset++;
		}
		else if (peek == 0x7F)	/* Shift delimeter */
		{
			fprintf (stderr, "dissect_wsp: header: shift delimeter %d (0x%02X)\n", peek, peek);
			offset++;
		}
		else if (peek < 127)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: header: application-header start %d (0x%02X)\n", peek, peek);
#endif
			while (tvb_get_guint8 (tvb, offset++)) { /* Do nothing, just look for NULL */ }
		}
		else if (peek & 0x80)	/* Well-known header */
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: header: well-known %d (0x%02X)\n", peek, peek);
#endif
			offset++;
		}

		/* Get value part of header */
		valueStart = offset;
		peek = tvb_get_guint8 (tvb, valueStart);
		if (peek <= 30)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Looking for %d octets\n", peek);
#endif
			valueStart++;
			valueEnd = offset+1+peek;
			offset += (peek+1);
		}
		else if (peek == 31)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Looking for uintvar octets\n");
#endif
			tvb_get_guintvar (tvb, valueStart, &count);
			valueEnd = offset+1+count;
			offset += (count+1);
		}
		else if (peek <= 127)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Looking for NULL-terminated string\n");
#endif
			valueEnd = valueStart+1;
			while (tvb_get_guint8 (tvb, valueEnd++)) { /* Do nothing, just look for NULL */ }
			offset = valueEnd;
		}
		else
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Value is %d\n", (peek & 0x7F));
#endif
			valueEnd = offset+1;
			offset++;
		}
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Creating value buffer from offset %d, size=%d\n", headerStart, (offset-headerStart));
#endif

		header_buff = tvb_new_subset (tvb, headerStart, (offset-headerStart), (offset-headerStart));
		value_buff = tvb_new_subset (tvb, valueStart, (valueEnd-valueStart), (valueEnd-valueStart));

		add_header (wsp_headers, header_buff, value_buff);
	}
}

static void
add_header (proto_tree *tree, tvbuff_t *header_buff, tvbuff_t *value_buff)
{
	guint offset = 0;
	guint8 headerType = 0;
	proto_item *ti;
	guint headerLen = tvb_reported_length (header_buff);
	guint valueLen = tvb_reported_length (value_buff);
	guint peek = 0;
	struct timeval timeValue;
	guint value = 0;

	headerType = tvb_get_guint8 (header_buff, 0);
	peek = tvb_get_guint8 (value_buff, 0);
#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Got header 0x%02x\n", headerType);
	fprintf (stderr, "dissect_wsp: First value octet is 0x%02x\n", peek);
#endif

	if (headerType == 0x7F)
	{
	}
	else if (headerType < 0x1F)
	{
	}
	else if (headerType & 0x80)
	{
		headerType = headerType & 0x7F;
		switch (headerType)
		{
		case 0x00:		/* Accept */
			if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept, header_buff, offset, headerLen, (peek & 0x7F));
			}
			else
			{
				proto_tree_add_string (tree, hf_wsp_header_accept_str,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			}
			break;

		case 0x01:		/* Accept-Charset */
			if (peek < 31)
			{
				/* Peek contains the number of octets to follow */
				switch (peek)
				{
					case 1:
						proto_tree_add_uint (tree, hf_wsp_header_accept_charset, header_buff, offset, headerLen, tvb_get_guint8 (value_buff, 1) );
						break;
					case 2:
						proto_tree_add_uint (tree, hf_wsp_header_accept_charset, header_buff, offset, headerLen, tvb_get_ntohs (value_buff, 1) );
						break;
					case 4:
						proto_tree_add_uint (tree, hf_wsp_header_accept_charset, header_buff, offset, headerLen, tvb_get_ntohl (value_buff, 1) );
						break;
					default:
						fprintf (stderr, "dissect_wsp: accept-charset size %d NYI\n", peek);
				}
			}
			else if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept_charset, header_buff, offset, headerLen, (peek & 0x7F) );
			}
			else
			{
				fprintf (stderr, "dissect_wsp: Accept-Charset value %d (0x%02X) NYI\n", peek, peek);
			}
			break;

		case 0x03:		/* Accept-Language */
			proto_tree_add_uint (tree, hf_wsp_header_accept_language, header_buff, offset, headerLen, (peek & 0x7F));
			break;

		case 0x04:		/* Accept-Ranges */
			if ((peek == 128) || (peek == 129))
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept_ranges, header_buff, offset, headerLen, peek);
			}
			else
			{
				fprintf (stderr, "dissect_wsp: accept-ranges NYI\n");
			}
			
			break;

		case 0x05:		/* Age */
			switch (valueLen)
			{
				case 1:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_guint8 (value_buff, 0));
					break;
				case 2:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_ntohs (value_buff, 0));
					break;
				case 3:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_ntoh24 (value_buff, 0));
					break;
				case 4:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_ntohl (value_buff, 0));
					break;
			};
			break;

		case 0x08:		/* Cache-Control */
			if (peek & 0x80)
			{
				if (valueLen == 1)	/* Well-known value */
				{
					proto_tree_add_uint (tree, hf_wsp_header_cache_control, header_buff, offset, headerLen, peek);
				}
				else
				{
					if ((peek == 0x82) || (peek == 0x83) || (peek == 0x84))	/* Delta seconds value to follow */
					{
						value = tvb_get_guint8 (value_buff, 1);
						if (value & 0x80)
						{
							proto_tree_add_text (tree,
							    header_buff, 0,
							    headerLen,
							    "Cache-Control: %s %d (0x%02X)",
							    val_to_str (peek,
							        vals_cache_control,
							        "Unknown (0x%02x)"),
							        (value & 0x7F),
							        peek);
						}
						else
						{
							fprintf (stderr, "dissect_wsp: Cache-Control integer value Delta seconds NYI\n");
						}
					}
					else if ((peek == 0x80) || (peek == 0x87))	/* Fields to follow */
					{
						fprintf (stderr, "dissect_wsp: Cache-Control field values NYI\n");
					}
					else
					{
						fprintf (stderr, "dissect_wsp: Cache-Control cache extension NYI\n");
					}
				}
			}
			else
			{
				fprintf (stderr, "dissect_wsp: Cache-Control cache extension NYI\n");
			}
			break;
				
		case 0x0D:		/* Content-Length */
			if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_content_length, header_buff, offset, headerLen, (peek & 0x7F));
			}
			else
			{
				fprintf (stderr, "dissect_wsp: Content-Length long-integer size NYI\n");
			}
			break;
				
		case 0x12:		/* Date */
			timeValue.tv_sec = tvb_get_ntohl (value_buff, 0);
			ti = proto_tree_add_time (tree, hf_wsp_header_date, header_buff, offset, headerLen, &timeValue);
			break;

		case 0x13:		/* Etag */
			ti = proto_tree_add_string (tree, hf_wsp_header_etag,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x14:		/* Expires */
			switch (valueLen)
			{
				case 1:
				case 2:
					fprintf (stderr, "dissect_wsp: Expires value length %d NYI\n", valueLen);
					break;
				case 3:
					timeValue.tv_sec = tvb_get_ntoh24 (value_buff, 0);
					break;
				case 4:
					timeValue.tv_sec = tvb_get_ntohl (value_buff, 0);
					break;
			};
			ti = proto_tree_add_time (tree, hf_wsp_header_expires, header_buff, offset, headerLen, &timeValue);
			break;

		case 0x17:		/* If-Modified-Since */
			if (valueLen == 4)
			{
				timeValue.tv_sec = tvb_get_ntohl (value_buff, 0);
			}
			else
			{
				timeValue.tv_sec = 0;
			}
			ti = proto_tree_add_time (tree, hf_wsp_header_if_modified_since, header_buff, offset, headerLen, &timeValue);
			break;
				
		case 0x1C:		/* Location */
			ti = proto_tree_add_string (tree, hf_wsp_header_location,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x1D:		/* Last-Modified */
			timeValue.tv_sec = tvb_get_ntohl (value_buff, 0);
			ti = proto_tree_add_time (tree, hf_wsp_header_last_modified, header_buff, offset, headerLen, &timeValue);
			break;
				
		case 0x1F:		/* Pragma */
			if (peek == 0x80)
			{
				proto_tree_add_text (tree, header_buff, 0, headerLen, "Pragma: No-cache");
			}
			else
			{
				proto_tree_add_text (tree, header_buff, 0, headerLen, "Unsupported Header (0x%02X)", (tvb_get_guint8 (header_buff, 0) & 0x7F));
			}
			break;
				
		case 0x26:		/* Server */
			ti = proto_tree_add_string (tree, hf_wsp_header_server,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x29:		/* User-Agent */
			ti = proto_tree_add_string (tree, hf_wsp_header_user_agent,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		default:
			ti = proto_tree_add_text (tree, header_buff, 0, headerLen, "Unsupported Header (0x%02X)", (tvb_get_guint8 (header_buff, 0) & 0x7F));
			break;
		}
	}
	else
	{
		/* Special case header X-WAP.TOD that is sometimes followed
		 * by a 4-byte date value */
		if (strncasecmp ("x-wap.tod", tvb_get_ptr (header_buff, 0, headerLen), 9) == 0)
		{
			if (tvb_reported_length (value_buff) == 4)	/* Probably a date value */
			{
				timeValue.tv_sec = tvb_get_ntohl (value_buff, 0);
				ti = proto_tree_add_time (tree, hf_wsp_header_x_wap_tod, header_buff, offset, headerLen, &timeValue);
			}
			else
			{
				ti = proto_tree_add_text (tree, header_buff, 0, headerLen, "%s: %s", tvb_get_ptr (header_buff, 0, headerLen), tvb_get_ptr (value_buff, 0, valueLen));
			}
		}
		else
		{
			ti = proto_tree_add_text (tree, header_buff, 0, headerLen, "%s: %s", tvb_get_ptr (header_buff, 0, headerLen), tvb_get_ptr (value_buff, 0, valueLen));
		}
	}

}

static guint
get_value_length (tvbuff_t *tvb, guint offset, guint *nextOffset)
{
	guint value = 0;
	guint count = 0;
	guint octet = tvb_get_guint8 (tvb, offset);

	if (octet <= 30)	/* Short length */
	{
		value = octet;
		*nextOffset = offset+1;
	}
	else if (octet == 31)
	{
		value = tvb_get_guintvar (tvb, offset+1, &count);
		*nextOffset = offset+1+count;
	}
	else
	{
		fprintf (stderr, "dissect_wsp: get_value_length: case NYI\n");
	}

	return (value);
}

static guint
add_content_type (proto_tree *tree, tvbuff_t *tvb, guint offset, guint *contentType)
{
	proto_tree *contentTypeTree;
	guint nextOffset = offset;
	guint fieldLength = 0;
	guint octet = tvb_get_guint8 (tvb, offset);
	guint totalSizeOfField = 0;

	if (octet <= 31)
	{
		fieldLength = get_value_length (tvb, offset, &nextOffset);
		totalSizeOfField = (nextOffset-offset)+fieldLength;
	}
	else if (octet & 0x80)
	{
		fieldLength = 1;
		totalSizeOfField = 1;
	}
	else
	{
		fprintf (stderr, "dissect-wsp: Content-type is un-supported\n");
	}

	*contentType = (tvb_get_guint8 (tvb, nextOffset) & 0x7F);
	contentTypeTree = proto_tree_add_uint (tree, hf_wsp_content_type, tvb, offset, totalSizeOfField, (tvb_get_guint8(tvb,nextOffset++) & 0x7F));

	while (nextOffset < (offset+totalSizeOfField))
	{
		/* add_parameter */
		nextOffset = add_parameter (contentTypeTree, tvb, nextOffset);
	}

	return (offset+totalSizeOfField);
}

static guint
add_parameter (proto_tree *tree, tvbuff_t *tvb, guint offset)
{
	guint octet = tvb_get_guint8 (tvb, offset);
	if (octet & 0x80)	/* Short integer */
	{
		offset++;
		octet = octet & 0x7F;
		switch ( octet )
		{
			case 0x01:
				offset = add_parameter_charset (tree, tvb, offset, offset-1);
				break;

			default:
				fprintf (stderr, "dissect-wsp: add_parameter octet=0x%02x\n", octet);
		};
	}
	else
	{
		fprintf (stderr, "dissect-wsp: add_parameter octet=0x%02x\n", octet);
	}

	return (offset);
}

static guint
add_parameter_charset (proto_tree *tree, tvbuff_t *tvb, guint offset, guint startOffset)
{
	guint octet = tvb_get_guint8 (tvb, offset);
	if (octet < 31)
	{
		offset += octet+1;
		proto_tree_add_item (tree, hf_wsp_parameter_well_known_charset, tvb, startOffset+1, octet, bo_big_endian);
	}
	else if (octet & 0x80)
	{
		offset++;
		proto_tree_add_uint (tree, hf_wsp_parameter_well_known_charset, tvb, startOffset, offset-startOffset, (octet & 0x7F));
	}

	return offset;
}

static void
add_post_data (proto_tree *tree, tvbuff_t *tvb, guint contentType)
{
	guint offset = 0;
	guint variableStart = 0;
	guint variableEnd = 0;
	guint valueStart = 0;
	guint valueEnd = 0;
	guint8 peek = 0;
	proto_item *ti;
	
	ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,END_OF_FRAME,bo_little_endian);

	if (contentType == 0x12)	/* URL Encoded data */
	{
		/* Iterate through post data */
		for (offset = 0; offset < tvb_reported_length (tvb); offset++)
		{
			peek = tvb_get_guint8 (tvb, offset);
			if (peek == '=')
			{
				variableEnd = offset-1;
				valueStart = offset+1;
			}
			else if (peek == '&')
			{
				if (variableEnd > 0)
				{
					add_post_variable (ti, tvb, variableStart, variableEnd, valueStart, offset);
				}
				variableStart = offset+1;
				variableEnd = 0;
				valueStart = 0;
				valueEnd = 0;
			}
		}

		/* See if there's outstanding data */
		if (variableEnd > 0)
		{
			add_post_variable (ti, tvb, variableStart, variableEnd, valueStart, offset);
		}
	}
}

static void
add_post_variable (proto_tree *tree, tvbuff_t *tvb, guint variableStart, guint variableEnd, guint valueStart, guint valueEnd)
{
	int variableLength = variableEnd-variableStart;
	int valueLength = 0;
	char *variableBuffer;
	char *valueBuffer;

	variableBuffer = g_malloc (variableLength+1);
	strncpy (variableBuffer, tvb_get_ptr (tvb, variableStart, variableLength), variableLength+1);
	variableBuffer[variableLength+1] = 0;

	if (valueEnd == 0)
	{
		valueBuffer = g_malloc (1);
		valueBuffer[0] = 0;
		valueEnd = valueStart;
	}
	else
	{
		valueLength = valueEnd-valueStart;
		valueBuffer = g_malloc (valueLength+1);
		strncpy (valueBuffer, tvb_get_ptr (tvb, valueStart, valueLength), valueLength);
		valueBuffer[valueLength] = 0;
	}

	/* Check for variables with no value */
	if (valueStart >= tvb_reported_length (tvb))
	{
		valueStart = tvb_reported_length (tvb);
		valueEnd = valueStart;
	}
	valueLength = valueEnd-valueStart;

	proto_tree_add_text (tree, tvb, variableStart, valueEnd-variableStart, "%s: %s", variableBuffer, valueBuffer);

	g_free (variableBuffer);
	g_free (valueBuffer);
}

/* Register the protocol with Ethereal */
void
proto_register_wsp(void)
{                 

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_wsp_header_tid,
			{ 	"Transmission ID",           
				"wsp.TID",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Transmission ID" 
			}
		},
		{ &hf_wsp_header_pdu_type,
			{ 	"PDU Type",           
				"wsp.pdu-type",
				 FT_UINT8, BASE_HEX, VALS( vals_pdu_type ), 0x00,
				"PDU Type" 
			}
		},
		{ &hf_wsp_version_major,
			{ 	"Version (Major)",           
				"wsp.version.major",
				 FT_UINT8, BASE_DEC, NULL, 0xF0,
				"Version (Major)" 
			}
		},
		{ &hf_wsp_version_minor,
			{ 	"Version (Minor)",           
				"wsp.version.minor",
				 FT_UINT8, BASE_DEC, NULL, 0x0F,
				"Version (Minor)" 
			}
		},
		{ &hf_wsp_capability_length,
			{ 	"Capability Length",           
				"wsp.capability.length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Capability Length" 
			}
		},
		{ &hf_wsp_header_length,
			{ 	"Headers Length",           
				"wsp.headers-length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Headers Length" 
			}
		},
		{ &hf_wsp_capabilities_section,
			{ 	"Capabilities",           
				"wsp.capabilities",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Capabilities" 
			}
		},
		{ &hf_wsp_headers_section,
			{ 	"Headers",           
				"wsp.headers",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Headers" 
			}
		},
		{ &hf_wsp_header,
			{ 	"Header",           
				"wsp.headers.header",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Header" 
			}
		},
		{ &hf_wsp_header_uri_len,
			{ 	"URI Length",           
				"wsp.uri-length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"URI Length" 
			}
		},
		{ &hf_wsp_header_uri,
			{ 	"URI",           
				"wsp.uri",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"URI" 
			}
		},
		{ &hf_wsp_server_session_id,
			{ 	"Server Session ID",           
				"wsp.server.session-id",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Server Session ID" 
			}
		},
		{ &hf_wsp_header_status,
			{ 	"Status",           
				"wsp.reply.status",
				 FT_UINT8, BASE_HEX, VALS( vals_status ), 0x00,
				"Status" 
			}
		},
		{ &hf_wsp_content_type,
			{ 	"Content Type",           
				"wsp.content-type.type",
				 FT_UINT8, BASE_HEX, VALS ( vals_content_types ), 0x00,
				"Content Type" 
			}
		},
		{ &hf_wsp_parameter_well_known_charset,
			{ 	"Charset",           
				"wsp.content-type.parameter.charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Charset" 
			}
		},
		{ &hf_wsp_reply_data,
			{ 	"Data",           
				"wsp.reply.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Data" 
			}
		},
		{ &hf_wsp_header_accept,
			{ 	"Accept",           
				"wsp.header.accept",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_UINT8, BASE_HEX, VALS ( vals_content_types ), 0x00,
				"Accept" 
			}
		},
		{ &hf_wsp_header_accept_str,
			{ 	"Accept",           
				"wsp.header.accept.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept" 
			}
		},
		{ &hf_wsp_header_accept_charset,
			{ 	"Accept-Charset",           
				"wsp.header.accept-charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Accept-Charset" 
			}
		},
		{ &hf_wsp_header_accept_language,
			{ 	"Accept-Language",           
				"wsp.header.accept-language",
				 FT_UINT8, BASE_HEX, VALS ( vals_languages ), 0x00,
				"Accept-Language" 
			}
		},
		{ &hf_wsp_header_accept_ranges,
			{ 	"Accept-Ranges",           
				"wsp.header.accept-ranges",
				 FT_UINT8, BASE_HEX, VALS ( vals_accept_ranges ), 0x00,
				"Accept-Ranges" 
			}
		},
		{ &hf_wsp_header_age,
			{ 	"Age",           
				"wsp.header.age",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Age" 
			}
		},
		{ &hf_wsp_header_cache_control,
			{ 	"Cache-Control",           
				"wsp.header.cache-control",
				 FT_UINT8, BASE_HEX, VALS ( vals_cache_control ), 0x00,
				"Cache-Control" 
			}
		},
		{ &hf_wsp_header_content_length,
			{ 	"Content-Length",           
				"wsp.header.content-length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Content-Length" 
			}
		},
		{ &hf_wsp_header_date,
			{ 	"Date",           
				"wsp.header.date",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Date" 
			}
		},
		{ &hf_wsp_header_etag,
			{ 	"Etag",           
				"wsp.header.etag",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Etag" 
			}
		},
		{ &hf_wsp_header_expires,
			{ 	"Expires",           
				"wsp.header.expires",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Expires" 
			}
		},
		{ &hf_wsp_header_last_modified,
			{ 	"Last-Modified",           
				"wsp.header.last-modified",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Last-Modified" 
			}
		},
		{ &hf_wsp_header_location,
			{ 	"Location",           
				"wsp.header.location",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Location" 
			}
		},
		{ &hf_wsp_header_if_modified_since,
			{ 	"If-Modified-Since",           
				"wsp.header.if-modified-since",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"If-Modified-Since" 
			}
		},
		{ &hf_wsp_header_server,
			{ 	"Server",           
				"wsp.header.server",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Server" 
			}
		},
		{ &hf_wsp_header_user_agent,
			{ 	"User-Agent",           
				"wsp.header.user-agent",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"User-Agent" 
			}
		},
		{ &hf_wsp_header_application_header,
			{ 	"Application Header",           
				"wsp.header.application-header",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Application Header" 
			}
		},
		{ &hf_wsp_header_application_value,
			{ 	"Application Header Value",           
				"wsp.header.application-header.value",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Application Header Value" 
			}
		},
		{ &hf_wsp_header_x_wap_tod,
			{ 	"X-WAP.TOD",           
				"wsp.header.x_wap_tod",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"X-WAP.TOD" 
			}
		},
		{ &hf_wsp_post_data,
			{ 	"Post Data",           
				"wsp.post.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Post Data" 
			}
		},
	};
	
/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wsp,
		&ett_header,
		&ett_headers,
		&ett_capabilities,
		&ett_content_type,
	};

/* Register the protocol name and description */
	proto_wsp = proto_register_protocol(
		"Wireless Session Protocol",   	/* protocol name for use by ethereal */ 
		"WSP",                          /* short version of name */
		"wap-wsp"                    	/* Abbreviated protocol name, should Match IANA 
						    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
						  */
	);

/* Required function calls to register the header fields and subtrees used  */
	proto_register_field_array(proto_wsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wsp", dissect_wsp, proto_wsp);
};

void
proto_reg_handoff_wsp(void)
{
	/* Only connection-less WSP has no previous handler */
	dissector_add("udp.port", UDP_PORT_WSP, dissect_wsp, proto_wsp);
	/* dissector_add("udp.port", UDP_PORT_WTP_WSP, dissect_wsp, proto_wsp); */
	/* dissector_add("udp.port", UDP_PORT_WTLS_WSP, dissect_wsp, proto_wsp); */
	/* dissector_add("udp.port", UDP_PORT_WTLS_WTP_WSP, dissect_wsp, proto_wsp); */
}
