/* packet-mmse.c
 * Routines for MMS Message Encapsulation dissection
 * Copyright 2001, Tom Uijldert <tom.uijldert@cmg.nl>
 *
 * $Id: packet-mmse.c,v 1.6 2002/01/21 07:36:37 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * ----------
 *
 * Dissector of an encoded Multimedia message PDU, as defined by the WAPForum
 * (http://www.wapforum.org) in "WAP-209.102-MMSEncapsulation" according
 * the draft version of 8-February-2001.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "packet-wap.h"
#include "packet-wsp.h"
/* #include "packet-mmse.h" */		/* We autoregister	*/

#define	MM_QUOTE		0x7F	/* Quoted string	*/

#define MMS_CONTENT_TYPE	0x3E	/* WINA-value for mms-message	*/

/*
 * Forward declarations
 */
static void dissect_mmse(tvbuff_t *, packet_info *, proto_tree *);

/*
 * Header field values
 */
#define MM_BCC_HDR		0x81	/* Bcc			*/
#define MM_CC_HDR		0x82	/* Cc			*/
#define MM_CLOCATION_HDR	0x83	/* Content-Location	*/
#define MM_CTYPE_HDR		0x84	/* Content-Type		*/
#define MM_DATE_HDR		0x85	/* Date			*/
#define MM_DREPORT_HDR		0x86	/* Delivery-Report	*/
#define MM_DTIME_HDR		0x87	/* Delivery-Time	*/
#define MM_EXPIRY_HDR		0x88	/* Expiry		*/
#define MM_FROM_HDR		0x89	/* From			*/
#define MM_MCLASS_HDR		0x8A	/* Message-Class	*/
#define MM_MID_HDR		0x8B	/* Message-ID		*/
#define MM_MTYPE_HDR		0x8C	/* Message-Type		*/
#define MM_VERSION_HDR		0x8D	/* MMS-Version		*/
#define MM_MSIZE_HDR		0x8E	/* Message-Size		*/
#define MM_PRIORITY_HDR		0x8F	/* Priority		*/
#define MM_RREPLY_HDR		0x90	/* Read-Reply		*/
#define MM_RALLOWED_HDR		0x91	/* Report-Allowed	*/
#define MM_RSTATUS_HDR		0x92	/* Response-Status	*/
#define MM_RTEXT_HDR		0x93	/* Response-Text	*/
#define MM_SVISIBILITY_HDR	0x94	/* Sender-Visibility	*/
#define MM_STATUS_HDR		0x95	/* Status		*/
#define MM_SUBJECT_HDR		0x96	/* Subject		*/
#define MM_TO_HDR		0x97	/* To			*/
#define MM_TID_HDR		0x98	/* Transaction-Id	*/

/*
 * Initialize the protocol and registered fields
 */
static int proto_mmse = -1;

static int hf_mmse_message_type		= -1;
static int hf_mmse_transaction_id	= -1;
static int hf_mmse_mms_version		= -1;
static int hf_mmse_bcc			= -1;
static int hf_mmse_cc			= -1;
static int hf_mmse_content_location	= -1;
static int hf_mmse_date			= -1;
static int hf_mmse_delivery_report	= -1;
static int hf_mmse_delivery_time_abs	= -1;
static int hf_mmse_delivery_time_rel	= -1;
static int hf_mmse_expiry_abs		= -1;
static int hf_mmse_expiry_rel		= -1;
static int hf_mmse_from			= -1;
static int hf_mmse_message_class_id	= -1;
static int hf_mmse_message_class_str	= -1;
static int hf_mmse_message_id		= -1;
static int hf_mmse_message_size		= -1;
static int hf_mmse_priority		= -1;
static int hf_mmse_read_reply		= -1;
static int hf_mmse_report_allowed	= -1;
static int hf_mmse_response_status	= -1;
static int hf_mmse_response_text	= -1;
static int hf_mmse_sender_visibility	= -1;
static int hf_mmse_status		= -1;
static int hf_mmse_subject		= -1;
static int hf_mmse_to			= -1;
static int hf_mmse_content_type		= -1;
static int hf_mmse_ffheader		= -1;

/*
 * Initialize the subtree pointers
 */
static gint ett_mmse = -1;

/*
 * Valuestrings for header contents
 */
static const value_string vals_message_type[] = {
    { 0x80, "m-send-req" },
    { 0x81, "m-send-conf" },
    { 0x82, "m-notification-ind" },
    { 0x83, "m-notifyresp-ind" },
    { 0x84, "m-retrieve-conf" },
    { 0x85, "m-acknowledge-ind" },
    { 0x86, "m-delivery-ind" },
    { 0x00, NULL },
};

static const value_string vals_yes_no[] = {
    { 0x80, "Yes" },
    { 0x81, "No" },
    { 0x00, NULL },
};

static const value_string vals_message_class[] = {
    { 0x80, "Personal" },
    { 0x81, "Advertisement" },
    { 0x82, "Informational" },
    { 0x82, "Auto" },
    { 0x00, NULL },
};

static const value_string vals_priority[] = {
    { 0x80, "Low" },
    { 0x81, "Normal" },
    { 0x81, "High" },
    { 0x00, NULL },
};

static const value_string vals_response_status[] = {
    { 0x80, "Ok" },
    { 0x81, "Unspecified" },
    { 0x82, "Service denied" },
    { 0x83, "Message format corrupt" },
    { 0x84, "sending address unresolved" },
    { 0x85, "message not found" },
    { 0x86, "Network problem" },
    { 0x87, "Content not accepted" },
    { 0x88, "Unsupported message" },
    { 0x00, NULL },
};

static const value_string vals_sender_visibility[] = {
    { 0x80, "Hide" },
    { 0x81, "Show" },
    { 0x00, NULL },
};

static const value_string vals_status[] = {
    { 0x80, "Expired" },
    { 0x81, "Retrieved" },
    { 0x82, "Rejected" },
    { 0x82, "Deferred" },
    { 0x82, "Unrecognized" },
    { 0x00, NULL },
};

/*!
 * Decodes a Text-string from the protocol data
 * 	Text-string = [Quote] *TEXT End-of-string
 * 	Quote	    = <Octet 127>
 * 	End-of-string = <Octet 0>
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param	tvb	The buffer with PDU-data
 * \param	offset	Offset within that buffer
 * \param	strval	String buffer to receive the text, reserve memory!
 *
 * \return		The length in bytes of the entire field
 */
static guint
get_text_string(tvbuff_t *tvb, guint offset, char *strval)
{
    guint	 len;

    len = tvb_strsize(tvb, offset);
    if (tvb_get_guint8(tvb, offset) == MM_QUOTE)
	tvb_memcpy(tvb, strval, offset + 1, len - 1);
    else
	tvb_memcpy(tvb, strval, offset, len);
    return len;
}

/*!
 * Decodes a Value-length from the protocol data.
 * 	Value-length = Short-length | (Length-quote Length)
 * 	Short-length = <Any octet 0-30>
 * 	Length-quote = <Octet 31>
 * 	Length	     = Uintvar-integer
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param	tvb		The buffer with PDU-data
 * \param	offset		Offset within that buffer
 * \param	byte_count	Returns the length in bytes of
 *				the "Value-length" field.
 *
 * \return			The actual value of "Value-length"
 */
static guint
get_value_length(tvbuff_t *tvb, guint offset, guint *byte_count)
{
    guint	 field;

    field = tvb_get_guint8(tvb, offset++);
    if (field < 31)
	*byte_count = 1;
    else {			/* Must be 31 so, Uintvar follows	*/
	field = tvb_get_guintvar(tvb, offset, byte_count);
	(*byte_count)++;
    }
    return field;
}

/*!
 * Decodes an Encoded-string-value from the protocol data
 * 	Encoded-string-value = Text-string | Value-length Char-set Text-string
 *
 * \param	tvb	The buffer with PDU-data
 * \param	offset	Offset within that buffer
 * \param	strval	String buffer to receive the text, reserve memory!
 *
 * \return		The length in bytes of the entire field
 */
static guint
get_encoded_strval(tvbuff_t *tvb, guint offset, char *strval)
{
    guint	 field;
    guint	 length;
    guint	 count;

    field = tvb_get_guint8(tvb, offset);

    if (field < 32) {
	length = get_value_length(tvb, offset, &count);
	/* \todo	Something with "Char-set", skip for now	*/
	tvb_memcpy(tvb, strval, offset + count + 1, length - 1);
	strval[length - 1] = '\0';	/* Just to make sure	*/
	return offset + count + length;
    } else
	return get_text_string(tvb, offset, strval);
}

/*!
 * Decodes a Long-integer from the protocol data
 * 	Long-integer = Short-length Multi-octet-integer
 * 	Short-length = <Any octet 0-30>
 * 	Multi-octet-integer = 1*30OCTET
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param	tvb		The buffer with PDU-data
 * \param	offset		Offset within that buffer
 * \param	byte_count	Returns the length in bytes of the field
 *
 * \return			The value of the Long-integer
 *
 * \note	A maximum of 4-byte integers will be handled.
 */
static guint
get_long_integer(tvbuff_t *tvb, guint offset, guint *byte_count)
{
    guint	 val;

    *byte_count = tvb_get_guint8(tvb, offset++);
    switch (*byte_count) {
	case 1:
	    val = tvb_get_guint8(tvb, offset);
	    break;
	case 2:
	    val = tvb_get_ntohs(tvb, offset);
	    break;
	case 3:
	    val = tvb_get_ntoh24(tvb, offset);
	    break;
	case 4:
	    val = tvb_get_ntohl(tvb, offset);
	    break;
	default:
	    val = 0;
	    break;
    }
    (*byte_count)++;
    return val;
}

/* Code to actually dissect the packets */
static gboolean
dissect_mmse_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8	 pdut;

    /*
     * Check if data makes sense for it to be dissected as MMSE:  Message-type
     * field must make sense and followed by Transaction-Id header
     */
    if (tvb_get_guint8(tvb, 0) != MM_MTYPE_HDR)
	return FALSE;
    pdut = tvb_get_guint8(tvb, 1);
    if (match_strval(pdut, vals_message_type) == NULL)
	return FALSE;
    if (tvb_get_guint8(tvb, 2) != MM_TID_HDR)
	return FALSE;
    dissect_mmse(tvb, pinfo, tree);
    return TRUE;
}

static void
dissect_mmse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8	 pdut;
    guint	 offset;
    guint8	 field = 0;
    char	 strval[BUFSIZ];
    guint	 length;
    guint	 count;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *mmse_tree;

    pdut = tvb_get_guint8(tvb, 1);
    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMSE");

    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "MMS %s",
		     match_strval(pdut, vals_message_type));
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree) {
	offset = 2;			/* Skip Message-Type	*/

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_mmse, tvb, 0,
				 tvb_length(tvb), FALSE);
	mmse_tree = proto_item_add_subtree(ti, ett_mmse);

	/* Report PDU-type	*/
	proto_tree_add_uint(mmse_tree, hf_mmse_message_type, tvb, 0, 2, pdut);
	/*
	 * Cycle through MMS-headers
	 */
	while ((offset < tvb_reported_length(tvb)) &&
	       (field = tvb_get_guint8(tvb, offset++)) != MM_CTYPE_HDR)
	{
	    switch (field)
	    {
		case MM_TID_HDR:		/* Text-string	*/
		    length = get_text_string(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_transaction_id,
					  tvb, offset - 1, length + 1,strval);
		    offset += length;
		    break;
		case MM_VERSION_HDR:		/* nibble-Major/nibble-minor*/
		    field = tvb_get_guint8(tvb, offset++);
		    {
			guint8	 major, minor;

			major = (field & 0x70) >> 4;
			minor = field & 0x0F;
			if (minor == 0x0F)
			    sprintf(strval, "%d", major);
			else
			    sprintf(strval, "%d.%d", major, minor);
		    }
		    proto_tree_add_string(mmse_tree, hf_mmse_mms_version, tvb,
			    		  offset - 2, 2, strval);
		    break;
		case MM_BCC_HDR:		/* Encoded-string-value	*/
		    length = get_encoded_strval(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_bcc, tvb,
			    		offset - 1, length + 1, strval);
		    offset += length;
		    break;
		case MM_CC_HDR:			/* Encoded-string-value	*/
		    length = get_encoded_strval(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_cc, tvb,
			    		offset - 1, length + 1, strval);
		    offset += length;
		    break;
		case MM_CLOCATION_HDR:		/* Uri-value		*/
		    length = get_text_string(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_content_location,
					  tvb, offset - 1, length + 1,strval);
		    offset += length;
		    break;
		case MM_DATE_HDR:		/* Long-integer		*/
		    {
			guint		 tval;
			nstime_t	 tmptime;

			tval = get_long_integer(tvb, offset, &count);
			tmptime.secs = tval;
			tmptime.nsecs = 0;
			proto_tree_add_time(mmse_tree, hf_mmse_date, tvb,
					    offset - 1, count + 1, &tmptime);
		    }
		    offset += count;
		    break;
		case MM_DREPORT_HDR:		/* Yes|No		*/
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree, hf_mmse_delivery_report, tvb,
					offset - 2, 2, field);
		    break;
		case MM_DTIME_HDR:
		    /*
		     * Value-length(Absolute-token Date-value|
		     * 		    Relative-token Delta-seconds-value)
		     */
		    length = get_value_length(tvb, offset, &count);
		    field = tvb_get_guint8(tvb, offset + count);
		    {
			guint		 tval;
			nstime_t	 tmptime;
			guint		 cnt;

			tval =  get_long_integer(tvb, offset + count, &cnt);
			tmptime.secs = tval;
			tmptime.nsecs = 0;
			if (field == 0x80)
			    proto_tree_add_time(mmse_tree,
					        hf_mmse_delivery_time_abs,
						tvb, offset - 1,
						length + count + 1, &tmptime);
			else
			    proto_tree_add_time(mmse_tree,
						hf_mmse_delivery_time_rel,
						tvb, offset - 1,
						length + count + 1, &tmptime);
		    }
		    offset += length + count;
		    break;
		case MM_EXPIRY_HDR:
		    /*
		     * Value-length(Absolute-token Date-value|
		     * 		    Relative-token Delta-seconds-value)
		     */
		    length = get_value_length(tvb, offset, &count);
		    field = tvb_get_guint8(tvb, offset + count);
		    {
			guint		 tval;
			nstime_t	 tmptime;
			guint		 cnt;

			tval = get_long_integer(tvb, offset + count + 1, &cnt);
			tmptime.secs = tval;
			tmptime.nsecs = 0;
			if (field == 0x80)
			    proto_tree_add_time(mmse_tree, hf_mmse_expiry_abs,
						tvb, offset - 1,
						length + count + 1, &tmptime);
			else
			    proto_tree_add_time(mmse_tree, hf_mmse_expiry_rel,
						tvb, offset - 1,
						length + count + 1, &tmptime);
		    }
		    offset += length + count;
		    break;
		case MM_FROM_HDR:
		    /*
		     * Value-length(Address-present-token Encoded-string-value
		     * 		    |Insert-address-token)
		     */
		    length = get_value_length(tvb, offset, &count);
		    field = tvb_get_guint8(tvb, offset + count);
		    if (field == 0x81) {
			strcpy(strval, "<insert address>");
		    } else {
			(void) get_encoded_strval(tvb, offset + count + 1,
						  strval);
		    }
		    proto_tree_add_string(mmse_tree, hf_mmse_from, tvb,
			    		  offset-1, length + 2, strval);
		    offset += length + 1;
		    break;
		case MM_MCLASS_HDR:
		    /*
		     * Class-identifier|Text-string
		     */
		    field = tvb_get_guint8(tvb, offset);
		    if (field & 0x80) {
			offset++;
			proto_tree_add_uint(mmse_tree,
					    hf_mmse_message_class_id,
					    tvb, offset - 2, 2, field);
		    } else {
			length = get_text_string(tvb, offset, strval);
			proto_tree_add_string(mmse_tree,
					      hf_mmse_message_class_str,
					      tvb, offset - 1, length + 1,
					      strval);
			offset += length;
		    }
		    break;
		case MM_MID_HDR:		/* Text-string		*/
		    length = get_text_string(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_message_id, tvb,
			    		  offset - 1, length + 1, strval);
		    offset += length;
		    break;
		case MM_MSIZE_HDR:		/* Long-integer		*/
		    length = get_long_integer(tvb, offset, &count);
		    proto_tree_add_uint(mmse_tree, hf_mmse_message_size, tvb,
			    		offset - 1, count + 1, length);
		    offset += count;
		    break;
		case MM_PRIORITY_HDR:		/* Low|Normal|High	*/
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree, hf_mmse_priority, tvb,
					offset - 2, 2, field);
		    break;
		case MM_RREPLY_HDR:		/* Yes|No		*/
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree, hf_mmse_read_reply, tvb,
					offset - 2, 2, field);
		    break;
		case MM_RALLOWED_HDR:		/* Yes|No		*/
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree, hf_mmse_report_allowed, tvb,
					offset - 2, 2, field);
		    break;
		case MM_RSTATUS_HDR:
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree, hf_mmse_response_status, tvb,
					offset - 2, 2, field);
		    break;
		case MM_RTEXT_HDR:		/* Encoded-string-value	*/
		    length = get_encoded_strval(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_response_text, tvb,
			    		offset - 1, length + 1, strval);
		    offset += length;
		    break;
		case MM_SVISIBILITY_HDR:	/* Hide|Show		*/
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree,hf_mmse_sender_visibility,
			    		tvb, offset - 2, 2, field);
		    break;
		case MM_STATUS_HDR:
		    field = tvb_get_guint8(tvb, offset++);
		    proto_tree_add_uint(mmse_tree, hf_mmse_status, tvb,
					offset - 2, 2, field);
		    break;
		case MM_SUBJECT_HDR:		/* Encoded-string-value	*/
		    length = get_encoded_strval(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_subject, tvb,
			    		offset - 1, length + 1, strval);
		    offset += length;
		    break;
		case MM_TO_HDR:			/* Encoded-string-value	*/
		    length = get_encoded_strval(tvb, offset, strval);
		    proto_tree_add_string(mmse_tree, hf_mmse_to, tvb,
			    		offset - 1, length + 1, strval);
		    offset += length;
		    break;
		default:
		    if (field & 0x80) {
			g_warning(
				"MMSE - Unknown field encountered (0x%02x)\n",
				field);
		    } else {
			guint	 length2;
			char	 strval2[BUFSIZ];

			--offset;
			length = get_text_string(tvb, offset, strval);
			length2= get_text_string(tvb, offset+length, strval2);

			proto_tree_add_string_format(mmse_tree,
						     hf_mmse_ffheader,
						     tvb, offset,
						     length + length2,
						     tvb_get_ptr(tvb,offset,length + length2),
						     "%s: %s",strval,strval2);
			offset += length + length2;
		    }
		    break;
	    }
	}
	if (field == MM_CTYPE_HDR) {
	    /*
	     * Eeehh, we're now actually back to good old WSP content-type
	     * encoding for multipart/related and multipart/mixed MIME-types.
	     * Let's steal that from the WSP-dissector.
	     */
	    tvbuff_t	*tmp_tvb;
	    guint	 type;
	    const char	*type_str;

	    offset = add_content_type(mmse_tree, tvb, offset, &type, &type_str);
	    tmp_tvb = tvb_new_subset(tvb, offset, -1, -1);
	    add_multipart_data(mmse_tree, tmp_tvb);
	}
    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Ethereal */

/* this format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_mmse(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details	*/
    static hf_register_info hf[] = {
	{   &hf_mmse_message_type,
	    {   "Message-Type", "mmse.message_type",
		FT_UINT8, BASE_HEX, VALS(vals_message_type), 0x00,
		"Specifies the transaction type. Effectively defines PDU.",
		HFILL
	    }
	},
	{   &hf_mmse_transaction_id,
	    {   "Transaction-ID", "mmse.transaction_id",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"A unique identifier for this transaction. "
		"Identifies request and corresponding response only.",
		HFILL
	    }
	},
	{   &hf_mmse_mms_version,
	    {   "MMS-Version", "mmse.mms_version",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Version of the protocol used.",
		HFILL
	    }
	},
	{   &hf_mmse_bcc,
	    {   "Bcc", "mmse.bcc",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Blind carbon copy.",
		HFILL
	    }
	},
	{   &hf_mmse_cc,
	    {   "Bcc", "mmse.bcc",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Carbon copy.",
		HFILL
	    }
	},
	{   &hf_mmse_content_location,
	    {   "Content-Location", "mmse.content_location",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Defines the location of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_date,
	    {   "Date", "mmse.date",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
		"Arrival timestamp of the message or sending timestamp.",
		HFILL
	    }
	},
	{   &hf_mmse_delivery_report,
	    {   "Delivery-Report", "mmse.delivery_report",
		FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
		"Whether a report of message delivery is wanted or not.",
		HFILL
	    }
	},
	{   &hf_mmse_delivery_time_abs,
	    {   "Delivery-Time", "mmse.delivery_time.abs",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
		"The time at which message delivery is desired.",
		HFILL
	    }
	},
	{   &hf_mmse_delivery_time_rel,
	    {   "Delivery-Time", "mmse.delivery_time.rel",
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
		"The desired message delivery delay.",
		HFILL
	    }
	},
	{   &hf_mmse_expiry_abs,
	    {   "Expiry", "mmse.expiry.abs",
		FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
		"Time when message expires and need not be delivered anymore.",
		HFILL
	    }
	},
	{   &hf_mmse_expiry_rel,
	    {   "Expiry", "mmse.expiry.rel",
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
		"Delay before message expires and need not be delivered anymore.",
		HFILL
	    }
	},
	{   &hf_mmse_from,
	    {   "From", "mmse.from",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Address of the message sender.",
		HFILL
	    }
	},
	{   &hf_mmse_message_class_id,
	    {   "Message-Class", "mmse.message_class.id",
		FT_UINT8, BASE_HEX, VALS(vals_message_class), 0x00,
		"Of what category is the message.",
		HFILL
	    }
	},
	{   &hf_mmse_message_class_str,
	    {   "Message-Class", "mmse.message_class.str",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Of what category is the message.",
		HFILL
	    }
	},
	{   &hf_mmse_message_id,
	    {   "Message-Id", "mmse.message_id",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Unique identification of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_message_size,
	    {   "Message-Size", "mmse.message_size",
		FT_UINT32, BASE_DEC, NULL, 0x00,
		"The size of the message in octets.",
		HFILL
	    }
	},
	{   &hf_mmse_priority,
	    {   "Priority", "mmse.priority",
		FT_UINT8, BASE_HEX, VALS(vals_priority), 0x00,
		"Priority of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_read_reply,
	    {   "Read-Reply", "mmse.read_reply",
		FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
		"Whether a read report from every recipient is wanted.",
		HFILL
	    }
	},
	{   &hf_mmse_report_allowed,
	    {   "Report-Allowed", "mmse.report_allowed",
		FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
		"Sending of delivery report allowed or not.",
		HFILL
	    }
	},
	{   &hf_mmse_response_status,
	    {   "Response-Status", "mmse.response_status",
		FT_UINT8, BASE_HEX, VALS(vals_response_status), 0x00,
		"MMS-specific result of a message submission or retrieval.",
		HFILL
	    }
	},
	{   &hf_mmse_response_text,
	    {   "Response-Text", "mmse.response_text",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Additional information on MMS-specific result.",
		HFILL
	    }
	},
	{   &hf_mmse_sender_visibility,
	    {   "Sender-Visibility", "mmse.sender_visibility",
		FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
		"Disclose sender identity to receiver or not.",
		HFILL
	    }
	},
	{   &hf_mmse_status,
	    {   "Status", "mmse.status",
		FT_UINT8, BASE_HEX, VALS(vals_status), 0x00,
		"Current status of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_subject,
	    {   "Subject", "mmse.subject",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Subject of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_to,
	    {   "To", "mmse.to",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Recipient(s) of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_content_type,
	    {   "Data", "mmse.content_type",
		FT_NONE, BASE_NONE, NULL, 0x00,
		"Media content of the message.",
		HFILL
	    }
	},
	{   &hf_mmse_ffheader,
	    {   "Free format (not encoded) header", "mmse.ffheader",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Application header without corresponding encoding.",
		HFILL
	    }
	},
    };
    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_mmse,
    };

    /* Register the protocol name and description */
    proto_mmse = proto_register_protocol("MMS Message Encapsulation",
					 "MMSE", "mmse");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_mmse, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_mmse(void)
{
    dissector_handle_t mmse_handle;

    heur_dissector_add("wsp", dissect_mmse_heur, proto_mmse);
    mmse_handle = create_dissector_handle(dissect_mmse, proto_mmse);
    dissector_add("wsp.content_type.type", MMS_CONTENT_TYPE,
		  mmse_handle);
    /*
     * \todo
     * The bearer could also be http (through the content-type field).
     * The wsp-dissector should then ofcourse be modified to cater for
     * such subdissectors...
     */
}
