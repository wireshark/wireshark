/* packet-wtp.c
 *
 * Routines to dissect WTP component of WAP traffic.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/emem.h>
#include "packet-wap.h"
#include "packet-wtp.h"
#include "packet-wsp.h"

static const true_false_string continue_truth = {
    "TPI Present" ,
    "No TPI"
};

static const true_false_string RID_truth = {
    "Re-Transmission",
    "First transmission"
};

static const true_false_string TIDNew_truth = {
    "TID is new" ,
    "TID is valid"
};

static const true_false_string tid_response_truth = {
    "Response" ,
    "Original"
};

static const true_false_string UP_truth = {
    "User Acknowledgement required" ,
    "User Acknowledgement optional"
};

static const true_false_string TVETOK_truth = {
    "True",
    "False"
};

static const value_string vals_wtp_pdu_type[] = {
    { 0, "Not Allowed" },
    { 1, "Invoke" },
    { 2, "Result" },
    { 3, "Ack" },
    { 4, "Abort" },
    { 5, "Segmented Invoke" },
    { 6, "Segmented Result" },
    { 7, "Negative Ack" },
    { 0, NULL }
};

static const value_string vals_transaction_trailer[] = {
    { 0, "Not last packet" },
    { 1, "Last packet of message" },
    { 2, "Last packet of group" },
    { 3, "Re-assembly not supported" },
    { 0, NULL }
};

static const value_string vals_version[] = {
    { 0, "Current" },
    { 1, "Undefined" },
    { 2, "Undefined" },
    { 3, "Undefined" },
    { 0, NULL }
};

static const value_string vals_abort_type[] = {
    { 0, "Provider" },
    { 1, "User (WSP)" },
    { 0, NULL }
};

static const value_string vals_abort_reason_provider[] = {
    { 0x00, "Unknown" },
    { 0x01, "Protocol Error" },
    { 0x02, "Invalid TID" },
    { 0x03, "Not Implemented Class 2" },
    { 0x04, "Not Implemented SAR" },
    { 0x05, "Not Implemented User Acknowledgement" },
    { 0x06, "WTP Version Zero" },
    { 0x07, "Capacity Temporarily Exceeded" },
    { 0x08, "No Response" },
    { 0x09, "Message Too Large" },
    { 0x00, NULL }
};

static const value_string vals_transaction_classes[] = {
    { 0x00, "Unreliable Invoke without Result" },
    { 0x01, "Reliable Invoke without Result" },
    { 0x02, "Reliable Invoke with Reliable Result" },
    { 0x00, NULL }
};

static const value_string vals_tpi_type[] = {
    { 0x00, "Error" },
    { 0x01, "Info" },
    { 0x02, "Option" },
    { 0x03, "Packet sequence number" },
    { 0x04, "SDU boundary" },
    { 0x05, "Frame boundary" },
    { 0x00, NULL }
};

static const value_string vals_tpi_opt[] = {
    { 0x01, "Maximum receive unit" },
    { 0x02, "Total message size" },
    { 0x03, "Delay transmission timer" },
    { 0x04, "Maximum group" },
    { 0x05, "Current TID" },
    { 0x06, "No cached TID" },
    { 0x00, NULL }
};

/* File scoped variables for the protocol and registered fields */
static int proto_wtp 				= HF_EMPTY;

/* These fields used by fixed part of header */
static int hf_wtp_header_sub_pdu_size 		= HF_EMPTY;
static int hf_wtp_header_flag_continue 		= HF_EMPTY;
static int hf_wtp_header_pdu_type 		= HF_EMPTY;
static int hf_wtp_header_flag_Trailer 		= HF_EMPTY;
static int hf_wtp_header_flag_RID 		= HF_EMPTY;
static int hf_wtp_header_flag_TID 		= HF_EMPTY;
static int hf_wtp_header_flag_TID_response 	= HF_EMPTY;

/* These fields used by Invoke packets */
static int hf_wtp_header_Inv_version 		= HF_EMPTY;
static int hf_wtp_header_Inv_flag_TIDNew 	= HF_EMPTY;
static int hf_wtp_header_Inv_flag_UP	 	= HF_EMPTY;
static int hf_wtp_header_Inv_Reserved	 	= HF_EMPTY;
static int hf_wtp_header_Inv_TransactionClass 	= HF_EMPTY;


static int hf_wtp_header_variable_part 		= HF_EMPTY;
static int hf_wtp_data 				= HF_EMPTY;

static int hf_wtp_tpi_type	 		= HF_EMPTY;
static int hf_wtp_tpi_psn	 		= HF_EMPTY;
static int hf_wtp_tpi_opt	 		= HF_EMPTY;
static int hf_wtp_tpi_optval	 		= HF_EMPTY;
static int hf_wtp_tpi_info	 		= HF_EMPTY;

static int hf_wtp_header_Ack_flag_TVETOK	= HF_EMPTY;
static int hf_wtp_header_Abort_type		= HF_EMPTY;
static int hf_wtp_header_Abort_reason_provider	= HF_EMPTY;
static int hf_wtp_header_Abort_reason_user	= HF_EMPTY;
static int hf_wtp_header_sequence_number	= HF_EMPTY;
static int hf_wtp_header_missing_packets	= HF_EMPTY;

/* These fields used when reassembling WTP fragments */
static int hf_wtp_fragments			= HF_EMPTY;
static int hf_wtp_fragment			= HF_EMPTY;
static int hf_wtp_fragment_overlap		= HF_EMPTY;
static int hf_wtp_fragment_overlap_conflict	= HF_EMPTY;
static int hf_wtp_fragment_multiple_tails	= HF_EMPTY;
static int hf_wtp_fragment_too_long_fragment	= HF_EMPTY;
static int hf_wtp_fragment_error		= HF_EMPTY;
static int hf_wtp_fragment_count		= HF_EMPTY;
static int hf_wtp_reassembled_in		= HF_EMPTY;
static int hf_wtp_reassembled_length		= HF_EMPTY;

/* Initialize the subtree pointers */
static gint ett_wtp 				= ETT_EMPTY;
static gint ett_wtp_sub_pdu_tree	= ETT_EMPTY;
static gint ett_header 				= ETT_EMPTY;
static gint ett_tpilist 			= ETT_EMPTY;
static gint ett_wsp_fragments			= ETT_EMPTY;
static gint ett_wtp_fragment			= ETT_EMPTY;

static const fragment_items wtp_frag_items = {
    &ett_wtp_fragment,
    &ett_wsp_fragments,
    &hf_wtp_fragments,
    &hf_wtp_fragment,
    &hf_wtp_fragment_overlap,
    &hf_wtp_fragment_overlap_conflict,
    &hf_wtp_fragment_multiple_tails,
    &hf_wtp_fragment_too_long_fragment,
    &hf_wtp_fragment_error,
    &hf_wtp_fragment_count,
    &hf_wtp_reassembled_in,
    &hf_wtp_reassembled_length,
    "fragments"
};

/* Handle for WSP dissector */
static dissector_handle_t wsp_handle;

/*
 * reassembly of WSP
 */
static GHashTable	*wtp_fragment_table = NULL;

static void
wtp_defragment_init(void)
{
    fragment_table_init(&wtp_fragment_table);
}

/*
 * Extract some bitfields
 */
#define pdu_type(octet)			(((octet) >> 3) & 0x0F)	/* Note pdu type must not be 0x00 */
#define transaction_class(octet)	((octet) & 0x03)	/* ......XX */
#define transmission_trailer(octet)	(((octet) >> 1) & 0x01)	/* ......X. */

static char retransmission_indicator(unsigned char octet)
{
    switch (pdu_type(octet)) {
	case INVOKE:
	case RESULT:
	case ACK:
	case SEGMENTED_INVOKE:
	case SEGMENTED_RESULT:
	case NEGATIVE_ACK:
	    return octet & 0x01;	/* .......X */
	default:
	    return 0;
    }
}

/*
 * dissect a TPI
 */
static void
wtp_handle_tpi(proto_tree *tree, tvbuff_t *tvb)
{
    int			 offset = 0;
    unsigned char	 tByte;
    unsigned char	 tType;
    unsigned char	 tLen;
    proto_tree     	*subTree = NULL;
    proto_item		*pi;

    tByte = tvb_get_guint8(tvb, offset++);
    tType = (tByte & 0x78) >> 3;
    if (tByte & 0x04)				/* Long TPI	*/
	tLen = tvb_get_guint8(tvb, offset++);
    else
	tLen = tByte & 0x03;
    pi = proto_tree_add_uint(tree, hf_wtp_tpi_type,
				  tvb, 0, tvb_length(tvb), tType);
    subTree = proto_item_add_subtree(pi, ett_tpilist);
    switch (tType) {
	case 0x00:			/* Error*/
	    /* \todo	*/
	    break;
	case 0x01:			/* Info	*/
	    /* Beware, untested case here	*/
	    proto_tree_add_item(subTree, hf_wtp_tpi_info,
				tvb, offset, tLen, bo_little_endian);
	    break;
	case 0x02:			/* Option	*/
	    proto_tree_add_item(subTree, hf_wtp_tpi_opt,
				tvb, offset++, 1, bo_little_endian);
	    proto_tree_add_item(subTree, hf_wtp_tpi_optval,
				tvb, offset, tLen - 1, bo_little_endian);
	    break;
	case 0x03:			/* PSN	*/
	    proto_tree_add_item(subTree, hf_wtp_tpi_psn,
				tvb, offset, 1, bo_little_endian);
	    break;
	case 0x04:			/* SDU boundary	*/
	    /* \todo	*/
	    break;
	case 0x05:			/* Frame boundary	*/
	    /* \todo	*/
	    break;
	default:
	    break;
    }
}

/* Code to actually dissect the packets */
static void
dissect_wtp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    char *szInfo;
    int			offCur		= 0;   /* current offset from start of WTP data */
    gint		returned_length, str_index = 0;

    unsigned char	b0;

    /* continuation flag */
    unsigned char  	fCon;			/* Continue flag	*/
    unsigned char  	fRID;			/* Re-transmission indicator*/
    unsigned char  	fTTR = '\0';		/* Transmission trailer	*/
    guint 		cbHeader   	= 0;	/* Fixed header length	*/
    guint 		vHeader   	= 0;	/* Variable header length*/
    int 		abortType  	= 0;

    /* Set up structures we'll need to add the protocol subtree and manage it */
    proto_item		*ti = NULL;
    proto_tree		*wtp_tree = NULL;

    char		pdut;
    char		clsTransaction = 3;
    int			numMissing = 0;		/* Number of missing packets in a negative ack */
    int			i;
    tvbuff_t		*wsp_tvb = NULL;
    guint8		psn = 0;		/* Packet sequence number*/
    guint16		TID = 0;		/* Transaction-Id	*/
    int			dataOffset;
    gint		dataLen;

#define SZINFO_SIZE 256
    szInfo=ep_alloc(SZINFO_SIZE);

    b0 = tvb_get_guint8 (tvb, offCur + 0);
    /* Discover Concatenated PDUs */
    if (b0 == 0) {
	guint	c_fieldlen = 0;		/* Length of length-field	*/
	guint	c_pdulen = 0;		/* Length of conc. PDU	*/

	if (tree) {
	    ti = proto_tree_add_item(tree, proto_wtp,
				    tvb, offCur, 1, bo_little_endian);
	    wtp_tree = proto_item_add_subtree(ti, ett_wtp_sub_pdu_tree);
		proto_item_append_text(ti, ", PDU concatenation");
	}
	offCur = 1;
	i = 1;
	while (offCur < (int) tvb_reported_length(tvb)) {
	    tvbuff_t *wtp_tvb;
	    /* The length of an embedded WTP PDU is coded as either:
	     *	- a 7-bit value contained in one octet with highest bit == 0.
	     *	- a 15-bit value contained in two octets (little endian)
	     *	  if the 1st octet has its highest bit == 1.
	     * This means that this is NOT encoded as an uintvar-integer!!!
	     */
	    b0 = tvb_get_guint8(tvb, offCur + 0);
	    if (b0 & 0x80) {
		c_fieldlen = 2;
		c_pdulen = ((b0 & 0x7f) << 8) | tvb_get_guint8(tvb, offCur + 1);
	    } else {
		c_fieldlen = 1;
		c_pdulen = b0;
	    }
	    if (tree) {
		proto_tree_add_uint(wtp_tree, hf_wtp_header_sub_pdu_size,
				    tvb, offCur, c_fieldlen, c_pdulen);
	    }
	    if (i > 1) {
		col_append_str(pinfo->cinfo, COL_INFO, ", ");
	    }
	    /* Skip the length field for the WTP sub-tvb */
	    wtp_tvb = tvb_new_subset(tvb, offCur + c_fieldlen, c_pdulen, c_pdulen);
	    dissect_wtp_common(wtp_tvb, pinfo, wtp_tree);
	    offCur += c_fieldlen + c_pdulen;
	    i++;
	}
	if (tree) {
		proto_item_append_text(ti, ", PDU count: %u", i);
	}
	return;
    }
    /* No concatenation */
    fCon = b0 & 0x80;
    fRID = retransmission_indicator(b0);
    pdut = pdu_type(b0);

#ifdef DEBUG
	printf("WTP packet %u: tree = %p, pdu = %s (%u) length: %u\n",
			pinfo->fd->num, tree,
			val_to_str(pdut, vals_wtp_pdu_type, "Unknown PDU type 0x%x"),
			pdut, tvb_length(tvb));
#endif

    /* Develop the string to put in the Info column */
    returned_length =  g_snprintf(szInfo, SZINFO_SIZE, "WTP %s",
		    val_to_str(pdut, vals_wtp_pdu_type, "Unknown PDU type 0x%x"));
    str_index += MIN(returned_length, SZINFO_SIZE-str_index);

    switch (pdut) {
	case INVOKE:
	    fTTR = transmission_trailer(b0);
	    TID = tvb_get_ntohs(tvb, offCur + 1);
	    psn = 0;
	    clsTransaction = transaction_class(tvb_get_guint8(tvb, offCur + 3));
	    returned_length = g_snprintf(&szInfo[str_index], SZINFO_SIZE-str_index,
		" Class %d", clsTransaction);
            str_index += MIN(returned_length, SZINFO_SIZE-str_index);
	    cbHeader = 4;
	    break;

	case SEGMENTED_INVOKE:
	case SEGMENTED_RESULT:
	    fTTR = transmission_trailer(b0);
	    TID = tvb_get_ntohs(tvb, offCur + 1);
	    psn = tvb_get_guint8(tvb, offCur + 3);
	    if (psn != 0) {
		returned_length = g_snprintf(&szInfo[str_index], SZINFO_SIZE-str_index,
			" (%u)", psn);
                str_index += MIN(returned_length, SZINFO_SIZE-str_index);
	    }
	    cbHeader = 4;
	    break;

	case ABORT:
	    cbHeader = 4;
	    break;

	case RESULT:
	    fTTR = transmission_trailer(b0);
	    TID = tvb_get_ntohs(tvb, offCur + 1);
	    psn = 0;
	    cbHeader = 3;
	    break;

	case ACK:
	    cbHeader = 3;
	    break;

	case NEGATIVE_ACK:
	    /* Variable number of missing packets */
	    numMissing = tvb_get_guint8(tvb, offCur + 3);
	    cbHeader = numMissing + 4;
	    break;

	default:
	    break;
    };
    if (fRID) {
	returned_length = g_snprintf(&szInfo[str_index], SZINFO_SIZE-str_index, " R" );
        str_index += MIN(returned_length, SZINFO_SIZE-str_index);
    };
    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: cbHeader = %d\n", cbHeader);
#endif
	/* NOTE - Length will be set when we process the TPI */
	ti = proto_tree_add_item(tree, proto_wtp, tvb, offCur, 0, bo_little_endian);
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: (7) Returned from proto_tree_add_item\n");
#endif
	wtp_tree = proto_item_add_subtree(ti, ett_wtp);

/* Code to process the packet goes here */
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: cbHeader = %d\n", cbHeader);
	fprintf(stderr, "dissect_wtp: offCur = %d\n", offCur);
#endif
	/* Add common items: only CON and PDU Type */
	proto_tree_add_item(
			wtp_tree,	 		/* tree */
			hf_wtp_header_flag_continue, 	/* id */
			tvb,
			offCur, 			/* start of highlight */
			1,				/* length of highlight*/
			b0				/* value */
	     );
	proto_tree_add_item(wtp_tree, hf_wtp_header_pdu_type, tvb, offCur, 1, bo_little_endian);

	switch(pdut) {
	    case INVOKE:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);

		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_version , tvb, offCur + 3, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_flag_TIDNew, tvb, offCur + 3, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_flag_UP, tvb, offCur + 3, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_Reserved, tvb, offCur + 3, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_TransactionClass, tvb, offCur + 3, 1, bo_little_endian);
		proto_item_append_text(ti,
				", PDU: Invoke (%u)"
				", Transaction Class: %s (%u)",
				INVOKE,
				val_to_str(clsTransaction, vals_transaction_classes, "Undefined"),
				clsTransaction);
		break;

	    case RESULT:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);
		proto_item_append_text(ti, ", PDU: Result (%u)", RESULT);
		break;

	    case ACK:
		proto_tree_add_item(wtp_tree, hf_wtp_header_Ack_flag_TVETOK, tvb, offCur, 1, bo_big_endian);

		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);
		proto_item_append_text(ti, ", PDU: ACK (%u)", ACK);
		break;

	    case ABORT:
		abortType = tvb_get_guint8 (tvb, offCur) & 0x07;
		proto_tree_add_item(wtp_tree, hf_wtp_header_Abort_type , tvb, offCur , 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);

		if (abortType == PROVIDER)
		{
			guint8 reason = tvb_get_guint8(tvb, offCur + 3);
		    proto_tree_add_item( wtp_tree, hf_wtp_header_Abort_reason_provider , tvb, offCur + 3 , 1, bo_little_endian);
			proto_item_append_text(ti,
					", PDU: Abort (%u)"
					", Type: Provider (%u)"
					", Reason: %s (%u)",
					ABORT,
					PROVIDER,
					val_to_str(reason, vals_abort_reason_provider, "Undefined"),
					reason);
		}
		else if (abortType == USER)
		{
			guint8 reason = tvb_get_guint8(tvb, offCur + 3);
		    proto_tree_add_item(wtp_tree, hf_wtp_header_Abort_reason_user , tvb, offCur + 3 , 1, bo_little_endian);
			proto_item_append_text(ti,
					", PDU: Abort (%u)"
					", Type: User (%u)"
					", Reason: %s (%u)",
					ABORT,
					PROVIDER,
					val_to_str_ext_const(reason, &vals_wsp_reason_codes_ext, "Undefined"),
					reason);
		}
		break;

	    case SEGMENTED_INVOKE:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);

		proto_tree_add_item(wtp_tree, hf_wtp_header_sequence_number , tvb, offCur + 3, 1, bo_little_endian);
		proto_item_append_text(ti,
				", PDU: Segmented Invoke (%u)"
				", Packet Sequence Number: %u",
				SEGMENTED_INVOKE, psn);
		break;

	    case SEGMENTED_RESULT:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);

		proto_tree_add_item(wtp_tree, hf_wtp_header_sequence_number , tvb, offCur + 3, 1, bo_little_endian);
		proto_item_append_text(ti,
				", PDU: Segmented Result (%u)"
				", Packet Sequence Number: %u",
				SEGMENTED_RESULT, psn);
		break;

	    case NEGATIVE_ACK:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian);

		proto_tree_add_item(wtp_tree, hf_wtp_header_missing_packets , tvb, offCur + 3, 1, bo_little_endian);
		/* Iterate through missing packets */
		for (i = 0; i < numMissing; i++)
		{
		    proto_tree_add_item(wtp_tree, hf_wtp_header_sequence_number, tvb, offCur + 4 + i, 1, bo_little_endian);
		}
		proto_item_append_text(ti,
				", PDU: Negative Ack (%u)"
				", Missing Packets: %u",
				NEGATIVE_ACK, numMissing);
		break;

	    default:
		break;
	};
	if (fRID) {
		proto_item_append_text(ti, ", Retransmission");
	}
    } else { /* tree is NULL */
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: (4) tree was %p\n", tree);
#endif
    }
	/* Process the variable part */
	if (fCon) {			/* Now, analyze variable part	*/
	    unsigned char	 tCon;
	    unsigned char	 tByte;
	    unsigned char	 tpiLen;
	    tvbuff_t		*tmp_tvb;

	    vHeader = 0;		/* Start scan all over	*/

	    do {
		tByte = tvb_get_guint8(tvb, offCur + cbHeader + vHeader);
		tCon = tByte & 0x80;
		if (tByte & 0x04)	/* Long TPI	*/
		    tpiLen = 2 + tvb_get_guint8(tvb,
					    offCur + cbHeader + vHeader + 1);
		else
		    tpiLen = 1 + (tByte & 0x03);
		if (tree)
		{
		tmp_tvb = tvb_new_subset(tvb, offCur + cbHeader + vHeader,
					tpiLen, tpiLen);
		wtp_handle_tpi(wtp_tree, tmp_tvb);
		}
		vHeader += tpiLen;
	    } while (tCon);
	} else {
		/* There is no variable part */
	}	/* End of variable part of header */

	/* Set the length of the WTP protocol part now we know the length of the
	 * fixed and variable WTP headers */
	if (tree)
	proto_item_set_len(ti, cbHeader + vHeader);

#ifdef DEBUG
    fprintf( stderr, "dissect_wtp: cbHeader = %d\n", cbHeader );
#endif

    /*
     * Any remaining data ought to be WSP data (if not WTP ACK, NACK
     * or ABORT pdu), so, if we have any remaining data, and it's
     * not an ACK, NACK, or ABORT PDU, hand it off (defragmented) to the
     * WSP dissector.
     * Note that the last packet of a fragmented WTP message needn't
     * contain any data, so we allow payloadless packets to be
     * reassembled.  (XXX - does the reassembly code handle this
     * for packets other than the last packet?)
     *
	 * Try calling a subdissector only if:
	 *	- The WTP payload is ressembled in this very packet,
	 *	- The WTP payload is not fragmented across packets.
	 */
    dataOffset = offCur + cbHeader + vHeader;
    dataLen = tvb_reported_length_remaining(tvb, dataOffset);
    if ((dataLen >= 0) &&
			! ((pdut==ACK) || (pdut==NEGATIVE_ACK) || (pdut==ABORT)))
    {
		/* Try to reassemble if needed, and hand over to WSP
		 * A fragmented WTP packet is either:
		 *	- An INVOKE with fTTR (transmission trailer) not set,
		 *	- a SEGMENTED_INVOKE,
		 *	- A RESULT with fTTR (transmission trailer) not set,
		 *	- a SEGMENTED_RESULT.
		 */
		if ( ( (pdut == SEGMENTED_INVOKE) || (pdut == SEGMENTED_RESULT)
				|| ( ((pdut == INVOKE) || (pdut == RESULT)) && (!fTTR) )
			) && tvb_bytes_exist(tvb, dataOffset, dataLen) )
		{
			/* Try reassembling fragments */
			fragment_data *fd_wtp = NULL;
			guint32 reassembled_in = 0;
			gboolean save_fragmented = pinfo->fragmented;

			pinfo->fragmented = TRUE;
			fd_wtp = fragment_add_seq(tvb, dataOffset, pinfo, TID,
					wtp_fragment_table, psn, dataLen, !fTTR);
			/* XXX - fragment_add_seq() yields NULL unless Wireshark knows
			 * that the packet is part of a reassembled whole. This means
			 * that fd_wtp will be NULL as long as Wireshark did not encounter
			 * (and process) the packet containing the last fragment.
			 * This implies that Wireshark needs two passes over the data for
			 * correct reassembly. At the first pass, a capture containing
			 * three fragments plus a retransmssion of the last fragment
			 * will progressively show:
			 *
			 *		Packet 1: (Unreassembled fragment 1)
			 *		Packet 2: (Unreassembled fragment 2)
			 *		Packet 3: (Reassembled WTP)
			 *		Packet 4: (WTP payload reassembled in packet 3)
			 *
			 * However at subsequent evaluation (e.g., by applying a display
			 * filter) the packet summary will show:
			 *
			 *		Packet 1: (WTP payload reassembled in packet 3)
			 *		Packet 2: (WTP payload reassembled in packet 3)
			 *		Packet 3: (Reassembled WTP)
			 *		Packet 4: (WTP payload reassembled in packet 3)
			 *
			 * This is important to know, and also affects read filters!
			 */
			wsp_tvb = process_reassembled_data(tvb, dataOffset, pinfo,
					"Reassembled WTP", fd_wtp, &wtp_frag_items,
					NULL, wtp_tree);
#ifdef DEBUG
			printf("WTP: Packet %u %s -> %d: wsp_tvb = %p, fd_wtp = %p, frame = %u\n",
					pinfo->fd->num,
					fd_wtp ? "Reassembled" : "Not reassembled",
					fd_wtp ? fd_wtp->reassembled_in : -1,
					wsp_tvb,
					fd_wtp
					);
#endif
			if (fd_wtp) {
				/* Reassembled */
				reassembled_in = fd_wtp->reassembled_in;
				if (pinfo->fd->num == reassembled_in) {
					/* Reassembled in this very packet:
					 * We can safely hand the tvb to the WSP dissector */
					call_dissector(wsp_handle, wsp_tvb, pinfo, tree);
				} else {
					/* Not reassembled in this packet */
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(pinfo->cinfo, COL_INFO,
								"%s (WTP payload reassembled in packet %u)",
								szInfo, fd_wtp->reassembled_in);
					}
					if (tree) {
						proto_tree_add_text(wtp_tree, tvb, dataOffset, -1,
								"Payload");
					}
				}
			} else {
				/* Not reassembled yet, or not reassembled at all */
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO,
								"%s (Unreassembled fragment %u)",
								szInfo, psn);
				}
				if (tree) {
					proto_tree_add_text(wtp_tree, tvb, dataOffset, -1,
							"Payload");
				}
			}
			/* Now reset fragmentation information in pinfo */
			pinfo->fragmented = save_fragmented;
		}
		else if ( ((pdut == INVOKE) || (pdut == RESULT)) && (fTTR) )
		{
			/* Non-fragmented payload */
			wsp_tvb = tvb_new_subset_remaining(tvb, dataOffset);
			/* We can safely hand the tvb to the WSP dissector */
			call_dissector(wsp_handle, wsp_tvb, pinfo, tree);
		}
		else
		{
			/* Nothing to hand to subdissector */
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_str(pinfo->cinfo, COL_INFO, szInfo);
		}
	}
	else
	{
		/* Nothing to hand to subdissector */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, szInfo);
	}
}

/*
 * Called directly from UDP.
 * Put "WTP+WSP" into the "Protocol" column.
 */
static void
dissect_wtp_fromudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WTP+WSP");
    col_clear(pinfo->cinfo, COL_INFO);

    dissect_wtp_common(tvb, pinfo, tree);
}

/*
 * Called from a higher-level WAP dissector, presumably WTLS.
 * Put "WTLS+WSP+WTP" to the "Protocol" column.
 *
 * XXX - is this supposed to be called from WTLS?  If so, we're not
 * calling it....
 *
 * XXX - can this be called from any other dissector?
 */
static void
dissect_wtp_fromwtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WTLS+WTP+WSP");
    col_clear(pinfo->cinfo, COL_INFO);

    dissect_wtp_common(tvb, pinfo, tree);
}

/* Register the protocol with Wireshark */
void
proto_register_wtp(void)
{

    /* Setup list of header fields */
    static hf_register_info hf[] = {
	{ &hf_wtp_header_sub_pdu_size,
	    { 	"Sub PDU size",
		"wtp.sub_pdu_size",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Size of Sub-PDU (bytes)", HFILL
	    }
	},
	{ &hf_wtp_header_flag_continue,
	    { 	"Continue Flag",
		"wtp.continue_flag",
		FT_BOOLEAN, 8, TFS( &continue_truth ), 0x80,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_pdu_type,
	    { 	"PDU Type",
		"wtp.pdu_type",
		FT_UINT8, BASE_HEX, VALS( vals_wtp_pdu_type ), 0x78,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_flag_Trailer,
	    { 	"Trailer Flags",
		"wtp.trailer_flags",
		FT_UINT8, BASE_HEX, VALS( vals_transaction_trailer ), 0x06,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_flag_RID,
	    { 	"Re-transmission Indicator",
		"wtp.RID",
		FT_BOOLEAN, 8, TFS( &RID_truth ), 0x01,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_flag_TID_response,
	    { 	"TID Response",
		"wtp.TID.response",
		FT_BOOLEAN, 16, TFS( &tid_response_truth ), 0x8000,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_flag_TID,
	    { 	"Transaction ID",
		"wtp.TID",
		FT_UINT16, BASE_HEX, NULL, 0x7FFF,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Inv_version,
	    { 	"Version",
		"wtp.header.version",
		FT_UINT8, BASE_HEX, VALS( vals_version ), 0xC0,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Inv_flag_TIDNew,
	    { 	"TIDNew",
		"wtp.header.TIDNew",
		FT_BOOLEAN, 8, TFS( &TIDNew_truth ), 0x20,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Inv_flag_UP,
	    { 	"U/P flag",
		"wtp.header.UP",
		FT_BOOLEAN, 8, TFS( &UP_truth ), 0x10,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Inv_Reserved,
	    { 	"Reserved",
		"wtp.inv.reserved",
		FT_UINT8, BASE_HEX, NULL, 0x0C,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Inv_TransactionClass,
	    { 	"Transaction Class",
		"wtp.inv.transaction_class",
		FT_UINT8, BASE_HEX, VALS( vals_transaction_classes ), 0x03,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Ack_flag_TVETOK,
	    { 	"Tve/Tok flag",
		"wtp.ack.tvetok",
		FT_BOOLEAN, 8, TFS( &TVETOK_truth ), 0x04,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Abort_type,
	    { 	"Abort Type",
		"wtp.abort.type",
		FT_UINT8, BASE_HEX, VALS ( vals_abort_type ), 0x07,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_Abort_reason_provider,
	    { 	"Abort Reason",
		"wtp.abort.reason.provider",
		FT_UINT8, BASE_HEX, VALS ( vals_abort_reason_provider ), 0x00,
		NULL, HFILL
	    }
	},
	/* Assume WSP is the user and use its reason codes */
	{ &hf_wtp_header_Abort_reason_user,
	    { 	"Abort Reason",
		"wtp.abort.reason.user",
		FT_UINT8, BASE_HEX|BASE_EXT_STRING, &vals_wsp_reason_codes_ext, 0x00,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_sequence_number,
	    { 	"Packet Sequence Number",
		"wtp.header.sequence",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_missing_packets,
	    { 	"Missing Packets",
		"wtp.header.missing_packets",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_header_variable_part,
	    { 	"Header: Variable part",
		"wtp.header_variable_part",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		"Variable part of the header", HFILL
	    }
	},
	{ &hf_wtp_data,
	    { 	"Data",
		"wtp.header_data",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_tpi_type,
	    { 	"TPI",
		"wtp.tpi",
		FT_UINT8, BASE_HEX, VALS(vals_tpi_type), 0x00,
		"Identification of the Transport Information Item", HFILL
	    }
	},
	{ &hf_wtp_tpi_psn,
	    { 	"Packet sequence number",
		"wtp.tpi.psn",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		"Sequence number of this packet", HFILL
	    }
	},
	{ &hf_wtp_tpi_opt,
	    { 	"Option",
		"wtp.tpi.opt",
		FT_UINT8, BASE_HEX, VALS(vals_tpi_opt), 0x00,
		"The given option for this TPI", HFILL
	    }
	},
	{ &hf_wtp_tpi_optval,
	    { 	"Option Value",
		"wtp.tpi.opt.val",
		FT_NONE, BASE_NONE, NULL, 0x00,
		"The value that is supplied with this option", HFILL
	    }
	},
	{ &hf_wtp_tpi_info,
	    { 	"Information",
		"wtp.tpi.info",
		FT_NONE, BASE_NONE, NULL, 0x00,
		"The information being send by this TPI", HFILL
	    }
	},

	/* Fragment fields */
	{ &hf_wtp_fragment_overlap,
	    {	"Fragment overlap",
		"wtp.fragment.overlap",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Fragment overlaps with other fragments", HFILL
	    }
	},
	{ &hf_wtp_fragment_overlap_conflict,
	    {	"Conflicting data in fragment overlap",
		"wtp.fragment.overlap.conflict",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Overlapping fragments contained conflicting data", HFILL
	    }
	},
	{ &hf_wtp_fragment_multiple_tails,
	    {	"Multiple tail fragments found",
		"wtp.fragment.multipletails",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Several tails were found when defragmenting the packet", HFILL
	    }
	},
	{ &hf_wtp_fragment_too_long_fragment,
	    {	"Fragment too long",
		"wtp.fragment.toolongfragment",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Fragment contained data past end of packet", HFILL
	    }
	},
	{ &hf_wtp_fragment_error,
	    {	"Defragmentation error",
		"wtp.fragment.error",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"Defragmentation error due to illegal fragments", HFILL
	    }
	},
	{ &hf_wtp_fragment_count,
	    {	"Fragment count",
		"wtp.fragment.count",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_reassembled_in,
	    {	"Reassembled in",
		"wtp.reassembled.in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"WTP fragments are reassembled in the given packet", HFILL
	    }
	},
	{ &hf_wtp_reassembled_length,
	    {	"Reassembled WTP length",
		"wtp.reassembled.length",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"The total length of the reassembled payload", HFILL
	    }
	},
	{ &hf_wtp_fragment,
	    {	"WTP Fragment",
		"wtp.fragment",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		NULL, HFILL
	    }
	},
	{ &hf_wtp_fragments,
	    {	"WTP Fragments",
		"wtp.fragments",
		FT_NONE, BASE_NONE, NULL, 0x0,
		NULL, HFILL
	    }
	},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_wtp,
	&ett_wtp_sub_pdu_tree,
	&ett_header,
	&ett_tpilist,
	&ett_wsp_fragments,
	&ett_wtp_fragment,
    };

    /* Register the protocol name and description */
    proto_wtp = proto_register_protocol(
	"Wireless Transaction Protocol",   /* protocol name for use by wireshark */
	"WTP",                             /* short version of name */
	"wtp"                      /* Abbreviated protocol name, should Match IANA
					    < URL:http://www.iana.org/assignments/port-numbers/ >
					    */
    );

    /* Required calls to register the header fields and subtrees used */
    proto_register_field_array(proto_wtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("wtp-wtls", dissect_wtp_fromwtls, proto_wtp);
    register_dissector("wtp-udp", dissect_wtp_fromudp, proto_wtp);
    register_init_routine(wtp_defragment_init);
}

void
proto_reg_handoff_wtp(void)
{
    dissector_handle_t wtp_fromudp_handle;

    /*
     * Get a handle for the connection-oriented WSP dissector - if WTP
     * PDUs have data, it is WSP.
     */
    wsp_handle = find_dissector("wsp-co");

    wtp_fromudp_handle = find_dissector("wtp-udp");
    dissector_add_uint("udp.port", UDP_PORT_WTP_WSP, wtp_fromudp_handle);
    dissector_add_uint("gsm-sms-ud.udh.port", UDP_PORT_WTP_WSP, wtp_fromudp_handle);
	dissector_add_uint("gsm-sms.udh.port", UDP_PORT_WTP_WSP, wtp_fromudp_handle);
}
