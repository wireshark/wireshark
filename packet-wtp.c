/* packet-wtp.c
 *
 * Routines to dissect WTP component of WAP traffic.
 * 
 * $Id: packet-wtp.c,v 1.20 2001/10/07 08:37:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
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

static const value_string vals_pdu_type[] = {
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

/* File scoped variables for the protocol and registered fields */
static int proto_wtp 							= HF_EMPTY;

/* These fields used by fixed part of header */
static int hf_wtp_header_fixed_part 			= HF_EMPTY;
static int hf_wtp_header_sub_pdu_size 			= HF_EMPTY;
static int hf_wtp_header_flag_continue 			= HF_EMPTY;
static int hf_wtp_header_pdu_type 				= HF_EMPTY;
static int hf_wtp_header_flag_Trailer 			= HF_EMPTY;
static int hf_wtp_header_flag_RID 				= HF_EMPTY;
static int hf_wtp_header_flag_TID 				= HF_EMPTY;
static int hf_wtp_header_flag_TID_response 		= HF_EMPTY;

/* These fields used by Invoke packets */
static int hf_wtp_header_Inv_version 			= HF_EMPTY;
static int hf_wtp_header_Inv_flag_TIDNew	 	= HF_EMPTY;
static int hf_wtp_header_Inv_flag_UP	 		= HF_EMPTY;
static int hf_wtp_header_Inv_Reserved	 		= HF_EMPTY;
static int hf_wtp_header_Inv_TransactionClass 	= HF_EMPTY;


static int hf_wtp_header_variable_part 			= HF_EMPTY;
static int hf_wtp_data 							= HF_EMPTY;

static int hf_wtp_header_Ack_flag_TVETOK		= HF_EMPTY;
static int hf_wtp_header_Abort_type				= HF_EMPTY;
static int hf_wtp_header_Abort_reason_provider	= HF_EMPTY;
static int hf_wtp_header_Abort_reason_user		= HF_EMPTY;
static int hf_wtp_header_sequence_number		= HF_EMPTY;
static int hf_wtp_header_missing_packets		= HF_EMPTY;

/* Initialize the subtree pointers */
static gint ett_wtp 							= ETT_EMPTY;
static gint ett_header 							= ETT_EMPTY;

/* Handle for WSP dissector */
static dissector_handle_t wsp_handle;

/* Declarations */
static char transaction_class(unsigned char octet);
static char pdu_type(unsigned char octet);
static char retransmission_indicator(unsigned char octet);

/* Code to actually dissect the packets */
static void
dissect_wtp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	frame_data *fdata = pinfo->fd;

	char szInfo[ 50 ];
	int offCur 			= 0; /* current offset from start of WTP data */

	/* bytes at offset 0 - 3 */
	/*
	unsigned char  b0 = pd[offset + 0];
	unsigned char  b3 = pd[offset + 3];
	*/
	unsigned char  b0;

	/* continuation flag */
	unsigned char  	fCon;
	unsigned char  	fRID;
	guint 		cbHeader   	= 0;
	guint 		vHeader   	= 0;
	int 		abortType  	= 0;

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wtp_tree = NULL;
	proto_tree *wtp_header_fixed;
	
	char pdut;
	char clsTransaction 		= ' ';
	int cchInfo;
	int numMissing = 0;		/* Number of missing packets in a negative ack */
	int i;
	tvbuff_t *wsp_tvb = NULL;

#ifdef DEBUG
	fprintf( stderr, "dissect_wtp: (Entering) Frame data at %p\n", fdata ); 
	fprintf( stderr, "dissect_wtp: tvb length is %d\n", tvb_reported_length( tvb ) ); 
#endif
	b0 = tvb_get_guint8 (tvb, offCur + 0);
	/* Discover Concatenated PDUs */
	if (b0 == 0) {
		if (tree) {
			wtp_tree = proto_tree_add_item(tree, proto_wtp, tvb, offCur, 1, bo_little_endian);
		}
		offCur = 1;
		i = 1;
		while (offCur < (int) tvb_reported_length (tvb)) {
			b0 = tvb_get_guint8 (tvb, offCur + 0);
			if (b0 & 0x80) {
				vHeader = 2;
				cbHeader = ((b0 & 0x7f) << 8) |
							tvb_get_guint8 (tvb, offCur + 1);
			} else {
				vHeader = 1;
				cbHeader = b0;
			}
		    if (tree) {
				proto_tree_add_item(wtp_tree, hf_wtp_header_sub_pdu_size, tvb, offCur, vHeader, bo_big_endian);
			}
			if (i > 1 && check_col(fdata, COL_INFO)) {
				col_append_str (fdata, COL_INFO, ", ");
			}
			wsp_tvb = tvb_new_subset(tvb,
				offCur + vHeader, -1, cbHeader);
			dissect_wtp_common (wsp_tvb, pinfo, wtp_tree);
			offCur += vHeader + cbHeader;
			i++;
		}
		return;
	}
	fCon = b0 & 0x80;
	fRID = retransmission_indicator( b0 );
	pdut = pdu_type( b0 );

	/* Develop the string to put in the Info column */
	cchInfo = snprintf( szInfo, sizeof( szInfo ), "WTP %s",
	    val_to_str(pdut, vals_pdu_type, "Unknown PDU type 0x%x"));

	switch( pdut ) {
		case INVOKE:
			clsTransaction = transaction_class( tvb_get_guint8 (tvb, offCur + 3) );
			snprintf( szInfo + cchInfo, sizeof( szInfo ) - cchInfo, " Class %d", clsTransaction  );

		case ABORT:
		case SEGMENTED_INVOKE:
		case SEGMENTED_RESULT:
			cbHeader = 4;
			break;

		case RESULT:
		case ACK:
			cbHeader = 3;
			break;

		case NEGATIVE_ACK:
			/* Varible number of missing packets */
			numMissing = tvb_get_guint8 (tvb, offCur + 3);
			cbHeader = numMissing + 4;
			break;

		default:
			break;
	};

	if( fRID ) {
		strcat( szInfo, " R" );
	};
	if( fCon ) {
		unsigned char	tCon;
		unsigned char	tByte;

		do {
			tByte = tvb_get_guint8(tvb, offCur + cbHeader + vHeader);
			tCon = tByte & 0x80;
			if (tByte & 0x04)
				vHeader = vHeader + tvb_get_guint8(tvb,
					offCur + cbHeader + vHeader + 1) + 2;
			else
				vHeader = vHeader + (tByte & 0x03) + 1;
		} while (tCon);
	}

#ifdef DEBUG
	fprintf( stderr, "dissect_wtp: cbHeader = %d\n", cbHeader );  
#endif

/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. */
	if (check_col(fdata, COL_INFO) &&
		tvb_reported_length (tvb) <= cbHeader + vHeader) {
#ifdef DEBUG
		fprintf( stderr, "dissect_wtp: (6) About to set info_col header to %s\n", szInfo );
#endif
		col_append_str(fdata, COL_INFO, szInfo );
	};
/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
#ifdef DEBUG
		fprintf( stderr, "dissect_wtp: cbHeader = %d\n", cbHeader );  
#endif
		ti = proto_tree_add_item(tree, proto_wtp, tvb, offCur, cbHeader + vHeader, bo_little_endian);
#ifdef DEBUG
		fprintf( stderr, "dissect_wtp: (7) Returned from proto_tree_add_item\n" );  
#endif
	        wtp_tree = proto_item_add_subtree(ti, ett_wtp);

/* Code to process the packet goes here */
		{
#ifdef DEBUG
			fprintf( stderr, "dissect_wtp: cbHeader = %d\n", cbHeader );  
			fprintf( stderr, "dissect_wtp: offCur = %d\n", offCur );  
			fprintf( stderr, "dissect_wtp: About to call proto_tree_add_item with %p %d %p %d %d %d\n", 
					wtp_tree, hf_wtp_header_fixed_part, tvb, offCur, cbHeader, bo_little_endian ); 
			ti = proto_tree_add_item( wtp_tree, hf_wtp_header_fixed_part, tvb, offCur, cbHeader, bo_little_endian );
			fprintf( stderr, "dissect_wtp: (6) Returned from proto_tree_add_item\n" );  
#endif
			wtp_header_fixed = proto_item_add_subtree(
					ti, 
					ett_header 
				);

			/* Add common items: only CON and PDU Type */
			ti = proto_tree_add_item(
					wtp_header_fixed, 		/* tree */
					hf_wtp_header_flag_continue, 	/* id */
					tvb, 
					offCur, 			/* start of high light */
					1,				/* length of high light */
					b0				/* value */
			     );
			ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_pdu_type, tvb, offCur, 1, bo_little_endian );

			switch( pdut ) {
				case INVOKE:
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );

					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Inv_version , tvb, offCur + 3, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Inv_flag_TIDNew, tvb, offCur + 3, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Inv_flag_UP, tvb, offCur + 3, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Inv_Reserved, tvb, offCur + 3, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Inv_TransactionClass, tvb, offCur + 3, 1, bo_little_endian );
					break;

				case RESULT:
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );
					break;

				case ACK:
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Ack_flag_TVETOK, tvb, offCur, 1, bo_big_endian );

					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );
					break;

				case ABORT:
					abortType = tvb_get_guint8 (tvb, offCur) & 0x07;
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Abort_type , tvb, offCur , 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );

					if (abortType == PROVIDER)
					{
						ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Abort_reason_provider , tvb, offCur + 3 , 1, bo_little_endian );
					}
					else if (abortType == USER)
					{
						ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_Abort_reason_user , tvb, offCur + 3 , 1, bo_little_endian );
					}
					break;

				case SEGMENTED_INVOKE:
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );

					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_sequence_number , tvb, offCur + 3, 1, bo_little_endian );
					break;

				case SEGMENTED_RESULT:
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_Trailer, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );

					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_sequence_number , tvb, offCur + 3, 1, bo_little_endian );
					break;

				case NEGATIVE_ACK:
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_RID, tvb, offCur, 1, bo_little_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, bo_big_endian );
					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, bo_big_endian );

					ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_missing_packets , tvb, offCur + 3, 1, bo_little_endian );
					/* Iterate through missing packets */
					for (i=0; i<numMissing; i++)
					{
						ti = proto_tree_add_item( wtp_header_fixed, hf_wtp_header_sequence_number , tvb, offCur + i, 1, bo_little_endian );
					}
					break;

				default:
					break;
			};

			if( fCon ) {
				/* There is a variable part if the Con flag is set */ 
				ti = proto_tree_add_bytes_format(
						wtp_tree, 			/* tree */
						hf_wtp_header_variable_part, 	/* id */
						tvb, 
						offCur + cbHeader,		/* start */
						vHeader,			/* length */
						"What should go here!",		/* value */
						"Header (Variable part) %02X %02X %02X %02X"  ,			/* format */
						0, 1, 2, 3
				    );
			} else {
				/* There is no variable part */
			}; /* End of variable part of header */
		}
	} else {
#ifdef DEBUG
		fprintf( stderr, "dissect_wtp: (4) tree was %p\n", tree ); 
#endif
	}

	/* Any remaining data ought to be WSP data,
	 * so hand off to the WSP dissector */
	if (tvb_reported_length (tvb) > cbHeader + vHeader)
	{
		wsp_tvb = tvb_new_subset(tvb, cbHeader + vHeader, -1,
			tvb_reported_length (tvb)-cbHeader-vHeader);
		call_dissector(wsp_handle, wsp_tvb, pinfo, tree);
	}

#ifdef DEBUG
	fprintf( stderr, "dissect_wtp: (leaving) fdata->cinfo is %p\n", fdata->cinfo ); 
#endif
}

/*
 * Called directly from UDP.
 * Put "WTP+WSP" into the "Protocol" column.
 */
void
dissect_wtp_fromudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "WTP+WSP" );
	if (check_col(pinfo->fd, COL_INFO)) {
		col_clear(pinfo->fd, COL_INFO);
	}

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
dissect_wtp_fromwap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "WTLS+WTP+WSP" );
	if (check_col(pinfo->fd, COL_INFO)) {
		col_clear(pinfo->fd, COL_INFO);
	}

	dissect_wtp_common(tvb, pinfo, tree);
}

static char pdu_type(unsigned char octet)
{
	char ch = (octet >> 3) & 0x0F;
	/* Note pdu type must not be 0x00 */
	return ch;
};

static char transaction_class(unsigned char octet)
{
	char ch = (octet >> 0) & 0x03; /* ......XX */
	return ch;
};

static char retransmission_indicator(unsigned char octet)
{
	switch ( pdu_type(octet) ) {
		case INVOKE:
		case RESULT:
		case ACK:
		case SEGMENTED_INVOKE:
		case SEGMENTED_RESULT:
		case NEGATIVE_ACK:
			return (octet >> 0) & 0x01; /* ......,X */
		default:
			return 0;
	}
};

/* Register the protocol with Ethereal */
void
proto_register_wtp(void)
{                 

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_wtp_header_fixed_part,
			{ 	"Header",           
				"wtp.header_fixed_part",
				FT_BYTES, BASE_HEX, NULL, 0x0,          
				"Fixed part of the header", HFILL
			}
		},
		{ &hf_wtp_header_sub_pdu_size,
			{ 	"Sub PDU size",           
				"wtp.sub_pdu_size",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				"Size of Sub-PDU", HFILL
			}
		},
		{ &hf_wtp_header_flag_continue,
			{ 	"Continue Flag",           
				"wtp.continue_flag",
				FT_BOOLEAN, 8, TFS( &continue_truth ), 0x80,          
				"Continue Flag", HFILL
			}
		},
		{ &hf_wtp_header_pdu_type,
			{ 	"PDU Type",           
				"wtp.pdu_type",
				 FT_UINT8, BASE_HEX, VALS( vals_pdu_type ), 0x78,
				"PDU Type", HFILL
			}
		},
		{ &hf_wtp_header_flag_Trailer,
			{ 	"Trailer Flags",           
				"wtp.trailer_flags",
				 FT_UINT8, BASE_HEX, VALS( vals_transaction_trailer ), 0x06,
				"Trailer Flags", HFILL
			}
		},
		{ &hf_wtp_header_flag_RID,
			{ 	"Re-transmission Indicator",           
				"wtp.RID",
				 FT_BOOLEAN, 8, TFS( &RID_truth ), 0x01,
				"Re-transmission Indicator", HFILL
			}
		},
		{ &hf_wtp_header_flag_TID_response,
			{ 	"TID Response",           
				"wtp.TID.response",
				FT_BOOLEAN, 16, TFS( &tid_response_truth ), 0x8000,
				"TID Response", HFILL
			}
		},
		{ &hf_wtp_header_flag_TID,
			{ 	"Transaction ID",           
				"wtp.TID",
				 FT_UINT16, BASE_HEX, NULL, 0x7FFF,
				"Transaction ID", HFILL
			}
		},
		{ &hf_wtp_header_Inv_version,
			{ 	"Version",           
				"wtp.header.version",
				 FT_UINT8, BASE_HEX, VALS( vals_version ), 0xC0,
				"Version", HFILL
			}
		},
		{ &hf_wtp_header_Inv_flag_TIDNew,
			{ 	"TIDNew",           
				"wtp.header.TIDNew",
				 FT_BOOLEAN, 8, TFS( &TIDNew_truth ), 0x20,
				"TIDNew", HFILL
			}
		},
		{ &hf_wtp_header_Inv_flag_UP,
			{ 	"U/P flag",           
				"wtp.header.UP",
				 FT_BOOLEAN, 8, TFS( &UP_truth ), 0x10,
				"U/P Flag", HFILL
			}
		},
		{ &hf_wtp_header_Inv_Reserved,
			{ 	"Reserved",           
				"wtp.inv.reserved",
				 FT_UINT8, BASE_HEX, NULL, 0x0C,
				"Reserved", HFILL
			}
		},
		{ &hf_wtp_header_Inv_TransactionClass,
			{ 	"Transaction Class",           
				"wtp.inv.transaction_class",
				 FT_UINT8, BASE_HEX, VALS( vals_transaction_classes ), 0x03,
				"Transaction Class", HFILL
			}
		},
		{ &hf_wtp_header_Ack_flag_TVETOK,
			{ 	"Tve/Tok flag",           
				"wtp.ack.tvetok",
				 FT_BOOLEAN, 8, TFS( &TVETOK_truth ), 0x04,
			 	"Tve/Tok flag", HFILL
			}
		},
		{ &hf_wtp_header_Abort_type,
			{ 	"Abort Type",           
				"wtp.abort.type",
				 FT_UINT8, BASE_HEX, VALS ( vals_abort_type ), 0x07,
				"Abort Type", HFILL
			}
		},
		{ &hf_wtp_header_Abort_reason_provider,
			{ 	"Abort Reason",           
				"wtp.abort.reason.provider",
				 FT_UINT8, BASE_HEX, VALS ( vals_abort_reason_provider ), 0x00,
				"Abort Reason", HFILL
			}
		},
		/* Assume WSP is the user and use its reason codes */
		{ &hf_wtp_header_Abort_reason_user,
			{ 	"Abort Reason",           
				"wtp.abort.reason.user",
				 FT_UINT8, BASE_HEX, VALS ( vals_wsp_reason_codes ), 0x00,
				"Abort Reason", HFILL
			}
		},
		{ &hf_wtp_header_sequence_number,
			{ 	"Packet Sequence Number",           
				"wtp.header.sequence",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Packet Sequence Number", HFILL
			}
		},
		{ &hf_wtp_header_missing_packets,
			{ 	"Missing Packets",           
				"wtp.header.missing_packets",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Missing Packets", HFILL
			}
		},
		{ &hf_wtp_header_variable_part,
			{ 	"Header: Variable part",           
				"wtp.header_variable_part",
				FT_BYTES, BASE_HEX, NULL, 0x0,          
				"Variable part of the header", HFILL
			}
		},
		{ &hf_wtp_data,
			{ 	"Data",           
				"wtp.header_data",
				FT_BYTES, BASE_HEX, NULL, 0x0,          
				"Data", HFILL
			}
		},
	};
	
/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wtp,
		&ett_header,
	};

/* Register the protocol name and description */
	proto_wtp = proto_register_protocol(
		"Wireless Transaction Protocol",   /* protocol name for use by ethereal */ 
		"WTP",                             /* short version of name */
		"wap-wsp-wtp"                      /* Abbreviated protocol name, should Match IANA 
						    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
						  */
	);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_wtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wtp", dissect_wtp_fromwap, proto_wtp);
};

void
proto_reg_handoff_wtp(void)
{
	/*
	 * Get a handle for the connection-oriented WSP dissector - if WTP
	 * PDUs have data, it is WSP.
	 */
	wsp_handle = find_dissector("wsp-co");

	dissector_add("udp.port", UDP_PORT_WTP_WSP, dissect_wtp_fromudp,
	    proto_wtp);
}
