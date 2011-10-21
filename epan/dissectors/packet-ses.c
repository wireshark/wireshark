/* packet-ses.c
*
* Routine to dissect ITU-T Rec. X.225 (1995 E)/ISO 8327-1 OSI Session Protocol packets
*
* $Id$
*
* Yuriy Sidelnikov <YSidelnikov@hotmail.com>
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>

#include "packet-ber.h"
#include "packet-ses.h"
#include "packet-frame.h"

/* #include <epan/prefs.h> */
#include <epan/emem.h>
#include <epan/strutil.h>

/* ses header fields             */
static int proto_ses          = -1;
static int hf_ses_type        = -1;
static int hf_ses_type_0      = -1;
static int hf_ses_length      = -1;
static int hf_ses_version     = -1;
static int hf_ses_reserved    = -1;

static int hf_ses_segment_data = -1;
static int hf_ses_segments = -1;
static int hf_ses_segment = -1;
static int hf_ses_segment_overlap = -1;
static int hf_ses_segment_overlap_conflicts = -1;
static int hf_ses_segment_multiple_tails = -1;
static int hf_ses_segment_too_long_segment = -1;
static int hf_ses_segment_error = -1;
static int hf_ses_segment_count = -1;
static int hf_ses_reassembled_in = -1;
static int hf_ses_reassembled_length = -1;

/* ses fields defining a sub tree */
static gint ett_ses           = -1;
static gint ett_ses_param     = -1;

static gint ett_ses_segment = -1;
static gint ett_ses_segments = -1;


/* flags */
static int hf_connect_protocol_options_flags = -1;
static int hf_version_number_options_flags = -1;
static int hf_enclosure_item_options_flags = -1;
static int hf_token_item_options_flags = -1;

static gint ett_connect_protocol_options_flags = -1;
static gint ett_protocol_version_flags = -1;
static gint ett_enclosure_item_flags = -1;
static gint ett_token_item_flags = -1;
static gint ett_ses_req_options_flags = -1;

/* called SS user reference */
static int hf_called_ss_user_reference = -1;

/* calling SS user reference */
static int hf_calling_ss_user_reference = -1;

/* common reference */
static int hf_common_reference = -1;

/* additional reference information */
static int hf_additional_reference_information = -1;

/* token item */
static int hf_release_token = -1;
static int hf_major_activity_token = -1;
static int hf_synchronize_minor_token = -1;
static int hf_data_token = -1;

/* protocol options */
static int hf_able_to_receive_extended_concatenated_SPDU = -1;

/* session requirement */
static int hf_session_user_req_flags = -1;
static int hf_session_exception_report= -1;
static int hf_data_separation_function_unit= -1;
static int hf_symmetric_synchronize_function_unit= -1;
static int hf_typed_data_function_unit= -1;
static int hf_exception_function_unit= -1;
static int hf_capability_function_unit=-1;
static int hf_negotiated_release_function_unit= -1;
static int hf_activity_management_function_unit= -1;
static int hf_resynchronize_function_unit= -1;
static int hf_major_resynchronize_function_unit= -1;
static int hf_minor_resynchronize_function_unit= -1;
static int hf_expedited_data_resynchronize_function_unit= -1;
static int hf_duplex_function_unit= -1;
static int hf_half_duplex_function_unit = -1;

/* TSDU maximum size */
static int hf_proposed_tsdu_maximum_size_i2r = -1;
static int hf_proposed_tsdu_maximum_size_r2i = -1;

/* protocol version */
static int hf_protocol_version_1 = -1;
static int hf_protocol_version_2 = -1;

/* initial serial number */
static int hf_initial_serial_number = -1;

/* enclosure item */
static int hf_beginning_of_SSDU = -1;
static int hf_end_of_SSDU = -1;

/* token setting item */

static const value_string token_setting_vals[] = {
	{ 0x00, "initiator's side" },
	{ 0x01, "responder's side" },
	{ 0x02, "called SS user's choice" },
	{ 0x03, "reserved" },
	{ 0, NULL }
};

static int hf_release_token_setting = -1;
static int hf_major_activity_token_setting = -1;
static int hf_synchronize_minor_token_setting = -1;
static int hf_data_token_setting = -1;

/* calling session selector */
static int hf_calling_session_selector = -1;

/* called session selector */
static int hf_called_session_selector = -1;

/* activity id */
static int hf_activity_identifier = -1;

/* serial number */
static int hf_serial_number = -1;

/* second serial number */
static int hf_second_serial_number = -1;

/* second initial serial number */
static int hf_second_initial_serial_number = -1;

/* large initial serial number */
static int hf_large_initial_serial_number = -1;

/* large second initial serial number */
static int hf_large_second_initial_serial_number = -1;

/* clses header fields             */
static int proto_clses          = -1;

#define PROTO_STRING_CLSES "ISO 9548-1 OSI Connectionless Session Protocol"

static dissector_handle_t pres_handle = NULL;

static GHashTable *ses_fragment_table = NULL;
static GHashTable *ses_reassembled_table = NULL;

static const fragment_items ses_frag_items = {
  /* Segment subtrees */
  &ett_ses_segment,
  &ett_ses_segments,
  /* Segment fields */
  &hf_ses_segments,
  &hf_ses_segment,
  &hf_ses_segment_overlap,
  &hf_ses_segment_overlap_conflicts,
  &hf_ses_segment_multiple_tails,
  &hf_ses_segment_too_long_segment,
  &hf_ses_segment_error,
  &hf_ses_segment_count,
  /* Reassembled in field */
  &hf_ses_reassembled_in,
  /* Reassembled length field */
  &hf_ses_reassembled_length,
  /* Tag */
  "SES segments"
};


const value_string ses_vals[] =
{
  {SES_CONNECTION_REQUEST,		"CONNECT (CN) SPDU" },			/* 13 */
  {SES_CONNECTION_ACCEPT,		"ACCEPT (AC) SPDU" },			/* 14 */
  {SES_EXCEPTION_REPORT,		"EXCEPTION REPORT (ER) SPDU"   },	/*  0 */
  {SES_DATA_TRANSFER,			"DATA TRANSFER (DT) SPDU" },		/*  1 */
  {SES_PLEASE_TOKENS,			"PLEASE TOKENS (PT) SPDU"   },		/*  2 */
  {SES_EXPEDITED,			"EXPEDITED (EX) SPDU"   },		/*  5 */
  {SES_PREPARE,				"PREPARE (PR) SPDU"   },		/*  7 */
  {SES_NOT_FINISHED,			"NOT FINISHED (NF) SPDU"   },		/*  8 */
  {SES_FINISH,				"FINISH (FN) SPDU"   },			/*  9 */
  {SES_DISCONNECT,			"DISCONNECT (DN) SPDU"   },		/* 10 */
  {SES_REFUSE,				"REFUSE (RF) SPDU"   },			/* 12 */
  {SES_CONNECTION_DATA_OVERFLOW,	"CONNECT DATA OVERFLOW (CDO) SPDU"},	/* 15 */
  {SES_OVERFLOW_ACCEPT,			"OVERFLOW ACCEPT (OA) SPDU"   },	/* 16 */
  {SES_GIVE_TOKENS_CONFIRM,		"GIVE TOKENS CONFIRM (GTC) SPDU"},	/* 21 */
  {SES_GIVE_TOKENS_ACK,			"GIVE TOKENS ACK (GTA) SPDU"   },	/* 22 */
  {SES_ABORT,				"ABORT (AB) SPDU"   },			/* 25 */
  {SES_ABORT_ACCEPT,			"ABORT ACCEPT (AA) SPDU"   },		/* 26 */
  {SES_ACTIVITY_RESUME,			"ACTIVITY RESUME (AR) SPDU"   },	/* 29 */
  {SES_TYPED_DATA,			"TYPED DATA (TD) SPDU"   },		/* 33 */
  {SES_RESYNCHRONIZE_ACK,		"RESYNCHRONIZE ACK (RA) SPDU"   },	/* 34 */
  {SES_MAJOR_SYNC_POINT,		"MAJOR SYNC POINT (MAP) SPDU"   },	/* 41 */
  {SES_MAJOR_SYNC_ACK,			"MAJOR SYNC ACK (MAA) SPDU"   },	/* 42 */
  {SES_ACTIVITY_START,			"ACTIVITY START (AS) SPDU"   },		/* 45 */
  {SES_EXCEPTION_DATA,			"EXCEPTION DATA (ED) SPDU"   },		/* 48 */
  {SES_MINOR_SYNC_POINT,		"MINOR SYNC POINT (MIP) SPDU"   },	/* 49 */
  {SES_MINOR_SYNC_ACK,			"MINOR SYNC ACK (MIA) SPDU"   },	/* 50 */
  {SES_RESYNCHRONIZE,			"RESYNCHRONIZE (RS) SPDU"   },		/* 53 */
  {SES_ACTIVITY_DISCARD,		"ACTIVITY DISCARD (AD) SPDU"   },	/* 57 */
  {SES_ACTIVITY_DISCARD_ACK,		"ACTIVITY DISCARD ACK (ADA) SPDU" },	/* 58 */
  {SES_CAPABILITY,			"CAPABILITY DATA (CD) SPDU"   },	/* 61 */
  {SES_CAPABILITY_DATA_ACK,		"CAPABILITY DATA ACK (CDA) SPDU" },	/* 62 */
  {CLSES_UNIT_DATA,			"UNIT DATA (UD) SPDU" },		/* 64 */
  {0,					NULL }
};

static const value_string ses_category0_vals[] =
{
  {SES_PLEASE_TOKENS,	"Please tokens PDU" },
  {SES_GIVE_TOKENS,	"Give tokens PDU" },
  {0,			NULL }
};


static const value_string param_vals[] =
{
  {Connection_Identifier, "Connection Identifier"},
  {Connect_Accept_Item, "Connect Accept Item"},
  {Called_SS_user_Reference, "Called SS user Reference"},
  {Calling_SS_user_Reference, "Calling SS user Reference"},
  {Common_Reference, "Common Reference"},
  {Sync_Type_Item, "Sync Type Item"},
  {Token_Item, "Token Item"},
  {Transport_Disconnect, "Transport_Disconnect"},
  {Additional_Reference_Information, "Additional Reference Information"},
  {Protocol_Options, "Protocol Options"},
  {TSDU_Maximum_Size, "TSDU Maximum Size"},
  {Version_Number, "Version Number"},
  {Initial_Serial_Number, "Initial Serial Number"},
  {Prepare_Type, "Prepare Type"},
  {EnclosureItem, "Enclosure Item"},
  {Token_Setting_Item, "Token Setting Item"},
  {Resync_Type, "Resync Type"},
  {Activity_Identifier, "Activity Identifier"},
  {Serial_Number, "Serial Number"},
  {Linking_Information, "Linking Information"},
  {Reflect_Parameter, "Reflect Parameter"},
  {Reason_Code, "Reason Code"},
  {Calling_Session_Selector, "Calling Session Selector"},
  {Called_Session_Selector, "Called Session Selector"},
  {Second_Resync_Type, "Second Resync Type"},
  {Second_Serial_Number, "Second Serial Number"},
  {Second_Initial_Serial_Number, "Second Initial Serial Number"},
  {Upper_Limit_Serial_Number, "Upper Limit Serial Number"},
  {Large_Initial_Serial_Number, "Large Initial Serial Number"},
  {Large_Second_Initial_Serial_Number, "Large Second Initial Serial Number"},
  {Data_Overflow, "Data Overflow"},
  {Session_Requirement, "Session Requirement"},
  {User_Data, "Session user data"},
  {Extended_User_Data, "Session extended user data"},
  {0, NULL}
};

static const value_string reason_vals[] =
{
  {reason_not_specified,  "Rejection by called SS-user; reason not specified" },
  {temporary_congestion,    "Rejection by called SS-user due to temporary congestion"   },
  {Subsequent,    "Rejection by called SS-user."   },
  {Session_Selector_unknown,  "Session Selector unknown" },
  {SS_user_not_attached_to_SSAP,    "SS-user not attached to SSAP"   },
  {SPM_congestion_at_connect_time,    "SPM congestion at connect time"   },
  {versions_not_supported,    "Proposed protocol versions not supported"   },
  {SPM_reason_not_specified,    "Rejection by the SPM; reason not specified"   },
  {SPM_implementation_restriction,    "Finish PDU"   },
  {SES_DISCONNECT,    "Rejection by the SPM; implementation restriction stated in the PICS"   },
  {0,             NULL           }
};

/* desegmentation of OSI over ses  */
static gboolean ses_desegment = TRUE;

/* RTSE reassembly data */
static guint ses_pres_ctx_id = 0;
static gboolean ses_rtse_reassemble = FALSE;

/* find the dissector for data */
static dissector_handle_t data_handle;

static void
call_pres_dissector(tvbuff_t *tvb, int offset, guint16 param_len,
		    packet_info *pinfo, proto_tree *tree,
		    proto_tree *param_tree,
		    struct SESSION_DATA_STRUCTURE *session)
{
	void *saved_private_data;

	/* do we have OSI presentation packet dissector ? */
	if(!pres_handle)
	{
		/* No - display as data */
		if (tree)
		{
			proto_tree_add_text(param_tree, tvb, offset, param_len,
			    "User data");
		}
	}
	else
	{
		/* Yes - call presentation dissector */
		tvbuff_t *next_tvb;

		next_tvb = tvb_new_subset(tvb, offset, param_len, param_len);
		/*   save type of session pdu. We'll need it in the presentation dissector  */
		saved_private_data = pinfo->private_data;
		pinfo->private_data = session;
		TRY
		{
			call_dissector(pres_handle, next_tvb, pinfo, tree);
		}
		CATCH_ALL
		{
			show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
		}
		ENDTRY;
		/* Restore private_data even if there was an exception */
		pinfo->private_data = saved_private_data;
	}
}

/* this routine returns length of parameter field, parameter group,
   or parameter */
static int
get_item_len(tvbuff_t *tvb, int offset, int *len_len)
{
	guint16 len;

	len = tvb_get_guint8(tvb, offset);
	if(len == TWO_BYTE_LEN)
	{
		len = tvb_get_ntohs(tvb, offset+1);
		*len_len = 3;
	}
	else
		*len_len = 1;
	return len;
}

static gboolean
dissect_parameter(tvbuff_t *tvb, int offset, proto_tree *tree,
	          proto_tree *param_tree, packet_info *pinfo, guint8 param_type,
	          guint16 param_len, guint8 *enclosure_item_flags,
		  struct SESSION_DATA_STRUCTURE *session)
{
	gboolean has_user_information = TRUE;
	guint16       flags;
	proto_item   *tf;
	proto_tree   *flags_tree;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	switch (param_type)
	{
	case Called_SS_user_Reference:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_called_ss_user_reference,
			    tvb, offset, param_len, ENC_NA);
		}
		break;

	case Calling_SS_user_Reference:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_calling_ss_user_reference,
			    tvb, offset, param_len, ENC_NA);
		}
		break;

	case Common_Reference:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_common_reference,
			    tvb, offset, param_len, ENC_NA);
		}
		break;

	case Additional_Reference_Information:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_additional_reference_information,
			    tvb, offset, param_len, ENC_NA);
		}
		break;

	case Token_Item:
		if (param_len != 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 1",
			    param_len);
			break;
		}
		if (tree)
		{
			flags = tvb_get_guint8(tvb, offset);
			tf = proto_tree_add_uint(param_tree,
			    hf_token_item_options_flags, tvb, offset, 1,
			    flags);
			flags_tree = proto_item_add_subtree(tf,
			    ett_token_item_flags);
			proto_tree_add_boolean(flags_tree, hf_release_token,
			    tvb, offset, 1, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_major_activity_token, tvb, offset, 1, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_synchronize_minor_token, tvb, offset, 1, flags);
			proto_tree_add_boolean(flags_tree, hf_data_token, tvb,
			    offset, 1, flags);
		}
		break;

	case Transport_Disconnect:
		if (param_len != 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 1",
			    param_len);
			break;
		}
		if (tree)
		{
			guint8       flags8;

			flags8 = tvb_get_guint8(tvb, offset);
			if(flags8 & transport_connection_is_released )
			{
				proto_tree_add_text(param_tree, tvb, offset, 1,
				    "transport connection is released");
			}
			else
			{
				proto_tree_add_text(param_tree, tvb, offset, 1,
				    "transport connection is kept");
			}

			if(flags8 & user_abort )
			{
				proto_tree_add_text(param_tree, tvb, offset, 1,
				    "user abort");
				session->abort_type = SESSION_USER_ABORT;
			}
			else
			{
				session->abort_type = SESSION_PROVIDER_ABORT;
			}

			if(flags8 & protocol_error )
			{
				proto_tree_add_text(param_tree, tvb, offset, 1,
				    "protocol error");
			}

			if(flags8 & no_reason )
			{
				proto_tree_add_text(param_tree, tvb, offset, 1,
				    "no reason");
			}

			if(flags8 & implementation_restriction )
			{
				proto_tree_add_text(param_tree, tvb, offset, 1,
				    "implementation restriction");
			}
		}
		break;

	case Protocol_Options:
		if (param_len != 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 1",
			    param_len);
			break;
		}
		if (tree)
		{
			flags = tvb_get_guint8(tvb, offset);
			tf = proto_tree_add_uint(param_tree,
			    hf_connect_protocol_options_flags, tvb, offset, 1,
			    flags);
			flags_tree = proto_item_add_subtree(tf,
			    ett_connect_protocol_options_flags);
			proto_tree_add_boolean(flags_tree,
			    hf_able_to_receive_extended_concatenated_SPDU,
			    tvb, offset, 1, flags);
		}
		break;

	case Session_Requirement:
		if (param_len != 2)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 2",
			    param_len);
			break;
		}
		if (tree)
		{
			flags = tvb_get_ntohs(tvb, offset);
			tf = proto_tree_add_uint(param_tree,
			    hf_session_user_req_flags, tvb, offset, 2,
			    flags);
			flags_tree = proto_item_add_subtree(tf,
			    ett_ses_req_options_flags);
			proto_tree_add_boolean(flags_tree,
			    hf_session_exception_report, tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_data_separation_function_unit, tvb, offset, 2,
			    flags);
			proto_tree_add_boolean(flags_tree,
			    hf_symmetric_synchronize_function_unit,
			    tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_typed_data_function_unit, tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_exception_function_unit, tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_capability_function_unit, tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_negotiated_release_function_unit,
			    tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_activity_management_function_unit,
			    tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_resynchronize_function_unit, tvb, offset, 2,
			    flags);
			proto_tree_add_boolean(flags_tree,
			    hf_major_resynchronize_function_unit,
			    tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_minor_resynchronize_function_unit,
			    tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_expedited_data_resynchronize_function_unit,
			    tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_duplex_function_unit, tvb, offset, 2, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_half_duplex_function_unit,
			    tvb, offset, 2, flags);
		}
		break;

	case TSDU_Maximum_Size:
		if (param_len != 4)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 4",
			    param_len);
			break;
		}
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_proposed_tsdu_maximum_size_i2r,
			    tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(param_tree,
			    hf_proposed_tsdu_maximum_size_r2i,
			    tvb, offset+2, 2, ENC_BIG_ENDIAN);
		}
		break;

	case Version_Number:
		if (param_len != 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 1",
			    param_len);
			break;
		}
		if (tree)
		{
			flags = tvb_get_guint8(tvb, offset);
			tf = proto_tree_add_uint(param_tree,
			    hf_version_number_options_flags, tvb, offset, 1,
			    flags);
			flags_tree = proto_item_add_subtree(tf,
			    ett_protocol_version_flags);
			proto_tree_add_boolean(flags_tree,
			    hf_protocol_version_2, tvb, offset, 1, flags);
			proto_tree_add_boolean(flags_tree,
			    hf_protocol_version_1, tvb, offset, 1, flags);
		}
		break;

	case Initial_Serial_Number:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_initial_serial_number,
			    tvb, offset, param_len, ENC_ASCII|ENC_NA);
		}
		break;

	case EnclosureItem:
		if (param_len != 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 1",
			    param_len);
			break;
		}
		flags = tvb_get_guint8(tvb, offset);
		*enclosure_item_flags = (guint8) flags;
		if (tree)
		{
			tf = proto_tree_add_uint(param_tree,
			    hf_enclosure_item_options_flags, tvb, offset, 1,
			    flags);
			flags_tree = proto_item_add_subtree(tf,
			    ett_enclosure_item_flags);
			proto_tree_add_boolean(flags_tree, hf_end_of_SSDU,
			    tvb, offset, 1, flags);
			proto_tree_add_boolean(flags_tree, hf_beginning_of_SSDU,
			    tvb, offset, 1, flags);
		}
		if (flags & END_SPDU) {
			/*
			 * In Data Transfer and Typed Data SPDUs, (X.225: 8.3.{11,13}.4)
			 * "The User Information Field shall be present
			 * if the Enclosure Item is not present, or has
			 * bit 2 = 0", which presumably means it shall
			 * *not* be present if the Enclosure item *is*
			 * present and has bit 2 = 1.
			 */

		  if(!(flags & BEGINNING_SPDU)) {
		    /* X.225 7.11.2 also states:
		     * "All DATA TRANSFER SPDUs, except the last DATA TRANSFER SPDU in a sequence greater than one, must have user information"
		     * So if BEGINNING_SPDU and END_SPDU are set in the enclosure item, then this is presumably a sequence of one and
		     * consequently there must be user information.
		     *
		     * So, there is only no user information if *only* END_SPDU is set.
		     */

		     has_user_information = FALSE;
		  }
		}
		break;

	case Token_Setting_Item:
		if (param_len != 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be 1",
			    param_len);
			break;
		}
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_release_token_setting,
			    tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(param_tree,
			    hf_major_activity_token_setting,
			    tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(param_tree,
			    hf_synchronize_minor_token_setting,
			    tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(param_tree,
			    hf_data_token_setting,
			    tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		break;

	case Activity_Identifier:
		if (param_len == 0)
			break;
		if (tree)
		{
			dissect_ber_integer(FALSE, &asn1_ctx, param_tree, tvb, offset,
			    hf_activity_identifier, NULL);
		}
		break;

	case Serial_Number:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_serial_number,
			    tvb, offset, param_len, ENC_ASCII|ENC_NA);
		}
		break;

	case Reason_Code:
/*
	0:	Rejection by called SS-user; reason not specified.
	1:	Rejection by called SS-user due to temporary congestion.
	2:	Rejection by called SS-user. Subsequent octets may be used for user data
up to a length of 512 octets if Protocol Version 1 has been selected, and up
to a length such that the total length (including SI and LI)  of the SPDU
does not exceed 65 539 octets if Protocol Version 2 has been selected.
	128 + 1:	Session Selector unknown.
	128 + 2:	SS-user not attached to SSAP.
	128 + 3:	SPM congestion at connect time.
	128 + 4:	Proposed protocol versions not supported.
	128 + 5:	Rejection by the SPM; reason not specified.
	128 + 6:	Rejection by the SPM; implementation restriction stated in the
PICS.    */
		if (param_len < 1)
		{
			proto_tree_add_text(param_tree, tvb, offset,
			    param_len, "Length is %u, should be >= 1",
			    param_len);
			break;
		}
		if (tree)
		{
			guint8      reason_code;

			reason_code = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(param_tree, tvb, offset, 1,
			    "Reason Code: %s",
			    val_to_str(reason_code, reason_vals, "Unknown (%u)"));
		}
		offset++;
		param_len--;
		if (param_len != 0)
		{
			call_pres_dissector(tvb, offset, param_len,
			    pinfo, tree, param_tree, session);
		}
		break;

	case Calling_Session_Selector:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_calling_session_selector,
			    tvb, offset, param_len, ENC_NA);
		}
		break;

	case Called_Session_Selector:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_called_session_selector,
			    tvb, offset, param_len, ENC_NA);
		}
		break;

	case Second_Serial_Number:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_second_serial_number,
			    tvb, offset, param_len, ENC_ASCII|ENC_NA);
		}
		break;

	case Second_Initial_Serial_Number:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_second_initial_serial_number,
			    tvb, offset, param_len, ENC_ASCII|ENC_NA);
		}
		break;

	case Large_Initial_Serial_Number:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_large_initial_serial_number,
			    tvb, offset, param_len, ENC_ASCII|ENC_NA);
		}
		break;

	case Large_Second_Initial_Serial_Number:
		if (param_len == 0)
			break;
		if (tree)
		{
			proto_tree_add_item(param_tree,
			    hf_large_second_initial_serial_number,
			    tvb, offset, param_len, ENC_ASCII|ENC_NA);
		}
		break;

	default:
		break;
	}
	return has_user_information;
}

static gboolean
dissect_parameter_group(tvbuff_t *tvb, int offset, proto_tree *tree,
		        proto_tree *pg_tree, packet_info *pinfo, guint16 pg_len,
		        guint8 *enclosure_item_flags, struct SESSION_DATA_STRUCTURE *session)
{
	gboolean has_user_information = TRUE;
	proto_item *ti;
	proto_tree *param_tree;
	guint8 param_type;
	const char *param_str;
	int len_len;
	guint16 param_len;

	while(pg_len != 0)
	{
		param_type = tvb_get_guint8(tvb, offset);
		ti = proto_tree_add_text(pg_tree, tvb, offset, -1, "%s",
		    val_to_str(param_type, param_vals,
		      "Unknown parameter type (0x%02x)"));
		param_tree = proto_item_add_subtree(ti, ett_ses_param);
		param_str = val_to_str_const(param_type, param_vals, "Unknown");
		proto_tree_add_text(param_tree, tvb, offset, 1,
		    "Parameter type: %s", param_str);
		offset++;
		pg_len--;
		param_len = get_item_len(tvb, offset, &len_len);
		if (len_len > pg_len) {
			proto_item_set_len(ti, pg_len + 1);
			proto_tree_add_text(param_tree, tvb, offset, pg_len,
			    "Parameter length doesn't fit in parameter");
			return has_user_information;
		}
		pg_len -= len_len;
		if (param_len > pg_len) {
			proto_item_set_len(ti, pg_len + 1 + len_len);
			proto_tree_add_text(param_tree, tvb, offset, pg_len,
			    "Parameter length: %u, should be <= %u",
			    param_len, pg_len);
			return has_user_information;
		}
		proto_item_set_len(ti, 1 + len_len + param_len);
		proto_tree_add_text(param_tree, tvb, offset, len_len,
		    "Parameter length: %u", param_len);
		offset += len_len;

		if (param_str != NULL)
		{
			switch(param_type)
			{
			/* PG's in PG's are invalid, presumably */
			case Extended_User_Data:
			case User_Data:
			case Connect_Accept_Item:
			case Connection_Identifier:
			case Linking_Information:
				proto_tree_add_text(param_tree, tvb, offset,
				    param_len,
				    "Parameter group inside parameter group");
				break;

			default:
				if (!dissect_parameter(tvb, offset, tree,
				    param_tree, pinfo, param_type, param_len,
				    enclosure_item_flags, session))
					has_user_information = FALSE;
				break;
			}
		}
		offset += param_len;
		pg_len -= param_len;
	}
	return has_user_information;
}

/*
 * Returns TRUE if there's a User Information field in this SPDU, FALSE
 * otherwise.
 */
static gboolean
dissect_parameters(tvbuff_t *tvb, int offset, guint16 len, proto_tree *tree,
	           proto_tree *ses_tree, packet_info *pinfo,
	           guint8 *enclosure_item_flags, struct SESSION_DATA_STRUCTURE *session)
{
	gboolean has_user_information = TRUE;
	proto_item *ti;
	proto_tree *param_tree;
	guint8 param_type;
	const char *param_str;
	int len_len;
	guint16 param_len;

	while (len != 0)
	{
		param_type = tvb_get_guint8(tvb, offset);
		ti = proto_tree_add_text(ses_tree, tvb, offset, -1, "%s",
		    val_to_str(param_type, param_vals,
		      "Unknown parameter type (0x%02x)"));
		param_tree = proto_item_add_subtree(ti, ett_ses_param);
		param_str = val_to_str_const(param_type, param_vals, "Unknown");
		proto_tree_add_text(param_tree, tvb, offset, 1,
		    "Parameter type: %s", param_str);
		offset++;
		len--;
		param_len = get_item_len(tvb, offset, &len_len);
		if (len_len > len) {
			proto_item_set_len(ti, len + 1 );
			proto_tree_add_text(param_tree, tvb, offset, len,
			    "Parameter length doesn't fit in parameter");
			return has_user_information;
		}
		len -= len_len;
		if (param_len > len) {
			proto_item_set_len(ti, len + 1 + len_len);
			proto_tree_add_text(param_tree, tvb, offset, len,
			    "Parameter length: %u, should be <= %u",
			    param_len, len);
			return has_user_information;
		}
		proto_item_set_len(ti, 1 + len_len + param_len);
		proto_tree_add_text(param_tree, tvb, offset, len_len,
		    "Parameter length: %u", param_len);
		offset += len_len;

		if (param_str != NULL)
		{
			switch(param_type)
			{
			case Extended_User_Data:
				call_pres_dissector(tvb, offset, param_len,
				    pinfo, tree, param_tree, session);
				break;

			case User_Data:
				call_pres_dissector(tvb, offset, param_len,
				    pinfo, tree, param_tree, session);
				break;

			/* handle PGI's  */
			case Connect_Accept_Item:
			case Connection_Identifier:
			case Linking_Information:
				/* Yes. */
				if (!dissect_parameter_group(tvb, offset, tree,
				    param_tree, pinfo, param_len, enclosure_item_flags, session))
					has_user_information = FALSE;
				break;

			/* everything else is a PI */
			default:
				if (!dissect_parameter(tvb, offset, tree,
				    param_tree, pinfo, param_type, param_len,
				    enclosure_item_flags, session))
					has_user_information = FALSE;
				break;
			}
		}
		offset += param_len;
		len -= param_len;
	}
	return has_user_information;
}

/*
 * Dissect an SPDU.
 */
static int
dissect_spdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
	     gboolean tokens, gboolean connectionless)
{
	gboolean has_user_information = FALSE;
	guint8 type;
	proto_item *ti = NULL;
	proto_tree *ses_tree = NULL;
	int len_len;
	guint16 parameters_len;
	tvbuff_t *next_tvb = NULL;
	void *save_private_data;
	guint32 *pres_ctx_id = NULL;
	guint8 enclosure_item_flags = BEGINNING_SPDU|END_SPDU;
	struct SESSION_DATA_STRUCTURE session;

	/*
	 * Get SPDU type.
	 */
	type = tvb_get_guint8(tvb, offset);
	session.spdu_type = type;
	session.abort_type = SESSION_NO_ABORT;
	session.ros_op = 0;
	session.rtse_reassemble = FALSE;

	if(connectionless) {
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(type, ses_vals, "Unknown SPDU type (0x%02x)"));
		if (tree) {
			ti = proto_tree_add_item(tree, proto_clses, tvb, offset,
				-1, ENC_NA);
			ses_tree = proto_item_add_subtree(ti, ett_ses);
			proto_tree_add_uint(ses_tree, hf_ses_type, tvb,
				offset, 1, type);
		}
		has_user_information = TRUE;
	}
	else if (tokens) {
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(type, ses_category0_vals, "Unknown SPDU type (0x%02x)"));
		if (tree) {
			ti = proto_tree_add_item(tree, proto_ses, tvb, offset,
			    -1, ENC_NA);
			ses_tree = proto_item_add_subtree(ti, ett_ses);
			proto_tree_add_uint(ses_tree, hf_ses_type_0, tvb,
			    offset, 1, type);
		}
	} else {
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(type, ses_vals, "Unknown SPDU type (0x%02x)"));
		if (tree) {
			ti = proto_tree_add_item(tree, proto_ses, tvb, offset,
				-1, ENC_NA);
			ses_tree = proto_item_add_subtree(ti, ett_ses);
			proto_tree_add_uint(ses_tree, hf_ses_type, tvb,
				offset, 1, type);
		}

		/*
		 * Might this SPDU have a User Information field?
		 */
		switch (type) {
		case SES_DATA_TRANSFER:
		case SES_EXPEDITED:
		case SES_TYPED_DATA:
			has_user_information = TRUE;
			break;
		case SES_MAJOR_SYNC_POINT:
			pres_ctx_id = p_get_proto_data (pinfo->fd, proto_ses);
			if (ses_rtse_reassemble != 0 && !pres_ctx_id) {
				/* First time visited - save pres_ctx_id */
				pres_ctx_id = se_alloc (sizeof (guint32));
				*pres_ctx_id = ses_pres_ctx_id;
				p_add_proto_data (pinfo->fd, proto_ses, pres_ctx_id);
			}
			if (pres_ctx_id) {
				session.pres_ctx_id = *pres_ctx_id;
				session.rtse_reassemble = TRUE;
				has_user_information = TRUE;
			}
			ses_rtse_reassemble = FALSE;
			break;
		}
	}
	offset++;

	/* get length of SPDU parameter field */
	parameters_len = get_item_len(tvb, offset, &len_len);
	if (tree)
		proto_tree_add_uint(ses_tree, hf_ses_length, tvb, offset,
		    len_len, parameters_len);
	offset += len_len;

	/* Dissect parameters. */
	if (!dissect_parameters(tvb, offset, parameters_len, tree, ses_tree,
				pinfo, &enclosure_item_flags, &session))
		has_user_information = FALSE;
	offset += parameters_len;

	proto_item_set_end(ti, tvb, offset);

	/* Dissect user information, if present */
	if (!ses_desegment || enclosure_item_flags == (BEGINNING_SPDU|END_SPDU)) {
		if (has_user_information) {
			/* Not desegment or only one segment */
			if (tvb_reported_length_remaining(tvb, offset) > 0 || type == SES_MAJOR_SYNC_POINT) {
				next_tvb = tvb_new_subset_remaining(tvb, offset);
			}
		}
	} else {
		conversation_t *conversation = NULL;
		fragment_data *frag_msg = NULL;
		gint fragment_len;
		guint32 ses_id = 0;

		/* Use conversation index as segment id */
		conversation  = find_conversation (pinfo->fd->num,
						   &pinfo->src, &pinfo->dst, pinfo->ptype,
						   pinfo->srcport, pinfo->destport, 0);
		if (conversation != NULL) {
			ses_id = conversation->index;
		}
		fragment_len = tvb_reported_length_remaining (tvb, offset);
		ti = proto_tree_add_item (ses_tree, hf_ses_segment_data, tvb, offset,
					  fragment_len, ENC_NA);
		proto_item_append_text (ti, " (%d byte%s)", fragment_len, plurality (fragment_len, "", "s"));
		frag_msg = fragment_add_seq_next (tvb, offset, pinfo,
						  ses_id, ses_fragment_table,
						  ses_reassembled_table, fragment_len,
						  (enclosure_item_flags & END_SPDU) ? FALSE : TRUE);
		next_tvb = process_reassembled_data (tvb, offset, pinfo, "Reassembled SES",
						     frag_msg, &ses_frag_items, NULL,
						     (enclosure_item_flags & END_SPDU) ? tree : ses_tree);

		has_user_information = TRUE;
		offset += fragment_len;
	}

	if (has_user_information && next_tvb) {
		if (!pres_handle) {
			call_dissector(data_handle, next_tvb, pinfo, tree);
		} else {
			/* save type of session pdu. We'll need it in the presentation dissector */
			save_private_data = pinfo->private_data;
			pinfo->private_data = &session;
			call_dissector(pres_handle, next_tvb, pinfo, tree);
			pinfo->private_data = save_private_data;
		}

		/*
		 * No more SPDUs to dissect.  Set the offset to the
		 * end of the tvbuff.
		 */
		offset = tvb_length(tvb);
		if (session.rtse_reassemble && type == SES_DATA_TRANSFER) {
			ses_pres_ctx_id = session.pres_ctx_id;
			ses_rtse_reassemble = TRUE;
		}
	}
	return offset;
}

/*
 * Dissect SPDUs inside a TSDU.
 */
static void
dissect_ses(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 type;
	gboolean is_clsp = FALSE;

	type = tvb_get_guint8(tvb, offset);
	if(type == CLSES_UNIT_DATA)
		is_clsp = TRUE;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, is_clsp ? "CLSES" : "SES");
  	col_clear(pinfo->cinfo, COL_INFO);


	/*
	 * Do we have a category 0 SPDU (GIVE_TOKENS/PLEASE_TOKENS) as
	 * the first SPDU?
	 *
	 * If so, dissect it as such (GIVE_TOKENS and DATA_TRANSFER have
	 * the same SPDU type value).
	 */
	if ((type == SES_PLEASE_TOKENS) || (type == SES_GIVE_TOKENS))
		offset = dissect_spdu(tvb, offset, pinfo, tree, TOKENS_SPDU, FALSE);


	/* Dissect the remaining SPDUs. */
	while (tvb_reported_length_remaining(tvb, offset) > 0)
		offset = dissect_spdu(tvb, offset, pinfo, tree, NON_TOKENS_SPDU, is_clsp);
}

static void ses_reassemble_init (void)
{
	fragment_table_init (&ses_fragment_table);
	reassembled_table_init (&ses_reassembled_table);
}

void
proto_register_ses(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_ses_type,
			{
				"SPDU Type",
				"ses.type",
				FT_UINT8,
				BASE_DEC,
				VALS(ses_vals),
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_ses_type_0,
			{
				"SPDU Type",
				"ses.type",
				FT_UINT8,
				BASE_DEC,
				VALS(ses_category0_vals),
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_ses_length,
			{
				"Length",
				"ses.length",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_ses_version,
			{
				"Version",
				"ses.version",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_ses_reserved,
			{
				"Reserved",
				"ses.reserved",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_called_ss_user_reference,
			{
				"Called SS User Reference",
				"ses.called_ss_user_reference",
				FT_BYTES, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_calling_ss_user_reference,
			{
				"Calling SS User Reference",
				"ses.calling_ss_user_reference",
				FT_BYTES, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_common_reference,
			{
				"Common Reference",
				"ses.common_reference",
				FT_BYTES, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_additional_reference_information,
			{
				"Additional Reference Information",
				"ses.additional_reference_information",
				FT_BYTES, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_release_token,
			{
				"release token",
				"ses.release_token",
				FT_BOOLEAN, 8,
				NULL,
				RELEASE_TOKEN,
				NULL,
				HFILL
			}
		},
		{
			&hf_major_activity_token,
			{
				"major/activity token",
				"ses.major.token",
				FT_BOOLEAN, 8,
				NULL,
				MAJOR_ACTIVITY_TOKEN,
				NULL,
				HFILL
			}
		},
		{
			&hf_synchronize_minor_token,
			{
				"synchronize minor token",
				"ses.synchronize_token",
				FT_BOOLEAN, 8,
				NULL,
				SYNCHRONIZE_MINOR_TOKEN,
				NULL,
				HFILL
			}
		},
		{
			&hf_data_token,
			{
				"data token",
				"ses.data_token",
				FT_BOOLEAN, 8,
				NULL,
				DATA_TOKEN,
				"data  token",
				HFILL
			}
		},
		{
			&hf_able_to_receive_extended_concatenated_SPDU,
			{
				"Able to receive extended concatenated SPDU",
				"ses.connect.f1",
				FT_BOOLEAN, 8,
				NULL,
				SES_EXT_CONT,
				NULL,
				HFILL
			}
		},
		{
			&hf_session_user_req_flags,
			{
				"Flags",
				"ses.req.flags",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_session_exception_report,
			{
				"Session exception report",
				"ses.exception_report.",
				FT_BOOLEAN, 16,
				NULL,
				SES_EXCEPTION_REPORT,
				NULL,
				HFILL
			}
		},
		{
			&hf_data_separation_function_unit,
			{
				"Data separation function unit",
				"ses.data_sep",
				FT_BOOLEAN, 16,
				NULL,
				DATA_SEPARATION_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_symmetric_synchronize_function_unit,
			{
				"Symmetric synchronize function unit",
				"ses.symm_sync",
				FT_BOOLEAN, 16,
				NULL,
				SYMMETRIC_SYNCHRONIZE_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_typed_data_function_unit,
			{
				"Typed data function unit",
				"ses.typed_data",
				FT_BOOLEAN, 16,
				NULL,
				TYPED_DATA_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_exception_function_unit,
			{
				"Exception function unit",
				"ses.exception_data",
				FT_BOOLEAN, 16,
				NULL,
				EXCEPTION_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_capability_function_unit,
			{
				"Capability function unit",
				"ses.capability_data",
				FT_BOOLEAN, 16,
				NULL,
				CAPABILITY_DATA_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_negotiated_release_function_unit,
			{
				"Negotiated release function unit",
				"ses.negotiated_release",
				FT_BOOLEAN, 16,
				NULL,
				NEGOTIATED_RELEASE_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_activity_management_function_unit,
			{
				"Activity management function unit",
				"ses.activity_management",
				FT_BOOLEAN, 16,
				NULL,
				ACTIVITY_MANAGEMENT_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_resynchronize_function_unit,
			{
				"Resynchronize function unit",
				"ses.resynchronize",
				FT_BOOLEAN, 16,
				NULL,
				RESYNCHRONIZE_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_major_resynchronize_function_unit,
			{
				"Major resynchronize function unit",
				"ses.major_resynchronize",
				FT_BOOLEAN, 16,
				NULL,
				MAJOR_SYNCHRONIZE_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_minor_resynchronize_function_unit,
			{
				"Minor resynchronize function unit",
				"ses.minor_resynchronize",
				FT_BOOLEAN, 16,
				NULL,
				MINOR_SYNCHRONIZE_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_expedited_data_resynchronize_function_unit,
			{
				"Expedited data function unit",
				"ses.expedited_data",
				FT_BOOLEAN, 16,
				NULL,
				EXPEDITED_DATA_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_duplex_function_unit,
			{
				"Duplex functional unit",
				"ses.duplex",
				FT_BOOLEAN, 16,
				NULL,
				DUPLEX_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_half_duplex_function_unit,
			{
				"Half-duplex functional unit",
				"ses.half_duplex",
				FT_BOOLEAN, 16,
				NULL,
				HALF_DUPLEX_FUNCTION_UNIT,
				NULL,
				HFILL
			}
		},
		{
			&hf_proposed_tsdu_maximum_size_i2r,
			{
				"Proposed TSDU Maximum Size, Initiator to Responder",
				"ses.proposed_tsdu_maximum_size_i2r",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_proposed_tsdu_maximum_size_r2i,
			{
				"Proposed TSDU Maximum Size, Responder to Initiator",
				"ses.proposed_tsdu_maximum_size_r2i",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_protocol_version_1,
			{
				"Protocol Version 1",
				"ses.protocol_version1",
				FT_BOOLEAN, 8,
				NULL,
				PROTOCOL_VERSION_1,
				NULL,
				HFILL
			}
		},
		{
			&hf_protocol_version_2,
			{
				"Protocol Version 2",
				"ses.protocol_version2",
				FT_BOOLEAN, 8,
				NULL,
				PROTOCOL_VERSION_2,
				NULL,
				HFILL
			}
		},
		{
			&hf_initial_serial_number,
			{
				"Initial Serial Number",
				"ses.initial_serial_number",
				FT_STRING, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_beginning_of_SSDU,
			{
				"beginning of SSDU",
				"ses.begininng_of_SSDU",
				FT_BOOLEAN, 8,
				NULL,
				BEGINNING_SPDU,
				NULL,
				HFILL
			}
		},
		{
			&hf_end_of_SSDU,
			{
				"end of SSDU",
				"ses.end_of_SSDU",
				FT_BOOLEAN, 8,
				NULL,
				END_SPDU,
				NULL,
				HFILL
			}
		},
		{
			&hf_release_token_setting,
			{
				"release token setting",
				"ses.release_token_setting",
				FT_UINT8, BASE_HEX,
				VALS(token_setting_vals),
				0xC0,
				NULL,
				HFILL
			}
		},
		{
			&hf_major_activity_token_setting,
			{
				"major/activity setting",
				"ses.major_activity_token_setting",
				FT_UINT8, BASE_HEX,
				VALS(token_setting_vals),
				0x30,
				"major/activity token setting",
				HFILL
			}
		},
		{
			&hf_synchronize_minor_token_setting,
			{
				"synchronize-minor token setting",
				"ses.synchronize_minor_token_setting",
				FT_UINT8, BASE_HEX,
				VALS(token_setting_vals),
				0x0C,
				NULL,
				HFILL
			}
		},
		{
			&hf_data_token_setting,
			{
				"data token setting",
				"ses.data_token_setting",
				FT_UINT8, BASE_HEX,
				VALS(token_setting_vals),
				0x03,
				NULL,
				HFILL
			}
		},
		{
			&hf_activity_identifier,
			{
				"Activity Identifier",
				"ses.activity_identifier",
				FT_UINT32, BASE_DEC,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_serial_number,
			{
				"Serial Number",
				"ses.serial_number",
				FT_STRING, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_calling_session_selector,
			{
				"Calling Session Selector",
				"ses.calling_session_selector",
				FT_BYTES, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_called_session_selector,
			{
				"Called Session Selector",
				"ses.called_session_selector",
				FT_BYTES, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_second_serial_number,
			{
				"Second Serial Number",
				"ses.second_serial_number",
				FT_STRING, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_second_initial_serial_number,
			{
				"Second Initial Serial Number",
				"ses.second_initial_serial_number",
				FT_STRING, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_large_initial_serial_number,
			{
				"Large Initial Serial Number",
				"ses.large_initial_serial_number",
				FT_STRING, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_large_second_initial_serial_number,
			{
				"Large Second Initial Serial Number",
				"ses.large_second_initial_serial_number",
				FT_STRING, BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_connect_protocol_options_flags,
			{
				"Flags",
				"ses.connect.flags",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_version_number_options_flags,

			{
				"Flags",
				"ses.version.flags",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},

		{
			&hf_token_item_options_flags,

			{
				"Flags",
				"ses.tken_item.flags",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},

		{
			&hf_enclosure_item_options_flags,

			{
				"Flags",
				"ses.enclosure.flags",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},

		{ &hf_ses_segment_data,
		  { "SES segment data", "ses.segment.data", FT_NONE, BASE_NONE,
		    NULL, 0x00, NULL, HFILL } },
		{ &hf_ses_segments,
		  { "SES segments", "ses.segments", FT_NONE, BASE_NONE,
		    NULL, 0x00, NULL, HFILL } },
		{ &hf_ses_segment,
		  { "SES segment", "ses.segment", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x00, NULL, HFILL } },
		{ &hf_ses_segment_overlap,
		  { "SES segment overlap", "ses.segment.overlap", FT_BOOLEAN,
		    BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ses_segment_overlap_conflicts,
		  { "SES segment overlapping with conflicting data",
		    "ses.segment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_ses_segment_multiple_tails,
		  { "SES has multiple tail segments",
		    "ses.segment.multiple_tails", FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, NULL, HFILL } },
		{ &hf_ses_segment_too_long_segment,
		  { "SES segment too long", "ses.segment.too_long_segment",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ses_segment_error,
		  { "SES desegmentation error", "ses.segment.error", FT_FRAMENUM,
		    BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{ &hf_ses_segment_count,
		  { "SES segment count", "ses.segment.count", FT_UINT32, BASE_DEC,
		    NULL, 0x00, NULL, HFILL } },
		{ &hf_ses_reassembled_in,
		  { "Reassembled SES in frame", "ses.reassembled.in", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x00, "This SES packet is reassembled in this frame", HFILL } },
		{ &hf_ses_reassembled_length,
		  { "Reassembled SES length", "ses.reassembled.length", FT_UINT32, BASE_DEC,
		    NULL, 0x00, "The total length of the reassembled payload", HFILL } }
	};

	static gint *ett[] =
	{
		&ett_ses,
		&ett_ses_param,
		&ett_connect_protocol_options_flags,
		&ett_protocol_version_flags,
		&ett_enclosure_item_flags,
		&ett_token_item_flags,
		&ett_ses_req_options_flags,
		&ett_ses_segment,
		&ett_ses_segments
	};
	module_t *ses_module;

	proto_ses = proto_register_protocol(PROTO_STRING_SES, "SES", "ses");
	proto_register_field_array(proto_ses, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine (&ses_reassemble_init);

	ses_module = prefs_register_protocol(proto_ses, NULL);

	prefs_register_bool_preference(ses_module, "desegment",
	    "Reassemble session packets ",
	    "Whether the session dissector should reassemble messages spanning multiple SES segments",
	    &ses_desegment);

	/*
	 * Register the dissector by name, so other dissectors can
	 * grab it by name rather than just referring to it directly
	 * (you can't refer to it directly from a plugin dissector
	 * on Windows without stuffing it into the Big Transfer Vector).
	 */
	register_dissector("ses", dissect_ses, proto_ses);
}

static gboolean
dissect_ses_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/* must check that this really is a ses packet */
	int offset = 0;
	guint8 type;
	int len_len;
	guint16 len;

	/* first, check do we have at least 4 bytes (type+length) */
	if (tvb_length(tvb) < 2)
		return FALSE;	/* no */

	/* can we recognize session PDU ? Return FALSE if  not */
	/*   get SPDU type */
	type = tvb_get_guint8(tvb, offset);
	/* check SPDU type */
	if (match_strval(type, ses_vals) == NULL)
	{
		return FALSE;  /* no, it isn't a session PDU */
	}

	/* can we recognize the second session PDU if the first one was
	 * a Give Tokens PDU? Return FALSE if not */
	if(tvb_bytes_exist(tvb, 2, 2) && type == SES_GIVE_TOKENS) {
		/*   get SPDU type */
		type = tvb_get_guint8(tvb, offset+2);
		/* check SPDU type */
		if (match_strval(type, ses_vals) == NULL)
		{
			return FALSE;  /* no, it isn't a session PDU */
		}
	}

	/* some Siemens SIMATIC protocols also use COTP, and shouldn't be
	 * misinterpreted as SES.
	 * the starter in this case is fixed to 0x32 (SES_MINOR_SYNC_ACK for SES),
	 * so if the parameter type is unknown, it's probably SIMATIC */
	if(type == 0x32 && tvb_length(tvb) >= 3) {
		type = tvb_get_guint8(tvb, offset+2);
		if (match_strval(type, param_vals) == NULL) {
			return FALSE; /* it's probably a SIMATIC protocol */
		}
	}

	/*  OK,let's check SPDU length  */
	/*  get length of SPDU */
	len = get_item_len(tvb, offset+1, &len_len);

	/*  add header length     */
	len+=len_len;
	/* do we have enough bytes ? */
	if (tvb_length(tvb) < len)
		return FALSE;	/* no */

	/* final check to see if the next SPDU, if present, is also valid */
	if (tvb_length(tvb) > len) {
	  type = tvb_get_guint8(tvb, offset + len + 1);
	  /* check SPDU type */
	  if (match_strval(type, ses_vals) == NULL) {
	    return FALSE;  /* no, it isn't a session PDU */
	  }
	}

	dissect_ses(tvb, pinfo, parent_tree);
	return TRUE;
}

void
proto_reg_handoff_ses(void)
{
	/*   find data dissector  */
	data_handle = find_dissector("data");

	/* define sub dissector */
	pres_handle = find_dissector("pres");

	/* add our session dissector to cotp dissector list
	 * and cotp_is dissector list*/
	heur_dissector_add("cotp", dissect_ses_heur, proto_ses);
	heur_dissector_add("cotp_is", dissect_ses_heur, proto_ses);
}



void proto_register_clses(void)
{
	proto_clses = proto_register_protocol(PROTO_STRING_CLSES, "CLSP", "clsp");
}

void
proto_reg_handoff_clses(void)
{
	/* add our session dissector to cltp dissector list */
	heur_dissector_add("cltp", dissect_ses_heur, proto_clses);
}

