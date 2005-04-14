/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg@users.sourceforge.net>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

// BACnet PDU Types
#define BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST 0
#define BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST 1
#define BACAPP_TYPE_SIMPLE_ACK 2
#define BACAPP_TYPE_COMPLEX_ACK 3
#define BACAPP_TYPE_SEGMENT_ACK 4
#define BACAPP_TYPE_ERROR 5
#define BACAPP_TYPE_REJECT 6
#define BACAPP_TYPE_ABORT 7
#define MAX_BACAPP_TYPE 8

static const value_string bacapp_type_names[] = {
	{ BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST, "Confirmed-Request" },
	{ BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST, "Unconfirmed-Request" },
	{ BACAPP_TYPE_SIMPLE_ACK, "SimpleACK" },
	{ BACAPP_TYPE_COMPLEX_ACK, "ComplexACK" },
	{ BACAPP_TYPE_SEGMENT_ACK, "SegmentACK" },
	{ BACAPP_TYPE_ERROR, "Error" },
	{ BACAPP_TYPE_REJECT, "Reject" },
	{ BACAPP_TYPE_ABORT, "Abort" },
	{ 0, NULL }
};
static const char *bacapp_unknown_str = "unknown";
static const char *bacapp_unknown_service_str = "unknown service";

static const value_string bacapp_confirmed_service_names[] = {
	{ 0, "Acknowledge-Alarm" },
	{ 1, "COV-Notification" },
	{ 2, "Event-Notification" },
	{ 3, "Get-Alarm-Summary" },
	{ 4, "Get-Enrollment-Summary" },
	{ 5, "Subscribe-COV" },
	{ 6, "Atomic-Read-File" },
	{ 7, "Atomic-Write-File" },
	{ 8, "Add-List-Element" },
	{ 9, "Remove-List-Element" },
	{ 10, "Create-Object" },
	{ 11, "Delete-Object" },
	{ 12, "Read-Property" },
	{ 13, "Read-Property-Conditional" },
	{ 14, "Read-Property-Multiple" },
	{ 15, "Write-Property" },
	{ 16, "Write-Property-Multiple" },
	{ 17, "Device-Communication-Control" },
	{ 18, "Private-Transfer" },
	{ 19, "Text-Message" },
	{ 20, "Reinitialize-Device" },
	{ 21, "VT-Open" },
	{ 22, "VT-Close" },
	{ 23, "VT-Data" },
	{ 24, "Authenticate" },
	{ 25, "Request-Key" },
	{ 26, "Read-Range" },
	{ 27, "Life-Safety_Operation" },
	{ 28, "Subscribe-COV-Property" },
	{ 29, "Get-Event-Information" },
	{ 0, NULL }
};

#define SERVICE_UNCONFIRMED_I_AM 0
#define SERVICE_UNCONFIRMED_I_HAVE 1
#define SERVICE_UNCONFIRMED_COV_NOTIFICATION 2
#define SERVICE_UNCONFIRMED_EVENT_NOTIFICATION 3
#define SERVICE_UNCONFIRMED_PRIVATE_TRANSFER 4
#define SERVICE_UNCONFIRMED_TEXT_MESSAGE 5
#define SERVICE_UNCONFIRMED_TIME_SYNCHRONIZATION 6
#define SERVICE_UNCONFIRMED_WHO_HAS 7
#define SERVICE_UNCONFIRMED_WHO_IS 8
#define SERVICE_UNCONFIRMED_UTC_TIME_SYNCHRONIZATION 9
/* Other services to be added as they are defined.
   All choice values in this production are reserved
   for definition by ASHRAE.
   Proprietary extensions are made by using the
   UnconfirmedPrivateTransfer service. See Clause 23.
*/
#define MAX_BACNET_UNCONFIRMED_SERVICE 10

static const value_string bacapp_unconfirmed_service_names[] = {
	{ SERVICE_UNCONFIRMED_I_AM, "I-Am" },
	{ SERVICE_UNCONFIRMED_I_HAVE, "I-Have" },
	{ SERVICE_UNCONFIRMED_COV_NOTIFICATION, "COV-Notification" },
	{ SERVICE_UNCONFIRMED_EVENT_NOTIFICATION, "Event-Notification" },
	{ SERVICE_UNCONFIRMED_PRIVATE_TRANSFER, "Private-Transfer" },
	{ SERVICE_UNCONFIRMED_TEXT_MESSAGE, "Text-Message" },
	{ SERVICE_UNCONFIRMED_TIME_SYNCHRONIZATION, "Time-Synchronization" },
	{ SERVICE_UNCONFIRMED_WHO_HAS, "Who-Has" },
	{ SERVICE_UNCONFIRMED_WHO_IS, "Who-Is" },
	{ SERVICE_UNCONFIRMED_UTC_TIME_SYNCHRONIZATION, "UTC-Time-Synchronization" },
	{ 0, NULL }
};

static const char*
bacapp_reject_reason_name (guint8 bacapp_reason){
	static const char *reason_names[] = {
		"Other",
		"Buffer Overflow",
		"Inconsistent Parameters",
		"Invalid Parameter Data Type",
		"Invalid Tag",
		"Missing Required Parameter",
		"Parameter Out of Range",
		"Too Many Arguments",
		"Undefined Enumeration",
		"Unrecognized Service"
	};
	if (bacapp_reason < 10)
		return reason_names[bacapp_reason];
	else if (bacapp_reason < 64)
		return "Reserved for Use by ASHRAE";

	return "Vendor Proprietary Reason";
}

static const char*
bacapp_abort_reason_name (guint8 bacapp_reason){
  static const char *reason_names[] = {
    "Other",
    "Buffer Overflow",
    "Invalid APDU in this State",
    "Preempted by Higher Priority Task",
    "Segmentation Not Supported"
	};
	if (bacapp_reason < 5)
		return reason_names[bacapp_reason];
	else if (bacapp_reason < 64)
		return "Reserved for Use by ASHRAE";

	return "Vendor Proprietary Reason";
}

/* from clause 20.1.2.4 max-segments-accepted
   returns the decoded value
   
   max-segments-accepted
   B'000'      Unspecified number of segments accepted.
   B'001'      2 segments accepted.
   B'010'      4 segments accepted.
   B'011'      8 segments accepted.
   B'100'      16 segments accepted.
   B'101'      32 segments accepted.
   B'110'      64 segments accepted.
   B'111'      Greater than 64 segments accepted.
*/
static guint8 decode_max_segs(guint8 octet)
{
    guint8 max_segs = 0;

    switch (octet & 0xF0)
    {
      case 0:
        max_segs = 0;
        break;
      case 0x10:
        max_segs = 2;
        break;
      case 0x20:
        max_segs = 4;
        break;
      case 0x30:
        max_segs = 8;
        break;
      case 0x40:
        max_segs = 16;
        break;
      case 0x50:
        max_segs = 32;
        break;
      case 0x60:
        max_segs = 64;
        break;
      case 0x70:
        max_segs = 65;
        break;
      default:
        break;
    }

    return max_segs;
}

/* from clause 20.1.2.5 max-APDU-length-accepted
   returns the decoded value
   
   max-APDU-length-accepted
   B'0000'  Up to MinimumMessageSize (50 octets)
   B'0001'  Up to 128 octets
   B'0010'  Up to 206 octets (fits in a LonTalk frame)
   B'0011'  Up to 480 octets (fits in an ARCNET frame)
   B'0100'  Up to 1024 octets
   B'0101'  Up to 1476 octets (fits in an ISO 8802-3 frame)
   B'0110'  reserved by ASHRAE
   B'0111'  reserved by ASHRAE
   B'1000'  reserved by ASHRAE
   B'1001'  reserved by ASHRAE
   B'1010'  reserved by ASHRAE
   B'1011'  reserved by ASHRAE
   B'1100'  reserved by ASHRAE
   B'1101'  reserved by ASHRAE
   B'1110'  reserved by ASHRAE
   B'1111'  reserved by ASHRAE
*/
static guint16 decode_max_apdu(guint8 octet)
{
    guint16 max_apdu = 0;
    
    switch (octet & 0x0F)
    {
      case 0:
        max_apdu = 50;
        break;
      case 1:
        max_apdu = 128;
        break;
      case 2:
        max_apdu = 206;
        break;
      case 3:
        max_apdu = 480;
        break;
      case 4:
        max_apdu = 1024;
        break;
      case 5:
        max_apdu = 1476;
        break;
      default:
        break;
    }

    return max_apdu;
}

#define BACAPP_SEGMENTED_REQUEST 0x08
static const true_false_string tfs_segmented_request = {
	"Segmented Request.",
	"Unsegmented Request."
};
#define BACAPP_MORE_SEGMENTS 0x04
static const true_false_string tfs_more_segments = {
	"More Segments Follow.",
	"No More Segments Follow."
};
#define BACAPP_SEGMENTED_RESPONSE 0x02
static const true_false_string tfs_segmented_response = {
	"Segmented Response Accepted.",
	"Segmented Response Not Accepted."
};
#define BACAPP_SEGMENT_NAK 0x02
static const true_false_string tfs_segment_nak = {
	"Negative Acknowledgement. Segment out of Order.",
	"Normal Acknowledgement."
};
#define BACAPP_SENT_BY 0x01
static const true_false_string tfs_sent_by = {
	"Sent By Server.",
	"Sent By Client."
};
static const true_false_string tfs_reserved_bit = {
	"Shall be zero, but is one.",
	"Shall be zero and is zero."
};

static int proto_bacapp = -1;

static int hf_bacapp_type = -1;
static int hf_bacapp_segmented_request = -1;
static int hf_bacapp_more_segments = -1;
static int hf_bacapp_segmented_response = -1;
static int hf_bacapp_max_segments = -1;
static int hf_bacapp_max_response = -1;
static int hf_bacapp_invoke_id = -1;
static int hf_bacapp_sequence_number = -1;
static int hf_bacapp_window_size = -1;
static int hf_bacapp_service_choice = -1;
static int hf_bacapp_segment_nak = -1;
static int hf_bacapp_sent_by = -1;
static int hf_bacapp_error_choice = -1;
static int hf_bacapp_reject_reason = -1;
static int hf_bacapp_abort_reason = -1;
/* generic reserved bits */
static int hf_bacapp_reserved_bit_0 = -1;
static int hf_bacapp_reserved_bit_1 = -1;
static int hf_bacapp_reserved_bit_2 = -1;
static int hf_bacapp_reserved_bit_3 = -1;
static int hf_bacapp_reserved_bit_4 = -1;
static int hf_bacapp_reserved_bit_5 = -1;
static int hf_bacapp_reserved_bit_6 = -1;
static int hf_bacapp_reserved_bit_7 = -1;

static gint ett_bacapp = -1;

static dissector_handle_t data_handle;

static void
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *bacapp_tree;
	guint8 offset;
	guint8 bacapp_type;
	guint8 bacapp_type_seg;
	guint8 bacapp_service;
	guint8 bacapp_reason;
	guint8 bacapp_max_seg_resp;
	guint8 bacapp_invoke_id;
	guint8 bacapp_sequence_number;
	guint8 bacapp_window_size;
	guint8 max_segs;
	guint16 max_apdu;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet-APDU");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, "BACnet APDU ");

	offset  = 0;
	bacapp_type_seg = tvb_get_guint8(tvb, offset);
	bacapp_type = (bacapp_type_seg >> 4) & 0xf;
	
	/* show some descriptive text in the INFO column */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(bacapp_type, bacapp_type_names, bacapp_unknown_str));
		switch (bacapp_type)
		{
			case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:
				/* segmented messages have 2 additional bytes */
				if (bacapp_type_seg & BACAPP_SEGMENTED_REQUEST)
					bacapp_service = tvb_get_guint8(tvb, offset + 5);
				else
					bacapp_service = tvb_get_guint8(tvb, offset + 3);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:
				bacapp_service = tvb_get_guint8(tvb, offset + 1);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						bacapp_unconfirmed_service_names,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_SIMPLE_ACK:
				bacapp_service = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_COMPLEX_ACK:
				/* segmented messages have 2 additional bytes */
				if (bacapp_type_seg & BACAPP_SEGMENTED_REQUEST)
					bacapp_service = tvb_get_guint8(tvb, offset + 4);
				else
					bacapp_service = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_SEGMENT_ACK:
				/* nothing more to add */
				break;
			case BACAPP_TYPE_ERROR:
				bacapp_service = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				break;
			case BACAPP_TYPE_REJECT:
				bacapp_reason = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					bacapp_reject_reason_name(bacapp_reason));
				break;
			case BACAPP_TYPE_ABORT:
				bacapp_reason = tvb_get_guint8(tvb, offset + 2);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					bacapp_abort_reason_name(bacapp_reason));
				break;
			/* UNKNOWN */
			default:
				/* nothing more to add */
				break;
		}
	}
   
	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, -1, FALSE);

		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		proto_tree_add_uint_format(bacapp_tree, hf_bacapp_type, tvb,
			offset, 1, bacapp_type, "APDU Type: %u (%s)", bacapp_type,
			val_to_str(bacapp_type, bacapp_type_names, bacapp_unknown_str));
		switch (bacapp_type)
		{
			case BACAPP_TYPE_CONFIRMED_SERVICE_REQUEST:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_segmented_request,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_more_segments,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_segmented_response,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_max_seg_resp = tvb_get_guint8(tvb, offset);
				max_segs = decode_max_segs(bacapp_max_seg_resp);
				if (max_segs > 64)
					proto_tree_add_uint_format(bacapp_tree, hf_bacapp_max_segments, 
						tvb, offset, 1, bacapp_max_seg_resp,
						"Maximum Segments Accepted: %u "
						"(Greater than 64 segments accepted).",
						((bacapp_max_seg_resp >> 4) & 0x0f));
				else
					proto_tree_add_uint_format(bacapp_tree, hf_bacapp_max_segments, 
						tvb, offset, 1, bacapp_max_seg_resp,
						"Maximum Segments Accepted: %u (%u segments accepted).",
						((bacapp_max_seg_resp >> 4) & 0x0f), max_segs);
				max_apdu = decode_max_apdu(bacapp_max_seg_resp);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_max_response, 
					tvb, offset, 1, bacapp_max_seg_resp,
					"Maximum APDU Accepted: %u (%u octets)",
					bacapp_max_seg_resp,max_apdu);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				/* segmented messages have 2 additional bytes */
				if (bacapp_type_seg & BACAPP_SEGMENTED_REQUEST)
				{
					bacapp_sequence_number = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(bacapp_tree, hf_bacapp_sequence_number, 
						tvb, offset, 1, bacapp_sequence_number);
					offset++;
					bacapp_window_size = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(bacapp_tree, hf_bacapp_window_size, 
						tvb, offset, 1, bacapp_window_size);
					offset++;
				}
				bacapp_service = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_service_choice, 
					tvb, offset, 1, bacapp_service, 
					"Service Choice: %u (%s)", bacapp_service,
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				offset++;
				break;
			case BACAPP_TYPE_UNCONFIRMED_SERVICE_REQUEST:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_service = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_service_choice, 
					tvb, offset, 1, bacapp_service, 
					"Service Choice: %u (%s)", bacapp_service,
					val_to_str(bacapp_service, 
						bacapp_unconfirmed_service_names,
						bacapp_unknown_service_str));
				offset++;
				break;
			case BACAPP_TYPE_SIMPLE_ACK:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				bacapp_service = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_service_choice, 
					tvb, offset, 1, bacapp_service, 
					"Service Choice: %u (%s)", bacapp_service,
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				offset++;
				break;
			case BACAPP_TYPE_COMPLEX_ACK:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_segmented_request,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_more_segments,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				/* segmented messages have 2 additional bytes */
				if (bacapp_type_seg & BACAPP_SEGMENTED_REQUEST)
				{
					bacapp_sequence_number = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(bacapp_tree, hf_bacapp_sequence_number, 
						tvb, offset, 1, bacapp_sequence_number);
					offset++;
					bacapp_window_size = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(bacapp_tree, hf_bacapp_window_size, 
						tvb, offset, 1, bacapp_window_size);
					offset++;
				}
				bacapp_service = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_service_choice, 
					tvb, offset, 1, bacapp_service, 
					"Service Choice: %u (%s)", bacapp_service,
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				offset++;
				break;
			case BACAPP_TYPE_SEGMENT_ACK:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_segment_nak,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_sent_by,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				bacapp_sequence_number = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_sequence_number, 
					tvb, offset, 1, bacapp_sequence_number);
				offset++;
				bacapp_window_size = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_window_size, 
					tvb, offset, 1, bacapp_window_size);
				offset++;
				break;
			case BACAPP_TYPE_ERROR:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				bacapp_service = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_error_choice, 
					tvb, offset, 1, bacapp_service, 
					"Error Choice: %u (%s)", bacapp_service,
					val_to_str(bacapp_service, 
						bacapp_confirmed_service_names,
						bacapp_unknown_service_str));
				offset++;
				break;
			case BACAPP_TYPE_REJECT:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				bacapp_reason = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_reject_reason, 
					tvb, offset, 1, bacapp_reason, 
					"Reject Reason: %u (%s)", bacapp_reason,
					bacapp_reject_reason_name(bacapp_reason));
				offset++;
				break;
			case BACAPP_TYPE_ABORT:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				bacapp_invoke_id = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(bacapp_tree, hf_bacapp_invoke_id, 
					tvb, offset, 1, bacapp_invoke_id);
				offset++;
				bacapp_reason = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format(bacapp_tree, hf_bacapp_reject_reason, 
					tvb, offset, 1, bacapp_reason, 
					"Abort Reason: %u (%s)", bacapp_reason,
					bacapp_abort_reason_name(bacapp_reason));
				offset++;
				break;
			default:
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_3,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_2,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_1,
					tvb, offset, 1, bacapp_type_seg);
				proto_tree_add_boolean(bacapp_tree, hf_bacapp_reserved_bit_0,
					tvb, offset, 1, bacapp_type_seg);
				offset++;
				break;
		}
	}
	next_tvb = tvb_new_subset(tvb,offset,-1,-1);
	call_dissector(data_handle,next_tvb, pinfo, tree);
}


void
proto_register_bacapp(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacapp_type,
			{ "APDU Type",
			"bacapp.apdu_type",
			FT_UINT8, BASE_DEC, NULL, 0xf0, "APDU Type", HFILL }
		},
		{ &hf_bacapp_segmented_request,
			{ "Segmented Request",
			"bacapp.segmented_request",
			FT_BOOLEAN, 8, TFS(&tfs_segmented_request), 
			BACAPP_SEGMENTED_REQUEST, "Segmented Request", HFILL }
		},
		{ &hf_bacapp_more_segments,
			{ "More Segments",
			"bacapp.more_segments",
			FT_BOOLEAN, 8, TFS(&tfs_more_segments), 
			BACAPP_MORE_SEGMENTS, "More Segments", HFILL }
		},
		{ &hf_bacapp_segmented_response,
			{ "Segmented Response",
			"bacapp.segmented_response",
			FT_BOOLEAN, 8, TFS(&tfs_segmented_response), 
			BACAPP_SEGMENTED_RESPONSE, "Segmented Response", HFILL }
		},
		{ &hf_bacapp_max_segments,
			{ "Maximum Segments Accepted",
			"bacapp.max_segments_accepted",
			FT_UINT8, BASE_DEC, NULL, 0x70, "Maximum Segments Accepted", HFILL }
		},
		{ &hf_bacapp_max_response,
			{ "Maximum APDU accepted",
			"bacapp.max_apdu_accepted",
			FT_UINT8, BASE_DEC, NULL, 0x0f, "Maximum APDU accepted", HFILL }
		},
		{ &hf_bacapp_invoke_id,
			{ "Invoke ID",           
			"bacapp.invoke_id",
			FT_UINT8, BASE_DEC, NULL, 0, "Invoke ID", HFILL }
		},
		{ &hf_bacapp_sequence_number,
			{ "Sequence Number",
			"bacapp.segment_sequence_number",
			FT_UINT8, BASE_DEC, NULL, 0, "Sequence Number", HFILL }
		},
		{ &hf_bacapp_window_size,
			{ "Proposed Window Size",           
			"bacapp.segment_window_size",
			FT_UINT8, BASE_DEC, NULL, 0, "Proposed Window Size", HFILL }
		},
		{ &hf_bacapp_service_choice,
			{ "Service Choice",           
			"bacapp.service_choice",
			FT_UINT8, BASE_DEC, NULL, 0, "Service Choice", HFILL }
		},
		{ &hf_bacapp_segment_nak,
			{ "Segment NAK",
			"bacapp.segment_nak",
			FT_BOOLEAN, 8, TFS(&tfs_segment_nak), 
			BACAPP_SEGMENT_NAK, "Segment NAK", HFILL }
		},
		{ &hf_bacapp_sent_by,
			{ "Sent By",
			"bacapp.segment_sent_by",
			FT_BOOLEAN, 8, TFS(&tfs_sent_by), 
			BACAPP_SENT_BY, "Sent By", HFILL }
		},
		{ &hf_bacapp_error_choice,
			{ "Error Choice",           
			"bacapp.error_choice",
			FT_UINT8, BASE_DEC, NULL, 0, "Error Choice", HFILL }
		},
		{ &hf_bacapp_reject_reason,
			{ "Reject Reason",           
			"bacapp.reject_reason",
			FT_UINT8, BASE_DEC, NULL, 0, "Reject Reason", HFILL }
		},
		{ &hf_bacapp_abort_reason,
			{ "Abort Reason",           
			"bacapp.abort_reason",
			FT_UINT8, BASE_DEC, NULL, 0, "Abort Reason", HFILL }
		},
		{ &hf_bacapp_reserved_bit_0,
			{ "Reserved Bit 0",
			"bacapp.reserved_bit_0",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x01, "Reserved Bit 0", HFILL }
		},
		{ &hf_bacapp_reserved_bit_1,
			{ "Reserved Bit 1",
			"bacapp.reserved_bit_1",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x02, "Reserved Bit 1", HFILL }
		},
		{ &hf_bacapp_reserved_bit_2,
			{ "Reserved Bit 2",
			"bacapp.reserved_bit_2",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x04, "Reserved Bit 2", HFILL }
		},
		{ &hf_bacapp_reserved_bit_3,
			{ "Reserved Bit 3",
			"bacapp.reserved_bit_3",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x08, "Reserved Bit 3", HFILL }
		},
		{ &hf_bacapp_reserved_bit_4,
			{ "Reserved Bit 4",
			"bacapp.reserved_bit_4",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x10, "Reserved Bit 4", HFILL }
		},
		{ &hf_bacapp_reserved_bit_5,
			{ "Reserved Bit 5",
			"bacapp.reserved_bit_5",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x20, "Reserved Bit 5", HFILL }
		},
		{ &hf_bacapp_reserved_bit_6,
			{ "Reserved Bit 6",
			"bacapp.reserved_bit_6",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x40, "Reserved Bit 6", HFILL }
		},
		{ &hf_bacapp_reserved_bit_7,
			{ "Reserved Bit 7",
			"bacapp.reserved_bit_7",
			FT_BOOLEAN, 8, TFS(&tfs_reserved_bit), 
			0x80, "Reserved Bit 7", HFILL }
		},
	};
	
	static gint *ett[] = {
		&ett_bacapp,
	};
	proto_bacapp = proto_register_protocol("Building Automation and Control Network APDU",
	    "BACapp", "bacapp");
	proto_register_field_array(proto_bacapp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("bacapp", dissect_bacapp, proto_bacapp);
}

void
proto_reg_handoff_bacapp(void)
{
	data_handle = find_dissector("data");
}

