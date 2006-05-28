/* packet-v5ua.c
 * Routines for V5.2-User Adaptation Layer dissection
 * 
 * Extension of ISDN Q.921-User Adaptation Layer dissection
 * Copyright 2002, Michael Tuexen <Michael.Tuexen[AT]siemens.com>
 *
 * Christoph Neusch <christoph.neusch@nortelnetworks.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/sctpppids.h>      /* include V5UA payload protocol ID */


/* Initialize the protocol and registered fields */

static int proto_v5ua                    = -1;


static dissector_handle_t q931_handle;

	/* round up parameter length to multiple of four */
#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

   /* common msg-header */
static int hf_version               = -1;
static int hf_reserved              = -1;
static int hf_msg_class             = -1;
static int hf_msg_type              = -1;
static int hf_msg_type_id           = -1;
static int hf_msg_length            = -1;
   /* V5UA message header */
static int hf_link_id               = -1;
static int hf_chnl_id               = -1;
static int hf_adaptation_layer_id   = -1;
static int hf_text_if_id     = -1;
static int hf_scn_protocol_id       = -1;
static int hf_info_string           = -1;
static int hf_dlci_zero_bit         = -1;
static int hf_dlci_spare_bit        = -1;
static int hf_dlci_sapi             = -1;
static int hf_dlci_one_bit          = -1;
static int hf_dlci_tei              = -1;
static int hf_efa                   = -1;
static int hf_spare_efa             = -1;

   /* variable length parameter (msg) */
static int hf_parameter_tag         = -1;
static int hf_parameter_tag_draft   = -1;
static int hf_parameter_length      = -1;
static int hf_parameter_value       = -1;
static int hf_parameter_padding     = -1;


	/* parameter fields */
static int hf_link_status           = -1;
static int hf_sa_bit_id             = -1;
static int hf_sa_bit_value          = -1;
static int hf_diagnostic_info       = -1;
static int hf_if_range_start        = -1;
static int hf_if_range_end          = -1;
static int hf_heartbeat_data        = -1;
static int hf_traffic_mode_type     = -1;
static int hf_error_code            = -1;
static int hf_draft_error_code      = -1;
static int hf_status_type           = -1;
static int hf_status_id             = -1;
static int hf_error_reason          = -1;
static int hf_asp_reason            = -1;
static int hf_tei_status            = -1;
static int hf_tei_draft_status      = -1;
static int hf_release_reason        = -1;

	/* Layer 3 message fields */
static int hf_l3_protocol_discriminator  = -1;
static int hf_l3_adress                  = -1;
static int hf_l3_low_adress              = -1;
static int hf_l3_msg_type                = -1;
static int hf_l3_info_element            = -1;

static int hf_l3_sequence_number         = -1;
static int hf_l3_v5_link_id              = -1;
static int hf_l3_v5_time_slot            = -1;

		/*PSTN Message*/
static int hf_l3_line_info               = -1;
static int hf_l3_cad_ringing             = -1;
static int hf_l3_pulse_type              = -1;
static int hf_l3_suppression_indicator   = -1;
static int hf_l3_pulse_duration          = -1;
static int hf_l3_ack_request_indicator   = -1;
static int hf_l3_number_of_pulses        = -1;
static int hf_l3_steady_signal           = -1;
static int hf_l3_auto_signalling_sequence= -1;
static int hf_l3_pulse_notify            = -1;
static int hf_l3_sequence_response       = -1;
static int hf_l3_digit_ack               = -1;
static int hf_l3_digit_info              = -1;
static int hf_l3_res_unavailable         = -1;
static int hf_l3_state                   = -1;
static int hf_l3_cause_type              = -1;
static int hf_l3_pstn_sequence_number    = -1;
static int hf_l3_duration_type           = -1;
		/*link control*/
static int hf_l3_link_control_function   = -1;
		/*Protection protocol*/
static int hf_l3_rejection_cause_type    = -1;
		/*BCC protocol*/
static int hf_l3_pstn_user_port_id            = -1;
static int hf_l3_pstn_user_port_id_lower      = -1;
static int hf_l3_isdn_user_port_id            = -1;
static int hf_l3_isdn_user_port_id_lower      = -1;
static int hf_l3_isdn_user_port_ts_num        = -1;
static int hf_l3_override                     = -1;
static int hf_l3_reject_cause_type            = -1;
static int hf_l3_bcc_protocol_error_cause     = -1;
static int hf_l3_connection_incomplete_reason = -1;
		/*Control protocol*/
static int hf_l3_control_function_element = -1;
static int hf_l3_control_function_id      = -1;
static int hf_l3_variant                  = -1;
static int hf_l3_if_id                    = -1;
static int hf_l3_performance_grading      = -1;
static int hf_l3_cp_rejection_cause       = -1;


/* Initialize the subtree pointers */
static gint ett_v5ua              = -1;
static gint ett_v5ua_common_header= -1;
static gint ett_v5ua_parameter    = -1;
static gint ett_v5ua_layer3       = -1;

#define RFC             0x1
#define DRAFT           0x2
	/* Version of IUA */
static int iua_version = RFC;
    /* Variables neccessary for dissection of draft messages */
static int msg_class   = -1;
static int msg_type    = -1;
static int msg_length  = -1;



/* Code to actually dissect the packets */


	/* define the parameters for the Tags: Tag-Type,Tag-Length,Tag-Value (Payload) */
#define PARAMETER_TAG_OFFSET    0
#define PARAMETER_TAG_LENGTH    2
#define PARAMETER_LENGTH_OFFSET (PARAMETER_TAG_OFFSET + PARAMETER_TAG_LENGTH)
#define PARAMETER_LENGTH_LENGTH 2
#define PARAMETER_VALUE_OFFSET  (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)
#define PARAMETER_HEADER_OFFSET PARAMETER_TAG_OFFSET
#define PARAMETER_HEADER_LENGTH (PARAMETER_TAG_LENGTH + PARAMETER_LENGTH_LENGTH)


/*----------------------V5UA Interface Identifier (int) (Draft,RFC)------------*/ 

	/* define parameter for the format of the integer formatted Interface Identifier */
#define INT_IF_ID_LINK_OFFSET PARAMETER_VALUE_OFFSET
#define INT_IF_ID_LINK_LENGTH 4
#define INT_IF_ID_CHNL_OFFSET INT_IF_ID_LINK_OFFSET
#define INT_IF_ID_CHNL_LENGTH 1
	
static void
dissect_int_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 identifier;

  proto_tree_add_item(parameter_tree, hf_link_id, parameter_tvb, INT_IF_ID_LINK_OFFSET, INT_IF_ID_LINK_LENGTH, FALSE);
  identifier = tvb_get_ntohl(parameter_tvb,INT_IF_ID_LINK_OFFSET)>>5;
  proto_item_append_text(parameter_item, "  Link: %d ",identifier);
  
  proto_tree_add_item(parameter_tree, hf_chnl_id, parameter_tvb, INT_IF_ID_CHNL_OFFSET+3, INT_IF_ID_CHNL_LENGTH, FALSE);
  identifier = tvb_get_guint8(parameter_tvb,INT_IF_ID_CHNL_OFFSET+3)&0x1f;
  proto_item_append_text(parameter_item, " Chnl: %d ", identifier);


}
/*----------------------V5UA Interface Identifier (int) (Draft,RFC)------------*/

/*----------------------Text Interface Identifier (RFC)------------------------*/

#define TEXT_IF_ID_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define TEXT_IF_ID_VALUE_OFFSET  PARAMETER_VALUE_OFFSET
#define TEXT_IF_ID_HEADER_LENGTH PARAMETER_HEADER_LENGTH
static void
dissect_text_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 if_id_length;

  if_id_length = tvb_get_ntohs(parameter_tvb, TEXT_IF_ID_LENGTH_OFFSET) - TEXT_IF_ID_HEADER_LENGTH;

  proto_tree_add_item(parameter_tree, hf_text_if_id, parameter_tvb, TEXT_IF_ID_VALUE_OFFSET, if_id_length, FALSE);
  proto_item_append_text(parameter_item, " (0x%.*s)", if_id_length,
                         (const char *)tvb_get_ptr(parameter_tvb, TEXT_IF_ID_VALUE_OFFSET, if_id_length));
}
/*----------------------Text Interface Identifier (RFC)------------------------*/

/*----------------------DLCI & Envelope Function Address------------------------*/


/* interpretation of EFA-values */
static const value_string efa_values[] = {
	{ 8175, "ISDN Protocol" },
	{ 8176, "PSTN Protocol" },
	{ 8177, "CC Protocol" },
	{ 8178, "BCC Protocol" },
	{ 8179, "PROT Protocol" },
	{ 8180, "Link Contol Protocol" },
	{ 8191, "VALUE RESERVED" },
	{ 0,    NULL } };

#define DLCI_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define DLCI_SAPI_OFFSET   PARAMETER_VALUE_OFFSET
#define DLCI_HEADER_LENGTH PARAMETER_HEADER_LENGTH

#define DLCI_SAPI_LENGTH   1
#define DLCI_TEI_LENGTH    1
#define EFA_LENGTH         2

static void
dissect_dlci_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 efa = 0, offset=0;

  if     (iua_version == RFC)   offset = DLCI_SAPI_OFFSET;
  else if(iua_version == DRAFT) offset = DLCI_HEADER_LENGTH + tvb_get_ntohs(parameter_tvb, DLCI_LENGTH_OFFSET);

  proto_tree_add_item(parameter_tree, hf_dlci_zero_bit,  parameter_tvb, offset,  DLCI_SAPI_LENGTH,  FALSE);
  proto_tree_add_item(parameter_tree, hf_dlci_spare_bit, parameter_tvb, offset,  DLCI_SAPI_LENGTH,  FALSE);
  proto_tree_add_item(parameter_tree, hf_dlci_sapi,      parameter_tvb, offset,  DLCI_SAPI_LENGTH,  FALSE);

  offset += DLCI_SAPI_LENGTH;
  proto_tree_add_item(parameter_tree, hf_dlci_one_bit,   parameter_tvb, offset,  DLCI_TEI_LENGTH,   FALSE);
  proto_tree_add_item(parameter_tree, hf_dlci_tei,       parameter_tvb, offset,  DLCI_TEI_LENGTH,   FALSE);

  /* if SAPI & TEI not set to ZERO, value of EFA must be decode (EFA = 0 -> ISDN protocol)*/
  if(tvb_get_ntohs(parameter_tvb,offset-DLCI_TEI_LENGTH) != 0x01){

	  offset += DLCI_TEI_LENGTH;
	  efa = tvb_get_ntohs(parameter_tvb, offset);
	  /* EFA-Values for ISDN-Protocal. For the "value_string"-function value must set to 8175 */
	  if(efa < 8175) efa = 8175;
	  /* Reserved values. For the "value_string"-function value must set to 8191 */
	  else if ((efa >= 8181) && (efa < 8191)) efa = 8191;
	  proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
								"Envelope function address: %s (%u)", val_to_str(efa, efa_values, "unknown EFA"),tvb_get_ntohs(parameter_tvb, offset));
	  proto_item_append_text(parameter_item, " (EFA: %s )",val_to_str(efa, efa_values, "unknown EFA-value"));
  }
  /* if SAPI & TEI set to ZERO, EFA also shall be set to ZERO and didn't comply with value for ISDN protocol */
  else{
	  proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
								"Envelope function address: 0");
	  proto_item_append_text(parameter_item, " (EFA: 0 )");
  }

}
/*----------------------DLCI & Envelope Function Address------------------------*/

/*----------------------Error Indication (Draft)-------------------------------*/

	/* define Error Code Parameter for Layer Management (MGMT) Messages */
#define MGMT_ERROR_INVALID_TEI_DRAFT                       0x00
#define MGMT_ERROR_INVALID_IFID_DRAFT                      0x01
#define MGMT_ERROR_UNDEFINIED_MSG_DRAFT                    0x02
#define MGMT_ERROR_VERSION_ERR_DRAFT                       0x03
#define MGMT_ERROR_INVALID_STID_DRAFT                      0x04
#define MGMT_ERROR_INVALID_SCNV_DRAFT                      0x05
#define MGMT_ERROR_INVALID_ALI_DRAFT                       0x06

static const value_string draft_error_code_values[] = {
  { MGMT_ERROR_INVALID_TEI_DRAFT,     "Invalid TEI" },
  { MGMT_ERROR_INVALID_IFID_DRAFT,    "Invalid interface ID" },
  { MGMT_ERROR_UNDEFINIED_MSG_DRAFT,  "An unexpected message was received" },
  { MGMT_ERROR_VERSION_ERR_DRAFT,     "The IUA layers are of different version" },
  { MGMT_ERROR_INVALID_STID_DRAFT,    "Invalid SCTP stream identifier" },
  { MGMT_ERROR_INVALID_SCNV_DRAFT,    "Invalid SCN version" },
  { MGMT_ERROR_INVALID_ALI_DRAFT,     "Invalid Adaptation Layer Identifier" },
  { 0,                                NULL } };

#define MGMT_ERROR_MSG_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define MGMT_ERROR_MSG_HEADER_LENGTH PARAMETER_HEADER_LENGTH

#define MGMT_ERROR_CODE_LENGTH 4

static void
dissect_draft_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  guint16 offset = MGMT_ERROR_MSG_HEADER_LENGTH + tvb_get_ntohs(parameter_tvb, MGMT_ERROR_MSG_LENGTH_OFFSET) + 4;
  proto_tree_add_item(parameter_tree, hf_draft_error_code, parameter_tvb, offset, MGMT_ERROR_CODE_LENGTH, FALSE);
  offset += MGMT_ERROR_CODE_LENGTH ;
  if( tvb_length_remaining(parameter_tvb,offset) > 0 )
	  proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, offset, msg_length - offset,FALSE);
}
/*----------------------Error Indication (Draft)-------------------------------*/

/*----------------------Error Indication (RFC)---------------------------------*/

	/* define Error Code Parameter for Layer Management (MGMT) Messages */
#define MGMT_ERROR_INVALID_VERSION                     0x01
#define MGMT_ERROR_INVALID_IF_ID                       0x02
#define MGMT_ERROR_UNSUPPORTED_MSG_CLASS               0x03
#define MGMT_ERROR_UNSUPPORTED_MSG_TYPE                0x04
#define MGMT_ERROR_UNSUPPORTED_TRAFFIC_HANDLING_MODE   0x05
#define MGMT_ERROR_UNEXPECTED_MSG                      0x06
#define MGMT_ERROR_PROTOCOL_ERROR                      0x07
#define MGMT_ERROR_UNSUPPORTED_IF_ID_TYPE              0x08
#define MGMT_ERROR_INVALID_STREAM_ID                   0x09
#define MGMT_ERROR_UNASSIGNED_TEI                      0x0a
#define MGMT_ERROR_UNRECOGNIZED_SAPI                   0x0b
#define MGMT_ERROR_INVALID_TEI_SAPI_COMBINATION        0x0c

static const value_string error_code_values[] = {
  { MGMT_ERROR_INVALID_VERSION,                       "Invalid version" },
  { MGMT_ERROR_INVALID_IF_ID,                         "Invalid interface identifier" },
  { MGMT_ERROR_UNSUPPORTED_MSG_CLASS,                 "Unsuported message class" },
  { MGMT_ERROR_UNSUPPORTED_MSG_TYPE,                  "Unsupported message type" },
  { MGMT_ERROR_UNSUPPORTED_TRAFFIC_HANDLING_MODE,     "Unsupported traffic handling mode" },
  { MGMT_ERROR_UNEXPECTED_MSG,                        "Unexpected message" },
  { MGMT_ERROR_PROTOCOL_ERROR,                        "Protocol error" },
  { MGMT_ERROR_UNSUPPORTED_IF_ID_TYPE,                "Unsupported interface identifier type" },
  { MGMT_ERROR_INVALID_STREAM_ID,                     "Invalid stream identifier" },
  { MGMT_ERROR_UNASSIGNED_TEI,                        "Unassigned TEI" },
  { MGMT_ERROR_UNRECOGNIZED_SAPI,                     "Unrecognized SAPI" },
  { MGMT_ERROR_INVALID_TEI_SAPI_COMBINATION,          "Invalid TEI/SAPI combination" },
  { 0,                                                NULL } };

#define MGMT_ERROR_CODE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_error_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_error_code, parameter_tvb, MGMT_ERROR_CODE_OFFSET, MGMT_ERROR_CODE_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, MGMT_ERROR_CODE_OFFSET), error_code_values, "Unknown error code"));
}

static void
dissect_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 diag_info_length;

  diag_info_length = tvb_get_ntohs(parameter_tvb, MGMT_ERROR_MSG_LENGTH_OFFSET) - MGMT_ERROR_MSG_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_diagnostic_info, parameter_tvb, PARAMETER_VALUE_OFFSET, diag_info_length, FALSE);
  proto_item_append_text(parameter_item, " (%u byte%s)", diag_info_length, plurality(diag_info_length, "", "s"));
}
/*----------------------Error Indication (RFC)---------------------------------*/

/*----------------------Notify (RFC)-------------------------------------------*/

	/* define Status Type parameters for Notify (NTFY) Messages */
#define NTFY_STATUS_TYPE_AS_STATE_CHANGE  0x01
#define NTFY_STATUS_TYPE_OTHER            0x02

static const value_string status_type_values[] = {
  { NTFY_STATUS_TYPE_AS_STATE_CHANGE,        "Application server state change" },
  { NTFY_STATUS_TYPE_OTHER,                  "Other" },
  { 0,                                       NULL } };

	/* define Status Identification parameters for NTFY Messages (AS state change)*/
#define NTFY_STATUS_IDENT_AS_DOWN          0x01
#define NTFY_STATUS_IDENT_AS_INACTIVE      0x02
#define NTFY_STATUS_IDENT_AS_ACTIVE        0x03
#define NTFY_STATUS_IDENT_AS_PENDING       0x04
	/* define Status Identification parameters for NTFY Messages (Other)*/
#define NTFY_STATUS_INSUFFICIENT_ASP_RES_ACTIVE 0x01
#define NTFY_STATUS_ALTERNATE_ASP_ACTIVE        0x02

static const value_string status_type_id_values[] = {
  { NTFY_STATUS_TYPE_AS_STATE_CHANGE * 256 * 256 + NTFY_STATUS_IDENT_AS_DOWN,         "Application server down" },
  { NTFY_STATUS_TYPE_AS_STATE_CHANGE * 256 * 256 + NTFY_STATUS_IDENT_AS_INACTIVE,     "Application server inactive" },
  { NTFY_STATUS_TYPE_AS_STATE_CHANGE * 256 * 256 + NTFY_STATUS_IDENT_AS_ACTIVE,       "Application server active" },
  { NTFY_STATUS_TYPE_AS_STATE_CHANGE * 256 * 256 + NTFY_STATUS_IDENT_AS_PENDING,      "Application server pending" },
  { NTFY_STATUS_TYPE_OTHER * 256 * 256 + NTFY_STATUS_INSUFFICIENT_ASP_RES_ACTIVE,     "Insufficient ASP resources active in AS" },
  { NTFY_STATUS_TYPE_OTHER * 256 * 256 + NTFY_STATUS_ALTERNATE_ASP_ACTIVE,            "Alternate ASP active" },
  { 0,                                           NULL } };

#define NTFY_STATUS_TYPE_OFFSET  PARAMETER_VALUE_OFFSET
#define NTFY_STATUS_TYPE_LENGTH  2
#define NTFY_STATUS_IDENT_OFFSET (NTFY_STATUS_TYPE_OFFSET + NTFY_STATUS_TYPE_LENGTH)
#define NTFY_STATUS_IDENT_LENGTH 2

static void
dissect_status_type_identification_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 status_type, status_id;

  status_type = tvb_get_ntohs(parameter_tvb, NTFY_STATUS_TYPE_OFFSET);
  status_id   = tvb_get_ntohs(parameter_tvb, NTFY_STATUS_IDENT_OFFSET);

  proto_tree_add_item(parameter_tree, hf_status_type, parameter_tvb, NTFY_STATUS_TYPE_OFFSET, NTFY_STATUS_TYPE_LENGTH, FALSE);
  proto_tree_add_uint_format(parameter_tree, hf_status_id,  parameter_tvb, NTFY_STATUS_IDENT_OFFSET, NTFY_STATUS_IDENT_LENGTH,
                             status_id, "Status identification: %u (%s)", status_id,
                             val_to_str(status_type * 256 * 256 + status_id, status_type_id_values, "unknown"));

  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(status_type * 256 * 256 + status_id, status_type_id_values, "Unknown status information"));
}
/*----------------------Notify (RFC)-------------------------------------------*/

/*----------------------TEI Status Indication,Confirm (RFC)--------------------*/

	/* define parameters for TEI Status (Indication,Confirm) Messages */
#define TEI_STATUS_ASSIGNED       0x0
#define TEI_STATUS_UNASSIGNED     0x1

static const value_string tei_status_values[] = {
  { TEI_STATUS_ASSIGNED,   "TEI is considered assigned by Q.921" },
  { TEI_STATUS_UNASSIGNED, "TEI is considered unassigned by Q.921" },
  { 0,                     NULL } };

#define TEI_STATUS_OFFSET PARAMETER_VALUE_OFFSET
#define TEI_STATUS_LENGTH 4

static void
dissect_tei_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_tei_status, parameter_tvb, TEI_STATUS_OFFSET, TEI_STATUS_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s)",
                      val_to_str(tvb_get_ntohl(parameter_tvb, TEI_STATUS_OFFSET), tei_status_values, "Unknown TEI status"));
}
/*----------------------TEI Status (RFC)---------------------------------------*/

/*----------------------TEI Status Indication,Confirm (Draft)------------------*/
#define TEI_DRAFT_IN_SERVICE     0x0
#define TEI_DRAFT_OUT_OF_SERVICE 0x1

static const value_string tei_draft_status_values[] = {
	{ TEI_DRAFT_IN_SERVICE,    "TEI is in service" },
	{ TEI_DRAFT_OUT_OF_SERVICE,"TEI is out of service" },
	{ 0,                       NULL } };

#define TEI_STATUS_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET

static void
dissect_draft_tei_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  gint length, offset;
  offset = tvb_get_ntohs(parameter_tvb, TEI_STATUS_LENGTH_OFFSET) + 8;
  length = msg_length - offset;
  if(tvb_length_remaining(parameter_tvb, offset) > 0 ){
	  proto_tree_add_item(parameter_tree, hf_tei_draft_status, parameter_tvb, offset, TEI_STATUS_LENGTH, FALSE);
	  proto_item_append_text(parameter_item, " (%s)",
								val_to_str(tvb_get_ntohl(parameter_tvb, offset), tei_draft_status_values, "Unknown TEI Status"));
  }
}
/*----------------------TEI Status (Draft)-------------------------------------*/

/*----------------------ASP Up,Down,Active,Inactive (Draft)--------------------*/

static void
dissect_asp_msg_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 adaptation_layer_id_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  proto_tree_add_item(parameter_tree, hf_adaptation_layer_id, parameter_tvb, PARAMETER_VALUE_OFFSET, adaptation_layer_id_length, FALSE);
  proto_item_append_text(parameter_item, " (%.*s)", adaptation_layer_id_length,
                         (const char *)tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, adaptation_layer_id_length));
}

static void
dissect_scn_protocol_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 id_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  proto_tree_add_item(parameter_tree, hf_scn_protocol_id, parameter_tvb, PARAMETER_VALUE_OFFSET, id_length, FALSE);
  proto_item_append_text(parameter_item, " (%.*s)", id_length,
                         (const char *)tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, id_length));
}

/*----------------------ASP (Draft)--------------------------------------------*/

/*----------------------ASP Down + Ack (RFC)--------------------------------*/
	/* define reason parameter for Application Server Process Maintenance (ASPM) Messages */
#define ASP_REASON_MGMT   1

static const value_string asp_reason_values[] = {
  { ASP_REASON_MGMT,      "Management inhibit" },
  { 0,                    NULL } };

#define ASP_REASON_OFFSET PARAMETER_VALUE_OFFSET
#define ASP_REASON_LENGTH 4

static void
dissect_asp_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_asp_reason, parameter_tvb, ASP_REASON_OFFSET, ASP_REASON_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s)", val_to_str(tvb_get_ntohl(parameter_tvb, ASP_REASON_OFFSET), asp_reason_values, "Unknown ASP down reason"));
}


/*----------------------ASP (RFC)----------------------------------------------*/

/*----------------------Heartbeat Data + Ack (RFC)-----------------------------*/

#define HEARTBEAT_MSG_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define HEARTBEAT_DATA_OFFSET       PARAMETER_VALUE_OFFSET
#define HEARTBEAT_MSG_HEADER_LENGTH PARAMETER_HEADER_LENGTH

static void
dissect_heartbeat_data_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 heartbeat_data_length;

  heartbeat_data_length = tvb_get_ntohs(parameter_tvb, HEARTBEAT_MSG_LENGTH_OFFSET) - HEARTBEAT_MSG_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_heartbeat_data, parameter_tvb, HEARTBEAT_DATA_OFFSET, heartbeat_data_length, FALSE);
  proto_item_append_text(parameter_item, " (%u byte%s)", heartbeat_data_length, plurality(heartbeat_data_length, "", "s"));
}
/*----------------------Heartbeat Data (RFC)-----------------------------------*/


/*----------------------ASP Active,Inactive + Ack (RFC)------------------------*/
#define OVER_RIDE_TRAFFIC_MODE_TYPE  1
#define LOAD_SHARE_TRAFFIC_MODE_TYPE 2

static const value_string traffic_mode_type_values[] = {
  { OVER_RIDE_TRAFFIC_MODE_TYPE,      "Over-ride" },
  { LOAD_SHARE_TRAFFIC_MODE_TYPE,     "Load-share" },
  { 0,                    NULL } };

#define TRAFFIC_MODE_TYPE_LENGTH 4
#define TRAFFIC_MODE_TYPE_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_traffic_mode_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET), traffic_mode_type_values, "Unknown traffic mode type"));
}

#define INT_RANGE_START_OFFSET  PARAMETER_VALUE_OFFSET
#define INT_RANGE_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define INT_RANGE_HEADER_LENGTH PARAMETER_HEADER_LENGTH

#define IF_ID_START_OFFSET      0
#define IF_ID_START_LENGTH      4
#define IF_ID_END_OFFSET        (IF_ID_START_OFFSET + IF_ID_START_LENGTH)
#define IF_ID_END_LENGTH        4
#define IF_ID_INTERVAL_LENGTH   (IF_ID_START_LENGTH + IF_ID_END_LENGTH)


static void
dissect_integer_range_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 number_of_ranges, range_number, offset;

  number_of_ranges = (tvb_get_ntohs(parameter_tvb, INT_RANGE_LENGTH_OFFSET) - INT_RANGE_HEADER_LENGTH) / IF_ID_INTERVAL_LENGTH;
  offset = INT_RANGE_START_OFFSET;
  for(range_number = 1; range_number <= number_of_ranges; range_number++) {
    proto_tree_add_item(parameter_tree, hf_if_range_start, parameter_tvb, offset + IF_ID_START_OFFSET, IF_ID_START_LENGTH, FALSE);
    proto_tree_add_item(parameter_tree, hf_if_range_end,   parameter_tvb, offset + IF_ID_END_OFFSET,   IF_ID_END_LENGTH,   FALSE);
    offset += IF_ID_INTERVAL_LENGTH;
  };

  proto_item_append_text(parameter_item, " (%u range%s)", number_of_ranges, plurality(number_of_ranges, "", "s"));
}
/*----------------------ASP Active,Inactive (RFC)------------------------------*/

/*----------------------Data Request,Indication (Draft,RFC)--------------------*/
/* message types of PSTN */
#define ESTABLISH           0x00
#define ESTABLISH_ACK       0x01
#define SIGNAL              0x02
#define SIGNAL_ACK          0x03
#define DISCONNECT          0x08
#define DISCONNECT_COMPLETE 0x09
#define STATUS_ENQUIRY      0x0c
#define STATUS              0x0d
#define PROTOCOL_PARAMETER  0x0e
/* message types of Control protocol */
#define PORT_CONTROL        0x10
#define PORT_CONTROL_ACK    0x11
#define COMMON_CONTROL      0x12
#define COMMON_CONTROL_ACK  0x13
/* message types of PROT protocol */
#define SWITCH_OVER_REQ     0x18
#define SWITCH_OVER_COM     0x19
#define OS_SWITCH_OVER_COM  0x1a
#define SWITCH_OVER_ACK     0x1b
#define SWITCH_OVER_REJECT  0x1c
#define PROT_PROTOCOL_ERROR 0x1d
#define RESET_SN_COM        0x1e
#define RESET_SN_ACK        0x1f
/* message types of BCC */
#define ALLOCATION             0x20
#define ALLOCATION_COMPLETE    0x21
#define ALLOCATION_REJECT      0x22
#define DE_ALLOCATION          0x23
#define DE_ALLOCATION_COMPLETE 0x24
#define DE_ALLOCATION_REJECT   0x25
#define AUDIT                  0x26
#define AUDIT_COMPLETE         0x27
#define AN_FAULT               0x28
#define AN_FAULT_ACKNOWLEDGE   0x29
#define BCC_PROTOCOL_ERROR     0x2a
/* message types of Link Control protocol */
#define LINK_CONTROL        0x30
#define LINK_CONTROL_ACK    0x31

static const value_string l3_msg_type_values [] = {
	{ ESTABLISH,             "Establish" },
	{ ESTABLISH_ACK,         "Establish Ack" },
	{ SIGNAL,                "Signal" },
	{ SIGNAL_ACK,            "Signal Ack" },
	{ DISCONNECT,            "Disconnect" },
	{ DISCONNECT_COMPLETE,   "Disconnect Complete" },
	{ STATUS_ENQUIRY,        "Status Enqueiry" },
	{ STATUS,                "Status" },
	{ PROTOCOL_PARAMETER,    "Protocol Parameter" },
	{ PORT_CONTROL,          "Port Control" },
	{ PORT_CONTROL_ACK,      "Port Control Ack" },
	{ COMMON_CONTROL,        "Common Control" },
	{ COMMON_CONTROL_ACK,    "Common Control Ack" },
	{ SWITCH_OVER_REQ,       "Switch-Over Request" },
	{ SWITCH_OVER_COM,       "Switch-Over Com" },
	{ OS_SWITCH_OVER_COM,    "OS-Switch-Over Com" },
	{ SWITCH_OVER_ACK,       "Switch-Over Ack" },
	{ SWITCH_OVER_REJECT,    "Switch-Over Reject" },
	{ PROT_PROTOCOL_ERROR,   "Protection Protocol Error" },
	{ RESET_SN_COM,          "Reset SN Com" },
	{ RESET_SN_ACK,          "Reset SN Ack" },
	{ ALLOCATION,            "Allocation" },
	{ ALLOCATION_COMPLETE,   "Allocation Complete" },
	{ ALLOCATION_REJECT,     "Allocation Reject" },
	{ DE_ALLOCATION,         "DE Allocation" },
	{ DE_ALLOCATION_COMPLETE,"DE Allocation Complete" },
	{ DE_ALLOCATION_REJECT,  "DE Allocation Reject" },
	{ AUDIT,                 "Audit" },
	{ AUDIT_COMPLETE,        "Audit Complete" },
	{ AN_FAULT,              "AN Fault" },
	{ AN_FAULT_ACKNOWLEDGE,  "AN Fault Ack" },
	{ BCC_PROTOCOL_ERROR,    "BCC Protocol Error" },
	{ LINK_CONTROL,          "Link Control" },
	{ LINK_CONTROL_ACK,      "Link Control Ack" },
	{ 0,                     NULL } };

/* PSTN protocol message info elements */
#define PULSE_NOTIFICATION   0xc0
#define LINE_INFORMATION     0x80
#define STATE                0x90
#define AUTO_SIG_SEQUENCE    0xa0
#define SEQUENCE_RESPONSE    0xb0
#define PSTN_SEQUENCE_NUMBER 0x00
#define CADENCED_RINGING     0x01
#define PULSED_SIGNAL        0x02
#define STEADY_SIGNAL        0x03
#define DIGIT_SIGNAL         0x04
#define RECOGNITION_TIME     0x10
#define ENABLE_AUTO_ACK      0x11
#define DISABLE_AUTO_ACK     0x12
#define CAUSE                0x13
#define RESOURCE_UNAVAILABLE 0x14

static const value_string l3_line_info_values [] = {
	{ 0x00, "Impedance marker reset" },
	{ 0x01, "Impedance marker set" },
	{ 0x02, "Low loop impedance" },
	{ 0x03, "Anomalous loop impedance" },
	{ 0x04, "Anomalous line condition received"},
	{ 0,    NULL } };

static const value_string l3_pulse_type_values [] = {
	{ 0xff, "Pulsed normal polarity" },
	{ 0xfe, "Pulsed reversed polarity" },
	{ 0xfd, "Pulsed battery on c-wire" },
	{ 0xfc, "Pulsed on hook" },
	{ 0xfb, "Pulsed reduced battery" },
	{ 0xfa, "Pulsed no battery" },
	{ 0xf9, "Initial ring" },
	{ 0xf8, "Meter pulse" },
	{ 0xf7, "50 Hz pulse" },
	{ 0xf6, "Register recall (timed loop open)" },
	{ 0xf5, "Pulsed off hook (pulsed loop closed)" },
	{ 0xf4, "Pulsed b-wire connected to earth" },
	{ 0xf3, "Earth loop pulse" },
	{ 0xf2, "Pulsed b-wire connected to battery" },
	{ 0xf1, "Pulsed a-wire connected to earth" },
	{ 0xf0, "Pulsed a-wire connected to battery" },
	{ 0xef, "Pulsed c-wire connected to earth" },
	{ 0xee, "Pulsed c-wire disconnected" },
	{ 0xed, "Pulsed normal battery" },
	{ 0xec, "Pulsed a-wire disconnected" },
	{ 0xeb, "Pulsed b-wire disconnected" },
	{ 0,    NULL } };

static const value_string l3_suppression_indication_values [] = {
	{ 0x0, "No suppression" },
	{ 0x1, "Suppression allowed by pre-defined V5.1 SIGNAL msg from LE" },
	{ 0x2, "Suppression allowed by pre-defined line signal from TE" },
	{ 0x3, "Suppression allowed by pre-defined V5.1 SIGNAL msg from LE or line signal from TE" },
	{ 0,   NULL } };

static const value_string l3_ack_request_indication_values [] = {
	{ 0x0, "No acknowledgement requested" },
	{ 0x1, "Ending acknowledgement requested when finished each pulses" },
	{ 0x2, "Ending acknowledgement requested when finished all pulses" },
	{ 0x3, "Start of pulse acknowledgement requested" },
	{ 0,   NULL } };

static const value_string l3_digit_ack_values [] = {
	{ 0x0, "No ending acknowledgement requested" },
	{ 0x1, "Ending acknowledgement requested when digit transmission is finished" },
	{ 0,   NULL } };

static const value_string l3_state_values [] = {
	{ 0x00, "AN0" },
	{ 0x01, "AN1" },
	{ 0x02, "AN2" },
	{ 0x03, "AN3" },
	{ 0x04, "AN4" },
	{ 0x05, "AN5" },
	{ 0x06, "AN6" },
	{ 0x07, "AN7" },
	{ 0,    NULL } };

static const value_string l3_steady_signal_values [] = {
	{ 0x80, "Normal polarity" },
	{ 0x81, "Reversed polarity" },
	{ 0x82, "Battery on c-wire" },
	{ 0x83, "No battery on c-wire" },
	{ 0x84, "Off hook (loop closed)" },
	{ 0x85, "On hook (loop open)" },
	{ 0x86, "Battery on a-wire" },
	{ 0x87, "A-wire on earth" },
	{ 0x88, "No battery on a-wire" },
	{ 0x89, "No batery on b-wire" },
	{ 0x8a, "Reduced battery" },
	{ 0x8b, "No battery" },
	{ 0x8c, "Alternate reduced power / no power" },
	{ 0x8d, "Normal battery" },
	{ 0x8e, "Stop ringing" },
	{ 0x8f, "Start pilot frequency" },
	{ 0x90, "Stop pilot frequency" },
	{ 0x91, "Low impedance on b-wire" },
	{ 0x92, "B-wire connected to earth" },
	{ 0x93, "B-wire disconnected from earth" },
	{ 0x94, "Battery on b-wire" },
	{ 0x95, "Low loop impedance" },
	{ 0x96, "High loop impedance" },
	{ 0x97, "Anomalous loop impedance" },
	{ 0x98, "A-wire disconnected from earth" },
	{ 0x99, "C-wire on earth" },
	{ 0x9a, "C-wire disconnected from earth" },
	{ 0,    NULL } };

static const value_string l3_cause_type_values [] = {
	{ 0x00, "Response to STATUS ENQUIRY" },
	{ 0x01, "Protocol discriminator error" },
	{ 0x03, "L3 address error" },
	{ 0x04, "Message type unrecognized" },
	{ 0x05, "Out of sequence information element" },
	{ 0x06, "Repeated optional information element" },
	{ 0x07, "Mandatory information element missing" },
	{ 0x08, "Unrecognized information element" },
	{ 0x09, "Mandatory information element content error" },
	{ 0x0a, "Optional information element content error" },
	{ 0x0b, "Message not compatible with path state" },
	{ 0x0c, "Repeated mandatory information element" },
	{ 0x0d, "Too many information elements" },
	{ 0,    NULL } };

/* BCC protocol message info elements */
#define USER_PORT_ID             0x40
#define ISDN_PORT_CHNL_ID        0x41
#define V5_TIME_SLOT_ID          0x42
#define MULTI_SLOT_MAP           0x43
#define BCC_REJECT_CAUSE         0x44
#define BCC_PROTOCOL_ERROR_CAUSE 0x45
#define CONNECTION_INCOMPLETE    0x46

static const value_string l3_reject_cause_type_values [] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Access network fault" },
	{ 0x02, "Access network blocked (internally)" },
	{ 0x03, "Connection already present at the PSTN user port to a different V5 time slot" },
	{ 0x04, "Connection already present at the V5 time slot(s) to a different port or ISDN user port time slot(s)" },
	{ 0x05, "Connection already present at the ISDN user port time slot(s) to a different V5 time slot(s)" },
	{ 0x06, "User port unavailable (blocked)" },
	{ 0x07, "De-allocation cannot completeddue to incompatible data content" },
	{ 0x08, "De-allocation cannot completeddue to V5 time slot(s) data incompatibility" },
	{ 0x09, "De-allocation cannot completeddue to port data incompatibility" },
	{ 0x0a, "De-allocation cannot completeddue to user port time slot(s) data incompatibility" },
	{ 0x0b, "User port not provisioned" },
	{ 0x0c, "Invalid V5 time slot(s) indication(s)" },
	{ 0x0d, "Invalid V5 2048 kbit/s link indication" },
	{ 0x0e, "Invalid user time slot(s) indication(s)" },
	{ 0x0f, "V5 time slot(s) being used as physikal C-channel(s)" },
	{ 0x10, "V5 link unavailable (blocked)" },
	{ 0,    NULL } };

static const value_string l3_bcc_protocol_error_cause_type_values [] = {
	{ 0x01, "Protocol discriminator error" },
	{ 0x04, "Message type unrecognized" },
	{ 0x05, "Out of sequence information element" },
	{ 0x06, "Repeated optional information element" },
	{ 0x07, "Mandatory information element missing" },
	{ 0x08, "Unrecognized information element" },
	{ 0x09, "Mandatory information element content error" },
	{ 0x0a, "Optional infromation element content error" },
	{ 0x0b, "Message not compatible with the BCC protocol state" },
	{ 0x0c, "Repeated mandatory information element" },
	{ 0x0d, "Too many information element" },
	{ 0x0f, "BCC Reference Number coding error" },
	{ 0,    NULL } };

static const value_string l3_connection_incomplete_reason_values [] = {
	{ 0x00, "Incomplete normal" },
	{ 0x01, "Access network fault" },
	{ 0x02, "User port not provisioned" },
	{ 0x03, "Invalid V5 time slot identification" },
	{ 0x04, "Invalid V5 2048 kbit/s link identification" },
	{ 0x05, "Time slot being used as physikal C-channel" },
	{ 0,    NULL } };


/* Link control protocol message info elements */
#define LINK_CONTROL_FUNCTION 0x30

static const value_string l3_link_control_function_values [] = {
	{ 0x00, "FE-IDReq" },
	{ 0x01, "FE-IDAck" },
	{ 0x02, "FE-IDRel" },
	{ 0x03, "FE-IDRej" },
	{ 0x04, "FE301/302 (link unblock)" },
	{ 0x05, "FE303/304 (link block)" },
	{ 0x06, "FE305 (deferred link block request" },
	{ 0x07, "FE306 (non-deferred link block request)" },
	{ 0,    NULL } };

/* Protection protocol message info elements */
#define SEQUENCE_NUMBER    0x50
#define C_CHANNEL_ID       0x51
#define PP_REJECTION_CAUSE 0x52
#define PROTOCOL_ERROR     0x53

/* Control protocolmessage info elements  */
#define PERFORMANCE_GRADING      0xe0
#define CP_REJECTION_CAUSE       0xf0
#define CONTROL_FUNCTION_ELEMENT 0x20
#define CONTROL_FUNCTION_ID      0x21
#define VARIANT                  0x22
#define INTERFACE_ID             0x23

static const value_string l3_performance_grading_values [] = {
	{ 0x00, "normal grade" },
	{ 0x01, "degraded" },
	{ 0,    NULL } };

static const value_string l3_cp_rejection_cause_values [] = {
	{ 0x00, "variant unknown" },
	{ 0x01, "variant known, not ready" },
	{ 0x02, "re-provisioning in progress (re-pro)" },
	{ 0,    NULL } };

static const value_string l3_control_function_element_values [] = {
	{ 0x01, "FE101 (activate access)" },
	{ 0x02, "FE102 (activation initiated by user)" },
	{ 0x03, "FE103 (DS activated)" },
	{ 0x04, "FE104 (access activated)" },
	{ 0x05, "FE105 (deactivate access)" },
	{ 0x06, "FE106 (access deactivated)" },
	{ 0x11, "FE201/202 (unblock)" },
	{ 0x13, "FE203/204 (block)" },
	{ 0x15, "FE205 (block request)" },
	{ 0x16, "FE206 (performance grading)" },
	{ 0x17, "FE207 (D-channel block)" },
	{ 0x18, "FE208 (D-channel unblock)" },
	{ 0,    NULL } };

static const value_string l3_control_function_id_values [] = {
	{ 0x00, "Verify re-provisioning" },
	{ 0x01, "Ready for re-provisioning" },
	{ 0x02, "Not ready for re-provisioning" },
	{ 0x03, "Switch-over to new variant" },
	{ 0x04, "Re-provisioning started" },
	{ 0x05, "Cannot re-provision" },
	{ 0x06, "Request variant and interface ID" },
	{ 0x07, "Variant and interface ID" },
	{ 0x08, "Blocking started" },
	{ 0x10, "Restart request" },
	{ 0x11, "Restart complete" },
	{ 0,    NULL } };

static const value_string l3_info_element_values [] = {
	{ PULSE_NOTIFICATION,      "Pulse notification" },
	{ LINE_INFORMATION,        "Line information" },
	{ STATE,                   "State" },
	{ AUTO_SIG_SEQUENCE,       "Autonomous signal sequence" },
	{ SEQUENCE_RESPONSE,       "Sequence response" },
	{ PSTN_SEQUENCE_NUMBER,    "Sequence number" },
	{ CADENCED_RINGING,        "Cadenced ringing" },
	{ PULSED_SIGNAL,           "Pulsed signal" },
	{ STEADY_SIGNAL,           "Steady signal" },
	{ DIGIT_SIGNAL,            "Digit signal" },
	{ RECOGNITION_TIME,        "Recognition time" },
	{ ENABLE_AUTO_ACK,         "Enable autonomous acknowledge" },
	{ DISABLE_AUTO_ACK,        "Disable autonomous acknowledge" },
	{ CAUSE,                   "Cause" },
	{ RESOURCE_UNAVAILABLE,    "Resource unavailable" },
	{ PERFORMANCE_GRADING,     "Performance grading" },
	{ CP_REJECTION_CAUSE,      "Rejection cause" },
	{ CONTROL_FUNCTION_ELEMENT,"Control function element" },
	{ CONTROL_FUNCTION_ID,     "Control function ID" },
	{ VARIANT,                 "Variant" },
	{ INTERFACE_ID,            "Interface ID" },
	{ LINK_CONTROL_FUNCTION,   "Link control funktion" },
	{ USER_PORT_ID,            "User port ID" },
	{ ISDN_PORT_CHNL_ID,       "ISDN port channel ID" },
	{ V5_TIME_SLOT_ID,         "V5 time slot ID" },
	{ MULTI_SLOT_MAP,          "Multi slot map" },
	{ BCC_REJECT_CAUSE,        "Reject cause" },
	{ BCC_PROTOCOL_ERROR_CAUSE,"Protocol error cause" },
	{ CONNECTION_INCOMPLETE,   "Connection incomplete" },
	{ SEQUENCE_NUMBER,         "Sequence number" },
	{ C_CHANNEL_ID,            "C-Channel ID" },
	{ PP_REJECTION_CAUSE,      "Rejection cause" },
	{ PROTOCOL_ERROR,          "Protocol error" },
	{ 0,                       NULL } };


#define DISCRIMINATOR_OFFSET 0
#define DISCRIMINATOR_LENGTH 1
#define ADDRESS_OFFSET       1
#define ADDRESS_LENGTH       1
#define LOW_ADDRESS_OFFSET   2
#define LOW_ADDRESS_LENGTH   1
#define MSG_TYPE_OFFSET      3
#define MSG_TYPE_LENGTH      1
#define MSG_HEADER_LENGTH    4
#define INFO_ELEMENT_OFFSET  4
#define INFO_ELEMENT_LENGTH  1

static void
dissect_layer3_message(tvbuff_t *layer3_data_tvb, proto_tree *v5ua_tree,proto_item *parameter_item, packet_info *pinfo)
{
  proto_item *layer3_header_item,*layer3_item;
  proto_tree *layer3_header_tree,*layer3_tree;
  guint16 discriminator_offset, address_offset, low_address_offset, msg_type_offset,  info_element_offset;
  guint8  info_element, info_element_length, buffer;

  if(iua_version == DRAFT){
	  discriminator_offset = DISCRIMINATOR_OFFSET;
	  address_offset       = ADDRESS_OFFSET;
	  low_address_offset   = LOW_ADDRESS_OFFSET;
	  msg_type_offset      = MSG_TYPE_OFFSET;
	  info_element_offset  = INFO_ELEMENT_OFFSET;
  }
  else{
	  discriminator_offset = DISCRIMINATOR_OFFSET + PARAMETER_HEADER_LENGTH;
	  address_offset       = ADDRESS_OFFSET + PARAMETER_HEADER_LENGTH;
	  low_address_offset   = LOW_ADDRESS_OFFSET + PARAMETER_HEADER_LENGTH;
	  msg_type_offset      = MSG_TYPE_OFFSET + PARAMETER_HEADER_LENGTH;
	  info_element_offset  = INFO_ELEMENT_OFFSET + PARAMETER_HEADER_LENGTH;
  }
  

  if(tvb_get_guint8(layer3_data_tvb, discriminator_offset) == 0x48){
	  layer3_header_item   = proto_tree_add_text(v5ua_tree, layer3_data_tvb, discriminator_offset, MSG_HEADER_LENGTH,"Layer3 header");
	  layer3_header_tree   = proto_item_add_subtree(layer3_header_item, ett_v5ua_layer3);

	  proto_tree_add_item(layer3_header_tree, hf_l3_protocol_discriminator, layer3_data_tvb, discriminator_offset, DISCRIMINATOR_LENGTH, FALSE);
	  proto_tree_add_item(layer3_header_tree, hf_l3_adress, layer3_data_tvb, address_offset, ADDRESS_LENGTH, FALSE);
	  proto_tree_add_item(layer3_header_tree, hf_l3_low_adress, layer3_data_tvb, low_address_offset, LOW_ADDRESS_LENGTH, FALSE);
	  proto_tree_add_item(layer3_header_tree, hf_l3_msg_type, layer3_data_tvb, msg_type_offset, MSG_TYPE_LENGTH, FALSE);
	  proto_item_append_text(layer3_header_item, "  Msg Type: %s",
						  val_to_str(tvb_get_guint8(layer3_data_tvb, msg_type_offset), l3_msg_type_values, "Unknown layer3 msg type"));

	  if(tvb_length_remaining(layer3_data_tvb,info_element_offset)){
		  layer3_item   = proto_tree_add_text(v5ua_tree, layer3_data_tvb, info_element_offset, tvb_length(layer3_data_tvb)-MSG_HEADER_LENGTH,"Layer3 message");
		  layer3_tree   = proto_item_add_subtree(layer3_item, ett_v5ua_layer3);

		  info_element_offset  = INFO_ELEMENT_OFFSET;

		  while(tvb_length_remaining(layer3_data_tvb,info_element_offset)){
			  info_element = tvb_get_guint8(layer3_data_tvb, info_element_offset);
			  proto_tree_add_item_hidden(layer3_tree, hf_l3_info_element, layer3_data_tvb,info_element_offset,INFO_ELEMENT_LENGTH,FALSE);
			  switch(tvb_get_guint8(layer3_data_tvb, msg_type_offset) & 0xf0){
			  case 0x00:
				  /* Variable Length */
				  if(info_element < 0x80){
				  switch(info_element){
				  case PSTN_SEQUENCE_NUMBER:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_pstn_sequence_number,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case CADENCED_RINGING:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_cad_ringing,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case PULSED_SIGNAL:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
  					  proto_tree_add_item(layer3_tree,hf_l3_pulse_type,layer3_data_tvb,info_element_offset+2,1,FALSE);/*info_element_length,FALSE); */
					  proto_tree_add_item(layer3_tree,hf_l3_suppression_indicator,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_pulse_duration,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_ack_request_indicator,layer3_data_tvb,info_element_offset+4,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_number_of_pulses,layer3_data_tvb,info_element_offset+4,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case STEADY_SIGNAL:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_steady_signal,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  proto_item_append_text(layer3_item, "  Steady Signal: %s",
											val_to_str(tvb_get_guint8(layer3_data_tvb, info_element_offset+2), l3_steady_signal_values, "Unknown Signal"));
					  info_element_offset +=info_element_length+2;
					  break;
				  case DIGIT_SIGNAL:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  buffer = tvb_get_guint8(layer3_data_tvb, info_element_offset+2)>>6;
					  buffer = buffer&0x01;
					  proto_tree_add_uint_format(layer3_tree, hf_l3_digit_ack,layer3_data_tvb,info_element_offset+2,1,buffer,
													"Digit ack request indication: %s",val_to_str(buffer,l3_digit_ack_values,"unknown"));
					  proto_tree_add_item(layer3_tree,hf_l3_digit_info,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case RECOGNITION_TIME:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
 					  buffer = tvb_get_guint8(layer3_data_tvb,info_element_offset+2)&0x7f;
					  /*Signal = Coding of pulse type*/
					  if(buffer>=0x6b)
						proto_tree_add_item(layer3_tree,hf_l3_pulse_type,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  /*Signal = Coding of steady signal type*/
					  else if(buffer<=0x1a)
						proto_tree_add_item(layer3_tree,hf_l3_steady_signal,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_duration_type,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case ENABLE_AUTO_ACK:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
  					  buffer = tvb_get_guint8(layer3_data_tvb,info_element_offset+2)&0x7f;
					  /*Signal*/
					  if(buffer>=0x6b)
						proto_tree_add_item(layer3_tree,hf_l3_pulse_type,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  else if(buffer<=0x1a)
						proto_tree_add_item(layer3_tree,hf_l3_steady_signal,layer3_data_tvb,info_element_offset+2,1,FALSE);

					  buffer = tvb_get_guint8(layer3_data_tvb,info_element_offset+3)&0x7f;
					  /*Response*/
					  if(buffer>=0x6b)
						proto_tree_add_item(layer3_tree,hf_l3_pulse_type,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  else if(buffer<=0x1a)
						proto_tree_add_item(layer3_tree,hf_l3_steady_signal,layer3_data_tvb,info_element_offset+3,1,FALSE);
						
					  if(tvb_length_remaining(layer3_data_tvb, info_element_offset+4)){
						proto_tree_add_item(layer3_tree,hf_l3_suppression_indicator,layer3_data_tvb,info_element_offset+4,1,FALSE);
						proto_tree_add_item(layer3_tree,hf_l3_pulse_duration,layer3_data_tvb,info_element_offset+4,1,FALSE);
					  }
					  if(tvb_length_remaining(layer3_data_tvb, info_element_offset+5)){
						proto_tree_add_item(layer3_tree,hf_l3_ack_request_indicator,layer3_data_tvb,info_element_offset+5,1,FALSE);
						proto_tree_add_item(layer3_tree,hf_l3_number_of_pulses,layer3_data_tvb,info_element_offset+5,1,FALSE);
					  }
					  info_element_offset +=info_element_length+2;
					  break;
				  case DISABLE_AUTO_ACK:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  buffer = tvb_get_guint8(layer3_data_tvb,info_element_offset+2)&0x7f;
					  if(buffer>=0x6b)
						proto_tree_add_item(layer3_tree,hf_l3_pulse_type,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  else if(buffer<=0x1a)
						proto_tree_add_item(layer3_tree,hf_l3_steady_signal,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case CAUSE:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_cause_type,layer3_data_tvb,info_element_offset+2,1,FALSE);
		  			  if(tvb_length_remaining(layer3_data_tvb, info_element_offset+3))
					  proto_tree_add_uint_format(layer3_tree, hf_l3_msg_type,layer3_data_tvb, info_element_offset+3,1,tvb_get_guint8(layer3_data_tvb,info_element_offset+3),
												"Diagnostic: %s",val_to_str(tvb_get_guint8(layer3_data_tvb,info_element_offset+3),l3_msg_type_values,"unknown"));
					  info_element_offset +=info_element_length+2;
					  break;
				  case RESOURCE_UNAVAILABLE:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_res_unavailable,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  default:
					  info_element_offset += 1;
					  break;
				  }
				  }
				  /* Single Octet */
				  else if(info_element >= 0x80){
					  switch(info_element & 0xf0){
					  case PULSE_NOTIFICATION:
						  proto_tree_add_item(layer3_tree,hf_l3_pulse_notify,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  case LINE_INFORMATION:
						  proto_tree_add_item(layer3_tree,hf_l3_line_info,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  case STATE:
						  proto_tree_add_item(layer3_tree,hf_l3_state,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  case AUTO_SIG_SEQUENCE:
						  proto_tree_add_item(layer3_tree,hf_l3_auto_signalling_sequence,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  case SEQUENCE_RESPONSE:
						  proto_tree_add_item(layer3_tree,hf_l3_sequence_response,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  default:
						  break;
					  }
					  info_element_offset += 1;
				  }
				  break;

			  case 0x10:
				  /* Variable Length */
				  if(info_element < 0x80){
				  switch(info_element){
				  case CONTROL_FUNCTION_ELEMENT:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_control_function_element,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case CONTROL_FUNCTION_ID:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_control_function_id,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case VARIANT:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_variant,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case INTERFACE_ID:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_if_id,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case SEQUENCE_NUMBER:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_sequence_number,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case C_CHANNEL_ID:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_v5_link_id,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_v5_time_slot,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case PP_REJECTION_CAUSE:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_rejection_cause_type,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case PROTOCOL_ERROR:
					  break;
				  default:
					  info_element_offset += 1;
					  break;
				  }
				  }
				  /* Single Octet */
				  else if(info_element >= 0x80){
					  switch(info_element & 0xf0){
					  case PERFORMANCE_GRADING:
						  proto_tree_add_item(layer3_tree,hf_l3_performance_grading,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  case CP_REJECTION_CAUSE:
						  proto_tree_add_item(layer3_tree,hf_l3_cp_rejection_cause,layer3_data_tvb,info_element_offset,1,FALSE);
						  break;
					  default:
						  break;
					  }
					  info_element_offset += 1;
				  }
				  break;

			  case 0x20:
				  /* Variable Length */
				  switch(info_element){
				  case USER_PORT_ID:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  buffer = tvb_get_guint8(layer3_data_tvb,info_element_offset+2)&0x01;
					  if(buffer==0x01){
						  proto_tree_add_item(layer3_tree,hf_l3_pstn_user_port_id,layer3_data_tvb,info_element_offset+2,1,FALSE);
						  proto_tree_add_item(layer3_tree,hf_l3_pstn_user_port_id_lower,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  }
					  else if(buffer == 0x00){
						  proto_tree_add_item(layer3_tree,hf_l3_isdn_user_port_id,layer3_data_tvb,info_element_offset+2,1,FALSE);
						  proto_tree_add_item(layer3_tree,hf_l3_isdn_user_port_id_lower,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  }
					  info_element_offset +=info_element_length+2;			  
					  break;
				  case ISDN_PORT_CHNL_ID:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_isdn_user_port_ts_num,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case V5_TIME_SLOT_ID:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_v5_link_id,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_override,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  proto_tree_add_item(layer3_tree,hf_l3_v5_time_slot,layer3_data_tvb,info_element_offset+3,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  case MULTI_SLOT_MAP:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_v5_link_id,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  /* add ts upts here */
					  info_element_offset +=info_element_length+2;
					  break;
				  case BCC_REJECT_CAUSE:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_reject_cause_type,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  /* add diagnostic */
					  info_element_offset +=info_element_length+2;
					  break;
				  case BCC_PROTOCOL_ERROR_CAUSE:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_bcc_protocol_error_cause,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  /* add diagnostic */
					  info_element_offset +=info_element_length+2;
					  break;
				  case CONNECTION_INCOMPLETE:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_connection_incomplete_reason,layer3_data_tvb,info_element_offset+2,1,FALSE);
					  info_element_offset +=info_element_length+2;
					  break;
				  default:
					  info_element_offset += 1;
					  break;
				  }
				  break;

			  case 0x30:
				  /* Variable Length */
				  switch(info_element){
				  case LINK_CONTROL_FUNCTION:
					  info_element_length = tvb_get_guint8(layer3_data_tvb,info_element_offset+1);
					  proto_tree_add_item(layer3_tree,hf_l3_link_control_function,layer3_data_tvb,info_element_offset+2,info_element_length,FALSE);
					  info_element_offset += info_element_length+2;
					  break;
				  default:
					  info_element_offset += 1;
					  break;
				  }
				  break;

			  default:
				  info_element_offset += 1;
				  break;
			  }
		  }
	  }
  }
  else{
	  guint16 protocol_data_length;
	  tvbuff_t *protocol_data_tvb;

	  protocol_data_length = tvb_get_ntohs(layer3_data_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
	  protocol_data_tvb    = tvb_new_subset(layer3_data_tvb, PARAMETER_VALUE_OFFSET, protocol_data_length, protocol_data_length);
	  call_dissector(q931_handle, protocol_data_tvb, pinfo, v5ua_tree);

	  proto_item_append_text(parameter_item, " (%u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));
  }
}

/*----------------------Data Request,Indication (Draft,RFC)------------------------*/

/*----------------------Establish Request,Confirm,Indication (Draft,RFC)-------*/
/*
 * no additional parameter
 */
/*----------------------Establish Request,Confirm,Indication (Draft,RFC)-------*/

/*----------------------Release Indication, Request (Draft,RFC)----------------*/

	/* define parameters for Release Request and Indication Messages */
#define RELEASE_MGMT   0x0
#define RELEASE_PHYS   0x1
#define RELEASE_DM     0x2
#define RELEASE_OTHER  0x3

static const value_string release_reason_values[] = {
	{ RELEASE_MGMT,    "Management layer generated release" },
	{ RELEASE_PHYS,    "Physical layer alarm generated release" },
	{ RELEASE_DM,      "Specific to a request" },
	{ RELEASE_OTHER,   "Other reason" },
	{ 0,               NULL } };

#define RELEASE_REASON_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define RELEASE_REASON_OFFSET        PARAMETER_VALUE_OFFSET
#define RELEASE_REASON_LENGTH        4

static void
dissect_release_reason_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  gint offset = RELEASE_REASON_OFFSET;
  if(iua_version == DRAFT) offset = tvb_get_ntohs(parameter_tvb, RELEASE_REASON_LENGTH_OFFSET)+8;
  proto_tree_add_item(parameter_tree, hf_release_reason, parameter_tvb, offset, RELEASE_REASON_LENGTH, FALSE);
  if(iua_version != DRAFT)
	  proto_item_append_text(parameter_item, " (%s)",
				                val_to_str(tvb_get_ntohl(parameter_tvb, offset), release_reason_values, "Unknown release reason"));
}
/*----------------------Release Indication,Request (Draft,RFC)-----------------*/

/*----------------------Link Status Start,Stop Report (Draft,RFC)--------------*/
/*
 * No additional Parameter
 */
/*----------------------Link Status Start,Stop Report (Draft,RFC)--------------*/

/*----------------------Link Status Indication (Draft,RFC)---------------------*/

	/* define parameters for Link Status Indication */
#define LINK_STATUS_OPERTIONAL      0x0
#define LINK_STATUS_NON_OPERTIONAL  0x1

static const value_string link_status_values[] = {
  { LINK_STATUS_OPERTIONAL,      "Link is in operation" },
  { LINK_STATUS_NON_OPERTIONAL,  "Link is not in operation" },
  { 0,                           NULL } };

#define LINK_STATUS_OFFSET   PARAMETER_VALUE_OFFSET
#define LINK_STATUS_LENGTH   4

static void
dissect_link_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_link_status, parameter_tvb, LINK_STATUS_OFFSET, LINK_STATUS_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s)",
					  val_to_str(tvb_get_ntohl(parameter_tvb, LINK_STATUS_OFFSET),link_status_values, "Unknown Link status"));
}
/*----------------------Link Status Indication (Draft,RFC)---------------------*/

/*----------------------Sa-Bit (Draft,RFC)-------------------------------------*/

	/* define parameter for sa-bit message */
#define SA_BIT_ID_ZERO     0x0
#define SA_BIT_ID_ONE      0x1
#define SA_BIT_VALUE_SA7   0x7

static const value_string sa_bit_values[] = {
	{ SA_BIT_ID_ZERO,    "set to ZERO" },
	{ SA_BIT_ID_ONE,     "set to ONE" },
	{ SA_BIT_VALUE_SA7,  "Sa7 Bit" },
	{ 0,                 NULL } };

#define SA_BIT_ID_OFFSET     PARAMETER_VALUE_OFFSET
#define SA_BIT_ID_LENGTH     2
#define SA_BIT_VALUE_OFFSET  (SA_BIT_ID_OFFSET + SA_BIT_ID_LENGTH)
#define SA_BIT_VALUE_LENGTH  2

static void
dissect_sa_bit_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sa_bit_id, parameter_tvb, SA_BIT_ID_OFFSET, SA_BIT_ID_LENGTH, FALSE);
  proto_tree_add_item(parameter_tree, hf_sa_bit_value, parameter_tvb, SA_BIT_VALUE_OFFSET, SA_BIT_VALUE_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s %s)",
					  val_to_str(tvb_get_ntohs(parameter_tvb, SA_BIT_ID_OFFSET), sa_bit_values, "unknown"),
					  val_to_str(tvb_get_ntohs(parameter_tvb, SA_BIT_VALUE_OFFSET), sa_bit_values, "unknown Bit"));

}
/*----------------------Sa-Bit (Draft,RFC)-------------------------------------*/

/*----------------------Error Indication (RFC)---------------------------------*/

#define ERROR_REASON_OVERLOAD 0x1

static const value_string error_reason_values[] = {
	{ ERROR_REASON_OVERLOAD, "C-Channel is in overload state" },
	{ 0,                     NULL } };

#define ERROR_REASON_LENGTH 4
#define ERROR_REASON_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_error_indication_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_error_reason, parameter_tvb, ERROR_REASON_OFFSET, ERROR_REASON_LENGTH, FALSE);
  proto_item_append_text(parameter_item, " (%s)",
					  val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_REASON_OFFSET), error_reason_values, "unknown"));
}
/*----------------------Error Indication (RFC)---------------------------------*/

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info_string_length;

  info_string_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  if(iua_version == DRAFT) info_string_length += 4;
  if(info_string_length > 4){
	info_string_length -= PARAMETER_HEADER_LENGTH;
	proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, FALSE);
	proto_item_append_text(parameter_item, " (%.*s)", info_string_length,
		                     (const char *)tvb_get_ptr(parameter_tvb, INFO_STRING_OFFSET, info_string_length));
  }
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 parameter_value_length;

  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, FALSE);
  proto_item_append_text(parameter_item, " with tag %u and %u byte%s value",
                         tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET), parameter_value_length, plurality(parameter_value_length, "", "s"));
}


#define INT_INTERFACE_IDENTIFIER_PARAMETER_TAG           0x01
#define ASP_MSG_PARAMETER_TAG                            0x02
#define TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG          0x03
#define INFO_PARAMETER_TAG                               0x04
#define DLCI_PARAMETER_TAG                               0x05
#define DIAGNOSTIC_INFORMATION_PARAMETER_TAG             0x07
#define INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG 0x08
#define HEARTBEAT_DATA_PARAMETER_TAG                     0x09
#define ASP_DOWN_REASON_PARAMETER_TAG                    0x0a
#define TRAFFIC_MODE_TYPE_PARAMETER_TAG                  0x0b
#define ERROR_CODE_PARAMETER_TAG                         0x0c
#define STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG        0x0d
#define PROTOCOL_DATA_PARAMETER_TAG                      0x0e
#define RELEASE_REASON_PARAMETER_TAG                     0x0f
#define TEI_STATUS_PARAMETER_TAG                         0x10
#define LINK_STATUS_PARAMETER_TAG                        0x11
#define SA_BIT_STATUS_PARAMETER_TAG                      0x12
#define ERROR_INDICATION_PARAMETER_TAG                   0x13

static const value_string parameter_tag_values[] = {
  { INT_INTERFACE_IDENTIFIER_PARAMETER_TAG,              "V5UA Interface Identifier (int)" },
  { TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG,             "Text Interface Identifier" },
  { INFO_PARAMETER_TAG,                                  "Info" },
  { DLCI_PARAMETER_TAG,                                  "DLCI" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,                "Diagnostic information" },
  { INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG,    "Integer range interface identifier" },
  { HEARTBEAT_DATA_PARAMETER_TAG,                        "Hearbeat data" },
  { ASP_DOWN_REASON_PARAMETER_TAG,                       "ASP DOWN Reason" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,                     "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                            "Error code" },
  { STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG,           "Status type/identification" },
  { PROTOCOL_DATA_PARAMETER_TAG,                         "Protocol Data" },
  { RELEASE_REASON_PARAMETER_TAG,                        "Reason" },
  { TEI_STATUS_PARAMETER_TAG,                            "TEI status" },
  { LINK_STATUS_PARAMETER_TAG,                           "Link status" },
  { SA_BIT_STATUS_PARAMETER_TAG,                         "SA-Bit status" },
  { ERROR_INDICATION_PARAMETER_TAG,                      "Error reason" },
  { 0,                                                   NULL } };

static const value_string parameter_tag_draft_values[] = {
  { INT_INTERFACE_IDENTIFIER_PARAMETER_TAG,              "V5UA Interface Identifier (int)" },
  { ASP_MSG_PARAMETER_TAG,                               "ASP Adaption Layer ID" },
  { TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG,             "SCN Protocol Identifier" },
  { INFO_PARAMETER_TAG,                                  "Info" },
  { LINK_STATUS_PARAMETER_TAG,                           "Link status" },
  { SA_BIT_STATUS_PARAMETER_TAG,                         "SA-Bit status" },
  { ERROR_INDICATION_PARAMETER_TAG,                      "Error reason" },
  { 0,                                                   NULL } };



static void
dissect_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *v5ua_tree)
{
  guint16 tag, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  /* extract tag and length from the parameter */
  tag      = tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET);
  length   = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  /* on IUA-Draft messages the message length not including the message header */
  if((iua_version==DRAFT)&&(tag<=0x4)){
	  /* at V5UA Header, length of header and length of DLCI+EFA must be added */
	  if(tag==0x1)       length += 8;
	  /* at ASP message tags only length of header must be added */
	  else if(tag<=0x4)  length += PARAMETER_HEADER_LENGTH;
	  /* for following message-tags are no length information available. Only in common msg header */
      if((msg_class==0 || msg_class==1 || msg_class==9) && msg_type<=10)
        length = msg_length;
  }
  padding_length = tvb_length(parameter_tvb) - length;

  /* create proto_tree stuff */

  switch(iua_version){
  case RFC:
	  parameter_item   = proto_tree_add_text(v5ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb),
			                                   val_to_str(tag, parameter_tag_values, "Unknown parameter"));
      parameter_tree   = proto_item_add_subtree(parameter_item, ett_v5ua_parameter);

	  /* add tag to the v5ua tree */
      proto_tree_add_item(parameter_tree, hf_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, FALSE);
	  break;

  case DRAFT:
  default:
  	  parameter_item   = proto_tree_add_text(v5ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb),
			                                   val_to_str(tag, parameter_tag_draft_values, "Unknown parameter"));
      parameter_tree   = proto_item_add_subtree(parameter_item, ett_v5ua_parameter);

	  /* add tag to the v5ua tree */
	 proto_tree_add_item(parameter_tree, hf_parameter_tag_draft, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, FALSE);
	  break;
  
  };

  /* add length to the v5ua tree */
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, FALSE);

  switch(tag) {
  case INT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    if(iua_version == RFC )
		dissect_int_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
	if(iua_version == DRAFT){
		dissect_int_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);

		dissect_dlci_parameter(parameter_tvb, parameter_tree, parameter_item);

		/* for the following parameters no tag- and length-informations available. Parameters must be dissect with info from common msg header */
		if(msg_class==0 && msg_type==0)    dissect_draft_error_code_parameter(parameter_tvb, parameter_tree);
		if(msg_class==1)                   dissect_draft_tei_status_parameter(parameter_tvb, parameter_tree, parameter_item);
		if(msg_class==9){
          if(msg_type==1||msg_type==2||msg_type==3||msg_type==4){
	         guint16 length, offset;
	         tvbuff_t *layer3_data_tvb;
	         offset = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) + 8;
	         length = msg_length - offset;

             if(length > 0){
               if(tvb_get_guint8(parameter_tvb, offset) == 0x48){
			      layer3_data_tvb = tvb_new_subset(parameter_tvb, offset, length, length);
			      dissect_layer3_message(layer3_data_tvb, v5ua_tree, parameter_item, pinfo);
			   }
			 }
		  }
		  else if(msg_type==8||msg_type==10) dissect_release_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
		}
	}
    break;
  case ASP_MSG_PARAMETER_TAG:
	dissect_asp_msg_parameter(parameter_tvb, parameter_tree, parameter_item);
	break;
  case TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    if(iua_version == RFC)
		dissect_text_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
	if(iua_version == DRAFT)
		dissect_scn_protocol_id_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INFO_PARAMETER_TAG:
    dissect_info_string_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DLCI_PARAMETER_TAG:
    dissect_dlci_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case DIAGNOSTIC_INFORMATION_PARAMETER_TAG:
    dissect_diagnostic_information_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG:
    dissect_integer_range_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HEARTBEAT_DATA_PARAMETER_TAG:
    dissect_heartbeat_data_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ASP_DOWN_REASON_PARAMETER_TAG:
    dissect_asp_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case TRAFFIC_MODE_TYPE_PARAMETER_TAG:
    dissect_traffic_mode_type_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ERROR_CODE_PARAMETER_TAG:
    dissect_error_code_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG:
    dissect_status_type_identification_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case PROTOCOL_DATA_PARAMETER_TAG:
	dissect_layer3_message(parameter_tvb, v5ua_tree, parameter_item, pinfo);
	break;
  case RELEASE_REASON_PARAMETER_TAG:
	dissect_release_reason_parameter(parameter_tvb, parameter_tree, parameter_item);
	break;
  case TEI_STATUS_PARAMETER_TAG:
    dissect_tei_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case LINK_STATUS_PARAMETER_TAG:
    dissect_link_status_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SA_BIT_STATUS_PARAMETER_TAG:
	dissect_sa_bit_status_parameter(parameter_tvb, parameter_tree, parameter_item);
	break;
  case ERROR_INDICATION_PARAMETER_TAG:
	dissect_error_indication_parameter( parameter_tvb, parameter_tree, parameter_item);
	break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };

  if (padding_length > 0){
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, FALSE);
  }
}

/* dissect the V5UA-Parameters into subsets which are separated by Tag-Length-Header and call up the dissector for the subsets */
static void
dissect_parameters(tvbuff_t *parameters_tvb, packet_info *pinfo, proto_tree *tree _U_, proto_tree *v5ua_tree)
{
  gint tag, offset, length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  
  offset = 0;
  while((remaining_length = tvb_length_remaining(parameters_tvb, offset))) {
	tag = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_TAG_OFFSET);
	length = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
	if(iua_version==DRAFT){
		if(tag==0x1) length += 8;		/* V5UA Header */
		else if(tag<=0x4) length += PARAMETER_HEADER_LENGTH;	/* ASP MSGs */

		/* add the parameters which are not separated by tag-length-header to the V5UA header */
		if((msg_class==0 || msg_class==1 || msg_class==9)&&msg_type<=10)
			length = msg_length;
	}	 
	total_length = ADD_PADDING(length);
	if (remaining_length >= length)
	  total_length = MIN(total_length, remaining_length);
	/* create a tvb for the parameter including the padding bytes */
	parameter_tvb  = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
	dissect_parameter(parameter_tvb, pinfo, v5ua_tree);
	/* get rid of the handled parameter */
	offset += total_length;
	}	
}



	/* define the common header fields of V5UA MSG */
#define COMMON_HEADER_VERSION_LENGTH        1
#define COMMON_HEADER_RESERVED_LENGTH       1
#define COMMON_HEADER_MSG_CLASS_LENGTH  1
#define COMMON_HEADER_MSG_TYPE_LENGTH   1
#define COMMON_HEADER_MSG_LENGTH_LENGTH 4
#define COMMON_HEADER_LENGTH                (COMMON_HEADER_VERSION_LENGTH + COMMON_HEADER_RESERVED_LENGTH +\
											 COMMON_HEADER_MSG_CLASS_LENGTH + COMMON_HEADER_MSG_TYPE_LENGTH +\
											 COMMON_HEADER_MSG_LENGTH_LENGTH)

	/* define the offsets of common header */
#define COMMON_HEADER_OFFSET            0
#define COMMON_HEADER_VERSION_OFFSET    COMMON_HEADER_OFFSET
#define COMMON_HEADER_RESERVED_OFFSET   (COMMON_HEADER_VERSION_OFFSET       + COMMON_HEADER_VERSION_LENGTH)
#define COMMON_HEADER_MSG_CLASS_OFFSET  (COMMON_HEADER_RESERVED_OFFSET      + COMMON_HEADER_RESERVED_LENGTH)
#define COMMON_HEADER_MSG_TYPE_OFFSET   (COMMON_HEADER_MSG_CLASS_OFFSET     + COMMON_HEADER_MSG_CLASS_LENGTH)
#define COMMON_HEADER_MSG_LENGTH_OFFSET (COMMON_HEADER_MSG_TYPE_OFFSET      + COMMON_HEADER_MSG_TYPE_LENGTH)
#define COMMON_HEADER_PARAMETERS_OFFSET (COMMON_HEADER_OFFSET               + COMMON_HEADER_LENGTH)

	/* version of V5UA protocol */
#define V5UA_PROTOCOL_VERSION_RELEASE_1     1	

static const value_string v5ua_protocol_version_values[] = {
  { V5UA_PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                                NULL } };

	/* define V5UA MSGs */
#define MSG_CLASS_MGMT_MSG       0
#define MSG_CLASS_MGMT_MSG_DRAFT 1
#define MSG_CLASS_ASPSM_MSG      3
#define MSG_CLASS_ASPTM_MSG      4
#define MSG_CLASS_V5PTM_MSG      9

static const value_string msg_class_values[] = {
	{ MSG_CLASS_MGMT_MSG,  "Management Messages" },
	{ MSG_CLASS_MGMT_MSG_DRAFT,"Management Messages"},
	{ MSG_CLASS_ASPSM_MSG, "ASP state maintenance message" },
	{ MSG_CLASS_ASPTM_MSG, "ASP traffic maintenance message" },
	{ MSG_CLASS_V5PTM_MSG, "V5 Boundary Primitives Transport Message" },
	{ 0,                           NULL } }; 

	/* message types for MGMT messages */
#define MGMT_MSG_TYPE_ERR                  0
#define MGMT_MSG_TYPE_NTFY                 1
#define MGMT_MSG_TYPE_TEI_STATUS_REQ       2
#define MGMT_MSG_TYPE_TEI_STATUS_CON       3
#define MGMT_MSG_TYPE_TEI_STATUS_IND       4
	/* MGMT messages for Nortel draft version*/
#define MGMT_MSG_DRAFT_TYPE_TEI_STATUS_REQ       1
#define MGMT_MSG_DRAFT_TYPE_TEI_STATUS_CON       2
#define MGMT_MSG_DRAFT_TYPE_TEI_STATUS_IND       3


	/* message types for ASPSM messages */
#define ASPSM_MSG_TYPE_UP                   1
#define ASPSM_MSG_TYPE_DOWN                 2
#define ASPSM_MSG_TYPE_BEAT                 3
#define ASPSM_MSG_TYPE_UP_ACK               4
#define ASPSM_MSG_TYPE_DOWN_ACK             5
#define ASPSM_MSG_TYPE_BEAT_ACK             6

	/* message types for ASPTM messages */
#define ASPTM_MSG_TYPE_ACTIVE               1
#define ASPTM_MSG_TYPE_INACTIVE             2
#define ASPTM_MSG_TYPE_ACTIVE_ACK           3
#define ASPTM_MSG_TYPE_INACTIVE_ACK         4

	/* message types for V5PTM messages */
#define V5PTM_MSG_TYPE_DATA_REQUEST                 1
#define V5PTM_MSG_TYPE_DATA_INDICATION              2
#define V5PTM_MSG_TYPE_UNIT_DATA_REQUEST            3
#define V5PTM_MSG_TYPE_UNIT_DATA_INDICATION         4
#define V5PTM_MSG_TYPE_ESTABLISH_REQUEST            5
#define V5PTM_MSG_TYPE_ESTABLISH_CONFIRM            6
#define V5PTM_MSG_TYPE_ESTABLISH_INDICATION         7
#define V5PTM_MSG_TYPE_RELEASE_REQUEST              8
#define V5PTM_MSG_TYPE_RELEASE_CONFIRM              9
#define V5PTM_MSG_TYPE_RELEASE_INDICATION          10
#define V5PTM_MSG_TYPE_LINK_STATUS_START_REPORTING 11
#define V5PTM_MSG_TYPE_LINK_STATUS_STOP_REPORTING  12
#define V5PTM_MSG_TYPE_LINK_STATUS_INDICATION      13
#define V5PTM_MSG_TYPE_SA_BIT_SET_REQUEST          14
#define V5PTM_MSG_TYPE_SA_BIT_SET_CONFIRM          15
#define V5PTM_MSG_TYPE_SA_BIT_STATUS_REQUEST       16
#define V5PTM_MSG_TYPE_SA_BIT_STATUS_INDICATION    17
#define V5PTM_MSG_TYPE_ERROR_INDICATION            18

static const value_string msg_class_type_values[] = {
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_ERR,                         "Error" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_NTFY,                        "Notify" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_REQ,              "TEI status request" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_CON,              "TEI status confirmation" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_IND,              "TEI status indication" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_REQ,   "TEI status request" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_CON,   "TEI status confimation" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_IND,   "TEI status indication" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_UP,                         "ASP up" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_DOWN,                       "ASP down" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_BEAT,                       "Heartbeat" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_UP_ACK,                     "ASP up ack" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_DOWN_ACK,                   "ASP down ack" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_BEAT_ACK,                   "Heartbeat ack" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_ACTIVE ,                    "ASP active" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_INACTIVE ,                  "ASP inactive" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_ACTIVE_ACK ,                "ASP active ack" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_INACTIVE_ACK ,              "ASP inactive ack" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_DATA_REQUEST,               "Data request" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_DATA_INDICATION,            "Data indication" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_UNIT_DATA_REQUEST,          "Unit data request" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_UNIT_DATA_INDICATION,       "Unit data indication" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ESTABLISH_REQUEST,          "Establish request" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ESTABLISH_CONFIRM,          "Establish confirmation" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ESTABLISH_INDICATION,       "Establish indication" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_RELEASE_REQUEST,            "Release request" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_RELEASE_CONFIRM,            "Release confirmation" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_RELEASE_INDICATION,         "Release indication" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_LINK_STATUS_START_REPORTING,"Link status start reporting" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_LINK_STATUS_STOP_REPORTING, "Link status stop reporting" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_LINK_STATUS_INDICATION,     "Link status indication" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_REQUEST,         "Sa-Bit set request" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_CONFIRM,         "Sa-Bit set confirm" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_REQUEST,      "Sa-Bit status request" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_INDICATION,   "Sa-Bit status indication" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ERROR_INDICATION,           "Error indication" },
  { 0,                                                                                  NULL } };
  

static void
dissect_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *v5ua_tree)
{
  proto_item *common_header_item;
  proto_tree *common_header_tree;

  guint8 message_class, message_type;

  message_class  = tvb_get_guint8(common_header_tvb, COMMON_HEADER_MSG_CLASS_OFFSET);
  message_type   = tvb_get_guint8(common_header_tvb, COMMON_HEADER_MSG_TYPE_OFFSET);

  /* Add message type into info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_class * 256 + message_type, msg_class_type_values, "UNKNOWN"));
    col_append_str(pinfo->cinfo, COL_INFO, " ");
  }

  if (v5ua_tree) {

	  /* create proto_tree stuff */
    common_header_item   = proto_tree_add_text(v5ua_tree, common_header_tvb, COMMON_HEADER_OFFSET, tvb_length(common_header_tvb),"Common Msg-Header");
    common_header_tree   = proto_item_add_subtree(common_header_item, ett_v5ua_common_header);

    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(common_header_tree, hf_version, common_header_tvb, COMMON_HEADER_VERSION_OFFSET, COMMON_HEADER_VERSION_LENGTH, FALSE);
    proto_tree_add_item(common_header_tree, hf_reserved, common_header_tvb, COMMON_HEADER_RESERVED_OFFSET, COMMON_HEADER_RESERVED_LENGTH, FALSE);
    proto_tree_add_item(common_header_tree, hf_msg_class, common_header_tvb, COMMON_HEADER_MSG_CLASS_OFFSET, COMMON_HEADER_MSG_CLASS_LENGTH, FALSE);
    proto_tree_add_uint_format(common_header_tree, hf_msg_type,
                              common_header_tvb, COMMON_HEADER_MSG_TYPE_OFFSET, COMMON_HEADER_MSG_TYPE_LENGTH,
                              message_type, "Message type: %s ( %u )",
                              val_to_str(message_class * 256 + message_type, msg_class_type_values, "reserved"), message_type);
    proto_tree_add_uint(common_header_tree, hf_msg_type_id, common_header_tvb, COMMON_HEADER_MSG_TYPE_OFFSET, COMMON_HEADER_MSG_TYPE_LENGTH,
                              message_class * 256 + message_type);
    proto_tree_add_item(common_header_tree, hf_msg_length, common_header_tvb, COMMON_HEADER_MSG_LENGTH_OFFSET, COMMON_HEADER_MSG_LENGTH_LENGTH, FALSE);
    
	/* Add message type to the Common Msg-Header line */
	proto_item_append_text(common_header_item, " (%s)",val_to_str(message_class * 256 + message_type, msg_class_type_values, "Unknown Msg-Type"));
  }
  
  /* the following info are required to dissect IUA-Draft messages.
		In the DRAFT-Specification V5UA-Parameters are not separated by Tag-Length-Header (as defined in RFC-Spec) */
  if (iua_version == DRAFT){
	  msg_class = message_class;
	  msg_type  = message_type;
	  msg_length = tvb_get_ntohl (common_header_tvb, COMMON_HEADER_MSG_LENGTH_OFFSET);
  }
}

/* dissect the V5UA-packet in two subsets: Common Msg-Header (used by all msgs) and V5UA-parameter */
static void
dissect_v5ua_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *v5ua_tree)
{
  tvbuff_t *common_header_tvb, *parameters_tvb;

  common_header_tvb = tvb_new_subset(tvb, COMMON_HEADER_OFFSET, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_common_header(common_header_tvb, pinfo, v5ua_tree);

  parameters_tvb    = tvb_new_subset(tvb, COMMON_HEADER_LENGTH, -1, -1);
  dissect_parameters(parameters_tvb, pinfo, tree, v5ua_tree);
}
	
	
static void
dissect_v5ua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

   gint    offset, remaining_length, length, tag, one_bit;


/* Set up structures needed to add the protocol subtree and manage it */
	proto_tree *v5ua_tree;
	proto_item *ti;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "V5UA");
    
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. See section 1.5
   for more information. */


	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

   
/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {

/* NOTE: The offset and length values in the call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   Supplying a length of -1 is the way to highlight all data from the
   offset to the end of the packet. */

/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_v5ua, tvb, 0, -1, FALSE);
		v5ua_tree = proto_item_add_subtree(ti, ett_v5ua);

	}
	else {
	v5ua_tree=NULL;
	};


	/* detect version of IUA */
   iua_version = RFC;
   offset = COMMON_HEADER_LENGTH;

   remaining_length = tvb_length_remaining(tvb, offset);

   while(remaining_length) {
	   tag = tvb_get_ntohs(tvb, offset);
	   /*0x01,0x03: Inerface Id (draft&RFC)*/
		if(tag==0x1){
			length = tvb_get_ntohs(tvb, offset+2);
			tag = tvb_get_ntohs(tvb, offset+length);
			/* tag 0x5 indicates the DLCI in the V5UA-Header accoriding to RFC spec */
			if(tag==0x5){
				remaining_length = FALSE;
			}
			else{
				one_bit = tvb_get_guint8(tvb, offset+4+length+1);
				/* no indication from DLCI by tag (in the V5UA-Header according DRAFT).
					Thus the ONE-Bit within DLCI have to compare */
				if((one_bit & 0x01) == 0x01){
					iua_version = DRAFT;
					remaining_length = FALSE;
				}
				/* an indication to incorrect bit in DLCI.
					Must be include to decode an incorrect implemented message on Nortels PVG*/
				else{
					proto_item_append_text(v5ua_tree, "   !! DLCI INCORRECT !!");

					iua_version = DRAFT;
					remaining_length = FALSE;
				}
			}
		}
		/*0x02: AL Id (draft) following after common msg header without V5UA header*/
		else if(tag==0x02){
			iua_version = DRAFT;
			remaining_length = FALSE;
		}
		/*0x03: Text formatted IId SHALL not be supported by draft*/
		else if(tag==0x03){
			iua_version = RFC;
			remaining_length = FALSE;
		}
		/*ASP, Notify and Error messages (RFC) only contain common msg header followed by parameter*/
		else if(tag==0x04 || tag == 0x0a || tag == 0x0b || tag == 0x0c || tag == 0x0d){
			remaining_length = FALSE;
		}
		else{
			offset+=2;
			remaining_length = tvb_length_remaining(tvb, offset);
		}
		/* add a notice for the draft version */
		if(iua_version == DRAFT){
			if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "V5UA (draft)");
		}
   }
 

   /* dissect the message */
  dissect_v5ua_message(tvb, pinfo, tree, v5ua_tree);
}



/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration. */


void
proto_register_v5ua(void)
{                 

/* Setup list of header fields  */
	static hf_register_info hf[] = {
		{ &hf_version,
			{ "Version",                "v5ua.version",
			   FT_UINT8,    BASE_DEC, VALS(v5ua_protocol_version_values),0x0,
			   "", HFILL } },
		{ &hf_reserved,
			{ "Reserved",               "v5ua.reserved",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_msg_class,
			{ "Message class",          "v5ua.msg_class",
			   FT_UINT8,    BASE_DEC, VALS(msg_class_values),           0x0,
			   "", HFILL } },
		{ &hf_msg_type,
			{ "Message Type",           "v5ua.msg_type",
			   FT_UINT8,    BASE_DEC, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_msg_type_id,
			{ "Message Type ID",        "v5ua.msg_type_id",
			   FT_UINT8,    BASE_DEC, VALS(msg_class_type_values),      0x0,
			   "", HFILL } },
		{ &hf_msg_length,
			{ "Message length",         "v5ua.msg_length",
               FT_UINT32,   BASE_DEC, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_link_id,
			{ "Link Identifier",        "v5ua.link_id",
			   FT_UINT32,   BASE_DEC, NULL,								~0x1f,
			   "", HFILL } },
		{ &hf_chnl_id,
			{ "Channel Identifier",     "v5ua.channel_id",
			   FT_UINT8,    BASE_DEC, NULL,								0x1f,
			   "", HFILL } },
		{ &hf_adaptation_layer_id,
			{ "Adaptation Layer ID",      "v5ua.adaptation_layer_id",
			   FT_STRING,   BASE_NONE,NULL,								0x0,
			   "", HFILL } },
		{ &hf_text_if_id,
			{ "Text interface identifier","v5ua.text_interface_id",
			   FT_STRING,   BASE_NONE,NULL,								0x0,
			   "", HFILL } },
		{ &hf_scn_protocol_id,
			{ "SCN Protocol Identifier","v5ua.scn_protocol_id",
			   FT_STRING,   BASE_NONE,NULL,								0x0,
			   "", HFILL } },
		{ &hf_info_string,
			{ "Info String",            "v5ua.info_string",
			   FT_STRING,   BASE_NONE,NULL,                             0x0,
			   "", HFILL } },
		{ &hf_dlci_zero_bit,
			{ "Zero bit",               "v5ua.dlci_zero_bit",
			   FT_BOOLEAN,	8,        NULL,                             0x01,
			   "", HFILL } },
		{ &hf_dlci_spare_bit,
			{ "Spare bit",              "v5ua.dlci_spare_bit",
               FT_BOOLEAN,	8,        NULL,                             0x02,
			   "", HFILL } },
		{ &hf_dlci_sapi,
			{ "SAPI",                   "v5ua.dlci_sapi",
			   FT_UINT8,	BASE_HEX, NULL,                             0xfc,
			   "", HFILL } },
		{ &hf_dlci_one_bit,
			{ "One bit",                "v5ua.dlci_one_bit",
			   FT_BOOLEAN,  8,        NULL,                             0x01,
			   "", HFILL } },
		{ &hf_dlci_tei,
			{ "TEI",                    "v5ua.dlci_tei",
			   FT_UINT8,    BASE_HEX, NULL,                             0xfe,
			   "", HFILL } },
		{ &hf_efa,
			{ "Envelope Function Address","v5ua.efa",
			   FT_UINT16,   BASE_DEC, VALS(efa_values),                 0x0,
			   "", HFILL } },
		{ &hf_spare_efa,
			{ "Envelope Function Address (spare)","v5ua.efa",
			   FT_UINT16,   BASE_DEC, NULL,                             ~7,
			   "", HFILL } },
		{ &hf_asp_reason,
			{ "Reason",                 "v5ua.asp_reason",
			   FT_UINT32,   BASE_HEX, VALS(asp_reason_values),          0x0,
			   "", HFILL } },
		{ &hf_release_reason,
			{ "Release Reason",         "v5ua.release_reason",
			   FT_UINT32,   BASE_HEX, VALS(release_reason_values),      0x0,
			   "", HFILL } },
		{ &hf_tei_status,
			{ "TEI status",             "v5ua.tei_status",
			   FT_UINT32,   BASE_HEX, VALS(tei_status_values),          0x0,
			   "", HFILL } },
		{ &hf_tei_draft_status,
			{ "TEI status",             "v5ua.tei_draft_status",
			   FT_UINT32,   BASE_HEX, VALS(tei_draft_status_values),    0x0,
			   "", HFILL } },
        { &hf_link_status,
			{ "Link Status",            "v5ua.link_status",
			   FT_UINT32,   BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_sa_bit_id,
			{ "BIT ID",                 "v5ua.sa_bit_id",
			   FT_UINT16,   BASE_HEX, VALS(sa_bit_values),              0x0,
			   "", HFILL } },
		{ &hf_sa_bit_value,
			{ "Bit Value",              "v5ua.sa_bit_value",
			   FT_UINT16,   BASE_HEX, VALS(sa_bit_values),              0x0,
			   "", HFILL } },
		{ &hf_parameter_tag,
			{ "Parameter Tag",          "v5ua.parameter_tag",
			   FT_UINT16,   BASE_HEX, VALS(parameter_tag_values),       0x0,
			   "", HFILL } },
		{ &hf_parameter_tag_draft,
			{ "Parameter Tag",          "v5ua.parameter_tag",
			   FT_UINT16,   BASE_HEX, VALS(parameter_tag_draft_values), 0x0,
			   "", HFILL } },
		{ &hf_parameter_length, 
			{ "Parameter length",       "v5ua.parameter_length",
			   FT_UINT16,   BASE_DEC, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_parameter_value,
			{ "Parameter value",        "v5ua.parameter_value",
			   FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   "", HFILL } },
		{ &hf_parameter_padding,
			{ "Parameter padding",      "v5ua.parameter_padding",
			   FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   "", HFILL } },
		{ &hf_diagnostic_info,
			{ "Diagnostic Information", "v5ua.diagnostic_info",
			   FT_BYTES,    BASE_NONE,NULL,						    	0x0,
			   "", HFILL } },
		{ &hf_if_range_start,
			{ "Interface range Start",  "v5ua.interface_range_start",
			   FT_UINT32,   BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_if_range_end,
			{ "Interface range End",    "v5ua.interface_range_end",
			   FT_UINT32,   BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_heartbeat_data,
			{ "Heartbeat data",         "v5ua.heartbeat_data",
               FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   "", HFILL } },
		{ &hf_traffic_mode_type,
			{ "Traffic mode type",      "v5ua.traffic_mode_type",
			   FT_UINT32,   BASE_HEX, VALS(traffic_mode_type_values),   0x0,
			   "", HFILL } },
		{ &hf_error_code,
            { "Error code",             "v5ua.error_code",
			   FT_UINT32,   BASE_HEX, VALS(error_code_values),          0x0,
			   "", HFILL } },
		{ &hf_draft_error_code,
			{ "Error code (draft)",     "v5ua.draft_error_code",
			   FT_UINT32,   BASE_HEX, VALS(draft_error_code_values),    0x0,
			   "", HFILL } },
		{ &hf_status_type,
			{ "Status type",            "v5ua.status_type",
			   FT_UINT16,   BASE_DEC, VALS(status_type_values),         0x0,
			   "", HFILL } },
		{ &hf_status_id,
			{ "Status identification",  "v5ua.status_id",
			   FT_UINT16,   BASE_DEC, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_error_reason,
			{ "Error Reason",           "v5ua.error_reason",
			   FT_UINT32,   BASE_HEX, VALS(error_reason_values),        0x0,
			   "", HFILL } },

			   
		/* header fields for layer 3 content*/
		{ &hf_l3_protocol_discriminator,
			{ "Protocol Discriminator", "v5ua.l3_protocol_disc",
               FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{ &hf_l3_adress,
			{ "Layer3 address",        "v5ua.l3_address",
			   FT_UINT8,    BASE_HEX, NULL,                             0xfe,
			   "", HFILL } },
		{ &hf_l3_low_adress,
			{ "Layer3 low address",    "v5ua.l3_low_address",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{&hf_l3_msg_type,
			{ "Layer3 message type",   "v5ua.l3_msg_type",
			   FT_UINT8,    BASE_HEX, VALS(l3_msg_type_values),         0x0,
			   "", HFILL } },
		{&hf_l3_info_element,
			{ "Layer3 information element",   "v5ua.l3_info_element",
			   FT_UINT8,    BASE_HEX, VALS(l3_info_element_values),     0x0,
			   "", HFILL } },
		{&hf_l3_line_info,
			{ "Line_Information",      "v5ua.l3_line_info",
			   FT_UINT8,    BASE_HEX, VALS(l3_line_info_values),        0x0f,
			   "", HFILL } },
		{&hf_l3_cad_ringing,
			{"Cadenced ringing type",  "v5ua.l3_cad_ringing",
			   FT_UINT8,    BASE_HEX, NULL,                             0x7f,
			   "", HFILL } },
		{&hf_l3_pulse_type,
			{ "Pulse Type",            "v5ua.l3_pulse_type",
			   FT_UINT8,    BASE_HEX, VALS(l3_pulse_type_values),       0x0,
			   "", HFILL } },
		{&hf_l3_suppression_indicator,
			{ "Suppression indicator",  "v5ua.l3_suppression_indicator",
			   FT_UINT8,    BASE_HEX, VALS(l3_suppression_indication_values),0x60,
			   "", HFILL } },
		{&hf_l3_pulse_duration,
			{ "Pulse duration type",   "v5ua.l3_pulse_duration",
			   FT_UINT8,    BASE_HEX, NULL,                             0x1f,
			   "", HFILL } },
		{&hf_l3_ack_request_indicator,
			{ "Ack request indicator",    "v5ua.l3_ack_request_indicator",
			   FT_UINT8,    BASE_HEX, VALS(l3_ack_request_indication_values),0x60,
			   "", HFILL } },
		{&hf_l3_number_of_pulses,
			{ "Number of pulses",      "v5ua.l3_number_of_pulses",
			   FT_UINT8,    BASE_DEC, NULL,                             0x1f,
			   "", HFILL } },
		{&hf_l3_steady_signal,
			{ "Steady Signal",         "v5ua.l3_steady_signal",
			   FT_UINT8,    BASE_HEX, VALS(l3_steady_signal_values),    0x0,
			   "", HFILL } },
		{&hf_l3_auto_signalling_sequence,
			{ "Autonomous signalling sequence","v5ua.l3_auto_signalling_sequence",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0f,
			   "", HFILL } },
		{&hf_l3_sequence_number,
			{ "Sequence number",    "v5ua.l3_sequence_number",
			   FT_UINT8,    BASE_HEX, NULL,                             0x7f,
			   "", HFILL } },
		{&hf_l3_pulse_notify,
			{ "Pulse notification",    "v5ua.l3_pulse_notification",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{&hf_l3_sequence_response,
			{ "Sequence response",    "v5ua.l3_sequence_response",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0f,
			   "", HFILL } },
		{&hf_l3_digit_ack,
			{ "Digit ack request indication","v5ua.l3_digit_ack",
			   FT_UINT8,    BASE_HEX, VALS(l3_digit_ack_values),        0x40,
			   "", HFILL } },
		{&hf_l3_digit_info,
			{ "Digit information",    "v5ua.l3_digit_info",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0f,
			   "", HFILL } },
		{&hf_l3_res_unavailable,
			{ "Resource unavailable", "v5ua.l3_res_unavailable",
			   FT_STRING,   BASE_NONE,NULL,                             0x0,
			   "", HFILL } },
		{&hf_l3_state,
			{ "PSTN FSM state",       "v5ua.l3_state",
			   FT_UINT8,    BASE_HEX, VALS(l3_state_values),            0x0f,
			   "", HFILL } },
		{&hf_l3_cause_type,
			{ "Cause type",           "v5ua.l3_cause_type",
			   FT_UINT8,    BASE_HEX, VALS(l3_cause_type_values),       0x7f,
			   "", HFILL } },
		{&hf_l3_link_control_function,
			{ "Link control function","v5ua.l3_link_control_function",
			   FT_UINT8,    BASE_HEX, VALS(l3_link_control_function_values),0x7f,
			   "", HFILL } },
		{&hf_l3_pstn_user_port_id,
			{ "PSTN User Port identification Value","v5ua.l3_pstn_user_port_id",
			   FT_UINT8,    BASE_HEX, NULL,                             0xfe,
			   "", HFILL } },
		{&hf_l3_pstn_user_port_id_lower,
			{ "PSTN User Port Identification Value (lower)","v5ua.l3_pstn_user_port_id_lower",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{&hf_l3_isdn_user_port_id,
			{ "ISDN User Port Identification Value","v5ua.l3_isdn_user_port_id",
			   FT_UINT8,    BASE_HEX, NULL,                             0xfc,
			   "", HFILL } },
		{&hf_l3_isdn_user_port_id_lower,
			{ "ISDN User Port Identification Value (lower)","v5ua.l3_user_port_id_lower",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0fe,
			   "", HFILL } },
		{&hf_l3_isdn_user_port_ts_num,
			{ "ISDN user port time slot number","v5ua.l3_isdn_user_port_ts_num",
			   FT_UINT8,    BASE_HEX, NULL,                             0x1f,
			   "", HFILL } },
		{&hf_l3_override,
			{ "Override",    "v5ua.l3_override", 
			   FT_BOOLEAN,  8,        NULL,                             0x20,
			   "", HFILL } },
		{&hf_l3_v5_link_id,
			{ "V5 2048 kbit/s Link Identifier",    "v5ua.l3_link_id",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   "", HFILL } },
		{&hf_l3_v5_time_slot,
			{ "V5 Time Slot Number",    "v5ua.l3_v5_time_slot",
			   FT_UINT8,    BASE_DEC, NULL,                             0x1f,
			   "", HFILL } },
		{&hf_l3_reject_cause_type,
			{ "Reject cause type",    "v5ua.l3_reject_cause_type",
			   FT_UINT8,    BASE_HEX, VALS(l3_reject_cause_type_values),0x7f,
			   "", HFILL } },
		{&hf_l3_bcc_protocol_error_cause,
			{ "BCC Protocol error cause type",    "v5ua.l3_bcc_protocol_cause",
			   FT_UINT8,    BASE_HEX, VALS(l3_bcc_protocol_error_cause_type_values),0x7f,
			   "", HFILL } },
		{&hf_l3_connection_incomplete_reason,
			{ "Reason",    "v5ua.l3_connection_incomplete_reason",
			   FT_UINT8,    BASE_HEX, VALS(l3_connection_incomplete_reason_values), 0x0,
			   "", HFILL } },
		{&hf_l3_control_function_element,
			{ "Control function element",    "v5ua.l3_control_function_element",
			   FT_UINT8,    BASE_HEX, VALS(l3_control_function_element_values),     0x7f,
			   "", HFILL } },
		{&hf_l3_control_function_id,
			{ "Control function ID",    "v5ua.l3_control_function",
			   FT_UINT8,    BASE_HEX, VALS(l3_control_function_id_values),          0x7f,
			   "", HFILL } },
		{&hf_l3_variant,
			{ "Variant",    "v5ua.l3_variant",
			   FT_UINT8,    BASE_DEC, NULL,                                         0x0,
			   "", HFILL } },
		{&hf_l3_if_id,
			{ "Interface ID",    "v5ua.l3_interface_id",
			   FT_UINT32,   BASE_HEX, NULL,                                         0x0,
			   "", HFILL } },
		{&hf_l3_performance_grading,
			{ "Performance grading",    "v5ua.l3_performance_grading",
			   FT_UINT8,    BASE_HEX, VALS(l3_performance_grading_values),          0x0f,
			   "", HFILL } },
		{&hf_l3_cp_rejection_cause,
			{ "Rejection cause",    "v5ua.l3_cp_rejection_cause",
			   FT_UINT8,    BASE_HEX, VALS(l3_cp_rejection_cause_values),           0x0f,
			   "", HFILL } },
		{&hf_l3_pstn_sequence_number,
			{ "Sequence number",    "v5ua.l3_pstn_sequence_number",
			   FT_UINT8,    BASE_HEX, NULL,                                         0x7f,
			   "", HFILL } },
		{&hf_l3_duration_type,
			{ "Duration Type",    "v5ua.l3_duration_type",
			   FT_UINT8,    BASE_HEX, NULL,                                         0x3f,
			   "", HFILL } },

		};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_v5ua,
		&ett_v5ua_common_header,
		&ett_v5ua_parameter,
		&ett_v5ua_layer3,
	};

/* Register the protocol name and description */

	proto_v5ua = proto_register_protocol("V5.2-User Adaptation Layer", "V5UA", "v5ua");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_v5ua, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* In RFC specification the SCTP registered User Port Number Assignment for V5UA is 5675 */
/* #define SCTP_PORT_V5UA      5675 */

#define SCTP_PORT_V5UA      10001

void
proto_reg_handoff_v5ua(void)
{
	dissector_handle_t v5ua_handle;

	v5ua_handle = create_dissector_handle(dissect_v5ua, proto_v5ua);
    q931_handle = find_dissector("q931");

	dissector_add("sctp.port", SCTP_PORT_V5UA, v5ua_handle);
	dissector_add("sctp.ppi",  V5UA_PAYLOAD_PROTOCOL_ID, v5ua_handle);
}
