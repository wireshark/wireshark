/* packet-v5ua.c
 *
 * Extension of all V5.2-User Adaptation Layer dissection elements
 * References:
 * RFC 3807
 * RFC 4233
 * RFC 5133
 *
 * Copyright 2009
 *
 * ISKRATEL d.o.o.            |       4S d.o.o.
 * http://www.iskratel.si/    |       http://www.4es.si/
 * <info@iskratel.si>         |       <projects@4es.si>
 * Vladimir Smrekar <vladimir.smrekar@gmail.com>
 *
 * Routines for V5.2-User Adaptation Layer dissection
 *
 * $Id$
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

#include <stdlib.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/sctpppids.h>      /* include V5UA payload protocol ID */

static int paddingl = 0;
static int dlci_efa = -1;

/* Initialize the protocol and registered fields */
static int proto_v5ua                    = -1;

static dissector_handle_t q931_handle;
static dissector_handle_t v52_handle;

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
static int hf_text_if_id            = -1;
static int hf_scn_protocol_id       = -1;
static int hf_info_string           = -1;
static int hf_asp_identifier        = -1;
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
static int messageclassCopy = -1;
static int sa_bit_id	= -1;
static int link_status_operational = -1;

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
#define INT_INTERFACE_ID_LENGTH 4

static int linkIdentifier = -1;

static void
dissect_int_interface_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 identifier;
  guint16 number_of_ids, id_number;
  gint offset;

  number_of_ids= (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / INT_INTERFACE_ID_LENGTH;

  offset = INT_IF_ID_LINK_OFFSET;
  identifier = tvb_get_ntohl(parameter_tvb,INT_IF_ID_LINK_OFFSET)>>5;
  proto_item_append_text(parameter_item, "(");
  for (id_number = 1; id_number <= number_of_ids; id_number++) {
    proto_tree_add_item(parameter_tree, hf_link_id, parameter_tvb, offset, INT_IF_ID_LINK_LENGTH, ENC_BIG_ENDIAN);
    identifier = tvb_get_ntohl(parameter_tvb,offset)>>5;
    if (id_number < 2) {
	proto_item_append_text(parameter_item, "L:%d",identifier);
    } else {
	proto_item_append_text(parameter_item, " | L:%d",identifier);
    }
    linkIdentifier = identifier;

    proto_tree_add_item(parameter_tree, hf_chnl_id, parameter_tvb, offset+3, INT_IF_ID_CHNL_LENGTH, ENC_BIG_ENDIAN);
    identifier = tvb_get_guint8(parameter_tvb,offset+3)&0x1f;
    proto_item_append_text(parameter_item, " C:%d", identifier);
    offset += INT_INTERFACE_ID_LENGTH;
    }
  proto_item_append_text(parameter_item, ")");
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

  proto_tree_add_item(parameter_tree, hf_text_if_id, parameter_tvb, TEXT_IF_ID_VALUE_OFFSET, if_id_length, ENC_ASCII|ENC_NA);
  proto_item_append_text(parameter_item, " (0x%.*s)", if_id_length,
                         tvb_get_ephemeral_string(parameter_tvb, TEXT_IF_ID_VALUE_OFFSET, if_id_length));
}
/*----------------------Text Interface Identifier (RFC)------------------------*/

/*----------------------DLCI & Envelope Function Address------------------------*/


/* interpretation of EFA-values */
static const value_string efa_values[] = {
	{ 8175, "ISDN Protocol" },
	{ 8176, "PSTN Protocol" },
	{ 8177, "CONTROL Protocol" },
	{ 8178, "BCC Protocol" },
	{ 8179, "PROT Protocol" },
	{ 8180, "Link Control Protocol" },
	{ 8191, "VALUE RESERVED" },
	{ 0,    NULL } };

#define DLCI_LENGTH_OFFSET PARAMETER_LENGTH_OFFSET
#define DLCI_SAPI_OFFSET   PARAMETER_VALUE_OFFSET
#define DLCI_HEADER_LENGTH PARAMETER_HEADER_LENGTH

#define DLCI_SAPI_LENGTH   1
#define DLCI_TEI_LENGTH    1
#define EFA_LENGTH         2

static void
dissect_dlci_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, packet_info *pinfo)
{
  guint16 efa = 0, offset = 0;

guint8 sapi = -1;
guint8 tei = -1;


  if     (iua_version == RFC)   offset = DLCI_SAPI_OFFSET;
  else if(iua_version == DRAFT) offset = DLCI_HEADER_LENGTH + tvb_get_ntohs(parameter_tvb, DLCI_LENGTH_OFFSET);

  proto_tree_add_item(parameter_tree, hf_dlci_zero_bit,  parameter_tvb, offset,  DLCI_SAPI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_spare_bit, parameter_tvb, offset,  DLCI_SAPI_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_sapi,      parameter_tvb, offset,  DLCI_SAPI_LENGTH,  ENC_BIG_ENDIAN);

  offset += DLCI_SAPI_LENGTH;
  proto_tree_add_item(parameter_tree, hf_dlci_one_bit,   parameter_tvb, offset,  DLCI_TEI_LENGTH,   ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_dlci_tei,       parameter_tvb, offset,  DLCI_TEI_LENGTH,   ENC_BIG_ENDIAN);

sapi = tvb_get_ntohs(parameter_tvb, offset-DLCI_TEI_LENGTH-DLCI_SAPI_LENGTH)>>2;
tei = tvb_get_ntohs(parameter_tvb, offset-DLCI_TEI_LENGTH)>>1;

  /* if SAPI & TEI not set to ZERO, value of EFA must be decode (EFA = 0 -> ISDN protocol)*/
  if(tvb_get_ntohs(parameter_tvb,offset-DLCI_TEI_LENGTH) != 0x01){

	  offset += DLCI_TEI_LENGTH;
	  efa = tvb_get_ntohs(parameter_tvb, offset);
	  dlci_efa = tvb_get_ntohs(parameter_tvb, offset);

	if (dlci_efa >= 0 && dlci_efa <= 8175) { col_append_fstr(pinfo->cinfo, COL_INFO, " | ISDN: %u", dlci_efa); }
	else if (dlci_efa == 8176) { col_append_str(pinfo->cinfo, COL_INFO, " | PSTN"); }
	else if (dlci_efa == 8177) { col_append_str(pinfo->cinfo, COL_INFO, " | Ctrl"); }
	else if (dlci_efa == 8178) { col_append_str(pinfo->cinfo, COL_INFO, " | BCC"); }
	else if (dlci_efa == 8179) { col_append_str(pinfo->cinfo, COL_INFO, " | ProtProt"); }
	else if (dlci_efa == 8180) { col_append_str(pinfo->cinfo, COL_INFO, " | LinkCtrl"); }
	else {};

	  if(efa <= 8175) {
	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: ISDN (%u)", efa);
	  proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:ISDN (%u))",sapi,tei,efa);
	  }
	  else if (efa > 8175 && efa <= 8180){
	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: %s (%u)", val_to_str(efa, efa_values, "unknown EFA"),tvb_get_ntohs(parameter_tvb, offset));
	  proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:%s (%u))",sapi,tei,val_to_str(efa, efa_values, "unknown EFA-value"),efa);
	  }
	  else if(efa >= 8181){
	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: RESERVED (%u)", efa);
	  proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:RESERVED (%u))",sapi,tei,efa);
	  }
	  else {
	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: %u", efa);
	  	proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:%u)",sapi,tei,efa);
	  }
  }
  /* if SAPI & TEI set to ZERO, EFA also shall be set to ZERO and didn't comply with value for ISDN protocol */
  else{
   	  offset += DLCI_TEI_LENGTH;
	  efa = tvb_get_ntohs(parameter_tvb, offset);
	  dlci_efa = tvb_get_ntohs(parameter_tvb, offset);

	if (dlci_efa >= 0 && dlci_efa <= 8175) { col_append_fstr(pinfo->cinfo, COL_INFO, " | ISDN: %u", dlci_efa); }
	else if (dlci_efa == 8176) { col_append_str(pinfo->cinfo, COL_INFO, " | PSTN"); }
	else if (dlci_efa == 8177) { col_append_str(pinfo->cinfo, COL_INFO, " | Ctrl"); }
	else if (dlci_efa == 8178) { col_append_str(pinfo->cinfo, COL_INFO, " | BCC"); }
	else if (dlci_efa == 8179) { col_append_str(pinfo->cinfo, COL_INFO, " | ProtProt"); }
	else if (dlci_efa == 8180) { col_append_str(pinfo->cinfo, COL_INFO, " | LinkCtrl"); }
	else {};

	  if(efa <= 8175) {

	  proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: ISDN (%u)", efa);
	  proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:ISDN (%u))",sapi,tei,efa);

	  }
	  else if (efa > 8175 && efa <= 8180){

	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: %s (%u)", val_to_str(efa, efa_values, "unknown EFA"),tvb_get_ntohs(parameter_tvb, offset));
	  proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:%s (%u))",sapi,tei,val_to_str(efa, efa_values, "unknown EFA-value"),efa);

	  }
	  else if(efa >= 8181){
	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: RESERVED (%u)", efa);
	  proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:RESERVED (%u))",sapi,tei,efa);
	  }
	  else {
	  	proto_tree_add_uint_format(parameter_tree, hf_efa,  parameter_tvb, offset, EFA_LENGTH, efa,
		"Envelope function address: %u", efa);
	  	proto_item_append_text(parameter_item, " (SAPI:%u TEI:%u EFA:%u)",sapi,tei,efa);
	  }
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
  proto_tree_add_item(parameter_tree, hf_draft_error_code, parameter_tvb, offset, MGMT_ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  offset += MGMT_ERROR_CODE_LENGTH ;
  if( tvb_length_remaining(parameter_tvb,offset) > 0 )
	  proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, offset, msg_length - offset,ENC_ASCII|ENC_NA);
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
  proto_tree_add_item(parameter_tree, hf_error_code, parameter_tvb, MGMT_ERROR_CODE_OFFSET, MGMT_ERROR_CODE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)",
                         val_to_str(tvb_get_ntohl(parameter_tvb, MGMT_ERROR_CODE_OFFSET), error_code_values, "Unknown error code"));
}

static void
dissect_diagnostic_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 diag_info_length;

  diag_info_length = tvb_get_ntohs(parameter_tvb, MGMT_ERROR_MSG_LENGTH_OFFSET) - MGMT_ERROR_MSG_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_diagnostic_info, parameter_tvb, PARAMETER_VALUE_OFFSET, diag_info_length, ENC_NA);
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

  proto_tree_add_item(parameter_tree, hf_status_type, parameter_tvb, NTFY_STATUS_TYPE_OFFSET, NTFY_STATUS_TYPE_LENGTH, ENC_BIG_ENDIAN);
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
  proto_tree_add_item(parameter_tree, hf_tei_status, parameter_tvb, TEI_STATUS_OFFSET, TEI_STATUS_LENGTH, ENC_BIG_ENDIAN);
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
  gint offset;
  offset = tvb_get_ntohs(parameter_tvb, TEI_STATUS_LENGTH_OFFSET) + 8;
  if(tvb_length_remaining(parameter_tvb, offset) > 0 ){
	  proto_tree_add_item(parameter_tree, hf_tei_draft_status, parameter_tvb, offset, TEI_STATUS_LENGTH, ENC_BIG_ENDIAN);
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

  proto_tree_add_item(parameter_tree, hf_adaptation_layer_id, parameter_tvb, PARAMETER_VALUE_OFFSET, adaptation_layer_id_length, ENC_ASCII|ENC_NA);
  proto_item_append_text(parameter_item, " (%.*s)", adaptation_layer_id_length,
                         tvb_get_ephemeral_string(parameter_tvb, PARAMETER_VALUE_OFFSET, adaptation_layer_id_length));
}

static void
dissect_scn_protocol_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 id_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  proto_tree_add_item(parameter_tree, hf_scn_protocol_id, parameter_tvb, PARAMETER_VALUE_OFFSET, id_length, ENC_ASCII|ENC_NA);
  proto_item_append_text(parameter_item, " (%.*s)", id_length,
                         tvb_get_ephemeral_string(parameter_tvb, PARAMETER_VALUE_OFFSET, id_length));
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
  proto_tree_add_item(parameter_tree, hf_asp_reason, parameter_tvb, ASP_REASON_OFFSET, ASP_REASON_LENGTH, ENC_BIG_ENDIAN);
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
  proto_tree_add_item(parameter_tree, hf_heartbeat_data, parameter_tvb, HEARTBEAT_DATA_OFFSET, heartbeat_data_length, ENC_NA);
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
  proto_tree_add_item(parameter_tree, hf_traffic_mode_type, parameter_tvb, TRAFFIC_MODE_TYPE_OFFSET, TRAFFIC_MODE_TYPE_LENGTH, ENC_BIG_ENDIAN);
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
    proto_tree_add_item(parameter_tree, hf_if_range_start, parameter_tvb, offset + IF_ID_START_OFFSET, IF_ID_START_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_if_range_end,   parameter_tvb, offset + IF_ID_END_OFFSET,   IF_ID_END_LENGTH,   ENC_BIG_ENDIAN);
    offset += IF_ID_INTERVAL_LENGTH;
  };

  proto_item_append_text(parameter_item, " (%u range%s)", number_of_ranges, plurality(number_of_ranges, "", "s"));
}
/*----------------------ASP Active,Inactive (RFC)------------------------------*/

/*----------------------Data Request,Indication (Draft,RFC)--------------------*/

#define DISCRIMINATOR_OFFSET 0
#define DISCRIMINATOR_LENGTH 1
#define ADDRESS_OFFSET       1
#define ADDRESS_LENGTH       1
#define LOW_ADDRESS_OFFSET   2
#define LOW_ADDRESS_LENGTH   1

#define ALL_ADDRESS_OFFSET   1
#define ALL_ADDRESS_LENGTH   2

#define MSG_TYPE_OFFSET      3
#define MSG_TYPE_LENGTH      1
#define MSG_HEADER_LENGTH    4
#define INFO_ELEMENT_OFFSET  4
#define INFO_ELEMENT_LENGTH  1

static void
dissect_layer3_message(tvbuff_t *layer3_data_tvb, proto_tree *v5ua_tree,proto_item *parameter_item, packet_info *pinfo)
{
  guint16 discriminator_offset;

  if(iua_version == DRAFT){
	  discriminator_offset = DISCRIMINATOR_OFFSET;
  }
  else{
	  discriminator_offset = DISCRIMINATOR_OFFSET + PARAMETER_HEADER_LENGTH;
  }

  if (tvb_get_guint8(layer3_data_tvb, discriminator_offset) == 0x48){
	  guint16 protocol_data_length;
	  tvbuff_t *protocol_data_tvb;

	  protocol_data_length = tvb_get_ntohs(layer3_data_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
	  protocol_data_tvb    = tvb_new_subset(layer3_data_tvb, PARAMETER_VALUE_OFFSET, protocol_data_length, protocol_data_length);

	  call_dissector(v52_handle, protocol_data_tvb, pinfo, v5ua_tree);

	  proto_item_append_text(parameter_item, " (%u byte%s)", protocol_data_length, plurality(protocol_data_length, "", "s"));

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
  proto_tree_add_item(parameter_tree, hf_release_reason, parameter_tvb, offset, RELEASE_REASON_LENGTH, ENC_BIG_ENDIAN);
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
  { LINK_STATUS_OPERTIONAL,      "Link operational" },
  { LINK_STATUS_NON_OPERTIONAL,  "Link not operational" },
  { 0,                           NULL } };

#define LINK_STATUS_OFFSET   PARAMETER_VALUE_OFFSET
#define LINK_STATUS_LENGTH   4

static void
dissect_link_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
	proto_tree_add_item(parameter_tree, hf_link_status, parameter_tvb, LINK_STATUS_OFFSET, LINK_STATUS_LENGTH, ENC_BIG_ENDIAN);
	proto_item_append_text(parameter_item, " (%s)",
	  val_to_str(tvb_get_ntohl(parameter_tvb, LINK_STATUS_OFFSET),link_status_values, "Unknown Link status"));

link_status_operational = tvb_get_ntohl(parameter_tvb, LINK_STATUS_OFFSET);
}
/*----------------------Link Status Indication (Draft,RFC)---------------------*/

/*----------------------Sa-Bit (Draft,RFC)-------------------------------------*/

	/* define parameter for sa-bit message */
#define SA_BIT_ID_ZERO     0x0
#define SA_BIT_ID_ONE      0x1
#define SA_BIT_VALUE_SA7   0x7

static const value_string sa_bit_values[] = {
	{ SA_BIT_ID_ZERO,    "set value ZERO" },
	{ SA_BIT_ID_ONE,     "set value ONE" },
	{ SA_BIT_VALUE_SA7,  "Addresses the Sa7 Bit" },
	{ 0,                 NULL } };

#define SA_BIT_ID_OFFSET     PARAMETER_VALUE_OFFSET
#define SA_BIT_ID_LENGTH     2
#define SA_BIT_VALUE_OFFSET  (SA_BIT_ID_OFFSET + SA_BIT_ID_LENGTH)
#define SA_BIT_VALUE_LENGTH  2

static void
dissect_sa_bit_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_sa_bit_id, parameter_tvb, SA_BIT_ID_OFFSET, SA_BIT_ID_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_sa_bit_value, parameter_tvb, SA_BIT_VALUE_OFFSET, SA_BIT_VALUE_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s %s)",
	  val_to_str(tvb_get_ntohs(parameter_tvb, SA_BIT_ID_OFFSET), sa_bit_values, "unknown"),
	  val_to_str(tvb_get_ntohs(parameter_tvb, SA_BIT_VALUE_OFFSET), sa_bit_values, "unknown Bit"));

sa_bit_id = tvb_get_ntohs(parameter_tvb, SA_BIT_VALUE_OFFSET);
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
  proto_tree_add_item(parameter_tree, hf_error_reason, parameter_tvb, ERROR_REASON_OFFSET, ERROR_REASON_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " (%s)",
	  val_to_str(tvb_get_ntohl(parameter_tvb, ERROR_REASON_OFFSET), error_reason_values, "unknown"));
}
/*----------------------Error Indication (RFC)---------------------------------*/

/*--------------------------ASP identifier-------------------------------------*/
#define ASP_IDENTIFIER_LENGTH 4
#define ASP_IDENTIFIER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_asp_identifier_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_asp_identifier, parameter_tvb, ASP_IDENTIFIER_OFFSET, ASP_IDENTIFIER_LENGTH, ENC_BIG_ENDIAN);
    proto_item_append_text(parameter_item, " (%d) ",tvb_get_ntohl(parameter_tvb,ASP_IDENTIFIER_OFFSET));
}
/*--------------------------ASP identifier-------------------------------------*/

#define INFO_STRING_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_info_string_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info_string_length;

  info_string_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  if(iua_version == DRAFT) info_string_length += 4;
  if(info_string_length > 4){
	info_string_length -= PARAMETER_HEADER_LENGTH;
	proto_tree_add_item(parameter_tree, hf_info_string, parameter_tvb, INFO_STRING_OFFSET, info_string_length, ENC_ASCII|ENC_NA);
	proto_item_append_text(parameter_item, " (%.*s)", info_string_length,
			       tvb_get_ephemeral_string(parameter_tvb, INFO_STRING_OFFSET, info_string_length));
  }
}


static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{

  guint16 parameter_value_length;

  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, ENC_NA);

  proto_item_append_text(parameter_item, " with tag %u and %u byte%s value",
  tvb_get_ntohs(parameter_tvb, PARAMETER_TAG_OFFSET), parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define Reserved_TAG 	         			 0x00
#define INT_INTERFACE_IDENTIFIER_PARAMETER_TAG           0x01
#define ASP_MSG_PARAMETER_TAG                            0x02
#define TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG          0x03
#define INFO_PARAMETER_TAG                               0x04
#define DLCI_PARAMETER_TAG                               0x81
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
#define ASP_IDENTIFIER_PARAMETER_TAG                     0x11
#define NOT_USED_IN_IUA_PARAMETER_TAG                    0x12
#define LINK_STATUS_PARAMETER_TAG                        0x82
#define SA_BIT_STATUS_PARAMETER_TAG                      0x83
#define ERROR_INDICATION_PARAMETER_TAG                   0x84

static const value_string parameter_tag_values[] = {
  { Reserved_TAG,              				 "Reserved" },
  { INT_INTERFACE_IDENTIFIER_PARAMETER_TAG,              "Interface Identifier (integer)" },
  { TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG,             "Interface Identifier (text)" },
  { INFO_PARAMETER_TAG,                                  "Info string" },
  { DLCI_PARAMETER_TAG,                                  "DLCI" },
  { DIAGNOSTIC_INFORMATION_PARAMETER_TAG,                "Diagnostic information" },
  { INTEGER_RANGE_INTERFACE_IDENTIFIER_PARAMETER_TAG,    "Interface Identifier Range" },
  { HEARTBEAT_DATA_PARAMETER_TAG,                        "Hearbeat data" },
  { ASP_DOWN_REASON_PARAMETER_TAG,                       "ASP DOWN Reason" },
  { TRAFFIC_MODE_TYPE_PARAMETER_TAG,                     "Traffic mode type" },
  { ERROR_CODE_PARAMETER_TAG,                            "Error code" },
  { STATUS_TYPE_INDENTIFICATION_PARAMETER_TAG,           "Status type/identification" },
  { PROTOCOL_DATA_PARAMETER_TAG,                         "Protocol Data" },
  { RELEASE_REASON_PARAMETER_TAG,                        "Release Reason" },
  { TEI_STATUS_PARAMETER_TAG,                            "TEI status" },
  { ASP_IDENTIFIER_PARAMETER_TAG,                        "ASP Identifier" },
  { NOT_USED_IN_IUA_PARAMETER_TAG,                       "Not used in IUA" },
  { LINK_STATUS_PARAMETER_TAG,                           "Link status" },
  { SA_BIT_STATUS_PARAMETER_TAG,                         "SA-Bit status" },
  { ERROR_INDICATION_PARAMETER_TAG,                      "Error reason" },
  { 0,                                                    NULL } };

static const value_string parameter_tag_draft_values[] = {
  { INT_INTERFACE_IDENTIFIER_PARAMETER_TAG,              "V5UA Interface Identifier (int)" },
  { ASP_MSG_PARAMETER_TAG,                               "ASP Adaption Layer ID" },
  { TEXT_INTERFACE_IDENTIFIER_PARAMETER_TAG,             "SCN Protocol Identifier" },
  { INFO_PARAMETER_TAG,                                  "Info" },
  { PROTOCOL_DATA_PARAMETER_TAG,                         "Protocol Data" },
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
  paddingl = padding_length;

  /* create proto_tree stuff */
  switch(iua_version){
  case RFC:
	  parameter_item   = proto_tree_add_text(v5ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s",
		val_to_str(tag, parameter_tag_values, "Unknown parameter"));
	  parameter_tree   = proto_item_add_subtree(parameter_item, ett_v5ua_parameter);
	  /* add tag to the v5ua tree */
	  proto_tree_add_item(parameter_tree, hf_parameter_tag, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, ENC_BIG_ENDIAN);
	  break;
  case DRAFT:
  default:
	  parameter_item   = proto_tree_add_text(v5ua_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s",
		val_to_str(tag, parameter_tag_draft_values, "Unknown parameter"));
	  parameter_tree   = proto_item_add_subtree(parameter_item, ett_v5ua_parameter);

	  /* add tag to the v5ua tree */
	  proto_tree_add_item(parameter_tree, hf_parameter_tag_draft, parameter_tvb, PARAMETER_TAG_OFFSET, PARAMETER_TAG_LENGTH, ENC_BIG_ENDIAN);
	  break;
  };

  /* add length to the v5ua tree */
  proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  switch(tag) {
  case INT_INTERFACE_IDENTIFIER_PARAMETER_TAG:
	if(iua_version == RFC) dissect_int_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
	if(iua_version == DRAFT){
		dissect_int_interface_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
		dissect_dlci_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo);

		/* for the following parameters no tag- and length-informations available. Parameters must be dissect with info from common msg header */
		if(msg_class==0 && msg_type==0)    dissect_draft_error_code_parameter(parameter_tvb, parameter_tree);
		if(msg_class==1)                   dissect_draft_tei_status_parameter(parameter_tvb, parameter_tree, parameter_item);
		if(msg_class==9){
			if(msg_type==1||msg_type==2||msg_type==3||msg_type==4){
				guint16 length_2, offset;
				tvbuff_t *layer3_data_tvb;
				offset = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) + 8;
				length_2 = msg_length - offset;
				if(length_2 > 0){
					if(tvb_get_guint8(parameter_tvb, offset) == 0x48){
						layer3_data_tvb = tvb_new_subset(parameter_tvb, offset, length_2, length_2);
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
    dissect_dlci_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo);
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
  case ASP_IDENTIFIER_PARAMETER_TAG:
    dissect_asp_identifier_parameter(parameter_tvb, parameter_tree, parameter_item);
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
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, ENC_NA);
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
#define COMMON_HEADER_MSG_CLASS_LENGTH      1
#define COMMON_HEADER_MSG_TYPE_LENGTH       1
#define COMMON_HEADER_MSG_LENGTH_LENGTH     4
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
  { V5UA_PROTOCOL_VERSION_RELEASE_1,  "Release 1.0" },
  { 0,                                NULL } };

	/* define V5UA MSGs */
#define MSG_CLASS_MGMT_MSG        0
#define MSG_CLASS_MGMT_MSG_DRAFT  1
#define MSG_CLASS_ASPSM_MSG       3
#define MSG_CLASS_ASPTM_MSG       4
#define MSG_CLASS_V5PTM_MSG_DRAFT 9
#define MSG_CLASS_V5PTM_MSG      14

static const value_string msg_class_values[] = {
	{ MSG_CLASS_MGMT_MSG,  "Management Messages" },
	{ MSG_CLASS_MGMT_MSG_DRAFT,"Management Messages"},
	{ MSG_CLASS_ASPSM_MSG, "ASP State Maintenance Message" },
	{ MSG_CLASS_ASPTM_MSG, "ASP Traffic Maintenance Message" },
	{ MSG_CLASS_V5PTM_MSG_DRAFT, "V5 Boundary Primitives Transport Message" },
	{ MSG_CLASS_V5PTM_MSG, "V5 Boundary Primitives Transport Message" },
	{ 0,                           NULL } };

	/* message types for MGMT messages */
#define MGMT_MSG_TYPE_ERR                  0
#define MGMT_MSG_TYPE_NTFY                 1
#define MGMT_MSG_TYPE_TEI_STATUS_REQ       2
#define MGMT_MSG_TYPE_TEI_STATUS_CON       3
#define MGMT_MSG_TYPE_TEI_STATUS_IND       4
#define MGMT_MSG_TYPE_TEI_QUERY_REQUEST5  5
#define MGMT_MSG_TYPE_TEI_QUERY_REQUEST   8
 /* end */

	/* MGMT messages for Nortel draft version*/
#define MGMT_MSG_DRAFT_TYPE_TEI_STATUS_REQ       1
#define MGMT_MSG_DRAFT_TYPE_TEI_STATUS_CON       2
#define MGMT_MSG_DRAFT_TYPE_TEI_STATUS_IND       3
#define MGMT_MSG_DRAFT_TYPE_TEI_QUERY_REQUEST5  5
#define MGMT_MSG_DRAFT_TYPE_TEI_QUERY_REQUEST   8
 /* end */

	/* message types for ASPSM messages */
#define ASPSM_MSG_TYPE_Reserved             0
#define ASPSM_MSG_TYPE_UP                   1
#define ASPSM_MSG_TYPE_DOWN                 2
#define ASPSM_MSG_TYPE_BEAT                 3
#define ASPSM_MSG_TYPE_UP_ACK               4
#define ASPSM_MSG_TYPE_DOWN_ACK             5
#define ASPSM_MSG_TYPE_BEAT_ACK             6

	/* message types for ASPTM messages */
#define ASPTM_MSG_TYPE_Reserved             0
#define ASPTM_MSG_TYPE_ACTIVE               1
#define ASPTM_MSG_TYPE_INACTIVE             2
#define ASPTM_MSG_TYPE_ACTIVE_ACK           3
#define ASPTM_MSG_TYPE_INACTIVE_ACK         4

	/* message types for V5PTM messages */
#define V5PTM_MSG_TYPE_Reserved                     0
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

#define MGMT_MSG_TYPE_TEI_STATUS_REQUEST5  5
#define MGMT_MSG_TYPE_TEI_STATUS_REQUEST   8

static const value_string msg_class_type_values[] = {
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_ERR,                         "Error" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_NTFY,                        "Notify" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_REQ,              "TEI status request" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_CON,              "TEI status confirmation" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_IND,              "TEI status indication" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_QUERY_REQUEST,           "TEI query request" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_QUERY_REQUEST5,          "TEI query request" },

  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_REQ,   "TEI status request" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_CON,   "TEI status confimation" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_IND,   "TEI status indication" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_QUERY_REQUEST,  "TEI query request" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_QUERY_REQUEST5, "TEI query request" },


  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_Reserved,                   "Reserved" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_UP,                         "ASP up" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_DOWN,                       "ASP down" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_BEAT,                       "Heartbeat" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_UP_ACK,                     "ASP up ack" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_DOWN_ACK,                   "ASP down ack" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_BEAT_ACK,                   "Heartbeat ack" },

  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_Reserved ,                  "Reserved" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_ACTIVE ,                    "ASP active" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_INACTIVE ,                  "ASP inactive" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_ACTIVE_ACK ,                "ASP active ack" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_INACTIVE_ACK ,              "ASP inactive ack" },

  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_Reserved,                   "Reserved" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_DATA_REQUEST,               "Data request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_DATA_INDICATION,            "Data indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_UNIT_DATA_REQUEST,          "Unit data request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_UNIT_DATA_INDICATION,       "Unit data indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ESTABLISH_REQUEST,          "Establish request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ESTABLISH_CONFIRM,          "Establish confirmation" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ESTABLISH_INDICATION,       "Establish indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_RELEASE_REQUEST,            "Release request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_RELEASE_CONFIRM,            "Release confirmation" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_RELEASE_INDICATION,         "Release indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_LINK_STATUS_START_REPORTING,"Link status start reporting" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_LINK_STATUS_STOP_REPORTING, "Link status stop reporting" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_LINK_STATUS_INDICATION,     "Link status indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_REQUEST,         "Sa-Bit set request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_CONFIRM,         "Sa-Bit set confirm" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_REQUEST,      "Sa-Bit status request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_INDICATION,   "Sa-Bit status indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ERROR_INDICATION,           "Error indication" },

  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_Reserved,                   "Reserved" },
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

static const value_string msg_class_type_values_short[] = {
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_ERR,                         "Error" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_NTFY,                        "Notify" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_REQ,              "TEI status request" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_CON,              "TEI status confirmation" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_STATUS_IND,              "TEI status indication" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_QUERY_REQUEST,           "TEI query request" },
  { MSG_CLASS_MGMT_MSG  * 256 + MGMT_MSG_TYPE_TEI_QUERY_REQUEST5,          "TEI query request" },

  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_REQ,   "TEI status request" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_CON,   "TEI status confimation" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_STATUS_IND,   "TEI status indication" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_QUERY_REQUEST,  "TEI query request" },
  { MSG_CLASS_MGMT_MSG_DRAFT * 256 + MGMT_MSG_DRAFT_TYPE_TEI_QUERY_REQUEST5, "TEI query request" },


  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_Reserved,                   "Reserved" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_UP,                         "ASP up" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_DOWN,                       "ASP down" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_BEAT,                       "Heartbeat" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_UP_ACK,                     "ASP up ack" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_DOWN_ACK,                   "ASP down ack" },
  { MSG_CLASS_ASPSM_MSG * 256 + ASPSM_MSG_TYPE_BEAT_ACK,                   "Heartbeat ack" },

  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_Reserved ,                  "Reserved" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_ACTIVE ,                    "ASP active" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_INACTIVE ,                  "ASP inactive" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_ACTIVE_ACK ,                "ASP active ack" },
  { MSG_CLASS_ASPTM_MSG * 256 + ASPTM_MSG_TYPE_INACTIVE_ACK ,              "ASP inactive ack" },

  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_Reserved,                   "Reserved" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_DATA_REQUEST,               "Data request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_DATA_INDICATION,            "Data indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_UNIT_DATA_REQUEST,          "Unit data request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_UNIT_DATA_INDICATION,       "Unit data indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ESTABLISH_REQUEST,          "Establish request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ESTABLISH_CONFIRM,          "Establish confirmation" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ESTABLISH_INDICATION,       "Establish indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_RELEASE_REQUEST,            "Release request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_RELEASE_CONFIRM,            "Release confirmation" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_RELEASE_INDICATION,         "Release indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_LINK_STATUS_START_REPORTING,"Link status start reporting" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_LINK_STATUS_STOP_REPORTING, "Link status stop reporting" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_LINK_STATUS_INDICATION,     "Link status indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_REQUEST,         "Sa-Bit set request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_CONFIRM,         "Sa-Bit set confirm" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_REQUEST,      "Sa-Bit status request" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_INDICATION,   "Sa-Bit status indication" },
  { MSG_CLASS_V5PTM_MSG_DRAFT * 256 + V5PTM_MSG_TYPE_ERROR_INDICATION,           "Error indication" },


  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_Reserved,                   "Reserved" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_DATA_REQUEST,               "Data Req" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_DATA_INDICATION,            "Data Ind" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_UNIT_DATA_REQUEST,          "U Data Req" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_UNIT_DATA_INDICATION,       "U Data Ind" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ESTABLISH_REQUEST,          "Est Req" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ESTABLISH_CONFIRM,          "Est Conf" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ESTABLISH_INDICATION,       "Est Ind" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_RELEASE_REQUEST,            "Rel Req" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_RELEASE_CONFIRM,            "Rel Con" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_RELEASE_INDICATION,         "Rel Ind" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_LINK_STATUS_START_REPORTING,"Link Status Start Rep" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_LINK_STATUS_STOP_REPORTING, "Link Status Stop Rep" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_LINK_STATUS_INDICATION,     "Link Status Ind" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_REQUEST,         "Sa-Bit Set Req" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_SET_CONFIRM,         "Sa-Bit set Conf" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_REQUEST,      "Sa-Bit Status Req" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_SA_BIT_STATUS_INDICATION,   "Sa-Bit Status Ind" },
  { MSG_CLASS_V5PTM_MSG * 256 + V5PTM_MSG_TYPE_ERROR_INDICATION,           "Error Ind" },
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
  col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_class * 256 + message_type, msg_class_type_values_short, "UNKNOWN"));


  if (v5ua_tree) {

	  /* create proto_tree stuff */
    common_header_item   = proto_tree_add_text(v5ua_tree, common_header_tvb, COMMON_HEADER_OFFSET, tvb_length(common_header_tvb),"Common Msg-Header");
    common_header_tree   = proto_item_add_subtree(common_header_item, ett_v5ua_common_header);

	  /* add the components of the common header to the protocol tree */
    proto_tree_add_item(common_header_tree, hf_version, common_header_tvb, COMMON_HEADER_VERSION_OFFSET, COMMON_HEADER_VERSION_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(common_header_tree, hf_reserved, common_header_tvb, COMMON_HEADER_RESERVED_OFFSET, COMMON_HEADER_RESERVED_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(common_header_tree, hf_msg_class, common_header_tvb, COMMON_HEADER_MSG_CLASS_OFFSET, COMMON_HEADER_MSG_CLASS_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(common_header_tree, hf_msg_type,
                              common_header_tvb, COMMON_HEADER_MSG_TYPE_OFFSET, COMMON_HEADER_MSG_TYPE_LENGTH,
                              message_type, "Message type: %s ( %u )",
                              val_to_str(message_class * 256 + message_type, msg_class_type_values, "reserved"), message_type);
    proto_tree_add_item(common_header_tree, hf_msg_length, common_header_tvb, COMMON_HEADER_MSG_LENGTH_OFFSET, COMMON_HEADER_MSG_LENGTH_LENGTH, ENC_BIG_ENDIAN);

	/* Add message type to the Common Msg-Header line */
    proto_item_append_text(common_header_item, " (%s)",val_to_str(message_class * 256 + message_type, msg_class_type_values, "Unknown Msg-Type"));
    messageclassCopy = message_class;
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

  parameters_tvb    = tvb_new_subset_remaining(tvb, COMMON_HEADER_LENGTH);
  dissect_parameters(parameters_tvb, pinfo, tree, v5ua_tree);
    if (dlci_efa >= 0 && dlci_efa <= 8175) {
	  if ((messageclassCopy == 0) || (messageclassCopy == 3) || (messageclassCopy == 4)) {
	  	messageclassCopy = -1;
	  }
	  else {
		  col_append_str(pinfo->cinfo, COL_INFO, " | ");
		  col_append_fstr(pinfo->cinfo, COL_INFO, "LinkId: %u", linkIdentifier);
	  }
   } else {};

   if (sa_bit_id > -1) {
		col_append_str(pinfo->cinfo, COL_INFO, " | ");
		col_append_fstr(pinfo->cinfo, COL_INFO, "SA7bit: %u", sa_bit_id);
		sa_bit_id = -1;
   } else {};

   if (link_status_operational > -1) {
	if (link_status_operational == 0) {
		col_append_str(pinfo->cinfo, COL_INFO, " | operational");
	}
	else if (link_status_operational == 1) {
		col_append_str(pinfo->cinfo, COL_INFO, " | non-operational");
	}else {
	}
	link_status_operational = -1;
   } else {};

}

static void
dissect_v5ua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

   gint    offset, remaining_length, length, tag, one_bit;


/* Set up structures needed to add the protocol subtree and manage it */
	proto_tree *v5ua_tree;
	proto_item *ti;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "V5UA");
/* end */
	col_clear(pinfo->cinfo, COL_INFO);
	if (tree) {
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
			if(tag==0x81){
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
		else if(tag==0x11){
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
			   NULL, HFILL } },
		{ &hf_reserved,
			{ "Reserved",               "v5ua.reserved",
			   FT_UINT8,    BASE_HEX, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_msg_class,
			{ "Message class",          "v5ua.msg_class",
			   FT_UINT8,    BASE_DEC, VALS(msg_class_values),           0x0,
			   NULL, HFILL } },
		{ &hf_msg_type,
			{ "Message Type",           "v5ua.msg_type",
			   FT_UINT8,    BASE_DEC, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_msg_type_id,
			{ "Message Type ID",        "v5ua.msg_type_id",
			   FT_UINT8,    BASE_DEC, VALS(msg_class_type_values),      0x0,
			   NULL, HFILL } },
		{ &hf_msg_length,
			{ "Message length",         "v5ua.msg_length",
			   FT_UINT32,   BASE_DEC, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_link_id,
			{ "Link Identifier",        "v5ua.link_id",
			   FT_UINT32,   BASE_DEC, NULL,                           0xffffffe0,
			   NULL, HFILL } },
		{ &hf_chnl_id,
			{ "Channel Identifier",     "v5ua.channel_id",
			   FT_UINT8,    BASE_DEC, NULL,                            0x1f,
			   NULL, HFILL } },

		{ &hf_adaptation_layer_id,
			{ "Adaptation Layer ID",    "v5ua.adaptation_layer_id",
			   FT_STRING,   BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_text_if_id,
			{ "Text interface identifier","v5ua.text_interface_id",
			   FT_STRING,   BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_scn_protocol_id,
			{ "SCN Protocol Identifier","v5ua.scn_protocol_id",
			   FT_STRING,   BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_info_string,
			{ "Info String",            "v5ua.info_string",
			   FT_STRING,   BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_asp_identifier,
			{ "ASP Identifier",          "v5ua.asp_identifier",
			   FT_UINT32,   BASE_HEX, NULL,						        0x0,
			   NULL, HFILL } },
		{ &hf_dlci_zero_bit,
			{ "Zero bit",               "v5ua.dlci_zero_bit",
			   FT_BOOLEAN,	8,        NULL,                             0x01,
			   NULL, HFILL } },
		{ &hf_dlci_spare_bit,
			{ "Spare bit",              "v5ua.dlci_spare_bit",
			   FT_BOOLEAN,	8,        NULL,                             0x02,
			   NULL, HFILL } },
		{ &hf_dlci_sapi,
			{ "SAPI",                   "v5ua.dlci_sapi",
			   FT_UINT8,	BASE_HEX, NULL,                             0xfc,
			   NULL, HFILL } },
		{ &hf_dlci_one_bit,
			{ "One bit",                "v5ua.dlci_one_bit",
			   FT_BOOLEAN,  8,        NULL,                             0x01,
			   NULL, HFILL } },
		{ &hf_dlci_tei,
			{ "TEI",                    "v5ua.dlci_tei",
			   FT_UINT8,    BASE_HEX, NULL,                             0xfe,
			   NULL, HFILL } },
		{ &hf_efa,
			{ "Envelope Function Address","v5ua.efa",
			   FT_UINT16,   BASE_DEC, VALS(efa_values),                 0x0,
			   NULL, HFILL } },
		{ &hf_spare_efa,
			{ "Envelope Function Address (spare)","v5ua.efa",
			   FT_UINT16,   BASE_DEC, NULL,                              ~7,
			   NULL, HFILL } },
		{ &hf_asp_reason,
			{ "Reason",                 "v5ua.asp_reason",
			   FT_UINT32,   BASE_HEX, VALS(asp_reason_values),          0x0,
			   NULL, HFILL } },
		{ &hf_release_reason,
			{ "Release Reason",         "v5ua.release_reason",
			   FT_UINT32,   BASE_HEX, VALS(release_reason_values),      0x0,
			   NULL, HFILL } },
		{ &hf_tei_status,
			{ "TEI status",             "v5ua.tei_status",
			   FT_UINT32,   BASE_HEX, VALS(tei_status_values),          0x0,
			   NULL, HFILL } },
		{ &hf_tei_draft_status,
			{ "TEI status",             "v5ua.tei_draft_status",
			   FT_UINT32,   BASE_HEX, VALS(tei_draft_status_values),    0x0,
			   NULL, HFILL } },
		{ &hf_link_status,
			{ "Link Status",            "v5ua.link_status",
			   FT_UINT32,   BASE_HEX, VALS(link_status_values),         0x0,
			   NULL, HFILL } },
		{ &hf_sa_bit_id,
			{ "BIT ID",                 "v5ua.sa_bit_id",
			   FT_UINT16,   BASE_HEX, VALS(sa_bit_values),              0x0,
			   NULL, HFILL } },
		{ &hf_sa_bit_value,
			{ "Bit Value",              "v5ua.sa_bit_value",
			   FT_UINT16,   BASE_HEX, VALS(sa_bit_values),              0x0,
			   NULL, HFILL } },
		{ &hf_parameter_tag,
			{ "Parameter Tag",          "v5ua.parameter_tag",
			   FT_UINT16,   BASE_HEX, VALS(parameter_tag_values),       0x0,
			   NULL, HFILL } },
		{ &hf_parameter_tag_draft,
			{ "Parameter Tag",          "v5ua.parameter_tag",
			   FT_UINT16,   BASE_HEX, VALS(parameter_tag_draft_values), 0x0,
			   NULL, HFILL } },
		{ &hf_parameter_length,
			{ "Parameter length",       "v5ua.parameter_length",
			   FT_UINT16,   BASE_DEC, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_parameter_value,
			{ "Parameter value",        "v5ua.parameter_value",
			   FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_parameter_padding,
			{ "Parameter padding",      "v5ua.parameter_padding",
			   FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_diagnostic_info,
			{ "Diagnostic Information", "v5ua.diagnostic_info",
			   FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_if_range_start,
			{ "Interface range Start",  "v5ua.interface_range_start",
			   FT_UINT32,   BASE_HEX, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_if_range_end,
			{ "Interface range End",    "v5ua.interface_range_end",
			   FT_UINT32,   BASE_HEX, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_heartbeat_data,
			{ "Heartbeat data",         "v5ua.heartbeat_data",
			   FT_BYTES,    BASE_NONE,NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_traffic_mode_type,
			{ "Traffic mode type",      "v5ua.traffic_mode_type",
			   FT_UINT32,   BASE_HEX, VALS(traffic_mode_type_values),   0x0,
			   NULL, HFILL } },
		{ &hf_error_code,
			{ "Error code",             "v5ua.error_code",
			   FT_UINT32,   BASE_HEX, VALS(error_code_values),          0x0,
			   NULL, HFILL } },
		{ &hf_draft_error_code,
			{ "Error code (draft)",     "v5ua.draft_error_code",
			   FT_UINT32,   BASE_HEX, VALS(draft_error_code_values),    0x0,
			   NULL, HFILL } },
		{ &hf_status_type,
			{ "Status type",            "v5ua.status_type",
			   FT_UINT16,   BASE_DEC, VALS(status_type_values),         0x0,
			   NULL, HFILL } },
		{ &hf_status_id,
			{ "Status identification",  "v5ua.status_id",
			   FT_UINT16,   BASE_DEC, NULL,                             0x0,
			   NULL, HFILL } },
		{ &hf_error_reason,
			{ "Error Reason",           "v5ua.error_reason",
			   FT_UINT32,   BASE_HEX, VALS(error_reason_values),        0x0,
			   NULL, HFILL } }
		};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_v5ua,
		&ett_v5ua_common_header,
		&ett_v5ua_parameter,
		&ett_v5ua_layer3
	};

/* Register the protocol name and description */
	proto_v5ua = proto_register_protocol("V5.2-User Adaptation Layer", "V5UA", "v5ua");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_v5ua, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* In RFC specification the SCTP registered User Port Number Assignment for V5UA is 5675 */
#define SCTP_PORT_V5UA_RFC         5675
#define SCTP_PORT_V5UA_DRAFT      10001

void
proto_reg_handoff_v5ua(void)
{
	dissector_handle_t v5ua_handle;

	v5ua_handle = create_dissector_handle(dissect_v5ua, proto_v5ua);
	q931_handle = find_dissector("q931");
	v52_handle = find_dissector("v52");

	dissector_add_uint("sctp.port", SCTP_PORT_V5UA_DRAFT, v5ua_handle);
	dissector_add_uint("sctp.port", SCTP_PORT_V5UA_RFC, v5ua_handle);
	dissector_add_uint("sctp.ppi",  V5UA_PAYLOAD_PROTOCOL_ID, v5ua_handle);
}
