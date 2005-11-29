/* packet-etheric.c
 * Routines for Etheric dissection a Ericsson propriatary protocol.
 * See
 *
 *	http://watersprings.org/pub/id/draft-toivanen-sccp-etheric-00.txt
 *
 * XXX - the version in that draft appears to use the same codes for
 * parameters as ISUP does, although it doesn't use all of them.  Should
 * we use the ISUP dissector's #defines and tables for them, as we do
 * now, or should we use our own?
 *
 * We also use its table for message types, but have our own #defines
 * for them; should we adopt the ISUP dissector's #defines, or have our
 * own table?
 * 
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <prefs.h>
#include "packet-e164.h"
#include "packet-q931.h"
#include "packet-isup.h"

/* Initialize the protocol and registered fields */
static int proto_etheric				= -1;
static int hf_etheric_protocol_version	= -1;
static int hf_etheric_message_length	= -1;
static int hf_etheric_cic				= -1;
static int hf_etheric_message_type		= -1;
static int hf_etheric_parameter_type	= -1;

static int hf_etheric_calling_partys_category					= -1;
static int hf_etheric_forw_call_isdn_access_indicator			= -1;
	
static int hf_etheric_transmission_medium_requirement			= -1;
static int hf_etheric_odd_even_indicator						= -1;
static int hf_etheric_called_party_nature_of_address_indicator	= -1;

static int hf_etheric_ni_indicator								= -1;
static int hf_etheric_calling_party_nature_of_address_indicator	= -1;

static int hf_etheric_inn_indicator								= -1;

static int hf_etheric_numbering_plan_indicator					= -1;

static int hf_etheric_address_presentation_restricted_indicator	= -1;
static int hf_etheric_screening_indicator						= -1;
static int hf_etheric_called_party_odd_address_signal_digit		= -1;
static int hf_etheric_calling_party_odd_address_signal_digit	= -1;
static int hf_etheric_called_party_even_address_signal_digit	= -1;
static int hf_etheric_calling_party_even_address_signal_digit	= -1;
static int hf_etheric_mandatory_variable_parameter_pointer		= -1;
static int hf_etheric_parameter_length							= -1;
static int hf_etheric_pointer_to_start_of_optional_part			= -1;
static int hf_etheric_inband_information_ind					= -1;
static int hf_etheric_cause_indicator							= -1;
static int hf_etheric_event_ind									= -1;	
static int hf_etheric_event_presentation_restricted_ind			= -1;

/* Initialize the subtree pointers */
static gint ett_etheric						= -1;
static gint ett_etheric_parameter			= -1;
static gint ett_etheric_address_digits		= -1;
static gint ett_etheric_circuit_state_ind	= -1;

/* set the tcp port */
static guint ethericTCPport1 =1806;
static guint ethericTCPport2 =10002;

static dissector_handle_t	q931_ie_handle = NULL;
/* Value strings */
static const value_string protocol_version_vals[] = {
	{ 0x00,	"Etheric 1.0" },
	{ 0x10,	"Etheric 2.0" },
	{ 0x11,	"Etheric 2.1" },
	{ 0,	NULL }
};

/* Definition of Message Types */
#define ETHERIC_MESSAGE_TYPE_INITIAL_ADDR       1
#define ETHERIC_MESSAGE_TYPE_SUBSEQ_ADDR        2
#define ETHERIC_MESSAGE_TYPE_INFO_REQ           3
#define ETHERIC_MESSAGE_TYPE_INFO               4
#define ETHERIC_MESSAGE_TYPE_CONTINUITY         5
#define ETHERIC_MESSAGE_TYPE_ADDR_CMPL          6
#define ETHERIC_MESSAGE_TYPE_CONNECT            7
#define ETHERIC_MESSAGE_TYPE_FORW_TRANS         8
#define ETHERIC_MESSAGE_TYPE_ANSWER             9
#define ETHERIC_MESSAGE_TYPE_RELEASE           12
#define ETHERIC_MESSAGE_TYPE_SUSPEND           13
#define ETHERIC_MESSAGE_TYPE_RESUME            14
#define ETHERIC_MESSAGE_TYPE_REL_CMPL          16
#define ETHERIC_MESSAGE_TYPE_CONT_CHECK_REQ    17
#define ETHERIC_MESSAGE_TYPE_RESET_CIRCUIT     18
#define ETHERIC_MESSAGE_TYPE_BLOCKING          19
#define ETHERIC_MESSAGE_TYPE_UNBLOCKING        20
#define ETHERIC_MESSAGE_TYPE_BLOCK_ACK         21
#define ETHERIC_MESSAGE_TYPE_UNBLOCK_ACK       22
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST      23
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_BLCK     24
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_UNBL     25
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_BL_ACK   26
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_UNBL_ACK 27
#define ETHERIC_MESSAGE_TYPE_FACILITY_REQ      31
#define ETHERIC_MESSAGE_TYPE_FACILITY_ACC      32
#define ETHERIC_MESSAGE_TYPE_FACILITY_REJ      33
#define ETHERIC_MESSAGE_TYPE_LOOP_BACK_ACK     36
#define ETHERIC_MESSAGE_TYPE_PASS_ALONG        40
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST_ACK  41
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_QRY      42
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_QRY_RSP  43
#define ETHERIC_MESSAGE_TYPE_CALL_PROGRSS      44
#define ETHERIC_MESSAGE_TYPE_USER2USER_INFO    45
#define ETHERIC_MESSAGE_TYPE_UNEQUIPPED_CIC    46
#define ETHERIC_MESSAGE_TYPE_CONFUSION         47
#define ETHERIC_MESSAGE_TYPE_OVERLOAD          48
#define ETHERIC_MESSAGE_TYPE_CHARGE_INFO       49
#define ETHERIC_MESSAGE_TYPE_NETW_RESRC_MGMT   50
#define ETHERIC_MESSAGE_TYPE_FACILITY          51
#define ETHERIC_MESSAGE_TYPE_USER_PART_TEST    52
#define ETHERIC_MESSAGE_TYPE_USER_PART_AVAIL   53
#define ETHERIC_MESSAGE_TYPE_IDENT_REQ         54
#define ETHERIC_MESSAGE_TYPE_IDENT_RSP         55
#define ETHERIC_MESSAGE_TYPE_SEGMENTATION      56
#define ETHERIC_MESSAGE_TYPE_LOOP_PREVENTION   64
#define ETHERIC_MESSAGE_TYPE_APPLICATION_TRANS 65
#define ETHERIC_MESSAGE_TYPE_PRE_RELEASE_INFO  66
#define ETHERIC_MESSAGE_TYPE_SUBSEQUENT_DIR_NUM 67

static const true_false_string isup_ISDN_originating_access_ind_value = {
  "originating access ISDN",
  "originating access non-ISDN"
};
static const value_string etheric_calling_partys_category_value[] = {
  { 0,	"Reserved"},
  { 1,	"Reserved"},
  { 2,	"Reserved"},
  { 3,	"Reserved"},
  { 4,	"Reserved"},
  { 5,	"Reserved"},
  { 10,	"Ordinary calling subscriber"},
  { 11,	"Reserved"},
  { 12,	"Reserved"},
  { 13,	"Test call"},
  /* q.763-200212Amd2 */
  { 14,	"Reserved"},
  { 15,	"Reserved"},
  { 0,	NULL}};

static const true_false_string isup_odd_even_ind_value = {
  "odd number of address signals",
  "even number of address signals"
};

static const value_string isup_called_party_nature_of_address_ind_value[] = {
  { 0,	"Spare"},
  { 1,	"Reserved"},
  { 2,	"Reserved"},
  { 3,	"national (significant) number"},
  { 4,	"international number"},
  { 5,	"Reserved"},
  { 0,	NULL}};

static const true_false_string isup_NI_ind_value = {
  "incomplete",
  "complete"
};

  static const value_string etheric_location_number_nature_of_address_ind_value[] = {
  { 0,	"Spare"},
  { 1,	"subscriber number (national use)"},
  { 2,	"unknown (national use)"},
  { 3,	"national (significant) number"},
  { 4,	"international number"},
  { 0,NULL}};

static const value_string isup_address_presentation_restricted_ind_value[] = {
  { 0,	"Presentation allowed"},
  { 1,	"Presentation restricted"},
  { 2,	"Reserved"},
  { 3,	"Spare"},
  { 0,	NULL}};

static const value_string isup_screening_ind_value[] = {
  { 0,     "Not available"},
  { 1,     "User provided, verified and passed"},
  { 2,     "reserved"},
  { 3,     "Network provided"},
  { 0,     NULL}};

static const value_string isup_called_party_address_digit_value[] = {
  { 0,  "0"},
  { 1,  "1"},
  { 2,  "2"},
  { 3,  "3"},
  { 4,  "4"},
  { 5,  "5"},
  { 6,  "6"},
  { 7,  "7"},
  { 8,  "8"},
  { 9,  "9"},
  { 10, "spare"},
  { 11, "code 11 "},
  { 12, "code 12"},
  { 15, "Stop sending"},
  { 0,  NULL}};

static const value_string isup_calling_party_address_digit_value[] = {
  { 0,  "0"},
  { 1,  "1"},
  { 2,  "2"},
  { 3,  "3"},
  { 4,  "4"},
  { 5,  "5"},
  { 6,  "6"},
  { 7,  "7"},
  { 8,  "8"},
  { 9,  "9"},
  { 10, "spare"},
  { 11, "code 11 "},
  { 12, "code 12"},
  { 15, "spare"},
  { 0,  NULL}};
static const true_false_string isup_INN_ind_value = {
  "routing to internal network number not allowed",
  "routing to internal network number allowed "
};
static const value_string isup_numbering_plan_ind_value[] = {
  { 1,	"ISDN (Telephony) numbering plan"},
  { 3,	"Data numbering plan (national use)"},
  { 4,	"Telex numbering plan (national use)"},
  { 5,	"Reserved for national use"},
  { 6,	"Reserved for national use"},
  { 0,	NULL}};

  static const true_false_string isup_inband_information_ind_value = {
  /* according 3.37/Q.763 */
  "in-band information or an appropirate pattern is now available",
  "no indication"
};
static const true_false_string isup_event_presentation_restricted_ind_value = {
  /* according 3.21/Q.763 */
  "presentation restricted",
  "no indication"
};
static const value_string isup_event_ind_value[] = {
  /* according 3.21/Q.763 */
  {  1,	"ALERTING"},
  {  2,	"PROGRESS"},
  {  3,	"in-band information or an appropriate pattern is now available"},
  {  4,	"call forwarded on busy (national use)"},
  {  5,	"call forwarded on no reply (national use)"},
  {  6,	"call forwarded unconditional (national use)"},
  {  0,	NULL}};

static void dissect_etheric_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *etheric_tree, guint8 etheric_version, guint8 message_length);

/* ------------------------------------------------------------------
  Mapping number to ASCII-character
 ------------------------------------------------------------------ */
static char number_to_char_2(int number)
{
  if (number < 10)
    return ((char) number + 0x30);
  else
    return ((char) number + 0x37);
}

/* Code to actually dissect the packets */
static int
dissect_etheric(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *etheric_tree;
	gint		offset = 0;
	guint8		message_length; 
	guint16		cic;
	guint8		message_type,etheric_version;
	
	tvbuff_t	*message_tvb;
	
	
	/* Do we have the version number? */
	if (!tvb_bytes_exist(tvb, 0, 1)) {
		/* No - reject this packet. */
		return 0;
	}
	etheric_version = tvb_get_guint8(tvb, 0);
	/* Do we know the version? */
	if (match_strval(etheric_version, protocol_version_vals) == NULL) {
		/* No - reject this packet. */
		return 0;
	}

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Etheric");

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	message_type = tvb_get_guint8(tvb, 4);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, isup_message_type_value_acro, "reserved"));

	if(tree){


/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_etheric, tvb, 0, -1, FALSE);

		etheric_tree = proto_item_add_subtree(ti, ett_etheric);
		proto_tree_add_item(etheric_tree, hf_etheric_protocol_version, tvb, offset, 1, FALSE);
		offset++;
		message_length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(etheric_tree, hf_etheric_message_length, tvb, offset, 1, FALSE);
		offset++;

		cic = tvb_get_letohs(tvb, offset) & 0x0FFF; /*since upper 4 bits spare */
		proto_tree_add_uint_format(etheric_tree, hf_etheric_cic, tvb, offset, 2, cic, "CIC: %u", cic);
		offset = offset + 2;
	
		message_tvb = tvb_new_subset(tvb, offset, -1, -1);
		dissect_etheric_message(message_tvb, pinfo, etheric_tree,etheric_version, message_length);


	}/* end end if tree */
	return tvb_length(tvb);
}

/* ------------------------------------------------------------------
 Dissector Parameter Forward Call Indicators
 */
static void
dissect_etheric_forward_call_indicators_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 forward_call_ind;

  forward_call_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_forw_call_isdn_access_indicator, 
	  parameter_tvb, 0, 1, forward_call_ind);

  proto_item_set_text(parameter_item, "Forward Call Indicators: 0x%x", forward_call_ind );
}

/* ------------------------------------------------------------------
 Dissector Parameter Calling Party's Category
 */
static void
dissect_etheric_calling_partys_category_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 calling_partys_category;

  calling_partys_category = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_etheric_calling_partys_category, parameter_tvb, 
	  0, 1, calling_partys_category);

  proto_item_set_text(parameter_item, "Calling Party's category: 0x%x (%s)", calling_partys_category,
	  val_to_str(calling_partys_category, etheric_calling_partys_category_value, "reserved/spare"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement
 */
static void
dissect_etheric_transmission_medium_requirement_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 transmission_medium_requirement;

  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_etheric_transmission_medium_requirement, parameter_tvb, 0, 1,transmission_medium_requirement);

  proto_item_set_text(parameter_item, "Transmission medium requirement: %u (%s)",  transmission_medium_requirement, val_to_str(transmission_medium_requirement, isup_transmission_medium_requirement_value, "spare"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Called party number
 */
static void
dissect_etheric_called_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char *called_number;
  e164_info_t e164_info;
 
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_etheric_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  offset = 1;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
					    "Called Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_etheric_address_digits);

  length = tvb_reported_length_remaining(parameter_tvb, offset);
  called_number = ep_alloc((length+1) *2);
  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_etheric_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char_2(address_digit_pair & 0x0F);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_etheric_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
    }
    offset++;
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_etheric_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
  }
  called_number[i++] = '\0';
  e164_info.e164_number_type = CALLED_PARTY_NUMBER;
  e164_info.nature_of_address = indicators1 & 0x7f;
  e164_info.E164_number_str = called_number;
  e164_info.E164_number_length = i - 1;
  dissect_e164_number(parameter_tvb, address_digits_tree, 2,
								  (offset - 2), e164_info);
  proto_item_set_text(address_digits_item, "Called Party Number: %s", called_number);
  proto_item_set_text(parameter_item, "Called Party Number: %s", called_number);
}
/* ------------------------------------------------------------------
  Dissector Parameter calling party number
 */
static void
dissect_etheric_calling_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char *calling_number;
  e164_info_t e164_info;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_etheric_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_etheric_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_etheric_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
					    "Calling Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_etheric_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  /* prevent running behind the end of calling_number array by throwing an exception */
  calling_number = ep_alloc((length+1) *2);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char_2(address_digit_pair & 0x0F);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xF0) / 0x10);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xF0) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Calling Party Number: %s", calling_number);
  proto_item_set_text(parameter_item, "Calling Party Number: %s", calling_number);
  
    e164_info.e164_number_type = CALLING_PARTY_NUMBER;
    e164_info.nature_of_address = indicators1 & 0x7f;
    e164_info.E164_number_str = calling_number;
    e164_info.E164_number_length = i - 1;
    dissect_e164_number(parameter_tvb, address_digits_tree, 2, (offset - 2), e164_info);
}
/* ------------------------------------------------------------------
  Dissector Parameter location number
 */
static void
dissect_etheric_location_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char *calling_number;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_etheric_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_etheric_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_etheric_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  if ((indicators2 & 0x70) == 0x50)
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, 1, "Different meaning for Location Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_etheric_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_etheric_screening_indicator, parameter_tvb, 1, 1, indicators2);

   /* NOTE  When the address presentation restricted indicator indicates address not available, the
    * subfields in items a), b), c) and d) are coded with 0's, and the screening indicator is set to 11
    * (network provided).
    */
  if ( indicators2 == 0x0b ){
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, -1, "Location number: address not available");
    proto_item_set_text(parameter_item, "Location number: address not available");
    return;
  }

  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
					    "Location number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_etheric_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  calling_number = ep_alloc((length+1) *2);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char_2(address_digit_pair & 0x0f);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Location number: %s", calling_number);
  proto_item_set_text(parameter_item, "Location number: %s", calling_number);
}

/* ------------------------------------------------------------------
  Dissector Parameter User service information- no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_etheric_user_service_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
	  "User service information (-> Q.931 Bearer_capability)");
  proto_item_set_text(parameter_item, "User service information, (%u byte%s length)",
	  length , plurality(length, "", "s"));
  dissect_q931_bearer_capability_ie(parameter_tvb,
					    0, length,
					    parameter_tree);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access Transport - no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_etheric_access_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree,
			 proto_item *parameter_item, packet_info *pinfo)
{ guint length = tvb_reported_length(parameter_tvb);

  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1, 
	  "Access transport parameter field (-> Q.931)");
  
  if (q931_ie_handle)
    call_dissector(q931_ie_handle, parameter_tvb, pinfo, parameter_tree);

  proto_item_set_text(parameter_item, "Access transport (%u byte%s length)",
	  length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
 Dissector Parameter Backward Call Indicators
 */
static void
dissect_etheric_backward_call_indicators_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 backward_call_ind;

  backward_call_ind = tvb_get_guint8(parameter_tvb, 0);


  proto_tree_add_boolean(parameter_tree, hf_etheric_inband_information_ind, parameter_tvb, 0, 1, backward_call_ind);

  proto_item_set_text(parameter_item, "Backward Call Indicators: 0x%x", backward_call_ind);
}
/* ------------------------------------------------------------------
  Dissector Parameter Cause Indicators - no detailed dissection since defined in Rec. Q.850
 */



/* ------------------------------------------------------------------
  Dissector Message Type release message
 */
static gint
dissect_etheric_release_message(tvbuff_t *message_tvb, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length;

  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = 0;
  parameter_length = 1;

  parameter_item = proto_tree_add_text(etheric_tree, message_tvb,
				       offset +  parameter_pointer, 1,"Cause indicators, see Q.850");

  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 1, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  proto_tree_add_item(parameter_tree, hf_etheric_cause_indicator, message_tvb, 0, 1,FALSE);
  offset += 1;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Parameter Event information
 */
static void
dissect_etheric_event_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_event_ind, parameter_tvb, 0, 1, indicators, "Event indicator: %s (%u)", val_to_str(indicators & 0x7f, isup_event_ind_value, "spare"), indicators & 0x7f);
  proto_tree_add_boolean(parameter_tree, hf_etheric_event_presentation_restricted_ind, parameter_tvb, 0, 1, indicators);

  proto_item_set_text(parameter_item,"Event information: %s (%u)", val_to_str(indicators & 0x7f, isup_event_ind_value, "spare"),indicators );
}

/* ------------------------------------------------------------------ */
static void
dissect_etheric_unknown_parameter(tvbuff_t *parameter_tvb, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_item_set_text(parameter_item, "Parameter Type unknown/reserved (%u Byte%s)", length , plurality(length, "", "s"));
}

/* ------------------------------------------------------------------ */
/* Dissectors for all used message types                              */
/* Called by dissect_etheric_message(),                               */
/* call parameter dissectors in order of mandatory parameters         */
/* (since not labeled)                                                */
/* ------------------------------------------------------------------
  Dissector Message Type Initial address message
 */
static gint
dissect_etheric_initial_address_message(tvbuff_t *message_tvb, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for 1nd mandatory fixed parameter: Forward Call Indicators */
  parameter_type =  PARAM_TYPE_FORW_CALL_IND;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1,
				       "Forward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(2, actual_length), 2 );
  dissect_etheric_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset +=  1;

  /* Do stuff for 2nd mandatory fixed parameter: Calling party's category */
  parameter_type = PARAM_TYPE_CALLING_PRTY_CATEG;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1, "Calling Party's category");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length),1 );
  dissect_etheric_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  /* Do stuff for 3d mandatory fixed parameter: Transmission medium requirement */
  parameter_type = PARAM_TYPE_TRANSM_MEDIUM_REQU;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1, "Transmission medium requirement");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length), 1);
  dissect_etheric_transmission_medium_requirement_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;


  /* Do stuff for mandatory variable parameter Called party number */
  parameter_type = PARAM_TYPE_CALLED_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(etheric_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + 1,
				       "Called Party Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_etheric_mandatory_variable_parameter_pointer,
	  message_tvb, offset, 1, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_length, message_tvb,
	  offset + parameter_pointer, 1, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + 1, MIN(parameter_length, actual_length), parameter_length );
  dissect_etheric_called_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  /* Do stuff for mandatory variable parameter Calling party number */
  parameter_type = PARAM_TYPE_CALLING_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(etheric_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + 1,
				       "Calling Party Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_etheric_mandatory_variable_parameter_pointer,
	  message_tvb, offset, 1, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_length, message_tvb,
	  offset + parameter_pointer, 1, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + 1, MIN(parameter_length, actual_length), parameter_length );
  dissect_etheric_calling_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Address complete
 */
static gint
dissect_etheric_address_complete_message(tvbuff_t *message_tvb, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: backward call indicators*/
  parameter_type = PARAM_TYPE_BACKW_CALL_IND;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1,
				       "Backward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length), 1);
  dissect_etheric_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Call Progress
*/
static gint
dissect_etheric_call_progress_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: Event information*/
  parameter_type = PARAM_TYPE_EVENT_INFO;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       1,
				       "Event information");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length), 1);
  dissect_etheric_event_information_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector all optional parameters
*/
static void
dissect_etheric_optional_parameter(tvbuff_t *optional_parameters_tvb,packet_info *pinfo, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  gint offset = 0;
  guint parameter_type, parameter_length, actual_length;
  tvbuff_t *parameter_tvb;

  /* Dissect all optional parameters while end of message isn't reached */
  parameter_type = 0xFF; /* Start-initializiation since parameter_type is used for while-condition */

  while ((tvb_length_remaining(optional_parameters_tvb, offset)  >= 1) && (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS)){
    parameter_type = tvb_get_guint8(optional_parameters_tvb, offset);

    if (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS){
      parameter_length = tvb_get_guint8(optional_parameters_tvb, offset + 1);

      parameter_item = proto_tree_add_text(etheric_tree, optional_parameters_tvb,
					   offset,
					   parameter_length  + 1 + 1,
					   "Parameter: type %u",
					   parameter_type);
      parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
      proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, optional_parameters_tvb, offset, 1, parameter_type, "Optional Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
      offset += 1;

      proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_length, optional_parameters_tvb, offset, 1, parameter_length, "Parameter length: %u", parameter_length);
      offset += 1;

      actual_length = tvb_length_remaining(optional_parameters_tvb, offset);
      if (actual_length > 0){
	parameter_tvb = tvb_new_subset(optional_parameters_tvb, offset, MIN(parameter_length, actual_length), parameter_length);
	switch (parameter_type) {
	case PARAM_TYPE_USER_SERVICE_INFO:
	  dissect_etheric_user_service_information_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_ACC_TRANSP:
	  dissect_etheric_access_transport_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo);
	  break;
	 
	case PARAM_TYPE_LOCATION_NR:
	  dissect_etheric_location_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;

	default:
	  dissect_etheric_unknown_parameter(parameter_tvb, parameter_item);
	  break;
	}
	offset += MIN(parameter_length, actual_length);
      }

    }
    else {
	/* End of optional parameters is reached */
	proto_tree_add_uint_format(etheric_tree, hf_etheric_message_type, optional_parameters_tvb , offset, 1, parameter_type, "End of optional parameters (%u)", parameter_type);
    }
  }
}
		

static void
dissect_etheric_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *etheric_tree, guint8 etheric_version, guint8 message_length)
{
  tvbuff_t *parameter_tvb;
  tvbuff_t *optional_parameter_tvb;
  gint offset, bufferlength;
  guint8 message_type; 
  guint8 opt_parameter_pointer = 0;
  gint opt_part_possible = FALSE; /* default setting - for message types allowing optional
				     params explicitely set to TRUE in case statement */
  offset = 0;
    /* Extract message type field */
  message_type = tvb_get_guint8(message_tvb,0);
  proto_tree_add_item(etheric_tree, hf_etheric_message_type, message_tvb, 0, 1,FALSE);
  offset ++;
  parameter_tvb = tvb_new_subset(message_tvb, offset, -1, -1);

  switch (message_type) {
    case ETHERIC_MESSAGE_TYPE_ADDR_CMPL:
       offset += dissect_etheric_address_complete_message(parameter_tvb, etheric_tree);
       opt_part_possible = FALSE;
      break;

    case ETHERIC_MESSAGE_TYPE_ANSWER:
      /* no dissector necessary since no mandatory parameters included */
		if (etheric_version > 0x10 ) /* 0x10,	"Etheric 2.0" */
	       opt_part_possible = TRUE;
      break;

    case ETHERIC_MESSAGE_TYPE_BLOCK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_BLOCKING:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_CONNECT:
		if (etheric_version > 0x10 ) /* 0x10,	"Etheric 2.0" */
			opt_part_possible = TRUE;
      break;

    case ETHERIC_MESSAGE_TYPE_CALL_PROGRSS:
       offset += dissect_etheric_call_progress_message(parameter_tvb, etheric_tree);
       opt_part_possible = TRUE;
      break;

    case ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_INITIAL_ADDR:
		offset += dissect_etheric_initial_address_message(parameter_tvb, etheric_tree);
		if (etheric_version > 0 ) /* 0x00,	"Etheric 1.0" */
			opt_part_possible = TRUE;
     break;

    case ETHERIC_MESSAGE_TYPE_RELEASE:
       offset += dissect_etheric_release_message(parameter_tvb, etheric_tree);
       opt_part_possible = FALSE;
      break;

	case ETHERIC_MESSAGE_TYPE_REL_CMPL:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case ETHERIC_MESSAGE_TYPE_RESET_CIRCUIT:
      /* no dissector necessary since no mandatory parameters included */
      break;
 
	case ETHERIC_MESSAGE_TYPE_UNBLOCKING:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case ETHERIC_MESSAGE_TYPE_UNBLOCK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;
 default:
     bufferlength = tvb_length_remaining(message_tvb, offset);
     if (bufferlength != 0)
       proto_tree_add_text(etheric_tree, parameter_tvb, 0, bufferlength, 
			"Unknown Message type (possibly reserved/used in former ISUP version)");
     break;
  }

   /* extract pointer to start of optional part (if any) */
   if (opt_part_possible == TRUE){
	   if (message_length > 5 ) {
		   opt_parameter_pointer = tvb_get_guint8(message_tvb, offset);

		   proto_tree_add_uint_format(etheric_tree, hf_etheric_pointer_to_start_of_optional_part,
				message_tvb, offset, 1, opt_parameter_pointer, "Pointer to start of optional part: %u", opt_parameter_pointer);
		   offset += opt_parameter_pointer;
		   if (opt_parameter_pointer > 0){
		     optional_parameter_tvb = tvb_new_subset(message_tvb, offset, -1, -1 );
		     dissect_etheric_optional_parameter(optional_parameter_tvb, pinfo, etheric_tree);
		   }
	   }
   }
   else if (message_type !=ETHERIC_MESSAGE_TYPE_CHARGE_INFO)
     proto_tree_add_text(etheric_tree, message_tvb, 0, 0, 
		"No optional parameters are possible with this message type");

}
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_etheric(void)
{
	static dissector_handle_t etheric_handle;

	static int tcp_port1 = 1806;
	static int tcp_port2 = 10002;
	static int Initialized=FALSE;


	if (!Initialized) {
		etheric_handle = find_dissector("etheric");
		Initialized=TRUE;
	}else{
		dissector_delete("udp.port", tcp_port1, etheric_handle);
		dissector_delete("udp.port", tcp_port2, etheric_handle);
	}

	tcp_port1 = ethericTCPport1;
	tcp_port2 = ethericTCPport2;

	dissector_add("tcp.port", ethericTCPport1, etheric_handle);
	dissector_add("tcp.port", ethericTCPport2, etheric_handle);
	q931_ie_handle = find_dissector("q931.ie");

}

void
proto_register_etheric(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_etheric_protocol_version,
			{ "Protocol version",           "etheric.protocol_version",
			FT_UINT8, BASE_HEX, VALS(&protocol_version_vals), 0x0,          
			"Etheric protocol version", HFILL }
		},
		{ &hf_etheric_message_length,
			{ "Message length",           "etheric.message.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"Etheric Message length", HFILL }
		},
		{ &hf_etheric_cic,
			{ "CIC",           "etheric.cic",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"Etheric CIC", HFILL }
		},
		{ &hf_etheric_message_type,
			{ "Message type",           "etheric.message.type",
			FT_UINT8, BASE_HEX, VALS(&isup_message_type_value), 0x0,          
			"Etheric message types", HFILL }
		},
		{ &hf_etheric_parameter_type,
			{ "Parameter Type",  "etheric.parameter_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_forw_call_isdn_access_indicator,
			{ "ISDN access indicator",  "etheric.forw_call_isdn_access_indicator",
			FT_BOOLEAN, 16, TFS(&isup_ISDN_originating_access_ind_value), 0x01,
			"", HFILL }},

		{ &hf_etheric_calling_partys_category,
			{ "Calling Party's category",  "etheric.calling_partys_category",
			FT_UINT8, BASE_HEX, VALS(etheric_calling_partys_category_value), 0x0,
			"", HFILL }},

		{ &hf_etheric_mandatory_variable_parameter_pointer,
			{ "Pointer to Parameter",  "etheric.mandatory_variable_parameter_pointer",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_pointer_to_start_of_optional_part,
			{ "Pointer to optional parameter part",  "etheric.optional_parameter_part_pointer",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_parameter_length,
			{ "Parameter Length",  "etheric.parameter_length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_transmission_medium_requirement,
			{ "Transmission medium requirement",  "etheric.transmission_medium_requirement",
			FT_UINT8, BASE_DEC, VALS(isup_transmission_medium_requirement_value), 0x0,
			"", HFILL }},

		{ &hf_etheric_odd_even_indicator,
			{ "Odd/even indicator",  "etheric.isdn_odd_even_indicator",
			FT_BOOLEAN, 8, TFS(&isup_odd_even_ind_value), 0x80,
			"", HFILL }},

		{ &hf_etheric_called_party_nature_of_address_indicator,
			{ "Nature of address indicator",  "etheric.called_party_nature_of_address_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_nature_of_address_ind_value), 0x3f,
			"", HFILL }},

		{ &hf_etheric_calling_party_nature_of_address_indicator,
			{ "Nature of address indicator",  "etheric.calling_party_nature_of_address_indicator",
			FT_UINT8, BASE_DEC, VALS(etheric_location_number_nature_of_address_ind_value), 0x7f,
			"", HFILL }},


		{ &hf_etheric_ni_indicator,
			{ "NI indicator",  "etheric.ni_indicator",
			FT_BOOLEAN, 8, TFS(&isup_NI_ind_value), 0x80,
			"", HFILL }},

		{ &hf_etheric_inn_indicator,
			{ "INN indicator",  "etheric.inn_indicator",
			FT_BOOLEAN, 8, TFS(&isup_INN_ind_value), 0x80,
			"", HFILL }},

		{ &hf_etheric_numbering_plan_indicator,
			{ "Numbering plan indicator",  "etheric.numbering_plan_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_numbering_plan_ind_value), 0x70,
			"", HFILL }},

		{ &hf_etheric_address_presentation_restricted_indicator,
			{ "Address presentation restricted indicator",  "etheric.address_presentation_restricted_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_address_presentation_restricted_ind_value), 0x0c,
			"", HFILL }},

		{ &hf_etheric_screening_indicator,
			{ "Screening indicator",  "etheric.screening_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_screening_ind_value), 0x03,
			"", HFILL }},

		{ &hf_etheric_called_party_odd_address_signal_digit,
			{ "Address signal digit",  "etheric.called_party_odd_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), 0x0F,
			"", HFILL }},

		{ &hf_etheric_calling_party_odd_address_signal_digit,
			{ "Address signal digit",  "etheric.calling_party_odd_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), 0x0F,
			"", HFILL }},

		{ &hf_etheric_called_party_even_address_signal_digit,
			{ "Address signal digit",  "etheric.called_party_even_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), 0xF0,
			"", HFILL }},

		{ &hf_etheric_calling_party_even_address_signal_digit,
			{ "Address signal digit",  "etheric.calling_party_even_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), 0xF0,
			"", HFILL }},

		{ &hf_etheric_inband_information_ind,
			{ "In-band information indicator",  "etheric.inband_information_ind",
			FT_BOOLEAN, 8, TFS(&isup_inband_information_ind_value), 0x01,
			"", HFILL }},

		{ &hf_etheric_cause_indicator,
			{ "Cause indicator",  "etheric.cause_indicator",
			FT_UINT8, BASE_DEC, VALS(q850_cause_code_vals), 0x7f,
			"", HFILL }},

		{ &hf_etheric_event_ind,
			{ "Event indicator",  "etheric.event_ind",
			  FT_UINT8, 8, VALS(isup_event_ind_value), 0x7f,
			"", HFILL }},

		{ &hf_etheric_event_presentation_restricted_ind,
			{ "Event presentation restricted indicator",  "etheric.event_presentatiation_restr_ind",
			FT_BOOLEAN, 8, TFS(&isup_event_presentation_restricted_ind_value), 0x80,
			"", HFILL }},


	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_etheric,
		&ett_etheric_parameter,
		&ett_etheric_address_digits,
		&ett_etheric_circuit_state_ind,
	};

	module_t *etheric_module;

/* Register the protocol name and description */
	proto_etheric = proto_register_protocol("Etheric",
	    "ETHERIC", "etheric");

	new_register_dissector("etheric", dissect_etheric, proto_etheric);


/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_etheric, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	/* Register a configuration option for port */
	etheric_module = prefs_register_protocol(proto_etheric,
											  proto_reg_handoff_etheric);

	prefs_register_uint_preference(etheric_module, "tcp.port1",
								   "etheric TCP Port 1",
								   "Set TCP port 1 for etheric messages",
								   10,
								   &ethericTCPport1);

	prefs_register_uint_preference(etheric_module, "tcp.port2",
								   "etheric TCP Port 2",
								   "Set TCP port 2 for etheric messages",
								   10,
								   &ethericTCPport2);
}
