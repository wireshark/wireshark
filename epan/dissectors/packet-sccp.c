/* packet-sccp.c
 * Routines for Signalling Connection Control Part (SCCP) dissection
 *
 * It is hopefully compliant to:
 *   ANSI T1.112.3-2001
 *   ITU-T Q.713 7/1996
 *   YDN 038-1997 (Chinese ITU variant)
 *   JT-Q713 and NTT-Q713 (Japan)
 *
 *   Note that Japan-specific GTT is incomplete; in particular, the specific
 *   TTs that are defined in TTC and NTT are not decoded in detail.
 *
 * Copyright 2002, Jeff Morriss <jeff.morriss[AT]ulticom.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m2pa.c
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
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/reassemble.h>
#include <epan/asn1.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include "packet-mtp3.h"
#include "packet-tcap.h"
#include "packet-sccp.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-frame.h"
#include <epan/tap.h>
#include <address.h>

/* function prototypes */
void proto_reg_handoff_sccp(void);

static Standard_Type decode_mtp3_standard;

#define SCCP_SI 3

#define SCCP_MSG_TYPE_OFFSET 0
#define SCCP_MSG_TYPE_LENGTH 1
#define POINTER_LENGTH      1
#define POINTER_LENGTH_LONG 2

#define INVALID_LR 0xffffff /* a reserved value */

/* Same as below but with names typed out */
static const value_string sccp_message_type_values[] = {
  { SCCP_MSG_TYPE_CR,		"Connection Request" },
  { SCCP_MSG_TYPE_CC,		"Connection Confirm" },
  { SCCP_MSG_TYPE_CREF,		"Connection Refused" },
  { SCCP_MSG_TYPE_RLSD,		"Released" },
  { SCCP_MSG_TYPE_RLC,		"Release Complete" },
  { SCCP_MSG_TYPE_DT1,		"Data Form 1" },
  { SCCP_MSG_TYPE_DT2,		"Data Form 2" },
  { SCCP_MSG_TYPE_AK,		"Data Acknowledgement" },
  { SCCP_MSG_TYPE_UDT,		"Unitdata" },
  { SCCP_MSG_TYPE_UDTS,		"Unitdata Service" },
  { SCCP_MSG_TYPE_ED,		"Expedited Data" },
  { SCCP_MSG_TYPE_EA,		"Expedited Data Acknowledgement" },
  { SCCP_MSG_TYPE_RSR,		"Reset Request" },
  { SCCP_MSG_TYPE_RSC,		"Reset Confirmation" },
  { SCCP_MSG_TYPE_ERR,		"Error" },
  { SCCP_MSG_TYPE_IT,		"Inactivity Timer" },
  { SCCP_MSG_TYPE_XUDT,		"Extended Unitdata" },
  { SCCP_MSG_TYPE_XUDTS,	"Extended Unitdata Service" },
  { SCCP_MSG_TYPE_LUDT,		"Long Unitdata" },
  { SCCP_MSG_TYPE_LUDTS,	"Long Unitdata Service" },
  { 0,				NULL } };

/* Same as above but in acronym form (for the Info column) */
const value_string sccp_message_type_acro_values[] = {
  { SCCP_MSG_TYPE_CR,		"CR" },
  { SCCP_MSG_TYPE_CC,		"CC" },
  { SCCP_MSG_TYPE_CREF,		"CREF" },
  { SCCP_MSG_TYPE_RLSD,		"RLSD" },
  { SCCP_MSG_TYPE_RLC,		"RLC" },
  { SCCP_MSG_TYPE_DT1,		"DT1" },
  { SCCP_MSG_TYPE_DT2,		"DT2" },
  { SCCP_MSG_TYPE_AK,		"AK" },
  { SCCP_MSG_TYPE_UDT,		"UDT" },
  { SCCP_MSG_TYPE_UDTS,		"UDTS" },
  { SCCP_MSG_TYPE_ED,		"ED" },
  { SCCP_MSG_TYPE_EA,		"EA" },
  { SCCP_MSG_TYPE_RSR,		"RSR" },
  { SCCP_MSG_TYPE_RSC,		"RSC" },
  { SCCP_MSG_TYPE_ERR,		"ERR" },
  { SCCP_MSG_TYPE_IT,		"IT" },
  { SCCP_MSG_TYPE_XUDT,		"XUDT" },
  { SCCP_MSG_TYPE_XUDTS,	"XUDTS" },
  { SCCP_MSG_TYPE_LUDT,		"LUDT" },
  { SCCP_MSG_TYPE_LUDTS,	"LUDTS" },
  { 0,				NULL } };

#define PARAMETER_LENGTH_LENGTH			1
#define PARAMETER_LONG_DATA_LENGTH_LENGTH	2
#define PARAMETER_TYPE_LENGTH			1

#define PARAMETER_END_OF_OPTIONAL_PARAMETERS	0x00
#define PARAMETER_DESTINATION_LOCAL_REFERENCE	0x01
#define PARAMETER_SOURCE_LOCAL_REFERENCE	0x02
#define PARAMETER_CALLED_PARTY_ADDRESS		0x03
#define PARAMETER_CALLING_PARTY_ADDRESS		0x04
#define PARAMETER_CLASS				0x05
#define PARAMETER_SEGMENTING_REASSEMBLING	0x06
#define PARAMETER_RECEIVE_SEQUENCE_NUMBER	0x07
#define PARAMETER_SEQUENCING_SEGMENTING		0x08
#define PARAMETER_CREDIT			0x09
#define PARAMETER_RELEASE_CAUSE			0x0a
#define PARAMETER_RETURN_CAUSE			0x0b
#define PARAMETER_RESET_CAUSE			0x0c
#define PARAMETER_ERROR_CAUSE			0x0d
#define PARAMETER_REFUSAL_CAUSE			0x0e
#define PARAMETER_DATA				0x0f
#define PARAMETER_SEGMENTATION			0x10
#define PARAMETER_HOP_COUNTER			0x11
/* Importance is ITU only */
#define PARAMETER_IMPORTANCE			0x12
#define PARAMETER_LONG_DATA			0x13
/* ISNI is ANSI only */
#define PARAMETER_ISNI				0xfa

static const value_string sccp_parameter_values[] = {
  { PARAMETER_END_OF_OPTIONAL_PARAMETERS,	"End of Optional Parameters" },
  { PARAMETER_DESTINATION_LOCAL_REFERENCE,	"Destination Local Reference" },
  { PARAMETER_SOURCE_LOCAL_REFERENCE,		"Source Local Reference" },
  { PARAMETER_CALLED_PARTY_ADDRESS,		"Called Party Address" },
  { PARAMETER_CALLING_PARTY_ADDRESS,		"Calling Party Address" },
  { PARAMETER_CLASS,				"Protocol Class" },
  { PARAMETER_SEGMENTING_REASSEMBLING,		"Segmenting/Reassembling" },
  { PARAMETER_RECEIVE_SEQUENCE_NUMBER,		"Receive Sequence Number" },
  { PARAMETER_SEQUENCING_SEGMENTING,		"Sequencing/Segmenting" },
  { PARAMETER_CREDIT,				"Credit" },
  { PARAMETER_RELEASE_CAUSE,			"Release Cause" },
  { PARAMETER_RETURN_CAUSE,			"Return Cause" },
  { PARAMETER_RESET_CAUSE,			"Reset Cause" },
  { PARAMETER_ERROR_CAUSE,			"Error Cause" },
  { PARAMETER_REFUSAL_CAUSE,			"Refusal Cause" },
  { PARAMETER_DATA,				"Data" },
  { PARAMETER_SEGMENTATION,			"Segmentation" },
  { PARAMETER_HOP_COUNTER,			"Hop Counter" },
  { PARAMETER_IMPORTANCE,			"Importance (ITU)" },
  { PARAMETER_LONG_DATA,			"Long Data" },
  { PARAMETER_ISNI,				"Intermediate Signaling Network Identification (ANSI)" },
  { 0,						 NULL } };


#define END_OF_OPTIONAL_PARAMETERS_LENGTH	1
#define DESTINATION_LOCAL_REFERENCE_LENGTH	3
#define SOURCE_LOCAL_REFERENCE_LENGTH		3
#define PROTOCOL_CLASS_LENGTH			1
#define RECEIVE_SEQUENCE_NUMBER_LENGTH		1
#define CREDIT_LENGTH				1
#define RELEASE_CAUSE_LENGTH			1
#define RETURN_CAUSE_LENGTH			1
#define RESET_CAUSE_LENGTH			1
#define ERROR_CAUSE_LENGTH			1
#define REFUSAL_CAUSE_LENGTH			1
#define HOP_COUNTER_LENGTH			1
#define IMPORTANCE_LENGTH			1


/* Parts of the Called and Calling Address parameters */
/* Address Indicator */
#define ADDRESS_INDICATOR_LENGTH	1
#define ITU_RESERVED_MASK		0x80
#define ANSI_NATIONAL_MASK		0x80
#define ROUTING_INDICATOR_MASK		0x40
#define GTI_MASK			0x3C
#define GTI_SHIFT			2
#define ITU_SSN_INDICATOR_MASK		0x02
#define ITU_PC_INDICATOR_MASK		0x01
#define ANSI_PC_INDICATOR_MASK		0x02
#define ANSI_SSN_INDICATOR_MASK		0x01

static const value_string sccp_national_indicator_values[] = {
  { 0x0,  "Address coded to International standard" },
  { 0x1,  "Address coded to National standard" },
  { 0,    NULL } };

#define ROUTE_ON_GT		0x0
#define ROUTE_ON_SSN		0x1
#define ROUTING_INDICATOR_SHIFT	6
static const value_string sccp_routing_indicator_values[] = {
  { ROUTE_ON_GT,  "Route on GT" },
  { ROUTE_ON_SSN, "Route on SSN" },
  { 0,		  NULL } };

#define AI_GTI_NO_GT			0x0
#define ITU_AI_GTI_NAI			0x1
#define AI_GTI_TT			0x2
#define ITU_AI_GTI_TT_NP_ES		0x3
#define ITU_AI_GTI_TT_NP_ES_NAI	0x4
static const value_string sccp_itu_global_title_indicator_values[] = {
  { AI_GTI_NO_GT,		"No Global Title" },
  { ITU_AI_GTI_NAI,		"Nature of Address Indicator only" },
  { AI_GTI_TT,			"Translation Type only" },
  { ITU_AI_GTI_TT_NP_ES,	"Translation Type, Numbering Plan, and Encoding Scheme included" },
  { ITU_AI_GTI_TT_NP_ES_NAI,	"Translation Type, Numbering Plan, Encoding Scheme, and Nature of Address Indicator included" },
  { 0,				NULL } };

/* #define AI_GTI_NO_GT		0x0 */
#define ANSI_AI_GTI_TT_NP_ES	0x1
/* #define AI_GTI_TT		0x2 */
static const value_string sccp_ansi_global_title_indicator_values[] = {
  { AI_GTI_NO_GT,		"No Global Title" },
  { ANSI_AI_GTI_TT_NP_ES,	"Translation Type, Numbering Plan, and Encoding Scheme included" },
  { AI_GTI_TT,			"Translation Type only" },
  { 0,				NULL } };

static const value_string sccp_ai_pci_values[] = {
  { 0x1,  "Point Code present" },
  { 0x0,  "Point Code not present" },
  { 0,    NULL } };

static const value_string sccp_ai_ssni_values[] = {
  { 0x1,  "SSN present" },
  { 0x0,  "SSN not present" },
  { 0,    NULL } };

#define ADDRESS_SSN_LENGTH	1
#define INVALID_SSN		0xff
  /* Some values from 3GPP TS 23.003 */
  /*  Japan TTC and NTT define a lot of SSNs, some of which conflict with
   *  these.  They are not added for now.
   */
static const value_string sccp_ssn_values[] = {
  { 0x00,  "SSN not known/not used" },
  { 0x01,  "SCCP management" },
  { 0x02,  "Reserved for ITU-T allocation" },
  { 0x03,  "ISDN User Part" },
  { 0x04,  "OMAP (Operation, Maintenance, and Administration Part)" },
  { 0x05,  "MAP (Mobile Application Part)" },
  { 0x06,  "HLR (Home Location Register)" },
  { 0x07,  "VLR (Visitor Location Register)" },
  { 0x08,  "MSC (Mobile Switching Center)" },
  { 0x09,  "EIC/EIR (Equipment Identifier Center/Equipment Identification Register)" },
  { 0x0a,  "AUC/AC (Authentication Center)" },
  { 0x0b,  "ISDN supplementary services (ITU only)" },
  { 0x0c,  "Reserved for international use (ITU only)" },
  { 0x0d,  "Broadband ISDN edge-to-edge applications (ITU only)" },
  { 0x0e,  "TC test responder (ITU only)" },
  /* The following national network subsystem numbers have been allocated for use within and
   * between GSM/UMTS networks:
   */
  { 0x8e,  "RANAP" },
  { 0x8f,  "RNSAP" },
  { 0x91,  "GMLC(MAP)" },
  { 0x92,  "CAP" },
  { 0x93,  "gsmSCF (MAP) or IM-SSF (MAP) or Presence Network Agent" },
  { 0x94,  "SIWF (MAP)" },
  { 0x95,  "SGSN (MAP)" },
  { 0x96,  "GGSN (MAP)" },
  /* The following national network subsystem numbers have been allocated for use within GSM/UMTS networks:*/
  { 0xf9,  "PCAP" },
  { 0xfa,  "BSC (BSSAP-LE)" },
  { 0xfb,  "MSC (BSSAP-LE)" },
  { 0xfc,  "IOS or SMLC (BSSAP-LE)" },
  { 0xfd,  "BSS O&M (A interface)" },
  { 0xfe,  "BSSAP/BSAP" },
  { 0,     NULL } };


/* * * * * * * * * * * * * * * * *
 * Global Title: ITU GTI == 0001 *
 * * * * * * * * * * * * * * * * */
#define GT_NAI_MASK 0x7F
#define GT_NAI_LENGTH 1
#define GT_NAI_UNKNOWN			0x00
#define GT_NAI_SUBSCRIBER_NUMBER	0x01
#define GT_NAI_RESERVED_NATIONAL	0x02
#define GT_NAI_NATIONAL_SIG_NUM		0x03
#define GT_NAI_INTERNATIONAL_NUM	0x04
static const value_string sccp_nai_values[] = {
  { GT_NAI_UNKNOWN,		"NAI unknown" },
  { GT_NAI_SUBSCRIBER_NUMBER,	"Subscriber Number" },
  { GT_NAI_RESERVED_NATIONAL,	"Reserved for national use" },
  { GT_NAI_NATIONAL_SIG_NUM,	"National significant number" },
  { GT_NAI_INTERNATIONAL_NUM,	"International number" },
  { 0,				NULL } };


#define GT_OE_MASK 0x80
#define GT_OE_EVEN 0
#define GT_OE_ODD  1
static const value_string sccp_oe_values[] = {
  { GT_OE_EVEN,	"Even number of address signals" },
  { GT_OE_ODD,	"Odd number of address signals" },
  { 0,		NULL } };

const value_string sccp_address_signal_values[] = {
  { 0,  "0" },
  { 1,  "1" },
  { 2,  "2" },
  { 3,  "3" },
  { 4,  "4" },
  { 5,  "5" },
  { 6,  "6" },
  { 7,  "7" },
  { 8,  "8" },
  { 9,  "9" },
  { 10, "(spare)" },
  { 11, "11" },
  { 12, "12" },
  { 13, "(spare)" },
  { 14, "(spare)" },
  { 15, "ST" },
  { 0,  NULL } };


/* * * * * * * * * * * * * * * * * * * * *
 * Global Title: ITU and ANSI GTI == 0010 *
 * * * * * * * * * * * * * * * * * * * * */
#define GT_TT_LENGTH 1


/* * * * * * * * * * * * * * * * * * * * * * * * * *
 * Global Title: ITU GTI == 0011, ANSI GTI == 0001 *
 * * * * * * * * * * * * * * * * * * * * * * * * * */
#define GT_NP_MASK		0xf0
#define GT_NP_SHIFT		4
#define GT_NP_ES_LENGTH		1
#define GT_NP_UNKNOWN		0x00
#define GT_NP_ISDN		0x01
#define GT_NP_GENERIC_RESERVED	0x02
#define GT_NP_DATA		0x03
#define GT_NP_TELEX		0x04
#define GT_NP_MARITIME_MOBILE	0x05
#define GT_NP_LAND_MOBILE	0x06
#define GT_NP_ISDN_MOBILE	0x07
#define GT_NP_PRIVATE_NETWORK	0x0e
#define GT_NP_RESERVED		0x0f
static const value_string sccp_np_values[] = {
  { GT_NP_UNKNOWN,		"Unknown" },
  { GT_NP_ISDN,			"ISDN/telephony" },
  { GT_NP_GENERIC_RESERVED,	"Generic (ITU)/Reserved (ANSI)" },
  { GT_NP_DATA,			"Data" },
  { GT_NP_TELEX,		"Telex" },
  { GT_NP_MARITIME_MOBILE,	"Maritime mobile" },
  { GT_NP_LAND_MOBILE,		"Land mobile" },
  { GT_NP_ISDN_MOBILE,		"ISDN/mobile" },
  { GT_NP_PRIVATE_NETWORK,	"Private network or network-specific" },
  { GT_NP_RESERVED,		"Reserved" },
  { 0,				NULL } };

#define GT_ES_MASK     0x0f
#define GT_ES_UNKNOWN  0x0
#define GT_ES_BCD_ODD  0x1
#define GT_ES_BCD_EVEN 0x2
#define GT_ES_NATIONAL 0x3
#define GT_ES_RESERVED 0xf
static const value_string sccp_es_values[] = {
  { GT_ES_UNKNOWN,	"Unknown" },
  { GT_ES_BCD_ODD,	"BCD, odd number of digits" },
  { GT_ES_BCD_EVEN,	"BCD, even number of digits" },
  { GT_ES_NATIONAL,	"National specific" },
  { GT_ES_RESERVED,	"Reserved (ITU)/Spare (ANSI)" },
  { 0,			NULL } };

/* Address signals above */


/* * * * * * * * * * * * * * * * *
 * Global Title: ITU GTI == 0100 *
 * * * * * * * * * * * * * * * * */
/* NP above */
/* ES above */
/* NAI above */
/* Address signals above */


#define CLASS_CLASS_MASK		0xf
#define CLASS_SPARE_HANDLING_MASK	0xf0
#define CLASS_SPARE_HANDLING_SHIFT	4
static const value_string sccp_class_handling_values [] = {
  { 0x0,  "No special options" },
  { 0x8,  "Return message on error" },
  { 0,    NULL } };


#define SEGMENTING_REASSEMBLING_LENGTH 1
#define SEGMENTING_REASSEMBLING_MASK   0x01
#define NO_MORE_DATA 0
#define MORE_DATA    1
/* This is also used by sequencing-segmenting parameter */
static const value_string sccp_segmenting_reassembling_values [] = {
  { NO_MORE_DATA,	"No more data" },
  { MORE_DATA,		"More data" },
  { 0,			NULL } };


#define RECEIVE_SEQUENCE_NUMBER_LENGTH		1
#define RSN_MASK				0xfe

#define SEQUENCING_SEGMENTING_LENGTH		2
#define SEQUENCING_SEGMENTING_SSN_LENGTH	1
#define SEQUENCING_SEGMENTING_RSN_LENGTH	1
#define SEND_SEQUENCE_NUMBER_MASK		0xfe
#define RECEIVE_SEQUENCE_NUMBER_MASK		0xfe
#define SEQUENCING_SEGMENTING_MORE_MASK		0x01


#define CREDIT_LENGTH 1

#define RELEASE_CAUSE_LENGTH 1
const value_string sccp_release_cause_values [] = {
  { 0x00,  "End user originated" },
  { 0x01,  "End user congestion" },
  { 0x02,  "End user failure" },
  { 0x03,  "SCCP user originated" },
  { 0x04,  "Remote procedure error" },
  { 0x05,  "Inconsistent connection data" },
  { 0x06,  "Access failure" },
  { 0x07,  "Access congestion" },
  { 0x08,  "Subsystem failure" },
  { 0x09,  "Subsystem congestion" },
  { 0x0a,  "MTP failure" },
  { 0x0b,  "Network congestion" },
  { 0x0c,  "Expiration of reset timer" },
  { 0x0d,  "Expiration of receive inactivity timer" },
  { 0x0e,  "Reserved" },
  { 0x0f,  "Unqualified" },
  { 0x10,  "SCCP failure (ITU only)" },
  { 0,     NULL } };


#define RETURN_CAUSE_LENGTH 1
const value_string sccp_return_cause_values [] = {
  { 0x00,  "No translation for an address of such nature" },
  { 0x01,  "No translation for this specific address" },
  { 0x02,  "Subsystem congestion" },
  { 0x03,  "Subsystem failure" },
  { 0x04,  "Unequipped failure" },
  { 0x05,  "MTP failure" },
  { 0x06,  "Network congestion" },
  { 0x07,  "Unqualified" },
  { 0x08,  "Error in message transport" },
  { 0x09,  "Error in local processing" },
  { 0x0a,  "Destination cannot perform reassembly" },
  { 0x0b,  "SCCP failure" },
  { 0x0c,  "Hop counter violation" },
  { 0x0d,  "Segmentation not supported" },
  { 0x0e,  "Segmentation failure" },
  { 0xf7,  "Message change failure (ANSI only)" },
  { 0xf8,  "Invalid INS routing request (ANSI only)" },
  { 0xf9,  "Invalid ISNI routing request (ANSI only)"},
  { 0xfa,  "Unauthorized message (ANSI only)" },
  { 0xfb,  "Message incompatibility (ANSI only)" },
  { 0xfc,  "Cannot perform ISNI constrained routing (ANSI only)" },
  { 0xfd,  "Redundant ISNI constrained routing (ANSI only)" },
  { 0xfe,  "Unable to perform ISNI identification (ANSI only)" },
  { 0,     NULL } };


#define RESET_CAUSE_LENGTH 1
const value_string sccp_reset_cause_values [] = {
  { 0x00,  "End user originated" },
  { 0x01,  "SCCP user originated" },
  { 0x02,  "Message out of order - incorrect send sequence number" },
  { 0x03,  "Message out of order - incorrect receive sequence number" },
  { 0x04,  "Remote procedure error - message out of window" },
  { 0x05,  "Remote procedure error - incorrect send sequence number after (re)initialization" },
  { 0x06,  "Remote procedure error - general" },
  { 0x07,  "Remote end user operational" },
  { 0x08,  "Network operational" },
  { 0x09,  "Access operational" },
  { 0x0a,  "Network congestion" },
  { 0x0b,  "Reserved (ITU)/Not obtainable (ANSI)" },
  { 0x0c,  "Unqualified" },
  { 0,     NULL } };


#define ERROR_CAUSE_LENGTH 1
const value_string sccp_error_cause_values [] = {
  { 0x00,  "Local Reference Number (LRN) mismatch - unassigned destination LRN" },
  { 0x01,  "Local Reference Number (LRN) mismatch - inconsistent source LRN" },
  { 0x02,  "Point code mismatch" },
  { 0x03,  "Service class mismatch" },
  { 0x04,  "Unqualified" },
  { 0,     NULL } };


#define REFUSAL_CAUSE_LENGTH 1
const value_string sccp_refusal_cause_values [] = {
  { 0x00,  "End user originated" },
  { 0x01,  "End user congestion" },
  { 0x02,  "End user failure" },
  { 0x03,  "SCCP user originated" },
  { 0x04,  "Destination address unknown" },
  { 0x05,  "Destination inaccessible" },
  { 0x06,  "Network resource - QOS not available/non-transient" },
  { 0x07,  "Network resource - QOS not available/transient" },
  { 0x08,  "Access failure" },
  { 0x09,  "Access congestion" },
  { 0x0a,  "Subsystem failure" },
  { 0x0b,  "Subsystem congestion" },
  { 0x0c,  "Expiration of connection establishment timer" },
  { 0x0d,  "Incompatible user data" },
  { 0x0e,  "Reserved" },
  { 0x0f,  "Unqualified" },
  { 0x10,  "Hop counter violation" },
  { 0x11,  "SCCP failure (ITU only)" },
  { 0x12,  "No translation for an address of such nature" },
  { 0x13,  "Unequipped user" },
  { 0,     NULL } };


#define SEGMENTATION_LENGTH		4
#define SEGMENTATION_FIRST_SEGMENT_MASK	0x80
#define SEGMENTATION_CLASS_MASK		0x40
#define SEGMENTATION_SPARE_MASK		0x30
#define SEGMENTATION_REMAINING_MASK	0x0f
static const value_string sccp_segmentation_first_segment_values [] = {
  { 1,  "First segment" },
  { 0,  "Not first segment" },
  { 0,  NULL } };
static const value_string sccp_segmentation_class_values [] = {
  { 0,  "Class 0 selected" },
  { 1,  "Class 1 selected" },
  { 0,  NULL } };


#define HOP_COUNTER_LENGTH 1

#define IMPORTANCE_LENGTH		1
#define IMPORTANCE_IMPORTANCE_MASK	0x7


#define ANSI_ISNI_ROUTING_CONTROL_LENGTH 1
#define ANSI_ISNI_MI_MASK		 0x01
#define ANSI_ISNI_IRI_MASK		 0x06
#define ANSI_ISNI_RES_MASK		 0x08
#define ANSI_ISNI_TI_MASK		 0x10
#define ANSI_ISNI_TI_SHIFT		 4
#define ANSI_ISNI_COUNTER_MASK		 0xe0
#define ANSI_ISNI_NETSPEC_MASK		 0x03

static const value_string sccp_isni_mark_for_id_values [] = {
  { 0x0,  "Do not identify networks" },
  { 0x1,  "Identify networks" },
  { 0,    NULL } };

static const value_string sccp_isni_iri_values [] = {
  { 0x0,  "Neither constrained nor suggested ISNI routing" },
  { 0x1,  "Constrained ISNI routing" },
  { 0x2,  "Reserved for suggested ISNI routing" },
  { 0x3,  "Spare" },
  { 0,    NULL } };

#define ANSI_ISNI_TYPE_0 0x0
#define ANSI_ISNI_TYPE_1 0x1
static const value_string sccp_isni_ti_values [] = {
  { ANSI_ISNI_TYPE_0,	"Type zero ISNI parameter format" },
  { ANSI_ISNI_TYPE_1,	"Type one ISNI parameter format" },
  { 0,			NULL } };


/* Initialize the protocol and registered fields */
static int proto_sccp = -1;
static int hf_sccp_message_type = -1;
static int hf_sccp_variable_pointer1 = -1;
static int hf_sccp_variable_pointer2 = -1;
static int hf_sccp_variable_pointer3 = -1;
static int hf_sccp_optional_pointer = -1;
static int hf_sccp_param_length = -1;
static int hf_sccp_ssn = -1;
static int hf_sccp_gt_digits = -1;

/* Called Party address */
static int hf_sccp_called_national_indicator = -1;
static int hf_sccp_called_routing_indicator = -1;
static int hf_sccp_called_itu_global_title_indicator = -1;
static int hf_sccp_called_ansi_global_title_indicator = -1;
static int hf_sccp_called_itu_ssn_indicator = -1;
static int hf_sccp_called_itu_point_code_indicator = -1;
static int hf_sccp_called_ansi_ssn_indicator = -1;
static int hf_sccp_called_ansi_point_code_indicator = -1;
static int hf_sccp_called_ssn = -1;
static int hf_sccp_called_pc_member = -1;
static int hf_sccp_called_pc_cluster = -1;
static int hf_sccp_called_pc_network = -1;
static int hf_sccp_called_ansi_pc = -1;
static int hf_sccp_called_chinese_pc = -1;
static int hf_sccp_called_itu_pc = -1;
static int hf_sccp_called_japan_pc = -1;
static int hf_sccp_called_gt_nai = -1;
static int hf_sccp_called_gt_oe = -1;
static int hf_sccp_called_gt_tt = -1;
static int hf_sccp_called_gt_np = -1;
static int hf_sccp_called_gt_es = -1;
static int hf_sccp_called_gt_digits = -1;
static int hf_sccp_called_gt_digits_length = -1;

/* Calling party address */
static int hf_sccp_calling_national_indicator = -1;
static int hf_sccp_calling_routing_indicator = -1;
static int hf_sccp_calling_itu_global_title_indicator = -1;
static int hf_sccp_calling_ansi_global_title_indicator = -1;
static int hf_sccp_calling_itu_ssn_indicator = -1;
static int hf_sccp_calling_itu_point_code_indicator = -1;
static int hf_sccp_calling_ansi_ssn_indicator = -1;
static int hf_sccp_calling_ansi_point_code_indicator = -1;
static int hf_sccp_calling_ssn = -1;
static int hf_sccp_calling_pc_member = -1;
static int hf_sccp_calling_pc_cluster = -1;
static int hf_sccp_calling_pc_network = -1;
static int hf_sccp_calling_ansi_pc = -1;
static int hf_sccp_calling_chinese_pc = -1;
static int hf_sccp_calling_itu_pc = -1;
static int hf_sccp_calling_japan_pc = -1;
static int hf_sccp_calling_gt_nai = -1;
static int hf_sccp_calling_gt_oe = -1;
static int hf_sccp_calling_gt_tt = -1;
static int hf_sccp_calling_gt_np = -1;
static int hf_sccp_calling_gt_es = -1;
static int hf_sccp_calling_gt_digits = -1;
static int hf_sccp_calling_gt_digits_length = -1;

/* Other parameter values */
static int hf_sccp_dlr = -1;
static int hf_sccp_slr = -1;
static int hf_sccp_lr = -1;
static int hf_sccp_class = -1;
static int hf_sccp_handling = -1;
static int hf_sccp_more = -1;
static int hf_sccp_rsn = -1;
static int hf_sccp_sequencing_segmenting_ssn = -1;
static int hf_sccp_sequencing_segmenting_rsn = -1;
static int hf_sccp_sequencing_segmenting_more = -1;
static int hf_sccp_credit = -1;
static int hf_sccp_release_cause = -1;
static int hf_sccp_return_cause = -1;
static int hf_sccp_reset_cause = -1;
static int hf_sccp_error_cause = -1;
static int hf_sccp_refusal_cause = -1;
static int hf_sccp_segmentation_first = -1;
static int hf_sccp_segmentation_class = -1;
static int hf_sccp_segmentation_remaining = -1;
static int hf_sccp_segmentation_slr = -1;
static int hf_sccp_hop_counter = -1;
static int hf_sccp_importance = -1;
static int hf_sccp_ansi_isni_mi = -1;
static int hf_sccp_ansi_isni_iri = -1;
static int hf_sccp_ansi_isni_ti = -1;
static int hf_sccp_ansi_isni_netspec = -1;
static int hf_sccp_ansi_isni_counter = -1;
static int hf_sccp_ansi_isni_network = -1;
static int hf_sccp_ansi_isni_cluster = -1;
static int hf_sccp_xudt_msg_fragments = -1;
static int hf_sccp_xudt_msg_fragment = -1;
static int hf_sccp_xudt_msg_fragment_overlap = -1;
static int hf_sccp_xudt_msg_fragment_overlap_conflicts = -1;
static int hf_sccp_xudt_msg_fragment_multiple_tails = -1;
static int hf_sccp_xudt_msg_fragment_too_long_fragment = -1;
static int hf_sccp_xudt_msg_fragment_error = -1;
static int hf_sccp_xudt_msg_fragment_count = -1;
static int hf_sccp_xudt_msg_reassembled_in = -1;
static int hf_sccp_xudt_msg_reassembled_length = -1;
static int hf_sccp_assoc_msg = -1;
static int hf_sccp_assoc_id = -1;

/* Initialize the subtree pointers */
static gint ett_sccp = -1;
static gint ett_sccp_called = -1;
static gint ett_sccp_called_ai = -1;
static gint ett_sccp_called_pc = -1;
static gint ett_sccp_called_gt = -1;
static gint ett_sccp_called_gt_digits = -1;
static gint ett_sccp_calling = -1;
static gint ett_sccp_calling_ai = -1;
static gint ett_sccp_calling_pc = -1;
static gint ett_sccp_calling_gt = -1;
static gint ett_sccp_calling_gt_digits = -1;
static gint ett_sccp_sequencing_segmenting = -1;
static gint ett_sccp_segmentation = -1;
static gint ett_sccp_ansi_isni_routing_control = -1;
static gint ett_sccp_xudt_msg_fragment = -1;
static gint ett_sccp_xudt_msg_fragments = -1;
static gint ett_sccp_assoc = -1;

/* Declarations to desegment XUDT Messages */
static gboolean sccp_xudt_desegment = TRUE;
static gboolean show_key_params = FALSE;
static gboolean set_addresses = FALSE;

static int sccp_tap = -1;


static const fragment_items sccp_xudt_msg_frag_items = {
	/* Fragment subtrees */
	&ett_sccp_xudt_msg_fragment,
	&ett_sccp_xudt_msg_fragments,
	/* Fragment fields */
	&hf_sccp_xudt_msg_fragments,
	&hf_sccp_xudt_msg_fragment,
	&hf_sccp_xudt_msg_fragment_overlap,
	&hf_sccp_xudt_msg_fragment_overlap_conflicts,
	&hf_sccp_xudt_msg_fragment_multiple_tails,
	&hf_sccp_xudt_msg_fragment_too_long_fragment,
	&hf_sccp_xudt_msg_fragment_error,
	&hf_sccp_xudt_msg_fragment_count,
	/* Reassembled in field */
	&hf_sccp_xudt_msg_reassembled_in,
	/* Reassembled length field */
	&hf_sccp_xudt_msg_reassembled_length,
	/* Tag */
	"SCCP XUDT Message fragments"
};

static GHashTable *sccp_xudt_msg_fragment_table = NULL;
static GHashTable *sccp_xudt_msg_reassembled_table = NULL;


#define SCCP_USER_DATA 0
#define SCCP_USER_TCAP 1
#define SCCP_USER_RANAP 2
#define SCCP_USER_BSSAP 3
#define SCCP_USER_GSMMAP 4
#define SCCP_USER_CAMEL 5
#define SCCP_USER_INAP 6

typedef struct _sccp_user_t {
	guint ni;
	range_t* called_pc;
	range_t* called_ssn;
	guint user;
	gboolean uses_tcap;
	dissector_handle_t* handlep;
} sccp_user_t;

static sccp_user_t* sccp_users;
static guint num_sccp_users;

static dissector_handle_t data_handle;
static dissector_handle_t tcap_handle;
static dissector_handle_t ranap_handle;
static dissector_handle_t bssap_handle;
static dissector_handle_t gsmmap_handle;
static dissector_handle_t camel_handle;
static dissector_handle_t inap_handle;
static dissector_handle_t default_handle;

static const char *default_payload=NULL;

static const value_string sccp_users_vals[] = {
	{ SCCP_USER_DATA,	"Data"},
	{ SCCP_USER_TCAP,	"TCAP"},
	{ SCCP_USER_RANAP,	"RANAP"},
	{ SCCP_USER_BSSAP,	"BSSAP"},
	{ SCCP_USER_GSMMAP,	"GSM MAP"},
	{ SCCP_USER_CAMEL,	"CAMEL"},
	{ SCCP_USER_INAP,	"INAP"},
	{ 0, NULL }
};

/*
 * Here are the global variables associated with
 * the various user definable characteristics of the dissection
 */
static guint32 sccp_source_pc_global = 0;
static gboolean sccp_show_length = FALSE;

static module_t *sccp_module;
static heur_dissector_list_t heur_subdissector_list;

/*  Keep track of SSN value of current message so if/when we get to the data
 *  parameter, we can call appropriate sub-dissector.  TODO: can this info
 *  be stored elsewhere?
 */

static guint8 message_type = 0;
static guint dlr = 0;
static guint slr = 0;

static dissector_table_t sccp_ssn_dissector_table;

static emem_tree_t* assocs = NULL;
static sccp_assoc_info_t* assoc;
static sccp_msg_info_t* sccp_msg;
static sccp_assoc_info_t no_assoc = {0,0,0,0,0,FALSE,FALSE,NULL,NULL,SCCP_PLOAD_NONE,NULL,NULL,NULL,0};
static gboolean trace_sccp = FALSE;
static guint32 next_assoc_id = 0;

static const value_string assoc_protos[] = {
	{ SCCP_PLOAD_BSSAP,	"BSSAP" },
	{ SCCP_PLOAD_RANAP,	"RANAP" },
	{ 0,			NULL }
};

static sccp_assoc_info_t *
new_assoc(guint32 calling, guint32 called)
{
	sccp_assoc_info_t* a = se_alloc0(sizeof(sccp_assoc_info_t));

	a->id = next_assoc_id++;
	a->calling_dpc = calling;
	a->called_dpc = called;
	a->calling_ssn = INVALID_SSN;
	a->called_ssn = INVALID_SSN;
	a->msgs = NULL;
	a->curr_msg = NULL;
	a->payload = SCCP_PLOAD_NONE;
	a->calling_party = NULL;
	a->called_party = NULL;
	a->extra_info = NULL;

	return a;
}

void
reset_sccp_assoc(void)
{
	assoc = NULL;
}

sccp_assoc_info_t *
get_sccp_assoc(packet_info* pinfo, guint offset, guint32 src_lr, guint32 dst_lr, guint msg_type)
{
    guint32 opck, dpck;
    address* opc = &(pinfo->src);
    address* dpc = &(pinfo->dst);
    guint framenum = pinfo->fd->num;

    if(assoc)
        return assoc;

    opck = opc->type == AT_SS7PC ? mtp3_pc_hash((const mtp3_addr_pc_t *)opc->data) : g_str_hash(ep_address_to_str(opc));
    dpck = dpc->type == AT_SS7PC ? mtp3_pc_hash((const mtp3_addr_pc_t *)dpc->data) : g_str_hash(ep_address_to_str(dpc));


    switch (msg_type) {
        case SCCP_MSG_TYPE_CR:
        {
            /* CR contains the opc,dpc,dlr key of backward messages swapped as dpc,opc,slr  */
            emem_tree_key_t bw_key[] = {
                {1, &dpck}, 
		{1, &opck}, 
		{1, &src_lr}, 
		{0, NULL}
            };

            if (! ( assoc = se_tree_lookup32_array(assocs,bw_key) ) && ! pinfo->fd->flags.visited ) {
                assoc = new_assoc(opck, dpck);
                se_tree_insert32_array(assocs, bw_key, assoc);
                assoc->has_bw_key = TRUE;
            }

            pinfo->p2p_dir = P2P_DIR_SENT;

            break;
        }
        case SCCP_MSG_TYPE_CC:
        {
            emem_tree_key_t fw_key[] = {
                {1, &dpck}, {1, &opck}, {1, &src_lr}, {0, NULL}
            };
            emem_tree_key_t bw_key[] = {
                {1, &opck}, {1, &dpck}, {1, &dst_lr}, {0, NULL}
            };

            if ( ( assoc = se_tree_lookup32_array(assocs, bw_key) ) ) {
                goto got_assoc;
            }

            if ( (assoc = se_tree_lookup32_array(assocs, fw_key) ) ) {
                goto got_assoc;
            }

            assoc = new_assoc(dpck,opck);

     got_assoc:

            pinfo->p2p_dir = P2P_DIR_RECV;

            if ( ! pinfo->fd->flags.visited && ! assoc->has_bw_key ) {
                se_tree_insert32_array(assocs, bw_key, assoc);
                assoc->has_bw_key = TRUE;
            }

            if ( ! pinfo->fd->flags.visited && ! assoc->has_fw_key ) {
                se_tree_insert32_array(assocs, fw_key, assoc);
                assoc->has_fw_key = TRUE;
            }

            break;
        }
        case SCCP_MSG_TYPE_RLC:
        {
            emem_tree_key_t bw_key[] = {
                {1, &dpck}, {1, &opck}, {1, &src_lr}, {0, NULL}
            };
            emem_tree_key_t fw_key[] = {
                {1, &opck}, {1, &dpck}, {1, &dst_lr}, {0, NULL}
            };
            if ( ( assoc = se_tree_lookup32_array(assocs, bw_key) ) ) {
                goto got_assoc_rlc;
            }

            if ( (assoc = se_tree_lookup32_array(assocs, fw_key) ) ) {
                goto got_assoc_rlc;
            }

            assoc = new_assoc(dpck, opck);

     got_assoc_rlc:

            pinfo->p2p_dir = P2P_DIR_SENT;

            if ( ! pinfo->fd->flags.visited && ! assoc->has_bw_key ) {
                se_tree_insert32_array(assocs, bw_key, assoc);
                assoc->has_bw_key = TRUE;
            }

            if ( ! pinfo->fd->flags.visited && ! assoc->has_fw_key ) {
                se_tree_insert32_array(assocs, fw_key, assoc);
                assoc->has_fw_key = TRUE;
            }
            break;
        }
        default:
        {
            emem_tree_key_t key[] = {
                {1, &opck}, {1, &dpck}, {1, &dst_lr}, {0, NULL}
            };

            assoc = se_tree_lookup32_array(assocs, key);

            if (assoc) {
                if (assoc->calling_dpc == dpck) {
                    pinfo->p2p_dir = P2P_DIR_RECV;
                } else {
                    pinfo->p2p_dir = P2P_DIR_SENT;
                }
            }

            break;
        }
    }

    if (assoc && trace_sccp) {
        if ( ! pinfo->fd->flags.visited) {
            sccp_msg_info_t* msg = se_alloc0(sizeof(sccp_msg_info_t));
            msg->framenum = framenum;
            msg->offset = offset;
            msg->data.co.next = NULL;
            msg->data.co.assoc = assoc;
            msg->data.co.label = NULL;
            msg->data.co.comment = NULL;
            msg->type = msg_type;

            if (assoc->msgs) {
                sccp_msg_info_t* m;
                for (m = assoc->msgs; m->data.co.next; m = m->data.co.next) ;
                m->data.co.next = msg;
            } else {
                assoc->msgs = msg;
            }

            assoc->curr_msg = msg;

        } else {

            sccp_msg_info_t* m;

            for (m = assoc->msgs; m; m = m->data.co.next) {
                if (m->framenum == framenum && m->offset == offset) {
                    assoc->curr_msg = m;
                    break;
                }
            }
        }
    }

    return assoc ? assoc : &no_assoc;
}


static void
dissect_sccp_unknown_message(tvbuff_t *message_tvb, proto_tree *sccp_tree)
{
  guint32 message_length;

  message_length = tvb_length(message_tvb);

  proto_tree_add_text(sccp_tree, message_tvb, 0, message_length,
                      "Unknown message (%u byte%s)",
                      message_length, plurality(message_length, "", "s"));
}

static void
dissect_sccp_unknown_param(tvbuff_t *tvb, proto_tree *tree, guint8 type, guint length)
{
  proto_tree_add_text(tree, tvb, 0, length, "Unknown parameter 0x%x (%u byte%s)",
                      type, length, plurality(length, "", "s"));
}

static void
dissect_sccp_dlr_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  proto_item *lr_item, *expert_item;

  if (length != 3) {
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 3, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 3, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  dlr = tvb_get_letoh24(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_dlr, tvb, 0, length, dlr);
  lr_item = proto_tree_add_uint(tree, hf_sccp_lr, tvb, 0, length, dlr);
  PROTO_ITEM_SET_HIDDEN(lr_item);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "DLR=%d ", dlr);
}

static void
dissect_sccp_slr_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  proto_item *lr_item, *expert_item;

  if (length != 3) {
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 3, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 3, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  slr = tvb_get_letoh24(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_slr, tvb, 0, length, slr);
  lr_item = proto_tree_add_uint(tree, hf_sccp_lr, tvb, 0, length, slr);
  PROTO_ITEM_SET_HIDDEN(lr_item);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "SLR=%d ", slr);
}


#define is_connectionless(m) \
         ( m == SCCP_MSG_TYPE_UDT || m == SCCP_MSG_TYPE_UDTS  \
        || m == SCCP_MSG_TYPE_XUDT|| m == SCCP_MSG_TYPE_XUDTS \
        || m == SCCP_MSG_TYPE_LUDT|| m == SCCP_MSG_TYPE_LUDTS)

static proto_tree *
dissect_sccp_gt_address_information(tvbuff_t *tvb, packet_info *pinfo,
				    proto_tree *tree, guint length,
				    gboolean even_length, gboolean called,
				    gboolean route_on_gt)
{
  guint offset = 0;
  guint8 odd_signal, even_signal;
  proto_item *digits_item;
  proto_tree *digits_tree;
  char *gt_digits;

  gt_digits = ep_alloc0(GT_MAX_SIGNALS+1);

  while(offset < length) {
    odd_signal = tvb_get_guint8(tvb, offset) & GT_ODD_SIGNAL_MASK;
    even_signal = tvb_get_guint8(tvb, offset) & GT_EVEN_SIGNAL_MASK;
    even_signal >>= GT_EVEN_SIGNAL_SHIFT;

    g_strlcat(gt_digits, val_to_str(odd_signal, sccp_address_signal_values,
				 "Unknown: %d"), GT_MAX_SIGNALS+1);

    /* If the last signal is NOT filler */
    if (offset != (length - 1) || even_length == TRUE)
      g_strlcat(gt_digits, val_to_str(even_signal, sccp_address_signal_values,
				   "Unknown: %d"), GT_MAX_SIGNALS+1);

    offset += GT_SIGNAL_LENGTH;
  }

  if (is_connectionless(message_type) && sccp_msg) {
	guint8** gt_ptr = called ? &(sccp_msg->data.ud.called_gt) : &(sccp_msg->data.ud.calling_gt);

	*gt_ptr  = (guint8 *)ep_strdup(gt_digits);
  }

  digits_item = proto_tree_add_string(tree, called ? hf_sccp_called_gt_digits
						   : hf_sccp_calling_gt_digits,
				      tvb, 0, length, gt_digits);
  digits_tree = proto_item_add_subtree(digits_item, called ? ett_sccp_called_gt_digits
							   : ett_sccp_calling_gt_digits);

  if (set_addresses && route_on_gt) {
    if (called) {
      SET_ADDRESS(&pinfo->dst, AT_STRINGZ, 1+(int)strlen(gt_digits), gt_digits);
    } else {
      SET_ADDRESS(&pinfo->src, AT_STRINGZ, 1+(int)strlen(gt_digits), gt_digits);
    }
  }

  proto_tree_add_string(digits_tree, hf_sccp_gt_digits, tvb, 0, length, gt_digits);
  proto_tree_add_uint(digits_tree, called ? hf_sccp_called_gt_digits_length
					  : hf_sccp_calling_gt_digits_length,
		      tvb, 0, length, (guint32)strlen(gt_digits));

  return digits_tree;
}

static void
dissect_sccp_global_title(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length,
			  guint8 gti, gboolean route_on_gt, gboolean called)
{
  proto_item *gt_item;
  proto_tree *gt_tree;
  proto_tree *digits_tree;
  tvbuff_t *signals_tvb;
  guint offset = 0;
  guint8 odd_even, nai = 0, np = 0, es;
  gboolean even = TRUE;

  /* Shift GTI to where we can work with it */
  gti >>= GTI_SHIFT;

  gt_item = proto_tree_add_text(tree, tvb, offset, length,
				"Global Title 0x%x (%u byte%s)",
				gti, length, plurality(length,"", "s"));
  gt_tree = proto_item_add_subtree(gt_item, called ? ett_sccp_called_gt
						   : ett_sccp_calling_gt);

  /* Decode Transation Type (if present) */
  if ((gti == AI_GTI_TT) ||
      (decode_mtp3_standard != ANSI_STANDARD &&
	  (gti == ITU_AI_GTI_TT_NP_ES || gti == ITU_AI_GTI_TT_NP_ES_NAI)) ||
      (decode_mtp3_standard == ANSI_STANDARD && gti == ANSI_AI_GTI_TT_NP_ES)) {

    proto_tree_add_item(gt_tree, called ? hf_sccp_called_gt_tt
					: hf_sccp_calling_gt_tt,
			tvb, offset, GT_TT_LENGTH, ENC_NA);
    offset += GT_TT_LENGTH;
  }

  if (gti == AI_GTI_TT) {
    /* Protocol doesn't tell us, so we ASSUME even... */
    even = TRUE;
  }

  /* Decode Numbering Plan and Encoding Scheme (if present) */
  if ((decode_mtp3_standard != ANSI_STANDARD &&
       (gti == ITU_AI_GTI_TT_NP_ES || gti == ITU_AI_GTI_TT_NP_ES_NAI)) ||
      (decode_mtp3_standard == ANSI_STANDARD && gti == ANSI_AI_GTI_TT_NP_ES)) {

    np = tvb_get_guint8(tvb, offset) & GT_NP_MASK;
    proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_np
					: hf_sccp_calling_gt_np,
			tvb, offset, GT_NP_ES_LENGTH, np);

    es = tvb_get_guint8(tvb, offset) & GT_ES_MASK;
    proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_es
					: hf_sccp_calling_gt_es,
			tvb, offset, GT_NP_ES_LENGTH, es);

    even = (es == GT_ES_BCD_EVEN) ? TRUE : FALSE;

    offset += GT_NP_ES_LENGTH;
  }

  /* Decode Nature of Address Indicator (if present) */
  if (decode_mtp3_standard != ANSI_STANDARD &&
      (gti == ITU_AI_GTI_NAI || gti == ITU_AI_GTI_TT_NP_ES_NAI)) {

    /* Decode Odd/Even Indicator (if present) */
    if (gti == ITU_AI_GTI_NAI) {
      odd_even = tvb_get_guint8(tvb, offset) & GT_OE_MASK;
      proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_oe
					  : hf_sccp_calling_gt_oe,
			  tvb, offset, GT_NAI_LENGTH, odd_even);
      even = (odd_even == GT_OE_EVEN) ? TRUE : FALSE;
    }

    nai = tvb_get_guint8(tvb, offset) & GT_NAI_MASK;
    proto_tree_add_uint(gt_tree, called ? hf_sccp_called_gt_nai
					: hf_sccp_calling_gt_nai,
			tvb, offset, GT_NAI_LENGTH, nai);

    offset += GT_NAI_LENGTH;
  }

  /* Decode address signal(s) */
  if (length < offset)
    return;

  signals_tvb = tvb_new_subset(tvb, offset, (length - offset),
			       (length - offset));

  digits_tree = dissect_sccp_gt_address_information(signals_tvb, pinfo, gt_tree,
						    (length - offset),
						    even, called, route_on_gt);

  /* Display the country code (if we can) */
  switch(np >> GT_NP_SHIFT) {
	case GT_NP_ISDN:
	case GT_NP_ISDN_MOBILE:
		if(nai == GT_NAI_INTERNATIONAL_NUM) {
			dissect_e164_cc(signals_tvb, digits_tree, 0, TRUE);
		}
	break;
	case GT_NP_LAND_MOBILE:
		dissect_e212_mcc_mnc_in_address(signals_tvb, pinfo, digits_tree, 0);
	break;
	default:
	break;
  }
}

static int
dissect_sccp_3byte_pc(tvbuff_t *tvb, proto_tree *call_tree, guint offset,
		      gboolean called)
{
  int hf_pc;

  if (decode_mtp3_standard == ANSI_STANDARD)
  {
    if (called)
      hf_pc = hf_sccp_called_ansi_pc;
    else
      hf_pc = hf_sccp_calling_ansi_pc;
  } else /* CHINESE_ITU_STANDARD */ {
    if (called)
      hf_pc = hf_sccp_called_chinese_pc;
    else
      hf_pc = hf_sccp_calling_chinese_pc;
  }

  /* create and fill the PC tree */
  dissect_mtp3_3byte_pc(tvb, offset, call_tree,
			called ? ett_sccp_called_pc : ett_sccp_calling_pc,
			hf_pc,
			called ? hf_sccp_called_pc_network : hf_sccp_calling_pc_network,
			called ? hf_sccp_called_pc_cluster : hf_sccp_calling_pc_cluster,
			called ? hf_sccp_called_pc_member  : hf_sccp_calling_pc_member,
			0, 0);

  return(offset + ANSI_PC_LENGTH);
}

/*  FUNCTION dissect_sccp_called_calling_param():
 *  Dissect the Calling or Called Party Address parameters.
 *
 *  The boolean 'called' describes whether this function is decoding a
 *  called (TRUE) or calling (FALSE) party address.  There is simply too
 *  much code in this function to have 2 copies of it (one for called, one
 *  for calling).
 *
 *  NOTE:  this function is called even when (!tree) so that we can get
 *  the SSN and subsequently call subdissectors (if and when there's a data
 *  parameter).  Realistically we should put if (!tree)'s around a lot of the
 *  code, but I think that would make it unreadable--and the expense of not
 *  doing so does not appear to be very high.
 */
static void
dissect_sccp_called_calling_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
				  guint length, gboolean called)
{
  proto_item *call_item = 0, *call_ai_item = 0, *item, *hidden_item, *expert_item;
  proto_tree *call_tree = 0, *call_ai_tree = 0;
  guint offset;
  guint8 national = 0xFFU, routing_ind, gti, pci, ssni, ssn;
  tvbuff_t *gt_tvb;
  dissector_handle_t ssn_dissector = NULL, tcap_ssn_dissector = NULL;
  const char *ssn_dissector_short_name = NULL;
  const char *tcap_ssn_dissector_short_name = NULL;

  call_item = proto_tree_add_text(tree, tvb, 0, length,
				  "%s Party address (%u byte%s)",
				  called ? "Called" : "Calling", length,
				  plurality(length, "", "s"));
  call_tree = proto_item_add_subtree(call_item, called ? ett_sccp_called
						       : ett_sccp_calling);

  call_ai_item = proto_tree_add_text(call_tree, tvb, 0,
				     ADDRESS_INDICATOR_LENGTH,
				     "Address Indicator");
  call_ai_tree = proto_item_add_subtree(call_ai_item, called ? ett_sccp_called_ai
							     : ett_sccp_calling_ai);

  if (decode_mtp3_standard == ANSI_STANDARD)
  {
    national = tvb_get_guint8(tvb, 0) & ANSI_NATIONAL_MASK;
    expert_item = proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_national_indicator
							   : hf_sccp_calling_national_indicator,
				      tvb, 0, ADDRESS_INDICATOR_LENGTH, national);
    if (national == 0)
          expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_WARN, "Address is coded to "
				 "international standards.  This doesn't normally happen in ANSI "
				 "networks.");
  }

  routing_ind = tvb_get_guint8(tvb, 0) & ROUTING_INDICATOR_MASK;
  proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_routing_indicator
					   : hf_sccp_calling_routing_indicator,
		      tvb, 0, ADDRESS_INDICATOR_LENGTH, routing_ind);
  /* Only shift off the other bits after adding the item */
  routing_ind >>= ROUTING_INDICATOR_SHIFT;

  gti = tvb_get_guint8(tvb, 0) & GTI_MASK;

  if (decode_mtp3_standard == ITU_STANDARD ||
      decode_mtp3_standard == CHINESE_ITU_STANDARD ||
      decode_mtp3_standard == JAPAN_STANDARD ||
      national == 0) {

    proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_itu_global_title_indicator
					     : hf_sccp_calling_itu_global_title_indicator,
			tvb, 0, ADDRESS_INDICATOR_LENGTH, gti);

    ssni = tvb_get_guint8(tvb, 0) & ITU_SSN_INDICATOR_MASK;
    expert_item = proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_itu_ssn_indicator
							   : hf_sccp_calling_itu_ssn_indicator,
				      tvb, 0, ADDRESS_INDICATOR_LENGTH, ssni);
    if (routing_ind == ROUTE_ON_SSN && ssni == 0) {
      expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_WARN,
			     "Message is routed on SSN, but SSN is not present");
    }

    pci = tvb_get_guint8(tvb, 0) & ITU_PC_INDICATOR_MASK;
    proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_itu_point_code_indicator
					     : hf_sccp_calling_itu_point_code_indicator,
			tvb, 0, ADDRESS_INDICATOR_LENGTH, pci);

    offset = ADDRESS_INDICATOR_LENGTH;

    /* Dissect PC (if present) */
    if (pci) {
      if (decode_mtp3_standard == ITU_STANDARD || national == 0) {
        if (length < offset + ITU_PC_LENGTH){
          expert_item = proto_tree_add_text(call_tree, tvb, 0, -1, "Wrong length indicated (%u) should be at least %u, PC is %u octets", length, offset + ITU_PC_LENGTH, ITU_PC_LENGTH);
          expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated");
          PROTO_ITEM_SET_GENERATED(expert_item);
          return;
        }
        proto_tree_add_item(call_tree, called ? hf_sccp_called_itu_pc
                                              : hf_sccp_calling_itu_pc,
                            tvb, offset, ITU_PC_LENGTH, TRUE);
        offset += ITU_PC_LENGTH;

      } else if (decode_mtp3_standard == JAPAN_STANDARD) {

        if (length < offset + JAPAN_PC_LENGTH){
          expert_item = proto_tree_add_text(call_tree, tvb, 0, -1, "Wrong length indicated (%u) should be at least %u, PC is %u octets", length, offset + JAPAN_PC_LENGTH, JAPAN_PC_LENGTH);
          expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated");
          PROTO_ITEM_SET_GENERATED(expert_item);
          return;
        }
        proto_tree_add_item(call_tree, called ? hf_sccp_called_japan_pc
                                              : hf_sccp_calling_japan_pc,
                            tvb, offset, JAPAN_PC_LENGTH, TRUE);

        offset += JAPAN_PC_LENGTH;

      } else /* CHINESE_ITU_STANDARD */ {

        if (length < offset + ANSI_PC_LENGTH){
          expert_item = proto_tree_add_text(call_tree, tvb, 0, -1, "Wrong length indicated (%u) should be at least %u, PC is %u octets", length, offset + ANSI_PC_LENGTH, ANSI_PC_LENGTH);
          expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated");
          PROTO_ITEM_SET_GENERATED(expert_item);
           return;
        }
        offset = dissect_sccp_3byte_pc(tvb, call_tree, offset, called);

      }
    }

    /* Dissect SSN (if present) */
    if (ssni) {
      ssn = tvb_get_guint8(tvb, offset);

      if (routing_ind == ROUTE_ON_SSN && ssn == 0) {
	expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_WARN,
			       "Message is routed on SSN, but SSN is zero (unspecified)");
      }

      if (called && assoc)
	assoc->called_ssn = ssn;
      else if (assoc)
	assoc->calling_ssn = ssn;

      if (is_connectionless(message_type) && sccp_msg) {
	guint *ssn_ptr = called ? &(sccp_msg->data.ud.called_ssn) : &(sccp_msg->data.ud.calling_ssn);

	*ssn_ptr  = ssn;
      }

      proto_tree_add_uint(call_tree, called ? hf_sccp_called_ssn
					    : hf_sccp_calling_ssn,
			  tvb, offset, ADDRESS_SSN_LENGTH, ssn);
      hidden_item = proto_tree_add_uint(call_tree, hf_sccp_ssn, tvb, offset,
					ADDRESS_SSN_LENGTH, ssn);
      PROTO_ITEM_SET_HIDDEN(hidden_item);

      offset += ADDRESS_SSN_LENGTH;

      /* Get the dissector handle of the dissector registered for this ssn
       * And print it's name.
       */
      ssn_dissector = dissector_get_uint_handle(sccp_ssn_dissector_table, ssn);

      if (ssn_dissector) {
	ssn_dissector_short_name = dissector_handle_get_short_name(ssn_dissector);

	if(ssn_dissector_short_name) {
	  item = proto_tree_add_text(call_tree, tvb, offset - 1, ADDRESS_SSN_LENGTH, "Linked to %s", ssn_dissector_short_name);
	  PROTO_ITEM_SET_GENERATED(item);

	  if (g_ascii_strncasecmp("TCAP", ssn_dissector_short_name, 4)== 0) {
	    tcap_ssn_dissector = get_itu_tcap_subdissector(ssn);

	    if(tcap_ssn_dissector) {
	      tcap_ssn_dissector_short_name = dissector_handle_get_short_name(tcap_ssn_dissector);
	      proto_item_append_text(item,", TCAP SSN linked to %s", tcap_ssn_dissector_short_name);
	    }
	  }
	} /* short name */
      } /* ssn_dissector */
    } /* ssni */

    /* Dissect GT (if present) */
    if (gti != AI_GTI_NO_GT) {
      if (length < offset)
	return;

      gt_tvb = tvb_new_subset(tvb, offset, (length - offset),
			      (length - offset));
      dissect_sccp_global_title(gt_tvb, pinfo, call_tree, (length - offset), gti,
				(routing_ind == ROUTE_ON_GT), called);
    }

  } else if (decode_mtp3_standard == ANSI_STANDARD) {

    proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_global_title_indicator
					     : hf_sccp_calling_ansi_global_title_indicator,
			tvb, 0, ADDRESS_INDICATOR_LENGTH, gti);

    pci = tvb_get_guint8(tvb, 0) & ANSI_PC_INDICATOR_MASK;
    proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_point_code_indicator
					     : hf_sccp_calling_ansi_point_code_indicator,
			tvb, 0, ADDRESS_INDICATOR_LENGTH, pci);

    ssni = tvb_get_guint8(tvb, 0) & ANSI_SSN_INDICATOR_MASK;
    expert_item = proto_tree_add_uint(call_ai_tree, called ? hf_sccp_called_ansi_ssn_indicator
							   : hf_sccp_calling_ansi_ssn_indicator,
				      tvb, 0, ADDRESS_INDICATOR_LENGTH, ssni);
    if (routing_ind == ROUTE_ON_SSN && ssni == 0) {
      expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_WARN,
			     "Message is routed on SSN, but SSN is not present");
    }

    offset = ADDRESS_INDICATOR_LENGTH;

    /* Dissect SSN (if present) */
    if (ssni) {
      ssn = tvb_get_guint8(tvb, offset);

      if (routing_ind == ROUTE_ON_SSN && ssn == 0) {
	expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_WARN,
			       "Message is routed on SSN, but SSN is zero (unspecified)");
      }

      if (called && assoc) {
	assoc->called_ssn = ssn;
      } else if (assoc) {
	assoc->calling_ssn = ssn;
      }

      if (is_connectionless(message_type) && sccp_msg) {
	guint *ssn_ptr = called ? &(sccp_msg->data.ud.called_ssn) : &(sccp_msg->data.ud.calling_ssn);

	*ssn_ptr  = ssn;
      }

      proto_tree_add_uint(call_tree, called ? hf_sccp_called_ssn
					    : hf_sccp_calling_ssn,
			  tvb, offset, ADDRESS_SSN_LENGTH, ssn);
      hidden_item = proto_tree_add_uint(call_tree, hf_sccp_ssn, tvb, offset,
					ADDRESS_SSN_LENGTH, ssn);
      PROTO_ITEM_SET_HIDDEN(hidden_item);

      offset += ADDRESS_SSN_LENGTH;
    }

    /* Dissect PC (if present) */
    if (pci) {
      offset = dissect_sccp_3byte_pc(tvb, call_tree, offset, called);
    }

    /* Dissect GT (if present) */
    if (gti != AI_GTI_NO_GT) {
      if (length < offset)
		  return;
      gt_tvb = tvb_new_subset(tvb, offset, (length - offset),
			      (length - offset));
      dissect_sccp_global_title(gt_tvb, pinfo, call_tree, (length - offset), gti,
				(routing_ind == ROUTE_ON_GT), called);
    }

  }

}

static void
dissect_sccp_called_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  dissect_sccp_called_calling_param(tvb, tree, pinfo, length, TRUE);
}

static void
dissect_sccp_calling_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  dissect_sccp_called_calling_param(tvb, tree, pinfo, length, FALSE);
}

static void
dissect_sccp_class_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 class;
  proto_item *pi;
  gboolean invalid_class = FALSE;

  if (length != 1) {
    pi = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(pi);
    return;
  }

  class = tvb_get_guint8(tvb, 0) & CLASS_CLASS_MASK;
  pi = proto_tree_add_uint(tree, hf_sccp_class, tvb, 0, length, class);

  switch(message_type) {
  case SCCP_MSG_TYPE_DT1:
    if (class != 2)
      invalid_class = TRUE;
    break;
  case SCCP_MSG_TYPE_DT2:
  case SCCP_MSG_TYPE_AK:
  case SCCP_MSG_TYPE_ED:
  case SCCP_MSG_TYPE_EA:
  case SCCP_MSG_TYPE_RSR:
  case SCCP_MSG_TYPE_RSC:
    if (class != 3)
      invalid_class = TRUE;
    break;
  case SCCP_MSG_TYPE_CR:
  case SCCP_MSG_TYPE_CC:
  case SCCP_MSG_TYPE_CREF:
  case SCCP_MSG_TYPE_RLSD:
  case SCCP_MSG_TYPE_RLC:
  case SCCP_MSG_TYPE_ERR:
  case SCCP_MSG_TYPE_IT:
    if (class != 2 && class != 3)
      invalid_class = TRUE;
    break;
  case SCCP_MSG_TYPE_UDT:
  case SCCP_MSG_TYPE_UDTS:
  case SCCP_MSG_TYPE_XUDT:
  case SCCP_MSG_TYPE_XUDTS:
  case SCCP_MSG_TYPE_LUDT:
  case SCCP_MSG_TYPE_LUDTS:
    if (class != 0 && class != 1)
      invalid_class = TRUE;
    break;
  }

  if (invalid_class)
    expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR, "Unexpected message class for this message type");

  if (class == 0 || class == 1) {
    guint8 handling = tvb_get_guint8(tvb, 0) & CLASS_SPARE_HANDLING_MASK;

    pi = proto_tree_add_item(tree, hf_sccp_handling, tvb, 0, length, ENC_NA);
    handling >>= CLASS_SPARE_HANDLING_SHIFT;

    if (match_strval(handling, sccp_class_handling_values) == NULL) {
      expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR, "Invalid message handling");
    }
  }
}

static void
dissect_sccp_segmenting_reassembling_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  proto_tree_add_item(tree, hf_sccp_more, tvb, 0, length, FALSE);
}

static void
dissect_sccp_receive_sequence_number_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 rsn;

  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  rsn = tvb_get_guint8(tvb, 0) >> 1;
  proto_tree_add_uint(tree, hf_sccp_rsn, tvb, 0, length, rsn);
}

static void
dissect_sccp_sequencing_segmenting_param(tvbuff_t *tvb, proto_tree *tree, guint length)
{
  guint8 rsn, ssn;
  proto_item *param_item;
  proto_tree *param_tree;

  ssn = tvb_get_guint8(tvb, 0) >> 1;
  rsn = tvb_get_guint8(tvb, SEQUENCING_SEGMENTING_SSN_LENGTH) >> 1;

  param_item = proto_tree_add_text(tree, tvb, 0, length, "%s",
				   val_to_str(PARAMETER_SEQUENCING_SEGMENTING,
					      sccp_parameter_values, "Unknown: %d"));
  param_tree = proto_item_add_subtree(param_item,
				      ett_sccp_sequencing_segmenting);

  proto_tree_add_uint(param_tree, hf_sccp_sequencing_segmenting_ssn, tvb, 0,
		      SEQUENCING_SEGMENTING_SSN_LENGTH, ssn);
  proto_tree_add_uint(param_tree, hf_sccp_sequencing_segmenting_rsn, tvb,
		      SEQUENCING_SEGMENTING_SSN_LENGTH,
		      SEQUENCING_SEGMENTING_RSN_LENGTH, rsn);
  proto_tree_add_item(param_tree, hf_sccp_sequencing_segmenting_more, tvb,
		      SEQUENCING_SEGMENTING_SSN_LENGTH,
		      SEQUENCING_SEGMENTING_RSN_LENGTH, ENC_NA);
}

static void
dissect_sccp_credit_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  proto_tree_add_item(tree, hf_sccp_credit, tvb, 0, length, ENC_NA);
}

static void
dissect_sccp_release_cause_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 cause;

  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  cause = tvb_get_guint8(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_release_cause, tvb, 0, length, cause);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", cause);
}

static void
dissect_sccp_return_cause_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 cause;

  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  cause = tvb_get_guint8(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_return_cause, tvb, 0, length, cause);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", cause);
}

static void
dissect_sccp_reset_cause_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 cause;

  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  cause = tvb_get_guint8(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_reset_cause, tvb, 0, length, cause);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", cause);
}

static void
dissect_sccp_error_cause_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 cause;

  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  cause = tvb_get_guint8(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_error_cause, tvb, 0, length, cause);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", cause);
}

static void
dissect_sccp_refusal_cause_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint8 cause;

  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  cause = tvb_get_guint8(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_refusal_cause, tvb, 0, length, cause);

  if (show_key_params && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "Cause=%d ", cause);
}


/* This function is used for both data and long data (ITU only) parameters */
static void
dissect_sccp_data_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 ssn = INVALID_SSN;
    guint8 other_ssn = INVALID_SSN;
    const mtp3_addr_pc_t* dpc = NULL;
    const mtp3_addr_pc_t* opc = NULL;

    if (trace_sccp && assoc && assoc != &no_assoc) {
        pinfo->sccp_info = assoc->curr_msg;
    } else {
        pinfo->sccp_info = NULL;
    }

    if (assoc) {
        switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            ssn = assoc->calling_ssn;
            other_ssn = assoc->called_ssn;
            dpc = (const mtp3_addr_pc_t*)pinfo->dst.data;
            opc = (const mtp3_addr_pc_t*)pinfo->src.data;
            break;
        case P2P_DIR_RECV:
            ssn = assoc->called_ssn;
            other_ssn = assoc->calling_ssn;
            dpc = (const mtp3_addr_pc_t*)pinfo->src.data;
            opc = (const mtp3_addr_pc_t*)pinfo->dst.data;
            break;
        default:
            ssn = assoc->called_ssn;
            other_ssn = assoc->calling_ssn;
            dpc = (const mtp3_addr_pc_t*)pinfo->dst.data;
            opc = (const mtp3_addr_pc_t*)pinfo->src.data;
            break;
        }
    }


    if (num_sccp_users && pinfo->src.type == AT_SS7PC) {
	guint i;
	dissector_handle_t handle = NULL;
        gboolean uses_tcap = FALSE;

	for (i=0; i < num_sccp_users; i++) {
	    sccp_user_t* u = &(sccp_users[i]);

	    if (!dpc || dpc->ni != u->ni) continue;

	    if (value_is_in_range(u->called_ssn, ssn)  && value_is_in_range(u->called_pc, dpc->pc) ) {
		handle = *(u->handlep);
		uses_tcap = u->uses_tcap;
		break;
	    } else if (value_is_in_range(u->called_ssn, other_ssn) && opc && value_is_in_range(u->called_pc, opc->pc) ) {
		handle = *(u->handlep);
		uses_tcap = u->uses_tcap;
		break;
	    }
	}

	if (handle) {
	    if (uses_tcap) {
		call_tcap_dissector(handle, tvb, pinfo, tree);
	    } else {
		call_dissector(handle, tvb, pinfo, tree);
	    }
	    return;
	}

   }

    if (ssn != INVALID_SSN && dissector_try_uint(sccp_ssn_dissector_table, ssn, tvb, pinfo, tree)) {
	return;
    }

    if (other_ssn != INVALID_SSN && dissector_try_uint(sccp_ssn_dissector_table, other_ssn, tvb, pinfo, tree)) {
	return;
    }

    /* try heuristic subdissector list to see if there are any takers */
    if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree)) {
	return;
    }

    /* try user default subdissector */
    if (default_handle) {
        call_dissector(default_handle, tvb, pinfo, tree);
        return;
    }

    /* No sub-dissection occured, treat it as raw data */
    call_dissector(data_handle, tvb, pinfo, tree);

}

static void
dissect_sccp_segmentation_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  proto_item *param_item;
  proto_tree *param_tree;

  param_item = proto_tree_add_text(tree, tvb, 0, length, "%s",
				   val_to_str(PARAMETER_SEGMENTATION,
					      sccp_parameter_values, "Unknown: %d"));
  param_tree = proto_item_add_subtree(param_item, ett_sccp_segmentation);

  proto_tree_add_item(param_tree, hf_sccp_segmentation_first, tvb, 0, 1, ENC_NA);
  proto_tree_add_item(param_tree, hf_sccp_segmentation_class, tvb, 0, 1, ENC_NA);
  proto_tree_add_item(param_tree, hf_sccp_segmentation_remaining, tvb, 0, 1, ENC_NA);

  if (length-1 != 3) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length-1, "Wrong length indicated. Expected 3, got %u", length-1);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 3, got %u", length-1);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  proto_tree_add_item(param_tree, hf_sccp_segmentation_slr, tvb, 1, length-1, ENC_LITTLE_ENDIAN);
}

static void
dissect_sccp_hop_counter_param(tvbuff_t *tvb, proto_tree *tree, guint length)
{
  guint8 hops;

  hops = tvb_get_guint8(tvb, 0);
  proto_tree_add_uint(tree, hf_sccp_hop_counter, tvb, 0, length, hops);
}

static void
dissect_sccp_importance_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint length)
{
  if (length != 1) {
    proto_item *expert_item;
    expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
    expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
    PROTO_ITEM_SET_GENERATED(expert_item);
    return;
  }

  proto_tree_add_item(tree, hf_sccp_importance, tvb, 0, length, ENC_NA);
}

static void
dissect_sccp_isni_param(tvbuff_t *tvb, proto_tree *tree, guint length)
{
  guint8 ti;
  guint offset = 0;
  proto_item *param_item;
  proto_tree *param_tree;

  /* Create a subtree for ISNI Routing Control */
  param_item = proto_tree_add_text(tree, tvb, offset, ANSI_ISNI_ROUTING_CONTROL_LENGTH,
				   "ISNI Routing Control");
  param_tree = proto_item_add_subtree(param_item,
				      ett_sccp_ansi_isni_routing_control);

  proto_tree_add_item(param_tree, hf_sccp_ansi_isni_mi, tvb, offset,
		      ANSI_ISNI_ROUTING_CONTROL_LENGTH, ENC_NA);

  proto_tree_add_item(param_tree, hf_sccp_ansi_isni_iri, tvb, offset,
		      ANSI_ISNI_ROUTING_CONTROL_LENGTH, ENC_NA);

  ti = tvb_get_guint8(tvb, offset) & ANSI_ISNI_TI_MASK;
  proto_tree_add_uint(param_tree, hf_sccp_ansi_isni_ti, tvb, offset,
		      ANSI_ISNI_ROUTING_CONTROL_LENGTH, ti);

  proto_tree_add_item(param_tree, hf_sccp_ansi_isni_counter, tvb, offset,
		      ANSI_ISNI_ROUTING_CONTROL_LENGTH, ENC_NA);

  offset += ANSI_ISNI_ROUTING_CONTROL_LENGTH;

  if ((ti >> ANSI_ISNI_TI_SHIFT) == ANSI_ISNI_TYPE_1) {
    proto_tree_add_uint(param_tree, hf_sccp_ansi_isni_netspec, tvb, offset,
			ANSI_ISNI_ROUTING_CONTROL_LENGTH, ti);
    offset += ANSI_ISNI_ROUTING_CONTROL_LENGTH;
  }

  while (offset < length) {

    proto_tree_add_item(tree, hf_sccp_ansi_isni_network, tvb, offset,
			ANSI_NCM_LENGTH, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_sccp_ansi_isni_cluster, tvb, offset,
			ANSI_NCM_LENGTH, ENC_NA);
    offset++;
  }

}

/*  FUNCTION dissect_sccp_parameter():
 *  Dissect a parameter given its type, offset into tvb, and length.
 */
static guint16
dissect_sccp_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *sccp_tree,
		       proto_tree *tree, guint8 parameter_type, guint16 offset,
		       guint16 parameter_length)
{
    tvbuff_t *parameter_tvb;

    switch (parameter_type) {
    case PARAMETER_CALLED_PARTY_ADDRESS:
    case PARAMETER_CALLING_PARTY_ADDRESS:
    case PARAMETER_DATA:
    case PARAMETER_LONG_DATA:
    case PARAMETER_SOURCE_LOCAL_REFERENCE:
    case PARAMETER_DESTINATION_LOCAL_REFERENCE:
    case PARAMETER_RELEASE_CAUSE:
    case PARAMETER_RETURN_CAUSE:
    case PARAMETER_RESET_CAUSE:
    case PARAMETER_ERROR_CAUSE:
    case PARAMETER_REFUSAL_CAUSE:

      /*  These parameters must be dissected even if !sccp_tree (so that
       *  assoc information can be created).
       */
      break;

    default:
      if (!sccp_tree) return(parameter_length);

    }

    parameter_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);

    switch (parameter_type) {

    case PARAMETER_END_OF_OPTIONAL_PARAMETERS:
      proto_tree_add_text(sccp_tree, tvb, offset, parameter_length,
			  "End of Optional");
      break;

    case PARAMETER_DESTINATION_LOCAL_REFERENCE:
      dissect_sccp_dlr_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_SOURCE_LOCAL_REFERENCE:
      dissect_sccp_slr_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_CALLED_PARTY_ADDRESS:
      dissect_sccp_called_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_CALLING_PARTY_ADDRESS:
      dissect_sccp_calling_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_CLASS:
      dissect_sccp_class_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_SEGMENTING_REASSEMBLING:
      dissect_sccp_segmenting_reassembling_param(parameter_tvb, pinfo, sccp_tree,
						   parameter_length);
      break;

    case PARAMETER_RECEIVE_SEQUENCE_NUMBER:
      dissect_sccp_receive_sequence_number_param(parameter_tvb, pinfo, sccp_tree,
						 parameter_length);
      break;

    case PARAMETER_SEQUENCING_SEGMENTING:
      dissect_sccp_sequencing_segmenting_param(parameter_tvb, sccp_tree,
					       parameter_length);
      break;

    case PARAMETER_CREDIT:
      dissect_sccp_credit_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_RELEASE_CAUSE:
      dissect_sccp_release_cause_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_RETURN_CAUSE:
      dissect_sccp_return_cause_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_RESET_CAUSE:
      dissect_sccp_reset_cause_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_ERROR_CAUSE:
      dissect_sccp_error_cause_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_REFUSAL_CAUSE:
      dissect_sccp_refusal_cause_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_DATA:
      dissect_sccp_data_param(parameter_tvb, pinfo, tree);

      /* TODO? Re-adjust length of SCCP item since it may be sub-dissected */
      /* sccp_length = proto_item_get_len(sccp_item);
       * sccp_length -= parameter_length;
       * proto_item_set_len(sccp_item, sccp_length);
       */
      break;

    case PARAMETER_SEGMENTATION:
		dissect_sccp_segmentation_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      break;

    case PARAMETER_HOP_COUNTER:
		dissect_sccp_hop_counter_param(parameter_tvb, sccp_tree, parameter_length);
      break;

    case PARAMETER_IMPORTANCE:
      if (decode_mtp3_standard != ANSI_STANDARD)
		  dissect_sccp_importance_param(parameter_tvb, pinfo, sccp_tree, parameter_length);
      else
		  dissect_sccp_unknown_param(parameter_tvb, sccp_tree, parameter_type,
				   parameter_length);
      break;

    case PARAMETER_LONG_DATA:
      dissect_sccp_data_param(parameter_tvb, pinfo, tree);
      break;

    case PARAMETER_ISNI:
      if (decode_mtp3_standard != ANSI_STANDARD)
		  dissect_sccp_unknown_param(parameter_tvb, sccp_tree, parameter_type,
				   parameter_length);
      else
		  dissect_sccp_isni_param(parameter_tvb, sccp_tree, parameter_length);
      break;

    default:
		dissect_sccp_unknown_param(parameter_tvb, sccp_tree, parameter_type,
				 parameter_length);
      break;
    }

    return(parameter_length);
}

/*  FUNCTION dissect_sccp_variable_parameter():
 *  Dissect a variable parameter given its type and offset into tvb.  Length
 *  of the parameter is gotten from tvb[0].
 *  Length returned is sum of (length + parameter).
 */
static guint16
dissect_sccp_variable_parameter(tvbuff_t *tvb, packet_info *pinfo,
				proto_tree *sccp_tree, proto_tree *tree,
				guint8 parameter_type, guint16 offset)
{
  guint16 parameter_length;
  guint8 length_length;
  proto_item *pi;

  if (parameter_type != PARAMETER_LONG_DATA) {
    parameter_length = tvb_get_guint8(tvb, offset);
    length_length = PARAMETER_LENGTH_LENGTH;
  } else {
    /* Long data parameter has 16 bit length */
    parameter_length = tvb_get_letohs(tvb, offset);
    length_length = PARAMETER_LONG_DATA_LENGTH_LENGTH;
  }

  pi = proto_tree_add_uint_format(sccp_tree, hf_sccp_param_length, tvb, offset,
				  length_length, parameter_length, "%s length: %d",
				  val_to_str(parameter_type, sccp_parameter_values,
					     "Unknown: %d"),
				  parameter_length);
  if (!sccp_show_length) {
    /* The user doesn't want to see it... */
    PROTO_ITEM_SET_HIDDEN(pi);
  }

  offset += length_length;

  dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree, parameter_type, offset,
			 parameter_length);

  return(parameter_length + length_length);
}

/*  FUNCTION dissect_sccp_optional_parameters():
 *  Dissect all the optional parameters given the start of the optional
 *  parameters into tvb.  Parameter types and lengths are read from tvb.
 */
static void
dissect_sccp_optional_parameters(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *sccp_tree, proto_tree *tree,
				 guint16 offset)
{
  guint8 parameter_type;

  while ((parameter_type = tvb_get_guint8(tvb, offset)) !=
	 PARAMETER_END_OF_OPTIONAL_PARAMETERS) {

    offset += PARAMETER_TYPE_LENGTH;
    offset += dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
					      parameter_type, offset);
  }

  /* Process end of optional parameters */
  dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree, parameter_type, offset,
			 END_OF_OPTIONAL_PARAMETERS_LENGTH);

}

static sccp_msg_info_t *
new_ud_msg(packet_info* pinfo, guint32 msg_type _U_)
{
	sccp_msg_info_t* m = ep_alloc0(sizeof(sccp_msg_info_t));
	m->framenum = pinfo->fd->num;
	m->data.ud.calling_gt = NULL;
	m->data.ud.called_gt = NULL;

	register_frame_end_routine(reset_sccp_assoc);
	return m;
}

static void
dissect_sccp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *sccp_tree,
		     proto_tree *tree)
{
  guint16 variable_pointer1 = 0, variable_pointer2 = 0, variable_pointer3 = 0;
  guint16 optional_pointer = 0, orig_opt_ptr = 0;
  guint16 offset = 0;
  gboolean   save_fragmented;
  tvbuff_t *new_tvb = NULL;
  fragment_data *frag_msg = NULL;
  guint32 source_local_ref=0;
  guint8 more;
  guint msg_offset = tvb_offset_from_real_beginning(tvb);

/* Macro for getting pointer to mandatory variable parameters */
#define VARIABLE_POINTER(var, hf_var, ptr_size) \
    if (ptr_size == POINTER_LENGTH) \
	var = tvb_get_guint8(tvb, offset); \
    else \
	var = tvb_get_letohs(tvb, offset); \
    proto_tree_add_uint(sccp_tree, hf_var, tvb, \
			offset, ptr_size, var); \
    var += offset; \
    if (ptr_size == POINTER_LENGTH_LONG) \
	var += 1; \
    offset += ptr_size;

/* Macro for getting pointer to optional parameters */
#define OPTIONAL_POINTER(ptr_size) \
    if (ptr_size == POINTER_LENGTH) \
	orig_opt_ptr = optional_pointer = tvb_get_guint8(tvb, offset); \
    else \
	orig_opt_ptr = optional_pointer = tvb_get_letohs(tvb, offset); \
    proto_tree_add_uint(sccp_tree, hf_sccp_optional_pointer, tvb, \
			offset, ptr_size, optional_pointer); \
    optional_pointer += offset; \
    if (ptr_size == POINTER_LENGTH_LONG) \
	optional_pointer += 1; \
    offset += ptr_size;


  /* Extract the message type;  all other processing is based on this */
  message_type   = tvb_get_guint8(tvb, SCCP_MSG_TYPE_OFFSET);
  offset = SCCP_MSG_TYPE_LENGTH;

  if (check_col(pinfo->cinfo, COL_INFO)) {
    /*  Do not change col_add_fstr() to col_append_fstr() here: we _want_
     *  this call to overwrite whatever's currently in the INFO column (e.g.,
     *  "DATA" from the SCTP dissector).
     *
     *  If there's something there that should not be overwritten, whoever
     *  put that info there should call col_set_fence() to protect it.
     */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
		 val_to_str(message_type, sccp_message_type_acro_values, "Unknown: %d"));
  };

  if (sccp_tree) {
    /* add the message type to the protocol tree */
    proto_tree_add_uint(sccp_tree, hf_sccp_message_type, tvb,
			SCCP_MSG_TYPE_OFFSET, SCCP_MSG_TYPE_LENGTH, message_type);

  };

  /* Starting a new message dissection; clear the global assoc, SLR, and DLR values */
  dlr = INVALID_LR;
  slr = INVALID_LR;
  assoc = NULL;

  no_assoc.calling_dpc = 0;
  no_assoc.called_dpc = 0;
  no_assoc.calling_ssn = INVALID_SSN;
  no_assoc.called_ssn = INVALID_SSN;
  no_assoc.has_fw_key = FALSE;
  no_assoc.has_bw_key = FALSE;
  no_assoc.payload = SCCP_PLOAD_NONE;
  no_assoc.called_party = NULL;
  no_assoc.calling_party = NULL;
  no_assoc.extra_info = NULL;

  switch(message_type) {
  case SCCP_MSG_TYPE_CR:
  /*  TTC and NTT (Japan) say that the connection-oriented messages are
   *  deleted (not standardized), but they appear to be used anyway, so
   *  we'll dissect it...
   */
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CLASS, offset,
				     PROTOCOL_CLASS_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH)
    OPTIONAL_POINTER(POINTER_LENGTH)

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);
    break;

  case SCCP_MSG_TYPE_CC:
    /*  TODO: connection has been established;  theoretically we could keep
     *  keep track of the SLR/DLR with the called/calling from the CR and
     *  track the connection (e.g., on subsequent messages regarding this
     *  SLR we could set the global vars "call*_ssn" so data could get
     *  sub-dissected).
     */
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CLASS, offset,
				     PROTOCOL_CLASS_LENGTH);
    OPTIONAL_POINTER(POINTER_LENGTH);
    break;

  case SCCP_MSG_TYPE_CREF:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_REFUSAL_CAUSE, offset,
				     REFUSAL_CAUSE_LENGTH);
    OPTIONAL_POINTER(POINTER_LENGTH);
    break;

  case SCCP_MSG_TYPE_RLSD:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_RELEASE_CAUSE, offset,
				     RELEASE_CAUSE_LENGTH);

    OPTIONAL_POINTER(POINTER_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    break;

  case SCCP_MSG_TYPE_RLC:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    break;

  case SCCP_MSG_TYPE_DT1:
    source_local_ref = tvb_get_letoh24(tvb, offset);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    more = tvb_get_guint8(tvb, offset) & SEGMENTING_REASSEMBLING_MASK;

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SEGMENTING_REASSEMBLING,
				     offset, SEGMENTING_REASSEMBLING_LENGTH);
    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH)

    /* Reassemble */
    if (!sccp_xudt_desegment) {
	proto_tree_add_text(sccp_tree, tvb, variable_pointer1,
			    tvb_get_guint8(tvb, variable_pointer1)+1,
			    "Segmented Data");
	dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
					PARAMETER_DATA, variable_pointer1);

    } else {
	save_fragmented = pinfo->fragmented;
	pinfo->fragmented = TRUE;
	frag_msg = fragment_add_seq_next(tvb, variable_pointer1 + 1, pinfo,
					 source_local_ref,			/* ID for fragments belonging together */
					 sccp_xudt_msg_fragment_table,		/* list of message fragments */
					 sccp_xudt_msg_reassembled_table,	/* list of reassembled messages */
					 tvb_get_guint8(tvb,variable_pointer1),	/* fragment length - to the end */
					 more);					/* More fragments? */

	new_tvb = process_reassembled_data(tvb, variable_pointer1 + 1, pinfo,
					   "Reassembled SCCP", frag_msg,
					   &sccp_xudt_msg_frag_items, NULL,
					   tree);

	if (frag_msg && frag_msg->next) { /* Reassembled */
	    col_append_str(pinfo->cinfo, COL_INFO, "(Message reassembled) ");
	} else if (more) { /* Not last packet of reassembled message */
	    col_append_str(pinfo->cinfo, COL_INFO, "(Message fragment) ");
	}

	pinfo->fragmented = save_fragmented;

	if (new_tvb)
	    dissect_sccp_data_param(new_tvb, pinfo, tree);
    }

    /* End reassemble */
    break;

  case SCCP_MSG_TYPE_DT2:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SEQUENCING_SEGMENTING, offset,
				     SEQUENCING_SEGMENTING_LENGTH);
    break;

  case SCCP_MSG_TYPE_AK:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_RECEIVE_SEQUENCE_NUMBER,
				     offset, RECEIVE_SEQUENCE_NUMBER_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CREDIT, offset, CREDIT_LENGTH);
    break;

  case SCCP_MSG_TYPE_UDT:
    pinfo->sccp_info = sccp_msg = new_ud_msg(pinfo,message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CLASS, offset,
				     PROTOCOL_CLASS_LENGTH);
    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH)

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLING_PARTY_ADDRESS,
				    variable_pointer2);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree, PARAMETER_DATA,
				    variable_pointer3);
    break;

  case SCCP_MSG_TYPE_UDTS:
  {
    gboolean save_in_error_pkt = pinfo->in_error_pkt;
    pinfo->in_error_pkt = TRUE;

    pinfo->sccp_info =  sccp_msg = new_ud_msg(pinfo,message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_RETURN_CAUSE, offset,
				     RETURN_CAUSE_LENGTH);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH)

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLING_PARTY_ADDRESS,
				    variable_pointer2);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree, PARAMETER_DATA,
				    variable_pointer3);
    pinfo->in_error_pkt = save_in_error_pkt;
    break;
  }

  case SCCP_MSG_TYPE_ED:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree, PARAMETER_DATA,
				    variable_pointer1);
    break;

  case SCCP_MSG_TYPE_EA:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    break;

  case SCCP_MSG_TYPE_RSR:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_RESET_CAUSE, offset,
				     RESET_CAUSE_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    break;

  case SCCP_MSG_TYPE_RSC:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    break;

  case SCCP_MSG_TYPE_ERR:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_ERROR_CAUSE, offset,
				     ERROR_CAUSE_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    break;

  case SCCP_MSG_TYPE_IT:
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_DESTINATION_LOCAL_REFERENCE,
				     offset,
				     DESTINATION_LOCAL_REFERENCE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SOURCE_LOCAL_REFERENCE,
				     offset, SOURCE_LOCAL_REFERENCE_LENGTH);
    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CLASS, offset,
				     PROTOCOL_CLASS_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_SEQUENCING_SEGMENTING,
				     offset, SEQUENCING_SEGMENTING_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CREDIT, offset, CREDIT_LENGTH);
    break;

  case SCCP_MSG_TYPE_XUDT:
    pinfo->sccp_info =  sccp_msg = new_ud_msg(pinfo,message_type);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CLASS, offset,
				     PROTOCOL_CLASS_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_HOP_COUNTER, offset,
				     HOP_COUNTER_LENGTH);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH)
    OPTIONAL_POINTER(POINTER_LENGTH)

    /*  Optional parameters are Segmentation and Importance
     *  NOTE 2 - Segmentation Should not be present in case of a single XUDT
     *  message.
     */

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLING_PARTY_ADDRESS,
				    variable_pointer2);

    if (tvb_get_guint8(tvb, optional_pointer) == PARAMETER_SEGMENTATION) {
	if (!sccp_xudt_desegment){
	    proto_tree_add_text(sccp_tree, tvb, variable_pointer3, tvb_get_guint8(tvb, variable_pointer3)+1, "Segmented Data");
	} else {
	    guint8 octet;
	    gboolean more_frag = TRUE;

	    /* Get the first octet of parameter Segmentation, Ch 3.17 in Q.713
	     * Bit 8 of octet 1 is used for First segment indication
	     * Bit 7 of octet 1 is used to keep in the message in sequence
	     *	     delivery option required by the SCCP user
	     * Bits 6 and 5 in octet 1 are spare bits.
	     * Bits 4-1 of octet 1 are used to indicate the number of
	     *		remaining segments.
	     * The values 0000 to 1111 are possible; the value 0000 indicates
	     * the last segment.
	     */
	    octet = tvb_get_guint8(tvb,optional_pointer+2);
	    source_local_ref = tvb_get_letoh24(tvb, optional_pointer+3);

	    if ((octet&0x0f) == 0)
		more_frag = FALSE;

	    save_fragmented = pinfo->fragmented;
	    pinfo->fragmented = TRUE;
	    frag_msg = fragment_add_seq_next(tvb, variable_pointer3 + 1, pinfo,
					     source_local_ref,				/* ID for fragments belonging together */
					     sccp_xudt_msg_fragment_table,		/* list of message fragments */
					     sccp_xudt_msg_reassembled_table,		/* list of reassembled messages */
					     tvb_get_guint8(tvb,variable_pointer3),	/* fragment length - to the end */
					     more_frag);				/* More fragments? */

	    if ((octet&0x80) == 0x80) /*First segment, set number of segments*/
		fragment_set_tot_len(pinfo, source_local_ref, sccp_xudt_msg_fragment_table,(octet & 0xf));

	    new_tvb = process_reassembled_data(tvb, variable_pointer3 + 1,
					       pinfo, "Reassembled SCCP",
					       frag_msg,
					       &sccp_xudt_msg_frag_items,
					       NULL, tree);

	    if (frag_msg) { /* Reassembled */
		col_append_str(pinfo->cinfo, COL_INFO,"(Message reassembled) ");
	    } else { /* Not last packet of reassembled message */
		col_append_str(pinfo->cinfo, COL_INFO,"(Message fragment) ");
	    }

	    pinfo->fragmented = save_fragmented;

	    if (new_tvb)
		dissect_sccp_data_param(new_tvb, pinfo, tree);
	}
    } else {
	dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
					PARAMETER_DATA, variable_pointer3);
    }
    break;

  case SCCP_MSG_TYPE_XUDTS:
  {
    gboolean save_in_error_pkt = pinfo->in_error_pkt;
    pinfo->in_error_pkt = TRUE;

    pinfo->sccp_info =  sccp_msg = new_ud_msg(pinfo,message_type);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_RETURN_CAUSE, offset,
				     RETURN_CAUSE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_HOP_COUNTER, offset,
				     HOP_COUNTER_LENGTH);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH)
    VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH)
    OPTIONAL_POINTER(POINTER_LENGTH)

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLING_PARTY_ADDRESS,
				    variable_pointer2);

    if (tvb_get_guint8(tvb, optional_pointer) == PARAMETER_SEGMENTATION) {
	if (!sccp_xudt_desegment){
	    proto_tree_add_text(sccp_tree, tvb, variable_pointer3, tvb_get_guint8(tvb, variable_pointer3)+1, "Segmented Data");

	} else {
	    guint8 octet;
	    gboolean more_frag = TRUE;


	    /* Get the first octet of parameter Segmentation, Ch 3.17 in Q.713
	     * Bit 8 of octet 1 is used for First segment indication
	     * Bit 7 of octet 1 is used to keep in the message in sequence
	     *	     delivery option required by the SCCP user
	     * Bits 6 and 5 in octet 1 are spare bits.
	     * Bits 4-1 of octet 1 are used to indicate the number of
	     *		remaining segments.
	     * The values 0000 to 1111 are possible; the value 0000 indicates
	     * the last segment.
	     */
	    octet = tvb_get_guint8(tvb,optional_pointer+2);
	    source_local_ref = tvb_get_letoh24(tvb, optional_pointer+3);

	    if ((octet&0x0f) == 0)
		more_frag = FALSE;

	    save_fragmented = pinfo->fragmented;
	    pinfo->fragmented = TRUE;
	    frag_msg = fragment_add_seq_next(tvb, variable_pointer3 + 1, pinfo,
					     source_local_ref,				/* ID for fragments belonging together */
					     sccp_xudt_msg_fragment_table,		/* list of message fragments */
					     sccp_xudt_msg_reassembled_table,		/* list of reassembled messages */
					     tvb_get_guint8(tvb,variable_pointer3),	/* fragment length - to the end */
					     more_frag);				/* More fragments? */

	    if ((octet&0x80) == 0x80) /*First segment, set number of segments*/
		fragment_set_tot_len(pinfo, source_local_ref, sccp_xudt_msg_fragment_table,(octet & 0xf));

	    new_tvb = process_reassembled_data(tvb, variable_pointer3 + 1,
					       pinfo, "Reassembled SCCP",
					       frag_msg,
					       &sccp_xudt_msg_frag_items,
					       NULL, tree);

	    if (frag_msg) { /* Reassembled */
		col_append_str(pinfo->cinfo, COL_INFO, "(Message reassembled) ");
	    } else { /* Not last packet of reassembled message */
		col_append_str(pinfo->cinfo, COL_INFO, "(Message fragment) ");
	    }

	    pinfo->fragmented = save_fragmented;

	    if (new_tvb)
		dissect_sccp_data_param(new_tvb, pinfo, tree);
	}
    } else {
	dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
					PARAMETER_DATA, variable_pointer3);
    }
    pinfo->in_error_pkt = save_in_error_pkt;
    break;
  }
  case SCCP_MSG_TYPE_LUDT:
    pinfo->sccp_info =  sccp_msg = new_ud_msg(pinfo,message_type);

    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_CLASS, offset,
				     PROTOCOL_CLASS_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_HOP_COUNTER, offset,
				     HOP_COUNTER_LENGTH);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH_LONG)
    VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH_LONG)
    VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH_LONG)
    OPTIONAL_POINTER(POINTER_LENGTH_LONG)

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLING_PARTY_ADDRESS,
				    variable_pointer2);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_LONG_DATA, variable_pointer3);
    break;

  case SCCP_MSG_TYPE_LUDTS:
    pinfo->sccp_info =  sccp_msg = new_ud_msg(pinfo,message_type);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_RETURN_CAUSE, offset,
				     RETURN_CAUSE_LENGTH);
    offset += dissect_sccp_parameter(tvb, pinfo, sccp_tree, tree,
				     PARAMETER_HOP_COUNTER, offset,
				     HOP_COUNTER_LENGTH);

    VARIABLE_POINTER(variable_pointer1, hf_sccp_variable_pointer1, POINTER_LENGTH_LONG)
    VARIABLE_POINTER(variable_pointer2, hf_sccp_variable_pointer2, POINTER_LENGTH_LONG)
    VARIABLE_POINTER(variable_pointer3, hf_sccp_variable_pointer3, POINTER_LENGTH_LONG)
    OPTIONAL_POINTER(POINTER_LENGTH_LONG)

    assoc = get_sccp_assoc(pinfo, msg_offset,  slr, dlr, message_type);

    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLED_PARTY_ADDRESS,
				    variable_pointer1);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_CALLING_PARTY_ADDRESS,
				    variable_pointer2);
    dissect_sccp_variable_parameter(tvb, pinfo, sccp_tree, tree,
				    PARAMETER_LONG_DATA, variable_pointer3);
    break;

  default:
    dissect_sccp_unknown_message(tvb, sccp_tree);
  }

  if (orig_opt_ptr)
    dissect_sccp_optional_parameters(tvb, pinfo, sccp_tree, tree,
				     optional_pointer);

  if (trace_sccp && assoc && assoc != &no_assoc) {
	  proto_item *pi = proto_tree_add_uint(sccp_tree, hf_sccp_assoc_id, tvb, 0, 0, assoc->id);
	  proto_tree *pt = proto_item_add_subtree(pi, ett_sccp_assoc);
	  PROTO_ITEM_SET_GENERATED(pi);
	  if (assoc->msgs) {
		sccp_msg_info_t* m;
		  for(m = assoc->msgs; m ; m = m->data.co.next) {
			pi = proto_tree_add_uint(pt, hf_sccp_assoc_msg, tvb, 0, 0, m->framenum);

			if (assoc->payload != SCCP_PLOAD_NONE)
				proto_item_append_text(pi," %s", val_to_str(assoc->payload, assoc_protos, "Unknown: %d"));

			if (m->data.co.label)
				proto_item_append_text(pi," %s", m->data.co.label);

			if (m->framenum == pinfo->fd->num && m->offset == msg_offset ) {
				tap_queue_packet(sccp_tap, pinfo, m);
				proto_item_append_text(pi," (current)");
			}
			PROTO_ITEM_SET_GENERATED(pi);
		  }
	  }
  }

}

static void
dissect_sccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *sccp_item = NULL;
  proto_tree *sccp_tree = NULL;
  const mtp3_addr_pc_t *mtp3_addr_p;

  if ((pinfo->src.type == AT_SS7PC) &&
      ((mtp3_addr_p = (const mtp3_addr_pc_t *)pinfo->src.data)->type <= CHINESE_ITU_STANDARD)) {
    /*
     *  Allow a protocol beneath to specify how the SCCP layer should be
     *  dissected.
     *
     *  It is possible to have multiple sets of SCCP traffic some of which is
     *  ITU and some of which is ANSI.
     *  An example is A-interface traffic having ANSI MTP3/ANSI SCCP/3GPP2 IOS
     *  and at the same time ITU MTP3/ITU SCCP/ANSI TCAP/ANSI MAP.
     */
    decode_mtp3_standard = mtp3_addr_p->type;
  } else {
    decode_mtp3_standard = mtp3_standard;
  }

  /* Make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    switch(decode_mtp3_standard) {
      case ITU_STANDARD:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCCP (Int. ITU)");
	break;
      case ANSI_STANDARD:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCCP (ANSI)");
	break;
      case CHINESE_ITU_STANDARD:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCCP (Chin. ITU)");
	break;
      case JAPAN_STANDARD:
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCCP (Japan)");
	break;
    };

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the sccp protocol tree */
    sccp_item = proto_tree_add_item(tree, proto_sccp, tvb, 0, -1, FALSE);
    sccp_tree = proto_item_add_subtree(sccp_item, ett_sccp);
  }

  /* Set whether message is UPLINK, DOWNLINK, or of UNKNOWN direction */

  if (pinfo->src.type == AT_SS7PC) {
    /*
     * XXX - we assume that the "data" pointers of the source and destination
     * addresses are set to point to "mtp3_addr_pc_t" structures, so that
     * we can safely cast them.
     */
    mtp3_addr_p = (const mtp3_addr_pc_t *)pinfo->src.data;

    if (sccp_source_pc_global == mtp3_addr_p->pc) {
       pinfo->p2p_dir = P2P_DIR_SENT;
    } else {
      /* assuming if src was SS7 PC then dst will be too */
      mtp3_addr_p = (const mtp3_addr_pc_t *)pinfo->dst.data;

      if (sccp_source_pc_global == mtp3_addr_p->pc)
      {
	 pinfo->p2p_dir = P2P_DIR_RECV;
      } else {
	 pinfo->p2p_dir = P2P_DIR_UNKNOWN;
      }
    }
  }

  /* dissect the message */
  dissect_sccp_message(tvb, pinfo, sccp_tree, tree);

}

/*** SccpUsers Table **/

static struct _sccp_ul {
	guint id;
	gboolean uses_tcap;
	dissector_handle_t* handlep;
	} user_list[] = {
	{SCCP_USER_DATA, FALSE, &data_handle},
	{SCCP_USER_TCAP, FALSE, &tcap_handle},
	{SCCP_USER_RANAP, FALSE, &ranap_handle},
	{SCCP_USER_BSSAP, FALSE, &bssap_handle},
	{SCCP_USER_GSMMAP, TRUE, &gsmmap_handle},
	{SCCP_USER_CAMEL, TRUE, &camel_handle},
	{SCCP_USER_INAP, TRUE, &inap_handle},
	{0, FALSE, NULL}
};

static void
sccp_users_update_cb(void* r, const char** err _U_)
{
	sccp_user_t* u = r;
	struct _sccp_ul* c;

	for (c=user_list; c->handlep; c++) {
		if (c->id == u->user) {
			u->uses_tcap = c->uses_tcap;
			u->handlep = c->handlep;
			return;
		}
	}

	u->uses_tcap = FALSE;
	u->handlep = &data_handle;
}

static void *
sccp_users_copy_cb(void* n, const void* o, size_t siz _U_)
{
	const sccp_user_t* u = o;
	sccp_user_t* un = n;

	un->ni = u->ni;
	un->user = u->user;
	un->uses_tcap = u->uses_tcap;
	un->handlep = u->handlep;
	if (u->called_pc) un->called_pc = range_copy(u->called_pc);
	if (u->called_ssn) un->called_ssn = range_copy(u->called_ssn);

	return n;
}

static void
sccp_users_free_cb(void*r)
{
	sccp_user_t* u = r;
	if (u->called_pc) g_free(u->called_pc);
	if (u->called_ssn) g_free(u->called_ssn);
}


UAT_DEC_CB_DEF(sccp_users, ni, sccp_user_t)
UAT_RANGE_CB_DEF(sccp_users, called_pc,sccp_user_t)
UAT_RANGE_CB_DEF(sccp_users, called_ssn,sccp_user_t)
UAT_VS_DEF(sccp_users, user, sccp_user_t, SCCP_USER_DATA, "Data")

/** End SccpUsersTable **/


static void
init_sccp(void)
{
    next_assoc_id = 1;
    fragment_table_init (&sccp_xudt_msg_fragment_table);
    reassembled_table_init(&sccp_xudt_msg_reassembled_table);

}

/* Register the protocol with Wireshark */
void
proto_register_sccp(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_sccp_message_type,
      { "Message Type", "sccp.message_type",
	FT_UINT8, BASE_HEX, VALS(sccp_message_type_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_variable_pointer1,
      { "Pointer to first Mandatory Variable parameter", "sccp.variable_pointer1",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_variable_pointer2,
      { "Pointer to second Mandatory Variable parameter", "sccp.variable_pointer2",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_variable_pointer3,
      { "Pointer to third Mandatory Variable parameter", "sccp.variable_pointer3",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_optional_pointer,
      { "Pointer to Optional parameter", "sccp.optional_pointer",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_param_length,
      { "Variable parameter length", "sccp.parameter_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_ssn,
      { "Called or Calling SubSystem Number", "sccp.ssn",
	FT_UINT8, BASE_DEC, VALS(sccp_ssn_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_gt_digits,
      { "Called or Calling GT Digits",
	"sccp.digits",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_called_national_indicator,
      { "National Indicator", "sccp.called.ni",
	FT_UINT8, BASE_HEX, VALS(sccp_national_indicator_values), ANSI_NATIONAL_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_routing_indicator,
      { "Routing Indicator", "sccp.called.ri",
	FT_UINT8, BASE_HEX, VALS(sccp_routing_indicator_values), ROUTING_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_itu_global_title_indicator,
      { "Global Title Indicator", "sccp.called.gti",
	FT_UINT8, BASE_HEX, VALS(sccp_itu_global_title_indicator_values), GTI_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_ansi_global_title_indicator,
      { "Global Title Indicator", "sccp.called.gti",
	FT_UINT8, BASE_HEX, VALS(sccp_ansi_global_title_indicator_values), GTI_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_itu_ssn_indicator,
      { "SubSystem Number Indicator", "sccp.called.ssni",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_ssni_values), ITU_SSN_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_itu_point_code_indicator,
      { "Point Code Indicator", "sccp.called.pci",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_pci_values), ITU_PC_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_ansi_ssn_indicator,
      { "SubSystem Number Indicator", "sccp.called.ssni",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_ssni_values), ANSI_SSN_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_ansi_point_code_indicator,
      { "Point Code Indicator", "sccp.called.pci",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_pci_values), ANSI_PC_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_ssn,
      { "SubSystem Number", "sccp.called.ssn",
	FT_UINT8, BASE_DEC, VALS(sccp_ssn_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_called_itu_pc,
      { "PC", "sccp.called.pc",
	FT_UINT16, BASE_DEC, NULL, ITU_PC_MASK,
	NULL, HFILL}},
    { &hf_sccp_called_ansi_pc,
      { "PC", "sccp.called.ansi_pc",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_called_chinese_pc,
      { "PC", "sccp.called.chinese_pc",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_called_japan_pc,
      { "PC", "sccp.called.pc",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_called_pc_network,
      { "PC Network",
	"sccp.called.network",
	FT_UINT24, BASE_DEC, NULL, ANSI_NETWORK_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_pc_cluster,
      { "PC Cluster",
	"sccp.called.cluster",
	FT_UINT24, BASE_DEC, NULL, ANSI_CLUSTER_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_pc_member,
      { "PC Member",
	"sccp.called.member",
	FT_UINT24, BASE_DEC, NULL, ANSI_MEMBER_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_gt_nai,
      { "Nature of Address Indicator",
	"sccp.called.nai",
	FT_UINT8, BASE_HEX, VALS(sccp_nai_values), GT_NAI_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_gt_oe,
      { "Odd/Even Indicator",
	"sccp.called.oe",
	FT_UINT8, BASE_HEX, VALS(sccp_oe_values), GT_OE_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_gt_tt,
      { "Translation Type",
	"sccp.called.tt",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_called_gt_np,
      { "Numbering Plan",
	"sccp.called.np",
	FT_UINT8, BASE_HEX, VALS(sccp_np_values), GT_NP_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_gt_es,
      { "Encoding Scheme",
	"sccp.called.es",
	FT_UINT8, BASE_HEX, VALS(sccp_es_values), GT_ES_MASK,
	NULL, HFILL }},
    { &hf_sccp_called_gt_digits,
      { "Called Party Digits",
	"sccp.called.digits",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_called_gt_digits_length,
      { "Number of Called Party Digits",
	"sccp.called.digits.length",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_calling_national_indicator,
      { "National Indicator", "sccp.calling.ni",
	FT_UINT8, BASE_HEX, VALS(sccp_national_indicator_values), ANSI_NATIONAL_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_routing_indicator,
      { "Routing Indicator", "sccp.calling.ri",
	FT_UINT8, BASE_HEX, VALS(sccp_routing_indicator_values), ROUTING_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_itu_global_title_indicator,
      { "Global Title Indicator", "sccp.calling.gti",
	FT_UINT8, BASE_HEX, VALS(sccp_itu_global_title_indicator_values), GTI_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_ansi_global_title_indicator,
      { "Global Title Indicator", "sccp.calling.gti",
	FT_UINT8, BASE_HEX, VALS(sccp_ansi_global_title_indicator_values), GTI_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_itu_ssn_indicator,
      { "SubSystem Number Indicator", "sccp.calling.ssni",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_ssni_values), ITU_SSN_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_itu_point_code_indicator,
      { "Point Code Indicator", "sccp.calling.pci",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_pci_values), ITU_PC_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_ansi_ssn_indicator,
      { "SubSystem Number Indicator", "sccp.calling.ssni",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_ssni_values), ANSI_SSN_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_ansi_point_code_indicator,
      { "Point Code Indicator", "sccp.calling.pci",
	FT_UINT8, BASE_HEX, VALS(sccp_ai_pci_values), ANSI_PC_INDICATOR_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_ssn,
      { "SubSystem Number", "sccp.calling.ssn",
	FT_UINT8, BASE_DEC, VALS(sccp_ssn_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_calling_itu_pc,
      { "PC", "sccp.calling.pc",
	FT_UINT16, BASE_DEC, NULL, ITU_PC_MASK,
	NULL, HFILL}},
    { &hf_sccp_calling_ansi_pc,
      { "PC", "sccp.calling.ansi_pc",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_calling_chinese_pc,
      { "PC", "sccp.calling.chinese_pc",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_calling_japan_pc,
      { "PC", "sccp.calling.pc",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_calling_pc_network,
      { "PC Network",
	"sccp.calling.network",
	FT_UINT24, BASE_DEC, NULL, ANSI_NETWORK_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_pc_cluster,
      { "PC Cluster",
	"sccp.calling.cluster",
	FT_UINT24, BASE_DEC, NULL, ANSI_CLUSTER_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_pc_member,
      { "PC Member",
	"sccp.calling.member",
	FT_UINT24, BASE_DEC, NULL, ANSI_MEMBER_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_nai,
      { "Nature of Address Indicator",
	"sccp.calling.nai",
	FT_UINT8, BASE_HEX, VALS(sccp_nai_values), GT_NAI_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_oe,
      { "Odd/Even Indicator",
	"sccp.calling.oe",
	FT_UINT8, BASE_HEX, VALS(sccp_oe_values), GT_OE_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_tt,
      { "Translation Type",
	"sccp.calling.tt",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_np,
      { "Numbering Plan",
	"sccp.calling.np",
	FT_UINT8, BASE_HEX, VALS(sccp_np_values), GT_NP_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_es,
      { "Encoding Scheme",
	"sccp.calling.es",
	FT_UINT8, BASE_HEX, VALS(sccp_es_values), GT_ES_MASK,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_digits,
      { "Calling Party Digits",
	"sccp.calling.digits",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_calling_gt_digits_length,
      { "Number of Calling Party Digits",
	"sccp.calling.digits.length",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_sccp_dlr,
      { "Destination Local Reference", "sccp.dlr",
	FT_UINT24, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_slr,
      { "Source Local Reference", "sccp.slr",
	FT_UINT24, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_lr,
    { "Local Reference", "sccp.lr",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      NULL, HFILL}},
    { &hf_sccp_class,
      { "Class", "sccp.class",
	FT_UINT8, BASE_HEX, NULL, CLASS_CLASS_MASK,
	NULL, HFILL}},
    { &hf_sccp_handling,
      { "Message handling", "sccp.handling",
	FT_UINT8, BASE_HEX, VALS(sccp_class_handling_values), CLASS_SPARE_HANDLING_MASK,
	NULL, HFILL}},
    { &hf_sccp_more,
      { "More data", "sccp.more",
	FT_UINT8, BASE_HEX, VALS(sccp_segmenting_reassembling_values), SEGMENTING_REASSEMBLING_MASK,
	NULL, HFILL}},
    { &hf_sccp_rsn,
      { "Receive Sequence Number", "sccp.rsn",
	FT_UINT8, BASE_HEX, NULL, RSN_MASK,
	NULL, HFILL}},
    { &hf_sccp_sequencing_segmenting_ssn,
      { "Sequencing Segmenting: Send Sequence Number", "sccp.sequencing_segmenting.ssn",
	FT_UINT8, BASE_HEX, NULL, SEND_SEQUENCE_NUMBER_MASK,
	NULL, HFILL}},
    { &hf_sccp_sequencing_segmenting_rsn,
      { "Sequencing Segmenting: Receive Sequence Number", "sccp.sequencing_segmenting.rsn",
	FT_UINT8, BASE_HEX, NULL, RECEIVE_SEQUENCE_NUMBER_MASK,
	NULL, HFILL}},
    { &hf_sccp_sequencing_segmenting_more,
      { "Sequencing Segmenting: More", "sccp.sequencing_segmenting.more",
	FT_UINT8, BASE_HEX, VALS(sccp_segmenting_reassembling_values), SEQUENCING_SEGMENTING_MORE_MASK,
	NULL, HFILL}},
    { &hf_sccp_credit,
      { "Credit", "sccp.credit",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_release_cause,
      { "Release Cause", "sccp.release_cause",
	FT_UINT8, BASE_HEX, VALS(sccp_release_cause_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_return_cause,
      { "Return Cause", "sccp.return_cause",
	FT_UINT8, BASE_HEX, VALS(sccp_return_cause_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_reset_cause,
      { "Reset Cause", "sccp.reset_cause",
	FT_UINT8, BASE_HEX, VALS(sccp_reset_cause_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_error_cause,
      { "Error Cause", "sccp.error_cause",
	FT_UINT8, BASE_HEX, VALS(sccp_error_cause_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_refusal_cause,
      { "Refusal Cause", "sccp.refusal_cause",
	FT_UINT8, BASE_HEX, VALS(sccp_refusal_cause_values), 0x0,
	NULL, HFILL}},
    { &hf_sccp_segmentation_first,
      { "Segmentation: First", "sccp.segmentation.first",
	FT_UINT8, BASE_HEX, VALS(sccp_segmentation_first_segment_values), SEGMENTATION_FIRST_SEGMENT_MASK,
	NULL, HFILL}},
    { &hf_sccp_segmentation_class,
      { "Segmentation: Class", "sccp.segmentation.class",
	FT_UINT8, BASE_HEX, VALS(sccp_segmentation_class_values), SEGMENTATION_CLASS_MASK,
	NULL, HFILL}},
    { &hf_sccp_segmentation_remaining,
      { "Segmentation: Remaining", "sccp.segmentation.remaining",
	FT_UINT8, BASE_HEX, NULL, SEGMENTATION_REMAINING_MASK,
	NULL, HFILL}},
    { &hf_sccp_segmentation_slr,
      { "Segmentation: Source Local Reference", "sccp.segmentation.slr",
	FT_UINT24, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_hop_counter,
      { "Hop Counter", "sccp.hops",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},
    { &hf_sccp_importance,
      { "Importance", "sccp.importance",
	FT_UINT8, BASE_HEX, NULL, IMPORTANCE_IMPORTANCE_MASK,
	NULL, HFILL}},
    /* ISNI is ANSI only */
    { &hf_sccp_ansi_isni_mi,
      { "ISNI Mark for Identification Indicator", "sccp.isni.mi",
	FT_UINT8, BASE_HEX, VALS(sccp_isni_mark_for_id_values), ANSI_ISNI_MI_MASK,
	NULL, HFILL}},
    { &hf_sccp_ansi_isni_iri,
      { "ISNI Routing Indicator", "sccp.isni.iri",
	FT_UINT8, BASE_HEX, VALS(sccp_isni_iri_values), ANSI_ISNI_IRI_MASK,
	NULL, HFILL}},
    { &hf_sccp_ansi_isni_ti,
      { "ISNI Type Indicator", "sccp.isni.ti",
	FT_UINT8, BASE_HEX, VALS(sccp_isni_ti_values), ANSI_ISNI_TI_MASK,
	NULL, HFILL}},
    { &hf_sccp_ansi_isni_netspec,
      { "ISNI Network Specific (Type 1)", "sccp.isni.netspec",
	FT_UINT8, BASE_HEX, NULL, ANSI_ISNI_NETSPEC_MASK,
	NULL, HFILL}},
    { &hf_sccp_ansi_isni_counter,
      { "ISNI Counter", "sccp.isni.counter",
	FT_UINT8, BASE_DEC, NULL, ANSI_ISNI_COUNTER_MASK,
	NULL, HFILL}},
    { &hf_sccp_ansi_isni_network,
      { "Network ID network", "sccp.isni.network",
	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_sccp_ansi_isni_cluster,
      { "Network ID cluster", "sccp.isni.cluster",
	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sccp_xudt_msg_fragments,
	{"Message fragments", "sccp.msg.fragments",
	FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment,
	{"Message fragment", "sccp.msg.fragment",
	FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment_overlap,
	{"Message fragment overlap", "sccp.msg.fragment.overlap",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment_overlap_conflicts,
	{"Message fragment overlapping with conflicting data", "sccp.msg.fragment.overlap.conflicts",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment_multiple_tails,
	{"Message has multiple tail fragments", "sccp.msg.fragment.multiple_tails",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment_too_long_fragment,
	{"Message fragment too long", "sccp.msg.fragment.too_long_fragment",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment_error,
	{"Message defragmentation error", "sccp.msg.fragment.error",
	FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_fragment_count,
	{"Message fragment count", "sccp.msg.fragment.count",
	FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_reassembled_in,
	{"Reassembled in", "sccp.msg.reassembled.in",
	FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_sccp_xudt_msg_reassembled_length,
	{"Reassembled SCCP length", "sccp.msg.reassembled.length",
	FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_sccp_assoc_id,
      { "Association ID", "sccp.assoc.id",
	FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sccp_assoc_msg,
	{"Message in frame", "sccp.assoc.msg",
	FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sccp,
    &ett_sccp_called,
    &ett_sccp_called_ai,
    &ett_sccp_called_pc,
    &ett_sccp_called_gt,
    &ett_sccp_called_gt_digits,
    &ett_sccp_calling,
    &ett_sccp_calling_ai,
    &ett_sccp_calling_pc,
    &ett_sccp_calling_gt,
    &ett_sccp_calling_gt_digits,
    &ett_sccp_sequencing_segmenting,
    &ett_sccp_segmentation,
    &ett_sccp_ansi_isni_routing_control,
    &ett_sccp_xudt_msg_fragment,
    &ett_sccp_xudt_msg_fragments,
    &ett_sccp_assoc
  };


  static uat_field_t users_flds[] = {
		UAT_FLD_DEC(sccp_users, ni, "Network Indicator", "Network Indicator"),
		UAT_FLD_RANGE(sccp_users, called_pc, "Called DPCs", 0xFFFFFF, "DPCs for which this protocol is to be used"),
		UAT_FLD_RANGE(sccp_users, called_ssn, "Called SSNs", 255, "Called SSNs for which this protocol is to be used"),
		UAT_FLD_VS(sccp_users, user, "User protocol", sccp_users_vals, "The User Protocol"),
		UAT_END_FIELDS
  };


  uat_t* users_uat = uat_new("SCCP Users Table", sizeof(sccp_user_t),
			     "sccp_users", TRUE, (void*) &sccp_users,
			     &num_sccp_users, UAT_CAT_PORTS, "ChSccpUsers",
			     sccp_users_copy_cb, sccp_users_update_cb,
			     sccp_users_free_cb, NULL, users_flds );

 /* Register the protocol name and description */
  proto_sccp = proto_register_protocol("Signalling Connection Control Part",
				       "SCCP", "sccp");

  register_dissector("sccp", dissect_sccp, proto_sccp);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sccp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  sccp_ssn_dissector_table = register_dissector_table("sccp.ssn", "SCCP SSN", FT_UINT8, BASE_DEC);

  register_heur_dissector_list("sccp", &heur_subdissector_list);

  sccp_module = prefs_register_protocol(proto_sccp, proto_reg_handoff_sccp);

  prefs_register_uint_preference(sccp_module, "source_pc",
				 "Source PC (in hex)",
				 "The source point code (usually MSC) (to determine whether message is uplink or downlink)",
				 16, &sccp_source_pc_global);

  prefs_register_bool_preference(sccp_module, "show_length", "Show length",
				 "Show parameter length in the protocol tree",
				 &sccp_show_length);

  prefs_register_bool_preference(sccp_module, "defragment_xudt",
				 "Reassemble XUDT messages",
				 "Whether XUDT messages should be reassembled",
				 &sccp_xudt_desegment);

  prefs_register_bool_preference(sccp_module, "trace_sccp",
				 "Trace Associations",
				 "Whether to keep information about messages and their associations",
				 &trace_sccp);


  prefs_register_bool_preference(sccp_module, "show_more_info",
				 "Show key parameters in Info Column",
				 "Show SLR, DLR, and CAUSE Parameters in the Information Column of the Summary",
				 &show_key_params);


  prefs_register_uat_preference(sccp_module, "users_table", "Users Table",
				 "A table that enumerates user protocols to be used against specific PCs and SSNs",
				 users_uat);

  prefs_register_bool_preference(sccp_module, "set_addresses", "Set source and destination GT addresses",
				 "Set the source and destination addresses to the GT digits (if RI=GT)."
				 "  This may affect TCAP's ability to recognize which messages belong to which TCAP session.", &set_addresses);

  prefs_register_string_preference(sccp_module, "default_payload", "Default Payload",
				   "The protocol which should be used to dissect the payload if nothing else has claimed it",
				   &default_payload);

  register_init_routine(&init_sccp);

  assocs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "sccp_associations");

  sccp_tap = register_tap("sccp");

}

void
proto_reg_handoff_sccp(void)
{
  dissector_handle_t sccp_handle;

  static gboolean initialised=FALSE;

  if (!initialised) {
    sccp_handle = find_dissector("sccp");

    dissector_add_uint("wtap_encap", WTAP_ENCAP_SCCP, sccp_handle);
    dissector_add_uint("mtp3.service_indicator", SCCP_SI, sccp_handle);
    dissector_add_string("tali.opcode", "sccp", sccp_handle);

    data_handle = find_dissector("data");
    tcap_handle = find_dissector("tcap");
    ranap_handle = find_dissector("ranap");
    bssap_handle = find_dissector("bssap");
    gsmmap_handle = find_dissector("gsm_map");
    camel_handle = find_dissector("camel");
    inap_handle = find_dissector("inap");

    initialised = TRUE;
  }

  default_handle = find_dissector(default_payload);
}
