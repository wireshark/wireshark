/* packet-ansi_map.c
 * Routines for ANSI 41 Mobile Application Part (IS41 MAP) dissection
 * Specications from 3GPP2 (www.3gpp2.org)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Should be very close to what ANSI/TIA/EIA-41-E will be as most known
 * changes have been added:  i.e. IS-778, IS-751, IS-725, IS-841, ...
 *
 * Title		3GPP2			Other
 *
 *   Cellular Radiotelecommunications Intersystem Operations
 *			3GPP2 N.S0005-0		ANSI/TIA/EIA-41-D
 *
 *   Network Support for MDN-Based Message Centers
 *			3GPP2 N.S0024-0 v1.0	IS-841
 *
 *   Enhanced International Calling
 *			3GPP2 N.S0027		IS-875
 *
 *   E-911 Phase 2
 *			3GPP2 N.S0030		J-STD-036-A
 *	XXX Teleservice_Priority not implemented, no parameter ID given!
 *
 *   ANSI-41-D Miscellaneous Enhancements Revision 0
 *			3GPP2 N.S0015		PN-3590 (ANSI-41-E)
 *
 *   TIA/EIA-41-D Internationalization
 *			3GPP2 N.S0016-0 v1.0
 *
 *   Authentication Enhancements
 *			3GPP2 N.S0014-0 v1.0	IS-778
 *
 *   PCS Multi-band-Based on IS-41C
 *			3GPP2 N.S0006-0 v1.0	TIA/EIA TSB-76
 *
 *   Roamer Database Verification Revision B
 *			3GPP2 N.S0025-B v1.0	IS-947 (aka IS-847 ?)
 *	XXX InvokingNEType not implemented, no parameter ID given!
 *
 *   Features In CDMA
 *			3GPP2 N.S0010-0 v1.0	IS-735
 *
 *   TIA/EIA-41-D Based Network Enhancements for CDMA Packet Data Service (C-PDS), Phase 1
 *			3GPP2 N.S0029-0 v1.0	IS-880
 *
 *   OTASP and OTAPA
 *			3GPP2 N.S0011-0 v1.0	IS-725-A
 *
 *   Circuit Mode Services
 *			3GPP2 N.S0008-0 v1.0	IS-737
 *	XXX SecondInterMSCCircuitID not implemented, parameter ID conflicts with ISLP Information!
 *
 *   IMSI
 *			3GPP2 N.S0009-0 v1.0	IS-751
 *
 *   WIN Phase 1
 *			3GPP2 N.S0013-0 v1.0	IS-771
 *
 *   WIN Phase 2
 *			3GPP2 N.S0004-0 v1.0	IS-848
 *
 *   TIA/EIA-41-D Pre-Paid Charging
 *			3GPP2 N.S0018-0 v1.0	IS-826
 *
 *   User Selective Call Forwarding
 *			3GPP2 N.S0021-0 v1.0	IS-838
 *
 *   CNAP/CNAR
 *			3GPP2 N.S0012-0 v1.0
 *
 *   Answer Hold
 *			3GPP2 N.S0022-0 v1.0	IS-837
 *
 *   Automatic Code Gapping
 *			3GPP2 N.S0023-0 v1.0
 *
 *   UIM
 *			3GPP2 N.S0003
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

#include "epan/packet.h"
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-ansi_a.h"
#include "packet-ansi_map.h"
#include "packet-tcap.h"

/* PROTOTYPES/FORWARDS */

static gboolean dissect_ansi_param(ASN1_SCK *asn1, proto_tree *tree);

/* ANSI PARAM STRINGS */
static const value_string ansi_param_1_strings[] = {
    { 0x81,	"Billing ID" },
    { 0x82,	"Serving Cell ID" },
    { 0x83,	"Target Cell ID" },
    { 0x84,	"Digits" },
    { 0x85,	"Channel Data" },
    { 0x86,	"Inter MSC Circuit ID" },
    { 0x87,	"Inter Switch Count" },
    { 0x88,	"Mobile Identification Number" },
    { 0x89,	"Electronic Serial Number" },
    { 0x8A,	"Release Reason" },
    { 0x8B,	"Signal Quality" },
    { 0x8C,	"Station Class Mark" },
    { 0x8D,	"Authorization Denied" },
    { 0x8E,	"Authorization Period" },
    { 0x8F,	"Seizure Type" },
    { 0x90,	"Trunk Status" },
    { 0x91,	"Qualification Information Code" },
    { 0x92,	"Feature Result" },
    { 0x93,	"Redirection Reason" },
    { 0x94,	"Access Denied Reason" },
    { 0x95,	"MSCID" },
    { 0x96,	"System My Type Code" },
    { 0x97,	"Origination Indicator" },
    { 0x98,	"Termination Restriction Code" },
    { 0x99,	"Calling Features Indicator" },
    { 0x9A,	"Faulty Parameter" },
    { 0x9B,	"Usage Indicator" },
    { 0x9C,	"TDMA Channel Data" },
    { 0x9D,	"TDMA Call Mode" },
    { 0x9E,	"Handoff Reason" },
    { 0, NULL },
};

static const value_string ansi_param_2_strings[] = {
    { 0x9F1F,	"TDMA Burst Indicator" },
    { 0x9F20,	"PC_SSN" },
    { 0x9F21,	"Location Area ID" },
    { 0x9F22,	"System Access Type" },
    { 0x9F23,	"Authentication Response" },
    { 0x9F24,	"Authentication Response Base Station" },
    { 0x9F25,	"Authentication Response Unique Challenge" },
    { 0x9F26,	"Call History Count" },
    { 0x9F27,	"Confidentiality Modes" },
    { 0x9F28,	"Random Variable" },
    { 0x9F29,	"Random Variable Base Station" },
    { 0x9F2A,	"Random Variable SSD" },
    { 0x9F2B,	"Random Variable Unique Challenge" },
    { 0x9F2C,	"Report Type" },
    { 0x9F2D,	"Signaling Message Encryption Key" },
    { 0x9F2E,	"Shared Secret Data" },
    { 0x9F2F,	"Terminal Type" },
    { 0x9F30,	"Voice Privacy Mask" },
    { 0x9F31,	"System Capabilities" },
    { 0x9F32,	"Deny Access" },
    { 0x9F33,	"Update Count" },
    { 0x9F34,	"SSD Not Shared" },
    { 0x9F35,	"Extended MSCID" },
    { 0x9F36,	"Extended System My Type Code" },
    { 0x9F37,	"Control Channel Data" },
    { 0x9F38,	"System Access Data" },
    { 0x9F39,	"Cancellation Denied" },
    { 0x9F3A,	"Border Cell Access" },
    { 0x9F3B,	"CDMA Station Class Mark" },
    { 0x9F3C,	"CDMA Serving One Way Delay" },
    { 0x9F3D,	"CDMA Target One Way Delay" },
    { 0x9F3E,	"CDMA Call Mode" },
    { 0x9F3F,	"CDMA Channel Data" },
    { 0x9F40,	"CDMA Signal Quality" },
    { 0x9F41,	"CDMA Pilot Strength" },
    { 0x9F42,	"CDMA Mobile Protocol Revision" },
    { 0x9F43,	"CDMA Private Long Code Mask" },
    { 0x9F44,	"CDMA Code Channel" },
    { 0x9F45,	"CDMA Search Window" },
    { 0x9F46,	"MS Location" },
    { 0x9F47,	"Page Indicator" },
    { 0x9F48,	"Received Signal Quality" },
    { 0x9F49,	"Deregistration Type" },
    { 0x9F4A,	"NAMPS Channel Data" },
    { 0x9F4B,	"Alert Code" },
    { 0x9F4C,	"Announcement Code" },
    { 0x9F4D,	"Authentication Algorithm Version" },
    { 0x9F4E,	"Authentication Capability" },
    { 0x9F4F,	"Call History Count Expected" },
    { 0x9F50,	"Calling Party Number Digits 1" },
    { 0x9F51,	"Calling Party Number Digits 2" },
    { 0x9F52,	"Calling Party Number String 1" },
    { 0x9F53,	"Calling Party Number String 2" },
    { 0x9F54,	"Calling Party Subaddress" },
    { 0x9F55,	"Cancellation Type" },
    { 0x9F56,	"Carrier Digits" },
    { 0x9F57,	"Destination Digits" },
    { 0x9F58,	"DMH Redirection Indicator" },
    { 0xBF59,	"Inter System Termination" },
    { 0x9F5A,	"Availability Type" },
    { 0xBF5B,	"Local Termination" },
    { 0x9F5C,	"Message Waiting Notification Count" },
    { 0x9F5D,	"Mobile Directory Number" },
    { 0x9F5E,	"MSCID Number" },
    { 0xBF5F,	"PSTN Termination" },
    { 0x9F60,	"No Answer Time" },
    { 0x9F61,	"One Time Feature Indicator" },
    { 0x9F62,	"Origination Triggers" },
    { 0x9F63,	"RANDC" },
    { 0x9F64,	"Redirecting Number Digits" },
    { 0x9F65,	"Redirecting Number String" },
    { 0x9F66,	"Redirecting Subaddress" },
    { 0x9F67,	"Sender Identification Number" },
    { 0x9F68,	"SMS Address" },
    { 0x9F69,	"SMS Bearer Data" },
    { 0x9F6A,	"SMS Charge Indicator" },
    { 0x9F6B,	"SMS Destination Address" },
    { 0x9F6C,	"SMS Message Count" },
    { 0x9F6D,	"SMS Notification Indicator" },
    { 0x9F6E,	"SMS Original Destination Address" },
    { 0x9F6F,	"SMS Original Destination Subaddress" },
    { 0x9F70,	"SMS Original Originating Address" },
    { 0x9F71,	"SMS Original Originating Subaddress" },
    { 0x9F72,	"SMS Originating Address" },
    { 0x9F73,	"SMS Originating Restrictions" },
    { 0x9F74,	"SMS Teleservice Identifier" },
    { 0x9F75,	"SMS Termination Restrictions" },
    { 0x9F76,	"SMS Message Waiting Indicator" },
    { 0x9F77,	"Termination Access Type" },
    { 0xBF78,	"Termination List" },
    { 0x9F79,	"Termination Treatment" },
    { 0x9F7A,	"Termination Triggers" },
    { 0x9F7B,	"Transaction Capability" },
    { 0x9F7C,	"Unique Challenge Report" },
    { 0, NULL },
};

static const value_string ansi_param_3_strings[] = {
    { 0x9F8100,	"Action Code" },
    { 0x9F8101,	"Alert Result" },
    { 0xBF8102,	"Announcement List" },
    { 0xBF8103,	"CDMA Code Channel Information" },
    { 0xBF8104,	"CDMA Code Channel List" },
    { 0xBF8105,	"CDMA Target Measurement Information" },
    { 0xBF8106,	"CDMA Target Measurement List" },
    { 0xBF8107,	"CDMA Target MAHO Information" },
    { 0xBF8108,	"CDMA Target MAHO List" },
    { 0x9F8109,	"Conference Calling Indicator" },
    { 0x9F810A,	"Count Update Report" },
    { 0x9F810B,	"Digit Collection Control" },
    { 0x9F810C,	"DMH Account Code Digits" },
    { 0x9F810D,	"DMH Alternate Billing Digits" },
    { 0x9F810E,	"DMH Billing Digits" },
    { 0x9F810F,	"Geographic Authorization" },
    { 0x9F8110,	"Leg Information" },
    { 0x9F8111,	"Message Waiting Notification Type" },
    { 0x9F8112,	"PACA Indicator" },
    { 0x9F8113,	"Preferred Language Indicator" },
    { 0x9F8114,	"Random Valid Time" },
    { 0x9F8115,	"Restriction Digits" },
    { 0x9F8116,	"Routing Digits" },
    { 0x9F8117,	"Setup Result" },
    { 0x9F8118,	"SMS Access Denied Reason" },
    { 0x9F8119,	"SMS Cause Code" },
    { 0x9F811A,	"SPINI PIN" },
    { 0x9F811B,	"SPINI Triggers" },
    { 0x9F811C,	"SSD Update Report" },
    { 0xBF811D,	"Target Measurement Information" },
    { 0xBF811E,	"Target Measurement List" },
    { 0x9F811F,	"Voice Mailbox PIN" },
    { 0x9F8120,	"Voice Mailbox Number" },
    { 0x9F8121,	"Authentication Data" },
    { 0x9F8122,	"Conditionally Denied Reason" },
    { 0x9F8123,	"Group Information" },
    { 0x9F8124,	"Handoff State" },
    { 0x9F8125,	"NAMPS Call Mode" },
    { 0x9F8126,	"CDMA Slot Cycle Index" },
    { 0x9F8127,	"Denied Authorization Period" },
    { 0x9F8128,	"Pilot Number" },
    { 0x9F8129,	"Pilot Billing ID" },
    { 0x9F812A,	"CDMA Band Class" },
    { 0xBF812B,	"CDMA Band Class Information" },
    { 0xBF812C,	"CDMA Band Class List" },
    { 0x9F812D,	"CDMA Pilot PN" },
    { 0x9F812E,	"CDMA Service Configuration Record" },
    { 0x9F812F,	"CDMA Service Option" },
    { 0xBF8130,	"CDMA Service Option List" },
    { 0x9F8131,	"CDMA Station Class Mark 2" },
    { 0x9F8132,	"TDMA Service Code" },
    { 0x9F8133,	"TDMA Terminal Capability" },
    { 0x9F8134,	"TDMA Voice Coder" },
    { 0x9F8135,	"A-Key Protocol Version" },
    { 0x9F8136,	"Authentication Response Reauthentication" },
    { 0x9F8137,	"Base Station Partial Key" },
    { 0x9F8138,	"Mobile Station MIN" },
    { 0x9F8139,	"Mobile Station Partial Key" },
    { 0x9F813A,	"Modulus Value" },
    { 0x9F813B,	"Newly Assigned MIN" },
    { 0x9F813D,	"OTASP Result Code" },
    { 0x9F813E,	"Primitive Value" },
    { 0x9F813F,	"Random Variable Reauthentication" },
    { 0x9F8140,	"Reauthentication Report" },
    { 0x9F8141,	"Service Indicator" },
    { 0x9F8142,	"Signaling Message Encryption Report" },
    { 0x9F8143,	"Temporary Reference Number" },
    { 0x9F8144,	"Voice Privacy Report" },
    { 0x9F8145,	"Base Station Manufacturer Code" },
    { 0x9F8146,	"BSMC Status" },
    { 0x9F8147,	"Control Channel Mode" },
    { 0x9F8148,	"Non Public Data" },
    { 0x9F8149,	"Paging Frame Class" },
    { 0x9F814A,	"PSID RSID Information" },
    { 0xBF814B,	"PSID RSID List" },
    { 0x9F814C,	"Services Result" },
    { 0x9F814D,	"SOC Status" },
    { 0x9F814E,	"System Operator Code" },
    { 0xBF814F,	"Target Cell ID List" },
    { 0x9F8150,	"User Group" },
    { 0x9F8151,	"User Zone Data" },
    { 0x9F8152,	"CDMA Connection Reference" },
    { 0xBF8153,	"CDMA Connection Reference Information" },
    { 0xBF8154,	"CDMA Connection Reference List" },
    { 0x9F8155,	"CDMA State" },
    { 0x9F8156,	"Change Service Attributes" },
    { 0x9F8157,	"Data Key" },
    { 0x9F8158,	"Data Privacy Parameters" },
    { 0x9F8159,	"ISLP Information" }, /* IS-737 *SPEC CONFLICT* */
    { 0x9F815A,	"Reason List" },
    { 0x9F815B,	"Second Inter MSC Circuit ID" },
    { 0x9F815C,	"TDMA Bandwidth" },
    { 0x9F815D,	"TDMA Data Features Indicator" },
    { 0x9F815E,	"TDMA Data Mode" },
    { 0x9F815F,	"TDMA Voice Mode" },
    { 0x9F8160,	"Analog Redirect Info" },
    { 0xBF8161,	"Analog Redirect Record" },
    { 0x9F8162,	"CDMA Channel Number" },
    { 0xBF8163,	"CDMA Channel Number List" },
    { 0xBF8164,	"CDMA Power Combined Indicator" },
    { 0x9F8165,	"CDMA Redirect Record" },
    { 0x9F8166,	"CDMA Search Parameters" },
    { 0x9F8168,	"CDMA Network Identification" },
    { 0x9F8169,	"Network TMSI" },
    { 0x9F816A,	"Network TMSI Expiration Time" },
    { 0x9F816B,	"New Network TMSI" },
    { 0x9F816C,	"Required Parameters Mask" },
    { 0x9F816D,	"Service Redirection Cause" },
    { 0x9F816E,	"Service Redirection Info" },
    { 0x9F816F,	"Roaming Indication" },
    { 0x9F8170,	"Emergency Services Routing Digits" },
    { 0x9F8171,	"Special Handling" },
    { 0x9F8172,	"International Mobile Subscriber Identity" },
    { 0x9F8173,	"Calling Party Name" },
    { 0x9F8174,	"Display Text" },
    { 0x9F8175,	"Redirecting Party Name" },
    { 0x9F8176,	"Service ID" },
    { 0x9F8177,	"All Or None" },
    { 0x9F8178,	"Change" },
    { 0xBF8179,	"Data Access Element" },
    { 0xBF817A,	"Data Access Element List" },
    { 0x9F817B,	"Data ID" },
    { 0x9F817C,	"Database Key" },
    { 0x9F817D,	"Data Result" },
    { 0xBF817E,	"Data Update Result" },
    { 0xBF817F,	"Data Update Result List" },
    { 0x9F8200,	"Data Value" },
    { 0xBF8202,	"Execute Script" },
    { 0x9F8203,	"Failure Cause" },
    { 0x9F8204,	"Failure Type" },
    { 0x9F8205,	"Global Title" },
    { 0xBF8206,	"Modification Request" },
    { 0xBF8207,	"Modification Request List" },
    { 0xBF8208,	"Modification Result List" },
    { 0x9F8209,	"Private Specialized Resource" },
    { 0x9F820B,	"Script Argument" },
    { 0x9F820C,	"Script Name" },
    { 0x9F820D,	"Script Result" },
    { 0xBF820E,	"Service Data Access Element" },
    { 0xBF820F,	"Service Data Access Element List" },
    { 0xBF8210,	"Service Data Result" },
    { 0xBF8211,	"Service Data Result List" },
    { 0x9F8212,	"Specialized Resource" },
    { 0x9F8213,	"Time Date Offset" },
    { 0xBF8214,	"Trigger Address List" },
    { 0x9F8215,	"Trigger Capability" },
    { 0xBF8216,	"Trigger List" },
    { 0x9F8217,	"Trigger Type" },
    { 0xBF8218,	"WIN Capability" },
    { 0x9F8219,	"WIN Operations Capability" },
    { 0x9F821B,	"WIN Trigger List" },
    { 0x9F821C,	"MSC Address" },
    { 0x9F821D,	"Suspicious Access" },
    { 0x9F821E,	"Mobile Station IMSI" },
    { 0x9F821F,	"Newly Assigned IMSI" },
    { 0x9F822A,	"Command Code" },
    { 0x9F822B,	"Display Text 2" },
    { 0x9F822C,	"Page Count" },
    { 0x9F822D,	"Page Response Time" },
    { 0x9F822E,	"SMS Transaction ID" },
    { 0x9F823C,	"CAVE Key" },
    { 0x9F8241,	"CDMA2000 Mobile Supported Capabilities" },
    { 0x9F8245,	"Enhanced Privacy Encryption Report" },
    { 0x9F8246,	"Inter Message Time" },
    { 0x9F8247,	"MSID Usage" },
    { 0x9F8248,	"New MIN Extension" },
    { 0x9F825C,	"QoS Priority" },
    { 0x9F825F,	"CDMA MS Measured Channel Identity" },
    { 0x9F8264,	"CDMA2000 Handoff Invoke IOS Data" },
    { 0x9F8265,	"CDMA2000 Handoff Response IOS Data" },
    { 0x9F8304,	"MIN Extension" },

    { 0xBF822F,	"Call Recovery ID" },
    { 0xBF8230,	"Call Recovery ID List" },
    { 0xBF8250,	"Position Information" },
    { 0xBF825A,	"CDMA PSMM List" },
    { 0x9F820A,	"Resume PIC" },
    { 0x9F8231,	"DMH Service ID" },
    { 0x9F8232,	"Feature Indicator" },
    { 0x9F8233,	"Control Network ID" },
    { 0x9F8234,	"Release Cause" },
    { 0x9F8235,	"Time Of Day" },
    { 0x9F8236,	"Call Status" },
    { 0x9F8237,	"DMH Charge Information" },
    { 0x9F8238,	"DMH Billing Indicator" },
    { 0x9F8239,	"MS Status" },
    { 0x9F823B,	"Position Information Code" },
    { 0x9F8249,	"DTX Indication" },
    { 0x9F824A,	"CDMA Mobile Capabilities" },
    { 0x9F824B,	"Generalized Time" },
    { 0x9F824C,	"Generic Digits" },
    { 0x9F824D,	"Geographic Position" },
    { 0x9F824E,	"Mobile Call Status" },
    { 0x9F824F,	"Mobile Position Capability" },
    { 0x9F8251,	"Position Request Type" },
    { 0x9F8252,	"Position Result" },
    { 0x9F8253,	"Position Source" },
    { 0x9F8254,	"ACG Encountered" },
    { 0x9F8255,	"Control Type" },
    { 0x9F8256,	"Gap Duration" },
    { 0x9F8257,	"SCF Overload Gap Interval" },
    { 0x9F8258,	"Service Management System Gap Interval" },
    { 0x9F8259,	"CDMA PSMM Count" },
    { 0x9F825B,	"CDMA Serving One Way Delay 2" },
    { 0x9F825D,	"PDSN Address" },
    { 0x9F825E,	"PDSN Protocol Type" },
    { 0x9F8261,	"Range" },
    { 0x9F8263,	"Calling Party Category" },
    { 0x9F8266,	"LCS Client ID" },
    { 0x9F8267,	"TDMA MAHO Cell ID" },
    { 0x9F8268,	"TDMA MAHO Channel" },
    { 0x9F8269,	"CDMA Service Option Connection Identifier" },
    { 0x9F826A,	"TDMA Time Alignment" },
    { 0x9F826C,	"TDMA MAHO Request" },
    { 0, NULL },
};

/* ANSI TCAP component type */
#define ANSI_TC_INVOKE_L 0xe9
#define ANSI_TC_RRL 0xea
#define ANSI_TC_RE 0xeb
#define ANSI_TC_REJECT 0xec
#define ANSI_TC_INVOKE_N 0xed
#define ANSI_TC_RRN 0xee

static const value_string ansi_cmp_type_strings[] = {
    { ANSI_TC_INVOKE_L,		"Invoke(Last)" },
    { ANSI_TC_RRL,		"RetRes(Last)" },
    { ANSI_TC_RE,		"RetErr" },
    { ANSI_TC_REJECT,		"Reject" },
    { ANSI_TC_INVOKE_N,		"Invoke(Not Last)" },
    { ANSI_TC_RRN,		"RetRes(Not Last)" },
    { 0, NULL },
};

const value_string ansi_map_opr_code_strings[] = {
    { 1,	"Handoff Measurement Request" },
    { 2,	"Facilities Directive" },
    { 3,	"Mobile On Channel" },
    { 4,	"Handoff Back" },
    { 5,	"Facilities Release" },
    { 6,	"Qualification Request" },
    { 7,	"Qualification Directive" },
    { 8,	"Blocking" },
    { 9,	"Unblocking" },
    { 10,	"Reset Circuit" },
    { 11,	"Trunk Test" },
    { 12,	"Trunk Test Disconnect" },
    { 13,	"Registration Notification" },
    { 14,	"Registration Cancellation" },
    { 15,	"Location Request" },
    { 16,	"Routing Request" },
    { 17,	"Feature Request" },
    { 18,	"Reserved 18 (Service Profile Request, IS-41-C)" },
    { 19,	"Reserved 19 (Service Profile Directive, IS-41-C)" },
    { 20,	"Unreliable Roamer Data Directive" },
    { 21,	"Reserved 21 (Call Data Request, IS-41-C)" },
    { 22,	"MS Inactive" },
    { 23,	"Transfer To Number Request" },
    { 24,	"Redirection Request" },
    { 25,	"Handoff To Third" },
    { 26,	"Flash Request" },
    { 27,	"Authentication Directive" },
    { 28,	"Authentication Request" },
    { 29,	"Base Station Challenge" },
    { 30,	"Authentication Failure Report" },
    { 31,	"Count Request" },
    { 32,	"Inter System Page" },
    { 33,	"Unsolicited Response" },
    { 34,	"Bulk Deregistration" },
    { 35,	"Handoff Measurement Request 2" },
    { 36,	"Facilities Directive 2" },
    { 37,	"Handoff Back 2" },
    { 38,	"Handoff To Third 2" },
    { 39,	"Authentication Directive Forward" },
    { 40,	"Authentication Status Report" },
    { 41,	"Reserved 41" },
    { 42,	"Information Directive" },
    { 43,	"Information Forward" },
    { 44,	"Inter System Answer" },
    { 45,	"Inter System Page 2" },
    { 46,	"Inter System Setup" },
    { 47,	"Origination Request" },
    { 48,	"Random Variable Request" },
    { 49,	"Redirection Directive" },
    { 50,	"Remote User Interaction Directive" },
    { 51,	"SMS Delivery Backward" },
    { 52,	"SMS Delivery Forward" },
    { 53,	"SMS Delivery Point to Point" },
    { 54,	"SMS Notification" },
    { 55,	"SMS Request" },
    { 56,	"OTASP Request" },
    { 57,	"Information Backward" },
    { 58,	"Change Facilities" },
    { 59,	"Change Service" },
    { 60,	"Parameter Request" },
    { 61,	"TMSI Directive" },
    { 62,	"Reserved 62" },
    { 63,	"Service Request" },
    { 64,	"Analyzed Information Request" },
    { 65,	"Connection Failure Report" },
    { 66,	"Connect Resource" },
    { 67,	"Disconnect Resource" },
    { 68,	"Facility Selected and Available" },
    { 69,	"Instruction Request" },
    { 70,	"Modify" },
    { 71,	"Reset Timer" },
    { 72,	"Search" },
    { 73,	"Seize Resource" },
    { 74,	"SRF Directive" },
    { 75,	"T Busy" },
    { 76,	"T NoAnswer" },
    { 77,	"Release" },
    { 78,	"SMS Delivery Point to Point Ack" },
    { 79,	"Message Directive" },
    { 80,	"Bulk Disconnection" },
    { 81,	"Call Control Directive" },
    { 82,	"O Answer" },
    { 83,	"O Disconnect" },
    { 84,	"Call Recovery Report" },
    { 85,	"T Answer" },
    { 86,	"T Disconnect" },
    { 87,	"Unreliable Call Data" },
    { 88,	"O CalledPartyBusy" },
    { 89,	"O NoAnswer" },
    { 90,	"Position Request" },
    { 91,	"Position Request Forward" },
    { 92,	"Call Termination Report" },
    { 93,	"Geo Position Directive" },
    { 94,	"Geo Position Request" },
    { 95,	"Inter System Position Request" },
    { 96,	"Inter System Position Request Forward" },
    { 97,	"ACG Directive" },
    { 98,	"Roamer Database Verification Request" },
    { 99,	"Add Service" },
    { 100,	"Drop Service" },
    { 0, NULL },
};

static const value_string ansi_tele_strings[] = {
    { 1,	"Reserved for maintenance" },
    { 4096,	"AMPS Extended Protocol Enhanced Services" },
    { 4097,	"CDMA Cellular Paging Teleservice" },
    { 4098,	"CDMA Cellular Messaging Teleservice" },
    { 4099,	"CDMA Voice Mail Notification" },
    { 32513,	"TDMA Cellular Messaging Teleservice" },
    { 32520,	"TDMA System Assisted Mobile Positioning through Satellite (SAMPS)" },
    { 32584,	"TDMA Segmented System Assisted Mobile Positioning Service" },
    { 0, NULL },
};

#define	NUM_BAND_CLASS_STR	(sizeof(band_class_str)/sizeof(gchar *))
static const gchar *band_class_str[] = {
    "800 MHz Cellular System",
    "1.850 to 1.990 GHz Broadband PCS",
    "872 to 960 MHz TACS Band",
    "832 to 925 MHz JTACS Band",
    "1.750 to 1.870 GHz Korean PCS",
    "450 MHz NMT",
    "2 GHz IMT-2000 Band",
    "North American 700 MHz Cellular Band",
    "1.710 to 1.880 GHz PCS",
    "880 to 960 MHz Band",
    "Secondary 800 MHz Band",
    "400 MHz European PAMR Band",
    "800 MHz European PAMR Band"
};

#define	NUM_QOS_PRI_STR		(sizeof(qos_pri_str)/sizeof(gchar *))
static const gchar *qos_pri_str[] = {
    "Priority Level 0.  This is the lowest level",
    "Priority Level 1",
    "Priority Level 2",
    "Priority Level 3",
    "Priority Level 4",
    "Priority Level 5",
    "Priority Level 6",
    "Priority Level 7",
    "Priority Level 8",
    "Priority Level 9",
    "Priority Level 10",
    "Priority Level 11",
    "Priority Level 12",
    "Priority Level 13",
    "Reserved, treat as Priority Level 14",
    "Reserved, treat as Priority Level 15"
};

/*
 * would prefer to have had the define set to the exact number of
 * elements in the array but that is not without it's own problems
 * (sizeof(ansi_a_ios401_elem_1_strings)/sizeof(value_string))
 */
#define	NUM_IOS401_ELEM	ANSI_A_MAX_NUM_IOS401_ELEM_1_STRINGS
static gint ett_ansi_map_ios401_elem[NUM_IOS401_ELEM];


/* Initialize the protocol and registered fields */
static int proto_ansi_map = -1;

static int ansi_map_tap = -1;

static int hf_ansi_map_tag = -1;
static int hf_ansi_map_length = -1;
static int hf_ansi_map_id = -1;
static int hf_ansi_map_opr_code = -1;
static int hf_ansi_map_param_id = -1;
static int hf_ansi_map_ios401_elem_id = -1;
static int hf_ansi_map_min = -1;
static int hf_ansi_map_number = -1;

static int hf_ansi_map_billing_id = -1;

/* Initialize the subtree pointers */
static gint ett_ansi_map = -1;
static gint ett_opr_code = -1;
static gint ett_component = -1;
static gint ett_components = -1;
static gint ett_params = -1;
static gint ett_param = -1;
static gint ett_error = -1;
static gint ett_problem = -1;
static gint ett_natnum = -1;
static gint ett_call_mode = -1;
static gint ett_chan_data = -1;
static gint ett_code_chan = -1;
static gint ett_clr_dig_mask = -1;
static gint ett_ent_dig_mask = -1;
static gint ett_all_dig_mask = -1;


static char bigbuf[1024];
static dissector_handle_t data_handle;
static dissector_table_t is637_tele_id_dissector_table; /* IS-637 Teleservice ID */
static dissector_table_t is683_dissector_table; /* IS-683-A (OTA) */
static dissector_table_t is801_dissector_table; /* IS-801 (PLD) */
static packet_info *g_pinfo;
static proto_tree *g_tree;
static gint32 ansi_map_sms_tele_id = -1;
static gboolean is683_ota;
static gboolean is801_pld;
static gboolean ansi_map_is_invoke;
static tvbuff_t *bd_tvb;


typedef struct dgt_set_t
{
    unsigned char out[15];
}
dgt_set_t;

static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
    }
};

static dgt_set_t Dgt_msid = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
    }
};

/* FUNCTIONS */

/*
 * Unpack BCD input pattern into output ASCII pattern
 *
 * Input Pattern is supplied using the same format as the digits
 *
 * Returns: length of unpacked pattern
 */
static int
my_dgt_tbcd_unpack(
    char	*out,		/* ASCII pattern out */
    guchar	*in,		/* packed pattern in */
    int		num_octs,	/* Number of octets to unpack */
    dgt_set_t	*dgt		/* Digit definitions */
    )
{
    int cnt = 0;
    unsigned char i;

    while (num_octs)
    {
	/*
	 * unpack first value in byte
	 */
	i = *in++;
	*out++ = dgt->out[i & 0x0f];
	cnt++;

	/*
	 * unpack second value in byte
	 */
	i >>= 4;

	if (i == 0x0f)	/* odd number bytes - hit filler */
	    break;

	*out++ = dgt->out[i];
	cnt++;
	num_octs--;
    }

    *out = '\0';

    return(cnt);
}

/* PARAM FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_text(tree, asn1->tvb, \
	    asn1->offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
	asn1->offset += ((edc_len) - (edc_max_len)); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_text(tree, asn1->tvb, \
	    asn1->offset, (sdc_len), "Short Data (?)"); \
	asn1->offset += (sdc_len); \
	return; \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_text(tree, asn1->tvb, \
	    asn1->offset, (edc_len), "Unexpected Data Length"); \
	asn1->offset += (edc_len); \
	return; \
    }

static void
param_mscid(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 market_id, switch_num;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &market_id);
    asn1_int32_value_decode(asn1, 1, &switch_num);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Market ID %u  Switch Number %u",
	market_id, switch_num);
}

static void
param_page_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Page"; break;
    case 2: str = "Listen only"; break;
    default:
	if ((value >= 3) && (value <= 223)) { str = "Reserved, treat as Page"; }
	else { str = "Reserved for protocol extension, treat as Page"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_srvc_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Undefined Service"; break;
    case 1: str = "CDMA OTASP Service"; is683_ota = TRUE; break;
    case 2: str = "TDMA OTASP Service"; break;
    case 3: str = "CDMA OTAPA Service"; is683_ota = TRUE; break;
    case 4: str = "CDMA Position Determination Service";  is801_pld = TRUE; break;
    case 5: str = "AMPS Position Determination Service"; break;
    default:
	if ((value >= 6) && (value <= 223)) { str = "Reserved, treat as Undefined Service"; }
	else { str = "Reserved for protocol extension, treat as Undefined Service"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);
}

static void
param_sme_report(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Signaling Message Encryption enabling not attempted"; break;
    case 2: str = "Signaling Message Encryption enabling no response"; break;
    case 3: str = "Signaling Message Encryption is enabled"; break;
    case 4: str = "Signaling Message Encryption enabling failed"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Signaling Message Encryption enabling not attempted"; }
	else { str = "Reserved for protocol extension, treat as Signaling Message Encryption enabling not attempted"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);
}

static void
param_alert_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xc0) >> 6)
    {
    case 0: str = "Medium"; break;
    case 1: str = "High"; break;
    case 2: str = "Low"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Pitch, %s",
	bigbuf,
	str);

    switch (value & 0x3f)
    {
    case 0: str = "NoTone"; break;
    case 1: str = "Long"; break;
    case 2: str = "ShortShort"; break;
    case 3: str = "ShortShortLong"; break;
    case 4: str = "ShortShort2"; break;
    case 5: str = "ShortLongShort"; break;
    case 6: str = "ShortShortShortShort"; break;
    case 7: str = "PBXLong"; break;
    case 8: str = "PBXShortShort"; break;
    case 9: str = "PBXShortShortLong"; break;
    case 10: str = "PBXShortLongShort"; break;
    case 11: str = "PBXShortShortShortShort"; break;
    case 12: str = "PipPipPipPip"; break;
    default:
	str = "Reserved, treat as NoTone";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Cadence, %s",
	bigbuf,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x07)
    {
    case 0: str = "Alert without waiting to report"; break;
    case 1: str = "Apply a reminder alert once"; break;
    default:
	str = "Reserved, treat as Alert without waiting to report";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Alert Action, %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_term_acc_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 252: str = "Mobile-to-Mobile Directory Number access"; break;
    case 253: str = "Land-to-Mobile Directory Number access"; break;
    case 254: str = "Land-to-Mobile Directory Number access"; break;
    case 255: str = "Roamer port access"; break;
    default:
	if ((value >= 1) && (value <= 127)) { str = "Reserved for controlling system assignment"; }
	else if ((value >= 128) && (value <= 160)) { str = "Reserved for protocol extension, treat as Land-to-Mobile Directory Number access"; }
	else { str = "Reserved"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_term_treat(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "MS Termination"; break;
    case 2: str = "Voice Mail Storage"; break;
    case 3: str = "Voice Mail Retrieval"; break;
    case 4: str = "Dialogue Termination"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Unrecognized parameter value"; }
	else { str = "Reserved for protocol extension, treat as Unrecognized parameter value"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_term_trig(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xc0) >> 6)
    {
    case 0: str = "No Answer Call"; break;
    case 1: str = "No Answer Trigger"; break;
    case 2: str = "No Answer Leg"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  No Answer (NA), %s",
	bigbuf,
	str);

    switch ((value & 0x30) >> 4)
    {
    case 0: str = "No Page Response Call"; break;
    case 1: str = "No Page Response Trigger"; break;
    case 2: str = "No Page Response Leg"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  No Page Response (NPR), %s",
	bigbuf,
	str);

    switch ((value & 0x0c) >> 2)
    {
    case 0: str = "Failed Call"; break;
    case 1: str = "Routing Failure Trigger"; break;
    case 2: str = "Failed Leg"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Routing Failure (RF), %s",
	bigbuf,
	str);

    switch (value & 0x03)
    {
    case 0: str = "Busy Call"; break;
    case 1: str = "Busy Trigger"; break;
    case 2: str = "Busy Leg"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Busy, %s",
	bigbuf,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfe, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  None Reachable (NR), %s",
	bigbuf,
	(value & 0x01) ? "Group Not Reachable" : "Member Not Reachable");

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_aav(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value as used in the CAVE algorithm (%u)",
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_ann_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Dialtone"; break;
    case 1: str = "Ringback or Audible Alerting"; break;
    case 2: str = "Intercept or Mobile Reorder"; break;
    case 3: str = "Congestion or Reorder"; break;
    case 4: str = "Busy"; break;
    case 5: str = "Confirmation"; break;
    case 6: str = "Answer"; break;
    case 7: str = "Call Waiting"; break;
    case 8: str = "Offhook"; break;
    case 17: str = "Recall Dial"; break;
    case 18: str = "Barge In"; break;
    case 20: str = "PPC Insufficient"; break;
    case 21: str = "PPC Warning 1"; break;
    case 22: str = "PPC Warning 2"; break;
    case 23: str = "PPC Warning 3"; break;
    case 24: str = "PPC Disconnect"; break;
    case 25: str = "PPC Redirect"; break;
    case 63: str = "Tones Off"; break;
    case 192: str = "Pip"; break;
    case 193: str = "Abbreviated Intercept"; break;
    case 194: str = "Abbreviated Congestion"; break;
    case 195: str = "Warning"; break;
    case 196: str = "Denial Tone Burst"; break;
    case 197: str = "Dial Tone Burst"; break;
    case 250: str = "Incoming Additional Call"; break;
    case 251: str = "Priority Additional Call"; break;
    default:
	str = "Reserved, treat as Tones Off";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Tone %u, %s",
	bigbuf,
	value,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x0f)
    {
    case 0: str = "Concurrent"; break;
    case 1: str = "Sequential"; break;
    default:
	if ((value >= 2) && (value <= 7)) { str = "Reserved, treat as Concurrent"; }
	else { str = "Reserved, treat as Sequential"; }
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Class %s",
	bigbuf,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "None"; break;
    case 1: str = "Unauthorized User"; break;
    case 2: str = "Invalid ESN"; break;
    case 3: str = "Unauthorized Mobile"; break;
    case 4: str = "Suspended Origination"; break;
    case 5: str = "Origination Denied"; break;
    case 6: str = "Service Area Denial"; break;
    case 16: str = "Partial Dial"; break;
    case 17: str = "Require 1 Plus"; break;
    case 18: str = "Require 1 Plus NPA"; break;
    case 19: str = "Require 0 Plus"; break;
    case 20: str = "Require 0 Plus NPA"; break;
    case 21: str = "Deny 1 Plus"; break;
    case 22: str = "Unsupported 10 plus"; break;
    case 23: str = "Deny 10 plus"; break;
    case 24: str = "Unsupported 10 XXX"; break;
    case 25: str = "Deny 10 XXX"; break;
    case 26: str = "Deny 10 XXX Locally"; break;
    case 27: str = "Require 10 Plus"; break;
    case 28: str = "Require NPA"; break;
    case 29: str = "Deny Toll Origination"; break;
    case 30: str = "Deny International Origination"; break;
    case 31: str = "Deny 0 Minus"; break;
    case 48: str = "Deny Number"; break;
    case 49: str = "Alternate Operator Services"; break;
    case 64: str = "No Circuit or All Circuits Busy or FacilityProblem"; break;
    case 65: str = "Overload"; break;
    case 66: str = "Internal Office Failure"; break;
    case 67: str = "No Wink Received"; break;
    case 68: str = "Interoffice Link Failure"; break;
    case 69: str = "Vacant"; break;
    case 70: str = "Invalid Prefix or Invalid Access Code"; break;
    case 71: str = "Other Dialing Irregularity"; break;
    case 80: str = "Vacant Number or Disconnected Number"; break;
    case 81: str = "Deny Termination"; break;
    case 82: str = "Suspended Termination"; break;
    case 83: str = "Changed Number"; break;
    case 84: str = "Inaccessible Subscriber"; break;
    case 85: str = "Deny Incoming Toll"; break;
    case 86: str = "Roamer Access Screening"; break;
    case 87: str = "Refuse Call"; break;
    case 88: str = "Redirect Call"; break;
    case 89: str = "No Page Response"; break;
    case 90: str = "No Answer"; break;
    case 96: str = "Roamer Intercept"; break;
    case 97: str = "General Information"; break;
    case 112: str = "Unrecognized Feature Code"; break;
    case 113: str = "Unauthorized Feature Code"; break;
    case 114: str = "Restricted Feature Code"; break;
    case 115: str = "Invalid Modifier Digits"; break;
    case 116: str = "Successful Feature Registration"; break;
    case 117: str = "Successful Feature Deregistration"; break;
    case 118: str = "Successful Feature Activation"; break;
    case 119: str = "Successful Feature Deactivation"; break;
    case 120: str = "Invalid Forward To Number"; break;
    case 121: str = "Courtesy Call Warning"; break;
    case 128: str = "Enter PIN Send Prompt"; break;
    case 129: str = "Enter PIN Prompt"; break;
    case 130: str = "Reenter PIN Send Prompt"; break;
    case 131: str = "Reenter PIN Prompt"; break;
    case 132: str = "Enter Old PIN Send Prompt"; break;
    case 133: str = "Enter Old PIN Prompt"; break;
    case 134: str = "Enter New PIN Send Prompt"; break;
    case 135: str = "Enter New PIN Prompt"; break;
    case 136: str = "Reenter New PIN Send Prompt"; break;
    case 137: str = "Reenter New PIN Prompt"; break;
    case 138: str = "Enter Password Prompt"; break;
    case 139: str = "Enter Directory Number Prompt"; break;
    case 140: str = "Reenter Directory Number Prompt"; break;
    case 141: str = "Enter Feature Code Prompt"; break;
    case 142: str = "Enter Credit Card Number Prompt"; break;
    case 143: str = "Enter Destination Number Prompt"; break;
    case 152: str = "PPC Insufficient Account Balance"; break;
    case 153: str = "PPC Five Minute Warning"; break;
    case 154: str = "PPC Three Minute Warning"; break;
    case 155: str = "PPC Two Minute Warning"; break;
    case 156: str = "PPC One Minute Warning"; break;
    case 157: str = "PPC Disconnect"; break;
    case 158: str = "PPC Redirect"; break;
    default:
	str = "Reserved, treat as None";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Standard Announcement, %s",
	bigbuf,
	str);

    if (len == 3) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Custom Announcement %u",
	bigbuf,
	value);

    EXTRANEOUS_DATA_CHECK(len, 4);
}

static void
param_alert_res(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not specified"; break;
    case 1: str = "Success"; break;
    case 2: str = "Failure"; break;
    case 3: str = "Denied"; break;
    case 4: str = "Not attempted"; break;
    case 5: str = "No page response"; break;
    case 6: str = "Busy"; break;
    default:
	str = "Reserved, treat as Not specified";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_conf_call_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = ", Not specified"; break;
    case 255: str = ", Unlimited number of conferees"; break;
    default:
	str = "";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Maximum Number of Conferees, (%u)%s",
	value,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_count_upd_report(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "COUNT Update not attempted"; break;
    case 2: str = "COUNT Update no response"; break;
    case 3: str = "COUNT Update successful"; break;
    default:
	if ((value >= 4) && (value <= 223)) { str = "Reserved, treat as COUNT Update not attempted"; }
	else { str = "Reserved for protocol extension, treat as COUNT Update not attempted"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_ssd_upd_report(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "SSD Update not attempted"; break;
    case 2: str = "SSD Update no response"; break;
    case 3: str = "SSD Update successful"; break;
    case 4: str = "SSD Update failed"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as SSD Update not attempted"; }
	else { str = "Reserved for protocol extension, treat as SSD Update not attempted"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cond_den_reason(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Waitable (i.e., Call Waiting is possible)"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved, treat as Waitable"; }
	else { str = "Reserved for protocol extension, treat as Waitable"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_den_auth_per(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Per Call. Re-authorization should be attempted on the next call attempt"; break;
    case 2: str = "Hours"; break;
    case 3: str = "Days"; break;
    case 4: str = "Weeks"; break;
    case 5: str = "Per Agreement"; break;
    case 6: str = "Reserved"; break;
    case 7: str = "Number of calls. Re-authorization should be attempted after this number of (rejected) call attempts"; break;
    case 8: str = "Minutes"; break;
    default:
	if ((value >= 9) && (value <= 223)) { str = "Reserved, treat as Per Call"; }
	else { str = "Reserved for protocol extension, treat as Per Call"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Period, %s",
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_ho_state(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfe, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Party Involved (PI), %s",
	bigbuf,
	(value & 0x01) ? "Terminator is handing off" : "Originator is handing off");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_geo_auth(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Authorized for all Market IDs served by the VLR"; break;
    case 2: str = "Authorized for this Market ID only"; break;
    case 3: str = "Authorized for this Market ID and Switch Number only"; break;
    case 4: str = "Authorized for this Location Area ID within a Market ID only"; break;
    default:
	if ((value >= 5) && (value <= 95)) { str = "Reserved, treat as Authorized for all Market IDs served by the VLR"; }
	else if ((value >= 96) && (value <= 127)) { str = "Reserved for protocol extension, treat as Authorized for all Market IDs served by the VLR"; }
	else if ((value >= 128) && (value <= 223)) { str = "Reserved, treat as Authorized for this Location Area ID within a Market ID only"; }
	else { str = "Reserved for protocol extension, treat as Authorized for this Location Area ID within a Market ID only"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_mw_noti_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x0c) >> 2)
    {
    case 0: str = "No MWI. Notification is not authorized or notification is not required"; break;
    case 1: str = "Reserved"; break;
    case 2: str = "MWI On. Notification is required. Messages waiting"; break;
    case 3: str = "MWI Off. Notification is required. No messages waiting"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Message Waiting Indication (MWI), %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Alert Pip Tone (APT), %s",
	bigbuf,
	(value & 0x02) ? "notification is required" : "notification is not authorized or notification is not required");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Pip Tone (PT), %s",
	bigbuf,
	(value & 0x01) ? "notification is required" : "notification is not authorized or notification is not required");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_paca_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x1e) >> 1)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Priority Level 1"; break;
    case 2: str = "Priority Level 2"; break;
    case 3: str = "Priority Level 3"; break;
    case 4: str = "Priority Level 4"; break;
    case 5: str = "Priority Level 5"; break;
    case 6: str = "Priority Level 6"; break;
    case 7: str = "Priority Level 7"; break;
    case 8: str = "Priority Level 8"; break;
    case 9: str = "Priority Level 9"; break;
    case 10: str = "Priority Level 10"; break;
    case 11: str = "Priority Level 11"; break;
    case 12: str = "Priority Level 12"; break;
    case 13: str = "Priority Level 13"; break;
    case 14: str = "Priority Level 14"; break;
    case 15: str = "Priority Level 15"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x1e, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  PACA Level, %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  PACA is %spermanently activated",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_digit_collect_ctrl(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    proto_item *item;
    proto_tree *subtree;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Break (BRK), %s",
	bigbuf,
	(value & 0x80) ? "Break In (default)" : "No Break");

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Type Ahead (TA), %s",
	bigbuf,
	(value & 0x40) ? "Buffer (default)" : "No Type Ahead");

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Maximum Collect (%u)",
	bigbuf,
	(value & 0x1f));

    if (len == 1) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Minimum Collect (%u)",
	bigbuf,
	(value & 0x1f));

    if (len == 2) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Maximum Interaction Time (%u) seconds",
	value);

    if (len == 3) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Initial Interdigit Time (%u) seconds",
	bigbuf,
	(value & 0x1f));

    if (len == 4) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Normal Interdigit Time (%u) seconds",
	bigbuf,
	(value & 0x1f));

    if (len == 5) return;

    saved_offset = asn1->offset;

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, (len > 6) ? 2 : 1,
	    "Clear Digits Digit Mask");

    subtree = proto_item_add_subtree(item, ett_clr_dig_mask);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  7 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  6 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  5 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  4 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  3 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  2 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  0 Digit",
	bigbuf);

    if (len == 6) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  # Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  * Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  9 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  8 Digit",
	bigbuf);

    if (len == 7) return;

    saved_offset = asn1->offset;

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, (len > 8) ? 2 : 1,
	    "Enter Digits Digit Mask");

    subtree = proto_item_add_subtree(item, ett_ent_dig_mask);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  7 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  6 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  5 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  4 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  3 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  2 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  0 Digit",
	bigbuf);

    if (len == 8) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  # Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  * Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  9 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  8 Digit",
	bigbuf);

    if (len == 9) return;

    saved_offset = asn1->offset;

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, (len > 10) ? 2 : 1,
	    "Allowed Digits Digit Mask");

    subtree = proto_item_add_subtree(item, ett_all_dig_mask);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  7 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  6 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  5 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  4 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  3 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  2 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  0 Digit",
	bigbuf);

    if (len == 10) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  # Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  * Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  9 Digit",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  8 Digit",
	bigbuf);

    if (len == 11) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Special Interdigit Time (%u)",
	bigbuf,
	value & 0x1f);

    if (len == 12) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 8",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 7",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 6",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 5",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 4",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 3",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 2",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 1",
	bigbuf);

    if (len == 13) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 16",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 15",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 14",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 13",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 12",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 11",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 10",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 9",
	bigbuf);

    if (len == 14) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 24",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 23",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 22",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 21",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 20",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 19",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 18",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 17",
	bigbuf);

    if (len == 15) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 31",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 30",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 29",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 28",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 27",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 26",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SIT 25",
	bigbuf);

    EXTRANEOUS_DATA_CHECK(len, 16);
}

static void
param_no_ans_time(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"(%u) The number of seconds to wait after alerting an MS or after seizing an outgoing trunk before applying no answer trigger treatment.",
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_mw_noti_count(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset, orig_offset;
    const gchar *str = NULL;
    char *buf;

    SHORT_DATA_CHECK(len, 2);

    orig_offset = asn1->offset;
    saved_offset = asn1->offset;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "Voice Messages"; break;
	case 1: str = "Short Message Services (SMS) messages"; break;
	case 2: str = "Group 3 (G3) Fax messages"; break;
	case 255: str = "Not specified"; break;
	default:
	    str = "Reserved, treat as Not specified";
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Type of messages, %s",
	    str);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "No messages are waiting"; break;
	case 254: str = "254 or more messages are waiting"; break;
	case 255: str = "An unknown number of messages are waiting (greater than zero)"; break;
	default:
	    buf=ep_alloc(512);
	    g_snprintf(buf, 512, "%u messages are waiting", value);
	    str = buf;
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    str);

	saved_offset = asn1->offset;
    }
    while ((len - (saved_offset - orig_offset)) >= 2);

    EXTRANEOUS_DATA_CHECK((len - (saved_offset - orig_offset)), 0);
}

static void
param_otfi(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xc0) >> 6)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "Presentation Allowed"; break;
    case 2: str = "Presentation Restricted"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Calling Number ID Restriction, %s",
	bigbuf,
	str);

    switch ((value & 0x30) >> 4)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "Pip Tone Inactive"; break;
    case 2: str = "Pip Tone Active"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Message Waiting Notification, %s",
	bigbuf,
	str);

    switch ((value & 0x0c) >> 2)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "No CW"; break;
    case 2: str = "Normal CW"; break;
    case 3: str = "Priority CW"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Waiting for Incoming Call (CWIC), %s",
	bigbuf,
	str);

    switch (value & 0x03)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "No CW"; break;
    case 2: str = "Normal CW"; break;
    case 3: str = "Priority CW"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Waiting for Future Incoming Call (CWFI), %s",
	bigbuf,
	str);

    if (len == 1) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x30) >> 4)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "Presentation Allowed"; break;
    case 2: str = "Presentation Restricted"; break;
    case 3: str = "Blocking Toggle"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Calling Name Restriction (CNAR), %s",
	bigbuf,
	str);

    switch ((value & 0x0c) >> 2)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "Flash Inactive"; break;
    case 2: str = "Flash Active"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Flash Privileges (Flash), %s",
	bigbuf,
	str);

    switch (value & 0x03)
    {
    case 0: str = "Ignore"; break;
    case 1: str = "PACA Demand Inactive"; break;
    case 2: str = "PACA Demand Actived"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Priority Access and Channel Assignment (PACA), %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

/*
 * For:
 *	Authentication Response
 *	Authentication Response Base Station
 *	Authentication Response Unique Challenge
 */
static void
param_auth_resp_all(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Response (MSB)",
	bigbuf);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Response",
	bigbuf);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Response (LSB)",
	bigbuf);
}

static void
param_sys_acc_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 5);

    param_mscid(asn1, tree, 3, add_string, string_len);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Serving Cell ID %u",
	value);
}

static void
param_bill_id(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 id, segcount;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 7);

    param_mscid(asn1, tree, 3, add_string, string_len);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 3, &id);

    proto_tree_add_int_format(tree, hf_ansi_map_billing_id, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,id,
	"ID Number %d",
	id);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &segcount);

    if (segcount == 255) { str = "Unspecified"; }
    else if ((segcount >= 0) && (segcount <= 127)) { str = "Number of call segments"; }
    else if ((segcount >= 128) && (segcount < 255)) { str = "Not used in TIA/EIA-41"; }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Segment Counter %u:  %s",
	segcount, str);
}

static void
param_cdma_so(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 so;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 2, &so);

    switch (so)
    {
    case 1: str = "Basic Variable Rate Voice Service (8 kbps)"; break;
    case 2: str = "Mobile Station Loopback (8 kbps)"; break;
    case 3: str = "Enhanced Variable Rate Voice Service (8 kbps)"; break;
    case 4: str = "Asynchronous Data Service (9.6 kbps)"; break;
    case 5: str = "Group 3 Facsimile (9.6 kbps)"; break;
    case 6: str = "Short Message Services (Rate Set 1)"; break;
    case 7: str = "Packet Data Service: Internet or ISO Protocol Stack (9.6 kbps)"; break;
    case 8: str = "Packet Data Service: CDPD Protocol Stack (9.6 kbps)"; break;
    case 9: str = "Mobile Station Loopback (13 kbps)"; break;
    case 10: str = "STU-III Transparent Service"; break;
    case 11: str = "STU-III Non-Transparent Service"; break;
    case 12: str = "Asynchronous Data Service (14.4 or 9.6 kbps)"; break;
    case 13: str = "Group 3 Facsimile (14.4 or 9.6 kbps)"; break;
    case 14: str = "Short Message Services (Rate Set 2)"; break;
    case 15: str = "Packet Data Service: Internet or ISO Protocol Stack (14.4 kbps)"; break;
    case 16: str = "Packet Data Service: CDPD Protocol Stack (14.4 kbps)"; break;
    case 17: str = "High Rate Voice Service (13 kbps)"; break;
    case 32768: str = "QCELP (13 kbps)"; break;
    case 18: str = "Over-the-Air Parameter Administration (Rate Set 1)"; break;
    case 19: str = "Over-the-Air Parameter Administration (Rate Set 2)"; break;
    case 20: str = "Group 3 Analog Facsimile (Rate Set 1)"; break;
    case 21: str = "Group 3 Analog Facsimile (Rate Set 2)"; break;
    case 22: str = "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS1 reverse)"; break;
    case 23: str = "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS2 reverse)"; break;
    case 24: str = "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS1 reverse)"; break;
    case 25: str = "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS2 reverse)"; break;
    case 26: str = "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS1 reverse)"; break;
    case 27: str = "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS2 reverse)"; break;
    case 28: str = "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS1 reverse)"; break;
    case 29: str = "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS2 reverse)"; break;
    case 30: str = "Supplemental Channel Loopback Test for Rate Set 1"; break;
    case 31: str = "Supplemental Channel Loopback Test for Rate Set 2"; break;
    case 32: str = "Test Data Service Option (TDSO)"; break;
    case 33: str = "cdma2000 High Speed Packet Data Service, Internet or ISO Protocol Stack"; break;
    case 34: str = "cdma2000 High Speed Packet Data Service, CDPD Protocol Stack"; break;
    case 35: str = "Location Services, Rate Set 1 (9.6 kbps)"; break;
    case 36: str = "Location Services, Rate Set 2 (14.4 kbps)"; break;
    case 37: str = "ISDN Interworking Service (64 kbps)"; break;
    case 38: str = "GSM Voice"; break;
    case 39: str = "GSM Circuit Data"; break;
    case 40: str = "GSM Packet Data"; break;
    case 41: str = "GSM Short Message Service"; break;
    case 42: str = "None Reserved for MC-MAP standard service options"; break;
    case 54: str = "Markov Service Option (MSO)"; break;
    case 55: str = "Loopback Service Option (LSO)"; break;
    case 56: str = "Selectable Mode Vocoder"; break;
    case 57: str = "32 kbps Circuit Video Conferencing"; break;
    case 58: str = "64 kbps Circuit Video Conferencing"; break;
    case 59: str = "HRPD Accounting Records Identifier"; break;
    case 60: str = "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Removal"; break;
    case 61: str = "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Compression"; break;
    case 62: str = "- 4099 None Reserved for standard service options"; break;
    case 4100: str = "Asynchronous Data Service, Revision 1 (9.6 or 14.4 kbps)"; break;
    case 4101: str = "Group 3 Facsimile, Revision 1 (9.6 or 14.4 kbps)"; break;
    case 4102: str = "Reserved for standard service option"; break;
    case 4103: str = "Packet Data Service: Internet or ISO Protocol Stack, Revision 1 (9.6 or 14.4 kbps)"; break;
    case 4104: str = "Packet Data Service: CDPD Protocol Stack, Revision 1 (9.6 or 14.4 kbps)"; break;
    default:
	if ((so >= 4105) && (so <= 32767)) { str = "Reserved for standard service options"; }
	else if ((so >= 32769) && (so <= 32771)) { str = "Proprietary QUALCOMM Incorporated"; }
	else if ((so >= 32772) && (so <= 32775)) { str = "Proprietary OKI Telecom"; }
	else if ((so >= 32776) && (so <= 32779)) { str = "Proprietary Lucent Technologies"; }
	else if ((so >= 32780) && (so <=32783)) { str = "Nokia"; }
	else if ((so >= 32784) && (so <=32787)) { str = "NORTEL NETWORKS"; }
	else if ((so >= 32788) && (so <=32791)) { str = "Sony Electronics Inc."; }
	else if ((so >= 32792) && (so <=32795)) { str = "Motorola"; }
	else if ((so >= 32796) && (so <=32799)) { str = "QUALCOMM Incorporated"; }
	else if ((so >= 32800) && (so <=32803)) { str = "QUALCOMM Incorporated"; }
	else if ((so >= 32804) && (so <=32807)) { str = "QUALCOMM Incorporated"; }
	else if ((so >= 32808) && (so <=32811)) { str = "QUALCOMM Incorporated"; }
	else if ((so >= 32812) && (so <=32815)) { str = "Lucent Technologies"; }
	else if ((so >= 32816) && (so <=32819)) { str = "Denso International"; }
	else if ((so >= 32820) && (so <=32823)) { str = "Motorola"; }
	else if ((so >= 32824) && (so <=32827)) { str = "Denso International"; }
	else if ((so >= 32828) && (so <=32831)) { str = "Denso International"; }
	else if ((so >= 32832) && (so <=32835)) { str = "Denso International"; }
	else if ((so >= 32836) && (so <=32839)) { str = "NEC America"; }
	else if ((so >= 32840) && (so <=32843)) { str = "Samsung Electronics"; }
	else if ((so >= 32844) && (so <=32847)) { str = "Texas Instruments Incorporated"; }
	else if ((so >= 32848) && (so <=32851)) { str = "Toshiba Corporation"; }
	else if ((so >= 32852) && (so <=32855)) { str = "LG Electronics Inc."; }
	else if ((so >= 32856) && (so <=32859)) { str = "VIA Telecom Inc."; }
	else { str = "Reserved"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s %u/0x%04x",
	str, so, so);

    g_snprintf(add_string, string_len, " - (SO=0x%04x)", so);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_tdma_sc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Analog Speech Only"; break;
    case 1: str = "Digital Speech Only"; break;
    case 2: str = "Analog or Digital Speech, Analog Preferred"; break;
    case 3: str = "Analog or Digital Speech, Digital Preferred"; break;
    case 4: str = "Asynchronous Data"; break;
    case 5: str = "G3 Fax"; break;
    case 6: str = "Not Used (Service Rejected)"; break;
    case 7: str = "STU III (Secure Telephone Unit)"; break;
    default:
	str = "Reserved, treat as Analog Speech Only";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s %u",
	str, value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_dmh_red_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 redind;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &redind);

    switch (redind)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Call Forwarding Unconditional (CFU)"; break;
    case 2: str = "Call Forwarding Busy (CFB)"; break;
    case 3: str = "Call Forwarding No Answer (CFNA)"; break;
    case 4: str = "Call Forwarding Other (CFO)"; break;
    case 5: str = "CD Unspecified"; break;
    case 6: str = "CD PSTN"; break;
    case 7: str = "CD Private"; break;
    case 8: str = "PSTN Tandem"; break;
    case 9: str = "Private Tandem"; break;
    case 10: str = "Busy"; break;
    case 11: str = "Inactive"; break;
    case 12: str = "Unassigned"; break;
    case 13: str = "Termination Denied"; break;
    case 14: str = "CD Failure"; break;
    case 15: str = "Explicit Call Transfer (ECT)"; break;
    case 16: str = "Mobile Access Hunting (MAH)"; break;
    case 17: str = "Flexible Alerting (FA)"; break;
    case 18: str = "Abandoned Call Leg"; break;
    case 19: str = "Password Call Acceptance (PCA) Call Refused"; break;
    case 20: str = "Selective Call Acceptance (SCA) Call Refused"; break;
    case 21: str = "Dialogue"; break;
    case 22: str = "Call Forwarding Default (CFD)"; break;
    case 23: str = "CD Local"; break;
    case 24: str = "Voice Mail Retrieval"; break;
    default:
	if ((redind >= 25) && (redind <= 127))
	{
	    str = "Reserved/Unknown";
	}
	else
	{
	    str = "Reserved for bilateral agreements";
	}
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str, redind);
}

static void
param_cic(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 tg, mem;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &tg);
    asn1_int32_value_decode(asn1, 1, &mem);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"Trunk Group %u  Member %u",
	tg, mem);

    g_snprintf(add_string, string_len, "- (%u/%u)", tg, mem);
}

static void
param_qic(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 qic;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &qic);

    switch (qic)
    {
    case 0: str = "Not used"; break;
    case 1: str = "No information"; break;
    case 2: str = "Validation only"; break;
    case 3: str = "Validation and profile"; break;
    case 4: str = "Profile only"; break;
    default:
	if ((qic >= 5) && (qic <= 223))
	{
	    str = "Reserved, treat as Validation and profile";
	}
	else
	{
	    str = "Reserved for extension, treat as Validation and profile";
	}
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_feat_result(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unsuccessful"; break;
    case 2: str = "Successful"; break;
    default:
	if ((value >= 3) && (value <= 95)) { str = "Reserved, treat as Unsuccessful"; }
	else if ((value >= 96) && (value <= 127)) { str = "Reserved, treat as Unsuccessful"; }
	else if ((value >= 128) && (value <= 223)) { str = "Reserved, treat as Successful"; }
	else { str = "Reserved for protocol extension, treat as Successful"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

const gchar *calling_feat_ind_str[] = {
    "Not used",
    "Not authorized",
    "Authorized but de-activated",
    "Authorized and activated"
};

static void
param_calling_feat_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Waiting Feature Activity (CW-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0xc0) >> 6]);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Forwarding No Answer Feature Activity (CFNA-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Forwarding Busy Feature Activity (CFB-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Forwarding Unconditional Feature Activity (CFU-FA), %s",
	bigbuf,
	calling_feat_ind_str[value & 0x03]);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Transfer Feature Activity (CT-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0xc0) >> 6]);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Privacy Feature Activity (VP-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Call Delivery Feature Activity (CD-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Three-Way Calling Feature Activity (3WC-FA), %s",
	bigbuf,
	calling_feat_ind_str[value & 0x03]);

    if (len == 2) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Calling Number ID Restriction Override Feature Activity (CNIROver-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0xc0) >> 6]);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Calling Number ID Restriction Feature Activity (CNIR-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Two number Calling Number ID Presentation Feature Activity (CNIP2-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  One number Calling Number ID Presentation Feature Activity (CNIP1-FA), %s",
	bigbuf,
	calling_feat_ind_str[value & 0x03]);

    if (len == 3) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  USCF divert to voice mail Feature Activity (USCFvm-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0xc0) >> 6]);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Answer Hold Feature Activity (AH-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Data Privacy Feature Activity (DP-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Priority Call Waiting Feature Activity (PCW-FA), %s",
	bigbuf,
	calling_feat_ind_str[value & 0x03]);

    if (len == 4) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA-Concurrent Service Feature Activity (CCS-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0xc0) >> 6]);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA-Packet Data Service Feature Activity (CPDS-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  USCF divert to network registered DN Feature Activity (USCFnr-FA), %s",
	bigbuf,
	calling_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  USCF divert to mobile station provided DN Feature Activity (USCFms-FA), %s",
	bigbuf,
	calling_feat_ind_str[value & 0x03]);

    if (len == 5) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  TDMA Enhanced Privacy and Encryption Feature Activity (TDMA EPE-FA), %s",
	bigbuf,
	calling_feat_ind_str[value & 0x03]);

    EXTRANEOUS_DATA_CHECK(len, 6);
}

static void
param_usage_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Unspecified"; break;
    case 1: str = "Sent-paid call"; break;
    case 2: str = "3rd number bill"; break;
    default:
	str = "Reserved, treat as Unspecified";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);
}

const gchar *tdma_data_feat_ind_str[] = {
    "Not used",
    "Not authorized",
    "Authorized but de-activated",
    "Authorized and activated"
};

static void
param_tdma_data_feat_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  STU-III Feature Activity (STUIII-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  G3 Fax Feature Activity (G3FAX-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  ADS Feature Activity (ADS-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[value & 0x03]);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Triple Rate data Feature Activity (3RATE-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[(value & 0xc0) >> 6]);

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Double Rate data Feature Activity (2RATE-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[(value & 0x30) >> 4]);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Full Rate data Feature Activity (FRATE-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[(value & 0x0c) >> 2]);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Half Rate data Feature Activity (HRATE-FA), %s",
	bigbuf,
	tdma_data_feat_ind_str[value & 0x03]);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_faulty(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;
    gint idx;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    str = match_strval_idx((guint32) value, ansi_param_1_strings, &idx);

    if (NULL == str)
    {
	if (len < 2)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, len,
		"Unrecognized parameter ID");
	    return;
	}

	asn1->offset = saved_offset;
	asn1_uint32_value_decode(asn1, 2, &value);

	str = match_strval_idx((guint32) value, ansi_param_2_strings, &idx);

	if (NULL == str)
	{
	    if (len < 3)
	    {
		proto_tree_add_text(tree, asn1->tvb,
		    saved_offset, len,
		    "Unrecognized parameter ID");
		return;
	    }

	    asn1->offset = saved_offset;
	    asn1_int32_value_decode(asn1, 3, &value);

	    str = match_strval_idx((guint32) value, ansi_param_3_strings, &idx);

	    if (NULL == str)
	    {
		if (((value >= 0x9FFF00) && (value <= 0x9FFF7F)) ||
		    ((value >= 0xBFFF00) && (value <= 0xBFFF7F)))
		{
		    str = "Reserved for protocol extension";
		}
		else if (((value >= 0x9FFE76) && (value <= 0x9FFE7F)) ||
		    ((value >= 0xBFFE76) && (value <= 0xBFFE7F)))
		{
		    str = "Reserved for National Network Use";
		}
		else
		{
		    str = "Unrecognized parameter ID";
		}
	    }
	}
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, asn1->offset - saved_offset);
}

static void
param_sys_type_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 sys_type_code;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &sys_type_code);

    switch (sys_type_code)
    {
    case 0: str = "Not used"; break;
    case 1: str = "EDS"; break;
    case 2: str = "Astronet"; break;
    case 3: str = "Lucent Technologies"; break;
    case 4: str = "Ericsson"; break;
    case 5: str = "GTE"; break;
    case 6: str = "Motorola"; break;
    case 7: str = "NEC"; break;
    case 8: str = "NORTEL"; break;
    case 9: str = "NovAtel"; break;
    case 10: str = "Plexsys"; break;
    case 11: str = "Digital Equipment Corp"; break;
    case 12: str = "INET"; break;
    case 13: str = "Bellcore"; break;
    case 14: str = "Alcatel SEL"; break;
    case 15: str = "Compaq (Tandem)"; break;
    case 16: str = "QUALCOMM"; break;
    case 17: str = "Aldiscon"; break;
    case 18: str = "Celcore"; break;
    case 19: str = "TELOS"; break;
    case 20: str = "ADI Limited (Stanilite)"; break;
    case 21: str = "Coral Systems"; break;
    case 22: str = "Synacom Technology"; break;
    case 23: str = "DSC"; break;
    case 24: str = "MCI"; break;
    case 25: str = "NewNet"; break;
    case 26: str = "Sema Group Telecoms"; break;
    case 27: str = "LG Information and Communications"; break;
    case 28: str = "CBIS"; break;
    case 29: str = "Siemens"; break;
    case 30: str = "Samsung Electronics"; break;
    case 31: str = "ReadyCom Inc."; break;
    case 32: str = "AG Communication Systems"; break;
    case 33: str = "Hughes Network Systems"; break;
    case 34: str = "Phoenix Wireless Group"; break;
    default:
	str = "Reserved/Unknown";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Vendor ID (%u) %s",
	sys_type_code, str);
}

static void
param_ext_sys_type_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 type;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &type);

    switch (type)
    {
    case 0: str = "Not specified"; break;
    case 1: str = "Serving MSC"; break;
    case 2: str = "Home MSC"; break;
    case 3: str = "Gateway MSC"; break;
    case 4: str = "HLR"; break;
    case 5: str = "VLR"; break;
    case 6: str = "EIR (reserved)"; break;
    case 7: str = "AC"; break;
    case 8: str = "Border MSC"; break;
    case 9: str = "Originating MSC"; break;
    default:
	if ((type >= 10) && (type <= 223)) { str = "Reserved, treat as Not specified"; }
	else { str = "Reserved for protocol extension, treat as Not specified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Type (%u) %s",
	type,
	str);

    param_sys_type_code(asn1, tree, len-1, add_string, string_len);
}

static void
param_cdma_sea_win(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Value %u",
	bigbuf,
	value & 0x0f);
}

static void
param_cdma_sea_param(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA Search Window, %u",
	bigbuf,
	value & 0x0f);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  T_ADD, %u",
	bigbuf,
	value & 0x3f);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  T_DROP, %u",
	bigbuf,
	value & 0x3f);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  T_TDROP, %u",
	bigbuf,
	value & 0xf0);

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  T_COMP, %u",
	bigbuf,
	value & 0x0f);

    EXTRANEOUS_DATA_CHECK(len, 4);
}

static void
param_cdma_code_chan(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA Code Channel %u",
	bigbuf,
	value & 0x3f);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_chan_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  SAT Color Code %u",
	bigbuf,
	(value & 0xc0 >> 6));

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	(value & 0x20) ? "Reserved" : "Analog Band Class",
	bigbuf);

    switch ((value & 0x18) >> 3)
    {
    case 0: str = "DTX disabled (not active/acceptable)"; break;
    case 1: str = "Reserved, treat as DTX disabled"; break;
    case 2: str = "DTX-low mode (i.e., 8 dB below DTX active/acceptable)"; break;
    case 3: str = "DTX mode active or acceptable"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x18, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Mobile Attenuation Code (VMAC) %u",
	bigbuf,
	value & 0x07);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Channel Number %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 3);
}

static void
param_cdma_plcm(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 6);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA Private Long Code Mask (PLCM) (MSB)",
	bigbuf);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len - 1,
	"CDMA Private Long Code Mask (PLCM)");

    asn1->offset += (len - 1);
}

static void
param_ctrl_chan_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Digital Color Code (DCC)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x38, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Control Mobile Attenuation Code (CMAC)",
	bigbuf);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Channel Number (CHNO), %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Supplementary Digital Color Codes (SDCC1)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Supplementary Digital Color Codes (SDCC2)",
	bigbuf);
}

static void
param_cdma_chan_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, temp_int;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 8);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    other_decode_bitfield_value(bigbuf, value >> 8, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value >> 8, 0x78, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Frame Offset (%u), %.2f ms",
	bigbuf,
	(value & 0x7800) >> 11,
	((value & 0x7800) >> 11) * 1.25);

    other_decode_bitfield_value(bigbuf, value >> 8, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  CDMA Channel Number (MSB), %u",
	bigbuf,
	value & 0x07ff);

    other_decode_bitfield_value(bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset+1, 1,
	"%s :  CDMA Channel Number (LSB)",
	bigbuf);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    temp_int = (value & 0x7c) >> 2;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
	str = "Reserved";
    }
    else
    {
	str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(bigbuf, value, 0x7c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Band Class, %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Long Code Mask (MSB)",
	bigbuf);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 1, 1,
	"%s :  Long Code Mask",
	bigbuf);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 2, 1,
	"%s :  Long Code Mask",
	bigbuf);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 3, 1,
	"%s :  Long Code Mask",
	bigbuf);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 4, 1,
	"%s :  Long Code Mask",
	bigbuf);

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 5, 1,
	"%s :  Long Code Mask (LSB)",
	bigbuf);

    if (len == 8) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  NP Extension",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x78, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Nominal Power, %u",
	bigbuf,
	(value & 0x78) >> 3);

    other_decode_bitfield_value(bigbuf, value, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Number Preamble, %u",
	bigbuf,
	value & 0x07);

    if (len == 9) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Base Station Protocol Revision, %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 10);
}

static void
param_namps_chan_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x1c) >> 2)
    {
    case 0: str = "Channel Data parameter SCC field applies"; break;
    case 1: str = "Digital SAT Color Code 1 (ignore SCC field)"; break;
    case 2: str = "Digital SAT Color Code 2 (ignore SCC field)"; break;
    case 3: str = "Digital SAT Color Code 3 (ignore SCC field)"; break;
    case 4: str = "Digital SAT Color Code 4 (ignore SCC field)"; break;
    case 5: str = "Digital SAT Color Code 5 (ignore SCC field)"; break;
    case 6: str = "Digital SAT Color Code 6 (ignore SCC field)"; break;
    case 7: str = "Digital SAT Color Code 7 (ignore SCC field)"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x1c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Color Code Indicator (CCIndicator), %s",
	bigbuf,
	str);

    switch (value & 0x03)
    {
    case 0: str = "Wide. 30 kHz AMPS voice channel"; break;
    case 1: str = "Upper. 10 kHz NAMPS voice channel"; break;
    case 2: str = "Middle. 10 kHz NAMPS voice channel"; break;
    case 3: str = "Lower. 10 kHz NAMPS voice channel"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Narrow Analog Voice Channel Assignment (NAVCA), %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_ms_meas_chan_id(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, temp_int;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    temp_int = (value & 0xf800) >> 11;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
	str = "Reserved";
    }
    else
    {
	str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(bigbuf, value >> 8, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Band Class, %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value >> 8, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  CDMA Channel Number (MSB), %u",
	bigbuf,
	value & 0x07ff);

    other_decode_bitfield_value(bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset+1, 1,
	"%s :  CDMA Channel Number (LSB)",
	bigbuf);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_tdma_chan_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 5);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x1f)
    {
    case 0: str = "Analog (not used if ChannelData is present)"; break;
    case 1: str = "Assigned to timeslot 1, full rate"; break;
    case 2: str = "Assigned to timeslot 2, full rate"; break;
    case 3: str = "Assigned to timeslot 3, full rate"; break;
    case 4: str = "Assigned to timeslots 1, 4 and 2, 5 Double rate"; break;
    case 5: str = "Assigned to timeslots 1, 4 and 3, 6 Double rate"; break;
    case 6: str = "Assigned to timeslots 2, 5 and 3, 6 Double rate"; break;
    case 9: str = "Assigned to timeslot 1, half rate"; break;
    case 10: str = "Assigned to timeslot 2, half rate"; break;
    case 11: str = "Assigned to timeslot 3, half rate"; break;
    case 12: str = "Assigned to timeslot 4, half rate"; break;
    case 13: str = "Assigned to timeslot 5, half rate"; break;
    case 14: str = "Assigned to timeslot 6, half rate"; break;
    case 15: str = "Assigned to timeslot 1, 2, 3, 4, 5, 6 Triple rate"; break;
    default:
	str = "Reserved, treat as Analog";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Time Slot and Rate indicator (TSR), %s",
	bigbuf,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Digital Verification Color Code (DVCC) %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xf0) >> 4)
    {
    case 0: str = "800 MHz"; break;
    case 1: str = "1800 MHz"; break;
    default:
	str = "Reserved, treat as 800 MHz";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Hyper Band, %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Digital Mobile Attenuation Code (DMAC) %u",
	bigbuf,
	value & 0x0f);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    other_decode_bitfield_value(bigbuf, value >> 8, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Channel Number (MSB), %u",
	bigbuf,
	value);

    other_decode_bitfield_value(bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 1, 1,
	"%s :  Channel Number (LSB)",
	bigbuf);

    EXTRANEOUS_DATA_CHECK(len, 5);
}

static void
param_tdma_call_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %sxtended modulation and framing",
	bigbuf,
	(value & 0x20) ? "E" : "No e");

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Other voice coding %sacceptable",
	bigbuf,
	(value & 0x10) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Other DQPSK channel %sacceptable",
	bigbuf,
	(value & 0x08) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Half rate digital traffic channel %sacceptable",
	bigbuf,
	(value & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Full rate digital traffic channel %sacceptable",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  AMPS channel %sacceptable",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_call_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    if (len == 1)
    {
	/* assuming older spec. no IS-880 */

	other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  Reserved",
	    bigbuf);
    }
    else
    {
	other_decode_bitfield_value(bigbuf, value, 0x80, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  450 MHz channel (Band Class 5) %sacceptable",
	    bigbuf,
	    (value & 0x80) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x40, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  Korean PCS channel (Band Class 4) %sacceptable",
	    bigbuf,
	    (value & 0x40) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x20, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  JTACS channel (Band Class 3) %sacceptable",
	    bigbuf,
	    (value & 0x20) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x10, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  TACS channel (Band Class 2) %sacceptable",
	    bigbuf,
	    (value & 0x10) ? "" : "not ");
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA 1900 MHz channel (Band Class 1) %sacceptable",
	bigbuf,
	(value & 0x08) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  NAMPS 800 MHz channel %sacceptable",
	bigbuf,
	(value & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  AMPS 800 MHz channel %sacceptable",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA 800 MHz channel (Band Class 0) %sacceptable",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    if (len == 1) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Secondary 800 MHz channel (Band Class 10) %sacceptable",
	bigbuf,
	(value & 0x10) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  900 MHz channel (Band Class 9) %sacceptable",
	bigbuf,
	(value & 0x08) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1800 MHz channel (Band Class 8) %sacceptable",
	bigbuf,
	(value & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  700 MHz channel (Band Class 7) %sacceptable",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  2 GHz channel (Band Class 6) %sacceptable",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_namps_call_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... %u... :  AMPS 1800 MHz channel %sacceptable",
	(value & 0x08) >> 3, (value & 0x08) ? "" : "not ");

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... .%u.. :  NAMPS 1800 MHz channel %sacceptable",
	(value & 0x04) >> 2, (value & 0x04) ? "" : "not ");

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... ..%u. :  AMPS 800 MHz channel %sacceptable",
	(value & 0x02) >> 1, (value & 0x02) ? "" : "not ");

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... ...%u :  NAMPS 800 MHz channel %sacceptable",
	value & 0x01, (value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_mob_rev(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Revision %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_band_class(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, temp_int;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    temp_int = value & 0x1f;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
	str = "Reserved";
    }
    else
    {
	str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Band Class %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_calling_party_name(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Spec. has hardcoded as 0 0 1",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Availability, %s",
	bigbuf,
	(value & 0x10) ?  "Name not available" : "Name available/unknown");

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x03)
    {
    case 0: str = "Presentation allowed"; break;
    case 1: str = "Presentation restricted"; break;
    case 2: str = "Blocking toggle"; break;
    case 3: str = "No indication"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Presentation Status, %s",
	bigbuf,
	str);

    if (len == 1) return;

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	asn1->offset, len - 1,
	"IA5 Digits");

    asn1->offset += (len - 1);
}

static void
param_red_party_name(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Spec. has hardcoded as 0 1 1",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Availability, %s",
	bigbuf,
	(value & 0x10) ?  "Name not available" : "Name available/unknown");

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x03)
    {
    case 0: str = "Presentation allowed"; break;
    case 1: str = "Presentation restricted"; break;
    case 2: str = "Blocking toggle"; break;
    case 3: str = "No indication"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Presentation Status, %s",
	bigbuf,
	str);

    if (len == 1) return;

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	asn1->offset, len - 1,
	"IA5 Digits");

    asn1->offset += (len - 1);
}

static void
param_srvc_id(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_text(tree, asn1->tvb,
	asn1->offset, len,
	"Service Identifier (Spec. does not define clearly)");

    asn1->offset += len;
}

static void
param_all_or_none(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "All changes must succeed or none should be applied"; break;
    case 2: str = "Treat each change independently"; break;
    default:
	if ((value >= 3) && (value <= 223)) { str = "Reserved, treat as All changes must succeed or none should be applied"; }
	else { str = "Reserved for protocol extension, treat as All changes must succeed or none should be applied"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_change(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Set Data Item to Default Value"; break;
    case 2: str = "Add Data Item"; break;
    case 3: str = "Delete Data Item"; break;
    case 4: str = "Replace Data Item with associated DataValue"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Set Data Item to Default Value"; }
	else { str = "Reserved for protocol extension, treat as Set Data Item to Default Value"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_data_result(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Successful"; break;
    case 2: str = "Unsuccessful, unspecified"; break;
    case 3: str = "Unsuccessful, no default value available"; break;
    default:
	if ((value >= 4) && (value <= 95)) { str = "Reserved, treat as Unsuccessful"; }
	else if ((value >= 96) && (value <= 127)) { str = "Reserved for protocol extension, treat as Unsuccessful"; }
	else if ((value >= 128) && (value <= 223)) { str = "Reserved, treat as Successful"; }
	else { str = "Reserved for protocol extension, treat as Successful"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_fail_cause(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"ISUP Cause Indicator");

    asn1->offset += len;
}

static void
param_fail_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Call abandoned"; break;
    case 2: str = "Resource disconnect"; break;
    case 3: str = "Failure at MSC"; break;
    case 4: str = "SSFT expiration"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, ignore"; }
	else { str = "Reserved for protocol extension, ignore"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_resume_pic(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Continue Call Processing"; break;
    case 2: str = "Collect Information PIC"; break;
    case 3: str = "Analyze Information PIC"; break;
    case 4: str = "Select Route PIC"; break;
    case 5: str = "Authorize Origination_Attempt PIC"; break;
    case 6: str = "Authorize Call Setup PIC"; break;
    case 7: str = "Send Call PIC"; break;
    case 8: str = "O Alerting PIC"; break;
    case 9: str = "O Active PIC"; break;
    case 10: str = "O Suspended PIC"; break;
    case 11: str = "O Null PIC"; break;
    case 32: str = "Select Facility PIC"; break;
    case 33: str = "Present Call PIC"; break;
    case 34: str = "Authorize Termination Attempt PIC"; break;
    case 35: str = "T Alerting PIC"; break;
    case 36: str = "T Active PIC"; break;
    case 37: str = "T Suspended PIC"; break;
    case 38: str = "T Null PIC"; break;
    default:
	if ((value >= 12) && (value <= 31)) { str = "Reserved, treat as Not used"; }
	else if ((value >= 39) && (value <= 223)) { str = "Reserved, ignore"; }
	else { str = "Reserved for protocol extension, ignore"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Point in Call, %s (%u)",
	str,
	value);
}

static void
param_special_rsc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, i;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    i = 0;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "Not used"; break;
	case 1: str = "DTMF tone detector"; break;
	case 2: str = "Automatic Speech Recognition - Speaker Independent - Digits"; break;
	case 3: str = "Automatic Speech Recognition - Speaker Independent - Speech User Interface Version 1"; break;
	default:
	    if ((value >= 4) && (value <= 223)) { str = "Reserved, treat as Not used"; }
	    else { str = "Reserved for protocol extension, treat as Not used"; }
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "[%u] Resource Type, %s",
	    i++,
	    str);

	saved_offset = asn1->offset;
    }
    while ((len - i) > 0);
}

static void
param_time_date_offset(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"In minutes (%u)",
	value);
}

static void
param_network_tmsi(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, addr_type, first_dig;
    guint saved_offset;
    const gchar *str = NULL;
    guchar *poctets;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 4, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"TMSI Code, %u",
	value);

    if (len == 4) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    first_dig = Dgt_tbcd.out[(value & 0xf0) >> 4];

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  First digit of TMSI Zone, %c",
	bigbuf,
	first_dig);

    addr_type = value & 0x0f;
    switch (addr_type)
    {
    case 0: str = "Not used"; break;
    case 1: str = "E.212 based routing"; break;
    case 2: str = "20-bit TDMA TMSI"; break;
    case 3: str = "24-bit TDMA TMSI"; break;
    default:
	str = "Reserved for protocol extension, treat as Not used";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Type of addressing, %s",
	bigbuf,
	str);

    if (len == 5) return;

    saved_offset = asn1->offset;

    asn1_string_value_decode(asn1, (len-5), &poctets);

    bigbuf[0] = first_dig;

    my_dgt_tbcd_unpack(bigbuf+1, poctets, (len-5), &Dgt_tbcd);
    g_free(poctets);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset - 1, (len-5)+1,
	"TMSI Zone, %s",
	bigbuf);
}

static void
param_reqd_param_mask(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Location Area ID (LOCID) %srequired",
	bigbuf,
	(value & 0x10) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  TMSI %srequired",
	bigbuf,
	(value & 0x08) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  ESN %srequired",
	bigbuf,
	(value & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  MIN %srequired",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  IMSI %srequired",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_srvc_red_cause(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Normal Registration"; break;
    case 2: str = "System Not Found"; break;
    case 3: str = "Protocol Mismatch"; break;
    case 4: str = "Registration Rejection"; break;
    case 5: str = "Wrong SID"; break;
    case 6: str = "Wrong NID"; break;
    default:
	if ((value >= 7) && (value <= 223)) { str = "Reserved, treat as Normal Registration"; }
	else { str = "Reserved for protocol extension. If unknown, treat as Normal Registration"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_srvc_red_info(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  NDSS Status (NDS), %ssuppressed",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Return If Fail (RIF), If MS fails to access the redirected system, MS shall %sreturn to the serving system",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_roaming_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Roaming Indicator On"; break;
    case 1: str = "Roaming Indicator Off"; break;
    case 2: str = "Roaming Indicator Flashing"; break;
    case 3: str = "Out of Neighborhood"; break;
    case 4: str = "Out of Building"; break;
    case 5: str = "Roaming - Preferred System"; break;
    case 6: str = "Roaming - Available System"; break;
    case 7: str = "Roaming - Alliance Partner"; break;
    case 8: str = "Roaming - Premium Partner"; break;
    case 9: str = "Roaming - Full Service Functionality"; break;
    case 10: str = "Roaming - Partial Service Functionality"; break;
    case 11: str = "Roaming Banner On"; break;
    case 12: str = "Roaming Banner Off"; break;
    default:
	if ((value >= 13) && (value <= 63)) { str = "Reserved for Standard Enhanced Roaming Indicator Numbers"; }
	else if ((value >= 64) && (value <= 127)) { str = "Reserved for Non-Standard Enhanced Roaming Indicator Numbers"; }
	else { str = "Reserved"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_pci(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfe, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  CDMA PWR_COMB_IND",
	bigbuf);
}

static void
param_cdma_chan_num(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    other_decode_bitfield_value(bigbuf, value >> 8, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value >> 8, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  CDMA Channel Number (MSB) %u",
	bigbuf,
	value & 0x07ff);

    other_decode_bitfield_value(bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset+1, 1,
	"%s :  CDMA Channel Number (LSB)",
	bigbuf);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_cdma_sci(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Slot Cycle Index, %u",
	bigbuf,
	(value & 0x07));
}

static void
param_vp_report(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Voice Privacy not attempted"; break;
    case 2: str = "Voice Privacy no response"; break;
    case 3: str = "Voiec Privacy successful is active"; break;
    case 4: str = "Voice Privacy failed"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Voice Privacy not attempted"; }
	else { str = "Reserved for protocol extension, treat as Voice Privacy not attempted"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);
}

static void
param_cdma_scm(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Dual-mode Indicator, %s",
	bigbuf,
	(value & 0x40) ? "Dual mode CDMA" : "CDMA only");

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Slotted mode Indicator, %s",
	bigbuf,
	(value & 0x20) ? "slotted capable" : "slotted incapable");

    other_decode_bitfield_value(bigbuf, value, 0x18, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Analog Transmission, %s",
	bigbuf,
	(value & 0x04) ? "discontinuous" : "continuous");

    switch (value & 0x03)
    {
    case 0: str = "Power Class I"; break;
    case 1: str = "Power Class II"; break;
    case 2: str = "Power Class III"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_ota_result_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Accepted - Successful"; break;
    case 1: str = "Rejected - Unknown cause"; break;
    case 2: str = "Computation Failure - E.g., unable to compute A-key"; break;
    case 3: str = "CSC Rejected - CSC challenge failure"; break;
    case 4: str = "Unrecognized OTASPCallEntry"; break;
    case 5: str = "Unsupported AKeyProtocolVersion(s)"; break;
    case 6: str = "Unable to Commit"; break;
    default:
	if ((value >= 7) && (value <= 223)) { str = "Reserved, treat as Rejected - Unknown cause"; }
	else { str = "Reserved for protocol extension, treat as Rejected - Unknown cause"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_scm2(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_tdma_term_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1800 MHz F channel %sacceptable",
	bigbuf,
	(value & 0x40) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1800 MHz E channel %sacceptable",
	bigbuf,
	(value & 0x20) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1800 MHz D channel %sacceptable",
	bigbuf,
	(value & 0x10) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1800 MHz C channel %sacceptable",
	bigbuf,
	(value & 0x08) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1800 MHz B channel %sacceptable",
	bigbuf,
	(value & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s acceptable",
	bigbuf,
	(value & 0x02) ? "1800 MHz A channel" : "1800 MHz A&B Digital channel not");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  800 MHz A&B channel %sacceptable",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  IS-641 Voice Coder %sacceptable",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  VSELP Voice Coder %sacceptable",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "EIA-553 or IS-54-A"; break;
    case 1: str = "TIA/EIA-627 (IS-54-B)"; break;
    case 2: str = "IS-136"; break;
    case 3: str = "Reserved (ANSI J-STD-011)"; break;
    case 4: str = "PV 0 as published in TIA/EIA-136-0 and IS-136-A"; break;
    case 5: str = "PV 1 as published in TIA/EIA-136-A"; break;
    case 6: str = "PV 2 as published in TIA/EIA-136-A"; break;
    case 7: str = "PV 3 as published in TIA/EIA-136-A"; break;
    default:
	str = "Reserved, treat as EIA-553 or IS-54-A";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"Protocol Version, %s",
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Triple Rate (3RATE) %ssupported",
	bigbuf,
	(value & 0x80) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Double Rate (2RATE) %ssupported",
	bigbuf,
	(value & 0x40) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Full Rate (FRATE) %ssupported",
	bigbuf,
	(value & 0x20) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Half Rate (HRATE) %ssupported",
	bigbuf,
	(value & 0x10) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Analog Voice (AVOX) %ssupported",
	bigbuf,
	(value & 0x08) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Secure Telephone Unit III (STU3) %ssupported",
	bigbuf,
	(value & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Group 3 Fax (G3FAX) %ssupported",
	bigbuf,
	(value & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Asynchronous Data (ADS) %ssupported",
	bigbuf,
	(value & 0x01) ? "" : "not ");

    EXTRANEOUS_DATA_CHECK(len, 4);
}

static void
param_tdma_voice_coder(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, vc;
    guint orig_offset, saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    orig_offset = asn1->offset;
    saved_offset = asn1->offset;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  Reserved",
	    bigbuf);

	vc = (value & 0x0f);
	switch (vc)
	{
	case 0: str = "Not used"; break;
	case 1: str = "VSELP Voice Coder acceptable"; break;
	case 2: str = "IS-641 Voice Coder acceptable"; break;
	case 6: str = "Reserved for SOC/BSMC Specific signaling. If unknown, use any acceptable value"; break;
	default:
	    if ((vc >= 3) && (vc <= 5)) { str = "Reserved. Ignore on reception, use any acceptable value"; }
	    else if ((vc >= 7) && (vc <= 12)) { str = "Reserved. Ignore on reception, use any acceptable value"; }
	    else if ((vc >= 13) && (vc <= 15)) { str = "Reserved for protocol extension. If unknown, use any acceptable value"; }
	    break;
	}

	other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "%s :  Voice Coder, %s",
	    bigbuf,
	    str);

	saved_offset = asn1->offset;
    }
    while ((len - (saved_offset - orig_offset)) > 0);
}

static void
param_cdma_pilot_pn(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    other_decode_bitfield_value(bigbuf, value >> 8, 0xfe, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value >> 8, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Pilot PN (MSB), %u",
	bigbuf, value & 0x01ff);

    other_decode_bitfield_value(bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset + 1, 1,
	"%s :  Pilot PN (LSB)",
	bigbuf);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_cdma_pilot_strength(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Value %u",
	bigbuf,
	value & 0x3f);
}

static void
param_trunk_stat(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Idle"; break;
    case 1: str = "Blocked"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved, treat as ERROR or Blocked"; }
	else { str = "Reserved for protocol extension, treat as ERROR or Blocked"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Trunk Status, %s",
	str);
}

static void
param_pref_lang_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Unspecified"; break;
    case 1: str = "English"; break;
    case 2: str = "French"; break;
    case 3: str = "Spanish"; break;
    case 4: str = "German"; break;
    case 5: str = "Portuguese"; break;
    default:
	str = "Reserved, treat as Unspecified";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Preferred Language, %s",
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_rand_valtime(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;
    char *buf;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    if (value == 0)
    {
	str = "RAND shall not be stored";
    }
    else
    {
	buf=ep_alloc(64);
	g_snprintf(buf, 64, "RAND may be used for %u minutes", value);
	str = buf;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_tdma_burst_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x7c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Time Alignment Offset (TA), %u",
	bigbuf,
	(value & 0x7c) >> 2);

    switch (value & 0x03)
    {
    case 0: str = "Transmit normal burst after cell-to-cell handoff"; break;
    case 1: str = "Transmit normal burst after handoff within cell"; break;
    case 2: str = "Transmit shortened burst after cell-to-cell handoff"; break;
    case 3: str = "Reserved, treat with RETURN ERROR"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Burst Code, %s",
	bigbuf,
	str);
}

static void
param_orig_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Prior agreement"; break;
    case 2: str = "Origination denied"; break;
    case 3: str = "Local calls only"; break;
    case 4: str = "Selected leading digits of directory number or of international E.164 number, see Digits(Destination)"; break;
    case 5: str = "Selected leading digits of directory number or of international E.164 number and local calls only, see Digits(Destination)"; break;
    case 6: str = "National long distance"; break;
    case 7: str = "International calls"; break;
    case 8: str = "Single directory number or international E.164 number, see Digits(Destination)"; break;
    default:
	if ((value >= 9) && (value <= 223)) { str = "Reserved, treat as Local calls only"; }
	else { str = "Reserved for protocol extension, treat as Local calls only"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Allowed Call Types, %s",
	str);
}

static void
param_ms_loc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 7);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 3, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Latitude in tenths of a second, %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 3, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Longitude in tenths of a second, %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, MIN(len - 6, 2), &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Resolution in units of 1 foot, %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 8);
}

static void
param_unique_chal_rep(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unique Challenge not attempted"; break;
    case 2: str = "Unique Challenge no response"; break;
    case 3: str = "Unique Challenge successful"; break;
    case 4: str = "Unique Challenge failed"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Unique Challenge not attempted"; }
	else { str = "Reserved for protocol extension, treat as Unique Challenge not attempted"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_rand_unique(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    EXACT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"24-bit random number used as input to the CAVE algorithm for authenticating a specific MS");

    asn1->offset += len;
}

static void
param_vpmask(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 66);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Privacy Mask-A (VPMASK-A) (MSB)",
	bigbuf);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 32,
	"Voice Privacy Mask-A (VPMASK-A)");

    asn1->offset += 32;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Privacy Mask-B (VPMASK-B) (MSB)",
	bigbuf);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 32,
	"Voice Privacy Mask-B (VPMASK-B)");

    asn1->offset += 32;
}

static void
param_ssd(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    EXACT_DATA_CHECK(len, 16);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 8,
	"Shared Secret Data-A (SSD-A)");

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset+8, 8,
	"Shared Secret Data-B (SSD-B)");

    asn1->offset += len;
}

static void
param_upd_count(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Update COUNT"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved, treat as Update COUNT"; }
	else { str = "Reserved for protocol extension, treat as Update COUNT"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s",
	str);
}

static void
param_sme_key(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    EXACT_DATA_CHECK(len, 8);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"Signaling Message Encryption Key (SMEKEY)");

    asn1->offset += len;
}

static void
param_rand_ssd(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    EXACT_DATA_CHECK(len, 7);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"56-bit random number used as input to the CAVE algorithm for generating Shared Secret Data");

    asn1->offset += len;
}

static void
param_setup_result(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unsuccessful"; break;
    case 2: str = "Successful"; break;
    default:
	str = "Reserved, treat as Unsuccessful";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_randc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"The 8 most significant bits of the 32-bit Random Variable used to compute the Authentication Response");

    asn1->offset += 1;

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_ext_mscid(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 type;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &type);

    switch (type)
    {
    case 0: str = "Not specified"; break;
    case 1: str = "Serving MSC"; break;
    case 2: str = "Home MSC"; break;
    case 3: str = "Gateway MSC"; break;
    case 4: str = "HLR"; break;
    case 5: str = "VLR"; break;
    case 6: str = "EIR (reserved)"; break;
    case 7: str = "AC"; break;
    case 8: str = "Border MSC"; break;
    case 9: str = "Originating MSC"; break;
    default:
	if ((type >= 10) && (type <= 223)) { str = "Reserved, treat as Not specified"; }
	else { str = "Reserved for protocol extension, treat as Not specified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Type (%u), %s",
	type,
	str);

    param_mscid(asn1, tree, len-1, add_string, string_len);
}

static void
param_sub_addr(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Should be 1",
	bigbuf);

    switch ((value & 0x70) >> 4)
    {
    case 0x00: str = "NSAP (CCITT Rec. X.213 or ISO 8348 AD2)"; break;
    case 0x02: str = "User specified"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x70, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Type of Subaddress %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Even number of subaddress signals follow"; break;
    case 0x01: str = "Odd number of subaddress signals follow"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    proto_tree_add_text(tree, asn1->tvb,
	asn1->offset, len - 1,
	"Subaddress");

    asn1->offset += len - 1;
}

static void
param_digits_basic(ASN1_SCK *asn1, proto_tree *tree, guint len, gboolean searchable)
{
    gint32 value, b1, b2, b3, b4, enc, plan;
    guint saved_offset;
    const gchar *str = NULL;
    proto_item *item;
    proto_tree *subtree;
    guchar *poctets;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Dialed Numer or Called Party Number"; break;
    case 2: str = "Calling Party Number"; break;
    case 3: str = "Caller Interaction (Not used)"; break;
    case 4: str = "Routing Number"; break;
    case 5: str = "Billing Number"; break;
    case 6: str = "Destination Number"; break;
    case 7: str = "LATA (Not used)"; break;
    case 8: str = "Carrier"; break;
    case 13: str = "ESRD"; break;
    default:
	str = "Reserved";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Type of Digits %u: %s",
	value, str);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Nature of Number");

    subtree = proto_item_add_subtree(item, ett_natnum);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x30) >> 4)
    {
    case 0x00: str = "User provided, not screened"; break;
    case 0x01: str = "User provided, screening passed"; break;
    case 0x02: str = "User provided, screening failed"; break;
    case 0x03: str = "Network provided"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x30, 8);
    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... %u... :  Reserved",
	(value & 0x08) >> 3);

    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... .%u.. :  Number is %savailable",
	(value & 0x04) >> 2, (value & 0x04) ? "not " : "");

    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... ..%u. :  Presentation %s",
	(value & 0x02) >> 1, (value & 0x02) ? "Restricted" : "Allowed");

    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	".... ...%u :  %s",
	value & 0x01, (value & 0x01) ? "International" : "National");

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    plan = (value & 0xf0) >> 4;
    switch (plan)
    {
    case 0x00: str = "Unknown or not applicable"; break;
    case 0x01: str = "ISDN Numbering (Not used)"; break;
    case 0x02: str = "Telephony Numbering (ITU-T Rec. E.164, E.163)"; break;
    case 0x03: str = "Data Numbering (ITU-T Rec. X.121)(Not used)"; break;
    case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)(Not used)"; break;
    case 0x05: str = "Maritime Mobile Numbering (Not used)"; break;
    case 0x06: str = "Land Mobile Numbering (ITU-T Rec. E.212)"; break;
    case 0x07: str = "Private Numbering Plan (service provider defined)"; break;
    case 0x0d: str = "ANSI SS7 Point Code (PC) and Subsystem Number (SSN)"; break;
    case 0x0e: str = "Internet Protocol (IP) Address"; break;
    case 0x0f: str = "Reserved for extension"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Numbering Plan: %s",
	bigbuf, str);

    enc = value & 0x0f;
    switch (enc)
    {
    case 0x00: str = "Not used"; break;
    case 0x01: str = "BCD"; break;
    case 0x02: str = "IA5"; break;
    case 0x03: str = "Octet String"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Encoding: %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    if (plan == 0x0d)
    {
	asn1_int32_value_decode(asn1, 1, &b1);
	asn1_int32_value_decode(asn1, 1, &b2);
	asn1_int32_value_decode(asn1, 1, &b3);
	asn1_int32_value_decode(asn1, 1, &b4);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Point Code %u-%u-%u  SSN %u",
	    b3, b2, b1, b4);
    }
    else if (plan == 0x0e)
    {
	asn1_int32_value_decode(asn1, 1, &b1);
	asn1_int32_value_decode(asn1, 1, &b2);
	asn1_int32_value_decode(asn1, 1, &b3);
	asn1_int32_value_decode(asn1, 1, &b4);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "IP Address %u.%u.%u.%u",
	    b1, b2, b3, b4);
    }
    else
    {
	asn1_int32_value_decode(asn1, 1, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Number of Digits: %u",
	    value);

	if (enc == 0x02)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		asn1->offset, value,
		"IA5 Digits: %s",
		tvb_format_text(asn1->tvb, asn1->offset, value));

	    asn1->offset += value;
	}
	else if (enc == 0x01)
	{
	    saved_offset = asn1->offset;
	    asn1_string_value_decode(asn1, (value+1)/2, &poctets);

	    my_dgt_tbcd_unpack(bigbuf, poctets, (value+1)/2, &Dgt_tbcd);
	    g_free(poctets);

	    if (searchable)
	    {
			proto_tree_add_string_format(tree, hf_ansi_map_number, asn1->tvb,
				saved_offset, (value+1)/2,
				bigbuf,
				"BCD Digits: %s",
				bigbuf);
	    }
	    else
	    {
			proto_tree_add_text(tree, asn1->tvb,
				saved_offset, (value+1)/2,
				"BCD Digits: %s",
				bigbuf);
		}
	}
	}
}

static void
param_digits(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    param_digits_basic(asn1, tree, len, FALSE);
}

static void
param_mdn(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    param_digits_basic(asn1, tree, len, TRUE);
}

static void
param_esn(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 4, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"ESN 0x%04x",
	value);

    g_snprintf(add_string, string_len, " - 0x%04x", value);
}

static void
param_sms_noti(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Notify when available"; break;
    case 2: str = "Do not notify when available"; break;
    default:
	if ((value >= 3) && (value <= 127)) { str = "Reserved, treat as Notify when available"; }
	else if ((value >= 128) && (value <= 223)) { str = "Reserved, treat as Do not notify when available"; }
	else { str = "Reserved for protocol extension"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_sms_orig_restric(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x08)
    {
    case 0x00: str = "No effect"; break;
    default:
	str = "Force indirect";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Force Message Center, %s",
	bigbuf, str);

    switch (value & 0x04)
    {
    case 0x00: str = "Block direct"; break;
    default:
	str = "Allow direct";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  DIRECT, %s",
	bigbuf, str);

    switch (value & 0x03)
    {
    case 0x00: str = "Block all"; break;
    case 0x02: str = "Allow specific"; break;
    case 0x03: str = "Allow all"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  DEFAULT, %s",
	bigbuf, str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_seizure(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Unspecified"; break;
    case 1: str = "Loopback"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved"; }
	else { str = "Reserved for protocol extension"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_sms_tele(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    ansi_map_sms_tele_id = -1;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    str = match_strval(value, ansi_tele_strings);
    if (str == NULL)
    {
	switch (value)
	{
	case 0: str = "Not used"; break;
	default:
	    if ((value >= 2) && (value <= 4095)) { str = "Reserved for assignment by TIA/EIA-41"; }
	    else if ((value >= 4100) && (value <= 32512)) { str = "Reserved for assignment by TIA/EIA-41"; }
	    else if ((value >= 32514) && (value <= 32639)) { str = "Reserved for assignment by this Standard for TDMA MS-based SMEs."; }
	    else if ((value >= 32640) && (value <= 32767)) { str = "Reserved for carrier specific teleservices for TDMA MS-based SMEs."; }
	    else if ((value >= 32768) && (value <= 49151)) { str = "Reserved for node specific teleservices."; }
	    else if ((value >= 49152) && (value <= 65535)) { str = "Reserved for carrier specific teleservices."; }
	    else { str = "Unknown teleservice ID"; }
	    break;
	}
    }

    ansi_map_sms_tele_id = value;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_sms_term_restric(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x04)
    {
    case 0x00: str = "Block messages charged to destination"; break;
    default:
	str = "Allow messages charged to destination";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reverse Charges, %s",
	bigbuf, str);

    switch (value & 0x03)
    {
    case 0x00: str = "Block all"; break;
    case 0x02: str = "Allow specific"; break;
    case 0x03: str = "Allow all"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  DEFAULT, %s",
	bigbuf, str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_sms_msg_count(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;
    char *buf;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "No more pending SMS messages"; break;
    default:
        buf=ep_alloc(64);
	g_snprintf(buf, 64, "%u pending SMS messages", value);
	str = buf;
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_qos_pri(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, temp_int;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    temp_int = (value & 0xf0) >> 4;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_QOS_PRI_STR))
    {
	str = "Reserved";
    }
    else
    {
	str = qos_pri_str[temp_int];
    }

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Assured Priority, %s",
	bigbuf,
	str);

    temp_int = value & 0x0f;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_QOS_PRI_STR))
    {
	str = "Reserved";
    }
    else
    {
	str = qos_pri_str[temp_int];
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Non-Assured Priority, %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_calling_party_cat(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Calling Party's Category, Refer to ITU-T Q.763 (Signalling System No. 7 ISDN user part formats and codes) for encoding of this parameter");
}

/*
 * Dissect IOS data parameters expected to be in TLV format
 */
static void
dissect_cdma2000_ios_data(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32	value;
    guint	num_elems;
    guchar	elem_len;
    guint32	orig_offset, saved_offset;
    proto_tree	*subtree;
    proto_item	*item;
    const gchar	*str;
    gint	idx;

    num_elems = 0;
    orig_offset = saved_offset = asn1->offset;

    while ((saved_offset - orig_offset + 2) <= len)
    {
	num_elems++;

	asn1_int32_value_decode(asn1, 1, &value);
	str = match_strval_idx((guint32) value, ansi_a_ios401_elem_1_strings, &idx);

	asn1_octet_decode(asn1, &elem_len);

	item =
	    proto_tree_add_text(tree,
		asn1->tvb, saved_offset, elem_len + 2,
		"IOS - %s",
		str);

	subtree = proto_item_add_subtree(item, ett_ansi_map_ios401_elem[idx]);

	proto_tree_add_none_format(subtree, hf_ansi_map_ios401_elem_id, asn1->tvb,
	    saved_offset, 1, "Element ID");

	proto_tree_add_uint(subtree, hf_ansi_map_length, asn1->tvb,
	    saved_offset + 1, 1, elem_len);

	if (elem_len > 0)
	{
	    proto_tree_add_text(subtree,
		asn1->tvb, saved_offset + 2, elem_len,
		"Element Value");

	    asn1->offset += elem_len;
	}

	saved_offset += elem_len + 2;
    }

    g_snprintf(add_string, string_len, " - (%u)", num_elems);

    EXTRANEOUS_DATA_CHECK((len - (saved_offset - orig_offset)), 0);
}

static void
param_cdma2000_ho_ivk_ios(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{

    dissect_cdma2000_ios_data(asn1, tree, len, add_string, string_len);
}

static void
param_cdma2000_ho_rsp_ios(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{

    dissect_cdma2000_ios_data(asn1, tree, len, add_string, string_len);
}

static void
param_msid_usage(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x03)
    {
    case 0: str = "Not used"; break;
    case 1: str = "MIN last used"; break;
    case 2: str = "IMSI last used"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_new_min_ext(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  MCC_M (MSB), see CDMA",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0e, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  IMSI_M_ADDR_NUM, see CDMA",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  IMSI_M_CLASS, see CDMA",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    bigbuf[0] = Dgt_tbcd.out[(value & 0xf0) >> 4];

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    bigbuf[1] = Dgt_tbcd.out[value & 0x0f];
    bigbuf[2] = Dgt_tbcd.out[(value & 0xf0) >> 4];
    bigbuf[3] = '\0';

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"MCC_M, %s, see CDMA",
	bigbuf);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    bigbuf[0] = Dgt_tbcd.out[value & 0x0f];
    bigbuf[1] = Dgt_tbcd.out[(value & 0xf0) >> 4];
    bigbuf[2] = '\0';

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"IMSI_11_12, %s, see CDMA",
	bigbuf);
}

static void
param_dtx_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfe, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x01)
    {
    case 0: str = "Discontinuous Transmission mode is not active"; break;
    case 1: str = "Discontinuous Transmission mode is active"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_mob_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfe, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x01)
    {
    case 0: str = "No MS-initiated position determination"; break;
    case 1: str = "MS-initiated position determination"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_gen_time(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    gint32 h, m, s, ts;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 6);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Year-2000, %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Month, %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Day of month, %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 3, &value);

    h = value / (3600 * 10);
    m = (value - (h * (3600 * 10))) / (60 * 10);
    s = (value - (h * (3600 * 10)) - (m * (60 * 10))) / 10;
    ts = (value - (h * (3600 * 10)) - (m * (60 * 10)) - (s * 10));

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Time of day (UTC) (in tenths of seconds - 1), %u (%u:%u:%u.%u)",
	value,
	h,
	m,
	s,
	ts);

    EXTRANEOUS_DATA_CHECK(len, 6);
}

static void
param_geo_pos(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"Calling Geodetic Location (CGL), see T1.628 CallingGeodeticLocation TCAP parameter for encoding");
}

static void
param_mob_call_status(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, auth;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    auth = (value & 0xf0) >> 4;
    switch (auth)
    {
    case 0: str = "Authorization not performed"; break;
    case 1: str = "Authorization successful"; break;
    case 2: str = "Invalid Electronic Serial Number (ESN)"; break;
    case 3: str = "Unassigned Directory Number (DN)"; break;
    case 4: str = "Duplicate Unit"; break;
    case 5: str = "Delinquent Account"; break;
    case 6: str = "Stolen Unit"; break;
    case 7: str = "Not authorized for MSC"; break;
    case 8: str = "Unspecified"; break;
    default:
	str = "Reserved, treat as Authorization not performed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Authorization, %s",
	bigbuf,
	str);

    auth = value & 0x0f;
    switch (auth)
    {
    case 0: str = "Authentication not performed. Authentication has not yet occurred or the MS is not capable of authentication"; break;
    case 1: str = "Authentication successful. Authentication has successfully occurred on the MS"; break;
    case 2: str = "Authentication failure. An authentication failure has occurred on the MS"; break;
    default:
	str = "Reserved, treat as Authentication not performed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Authentication, %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_pos_req_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Initial position. Return updated position only if initial position is unavailable."; break;
    case 2: str = "Return the updated position"; break;
    case 3: str = "Return the updated or last known position"; break;
    case 4: str = "Reserved for LSP interface. Treat as Not used"; break;
    default:
	if ((value >= 5) && (value <= 95)) { str = "Reserved, treat as Initial position"; }
	else { str = "Reserved for protocol extension, treat as Initial position"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Position Request Type, %s",
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_pos_result(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Initial position returned"; break;
    case 2: str = "Updated position returned"; break;
    case 3: str = "Last known position returned"; break;
    case 4: str = "Requested position is not available"; break;
    case 5: str = "Caller disconnected. No call in progress for caller identified"; break;
    case 6: str = "Caller has handed-off. Position is unavailable due to a hand-off (e.g. handoff to a position incapable system)"; break;
    case 7: str = "Identified MS is inactive or has roamed to another system"; break;
    case 8: str = "Unresponsive"; break;
    case 9: str = "Identified MS is responsive, but refused position request"; break;
    case 10: str = "System Failure"; break;
    case 11: str = "MSID is not known"; break;
    case 12: str = "Callback number is not known"; break;
    case 13: str = "Improper request (e.g. invalid channel information, invalid ESN)"; break;
    case 14: str = "Mobile channel information returned"; break;
    case 15: str = "Signal not detected"; break;
    case 16: str = "PDE Timeout"; break;
    case 17: str = "Position pending"; break;
    case 18: str = "TDMA MAHO Information Returned"; break;
    case 19: str = "TDMA MAHO Information is not available"; break;
    default:
	if ((value >= 20) && (value <= 223)) { str = "Reserved, treat as Not used"; }
	else { str = "Reserved for protocol extension, treat as Not used"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Position Result, %s",
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_pos_source(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Network Unspecified"; break;
    case 2: str = "Network AOA (Angle of Arrival)"; break;
    case 3: str = "Network TOA (Time of Arrival)"; break;
    case 4: str = "Network TDOA (Time Difference of Arrival)"; break;
    case 5: str = "Network RF Fingerprinting"; break;
    case 6: str = "Network Cell/Sector"; break;
    case 7: str = "Network Cell/Sector with Timing"; break;
    case 16: str = "Handset Unspecified"; break;
    case 17: str = "Handset GPS"; break;
    case 18: str = "Handset AGPS (Assisted GPS)"; break;
    case 19: str = "Handset EOTD (Enhanced Observed Time Difference)"; break;
    case 20: str = "Handset AFLT (Advanced Forward Link Trilateration)"; break;
    case 21: str = "Handset EFLT (Enhanced Forward Link Trilateration)"; break;
    default:
	if ((value >= 8) && (value <= 15)) { str = "Reserved, treat as Network Unspecified"; }
	else if ((value >= 22) && (value <= 31)) { str = "Reserved, treat as Handset Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Not used"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Position Source, %s",
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_acg_encounter(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xc0) >> 6)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Service Management System Initiated control encountered"; break;
    case 2: str = "SCF Overload control encountered"; break;
    case 3: str = "Reserved, treat as Not used"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Control Type, %s",
	bigbuf,
	str);

    switch (value & 0x3f)
    {
    case 0: str = "PC_SSN"; break;
    case 1: str = "1-digit control"; break;
    case 2: str = "2-digit control"; break;
    case 3: str = "3-digit control"; break;
    case 4: str = "4-digit control"; break;
    case 5: str = "5-digit control"; break;
    case 6: str = "6-digit control"; break;
    case 7: str = "7-digit control"; break;
    case 8: str = "8-digit control"; break;
    case 9: str = "9-digit control"; break;
    case 10: str = "10-digit control"; break;
    case 11: str = "11-digit control"; break;
    case 12: str = "12-digit control"; break;
    case 13: str = "13-digit control"; break;
    case 14: str = "14-digit control"; break;
    case 15: str = "15-digit control"; break;
    default:
	str = "Reserved, treat as 15-digit control";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);
}

static void
param_ctrl_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xc0) >> 6)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Service Management System Initiated control"; break;
    case 2: str = "SCF Overload control"; break;
    case 3: str = "Reserved, treat as Not used"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Control Type, %s",
	bigbuf,
	str);

    switch (value & 0x3f)
    {
    case 0: str = "PC_SSN"; break;
    case 1: str = "1-digit control"; break;
    case 2: str = "2-digit control"; break;
    case 3: str = "3-digit control"; break;
    case 4: str = "4-digit control"; break;
    case 5: str = "5-digit control"; break;
    case 6: str = "6-digit control"; break;
    case 7: str = "7-digit control"; break;
    case 8: str = "8-digit control"; break;
    case 9: str = "9-digit control"; break;
    case 10: str = "10-digit control"; break;
    case 11: str = "11-digit control"; break;
    case 12: str = "12-digit control"; break;
    case 13: str = "13-digit control"; break;
    case 14: str = "14-digit control"; break;
    case 15: str = "15-digit control"; break;
    default:
	str = "Reserved, treat as 15-digit control";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);
}

static void
param_gap_duration(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "1 second"; break;
    case 2: str = "2 seconds"; break;
    case 3: str = "4 seconds"; break;
    case 4: str = "8 seconds"; break;
    case 5: str = "16 seconds"; break;
    case 6: str = "32 seconds"; break;
    case 7: str = "64 seconds"; break;
    case 8: str = "128 seconds"; break;
    case 9: str = "256 seconds"; break;
    case 10: str = "512 seconds"; break;
    case 11: str = "1024 seconds"; break;
    case 12: str = "2048 seconds"; break;
    case 13: str = "Infinity"; break;
    default:
	str = "Reserved, treat as Not used";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_scf_overload_gap_int(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "0 seconds"; break;
    case 1: str = "3 seconds"; break;
    case 2: str = "4 seconds"; break;
    case 3: str = "6 seconds"; break;
    case 4: str = "8 seconds"; break;
    case 5: str = "11 seconds"; break;
    case 6: str = "16 seconds"; break;
    case 7: str = "22 seconds"; break;
    case 8: str = "30 seconds"; break;
    case 9: str = "42 seconds"; break;
    case 10: str = "58 seconds"; break;
    case 11: str = "81 seconds"; break;
    case 12: str = "112 seconds"; break;
    case 13: str = "156 seconds"; break;
    case 14: str = "217 seconds"; break;
    case 15: str = "300 seconds"; break;
    case 16: str = "Remove gap control"; break;
    case 17: str = "0.10 seconds"; break;
    case 18: str = "0.25 seconds"; break;
    case 19: str = "0.5 seconds"; break;
    case 20: str = "1 second"; break;
    case 21: str = "2 seconds"; break;
    default:
	str = "Reserved, treat as 0 seconds";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_tdma_time_align(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);


    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Time Alignment Offset (TA), %u",
	bigbuf,
	value & 0x1f);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
dump_rssi(ASN1_SCK *asn1, proto_tree *tree, const gchar *leader)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xc0) >> 6)
    {
    case 0: str = "800 MHz"; break;
    case 1: str = "1900 MHz"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %sHyper, %s",
	bigbuf,
	leader,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %sRSSI, %u",
	bigbuf,
	leader,
	value & 0x1f);
}

static void
param_tdma_maho_cell_id(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 value, num_rssi, num_msc;
    guint saved_offset, orig_offset;
    gint32 i, j;

    SHORT_DATA_CHECK(len, 3);

    orig_offset = asn1->offset;

    dump_rssi(asn1, tree, "Serving Cell ");

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &num_rssi);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Number of RSSI %u",
	num_rssi);

    for (i = 0; i < num_rssi; i++)
    {
	if ((len - (asn1->offset - orig_offset)) < 3)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		asn1->offset, len - (asn1->offset - orig_offset),
		"Short Data (?)");

	    asn1->offset += len - (asn1->offset - orig_offset);
	    return;
	}

	dump_rssi(asn1, tree, "");

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 2, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Measured Cell ID %u",
	    value);
    }

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &num_msc);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Number of MSC %u",
	num_msc);

    for (i = 0; i < num_msc; i++)
    {
	if ((len - (asn1->offset - orig_offset)) < 4)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		asn1->offset, len - (asn1->offset - orig_offset),
		"Short Data (?)");

	    asn1->offset += len - (asn1->offset - orig_offset);
	    return;
	}

	param_mscid(asn1, tree, 3, add_string, string_len);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &num_rssi);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Number of RSSI %u",
	    num_rssi);

	for (j = 0; j < num_rssi; j++)
	{
	    if ((len - (asn1->offset - orig_offset)) < 3)
	    {
		proto_tree_add_text(tree, asn1->tvb,
		    asn1->offset, len - (asn1->offset - orig_offset),
		    "Short Data (?)");

		asn1->offset += len - (asn1->offset - orig_offset);
		return;
	    }

	    dump_rssi(asn1, tree, "");

	    saved_offset = asn1->offset;

	    asn1_int32_value_decode(asn1, 2, &value);

	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset,
		"Measured Cell ID %u",
		value);
	}
    }

    EXTRANEOUS_DATA_CHECK((len - (asn1->offset - orig_offset)), 0);
}

static void
param_tdma_maho_chan(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    gint32 value, num_rssi, num_msc;
    guint saved_offset, orig_offset;
    gint32 i, j;

    SHORT_DATA_CHECK(len, 3);

    orig_offset = asn1->offset;

    dump_rssi(asn1, tree, "Serving Cell ");

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &num_rssi);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Number of RSSI %u",
	num_rssi);

    for (i = 0; i < num_rssi; i++)
    {
	if ((len - (asn1->offset - orig_offset)) < 3)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		asn1->offset, len - (asn1->offset - orig_offset),
		"Short Data (?)");

	    asn1->offset += len - (asn1->offset - orig_offset);
	    return;
	}

	dump_rssi(asn1, tree, "");

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 2, &value);

	other_decode_bitfield_value(bigbuf, value >> 8, 0xff, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Measured Channel (MSB), %u",
	    bigbuf,
	    (value & 0xffe0) >> 5);

	other_decode_bitfield_value(bigbuf, value & 0xff, 0xe0, 8);
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset+1, 1,
	    "%s :  Measured Channel (LSB)",
	    bigbuf);
    }

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &num_msc);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Number of MSC %u",
	num_msc);

    for (i = 0; i < num_msc; i++)
    {
	if ((len - (asn1->offset - orig_offset)) < 4)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		asn1->offset, len - (asn1->offset - orig_offset),
		"Short Data (?)");

	    asn1->offset += len - (asn1->offset - orig_offset);
	    return;
	}

	param_mscid(asn1, tree, 3, add_string, string_len);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &num_rssi);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Number of RSSI %u",
	    num_rssi);

	for (j = 0; j < num_rssi; j++)
	{
	    if ((len - (asn1->offset - orig_offset)) < 3)
	    {
		proto_tree_add_text(tree, asn1->tvb,
		    asn1->offset, len - (asn1->offset - orig_offset),
		    "Short Data (?)");

		asn1->offset += len - (asn1->offset - orig_offset);
		return;
	    }

	    dump_rssi(asn1, tree, "");

	    saved_offset = asn1->offset;

	    asn1_int32_value_decode(asn1, 2, &value);

	    other_decode_bitfield_value(bigbuf, value >> 8, 0xff, 8);
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, 1,
		"%s :  Measured Channel (MSB), %u",
		bigbuf,
		(value & 0xffe0) >> 5);

	    other_decode_bitfield_value(bigbuf, value & 0xff, 0xe0, 8);
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset+1, 1,
		"%s :  Measured Channel (LSB)",
		bigbuf);
	}
    }

    EXTRANEOUS_DATA_CHECK((len - (asn1->offset - orig_offset)), 0);
}

static void
param_tdma_maho_req(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "No MAHO information requested"; break;
    case 1: str = "MAHO information requested"; break;
    default:
	str = "Reserved, treat as No MAHO information requested";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_sm_gap_int(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Remove gap control"; break;
    case 1: str = "0 seconds"; break;
    case 2: str = "0.10 seconds"; break;
    case 3: str = "0.25 seconds"; break;
    case 4: str = "0.50 seconds"; break;
    case 5: str = "1 second"; break;
    case 6: str = "2 seconds"; break;
    case 7: str = "5 seconds"; break;
    case 8: str = "10 seconds"; break;
    case 9: str = "15 seconds"; break;
    case 10: str = "30 seconds"; break;
    case 11: str = "60 seconds"; break;
    case 12: str = "120 seconds"; break;
    case 13: str = "300 seconds"; break;
    case 14: str = "600 seconds"; break;
    case 15: str = "Stop all queries"; break;
    default:
	str = "Reserved, treat as Remove gap control";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_mob_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset, i;
    const gchar *str = NULL;

    for (i=0; i < len; i++)
    {
	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "Undefined Mobile Position Capabilities"; break;
	case 1: str = "CDMA None"; break;
	case 2: str = "CDMA Pilot Phase + GPS - MS shall be capable of supporting A-FLT and GPS for position determination"; break;
	case 3: str = "CDMA Pilot Phase Only - MS shall be capable of supporting A-FLT only for position determination"; break;
	case 4: str = "CDMA GPS Only - MS shall be capable of supporting GPS only for position determination"; break;
	case 51: str = "TDMA None. See TIA/EIA-136-740"; break;
	case 52: str = "TDMA MS-Based with Network Assistance SAMPS Supported. See TIA/EIA-136-740"; break;
	case 53: str = "TDMA MS-Assisted SAMPS Supported. See TIA/EIA-136-740"; break;
	case 54: str = "TDMA SAMPS Time Measurement Capability Supported. See TIA/EIA-136-740"; break;
	case 55: str = "TDMA MS-Based Stand-alone SAMPS Supported. See TIA/EIA-136-740"; break;
	case 101: str = "AMPS None"; break;
	case 102: str = "AMPS MS-based - MS shall be capable of autonomously determining the position without assistance from the network"; break;
	case 103: str = "AMPS assisted GPS - MS shall be capable of utilizing network assistance in providing GPS satellite measurements for position determination in the network or of utilizing network assistance in position determination in the MS"; break;
	default:
	    if ((value >= 5) && (value <= 50)) { str = "Reserved for CDMA, treat as CDMA None"; }
	    else if ((value >= 56) && (value <= 100)) { str = "Reserved for TDMA, treat as TDMA None"; }
	    else if ((value >= 104) && (value <= 150)) { str = "Reserved for AMPS, treat as AMPS None"; }
	    else if ((value >= 151) && (value <= 223)) { str = "Reserved, treat as Undefined"; }
	    else { str = "Reserved for protocol extension, treat as Undefined"; }
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Mobile Position Capability, %s",
	    str);
    }
}

static void
param_cdma_psmm_count(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Number of CDMA Pilot Strength Measurements to return, %u",
	value);
}

static void
param_cdma_sowd2(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 5);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"CDMA Serving One Way Delay, %u",
	value);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x03)
    {
    case 0: str = "100 nsec"; break;
    case 1: str = "50 nsec"; break;
    case 2: str = "1/16 CDMA PN Chip"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Resolution, %s",
	bigbuf,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Serving One Way Delay TimeStamp, %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 5);
}

static void
param_sms_charge_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "No charge"; break;
    case 2: str = "Charge original originator"; break;
    case 3: str = "Charge original destination"; break;
    default:
	str = "Reserved";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Charge %u, %s",
	value,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_auth_per(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Per call"; break;
    case 2: str = "Hours"; break;
    case 3: str = "Days"; break;
    case 4: str = "Weeks"; break;
    case 5: str = "Per agreement"; break;
    case 6: str = "Indefinite"; break;
    case 7: str = "Number of calls"; break;
    default:
	if ((value >= 8) && (value <= 223)) { str = "Reserved, treat as Per call"; }
	else { str = "Reserved for protocol extension, treat as Per call"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Period (%u) %s",
	value,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value %u",
	value);
}

static void
param_ctrl_chan_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Unknown"; break;
    case 1: str = "MS is in Analog CC Mode"; break;
    case 2: str = "MS is in Digital CC Mode"; break;
    case 3: str = "MS is in NAMPS CC Mode"; break;
    default:
	if ((value >= 4) && (value <= 223)) { str = "Reserved, treat as Unknown"; }
	else { str = "Reserved for protocol extension, treat as Unknown"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_tdma_data_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xe0) >> 5)
    {
    case 0: str = "As per IS-135"; break;
    case 1: str = "As per FSVS - 211 (STU-III)"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Data Part, %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  AD, %s",
	bigbuf,
	(value & 0x10) ? "unacknowledged data only" : "unacked data or both");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	(value & 0x08) ? "SAP 0 and 1" : "SAP 0 only");

    switch (value & 0x07)
    {
    case 0: str = "No Data Privacy"; break;
    case 1: str = "Data Privacy Algorithm A"; break;
    default:
	str = "Reserved, treat as No Data Privacy";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x07, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Data Privacy Mode, %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x0c) >> 2)
    {
    case 0: str = "RLP1"; break;
    case 1: str = "RLP2"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    switch (value & 0x03)
    {
    case 0: str = "16-bit Cyclic Redundancy Check"; break;
    case 1: str = "24-bit Cyclic Redundancy Check"; break;
    case 2: str = "No Cyclic Redundancy Check"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 2);
}

static void
param_tdma_voice_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0xf0) >> 4)
    {
    case 0: str = "No Voice Privacy"; break;
    case 1: str = "Voice Privacy Algorithm A"; break;
    case 2: str = "Reserved, treat as No Voice Privacy"; break;
    case 3: str = "Reserved, treat as No Voice Privacy"; break;
    case 4: str = "Reserved for SOC/BMSC Specific signaling"; break;
    default:
	str = "Reserved, treat as No Voice Privacy";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Privacy Mode, %s",
	bigbuf,
	str);

    switch (value & 0x0f)
    {
    case 0: str = "No Voice Coder"; break;
    case 1: str = "VSELP Voice Coder"; break;
    case 2: str = "IS-641 Voice Coder"; break;
    case 6: str = "Reserved for SOC/BMSC Specific signaling"; break;
    default:
	str = "Reserved, treat as No Voice Coder";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Coder, %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_tdma_bandwidth(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x0f)
    {
    case 0: str = "Half-Rate Digital Traffic Channel Only"; break;
    case 1: str = "Full-Rate Digital Traffic Channel Only"; break;
    case 2: str = "Half-Rate or Full-rate Digital Traffic Channel - Full-Rate Preferred"; break;
    case 3: str = "Half-rate or Full-rate Digital Traffic Channel - Half-rate Preferred"; break;
    case 4: str = "Double Full-Rate Digital Traffic Channel Only"; break;
    case 5: str = "Triple Full-Rate Digital Traffic Channel Only"; break;
    default:
	str = "Reserved, treat as Full-Rate Digital Traffic Channel Only";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Bandwidth, %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_change_srvc_attr(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x0c) >> 2)
    {
    case 0: str = "Service Negotiation Used"; break;
    case 1: str = "Service Negotiation Not Used"; break;
    case 2: str = "Service Negotiation Required"; break;
    case 3: str = "Service Negotiation Not Required"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Service Negotiate Flag (SRVNEG), %s",
	bigbuf,
	str);

    switch (value & 0x03)
    {
    case 0 : str = "Change Facilities Operation Requested"; break;
    case 1 : str = "Change Facilities Operation Not Requested"; break;
    case 2 : str = "Change Facilities Operation Used"; break;
    case 3 : str = "Change Facilities Operation Not Used"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Change Facilities Flag (CHGFAC), %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_dp_params(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xfc, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch (value & 0x03)
    {
    case 0: str = "Privacy inactive or not supported"; break;
    case 1: str = "Privacy Requested or Acknowledged"; break;
    default:
	str = "Reserved, treat as Privacy inactive or not supported";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Privacy Mode, %s",
	bigbuf,
	str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Data Privacy Version 1"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved, treat as Not used"; }
	else { str = "Reserved for protocol extension, treat as Not used"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Data Privacy Version, %s",
	str);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len - 2,
	"Data Privacy data");

    asn1->offset += (len - 2);
}

static void
param_trn(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint saved_offset;
    guchar *poctets;

    saved_offset = asn1->offset;

    asn1_string_value_decode(asn1, len, &poctets);

    my_dgt_tbcd_unpack(bigbuf, poctets, len, &Dgt_msid);
    g_free(poctets);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len, "TRN %s", bigbuf);
}

static void
param_islp_info(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "No ISLP supported"; break;
    case 1: str = "ISLP supported (see ISLP)"; break;
    default:
	if ((value >= 2) && (value <= 112)) { str = "Reserved, treat as No ISLP supported"; }
	else if ((value >= 113) && (value <= 223)) { str = "Reserved, treat as ISLP supported"; }
	else if ((value >= 224) && (value <= 240)) { str = "Reserved for protocol extension, treat as No ISLP supported"; }
	else { str = "Reserved for protocol extension, treat as ISLP supported"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_ana_red_info(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Ignore CDMA, %s",
	bigbuf,
	(value & 0x20) ?  "Ignore the CDMA Capability Message on the analog system to which it is being redirected" :
	    "Don't ignore the CDMA Capability Message on the analog system to which it is being redirected");

    switch (value & 0x1f)
    {
    case 0: str = "Attempt to obtain service on either System A or B in accordance with the custom system selection process"; break;
    case 1: str = "Attempt to obtain service on System A only"; break;
    case 2: str = "Error in IS-735, text was unspecified but not reserved"; break;
    case 3: str = "Attempt to obtain service on System A first.  If unsuccessful, attempt to obtain service on System B"; break;
    case 4: str = "Attempt to obtain service on System B first.  If unsuccessful, attempt to obtain service on System A"; break;
    case 5: str = "Attempt to obtain service on either System A or System B. If unsuccessful, attempt to obtain service on the alternate system (System A or System B)"; break;

    default:
	str = "Reserved for protocol extension";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Sys Ordering, %s",
	bigbuf,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_reason_list(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    gint i;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    i = 0;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "Unknown"; break;
	case 1: str = "Unable to configure ISLP"; break;
	case 2: str = "ISLP failure"; break;
	case 3: str = "Service allowed but facilities not available"; break;
	case 4: str = "Service not allowed"; break;
	case 5: str = "No Response to TMSI assignment"; break;
	case 6: str = "Required parameters unavailable. (e.g., as indicated by the RequiredParametersMask parameter)"; break;
	default:
	    if ((value >= 7) && (value <= 110)) { str = "Reserved for common CDMA and TDMA network error causes. If unknown, treat as Unknown"; }
	    else if ((value >= 111) && (value <= 127)) { str = "Reserved for common CDMA and TDMA network error causes for protocol extension. If unknown, treat as Unknown"; }
	    else if ((value >= 128) && (value <= 174)) { str = "CDMA Specific error causes. If unknown, treat as Unknown"; }
	    else if ((value >= 175) && (value <= 191)) { str = "CDMA Specific error causes for protocol extension. If unknown treat as Unknown"; }
	    else if ((value >= 192) && (value <= 237)) { str = "TDMA Specific error causes as defined by the TDMACause parameter. If unknown treat as Unknown"; }
	    else { str = "TDMA Specific error causes for protocol extension. If unknown, treat as Unknown"; }
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "[%u] %s",
	    i++,
	    str);

	saved_offset = asn1->offset;
    }
    while ((len - i) > 0);
}

static void
param_imsi(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    guint saved_offset;
    guchar *poctets;

    saved_offset = asn1->offset;
    asn1_string_value_decode(asn1, len, &poctets);

    my_dgt_tbcd_unpack(bigbuf, poctets, len, &Dgt_msid);
    g_free(poctets);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	"IMSI %s",
	bigbuf);

    g_snprintf(add_string, string_len, " - %s", bigbuf);
}

static void
param_min_basic(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len, gboolean true_min)
{
    guint saved_offset;
    guchar *poctets;

    EXACT_DATA_CHECK(len, 5);

    saved_offset = asn1->offset;
    asn1_string_value_decode(asn1, len, &poctets);

    my_dgt_tbcd_unpack(bigbuf, poctets, len, &Dgt_msid);
    g_free(poctets);

    if (true_min)
    {
	proto_tree_add_string_format(tree, hf_ansi_map_min, asn1->tvb,
	    saved_offset, len,
	    bigbuf,
	    "MIN %s",
	    bigbuf);
    }
    else
    {
    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, len,
		"MIN %s",
		bigbuf);
	}

    g_snprintf(add_string, string_len, " - %s", bigbuf);
}

static void
param_ms_min(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    param_min_basic(asn1, tree, len, add_string, string_len, FALSE);
}

static void
param_new_min(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    param_min_basic(asn1, tree, len, add_string, string_len, FALSE);
}

static void
param_min(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    param_min_basic(asn1, tree, len, add_string, string_len, TRUE);
}

static void
param_auth_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "No authentication required"; break;
    case 2: str = "Authentication required"; break;
    case 128: str = "Authentication required and UIM capable"; break;
    default:
	if ((value >= 3) && (value <= 95)) { str = "Reserved, treat as No authentication required"; }
	else if ((value >= 96) && (value <= 127)) { str = "Reserved for protocol extension, treat as No authentication required"; }
	else if ((value >= 129) && (value <= 223)) { str = "Reserved, treat as Authentication required"; }
	else { str = "Reserved for protocol extension, treat as Authentication required"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_sus_acc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Anomalous digits"; break;
    case 2: str = "Unspecified"; break;
    default:
	if ((value >= 3) && (value <= 113)) { str = "Reserved, treat as Anomalous digits"; }
	else if ((value >= 114) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Reason, %s",
	str);
}

static void
param_dis_text(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Spec. has hardcoded 1",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x7f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Display type, see ANSI T1.610 for encoding",
	bigbuf);

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len - 1,
	"Display data");

    asn1->offset += len - 1;
}

static void
param_dis_text2(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint orig_offset, saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 4);

    orig_offset = asn1->offset;
    saved_offset = asn1->offset;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "Not used"; break;
	case 1: str = "ASCII"; break;
	case 2: str = "ITU T.50. The International Reference Alphabet as defined in ITU-R Rec. T.50"; break;
	case 3: str = "User Specific"; break;
	case 4: str = "ISO 8859-1. The 8-bit single-byte coded character set Latin 1 as defined in ISO/IEC Standard 8859-1"; break;
	case 5: str = "ISO 10646. The Universal Multiple-Octet Coded Character Set (USC) as defined in ISO/IEC Standard 10646"; break;
	case 6: str = "ISO 8859-8. The 8-bit single-byte coded character set Hebrew as defined in ISO/IEC Standard 8859-8"; break;
	case 7: str = "IS-91 Extended Protocol Message. The length is determined by the Message Type; see TIA/EIA/IS-90"; break;
	case 8: str = "Shift-JIS. Variable 1-2 byte nonmodal encoding for Kanji, Kana, and Latin character sets defined in JIS X0201 and JIS X0206"; break;
	case 9: str = "KC C 5601. Variable 1-2 byte Korean encoding method"; break;
	default:
	    if ((value >= 10) && (value <= 223)) { str = "Reserved, treat as ASCII"; }
	    else { str = "Reserved, treat as ASCII"; }
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Display Character Set, %s",
	    str);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Display Type, %u, see ANSI T1.610",
	    value);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Display Tag, %u",
	    value);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Display Length, %u",
	    value);

	saved_offset = asn1->offset;

	if (value > 0)
	{
	    if ((guint32) value > (len - (saved_offset - orig_offset)))
	    {
		proto_tree_add_text(tree, asn1->tvb,
		    saved_offset, len - (saved_offset - orig_offset),
		    "Short Data (?)");

		asn1->offset += len - (saved_offset - orig_offset);
		return;
	    }

	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, value,
		"Display data");

	    asn1->offset += value;

	    saved_offset = asn1->offset;
	}
    }
    while ((len - (saved_offset - orig_offset)) >= 4);

    EXTRANEOUS_DATA_CHECK((len - (saved_offset - orig_offset)), 0);
}

static void
param_dmh_srvc_id(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint orig_offset, saved_offset;

    SHORT_DATA_CHECK(len, 5);

    orig_offset = asn1->offset;
    saved_offset = asn1->offset;

    do
    {
	asn1_int32_value_decode(asn1, 2, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Market ID %u",
	    value);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Market Segment ID %u",
	    value);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 2, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "DMH Service ID Value %u",
	    value);

	saved_offset = asn1->offset;
    }
    while ((len - (saved_offset - orig_offset)) >= 5);

    EXTRANEOUS_DATA_CHECK((len - (saved_offset - orig_offset)), 0);
}

static void
param_feat_ind(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint orig_offset, saved_offset;

    SHORT_DATA_CHECK(len, 5);

    orig_offset = asn1->offset;
    saved_offset = asn1->offset;

    do
    {
	asn1_int32_value_decode(asn1, 2, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Market ID %u",
	    value);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 1, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Market Segment ID %u",
	    value);

	saved_offset = asn1->offset;

	asn1_int32_value_decode(asn1, 2, &value);

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "DMH Service ID Value %u",
	    value);

	saved_offset = asn1->offset;
    }
    while ((len - (saved_offset - orig_offset)) >= 5);

    EXTRANEOUS_DATA_CHECK((len - (saved_offset - orig_offset)), 0);
}

static void
param_a_key_ver(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    gint i;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    i = 0;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0: str = "Not used"; break;
	case 1: str = "A-key Generation not supported"; break;
	case 2: str = "Diffie Hellman with 768-bit modulus, 160-bit primitive, and 160-bit exponents"; break;
	case 3: str = "Diffie Hellman with 512-bit modulus, 160-bit primitive, and 160-bit exponents"; break;
	case 4: str = "Diffie Hellman with 768-bit modulus, 32-bit primitive, and 160-bit exponents"; break;
	default:
	    if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as A-key Generation not supported"; }
	    else { str = "Reserved for protocol extension, treat as A-key Generation not supported"; }
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "[%u] %s",
	    i++,
	    str);

	saved_offset = asn1->offset;
    }
    while ((len - i) > 0);
}

static void
param_inter_msg_time(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Timer Value, %u, %u seconds",
	value,
	value * 10);

	/* XXX * 10 or / 10 ? */
}

static void
param_rel_cause(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Unspecified"; break;
    case 1: str = "Calling Party"; break;
    case 2: str = "Called Party"; break;
    case 3: str = "Commanded Disconnect"; break;
    default:
	if ((value >= 4) && (value <= 23)) { str = "Reserved, treat as Calling Party"; }
	else if ((value >= 24) && (value <= 31)) { str = "Reserved for protocol extension. If unknown, treat as Calling Party"; }
	else if ((value >= 32) && (value <= 55)) { str = "Reserved, treat as Called Party"; }
	else if ((value >= 56) && (value <= 63)) { str = "Reserved for protocol extension. If unknown, treat as Called Party"; }
	else if ((value >= 64) && (value <= 87)) { str = "Reserved, treat as Commanded Disconnect"; }
	else if ((value >= 88) && (value <= 95)) { str = "Reserved for protocol extension. If unknown, treat as Commanded Disconnect"; }
	else if ((value >= 96) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension. If unknown, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_time_day(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    gint32 h, m, s, ts;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 3);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 3, &value);

    h = value / (3600 * 10);
    m = (value - (h * (3600 * 10))) / (60 * 10);
    s = (value - (h * (3600 * 10)) - (m * (60 * 10))) / 10;
    ts = (value - (h * (3600 * 10)) - (m * (60 * 10)) - (s * 10));

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"(UTC) (in tenths of seconds - 1), %u (%u:%u:%u.%u)",
	value,
	h,
	m,
	s,
	ts);
}

static void
param_call_status(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    if (len > 4)
    {
	proto_tree_add_text(tree, asn1->tvb,
	    asn1->offset, len, "Long Data (?)");
	asn1->offset += len;
	return;
    }

    saved_offset = asn1->offset;

    asn1->offset = saved_offset;

    asn1_int32_value_decode(asn1, len, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Call Setup in Progress"; break;
    case 2: str = "Locally Allowed Call - No Action"; break;
    default:
	if (value < 0) { str = "Reserved for bilateral agreements. If unknown, treat as Not used"; }
	else { str = "Reserved, treat as Not used"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, len,
	str);
}

static void
param_ms_status(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;
    gboolean has_chan;
    gboolean extended;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    extended = (value & 0x80) >> 7;

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Extension (EXT), %s",
	bigbuf,
	extended ? "No Extension, last octet of sequence" : "Extension indicator, the octet continues through the next octet");

    other_decode_bitfield_value(bigbuf, value, 0x60, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Location Information (LOC), %s",
	bigbuf,
	(value & 0x10) ? "MS location information available" : "No MS location information available");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Contact, %s",
	bigbuf,
	(value & 0x08) ? "Radio Contact Established" : "No Radio Contact");

    has_chan = (value & 0x04) >> 2;

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Channel, %s",
	bigbuf,
	has_chan ? "Traffic Channel Assigned" : "No Traffic Channel");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Handoff, %s",
	bigbuf,
	(value & 0x02) ? "Intersystem Handoff" : "No Intersystem Handoff");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Inactive, %s",
	bigbuf,
	(value & 0x01) ? "MS Inactive" : "MS Active");

    if (len == 1) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    if (extended)
    {
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Octet 1a ? spec. does not provide details");

	saved_offset = asn1->offset;

	EXTRANEOUS_DATA_CHECK(len, 2);

	return;
    }

    if (has_chan)
    {
	switch (value)
	{
	case 0: str = "Not used "; break;
	case 1: str = "Analog. The MS is currently assigned to an analog traffic channel"; break;
	case 2: str = "NAMPS. The MS is currently assigned to an NAMPS traffic channel"; break;
	case 3: str = "TDMA. The MS is currently assigned to a TDMA traffic channel"; break;
	case 4: str = "CDMA. The MS is currently assigned to a CDMA traffic channel"; break;
	default:
	    if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Not used"; }
	    else { str = "Reserved for protocol extension, treat as Not used"; }
	    break;
	}

	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Radio Channel Type, %s",
	    str);

	saved_offset = asn1->offset;

	EXTRANEOUS_DATA_CHECK(len, 2);

	return;
    }

    asn1->offset -= 1;

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_pos_info_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  MS Identity (MSID), %s",
	bigbuf,
	(value & 0x10) ? "MS Identity Requested" : "No MS Identity Requested");

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Routing Address (ROUTE), %s",
	bigbuf,
	(value & 0x08) ? "Routing Address Requested" : "No Routing Address Requested");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Serving Cell ID (CELLID), %s",
	bigbuf,
	(value & 0x04) ? "Serving Cell ID Requested" : "No Serving Cell ID Requested");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Location Area ID (LOCID), %s",
	bigbuf,
	(value & 0x02) ?  "Location Area ID Requested" : "No Location Area ID Requested");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Current, %s",
	bigbuf,
	(value & 0x01) ? "Provide the current MS location" : "Provide the last known MS location information, if known");

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_rel_reason(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Unspecified"; break;
    case 1: str = "Call Over Clear Forward"; break;
    case 2: str = "Call Over Clear Backward"; break;
    case 3: str = "Handoff Successful"; break;
    case 4: str = "Handoff Abort - call over"; break;
    case 5: str = "Handoff Abort - not received"; break;
    case 6: str = "Abnormal mobile termination"; break;
    case 7: str = "Abnormal switch termination"; break;
    case 8: str = "Special feature release"; break;
    case 9: str = "Session Over Clear Forward"; break;
    case 10: str = "Session Over Clear Backward"; break;
    case 11: str = "Clear All Services Forward"; break;
    case 12: str = "Clear All Services Backward"; break;
    case 13: str = "Anchor MSC was removed from the packet data session"; break;
    default:
	if ((value >= 14) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Reason, %s",
	str);
}

static void
param_ho_reason(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unspecified"; break;
    case 2: str = "Weak signal"; break;
    case 3: str = "Off-loading"; break;
    case 4: str = "Anticipatory"; break;
    default:
	if ((value >= 5) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_red_reason(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Busy"; break;
    case 2: str = "No answer"; break;
    case 3: str = "Unconditional"; break;
    case 4: str = "No page response"; break;
    case 5: str = "Unavailable"; break;
    case 6: str = "Unroutable"; break;
    case 7: str = "Call accepted"; break;
    case 8: str = "Call refused"; break;
    case 9: str = "USCFvm, divert to voice mail"; break;
    case 10: str = "USCFms, divert to an MS provided DN"; break;
    case 11: str = "USCFnr, divert to a network registered DN"; break;
    default:
	if ((value >= 12) && (value <= 223)) { str = "Reserved, treat as No answer"; }
	else { str = "Reserved for protocol extension, treat as No answer"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_confid_mode(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Data Privacy (DP), %s",
	bigbuf,
	(value & 0x04) ? "ON" : "OFF");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Signaling Message Encryption (SE), %s",
	bigbuf,
	(value & 0x02) ? "ON" : "OFF");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Voice Privacy (VP), %s",
	bigbuf,
	(value & 0x01) ? "ON" : "OFF");
}

static void
param_sys_acc_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unspecified"; break;
    case 2: str = "Flash request"; break;
    case 3: str = "Autonomous registration"; break;
    case 4: str = "Call origination"; break;
    case 5: str = "Page response"; break;
    case 6: str = "No access"; break;
    case 7: str = "Power down registration"; break;
    case 8: str = "SMS page response"; break;
    case 9: str = "OTASP"; break;
    default:
	if ((value >= 10) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_scm(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, temp_int;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    temp_int = ((value & 0x10) >> 2) | (value & 0x03);
    switch (temp_int)
    {
    case 0: str = "Class I"; break;
    case 1: str = "Class II"; break;
    case 2: str = "Class III"; break;
    case 3: str = "Class IV"; break;
    case 4: str = "Class V"; break;
    case 5: str = "Class VI"; break;
    case 6: str = "Class VII"; break;
    case 7: str = "Class VIII"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x13, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Power %s",
	bigbuf,
	str);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Bandwidth %s",
	bigbuf,
	(value & 0x08) ? "25 MHz" : "20 MHz");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Transmission, %s",
	bigbuf,
	(value & 0x04) ? "Discontinuous" : "Continuous");
}

static void
param_deny_acc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unspecified"; break;
    case 2: str = "SSD Update failure"; break;
    case 3: str = "COUNT Update failure"; break;
    case 4: str = "Unique Challenge failure"; break;
    case 5: str = "AUTHR mismatch"; break;
    case 6: str = "COUNT mismatch"; break;
    case 7: str = "Process collision"; break;
    case 8: str = "Missing authentication parameters"; break;
    case 9: str = "TerminalType mismatch"; break;
    case 10: str = "MIN, IMSI or ESN authorization failure"; break;
    default:
	if ((value >= 11) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_cdma_sig_qual(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Value %u",
	bigbuf,
	value & 0x3f);
}

static void
param_rec_sig_qual(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not a usable signal"; break;
    case 255: str = "Interference"; break;
    default:
	if ((value >= 1) && (value <= 8)) { str = "Reserved, treat as Not a usable signal"; }
	else if ((value >= 9) && (value <= 245)) { str = "Usable signal range"; }
	else if ((value >= 246) && (value <= 254)) { str = "Reserved, treat as Interference"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_sig_qual(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not a usable signal"; break;
    case 255: str = "Interference"; break;
    default:
	if ((value >= 1) && (value <= 8)) { str = "Reserved, treat as Not a usable signal"; }
	else if ((value >= 9) && (value <= 245)) { str = "Usable signal range"; }
	else if ((value >= 246) && (value <= 254)) { str = "Reserved, treat as Interference"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_ssd_no_share(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Discard SSD"; break;
    default:
	str = "Reserved, treat as Discard SSD";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_report_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unspecified security violation"; break;
    case 2: str = "MSID/ESN mismatch"; break;
    case 3: str = "RANDC mismatch"; break;
    case 4: str = "Reserved (see TSB51)"; break;
    case 5: str = "SSD Update failed"; break;
    case 6: str = "Reserved (see TSB51)"; break;
    case 7: str = "COUNT mismatch"; break;
    case 8: str = "Reserved (see TSB51)"; break;
    case 9: str = "Unique Challenge failed"; break;
    case 10: str = "Unsolicited Base Station Challenge"; break;
    case 11: str = "SSD Update no response"; break;
    case 12: str = "COUNT Update no response"; break;
    case 13: str = "Unique Challenge no response"; break;
    case 14: str = "AUTHR mismatch"; break;
    case 15: str = "TERMTYP mismatch"; break;
    case 16: str = "Missing authentication parameters"; break;
    default:
	if ((value >= 17) && (value <= 223)) { str = "Reserved, treat as Unspecified security violation"; }
	else { str = "Reserved for protocol extension, treat as Unspecified security violation"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_term_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Not distinguished, EIA/TIA-553, IS-54-A, IS-88, IS-91, IS-94"; break;
    case 2: str = "IS-54-B"; break;
    case 3: str = "IS-136"; break;
    case 4: str = "J-STD-011 (rescinded 11/23/99)"; break;
    case 5: str = "IS-136-A or TIA/EIA-136 Revision-0"; break;
    case 6: str = "TIA/EIA-136-A"; break;
    case 7: str = "TIA/EIA-136-B"; break;
    case 32: str = "IS-95"; break;
    case 33: str = "IS-95-A"; break;
    case 34: str = "J-STD-008"; break;
    case 35: str = "IS-95-B"; break;
    case 36: str = "IS-2000"; break;
    case 64: str = "IS-88"; break;
    case 65: str = "IS-94"; break;
    case 66: str = "IS-91"; break;
    case 67: str = "J-STD-014"; break;
    case 68: str = "TIA/EIA-553-A"; break;
    case 69: str = "IS-91-A"; break;
    default:
	if ((value >= 8) && (value <= 31)) { str = "Reserved, treat as IS-54-B"; }
	else if ((value >= 37) && (value <= 63)) { str = "Reserved, treat as IS-95-A"; }
	else if ((value >= 70) && (value <= 223)) { str = "Reserved, treat as Not distinguished"; }
	else { str = "Reserved for protocol extension, treat as Not distinguished"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_term_res(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Termination denied"; break;
    case 2: str = "Unrestricted"; break;
    case 3: str = "Treatment for this value is not specified"; break;
    default:
	if ((value >= 4) && (value <= 223)) { str = "Reserved, treat as Unrestricted"; }
	else { str = "Reserved for protocol extension, treat as Unrestricted"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_dereg(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Deregister for an unspecified reason"; break;
    case 2: str = "Deregister for an adminstrative reason"; break;
    case 3: str = "Deregister due to MS power down"; break;
    default:
	if ((value >= 4) && (value <= 223)) { str = "Reserved, treat as Deregister for an unspecified reason"; }
	else { str = "Reserved for protocol extension, treat as Deregister for an unspecified reason"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);
}

static void
param_group_info(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 4, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 4);
}

static void
param_auth_den(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Delinquent account"; break;
    case 2: str = "Invalid serial number"; break;
    case 3: str = "Stolen unit"; break;
    case 4: str = "Duplicate unit"; break;
    case 5: str = "Unassigned directory number"; break;
    case 6: str = "Unspecified"; break;
    case 7: str = "Multiple access"; break;
    case 8: str = "Not Authorized for the MSC"; break;
    case 9: str = "Missing authentication parameters"; break;
    case 10: str = "Terminal Type mismatch"; break;
    default:
	if ((value >= 11) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Reason, %s (%u)",
	str,
	value);
}

static const gchar *
find_trig_type(gint32 value)
{
    const gchar *str = NULL;

    switch (value)
    {
    case 0: str = "Unspecified"; break;
    case 1: str = "All Calls"; break;
    case 2: str = "Double Introducing Star"; break;
    case 3: str = "Single Introducing Star"; break;
    case 4: str = "Reserved [for Home System Feature Code"; break;
    case 5: str = "Double Introducing Pound"; break;
    case 6: str = "Single Introducing Pound"; break;
    case 7: str = "Revertive Call"; break;
    case 8: str = "0 Digit"; break;
    case 9: str = "1 Digit"; break;
    case 10: str = "2 Digit"; break;
    case 11: str = "3 Digit"; break;
    case 12: str = "4 Digit"; break;
    case 13: str = "5 Digit"; break;
    case 14: str = "6 Digit"; break;
    case 15: str = "7 Digit"; break;
    case 16: str = "8 Digit"; break;
    case 17: str = "9 Digit"; break;
    case 18: str = "10 Digit"; break;
    case 19: str = "11 Digit"; break;
    case 20: str = "12 Digit"; break;
    case 21: str = "13 Digit"; break;
    case 22: str = "14 Digit"; break;
    case 23: str = "15 Digit"; break;
    case 24: str = "Local Call"; break;
    case 25: str = "Intra-LATA Toll Call"; break;
    case 26: str = "Inter-LATA Toll Call"; break;
    case 27: str = "World Zone Call"; break;
    case 28: str = "International Call"; break;
    case 29: str = "Unrecognized Number"; break;
    case 30: str = "Prior Agreement"; break;
    case 31: str = "Specific Called Party Digit String"; break;
    case 32: str = "Mobile Termination"; break;
    case 33: str = "Advanced Termination"; break;
    case 34: str = "Location"; break;
    case 35: str = "Locally Allowed Specific Digit String"; break;
    case 36: str = "Origination Attempt Authorized"; break;
    case 37: str = "Calling Routing Address Available"; break;
    case 38: str = "Initial Termination"; break;
    case 39: str = "Called Routing Address Available"; break;
    case 40: str = "O Answer"; break;
    case 41: str = "O Disconnect"; break;
    case 42: str = "O Called Party Busy"; break;
    case 43: str = "O No Answer"; break;
    case 64: str = "Terminating Resource Available"; break;
    case 65: str = "T Busy"; break;
    case 66: str = "T No Answer"; break;
    case 67: str = "T No Page Response"; break;
    case 68: str = "T Unroutable"; break;
    case 69: str = "T Answer"; break;
    case 70: str = "T Disconnect"; break;
    case 220: str = "Reserved for TDP-R DP Type value"; break;
    case 221: str = "Reserved for TDP-N DP Type value"; break;
    case 222: str = "Reserved for EDP-R DP Type value"; break;
    case 223: str = "Reserved for EDP-N DP Type value"; break;
    default:
	if ((value >= 44) && (value <= 63)) { str = "Reserved, treat as Unspecified"; }
	else if ((value >= 71) && (value <= 219)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    return(str);
}

static void
param_trig_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Trigger (%u) %s",
	value,
	find_trig_type(value));
}

static void
param_win_op_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Sender does not support PositionRequest OP"; break;
    default:
	str = "Sender supports PositionRequest OP";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Sender does not support CallControlDirective OP"; break;
    default:
	str = "Sender supports CallControlDirective OP";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Sender does not support ConnectResource, DisconnectResource, ConnectionFailureReport and ResetTimer (SSFT timer) OPs"; break;
    default:
	str = "Sender supports ConnectResource, DisconnectResource, ConnectionFailureReport and ResetTimer (SSFT timer) OPs";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_win_trig_list(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, i, j;
    guint saved_offset;

    saved_offset = asn1->offset;

    j = 0;
    i = 0;

    do
    {
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0xdc:
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset,
		"TDP-R's armed");

	    j = 0;
	    break;

	case 0xdd:
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset,
		"TDP-N's armed");

	    j = 0;
	    break;

	case 0xde:
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset,
		"EDP-R's armed");

	    j = 0;
	    break;

	case 0xdf:
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset,
		"EDP-N's armed");

	    j = 0;
	    break;

	default:
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset,
		"[%u] (%u) %s",
		j,
		value,
		find_trig_type(value));
	    j++;
	    break;
	}

	saved_offset = asn1->offset;
	i++;
    }
    while ((len - i) > 0);
}

static void
param_trans_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;
    char *p;
    char *buf;

    buf=ep_alloc(1024);
    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "System is not capable of supporting CNAP/CNAR (NAMI)"; break;
    default:
	str = "System is capable of supporting CNAP/CNAR (NAMI)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "System is not capable of supporting NDSS"; break;
    default:
	str = "System is capable of supporting NDSS";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "System is not capable of supporting User Zones (UZCI)"; break;
    default:
	str = "System is capable of supporting User Zones (UZCI)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "System is not capable of supporting local SPINI"; break;
    default:
	str = "System is capable of supporting local SPINI";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "System is not capable of interacting with the user (RUI)"; break;
    default:
	str = "System is capable of interacting with the user (RUI)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "System is not capable of honoring the Announcement List parameter (ANN)"; break;
    default:
	str = "System is capable of honoring the Announcement List parameter (ANN)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "System is not capable of detecting a busy condition (BUSY)"; break;
    default:
	str = "System is capable of detecting a busy condition (BUSY)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "System is not capable of supporting the IS-41-C profile parameter (PROFILE)"; break;
    default:
	str = "System is capable of supporting the IS-41-C profile parameter (PROFILE)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    if (len == 1) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "System is not capable of supporting the CDMA Over the Air Parameter Administration"; break;
    default:
	str = "System is capable of supporting the CDMA Over the Air Parameter Administration";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "System is not capable of supporting lower layer segmentation & reassembly (S&R)"; break;
    default:
	str = "System is capable of supporting lower layer segmentation & reassembly (S&R)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "System is not capable of supporting the Trigger Address List parameter (WADDR)"; break;
    default:
	str = "System is capable of supporting the Trigger Address List parameter (WADDR)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "System is not capable of supporting the Termination List parameter (TL)"; break;
    default:
	str = "System is capable of supporting the Termination List parameter (TL)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    p = other_decode_bitfield_value(buf, value, 0x0f, 8);
    switch (value & 0x0f)
    {
    case 0x00: strcat(p, " :  System cannot accept a termination at this time"); break;
    default:
	g_snprintf(p, 1024-(p-buf), " :  System supports %u call leg(s)", value & 0x0f);
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s",
	buf);

    if (len == 2) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(buf, value, 0xf8, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	buf);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "The system is not capable of supporting external MAHO requests"; break;
    default:
	str = "The system is capable of supporting external MAHO requests (e.g. for positioning)";
	break;
    }

    other_decode_bitfield_value(buf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	buf, str);

    other_decode_bitfield_value(buf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	buf);

    EXTRANEOUS_DATA_CHECK(len, 3);
}

static void
param_spini_trig(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any Revertive Call attempt"; break;
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Revertive Call (RvtC), %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt to an unrecognized number"; break;
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Unrecognized Number (Unrec), %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt outside of the current World Zone (as defined in ITU-T Rec. E.164)";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  World Zone (WZ), %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any international call attempt";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  International (Intl), %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any toll calls outside the local carrier's serving area";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Non-Local (Inter-LATA) Toll (NLTOLL/OLATA), %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any local toll call attempt.  Refers to intra-LATA toll within the NANP";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Local (Intra-LATA) Toll (LTOLL/ILATA), %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any local call attempt";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Local, %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt. This overrides all other values.";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  All Origination (All), %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any number matching a criteria of a prior agreement";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Prior Agreement (PA), %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any number beginning with two Pound ## digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Double Pound (DP), %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any number beginning with a Pound # digit";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Pound, %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any number beginning with two Star ** digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Double Star (DS), %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any number beginning with a Star * digit";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Star, %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 7 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  7 digits, %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 6 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  6 digits, %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 5 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  5 digits, %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 4 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  4 digits, %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 3 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  3 digits, %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 2 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  2 digits, %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 1 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1 digits, %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with no digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  No digits, %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 15 or more digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  15 digits, %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 14 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  14 digits, %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 13 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  13 digits, %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 12 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  12 digits, %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 11 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  11 digits, %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 10 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  10 digits, %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 9 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  9 digits, %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Execute local SPINI procedures for any call attempt with 8 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  8 digits, %s",
	bigbuf, str);

    EXTRANEOUS_DATA_CHECK(len, 4);
}

static void
param_orig_trig(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 4);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any Revertive Call attempt"; break;
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Revertive Call (RvtC), %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt to an unrecognized number"; break;
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Unrecognized Number (Unrec), %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt outside of the current World Zone (as defined in ITU-T Rec. E.164)";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  World Zone (WZ), %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any international call attempt";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  International (Intl), %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any toll calls outside the local carrier's serving area";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Non-Local (Inter-LATA) Toll (NLTOLL/OLATA), %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any local toll call attempt.  Refers to intra-LATA toll within the NANP";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Local (Intra-LATA) Toll (LTOLL/ILATA), %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any local call attempt";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Local, %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt. This overrides all other values.";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  All Origination (All), %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any number matching a criteria of a prior agreement";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Prior Agreement (PA), %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any number beginning with two Pound ## digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Double Pound (DP), %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any number beginning with a Pound # digit";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Pound, %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any number beginning with two Star ** digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Double Star (DS), %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any number beginning with a Star * digit";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Star, %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 7 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  7 digits, %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 6 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  6 digits, %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 5 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  5 digits, %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 4 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  4 digits, %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 3 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  3 digits, %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 2 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  2 digits, %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 1 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  1 digits, %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with no digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  No digits, %s",
	bigbuf, str);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 15 or more digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  15 digits, %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 14 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  14 digits, %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 13 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  13 digits, %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 12 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  12 digits, %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 11 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  11 digits, %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 10 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  10 digits, %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 9 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  9 digits, %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Trigger is not active"; break;
    default:
	str = "Launch an Origination Request for any call attempt with 8 digits";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  8 digits, %s",
	bigbuf, str);

    EXTRANEOUS_DATA_CHECK(len, 4);
}

static void
param_trig_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "O No Answer (ONA) cannot be armed"; break;
    default:
	str = "O No Answer (ONA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "O Disconnect (ODISC) cannot be armed"; break;
    default:
	str = "O Disconnect (ODISC) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "O Answer (OANS) cannot be armed"; break;
    default:
	str = "O Answer (OANS) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Origination Attempt Authorized (OAA) cannot be armed"; break;
    default:
	str = "Origination Attempt Authorized (OAA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Revertive Call trigger (RvtC) cannot be armed"; break;
    default:
	str = "Revertive Call trigger (RvtC) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "All Calls trigger (All) cannot be armed"; break;
    default:
	str = "All Calls trigger (All) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "K-digit triggers (K-digit) cannot be armed"; break;
    default:
	str = "K-digit triggers (K-digit) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Introducing Star/Pound triggers (INIT) cannot be armed"; break;
    default:
	str = "Introducing Star/Pound triggers (INIT) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    if (len == 1) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch ((value & 0x80) >> 7)
    {
    case 0x00: str = "O Called Party Busy (OBSY) cannot be armed"; break;
    default:
	str = "O Called Party Busy (OBSY) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x40) >> 6)
    {
    case 0x00: str = "Called Routing Address Available (CdRAA) cannot be armed"; break;
    default:
	str = "Called Routing Address Available (CdRAA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "Initial Termination (IT) cannot be armed"; break;
    default:
	str = "Initial Termination (IT) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "Calling Routing Address Available (CgRAA) cannot be armed"; break;
    default:
	str = "Calling Routing Address Available (CgRAA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "Advanced Termination trigger (AT) cannot be armed"; break;
    default:
	str = "Advanced Termination trigger (AT) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Prior Agreement trigger (PA) cannot be armed"; break;
    default:
	str = "Prior Agreement trigger (PA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "Unrecognized Number trigger (Unrec) cannot be armed"; break;
    default:
	str = "Unrecognized Number trigger (Unrec) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Call Type triggers (CT) cannot be armed"; break;
    default:
	str = "Call Type triggers (CT) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    if (len == 2) return;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "T Disconnect (TDISC) cannot be armed"; break;
    default:
	str = "T Disconnect (TDISC) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "T Answer (TANS) cannot be armed"; break;
    default:
	str = "T Answer (TANS) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "T No Answer trigger (TNA) cannot be armed"; break;
    default:
	str = "T No Answer trigger (TNA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "T Busy trigger (TBusy) cannot be armed"; break;
    default:
	str = "T Busy trigger (TBusy) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Terminating Resource Available triggers (TRA) cannot be armed"; break;
    default:
	str = "Terminating Resource Available triggers (TRA) can be armed";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    EXTRANEOUS_DATA_CHECK(len, 3);
}

static void
param_sys_cap(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  Reserved",
	bigbuf);

    switch ((value & 0x20) >> 5)
    {
    case 0x00: str = "DP is not supported by the system"; break;
    default:
	str = "DP is supported by the system";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x10) >> 4)
    {
    case 0x00: str = "SSD is not shared with the system for the indicated MS"; break;
    default:
	str = "SSD is shared with the system for the indicated MS";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x08) >> 3)
    {
    case 0x00: str = "System cannot execute CAVE algorithm"; break;
    default:
	str = "System can execute CAVE algorithm";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x04) >> 2)
    {
    case 0x00: str = "Voice Privacy is not supported"; break;
    default:
	str = "Voice Privacy is supported";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch ((value & 0x02) >> 1)
    {
    case 0x00: str = "SME is not supported"; break;
    default:
	str = "SME is supported";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch (value & 0x01)
    {
    case 0x00: str = "Authentication parameters were not requested"; break;
    default:
	str = "Authentication parameters were requested";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);
}

static void
param_act_code(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Continue processing"; break;
    case 2: str = "Disconnect call"; break;
    case 3: str = "Disconnect call leg"; break;
    case 4: str = "Conference calling drop last party"; break;
    case 5: str = "Bridge call leg(s) to conference call"; break;
    case 6: str = "Drop call leg on busy or routing failure"; break;
    case 7: str = "Disconnect all call legs"; break;
    case 8: str = "Attach MSC to OTAF"; break;
    case 9: str = "Initiate Registration Notification"; break;
    case 10: str = "Generate Public Encryption values"; break;
    case 11: str = "Generate A-Key"; break;
    case 12: str = "Perform SSD Update procedure"; break;
    case 13: str = "Perform Re-authentication procedure"; break;
    case 14: str = "Release TRN"; break;
    case 15: str = "Commit A-key"; break;
    case 16: str = "Release Resources"; break;
    case 17: str = "Record NEWMSID"; break;
    case 18: str = "Allocate Resources"; break;
    case 19: str = "Generate Authentication Signature"; break;
    case 20: str = "Release leg and redirect subscriber"; break;
    case 21: str = "Do Not Wait For MS User Level Response"; break;
    default:
	if ((value >= 22) && (value <= 95)) { str = "Reserved, treat as Continue processing"; }
	if ((value >= 96) && (value <= 127)) { str = "Reserved for protocol extension, treat as Continue processing"; }
	if ((value >= 128) && (value <= 223)) { str = "Reserved, treat as Disconnect call"; }
	else { str = "Reserved for protocol extension, treat as Disconnect call"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Action Code, %s (%u)",
	str,
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_border_acc(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Border Cell Access"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved, treat as Border Cell Access"; }
	else { str = "Reserved for protocol extension, treat as Border Cell Access"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Indication, %s (%u)",
	str,
	value);
}

static void
param_avail_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unspecified MS inactivity type"; break;
    default:
	if ((value >= 2) && (value <= 223)) { str = "Reserved, treat as Unspecified"; }
	else { str = "Reserved for protocol extension, treat as Unspecified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_can_type(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Serving System Option.  The serving system may discontinue a call or service in progress at its option."; break;
    case 2: str = "Report In Call.  The serving system shall continue to provide service when a call or service is in progress and just report its incidence."; break;
    case 3: str = "Discontinue.  The serving system shall discontinue any call or service in progress, regardless of the MS’s qualification, profile or authentication."; break;
    default:
	if ((value >= 4) && (value <= 223)) { str = "Reserved, treat as Serving System Option"; }
	else { str = "Reserved for protocol extension, treat as Serving System Option"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	str);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_can_den(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Multiple Access"; break;
    case 2: str = "Busy"; break;
    default:
	if ((value >= 3) && (value <= 223)) { str = "Reserved, treat as Multiple Access"; }
	else { str = "Reserved for protocol extension, treat as Multiple Access"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Indication, %s (%u)",
	str,
	value);
}

static void
param_acc_den(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Unassigned directory number"; break;
    case 2: str = "Inactive"; break;
    case 3: str = "Busy"; break;
    case 4: str = "Termination denied"; break;
    case 5: str = "No Page response"; break;
    case 6: str = "Unavailable"; break;
    case 7: str = "Service Rejected by MS"; break;
    case 8: str = "Service Rejected by the System"; break;
    case 9: str = "Service Type Mismatch"; break;
    case 10: str = "Service Denied"; break;
    case 11: str = "Call Rejected"; break;
    default:
	if ((value >= 12) && (value <= 223)) { str = "Reserved, treat as Termination denied"; }
	else { str = "Reserved for protocol extension, treat as Termination denied"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Access Denied Reason, %s (%u)",
	str,
	value);
}

static void
param_sms_acc_den_reason(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not used"; break;
    case 1: str = "Denied"; break;
    case 2: str = "Postponed"; break;
    case 3: str = "Unavailable"; break;
    case 4: str = "Invalid"; break;
    default:
	if ((value >= 5) && (value <= 63)) { str = "Reserved, treat as Denied"; }
	else if ((value >= 64) && (value <= 127)) { str = "Reserved, treat as Postponed"; }
	else if ((value >= 128) && (value <= 223)) { str = "Reserved, treat as Unavailable"; }
	else { str = "Reserved for protocol extension, treat as Unavailable"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Access Denied Reason, %s (%u)",
	str,
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_sms_bd(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{

    bd_tvb = tvb_new_subset(asn1->tvb, asn1->offset, len, len);

    proto_tree_add_text(tree, asn1->tvb,
	asn1->offset, len,
	"Parameter Data");

    asn1->offset += len;
}

static void
param_sms_cause(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;
    const gchar *str = NULL;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Address vacant"; break;
    case 1: str = "Address translation failure"; break;
    case 2: str = "Network resource shortage"; break;
    case 3: str = "Network failure"; break;
    case 4: str = "Invalid Teleservice ID"; break;
    case 5: str = "Other network problem"; break;
    case 6: str = "Unsupported network interface"; break;
    case 32: str = "No page response"; break;
    case 33: str = "Destination busy"; break;
    case 34: str = "No acknowledgement"; break;
    case 35: str = "Destination resource shortage"; break;
    case 36: str = "SMS delivery postponed"; break;
    case 37: str = "Destination out of service"; break;
    case 38: str = "Destination no longer at this address"; break;
    case 39: str = "Other terminal problem"; break;
    case 64: str = "Radio interface resource shortage"; break;
    case 65: str = "Radio interface incompatibility"; break;
    case 66: str = "Other radio interface problem"; break;
    case 67: str = "Unsupported Base Station Capability"; break;
    case 96: str = "Encoding problem"; break;
    case 97: str = "Service origination denied"; break;
    case 98: str = "Service termination denied"; break;
    case 99: str = "Supplementary service not supported"; break;
    case 100: str = "Service not supported"; break;
    case 101: str = "Reserved"; break;
    case 102: str = "Missing expected parameter"; break;
    case 103: str = "Missing mandatory parameter"; break;
    case 104: str = "Unrecognized parameter value"; break;
    case 105: str = "Unexpected parameter value"; break;
    case 106: str = "User Data size error"; break;
    case 107: str = "Other general problems"; break;
    case 108: str = "Session not active"; break;
    default:
	if ((value >= 7) && (value <= 31)) { str = "Reserved, treat as Other network problem"; }
	else if ((value >= 40) && (value <= 47)) { str = "Reserved, treat as Other terminal problem"; }
	else if ((value >= 48) && (value <= 63)) { str = "Reserved, treat as SMS delivery postponed"; }
	else if ((value >= 68) && (value <= 95)) { str = "Reserved, treat as Other radio interface problem"; }
	else if ((value >= 109) && (value <= 223)) { str = "Reserved, treat as Other general problems"; }
	else { str = "Reserved for protocol extension, treat as Other general problems"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s (%u)",
	str,
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_cdma_soci(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value %u",
	value);

    EXTRANEOUS_DATA_CHECK(len, 1);
}

static void
param_int(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    if (len > 4)
    {
	proto_tree_add_text(tree, asn1->tvb,
	    asn1->offset, len, "Long Data (?)");
	asn1->offset += len;
	return;
    }

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, len, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Value %u",
	value);
}

static void
param_pc_ssn(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value, b1, b2, b3, b4;
    guint saved_offset;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 5);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "Not specified"; break;
    case 1: str = "Serving MSC"; break;
    case 2: str = "Home MSC"; break;
    case 3: str = "Gateway MSC"; break;
    case 4: str = "HLR"; break;
    case 5: str = "VLR"; break;
    case 6: str = "EIR (reserved)"; break;
    case 7: str = "AC"; break;
    case 8: str = "Border MSC"; break;
    case 9: str = "Originating MSC"; break;
    default:
	if ((value >= 10) && (value <= 223)) { str = "Reserved, treat as Not specified"; }
	else { str = "Reserved for protocol extension, treat as Not specified"; }
	break;
    }

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Type (%u) %s",
	value,
	str);

    asn1_int32_value_decode(asn1, 1, &b1);
    asn1_int32_value_decode(asn1, 1, &b2);
    asn1_int32_value_decode(asn1, 1, &b3);
    asn1_int32_value_decode(asn1, 1, &b4);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"Point Code %u-%u-%u  SSN %u",
	b3, b2, b1, b4);
}

static void
param_lai(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string _U_, int string_len _U_)
{
    gint32 value;
    guint saved_offset;

    EXACT_DATA_CHECK(len, 2);

    saved_offset = asn1->offset;

    asn1_int32_value_decode(asn1, 2, &value);

    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"LAI %u (0x%04x)",
	value,
	value);
}

static void
param_list(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len)
{
    guint saved_offset;
    guint num_parms;

    num_parms = 0;
    saved_offset = asn1->offset;

    while (len > (asn1->offset - saved_offset))
    {
	num_parms++;

	if (!dissect_ansi_param(asn1, tree))
	{
	    proto_tree_add_text(tree,
		asn1->tvb, asn1->offset, len - (asn1->offset - saved_offset),
		"Unknown Parameter Data");

	    asn1->offset = saved_offset + len;
	    break;
	}
    }

    g_snprintf(add_string, string_len, " - (%u)", num_parms);
}


#define	NUM_PARAM_1 (sizeof(ansi_param_1_strings)/sizeof(value_string))
static gint ett_ansi_param_1[NUM_PARAM_1];
static void (*param_1_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len) = {
    param_bill_id,	/* Billing ID */
    param_int,	/* Serving Cell ID */
    param_int,	/* Target Cell ID */
    param_digits,	/* Digits */
    param_chan_data,	/* Channel Data */
    param_cic,	/* Inter MSC Circuit ID */
    param_int,	/* Inter Switch Count */
    param_min,	/* Mobile Identification Number */
    param_esn,	/* Electronic Serial Number */
    param_rel_reason,	/* Release Reason */
    param_sig_qual,	/* Signal Quality */
    param_scm,	/* Station Class Mark */
    param_auth_den,	/* Authorization Denied */
    param_auth_per,	/* Authorization Period */
    param_seizure,	/* Seizure Type */
    param_trunk_stat,	/* Trunk Status */
    param_qic,	/* Qualification Information Code */
    param_feat_result,	/* Feature Result */
    param_red_reason,	/* Redirection Reason */
    param_acc_den,	/* Access Denied Reason */
    param_mscid,	/* MSCID */
    param_sys_type_code,	/* System My Type Code */
    param_orig_ind,	/* Origination Indicator */
    param_term_res,	/* Termination Restriction Code */
    param_calling_feat_ind,	/* Calling Features Indicator */
    param_faulty,	/* Faulty Parameter */
    param_usage_ind,	/* Usage Indicator */
    param_tdma_chan_data,	/* TDMA Channel Data */
    param_tdma_call_mode,	/* TDMA Call Mode */
    param_ho_reason,	/* Handoff Reason */
    NULL,	/* NONE */
};


#define	NUM_PARAM_2 (sizeof(ansi_param_2_strings)/sizeof(value_string))
static gint ett_ansi_param_2[NUM_PARAM_2];
static void (*param_2_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len) = {
    param_tdma_burst_ind,	/* TDMA Burst Indicator */
    param_pc_ssn,	/* PC_SSN */
    param_lai,	/* Location Area ID */
    param_sys_acc_type,	/* System Access Type */
    param_auth_resp_all,	/* Authentication Response */
    param_auth_resp_all,	/* Authentication Response Base Station */
    param_auth_resp_all,	/* Authentication Response Unique Challenge */
    param_int,	/* Call History Count */
    param_confid_mode,	/* Confidentiality Modes */
    param_int,	/* Random Variable */
    param_int,	/* Random Variable Base station */
    param_rand_ssd,	/* Random Variable SSD */
    param_rand_unique,	/* Random Variable Unique Challenge */
    param_report_type,	/* Report Type */
    param_sme_key,	/* Signaling Message Encryption Key */
    param_ssd,	/* Shared Secret Data */
    param_term_type,	/* Terminal Type */
    param_vpmask,	/* Voice Privacy Mask */
    param_sys_cap,	/* System Capabilities */
    param_deny_acc,	/* Deny Access */
    param_upd_count,	/* Update Count */
    param_ssd_no_share,	/* SSD Not Shared */
    param_ext_mscid,	/* Extended MSCID */
    param_ext_sys_type_code,	/* Extended System My Type Code */
    param_ctrl_chan_data,	/* Control Channel Data */
    param_sys_acc_data,	/* System Access Data */
    param_can_den,	/* Cancellation Denied */
    param_border_acc,	/* Border Cell Access */
    param_cdma_scm,	/* CDMA Station Class Mark */
    param_int,	/* CDMA Serving One Way Delay */
    param_int,	/* CDMA Target One Way Delay */
    param_cdma_call_mode,	/* CDMA Call Mode */
    param_cdma_chan_data,	/* CDMA Channel Data */
    param_cdma_sig_qual,	/* CDMA Signal Quality */
    param_cdma_pilot_strength,	/* CDMA Pilot Strength */
    param_mob_rev,	/* CDMA Mobile Protocol Revision */
    param_cdma_plcm,	/* CDMA Private Long Code Mask */
    param_cdma_code_chan,	/* CDMA Code Channel */
    param_cdma_sea_win,	/* CDMA Search Window */
    param_ms_loc,	/* MS Location */
    param_page_ind,	/* Page Indicator */
    param_rec_sig_qual,	/* Received Signal Quality */
    param_dereg,	/* Deregistration Type */
    param_namps_chan_data,	/* NAMPS Channel Data */
    param_alert_code,	/* Alert Code */
    param_ann_code,	/* Announcement Code */
    param_aav,	/* Authentication Algorithm Version */
    param_auth_cap,	/* Authentication Capability */
    param_int,	/* Call History Count Expected */
    param_digits,	/* Calling Party Number Digits 1 */
    param_digits,	/* Calling Party Number Digits 2 */
    param_digits,	/* Calling Party Number String 1 */
    param_digits,	/* Calling Party Number String 2 */
    param_sub_addr,	/* Calling Party Subaddress */
    param_can_type,	/* Cancellation Type */
    param_digits,	/* Carrier Digits */
    param_digits,	/* Destination Digits */
    param_dmh_red_ind,	/* DMH Redirection Indicator */
    param_list,	/* Inter System Termination */
    param_avail_type,	/* Availability Type */
    param_list,	/* Local Termination */
    param_mw_noti_count,	/* Message Waiting Notification Count */
    param_mdn,	/* Mobile Directory Number */
    param_digits,	/* MSCID Number */
    param_list,	/* PSTN Termination */
    param_no_ans_time,	/* No Answer Time */
    param_otfi,	/* One Time Feature Indicator */
    param_orig_trig,	/* Origination Triggers */
    param_randc,	/* RANDC */
    param_digits,	/* Redirecting Number Digits */
    param_digits,	/* Redirecting Number String */
    param_sub_addr,	/* Redirecting Number Subaddress */
    param_digits,	/* Sender Identification Number */
    param_digits,	/* SMS Address */
    param_sms_bd,	/* SMS Bearer Data */
    param_sms_charge_ind,	/* SMS Charge Indicator */
    param_digits,	/* SMS Destination Address */
    param_sms_msg_count,	/* SMS Message Count */
    param_sms_noti,	/* SMS Notification Indicator */
    param_digits,	/* SMS Original Destination Address */
    param_sub_addr,	/* SMS Original Destination Subaddress */
    param_digits,	/* SMS Original Originating Address */
    param_sub_addr,	/* SMS Original Originating Subaddress */
    param_digits,	/* SMS Originating Address */
    param_sms_orig_restric,	/* SMS Originating Restrictions */
    param_sms_tele,	/* SMS Teleservice Identifier */
    param_sms_term_restric,	/* SMS Termination Restrictions */
    NULL/* no data */,	/* SMS Message Waiting Indicator */
    param_term_acc_type,	/* Termination Access Type */
    param_list,	/* Termination List */
    param_term_treat,	/* Termination Treatment */
    param_term_trig,	/* Termination Triggers */
    param_trans_cap,	/* Transaction Capability */
    param_unique_chal_rep,	/* Unique Challenge Report */
    NULL,	/* NONE */
};


#define	NUM_PARAM_3 (sizeof(ansi_param_3_strings)/sizeof(value_string))
static gint ett_ansi_param_3[NUM_PARAM_3];
static void (*param_3_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len) = {
    param_act_code,	/* Action Code */
    param_alert_res,	/* Alert Result */
    param_list,	/* Announcement List */
    param_list,	/* CDMA Code Channel Information */
    param_list,	/* CDMA Code Channel List */
    param_list,	/* CDMA Target Measurement Information */
    param_list,	/* CDMA Target Measurement List */
    param_list,	/* CDMA Target MAHO Information */
    param_list,	/* CDMA Target MAHO List */
    param_conf_call_ind,	/* Conference Calling Indicator */
    param_count_upd_report,	/* Count Update Report */
    param_digit_collect_ctrl,	/* Digit Collection Control */
    param_digits,	/* DMH Account Code Digits */
    param_digits,	/* DMH Alternate Billing Digits */
    param_digits,	/* DMH Billing Digits */
    param_geo_auth,	/* Geographic Authorization */
    param_int,	/* Leg Information */
    param_mw_noti_type,	/* Message Waiting Notification Type */
    param_paca_ind,	/* PACA Indicator */
    param_pref_lang_ind,	/* Preferred Language Indicator */
    param_rand_valtime,	/* Random Valid Time */
    param_digits,	/* Restriction Digits */
    param_digits,	/* Routing Digits */
    param_setup_result,	/* Setup Result */
    param_sms_acc_den_reason,	/* SMS Access Denied Reason */
    param_sms_cause,	/* SMS Cause Code */
    param_digits,	/* SPINI PIN */
    param_spini_trig,	/* SPINI Triggers */
    param_ssd_upd_report,	/* SSD Update Report */
    param_list,	/* Target Measurement Information */
    param_list,	/* Target Measurement List */
    param_digits,	/* Voice Mailbox PIN */
    param_digits,	/* Voice Mailbox Number */
    NULL/* no special handling */,	/* Authentication Data */
    param_cond_den_reason,	/* Conditionally Denied Reason */
    param_group_info,	/* Group Information */
    param_ho_state,	/* Handoff State */
    param_namps_call_mode,	/* NAMPS Call Mode */
    param_cdma_sci,	/* CDMA Slot Cycle Index */
    param_den_auth_per,	/* Denied Authorization Period */
    param_digits,	/* Pilot Number */
    param_bill_id,	/* Pilot Billing ID */
    param_cdma_band_class,	/* CDMA Band Class */
    param_list,	/* CDMA Band Class Information */
    param_list,	/* CDMA Band Class List */
    param_cdma_pilot_pn,	/* CDMA Pilot PN */
    NULL/* no special handling */,	/* CDMA Service Configuration Record */
    param_cdma_so,	/* CDMA Service Option */
    param_list,	/* CDMA Service Option List */
    param_cdma_scm2,	/* CDMA Station Class Mark 2 */
    param_tdma_sc,	/* TDMA Service Code */
    param_tdma_term_cap,	/* TDMA Terminal Capability */
    param_tdma_voice_coder,	/* TDMA Voice Coder */
    param_a_key_ver,	/* A-Key Protocol Version */
    NULL/* XXX what spec ? */,	/* Authentication Response Reauthentication */
    NULL/* no special handling */,	/* Base Station Partial Key */
    param_ms_min,	/* Mobile Station MIN */
    NULL/* no special handling */,	/* Mobile Station Partial Key */
    NULL/* no special handling */,	/* Modulus Value */
    param_new_min,	/* Newly Assigned MIN */
    param_ota_result_code,	/* OTASP Result Code */
    NULL/* no special handling */,	/* Primitive Value */
    NULL/* XXX what spec ? */,	/* Random Variable Reauthentication */
    NULL/* XXX what spec ? */,	/* Reauthentication Report */
    param_srvc_ind,	/* Service Indicator */
    param_sme_report,	/* Signaling Message Encryption Report */
    param_trn,	/* Temporary Reference Number */
    param_vp_report,	/* Voice Privacy Report */
    NULL/* XXX */,	/* Base Station Manufacturer Code */
    NULL/* XXX */,	/* BSMC Status */
    param_ctrl_chan_mode,	/* Control Channel Mode */
    NULL/* XXX */,	/* Non Public Data */
    NULL/* XXX */,	/* Paging Frame Class */
    NULL/* XXX */,	/* PSID RSID Information */
    NULL/* XXX */,	/* PSID RSID List */
    NULL/* XXX */,	/* Service Result */
    NULL/* XXX */,	/* SOC Status */
    NULL/* XXX */,	/* System Operator Code */
    NULL/* XXX */,	/* Target Cell ID List */
    NULL/* XXX */,	/* User Group */
    NULL/* XXX */,	/* User Zone Data */
    NULL/* no special handling */,	/* CDMA Connection Reference */
    param_list,	/* CDMA Connection Reference Information */
    param_list,	/* CDMA Connection Reference List */
    NULL/* XXX */,	/* CDMA State */
    param_change_srvc_attr,	/* Change Service Attributes */
    NULL/* no special handling */,	/* Data Key */
    param_dp_params,	/* Data Privacy Parameters */
    param_islp_info,	/* ISLP Information */
    param_reason_list,	/* Reason List */
    NULL/* XXX */,	/* Second Inter MSC Circuit ID */
    param_tdma_bandwidth,	/* TDMA Bandwidth */
    param_tdma_data_feat_ind,	/* TDMA Data Features Indicator */
    param_tdma_data_mode,	/* TDMA Data Mode */
    param_tdma_voice_mode,	/* TDMA Voice Mode */
    param_ana_red_info,	/* Analog Redirect Info */
    param_list,	/* Analog Redirect Record */
    param_cdma_chan_num,	/* CDMA Channel Number */
    param_list,	/* CDMA Channel Number List */
    param_cdma_pci,	/* CDMA Power Combined Indicator */
    param_list,	/* CDMA Redirect Record */
    param_cdma_sea_param,	/* CDMA Search Parameters */
    param_int,	/* CDMA Network Identification */
    param_network_tmsi,	/* Network TMSI */
    param_int,	/* Network TMSI Expiration Time */
    param_network_tmsi,	/* New Network TMSI */
    param_reqd_param_mask,	/* Required Parameters Mask */
    param_srvc_red_cause,	/* Service Redirection Cause */
    param_srvc_red_info,	/* Service Redirection Info */
    param_roaming_ind,	/* Roaming Indication */
    NULL/* XXX */,	/* Emergency Services Routing Digits */
    NULL/* XXX */,	/* Special Handling */
    param_imsi,	/* International Mobile Subscriber Identity */
    param_calling_party_name,	/* Calling Party Name */
    param_dis_text,	/* Display Text */
    param_red_party_name,	/* Redirecting Party Name */
    param_srvc_id,	/* Service ID */
    param_all_or_none,	/* All Or None */
    param_change,	/* Change */
    param_list,	/* Data Access Element */
    param_list,	/* Data Access Element List */
    NULL/* no special handling */,	/* Data ID */
    NULL/* no special handling */,	/* Database Key */
    param_data_result,	/* Data Result */
    param_list,	/* Data Update Result */
    param_list,	/* Data Update Result List */
    NULL/* no special handling */,	/* Data Value */
    param_list,	/* Execute Script */
    param_fail_cause,	/* Failure Cause */
    param_fail_type,	/* Failure Type */
    NULL/* no special handling */,	/* Global Title */
    param_list,	/* Modification Request */
    param_list,	/* Modification Request List */
    param_list,	/* Modification Result List */
    NULL/* no special handling */,	/* Private Specialized Resource */
    NULL/* no special handling */,	/* Script Argument */
    NULL/* no special handling */,	/* Script Name */
    NULL/* no special handling */,	/* Script Result */
    param_list,	/* Service Data Access Element */
    param_list,	/* Service Data Access Element List */
    param_list,	/* Service Data Result */
    param_list,	/* Service Data Result List */
    param_special_rsc,	/* Specialized Resource */
    param_time_date_offset,	/* Time Date Offset */
    param_list,	/* Trigger Address List */
    param_trig_cap,	/* Trigger Capability */
    param_list,	/* Trigger List */
    param_trig_type,	/* Trigger Type */
    param_list,	/* WIN Capability */
    param_win_op_cap,	/* WIN Operations Capability */
    param_win_trig_list,	/* WIN Trigger List */
    param_digits,	/* MSC Address */
    param_sus_acc,	/* Suspicious Access */
    param_imsi,	/* Mobile Station IMSI */
    param_imsi,	/* Newly Assigned IMSI */
    NULL/* XXX what spec ? */,	/* Command Code */
    param_dis_text2,	/* Display Text 2 */
    NULL/* XXX what spec ? */,	/* Page Count */
    NULL/* XXX what spec ? */,	/* Page Response Time */
    NULL/* XXX what spec ? */,	/* SMS Transaction ID */
    NULL/* XXX what spec ? */,	/* CAVE Key */
    NULL/* XXX what spec ? */,	/* CDMA2000 Mobile Supported Capabilities */
    NULL/* XXX what spec ? */,	/* Enhanced Privacy Encryption Report */
    param_inter_msg_time,	/* Inter Message Time */
    param_msid_usage,	/* MSID Usage */
    param_new_min_ext,	/* New MIN Extension */
    param_qos_pri,	/* QoS Priority */
    param_cdma_ms_meas_chan_id,	/* CDMA MS Measured Channel Identity */
    param_cdma2000_ho_ivk_ios,	/* CDMA2000 Handoff Invoke IOS Data */
    param_cdma2000_ho_rsp_ios,	/* CDMA2000 Handoff Response IOS Data */
    NULL/* XXX */,	/* MIN Extension */

    param_list,	/* Call Recovery ID */
    param_list,	/* Call Recovery ID List */
    param_list,	/* Position Information */
    param_list,	/* CDMA PSMM List */
    param_resume_pic,	/* Resume PIC */
    param_dmh_srvc_id,	/* DMH Service ID */
    param_feat_ind,	/* Feature Indicator */
    param_mscid,	/* Control Network ID */
    param_rel_cause,	/* Release Cause */
    param_time_day,	/* Time Of Day */
    param_call_status,	/* Call Status */
    NULL/* no special handling */,	/* DMH Charge Information */
    NULL/* no special handling */,	/* DMH Billing Indicator */
    param_ms_status,	/* MS Status */
    param_pos_info_code,	/* Position Information Code */
    param_dtx_ind,	/* DTX Indication */
    param_cdma_mob_cap,	/* CDMA Mobile Capabilities */
    param_gen_time,	/* Generalized Time */
    param_digits,	/* Generic Digits */
    param_geo_pos,	/* Geographic Position */
    param_mob_call_status,	/* Mobile Call Status */
    param_mob_cap,	/* Mobile Position Capability */
    param_pos_req_type,	/* Position Request Type */
    param_pos_result,	/* Position Result */
    param_pos_source,	/* Position Source */
    param_acg_encounter,	/* ACG Encountered */
    param_ctrl_type,	/* Control Type */
    param_gap_duration,	/* Gap Duration */
    param_scf_overload_gap_int,	/* SCF Overload Gap Interval */
    param_sm_gap_int,	/* Service Management System Gap Interval */
    param_cdma_psmm_count,	/* CDMA PSMM Count */
    param_cdma_sowd2,	/* CDMA Serving One Way Delay 2 */
    NULL/* no special handling */,	/* PDSN Address */
    NULL/* no special handling */,	/* PDSN Protocol Type */
    NULL/* no special handling */,	/* Range */
    param_calling_party_cat,	/* Calling Party Category */
    param_digits,	/* LCS Client ID */
    param_tdma_maho_cell_id,	/* TDMA MAHO Cell ID */
    param_tdma_maho_chan,	/* TDMA MAHO Channel */
    param_cdma_soci,	/* CDMA Service Option Connection Identifier */
    param_tdma_time_align,	/* TDMA Time Alignment */
    param_tdma_maho_req,	/* TDMA MAHO Request */
    NULL,	/* NONE */
};

/* GENERIC MAP DISSECTOR FUNCTIONS */

static void
dissect_ansi_map_len(ASN1_SCK *asn1, proto_tree *tree, gboolean *def_len, guint *len)
{
    guint	saved_offset;
    int		ret;


    saved_offset = asn1->offset;
    *def_len = FALSE;
    *len = 0;

    ret = asn1_length_decode(asn1, def_len, len);

    if (*def_len)
    {
	proto_tree_add_uint(tree, hf_ansi_map_length, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    *len);
    }
    else
    {
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset,
	    "Length: Indefinite");
    }

}

static gboolean
check_ansi_map_tag(ASN1_SCK *asn1, guint tag)
{
    guint saved_offset, real_tag;


    saved_offset = asn1->offset;

    asn1_id_decode1(asn1, &real_tag);

    asn1->offset = saved_offset;

    return(tag == real_tag);
}

static void
dissect_ansi_map_octet(ASN1_SCK *asn1, proto_tree *tree, const guchar * str)
{
    guint saved_offset;
    guchar my_oct;


    saved_offset = asn1->offset;

    asn1_octet_decode(asn1, &my_oct);

    proto_tree_add_uint_format(tree, hf_ansi_map_id, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, my_oct,
	"%s %u",
	str, my_oct);
}

static proto_tree *
dissect_ansi_map_component(ASN1_SCK *asn1, proto_tree *tree, guint *len_p)
{
    guint saved_offset;
    guint tag;
    proto_item *item;
    proto_tree *subtree;
    gboolean def_len;


    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, -1, "Component ID");

    subtree = proto_item_add_subtree(item, ett_component);

    proto_tree_add_uint_format(subtree, hf_ansi_map_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag,
	"Component ID Identifier");

    dissect_ansi_map_len(asn1, subtree, &def_len, len_p);

    if ((gint) (asn1->offset - saved_offset + *len_p) < 0)
	THROW (ReportedBoundsError);

    proto_item_set_len(item, (asn1->offset - saved_offset) + *len_p);

    return(subtree);
}

static void
dissect_ansi_opr_code(ASN1_SCK *asn1, packet_info *pinfo, proto_tree *tree, gint32 *opr_code_p)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    gint32 val;
    const gchar *str = NULL;
    guchar my_oct;
    proto_item *item;
    proto_tree *subtree;
    gboolean def_len;


    *opr_code_p = -1;

#define TCAP_NAT_OPR_CODE_TAG 0xd0
    if (check_ansi_map_tag(asn1, TCAP_NAT_OPR_CODE_TAG))
    {
	str = "National TCAP Operation Code Identifier";
    }
#define TCAP_PRIV_OPR_CODE_TAG 0xd1
    else if (check_ansi_map_tag(asn1, TCAP_PRIV_OPR_CODE_TAG))
    {
	str = "Private TCAP Operation Code Identifier";
    }
    else
    {
	proto_tree_add_text(tree, asn1->tvb,
	    asn1->offset, -1, "Unexpected tag, not National or Private TCAP Operation Code");
	return;
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, -1, "Operation Code");

    subtree = proto_item_add_subtree(item, ett_opr_code);

    proto_tree_add_uint_format(subtree, hf_ansi_map_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_ansi_map_len(asn1, subtree, &def_len, &len);

    if ((gint) (asn1->offset - saved_offset + len) < 0)
	THROW (ReportedBoundsError);

    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    if (len > 0)
    {
	saved_offset = asn1->offset;
	asn1_octet_decode(asn1, &my_oct);

#define ANSI_MAP_OPR_FAMILY 0x09
	if (my_oct != ANSI_MAP_OPR_FAMILY)
	{
	    asn1->offset = saved_offset;
	    return;
	}

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1, "Operation Code Family");

	saved_offset = asn1->offset;
	asn1_int32_value_decode(asn1, len-1, &val);
	proto_tree_add_int(subtree, hf_ansi_map_opr_code, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, val);

	str = match_strval(val, ansi_map_opr_code_strings);

	if (NULL == str) return;

	*opr_code_p = val;

	if (check_col(pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);
	}
    }
}

static void
dissect_ansi_problem(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    proto_tree *subtree;
    proto_item *item = NULL;
    const gchar *str = NULL;
    const gchar *type_str = NULL;
    gint32 type, spec;
    gboolean def_len;


#define TCAP_PROB_CODE_TAG 0xd5
    if (check_ansi_map_tag(asn1, TCAP_PROB_CODE_TAG))
    {
	str = "Problem Code Identifier";
    }
    else
    {
	/* XXX */
	return;
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, -1, "Problem Code");

    subtree = proto_item_add_subtree(item, ett_problem);

    proto_tree_add_uint_format(subtree, hf_ansi_map_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_ansi_map_len(asn1, subtree, &def_len, &len);

    if ((gint) (asn1->offset - saved_offset + len) < 0)
	THROW (ReportedBoundsError);

    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    if (len != 2)
    {
	proto_tree_add_text(subtree, asn1->tvb,
	    asn1->offset, len, "Unknown encoding of Problem Code");

	asn1->offset += len;
	return;
    }

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &type);
    asn1_int32_value_decode(asn1, 1, &spec);

    switch (type)
    {
    case 0: type_str = "Not used"; break;

    case 1:
	type_str = "General";
	switch (spec)
	{
	case 1: str = "Unrecognized Component Type"; break;
	case 2: str = "Incorrect Component Portion"; break;
	case 3: str = "Badly Structured Component Portion"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 2:
	type_str = "Invoke";
	switch (spec)
	{
	case 1: str = "Duplicate Invoke ID"; break;
	case 2: str = "Unrecognized Operation Code"; break;
	case 3: str = "Incorrect Parameter"; break;
	case 4: str = "Unrecognized Correlation ID"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 3:
	type_str = "Return Result";
	switch (spec)
	{
	case 1: str = "Unrecognized Correlation ID"; break;
	case 2: str = "Unexpected Return Result"; break;
	case 3: str = "Incorrect Parameter"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 4:
	type_str = "Return Error";
	switch (spec)
	{
	case 1: str = "Unrecognized Correlation ID"; break;
	case 2: str = "Unexpected Return Error"; break;
	case 3: str = "Unrecognized Error"; break;
	case 4: str = "Unexpected Error"; break;
	case 5: str = "Incorrect Parameter"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 5:
	type_str = "Transaction Portion";
	switch (spec)
	{
	case 1: str = "Unrecognized Package Type"; break;
	case 2: str = "Incorrect Transaction Portion"; break;
	case 3: str = "Badly Structured Transaction Portion"; break;
	case 4: str = "Unrecognized Transaction ID"; break;
	case 5: str = "Permission to Release"; break;
	case 6: str = "Resource Unavailable"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    default:
	type_str = "Undefined";
	break;
    }

    if (spec == 255) { str = "Reserved"; }
    else if (spec == 0) { str = "Not used"; }

    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset, 1, "Problem Type %s", type_str);

    proto_tree_add_text(subtree, asn1->tvb,
	saved_offset + 1, 1, "Problem Specifier %s", str);
}

static void
dissect_ansi_error(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    gint32 value;
    proto_tree *subtree;
    proto_item *item = NULL;
    const gchar *str = NULL;
    gboolean def_len;


#define TCAP_NAT_ERR_CODE_TAG 0xd3
    if (check_ansi_map_tag(asn1, TCAP_NAT_ERR_CODE_TAG))
    {
	str = "National TCAP Error Code Identifier";
    }
#define TCAP_PRIV_ERR_CODE_TAG 0xd4
    else if (check_ansi_map_tag(asn1, TCAP_PRIV_ERR_CODE_TAG))
    {
	str = "Private TCAP Error Code Identifier";
    }
    else
    {
	/* XXX */
	return;
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, -1, "TCAP Error Code");

    subtree = proto_item_add_subtree(item, ett_error);

    proto_tree_add_uint_format(subtree, hf_ansi_map_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_ansi_map_len(asn1, subtree, &def_len, &len);

    if ((gint) (asn1->offset - saved_offset + len) < 0)
	THROW (ReportedBoundsError);

    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    if ((tag == TCAP_PRIV_ERR_CODE_TAG) &&
	(len == 1))
    {
	saved_offset = asn1->offset;
	asn1_int32_value_decode(asn1, 1, &value);

	switch (value)
	{
	case 0x81: str = "Unrecognized MIN"; break;
	case 0x82: str = "Unrecognized ESN"; break;
	case 0x83: str = "MIN/HLR Mismatch"; break;
	case 0x84: str = "Operation Sequence Problem"; break;
	case 0x85: str = "Resource Shortage"; break;
	case 0x86: str = "Operation Not Supported"; break;
	case 0x87: str = "Trunk Unavailable"; break;
	case 0x88: str = "Parameter Error"; break;
	case 0x89: str = "System Failure"; break;
	case 0x8a: str = "Unrecognized Parameter Value"; break;
	case 0x8b: str = "Feature Inactive"; break;
	case 0x8c: str = "Missing Parameter"; break;
	default:
	    if ((value >= 0xe0) && (value <= 0xff)) { str = "Reserved for protocol extension"; }
	    else { str = "Reserved"; }
	    break;
	}

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1, str);
    }
    else
    {
	proto_tree_add_text(subtree, asn1->tvb,
	    asn1->offset, len, "Error Code");

	asn1->offset += len;
    }
}


static gboolean
dissect_ansi_param(ASN1_SCK *asn1, proto_tree *tree)
{
    void (*param_fcn)(ASN1_SCK *asn1, proto_tree *tree, guint len, gchar *add_string, int string_len) = NULL;
    guint saved_offset = 0;
    guint len;
    proto_tree *subtree;
    proto_item *item;
    guint val;
    const gchar *str = NULL;
    gint ett_param_idx, idx;
    gboolean def_len;


    saved_offset = asn1->offset;

    asn1_uint32_value_decode(asn1, 1, &val);
    str = match_strval_idx((guint32) val, ansi_param_1_strings, &idx);

    if (NULL == str)
    {
	asn1->offset = saved_offset;
	asn1_uint32_value_decode(asn1, 2, &val);

	str = match_strval_idx((guint32) val, ansi_param_2_strings, &idx);

	if (NULL == str)
	{
	    asn1->offset = saved_offset;
	    asn1_int32_value_decode(asn1, 3, &val);

	    str = match_strval_idx((guint32) val, ansi_param_3_strings, &idx);

	    if (NULL == str)
	    {
		if (((val >= 0x9FFF00) && (val <= 0x9FFF7F)) ||
		    ((val >= 0xBFFF00) && (val <= 0xBFFF7F)))
		{
		    str = "Reserved for protocol extension";
		}
		else if (((val >= 0x9FFE76) && (val <= 0x9FFE7F)) ||
		    ((val >= 0xBFFE76) && (val <= 0xBFFE7F)))
		{
		    str = "Reserved for National Network Use";
		}
		else
		{
		    str = "Unknown Parameter Data";
		    param_fcn = NULL;
		}

		ett_param_idx = ett_param;
	    }
	    else
	    {
		ett_param_idx = ett_ansi_param_3[idx];
		param_fcn = param_3_fcn[idx];
	    }
	}
	else
	{
	    ett_param_idx = ett_ansi_param_2[idx];
	    param_fcn = param_2_fcn[idx];
	}
    }
    else
    {
	ett_param_idx = ett_ansi_param_1[idx];
	param_fcn = param_1_fcn[idx];
    }

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, -1, str);

    subtree = proto_item_add_subtree(item, ett_param_idx);

    proto_tree_add_uint_format(subtree, hf_ansi_map_param_id, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, val, "Parameter ID");

    dissect_ansi_map_len(asn1, subtree, &def_len, &len);

    if ((gint) (asn1->offset - saved_offset + len) < 0)
	THROW (ReportedBoundsError);

    proto_item_set_len(item, asn1->offset - saved_offset + len);

    if (len > 0)
    {
	if (param_fcn == NULL)
	{
	    proto_tree_add_text(subtree, asn1->tvb,
		asn1->offset, len, "Parameter Data");
	    asn1->offset += len;
	}
	else
	{
            gchar *ansi_map_add_string;

	    ansi_map_add_string=ep_alloc(1024);
	    ansi_map_add_string[0] = '\0';

	    (*param_fcn)(asn1, subtree, len, ansi_map_add_string, 1024);

	    if (ansi_map_add_string[0] != '\0')
	    {
		proto_item_append_text(item, ansi_map_add_string);
	    }
	}
    }

    return(TRUE);
}


static void
dissect_ansi_params(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    proto_tree *subtree;
    proto_item *item = NULL;
    const gchar *str = NULL;
    gboolean def_len;
    gchar *ansi_map_add_string;

#define TCAP_PARAM_SET_TAG 0xf2
    if (check_ansi_map_tag(asn1, TCAP_PARAM_SET_TAG))
    {
	str = "Parameter Set Identifier";
    }
#define TCAP_PARAM_SEQ_TAG 0x30
    else if (check_ansi_map_tag(asn1, TCAP_PARAM_SEQ_TAG))
    {
	str = "Parameter Sequence Identifier";
    }
    else
    {
	/* XXX */
	return;
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, -1, "Parameters");

    subtree = proto_item_add_subtree(item, ett_params);

    proto_tree_add_uint_format(subtree, hf_ansi_map_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_ansi_map_len(asn1, subtree, &def_len, &len);

    if ((gint) (asn1->offset - saved_offset + len) < 0)
	THROW (ReportedBoundsError);

    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    ansi_map_add_string = ep_alloc(1024);
    ansi_map_add_string[0] = '\0';

    param_list(asn1, subtree, len, ansi_map_add_string, 1024);

    if (ansi_map_add_string[0] != '\0')
    {
	proto_item_append_text(item, ansi_map_add_string);
    }
}

static void
dissect_ansi_map_reject(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_ansi_map_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_ansi_map_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_ansi_map_octet(asn1, subtree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_problem(asn1, tree);

    dissect_ansi_params(asn1, tree);
}

static void
dissect_ansi_map_re(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_ansi_map_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_ansi_map_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_ansi_map_octet(asn1, subtree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_error(asn1, tree);

    dissect_ansi_params(asn1, tree);
}

static void
dissect_ansi_map_rr(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_ansi_map_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_ansi_map_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_ansi_map_octet(asn1, subtree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_params(asn1, tree);
}

static void
dissect_ansi_map_invoke(ASN1_SCK *asn1, packet_info *pinfo, proto_tree *tree, gint *opr_code_p)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_ansi_map_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_ansi_map_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_ansi_map_octet(asn1, subtree, "Invoke ID:");
	    break;

	case 2:
	    dissect_ansi_map_octet(asn1, subtree, "Invoke ID:");
	    dissect_ansi_map_octet(asn1, subtree, "Correlation ID:");
	    break;
	}
    }

    ansi_map_is_invoke = TRUE;

    dissect_ansi_opr_code(asn1, pinfo, tree, opr_code_p);

    dissect_ansi_params(asn1, tree);
}

static void
dissect_ansi_map_message(ASN1_SCK *asn1, packet_info *pinfo, proto_tree *ansi_map_tree)
{
    static ansi_map_tap_rec_t tap_rec;
    guint	saved_offset;
    guint	tag;
    guint	len;
    const gchar	*str = NULL;
    proto_item *item, *tag_item;
    proto_tree *subtree, *tag_subtree;
    gboolean def_len;
    static int	i = 0;
    gint opr_code;


    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    str = match_strval(tag, ansi_cmp_type_strings);

    if (NULL == str) return;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        if (0 == i)
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO,  "%s ", str);
	}
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO,  "& %s ", str);
        }
    }

    item =
	proto_tree_add_text(ansi_map_tree, asn1->tvb,
	    saved_offset, -1, "Components");
    subtree = proto_item_add_subtree(item, ett_components);

    tag_item =
	proto_tree_add_uint_format(subtree, hf_ansi_map_tag, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_ansi_map_len(asn1, subtree, &def_len, &len);

    tag_subtree = proto_item_add_subtree(tag_item, ett_components);

    opr_code = -1;

    switch (tag)
    {
    case ANSI_TC_INVOKE_L:
	dissect_ansi_map_invoke(asn1, pinfo, tag_subtree, &opr_code);
	break;

    case ANSI_TC_RRL:
	dissect_ansi_map_rr(asn1, tag_subtree);
	break;

    case ANSI_TC_RE:
	dissect_ansi_map_re(asn1, tag_subtree);
	break;

    case ANSI_TC_REJECT:
	dissect_ansi_map_reject(asn1, tag_subtree);
	break;

    case ANSI_TC_INVOKE_N:
	dissect_ansi_map_invoke(asn1, pinfo, tag_subtree, &opr_code);
	break;

    case ANSI_TC_RRN:
	dissect_ansi_map_rr(asn1, tag_subtree);
	break;

    default:
	/* XXX */
	break;
    }

    if (bd_tvb != NULL)
    {
	if (ansi_map_sms_tele_id != -1)
	{
	    dissector_try_port(is637_tele_id_dissector_table, ansi_map_sms_tele_id, bd_tvb, g_pinfo, g_tree);
	    ansi_map_sms_tele_id = -1;
	}
	else if (is683_ota)
	{
	    dissector_try_port(is683_dissector_table, ansi_map_is_invoke ? 0 : 1, bd_tvb, g_pinfo, g_tree);
	}
	else if (is801_pld)
	{
	    dissector_try_port(is801_dissector_table, ansi_map_is_invoke ? 0 : 1, bd_tvb, g_pinfo, g_tree);
	}
    }

    proto_item_set_len(item, asn1->offset - saved_offset);

    if (opr_code != -1)
    {
	tap_rec.message_type = opr_code;
	tap_rec.size = asn1->offset - saved_offset;

	tap_queue_packet(ansi_map_tap, pinfo, &tap_rec);
    }
}

static void
dissect_ansi_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ansi_map_item;
    proto_tree *ansi_map_tree = NULL;
    ASN1_SCK   asn1;
    int        offset = 0;

    g_pinfo = pinfo;

    /*
     * Make entry in the Protocol column on summary display
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI MAP");
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	g_tree = tree;

	/*
	 * create the ansi_map protocol tree
	 */
	ansi_map_item =
	    proto_tree_add_item(tree, proto_ansi_map, tvb, 0, -1, FALSE);

	ansi_map_tree =
	    proto_item_add_subtree(ansi_map_item, ett_ansi_map);

        asn1_open(&asn1, tvb, offset);

	ansi_map_is_invoke = FALSE;
	is683_ota = FALSE;
	is801_pld = FALSE;
	bd_tvb = NULL;
	dissect_ansi_map_message(&asn1, pinfo, ansi_map_tree);

	asn1_close(&asn1, &offset);
    }
}


/* Register the protocol with Ethereal */
void
proto_register_ansi_map(void)
{
    guint		i;
    gint		last_offset;

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
	{ &hf_ansi_map_tag,
	    { "Tag",		"ansi_map.tag",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_length,
	    { "Length",		"ansi_map.len",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_id,
	    { "Value",		"ansi_map.id",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_opr_code,
	    { "Operation Code",	"ansi_map.oprcode",
	    FT_INT32, BASE_DEC, VALS(ansi_map_opr_code_strings), 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_param_id,
	    { "Param ID",	"ansi_map.param_id",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_billing_id,
	    { "Billing ID",	"ansi_map.billing_id",
	    FT_INT32, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_ios401_elem_id,
	    { "IOS 4.0.1 Element ID",	"ansi_map.ios401_elem_id",
	    FT_NONE, 0, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_min,
	    { "MIN",		"ansi_map.min",
	    FT_STRING, BASE_DEC, 0, 0,
	    "", HFILL }
	},
	{ &hf_ansi_map_number,
	    { "Number",		"ansi_map.number",
	    FT_STRING, BASE_DEC, 0, 0,
	    "", HFILL }
	},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	15
    gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_PARAM_1+NUM_PARAM_2+NUM_PARAM_3+NUM_IOS401_ELEM];

    memset((void *) ett, -1, sizeof(ett));

    ett[0] = &ett_ansi_map;
    ett[1] = &ett_opr_code;
    ett[2] = &ett_component;
    ett[3] = &ett_components;
    ett[4] = &ett_param;
    ett[5] = &ett_params;
    ett[6] = &ett_error;
    ett[7] = &ett_problem;
    ett[8] = &ett_natnum;
    ett[9] = &ett_call_mode;
    ett[10] = &ett_chan_data;
    ett[11] = &ett_code_chan;
    ett[12] = &ett_clr_dig_mask;
    ett[13] = &ett_ent_dig_mask;
    ett[14] = &ett_all_dig_mask;

    last_offset = NUM_INDIVIDUAL_PARAMS;

    for (i=0; i < NUM_PARAM_1; i++, last_offset++)
    {
	ett[last_offset] = &ett_ansi_param_1[i];
    }

    for (i=0; i < NUM_PARAM_2; i++, last_offset++)
    {
	ett[last_offset] = &ett_ansi_param_2[i];
    }

    for (i=0; i < NUM_PARAM_3; i++, last_offset++)
    {
	ett[last_offset] = &ett_ansi_param_3[i];
    }

    for (i=0; i < NUM_IOS401_ELEM; i++, last_offset++)
    {
	ett[last_offset] = &ett_ansi_map_ios401_elem[i];
    }

    /* Register the protocol name and description */
    proto_ansi_map =
	proto_register_protocol("ANSI Mobile Application Part",
	    "ANSI MAP", "ansi_map");

    is637_tele_id_dissector_table =
	register_dissector_table("ansi_map.tele_id", "IS-637 Teleservice ID",
	    FT_UINT8, BASE_DEC);

    is683_dissector_table =
	register_dissector_table("ansi_map.ota", "IS-683-A (OTA)",
	    FT_UINT8, BASE_DEC);

    is801_dissector_table =
	register_dissector_table("ansi_map.pld", "IS-801 (PLD)",
	    FT_UINT8, BASE_DEC);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_map, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ansi_map_tap = register_tap("ansi_map");
}


void
proto_reg_handoff_ansi_map(void)
{
    dissector_handle_t ansi_map_handle;

    ansi_map_handle = create_dissector_handle(dissect_ansi_map, proto_ansi_map);

    add_ansi_tcap_subdissector(5, ansi_map_handle);
    add_ansi_tcap_subdissector(6, ansi_map_handle);
    add_ansi_tcap_subdissector(7, ansi_map_handle);
    add_ansi_tcap_subdissector(8, ansi_map_handle);
    add_ansi_tcap_subdissector(9 , ansi_map_handle);
    add_ansi_tcap_subdissector(10 , ansi_map_handle);
    add_ansi_tcap_subdissector(11 , ansi_map_handle);
    add_ansi_tcap_subdissector(12 , ansi_map_handle);
    add_ansi_tcap_subdissector(13 , ansi_map_handle);
    add_ansi_tcap_subdissector(14 , ansi_map_handle);

    data_handle = find_dissector("data");
}
