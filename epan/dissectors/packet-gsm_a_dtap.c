/* packet-gsm_a_dtap.c
 * Routines for GSM A Interface DTAP dissection - A.K.A. GSM layer 3
 * NOTE: it actually includes RR messages, which are (generally) not carried
 * over the A interface on DTAP, but are part of the same Layer 3 protocol set
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 *
 * Added the GPRS Mobility Managment Protocol and
 * the GPRS Session Managment Protocol
 *   Copyright 2004, Rene Pilz <rene.pilz [AT] ftw.com>
 *   In association with Telecommunications Research Center
 *   Vienna (ftw.)Betriebs-GmbH within the Project Metawin.
 *
 * Added Dissection of Radio Resource Management Information Elements
 * and othere enhancements and fixes.
 * Copyright 2005 - 2006, Anders Broman [AT] ericsson.com
 * Small bugfixes, mainly in Qos and TFT by Nils Ljungberg and Stefan Boman [AT] ericsson.com
 *
 * Title		3GPP			Other
 *
 *   Reference [1]
 *   Mobile radio interface signalling layer 3;
 *   General Aspects
 *   (3GPP TS 24.007 version 3.9.0 Release 1999)
 *
 *   Reference [3]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 4.7.0 Release 4)
 *   (ETSI TS 124 008 V6.8.0 (2005-03))
 *
 *   Reference [4]
 *   Mobile radio interface layer 3 specification;
 *   Radio Resource Control Protocol
 *   (GSM 04.18 version 8.4.1 Release 1999)
 *   (3GPP TS 04.18 version 8.26.0 Release 1999)
 *
 *   Reference [5]
 *   Point-to-Point (PP) Short Message Service (SMS)
 *   support on mobile radio interface
 *   (3GPP TS 24.011 version 4.1.1 Release 4)
 *
 *   Reference [6]
 *   Mobile radio Layer 3 supplementary service specification;
 *   Formats and coding
 *   (3GPP TS 24.080 version 4.3.0 Release 4)
 *
 *   Reference [7]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 5.9.0 Release 5)
 *
 *   Reference [8]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 6.7.0 Release 6)
 *	 (3GPP TS 24.008 version 6.8.0 Release 6)
 *
 * $Id$
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/asn1.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_a_common.h"
#include "packet-ipv6.h"
#include "packet-e212.h"
#include "packet-ppp.h"

/* PROTOTYPES/FORWARDS */

const value_string gsm_a_dtap_msg_mm_strings[] = {
	{ 0x01,	"IMSI Detach Indication" },
	{ 0x02,	"Location Updating Accept" },
	{ 0x04,	"Location Updating Reject" },
	{ 0x08,	"Location Updating Request" },
	{ 0x11,	"Authentication Reject" },
	{ 0x12,	"Authentication Request" },
	{ 0x14,	"Authentication Response" },
	{ 0x1c,	"Authentication Failure" },
	{ 0x18,	"Identity Request" },
	{ 0x19,	"Identity Response" },
	{ 0x1a,	"TMSI Reallocation Command" },
	{ 0x1b,	"TMSI Reallocation Complete" },
	{ 0x21,	"CM Service Accept" },
	{ 0x22,	"CM Service Reject" },
	{ 0x23,	"CM Service Abort" },
	{ 0x24,	"CM Service Request" },
	{ 0x25,	"CM Service Prompt" },
	{ 0x26,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x28,	"CM Re-establishment Request" },
	{ 0x29,	"Abort" },
	{ 0x30,	"MM Null" },
	{ 0x31,	"MM Status" },
	{ 0x32,	"MM Information" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_cc_strings[] = {
	{ 0x01,	"Alerting" },
	{ 0x08,	"Call Confirmed" },
	{ 0x02,	"Call Proceeding" },
	{ 0x07,	"Connect" },
	{ 0x0f,	"Connect Acknowledge" },
	{ 0x0e,	"Emergency Setup" },
	{ 0x03,	"Progress" },
	{ 0x04,	"CC-Establishment" },
	{ 0x06,	"CC-Establishment Confirmed" },
	{ 0x0b,	"Recall" },
	{ 0x09,	"Start CC" },
	{ 0x05,	"Setup" },
	{ 0x17,	"Modify" },
	{ 0x1f,	"Modify Complete" },
	{ 0x13,	"Modify Reject" },
	{ 0x10,	"User Information" },
	{ 0x18,	"Hold" },
	{ 0x19,	"Hold Acknowledge" },
	{ 0x1a,	"Hold Reject" },
	{ 0x1c,	"Retrieve" },
	{ 0x1d,	"Retrieve Acknowledge" },
	{ 0x1e,	"Retrieve Reject" },
	{ 0x25,	"Disconnect" },
	{ 0x2d,	"Release" },
	{ 0x2a,	"Release Complete" },
	{ 0x39,	"Congestion Control" },
	{ 0x3e,	"Notify" },
	{ 0x3d,	"Status" },
	{ 0x34,	"Status Enquiry" },
	{ 0x35,	"Start DTMF" },
	{ 0x31,	"Stop DTMF" },
	{ 0x32,	"Stop DTMF Acknowledge" },
	{ 0x36,	"Start DTMF Acknowledge" },
	{ 0x37,	"Start DTMF Reject" },
	{ 0x3a,	"Facility" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_gmm_strings[] = {
	{ 0x01,	"Attach Request" },
	{ 0x02,	"Attach Accept" },
	{ 0x03,	"Attach Complete" },
	{ 0x04,	"Attach Reject" },
	{ 0x05,	"Detach Request" },
	{ 0x06,	"Detach Accept" },
	{ 0x08,	"Routing Area Update Request" },
	{ 0x09,	"Routing Area Update Accept" },
	{ 0x0a,	"Routing Area Update Complete" },
	{ 0x0b,	"Routing Area Update Reject" },
	{ 0x0c,	"Service Request" },
	{ 0x0d,	"Service Accept" },
	{ 0x0e,	"Service Reject" },
	{ 0x10,	"P-TMSI Reallocation Command" },
	{ 0x11,	"P-TMSI Reallocation Complete" },
	{ 0x12,	"Authentication and Ciphering Req" },
	{ 0x13,	"Authentication and Ciphering Resp" },
	{ 0x14,	"Authentication and Ciphering Rej" },
	{ 0x1c,	"Authentication and Ciphering Failure" },
	{ 0x15,	"Identity Request" },
	{ 0x16,	"Identity Response" },
	{ 0x20,	"GMM Status" },
	{ 0x21,	"GMM Information" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_sms_strings[] = {
	{ 0x01,	"CP-DATA" },
	{ 0x04,	"CP-ACK" },
	{ 0x10,	"CP-ERROR" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_sm_strings[] = {
	{ 0x41,	"Activate PDP Context Request" },
	{ 0x42,	"Activate PDP Context Accept" },
	{ 0x43,	"Activate PDP Context Reject" },
	{ 0x44,	"Request PDP Context Activation" },
	{ 0x45,	"Request PDP Context Activation rej." },
	{ 0x46,	"Deactivate PDP Context Request" },
	{ 0x47,	"Deactivate PDP Context Accept" },
	{ 0x48,	"Modify PDP Context Request(Network to MS direction)" },
	{ 0x49,	"Modify PDP Context Accept (MS to network direction)" },
	{ 0x4a,	"Modify PDP Context Request(MS to network direction)" },
	{ 0x4b,	"Modify PDP Context Accept (Network to MS direction)" },
	{ 0x4c,	"Modify PDP Context Reject" },
	{ 0x4d,	"Activate Secondary PDP Context Request" },
	{ 0x4e,	"Activate Secondary PDP Context Accept" },
	{ 0x4f,	"Activate Secondary PDP Context Reject" },
	{ 0x50,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x51,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x52,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x53,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x54,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x55,	"SM Status" },
	{ 0x56,	"Activate MBMS Context Request" },
	{ 0x57,	"Activate MBMS Context Accept" },
	{ 0x58,	"Activate MBMS Context Reject" },
	{ 0x59,	"Request MBMS Context Activation" },
	{ 0x5a,	"Request MBMS Context Activation Reject" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_ss_strings[] = {
	{ 0x2a,	"Release Complete" },
	{ 0x3a,	"Facility" },
	{ 0x3b,	"Register" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_tp_strings[] = {
    { 0x00, "Close TCH Loop Cmd" },
    { 0x01, "Close TCH Loop Ack" },
    { 0x06, "Open Loop Cmd" },
    { 0x0c, "Act EMMI Cmd" },
    { 0x0d, "Act EMMI Ack" },
    { 0x10, "Deact EMMI" },
    { 0x14, "Test Interface" },
    { 0x20, "Close Multi-slot Loop Cmd" },
    { 0x21, "Close Multi-slot Loop Ack" },
    { 0x22, "Open Multi-slot Loop Cmd" },
    { 0x23, "Open Multi-slot Loop Ack" },
    { 0x24, "GPRS Test Mode Cmd" },
    { 0x25, "EGPRS Start Radio Block Loopback Cmd" },
    { 0x40, "Close UE Test Loop" },
    { 0x41, "Close UE Test Loop Complete" },
    { 0x42, "Open UE Test Loop" },
    { 0x43, "Open UE Test Loop Complete" },
    { 0x44, "Activate RB Test Mode" },
    { 0x45, "Activate RB Test Mode Complete" },
    { 0x46, "Deactivate RB Test Mode" },
    { 0x47, "Deactivate RB Test Mode Complete" },
    { 0x48, "Reset UE Positioning Stored Information" },
    { 0x49, "UE Test Loop Mode 3 RLC SDU Counter Request" },
    { 0x4A, "UE Test Loop Mode 3 RLC SDU Counter Response" },
    { 0, NULL }
};

const value_string gsm_dtap_elem_strings[] = {
	/* Mobility Management Information Elements 10.5.3 */
	{ 0x00,	"Authentication Parameter RAND" },
	{ 0x00,	"Authentication Parameter AUTN (UMTS authentication challenge only)" },
	{ 0x00,	"Authentication Response Parameter" },
	{ 0x00,	"Authentication Response Parameter (extension) (UMTS authentication challenge only)" },
	{ 0x00,	"Authentication Failure Parameter (UMTS authentication challenge only)" },
	{ 0x00,	"CM Service Type" },
	{ 0x00,	"Identity Type" },
	/* Pos 50 */
	{ 0x00,	"Location Updating Type" },
	{ 0x00,	"Network Name" },
	{ 0x00,	"Reject Cause" },
	{ 0x00,	"Follow-on Proceed" },
	{ 0x00,	"Time Zone" },
	{ 0x00,	"Time Zone and Time" },
	{ 0x00,	"CTS Permission" },
	{ 0x00,	"LSA Identifier" },
	{ 0x00,	"Daylight Saving Time" },
	{ 0x00, "Emergency Number List" },
	/* Call Control Information Elements 10.5.4 */
	/* Pos 60 */
	{ 0x00,	"Auxiliary States" },					/* 10.5.4.4 Auxiliary states */
	{ 0x00,	"Bearer Capability" },					/* 10.5.4.4a Backup bearer capability */
	{ 0x00,	"Call Control Capabilities" },
	{ 0x00,	"Call State" },
	{ 0x00,	"Called Party BCD Number" },
	{ 0x00,	"Called Party Subaddress" },
	{ 0x00,	"Calling Party BCD Number" },
	{ 0x00,	"Calling Party Subaddress" },
	{ 0x00,	"Cause" },
	{ 0x00,	"CLIR Suppression" },
	{ 0x00,	"CLIR Invocation" },
	{ 0x00,	"Congestion Level" },
	{ 0x00,	"Connected Number" },
	{ 0x00,	"Connected Subaddress" },
	{ 0x00,	"Facility" },
	{ 0x00,	"High Layer Compatibility" },
	{ 0x00,	"Keypad Facility" },
	{ 0x00,	"Low Layer Compatibility" },
	{ 0x00,	"More Data" },
	{ 0x00,	"Notification Indicator" },
	{ 0x00,	"Progress Indicator" },
	{ 0x00,	"Recall type $(CCBS)$" },
	{ 0x00,	"Redirecting Party BCD Number" },
	{ 0x00,	"Redirecting Party Subaddress" },
	{ 0x00,	"Repeat Indicator" },
	{ 0x00,	"Reverse Call Setup Direction" },
	{ 0x00,	"SETUP Container $(CCBS)$" },
	{ 0x00,	"Signal" },
	{ 0x00,	"SS Version Indicator" },
	{ 0x00,	"User-user" },
	{ 0x00,	"Alerting Pattern $(NIA)$" },			/* 10.5.4.26 Alerting Pattern $(NIA)$ */
	{ 0x00,	"Allowed Actions $(CCBS)$" },
	{ 0x00,	"Stream Identifier" },
	{ 0x00,	"Network Call Control Capabilities" },
	{ 0x00,	"Cause of No CLI" },
	{ 0x00,	"Immediate Modification Indicator" },	/* 10.5.4.30 Cause of No CLI */
	/* 10.5.4.31 Void */
	{ 0x00,	"Supported Codec List" },				/* 10.5.4.32 Supported codec list */
	{ 0x00,	"Service Category" },					/* 10.5.4.33 Service category */
	/* 10.5.4.34 Redial */
	/* 10.5.4.35 Network-initiated Service Upgrade indicator */
	/* GPRS Mobility Management Information Elements 10.5.5 */
	{ 0x00,	"Attach Result" },
	{ 0x00,	"Attach Type" },
	{ 0x00,	"Cipher Algorithm" },
	{ 0x00,	"TMSI Status" },
	{ 0x00,	"Detach Type" },
	{ 0x00,	"DRX Parameter" },
	{ 0x00,	"Force to Standby" },
	{ 0x00, "Force to Standby" },
	{ 0x00,	"P-TMSI Signature" },
	{ 0x00,	"P-TMSI Signature 2" },
	{ 0x00,	"Identity Type 2" },
	{ 0x00,	"IMEISV Request" },
	{ 0x00,	"Receive N-PDU Numbers List" },
	{ 0x00,	"MS Network Capability" },
	{ 0x00,	"MS Radio Access Capability" },
	{ 0x00,	"GMM Cause" },
	{ 0x00,	"Routing Area Identification" },
	{ 0x00,	"Update Result" },
	{ 0x00, "Update Type" },
	{ 0x00,	"A&C Reference Number" },
	{ 0x00, "A&C Reference Number" },
	{ 0x00,	"Service Type" },
	{ 0x00,	"Cell Notification" },
	{ 0x00, "PS LCS Capability" },
	{ 0x00,	"Network Feature Support" },
	{ 0x00, "Inter RAT information container" },
	/* Short Message Service Information Elements [5] 8.1.4 */
	{ 0x00,	"CP-User Data" },
	{ 0x00,	"CP-Cause" },
	/* Short Message Service Information Elements [5] 8.2 */
	{ 0x00,	"RP-Message Reference" },
	{ 0x00,	"RP-Origination Address" },
	{ 0x00,	"RP-Destination Address" },
	{ 0x00,	"RP-User Data" },
	{ 0x00,	"RP-Cause" },
	/* Session Management Information Elements 10.5.6 */
	{ 0x00,	"Access Point Name" },
	{ 0x00,	"Network Service Access Point Identifier" },
	{ 0x00,	"Protocol Configuration Options" },
	{ 0x00,	"Packet Data Protocol Address" },
	{ 0x00,	"Quality Of Service" },
	{ 0x00,	"SM Cause" },
	{ 0x00,	"Linked TI" },
	{ 0x00,	"LLC Service Access Point Identifier" },
	{ 0x00,	"Tear Down Indicator" },
	{ 0x00,	"Packet Flow Identifier" },
	{ 0x00,	"Traffic Flow Template" },
	/* GPRS Common Information Elements 10.5.7 */
	{ 0x00,	"PDP Context Status" },
	{ 0x00,	"Radio Priority" },
	{ 0x00,	"GPRS Timer" },
	{ 0x00,	"GPRS Timer 2" },
	{ 0x00, "Radio Priority 2"},
	{ 0x00,	"MBMS context status"},
	{ 0x00, "Spare Nibble"},
    /* Tests procedures information elements 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0 */
    { 0x00, "Close TCH Loop Cmd Sub-channel"},
    { 0x00, "Open Loop Cmd Ack"},
    { 0x00, "Close Multi-slot Loop Cmd Loop type"},
    { 0x00, "Close Multi-slot Loop Ack Result"},
    { 0x00, "Test Interface Tested device"},
    { 0x00, "GPRS Test Mode Cmd PDU description"},
    { 0x00, "GPRS Test Mode Cmd Mode flag"},
    { 0x00, "EGPRS Start Radio Block Loopback Cmd Mode flag"},
    { 0x00, "Close UE Test Loop Mode"},
    { 0x00, "UE Positioning Technology"},
    { 0x00, "RLC SDU Counter Value"},
	{ 0, NULL }
};

const gchar *gsm_a_pd_str[] = {
	"Group Call Control",
	"Broadcast Call Control",
	"Reserved: was allocated in earlier phases of the protocol",
	"Call Control; call related SS messages",
	"GPRS Transparent Transport Protocol (GTTP)",
	"Mobility Management messages",
	"Radio Resources Management messages",
	"Unknown",
	"GPRS Mobility Management messages",
	"SMS messages",
	"GPRS Session Management messages",
	"Non call related SS messages",
	"Location Services",
	"Unknown",
	"Reserved for extension of the PD to one octet length",
    "Special conformance testing functions"
};
/* L3 Protocol discriminator values according to TS 24 007 (6.4.0)  */
const value_string protocol_discriminator_vals[] = {
	{0x0,		"Group call control"},
	{0x1,		"Broadcast call control"},
	{0x2,		"Reserved: was allocated in earlier phases of the protocol"},
	{0x3,		"Call Control; call related SS messages"},
	{0x4,		"GPRS Transparent Transport Protocol (GTTP)"},
	{0x5,		"Mobility Management messages"},
	{0x6,		"Radio Resources Management messages"},
	{0x7,		"Unknown"},
	{0x8,		"GPRS mobility management messages"},
	{0x9,		"SMS messages"},
	{0xa,		"GPRS session management messages"},
	{0xb,		"Non call related SS messages"},
	{0xc,		"Location services specified in 3GPP TS 44.071 [8a]"},
	{0xd,		"Unknown"},
	{0xe,		"Reserved for extension of the PD to one octet length "},
	{0xf,		"Special conformance testing functions"},
	{ 0,	NULL }
};

const value_string gsm_a_pd_short_str_vals[] = {
	{0x0,		"GCC"},				/* Group Call Control */
	{0x1,		"BCC"},				/* Broadcast Call Control */
	{0x2,		"Reserved"},		/* : was allocated in earlier phases of the protocol */
	{0x3,		"CC"},				/* Call Control; call related SS messages */
	{0x4,		"GTTP"},			/* GPRS Transparent Transport Protocol (GTTP) */
	{0x5,		"MM"},				/* Mobility Management messages */
	{0x6,		"RR"},				/* Radio Resources Management messages */
	{0x7,		"Unknown"},
	{0x8,		"GMM"},				/* GPRS Session Management messages */
	{0x9,		"SMS"},
	{0xa,		"SM"},				/* GPRS Session Management messages */
	{0xb,		"SS"},
	{0xc,		"LS"},				/* Location Services */
	{0xd,		"Unknown"},
	{0xe,		"Reserved"},		/*  for extension of the PD to one octet length  */
	{0xf,		"TP"},		/*  for tests procedures described in 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0.*/
	{ 0,	NULL }
};


#define	DTAP_PD_MASK		0x0f
#define	DTAP_SKIP_MASK		0xf0
#define	DTAP_TI_MASK		DTAP_SKIP_MASK
#define	DTAP_TIE_PRES_MASK	0x07			/* after TI shifted to right */
#define	DTAP_TIE_MASK		0x7f

#define	DTAP_MM_IEI_MASK	0x3f
#define	DTAP_RR_IEI_MASK	0xff
#define	DTAP_CC_IEI_MASK	0x3f
#define	DTAP_GMM_IEI_MASK	0xff
#define	DTAP_SMS_IEI_MASK	0xff
#define	DTAP_SM_IEI_MASK	0xff
#define	DTAP_SS_IEI_MASK	0x3f
#define DTAP_TP_IEI_MASK  0xff

/* Initialize the protocol and registered fields */
static int proto_a_dtap = -1;

static int hf_gsm_a_dtap_msg_mm_type = -1;
static int hf_gsm_a_dtap_msg_cc_type = -1;
static int hf_gsm_a_dtap_msg_gmm_type = -1;
static int hf_gsm_a_dtap_msg_sms_type = -1;
static int hf_gsm_a_dtap_msg_sm_type = -1;
static int hf_gsm_a_dtap_msg_ss_type = -1;
static int hf_gsm_a_dtap_msg_tp_type = -1;
int hf_gsm_a_dtap_elem_id = -1;
static int hf_gsm_a_cld_party_bcd_num = -1;
static int hf_gsm_a_clg_party_bcd_num = -1;
static int hf_gsm_a_dtap_cause = -1;

static int hf_gsm_a_qos_delay_cls	= -1;
static int hf_gsm_a_qos_qos_reliability_cls = -1;
static int hf_gsm_a_qos_traffic_cls = -1;
static int hf_gsm_a_qos_del_order = -1;
static int hf_gsm_a_qos_del_of_err_sdu = -1;
static int hf_gsm_a_qos_ber = -1;
static int hf_gsm_a_qos_sdu_err_rat = -1;
static int hf_gsm_a_qos_traff_hdl_pri = -1;

static int hf_gsm_a_gmm_split_on_ccch = -1;
static int hf_gsm_a_gmm_non_drx_timer = -1;
static int hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef = -1;

int hf_gsm_a_extension = -1;
static int hf_gsm_a_type_of_number = -1;
static int hf_gsm_a_numbering_plan_id = -1;

static int hf_gsm_a_ptmsi_sig =-1;
static int hf_gsm_a_ptmsi_sig2 =-1;

static int hf_gsm_a_tft_op_code = -1;
static int hf_gsm_a_tft_e_bit = -1;
static int hf_gsm_a_tft_pkt_flt = -1;
static int hf_gsm_a_tft_ip4_address = -1;
static int hf_gsm_a_tft_ip4_mask = -1;
static int hf_gsm_a_tft_ip6_address = -1;
static int hf_gsm_a_tft_ip6_mask = -1;
static int hf_gsm_a_tft_protocol_header = -1;
static int hf_gsm_a_tft_port = -1;
static int hf_gsm_a_tft_port_low = -1;
static int hf_gsm_a_tft_port_high = -1;
static int hf_gsm_a_tft_security = -1;
static int hf_gsm_a_tft_traffic_mask = -1;

static int hf_gsm_a_lsa_id = -1;

/* Initialize the subtree pointers */
static gint ett_dtap_msg = -1;
static gint ett_elems = -1;
static gint ett_elem = -1;
static gint ett_dtap_oct_1 = -1;
static gint ett_cm_srvc_type = -1;
static gint ett_gsm_enc_info = -1;
static gint ett_bc_oct_3a = -1;
static gint ett_bc_oct_4 = -1;
static gint ett_bc_oct_5 = -1;
static gint ett_bc_oct_5a = -1;
static gint ett_bc_oct_5b = -1;
static gint ett_bc_oct_6 = -1;
static gint ett_bc_oct_6a = -1;
static gint ett_bc_oct_6b = -1;
static gint ett_bc_oct_6c = -1;
static gint ett_bc_oct_6d = -1;
static gint ett_bc_oct_6e = -1;
static gint ett_bc_oct_6f = -1;
static gint ett_bc_oct_6g = -1;
static gint ett_bc_oct_7 = -1;

static gint ett_tc_component = -1;
static gint ett_tc_invoke_id = -1;
static gint ett_tc_linked_id = -1;
static gint ett_tc_opr_code = -1;
static gint ett_tc_err_code = -1;
static gint ett_tc_prob_code = -1;
static gint ett_tc_sequence = -1;

static gint ett_gmm_drx = -1;
static gint ett_gmm_detach_type = -1;
static gint ett_gmm_attach_type = -1;
static gint ett_gmm_context_stat = -1;
static gint ett_gmm_update_type = -1;
static gint ett_gmm_radio_cap = -1;
static gint ett_gmm_rai = -1;

static gint ett_sm_tft = -1;

static char a_bigbuf[1024];

static dissector_handle_t data_handle;
static dissector_handle_t gsm_map_handle;
static dissector_handle_t gsm_bsslap_handle = NULL;
static dissector_handle_t dtap_handle;
static dissector_handle_t rp_handle;

static dissector_table_t gprs_sm_pco_subdissector_table; /* GPRS SM PCO PPP Protocols */

static packet_info *g_pinfo;
static proto_tree *g_tree;
static gint comp_type_tag;

/*
 * this should be set on a per message basis, if possible
 */
static gint is_uplink;

#define	NUM_GSM_DTAP_ELEM (sizeof(gsm_dtap_elem_strings)/sizeof(value_string))
gint ett_gsm_dtap_elem[NUM_GSM_DTAP_ELEM];

static dgt_set_t Dgt_mbcd = {
	{
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
	 '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c'
	}
};

/*
 * [3] 10.5.3.1
 */
static guint8
de_auth_param_rand(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

/*
 * 16 octets == 128 bits
 */
#define	AUTH_PARAM_RAND_LEN	16

	proto_tree_add_text(tree,
	tvb, curr_offset, AUTH_PARAM_RAND_LEN,
			"RAND value: %s",
			tvb_bytes_to_str(tvb, curr_offset, AUTH_PARAM_RAND_LEN));

	curr_offset += AUTH_PARAM_RAND_LEN;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.1.1
 */
static guint8
de_auth_param_autn(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,
	tvb, curr_offset, len,
	"AUTN value: %s",
	tvb_bytes_to_str(tvb, curr_offset, len));

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.2
 */
static guint8
de_auth_resp_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

/*
 * 4 octets == 32 bits
 */
#define	AUTH_PARAM_SRES_LEN	4

	proto_tree_add_text(tree,
	tvb, curr_offset, AUTH_PARAM_SRES_LEN,
			"SRES value: %s",
			tvb_bytes_to_str(tvb, curr_offset, AUTH_PARAM_SRES_LEN));

	curr_offset += AUTH_PARAM_SRES_LEN;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.2.1
 */
static guint8
de_auth_resp_param_ext(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,
	tvb, curr_offset, len,
	 "XRES value: %s",
	 tvb_bytes_to_str(tvb, curr_offset, len));

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.2.2
 */
static guint8
de_auth_fail_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,
	tvb, curr_offset, len,
	"AUTS value: %s",
	tvb_bytes_to_str(tvb, curr_offset, len));

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.5a
 */
static guint8
de_network_name(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	switch ((oct & 0x70) >> 4)
	{
	case 0x00: str = "Cell Broadcast data coding scheme, GSM default alphabet, language unspecified, defined in 3GPP TS 03.38"; break;
	case 0x01: str = "UCS2 (16 bit)"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Coding Scheme: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Add CI: The MS should %s",
	a_bigbuf,
	(oct & 0x08) ?
	    "add the letters for the Country's Initials and a separator (e.g. a space) to the text string" :
	    "The MS should not add the letters for the Country's Initials to the text string");

	switch (oct & 0x07)
	{
	case 1: str = "bit 8 is spare and set to '0' in octet n"; break;
	case 2: str = "bits 7 and 8 are spare and set to '0' in octet n"; break;
	case 3: str = "bits 6 to 8(inclusive) are spare and set to '0' in octet n"; break;
	case 4: str = "bits 5 to 8(inclusive) are spare and set to '0' in octet n"; break;
	case 5: str = "bits 4 to 8(inclusive) are spare and set to '0' in octet n"; break;
	case 6: str = "bits 3 to 8(inclusive) are spare and set to '0' in octet n"; break;
	case 7: str = "bits 2 to 8(inclusive) are spare and set to '0' in octet n"; break;
	default:
	str = "this field carries no information about the number of spare bits in octet n";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Number of spare bits in last octet: %s",
	a_bigbuf,
	str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_text(tree,
	tvb, curr_offset, len - 1,
	"Text string encoded according to Coding Scheme");

	curr_offset += len - 1;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/* 3GPP TS 24.008
 * [3] 10.5.3.6 Reject cause
 */
guint8
de_rej_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
	case 0x02: str = "IMSI unknown in HLR"; break;
	case 0x03: str = "Illegal MS"; break;
	case 0x04: str = "IMSI unknown in VLR"; break;
	case 0x05: str = "IMEI not accepted"; break;
	case 0x06: str = "Illegal ME"; break;
	case 0x0b: str = "PLMN not allowed"; break;
	case 0x0c: str = "Location Area not allowed"; break;
	case 0x0d: str = "Roaming not allowed in this location area"; break;
	case 0x0f: str = "No Suitable Cells In Location Area"; break;
	case 0x11: str = "Network failure"; break;
	case 0x14: str = "MAC failure"; break;
	case 0x15: str = "Synch failure"; break;
	case 0x16: str = "Congestion"; break;
	case 0x17: str = "GSM authentication unacceptable"; break;
	case 0x20: str = "Service option not supported"; break;
	case 0x21: str = "Requested service option not subscribed"; break;
	case 0x22: str = "Service option temporarily out of order"; break;
	case 0x26: str = "Call cannot be identified"; break;
	case 0x5f: str = "Semantically incorrect message"; break;
	case 0x60: str = "Invalid mandatory information"; break;
	case 0x61: str = "Message type non-existent or not implemented"; break;
	case 0x62: str = "Message type not compatible with the protocol state"; break;
	case 0x63: str = "Information element non-existent or not implemented"; break;
	case 0x64: str = "Conditional IE error"; break;
	case 0x65: str = "Message not compatible with the protocol state"; break;
	case 0x6f: str = "Protocol error, unspecified"; break;
	default:
	switch (is_uplink)
	{
	case IS_UPLINK_FALSE:
	    str = "Service option temporarily out of order";
	    break;
	default:
	    str = "Protocol error, unspecified";
	    break;
	}
	break;
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Reject Cause value: 0x%02x (%u) %s",
	oct,
	oct,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.8
 */
static guint8
de_time_zone(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	char sign;

	len = len;
	curr_offset = offset;

	/* 3GPP TS 23.040 version 6.6.0 Release 6
	 * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
	 * :
	 * The Time Zone indicates the difference, expressed in quarters of an hour,
	 * between the local time and GMT. In the first of the two semi-octets,
	 * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
	 * represents the algebraic sign of this difference (0: positive, 1: negative).
	 */

	oct = tvb_get_guint8(tvb, curr_offset);
	sign = (oct & 0x08)?'-':'+';
	oct = (oct >> 4) + (oct & 0x07) * 10;

	proto_tree_add_text(tree,
	tvb, offset, 1,
	"Timezone: GMT %c %d hours %d minutes",
	sign, oct / 4, oct % 4 * 15);
	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.9
 */
static guint8
de_time_zone_time(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct, oct2, oct3;
	guint32	curr_offset;
	char sign;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct2 = tvb_get_guint8(tvb, curr_offset+1);
	oct3 = tvb_get_guint8(tvb, curr_offset+2);

	proto_tree_add_text(tree,
	tvb, curr_offset, 3,
	"Year %u%u, Month %u%u, Day %u%u",
	oct & 0x0f,
	(oct & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct3 & 0x0f,
	(oct3 & 0xf0) >> 4);

	curr_offset += 3;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct2 = tvb_get_guint8(tvb, curr_offset+1);
	oct3 = tvb_get_guint8(tvb, curr_offset+2);

	proto_tree_add_text(tree,
	tvb, curr_offset, 3,
	"Hour %u%u, Minutes %u%u, Seconds %u%u",
	oct & 0x0f,
	(oct & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct3 & 0x0f,
	(oct3 & 0xf0) >> 4);

	curr_offset += 3;

	/* 3GPP TS 23.040 version 6.6.0 Release 6
	 * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
	 * :
	 * The Time Zone indicates the difference, expressed in quarters of an hour,
	 * between the local time and GMT. In the first of the two semi-octets,
	 * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
	 * represents the algebraic sign of this difference (0: positive, 1: negative).
	 */

	oct = tvb_get_guint8(tvb, curr_offset);
	sign = (oct & 0x08)?'-':'+';
	oct = (oct >> 4) + (oct & 0x07) * 10;

	proto_tree_add_text(tree,
	tvb, offset, 1,
	"Timezone: GMT %c %d hours %d minutes",
	sign, oct / 4, oct % 4 * 15);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.11 3GPP TS 24.008 version 6.8.0 Release 6
 */
static guint8
de_lsa_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	if (len == 0){
		proto_tree_add_text(tree,tvb, curr_offset, len,"LSA ID not included");
	}else{
		proto_tree_add_item(tree, hf_gsm_a_lsa_id, tvb, curr_offset, 3, FALSE);
	}

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.3.12
 */
static guint8
de_day_saving_time(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch (oct & 0x03)
	{
	case 0: str = "No adjustment for Daylight Saving Time"; break;
	case 1: str = "+1 hour adjustment for Daylight Saving Time"; break;
	case 2: str = "+2 hours adjustment for Daylight Saving Time"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  %s",
	a_bigbuf,
	str);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.4
 */
static guint8
de_aux_states(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch ((oct & 0x0c) >> 2)
	{
	case 0: str = "Idle"; break;
	case 1: str = "Hold request"; break;
	case 2: str = "Call held"; break;
	default:
	str = "Retrieve request";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0c, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Hold auxiliary state: %s",
	a_bigbuf,
	str);

	switch (oct & 0x03)
	{
	case 0: str = "Idle"; break;
	case 1: str = "MPTY request"; break;
	case 2: str = "Call in MPTY"; break;
	default:
	str = "Split request";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Multi party auxiliary state: %s",
	a_bigbuf,
	str);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.5
 */
static guint8
de_bearer_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint8	itc;
	gboolean	extended;
	guint32	curr_offset;
	guint32	saved_offset;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

#define	DE_BC_ITC_SPEECH	0x00
#define	DE_BC_ITC_UDI		0x01
#define	DE_BC_ITC_EX_PLMN	0x02
#define	DE_BC_ITC_FASC_G3	0x03
#define	DE_BC_ITC_OTHER_ITC	0x05
#define	DE_BC_ITC_RSVD_NET	0x07

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* octet 3 */

	/*
	 * warning, bearer cap uses extended values that
	 * are reversed from other parameters!
	 */
	extended = (oct & 0x80) ? FALSE : TRUE;
	itc = oct & 0x07;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension: %s",
	a_bigbuf,
	extended ? "extended" : "not extended");

	switch (is_uplink)
	{
	case IS_UPLINK_FALSE:
	str = "Spare";
	break;

	case IS_UPLINK_TRUE:
	/*
	 * depends on Information transfer capability
	 */
	switch (itc)
	{
	case DE_BC_ITC_SPEECH:
	    if (extended)
	    {
		switch ((oct & 0x60) >> 5)
		{
		case 1: str = "MS supports at least full rate speech version 1 but does not support half rate speech version 1"; break;
		case 2: str = "MS supports at least full rate speech version 1 and half rate speech version 1. MS has a greater preference for half rate speech version 1 than for full rate speech version 1"; break;
		case 3: str = "MS supports at least full rate speech version 1 and half rate speech version 1. MS has a greater preference for full rate speech version 1 than for half rate speech version 1"; break;
		default:
		    str = "Reserved";
		    break;
		}
	    }
	    else
	    {
		switch ((oct & 0x60) >> 5)
		{
		case 1: str = "Full rate support only MS/fullrate speech version 1 supported"; break;
		case 2: str = "Dual rate support MS/half rate speech version 1 preferred, full rate speech version 1 also supported"; break;
		case 3: str = "Dual rate support MS/full rate speech version 1 preferred, half rate speech version 1 also supported"; break;
		default:
		    str = "Reserved";
		    break;
		}
	    }
	    break;

	default:
	    switch ((oct & 0x60) >> 5)
	    {
	    case 1: str = "Full rate support only MS"; break;
	    case 2: str = "Dual rate support MS/half rate preferred"; break;
	    case 3: str = "Dual rate support MS/full rate preferred"; break;
	    default:
		str = "Reserved";
		break;
	    }
	    break;
	}
	break;

	default:
	str = "(dissect problem)";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Radio channel requirement: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Coding standard: %s",
	a_bigbuf,
	(oct & 0x10) ? "reserved" : "GSM standardized coding");

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Transfer mode: %s",
	a_bigbuf,
	(oct & 0x08) ? "packet" : "circuit");

	switch (itc)
	{
	case DE_BC_ITC_SPEECH: str = "Speech"; break;
	case DE_BC_ITC_UDI: str = "Unrestricted digital information"; break;
	case DE_BC_ITC_EX_PLMN: str = "3.1 kHz audio, ex PLMN"; break;
	case DE_BC_ITC_FASC_G3: str = "Facsimile group 3"; break;
	case DE_BC_ITC_OTHER_ITC: str = "Other ITC (See Octet 5a)"; break;
	case DE_BC_ITC_RSVD_NET: str = "Reserved, to be used in the network"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Information transfer capability: %s",
	a_bigbuf,
	str);

	if (add_string)
	g_snprintf(add_string, string_len, " - (%s)", str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	switch (itc)
	{
	case DE_BC_ITC_SPEECH:
	/* octets 3a */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, -1,
		"Octets 3a - Speech Versions");

	subtree = proto_item_add_subtree(item, ett_bc_oct_3a);

	saved_offset = curr_offset;

	do
	{
	    oct = tvb_get_guint8(tvb, curr_offset);

	    extended = (oct & 0x80) ? FALSE : TRUE;

	    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Extension: %s",
		a_bigbuf,
		extended ? "extended" : "not extended");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Coding: octet used for %s",
		a_bigbuf,
		(oct & 0x40) ? "other extension of octet 3" :
		    "extension of information transfer capability");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Spare",
		a_bigbuf);

	    switch (oct & 0x0f)
	    {
	    case 0: str = "GSM full rate speech version 1"; break;
	    case 2: str = "GSM full rate speech version 2"; break;
	    case 4: str = "GSM full rate speech version 3"; break;
	    case 1: str = "GSM half rate speech version 1"; break;
	    case 5: str = "GSM half rate speech version 3"; break;
	    default:
		str = "Speech version TBD";
		break;
	    }

	    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Speech version indication: %s",
		a_bigbuf,
		str);

	    curr_offset++;
	}
	while (extended &&
	    ((len - (curr_offset - offset)) > 0));

	proto_item_set_len(item, curr_offset - saved_offset);
	break;

	default:
	/* octet 4 */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 4");

	subtree = proto_item_add_subtree(item, ett_bc_oct_4);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Compression: data compression %s%s",
	    a_bigbuf,
	    (oct & 0x40) ? "" : "not ",
	    is_uplink ? "allowed" : "possible");

	switch ((oct & 0x30) >> 4)
	{
	case 0x00: str = "Service data unit integrity"; break;
	case 0x03: str = "Unstructured"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Structure: %s",
	    a_bigbuf,
	    str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Duplex mode: %s",
	    a_bigbuf,
	    (oct & 0x08) ? "Full" : "Half");

	other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Configuration: %s",
	    a_bigbuf,
	    (oct & 0x04) ? "Reserved" : "Point-to-point");

	other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  NIRR: %s",
	    a_bigbuf,
	    (oct & 0x02) ?
		"Data up to and including 4.8 kb/s, full rate, non-transparent, 6 kb/s radio interface rate is requested" :
		"No meaning is associated with this value");

	other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Establishment: %s",
	    a_bigbuf,
	    (oct & 0x01) ? "Reserved" : "Demand");

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	/* octet 5 */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 5");

	subtree = proto_item_add_subtree(item, ett_bc_oct_5);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Access Identity: %s",
	    a_bigbuf,
	    (oct & 0x60) ? "Reserved" : "Octet identifier");

	switch ((oct & 0x18) >> 3)
	{
	case 0x00: str = "No rate adaption"; break;
	case 0x01: str = "V.110, I.460/X.30 rate adaptation"; break;
	case 0x02: str = "ITU-T X.31 flag stuffing"; break;
	default:
	    str = "Other rate adaption (see octet 5a)";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x18, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Rate Adaption: %s",
	    a_bigbuf,
	    str);

	switch (oct & 0x07)
	{
	case 0x01: str = "I.440/450"; break;
	case 0x02: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	case 0x03: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	case 0x04: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	case 0x05: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	case 0x06: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Signalling Access Protocol: %s",
	    a_bigbuf,
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_6;

	/* octet 5a */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 5a");

	subtree = proto_item_add_subtree(item, ett_bc_oct_5a);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Other ITC: %s",
	    a_bigbuf,
	    (oct & 0x60) ? "Reserved" : "Restricted digital information");

	switch ((oct & 0x18) >> 3)
	{
	case 0x00: str = "V.120"; break;
	case 0x01: str = "H.223 & H.245"; break;
	case 0x02: str = "PIAFS"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x18, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Other Rate Adaption: %s",
	    a_bigbuf,
	    str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Spare",
	    a_bigbuf);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_6;

	/* octet 5b */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 5b");

	subtree = proto_item_add_subtree(item, ett_bc_oct_5b);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Rate Adaption Header: %sincluded",
	    a_bigbuf,
	    (oct & 0x40) ? "" : "not ");

	other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Multiple frame establishment support in data link: %s",
	    a_bigbuf,
	    (oct & 0x20) ? "Supported" : "Not supported, only UI frames allowed");

	other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Mode of operation: %s",
	    a_bigbuf,
	    (oct & 0x10) ? "Protocol sensitive" : "Bit transparent");

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Logical link identifier negotiation: %s",
	    a_bigbuf,
	    (oct & 0x08) ? "Full protocol negotiation" : "Default, LLI=256 only");

	other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Assignor/Assignee: Message originator is '%s'",
	    a_bigbuf,
	    (oct & 0x04) ? "assignor only" : "default assignee");

	other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  In band/Out of band negotiation: Negotiation is done %s",
	    a_bigbuf,
	    (oct & 0x02) ?
		"with USER INFORMATION messages on a temporary signalling connection" :
		"in-band using logical link zero");

	other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Spare",
	    a_bigbuf);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

bc_octet_6:

	/* octet 6 */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Layer 1 Identity: %s",
	    a_bigbuf,
	    ((oct & 0x60) == 0x20) ? "Octet identifier" : "Reserved");

	other_decode_bitfield_value(a_bigbuf, oct, 0x1e, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  User information layer 1 protocol: %s",
	    a_bigbuf,
	    (oct & 0x1e) ? "Reserved" : "Default layer 1 protocol");

	other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Synchronous/asynchronous: %s",
	    a_bigbuf,
	    (oct & 0x01) ? "Asynchronous" : "Synchronous");

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6a */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6a");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6a);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Number of Stop Bits: %s",
	    a_bigbuf,
	    (oct & 0x40) ? "2" : "1");

	other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Negotiation: %s",
	    a_bigbuf,
	    (oct & 0x20) ? "Reserved" : "In-band negotiation not possible");

	other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Number of data bits excluding parity bit if present: %s",
	    a_bigbuf,
	    (oct & 0x10) ? "8" : "7");

	switch (oct & 0x0f)
	{
	case 0x01: str = "0.3 kbit/s Recommendation X.1 and V.110"; break;
	case 0x02: str = "1.2 kbit/s Recommendation X.1 and V.110"; break;
	case 0x03: str = "2.4 kbit/s Recommendation X.1 and V.110"; break;
	case 0x04: str = "4.8 kbit/s Recommendation X.1 and V.110"; break;
	case 0x05: str = "9.6 kbit/s Recommendation X.1 and V.110"; break;
	case 0x06: str = "12.0 kbit/s transparent (non compliance with X.1 and V.110)"; break;
	case 0x07: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  User rate: %s",
	    a_bigbuf,
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6b */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6b");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6b);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	switch ((oct & 0x60) >> 5)
	{
	case 0x02: str = "8 kbit/s"; break;
	case 0x03: str = "16 kbit/s"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  V.110/X.30 rate adaptation Intermediate rate: %s",
	    a_bigbuf,
	    str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Network independent clock (NIC) on transmission (Tx): %s to send data with network independent clock",
	    a_bigbuf,
	    (oct & 0x10) ? "requires" : "does not require");

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Network independent clock (NIC) on reception (Rx): %s accept data with network independent clock",
	    a_bigbuf,
	    (oct & 0x08) ? "can" : "cannot");

	switch (oct & 0x07)
	{
	case 0x00: str = "Odd"; break;
	case 0x02: str = "Even"; break;
	case 0x03: str = "None"; break;
	case 0x04: str = "Forced to 0"; break;
	case 0x05: str = "Forced to 1"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Parity information: %s",
	    a_bigbuf,
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6c */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6c");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6c);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	switch ((oct & 0x60) >> 5)
	{
	case 0x01: str = "Non transparent (RLP)"; break;
	case 0x02: str = "Both, transparent preferred"; break;
	case 0x03: str = "Both, non transparent preferred"; break;
	default:
	    str = "Transparent";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Connection element: %s",
	    a_bigbuf,
	    str);

	switch (oct & 0x1f)
	{
	case 0x00: str = "None"; break;
	case 0x01: str = "V.21"; break;
	case 0x02: str = "V.22"; break;
	case 0x03: str = "V.22 bis"; break;
	case 0x04: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	case 0x05: str = "V.26 ter"; break;
	case 0x06: str = "V.32"; break;
	case 0x07: str = "Modem for undefined interface"; break;
	case 0x08: str = "Autobauding type 1"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Modem type: %s",
	    a_bigbuf,
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6d */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6d");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6d);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	switch ((oct & 0x60) >> 5)
	{
	case 0x00: str = "No other modem type specified in this field"; break;
	case 0x02: str = "V.34"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Other modem type: %s",
	    a_bigbuf,
	    str);

	switch (oct & 0x1f)
	{
	case 0x00: str = "Fixed network user rate not applicable/No meaning is associated with this value"; break;
	case 0x01: str = "9.6 kbit/s Recommendation X.1 and V.110"; break;
	case 0x02: str = "14.4 kbit/s Recommendation X.1 and V.110"; break;
	case 0x03: str = "19.2 kbit/s Recommendation X.1 and V.110"; break;
	case 0x04: str = "28.8 kbit/s Recommendation X.1 and V.110"; break;
	case 0x05: str = "38.4 kbit/s Recommendation X.1 and V.110"; break;
	case 0x06: str = "48.0 kbit/s Recommendation X.1 and V.110(synch)"; break;
	case 0x07: str = "56.0 kbit/s Recommendation X.1 and V.110(synch) /bit transparent"; break;
	case 0x08: str = "64.0 kbit/s bit transparent"; break;
	case 0x09: str = "33.6 kbit/s bit transparent"; break;
	case 0x0a: str = "32.0 kbit/s Recommendation I.460"; break;
	case 0x0b: str = "31.2 kbit/s Recommendation V.34"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Fixed network user rate: %s",
	    a_bigbuf,
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6e */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6e");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6e);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	if (is_uplink == IS_UPLINK_TRUE)
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings: TCH/F14.4 %sacceptable",
		a_bigbuf,
		(oct & 0x40) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings: Spare",
		a_bigbuf);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings: TCH/F9.6 %sacceptable",
		a_bigbuf,
		(oct & 0x10) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings: TCH/F4.8 %sacceptable",
		a_bigbuf,
		(oct & 0x08) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Maximum number of traffic channels: %u TCH",
		a_bigbuf,
		(oct & 0x07) + 1);
	}
	else
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x78, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings: Spare",
		a_bigbuf);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Maximum number of traffic channels: Spare",
		a_bigbuf);
	}

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6f */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6f");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6f);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	switch ((oct & 0x70) >> 4)
	{
	case 0x00: str = "not allowed/required/applicable"; break;
	case 0x01: str = "up to 1 TCH/F allowed/may be requested"; break;
	case 0x02: str = "up to 2 TCH/F allowed/may be requested"; break;
	case 0x03: str = "up to 3 TCH/F allowed/may be requested"; break;
	case 0x04: str = "up to 4 TCH/F allowed/may be requested"; break;
	default:
	    str = "up to 4 TCH/F may be requested";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  UIMI, User initiated modification indication: %s",
	    a_bigbuf,
	    str);

	if (is_uplink == IS_UPLINK_TRUE)
	{
	    switch (oct & 0x0f)
	    {
	    case 0x00: str = "Air interface user rate not applicable/No meaning associated with this value"; break;
	    case 0x01: str = "9.6 kbit/s"; break;
	    case 0x02: str = "14.4 kbit/s"; break;
	    case 0x03: str = "19.2 kbit/s"; break;
	    case 0x05: str = "28.8 kbit/s"; break;
	    case 0x06: str = "38.4 kbit/s"; break;
	    case 0x07: str = "43.2 kbit/s"; break;
	    case 0x08: str = "57.6 kbit/s"; break;
	    case 0x09: str = "interpreted by the network as 38.4 kbit/s in this version of the protocol"; break;
	    case 0x0a: str = "interpreted by the network as 38.4 kbit/s in this version of the protocol"; break;
	    case 0x0b: str = "interpreted by the network as 38.4 kbit/s in this version of the protocol"; break;
	    case 0x0c: str = "interpreted by the network as 38.4 kbit/s in this version of the protocol"; break;
	    default:
		str = "Reserved";
		break;
	    }

	    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Wanted air interface user rate: %s",
		a_bigbuf,
		str);
	}
	else
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Wanted air interface user rate: Spare",
		a_bigbuf);
	}

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	if (!extended) goto bc_octet_7;

	/* octet 6g */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 6g");

	subtree = proto_item_add_subtree(item, ett_bc_oct_6g);

	oct = tvb_get_guint8(tvb, curr_offset);

	extended = (oct & 0x80) ? FALSE : TRUE;

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	if (is_uplink == IS_UPLINK_TRUE)
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings extended: TCH/F28.8 %sacceptable",
		a_bigbuf,
		(oct & 0x40) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings extended: TCH/F32.0 %sacceptable",
		a_bigbuf,
		(oct & 0x20) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings extended: TCH/F43.2 %sacceptable",
		a_bigbuf,
		(oct & 0x10) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Acceptable channel codings extended: TCH/F43.2 %sacceptable",
		a_bigbuf,
		(oct & 0x10) ? "" : "not ");

	    switch ((oct & 0x0c) >> 2)
	    {
	    case 0: str = "Channel coding symmetry preferred"; break;
	    case 2: str = "Downlink biased channel coding asymmetry is preferred"; break;
	    case 1: str = "Uplink biased channel coding asymmetry is preferred"; break;
	    default:
		str = "Unused, treat as Channel coding symmetry preferred";
		break;
	    }

	    other_decode_bitfield_value(a_bigbuf, oct, 0x0c, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Channel Coding Asymmetry Indication: %s",
		a_bigbuf,
		str);
	}
	else
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x7c, 8);
	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  EDGE Channel Codings: Spare",
		a_bigbuf);
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Spare",
	    a_bigbuf);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

bc_octet_7:

	/* octet 7 */

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Octet 7");

	subtree = proto_item_add_subtree(item, ett_bc_oct_7);

	extended = (oct & 0x80) ? FALSE : TRUE;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    extended ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Layer 2 Identity: %s",
	    a_bigbuf,
	    ((oct & 0x60) == 0x40) ? "Octet identifier" : "Reserved");

	switch (oct & 0x1f)
	{
	case 0x06: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	case 0x08: str = "ISO 6429, codeset 0 (DC1/DC3)"; break;
	case 0x09: str = "Reserved: was allocated but never used in earlier phases of the protocol"; break;
	case 0x0a: str = "Videotex profile 1"; break;
	case 0x0c: str = "COPnoFlCt (Character oriented Protocol with no Flow Control mechanism)"; break;
	case 0x0d: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	default:
	    str = "Reserved";
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  User information layer 2 protocol: %s",
	    a_bigbuf,
	    str);
	break;
	}

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.5a
 */
static guint8
de_cc_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);

	switch ((oct & 0xf0) >> 4)
	{
	case 0:
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Maximum number of supported bearers: 1",
	    a_bigbuf);
	break;

	default:
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Maximum number of supported bearers: %u",
	    a_bigbuf,
	    (oct & 0xf0) >> 4);
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0c, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  PCP: the mobile station %s the Prolonged Clearing Procedure",
	a_bigbuf,
	(oct & 0x02) ? "supports" : "does not support");

	other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  DTMF: %s",
	a_bigbuf,
	(oct & 0x01) ?
	    "the mobile station supports DTMF as specified in subclause 5.5.7 of TS 24.008" :
	    "reserved for earlier versions of the protocol");

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Maximum number of speech bearers: %u",
	a_bigbuf,
	oct & 0x0f);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.6
 */
static guint8
de_call_state(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_CALL_STATE].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CALL_STATE]);

	switch ((oct & 0xc0) >> 6)
	{
	case 0: str = "Coding as specified in ITU-T Rec. Q.931"; break;
	case 1: str = "Reserved for other international standards"; break;
	case 2: str = "National standard"; break;
	default:
	str = "Standard defined for the GSM PLMNS";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Coding standard: %s",
	a_bigbuf,
	str);

	switch (oct & 0x3f)
	{
	case 0x00: str = "UO - null                                 NO - null"; break;
	case 0x02: str = "U0.1- MM connection pending               N0.1- MM connection pending"; break;
	case 0x22: str = "U0.2- CC prompt present                   N0.2- CC connection pending"; break;
	case 0x23: str = "U0.3- Wait for network information        N0.3- Network answer pending"; break;
	case 0x24: str = "U0.4- CC-Establishment present            N0.4- CC-Establishment present"; break;
	case 0x25: str = "U0.5- CC-Establishment confirmed          N0.5- CC-Establishment confirmed"; break;
	case 0x26: str = "U0.6- Recall present                      N0.6- Recall present"; break;
	case 0x01: str = "U1 - call initiated                       N1 - call initiated"; break;
	case 0x03: str = "U3 - mobile originating call proceeding   N3 - mobile originating call proceeding"; break;
	case 0x04: str = "U4 - call delivered                       N4 - call delivered"; break;
	case 0x06: str = "U6 - call present                         N6 - call present"; break;
	case 0x07: str = "U7 - call received                        N7 - call received"; break;
	case 0x08: str = "U8 - connect request                      N8 - connect request"; break;
	case 0x09: str = "U9 - mobile terminating call confirmed    N9 - mobile terminating call confirmed"; break;
	case 0x0a: str = "U10- active                               N10- active"; break;
	case 0x0b: str = "U11- disconnect request"; break;
	case 0x0c: str = "U12- disconnect indication                N12-disconnect indication"; break;
	case 0x13: str = "U19- release request                      N19- release request"; break;
	case 0x1a: str = "U26- mobile originating modify            N26- mobile originating modify"; break;
	case 0x1b: str = "U27- mobile terminating modify            N27- mobile terminating modify"; break;
	case 0x1c: str = "                                          N28- connect indication"; break;
	default:
	str = "Unknown";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Call state value: %s",
	a_bigbuf,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

static const true_false_string gsm_a_extension_value = {
  "No Extension",
  "Extension"
};

const value_string gsm_a_type_of_number_values[] = {
	{   0x00,	"unknown" },
	{   0x01,	"International Number" },
	{   0x02,	"National number" },
	{   0x03,	"Network Specific Number" },
	{   0x04,	"Dedicated access, short code" },
	{   0x05,	"Reserved" },
	{   0x06,	"Reserved" },
	{   0x07,	"Reserved for extension" },
	{ 0, NULL }
};

const value_string gsm_a_numbering_plan_id_values[] = {
	{   0x00,	"unknown" },
	{   0x01,	"ISDN/Telephony Numbering (Rec ITU-T E.164)" },
	{   0x02,	"spare" },
	{   0x03,	"Data Numbering (ITU-T Rec. X.121)" },
	{   0x04,	"Telex Numbering (ITU-T Rec. F.69)" },
	{   0x08,	"National Numbering" },
	{   0x09,	"Private Numbering" },
	{	0x0d,	"reserved for CTS (see 3GPP TS 44.056 [91])" },
	{   0x0f,	"Reserved for extension" },
	{ 0, NULL }
};

/*
 * [3] 10.5.4.7
 */
guint8
de_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	*poctets;
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_type_of_number , tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_numbering_plan_id , tvb, curr_offset, 1, FALSE);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

	my_dgt_tbcd_unpack(a_bigbuf, poctets, len - (curr_offset - offset),
	&Dgt_mbcd);

	proto_tree_add_string_format(tree, hf_gsm_a_cld_party_bcd_num,
	tvb, curr_offset, len - (curr_offset - offset),
	a_bigbuf,
	"BCD Digits: %s",
	a_bigbuf);

	if (sccp_assoc && ! sccp_assoc->called_party) {
		sccp_assoc->called_party = se_strdup(a_bigbuf);
	}

	curr_offset += len - (curr_offset - offset);

	if (add_string)
	g_snprintf(add_string, string_len, " - (%s)", a_bigbuf);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.8
 */
static guint8
de_cld_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	switch ((oct & 0x70) >> 4)
	{
	case 0: str = "NSAP (X.213/ISO 8348 AD2)"; break;
	case 2: str = "User specified"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Type of subaddress: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Odd/Even indicator: %s",
	a_bigbuf,
	(oct & 0x08) ?
	    "odd number of address signals" : "even number of address signals");

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Subaddress information");

	curr_offset += len - (curr_offset - offset);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/* 3GPP TS 24.008
 * [3] 10.5.4.9
 */
static guint8
de_clg_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint8	*poctets;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_type_of_number , tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_numbering_plan_id , tvb, curr_offset, 1, FALSE);

	curr_offset++;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	switch ((oct & 0x60) >> 5)
	{
	case 0: str = "Presentation allowed"; break;
	case 1: str = "Presentation restricted"; break;
	case 2: str = "Number not available due to interworking"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Presentation indicator: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x1c, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch (oct & 0x03)
	{
	case 0: str = "User-provided, not screened"; break;
	case 1: str = "User-provided, verified and passed"; break;
	case 2: str = "User-provided, verified and failed"; break;
	default:
	str = "Network provided";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Screening indicator: %s",
	a_bigbuf,
	str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

	my_dgt_tbcd_unpack(a_bigbuf, poctets, len - (curr_offset - offset),
	&Dgt_mbcd);

	proto_tree_add_string_format(tree, hf_gsm_a_clg_party_bcd_num,
	tvb, curr_offset, len - (curr_offset - offset),
	a_bigbuf,
	"BCD Digits: %s",
	a_bigbuf);

	curr_offset += len - (curr_offset - offset);

	if (add_string)
	g_snprintf(add_string, string_len, " - (%s)", a_bigbuf);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.10
 */
static guint8
de_clg_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	switch ((oct & 0x70) >> 4)
	{
	case 0: str = "NSAP (X.213/ISO 8348 AD2)"; break;
	case 2: str = "User specified"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Type of subaddress: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Odd/Even indicator: %s",
	a_bigbuf,
	(oct & 0x08) ?
	    "odd number of address signals" : "even number of address signals");

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Subaddress information");

	curr_offset += len - (curr_offset - offset);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.11
 */
static guint8
de_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint8	cause;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension: %s",
	a_bigbuf,
	(oct & 0x80) ? "not extended" : "extended");

	switch ((oct & 0x60) >> 5)
	{
	case 0: str = "Coding as specified in ITU-T Rec. Q.931"; break;
	case 1: str = "Reserved for other international standards"; break;
	case 2: str = "National standard"; break;
	default:
	str = "Standard defined for the GSM PLMNS";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Coding standard: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch (oct & 0x0f)
	{
	case 0: str = "User"; break;
	case 1: str = "Private network serving the local user"; break;
	case 2: str = "Public network serving the local user"; break;
	case 3: str = "Transit network"; break;
	case 4: str = "Public network serving the remote user"; break;
	case 5: str = "Private network serving the remote user"; break;
	case 7: str = "International network"; break;
	case 10: str = "Network beyond interworking point"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Location: %s",
	a_bigbuf,
	str);

	curr_offset++;

	oct = tvb_get_guint8(tvb, curr_offset);

	if (!(oct & 0x80))
	{
	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Recommendation",
	    a_bigbuf);

	curr_offset++;

	oct = tvb_get_guint8(tvb, curr_offset);
	}

	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, FALSE);

	cause = oct & 0x7f;
	switch (cause)
	{
	case 1: str = "Unassigned (unallocated) number"; break;
	case 3: str = "No route to destination"; break;
	case 6: str = "Channel unacceptable"; break;
	case 8: str = "Operator determined barring"; break;
	case 16: str = "Normal call clearing"; break;
	case 17: str = "User busy"; break;
	case 18: str = "No user responding"; break;
	case 19: str = "User alerting, no answer"; break;
	case 21: str = "Call rejected"; break;
	case 22: str = "Number changed"; break;
	case 25: str = "Pre-emption"; break;
	case 26: str = "Non selected user clearing"; break;
	case 27: str = "Destination out of order"; break;
	case 28: str = "Invalid number format (incomplete number)"; break;
	case 29: str = "Facility rejected"; break;
	case 30: str = "Response to STATUS ENQUIRY"; break;
	case 31: str = "Normal, unspecified"; break;
	case 34: str = "No circuit/channel available"; break;
	case 38: str = "Network out of order"; break;
	case 41: str = "Temporary failure"; break;
	case 42: str = "Switching equipment congestion"; break;
	case 43: str = "Access information discarded"; break;
	case 44: str = "requested circuit/channel not available"; break;
	case 47: str = "Resources unavailable, unspecified"; break;
	case 49: str = "Quality of service unavailable"; break;
	case 50: str = "Requested facility not subscribed"; break;
	case 55: str = "Incoming calls barred within the CUG"; break;
	case 57: str = "Bearer capability not authorized"; break;
	case 58: str = "Bearer capability not presently available"; break;
	case 63: str = "Service or option not available, unspecified"; break;
	case 65: str = "Bearer service not implemented"; break;
	case 68: str = "ACM equal to or greater than ACMmax"; break;
	case 69: str = "Requested facility not implemented"; break;
	case 70: str = "Only restricted digital information bearer capability is available"; break;
	case 79: str = "Service or option not implemented, unspecified"; break;
	case 81: str = "Invalid transaction identifier value"; break;
	case 87: str = "User not member of CUG"; break;
	case 88: str = "Incompatible destination"; break;
	case 91: str = "Invalid transit network selection"; break;
	case 95: str = "Semantically incorrect message"; break;
	case 96: str = "Invalid mandatory information"; break;
	case 97: str = "Message type non-existent or not implemented"; break;
	case 98: str = "Message type not compatible with protocol state"; break;
	case 99: str = "Information element non-existent or not implemented"; break;
	case 100: str = "Conditional IE error"; break;
	case 101: str = "Message not compatible with protocol state"; break;
	case 102: str = "Recovery on timer expiry"; break;
	case 111: str = "Protocol error, unspecified"; break;
	case 127: str = "Interworking, unspecified"; break;
	default:
	if (cause <= 31) { str = "Treat as Normal, unspecified"; }
	else if ((cause >= 32) && (cause <= 47)) { str = "Treat as Resources unavailable, unspecified"; }
	else if ((cause >= 48) && (cause <= 63)) { str = "Treat as Service or option not available, unspecified"; }
	else if ((cause >= 64) && (cause <= 79)) { str = "Treat as Service or option not implemented, unspecified"; }
	else if ((cause >= 80) && (cause <= 95)) { str = "Treat as Semantically incorrect message"; }
	else if ((cause >= 96) && (cause <= 111)) { str = "Treat as Protocol error, unspecified"; }
	else if ((cause >= 112) && (cause <= 127)) { str = "Treat as Interworking, unspecified"; }
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	proto_tree_add_uint_format(tree, hf_gsm_a_dtap_cause,
	tvb, curr_offset, 1, cause,
	"%s :  Cause: (%u) %s",
	a_bigbuf,
	cause,
	str);

	curr_offset++;

	if (add_string)
	g_snprintf(add_string, string_len, " - (%u) %s", cause, str);

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Diagnostics");

	curr_offset += len - (curr_offset - offset);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * 10.5.4.18 Low layer compatibility
 */
static guint8
de_llc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	dissect_q931_bearer_capability_ie(tvb, offset, len, tree);

	curr_offset = curr_offset + len;
	return(curr_offset - offset);
}

/*
 * [6] 3.6
 */


static guint8
de_facility(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint fac_len, gchar *add_string _U_, int string_len _U_)
{
	guint	saved_offset;
	gint8 class;
	gboolean pc;
	gboolean ind = FALSE;
	guint32 component_len = 0;
	guint32 header_end_offset;
	guint32 header_len;
	asn1_ctx_t asn1_ctx;
	tvbuff_t *SS_tvb = NULL;
	void *save_private_data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, g_pinfo);


	save_private_data= g_pinfo->private_data;
	saved_offset = offset;
	g_pinfo->private_data = NULL;
	while ( fac_len > (offset - saved_offset)){

		/* Get the length of the component there can be more tnan one component in a facility message */

		header_end_offset = get_ber_identifier(tvb, offset, &class, &pc, &comp_type_tag);
		header_end_offset = get_ber_length(tvb, header_end_offset, &component_len, &ind);
		if (ind){
			proto_tree_add_text(tree, tvb, offset+1, 1,
				"Indefinte length, ignoring component");
			return (fac_len);
		}
		header_len = header_end_offset - offset;
		component_len = header_len + component_len;
		/*
		dissect_ROS_Component(FALSE, tvb, offset, &asn1_ctx, tree, hf_ROS_component);
		TODO Call gsm map here
		*/
	    SS_tvb = tvb_new_subset(tvb, offset, component_len, component_len);
		call_dissector(gsm_map_handle, SS_tvb, g_pinfo, tree);
		offset = offset + component_len;
	}
	g_pinfo->private_data = save_private_data;
	return(fac_len);


}

/*
 * [3] 10.5.4.17
 */
static guint8
de_keypad_facility(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Keypad information: %c",
	a_bigbuf,
	oct & 0x7f);

	curr_offset++;

	if (add_string)
	g_snprintf(add_string, string_len, " - %c", oct & 0x7f);

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.21
 */
static guint8
de_prog_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension: %s",
	a_bigbuf,
	(oct & 0x80) ? "extended" : "not extended");

	switch ((oct & 0x60) >> 5)
	{
	case 0: str = "Coding as specified in ITU-T Rec. Q.931"; break;
	case 1: str = "Reserved for other international standards"; break;
	case 2: str = "National standard"; break;
	default:
	str = "Standard defined for the GSM PLMNS";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Coding standard: %s",
	a_bigbuf,
	str);

	other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch (oct & 0x0f)
	{
	case 0: str = "User"; break;
	case 1: str = "Private network serving the local user"; break;
	case 2: str = "Public network serving the local user"; break;
	case 4: str = "Public network serving the remote user"; break;
	case 5: str = "Private network serving the remote user"; break;
	case 10: str = "Network beyond interworking point"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Location: %s",
	a_bigbuf,
	str);

	curr_offset++;

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension: %s",
	a_bigbuf,
	(oct & 0x80) ? "extended" : "not extended");

	switch (oct & 0x7f)
	{
	case 1: str = "Call is not end-to-end PLMN/ISDN, further call progress information may be available in-band"; break;
	case 2: str = "Destination address in non-PLMN/ISDN"; break;
	case 3: str = "Origination address in non-PLMN/ISDN"; break;
	case 4: str = "Call has returned to the PLMN/ISDN"; break;
	case 8: str = "In-band information or appropriate pattern now available"; break;
	case 32: str = "Call is end-to-end PLMN/ISDN"; break;
	case 64: str = "Queueing"; break;
	default:
	str = "Unspecific";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Progress Description: %s (%d)",
	a_bigbuf,
	str,
	oct & 0x7f);

	if (add_string)
	g_snprintf(add_string, string_len, " - %d", oct & 0x7f);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [3] 10.5.4.22
 */
static guint8
de_repeat_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct & 0x0f)
	{
	case 1: str = "Circular for successive selection 'mode 1 alternate mode 2'"; break;
	case 2: str = "Support of fallback  mode 1 preferred, mode 2 selected if setup of mode 1 fails"; break;
	case 3: str = "Reserved: was allocated in earlier phases of the protocol"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  %s",
	a_bigbuf,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [6] 3.7.2
 */
static guint8
de_ss_ver_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
	case 0: str = "Phase 2 service, ellipsis notation, and phase 2 error handling is supported"; break;
	case 1: str = "SS-Protocol version 3 is supported, and phase 2 error handling is supported"; break;
	default:
	str = "Reserved";
	break;
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s",
	str);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [5] 8.1.4.1 3GPP TS 24.011 version 6.1.0 Release 6
 */
static guint8
de_cp_user_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	tvbuff_t	*rp_tvb;

	curr_offset = offset;

	proto_tree_add_text(tree, tvb, curr_offset, len,
	"RPDU (not displayed)");

	/*
	 * dissect the embedded RP message
	 */
	rp_tvb = tvb_new_subset(tvb, curr_offset, len, len);

	call_dissector(rp_handle, rp_tvb, g_pinfo, g_tree);

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [5] 8.1.4.2
 */
static guint8
de_cp_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
	case 17: str = "Network failure"; break;
	case 22: str = "Congestion"; break;
	case 81: str = "Invalid Transaction Identifier value"; break;
	case 95: str = "Semantically incorrect message"; break;
	case 96: str = "Invalid mandatory information"; break;
	case 97: str = "Message type non-existent or not implemented"; break;
	case 98: str = "Message not compatible with the short message protocol state"; break;
	case 99: str = "Information element non-existent or not implemented"; break;
	case 111: str = "Protocol error, unspecified"; break;
	default:
	str = "Reserved, treat as Protocol error, unspecified";
	break;
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Cause: (%u) %s",
	oct,
	str);

	curr_offset++;

	if (add_string)
	g_snprintf(add_string, string_len, " - (%u) %s", oct, str);

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.1
 */
static guint8
de_gmm_attach_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1: str="GPRS only attached"; break;
		case 3: str="Combined GPRS/IMSI attached";	break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Attach Result: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.2
 */
static guint8
de_gmm_attach_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint8      oct_ciph;
	guint32	curr_offset;
	const gchar	*str_follow;
	const gchar	*str_attach;
	proto_item  *tf = NULL;
	proto_tree      *tf_tree = NULL;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct_ciph = oct>>4;

	oct &= 0x0f;

	switch(oct&7)
	{
		case 1: str_attach="GPRS attach"; break;
		case 2: str_attach="GPRS attach while IMSI attached"; break;
		case 3: str_attach="Combined GPRS/IMSI attach"; break;
		default: str_attach="reserved";
	}
	switch(oct&8)
	{
		case 8: str_follow="Follow-on request pending"; break;
		default: str_follow="No follow-on request pending";
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Attach Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_attach_type );

	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Type: (%u) %s",
	oct&7,
	str_attach);
	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Follow: (%u) %s",
	(oct>>3)&1,
	str_follow);

	/* The ciphering key sequence number is added here */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Ciphering key sequence number: 0x%02x (%u)",
	oct_ciph,
	oct_ciph);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.3
 */
static guint8
de_gmm_ciph_alg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 0: str="ciphering not used"; break;
		case 1: str="GPRS Encryption Algorithm GEA/1"; break;
		case 2: str="GPRS Encryption Algorithm GEA/2"; break;
		case 3: str="GPRS Encryption Algorithm GEA/3"; break;
		case 4: str="GPRS Encryption Algorithm GEA/4"; break;
		case 5: str="GPRS Encryption Algorithm GEA/5"; break;
		case 6: str="GPRS Encryption Algorithm GEA/6"; break;
		case 7: str="GPRS Encryption Algorithm GEA/7"; break;
		default: str="This should never happen";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Ciphering Algorithm: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.4
 */
static guint8
de_gmm_tmsi_stat(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&1)
	{
		case 0: str="no valid TMSI available"; break;
		case 1: str="valid TMSI available"; break;
		default: str="This should never happen";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"TMSI Status: (%u) %s",
	oct&1,
	str);

	/* curr_offset++;  - It is encoded in the octed before */

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.5
 */
static guint8
de_gmm_detach_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;
	const gchar *str_power;
	proto_item  *tf = NULL;
	proto_tree      *tf_tree = NULL;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1: str="GPRS detach/re-attach required"; break;
		case 2: str="IMSI detach/re-attach not required"; break;
		case 3: str="Combined GPRS/IMSI detach/IMSI detach (after VLR failure)"; break;
		default: str="Combined GPRS/IMSI detach/re-attach not required";
	}

	switch(oct&8)
	{
		case 8: str_power="power switched off"; break;
		default: str_power="normal detach"; break;
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Detach Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_detach_type );

	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Type: (%u) %s",
	oct&7,
	str);

	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Power: (%u) %s",
	(oct>>3)&1,
	str_power);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.6
 *
 * SPLIT on CCCH, octet 3 (bit 4)
 * 0 Split pg cycle on CCCH is not supported by the mobile station
 * 1 Split pg cycle on CCCH is supported by the mobile station
 */
static const true_false_string gsm_a_gmm_split_on_ccch_value  = {
  "Split pg cycle on CCCH is supported by the mobile station",
  "Split pg cycle on CCCH is not supported by the mobile station"
};

/* non-DRX timer, octet 3
 * bit
 * 3 2 1
 */
static const value_string gsm_a_gmm_non_drx_timer_strings[] = {
	{ 0x00,	"no non-DRX mode after transfer state" },
	{ 0x01,	"max. 1 sec non-DRX mode after transfer state" },
	{ 0x02,	"max. 2 sec non-DRX mode after transfer state" },
	{ 0x03,	"max. 4 sec non-DRX mode after transfer state" },
	{ 0x04,	"max. 8 sec non-DRX mode after transfer state" },
	{ 0x05,	"max. 16 sec non-DRX mode after transfer state" },
	{ 0x06,	"max. 32 sec non-DRX mode after transfer state" },
	{ 0x07,	"max. 64 sec non-DRX mode after transfer state" },
	{ 0, NULL },
};
/*
 * CN Specific DRX cycle length coefficient, octet 3
 * bit
 * 8 7 6 5 Iu mode specific
 * 0 0 0 0 CN Specific DRX cycle length coefficient not specified by the MS, ie. the
 * system information value 'CN domain specific DRX cycle length' is used.
 * (Ref 3GPP TS 25.331)
 * 0 1 1 0 CN Specific DRX cycle length coefficient 6
 * 0 1 1 1 CN Specific DRX cycle length coefficient 7
 * 1 0 0 0 CN Specific DRX cycle length coefficient 8
 * 1 0 0 1 CN Specific DRX cycle length coefficient 9
 * All other values shall be interpreted as "CN Specific DRX cycle length coefficient not
 * specified by the MS " by this version of the protocol.
 * NOTE: In Iu mode this field (octet 3 bits 8 to 5) is used, but was spare in earlier
 * versions of this protocol.
 */
static const value_string gsm_a_gmm_cn_spec_drs_cycle_len_coef_strings[] = {
	{ 0x00,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x01,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x02,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x03,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x04,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x05,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x06,	"CN Specific DRX cycle length coefficient 6" },
	{ 0x07,	"CN Specific DRX cycle length coefficient 7" },
	{ 0x08,	"CN Specific DRX cycle length coefficient 8" },
	{ 0x09,	"CN Specific DRX cycle length coefficient 9" },
	{ 0x0a,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0b,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0c,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0d,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0e,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0f,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0, NULL },
};
guint8
de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;
	gchar	str_val[3];
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;

	len = len;
	curr_offset = offset;

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 2,
		"DRX Parameter");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_drx );

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct)
	{
		case 0: str="704"; break;
		case 65: str="71"; break;
		case 66: str="72"; break;
		case 67: str="74"; break;
		case 68: str="75"; break;
		case 69: str="77"; break;
		case 70: str="79"; break;
		case 71: str="80"; break;
		case 72: str="83"; break;
		case 73: str="86"; break;
		case 74: str="88"; break;
		case 75: str="90"; break;
		case 76: str="92"; break;
		case 77: str="96"; break;
		case 78: str="101"; break;
		case 79: str="103"; break;
		case 80: str="107"; break;
		case 81: str="112"; break;
		case 82: str="116"; break;
		case 83: str="118"; break;
		case 84: str="128"; break;
		case 85: str="141"; break;
		case 86: str="144"; break;
		case 87: str="150"; break;
		case 88: str="160"; break;
		case 89: str="171"; break;
		case 90: str="176"; break;
		case 91: str="192"; break;
		case 92: str="214"; break;
		case 93: str="224"; break;
		case 94: str="235"; break;
		case 95: str="256"; break;
		case 96: str="288"; break;
		case 97: str="320"; break;
		case 98: str="352"; break;
	default:
		str_val[0]=oct/10+'0';
		str_val[1]=oct%10+'0';
		str_val[2]=0;
		str=str_val;
	}

	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Split PG Cycle Code: (%u) %s",
	oct,
	str);

	curr_offset++;
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_split_on_ccch, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_non_drx_timer, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.7
 */
static guint8
de_gmm_ftostby(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1: str="Force to standby indicated"; break;
		default: str="force to standby not indicated";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Force to Standby: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.7
 */
static guint8
de_gmm_ftostby_h(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch(oct&7)
	{
		case 1: str="Force to standby indicated"; break;
		default: str="force to standby not indicated";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Force to Standby: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.8
 */
static guint8
de_gmm_ptmsi_sig(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	proto_item 	*curr_item;
	curr_offset = offset;
	curr_item= proto_tree_add_item(tree,hf_gsm_a_ptmsi_sig,tvb,curr_offset,3,FALSE);
	proto_item_append_text(curr_item,"%s",add_string ? add_string : "");

	curr_offset+=3;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.8a
 */
static guint8
de_gmm_ptmsi_sig2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint32	curr_offset;
	proto_item	*curr_item;
	curr_offset = offset;

	curr_item= proto_tree_add_item(tree,hf_gsm_a_ptmsi_sig2,tvb,curr_offset,3,FALSE);
	proto_item_append_text(curr_item,"%s",add_string ? add_string : "");
	curr_offset+=3;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.9
 */
static guint8
de_gmm_ident_type2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&7 )
	{
		case 2: str="IMEI"; break;
		case 3: str="IMEISV"; break;
		case 4: str="TMSI"; break;
	default: str="IMSI";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Identity Type 2: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.10
 */
static guint8
de_gmm_imeisv_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch ( oct&7 )
	{
		case 1: str="IMEISV requested"; break;
	default: str="IMEISV not requested";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"IMEISV Request: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.11
 */
static guint8
de_gmm_rec_npdu_lst(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_len = len;
	curr_offset = offset;

	if ( len == 0 ) return 0;

	do
	{
	    guint32	oct;
	    oct = tvb_get_guint8(tvb, curr_offset);
	    oct <<=8;
	    oct |= tvb_get_guint8(tvb, curr_offset+1);
	    curr_len -= 2;
	    oct <<=8;

	    proto_tree_add_text(tree,
		tvb, curr_offset, 2,
		"NSAPI %d: 0x%02x (%u)",
		oct>>20,
		(oct>>12)&0xff,
		(oct>>12)&0xff);
	    curr_offset+= 2;

	    if ( curr_len > 2 )
	    {
		    oct |= tvb_get_guint8(tvb, curr_offset+2);
		    curr_len--;
		    oct <<= 12;

		    proto_tree_add_text(tree,
			tvb, curr_offset-1, 2,
			"NSAPI %d: 0x%02x (%u)",
			oct>>20,
			(oct>>12)&0xff,
			(oct>>12)&0xff);
		    curr_offset++;
	    }


	} while ( curr_len > 1 );

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.12
 */
guint8
de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	guint	curr_len;
	guint	gea_val;

	gchar answer_gea[2][40]={ "encryption algorithm not available",
				"encryption algorithm available" };
	gchar answer_smdch[2][120]={ "Mobile station does not support mobile terminated point to point SMS via dedicated signalling channels",
				"Mobile station supports mobile terminated point to point SMS via dedicated signalling channels" };
	gchar answer_smgprs[2][100]={ "Mobile station does not support mobile terminated point to point SMS via GPRS packet data channels",
				"Mobile station supports mobile terminated point to point SMS via GPRS packet data channels" };
	gchar answer_ucs2[2][100]={ "the ME has a preference for the default alphabet (defined in 3GPP TS 23.038 [8b]) over UCS2",
				"the ME has no preference between the use of the default alphabet and the use of UCS2" };

	gchar answer_ssid[4][80]={ "default value of phase 1",
				"capability of handling of ellipsis notation and phase 2 error handling",
				"capability of handling of ellipsis notation and phase 2 error handling",
				"capability of handling of ellipsis notation and phase 2 error handling" };

	gchar answer_solsa[2][40]={ "The ME does not support SoLSA",
				"The ME supports SoLSA" };
			
	gchar answer_rev[2][80]={ "used by a mobile station not supporting R99 or later versions of the protocol",
				"used by a mobile station supporting R99 or later versions of the protocol" };

	gchar answer_pfc[2][80]={ "Mobile station does not support BSS packet flow procedures",
				"Mobile station does support BSS packet flow procedures" };

	gchar answer_lcs[2][80]={ "LCS value added location request notification capability not supported" ,
				"LCS value added location request notification capability supported" };

	curr_len = len;
	curr_offset = offset;

	if ( curr_len == 0 ){ EXTRANEOUS_DATA_CHECK(len, curr_offset - offset); return(curr_offset - offset); }
	oct = tvb_get_guint8(tvb, curr_offset);
	curr_len--;

	/* bit 8 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"GEA1: (%u) %s",
	oct>>7,
	answer_gea[oct>>7]);
	oct<<=1;

	/* bit 7 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"SM capabilities via dedicated channels: (%u) %s",
	oct>>7,
	answer_smdch[oct>>7]);
	oct<<=1;

	/* bit 6 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"SM capabilities via GPRS channels: (%u) %s",
	oct>>7,
	answer_smgprs[oct>>7]);
	oct<<=1;

	/* bit 5 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"UCS2 support: (%u) %s",
	oct>>7,
	answer_ucs2[oct>>7]);
	oct<<=1;

	/* bit 4 3 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"SS Screening Indicator: (%u) %s",
	oct>>6,
	answer_ssid[oct>>6]);
	oct<<=2;

	/* bit 2 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"SoLSA Capability: (%u) %s",
	oct>>7,
	answer_solsa[oct>>7]);
	oct<<=1;

	/* bit 1 */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Revision level indicator: (%u) %s",
	oct>>7,
	answer_rev[oct>>7]);

	curr_offset++;

	if ( curr_len == 0 ){ EXTRANEOUS_DATA_CHECK(len, curr_offset - offset); return(curr_offset - offset); }
	oct = tvb_get_guint8(tvb, curr_offset);
	curr_len--;

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"PFC feature mode: (%u) %s",
	oct>>7,
	answer_pfc[oct>>7]);
	oct<<=1;

	for( gea_val=2; gea_val<8 ; gea_val++ )
	{
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GEA%d: (%u) %s", gea_val,
		oct>>7,
		answer_gea[oct>>7]);
	    oct<<=1;
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"LCS VA capability:: (%u) %s",
	oct>>7,
	answer_lcs[oct>>7]);

	curr_offset++;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.12a
 */
#define GET_DATA				/* check if we have enough bits left */ \
		if ( curr_bits_length < bits_needed ) \
			continue; \
		/* check if oct has enougth bits */ \
		if ( bits_in_oct < bits_needed ) \
		{ \
			guint32 tmp_oct; \
			if ( curr_len == 0 ) \
			{ \
				proto_tree_add_text(tf_tree, \
				tvb, curr_offset, 1, \
				"Not enough data available"); \
			} \
			tmp_oct = tvb_get_guint8(tvb, curr_offset); \
			oct |= tmp_oct<<(32-8-bits_in_oct); \
			curr_len--; \
			curr_offset++; \
			if ( bits_in_oct != 0 ) \
				add_ocetets = 1; \
			else \
				add_ocetets = 0; \
			bits_in_oct += 8; \
		} \
		else \
			add_ocetets = 0;

guint8
de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	proto_item  *tf = NULL;
	proto_tree      *tf_tree = NULL;
	guint32     oct;
	guchar      bits_in_oct;
	guchar      bits_needed;
	guint       bits_length;
	guint       add_ocetets;	/* octets which are covered by one element -1 */
	guint       curr_bits_length;
	guchar	acc_type;
	const gchar	*str;
	gchar       multi_slot_str[64][230] = {
		"Not specified", /* 00 */
		"Max Rx-Slot/TDMA:1 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:2 Tta:3 Ttb:2 Tra:4 Trb:2 Type:1", /* 01 */
		"Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1", /* 02 */
		"Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1", /* 03 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 04 */
		"Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 05 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 06 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 07 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 08 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 09 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 10 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 11 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1", /* 12 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 13 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 14 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 15 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:2 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 16 */
		"Max Rx-Slot/TDMA:7 Max Tx-Slot/TDMA:7 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:1 Trb:0 Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 17 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:8 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:0 Tra:0 Trb:0 Type:2", /* 18 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 19 */   
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 20 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 21 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 22 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 23 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 24 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 25 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 26 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 27 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 28 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:8 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 29 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 30 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 31 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 32 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 33 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 34 */
	   	"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 35 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 36 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 37 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 38 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 39 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 40 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 41 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 42 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 43 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 44 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 45 */
		"Not specified", /* 46 */
		"Not specified", /* 47 */
		"Not specified", /* 48 */
		"Not specified", /* 49 */
		"Not specified", /* 50 */
		"Not specified", /* 51 */
		"Not specified", /* 52 */
		"Not specified", /* 53 */
		"Not specified", /* 54 */
		"Not specified", /* 55 */
		"Not specified", /* 56 */
		"Not specified", /* 57 */
		"Not specified", /* 58 */
		"Not specified", /* 59 */
		"Not specified", /* 60 */
		"Not specified", /* 61 */
		"Not specified", /* 62 */
		"Not specified", /* 63 */
	};
    guint indx = 0;
	guchar dtm_gprs_mslot = 0;
	guchar dtm_egprs_mslot = 4;
	gboolean finished = TRUE;

	curr_len = len;
	curr_offset = offset;

	bits_in_oct = 0;
	oct = 0;

	do
	{
	/* check for a new round */
	if (( curr_len*8 + bits_in_oct ) < 11 )
		break;

	/* now read the first 11 bits */
		curr_bits_length = 11;
	/*
	 *
	 */
	if ( curr_len != len )
	{
		bits_needed = 1;
		GET_DATA;

		if (( oct>>(32-bits_needed) ) == 1 )
		{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
	    	
	    		if (( curr_len*8 + bits_in_oct ) < 11 )
	    			break;
	    		curr_bits_length = 11;
		}
		else
		{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
	    		break;
		}
	}

	indx++;
	tf = proto_tree_add_text(tree,
			tvb, curr_offset, 1,
	    	"MS RA capability %d",indx);

	tf_tree = proto_item_add_subtree(tf, ett_gmm_radio_cap );

	/*
	 * Access Technology
	 */
	bits_needed = 4;
	GET_DATA;

	acc_type = oct>>(32-bits_needed);
	switch ( acc_type )
	{
	    	case 0x00: str="GSM P"; break;
			case 0x01: str="GSM E --note that GSM E covers GSM P"; break;
   	 	case 0x02: str="GSM R --note that GSM R covers GSM E and GSM P"; break;
			case 0x03: str="GSM 1800"; break;
			case 0x04: str="GSM 1900"; break;
			case 0x05: str="GSM 450"; break;
			case 0x06: str="GSM 480"; break;
			case 0x07: str="GSM 850"; break;
			case 0x08: str="GSM 700"; break;
			case 0x0f: str="Indicates the presence of a list of Additional access technologies"; break;
   	 	default: str="unknown";
   	 }

	proto_tree_add_text(tf_tree,
	    	tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Access Technology Type: (%u) %s",acc_type,str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

	/*
	 * get bits_length
	 */
	bits_needed = 7;
	GET_DATA;

	bits_length = curr_bits_length = oct>>(32-bits_needed);
	proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Length: 0x%02x bits (%u)",bits_length,bits_length);
		/* This is already done - length doesn't contain this field
		 curr_bits_length -= bits_needed;
		*/
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

	if ( acc_type == 0x0f )
	{
		do
		{
		/*
		 * Additional access technologies:
		 */
			finished = TRUE; /* Break out of the loop unless proven unfinished */

			/*
			 * Presence bit
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="Not Present"; finished = TRUE; break;
				case 0x01: str="Present"; finished = FALSE; break;
				default: str="This should not happen";
			}

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Presence: (%u) %s",oct>>(32-bits_needed),str);
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			if (finished)
			{
				/*
				 * No more valid data, get spare bits if any
				 */
				while ( curr_bits_length > 0 )
				{
					if ( curr_bits_length > 8 )
						bits_needed = 8;
					else
						bits_needed = curr_bits_length;
					GET_DATA;
					curr_bits_length -= bits_needed;
					oct <<= bits_needed;
					bits_in_oct -= bits_needed;
				}
				continue;
			}

		/*
		 * Access Technology
		 */
		bits_needed = 4;
		GET_DATA;

		acc_type = oct>>(32-bits_needed);
		switch ( acc_type )
		{
		    	case 0x00: str="GSM P"; break;
				case 0x01: str="GSM E --note that GSM E covers GSM P"; break;
	   	 	case 0x02: str="GSM R --note that GSM R covers GSM E and GSM P"; break;
				case 0x03: str="GSM 1800"; break;
				case 0x04: str="GSM 1900"; break;
	    		case 0x05: str="GSM 450"; break;
				case 0x06: str="GSM 480"; break;
				case 0x07: str="GSM 850"; break;
	    		case 0x08: str="GSM 700"; break;
				case 0x0f: str="Indicates the presence of a list of Additional access technologies"; break;
   	 		default: str="unknown";
	   	 }

		proto_tree_add_text(tf_tree,
	    		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
	    		"Access Technology Type: (%u) %s",acc_type,str);
			curr_bits_length -= bits_needed;
	    	oct <<= bits_needed;
			bits_in_oct -= bits_needed;

	    	/*
			 * RF Power
	    	 */
	    	bits_needed = 3;
		GET_DATA;

		/* analyse bits */
		if ( acc_type == 0x04 )	/* GSM 1900 */
		{
				switch ( oct>>(32-bits_needed) )
	    		{
					case 0x01: str="1 W (30 dBm)"; break;
	    			case 0x02: str="0,25 W (24 dBm)"; break;
		    		case 0x03: str="2 W (33 dBm)"; break;
					default: str="Not specified";
	    		}
			}
	    	else if ( acc_type == 0x03 )
			{
				switch ( oct>>(32-bits_needed) )
	 	   	{
					case 0x01: str="1 W (30 dBm)"; break;
					case 0x02: str="0,25 W (24 dBm)"; break;
					case 0x03: str="4 W (36 dBm)"; break;
	    			default: str="Not specified";
				}
	    	}
		else if ( acc_type <= 0x08 )
	    	{
				switch ( oct>>(32-bits_needed) )
				{
					case 0x02: str="8 W (39 dBm)"; break;
	    			case 0x03: str="5 W (37 dBm)"; break;
					case 0x04: str="2 W (33 dBm)"; break;
					case 0x05: str="0,8 W (29 dBm)"; break;
					default: str="Not specified";
	    		}
			}
	    	else
				str="Not specified??";

	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"RF Power Capability, GMSK Power Class: (%u) %s",oct>>(32-bits_needed),str);
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
	    	bits_in_oct -= bits_needed;

	    	/*
			 * 8PSK Power Class
	    	 */
			bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
			{
			case 0x00: str="8PSK modulation not supported for uplink"; break;
			case 0x01: str="Power class E1"; break;
			case 0x02: str="Power class E2"; break;
			case 0x03: str="Power class E3"; break;
			default: str="This should not happen";
	    	}

			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"8PSK Power Class: (%u) %s",oct>>(32-bits_needed),str);
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

		} while (!finished);
	
		/* goto next one */
		continue;
	}
		/*
		 * RF Power
		 */
		bits_needed = 3;
	GET_DATA;

	/* analyse bits */
	if ( acc_type == 0x04 )	/* GSM 1900 */
	{
			switch ( oct>>(32-bits_needed) )
	    	{
				case 0x01: str="1 W (30 dBm)"; break;
				case 0x02: str="0,25 W (24 dBm)"; break;
	    		case 0x03: str="2 W (33 dBm)"; break;
				default: str="Not specified";
			}
		}
		else if ( acc_type == 0x03 )
		{
			switch ( oct>>(32-bits_needed) )
 	   	{
				case 0x01: str="1 W (30 dBm)"; break;
				case 0x02: str="0,25 W (24 dBm)"; break;
				case 0x03: str="4 W (36 dBm)"; break;
				default: str="Not specified";
			}
		}
	else if ( acc_type <= 0x08 )
		{
			switch ( oct>>(32-bits_needed) )
			{
				case 0x02: str="8 W (39 dBm)"; break;
				case 0x03: str="5 W (37 dBm)"; break;
				case 0x04: str="2 W (33 dBm)"; break;
				case 0x05: str="0,8 W (29 dBm)"; break;
				default: str="Not specified";
			}
		}
		else
			str="Not specified??";

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"RF Power Capability, GMSK Power Class: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * A5 Bits?
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"A5 Bits: (%u) same values apply for parameters as in the immediately preceding Access capabilities field within this IE",oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;
		}
		else
		{
			int i;

	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"A5 Bits: (%u) A5 bits follows",oct>>(32-bits_needed));

	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		
			for (i=1; i<= 7 ; i++ )
			{
		    	/*
		    	 * A5 Bits decoding
		    	 */
		    	bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
		    	{
				case 0x00: str="encryption algorithm not available"; break;
				case 0x01: str="encryption algorithm available"; break;
				default: str="This should not happen";
		    	}

		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"A5/%d: (%u) %s",i,oct>>(32-bits_needed),str);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
			}
	}

		/*
		 * ES IND
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="controlled early Classmark Sending option is not implemented"; break;
		case 0x01: str="controlled early Classmark Sending option is implemented"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Controlled early Classmark Sending: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * PS
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="PS capability not present"; break;
		case 0x01: str="PS capability present"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Pseudo Synchronisation: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * VGCS
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="no VGCS capability or no notifications wanted"; break;
		case 0x01: str="VGCS capability and notifications wanted"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Voice Group Call Service: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * VBS
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="no VBS capability or no notifications wanted"; break;
		case 0x01: str="VBS capability and notifications wanted"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Voice Broadcast Service: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Multislot capability?
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Multislot capability: (%u) same values apply for parameters as in the immediately preceding Access capabilities field within this IE",oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;
		}
		else
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Multislot capability: (%u) Multislot capability struct available",oct>>(32-bits_needed));

	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;

	    	/*
			 * HSCSD multislot class?
	    	 */
	    	bits_needed = 1;
		GET_DATA;

		/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
	        {
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"HSCSD multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
	    	}
			else
	    	{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;

		    	/*
		    	 * HSCSD multislot class
				 */
		    	bits_needed = 5;
			GET_DATA;

			/* analyse bits */
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"HSCSD multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
		}

	    	/*
			 * GPRS multislot class?
	    	 */
	    	bits_needed = 1;
		GET_DATA;

		/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
	        {
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"GPRS multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
	    	}
			else
	    	{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;

		    	/*
		    	 * GPRS multislot class
				 */
		    	bits_needed = 5;
			GET_DATA;

			/* analyse bits */
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"GPRS multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;

		    	/*
		    	 * GPRS Extended Dynamic Allocation Capability
				 */
		    	bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="Extended Dynamic Allocation Capability for GPRS is not implemented"; break;
				case 0x01: str="Extended Dynamic Allocation Capability for GPRS is implemented"; break;
				default: str="This should not happen";
			}
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"GPRS Extended Dynamic Allocation Capability: (%u) %s",oct>>(32-bits_needed),str);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
		}

		/*
		 * SMS/SM values
		 */
	    	bits_needed = 1;
		GET_DATA;

		/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
	        {
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"SMS/SM values: (%u) Bits are not available",oct>>(32-bits_needed));
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
	    	}
			else
	    	{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;

		    	/*
		    	 * Switch-Measure-Switch value
				 */
		    	bits_needed = 4;
			GET_DATA;

			/* analyse bits */
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Switch-Measure-Switch value: (%u) %d/4 timeslot (~%d microseconds)",
				oct>>(32-bits_needed),oct>>(32-bits_needed),(oct>>(32-bits_needed))*144);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;

		    	/*
		    	 * Switch-Measure value
				 */
		    	bits_needed = 4;
			GET_DATA;

			/* analyse bits */
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Switch-Measure value: (%u) %d/4 timeslot (~%d microseconds)",
				oct>>(32-bits_needed),oct>>(32-bits_needed),(oct>>(32-bits_needed))*144);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
		}

	    	/*
			 * ECSD multislot class?
	    	 */
	    	bits_needed = 1;
		GET_DATA;

		/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
	        {
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"ECSD multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
	    	}
			else
	    	{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;

		    	/*
		    	 * ECSD multislot class
				 */
		    	bits_needed = 5;
			GET_DATA;

			/* analyse bits */
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"ECSD multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
		}

	    	/*
			 * EGPRS multislot class?
	    	 */
	    	bits_needed = 1;
		GET_DATA;

		/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
	        {
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"EGPRS multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
	    	}
			else
	    	{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;

		    	/*
		    	 * EGPRS multislot class
				 */
		    	bits_needed = 5;
			GET_DATA;

			/* analyse bits */
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"EGPRS multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;

		    	/*
		    	 * EGPRS Extended Dynamic Allocation Capability
				 */
		    	bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="Extended Dynamic Allocation Capability for EGPRS is not implemented"; break;
				case 0x01: str="Extended Dynamic Allocation Capability for EGPRS is implemented"; break;
				default: str="This should not happen";
			}
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"EGPRS Extended Dynamic Allocation Capability: (%u) %s",oct>>(32-bits_needed),str);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;
		}

		/*
		 * DTM GPRS Multi Slot Class ?
		*/
	    	bits_needed = 1;
		GET_DATA;

		/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
	        {
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"DTM GPRS Multi Slot Class: (%u) Bits are not available",oct>>(32-bits_needed));
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;
	    	}
			else
	    	{
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 		bits_in_oct -= bits_needed;

		    	/*
		    	 * DTM GPRS Multi Slot Class
				 */
		    	bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			dtm_gprs_mslot = oct>>(32-bits_needed);

			switch ( oct>>(32-bits_needed) )
			{
				case 0: str="Unused. If received, the network shall interpret this as Multislot class 5"; break;
				case 1: str="Multislot class 5 supported"; break;
				case 2: str="Multislot class 9 supported"; break;
				case 3: str="Multislot class 11 supported"; break;
				default: str="This should not happen";
			}
		
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"DTM GPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;

		    	/*
		    	 * Single Slot DTM
				 */
		    	bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="Single Slot DTM not supported"; break;
				case 0x01: str="Single Slot DTM supported"; break;
				default: str="This should not happen";
			}
		    	proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Single Slot DTM: (%u) %s",oct>>(32-bits_needed),str);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
	    		bits_in_oct -= bits_needed;

			/*
			 * DTM EGPRS Multi Slot Class ?
			*/
		    	bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			dtm_egprs_mslot = oct>>(32-bits_needed);

				if ((oct>>(32-bits_needed))==0)
	        	{
		    		proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"DTM EGPRS Multi Slot Class: (%u) Bits are not available",oct>>(32-bits_needed));
			    	curr_bits_length -= bits_needed;
					oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;
	    		}
	    		else
		    	{
			    	curr_bits_length -= bits_needed;
					oct <<= bits_needed;
  	 	 		bits_in_oct -= bits_needed;

			    	/*
			    	 * DTM EGPRS Multi Slot Class
	    			 */
			    	bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0: str="Unused. If received, the network shall interpret this as Multislot class 5"; break;
					case 1: str="Multislot class 5 supported"; break;
					case 2: str="Multislot class 9 supported"; break;
					case 3: str="Multislot class 11 supported"; break;
					default: str="This should not happen";
				}
		
		    		proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"DTM EGPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
			    	curr_bits_length -= bits_needed;
					oct <<= bits_needed;
	    			bits_in_oct -= bits_needed;
			}
		}
	}

		/*
		 * 8PSK Power Capability?
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"8PSK Power Capability: (%u) Bits are not available",oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;
		}
		else
		{
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;

	    	/*
			 * 8PSK Power Capability
	    	 */
			bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
			{
			case 0x00: str="Reserved"; break;
			case 0x01: str="Power class E1"; break;
			case 0x02: str="Power class E2"; break;
			case 0x03: str="Power class E3"; break;
			default: str="This should not happen";
	    	}

			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"8PSK Power Capability: (%u) %s",oct>>(32-bits_needed),str);
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
	}

		/*
		 * COMPACT Interference Measurement Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="COMPACT Interference Measurement Capability is not implemented"; break;
		case 0x01: str="COMPACT Interference Measurement Capability is implemented"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"COMPACT Interference Measurement Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Revision Level Indicator
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="The ME is Release 98 or older"; break;
		case 0x01: str="The ME is Release 99 onwards"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Revision Level Indicator: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS FDD Radio Access Technology Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="UMTS FDD not supported"; break;
		case 0x01: str="UMTS FDD supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"UMTS FDD Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS 3.84 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="UMTS 3.84 Mcps TDD not supported"; break;
		case 0x01: str="UMTS 3.84 Mcps TDD supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"UMTS 3.84 Mcps TDD Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * CDMA 2000 Radio Access Technology Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="CDMA 2000 not supported"; break;
		case 0x01: str="CDMA 2000 supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"CDMA 2000 Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS 1.28 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="UMTS 1.28 Mcps TDD not supported"; break;
		case 0x01: str="UMTS 1.28 Mcps TDD supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"UMTS 1.28 Mcps TDD Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * GERAN Feature Package 1
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="GERAN feature package 1 not supported"; break;
		case 0x01: str="GERAN feature package 1 supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"GERAN Feature Package 1: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Extended DTM (E)GPRS Multi Slot Class
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Extended DTM (E)GPRS Multi Slot Class: (%u) Bits are not available",oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;
		}
		else
		{
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;

	    	/*
			 * Extended DTM GPRS Multi Slot Class
	    	 */
			bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( (oct>>(32-bits_needed))|(dtm_gprs_mslot<<4) )
			{
				case 0x00: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x01: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x02: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x03: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x10: str="Multislot class 5 supported"; break;
				case 0x11: str="Multislot class 6 supported"; break;
				case 0x12: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x13: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x20: str="Multislot class 9 supported"; break;
				case 0x21: str="Multislot class 10 supported"; break;
				case 0x22: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
				case 0x23: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
				case 0x30: str="Multislot class 11 supported"; break;
				case 0x31: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				case 0x32: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				case 0x33: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				default: str="This should not happen";
	    	}

			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Extended DTM GPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

		if ( dtm_egprs_mslot <= 3 )
		{
		    	/*
				 * Extended DTM EGPRS Multi Slot Class
	    		 */
	    		bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( (oct>>(32-bits_needed))|(dtm_egprs_mslot<<4) )
				{
					case 0x00: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x01: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
   	 			case 0x02: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x03: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x10: str="Multislot class 5 supported"; break;
					case 0x11: str="Multislot class 6 supported"; break;
					case 0x12: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x13: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x20: str="Multislot class 9 supported"; break;
					case 0x21: str="Multislot class 10 supported"; break;
					case 0x22: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
					case 0x23: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
					case 0x30: str="Multislot class 11 supported"; break;
					case 0x31: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
   	 			case 0x32: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					case 0x33: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					default: str="This should not happen";
	    		}

	    		proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Extended DTM EGPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
		    	curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
		}
	}

		/*
		 * Modulation based multislot class support
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="Modulation based multislot class not supported"; break;
		case 0x01: str="Modulation based multislot class supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"Modulation based multislot class support: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * High Multislot Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"High Multislot Capability: (%u) Bits are not available",oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;
		}
		else
		{
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;

	    	/*
			 * High Multislot Capability
	    	 */
			bits_needed = 2;
		GET_DATA;

		/* analyse bits */
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"High Multislot Capability: 0x%02x (%u) - This field effect all other multislot fields. To understand the value please read TS 24.008 5.6.0 Release 5 Chap 10.5.5.12 Page 406",oct>>(32-bits_needed),oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

	}

		/*
		 * GERAN Iu Mode Capability
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
	switch ( oct>>(32-bits_needed) )
		{
		case 0x00: str="GERAN Iu mode not supported"; break;
		case 0x01: str="GERAN Iu mode supported"; break;
		default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"GERAN Iu Mode Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * GMSK/8-PSK Multislot Power Profile
		 */
		bits_needed = 1;
	GET_DATA;

	/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
	    	proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"GMSK/8-PSK Multislot Power Profile: (%u) Bits are not available",oct>>(32-bits_needed));
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;
		}
		else
		{
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   	 	bits_in_oct -= bits_needed;

	    	/*
			 * GMSK Multislot Power Profile
	    	 */
			bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="GMSK_MULTISLOT_POWER_PROFILE 0"; break;
			case 0x01: str="GMSK_MULTISLOT_POWER_PROFILE 1"; break;
			case 0x02: str="GMSK_MULTISLOT_POWER_PROFILE 2"; break;
			case 0x03: str="GMSK_MULTISLOT_POWER_PROFILE 3"; break;
			default: str="This should not happen";
		}
	
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"GMSK Multislot Power Profile: (%u) %s",oct>>(32-bits_needed),str);
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

	    	/*
			 * 8-PSK Multislot Power Profile
	    	 */
			bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="8-PSK_MULTISLOT_POWER_PROFILE 0"; break;
			case 0x01: str="8-PSK_MULTISLOT_POWER_PROFILE 1"; break;
			case 0x02: str="8-PSK_MULTISLOT_POWER_PROFILE 2"; break;
			case 0x03: str="8-PSK_MULTISLOT_POWER_PROFILE 3"; break;
			default: str="This should not happen";
		}
	
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"8-PSK Multislot Power Profile: (%u) %s",oct>>(32-bits_needed),str);
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

	}

	/*
	 * we are too long ... so jump over it
	 */
	while ( curr_bits_length > 0 )
	{
		if ( curr_bits_length > 8 )
			bits_needed = 8;
		else
			bits_needed = curr_bits_length;
		GET_DATA;
	    	curr_bits_length -= bits_needed;
			oct <<= bits_needed;
		bits_in_oct -= bits_needed;
	}

	} while ( 1 );

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.14
 */
static guint8
de_gmm_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		/* additional causes can be found in annex g */
		case 0x02: str="IMSI unknown in HLR"; break;
		case 0x03: str="Illegal MS"; break;
		case 0x04: str="IMSI unknown in VLR"; break;
		case 0x05: str="IMEI not accepted"; break;
		case 0x06: str="Illegal ME"; break;
		case 0x07: str="GPRS services not allowed"; break;
		case 0x08: str="GPRS services and non-GPRS services not	allowed"; break;
		case 0x09: str="MS identity cannot be derived by the network"; break;
		case 0x0a: str="Implicitly detached"; break;
		case 0x0b: str="PLMN not allowed"; break;
		case 0x0c: str="Location Area not allowed"; break;
		case 0x0d: str="Roaming not allowed in this location area"; break;
		case 0x0e: str="GPRS services not allowed in this PLMN"; break;
		case 0x0f: str="No Suitable Cells In Location Area"; break;
		case 0x10: str="MSC temporarily not reachable"; break;
		case 0x11: str="Network failure"; break;
		case 0x14: str="MAC failure"; break;
		case 0x15: str="Synch failure"; break;
		case 0x16: str="Congestion"; break;
		case 0x17: str="GSM authentication unacceptable"; break;
		case 0x20: str="Service option not supported"; break;
		case 0x21: str="Requested service option not subscribed"; break;
		case 0x22: str="Service option temporarily out of order"; break;
		case 0x26: str="Call cannot be identified"; break;
		case 0x28: str="No PDP context activated"; break;
		case 0x30: str="retry upon entry into a new cell"; break;
		case 0x31: str="retry upon entry into a new cell"; break;
		case 0x32: str="retry upon entry into a new cell"; break;
		case 0x33: str="retry upon entry into a new cell"; break;
		case 0x34: str="retry upon entry into a new cell"; break;
		case 0x35: str="retry upon entry into a new cell"; break;
		case 0x36: str="retry upon entry into a new cell"; break;
		case 0x37: str="retry upon entry into a new cell"; break;
		case 0x38: str="retry upon entry into a new cell"; break;
		case 0x39: str="retry upon entry into a new cell"; break;
		case 0x3a: str="retry upon entry into a new cell"; break;
		case 0x3b: str="retry upon entry into a new cell"; break;
		case 0x3c: str="retry upon entry into a new cell"; break;
		case 0x3d: str="retry upon entry into a new cell"; break;
		case 0x3e: str="retry upon entry into a new cell"; break;
		case 0x3f: str="retry upon entry into a new cell"; break;
		case 0x5f: str="Semantically incorrect message"; break;
		case 0x60: str="Invalid mandatory information"; break;
		case 0x61: str="Message type non-existent or not implemented"; break;
		case 0x62: str="Message type not compatible with the protocol state"; break;
		case 0x63: str="Information element non-existent or not implemented"; break;
		case 0x64: str="Conditional IE error"; break;
		case 0x65: str="Message not compatible with the protocol state"; break;
		case 0x6f: str="Protocol error, unspecified"; break;
	default: str="Protocol error, unspecified";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"gmm Cause: (%u) %s",
	oct,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.15 Routing area identification
 */
guint8
de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree		*subtree;
    proto_item		*item;

	guint32	mcc;
	guint32	mnc;
	guint32	lac;
	guint32	rac;
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	mcc = (tvb_get_guint8(tvb, curr_offset) & 0x0f) <<8;
	mcc |= (tvb_get_guint8(tvb, curr_offset) & 0xf0);
	mcc |= (tvb_get_guint8(tvb, curr_offset+1) & 0x0f);
	mnc = (tvb_get_guint8(tvb, curr_offset+2) & 0x0f) <<8;
	mnc |= (tvb_get_guint8(tvb, curr_offset+2) & 0xf0);
	mnc |= (tvb_get_guint8(tvb, curr_offset+1) & 0xf0) >>4;
	if ((mnc&0x000f) == 0x000f)
		 mnc = mnc>>4;

	lac = tvb_get_guint8(tvb, curr_offset+3);
	lac <<= 8;
	lac |= tvb_get_guint8(tvb, curr_offset+4);
	rac = tvb_get_guint8(tvb, curr_offset+5);

	item = proto_tree_add_text(tree,
		tvb, curr_offset, 6,
		"Routing area identification: %x-%x-%x-%x",
		mcc,mnc,lac,rac);

	subtree = proto_item_add_subtree(item, ett_gmm_rai);
	dissect_e212_mcc_mnc(tvb, subtree, offset);
	curr_offset+=6;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.17
 */
static guint8
de_gmm_update_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch(oct&7)
	{
		case 0: str="RA updated"; break;
		case 1: str="combined RA/LA updated";	break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Update Result: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.18
 */
static guint8
de_gmm_update_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint8	oct_ciph;
	guint32	curr_offset;
	const gchar	*str_follow;
	const gchar	*str_update;
	proto_item  *tf = NULL;
	proto_tree      *tf_tree = NULL;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct_ciph = oct>>4;

	oct &= 0x0f;

	switch(oct&7)
	{
		case 0: str_update="RA updating"; break;
		case 1: str_update="combined RA/LA updating"; break;
		case 2: str_update="combined RA/LA updating with IMSI attach"; break;
		case 3: str_update="Periodic updating"; break;
		default: str_update="reserved";
	}
	switch(oct&8)
	{
		case 8: str_follow="Follow-on request pending"; break;
		default: str_follow="No follow-on request pending";
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Update Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_update_type );

	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Type: (%u) %s",
	oct&7,
	str_update);
	proto_tree_add_text(tf_tree,
	tvb, curr_offset, 1,
	"Follow: (%u) %s",
	(oct>>3)&1,
	str_follow);

	/* The ciphering key sequence number is added here */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Ciphering key sequence number: 0x%02x (%u)",
	oct_ciph,
	oct_ciph);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.19
 */
static guint8
de_gmm_ac_ref_nr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"A&C reference number: 0x%02x (%u)",
	oct&0xf,
	oct&0xf);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.19
 */
static guint8
de_gmm_ac_ref_nr_h(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"A&C reference number: 0x%02x (%u)",
	oct,
	oct);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [8] 10.5.5.20
 */
static guint8
de_gmm_service_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint8	oct_ciph;
	guint32	curr_offset;
	const gchar *str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct_ciph = oct;
	oct_ciph &= 7;

	oct = oct >> 4;

	switch ( oct&7 )
	{
		case 0: str="Signalling"; break;
		case 1: str="Data"; break;
		case 2: str="Paging Response"; break;
		case 3: str="MBMS Notification Response"; break;/* reponse->response*/
		default: str="reserved";
	}

	/* The ciphering key sequence number is added here */
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Ciphering key sequence number: 0x%02x (%u)",
	oct_ciph,
	oct_ciph);

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Service Type: (%u) %s",
	oct&7,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.21
 */
static guint8
de_gmm_cell_notfi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	proto_tree_add_text(tree,
		tvb, curr_offset, 0,
		"Cell Notification");

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.22
 */
static guint8
de_gmm_ps_lcs_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	gchar	str_otd[2][40]={ "MS assisted E-OTD not supported",
				"MS assisted E-OTD supported" };
	gchar	str_gps[2][40]={ "MS assisted GPS not supported",
				"MS assisted GPS supported" };

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	oct <<=3;   /* move away the spare bits */

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"OTD-A: (%u) %s",
	oct>>7,
	str_otd[oct>>7]);
	oct <<=1;
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"OTD-B: (%u) %s",
	oct>>7,
	str_otd[oct>>7]);
	oct <<=1;

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"GPS-A: (%u) %s",
	oct>>7,
	str_gps[oct>>7]);
	oct <<=1;
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"GPS-B: (%u) %s",
	oct>>7,
	str_gps[oct>>7]);
	oct <<=1;
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"GPS-C: (%u) %s",
	oct>>7,
	str_gps[oct>>7]);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.23
 */
static guint8
de_gmm_net_feat_supp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&8)
	{
		case 8: str="LCS-MOLR via PS domain not supported"; break;
		default: str="LCS-MOLR via PS domain supported";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Network Feature Support: (%u) %s",
	(oct>>3)&1,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/* [7] 10.5.24 Inter RAT information container */
static guint8
de_gmm_rat_info_container(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

/* The value part of the Inter RAT information container information element is the INTER RAT HANDOVER INFO as
defined in 3GPP TS 25.331 [23c]. If this field includes padding bits, they are defined in 3GPP TS 25.331 [23c].*/
	proto_tree_add_text(tree, tvb, curr_offset, len,"INTER RAT HANDOVER INFO - Not decoded");

	return len;

}

/*
 * [7] 10.5.7.1
 */
static guint8
de_gc_context_stat(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint16	pdp_nr;
	guint32	curr_offset;
	proto_item  *tf = NULL;
	proto_tree      *tf_tree = NULL;

	gchar 	str[2][20]={ "PDP-INACTIVE", "PDP-ACTIVE" };

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PDP Context Status");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_context_stat );

	oct = tvb_get_guint8(tvb, curr_offset);

	for ( pdp_nr=0;pdp_nr<16; pdp_nr++ )
	{
			if ( pdp_nr == 8 )
			{
				curr_offset++;
				oct = tvb_get_guint8(tvb, curr_offset);
			}
	    proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"NSAPI %d: (%u) %s",pdp_nr,
		oct&1,
		str[oct&1]);
	    oct>>=1;
	}

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.2
 */
static guint8
de_gc_radio_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&7 )
	{
		case 1: str="priority level 1 (highest)"; break;
		case 2: str="priority level 2"; break;
		case 3: str="priority level 3"; break;
		case 4: str="priority level 4 (lowest)"; break;
		default: str="priority level 4 (lowest)";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Radio Priority (PDP or SMS): (%u) %s",
	oct&7,
	str);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.3
 */
static guint8
de_gc_timer(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint16	val;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch(oct>>5)
	{
		case 0: str="sec"; val*=2; break;
		case 1: str="min"; break;
		case 2: str="min"; val*=6; break;
		case 7:
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPRS Timer: timer is deactivated");

		default: str="min";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"GPRS Timer: (%u) %u %s",
	oct, val,
	str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.4
 */
static guint8
de_gc_timer2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint16	val;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch(oct>>5)
	{
		case 0: str="sec"; val*=2; break;
		case 1: str="min"; break;
		case 2: str="min"; val*=6; break;
		case 7:
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPRS Timer: timer is deactivated");

		default: str="min";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"GPRS Timer: (%u) %u %s %s",
	oct, val,
	str, add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}


/*
 * [7] 10.5.7.5
 */
static guint8
de_gc_radio_prio2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch ( oct&7 )
	{
		case 1: str="priority level 1 (highest)"; break;
		case 2: str="priority level 2"; break;
		case 3: str="priority level 3"; break;
		case 4: str="priority level 4 (lowest)"; break;
		default: str="priority level 4 (lowest)";
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Radio Priority (TOM8): (%u) %s",
	oct&7,
	str);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [8] 10.5.7.6 MBMS context status
 */
static guint8
de_gc_mbms_context_stat(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len,	"MBMS context status - Not decoded");

	return(len);
}
/*
 * [7] 10.5.6.1
 */
#define MAX_APN_LENGTH		50

guint8
de_sm_apn(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint32	curr_offset;
	guint       curr_len;
	const guint8	*cptr;
	guint8      str[MAX_APN_LENGTH+1];

	cptr = tvb_get_ptr(tvb, offset, len);


	curr_offset = offset;

	/* init buffer and copy it */
	memset ( str , 0 , MAX_APN_LENGTH );
	memcpy ( str , cptr , len<MAX_APN_LENGTH?len:MAX_APN_LENGTH );

	curr_len = 0;
	while (( curr_len < len ) && ( curr_len < MAX_APN_LENGTH ))
	{
		guint step = str[curr_len];
		str[curr_len]='.';
		curr_len += step+1;
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, len,
		"APN: %s %s", str+1 , add_string ? add_string : "");

	curr_offset+= len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.2
 */
static guint8
de_sm_nsapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"NSAPI: 0x%02x (%u) %s",
	oct&0x0f, oct&0x0f,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.3
 */
static guint8
de_sm_pco(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guchar	oct;
	struct e_in6_addr ipv6_addr;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	curr_len--;
	curr_offset++;

	proto_tree_add_text(tree,tvb, curr_offset, 1, "Ext: 0x%02x (%u)",oct>>7,oct>>7);
	proto_tree_add_text(tree,tvb, curr_offset, 1, "Configuration Protocol: PPP (%u)",oct&0x0f);

	while ( curr_len > 0 )
	{
		guchar e_len;
		guint16 prot;
	tvbuff_t *l3_tvb;
	dissector_handle_t handle = NULL;
	static packet_info p_info;

	prot = tvb_get_guint8(tvb, curr_offset);
	prot <<= 8;
	prot |= tvb_get_guint8(tvb, curr_offset+1);
	e_len = tvb_get_guint8(tvb, curr_offset+2);
		curr_len-=3;
		curr_offset+=3;

		switch ( prot )
		{
			case 0x0001:
		{
	    	    proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) P-CSCF Address" , prot );
	    	    proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);

		    tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
		    proto_tree_add_text(tree,
			tvb, curr_offset, 16,
			"IPv6: %s", ip6_to_str(&ipv6_addr));
	    	    break;
	    	}
			case 0x0002:
	    	    proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) IM CN Subsystem Signaling Flag" , prot );
	    	    proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
	    	    break;
			case 0x0003:
			{
	    	    proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) DNS Server Address" , prot );
	    	    proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);

		    tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
		    proto_tree_add_text(tree,
			tvb, curr_offset, 16,
			"IPv6: %s", ip6_to_str(&ipv6_addr));
	    	    break;
	    	}
			case 0x0004:
	    	    proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) Policy Control rejection code" , prot );
	    	    proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
	    	    oct = tvb_get_guint8(tvb, curr_offset);
	    	    proto_tree_add_text(tree,tvb, curr_offset, 1, "Reject Code: 0x%02x (%u)", e_len , e_len);
	    	    break;
		default:
			handle = dissector_get_port_handle ( gprs_sm_pco_subdissector_table , prot );
			if ( handle != NULL )
			{
				proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Protocol: (%u) %s" ,
					prot , val_to_str(prot, ppp_vals, "Unknown"));
				proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
				/*
				 * dissect the embedded message
				 */
				l3_tvb = tvb_new_subset(tvb, curr_offset, e_len, e_len);
				call_dissector(handle, l3_tvb ,  &p_info  , tree );
			}
			else
			{
				proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Protocol/Parameter: (%u) unknwown" , prot );
				proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
				/*
				* dissect the embedded DATA message
				*/
				l3_tvb = tvb_new_subset(tvb, curr_offset, e_len, e_len);
				call_dissector(data_handle, l3_tvb, &p_info , tree);
			}
		}

	curr_len-= e_len;
	curr_offset+= e_len;
	}
	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.4
 */
static guint8
de_sm_pdp_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	const gchar	*str;
	guchar      oct;
	guchar      oct2;
	struct e_in6_addr ipv6_addr;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&0x0f )
	{
		case 0x00: str="ETSI allocated address"; break;
		case 0x01: str="IETF allocated address"; break;
		case 0x0f: str="Empty PDP type"; break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PDP type organisation: (%u) %s",oct&0x0f,str);

	oct2 = tvb_get_guint8(tvb, curr_offset+1);

	if (( oct&0x0f ) == 0 )
	{
	    switch ( oct2 )
	    {
			case 0x00: str="Reserved, used in earlier version of this protocol"; break;
			case 0x01: str="PDP-type PPP"; break;
			default: str="reserved";
		    }
	}
	else if (( oct&0x0f) == 1 )
	{
		    switch ( oct2 )
		    {
	      	case 0x21: str="IPv4 address"; break;
			case 0x57: str="IPv6 address"; break;
			default: str="IPv4 address";
		    }
	}
	else if ((oct2==0) && (( oct&0x0f) == 0x0f ))
		    str="Empty";
	else
			str="Not specified";    

	proto_tree_add_text(tree,
		tvb, curr_offset+1, 1,
		"PDP type number: (%u) %s",oct2,str);

	if (( len == 2 ) && (( oct2 == 0x21 ) || ( oct2 == 0x57 )))
	{
			proto_tree_add_text(tree,
			tvb, curr_offset+1, 1,
			"Dynamic addressing");
	
	    curr_offset+= curr_len;

	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		   return(curr_offset - offset);
	}
	else if ( len == 2 )
	{
			proto_tree_add_text(tree,
			tvb, curr_offset+1, 1,
			"No PDP address is included");
	
	    curr_offset+= curr_len;

	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		   return(curr_offset - offset);
	}
	else if ( len < 2 )
	{
			proto_tree_add_text(tree,
			tvb, curr_offset+1, 1,
			"Length is bogus - should be >= 2");
	
	    curr_offset+= curr_len;

	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		   return(curr_offset - offset);
	}

	if ((( oct2 == 0x21 ) && ( len != 6 )) ||
	   (( oct2 == 0x57 ) && ( len != 18 )))
	{
			proto_tree_add_text(tree,
			tvb, curr_offset+2, len-2,
			"Can't display address");
	}


	switch ( oct2 )
	{
		case 0x21:
			if (len-2 != 4) {
				proto_tree_add_text(tree,
	            tvb, curr_offset+2, 0,
		            "IPv4: length is wrong");
		    } else {
				proto_tree_add_text(tree,
		            tvb, curr_offset+2, len-2,
		            "IPv4: %s", ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
		    }
		    break;

		case 0x57:
			if (len-2 != 16) {
				proto_tree_add_text(tree,
	            tvb, curr_offset+2, 0,
		            "IPv6: length is wrong");
		    } else {
		        tvb_get_ipv6(tvb, curr_offset+2, &ipv6_addr);
				proto_tree_add_text(tree,
					tvb, curr_offset+2, len-2,
		            "IPv6: %s", ip6_to_str(&ipv6_addr));
		    }
		    break;
	}

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.5 3GPP TS 24.008 version 7.8.0 Release 7
 */

static const value_string gsm_a_qos_delay_cls_vals[] = {
	{ 0x00, "Subscribed delay class (in MS to network direction)" },
	{ 0x01, "Delay class 1" },
	{ 0x02, "Delay class 2" },
	{ 0x03, "Delay class 3" },
	{ 0x04, "Delay class 4 (best effort)" },
	{ 0x07,	"Reserved" },
	{ 0, NULL }
};

static const value_string gsm_a_qos_reliability_vals[] = {
	{ 0x00, "Subscribed reliability class (in MS to network direction)" },
	{ 0x01, "Acknowledged GTP, LLC, and RLC; Protected data" },
	{ 0x02, "Unacknowledged GTP, Ack LLC/RLC, Protected data" },
	{ 0x03, "Unacknowledged GTP/LLC, Ack RLC, Protected data" },
	{ 0x04, "Unacknowledged GTP/LLC/RLC, Protected data" },
	{ 0x05, "Unacknowledged GTP/LLC/RLC, Unprotected data" },
	{ 0x07, "Reserved" },
	{ 0, NULL }
};
 /* Delivery of erroneous SDUs, octet 6 (see 3GPP TS 23.107) Bits 3 2 1 */
const value_string gsm_a_qos_del_of_err_sdu_vals[] = {
	{ 0, "Subscribed delivery of erroneous SDUs/Reserved" },
	{ 1, "No detect('-')" },
	{ 2, "Erroneous SDUs are delivered('yes')" },
	{ 3, "Erroneous SDUs are not delivered('No')" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

 /* Delivery order, octet 6 (see 3GPP TS 23.107) Bits 5 4 3 */
const value_string gsm_a_qos_del_order_vals[] = {
	{ 0, "Subscribed delivery order/Reserved" },
	{ 1, "With delivery order ('yes')" },
	{ 2, "Without delivery order ('no')" },
	{ 3, "Reserved" },
	{ 0, NULL }
};
/* Traffic class, octet 6 (see 3GPP TS 23.107) Bits 8 7 6 */
const value_string gsm_a_qos_traffic_cls_vals[] = {
	{ 0, "Subscribed traffic class/Reserved" },
	{ 1, "Conversational class" },
	{ 2, "Streaming class" },
	{ 3, "Interactive class" },
	{ 4, "Background class" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Residual Bit Error Rate (BER), octet 10 (see 3GPP TS 23.107) Bits 8 7 6 5 */
const value_string gsm_a_qos_ber_vals[] = {
	{ 0, "Subscribed residual BER/Reserved" },
	{ 1, "5*10-2" },
	{ 2, "1*10-2" },
	{ 3, "5*10-3" },
	{ 4, "4*10-3" },
	{ 5, "1*10-3" },
	{ 6, "1*10-4" },
	{ 7, "1*10-5" },
	{ 8, "1*10-6" },
	{ 9, "6*10-8" },
	{ 10, "Reserved" },
	{ 0, NULL }
};

/* SDU error ratio, octet 10 (see 3GPP TS 23.107) Bits 4 3 2 1 */
const value_string gsm_a_qos_sdu_err_rat_vals[] = {
	{ 0, "Subscribed SDU error ratio/Reserved" },
	{ 1, "1*10-2" },
	{ 2, "7*10-3" },
	{ 3, "1*10-3" },
	{ 4, "1*10-4" },
	{ 5, "1*10-5" },
	{ 6, "1*10-6" },
	{ 7, "1*10-1" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Traffic handling priority, octet 11 (see 3GPP TS 23.107) Bits 2 1 */
const value_string gsm_a_qos_traff_hdl_pri_vals[] = {
	{ 0, "Subscribed traffic handling priority/Reserved" },
	{ 1, "Priority level 1" },
	{ 2, "Priority level 2" },
	{ 3, "Priority level 3" },
	{ 0, NULL }
};

guint8
de_sm_qos(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guchar       oct, tmp_oct;
	const gchar	*str;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_item(tree, hf_gsm_a_qos_delay_cls, tvb, curr_offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gsm_a_qos_qos_reliability_cls, tvb, curr_offset, 1, FALSE);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct>>4 )
	{
		case 0x00: str="Subscribed peak throughput/reserved"; break;
		case 0x01: str="Up to 1 000 octet/s"; break;
		case 0x02: str="Up to 2 000 octet/s"; break;
		case 0x03: str="Up to 4 000 octet/s"; break;
		case 0x04: str="Up to 8 000 octet/s"; break;
		case 0x05: str="Up to 16 000 octet/s"; break;
		case 0x06: str="Up to 32 000 octet/s"; break;
		case 0x07: str="Up to 64 000 octet/s"; break;
		case 0x08: str="Up to 128 000 octet/s"; break;
		case 0x09: str="Up to 256 000 octet/s"; break;
		case 0x0f: str="Reserved"; break;
		default: str="Up to 1 000 octet/s";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Peak throughput: (%u) %s",oct>>4,str);

	switch ( oct&0x7 )
	{
		case 0x00: str="Subscribed precedence/reserved"; break;
		case 0x01: str="High priority"; break;
		case 0x02: str="Normal priority"; break;
		case 0x03: str="Low priority"; break;
		case 0x07: str="Reserved"; break;
		default: str="Normal priority";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Precedence class: (%u) %s",oct&7,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&0x1f )
	{
		case 0x00: str="Subscribed peak throughput/reserved"; break;
		case 0x01: str="100 octet/h"; break;
		case 0x02: str="200 octet/h"; break;
		case 0x03: str="500 octet/h"; break;
		case 0x04: str="1 000 octet/h"; break;
		case 0x05: str="2 000 octet/h"; break;
		case 0x06: str="5 000 octet/h"; break;
		case 0x07: str="10 000 octet/h"; break;
		case 0x08: str="20 000 octet/h"; break;
		case 0x09: str="50 000 octet/h"; break;
		case 0x0a: str="100 000 octet/h"; break;
		case 0x0b: str="200 000 octet/h"; break;
		case 0x0c: str="500 000 octet/h"; break;
		case 0x0d: str="1 000 000 octet/h"; break;
		case 0x0e: str="2 000 000 octet/h"; break;
		case 0x0f: str="5 000 000 octet/h"; break;
		case 0x10: str="10 000 000 octet/h"; break;
		case 0x11: str="20 000 000 octet/h"; break;
		case 0x12: str="50 000 000 octet/h"; break;
		case 0x1e: str="Reserved"; break;
		case 0x1f: str="Best effort"; break;
		default: str="Best effort";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Mean throughput: (%u) %s",oct&0x1f,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	proto_tree_add_item(tree, hf_gsm_a_qos_traffic_cls, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_order, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_of_err_sdu, tvb, curr_offset, 1, FALSE);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum SDU size/reserved"; break;
		case 0x97: str="1502 octets"; break;
		case 0x98: str="1510 octets"; break;
		case 0x99: str="1520 octets"; break;
		case 0xff: str="Reserved"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x96 ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
	    	"Maximum SDU size: (%u) %u octets",oct,oct*10);
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
	    	"Maximum SDU size: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for uplink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for uplink: (%u) %ukbps",oct,(oct-0x40)*8+64); /* - was (oct-0x40)*8  */
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for uplink: (%u) %ukbps",oct,(oct-0x80)*64+576); /* - was (oct-0x80)*64 */
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for uplink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for downlink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for downlink: (%u) %ukbps",oct,(oct-0x40)*8+64);/*same as above*/
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for downlink: (%u) %ukbps",oct,(oct-0x80)*64+576);/*same as above*/
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for downlink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	proto_tree_add_item(tree, hf_gsm_a_qos_ber, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_sdu_err_rat, tvb, curr_offset, 1, FALSE);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct>>2 )
	{
		case 0x00: str="Subscribed transfer delay/reserved"; break;
		case 0x3f: str="Reserved"; break;
		default: str="This should not happen - BUG";
	}

	tmp_oct = oct>>2;

	if (( tmp_oct >= 1 ) && ( tmp_oct <= 0x0f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %ums",oct>>2,(oct>>2)*10);
	else if (( tmp_oct >= 0x10 ) && ( tmp_oct <= 0x1f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %ums",oct>>2,((oct>>2)-0x10)*50+200);
	else if (( tmp_oct >= 0x20 ) && ( tmp_oct <= 0x3e ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %ums",oct>>2,((oct>>2)-0x20)*100+1000);
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %s",oct>>2,str);

	switch ( oct&0x03 )
	{
		case 0x00: str="Subscribed traffic handling priority/reserved"; break;
		case 0x01: str="Priority level 1"; break;
		case 0x02: str="Priority level 2"; break;
		case 0x03: str="Priority level 3"; break;
		default: str="This should not happen - BUG";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Traffic Handling priority: (%u) %s",oct&0x03,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed guaranteed bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for uplink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for uplink: (%u) %ukbps",oct,(oct-0x40)*8+64);/*same as for max bit rate*/
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for uplink: (%u) %ukbps",oct,(oct-0x80)*64+576);/*same as for max bit rate*/
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for uplink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed guaranteed bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for downlink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for downlink: (%u) %ukbps",oct,(oct-0x40)*8+64);/*same as above*/
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for downlink: (%u) %ukbps",oct,(oct-0x80)*64+576);/*same as above*/
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for downlink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( (oct>>4)&1 )
	{
		case 0x00: str="Not optimised for signalling traffic"; break;
		case 0x01: str="Optimised for signalling traffic"; break;
		default: str="This should not happen - BUG";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Signalling Indication: (%u) %s",(oct>>4)&1,str);

	switch ( oct&7 )
	{
		case 0x00: str="unknown"; break;
		case 0x01: str="speech"; break;
		default: str="unknown";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Source Statistics Descriptor: (%u) %s",oct&7,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}


	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Use the value indicated by the Maximum bit rate for downlink"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for downlink (extended): (%u) %ukbps",oct,oct*100);
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Maximum bit rate for downlink (extended): (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
	    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	    return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Use the value indicated by the Guaranteed bit rate for downlink"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x4a ))
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for downlink (extended): (%u) %ukbps",oct,oct*100);
	else
	    proto_tree_add_text(tree,
			tvb, curr_offset, 1,
   	 	"Guaranteed bit rate for downlink (extended): (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [8] 10.5.6.6 SM cause
 */
static guint8
de_sm_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x08: str="Operator Determined Barring"; break;
		case 0x18: str="MBMS bearer capabilities insufficient for the service"; break;
		case 0x19: str="LLC or SNDCP failure(GSM only)"; break;
		case 0x1a: str="Insufficient resources"; break;
		case 0x1b: str="Missing or unknown APN"; break;
		case 0x1c: str="Unknown PDP address or PDP type"; break;
		case 0x1d: str="User Aauthentication failed"; break;
		case 0x1e: str="Activation rejected by GGSN"; break;
		case 0x1f: str="Activation rejected, unspecified"; break;
		case 0x20: str="Service option not supported"; break;
		case 0x21: str="Requested service option not subscribed"; break;
		case 0x22: str="Service option temporarily out of order"; break;
		case 0x23: str="NSAPI already used (not sent)"; break;
		case 0x24: str="Regular deactivation"; break;
		case 0x25: str="QoS not accepted"; break;
		case 0x26: str="Network failure"; break;
		case 0x27: str="Reactivation required"; break;
		case 0x28: str="Feature not supported"; break;
		case 0x29: str="Semantic error in the TFT operation"; break;
		case 0x2a: str="Syntactical error in the TFT operation"; break;
		case 0x2b: str="Unknown PDP context"; break;
		case 0x2e: str="PDP context without TFT already activated"; break;
		case 0x2f: str="Multicast group membership time-out"; break;
		case 0x2c: str="Semantic errors in packet filter(s)"; break;
		case 0x2d: str="Syntactical errors in packet filter(s)"; break;
		case 0x51: str="Invalid transaction identifier value"; break;
		case 0x5f: str="Semantically incorrect message"; break;
		case 0x60: str="Invalid mandatory information"; break;
		case 0x61: str="Message type non-existent or not implemented"; break;
		case 0x62: str="Message type not compatible with the protocol state"; break;
		case 0x63: str="Information element non-existent or not implemented"; break;
		case 0x64: str="Conditional IE error"; break;
		case 0x65: str="Message not compatible with the protocol state"; break;
		case 0x6f: str="Protocol error, unspecified"; break;
		case 0x70: str="APN restriction value incompatible with active PDP context"; break;
		default: str="Protocol error, unspecified"; break;
	}

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Cause: (%u) %s %s",
	oct, str,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.7
 */
static guint8
de_sm_linked_ti(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	gchar       oct;

	gchar       ti_flag[2][80]={ "The message is sent from the side that originates the TI" ,
				"The message is sent to the side that originates the TI" };

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"TI flag: (%u) %s",oct>>7,ti_flag[oct>>7]);

	if ( curr_len > 1 )
	{
		oct = tvb_get_guint8(tvb, curr_offset);
	
		proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"TI value: 0x%02x (%u)",oct&0x7f,oct&0x7f);

		proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"ext: 0x%02x (%u)",oct>>7,oct>>7);

	}
	else
	{
		proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"TI value: 0x%02x (%u)",(oct>>4)&7,(oct>>4)&7);
	}

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.9
 */
static guint8
de_sm_sapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"LLC SAPI: 0x%02x (%u) %s",
	oct&0x0f, oct&0x0f,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.10
 */
static guint8
de_sm_tear_down(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	gchar	str[2][30] = { "tear down not requested" , "tear down requested" };

	len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Tear Down Indicator: (%u) %s %s",
	oct&1, str[oct&1],add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.11
 */
/* Packet Flow Identifier value (octet 3) */
static const value_string gsm_a_packet_flow_id_vals[] = {
	{ 0,		"Best Effort"},
	{ 1,		"Signaling"},
	{ 2,		"SMS"},
	{ 3,		"TOM8"},
	{ 4,		"reserved"},
	{ 5,		"reserved"},
	{ 6,		"reserved"},
	{ 7,		"reserved"},
	{ 0,	NULL }
};
guint8
de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guchar	oct;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Packet Flow Identifier: (%u) %s",oct&0x7f,
		val_to_str(oct&0x7f, gsm_a_packet_flow_id_vals, "dynamically assigned (%u)"));

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.12     TFT - Traffic Flow Template
 */
/* TFT operation code (octet 3) */
static const value_string gsm_a_tft_op_code_vals[] = {
	{ 0,		"Spare"},
	{ 1,		"Create new TFT"},
	{ 2,		"Delete existing TFT"},
	{ 3,		"Add packet filters to existing TFT"},
	{ 4,		"Replace packet filters in existing TFT"},
	{ 5,		"Delete packet filters from existing TFT"},
	{ 6,		"No TFT operation"},
	{ 7,		"Reserved"},
	{ 0,	NULL }
};

static const true_false_string gsm_a_tft_e_bit  = {
  "parameters list is included",
  "parameters list is not included"
};


static guint8
de_sm_tflow_temp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	proto_item  *tf = NULL;
	proto_tree      *tf_tree = NULL;
	proto_tree 	*comp_tree = NULL;
	guchar	op_code;
	guchar	pkt_fil_count;
	guchar      e_bit;
	const gchar *str;
	guchar      count;
	guchar	oct;
	gint pf_length;
	gint pf_identifier;
	gint pack_component_type;

	curr_len = len;
	curr_offset = offset;

	/*
	 * parse first octet. It contain TFT operation code, E bit and Number of packet filters
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	op_code = oct>>5;
	pkt_fil_count = oct&0x0f;
	e_bit = (oct>>4)&1;

	proto_tree_add_item(tree,hf_gsm_a_tft_op_code,tvb,curr_offset,1,FALSE);
	proto_tree_add_item(tree,hf_gsm_a_tft_e_bit,tvb,curr_offset,1,FALSE);
	proto_tree_add_item(tree,hf_gsm_a_tft_pkt_flt,tvb,curr_offset,1,FALSE);

	curr_offset++;
	curr_len--;

	/* Packet filter list dissect */

	count = 0;
	if ( op_code == 2 )			/* delete TFT contains no packet filters. so we will jump over it */
	count = pkt_fil_count;
	while ( count < pkt_fil_count )
	{
	tf = proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Packet filter %d",count);   /* 0-> 7 */

		tf_tree = proto_item_add_subtree(tf, ett_sm_tft );

	if ( op_code == 5 )  /* Delete packet filters from existing TFT - just a list of identifiers */

	{
		if ((curr_offset-offset)<1) {
			proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
			return(curr_offset-offset);
		}
		oct = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet filter identifier: 0x%02x (%u)",oct,oct );	
	}
	else				/* create new, Add packet filters or Replace packet filters */
	{
	
		if ((curr_offset-offset)<1) {
			proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
			return(curr_offset-offset);
		}
		pf_identifier = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet filter identifier: %u (%u)",pf_identifier, pf_identifier);	

		if ((curr_offset-offset)<1) {
			proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
			return(curr_offset-offset);
		}
		oct = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet evaluation precedence: 0x%02x (%u)",oct,oct );	

		if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data"); return(curr_offset-offset);}
		pf_length = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet filter length: 0x%02x (%u)",pf_length,pf_length );	
		/* New tree for component */

		/* Dissect Packet filter Component */
		/* while ( filter_len > 1 ) */
		/* packet filter component type identifier: */

		if (pf_length > 0 ){
			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(curr_offset-offset);
			}
			pack_component_type = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			tf=proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Packet filter component type identifier: ");
	    	comp_tree = proto_item_add_subtree(tf, ett_sm_tft );
		
			switch ( pack_component_type ){
			
				case 0x10:
					str="IPv4 source address type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip4_address,tvb,curr_offset,4,FALSE);
	                curr_offset+=4;
	                curr_len-=4;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip4_mask,tvb,curr_offset,4,FALSE);
	                curr_offset+=4;
	                curr_len-=4;
					break;


				case 0x20:
					str="IPv6 source address type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip6_address,tvb,curr_offset,16,FALSE);
					curr_offset+=16;
					curr_len-=16;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip6_mask,tvb,curr_offset,16,FALSE);
					curr_offset+=16;
					curr_len-=16;
					break;

				case 0x30:
					str="Protocol identifier/Next header type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_protocol_header,tvb,curr_offset,1,FALSE);
					curr_offset+=1;
					curr_len-=1;
					break;

				case 0x40:
					str="Single destination port type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port,tvb,curr_offset,2,FALSE);
					curr_offset+=2;
					curr_len-=2;

				case 0x41:
					str="Destination port range type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_low,tvb,curr_offset,2,FALSE);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_high,tvb,curr_offset,2,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;

				case 0x50:
					str="Single source port type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port,tvb,curr_offset,2,FALSE);
					curr_offset+=2;
					curr_len-=2;
					break;

				case 0x51:
					str="Source port range type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_low,tvb,curr_offset,2,FALSE);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_high,tvb,curr_offset,2,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;

				case 0x60:
					str="Security parameter index type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_security,tvb,curr_offset,4,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;


				case 0x70:
					str="Type of service/Traffic class type";
					proto_tree_add_item(comp_tree,hf_gsm_a_qos_traffic_cls,tvb,curr_offset,1,FALSE);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_traffic_mask,tvb,curr_offset,1,FALSE);
					curr_offset+=2;
					curr_len-=2;
					break;

				case 0x80:
					str="Flow label type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_traffic_mask,tvb,curr_offset,1,FALSE);
					curr_offset+=3;
					curr_len-=3;
					break;

				default:
					str="not specified";
			}
			proto_item_append_text(tf, "(%u) %s", pack_component_type, str );
			count++;
			}
		}
	}


	/* The parameters list contains a variable number of parameters that might need to be
	 * transferred in addition to the packet filters. If the parameters list is included, the E
	 * bit is set to 1; otherwise, the E bit is set to 0.
	 */
	 if (e_bit == 1){
		 proto_tree_add_text(tf_tree, tvb, curr_offset, 1, "Note: Possible Authorizaton Token/Flow Identifier not decoded yet");
	 }
 return(curr_offset - offset);
}

static guint8
de_tp_sub_channel(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;
    const gchar	*str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset) & 0x3f;
    if ((oct & 0x38) == 0x38)
        str = "I";
    else if ((oct & 0x38) == 0x18)
        str = "F";
    else if ((oct & 0x38) == 0x10)
        str = "E";
    else if ((oct & 0x38) == 0x08)
        str = "D";
    else if ((oct & 0x3c) == 0x04)
        str = "C";
    else if ((oct & 0x3e) == 0x02)
        str = "B";
    else if ((oct & 0x3e) == 0x00)
        str = "A";
    else
        str = "unknown";

    proto_tree_add_text(tree,
    	tvb, curr_offset, 1,
    	"Test Loop %s",str);

    if (oct & 0x01)
        proto_tree_add_text(tree,
        	tvb, curr_offset, 1,
        	"Only one TCH active or sub-channel 0 of two half rate channels is to be looped");
    else
        proto_tree_add_text(tree,
        	tvb, curr_offset, 1,
        	"Sub-channel 1 of two half rate channels is to be looped");

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if ((oct & 0xF0) == 0x80)
        proto_tree_add_text(tree,tvb, curr_offset, 1, "Acknowledgment element: %d",oct&0x01);
    else
        proto_tree_add_text(tree,tvb, curr_offset, 1, "No acknowledgment element present");

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_loop_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x03)
    {
        case 0x00:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Channel coding not needed. The Burst-by-Burst loop is activated, type G");
            break;
        case 0x01:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Channel coding needed. Frame erasure is to be signalled, type H");
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Channel coding reserved (%d)",oct & 0x03);
            break;
    }

    switch (oct & 0x1c)
    {
        case 0x00:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Multi-slot mechanism 1");
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Timeslot number %d",(oct & 0xe0)>>5);
            break;
        case 0x04:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Multi-slot mechanism 2");
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Loop mechanism reserved (%d)",(oct & 0x1c)>>2);
            break;
    }

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_loop_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x30)
    {
        case 0x00:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Channel coding not needed. The Burst-by-Burst loop is activated, type G");
            break;
        case 0x10:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Channel coding needed. Frame erasure is to be signalled, type H");
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Channel coding reserved (%d)",(oct & 0x30)>>4);
            break;
    }

    switch (oct & 0x0e)
    {
        case 0x00:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Multi-slot mechanism 1");
            break;
        case 0x02:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Multi-slot mechanism 2");
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Loop mechanism reserved (%d)",(oct & 0x0e)>>1);
            break;
    }

    if (oct & 0x01)
        proto_tree_add_text(tree, tvb, curr_offset, 1, "Multi-slot TCH loop was not closed due to error");
    else
        proto_tree_add_text(tree, tvb, curr_offset, 1, "Multi-slot TCH loop was closed successfully");

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_tested_device(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
        case 0:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Normal operation (no tested device via DAI)");
            break;
        case 1:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Test of speech decoder / DTX functions (downlink)");
            break;
        case 2:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Test of speech encoder / DTX functions (uplink)");
            break;
        case 4:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Test of acoustic devices and A/D & D/A");
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Tested device reserved (%d)",oct);
            break;
    }

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_pdu_description(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guint16  value;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);
    curr_offset += 2;

    if (value & 0x8000)
    {
        if ((value & 0xfff) == 0)
            proto_tree_add_text(tree, tvb, curr_offset, 1, "Infinite number of PDUs to be transmitted in the TBF");
        else
            proto_tree_add_text(tree, tvb, curr_offset, 1, "%d PDUs to be transmitted in the TBF",value & 0xfff);
    }
    else
        proto_tree_add_text(tree, tvb, curr_offset, 1, "PDU description reserved");

    return(curr_offset - offset);
}

static guint8
de_tp_mode_flag(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct & 0x01)
        proto_tree_add_text(tree, tvb, curr_offset, 1, "MS shall select the loop back option");
    else
        proto_tree_add_text(tree, tvb, curr_offset, 1, "MS shall itself generate the pseudorandom data");

    proto_tree_add_text(tree, tvb, curr_offset, 1, "Downlink Timeslot Offset: timeslot number %d",(oct & 0x0e)>>1);

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_egprs_mode_flag(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct & 0x01)
        proto_tree_add_text(tree, tvb, curr_offset, 1, "MS loops back blocks on the uplink using GMSK modulation only");
    else
        proto_tree_add_text(tree, tvb, curr_offset, 1, "MS loops back blocks on the uplink using either GMSK or 8-PSK modulation following the detected received modulation");

    proto_tree_add_text(tree, tvb, curr_offset, 1, "Downlink Timeslot Offset: timeslot number %d",(oct & 0x0e)>>1);

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_ue_test_loop_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;
    guint8  lb_setup_length,i,j;
    guint16 value;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    curr_offset+= 1;

    switch (oct & 0x03)
    {
        case 0:
        {
            proto_tree_add_text(tree, tvb, curr_offset, 1, "UE test loop mode 1 loop back (loopback of RLC SDUs or PDCP SDUs)");
            lb_setup_length = tvb_get_guint8(tvb, curr_offset);
            curr_offset += 1;
            for (i=0,j=0; (i<lb_setup_length) && (j<4); i+=3,j++)
            {
                proto_tree_add_text(tree, tvb, curr_offset, 1, "LB setup RB IE %d",j+1);
                value = tvb_get_ntohs(tvb, curr_offset);
                curr_offset += 2;
                proto_tree_add_text(tree, tvb, curr_offset, 1, "Uplink RLC SDU size is %d bits",value);
                oct = tvb_get_guint8(tvb, curr_offset);
                curr_offset+= 1;
                proto_tree_add_text(tree, tvb, curr_offset, 1, "Radio Bearer %d",oct & 0x1f);
            }
            break;
        }
        case 1:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "UE test loop mode 2 loop back (loopback of transport block data and CRC bits)");
            break;
        case 2:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "UE test loop mode 3 RLC SDU counting (counting of received RLC SDUs)");
            oct = tvb_get_guint8(tvb, curr_offset);
            curr_offset+= 1;
            proto_tree_add_text(tree, tvb, curr_offset, 1, "MBMS short transmission identity %d",(oct & 0x1f)+1);
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "UE test loop mode reserved (%d)",oct & 0x03);
            break;
    }

    return(curr_offset - offset);
}

static guint8
de_tp_ue_positioning_technology(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
        case 0:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "AGPS");
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, 1, "UE positioning technology reserved (%d)",oct);
            break;
    }

    curr_offset+= 1;

    return(curr_offset - offset);
}

static guint8
de_tp_rlc_sdu_counter_value(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guint32 value;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);
    curr_offset+= 4;

    proto_tree_add_text(tree, tvb, curr_offset, 1, "UE received RLC SDU counter value %d",value);

    return(curr_offset - offset);
}

guint8 (*dtap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* Mobility Management Information Elements 10.5.3 */
	de_auth_param_rand,	/* Authentication Parameter RAND */
	de_auth_param_autn,	/* Authentication Parameter AUTN (UMTS authentication challenge only) */
	de_auth_resp_param,	/* Authentication Response Parameter */
	de_auth_resp_param_ext,	/* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
	de_auth_fail_param,	/* Authentication Failure Parameter (UMTS authentication challenge only) */
	NULL /* handled inline */,	/* CM Service Type */
	NULL /* handled inline */,	/* Identity Type */
	/* Pos 50 */
	NULL /* handled inline */,	/* Location Updating Type */
	de_network_name,	/* Network Name */
	de_rej_cause,	/* Reject Cause */
	NULL /* no associated data */,	/* Follow-on Proceed */
	de_time_zone,	/* Time Zone */
	de_time_zone_time,	/* Time Zone and Time */
	NULL /* no associated data */,	/* CTS Permission */
	de_lsa_id,	/* LSA Identifier */
	de_day_saving_time,	/* Daylight Saving Time */
	NULL, /* Emergency Number List */
	/* Call Control Information Elements 10.5.4 */
	/* Pos 60 */
	de_aux_states,	/* Auxiliary States */
	de_bearer_cap,	/* Bearer Capability */
	de_cc_cap,	/* Call Control Capabilities */
	de_call_state,	/* Call State */
	de_cld_party_bcd_num,	/* Called Party BCD Number */
	de_cld_party_sub_addr,	/* Called Party Subaddress */
	de_clg_party_bcd_num,	/* Calling Party BCD Number */
	de_clg_party_sub_addr,	/* Calling Party Subaddress */
	de_cause,	/* Cause */
	NULL /* no associated data */,	/* CLIR Suppression */
	NULL /* no associated data */,	/* CLIR Invocation */
	NULL /* handled inline */,	/* Congestion Level */
	NULL,	/* Connected Number */
	NULL,	/* Connected Subaddress */
	de_facility,	/* Facility */
	NULL,	/* High Layer Compatibility */
	de_keypad_facility,	/* Keypad Facility */
	de_llc,							/* 10.5.4.18 Low layer compatibility */
	NULL,	/* More Data */
	NULL,	/* Notification Indicator */
	de_prog_ind,	/* Progress Indicator */
	NULL,	/* Recall type $(CCBS)$ */
	NULL,	/* Redirecting Party BCD Number */
	NULL,	/* Redirecting Party Subaddress */
	de_repeat_ind,	/* Repeat Indicator */
	NULL /* no associated data */,	/* Reverse Call Setup Direction */
	NULL,	/* SETUP Container $(CCBS)$ */
	NULL,	/* Signal */
	de_ss_ver_ind,	/* SS Version Indicator */
	NULL,	/* User-user */
	NULL,	/* Alerting Pattern $(NIA)$ */
	NULL,	/* Allowed Actions $(CCBS)$ */
	NULL,	/* Stream Identifier */
	NULL,	/* Network Call Control Capabilities */
	NULL,	/* Cause of No CLI */
	NULL,	/* Immediate Modification Indicator */
	NULL,	/* Supported Codec List */
	NULL,	/* Service Category */
	/* GPRS Mobility Management Information Elements 10.5.5 */
	de_gmm_attach_res,	/* Attach Result */
	de_gmm_attach_type,	/* Attach Type */
	de_gmm_ciph_alg,	/* Cipher Algorithm */
	de_gmm_tmsi_stat,	/* TMSI Status */
	de_gmm_detach_type,	/* Detach Type */
	de_gmm_drx_param,	/* DRX Parameter */
	de_gmm_ftostby,	/* Force to Standby */
	de_gmm_ftostby_h,	/* Force to Standby - Info is in the high nibble */
	de_gmm_ptmsi_sig,	/* P-TMSI Signature */
	de_gmm_ptmsi_sig2,	/* P-TMSI Signature 2 */
	de_gmm_ident_type2,	/* Identity Type 2 */
	de_gmm_imeisv_req,	/* IMEISV Request */
	de_gmm_rec_npdu_lst,	/* Receive N-PDU Numbers List */
	de_gmm_ms_net_cap,	/* MS Network Capability */
	de_gmm_ms_radio_acc_cap,	/* MS Radio Access Capability */
	de_gmm_cause,				/* GMM Cause */
	de_gmm_rai,					/* Routing Area Identification */
	de_gmm_update_res,	/* Update Result */
	de_gmm_update_type,	/* Update Type */
	de_gmm_ac_ref_nr,	/* A&C Reference Number */
	de_gmm_ac_ref_nr_h, /* A&C Reference Numer - Info is in the high nibble */
	de_gmm_service_type,	/* Service Type */
	de_gmm_cell_notfi,	/* Cell Notification */
	de_gmm_ps_lcs_cap,	/* PS LCS Capability */
	de_gmm_net_feat_supp,	/* Network Feature Support */
	de_gmm_rat_info_container, /* Inter RAT information container */
	/* Short Message Service Information Elements [5] 8.1.4 */
	de_cp_user_data,	/* CP-User Data */
	de_cp_cause,	/* CP-Cause */
	/* Session Management Information Elements 10.5.6 */
	de_sm_apn,	/* Access Point Name */
	de_sm_nsapi,	/* Network Service Access Point Identifier */
	de_sm_pco,	/* Protocol Configuration Options */
	de_sm_pdp_addr,	/* Packet Data Protocol Address */
	de_sm_qos,	/* Quality Of Service */
	de_sm_cause,	/* SM Cause */
	de_sm_linked_ti,	/* Linked TI */
	de_sm_sapi,	/* LLC Service Access Point Identifier */
	de_sm_tear_down,	/* Tear Down Indicator */
	de_sm_pflow_id,	/* Packet Flow Identifier */
	de_sm_tflow_temp,	/* Traffic Flow Template */
	/* GPRS Common Information Elements 10.5.7 */
	de_gc_context_stat,	/* PDP Context Status */
	de_gc_radio_prio,	/* Radio Priority */
	de_gc_timer,	/* GPRS Timer */
	de_gc_timer2,	/* GPRS Timer 2 */
	de_gc_radio_prio2,	/* Radio Priority 2 */
	de_gc_mbms_context_stat, /* 10.5.7.6 MBMS context status */
    /* Tests procedures information elements 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0 */
    de_tp_sub_channel,	/* Close TCH Loop Cmd Sub-channel */
    de_tp_ack,	/* Open Loop Cmd Ack */
    de_tp_loop_type,			/* Close Multi-slot Loop Cmd Loop type */
    de_tp_loop_ack,			/* Close Multi-slot Loop Ack Result */
    de_tp_tested_device,			/* Test Interface Tested device */
    de_tp_pdu_description,			/* GPRS Test Mode Cmd PDU description */
    de_tp_mode_flag,			/* GPRS Test Mode Cmd Mode flag */
    de_tp_egprs_mode_flag,			/* EGPRS Start Radio Block Loopback Cmd Mode flag */
    de_tp_ue_test_loop_mode,			/* Close UE Test Loop Mode */
    de_tp_ue_positioning_technology,			/* UE Positioning Technology */
    de_tp_rlc_sdu_counter_value,			/* RLC SDU Counter Value */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * [4] 9.2.2
 */
static void
dtap_mm_auth_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8	oct;
	proto_tree	*subtree;
	proto_item	*item;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	/*
	 * special dissection for Cipher Key Sequence Number
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_common_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);

	switch (oct & 0x07)
	{
	case 0x07:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: No key is available",
	    a_bigbuf);
	break;

	default:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: %u",
	    a_bigbuf,
	    oct & 0x07);
	break;
	}

	curr_offset++;
	curr_len--;

	if (curr_len <= 0) return;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND);

	ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.2.3
 */
static void
dtap_mm_auth_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM);

	ELEM_OPT_TLV(0x21, GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.2.3a
 */
static void
dtap_mm_auth_fail(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE);

	ELEM_OPT_TLV(0x22, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.4
 */
static void
dtap_mm_cm_reestab_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8	oct;
	proto_tree	*subtree;
	proto_item	*item;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	/*
	 * special dissection for Cipher Key Sequence Number
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_common_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);

	switch (oct & 0x07)
	{
	case 0x07:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: No key is available",
	    a_bigbuf);
	break;

	default:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: %u",
	    a_bigbuf,
	    oct & 0x07);
	break;
	}

	curr_offset++;
	curr_len--;

	if (curr_len <= 0) return;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, "");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	ELEM_OPT_TV(0x13, GSM_A_PDU_TYPE_COMMON, DE_LAI, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.5a
 */
static void
dtap_mm_cm_srvc_prompt(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_PD_SAPI);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.2.6
 */
static void
dtap_mm_cm_srvc_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.2.8
 */
static void
dtap_mm_abort(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.9
 */
static void
dtap_mm_cm_srvc_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8	oct;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	/*
	 * special dissection for CM Service Type
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_common_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);

	switch ((oct & 0x70) >> 4)
	{
	case 0x07:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: No key is available",
	    a_bigbuf);
	break;

	default:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: %u",
	    a_bigbuf,
	    (oct & 0x70) >> 4);
	break;
	}

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_CM_SRVC_TYPE].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CM_SRVC_TYPE]);

	switch (oct & 0x0f)
	{
	case 0x01: str = "Mobile originating call establishment or packet mode connection establishment"; break;
	case 0x02: str = "Emergency call establishment"; break;
	case 0x04: str = "Short message service"; break;
	case 0x08: str = "Supplementary service activation"; break;
	case 0x09: str = "Voice group call establishment"; break;
	case 0x0a: str = "Voice broadcast call establishment"; break;
	case 0x0b: str = "Location Services"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Service Type: (%u) %s",
	a_bigbuf,
	oct & 0x0f,
	str);

	curr_offset++;
	curr_len--;

	if (curr_len <= 0) return;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, "");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_PRIO, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.10
 */
static void
dtap_mm_id_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint8	oct;
	guint32	curr_offset;
	guint	curr_len;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	/*
	 * special dissection for Identity Type
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_ID_TYPE].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_ID_TYPE]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch (oct & 0x07)
	{
	case 1: str = "IMSI"; break;
	case 2: str = "IMEI"; break;
	case 3: str = "IMEISV"; break;
	case 4: str = "TMSI"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Type of identity: %s",
	a_bigbuf,
	str);

	curr_offset++;
	curr_len--;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.11
 */
static void
dtap_mm_id_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.12
 */
static void
dtap_mm_imsi_det_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_1);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.13
 */
static void
dtap_mm_loc_upd_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI);

	ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	ELEM_OPT_T(0xa1, GSM_A_PDU_TYPE_DTAP, DE_FOP, "");

	ELEM_OPT_T(0xa2, GSM_A_PDU_TYPE_DTAP, DE_CTS_PERM, "");

	ELEM_OPT_TLV(0x4a, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, " Equivalent");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.14
 */
static void
dtap_mm_loc_upd_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.15
 */
static void
dtap_mm_loc_upd_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8	oct;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	/*
	 * special dissection for Location Updating Type
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_common_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);

	switch ((oct & 0x70) >> 4)
	{
	case 0x07:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: No key is available",
	    a_bigbuf);
	break;

	default:
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Ciphering Key Sequence Number: %u",
	    a_bigbuf,
	    (oct & 0x70) >> 4);
	break;
	}

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_LOC_UPD_TYPE].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_LOC_UPD_TYPE]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Follow-On Request (FOR): %s",
	a_bigbuf,
	(oct & 0x08) ? "Follow-on request pending" : "No follow-on request pending");

	other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	switch (oct & 0x03)
	{
	case 0: str = "Normal"; break;
	case 1: str = "Periodic"; break;
	case 2: str = "IMSI attach"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Updating Type: %s",
	a_bigbuf,
	str);

	proto_item_append_text(item, " - %s", str);

	curr_offset++;
	curr_len--;

	if (curr_len <= 0) return;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI);

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_1);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}


/*
 * [4] 9.2.15a
 */
void
dtap_mm_mm_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full Name");

	ELEM_OPT_TLV(0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");

	ELEM_OPT_TV(0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");

	ELEM_OPT_TV(0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");

	ELEM_OPT_TLV(0x48, GSM_A_PDU_TYPE_DTAP, DE_LSA_ID, "");

	ELEM_OPT_TLV(0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.2.16
 */
static void
dtap_mm_mm_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [3] 9.2.17
 */
static void
dtap_mm_tmsi_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.1
 */
static void
dtap_cc_alerting(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, "");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.2
 */
static void
dtap_cc_call_conf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

	ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_DTAP, DE_CC_CAP, "");

	ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, "");

	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.3
 */
static void
dtap_cc_call_proceed(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, "");

	ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_PRIO, "");

	ELEM_OPT_TLV(0x2f, GSM_A_PDU_TYPE_DTAP, DE_NET_CC_CAP, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.4
 */
static void
dtap_cc_congestion_control(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8	oct;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	/*
	 * special dissection for Congestion Level
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_CONGESTION].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CONGESTION]);

	switch (oct & 0x0f)
	{
	case 0: str = "Receiver ready"; break;
	case 15: str = "Receiver not ready"; break;
	default:
	str = "Reserved";
	break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Congestion level: %s",
	a_bigbuf,
	str);

	curr_offset++;
	curr_len--;

	if (curr_len <= 0) return;

	ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.5
 */
static void
dtap_cc_connect(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, "");

	ELEM_OPT_TLV(0x4c, GSM_A_PDU_TYPE_DTAP, DE_CONN_NUM, "");

	ELEM_OPT_TLV(0x4d, GSM_A_PDU_TYPE_DTAP, DE_CONN_SUB_ADDR, "");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.7
 */
static void
dtap_cc_disconnect(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, "");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	ELEM_OPT_TLV(0x7b, GSM_A_PDU_TYPE_DTAP, DE_ALLOWED_ACTIONS, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.8
 */
static void
dtap_cc_emerg_setup(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

	ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, "");

	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

	ELEM_OPT_TLV(0x2e, GSM_A_PDU_TYPE_DTAP, DE_SRVC_CAT, " Emergency");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.9
 */
static void
dtap_cc_facility(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.12
 */
static void
dtap_cc_hold_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.13
 */
static void
dtap_cc_modify(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

	ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, "");

	ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, "");

	ELEM_OPT_T(0xa3, GSM_A_PDU_TYPE_DTAP, DE_REV_CALL_SETUP_DIR, "");

	ELEM_OPT_T(0xa4, GSM_A_PDU_TYPE_DTAP, DE_IMM_MOD_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.14
 */
static void
dtap_cc_modify_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

	ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, "");

	ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, "");

	ELEM_OPT_T(0xa3, GSM_A_PDU_TYPE_DTAP, DE_REV_CALL_SETUP_DIR, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.15
 */
static void
dtap_cc_modify_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, "");

	ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.16
 */
static void
dtap_cc_notify(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_NOT_IND);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.17
 */
static void
dtap_cc_progress(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, "");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.17a
 */
static void
dtap_cc_cc_est(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_SETUP_CONTAINER, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.17b
 */
static void
dtap_cc_cc_est_conf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " Repeat indicator");

	ELEM_MAND_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

	ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.18
 */
static void
dtap_cc_release(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, " 2");

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.18a
 */
static void
dtap_cc_recall(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RECALL_TYPE);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.19
 */
static void
dtap_cc_release_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.22
 */
static void
dtap_cc_retrieve_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.23
 * 3GPP TS 24.008 version 7.5.0 Release 7
 */
static void
dtap_cc_setup(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, "");

	ELEM_OPT_TV(0x34, GSM_A_PDU_TYPE_DTAP, DE_SIGNAL, "");

	ELEM_OPT_TLV(0x5c, GSM_A_PDU_TYPE_DTAP, DE_CLG_PARTY_BCD_NUM, "");

	ELEM_OPT_TLV(0x5d, GSM_A_PDU_TYPE_DTAP, DE_CLG_PARTY_SUB_ADDR, "");

	ELEM_OPT_TLV(0x5e, GSM_A_PDU_TYPE_DTAP, DE_CLD_PARTY_BCD_NUM, "");

	ELEM_OPT_TLV(0x6d, GSM_A_PDU_TYPE_DTAP, DE_CLD_PARTY_SUB_ADDR, "");

	ELEM_OPT_TLV(0x74, GSM_A_PDU_TYPE_DTAP, DE_RED_PARTY_BCD_NUM, "");

	ELEM_OPT_TLV(0x75, GSM_A_PDU_TYPE_DTAP, DE_RED_PARTY_SUB_ADDR, "");

	ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " LLC repeat indicator");

	ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, " 1");

	ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, " 2");

	ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " HLC repeat indicator");

	ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, " 1");

	ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, " 2");

	ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	/* downlink only */

	ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_PRIO, "");

	ELEM_OPT_TLV(0x19, GSM_A_PDU_TYPE_DTAP, DE_ALERT_PATTERN, "");

	ELEM_OPT_TLV(0x2f, GSM_A_PDU_TYPE_DTAP, DE_NET_CC_CAP, "");

	ELEM_OPT_TLV(0x3a, GSM_A_PDU_TYPE_DTAP, DE_CAUSE_NO_CLI, "");

	/* Backup bearer capability O TLV 3-15 10.5.4.4a */
	ELEM_OPT_TLV(0x41, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

	/* uplink only */

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	ELEM_OPT_T(0xa1, GSM_A_PDU_TYPE_DTAP, DE_CLIR_SUP, "");

	ELEM_OPT_T(0xa2, GSM_A_PDU_TYPE_DTAP, DE_CLIR_INV, "");

	ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_DTAP, DE_CC_CAP, "");

	ELEM_OPT_TLV(0x1d, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, " $(CCBS)$ (advanced recall alignment)");

	ELEM_OPT_TLV(0x1b, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, " (recall alignment Not essential) $(CCBS)$");

	ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, "");

	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

	/*A3 Redial Redial O T 1 10.5.4.34
	 * TODO add this element
	 * ELEM_OPT_T(0xA3, GSM_A_PDU_TYPE_DTAP, DE_REDIAL, "");
	 */

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.23a
 */
static void
dtap_cc_start_cc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_DTAP, DE_CC_CAP, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.24
 */
static void
dtap_cc_start_dtmf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_TV(0x2c, GSM_A_PDU_TYPE_DTAP, DE_KEYPAD_FACILITY, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.25
 */
static void
dtap_cc_start_dtmf_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_TV(0x2c, GSM_A_PDU_TYPE_DTAP, DE_KEYPAD_FACILITY, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.26
 */
static void
dtap_cc_start_dtmf_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.27
 */
static void
dtap_cc_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, "");

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_CALL_STATE);

	ELEM_OPT_TLV(0x24, GSM_A_PDU_TYPE_DTAP, DE_AUX_STATES, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.31
 */
static void
dtap_cc_user_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "");

	ELEM_OPT_T(0xa0, GSM_A_PDU_TYPE_DTAP, DE_MORE_DATA, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [6] 2.4.2
 */
static void
dtap_ss_register(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, "");

	ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.2.1
 */
static void
dtap_sms_cp_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CP_USER_DATA, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.2.3
 */
static void
dtap_sms_cp_error(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_CP_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.1
 */
static void
dtap_gmm_attach_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_MS_NET_CAP, "");

	/* Included in attach type

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM );
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_ATTACH_TYPE );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_DRX_PARAM );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_MS_RAD_ACC_CAP , "" );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_DTAP, DE_P_TMSI_SIG, " - Old P-TMSI Signature");

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Ready Timer" );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_DTAP, DE_TMSI_STAT , "" );

	ELEM_OPT_TLV( 0x33 , GSM_A_PDU_TYPE_DTAP, DE_PS_LCS_CAP , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.2
 */
static void
dtap_gmm_attach_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H );
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_ATTACH_RES );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAD_PRIO_2 );
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAD_PRIO );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAI );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_DTAP, DE_P_TMSI_SIG, "" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Negotiated Ready Timer" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI" );

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE , "" );

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );

	ELEM_OPT_T( 0x8C , GSM_A_PDU_TYPE_DTAP, DE_CELL_NOT , "" );

	ELEM_OPT_TLV( 0x4A , GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST , "" );

	ELEM_OPT_TV_SHORT( 0xB0 , GSM_A_PDU_TYPE_DTAP, DE_NET_FEAT_SUP , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.3
 */
static void
dtap_gmm_attach_com(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{

	guint32	curr_offset;
/*    guint32	consumed; */
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.4
 */
static void
dtap_gmm_attach_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE );

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.5
 */
static void
dtap_gmm_detach_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H );
	/* Force to standy might be wrong - To decode it correct, we need the direction */
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_DETACH_TYPE );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE , "" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI" );

	ELEM_OPT_TLV( 0x19 , GSM_A_PDU_TYPE_DTAP, DE_P_TMSI_SIG , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.6
 */
static void
dtap_gmm_detach_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	if ( curr_len != 0 )
	{
		ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
		curr_len++;
		curr_offset--;
	
		ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );
	}

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.7
 */
static void
dtap_gmm_ptmsi_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAI );

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI Signature" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.8
 */
static void
dtap_gmm_ptmsi_realloc_com(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
/*    guint32	consumed; */
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.9
 */
static void
dtap_gmm_auth_ciph_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8      oct;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_IMEISV_REQ );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_CIPH_ALG );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AC_REF_NUM_H );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );

	ELEM_OPT_TV( 0x21 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND , "" );

#if 0
	ELEM_OPT_TV_SHORT( 0x08 , GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM , "" );
#else
	if ( curr_len > 0 )
	{
	    oct = tvb_get_guint8(tvb, curr_offset);
	    if (( oct & 0xf0 ) == 0x80 )
	    {
			/* The ciphering key sequence number is added here */
	    	proto_tree_add_text(tree,
				tvb, curr_offset, 1,
				"Ciphering key sequence number: 0x%02x (%u)",
	    		oct&7,
				oct&7);
	    	curr_offset++;
			curr_len--;
		    }
	}
#endif

	if ( curr_len == 0  )
	{
		EXTRANEOUS_DATA_CHECK(curr_len, 0);
	return;
	}
	
	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.10
 */
static void
dtap_gmm_auth_ciph_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AC_REF_NUM );

	ELEM_OPT_TV( 0x22 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM , "" );

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - IMEISV" );

	ELEM_OPT_TLV( 0x29 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.11
 */
static void
dtap_gmm_auth_ciph_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
/*    guint32	consumed; */
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.10a
 */
static void
dtap_gmm_auth_ciph_fail(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE );

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.12
 */
static void
dtap_gmm_ident_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

/*  If the half octect that are about to get decoded is the LAST in the octetstream, the macro will call return BEFORE we get a chance to fix the index. The end result will be that the first half-octet will be decoded but not the last. */
/*    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_ID_TYPE_2 );
	curr_offset--;
	curr_len++;
	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H );*/

	elem_v(tvb, tree, GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H, curr_offset);
	elem_v(tvb, tree, GSM_A_PDU_TYPE_DTAP, DE_ID_TYPE_2, curr_offset);

	curr_offset+=1;
	curr_len-=1;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.13
 */
static void
dtap_gmm_ident_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.14
 */
static void
dtap_gmm_rau_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	/* is included in update type
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM );
	curr_offset--;
	curr_len++;

	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_UPD_TYPE );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_MS_RAD_ACC_CAP , "" );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_DTAP, DE_P_TMSI_SIG , " - Old P-TMSI Signature" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Requested Ready Timer" );

	ELEM_OPT_TV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_DRX_PARAM , "" );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_DTAP, DE_TMSI_STAT , "" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI" );

	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_DTAP, DE_MS_NET_CAP , "" );

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );

	ELEM_OPT_TLV( 0x33 , GSM_A_PDU_TYPE_DTAP, DE_PS_LCS_CAP , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.15
 */
static void
dtap_gmm_rau_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_UPD_RES );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAI );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_DTAP, DE_P_TMSI_SIG , "" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI");

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_DTAP, DE_REC_N_PDU_NUM_LIST , "" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Negotiated Ready Timer" );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE , "" );

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );

	ELEM_OPT_T( 0x8C , GSM_A_PDU_TYPE_DTAP, DE_CELL_NOT , "" );

	ELEM_OPT_TLV( 0x4A , GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST , "" );

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );

	ELEM_OPT_TV_SHORT ( 0xB0 , GSM_A_PDU_TYPE_DTAP, DE_NET_FEAT_SUP , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.16
 */
static void
dtap_gmm_rau_com(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;
	/* [7] 10.5.5.11 */
	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_DTAP, DE_REC_N_PDU_NUM_LIST , "" );
	/* Inter RAT information container 10.5.5.24 TS 24.008 version 6.8.0 Release 6 */
	/*TO DO: Implement */
	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_RAT_INFO_CONTAINER , "" );
	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.17
 */
static void
dtap_gmm_rau_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE );

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );

	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.18
 */
static void
dtap_gmm_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	 is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.4.19 GMM Information
 */
static void
dtap_gmm_information(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x43 , GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Full Name" );

	ELEM_OPT_TLV( 0x45 , GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Short Name" );

	ELEM_OPT_TV( 0x46 , GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE , "" );

	ELEM_OPT_TV( 0x47 , GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME , "" );

	ELEM_OPT_TLV( 0x48 , GSM_A_PDU_TYPE_DTAP, DE_LSA_ID , "" );

	ELEM_OPT_TLV( 0x49 , GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.20
 */
static void
dtap_gmm_service_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_TRUE;
	g_pinfo->p2p_dir = P2P_DIR_RECV;

	/* Is included in SRVC TYPE
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM );
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SRVC_TYPE );

	/* P-TMSI Mobile station identity 10.5.1.4 M LV 6 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.21
 */
static void
dtap_gmm_service_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.22
 */
static void
dtap_gmm_service_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_FALSE;
	g_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GMM_CAUSE );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.1 Activate PDP context request
 */
static void
dtap_sm_act_pdp_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_NET_SAPI );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_QOS , " - Requested QoS" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , " - Requested PDP address" );

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_DTAP, DE_ACC_POINT_NAME , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.2 Activate PDP context accept
 */
static void
dtap_sm_act_pdp_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_QOS , " - Negotiated QoS" );

#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SPARE );
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAD_PRIO );

	ELEM_OPT_TLV( 0x2B , GSM_A_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.3 Activate PDP context reject
 */
static void
dtap_sm_act_pdp_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.4 Activate Secondary PDP Context Request
 */
static void
dtap_sm_act_sec_pdp_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_NET_SAPI );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_QOS , " - Requested QoS" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_LINKED_TI , "" );

	/* 3GPP TS 24.008 version 6.8.0 Release 6, 36 TFT Traffic Flow Template 10.5.6.12 O TLV 3-257 */
	ELEM_OPT_TLV( 0x36 , GSM_A_PDU_TYPE_DTAP, DE_TRAFFIC_FLOW_TEMPLATE , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.5.5
 */
static void
dtap_sm_act_sec_pdp_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_QOS , " - Negotiated QoS" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RAD_PRIO);

#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SPARE );
	curr_offset--;
	curr_len++;
#endif

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.6 Activate Secondary PDP Context Reject
 */
static void
dtap_sm_act_sec_pdp_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.7 Request PDP context activation
 */
static void
dtap_sm_req_pdp_act(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , " - Offered PDP address" );

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_DTAP, DE_ACC_POINT_NAME , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.8 Request PDP context activation reject
 */
static void
dtap_sm_req_pdp_act_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.9 Modify PDP context request (Network to MS direction)
 */
static void
dtap_sm_mod_pdp_req_net(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP,DE_RAD_PRIO);
#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SPARE );
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_QOS , " - New QoS" );

	ELEM_OPT_TLV( 0x2B , GSM_A_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.10 Modify PDP context request (MS to network direction)
 */
static void
dtap_sm_mod_pdp_req_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI , " - Requested LLC SAPI" );

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_DTAP, DE_QOS , " - Requested new QoS" );

	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_DTAP, DE_TRAFFIC_FLOW_TEMPLATE , " - New TFT" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.11 Modify PDP context accept (MS to network direction)
 */
static void
dtap_sm_mod_pdp_acc_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.12 Modify PDP context accept (Network to MS direction)
 */
static void
dtap_sm_mod_pdp_acc_net(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_DTAP, DE_QOS , " - Negotiated QoS" );

	ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_DTAP, DE_LLC_SAPI , " - Negotiated LLC SAPI" );

	ELEM_OPT_TV_SHORT ( 0x80 , GSM_A_PDU_TYPE_DTAP , DE_RAD_PRIO , " - New radio priority" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.13 Modify PDP Context Reject
 */
static void
dtap_sm_mod_pdp_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.14 Deactivate PDP context request
 */
static void
dtap_sm_deact_pdp_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SM_CAUSE );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_DTAP , DE_TEAR_DOWN_IND , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}


/*
 * [8] 9.5.15 Deactivate PDP context accept
 */
static void
dtap_sm_deact_pdp_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	 is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.21 SM Status
 */
static void
dtap_sm_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	 is_uplink = IS_UPLINK_UNKNOWN;
	g_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_SM_CAUSE );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.22 Activate MBMS Context Request
 */

	/* Requested MBMS NSAPI Enhanced Network service access point identifier 10.5.6.15 M V */
	/* Requested LLC SAPI LLC service access point identifier 10.5.6.9 M V 1 */
	/* Supported MBMS bearer capabilities MBMS bearer capabilities 10.5.6.14 M LV 2 - 3 */
	/* Requested multicast address Packet data protocol address 10.5.6.4 M LV 3 - 19 */
	/* Access point name Access point name 10.5.6.1 M LV 2 - 101 */
	/* 35 MBMS protocol configuration options MBMS protocol configuration options 10.5.6.15 O TLV 3 - 253 */

/*
 * [8] 9.5.23 Activate MBMS Context Accept
 */

/*
 * [8] 9.5.24 Activate MBMS Context Reject
 */

/*
 * [8] 9.5.25 Request MBMS Context Activation
 */

/*
 * [8] 9.5.26 Request MBMS Context Activation Reject
 */

static void
dtap_tp_close_tch_loop_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_SUB_CHANNEL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_open_loop_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    if (curr_len)
        ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_ACK );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_multi_slot_loop_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_LOOP_TYPE );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_multi_slot_loop_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_LOOP_ACK );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_test_interface(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_TESTED_DEVICE );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_gprs_test_mode_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_PDU_DESCRIPTION );

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_MODE_FLAG );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_egprs_start_radio_block_loopback_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EGPRS_MODE_FLAG );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_close_ue_test_loop(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_UE_TEST_LOOP_MODE );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_reset_ue_positioning_ue_stored_information(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_UE_POSITIONING_TECHNOLOGY );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_tp_ue_test_loop_mode_3_rlc_sdu_counter_response(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_RLC_SDU_COUNTER_VALUE );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

#define	NUM_GSM_DTAP_MSG_MM (sizeof(gsm_a_dtap_msg_mm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_mm[NUM_GSM_DTAP_MSG_MM];
static void (*dtap_msg_mm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_mm_imsi_det_ind,	/* IMSI Detach Indication */
	dtap_mm_loc_upd_acc,	/* Location Updating Accept */
	dtap_mm_loc_upd_rej,	/* Location Updating Reject */
	dtap_mm_loc_upd_req,	/* Location Updating Request */
	NULL /* no associated data */,	/* Authentication Reject */
	dtap_mm_auth_req,	/* Authentication Request */
	dtap_mm_auth_resp,	/* Authentication Response */
	dtap_mm_auth_fail,	/* Authentication Failure */
	dtap_mm_id_req,	/* Identity Request */
	dtap_mm_id_resp,	/* Identity Response */
	dtap_mm_tmsi_realloc_cmd,	/* TMSI Reallocation Command */
	NULL /* no associated data */,	/* TMSI Reallocation Complete */
	NULL /* no associated data */,	/* CM Service Accept */
	dtap_mm_cm_srvc_rej,	/* CM Service Reject */
	NULL /* no associated data */,	/* CM Service Abort */
	dtap_mm_cm_srvc_req,	/* CM Service Request */
	dtap_mm_cm_srvc_prompt,	/* CM Service Prompt */
	NULL,	/* Reserved: was allocated in earlier phases of the protocol */
	dtap_mm_cm_reestab_req,	/* CM Re-establishment Request */
	dtap_mm_abort,	/* Abort */
	NULL /* no associated data */,	/* MM Null */
	dtap_mm_mm_status,	/* MM Status */
	dtap_mm_mm_info,	/* MM Information */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_CC (sizeof(gsm_a_dtap_msg_cc_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_cc[NUM_GSM_DTAP_MSG_CC];
static void (*dtap_msg_cc_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_cc_alerting,	/* Alerting */
	dtap_cc_call_conf,	/* Call Confirmed */
	dtap_cc_call_proceed,	/* Call Proceeding */
	dtap_cc_connect,	/* Connect */
	NULL /* no associated data */,	/* Connect Acknowledge */
	dtap_cc_emerg_setup,	/* Emergency Setup */
	dtap_cc_progress,	/* Progress */
	dtap_cc_cc_est,	/* CC-Establishment */
	dtap_cc_cc_est_conf,	/* CC-Establishment Confirmed */
	dtap_cc_recall,	/* Recall */
	dtap_cc_start_cc,	/* Start CC */
	dtap_cc_setup,	/* Setup */
	dtap_cc_modify,	/* Modify */
	dtap_cc_modify_complete,	/* Modify Complete */
	dtap_cc_modify_rej,	/* Modify Reject */
	dtap_cc_user_info,	/* User Information */
	NULL /* no associated data */,	/* Hold */
	NULL /* no associated data */,	/* Hold Acknowledge */
	dtap_cc_hold_rej,	/* Hold Reject */
	NULL /* no associated data */,	/* Retrieve */
	NULL /* no associated data */,	/* Retrieve Acknowledge */
	dtap_cc_retrieve_rej,	/* Retrieve Reject */
	dtap_cc_disconnect,	/* Disconnect */
	dtap_cc_release,	/* Release */
	dtap_cc_release_complete,	/* Release Complete */
	dtap_cc_congestion_control,	/* Congestion Control */
	dtap_cc_notify,	/* Notify */
	dtap_cc_status,	/* Status */
	NULL /* no associated data */,	/* Status Enquiry */
	dtap_cc_start_dtmf,	/* Start DTMF */
	NULL /* no associated data */,	/* Stop DTMF */
	NULL /* no associated data */,	/* Stop DTMF Acknowledge */
	dtap_cc_start_dtmf_ack,	/* Start DTMF Acknowledge */
	dtap_cc_start_dtmf_rej,	/* Start DTMF Reject */
	dtap_cc_facility,	/* Facility */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_GMM (sizeof(gsm_a_dtap_msg_gmm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_gmm[NUM_GSM_DTAP_MSG_GMM];
static void (*dtap_msg_gmm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_gmm_attach_req,		/* Attach Request */
	dtap_gmm_attach_acc,		/* Attach Accept */
	dtap_gmm_attach_com,		/* Attach Complete */
	dtap_gmm_attach_rej,		/* Attach Reject */
	dtap_gmm_detach_req,		/* Detach Request */
	dtap_gmm_detach_acc,		/* Detach Accept */
	dtap_gmm_rau_req,			/* Routing Area Update Request */
	dtap_gmm_rau_acc,			/* Routing Area Update Accept */
	dtap_gmm_rau_com,			/* Routing Area Update Complete */
	dtap_gmm_rau_rej,			/* Routing Area Update Reject */
	dtap_gmm_service_req,		/* Service Request */
	dtap_gmm_service_acc,		/* Service Accept */
	dtap_gmm_service_rej,		/* Service Reject */
	dtap_gmm_ptmsi_realloc_cmd,	/* P-TMSI Reallocation Command */
	dtap_gmm_ptmsi_realloc_com,	/* P-TMSI Reallocation Complete */
	dtap_gmm_auth_ciph_req,		/* Authentication and Ciphering Req */
	dtap_gmm_auth_ciph_resp,	/* Authentication and Ciphering Resp */
	dtap_gmm_auth_ciph_rej,		/* Authentication and Ciphering Rej */
	dtap_gmm_auth_ciph_fail,	/* Authentication and Ciphering Failure */
	dtap_gmm_ident_req,			/* Identity Request */
	dtap_gmm_ident_res,			/* Identity Response */
	dtap_gmm_status,			/* GMM Status */
	dtap_gmm_information,		/* GMM Information */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_SMS (sizeof(gsm_a_dtap_msg_sms_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_sms[NUM_GSM_DTAP_MSG_SMS];
static void (*dtap_msg_sms_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_sms_cp_data,	/* CP-DATA */
	NULL /* no associated data */,	/* CP-ACK */
	dtap_sms_cp_error,	/* CP-ERROR */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_SM (sizeof(gsm_a_dtap_msg_sm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_sm[NUM_GSM_DTAP_MSG_SM];
static void (*dtap_msg_sm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_sm_act_pdp_req,		/* Activate PDP Context Request */
	dtap_sm_act_pdp_acc,		/* Activate PDP Context Accept */
	dtap_sm_act_pdp_rej,		/* Activate PDP Context Reject */
	dtap_sm_req_pdp_act,		/* Request PDP Context Activation */
	dtap_sm_req_pdp_act_rej,	/* Request PDP Context Activation rej. */
	dtap_sm_deact_pdp_req,		/* Deactivate PDP Context Request */
	dtap_sm_deact_pdp_acc,		/* Deactivate PDP Context Accept */
	dtap_sm_mod_pdp_req_net,	/* Modify PDP Context Request(Network to MS direction) */
	dtap_sm_mod_pdp_acc_ms,		/* Modify PDP Context Accept (MS to network direction) */
	dtap_sm_mod_pdp_req_ms,		/* Modify PDP Context Request(MS to network direction) */
	dtap_sm_mod_pdp_acc_net,	/* Modify PDP Context Accept (Network to MS direction) */
	dtap_sm_mod_pdp_rej,		/* Modify PDP Context Reject */
	dtap_sm_act_sec_pdp_req,	/* Activate Secondary PDP Context Request */
	dtap_sm_act_sec_pdp_acc,	/* Activate Secondary PDP Context Accept */
	dtap_sm_act_sec_pdp_rej,	/* Activate Secondary PDP Context Reject */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	dtap_sm_status,				/* SM Status */
								/* Activate MBMS Context Request */
								/* Activate MBMS Context Accept */
								/* Activate MBMS Context Reject */
								/* Request MBMS Context Activation */
								/* Request MBMS Context Activation Reject */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_SS (sizeof(gsm_a_dtap_msg_ss_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_ss[NUM_GSM_DTAP_MSG_SS];
static void (*dtap_msg_ss_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_cc_release_complete,	/* Release Complete */
	dtap_cc_facility,	/* Facility */
	dtap_ss_register,	/* Register */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_TP (sizeof(gsm_a_dtap_msg_tp_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_tp[NUM_GSM_DTAP_MSG_TP];
static void (*dtap_msg_tp_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
    dtap_tp_close_tch_loop_cmd,	/* CLOSE TCH LOOP CMD */
    NULL,	/* CLOSE TCH LOOP ACK */
    dtap_tp_open_loop_cmd,	/* OPEN LOOP CMD */
    NULL,	/* ACT EMMI CMD */
    NULL,	/* ACT EMMI ACK */
    NULL,	/* DEACT EMMI */
    dtap_tp_test_interface,	/* Test Interface */
    dtap_tp_multi_slot_loop_cmd,	/* CLOSE Multi-slot LOOP CMD */
    dtap_tp_multi_slot_loop_ack,	/* CLOSE Multi-slot LOOP ACK */
    NULL,	/* OPEN Multi-slot LOOP CMD */
    NULL,	/* OPEN Multi-slot LOOP ACK */
    dtap_tp_gprs_test_mode_cmd,	/* GPRS TEST MODE CMD */
    dtap_tp_egprs_start_radio_block_loopback_cmd,	/* EGPRS START RADIO BLOCK LOOPBACK CMD */
    dtap_tp_close_ue_test_loop,	/* CLOSE UE TEST LOOP */
    NULL,	/* CLOSE UE TEST LOOP COMPLETE */
    NULL,	/* OPEN UE TEST LOOP */
    NULL,	/* OPEN UE TEST LOOP COMPLETE */
    NULL,	/* ACTIVATE RB TEST MODE */
    NULL,	/* ACTIVATE RB TEST MODE COMPLETE */
    NULL,	/* DEACTIVATE RB TEST MODE */
    NULL,	/* DEACTIVATE RB TEST MODE COMPLETE */
    dtap_tp_reset_ue_positioning_ue_stored_information,	/* RESET UE POSITIONING STORED INFORMATION */
    NULL,	/* UE Test Loop Mode 3 RLC SDU Counter Request */
    dtap_tp_ue_test_loop_mode_3_rlc_sdu_counter_response,	/* UE Test Loop Mode 3 RLC SDU Counter Response */
    NULL,	/* NONE */
};

/* GENERIC DISSECTOR FUNCTIONS */


static void
dissect_dtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	static gsm_a_tap_rec_t	tap_rec[4];
	static gsm_a_tap_rec_t	*tap_p;
	static guint			tap_current=0;
	void			(*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);
	guint8			oct;
	guint8			pd;
	guint32			offset;
	guint32			len;
	guint32			oct_1, oct_2;
	gint			idx;
	proto_item			*dtap_item = NULL;
	proto_tree			*dtap_tree = NULL;
	proto_item			*oct_1_item = NULL;
	proto_tree			*pd_tree = NULL;
	const gchar			*msg_str;
	gint			ett_tree;
	gint			ti;
	int				hf_idx;
	gboolean			nsd;


	len = tvb_length(tvb);

	if (len < 2)
	{
	/*
	 * too short to be DTAP
	 */
	call_dissector(data_handle, tvb, pinfo, tree);
	return;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	{
	col_append_str(pinfo->cinfo, COL_INFO, "(DTAP) ");
	}

	/*
	 * set tap record pointer
	 */
	tap_current++;
	if (tap_current >= 4)
	{
	tap_current = 0;
	}
	tap_p = &tap_rec[tap_current];


	offset = 0;
	oct_2 = 0;

	g_pinfo = pinfo;
	g_tree = tree;

	/*
	 * get protocol discriminator
	 */
	oct_1 = tvb_get_guint8(tvb, offset++);

	if ((((oct_1 & DTAP_TI_MASK) >> 4) & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK)
	{
	/*
	 * eventhough we don't know if a TI should be in the message yet
	 * we rely on the TI/SKIP indicator to be 0 to avoid taking this
	 * octet
	 */
	oct_2 = tvb_get_guint8(tvb, offset++);
	}

	oct = tvb_get_guint8(tvb, offset);

	pd = oct_1 & DTAP_PD_MASK;
	ti = -1;
	msg_str = NULL;
	ett_tree = -1;
	hf_idx = -1;
	msg_fcn = NULL;
	nsd = FALSE;
	if (check_col(pinfo->cinfo, COL_INFO))
	{
	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",val_to_str(pd,gsm_a_pd_short_str_vals,"unknown"));
	}

	/*
	 * octet 1
	 */
	switch (pd)
	{
	case 3:
	msg_str = match_strval_idx((guint32) (oct & DTAP_CC_IEI_MASK), gsm_a_dtap_msg_cc_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_cc[idx];
	hf_idx = hf_gsm_a_dtap_msg_cc_type;
	msg_fcn = dtap_msg_cc_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	nsd = TRUE;
	break;

	case 5:
	msg_str = match_strval_idx((guint32) (oct & DTAP_MM_IEI_MASK), gsm_a_dtap_msg_mm_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_mm[idx];
	hf_idx = hf_gsm_a_dtap_msg_mm_type;
	msg_fcn = dtap_msg_mm_fcn[idx];
	nsd = TRUE;
	break;

	case 6:
		get_rr_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn);
	break;

	case 8:
	msg_str = match_strval_idx((guint32) (oct & DTAP_GMM_IEI_MASK), gsm_a_dtap_msg_gmm_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_gmm[idx];
	hf_idx = hf_gsm_a_dtap_msg_gmm_type;
	msg_fcn = dtap_msg_gmm_fcn[idx];
	break;

	case 9:
	msg_str = match_strval_idx((guint32) (oct & DTAP_SMS_IEI_MASK), gsm_a_dtap_msg_sms_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_sms[idx];
	hf_idx = hf_gsm_a_dtap_msg_sms_type;
	msg_fcn = dtap_msg_sms_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	break;

	case 10:
	msg_str = match_strval_idx((guint32) (oct & DTAP_SM_IEI_MASK), gsm_a_dtap_msg_sm_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_sm[idx];
	hf_idx = hf_gsm_a_dtap_msg_sm_type;
	msg_fcn = dtap_msg_sm_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	break;

	case 11:
	msg_str = match_strval_idx((guint32) (oct & DTAP_SS_IEI_MASK), gsm_a_dtap_msg_ss_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_ss[idx];
	hf_idx = hf_gsm_a_dtap_msg_ss_type;
	msg_fcn = dtap_msg_ss_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	nsd = TRUE;
	break;

    case 15:
	msg_str = match_strval_idx((guint32) (oct & DTAP_TP_IEI_MASK), gsm_a_dtap_msg_tp_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_tp[idx];
	hf_idx = hf_gsm_a_dtap_msg_tp_type;
	msg_fcn = dtap_msg_tp_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	nsd = TRUE;
	break;

	default:
	/* XXX - hf_idx is still -1! this is a bug in the implementation, and I don't know how to fix it so simple return here */
	return;
	}

	sccp_msg = pinfo->sccp_info;

	if (sccp_msg && sccp_msg->data.co.assoc) {
		sccp_assoc = sccp_msg->data.co.assoc;
	} else {
		sccp_assoc = NULL;
		sccp_msg = NULL;
	}

	/*
	 * create the protocol tree
	 */
	if (msg_str == NULL)
	{
	dtap_item =
	    proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, len,
		"GSM A-I/F DTAP - Unknown DTAP Message Type (0x%02x)",
		oct);

	dtap_tree = proto_item_add_subtree(dtap_item, ett_dtap_msg);

	if (sccp_msg && !sccp_msg->data.co.label) {
		sccp_msg->data.co.label = se_strdup_printf("DTAP (0x%02x)",oct);
	}


	}
	else
	{
	dtap_item =
	    proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, -1,
		"GSM A-I/F DTAP - %s",
		msg_str);

	dtap_tree = proto_item_add_subtree(dtap_item, ett_tree);

	if (sccp_msg && !sccp_msg->data.co.label) {
		sccp_msg->data.co.label = se_strdup(msg_str);
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
	}
	}

	oct_1_item =
	proto_tree_add_text(dtap_tree,
	    tvb, 0, 1,
	    "Protocol Discriminator: %s",
	    val_to_str(pd, protocol_discriminator_vals, "Unknown (%u)"));

	pd_tree = proto_item_add_subtree(oct_1_item, ett_dtap_oct_1);

	if (ti == -1)
	{
	proto_tree_add_item(pd_tree, hf_gsm_a_skip_ind, tvb, 0, 1, FALSE);
	}
	else
	{
	other_decode_bitfield_value(a_bigbuf, oct_1, 0x80, 8);
	proto_tree_add_text(pd_tree,
	    tvb, 0, 1,
	    "%s :  TI flag: %s",
	    a_bigbuf,
	    ((oct_1 & 0x80) ?  "allocated by receiver" : "allocated by sender"));

	if ((ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK)
	{
	    /* ti is extended to next octet */

	    other_decode_bitfield_value(a_bigbuf, oct_1, 0x70, 8);
	    proto_tree_add_text(pd_tree,
		tvb, 0, 1,
		"%s :  TIO: The TI value is given by the TIE in octet 2",
		a_bigbuf);
	}
	else
	{
	    other_decode_bitfield_value(a_bigbuf, oct_1, 0x70, 8);
	    proto_tree_add_text(pd_tree,
		tvb, 0, 1,
		"%s :  TIO: %u",
		a_bigbuf,
		ti & DTAP_TIE_PRES_MASK);
	}
	}

	proto_tree_add_item(pd_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 0, 1, FALSE);

	if ((ti != -1) &&
	(ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK)
	{
	proto_tree_add_item(tree, hf_gsm_a_extension, tvb, 1, 1, FALSE);

	other_decode_bitfield_value(a_bigbuf, oct_2, DTAP_TIE_MASK, 8);
	proto_tree_add_text(pd_tree,
	    tvb, 1, 1,
	    "%s :  TIE: %u",
	    a_bigbuf,
	    oct_2 & DTAP_TIE_MASK);
	}

	/*
	 * N(SD)
	 */
	if ((pinfo->p2p_dir == P2P_DIR_RECV) &&
	nsd)
	{
	/* XXX */
	}

	/*
	 * add DTAP message name
	 */
	proto_tree_add_uint_format(dtap_tree, hf_idx,
	tvb, offset, 1, oct,
	"Message Type %s",msg_str ? msg_str : "(Unknown)");

	offset++;

	tap_p->pdu_type = GSM_A_PDU_TYPE_DTAP;
	tap_p->message_type = (nsd ? (oct & 0x3f) : oct);
	tap_p->protocol_disc = pd;

	tap_queue_packet(gsm_a_tap, pinfo, tap_p);

	if (msg_str == NULL) return;

	if ((len - offset) <= 0) return;

	/*
	 * decode elements
	 */
	if (msg_fcn == NULL)
	{
	proto_tree_add_text(dtap_tree,
	    tvb, offset, len - offset,
	    "Message Elements");
	}
	else
	{
	(*msg_fcn)(tvb, dtap_tree, offset, len - offset);
	}
}


/* Register the protocol with Wireshark */
void
proto_register_gsm_a_dtap(void)
{
	guint		i;
	guint		last_offset;

	/* Setup list of header fields */

	static hf_register_info hf[] =
	{
	{ &hf_gsm_a_dtap_msg_mm_type,
	    { "DTAP Mobility Management Message Type",	"gsm_a.dtap_msg_mm_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_mm_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_cc_type,
	    { "DTAP Call Control Message Type",	"gsm_a.dtap_msg_cc_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_cc_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_gmm_type,
	    { "DTAP GPRS Mobility Management Message Type",	"gsm_a.dtap_msg_gmm_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_gmm_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_sms_type,
	    { "DTAP Short Message Service Message Type",	"gsm_a.dtap_msg_sms_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_sms_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_sm_type,
	    { "DTAP GPRS Session Management Message Type",	"gsm_a.dtap_msg_sm_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_sm_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_ss_type,
	    { "DTAP Non call Supplementary Service Message Type",	"gsm_a.dtap_msg_ss_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_ss_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_tp_type,
	    { "DTAP Tests Procedures Message Type",	"gsm_a.dtap_msg_tp_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_tp_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_elem_id,
	    { "Element ID",	"gsm_a_dtap.elem_id",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_cld_party_bcd_num,
	    { "Called Party BCD Number",	"gsm_a.cld_party_bcd_num",
	    FT_STRING, BASE_DEC, 0, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_clg_party_bcd_num,
	    { "Calling Party BCD Number",	"gsm_a.clg_party_bcd_num",
	    FT_STRING, BASE_DEC, 0, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_cause,
	    { "DTAP Cause",	"gsm_a_dtap.cause",
	    FT_UINT8, BASE_HEX, 0, 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_qos_delay_cls,
		{ "Delay class", "gsm_a.qos.delay_cls",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_delay_cls_vals), 0x38,
		"Quality of Service Delay Class", HFILL }},
	{ &hf_gsm_a_qos_qos_reliability_cls,
		{ "Reliability class", "gsm_a.qos.delay_cls",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_delay_cls_vals), 0x07,
		"Reliability class", HFILL }},
	{ &hf_gsm_a_qos_traffic_cls,
	  { "Traffic class", "gsm_a.qos.traffic_cls",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0xe0,
		"Traffic class", HFILL }},
	{ &hf_gsm_a_qos_del_order,
	  { "Delivery order", "gsm_a.qos.del_order",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0x18,
		"Delivery order", HFILL }},
	{ &hf_gsm_a_qos_del_of_err_sdu,
	  { "Delivery of erroneous SDUs", "gsm_a.qos.del_of_err_sdu",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_del_of_err_sdu_vals), 0x03,
		"Delivery of erroneous SDUs", HFILL }},
	{ &hf_gsm_a_qos_ber,
	  { "Residual Bit Error Rate (BER)", "gsm_a.qos.ber",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_ber_vals), 0xf0,
		"Residual Bit Error Rate (BER)", HFILL }},
	{ &hf_gsm_a_qos_sdu_err_rat,
	  { "SDU error ratio", "gsm_a.qos.sdu_err_rat",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_sdu_err_rat_vals), 0x0f,
		"SDU error ratio", HFILL }},
	{ &hf_gsm_a_qos_traff_hdl_pri,
	  { "Traffic handling priority", "gsm_a.qos.traff_hdl_pri",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traff_hdl_pri_vals), 0x03,
		"Traffic handling priority", HFILL }},

	{ &hf_gsm_a_gmm_split_on_ccch,
		{ "SPLIT on CCCH","gsm_a.gmm.split_on_ccch",
		FT_BOOLEAN,8,  TFS(&gsm_a_gmm_split_on_ccch_value), 0x08,
		"SPLIT on CCCH", HFILL }
	},
	{ &hf_gsm_a_gmm_non_drx_timer,
		{ "Non-DRX timer","gsm_a.gmm.non_drx_timer",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_gmm_non_drx_timer_strings), 0x07,
		"Non-DRX timer", HFILL }
	},
	{ &hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef,
		{ "CN Specific DRX cycle length coefficient","gsm_a.gmm.cn_spec_drs_cycle_len_coef",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_gmm_cn_spec_drs_cycle_len_coef_strings), 0xf0,
		"CN Specific DRX cycle length coefficient", HFILL }
	},
	  { &hf_gsm_a_extension,
	  { "Extension", "gsm_a.extension",
		FT_BOOLEAN, 8, TFS(&gsm_a_extension_value), 0x80,
		"Extension", HFILL }},
	   { &hf_gsm_a_type_of_number,
	  { "Type of number", "gsm_a.type_of_number",
		FT_UINT8, BASE_HEX, VALS(gsm_a_type_of_number_values), 0x70,
		"Type of number", HFILL }},
	   { &hf_gsm_a_numbering_plan_id,
	  { "Numbering plan identification", "gsm_a.numbering_plan_id",
		FT_UINT8, BASE_HEX, VALS(gsm_a_numbering_plan_id_values), 0x0f,
		"Numbering plan identification", HFILL }},
	{ &hf_gsm_a_tft_op_code,
		{ "TFT operation code", "gsm_a.tft.op_code",
		FT_UINT8, BASE_DEC, VALS(gsm_a_tft_op_code_vals), 0xe0,
		"TFT operation code", HFILL }
	},
	{ &hf_gsm_a_tft_e_bit,
		{ "E bit","gsm_a.tft.e_bit",
		FT_BOOLEAN,8,  TFS(&gsm_a_tft_e_bit), 0x10,
		"E bit", HFILL }
	},
	{ &hf_gsm_a_tft_pkt_flt,
		{ "Number of packet filters", "gsm_a.tft.pkt_flt",
		FT_UINT8, BASE_DEC, NULL, 0x0f,
		"Number of packet filters", HFILL }
	},

	   { &hf_gsm_a_tft_ip4_address,
	  { "IPv4 adress", "gsm_a.tft.ip4_address", FT_IPv4, BASE_NONE, NULL, 0x0,
		"IPv4 address", HFILL }},
	{ &hf_gsm_a_tft_ip4_mask,
	  { "IPv4 address mask", "gsm_a.tft.ip4_mask", FT_IPv4, BASE_NONE, NULL, 0x0,
		"IPv4 address mask", HFILL }},
	{ &hf_gsm_a_tft_ip6_address,
	  { "IPv6 adress", "gsm_a.tft.ip6_address", FT_IPv6, BASE_NONE, NULL, 0x0,
		"IPv6 address", HFILL }},
	{ &hf_gsm_a_tft_ip6_mask,
	{ "IPv6 adress mask", "gsm_a.tft.ip6_mask", FT_IPv6, BASE_NONE, NULL, 0x0,
		"IPv6 address mask", HFILL }},
	{ &hf_gsm_a_tft_protocol_header,
	{ "Protocol/header", "gsm_a.tft.protocol_header", FT_UINT8, BASE_HEX, NULL, 0x0,
		"Protocol/header", HFILL }},
	{ &hf_gsm_a_tft_port,
	{ "Port", "gsm_a.tft.port", FT_UINT16, BASE_DEC, NULL, 0x0,
		"Port", HFILL }},
	{ &hf_gsm_a_tft_port_low,
	{ "Low limit port", "gsm_a.tft.port_low", FT_UINT16, BASE_DEC, NULL, 0x0,
		"Low limit port", HFILL }},
	{ &hf_gsm_a_tft_port_high,
	{ "High limit port", "gsm_a.tft.port_high", FT_UINT16, BASE_DEC, NULL, 0x0,
		"High limit port", HFILL }},
	{ &hf_gsm_a_tft_security,
	{ "IPSec security parameter index", "gsm_a.tft.security", FT_UINT32, BASE_HEX, NULL, 0x0,
		"IPSec security parameter index", HFILL }},
	{ &hf_gsm_a_tft_traffic_mask,
	{ "Mask field", "gsm_a.tft.traffic_mask", FT_UINT8, BASE_HEX, NULL, 0x0,
		"Mask field", HFILL }},

	{ &hf_gsm_a_ptmsi_sig,
	{ "P-TMSI Signature", "gsm_a.ptmsi_sig", FT_UINT24, BASE_HEX, NULL, 0x0,
		"P-TMSI Signature", HFILL }},
	{ &hf_gsm_a_ptmsi_sig2,
	{ "P-TMSI Signature 2", "gsm_a.ptmsi_sig2", FT_UINT24, BASE_HEX, NULL, 0x0,
		"P-TMSI Signature 2", HFILL }},

	{ &hf_gsm_a_lsa_id,
		{ "LSA Identifier", "gsm_a.lsa_id",
		FT_UINT24, BASE_HEX, NULL, 0x0,
		"LSA Identifier", HFILL }
	},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	35
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
			NUM_GSM_DTAP_MSG_MM + NUM_GSM_DTAP_MSG_CC +
			NUM_GSM_DTAP_MSG_GMM + NUM_GSM_DTAP_MSG_SMS +
			NUM_GSM_DTAP_MSG_SM + NUM_GSM_DTAP_MSG_SS + NUM_GSM_DTAP_MSG_TP +
			NUM_GSM_DTAP_ELEM];

	ett[0] = &ett_dtap_msg;
	ett[1] = &ett_elems;
	ett[2] = &ett_elem;
	ett[3] = &ett_dtap_oct_1;
	ett[4] = &ett_cm_srvc_type;
	ett[5] = &ett_gsm_enc_info;
	ett[6] = &ett_bc_oct_3a;
	ett[7] = &ett_bc_oct_4;
	ett[8] = &ett_bc_oct_5;
	ett[9] = &ett_bc_oct_5a;
	ett[10] = &ett_bc_oct_5b;
	ett[11] = &ett_bc_oct_6;
	ett[12] = &ett_bc_oct_6a;
	ett[13] = &ett_bc_oct_6b;
	ett[14] = &ett_bc_oct_6c;
	ett[15] = &ett_bc_oct_6d;
	ett[16] = &ett_bc_oct_6e;
	ett[17] = &ett_bc_oct_6f;
	ett[18] = &ett_bc_oct_6g;
	ett[19] = &ett_bc_oct_7;
	ett[20] = &ett_tc_component;
	ett[21] = &ett_tc_invoke_id;
	ett[22] = &ett_tc_linked_id;
	ett[23] = &ett_tc_opr_code;
	ett[24] = &ett_tc_err_code;
	ett[25] = &ett_tc_prob_code;
	ett[26] = &ett_tc_sequence;
	ett[27] = &ett_gmm_drx;
	ett[28] = &ett_gmm_detach_type;
	ett[29] = &ett_gmm_attach_type;
	ett[30] = &ett_gmm_context_stat;
	ett[31] = &ett_gmm_update_type;
	ett[32] = &ett_gmm_radio_cap;
	ett[33] = &ett_gmm_rai;
	ett[34] = &ett_sm_tft;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_DTAP_MSG_MM; i++, last_offset++)
	{
	ett_gsm_dtap_msg_mm[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_mm[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_CC; i++, last_offset++)
	{
	ett_gsm_dtap_msg_cc[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_cc[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_GMM; i++, last_offset++)
	{
	ett_gsm_dtap_msg_gmm[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_gmm[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_SMS; i++, last_offset++)
	{
	ett_gsm_dtap_msg_sms[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_sms[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_SM; i++, last_offset++)
	{
	ett_gsm_dtap_msg_sm[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_sm[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_SS; i++, last_offset++)
	{
	ett_gsm_dtap_msg_ss[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_ss[i];
	}

    for (i=0; i < NUM_GSM_DTAP_MSG_TP; i++, last_offset++)
    {
	ett_gsm_dtap_msg_tp[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_tp[i];
    }

	for (i=0; i < NUM_GSM_DTAP_ELEM; i++, last_offset++)
	{
	ett_gsm_dtap_elem[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_elem[i];
	}


	/* Register the protocol name and description */

	proto_a_dtap =
	proto_register_protocol("GSM A-I/F DTAP", "GSM DTAP", "gsm_a_dtap");

	proto_register_field_array(proto_a_dtap, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	gprs_sm_pco_subdissector_table = register_dissector_table("sm_pco.protocol",
		"GPRS SM PCO PPP protocol", FT_UINT16, BASE_HEX);

	register_dissector("gsm_a_dtap", dissect_dtap, proto_a_dtap);
}


void
proto_reg_handoff_gsm_a_dtap(void)
{

	dtap_handle = find_dissector("gsm_a_dtap");
	rp_handle = find_dissector("gsm_a_rp");

	dissector_add("bssap.pdu_type",  GSM_A_PDU_TYPE_DTAP, dtap_handle);
	dissector_add("ranap.nas_pdu",  GSM_A_PDU_TYPE_DTAP, dtap_handle);
	dissector_add("llcgprs.sapi", 1 , dtap_handle); /* GPRS Mobility Management */
	dissector_add("llcgprs.sapi", 7 , dtap_handle); /* SMS */
	data_handle = find_dissector("data");
	gsm_map_handle = find_dissector("gsm_map");
	gsm_bsslap_handle = find_dissector("gsm_bsslap");
}
