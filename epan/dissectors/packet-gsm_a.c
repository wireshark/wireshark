/* packet-gsm_a.c
 * Routines for GSM A Interface (BSSMAP/DTAP) dissection
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
 * Copyright 2005 - 2006, Anders Broman [AT] ericsson.com
 *
 * Title		3GPP			Other
 *
 *   Reference [1]
 *   Mobile radio interface signalling layer 3;
 *   General Aspects
 *   (3GPP TS 24.007 version 3.9.0 Release 1999)
 *
 *   Reference [2]
 *   Mobile-services Switching Centre - Base Station System
 *   (MSC - BSS) interface;
 *   Layer 3 specification
 *   (GSM 08.08 version 7.7.0 Release 1998)	TS 100 590 v7.7.0
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-bssap.h"
#include "packet-gsm_ss.h"
#include "packet-ber.h"
#include "packet-gsm_a.h"

#include "packet-ppp.h"

/* PROTOTYPES/FORWARDS */

const value_string gsm_a_bssmap_msg_strings[] = {
    { 0x01,	"Assignment Request" },
    { 0x02,	"Assignment Complete" },
    { 0x03,	"Assignment Failure" },
    { 0x10,	"Handover Request" },
    { 0x11,	"Handover Required" },
    { 0x12,	"Handover Request Acknowledge" },
    { 0x13,	"Handover Command" },
    { 0x14,	"Handover Complete" },
    { 0x15,	"Handover Succeeded" },
    { 0x16,	"Handover Failure" },
    { 0x17,	"Handover Performed" },
    { 0x18,	"Handover Candidate Enquire" },
    { 0x19,	"Handover Candidate Response" },
    { 0x1a,	"Handover Required Reject" },
    { 0x1b,	"Handover Detect" },
    { 0x20,	"Clear Command" },
    { 0x21,	"Clear Complete" },
    { 0x22,	"Clear Request" },
    { 0x23,	"Reserved" },
    { 0x24,	"Reserved" },
    { 0x25,	"SAPI 'n' Reject" },
    { 0x26,	"Confusion" },
    { 0x28,	"Suspend" },
    { 0x29,	"Resume" },
    { 0x2a,	"Connection Oriented Information" },
    { 0x2b,	"Perform Location Request" },
    { 0x2c,	"LSA Information" },
    { 0x2d,	"Perform Location Response" },
    { 0x2e,	"Perform Location Abort" },
    { 0x30,	"Reset" },
    { 0x31,	"Reset Acknowledge" },
    { 0x32,	"Overload" },
    { 0x33,	"Reserved" },
    { 0x34,	"Reset Circuit" },
    { 0x35,	"Reset Circuit Acknowledge" },
    { 0x36,	"MSC Invoke Trace" },
    { 0x37,	"BSS Invoke Trace" },
    { 0x3a,	"Connectionless Information" },
    { 0x40,	"Block" },
    { 0x41,	"Blocking Acknowledge" },
    { 0x42,	"Unblock" },
    { 0x43,	"Unblocking Acknowledge" },
    { 0x44,	"Circuit Group Block" },
    { 0x45,	"Circuit Group Blocking Acknowledge" },
    { 0x46,	"Circuit Group Unblock" },
    { 0x47,	"Circuit Group Unblocking Acknowledge" },
    { 0x48,	"Unequipped Circuit" },
    { 0x4e,	"Change Circuit" },
    { 0x4f,	"Change Circuit Acknowledge" },
    { 0x50,	"Resource Request" },
    { 0x51,	"Resource Indication" },
    { 0x52,	"Paging" },
    { 0x53,	"Cipher Mode Command" },
    { 0x54,	"Classmark Update" },
    { 0x55,	"Cipher Mode Complete" },
    { 0x56,	"Queuing Indication" },
    { 0x57,	"Complete Layer 3 Information" },
    { 0x58,	"Classmark Request" },
    { 0x59,	"Cipher Mode Reject" },
    { 0x5a,	"Load Indication" },
    { 0x04,	"VGCS/VBS Setup" },
    { 0x05,	"VGCS/VBS Setup Ack" },
    { 0x06,	"VGCS/VBS Setup Refuse" },
    { 0x07,	"VGCS/VBS Assignment Request" },
    { 0x1c,	"VGCS/VBS Assignment Result" },
    { 0x1d,	"VGCS/VBS Assignment Failure" },
    { 0x1e,	"VGCS/VBS Queuing Indication" },
    { 0x1f,	"Uplink Request" },
    { 0x27,	"Uplink Request Acknowledge" },
    { 0x49,	"Uplink Request Confirmation" },
    { 0x4a,	"Uplink Release Indication" },
    { 0x4b,	"Uplink Reject Command" },
    { 0x4c,	"Uplink Release Command" },
    { 0x4d,	"Uplink Seized Command" },
    { 0, NULL },
};

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
    { 0, NULL },
};

const value_string gsm_a_dtap_msg_rr_strings[] = {
    { 0x3c,	"RR Initialisation Request" },
    { 0x3b,	"Additional Assignment" },
    { 0x3f,	"Immediate Assignment" },
    { 0x39,	"Immediate Assignment Extended" },
    { 0x3a,	"Immediate Assignment Reject" },

    { 0x48,	"DTM Assignment Failure" },
    { 0x49,	"DTM Reject" },
    { 0x4a,	"DTM Request" },
    { 0x4b,	"Main DCCH Assignment Command" },
    { 0x4c,	"Packet Assignment Command" },

    { 0x35,	"Ciphering Mode Command" },
    { 0x32,	"Ciphering Mode Complete" },

    { 0x30,	"Configuration Change Command" },
    { 0x31,	"Configuration Change Ack." },
    { 0x33,	"Configuration Change Reject" },

    { 0x2e,	"Assignment Command" },
    { 0x29,	"Assignment Complete" },
    { 0x2f,	"Assignment Failure" },
    { 0x2b,	"Handover Command" },
    { 0x2c,	"Handover Complete" },
    { 0x28,	"Handover Failure" },
    { 0x2d,	"Physical Information" },
    { 0x4d,	"DTM Assignment Command" },

    { 0x08,	"RR-cell Change Order" },
    { 0x23,	"PDCH Assignment Command" },

    { 0x0d,	"Channel Release" },
    { 0x0a,	"Partial Release" },
    { 0x0f,	"Partial Release Complete" },

    { 0x21,	"Paging Request Type 1" },
    { 0x22,	"Paging Request Type 2" },
    { 0x24,	"Paging Request Type 3" },
    { 0x27,	"Paging Response" },
    { 0x20,	"Notification/NCH" },
    { 0x25,	"Reserved" },
    { 0x26,	"Notification/Response" },

    { 0x0b,	"Reserved" },

/*	ETSI TS 101 503 V8.5.0 Seems to give Other def for this Messages???
    { 0xc0,	"Utran Classmark Change" }, CONFLICTS WITH Handover To UTRAN Command 
    { 0xc1,	"UE RAB Preconfiguration" },
    { 0xc2,	"cdma2000 Classmark Change" },*/

	/* ETSI TS 101 503 V8.5.0 */
    { 0x60,	"Utran Classmark Change" },  
    { 0x61,	"UE RAB Preconfiguration" },
    { 0x62,	"cdma2000 Classmark Change" },
    { 0x63,	"Inter System to UTRAN Handover Command" },
    { 0x64,	"Inter System to cdma2000 Handover Command" },
    { 0x18,	"System Information Type 8" },
    { 0x19,	"System Information Type 1" },
    { 0x1a,	"System Information Type 2" },
    { 0x1b,	"System Information Type 3" },
    { 0x1c,	"System Information Type 4" },
    { 0x1d,	"System Information Type 5" },
    { 0x1e,	"System Information Type 6" },
    { 0x1f,	"System Information Type 7" },

    { 0x02,	"System Information Type 2bis" },
    { 0x03,	"System Information Type 2ter" },
    { 0x07,	"System Information Type 2quater" },
    { 0x05,	"System Information Type 5bis" },
    { 0x06,	"System Information Type 5ter" },
    { 0x04,	"System Information Type 9" },
    { 0x00,	"System Information Type 13" },

    { 0x3d,	"System Information Type 16" },
    { 0x3e,	"System Information Type 17" },

    { 0x40,	"System Information Type 18" },
    { 0x41,	"System Information Type 19" },
    { 0x42,	"System Information Type 20" },

    { 0x10,	"Channel Mode Modify" },
    { 0x12,	"RR Status" },
    { 0x17,	"Channel Mode Modify Acknowledge" },
    { 0x14,	"Frequency Redefinition" },
    { 0x15,	"Measurement Report" },
    { 0x16,	"Classmark Change" },
    { 0x13,	"Classmark Enquiry" },
    { 0x36,	"Extended Measurement Report" },
    { 0x37,	"Extended Measurement Order" },
    { 0x34,	"GPRS Suspension Request" },

    { 0x09,	"VGCS Uplink Grant" },
    { 0x0e,	"Uplink Release" },
    { 0x0c,	"Reserved" },
    { 0x2a,	"Uplink Busy" },
    { 0x11,	"Talker Indication" },

    { 0xc0,	"UTRAN Classmark Change/Handover To UTRAN Command" },	/* spec conflict */

    { 0x38,	"Application Information" },

    { 0, NULL },
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
    { 0, NULL },
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
    { 0, NULL },
};

const value_string gsm_a_dtap_msg_sms_strings[] = {
    { 0x01,	"CP-DATA" },
    { 0x04,	"CP-ACK" },
    { 0x10,	"CP-ERROR" },
    { 0, NULL },
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
    { 0, NULL },
};

const value_string gsm_a_dtap_msg_ss_strings[] = {
    { 0x2a,	"Release Complete" },
    { 0x3a,	"Facility" },
    { 0x3b,	"Register" },
    { 0, NULL },
};

static const value_string gsm_rp_msg_strings[] = {
    { 0x00,	"RP-DATA (MS to Network)" },
    { 0x01,	"RP-DATA (Network to MS)" },
    { 0x02,	"RP-ACK (MS to Network)" },
    { 0x03,	"RP-ACK (Network to MS)" },
    { 0x04,	"RP-ERROR (MS to Network)" },
    { 0x05,	"RP-ERROR (Network to MS)" },
    { 0x06,	"RP-SMMA (MS to Network)" },
    { 0, NULL },
};

static const value_string gsm_bssmap_elem_strings[] = {
    { 0x01,	"Circuit Identity Code" },
    { 0x02,	"Reserved" },
    { 0x03,	"Resource Available" },
    { 0x04,	"Cause" },
    { 0x05,	"Cell Identifier" },
    { 0x06,	"Priority" },
    { 0x07,	"Layer 3 Header Information" },
    { 0x08,	"IMSI" },
    { 0x09,	"TMSI" },
    { 0x0a,	"Encryption Information" },
    { 0x0b,	"Channel Type" },
    { 0x0c,	"Periodicity" },
    { 0x0d,	"Extended Resource Indicator" },
    { 0x0e,	"Number Of MSs" },
    { 0x0f,	"Reserved" },
    { 0x10,	"Reserved" },
    { 0x11,	"Reserved" },
    { 0x12,	"Classmark Information Type 2" },
    { 0x13,	"Classmark Information Type 3" },
    { 0x14,	"Interference Band To Be Used" },
    { 0x15,	"RR Cause" },
    { 0x16,	"Reserved" },
    { 0x17,	"Layer 3 Information" },
    { 0x18,	"DLCI" },
    { 0x19,	"Downlink DTX Flag" },
    { 0x1a,	"Cell Identifier List" },
    { 0x1b,	"Response Request" },
    { 0x1c,	"Resource Indication Method" },
    { 0x1d,	"Classmark Information Type 1" },
    { 0x1e,	"Circuit Identity Code List" },
    { 0x1f,	"Diagnostic" },
    { 0x20,	"Layer 3 Message Contents" },
    { 0x21,	"Chosen Channel" },
    { 0x22,	"Total Resource Accessible" },
    { 0x23,	"Cipher Response Mode" },
    { 0x24,	"Channel Needed" },
    { 0x25,	"Trace Type" },
    { 0x26,	"TriggerID" },
    { 0x27,	"Trace Reference" },
    { 0x28,	"TransactionID" },
    { 0x29,	"Mobile Identity" },
    { 0x2a,	"OMCID" },
    { 0x2b,	"Forward Indicator" },
    { 0x2c,	"Chosen Encryption Algorithm" },
    { 0x2d,	"Circuit Pool" },
    { 0x2e,	"Circuit Pool List" },
    { 0x2f,	"Time Indication" },
    { 0x30,	"Resource Situation" },
    { 0x31,	"Current Channel Type 1" },
    { 0x32,	"Queuing Indicator" },
    { 0x40,	"Speech Version" },
    { 0x33,	"Assignment Requirement" },
    { 0x35,	"Talker Flag" },
    { 0x36,	"Connection Release Requested" },
    { 0x37,	"Group Call Reference" },
    { 0x38,	"eMLPP Priority" },
    { 0x39,	"Configuration Evolution Indication" },
    { 0x3a,	"Old BSS to New BSS Information" },
    { 0x3b,	"LSA Identifier" },
    { 0x3c,	"LSA Identifier List" },
    { 0x3d,	"LSA Information" },
    { 0x3e,	"LCS QoS" },
    { 0x3f,	"LSA access control suppression" },
    { 0x43,	"LCS Priority" },
    { 0x44,	"Location Type" },
    { 0x45,	"Location Estimate" },
    { 0x46,	"Positioning Data" },
    { 0x47,	"LCS Cause" },
    { 0x48,	"LCS Client Type" },
    { 0x49,	"APDU" },
    { 0x4a,	"Network Element Identity" },
    { 0x4b,	"GPS Assistance Data" },
    { 0x4c,	"Deciphering Keys" },
    { 0x4d,	"Return Error Request" },
    { 0x4e,	"Return Error Cause" },
    { 0x4f,	"Segmentation" },
    { 0, NULL },
};

static const value_string gsm_dtap_elem_strings[] = {
    /* Common Information Elements 10.5.1 */
    { 0x00,	"Cell Identity" },
    { 0x00,	"Ciphering Key Sequence Number" },
    { 0x00,	"Location Area Identification" },
    { 0x00,	"Mobile Identity" },
    { 0x00,	"Mobile Station Classmark 1" },
    { 0x00,	"Mobile Station Classmark 2" },
    { 0x00,	"Mobile Station Classmark 3" },
    { 0x00,	"Descriptive group or broadcast call reference" },
    { 0x00,	"Group Cipher Key Number" },
    { 0x00,	"PD and SAPI $(CCBS)$" },
    { 0x00,	"Priority Level" },
    { 0x00,	"PLMN List" },
    /* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1 */
/*
 * [3]  10.5.2.1a	BA Range
 */
    { 0x00,	"Cell Channel Description" },		/* [3]  10.5.2.1b	*/	
/* [3]  10.5.2.1c	BA List Pref
 * [3]  10.5.2.1d	UTRAN Frequency List
 * [3]  10.5.2.1e	Cell selection indicator after release of all TCH and SDCCH IE
 */
	{ 0x00, "Cell Description" },				/* 10.5.2.2  */
/*
 * [3]  10.5.2.3	Cell Options (BCCH)	
 * [3]  10.5.2.3a	Cell Options (SACCH)
 * [3]  10.5.2.4	Cell Selection Parameters
 * [3]  10.5.2.4a	(void) */
	{ 0x00, "Channel Description" },			/* 10.5.2.5	 */
	{ 0x00, "Channel Description 2" },			/* 10.5.2.5a */

	{ 0x00, "Channel Mode" },					/* [3]  10.5.2.6 */	
	{ 0x00, "Channel Mode 2" },					/* [3]  10.5.2.7 */	
/* [3]  10.5.2.7a	UTRAN predefined configuration status information / START-CS / UE CapabilityUTRAN Classmark information element	218
 * [3]  10.5.2.7b	(void) */
	{ 0x00, "Classmark Enquiry Mask" },			/* [3]  10.5.2.7c */
/* [3]  10.5.2.7d	GERAN Iu Mode Classmark information element
 * [3]  10.5.2.8	Channel Needed
 * [3]  10.5.2.8a	(void)	
 * [3]  10.5.2.8b	Channel Request Description 2 */
 	{ 0x00, "Cipher Mode Setting" },				/* [3]  10.5.2.9	*/
/* [3]  10.5.2.10	Cipher Response
 * [3]  10.5.2.11	Control Channel Description
 * [3]  10.5.2.11a	DTM Information Details */
	{ 0x00, "Dynamic ARFCN Mapping" },			/* [3]  10.5.2.11b	*/
	{ 0x00, "Frequency Channel Sequence" },		/* [3]  10.5.2.12	*/
    { 0x00,	"Frequency List" },					/* 10.5.2.13		*/
	{ 0x00,	"Frequency Short List" },			/* 10.5.2.14		*/
	{ 0x00,	"Frequency Short List2" },			/* 10.5.2.14a		*/
/* [3]  10.5.2.14b	Group Channel Description
 * [3]  10.5.2.14c	GPRS Resumption
 * [3]  10.5.2.14d	GPRS broadcast information
 * [3]  10.5.2.14e	Enhanced DTM CS Release Indication
 */
	{ 0x00, "Handover Reference" },				/* 10.5.2.15 */
/*
 * [3] 10.5.2.16 IA Rest Octets
 * [3] 10.5.2.17 IAR Rest Octets
 * [3] 10.5.2.18 IAX Rest Octets
 * [3] 10.5.2.19 L2 Pseudo Length
 * [3] 10.5.2.20 Measurement Results
 * [3] 10.5.2.20a GPRS Measurement Results
 */
 	{ 0x00, "Mobile Allocation" },				/* [3] 10.5.2.21	*/ 
 	{ 0x00, "Mobile Time Difference" },			/* [3] 10.5.2.21a	*/
 	{ 0x00, "MultiRate configuration" },		/* [3] 10.5.2.21aa	*/
	{ 0x00, "Multislot Allocation" },			/* [3] 10.5.2.21b	*/ 
 /*
 * [3] 10.5.2.21c NC mode
 * [3] 10.5.2.22 Neighbour Cell Description
 * [3] 10.5.2.22a Neighbour Cell Description 2
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets
 * [3] 10.5.2.25a Packet Channel Description
 * [3] 10.5.2.25b Dedicated mode or TBF
 * [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 * [3] 10.5.2.26 Page Mode
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 * [3] 10.5.2.27 NCC Permitted
 */
	{ 0x00, "Power Command" },					/* 10.5.2.28 */
	{ 0x00, "Power Command and access type" },	/* 10.5.2.28a */
/*
 * [3] 10.5.2.29 RACH Control Parameters
 * [3] 10.5.2.30 Request Reference
 */
    { 0x00,	"RR Cause" },						/* 10.5.2.31 */
	{ 0x00,	"Synchronization Indication" },		/* 10.5.2.39 */
/* [3] 10.5.2.32 SI 1 Rest Octets
 * [3] 10.5.2.33 SI 2bis Rest Octets 
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 * [3] 10.5.2.34 SI 3 Rest Octets
 * [3] 10.5.2.35 SI 4 Rest Octets
 * [3] 10.5.2.35a SI 6 Rest Octets
 * [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 * [3] 10.5.2.37b SI 13 Rest Octets
 * [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
    { 0x00,	"Starting Time" },					/* [3] 10.5.2.38 Starting Time	*/
    { 0x00,	"Timing Advance" },					/* [3] 10.5.2.40 Timing Advance */ 
	{ 0x00,	"Time Difference" },				/* [3] 10.5.2.41 Time Difference				*/
	{ 0x00,	"TLLI" },							/* [3] 10.5.2.41a TLLI							*/
/*
 * [3] 10.5.2.42 TMSI/P-TMSI */
	{ 0x00,	"VGCS target mode Indication" },	/* [3] 10.5.2.42a								*/ 
	{ 0x00,	"VGCS Ciphering Parameters" },		/* [3] 10.5.2.42b								*/
/* [3] 10.5.2.43 Wait Indication
 * [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List */
	{ 0x00,	"Suspension Cause" },				/* [3] 10.5.2.47								*/ 
/* [3] 10.5.2.48 APDU ID 
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command 
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell */
	{ 0x00,	"Dedicated Service Information" },		/* [3] 10.5.2.59	*/


    /* Mobility Management Information Elements 10.5.3 */
    { 0x00,	"Authentication Parameter RAND" },
    { 0x00,	"Authentication Parameter AUTN (UMTS authentication challenge only)" },
    { 0x00,	"Authentication Response Parameter" },
    { 0x00,	"Authentication Response Parameter (extension) (UMTS authentication challenge only)" },
    { 0x00,	"Authentication Failure Parameter (UMTS authentication challenge only)" },
    { 0x00,	"CM Service Type" },
    { 0x00,	"Identity Type" },
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
    { 0x00,	"Auxiliary States" },
    { 0x00,	"Bearer Capability" },
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
    { 0x00,	"Alerting Pattern $(NIA)$" },
    { 0x00,	"Allowed Actions $(CCBS)$" },
    { 0x00,	"Stream Identifier" },
    { 0x00,	"Network Call Control Capabilities" },
    { 0x00,	"Cause of No CLI" },
    { 0x00,	"Immediate Modification Indicator" },
    { 0x00,	"Supported Codec List" },
    { 0x00,	"Service Category" },
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
    { 0, NULL },
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
    "Reserved for tests procedures"
};
/* L3 Protocol discriminator values according to TS 24 007 (6.4.0)  */
static const value_string protocol_discriminator_vals[] = {
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
	{0xf,		"Reserved for tests procedures described in 3GPP TS 44.014 [5a] and 3GPP TS 34.109 [17a]."},
	{ 0,	NULL }
};

static const value_string gsm_a_pd_short_str_vals[] = {
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
	{0xf,		"Reserved"},		/*  for tests procedures described in 3GPP TS 44.014 [5a] and 3GPP TS 34.109 [17a].*/
	{ 0,	NULL }
};
static const value_string bssap_cc_values[] = {
    { 0x00,		"not further specified" },
    { 0x80,		"FACCH or SDCCH" },
    { 0xc0,		"SACCH" },
    { 0,		NULL } };

static const value_string bssap_sapi_values[] = {
    { 0x00,		"RR/MM/CC" },
    { 0x03,		"SMS" },
    { 0,		NULL } };

/* Mobile Station Classmark Value strings
 */

/* Mobile Station Classmark  
 * Revision level 
 */
const value_string gsm_a_msc_rev_vals[] = {
	{ 0,		"Reserved for GSM phase 1"},
	{ 1,		"Used by GSM phase 2 mobile stations"},
	{ 2,		"Used by mobile stations supporting R99 or later versions of the protocol"},
	{ 3,		"Reserved for future use"},
	{ 0,	NULL }
};

/* ES IND (octet 3, bit 5) "Controlled Early Classmark Sending" option implementation */
static const value_string ES_IND_vals[] = {
	{ 0,		"Controlled Early Classmark Sending option is not implemented in the MS"},
	{ 1,		"Controlled Early Classmark Sending option is implemented in the MS"},
	{ 0,	NULL }
};
/* A5/1 algorithm supported (octet 3, bit 4 */
static const value_string A5_1_algorithm_sup_vals[] = {
	{ 0,		"encryption algorithm A5/1 available"},
	{ 1,		"encryption algorithm A5/1 not available"},
	{ 0,	NULL }
};
/* RF Power Capability (Octet 3) */
static const value_string RF_power_capability_vals[] = {
	{ 0,		"class 1"},
	{ 1,		"class 2"},
	{ 2,		"class 3"},
	{ 3,		"class 4"},
	{ 4,		"class 5"},
	{ 7,		"RF Power capability is irrelevant in this information element"},
	{ 0,	NULL }
};
/* PS capability (pseudo-synchronization capability) (octet 4) */
static const value_string ps_sup_cap_vals[] = {
	{ 0,		"PS capability not present"},
	{ 1,		"PS capability present"},
	{ 0,	NULL }
};
/* SS Screening Indicator (octet 4)defined in 3GPP TS 24.080 */
static const value_string SS_screening_indicator_vals[] = {
	{ 0,		"Default value of phase 1"},
	{ 1,		"Capability of handling of ellipsis notation and phase 2 error handling "},
	{ 2,		"For future use"},
	{ 3,		"For future use"},
	{ 0,	NULL }
};
/* SM capability (MT SMS pt to pt capability) (octet 4)*/
static const value_string SM_capability_vals[] = {
	{ 0,		"Mobile station does not support mobile terminated point to point SMS"},
	{ 1,		"Mobile station supports mobile terminated point to point SMS"},
	{ 0,	NULL }
};
/* VBS notification reception (octet 4) */
static const value_string VBS_notification_rec_vals[] = {
	{ 0,		"no VBS capability or no notifications wanted"},
	{ 1,		"VBS capability and notifications wanted"},
	{ 0,	NULL }
};
/* VGCS notification reception (octet 4) */
static const value_string VGCS_notification_rec_vals[] = {
	{ 0,		"no VGCS capability or no notifications wanted"},
	{ 1,		"VGCS capability and notifications wanted"},
	{ 0,	NULL }
};
/* FC Frequency Capability (octet 4 ) */
static const value_string FC_frequency_cap_vals[] = {
	{ 0,		"The MS does not support the E-GSM or R-GSM band"},
	{ 1,		"The MS does support the E-GSM or R-GSM "},
	{ 0,	NULL }
};
/* CM3 (octet 5, bit 8) */
static const value_string CM3_vals[] = {
	{ 0,		"The MS does not support any options that are indicated in CM3"},
	{ 1,		"The MS supports options that are indicated in classmark 3 IE"},
	{ 0,	NULL }
};
/* LCS VA capability (LCS value added location request notification capability) (octet 5,bit 6) */
static const value_string LCS_VA_cap_vals[] = {
	{ 0,		"LCS value added location request notification capability not supported"},
	{ 1,		"LCS value added location request notification capability supported"},
	{ 0,	NULL }
};
/* UCS2 treatment (octet 5, bit 5) */
static const value_string UCS2_treatment_vals[] = {
	{ 0,		"the ME has a preference for the default alphabet"},
	{ 1,		"the ME has no preference between the use of the default alphabet and the use of UCS2"},
	{ 0,	NULL }
};
/* SoLSA (octet 5, bit 4) */
static const value_string SoLSA_vals[] = {
	{ 0,		"The ME does not support SoLSA"},
	{ 1,		"The ME supports SoLSA"},
	{ 0,	NULL }
};
/* CMSP: CM Service Prompt (octet 5, bit 3) */
static const value_string CMSP_vals[] = {
	{ 0,		"Network initiated MO CM connection request not supported"},
	{ 1,		"Network initiated MO CM connection request supported for at least one CM protocol"},
	{ 0,	NULL }
};
/* A5/3 algorithm supported (octet 5, bit 2) */
static const value_string A5_3_algorithm_sup_vals[] = {
	{ 0,		"encryption algorithm A5/3 not available"},
	{ 1,		"encryption algorithm A5/3 available"},
	{ 0,	NULL }
};

/* A5/2 algorithm supported (octet 5, bit 1) */
static const value_string A5_2_algorithm_sup_vals[] = {
	{ 0,		"encryption algorithm A5/2 not available"},
	{ 1,		"encryption algorithm A5/2 available"},
	{ 0,	NULL }
};

 static const value_string gsm_a_algorithm_identifier_vals[] = {
	{ 0,		"Cipher with algorithm A5/1"},
 	{ 1,		"Cipher with algorithm A5/2"},
 	{ 2,		"Cipher with algorithm A5/3"},
	{ 3,		"Cipher with algorithm A5/4"},
 	{ 4,		"Cipher with algorithm A5/5"},
 	{ 5,		"Cipher with algorithm A5/6"},
 	{ 6,		"Cipher with algorithm A5/7"},
	{ 7,		"Reserved"},
	{ 0,	NULL }
};

 static const value_string mobile_identity_type_vals[] = {
	{ 1,		"IMSI"},
	{ 2,		"IMEI"},
	{ 3,		"IMEISV"},
	{ 4,		"TMSI/P-TMSI"},
	{ 5,		"TMGI and optional MBMS Session Identity"}, /* ETSI TS 124 008 V6.8.0 (2005-03) p326 */
	{ 0,		"No Identity"},
	{ 0,	NULL }
};

static const value_string oddevenind_vals[] = {
	{ 0,		"Even number of identity digits"},
	{ 1,		"Odd number of identity digits"},
	{ 0,	NULL }
};

/* RR cause value (octet 2) TS 44.018 6.11.0*/
static const value_string gsm_a_rr_RR_cause_vals[] = {
	{ 0,		"Normal event"},
	{ 1,		"Abnormal release, unspecified"},
	{ 2,		"Abnormal release, channel unacceptable"},
	{ 3,		"Abnormal release, timer expired"},
	{ 4,		"Abnormal release, no activity on the radio path"},
	{ 5,		"Preemptive release"},
	{ 6,		"UTRAN configuration unknown"},
	{ 8,		"Handover impossible, timing advance out of range"},
	{ 9,		"Channel mode unacceptable"},
	{ 10,		"Frequency not implemented"},
	{ 13,		"Originator or talker leaving group call area"},
	{ 12,		"Lower layer failure"},
	{ 0x41,		"Call already cleared"},
	{ 0x5f,		"Semantically incorrect message"},
	{ 0x60,		"Invalid mandatory information"},
	{ 0x61,		"Message type non-existent or not implemented"},
	{ 0x62,		"Message type not compatible with protocol state"},
	{ 0x64,		"Conditional IE error"},
	{ 0x65,		"No cell allocation available"},
	{ 0x6f,		"Protocol error unspecified"},
	{ 0,	NULL }
};
/* Cell identification discriminator */
static const value_string gsm_a_rr_cell_id_disc_vals[] = {
	{ 0,		"The whole Cell Global Identification, CGI, is used to identify the cells."},
	{ 1,		"Location Area Code, LAC, and Cell Identify, CI, is used to identify the cells."},
	{ 2,		"Cell Identity, CI, is used to identify the cells."},
	{ 3,		"No cell is associated with the transaction."},
	{ 4,		"Location Area Identification, LAI, is used to identify all cells within a Location Area."},
	{ 5,		"Location Area Code, LAC, is used to identify all cells within a location area."},
	{ 6,		"All cells on the BSS are identified."},
	{ 8,		"Intersystem Handover to UTRAN or cdma2000. PLMN-ID, LAC, and RNC-ID, are encoded to identify the target RNC."},
	{ 9,		"Intersystem Handover to UTRAN or cdma2000. The RNC-ID is coded to identify the target RNC."},
	{ 10,		"Intersystem Handover to UTRAN or cdma2000. LAC and RNC-ID are encoded to identify the target RNC."},
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

/* Initialize the protocol and registered fields */
static int proto_a_bssmap = -1;
static int proto_a_dtap = -1;
static int proto_a_rp = -1;

static int gsm_a_tap = -1;

static int hf_gsm_a_none = -1;
static int hf_gsm_a_bssmap_msg_type = -1;
static int hf_gsm_a_dtap_msg_mm_type = -1;
static int hf_gsm_a_dtap_msg_rr_type = -1;
static int hf_gsm_a_dtap_msg_cc_type = -1;
static int hf_gsm_a_dtap_msg_gmm_type = -1;
static int hf_gsm_a_dtap_msg_sms_type = -1;
static int hf_gsm_a_dtap_msg_sm_type = -1;
static int hf_gsm_a_dtap_msg_ss_type = -1;
static int hf_gsm_a_rp_msg_type = -1;
static int hf_gsm_a_length = -1;
static int hf_gsm_a_bssmap_elem_id = -1;
static int hf_gsm_a_dtap_elem_id = -1;
static int hf_gsm_a_imsi = -1;
static int hf_gsm_a_tmsi = -1;
static int hf_gsm_a_imei = -1;
static int hf_gsm_a_imeisv = -1;
static int hf_gsm_a_cld_party_bcd_num = -1;
static int hf_gsm_a_clg_party_bcd_num = -1;
static int hf_gsm_a_cell_ci = -1;
static int hf_gsm_a_cell_lac = -1;
static int hf_gsm_a_dlci_cc = -1;
static int hf_gsm_a_dlci_spare = -1;
static int hf_gsm_a_dlci_sapi = -1;
static int hf_gsm_a_bssmap_cause = -1;
static int hf_gsm_a_dtap_cause = -1;

static int hf_gsm_a_MSC_rev = -1;
static int hf_gsm_a_ES_IND			= -1;
static int hf_gsm_a_qos_traffic_cls = -1;
static int hf_gsm_a_qos_del_order = -1;
static int hf_gsm_a_qos_del_of_err_sdu = -1;
static int hf_gsm_a_qos_ber = -1;
static int hf_gsm_a_qos_sdu_err_rat = -1;
static int hf_gsm_a_qos_traff_hdl_pri = -1;
static int hf_gsm_a_A5_1_algorithm_sup = -1;
static int hf_gsm_a_RF_power_capability = -1;
static int hf_gsm_a_ps_sup_cap		= -1;
static int hf_gsm_a_SS_screening_indicator = -1;
static int hf_gsm_a_SM_capability		 = -1;
static int hf_gsm_a_VBS_notification_rec = -1;
static int hf_gsm_a_VGCS_notification_rec = -1;
static int hf_gsm_a_FC_frequency_cap	= -1;
static int hf_gsm_a_CM3				= -1;
static int hf_gsm_a_LCS_VA_cap		= -1;
static int hf_gsm_a_UCS2_treatment	= -1;
static int hf_gsm_a_SoLSA				= -1;
static int hf_gsm_a_CMSP				= -1;
static int hf_gsm_a_A5_3_algorithm_sup= -1;
static int hf_gsm_a_A5_2_algorithm_sup = -1;

static int hf_gsm_a_odd_even_ind = -1;
static int hf_gsm_a_mobile_identity_type = -1;
static int hf_gsm_a_L3_protocol_discriminator = -1; 
static int hf_gsm_a_skip_ind = -1; 

static int hf_gsm_a_bcc				= -1;
static int hf_gsm_a_ncc				= -1;
static int hf_gsm_a_bcch_arfcn		= -1;
static int hf_gsm_a_rr_ho_ref_val = -1;
static int hf_gsm_a_b7spare = -1;
static int hf_gsm_a_b8spare = -1;
static int hf_gsm_a_rr_pow_cmd_atc = -1;
static int hf_gsm_a_rr_pow_cmd_epc = -1;
static int hf_gsm_a_rr_pow_cmd_fpcepc = -1;
static int hf_gsm_a_rr_pow_cmd_powlev = -1;
static int hf_gsm_a_rr_sync_ind_nci = -1;
static int hf_gsm_a_rr_sync_ind_rot = -1;
static int hf_gsm_a_rr_sync_ind_si = -1;
static int hf_gsm_a_rr_format_id = -1;
static int hf_gsm_a_rr_channel_mode = -1;
static int hf_gsm_a_rr_channel_mode2 = -1;
static int hf_gsm_a_rr_sc = -1;
static int hf_gsm_a_algorithm_id = -1;
static int hf_gsm_a_rr_multirate_speech_ver = -1;
static int hf_gsm_a_rr_NCSB				= -1;
static int hf_gsm_a_rr_ICMI				= -1;
static int hf_gsm_a_rr_start_mode		= -1;
static int hf_gsm_a_rr_timing_adv = -1;
static int hf_gsm_a_rr_time_diff = -1;
static int hf_gsm_a_rr_tlli = -1;
static int hf_gsm_a_rr_target_mode = -1;
static int hf_gsm_a_rr_group_cipher_key_number = -1;
static int hf_gsm_a_rr_last_segment = -1;
static int hf_gsm_a_gmm_split_on_ccch = -1;
static int hf_gsm_a_gmm_non_drx_timer = -1;
static int hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef = -1;
static int hf_gsm_a_rr_RR_cause = -1;
static int hf_gsm_a_be_cell_id_disc = -1;
static int hf_gsm_a_be_rnc_id = -1;
static int hf_gsm_a_rr_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_utran_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_cdma200_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_geran_iu_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_suspension_cause = -1;
static int hf_ROS_component = -1;
static int hf_ROS_invoke = -1;                    /* Invoke */
static int hf_ROS_returnResultLast = -1;          /* ReturnResult */
static int hf_ROS_returnError = -1;               /* ReturnError */
static int hf_ROS_reject = -1;                    /* Reject */
static int hf_ROS_invokeID = -1;                  /* InvokeIdType */
static int hf_ROS_linkedID = -1;                  /* InvokeIdType */
static int hf_ROS_opCode = -1;                    /* OPERATION */
static int hf_ROS_parameter = -1;                 /* Parameter */
static int hf_ROS_resultretres = -1;              /* T_resultretres */
static int hf_ROS_errorCode = -1;                 /* ErrorCode */
static int hf_ROS_invokeIDRej = -1;               /* T_invokeIDRej */
static int hf_ROS_derivable = -1;                 /* InvokeIdType */
static int hf_ROS_not_derivable = -1;             /* NULL */
static int hf_ROS_problem = -1;                   /* T_problem */
static int hf_ROS_generalProblem = -1;            /* GeneralProblem */
static int hf_ROS_invokeProblem = -1;             /* InvokeProblem */
static int hf_ROS_returnResultProblem = -1;       /* ReturnResultProblem */
static int hf_ROS_returnErrorProblem = -1;        /* ReturnErrorProblem */
static int hf_ROS_localValue = -1;                /* INTEGER */
static int hf_ROS_globalValue = -1;               /* OBJECT_IDENTIFIER */
static int hf_ROS_nationaler = -1;                /* INTEGER_M32768_32767 */
static int hf_ROS_privateer = -1;                 /* INTEGER */
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1 = -1;

/* Initialize the subtree pointers */
static gint ett_bssmap_msg = -1;
static gint ett_dtap_msg = -1;
static gint ett_rp_msg = -1;
static gint ett_elems = -1;
static gint ett_elem = -1;
static gint ett_dtap_oct_1 = -1;
static gint ett_cm_srvc_type = -1;
static gint ett_gsm_enc_info = -1;
static gint ett_cell_list = -1;
static gint ett_dlci = -1;
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

static gint ett_ros = -1;
static gint ett_ROS_Component = -1;
static gint ett_ROS_Invoke = -1;
static gint ett_ROS_ReturnResult = -1;
static gint ett_ROS_T_resultretres = -1;
static gint ett_ROS_ReturnError = -1;
static gint ett_ROS_Reject = -1;
static gint ett_ROS_T_invokeIDRej = -1;
static gint ett_ROS_T_problem = -1;
static gint ett_ROS_OPERATION = -1;
static gint ett_ROS_ERROR = -1;
static gint ett_ROS_ErrorCode = -1;

static gint ett_sm_tft = -1;

static char a_bigbuf[1024];

static dissector_handle_t data_handle;
static dissector_handle_t bssmap_handle;
static dissector_handle_t dtap_handle;
static dissector_handle_t rp_handle;
static dissector_table_t sms_dissector_table;	/* SMS TPDU */
static dissector_table_t gprs_sm_pco_subdissector_table; /* GPRS SM PCO PPP Protocols */

static packet_info *g_pinfo;
static proto_tree *g_tree;
static gint comp_type_tag;
static guint32 localValue;


/*
 * this should be set on a per message basis, if possible
 */
#define	IS_UPLINK_FALSE		0
#define	IS_UPLINK_TRUE		1
#define	IS_UPLINK_UNKNOWN	2
static gint is_uplink;


typedef struct dgt_set_t
{
    unsigned char out[15];
}
dgt_set_t;

static dgt_set_t Dgt_mbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c'
    }
};

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


/* ELEMENT FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_text(tree, tvb, \
	    curr_offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
	curr_offset += ((edc_len) - (edc_max_len)); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_text(tree, tvb, \
	    curr_offset, (sdc_len), "Short Data (?)"); \
	curr_offset += (sdc_len); \
	return(curr_offset - offset); \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_text(tree, tvb, \
	    curr_offset, (edc_len), "Unexpected Data Length"); \
	curr_offset += (edc_len); \
	return(curr_offset - offset); \
    }

#define	NO_MORE_DATA_CHECK(nmdc_len) \
    if ((nmdc_len) == (curr_offset - offset)) return(nmdc_len);

/*
 * Decode the MCC/MNC from 3 octets in 'octs'
 */
static void
mcc_mnc_aux(guint8 *octs, gchar *mcc, gchar *mnc)
{
    if ((octs[0] & 0x0f) <= 9)
    {
	mcc[0] = Dgt_tbcd.out[octs[0] & 0x0f];
    }
    else
    {
	mcc[0] = (octs[0] & 0x0f) + 55;
    }

    if (((octs[0] & 0xf0) >> 4) <= 9)
    {
	mcc[1] = Dgt_tbcd.out[(octs[0] & 0xf0) >> 4];
    }
    else
    {
	mcc[1] = ((octs[0] & 0xf0) >> 4) + 55;
    }

    if ((octs[1] & 0x0f) <= 9)
    {
	mcc[2] = Dgt_tbcd.out[octs[1] & 0x0f];
    }
    else
    {
	mcc[2] = (octs[1] & 0x0f) + 55;
    }

    mcc[3] = '\0';

    if (((octs[1] & 0xf0) >> 4) <= 9)
    {
	mnc[2] = Dgt_tbcd.out[(octs[1] & 0xf0) >> 4];
    }
    else
    {
	mnc[2] = ((octs[1] & 0xf0) >> 4) + 55;
    }

    if ((octs[2] & 0x0f) <= 9)
    {
	mnc[0] = Dgt_tbcd.out[octs[2] & 0x0f];
    }
    else
    {
	mnc[0] = (octs[2] & 0x0f) + 55;
    }

    if (((octs[2] & 0xf0) >> 4) <= 9)
    {
	mnc[1] = Dgt_tbcd.out[(octs[2] & 0xf0) >> 4];
    }
    else
    {
	mnc[1] = ((octs[2] & 0xf0) >> 4) + 55;
    }

    if (mnc[1] == 'F')
    {
	/*
	 * only a 1 digit MNC (very old)
	 */
	mnc[1] = '\0';
    }
    else if (mnc[2] == 'F')
    {
	/*
	 * only a 2 digit MNC
	 */
	mnc[2] = '\0';
    }
    else
    {
	mnc[3] = '\0';
    }
}

typedef enum
{
    BE_CIC,	 /* Circuit Identity Code */
    BE_RSVD_1,	 /* Reserved */
    BE_RES_AVAIL,	 /* Resource Available */
    BE_CAUSE,	 /* Cause */
    BE_CELL_ID,	 /* Cell Identifier */
    BE_PRIO,	 /* Priority */
    BE_L3_HEADER_INFO,	 /* Layer 3 Header Information */
    BE_IMSI,	 /* IMSI */
    BE_TMSI,	 /* TMSI */
    BE_ENC_INFO,	 /* Encryption Information */
    BE_CHAN_TYPE,	 /* Channel Type */
    BE_PERIODICITY,	 /* Periodicity */
    BE_EXT_RES_IND,	 /* Extended Resource Indicator */
    BE_NUM_MS,	 /* Number Of MSs */
    BE_RSVD_2,	 /* Reserved */
    BE_RSVD_3,	 /* Reserved */
    BE_RSVD_4,	 /* Reserved */
    BE_CM_INFO_2,	 /* Classmark Information Type 2 */
    BE_CM_INFO_3,	 /* Classmark Information Type 3 */
    BE_INT_BAND,	 /* Interference Band To Be Used */
    BE_RR_CAUSE,	 /* RR Cause */
    BE_RSVD_5,	 /* Reserved */
    BE_L3_INFO,	 /* Layer 3 Information */
    BE_DLCI,	 /* DLCI */
    BE_DOWN_DTX_FLAG,	 /* Downlink DTX Flag */
    BE_CELL_ID_LIST,	 /* Cell Identifier List */
    BE_RESP_REQ,	 /* Response Request */
    BE_RES_IND_METHOD,	 /* Resource Indication Method */
    BE_CM_INFO_1,	 /* Classmark Information Type 1 */
    BE_CIC_LIST,	 /* Circuit Identity Code List */
    BE_DIAG,	 /* Diagnostic */
    BE_L3_MSG,	 /* Layer 3 Message Contents */
    BE_CHOSEN_CHAN,	 /* Chosen Channel */
    BE_TOT_RES_ACC,	 /* Total Resource Accessible */
    BE_CIPH_RESP_MODE,	 /* Cipher Response Mode */
    BE_CHAN_NEEDED,	 /* Channel Needed */
    BE_TRACE_TYPE,	 /* Trace Type */
    BE_TRIGGERID,	 /* TriggerID */
    BE_TRACE_REF,	 /* Trace Reference */
    BE_TRANSID,	 /* TransactionID */
    BE_MID,	 /* Mobile Identity */
    BE_OMCID,	 /* OMCID */
    BE_FOR_IND,	 /* Forward Indicator */
    BE_CHOSEN_ENC_ALG,	 /* Chosen Encryption Algorithm */
    BE_CCT_POOL,	 /* Circuit Pool */
    BE_CCT_POOL_LIST,	 /* Circuit Pool List */
    BE_TIME_IND,	 /* Time Indication */
    BE_RES_SIT,	 /* Resource Situation */
    BE_CURR_CHAN_1,	 /* Current Channel Type 1 */
    BE_QUE_IND,	 /* Queueing Indicator */
    BE_SPEECH_VER,	 /* Speech Version */
    BE_ASS_REQ,	 /* Assignment Requirement */
    BE_TALKER_FLAG,	 /* Talker Flag */
    BE_CONN_REL_REQ,	 /* Connection Release Requested */
    BE_GROUP_CALL_REF,	 /* Group Call Reference */
    BE_EMLPP_PRIO,	 /* eMLPP Priority */
    BE_CONF_EVO_IND,	 /* Configuration Evolution Indication */
    BE_OLD2NEW_INFO,	 /* Old BSS to New BSS Information */
    BE_LSA_ID,	 /* LSA Identifier */
    BE_LSA_ID_LIST,	 /* LSA Identifier List */
    BE_LSA_INFO,	 /* LSA Information */
    BE_LCS_QOS,	 /* LCS QoS */
    BE_LSA_ACC_CTRL,	 /* LSA access control suppression */
    BE_LCS_PRIO,	 /* LCS Priority */
    BE_LOC_TYPE,	 /* Location Type */
    BE_LOC_EST,	 /* Location Estimate */
    BE_POS_DATA,	 /* Positioning Data */
    BE_LCS_CAUSE,	 /* LCS Cause */
    BE_LCS_CLIENT,	 /* LCS Client Type */
    BE_APDU,	 /* APDU */
    BE_NE_ID,	 /* Network Element Identity */
    BE_GSP_ASSIST_DATA,	 /* GPS Assistance Data */
    BE_DECIPH_KEYS,	 /* Deciphering Keys */
    BE_RET_ERR_REQ,	 /* Return Error Request */
    BE_RET_ERR_CAUSE,	 /* Return Error Cause */
    BE_SEG,	 /* Segmentation */
    BE_NONE	/* NONE */
}
bssmap_elem_idx_t;

#define	NUM_GSM_BSSMAP_ELEM (sizeof(gsm_bssmap_elem_strings)/sizeof(value_string))
static gint ett_gsm_bssmap_elem[NUM_GSM_BSSMAP_ELEM];

/*
 * [2] 3.2.2.2
 */
static guint8
be_cic(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32	curr_offset;
    guint32	value;

    len = len;
    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, value, 0xffe0, 16);
    proto_tree_add_text(tree,
	tvb, curr_offset, 2,
	"%s :  PCM Multiplexer: %u",
	a_bigbuf,
	(value & 0xffe0) >> 5);

    other_decode_bitfield_value(a_bigbuf, value, 0x001f, 16);
    proto_tree_add_text(tree,
	tvb, curr_offset, 2,
	"%s :  Timeslot: %u",
	a_bigbuf,
	value & 0x001f);

    curr_offset += 2;

    if (add_string)
	g_snprintf(add_string, string_len, " - (%u) (0x%04x)", value, value);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.5
 */
static guint8
be_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint32	value;
    guint32	curr_offset;
    const gchar	*str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension: %s",
	a_bigbuf,
	(oct & 0x80) ? "extended" : "not extended");

    if (oct & 0x80)
    {
	/* 2 octet cause */

	if ((oct & 0x0f) == 0x00)
	{
	    /* national cause */
	    switch ((oct & 0x70) >> 4)
	    {
	    case 0: str = "Normal Event"; break;
	    case 1: str = "Normal Event"; break;
	    case 2: str = "Resource Unavailable"; break;
	    case 3: str = "Service or option not available"; break;
	    case 4: str = "Service or option not implemented"; break;
	    case 5: str = "Invalid message (e.g., parameter out of range)"; break;
	    case 6: str = "Protocol error"; break;
	    default:
		str = "Interworking";
		break;
	    }

	    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  Cause Class: %s",
		a_bigbuf,
		str);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  National Cause",
		a_bigbuf);

	    curr_offset++;

	    proto_tree_add_text(tree, tvb, curr_offset, 1,
		"Cause Value");

	    curr_offset++;

	    if (add_string)
		g_snprintf(add_string, string_len, " - (National Cause)");
	}
	else
	{
	    value = tvb_get_guint8(tvb, curr_offset + 1);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  Cause (MSB): %u",
		a_bigbuf,
		((oct & 0x7f) << 8) | value);

	    curr_offset++;

	    other_decode_bitfield_value(a_bigbuf, value, 0xff, 8);
	    proto_tree_add_text(tree, tvb, curr_offset, 1,
		"%s :  Cause (LSB)",
		a_bigbuf);

	    curr_offset++;
	}
    }
    else
    {
	switch (oct)
	{
	case 0x00: str = "Radio interface message failure"; break;
	case 0x01: str = "Radio interface failure"; break;
	case 0x02: str = "Uplink quality"; break;
	case 0x03: str = "Uplink strength"; break;
	case 0x04: str = "Downlink quality"; break;
	case 0x05: str = "Downlink strength"; break;
	case 0x06: str = "Distance"; break;
	case 0x07: str = "O and M intervention"; break;
	case 0x08: str = "Response to MSC invocation"; break;
	case 0x09: str = "Call control"; break;
	case 0x0a: str = "Radio interface failure, reversion to old channel"; break;
	case 0x0b: str = "Handover successful"; break;
	case 0x0c: str = "Better Cell"; break;
	case 0x0d: str = "Directed Retry"; break;
	case 0x0e: str = "Joined group call channel"; break;
	case 0x0f: str = "Traffic"; break;

	case 0x20: str = "Equipment failure"; break;
	case 0x21: str = "No radio resource available"; break;
	case 0x22: str = "Requested terrestrial resource unavailable"; break;
	case 0x23: str = "CCCH overload"; break;
	case 0x24: str = "Processor overload"; break;
	case 0x25: str = "BSS not equipped"; break;
	case 0x26: str = "MS not equipped"; break;
	case 0x27: str = "Invalid cell"; break;
	case 0x28: str = "Traffic Load"; break;
	case 0x29: str = "Preemption"; break;

	case 0x30: str = "Requested transcoding/rate adaption unavailable"; break;
	case 0x31: str = "Circuit pool mismatch"; break;
	case 0x32: str = "Switch circuit pool"; break;
	case 0x33: str = "Requested speech version unavailable"; break;
	case 0x34: str = "LSA not allowed"; break;

	case 0x40: str = "Ciphering algorithm not supported"; break;

	case 0x50: str = "Terrestrial circuit already allocated"; break;
	case 0x51: str = "Invalid message contents"; break;
	case 0x52: str = "Information element or field missing"; break;
	case 0x53: str = "Incorrect value"; break;
	case 0x54: str = "Unknown Message type"; break;
	case 0x55: str = "Unknown Information Element"; break;

	case 0x60: str = "Protocol Error between BSS and MSC"; break;
	case 0x61: str = "VGCS/VBS call non existent"; break;

	default:
	    if ((oct >= 0x10) && (oct <= 0x17)) { str = "Reserved for international use"; }
	    else if ((oct >= 0x18) && (oct <= 0x1f)) { str = "Reserved for national use"; }
	    else if ((oct >= 0x2a) && (oct <= 0x2f)) { str = "Reserved for national use"; }
	    else if ((oct >= 0x35) && (oct <= 0x3f)) { str = "Reserved for international use"; }
	    else if ((oct >= 0x41) && (oct <= 0x47)) { str = "Reserved for international use"; }
	    else if ((oct >= 0x48) && (oct <= 0x4f)) { str = "Reserved for national use"; }
	    else if ((oct >= 0x56) && (oct <= 0x57)) { str = "Reserved for international use"; }
	    else if ((oct >= 0x58) && (oct <= 0x5f)) { str = "Reserved for national use"; }
	    else if ((oct >= 0x62) && (oct <= 0x67)) { str = "Reserved for international use"; }
	    else if ((oct >= 0x68) && (oct <= 0x6f)) { str = "Reserved for national use"; }
	    else if ((oct >= 0x70) && (oct <= 0x77)) { str = "Reserved for international use"; }
	    else if ((oct >= 0x78) && (oct <= 0x7f)) { str = "Reserved for national use"; }
	    break;
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	proto_tree_add_uint_format(tree, hf_gsm_a_bssmap_cause,
	    tvb, curr_offset, 1, oct & 0x7f,
	    "%s :  Cause: (%u) %s",
	    a_bigbuf,
	    oct & 0x7f,
	    str);

	curr_offset++;

	if (add_string)
	    g_snprintf(add_string, string_len, " - (%u) %s", oct & 0x7f, str);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.7
 */
static guint8
be_tmsi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32	curr_offset;
    guint32	value;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_uint(tree, hf_gsm_a_tmsi,
	tvb, curr_offset, 4,
	value);

    if (add_string)
	g_snprintf(add_string, string_len, " - (0x%04x)", value);

    curr_offset += 4;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.9
 */
static guint8
be_l3_header_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, curr_offset, 1, FALSE);


    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  TI flag: %s",
	a_bigbuf,
	((oct & 0x08) ?  "allocated by receiver" : "allocated by sender"));

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  TIO: %u",
	a_bigbuf,
	oct & 0x07);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.10
 */
static guint8
be_enc_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint8	mask;
    guint8	alg_id;
    guint32	curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    mask = 0x80;
    alg_id = 7;

    do
    {
	other_decode_bitfield_value(a_bigbuf, oct, mask, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  GSM A5/%u: %spermitted",
	    a_bigbuf,
	    alg_id,
	    (mask & oct) ? "" : "not ");

	mask >>= 1;
	alg_id--;
    }
    while (mask != 0x01);

    other_decode_bitfield_value(a_bigbuf, oct, mask, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  No encryption: %spermitted",
	a_bigbuf,
	(mask & oct) ? "" : "not ");

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Key");

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.11
 */
static guint8
be_chan_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint8	sdi;
    guint8	num_chan;
    guint32	curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    sdi = oct & 0x0f;
    switch (sdi)
    {
    case 1: str = "Speech"; break;
    case 2: str = "Data"; break;
    case 3: str = "Signalling"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Speech/Data Indicator: %s",
	a_bigbuf,
	str);

    if (add_string)
	g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (sdi == 0x01)
    {
	/* speech */

	switch (oct)
	{
	case 0x08: str = "Full rate TCH channel Bm.  Prefer full rate TCH"; break;
	case 0x09: str = "Half rate TCH channel Lm.  Prefer half rate TCH"; break;
	case 0x0a: str = "Full or Half rate channel, Full rate preferred changes allowed after first allocation"; break;
	case 0x0b: str = "Full or Half rate channel, Half rate preferred changes allowed after first allocation"; break;
	case 0x1a: str = "Full or Half rate channel, Full rate preferred changes between full and half rate not allowed after first allocation"; break;
	case 0x1b: str = "Full or Half rate channel, Half rate preferred changes between full and half rate not allowed after first allocation"; break;
	case 0x0f: str = "Full or Half rate channel, changes allowed after first allocation"; break;
	case 0x1f: str = "Full or Half rate channel, changes between full and half rate not allowed after first allocation"; break;
	default:
	    str = "Reserved";
	    break;
	}

	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "Channel Rate and Type: %s",
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	do
	{
	    oct = tvb_get_guint8(tvb, curr_offset);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  Extension: %s",
		a_bigbuf,
		(oct & 0x80) ? "extended" : "not extended");

	    switch (oct & 0x7f)
	    {
	    case 0x01: str = "GSM speech full rate version 1"; break;
	    case 0x11: str = "GSM speech full rate version 2"; break;
	    case 0x21: str = "GSM speech full rate version 3 (AMR)"; break;

	    case 0x05: str = "GSM speech half rate version 1"; break;
	    case 0x15: str = "GSM speech half rate version 2"; break;
	    case 0x25: str = "GSM speech half rate version 3 (AMR)"; break;

	    default:
		str = "Reserved";
		break;
	    }

	    other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  Speech version identifier: %s",
		a_bigbuf,
		str);

	    curr_offset++;
	}
	while ((len - (curr_offset - offset)) > 0);
    }
    else if (sdi == 0x02)
    {
	/* data */

	num_chan = 0;

	switch (oct)
	{
	case 0x08: str = "Full rate TCH channel Bm"; break;
	case 0x09: str = "Half rate TCH channel Lm"; break;
	case 0x0a: str = "Full or Half rate TCH channel, Full rate preferred, changes allowed also after first channel allocation as a result of the request"; break;
	case 0x0b: str = "Full or Half rate TCH channel, Half rate preferred, changes allowed also after first channel allocation as a result of the request"; break;
	case 0x1a: str = "Full or Half rate TCH channel, Full rate preferred, changes not allowed after first channel allocation as a result of the request"; break;
	case 0x1b: str = "Full or Half rate TCH channel. Half rate preferred, changes not allowed after first channel allocation as a result of the request"; break;
	default:
	    if ((oct >= 0x20) && (oct <= 0x27))
	    {
		str = "Full rate TCH channels in a multislot configuration, changes by the BSS of the the number of TCHs and if applicable the used radio interface rate per channel allowed after first channel allocation as a result of the request";

		num_chan = (oct - 0x20) + 1;
	    }
	    else if ((oct >= 0x30) && (oct <= 0x37))
	    {
		str = "Full rate TCH channels in a multislot configuration, changes by the BSS of the number of TCHs or the used radio interface rate per channel not allowed after first channel allocation as a result of the request";

		num_chan = (oct - 0x30) + 1;
	    }
	    else
	    {
		str = "Reserved";
	    }
	    break;
	}

	if (num_chan > 0)
	{
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Channel Rate and Type: Max channels %u, %s",
		num_chan,
		str);
	}
	else
	{
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Channel Rate and Type: %s",
		str);
	}

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    (oct & 0x80) ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  %sTransparent service",
	    a_bigbuf,
	    (oct & 0x40) ? "Non-" : "");

	if (num_chan == 0)
	{
	    if (oct & 0x40)
	    {
		/* non-transparent */

		switch (oct & 0x3f)
		{
		case 0x00: str = "12 kbit/s if the channel is a full rate TCH, or 6 kbit/s if the channel is a half rate TCH"; break;
		case 0x18: str = "14.5 kbit/s"; break;
		case 0x10: str = "12 kbits/s"; break;
		case 0x11: str = "6 kbits/s"; break;
		default:
		    str = "Reserved";
		    break;
		}
	    }
	    else
	    {
		switch (oct & 0x3f)
		{
		case 0x18: str = "14.4 kbit/s"; break;
		case 0x10: str = "9.6kbit/s"; break;
		case 0x11: str = "4.8kbit/s"; break;
		case 0x12: str = "2.4kbit/s"; break;
		case 0x13: str = "1.2Kbit/s"; break;
		case 0x14: str = "600 bit/s"; break;
		case 0x15: str = "1200/75 bit/s (1200 network-to-MS / 75 MS-to-network)"; break;
		default:
		    str = "Reserved";
		    break;
		}
	    }
	}
	else
	{
	    if (oct & 0x40)
	    {
		/* non-transparent */

		switch (oct & 0x3f)
		{
		case 0x16: str = "58 kbit/s (4x14.5 kbit/s)"; break;
		case 0x14: str = "48.0 / 43.5 kbit/s (4x12 kbit/s or 3x14.5 kbit/s)"; break;
		case 0x13: str = "36.0 / 29.0 kbit/s (3x12 kbit/s or 2x14.5 kbit/s)"; break;
		case 0x12: str = "24.0 / 24.0 (4x6 kbit/s or 2x12 kbit/s)"; break;
		case 0x11: str = "18.0 / 14.5 kbit/s (3x6 kbit/s or 1x14.5 kbit/s)"; break;
		case 0x10: str = "12.0 / 12.0 kbit/s (2x6 kbit/s or 1x12 kbit/s)"; break;
		default:
		    str = "Reserved";
		    break;
		}
	    }
	    else
	    {
		switch (oct & 0x3f)
		{
		case 0x1f: str = "64 kbit/s, bit transparent"; break;
		case 0x1e: str = "56 kbit/s, bit transparent"; break;
		case 0x1d: str = "56 kbit/s"; break;
		case 0x1c: str = "48 kbit/s"; break;
		case 0x1b: str = "38.4 kbit/s"; break;
		case 0x1a: str = "28.8 kbit/s"; break;
		case 0x19: str = "19.2 kbit/s"; break;
		case 0x18: str = "14.4 kbit/s"; break;
		case 0x10: str = "9.6 kbit/s"; break;
		default:
		    str = "Reserved";
		    break;
		}
	    }
	}

	other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Rate: %s",
	    a_bigbuf,
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Extension: %s",
	    a_bigbuf,
	    (oct & 0x80) ? "extended" : "not extended");

	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Spare",
	    a_bigbuf);

	if (num_chan == 0)
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  14.5 kbit/s (TCH/F14.4) %sallowed",
		a_bigbuf,
		(oct & 0x08) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  Spare",
		a_bigbuf);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  12.0 kbit/s (TCH F/9.6) %sallowed",
		a_bigbuf,
		(oct & 0x02) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  6.0 kbit/s (TCH F/4.8) %sallowed",
		a_bigbuf,
		(oct & 0x01) ? "" : "not ");
	}
	else
	{
	    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  14.5/14.4 kbit/s (TCH/F14.4) %sallowed",
		a_bigbuf,
		(oct & 0x08) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  Spare",
		a_bigbuf);

	    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  12.0/9.6 kbit/s (TCH F/9.6) %sallowed",
		a_bigbuf,
		(oct & 0x02) ? "" : "not ");

	    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"%s :  6.0/4.8 kbit/s (TCH F/4.8) %sallowed",
		a_bigbuf,
		(oct & 0x01) ? "" : "not ");
	}

	curr_offset++;
    }
    else if (sdi == 0x03)
    {
	/* signalling */

	switch (oct)
	{
	case 0x00: str = "SDCCH or Full rate TCH channel Bm or Half rate TCH channel Lm"; break;
	case 0x01: str = "SDCCH"; break;
	case 0x02: str = "SDCCH or Full rate TCH channel Bm"; break;
	case 0x03: str = "SDCCH or Half rate TCH channel Lm"; break;
	case 0x08: str = "Full rate TCH channel Bm"; break;
	case 0x09: str = "Half rate TCH channel Lm"; break;
	case 0x0a: str = "Full or Half rate TCH channel, Full rate preferred, changes allowed also after first channel allocation as a result of the request"; break;
	case 0x0b: str = "Full or Half rate TCH channel, Half rate preferred, changes allowed also after first channel allocation as a result of the request"; break;
	case 0x1a: str = "Full or Half rate TCH channel, Full rate preferred, changes not allowed after first channel allocation as a result of the request"; break;
	case 0x1b: str = "Full or Half rate TCH channel. Half rate preferred, changes not allowed after first channel allocation as a result of the request"; break;
	default:
	    str = "Reserved";
	    break;
	}

	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "Channel Rate and Type: %s",
	    str);

	curr_offset++;

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_text(tree,
	    tvb, curr_offset, len - (curr_offset - offset),
	    "Spare");

	curr_offset += len - (curr_offset - offset);
    }
    else
    {
	/* unknown format */

	proto_tree_add_text(tree,
	    tvb, curr_offset, len - (curr_offset - offset),
	    "Unknown format");

	curr_offset += len - (curr_offset - offset);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.17
 * Formats everything after the discriminator, shared function
 */
static guint8
be_cell_id_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len, guint8 disc)
{
    guint8	octs[3];
    guint32	value;
    guint32	curr_offset;
    gchar	mcc[4];
    gchar	mnc[4];

    if (add_string)
	add_string[0] = '\0';
    curr_offset = offset;

    switch (disc)
    {
    case 0x00:
	/* FALLTHRU */

    case 0x04:
	/* FALLTHRU */

    case 0x08:  /* For intersystem handover from GSM to UMTS or cdma2000: */
	octs[0] = tvb_get_guint8(tvb, curr_offset);
	octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
	octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

	mcc_mnc_aux(octs, mcc, mnc);

	proto_tree_add_text(tree,
	    tvb, curr_offset, 3,
	    "Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
	    mcc,
	    mnc);

	curr_offset += 3;

	/* FALLTHRU */

    case 0x01:
    case 0x05:
	case 0x0a: /*For intersystem handover from GSM to UMTS or cdma2000: */

	/* LAC */

	value = tvb_get_ntohs(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_cell_lac, tvb, curr_offset, 2, FALSE);

	curr_offset += 2;

	if (add_string)
	    g_snprintf(add_string, string_len, " - LAC (0x%04x)", value);

	case 0x09: /* For intersystem handover from GSM to UMTS or cdma2000: */

	if ((disc == 0x08) ||(disc == 0x09) || (disc == 0x0a)){ 
		/* RNC-ID */
		value = tvb_get_ntohs(tvb, curr_offset);
		proto_tree_add_item(tree, hf_gsm_a_be_rnc_id, tvb, curr_offset, 2, FALSE);

		if (add_string)
		{
		    if (add_string[0] == '\0')
		    {
			g_snprintf(add_string, string_len, " - RNC-ID (%u)", value);
		    }
		    else
		    {
			g_snprintf(add_string, string_len, "%s/RNC-ID (%u)", add_string, value);
		    }
		}
		break;
	}

	if ((disc == 0x04) || (disc == 0x05) || (disc == 0x08)) break;

	/* FALLTHRU */

    case 0x02:

	/* CI */

	value = tvb_get_ntohs(tvb, curr_offset);

	proto_tree_add_uint(tree, hf_gsm_a_cell_ci, tvb,
	    curr_offset, 2, value);

	curr_offset += 2;

	if (add_string)
	{
	    if (add_string[0] == '\0')
	    {
		g_snprintf(add_string, string_len, " - CI (%u)", value);
	    }
	    else
	    {
		g_snprintf(add_string, string_len, "%s/CI (%u)", add_string, value);
	    }
	}
	break;

    default:
	proto_tree_add_text(tree, tvb, curr_offset, len,
	    "Cell ID - Unknown format");

	curr_offset += (len);
	break;
    }

    return(curr_offset - offset);
}

static guint8
be_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint8	disc;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    proto_tree_add_item(tree, hf_gsm_a_be_cell_id_disc, tvb, curr_offset, 1, FALSE);
	disc = oct&0x0f;
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    curr_offset +=
	be_cell_id_aux(tvb, tree, curr_offset, len - (curr_offset - offset), add_string, string_len, disc);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.18
 */
static guint8
be_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
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
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Preemption Capability Indicator (PCI): this allocation request %s preempt an existing connection",
	a_bigbuf,
	(oct & 0x40) ? "may" : "shall not");

    switch ((oct & 0x3c) >> 2)
    {
    case 0x00: str = "Spare"; break;
    case 0x0f: str = "priority not used"; break;
    default:
	str = "1 is highest";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x3c, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Priority Level: (%u) %s",
	a_bigbuf,
	(oct & 0x3c) >> 2,
	str);

    if (add_string)
	g_snprintf(add_string, string_len, " - (%u)", (oct & 0x3c) >> 2);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Queuing Allowed Indicator (QA): queuing %sallowed",
	a_bigbuf,
	(oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Preemption Vulnerability Indicator (PVI): this connection %s be preempted by another allocation request",
	a_bigbuf,
	(oct & 0x01) ? "might" : "shall not");

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.24
 */
static guint8
be_l3_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    tvbuff_t	*l3_tvb;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
	"Layer 3 Information value");

    /*
     * dissect the embedded DTAP message
     */
    l3_tvb = tvb_new_subset(tvb, curr_offset, len, len);

    call_dissector(dtap_handle, l3_tvb, g_pinfo, g_tree);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.25
 */
static guint8
be_dlci(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;
    proto_item	*item = NULL;
    proto_tree	*subtree = NULL;

    len = len;
    curr_offset = offset;

    item =
	proto_tree_add_text(tree, tvb, curr_offset, 1,
	    "Data Link Connection Identifier");

    subtree = proto_item_add_subtree(item, ett_dlci);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint(subtree, hf_gsm_a_dlci_cc, tvb, curr_offset, 1, oct);
    proto_tree_add_uint(subtree, hf_gsm_a_dlci_spare, tvb, curr_offset, 1, oct);
    proto_tree_add_uint(subtree, hf_gsm_a_dlci_sapi, tvb, curr_offset, 1, oct);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.26
 */
static guint8
be_down_dtx_flag(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint	oct;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfe, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  BSS is %s to activate DTX in the downlink direction",
	a_bigbuf,
	(oct & 0x01) ? "forbidden" : "allowed");

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.27
 */
guint8
be_cell_id_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint8	consumed;
    guint8	disc;
    guint8	num_cells;
    guint32	curr_offset;
    proto_item	*item = NULL;
    proto_tree	*subtree = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	disc = oct & 0x0f;
	proto_tree_add_item(tree, hf_gsm_a_be_cell_id_disc, tvb, curr_offset, 1, FALSE);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    num_cells = 0;
    do
    {
	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, -1,
		"Cell %u",
		num_cells + 1);

	subtree = proto_item_add_subtree(item, ett_cell_list);

	if (add_string)
	    add_string[0] = '\0';
	consumed =
	    be_cell_id_aux(tvb, subtree, curr_offset, len - (curr_offset - offset), add_string, string_len, disc);

	if (add_string && add_string[0] != '\0')
	{
	    proto_item_append_text(item, "%s", add_string ? add_string : "");
	}

	proto_item_set_len(item, consumed);

	curr_offset += consumed;

	num_cells++;
    }
    while ((len - (curr_offset - offset)) > 0);

    if (add_string) {
	g_snprintf(add_string, string_len, " - %u cell%s",
	    num_cells, plurality(num_cells, "", "s"));
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.33
 */
static guint8
be_chosen_chan(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str = NULL;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch ((oct & 0xf0) >> 4)
    {
    case 0: str = "No channel mode indication"; break;
    case 9: str = "Speech (full rate or half rate)"; break;
    case 14: str = "Data, 14.5 kbit/s radio interface rate"; break;
    case 11: str = "Data, 12.0 kbit/s radio interface rate"; break;
    case 12: str = "Data, 6.0 kbit/s radio interface rate"; break;
    case 13: str = "Data, 3.6 kbit/s radio interface rate"; break;
    case 8: str = "Signalling only"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Channel mode: %s",
	a_bigbuf,
	str);

    switch (oct & 0x0f)
    {
    case 0: str = "None"; break;
    case 1: str = "SDCCH"; break;
    case 8: str = "1 Full rate TCH"; break;
    case 9: str = "1 Half rate TCH"; break;
    case 10: str = "2 Full Rate TCHs"; break;
    case 11: str = "3 Full Rate TCHs"; break;
    case 12: str = "4 Full Rate TCHs"; break;
    case 13: str = "5 Full Rate TCHs"; break;
    case 14: str = "6 Full Rate TCHs"; break;
    case 15: str = "7 Full Rate TCHs"; break;
    case 4: str = "8 Full Rate TCHs"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Channel: %s",
	a_bigbuf,
	str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.34
 */
static guint8
be_ciph_resp_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfe, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  IMEISV must %sbe included by the mobile station",
	a_bigbuf,
	(oct & 0x01) ? "" : "not ");

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.35
 */
static guint8
be_l3_msg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    tvbuff_t	*l3_tvb;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
	"Layer 3 Message Contents");

    /*
     * dissect the embedded DTAP message
     */
    l3_tvb = tvb_new_subset(tvb, curr_offset, len, len);

    call_dissector(dtap_handle, l3_tvb, g_pinfo, g_tree);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.43
 */
static guint8
be_for_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str = NULL;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    switch (oct & 0x0f)
    {
    case 1: str = "forward to subsequent BSS, no trace at MSC"; break;
    case 2: str = "forward to subsequent BSS, and trace at MSC"; break;
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
 * [2] 3.2.2.44
 */
static guint8
be_chosen_enc_alg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str = NULL;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0x01: str = "No encryption used"; break;
    case 0x02: str = "GSM A5/1"; break;
    case 0x03: str = "GSM A5/2"; break;
    case 0x04: str = "GSM A5/3"; break;
    case 0x05: str = "GSM A5/4"; break;
    case 0x06: str = "GSM A5/5"; break;
    case 0x07: str = "GSM A5/6"; break;
    case 0x08: str = "GSM A5/7"; break;
    default:
	str = "Reserved";
	break;
    }

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Algorithm Identifier: %s",
	str);

    curr_offset++;

    if (add_string)
	g_snprintf(add_string, string_len, " - %s", str);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.45
 */
static guint8
be_cct_pool(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str = NULL;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct <= 32)
    {
	str = "";
    }
    else if ((oct >= 0x80) && (oct <= 0x8f))
    {
	str = ", for national/local use";
    }
    else
    {
	str = ", reserved for future international use";
    }

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Circuit pool number: %u%s",
	oct,
	str);

    curr_offset++;

    if (add_string)
	g_snprintf(add_string, string_len, " - (%u)", oct);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.49
 */
static guint8
be_curr_chan_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch ((oct & 0xf0) >> 4)
    {
    case 0x00: str = "Signalling only"; break;
    case 0x01: str = "Speech (full rate or half rate)"; break;
    case 0x06: str = "Data, 14.5 kbit/s radio interface rate"; break;
    case 0x03: str = "Data, 12.0 kbit/s radio interface rate"; break;
    case 0x04: str = "Data, 6.0 kbit/s radio interface rate"; break;
    case 0x05: str = "Data, 3.6 kbit/s radio interface rate"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Channel Mode: %s",
	a_bigbuf,
	str);

    switch (oct & 0x0f)
    {
    case 0x01: str = "SDCCH"; break;
    case 0x08: str = "1 Full rate TCH"; break;
    case 0x09: str = "1 Half rate TCH"; break;
    case 0x0a: str = "2 Full Rate TCHs"; break;
    case 0x0b: str = "3 Full Rate TCHs"; break;
    case 0x0c: str = "4 Full Rate TCHs"; break;
    case 0x0d: str = "5 Full Rate TCHs"; break;
    case 0x0e: str = "6 Full Rate TCHs"; break;
    case 0x0f: str = "7 Full Rate TCHs"; break;
    case 0x04: str = "8 Full Rate TCHs"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Channel: (%u) %s",
	a_bigbuf,
	oct & 0x0f,
	str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.50
 */
static guint8
be_que_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  qri: it is recommended %sto allow queuing",
	a_bigbuf,
	(oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.51
 */
static guint8
be_speech_ver(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str = NULL;
    const gchar	*short_str = NULL;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    switch (oct & 0x7f)
    {
    case 0x01: str = "GSM speech full rate version 1"; short_str = "FR1"; break;
    case 0x11: str = "GSM speech full rate version 2"; short_str = "FR2"; break;
    case 0x21: str = "GSM speech full rate version 3 (AMR)"; short_str = "FR3 (AMR)"; break;

    case 0x05: str = "GSM speech half rate version 1"; short_str = "HR1"; break;
    case 0x15: str = "GSM speech half rate version 2"; short_str = "HR2"; break;
    case 0x25: str = "GSM speech half rate version 3 (AMR)"; short_str = "HR3 (AMR)"; break;

    default:
	str = "Reserved";
	short_str = str;
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Speech version identifier: %s",
	a_bigbuf,
	str);

    curr_offset++;

    if (add_string)
	g_snprintf(add_string, string_len, " - (%s)", short_str);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.68
 */
static guint8
be_apdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
	"APDU");

    /*
     * dissect the embedded APDU message
     * if someone writes a TS 09.31 dissector
     */

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

typedef enum
{
    /* Common Information Elements 10.5.1 */
    DE_CELL_ID,	/* Cell Identity */
    DE_CIPH_KEY_SEQ_NUM,	/* Ciphering Key Sequence Number */
    DE_LAI,	/* Location Area Identification */
    DE_MID,	/* Mobile Identity */
    DE_MS_CM_1,	/* Mobile Station Classmark 1 */
    DE_MS_CM_2,	/* Mobile Station Classmark 2 */
    DE_MS_CM_3,	/* Mobile Station Classmark 3 */
    DE_D_GB_CALL_REF,	/* Descriptive group or broadcast call reference */
    DE_G_CIPH_KEY_NUM,	/* Group Cipher Key Number */
    DE_PD_SAPI,	/* PD and SAPI $(CCBS)$ */
    DE_PRIO,	/* Priority Level */
    DE_PLMN_LIST,	/* PLMN List */

    /* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1	*/
/*
 * [3]  10.5.2.1a	BA Range
 */
	DE_RR_CELL_CH_DSC,				/* [3]  10.5.2.1b	Cell Channel Description	*/

/* [3]  10.5.2.1c	BA List Pref
 * [3]  10.5.2.1d	UTRAN Frequency List
 * [3]  10.5.2.1e	Cell selection indicator after release of all TCH and SDCCH IE
 */
	DE_RR_CELL_DSC,					/* 10.5.2.2   RR Cell Description				*/
/*
 * [3]  10.5.2.3	Cell Options (BCCH)	
 * [3]  10.5.2.3a	Cell Options (SACCH)
 * [3]  10.5.2.4	Cell Selection Parameters
 * [3]  10.5.2.4a	(void)
 */
	DE_RR_CH_DSC,					/* [3]  10.5.2.5	Channel Description			*/
	DE_RR_CH_DSC2,					/* [3]  10.5.2.5a   Channel Description 2 		*/
	DE_RR_CH_MODE,					/* [3]  10.5.2.6	Channel Mode				*/
	DE_RR_CH_MODE2,					/* [3]  10.5.2.7	Channel Mode 2				*/
/* [3]  10.5.2.7a	UTRAN predefined configuration status information / START-CS / UE CapabilityUTRAN Classmark information element	218
 * [3]  10.5.2.7b	(void) */
	DE_RR_CM_ENQ_MASK,				/* [3]  10.5.2.7c	Classmark Enquiry Mask		*/
/* [3]  10.5.2.7d	GERAN Iu Mode Classmark information element
 * [3]  10.5.2.8	Channel Needed
 * [3]  10.5.2.8a	(void)	
 * [3]  10.5.2.8b	Channel Request Description 2 */
	DE_RR_CIP_MODE_SET,				/* [3]  10.5.2.9	Cipher Mode Setting			*/
/* [3]  10.5.2.10	Cipher Response
 * [3]  10.5.2.11	Control Channel Description
 * [3]  10.5.2.11a	DTM Information Details */
	DE_RR_DYN_ARFCN_MAP,			/* [3]  10.5.2.11b	Dynamic ARFCN Mapping		*/
	DE_RR_FREQ_CH_SEQ,				/* [3]  10.5.2.12	Frequency Channel Sequence	*/
	DE_RR_FREQ_LIST,				/* [3]  10.5.2.13	Frequency List				*/
	DE_RR_FREQ_SHORT_LIST,			/* [3]  10.5.2.14	Frequency Short List		*/
	DE_RR_FREQ_SHORT_LIST2,			/* [3]  10.5.2.14a	Frequency Short List 2		*/
/* [3]  10.5.2.14b	Group Channel Description
 * [3]  10.5.2.14c	GPRS Resumption
 * [3]  10.5.2.14d	GPRS broadcast information
 * [3]  10.5.2.14e	Enhanced DTM CS Release Indication
 */

	DE_RR_HO_REF,					/* 10.5.2.15  Handover Reference				*/
/*
 * [3] 10.5.2.16 IA Rest Octets
 * [3] 10.5.2.17 IAR Rest Octets
 * [3] 10.5.2.18 IAX Rest Octets
 * [3] 10.5.2.19 L2 Pseudo Length
 * [3] 10.5.2.20 Measurement Results
 * [3] 10.5.2.20a GPRS Measurement Results
 */
	DE_RR_MOB_ALL,					/* [3] 10.5.2.21 Mobile Allocation				*/
	DE_RR_MOB_TIME_DIFF,			/* [3] 10.5.2.21a Mobile Time Difference		*/
	DE_RR_MULTIRATE_CONF,			/* [3] 10.5.2.21aa MultiRate configuration		*/
	DE_RR_MULT_ALL,					/* [3] 10.5.2.21b Multislot Allocation			*/

/*
 * [3] 10.5.2.21c NC mode
 * [3] 10.5.2.22 Neighbour Cell Description
 * [3] 10.5.2.22a Neighbour Cell Description 2
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets
 * [3] 10.5.2.25a Packet Channel Description
 * [3] 10.5.2.25b Dedicated mode or TBF
 * [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 * [3] 10.5.2.26 Page Mode
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 * [3] 10.5.2.27 NCC Permitted
 */
	DE_RR_POW_CMD,					/* 10.5.2.28  Power Command						*/
	DE_RR_POW_CMD_AND_ACC_TYPE,		/* 10.5.2.28a Power Command and access type		*/
/*
 * [3] 10.5.2.29 RACH Control Parameters
 * [3] 10.5.2.30 Request Reference
 */
    DE_RR_CAUSE,					/* 10.5.2.31  RR Cause							*/
	DE_RR_SYNC_IND,					/* 10.5.2.39  Synchronization Indication		*/
/* [3] 10.5.2.32 SI 1 Rest Octets
 * [3] 10.5.2.33 SI 2bis Rest Octets 
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 * [3] 10.5.2.34 SI 3 Rest Octets
 * [3] 10.5.2.35 SI 4 Rest Octets
 * [3] 10.5.2.35a SI 6 Rest Octets
 * [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 * [3] 10.5.2.37b SI 13 Rest Octets
 * [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
	DE_RR_STARTING_TIME,			/* [3] 10.5.2.38 Starting Time					*/
	DE_RR_TIMING_ADV,				/* [3] 10.5.2.40 Timing Advance					*/
	DE_RR_TIME_DIFF,				/* [3] 10.5.2.41 Time Difference				*/
	DE_RR_TLLI,						/* [3] 10.5.2.41a TLLI							*/
/*
 * [3] 10.5.2.42 TMSI/P-TMSI */
	DE_RR_VGCS_TAR_MODE_IND,		/* [3] 10.5.2.42a VGCS target mode Indication	*/
	DE_RR_VGCS_CIP_PAR,				/* [3] 10.5.2.42b	VGCS Ciphering Parameters	*/

/* [3] 10.5.2.43 Wait Indication
 * [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List */
	DE_RR_SUS_CAU,					/* [3] 10.5.2.47 Suspension Cause				*/
/* [3] 10.5.2.48 APDU ID 
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command 
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell */
	DE_RR_DED_SERV_INF,				/* [3] 10.5.2.59	Dedicated Service Information */


    /* Mobility Management Information Elements 10.5.3 */
    DE_AUTH_PARAM_RAND,				/* Authentication Parameter RAND */
    DE_AUTH_PARAM_AUTN,				/* Authentication Parameter AUTN (UMTS authentication challenge only) */
    DE_AUTH_RESP_PARAM,				/* Authentication Response Parameter */
    DE_AUTH_RESP_PARAM_EXT,			/* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
    DE_AUTH_FAIL_PARAM,				/* Authentication Failure Parameter (UMTS authentication challenge only) */
    DE_CM_SRVC_TYPE,				/* CM Service Type */
    DE_ID_TYPE,						/* Identity Type */
    DE_LOC_UPD_TYPE,				/* Location Updating Type */
    DE_NETWORK_NAME,				/* Network Name */
    DE_REJ_CAUSE,					/* Reject Cause */
    DE_FOP,							/* Follow-on Proceed */
    DE_TIME_ZONE,					/* Time Zone */
    DE_TIME_ZONE_TIME,				/* Time Zone and Time */
    DE_CTS_PERM,					/* CTS Permission */
    DE_LSA_ID,						/* LSA Identifier */
    DE_DAY_SAVING_TIME,				/* Daylight Saving Time */
    DE_EMERGENCY_NUM_LIST,			/* Emergency Number List */
    /* Call Control Information Elements 10.5.4 */
    DE_AUX_STATES,					/* Auxiliary States */
    DE_BEARER_CAP,					/* Bearer Capability */
    DE_CC_CAP,						/* Call Control Capabilities */
    DE_CALL_STATE,					/* Call State */
    DE_CLD_PARTY_BCD_NUM,			/* Called Party BCD Number */
    DE_CLD_PARTY_SUB_ADDR,			/* Called Party Subaddress */
    DE_CLG_PARTY_BCD_NUM,			/* Calling Party BCD Number */
    DE_CLG_PARTY_SUB_ADDR,			/* Calling Party Subaddress */
    DE_CAUSE,						/* Cause */
    DE_CLIR_SUP,					/* CLIR Suppression */
    DE_CLIR_INV,					/* CLIR Invocation */
    DE_CONGESTION,					/* Congestion Level */
    DE_CONN_NUM,					/* Connected Number */
    DE_CONN_SUB_ADDR,				/* Connected Subaddress */
    DE_FACILITY,					/* Facility */
    DE_HLC,							/* High Layer Compatibility */
    DE_KEYPAD_FACILITY,				/* Keypad Facility */
    DE_LLC,							/* Low Layer Compatibility */
    DE_MORE_DATA,					/* More Data */
    DE_NOT_IND,						/* Notification Indicator */
    DE_PROG_IND,					/* Progress Indicator */
    DE_RECALL_TYPE,					/* Recall type $(CCBS)$ */
    DE_RED_PARTY_BCD_NUM,			/* Redirecting Party BCD Number */
    DE_RED_PARTY_SUB_ADDR,			/* Redirecting Party Subaddress */
    DE_REPEAT_IND,					/* Repeat Indicator */
    DE_REV_CALL_SETUP_DIR,			/* Reverse Call Setup Direction */
    DE_SETUP_CONTAINER,				/* SETUP Container $(CCBS)$ */
    DE_SIGNAL,						/* Signal */
    DE_SS_VER_IND,					/* SS Version Indicator */
    DE_USER_USER,					/* User-user */
    DE_ALERT_PATTERN,				/* Alerting Pattern $(NIA)$ */
    DE_ALLOWED_ACTIONS,				/* Allowed Actions $(CCBS)$ */
    DE_SI,							/* Stream Identifier */
    DE_NET_CC_CAP,					/* Network Call Control Capabilities */
    DE_CAUSE_NO_CLI,				/* Cause of No CLI */
    DE_IMM_MOD_IND,					/* Immediate Modification Indicator */
    DE_SUP_CODEC_LIST,				/* Supported Codec List */
    DE_SRVC_CAT,					/* Service Category */
    /* GPRS Mobility Management Information Elements 10.5.5 */
    DE_ATTACH_RES,					/* [7] 10.5.1 Attach Result*/
    DE_ATTACH_TYPE,					/* [7] 10.5.2 Attach Type */
    DE_CIPH_ALG,					/* [7] 10.5.3 Cipher Algorithm */
    DE_TMSI_STAT,					/* [7] 10.5.4 TMSI Status */
    DE_DETACH_TYPE,					/* [7] 10.5.5 Detach Type */
    DE_DRX_PARAM,					/* [7] 10.5.6 DRX Parameter */
    DE_FORCE_TO_STAND,				/* [7] 10.5.7 Force to Standby */
    DE_FORCE_TO_STAND_H,			/* [7] 10.5.8 Force to Standby - Info is in the high nibble */
    DE_P_TMSI_SIG,					/* [7] 10.5.9 P-TMSI Signature */
    DE_P_TMSI_SIG_2,				/* [7] 10.5.10 P-TMSI Signature 2 */
    DE_ID_TYPE_2,					/* [7] 10.5.11 Identity Type 2 */
    DE_IMEISV_REQ,					/* [7] 10.5.12 IMEISV Request */
    DE_REC_N_PDU_NUM_LIST,			/* [7] 10.5.13 Receive N-PDU Numbers List */
    DE_MS_NET_CAP,					/* [7] 10.5.14 MS Network Capability */
    DE_MS_RAD_ACC_CAP,				/* [7] 10.5.15 MS Radio Access Capability */
    DE_GMM_CAUSE,					/* [7] 10.5.16 GMM Cause */
    DE_RAI,							/* [7] 10.5.17 Routing Area Identification */
    DE_UPD_RES,						/* [7] 10.5.18 Update Result */
    DE_UPD_TYPE,					/* [7] 10.5.19 Update Type */
    DE_AC_REF_NUM,					/* [7] 10.5.20 A&C Reference Number */
    DE_AC_REF_NUM_H,				/* A&C Reference Number - Info is in the high nibble */
    DE_SRVC_TYPE,					/* [7] 10.5.20 Service Type */
    DE_CELL_NOT,					/* [7] 10.5.21 Cell Notification */
    DE_PS_LCS_CAP,					/* [7] 10.5.22 PS LCS Capability */
    DE_NET_FEAT_SUP,				/* [7] 10.5.23 Network Feature Support */
	DE_RAT_INFO_CONTAINER,			/* [7] 10.5.24 Inter RAT information container */
	/* [7] 10.5.25 Requested MS information */

    /* Short Message Service Information Elements [5] 8.1.4 */
    DE_CP_USER_DATA,				/* CP-User Data */
    DE_CP_CAUSE,					/* CP-Cause */
    /* Short Message Service Information Elements [5] 8.2 */
    DE_RP_MESSAGE_REF,				/* RP-Message Reference */
    DE_RP_ORIG_ADDR,				/* RP-Origination Address */
    DE_RP_DEST_ADDR,				/* RP-Destination Address */
    DE_RP_USER_DATA,				/* RP-User Data */
    DE_RP_CAUSE,					/* RP-Cause */
    /* Session Management Information Elements 10.5.6 */
    DE_ACC_POINT_NAME,				/* Access Point Name */
    DE_NET_SAPI,					/* Network Service Access Point Identifier */
    DE_PRO_CONF_OPT,				/* Protocol Configuration Options */
    DE_PD_PRO_ADDR,					/* Packet Data Protocol Address */
    DE_QOS,							/* Quality Of Service */
    DE_SM_CAUSE,					/* SM Cause */
    DE_LINKED_TI,					/* Linked TI */
    DE_LLC_SAPI,					/* LLC Service Access Point Identifier */
    DE_TEAR_DOWN_IND,				/* Tear Down Indicator */
    DE_PACKET_FLOW_ID,				/* Packet Flow Identifier */
    DE_TRAFFIC_FLOW_TEMPLATE,		/* Traffic Flow Template */
    /* GPRS Common Information Elements 10.5.7 */
    DE_PDP_CONTEXT_STAT,			/* [8] 10.5.7.1		PDP Context Status */
    DE_RAD_PRIO,					/* [8] 10.5.7.2		Radio Priority */
    DE_GPRS_TIMER,					/* [8] 10.5.7.3		GPRS Timer */
    DE_GPRS_TIMER_2,				/* [8] 10.5.7.4		GPRS Timer 2 */
    DE_RAD_PRIO_2,					/* [8] 10.5.7.5		Radio Priority 2 */
	DE_MBMS_CTX_STATUS,				/* [8] 10.5.7.6		MBMS context status */
    DE_SPARE_NIBBLE,				/* Spare Nibble */
    DE_NONE							/* NONE */
}
dtap_elem_idx_t;

#define	NUM_GSM_DTAP_ELEM (sizeof(gsm_dtap_elem_strings)/sizeof(value_string))
static gint ett_gsm_dtap_elem[NUM_GSM_DTAP_ELEM];

/*
 * [3] 10.5.1.1
 */
static guint8
de_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32	curr_offset;

    curr_offset = offset;

    curr_offset +=
		/* Is this correct???? - Anders Broman */
	be_cell_id_aux(tvb, tree, offset, len, add_string, string_len, 0x02);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.3
 */
guint8
de_lai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	octs[3];
    guint16	value;
    guint32	curr_offset;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	mcc[4];
    gchar	mnc[4];

    len = len;
    curr_offset = offset;

    item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 5,
	    gsm_dtap_elem_strings[DE_LAI].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_LAI]);

    octs[0] = tvb_get_guint8(tvb, curr_offset);
    octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
    octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

    mcc_mnc_aux(octs, mcc, mnc);


    proto_tree_add_text(subtree,
	tvb, curr_offset, 3,
	"Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
	mcc,
	mnc);

    curr_offset += 3;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_text(subtree,
	tvb, curr_offset, 2,
	"Location Area Code (LAC): 0x%04x (%u)",
	value,
	value);

    proto_item_append_text(item, " - LAC (0x%04x)", value);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.4
 */
guint8
de_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint32	curr_offset;
    guint8	*poctets;
    guint32	value;
    gboolean	odd;

    curr_offset = offset;
    odd = FALSE;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x07)
    {
    case 0:	/* No Identity */
	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Unused",
	    a_bigbuf);

	proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);

	if (add_string)
	    g_snprintf(add_string, string_len, " - No Identity Code");

	curr_offset++;

	if (len > 1)
	{
	    proto_tree_add_text(tree, tvb, curr_offset, len - 1,
		"Format not supported");
	}

	curr_offset += len - 1;
	break;

    case 3:	/* IMEISV */

	/* FALLTHRU */

    case 1:	/* IMSI */

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Identity Digit 1: %c",
	    a_bigbuf,
	    Dgt_msid.out[(oct & 0xf0) >> 4]);

	odd = oct & 0x08;

	proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);


	a_bigbuf[0] = Dgt_msid.out[(oct & 0xf0) >> 4];
	curr_offset++;

	poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

	my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
	    &Dgt_msid);

	proto_tree_add_string_format(tree,
	    ((oct & 0x07) == 3) ? hf_gsm_a_imeisv : hf_gsm_a_imsi,
	    tvb, curr_offset, len - (curr_offset - offset),
	    a_bigbuf,
	    "BCD Digits: %s",
	    a_bigbuf);

	if (add_string)
	    g_snprintf(add_string, string_len, " - %s (%s)",
		((oct & 0x07) == 3) ? "IMEISV" : "IMSI",
		a_bigbuf);

	curr_offset += len - (curr_offset - offset);

	if (!odd)
	{
	    oct = tvb_get_guint8(tvb, curr_offset - 1);

	    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	    proto_tree_add_text(tree,
		tvb, curr_offset - 1, 1,
		"%s :  Filler",
		a_bigbuf);
	}
	break;

    case 2:	/* IMEI */
	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Identity Digit 1: %c",
	    a_bigbuf,
	    Dgt_msid.out[(oct & 0xf0) >> 4]);

	proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);


	a_bigbuf[0] = Dgt_msid.out[(oct & 0xf0) >> 4];
	curr_offset++;

	poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

	my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
	    &Dgt_msid);

	proto_tree_add_string_format(tree,
	    hf_gsm_a_imei,
	    tvb, curr_offset, len - (curr_offset - offset),
	    a_bigbuf,
	    "BCD Digits: %s",
	    a_bigbuf);

	if (add_string)
	    g_snprintf(add_string, string_len, " - IMEI (%s)", a_bigbuf);

	curr_offset += len - (curr_offset - offset);
	break;

    case 4:	/* TMSI/P-TMSI */
	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Unused",
	    a_bigbuf);

	proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);


	curr_offset++;

	value = tvb_get_ntohl(tvb, curr_offset);

	proto_tree_add_uint(tree, hf_gsm_a_tmsi,
	    tvb, curr_offset, 4,
	    value);

	if (add_string)
	    g_snprintf(add_string, string_len, " - TMSI/P-TMSI (0x%04x)", value);

	curr_offset += 4;
	break;

    default:	/* Reserved */
	proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, FALSE);
 	proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, FALSE);
	proto_tree_add_text(tree, tvb, curr_offset, len,
	    "Mobile station identity Format %u, Format Unknown",(oct & 0x07));

	if (add_string)
	    g_snprintf(add_string, string_len, " - Format Unknown");

	curr_offset += len;
	break;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.5
 */
static guint8
de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;
    proto_tree	*subtree;
    proto_item	*item;
    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_MS_CM_1].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_MS_CM_1]);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    proto_tree_add_item(subtree, hf_gsm_a_MSC_rev, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(subtree, hf_gsm_a_ES_IND, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(subtree, hf_gsm_a_A5_1_algorithm_sup, tvb, curr_offset, 1, FALSE);

    proto_tree_add_item(subtree, hf_gsm_a_RF_power_capability, tvb, curr_offset, 1, FALSE);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.6
 */
guint8
de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    curr_offset = offset;


    proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_MSC_rev, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_ES_IND, tvb, curr_offset, 1, FALSE);

	proto_tree_add_item(tree, hf_gsm_a_A5_1_algorithm_sup, tvb, curr_offset, 1, FALSE);

    proto_tree_add_item(tree, hf_gsm_a_RF_power_capability, tvb, curr_offset, 1, FALSE);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);

    proto_tree_add_item(tree, hf_gsm_a_ps_sup_cap, tvb, curr_offset, 1, FALSE);

    proto_tree_add_item(tree, hf_gsm_a_SS_screening_indicator, tvb, curr_offset, 1, FALSE);

    /* SM capability (MT SMS pt to pt capability) (octet 4)*/
	proto_tree_add_item(tree, hf_gsm_a_SM_capability, tvb, curr_offset, 1, FALSE);
	/* VBS notification reception (octet 4) */
	proto_tree_add_item(tree, hf_gsm_a_VBS_notification_rec, tvb, curr_offset, 1, FALSE);
	/*VGCS notification reception (octet 4)*/
	proto_tree_add_item(tree, hf_gsm_a_VGCS_notification_rec, tvb, curr_offset, 1, FALSE);
	/* FC Frequency Capability (octet 4 ) */
	proto_tree_add_item(tree, hf_gsm_a_FC_frequency_cap, tvb, curr_offset, 1, FALSE);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

	/* CM3 (octet 5, bit 8) */
	proto_tree_add_item(tree, hf_gsm_a_CM3, tvb, curr_offset, 1, FALSE);
	/* spare bit 7 */
        proto_tree_add_item(tree, hf_gsm_a_b7spare, tvb, curr_offset, 1, FALSE);
	/* LCS VA capability (LCS value added location request notification capability) (octet 5,bit 6) */
	proto_tree_add_item(tree, hf_gsm_a_LCS_VA_cap, tvb, curr_offset, 1, FALSE);
	/* UCS2 treatment (octet 5, bit 5) */
	proto_tree_add_item(tree, hf_gsm_a_UCS2_treatment, tvb, curr_offset, 1, FALSE);
	/* SoLSA (octet 5, bit 4) */
	proto_tree_add_item(tree, hf_gsm_a_SoLSA, tvb, curr_offset, 1, FALSE);
	/* CMSP: CM Service Prompt (octet 5, bit 3) */
	proto_tree_add_item(tree, hf_gsm_a_CMSP, tvb, curr_offset, 1, FALSE);
	/* A5/3 algorithm supported (octet 5, bit 2) */
	proto_tree_add_item(tree, hf_gsm_a_A5_3_algorithm_sup, tvb, curr_offset, 1, FALSE);
	/* A5/2 algorithm supported (octet 5, bit 1) */
	proto_tree_add_item(tree, hf_gsm_a_A5_2_algorithm_sup, tvb, curr_offset, 1, FALSE);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.9
 */
static guint8
de_d_gb_call_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	value;
    guint32	curr_offset;
    const gchar *str;

    len = len;
    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, value, 0xffffffe0, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
	"%s :  Group or Broadcast call reference: %u (0x%04x)",
	a_bigbuf,
	(value & 0xffffffe0) >> 5,
	(value & 0xffffffe0) >> 5);

    other_decode_bitfield_value(a_bigbuf, value, 0x00000010, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
	"%s :  SF Service Flag: %s",
	a_bigbuf,
	(value & 0x00000010) ?
	    "VGCS (Group call reference)" : "VBS (Broadcast call reference)");

    other_decode_bitfield_value(a_bigbuf, value, 0x00000008, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
	"%s :  AF Acknowledgement Flag: acknowledgment is %srequired",
	a_bigbuf,
	(value & 0x00000008) ? "" : "not ");

    switch (value & 0x00000007)
    {
    case 1: str = "call priority level 4"; break;
    case 2: str = "call priority level 3"; break;
    case 3: str = "call priority level 2"; break;
    case 4: str = "call priority level 1"; break;
    case 5: str = "call priority level 0"; break;
    case 6: str = "call priority level B"; break;
    case 7: str = "call priority level A"; break;
    default:
	str = "no priority applied";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, value, 0x00000007, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
	"%s :  Call Priority: %s",
	a_bigbuf,
	str);

    curr_offset += 4;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
	"%s :  Ciphering Information",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.10a
 */
static guint8
de_pd_sapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
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
	    gsm_dtap_elem_strings[DE_PD_SAPI].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_PD_SAPI]);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    switch ((oct & 0x30) >> 4)
    {
    case 0: str = "SAPI 0"; break;
    case 3: str = "SAPI 3"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
	"%s :  SAPI (Sevice Access Point Identifier): %s",
	a_bigbuf,
	str);

    proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, curr_offset, 1, FALSE);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.11
 */
static guint8
de_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    switch (oct & 0x07)
    {
    case 1: str = "Call priority level 4"; break;
    case 2: str = "Call priority level 3"; break;
    case 3: str = "Call priority level 2"; break;
    case 4: str = "Call priority level 1"; break;
    case 5: str = "Call priority level 0"; break;
    case 6: str = "Call priority level B"; break;
    case 7: str = "Call priority level A"; break;
    default:
	str = "No priority applied";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
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
 * [3] 10.5.1.13
 */
static guint8
de_plmn_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	octs[3];
    guint32	curr_offset;
    gchar	mcc[4];
    gchar	mnc[4];
    guint8	num_plmn;

    curr_offset = offset;

    num_plmn = 0;
    while ((len - (curr_offset - offset)) >= 3)
    {
	octs[0] = tvb_get_guint8(tvb, curr_offset);
	octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
	octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

	mcc_mnc_aux(octs, mcc, mnc);

	proto_tree_add_text(tree,
	    tvb, curr_offset, 3,
	    "PLMN[%u]  Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
	    num_plmn + 1,
	    mcc,
	    mnc);

	curr_offset += 3;

	num_plmn++;
    }

    if (add_string)
	g_snprintf(add_string, string_len, " - %u PLMN%s",
	    num_plmn, plurality(num_plmn, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}
/*
10.5.2 Radio Resource management information elements
 * [3] 10.5.2.1a BA Range
 */
/*
 * [3] 10.5.2.1b Cell Channel Description
 */
static guint8
de_rr_cell_ch_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);
	/* Cell Channel Description */ 
	proto_tree_add_text(tree,tvb, curr_offset, len-1,"Cell Channel Description(Not decoded)");

	
	curr_offset = curr_offset + 17;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.1c BA List Pref 
 * [3] 10.5.2.1d UTRAN Frequency List 
 */
/*
 * [3] 10.5.2.2 Cell Description 
 */
guint8
de_rr_cell_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree	*subtree;
    proto_item	*item;
    guint8	oct;
    guint32	curr_offset;
	guint16 bcch_arfcn;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 2,
	    gsm_dtap_elem_strings[DE_RR_CELL_DSC].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_RR_CELL_DSC]);

	proto_tree_add_item(subtree, hf_gsm_a_ncc, tvb, curr_offset, 1, FALSE);
  	proto_tree_add_item(subtree, hf_gsm_a_bcc, tvb, curr_offset, 1, FALSE);
	bcch_arfcn = (tvb_get_guint8(tvb,curr_offset) & 0xc0) << 2;
	bcch_arfcn = bcch_arfcn | tvb_get_guint8(tvb,curr_offset+1);
	proto_tree_add_uint(subtree, hf_gsm_a_bcch_arfcn , tvb, curr_offset, 2, bcch_arfcn );


    curr_offset = curr_offset + 2;


    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.3 Cell Options (BCCH) 
 * [3] 10.5.2.3a Cell Options (SACCH) 
 * [3] 10.5.2.4 Cell Selection Parameters
 * [3] 10.5.2.4a MAC Mode and Channel Coding Requested 
 * [3] 10.5.2.5 Channel Description
 */
static guint8
de_rr_ch_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    proto_tree_add_text(tree,tvb, curr_offset, 4,"Channel Description(Not decoded)");
	
	curr_offset = curr_offset + 4;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.5a Channel Description 2
 */
static guint8
de_rr_ch_dsc2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    proto_tree_add_text(tree,tvb, curr_offset, 3,"Channel Description 2(Not decoded)");
	
	curr_offset = curr_offset + 3;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.6 Channel Mode
 */

/* Channel Mode  */
static const value_string gsm_a_rr_channel_mode_vals[] = {
{ 0x00,		"signalling only"},
{ 0x01,		"speech full rate or half rate version 1(GSM FR or GSM HR)"},
{ 0x21,		"speech full rate or half rate version 2(GSM EFR)"},
{ 0x41,		"speech full rate or half rate version 3(FR AMR or HR AMR)"},
{ 0x81,		"speech full rate or half rate version 4(OFR AMR-WB or OHR AMR-WB)"},
{ 0x82,		"speech full rate or half rate version 5(FR AMR-WB )"},
{ 0x83,		"speech full rate or half rate version 6(OHR AMR )"},
{ 0x61,		"data, 43.5 kbit/s (downlink)+14.5 kbps (uplink)"},
{ 0x62,		"data, 29.0 kbit/s (downlink)+14.5 kbps (uplink)"},
{ 0x64,		"data, 43.5 kbit/s (downlink)+29.0 kbps (uplink)"},
{ 0x67,		"data, 14.5 kbit/s (downlink)+43.5 kbps (uplink)"},
{ 0x65,		"data, 14.5 kbit/s (downlink)+29.0 kbps (uplink)"},
{ 0x66,		"data, 29.0 kbit/s (downlink)+43.5 kbps (uplink)"},
{ 0x27,		"data, 43.5 kbit/s radio interface rate"},
{ 0x63,		"data, 32.0 kbit/s radio interface rate"},
{ 0x43,		"data, 29.0 kbit/s radio interface rate"},
{ 0x0f,		"data, 14.5 kbit/s radio interface rate"},
{ 0x03,		"data, 12.0 kbit/s radio interface rate"},
{ 0x0b,		"data, 6.0 kbit/s radio interface rate"},
{ 0x13,		"data, 3.6 kbit/s radio interface rate"},
	{ 0,	NULL }
};

guint8
de_rr_ch_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_channel_mode, tvb, curr_offset, 1, FALSE);
	
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.7 Channel Mode 2 
 */

static const value_string gsm_a_rr_channel_mode2_vals[] = {
{ 0x00,		"signalling only"},
{ 0x05,		"speech half rate version 1(GSM HR)"},
{ 0x25,		"speech half rate version 2(GSM EFR)"},
{ 0x45,		"speech half rate version 3(HR AMR)"},
{ 0x85,		"speech half rate version 4(OHR AMR-WB)"},
{ 0x06,		"speech half rate version 6(OHR AMR )"},
{ 0x0f,		"data, 6.0 kbit/s radio interface rate"},
{ 0x17,		"data, 3.6 kbit/s radio interface rate"},
	{ 0,	NULL }
};

static guint8
de_rr_ch_mode2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_channel_mode2, tvb, curr_offset, 1, FALSE);
	
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}  
/*
 * [3] 10.5.2.7a UTRAN Classmark information element
 * [3] 10.5.2.7b (void)
 */
/*
 * [3] 10.5.2.7c Classmark Enquiry Mask
 * Bit 8:
 * 0	CLASSMARK CHANGE message is requested
 * 1	CLASSMARK CHANGE message is not requested
 * Bits 7-5 . 5
 * 000	UTRAN CLASSMARK CHANGE message including status on predefined configurations (i.e. Sequence Description) is requested
 * 111	UTRAN CLASSMARK CHANGE message including status on predefined configurations (i.e. Sequence Description) is not requested.
 * All other values shall not be sent. If received, they shall be interpreted as '000'.
 * Bit 4:
 * 0	CDMA2000 CLASSMARK CHANGE message requested
 * 1	CDMA2000 CLASSMARK CHANGE message not requested.
 * Bit 3:
 * 0	GERAN IU MODE CLASSMARK CHANGE message requested
 * 1	GERAN IU MODE CLASSMARK CHANGE message not requested.
 * Bits 2 - 1: spare(0).
 */
static const true_false_string gsm_a_msg_req_value  = {
  "message is not requested",
  "message is requested"
};
static const value_string gsm_a_rr_utran_cm_cng_msg_req_vals[] = {
{ 0x0,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x1,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x2,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x3,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x4,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x5,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x6,		"message including status on predefined configurations (i.e. Sequence Description) is requested"},
{ 0x7,		"message including status on predefined configurations (i.e. Sequence Description) is not requested."},
	{ 0,	NULL }
};
guint8
de_rr_cm_enq_mask(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;
	
	proto_tree_add_item(tree, hf_gsm_a_rr_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_utran_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_cdma200_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_geran_iu_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.8 Channel Needed
 * [3] 10.5.2.8a Channel Request Description
 * [3] 10.5.2.8b Channel Request Description 2
 */
/*
 * [3] 10.5.2.9 Cipher Mode Setting
 */
/* SC (octet 1) */
static const value_string gsm_a_rr_sc_vals[] = {
	{ 0,		"No ciphering"},
	{ 1,		"Start ciphering"},
	{ 0,	NULL }
};
/* algorithm identifier
 * If SC=1 then:
 * bits
 * 4 3 2
 */

guint8
de_rr_cip_mode_set(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
	guint8 oct;

    len = len;
    curr_offset = offset;		

	/* Cipher Mode Setting
		 * Note: The coding of fields SC and algorithm identifier is defined in [44.018] 
		 * as part of the Cipher Mode Setting IE.
		 */
		proto_tree_add_item(tree, hf_gsm_a_rr_sc, tvb, curr_offset, 1, FALSE);
		oct = tvb_get_guint8(tvb,curr_offset);
		if ( (oct & 1) == 1){ /* Start ciphering */
			/* algorithm identifier */
			proto_tree_add_item(tree, hf_gsm_a_algorithm_id, tvb, curr_offset, 1, FALSE);
		}
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.10 Cipher Response
 * [3] 10.5.2.11 Control Channel Description
 * [3] 10.5.2.11a DTM Information Details
 */
/* 
 * [3]  10.5.2.11b	Dynamic ARFCN Mapping		
 */
static guint8
de_rr_dyn_arfcn_map(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len,"Dynamic ARFCN Mapping content(Not decoded)");

	
	curr_offset = curr_offset + len;

    return(curr_offset - offset);
}  
/*
 * [3] 10.5.2.12 Frequency Channel Sequence
 */
static guint8
de_rr_freq_ch_seq(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, 3,"Frequency Channel Sequence(Not decoded)");

	
	curr_offset = curr_offset + 10;

    return(curr_offset - offset);
}  
/*
 * [3] 10.5.2.13 Frequency List
 * 
 * Bit Bit Bit Bit Bit format notation
 * 8 7  4 3 2
 * 0 0  X X X bit map 0
 * 1 0  0 X X 1024 range
 * 1 0  1 0 0 512 range
 * 1 0  1 0 1 256 range
 * 1 0  1 1 0 128 range
 * 1 0  1 1 1 variable bit map
 */
/* The mask 0xce (1100 1110) will produce the result 0110 0111*/ 
static const value_string gsm_a_rr_freq_list_format_id_vals[] = {
	{ 0x00,		"bit map 0"},
	{ 0x02,		"bit map 0"},
	{ 0x04,		"bit map 0"},
	{ 0x06,		"bit map 0"},
	{ 0x08,		"bit map 0"},
	{ 0x0a,		"bit map 0"},
	{ 0x0c,		"bit map 0"},
	{ 0x0e,		"bit map 0"},
	{ 0x40,		"1024 range"},
	{ 0x41,		"1024 range"},
	{ 0x42,		"1024 range"},
	{ 0x43,		"1024 range"},
	{ 0x44,		"512 range"},
	{ 0x45,		"256 range"},
	{ 0x46,		"128 range"},
	{ 0x47,		"variable bit map"},
	{ 0x00,	NULL }
};
static guint8
de_rr_freq_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);
	/* Frequency list */ 
	proto_tree_add_text(tree,tvb, curr_offset, len-1,"Frequency Data(Not decoded)");

	curr_offset = curr_offset + len;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.13.1 General description
 * [3] 10.5.2.13.2 Bit map 0 format
 * [3] 10.5.2.13.3 Range 1024 format
 * [3] 10.5.2.13.4 Range 512 format
 * [3] 10.5.2.13.5 Range 256 format
 * [3] 10.5.2.13.6 Range 128 format
 * [3] 10.5.2.13.7 Variable bit map format
 */
/*
 * [3] 10.5.2.14 Frequency Short List
 *
 *The Frequency Short List information element is a type 3 information element of 10 octet length.
 *
 * This element is encoded exactly as the Frequency List information element, 
 * except that it has a fixed length instead of a variable length and does 
 * not contain a length indicator and that it shall not be encoded in bitmap 0 format.
 */
static guint8
de_rr_freq_short_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);
	/* Frequency list */ 
	proto_tree_add_text(tree,tvb, curr_offset, 9,"Frequency Data(Not decoded)");

	curr_offset = curr_offset + 10;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.14a Frequency Short List 2
 *
 * The Frequency Short List information element is a type 3 information element of 8 octet length.
 *
 * This element is encoded exactly as the Frequency List information element, 
 * except that it has a fixed length instead of a variable length and does 
 * not contain a length indicator and that it shall not be encoded in bitmap 0 format.
 */
static guint8
de_rr_freq_short_list2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);

	/* Frequency list */ 
	proto_tree_add_text(tree,tvb, curr_offset, 7,"Frequency Data(Not decoded)");

	curr_offset = curr_offset + 8;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.14b Group Channel Description
 * [3] 10.5.2.14c GPRS Resumption
 * [3] 10.5.2.14d GPRS broadcast information
 */
/*
 * [3] 10.5.2.15 Handover Reference
 */
static guint8
de_rr_ho_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree	*subtree;
    proto_item	*item;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_RR_HO_REF].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_RR_HO_REF]);

	/* Handover reference value */
    proto_tree_add_item(subtree, hf_gsm_a_rr_ho_ref_val, tvb, curr_offset, 1, FALSE);
	
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.16 IA Rest Octets
 * [3] 10.5.2.17 IAR Rest Octets
 * [3] 10.5.2.18 IAX Rest Octets
 * [3] 10.5.2.19 L2 Pseudo Length
 * [3] 10.5.2.20 Measurement Results
 * [3] 10.5.2.20a GPRS Measurement Results
 */
/*
 * [3] 10.5.2.21 Mobile Allocation
 */
static guint8
de_rr_mob_all(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21a Mobile Time Difference
 */
static guint8
de_rr_mob_time_diff(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21aa MultiRate configuration
 */
/*	Multirate speech version Octet 3 Bits 8 7 6 */
static const value_string multirate_speech_ver_vals[] = {
	{ 1,		"Adaptive Multirate speech version 1"},
	{ 2,		"Adaptive Multirate speech version 2"},
	{ 0,	NULL }
};
/* Bit	5 	NSCB: Noise Suppression Control Bit */
static const value_string NSCB_vals[] = {
	{ 0,		"Noise Suppression can be used (default)"},
	{ 1,		"Noise Suppression shall be turned off"},
	{ 0,	NULL }
};
/* Bit	4	ICMI: Initial Codec Mode Indicator */
static const value_string ICMI_vals[] = {
	{ 0,		"The initial codec mode is defined by the implicit rule provided in 3GPP TS 05.09"},
	{ 1,		"The initial codec mode is defined by the Start Mode field"},
	{ 0,	NULL }
};
/*
Table 10.5.2.21aa.2: Set of adaptive multirate codec modes field (octet 4)
for the Multirate speech version 1
*/
static const true_false_string gsm_a_rr_set_of_amr_codec_modes  = {
  "is part of the subset",
  "is not part of the subset"
};



static guint8
de_rr_multirate_conf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
	guint8 oct;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_multirate_speech_ver, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_NCSB, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_ICMI, tvb, curr_offset, 1, FALSE);
	/* The initial codec mode is coded as in 3GPP TS 45.009 */
	proto_tree_add_item(tree, hf_gsm_a_rr_start_mode, tvb, curr_offset, 1, FALSE);
	oct = ( tvb_get_guint8(tvb,curr_offset) &0xe0 ) >> 5;
	curr_offset++;
	switch ( oct){
	case 1:
		/* Adaptive Multirate speech version 1 */
		/* Set of AMR codec modes */
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1, tvb, curr_offset, 1, FALSE);
		curr_offset++;

		proto_tree_add_text(tree,tvb, curr_offset, len-2 ,"Parameters for multirate speech field(Not decoded)");

		break;
	case 2:
		/* Adaptive Multirate speech version 2 */
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1, tvb, curr_offset, 1, FALSE);
		curr_offset++;

		proto_tree_add_text(tree,tvb, curr_offset, len-2 ,"Parameters for multirate speech field(Not decoded)");
		break;
	default:
		proto_tree_add_text(tree,tvb,offset,1,"Unknown version");
		proto_tree_add_text(tree,tvb, curr_offset, len-1 ,"Data(Not decoded)");
			break;
	}

	curr_offset = offset + len;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21b Multislot Allocation
 */
static guint8
de_rr_mult_all(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21c NC mode
 * [3] 10.5.2.22 Neighbour Cell Description
 * [3] 10.5.2.22a Neighbour Cell Description 2
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets
 * [3] 10.5.2.25a Packet Channel Description
 * [3] 10.5.2.25b Dedicated mode or TBF
 * [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 * [3] 10.5.2.26 Page Mode
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 * [3] 10.5.2.27 NCC Permitted
 */
/*
 * [3] 10.5.2.28 Power Command
 *
 *
 * ATC (Access Type Control) (octet 2)Bit 8
 * 0	Sending of Handover access is mandatory
 * 1	Sending of Handover access is optional
 */
static const true_false_string gsm_a_rr_pow_cmd_atc_value  = {
  "Sending of Handover access is optional",
  "Sending of Handover access is mandatory"
};
/*
 *  The EPC mode field (octet 2) indicates whether the assigned channel(s) 
 *  shall be in enhanced power control (EPC) mode. It is only valid for channels
 *  on which EPC may be used. It is coded as follows:
*/
static const true_false_string gsm_a_rr_pow_cmd_epc_value  = {
  "Channel(s) in EPC mode",
  "Channel(s) not in EPC mode"
};
/*
 * FPC_EPC (octet 2)
 * The FPC_EPC field (octet 2) has different interpretation depending
 *		on the channel mode	of the assigned channel (s) and the value 
 *		of the EPC mode field.
 * If the channel mode is such that fast power control (FPC) may be 
 *		used, the FPC_EPC field indicates whether Fast Measurement
 *		Reporting and Power Control mechanism is used.
 *		It is coded as follows:
 * Value 0	FPC not in use
 *       1	FPC in use
 * If the channel mode is such that EPC may be used and the EPC mode 
 *		field indicates that the channel is in EPC mode, the FPC_EPC
 *		field indicates whether EPC shall be used for uplink power control. 
 * It is coded as follows:
 * Value 0	EPC not in use for uplink power control
 *		 1	EPC in use for uplink power control
 *
 */
static const true_false_string gsm_a_rr_pow_cmd_fpcepc_value  = {
  "FPC in use/EPC in use for uplink power control",
  "FPC not in use/C not in use for uplink power control"
};

/*
 * Power level (octet 2)The power level field is coded as the binaryRepresentation 
 * of the "power control level", see 3GPP TS 3GPP TS 45.005. This value shall be used 
 * by the mobile station According to 3GPP TS 45.008.Range: 0 to 31.
 */

static guint8
de_rr_pow_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree	*subtree;
    proto_item	*item;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_RR_POW_CMD].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_RR_POW_CMD]);

    proto_tree_add_item(subtree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);
	/*EPC mode */	
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_epc, tvb, curr_offset, 1, FALSE);
	/*FPC_EPC*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_fpcepc, tvb, curr_offset, 1, FALSE);
	/*POWER LEVEL*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_powlev, tvb, curr_offset, 1, FALSE);
	
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.28a Power Command and access type
 */
static guint8
de_rr_pow_cmd_and_acc_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree	*subtree;
    proto_item	*item;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    gsm_dtap_elem_strings[DE_RR_POW_CMD_AND_ACC_TYPE].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_RR_POW_CMD_AND_ACC_TYPE]);

	/*ATC */	
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_atc, tvb, curr_offset, 1, FALSE);
	/*EPC mode */	
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_epc, tvb, curr_offset, 1, FALSE);
	/*FPC_EPC*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_fpcepc, tvb, curr_offset, 1, FALSE);
	/*POWER LEVEL*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_powlev, tvb, curr_offset, 1, FALSE);
	
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.29 RACH Control Parameters
 * [3] 10.5.2.30 Request Reference
 */

/*
 * [3] 10.5.2.31
 */
guint8
de_rr_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_RR_cause, tvb, curr_offset, 1, FALSE);

    curr_offset++;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.32 SI 1 Rest Octets
 * [3] 10.5.2.33 SI 2bis Rest Octets 
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 * [3] 10.5.2.34 SI 3 Rest Octets
 * [3] 10.5.2.35 SI 4 Rest Octets
 * [3] 10.5.2.35a SI 6 Rest Octets
 * [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 * [3] 10.5.2.37b SI 13 Rest Octets
 * [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets
 */
/*
 * [3] 10.5.2.38 Starting Time
 */
static guint8
de_rr_starting_time(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, 3 ,"Data(Not decoded)");

	curr_offset = curr_offset + 3;
    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.39 Synchronization Indication
 */
/*
 * ROT: Report Observed Time Difference (Octet1 bit 3) */

static const true_false_string sm_a_rr_sync_ind_rot_value  = {
  "Mobile Time Difference IE shall be included in the HANDOVER COMPLETE message",
  "Mobile Time Difference IE shall not be included in the HANDOVER COMPLETE message"
};

/* SI: Synchronization indication (octet 1)Bit2 1 */

static const value_string gsm_a_rr_sync_ind_si_vals[] = {
	{ 0,		"Non-synchronized"},
	{ 1,		"Synchronized"},
	{ 2,		"Pre-synchronised"},
	{ 3,		"Pseudo-synchronised"},
	{ 0,	NULL }
};
/* NCI: Normal cell indication (octet 1, bit 4) */

static const true_false_string gsm_a_rr_sync_ind_nci_value  = {
  "Out of range timing advance shall trigger a handover failure procedure",
  "Out of range timing advance is ignored"
};


static guint8
de_rr_sync_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	/*NCI */	
    proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_nci, tvb, curr_offset, 1, FALSE);
	/*ROT */	
    proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_rot, tvb, curr_offset, 1, FALSE);
	/*SI*/
    proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_si, tvb, curr_offset, 1, FALSE);
	
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.40 Timing Advance
 */
static guint8
de_rr_timing_adv(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_timing_adv, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.41 Time Difference
 */
static guint8
de_rr_time_diff(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_time_diff, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.41a TLLI
 * The TLLI is encoded as a binary number with a length of 4 octets. TLLI is defined in 3GPP TS 23.003
 */
guint8
de_rr_tlli(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_tlli, tvb, curr_offset, 4, FALSE);
	curr_offset = curr_offset + 4;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.42 TMSI/P-TMSI
 */
/*
 * [3] 10.5.2.42a VGCS target mode Indication
 */
/*
Target mode (octet 3)
Bit	8 7
	0 0	dedicated mode
	0 1	group transmit mode
	Other values are reserved for future use.
*/
static const value_string gsm_a_rr_target_mode_vals[] = {
	{ 0,		"Dedicated mode"},
	{ 1,		"Group transmit mode"},
	{ 0,	NULL }
};
static guint8
de_rr_vgcs_tar_mode_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_target_mode, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_group_cipher_key_number, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/* 
 * [3] 10.5.2.42b	VGCS Ciphering Parameters	
 */
static guint8
de_rr_vgcs_cip_par(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + 3;
    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.43 Wait Indication
 * [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List
 */
/*
 * [3] 10.5.2.47 Suspension Cause
 */
/*Suspension cause value (octet 2)*/
static const value_string gsm_a_rr_suspension_cause_vals[] = {
	{ 0,		"Emergency call, mobile originating call or call re-establishment"},
	{ 1,		"Location Area Update"},
	{ 2,		"MO Short message service"},
	{ 3,		"Other procedure which can be completed with an SDCCH"},
	{ 4,		"MO Voice broadcast or group call"},
	{ 5,		"Mobile terminating CS connection"},
	{ 6,		"DTM not supported in the cell"},
	{ 0,	NULL }
};
guint8
de_rr_sus_cau(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_suspension_cause, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;
    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.48 APDU ID 
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command 
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell
*/
/* 
 * [3] 10.5.2.59	Dedicated Service Information 
 */
/*
Last Segment (octet 2)
bit 1
0	mobile station shall not perform Service Information Sending procedure on new cell.
1	mobile station shall perform Service Information Sending procedure on new cell.
*/
static const true_false_string gsm_a_rr_last_segment_value  = {
  "Mobile station shall perform Service Information Sending procedure on new cell.",
  "mobile station shall not perform Service Information Sending procedure on new cell."
};
static guint8
de_rr_ded_serv_inf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_last_segment, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 3;
    return(curr_offset - offset);
}



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
	"RAND value");

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
	"AUTN value");

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
#define	AUTH_PARAM_RESP_LEN	4

    proto_tree_add_text(tree,
	tvb, curr_offset, AUTH_PARAM_RESP_LEN,
	"SRES value");

    curr_offset += AUTH_PARAM_RESP_LEN;

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
	"RES (extension) value");

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
	"AUTS value");

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

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

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

/*
 * [3] 10.5.3.6
 */
static guint8
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
	guint8 hour;
	guint8 minute;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
	hour = (oct&0x3f)>>2;
	minute = (oct&0x3)*15;

	/* 3GPP TS 23.040 version 6.6.0 Release 6 
	 * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
	 * :
	 * The Time Zone indicates the difference, expressed in quarters of an hour, 
	 * between the local time and GMT. In the first of the two semi-octets, 
	 * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
	 * represents the algebraic sign of this difference (0: positive, 1: negative).
	 */

	if ((oct&0x40)== 0x40 ){/* + */
		proto_tree_add_text(tree,tvb, curr_offset, 1,"Time Zone GMT +%u:%u",hour,minute);
	}else{
		proto_tree_add_text(tree,tvb, curr_offset, 1,"Time Zone GMT -%u:%u",hour,minute);
	}
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
	guint8 hour;
	guint8 minute;

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

    oct = tvb_get_guint8(tvb, curr_offset);

	hour = (oct&0x3f)>>2;
	minute = (oct&0x3)*15;

	/* 3GPP TS 23.040 version 6.6.0 Release 6 
	 * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
	 * :
	 * The Time Zone indicates the difference, expressed in quarters of an hour, 
	 * between the local time and GMT. In the first of the two semi-octets, 
	 * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
	 * represents the algebraic sign of this difference (0: positive, 1: negative).
	 */

	if ((oct&0x40)== 0x40 ){/* + */
		proto_tree_add_text(tree,tvb, curr_offset, 1,"Time Zone GMT +%u:%u",hour,minute);
	}else{
		proto_tree_add_text(tree,tvb, curr_offset, 1,"Time Zone GMT -%u:%u",hour,minute);
	}

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.3.11
 */
static guint8
de_lsa_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree,
	tvb, curr_offset, len,
	"LSA ID");

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

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

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
		break;
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
		break;
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
	    str = "Other rate adaption (see octet 5a)"; break;
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
	    str = "Reserved"; break;
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

/*
 * [3] 10.5.4.7
 */
static guint8
de_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint8	ton;
    guint8	*poctets;
    guint32	curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

    ton = (oct & 0x70) >> 4;
    switch (ton)
    {
    case 0: str = "Unknown"; break;
    case 1: str = "International number"; break;
    case 2: str = "National number"; break;
    case 3: str = "Network specific number"; break;
    case 4: str = "Dedicated access, short code"; break;
    case 7: str = "Reserved for extension"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Type of number: %s",
	a_bigbuf,
	str);

    if ((ton == 0) ||
	(ton == 1) ||
	(ton == 2) ||
	(ton == 4))
    {
	switch (oct & 0x0f)
	{
	case 0: str = "Unknown"; break;
	case 1: str = "ISDN/telephony numbering plan (Rec. E.164/E.163)"; break;
	case 3: str = "Data numbering plan (Recommendation X.121)"; break;
	case 4: str = "Telex numbering plan (Recommendation F.69)"; break;
	case 8: str = "National numbering plan"; break;
	case 9: str = "Private numbering plan"; break;
	case 11: str = "Reserved for CTS (see 3GPP TS 44.056)"; break;
	case 15: str = "Reserved for extension"; break;
	default:
	    str = "Reserved";
	    break;
	}
    }
    else
    {
	str = "not applicable";
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Numbering plan identification: %s",
	a_bigbuf,
	str);

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

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

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
 * [3] 10.5.4.9
 */
static guint8
de_clg_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint8	ton;
    guint8	*poctets;
    guint32	curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

    ton = (oct & 0x70) >> 4;
    switch (ton)
    {
    case 0: str = "Unknown"; break;
    case 1: str = "International number"; break;
    case 2: str = "National number"; break;
    case 3: str = "Network specific number"; break;
    case 4: str = "Dedicated access, short code"; break;
    case 7: str = "Reserved for extension"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Type of number: %s",
	a_bigbuf,
	str);

    if ((ton == 0) ||
	(ton == 1) ||
	(ton == 2) ||
	(ton == 4))
    {
	switch (oct & 0x0f)
	{
	case 0: str = "Unknown"; break;
	case 1: str = "ISDN/telephony numbering plan (Rec. E.164/E.163)"; break;
	case 3: str = "Data numbering plan (Recommendation X.121)"; break;
	case 4: str = "Telex numbering plan (Recommendation F.69)"; break;
	case 8: str = "National numbering plan"; break;
	case 9: str = "Private numbering plan"; break;
	case 11: str = "Reserved for CTS (see 3GPP TS 44.056)"; break;
	case 15: str = "Reserved for extension"; break;
	default:
	    str = "Reserved";
	    break;
	}
    }
    else
    {
	str = "not applicable";
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Numbering plan identification: %s",
	a_bigbuf,
	str);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

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

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

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
	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Extension",
	    a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Recommendation",
	    a_bigbuf);

	curr_offset++;

	oct = tvb_get_guint8(tvb, curr_offset);
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension",
	a_bigbuf);

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
 * [6] 3.6
 */
 static int
dissect_ROS_InvokeIdType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_InvokeIdType(FALSE, tvb, offset, pinfo, tree, hf_ROS_invokeID);
}
static int dissect_linkedID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_InvokeIdType(TRUE, tvb, offset, pinfo, tree, hf_ROS_linkedID);
}
static int dissect_derivable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_InvokeIdType(FALSE, tvb, offset, pinfo, tree, hf_ROS_derivable);
}



static int
dissect_ROS_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &localValue);

  return offset;
}
static int dissect_localValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_ROS_localValue);
}
static int dissect_privateer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_ROS_privateer);
}



static int
dissect_ROS_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_globalValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_ROS_globalValue);
}


static const value_string ROS_OPERATION_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t OPERATION_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ROS_OPERATION(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              OPERATION_choice, hf_index, ett_ROS_OPERATION, NULL);

  return offset;
}
static int dissect_opCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_OPERATION(FALSE, tvb, offset, pinfo, tree, hf_ROS_opCode);
}



static int
dissect_ROS_Parameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = gsm_ss_dissect(tvb, pinfo, tree, offset, localValue, comp_type_tag);
	
  return offset;
}
static int dissect_parameter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_Parameter(FALSE, tvb, offset, pinfo, tree, hf_ROS_parameter);
}

static const ber_sequence_t Invoke_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_linkedID_impl },
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_opCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_parameter },
  { 0, 0, 0, NULL }
};

static int
dissect_ROS_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Invoke_sequence, hf_index, ett_ROS_Invoke);

  return offset;
}
static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_Invoke(TRUE, tvb, offset, pinfo, tree, hf_ROS_invoke);
}

static const ber_sequence_t T_resultretres_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_opCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_parameter },
  { 0, 0, 0, NULL }
};

static int
dissect_ROS_T_resultretres(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_resultretres_sequence, hf_index, ett_ROS_T_resultretres);

  return offset;
}
static int dissect_resultretres(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_T_resultretres(FALSE, tvb, offset, pinfo, tree, hf_ROS_resultretres);
}

static const ber_sequence_t ReturnResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_resultretres },
  { 0, 0, 0, NULL }
};

static int
dissect_ROS_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReturnResult_sequence, hf_index, ett_ROS_ReturnResult);

  return offset;
}
static int dissect_returnResultLast_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_ReturnResult(TRUE, tvb, offset, pinfo, tree, hf_ROS_returnResultLast);
}



static int
dissect_ROS_INTEGER_M32768_32767(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_nationaler_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_INTEGER_M32768_32767(TRUE, tvb, offset, pinfo, tree, hf_ROS_nationaler);
}


static const value_string ROS_ErrorCode_vals[] = {
  {  19, "nationaler" },
  {  20, "privateer" },
  { 0, NULL }
};

static const ber_choice_t ErrorCode_choice[] = {
  {  19, BER_CLASS_PRI, 19, BER_FLAGS_IMPLTAG, dissect_nationaler_impl },
  {  20, BER_CLASS_PRI, 20, BER_FLAGS_IMPLTAG, dissect_privateer_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ROS_ErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              ErrorCode_choice, hf_index, ett_ROS_ErrorCode, NULL);

  return offset;
}
static int dissect_errorCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_ErrorCode(FALSE, tvb, offset, pinfo, tree, hf_ROS_errorCode);
}

static const ber_sequence_t ReturnError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_PRI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_errorCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_parameter },
  { 0, 0, 0, NULL }
};

static int
dissect_ROS_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReturnError_sequence, hf_index, ett_ROS_ReturnError);

  return offset;
}
static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_ReturnError(TRUE, tvb, offset, pinfo, tree, hf_ROS_returnError);
}



static int
dissect_ROS_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_not_derivable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_NULL(FALSE, tvb, offset, pinfo, tree, hf_ROS_not_derivable);
}


static const value_string ROS_T_invokeIDRej_vals[] = {
  {   0, "derivable" },
  {   1, "not-derivable" },
  { 0, NULL }
};

static const ber_choice_t T_invokeIDRej_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_derivable },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_not_derivable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ROS_T_invokeIDRej(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_invokeIDRej_choice, hf_index, ett_ROS_T_invokeIDRej, NULL);

  return offset;
}
static int dissect_invokeIDRej(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_T_invokeIDRej(FALSE, tvb, offset, pinfo, tree, hf_ROS_invokeIDRej);
}


static const value_string ROS_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_ROS_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_generalProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_GeneralProblem(TRUE, tvb, offset, pinfo, tree, hf_ROS_generalProblem);
}


static const value_string ROS_InvokeProblem_vals[] = {
  {   0, "duplicateInvokeID" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedParameter" },
  {   3, "resourceLimitation" },
  {   4, "initiatingRelease" },
  {   5, "unrecognizedLinkedID" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_ROS_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_InvokeProblem(TRUE, tvb, offset, pinfo, tree, hf_ROS_invokeProblem);
}


static const value_string ROS_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnResultUnexpected" },
  {   2, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_ROS_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnResultProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_ReturnResultProblem(TRUE, tvb, offset, pinfo, tree, hf_ROS_returnResultProblem);
}


static const value_string ROS_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnErrorUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_ROS_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnErrorProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_ReturnErrorProblem(TRUE, tvb, offset, pinfo, tree, hf_ROS_returnErrorProblem);
}


static const value_string ROS_T_problem_vals[] = {
  {   0, "generalProblem" },
  {   1, "invokeProblem" },
  {   2, "returnResultProblem" },
  {   3, "returnErrorProblem" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_generalProblem_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invokeProblem_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultProblem_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnErrorProblem_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ROS_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_problem_choice, hf_index, ett_ROS_T_problem, NULL);

  return offset;
}
static int dissect_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_T_problem(FALSE, tvb, offset, pinfo, tree, hf_ROS_problem);
}

static const ber_sequence_t Reject_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeIDRej },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_problem },
  { 0, 0, 0, NULL }
};

static int
dissect_ROS_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Reject_sequence, hf_index, ett_ROS_Reject);

  return offset;
}
static int dissect_reject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ROS_Reject(TRUE, tvb, offset, pinfo, tree, hf_ROS_reject);
}


static const value_string ROS_Component_vals[] = {
  {   1, "invoke" },
  {   2, "returnResultLast" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t Component_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultLast_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ROS_Component(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              Component_choice, hf_index, ett_ROS_Component, NULL);
  /* branch taken will be component type -1 */

  return offset;
}


static const value_string ROS_ERROR_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t ERROR_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ROS_ERROR(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              ERROR_choice, hf_index, ett_ROS_ERROR, NULL);

  return offset;
}

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

	
	saved_offset = offset;
	while ( fac_len > (offset - saved_offset)){ 

		/* Get the length of the component there can be more tnan one component in a facility message */
	  
		header_end_offset = get_ber_identifier(tvb, offset, &class, &pc, &comp_type_tag);
		header_end_offset = get_ber_length(tree, tvb, header_end_offset, &component_len, &ind);
		if (ind){
			proto_tree_add_text(tree, tvb, offset+1, 1,
				"Indefinte length, ignoring component");
			return (fac_len);
		}
		header_len = header_end_offset - offset;
		component_len = header_len + component_len;
		dissect_ROS_Component(FALSE, tvb, offset, g_pinfo, tree, hf_ROS_component);
		offset = offset + component_len;

	} 
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
 * [5] 8.1.4.1
 */
static guint8
de_cp_user_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    tvbuff_t	*rp_tvb;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
	"RPDU");

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
 * [5] 8.2.3
 */
static guint8
de_rp_message_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"RP-Message Reference: 0x%02x (%u)",
	oct,
	oct);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [5] 8.2.5.1
 */
static guint8
de_rp_orig_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    return(de_cld_party_bcd_num(tvb, tree, offset, len, add_string, string_len));
}

/*
 * [5] 8.2.5.2
 */
static guint8
de_rp_dest_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    return(de_cld_party_bcd_num(tvb, tree, offset, len, add_string, string_len));
}

/*
 * [5] 8.2.5.3
 */
static guint8
de_rp_user_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    tvbuff_t	*tpdu_tvb;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
	"TPDU");

    /*
     * dissect the embedded TPDU message
     */
    tpdu_tvb = tvb_new_subset(tvb, curr_offset, len, len);

    dissector_try_port(sms_dissector_table, 0, tpdu_tvb, g_pinfo, g_tree);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [5] 8.2.5.4
 */
static guint8
de_rp_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8	oct;
    guint32	curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Extension: %s",
	a_bigbuf,
	(oct & 0x80) ? "extended" : "not extended");

    switch (oct & 0x7f)
    {
    case 1: str = "Unassigned (unallocated) number"; break;
    case 8: str = "Operator determined barring"; break;
    case 10: str = "Call barred"; break;
    case 11: str = "Reserved"; break;
    case 21: str = "Short message transfer rejected"; break;
    case 22: str = "Memory capacity exceeded"; break;
    case 27: str = "Destination out of order"; break;
    case 28: str = "Unidentified subscriber"; break;
    case 29: str = "Facility rejected"; break;
    case 30: str = "Unknown subscriber"; break;
    case 38: str = "Network out of order"; break;
    case 41: str = "Temporary failure"; break;
    case 42: str = "Congestion"; break;
    case 47: str = "Resources unavailable, unspecified"; break;
    case 50: str = "Requested facility not subscribed"; break;
    case 69: str = "Requested facility not implemented"; break;
    case 81: str = "Invalid short message transfer reference value"; break;
    case 95: str = "Semantically incorrect message"; break;
    case 96: str = "Invalid mandatory information"; break;
    case 97: str = "Message type non-existent or not implemented"; break;
    case 98: str = "Message not compatible with short message protocol state"; break;
    case 99: str = "Information element non-existent or not implemented"; break;
    case 111: str = "Protocol error, unspecified"; break;
    case 127: str = "Interworking, unspecified"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Cause: (%u) %s",
	a_bigbuf,
	oct & 0x7f,
	str);

    curr_offset++;

    if (add_string)
	g_snprintf(add_string, string_len, " - (%u) %s", oct & 0x7f, str);

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Diagnostic field");

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

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
de_gmm_ptmsi_sig(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	val;
    guint32	curr_offset;
    
    len = len;
    curr_offset = offset;

    val = tvb_get_guint8(tvb, curr_offset);
    val <<= 8;
    val |= tvb_get_guint8(tvb, curr_offset+1);
    val <<= 8;
    val |= tvb_get_guint8(tvb, curr_offset+2);

    proto_tree_add_text(tree,
	tvb, curr_offset, 3,
	"P-TMSI Signature: 0x%08x (%u)",
	val,
	val);

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
    guint32	val;
    guint32	curr_offset;

    curr_offset = offset;

    val = tvb_get_guint8(tvb, curr_offset);
    val <<= 8;
    val |= tvb_get_guint8(tvb, curr_offset+1);
    val <<= 8;
    val |= tvb_get_guint8(tvb, curr_offset+2);

    proto_tree_add_text(tree,
	tvb, curr_offset, 3,
	"P-TMSI Signature 2: 0x%08x (%u) %s",
	val, val , add_string ? add_string : "");

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
    guint index = 0;
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

	index++;
	tf = proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
	    	"MS RA capability %d",index);

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
 * [7] 10.5.5.13
 */
static guint8
de_gc_spare(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    
    len = len;
    curr_offset = offset;

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Spare Nibble");

    curr_offset++;

    /* no length check possible */

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
 * [7] 10.5.5.15
 */
guint8
de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
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

	proto_tree_add_text(tree,
		tvb, curr_offset, 6,
		"Routing area identification: %x-%x-%x-%x",
		mcc,mnc,lac,rac);

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
    	case 0x0f: str="Empty PDP type";
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
 * [7] 10.5.6.5
 */
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
    guchar       oct;
    const gchar	*str;
    
    curr_len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch ( (oct>>3)&7 )
    {
    	case 0x00: str="Subscribed delay class/reserved"; break;
    	case 0x01: str="Delay class 1"; break;
    	case 0x02: str="Delay class 2"; break;
    	case 0x03: str="Delay class 3"; break;
    	case 0x04: str="Delay class 4 (best effort)"; break;
    	case 0x07: str="Reserved"; break;
    	default: str="Delay class 4 (best effort)";
    }

    proto_tree_add_text(tree,
    	tvb, curr_offset, 1,
    	"Delay class: (%u) %s",(oct>>3)&7,str);

    switch ( oct&0x7 )
    {
    	case 0x00: str="Subscribed reliability class/reserved"; break;
    	case 0x01: str="Acknowledged GTP, LLC, and RLC; Protected data"; break;
    	case 0x02: str="Unacknowledged GTP; Acknowledged LLC and RLC, Protected data"; break;
    	case 0x03: str="Unacknowledged GTP and LLC; Acknowledged RLC, Protected data"; break;
    	case 0x04: str="Unacknowledged GTP, LLC, and RLC, Protected data"; break;
    	case 0x05: str="Unacknowledged GTP, LLC, and RLC, Unprotected data"; break;
    	case 0x07: str="Reserved"; break;
    	default: str="Unacknowledged GTP and LLC; Acknowledged RLC, Protected data";
    }

    proto_tree_add_text(tree,
    	tvb, curr_offset, 1,
    	"Reliability class: (%u) %s",oct&7,str);

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

    proto_tree_add_item(tree, hf_gsm_a_qos_traffic_cls, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_order, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gsm_a_qos_del_of_err_sdu, tvb, offset, 1, FALSE);

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

    if (( oct >= 1 ) && ( oct <= 96 ))
	    proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
	    	"Maximum SDU size: (%u) %u octets",oct,oct);
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

    proto_tree_add_item(tree, hf_gsm_a_qos_ber, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_sdu_err_rat, tvb, offset, 1, FALSE);

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

    if (( oct >= 1 ) && ( oct <= 0x0f ))
	    proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
    		"Transfer Delay: (%u) %ums",oct>>2,(oct>>2)*10);
    else if (( oct >= 0x10 ) && ( oct <= 0x1f ))
	    proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
    		"Transfer Delay: (%u) %ums",oct>>2,((oct>>2)-0x10)*50);
    else if (( oct >= 0x20 ) && ( oct <= 0x3e ))
	    proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
    		"Transfer Delay: (%u) %ums",oct>>2,((oct>>2)-0x20)*100);
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
	"LLC SAPI: (%u) %s %s",
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
 * [7] 10.5.6.12
 */
static guint8
de_sm_tflow_temp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32	curr_offset;
    guint	curr_len;
    proto_item  *tf = NULL;
    proto_tree      *tf_tree = NULL;
    guchar	op_code;
    guchar	pkt_fil_count;
    guchar      e_bit;
    const gchar *str;
    guchar      count;
    guchar	oct;
    
    curr_len = len;
    curr_offset = offset;

    /*
     * parse first byte
     */
    oct = tvb_get_guint8(tvb, curr_offset);
    curr_offset++;
    curr_len--;

    op_code = oct>>5;
    pkt_fil_count = oct&0x0f;
    e_bit = (oct>>4)&1;

    switch ( op_code )
    {
    	case 0x00: str="Spare"; break;
    	case 0x01: str="Create new TFT"; break;
    	case 0x02: str="Delete existing TFT"; break;
    	case 0x03: str="Add packet filters to existing TFT"; break;
    	case 0x04: str="Replace packet filters in existing TFT"; break;
    	case 0x05: str="Delete packet filters from existing TFT"; break;
    	case 0x06: str="No TFT operation"; break;
    	case 0x07: str="Reserved"; break;
    	default: str="dissector bug";
    }
    proto_tree_add_text(tree,
    	tvb, curr_offset-1, 1,
    	"Operation code: (%u) %s",op_code,str);

    switch ( e_bit )
    {
    	case 0x00: str="parameters list is not included"; break;
    	case 0x01: str="parameters list is included"; break;
    	default: str="dissector bug";
    }
    proto_tree_add_text(tree,
    	tvb, curr_offset-1, 1,
    	"E bit: (%u) %s",e_bit,str);

    proto_tree_add_text(tree,
    	tvb, curr_offset-1, 1,
    	"Number of packet filters: 0x%02x (%u)",pkt_fil_count,pkt_fil_count);

    count = 0;
    if ( op_code == 2 )			/* delete TFT contains no packet filters. so we will jump over it */
	count = pkt_fil_count;
    while ( count < pkt_fil_count )
    {
	tf = proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
    		"Packet filter %d",count+1);

    	tf_tree = proto_item_add_subtree(tf, ett_sm_tft );

	if ( op_code == 5 )
	{
		if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Not enough data"); return(curr_offset-offset);}
		oct = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet filter identifier: 0x%02x (%u)",oct,oct );		
	}
	else
	{
		gint pf_length;
		gint pf_identifier;
		guchar *pchar;
		
		if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Not enough data"); return(curr_offset-offset);}
		pf_identifier = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		switch ( pf_identifier )
		{
			case 0x10: str="IPv4 source address type"; break;
			case 0x20: str="IPv6 source address type"; break;
			case 0x30: str="Protocol identifier/Next header type"; break;
			case 0x40: str="Single destination port type"; break;
			case 0x41: str="Destination port range type"; break;
			case 0x50: str="Single source port type"; break;
			case 0x51: str="Source port range type"; break;
			case 0x60: str="Security parameter index type"; break;
			case 0x70: str="Type of service/Traffic class type"; break;
			case 0x80: str="Flow label type"; break;
			default: str="not specified";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet filter identifier: (%u) %s",pf_identifier,str );		

		if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Not enough data"); return(curr_offset-offset);}
		oct = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet evaluation precedence: 0x%02x (%u)",oct,oct );		

		if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Not enough data"); return(curr_offset-offset);}
		pf_length = tvb_get_guint8(tvb, curr_offset);
		curr_offset++;
		curr_len--;

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1, 1,
			"Packet filter length: 0x%02x (%u)",pf_length,pf_length );		

		if (( pf_identifier == 0x10 ) && ( pf_length == 4 ))
		{
	                proto_tree_add_text(tree,
    		            tvb, curr_offset, pf_length,
    	        	    "Packet filter content: IPv4 %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		}
		else if (( pf_identifier == 0x20 ) && ( pf_length == 16 ))
		{
			struct e_in6_addr ipv6_addr;

			tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
			proto_tree_add_text(tree,
				tvb, curr_offset+2, len-2,
				"Packet filter content: IPv6 %s", ip6_to_str(&ipv6_addr));

		}
		else if (( pf_identifier == 0x30 ) && ( pf_length == 1 ))
		{
			oct = tvb_get_guint8(tvb, curr_offset);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content: Protocol identifier/Next header %u",
				oct );
		}
		else if (( pf_identifier == 0x40 ) && ( pf_length == 2 ))
		{
			pchar = (guchar*)tvb_get_ptr(tvb, curr_offset, pf_length);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content: Single destination port %u",
				(pchar[0]<<8)|pchar[1] );
		}
		else if (( pf_identifier == 0x50 ) && ( pf_length == 2 ))
		{
			pchar = (guchar*)tvb_get_ptr(tvb, curr_offset, pf_length);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content: Single source port %u",
				(pchar[0]<<8)|pchar[1] );
		}
		else if (( pf_identifier == 0x41 ) && ( pf_length == 4 ))
		{
			pchar =  (guchar*)tvb_get_ptr(tvb, curr_offset, pf_length);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content:  Destination port range %u - %u", 
				(pchar[0]<<8)|pchar[1] , (pchar[2]<<8)|pchar[3] );
		}
		else if (( pf_identifier == 0x51 ) && ( pf_length == 4 ))
		{
			pchar = (guchar*)tvb_get_ptr(tvb, curr_offset, pf_length);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content:  Source port range %u - %u", 
				(pchar[0]<<8)|pchar[1] , (pchar[2]<<8)|pchar[3] );
		}
		else if (( pf_identifier == 0x70 ) && ( pf_length == 1 ))
		{
			oct = tvb_get_guint8(tvb, curr_offset);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content: Type of service/Traffic class %u",
				oct );
		}
		else if (( pf_identifier == 0x80 ) && ( pf_length == 3 ))
		{
			guint32 fl;
			oct = tvb_get_guint8(tvb, curr_offset);
			fl = oct;
			fl <<=8;
			oct = tvb_get_guint8(tvb, curr_offset+1);
			fl |= oct;
			fl <<=8;
			oct = tvb_get_guint8(tvb, curr_offset+2);
			fl |= oct;
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content: Flow label type %u",
				fl );
		}
		else if (( pf_identifier == 0x60 ) && ( pf_length == 4 ))
		{
			pchar =  (guchar*)tvb_get_ptr(tvb, curr_offset, pf_length);
			
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content:  Security parameter index 0x%08x", 
				(pchar[0]<<24)|(pchar[1]<<16)|(pchar[2]<<8)|pchar[3] );
		}
		else
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, pf_length ,
				"Packet filter content" );		
		}
		curr_offset+= pf_length;
	}
    }

    if ( e_bit == 0 )
    {
	proto_tree_add_text(tf_tree,
		tvb, curr_offset, curr_len ,
		"Too much data" );		
	curr_offset+= curr_len;	   
	   	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);

    }
    
    count = 0;
    while ((curr_offset-offset)>=2)
    {
	gint p_length;
	gint p_identifier;
	guchar *pchar;

	tf = proto_tree_add_text(tree,
    		tvb, curr_offset, 1,
    		"Parameters list %d",count+1);

    	tf_tree = proto_item_add_subtree(tf, ett_sm_tft );

	if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Not enough data"); return(curr_offset-offset);}
	p_identifier = tvb_get_guint8(tvb, curr_offset);
	curr_offset++;
	curr_len--;

	switch ( p_identifier )
	{
		case 0x01: str="Authorization Token";
		case 0x02: str="Flow Identifier";
		default: str="not specified";
	}

	proto_tree_add_text(tf_tree,
		tvb, curr_offset-1, 1,
		"Parameter identifier: (%u) %s",p_identifier,str );		

	if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Not enough data"); return(curr_offset-offset);}
	p_length = tvb_get_guint8(tvb, curr_offset);
	curr_offset++;
	curr_len--;

	proto_tree_add_text(tf_tree,
		tvb, curr_offset-1, 1,
		"Parameter length: 0x%02x (%u)",p_length,p_length );		

	if (( p_identifier == 0x01 ) && ( p_length == 4 ))
	{
		pchar =  (guchar*)tvb_get_ptr(tvb, curr_offset, p_length);
		
		proto_tree_add_text(tf_tree,
			tvb, curr_offset, p_length ,
			"Parameter content: Media component %u IP Flow %u",
			(pchar[0]<<8)|pchar[1] , (pchar[2]<<8)|pchar[3] );
	}
	else if ( p_identifier == 0x02 )
	{
		proto_tree_add_text(tf_tree,
			tvb, curr_offset, p_length ,
			"Parameter content: Authentication Token" );		
	}
	else
	{
		proto_tree_add_text(tf_tree,
			tvb, curr_offset, p_length ,
			"Parameter content" );		
	}
	curr_offset+= p_length;
    
    }
    
    curr_offset+= curr_len;	   
	   	   
    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

static guint8 (*bssmap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
    be_cic,	/* Circuit Identity Code */
    NULL,	/* Reserved */
    NULL,	/* Resource Available */
    be_cause,	/* Cause */
    be_cell_id,	/* Cell Identifier */
    be_prio,	/* Priority */
    be_l3_header_info,	/* Layer 3 Header Information */
    de_mid,	/* IMSI */
    be_tmsi,	/* TMSI */
    be_enc_info,	/* Encryption Information */
    be_chan_type,	/* Channel Type */
    NULL,	/* Periodicity */
    NULL,	/* Extended Resource Indicator */
    NULL,	/* Number Of MSs */
    NULL,	/* Reserved */
    NULL,	/* Reserved */
    NULL,	/* Reserved */
    de_ms_cm_2,	/* Classmark Information Type 2 */
    NULL,	/* Classmark Information Type 3 */
    NULL,	/* Interference Band To Be Used */
    de_rr_cause,	/* RR Cause */
    NULL,	/* Reserved */
    be_l3_info,	/* Layer 3 Information */
    be_dlci,	/* DLCI */
    be_down_dtx_flag,	/* Downlink DTX Flag */
    be_cell_id_list,	/* Cell Identifier List */
    NULL /* no associated data */,	/* Response Request */
    NULL,	/* Resource Indication Method */
    de_ms_cm_1,	/* Classmark Information Type 1 */
    NULL,	/* Circuit Identity Code List */
    NULL,	/* Diagnostic */
    be_l3_msg,	/* Layer 3 Message Contents */
    be_chosen_chan,	/* Chosen Channel */
    NULL,	/* Total Resource Accessible */
    be_ciph_resp_mode,	/* Cipher Response Mode */
    NULL,	/* Channel Needed */
    NULL,	/* Trace Type */
    NULL,	/* TriggerID */
    NULL,	/* Trace Reference */
    NULL,	/* TransactionID */
    de_mid,	/* Mobile Identity */
    NULL,	/* OMCID */
    be_for_ind,	/* Forward Indicator */
    be_chosen_enc_alg,	/* Chosen Encryption Algorithm */
    be_cct_pool,	/* Circuit Pool */
    NULL,	/* Circuit Pool List */
    NULL,	/* Time Indication */
    NULL,	/* Resource Situation */
    be_curr_chan_1,	/* Current Channel Type 1 */
    be_que_ind,	/* Queueing Indicator */
    be_speech_ver,	/* Speech Version */
    NULL,	/* Assignment Requirement */
    NULL /* no associated data */,	/* Talker Flag */
    NULL /* no associated data */,	/* Connection Release Requested */
    NULL,	/* Group Call Reference */
    NULL,	/* eMLPP Priority */
    NULL,	/* Configuration Evolution Indication */
    NULL /* no decode required */,	/* Old BSS to New BSS Information */
    NULL,	/* LSA Identifier */
    NULL,	/* LSA Identifier List */
    NULL,	/* LSA Information */
    NULL,	/* LCS QoS */
    NULL,	/* LSA access control suppression */
    NULL,	/* LCS Priority */
    NULL,	/* Location Type */
    NULL,	/* Location Estimate */
    NULL,	/* Positioning Data */
    NULL,	/* LCS Cause */
    NULL,	/* LCS Client Type */
    be_apdu,	/* APDU */
    NULL,	/* Network Element Identity */
    NULL,	/* GPS Assistance Data */
    NULL,	/* Deciphering Keys */
    NULL,	/* Return Error Request */
    NULL,	/* Return Error Cause */
    NULL,	/* Segmentation */
    NULL,	/* NONE */
};

static guint8 (*dtap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
    /* Common Information Elements 10.5.1 */
    de_cell_id,	/* Cell Identity */
    NULL /* handled inline */,	/* Ciphering Key Sequence Number */
    de_lai,	/* Location Area Identification */
    de_mid,	/* Mobile Identity */
    de_ms_cm_1,	/* Mobile Station Classmark 1 */
    de_ms_cm_2,	/* Mobile Station Classmark 2 */
    NULL,	/* Mobile Station Classmark 3 */
    de_d_gb_call_ref,	/* Descriptive group or broadcast call reference */
    NULL /* handled inline */,	/* Group Cipher Key Number */
    de_pd_sapi,	/* PD and SAPI $(CCBS)$ */
    de_prio /* handled inline */,	/* Priority Level */
    de_plmn_list,	/* PLMN List */
    /* Radio Resource Management  Information Elements 10.5.2, most are from 10.5.1 */
/*
 * [3]  10.5.2.1a	BA Range
 */
	de_rr_cell_ch_dsc,				/* [3]  10.5.2.1b	Cell Channel Description	*/
/* [3]  10.5.2.1c	BA List Pref
 * [3]  10.5.2.1d	UTRAN Frequency List
 * [3]  10.5.2.1e	Cell selection indicator after release of all TCH and SDCCH IE
 */
	de_rr_cell_dsc,					/* 10.5.2.2   RR Cell Description				*/
/*
 * [3]  10.5.2.3	Cell Options (BCCH)	
 * [3]  10.5.2.3a	Cell Options (SACCH)
 * [3]  10.5.2.4	Cell Selection Parameters
 * [3]  10.5.2.4a	(void)
 */
	de_rr_ch_dsc,					/* [3]  10.5.2.5	Channel Description			*/
	de_rr_ch_dsc2,					/* [3]  10.5.2.5a   RR Channel Description 2 	*/
	de_rr_ch_mode,					/* [3]  10.5.2.6	Channel Mode				*/
	de_rr_ch_mode2,					/* [3]  10.5.2.7	Channel Mode 2				*/
/*
 * [3]  10.5.2.7a	UTRAN predefined configuration status information / START-CS / UE CapabilityUTRAN Classmark information element	218
 * [3]  10.5.2.7b	(void) */

	de_rr_cm_enq_mask,				/* [3]  10.5.2.7c	Classmark Enquiry Mask		*/
/* [3]  10.5.2.7d	GERAN Iu Mode Classmark information element
 * [3]  10.5.2.8	Channel Needed
 * [3]  10.5.2.8a	(void)	
 * [3]  10.5.2.8b	Channel Request Description 2 */
	de_rr_cip_mode_set,					/* [3]  10.5.2.9	Cipher Mode Setting		*/
/* [3]  10.5.2.10	Cipher Response
 * [3]  10.5.2.11	Control Channel Description
 * [3]  10.5.2.11a	DTM Information Details */
	de_rr_dyn_arfcn_map,				/* [3]  10.5.2.11b	Dynamic ARFCN Mapping		*/
	de_rr_freq_ch_seq,					/* [3]  10.5.2.12	Frequency Channel Sequence	*/
	de_rr_freq_list,					/* [3]  10.5.2.13	Frequency List				*/
	de_rr_freq_short_list,				/* [3]  10.5.2.14	Frequency Short List		*/
	de_rr_freq_short_list2,				/* [3]  10.5.2.14a	Frequency Short List 2		*/
/* [3]  10.5.2.14b	Group Channel Description
 * [3]  10.5.2.14c	GPRS Resumption
 * [3]  10.5.2.14d	GPRS broadcast information
 * [3]  10.5.2.14e	Enhanced DTM CS Release Indication
 */
	de_rr_ho_ref,					/* 10.5.2.15  Handover Reference				*/
/*
 * [3] 10.5.2.16 IA Rest Octets
 * [3] 10.5.2.17 IAR Rest Octets
 * [3] 10.5.2.18 IAX Rest Octets
 * [3] 10.5.2.19 L2 Pseudo Length
 * [3] 10.5.2.20 Measurement Results
 * [3] 10.5.2.20a GPRS Measurement Results
 */
	de_rr_mob_all,					/* [3] 10.5.2.21 Mobile Allocation				*/
	de_rr_mob_time_diff,			/* [3] 10.5.2.21a Mobile Time Difference		*/
	de_rr_multirate_conf,			/* [3] 10.5.2.21aa MultiRate configuration		*/
	de_rr_mult_all,					/* [3] 10.5.2.21b Multislot Allocation			*/
/*
 * [3] 10.5.2.21c NC mode
 * [3] 10.5.2.22 Neighbour Cell Description
 * [3] 10.5.2.22a Neighbour Cell Description 2
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets
 * [3] 10.5.2.25a Packet Channel Description
 * [3] 10.5.2.25b Dedicated mode or TBF
 * [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 * [3] 10.5.2.26 Page Mode
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 * [3] 10.5.2.27 NCC Permitted
 */
	de_rr_pow_cmd,					/* 10.5.2.28  Power Command						*/
	de_rr_pow_cmd_and_acc_type,		/* 10.5.2.28a Power Command and access type		*/
/*
 * [3] 10.5.2.29 RACH Control Parameters
 * [3] 10.5.2.30 Request Reference
 */
    de_rr_cause,					/* 10.5.2.31  RR Cause							*/
	de_rr_sync_ind,					/* 10.5.2.39  Synchronization Indication		*/
/* [3] 10.5.2.32 SI 1 Rest Octets
 * [3] 10.5.2.33 SI 2bis Rest Octets 
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 * [3] 10.5.2.34 SI 3 Rest Octets
 * [3] 10.5.2.35 SI 4 Rest Octets
 * [3] 10.5.2.35a SI 6 Rest Octets
 * [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 * [3] 10.5.2.37b SI 13 Rest Octets
 * [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
	de_rr_starting_time,				/* [3] 10.5.2.38 Starting Time					*/
	de_rr_timing_adv,					/* [3] 10.5.2.40 Timing Advance					*/ 
	de_rr_time_diff,					/* [3] 10.5.2.41 Time Difference				*/
	de_rr_tlli,							/* [3] 10.5.2.41a TLLI							*/
/*
 * [3] 10.5.2.42 TMSI/P-TMSI */
	de_rr_vgcs_tar_mode_ind,			/* [3] 10.5.2.42a VGCS target mode Indication	*/
	de_rr_vgcs_cip_par,					/* [3] 10.5.2.42b	VGCS Ciphering Parameters	*/
/* [3] 10.5.2.43 Wait Indication
 * [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List */
	de_rr_sus_cau,						/* [3] 10.5.2.47 Suspension Cause				*/
/* [3] 10.5.2.48 APDU ID 
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command 
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell
*/
	de_rr_ded_serv_inf,					/* [3] 10.5.2.59	Dedicated Service Information */

	/* Mobility Management Information Elements 10.5.3 */
    de_auth_param_rand,	/* Authentication Parameter RAND */
    de_auth_param_autn,	/* Authentication Parameter AUTN (UMTS authentication challenge only) */
    de_auth_resp_param,	/* Authentication Response Parameter */
    de_auth_resp_param_ext,	/* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
    de_auth_fail_param,	/* Authentication Failure Parameter (UMTS authentication challenge only) */
    NULL /* handled inline */,	/* CM Service Type */
    NULL /* handled inline */,	/* Identity Type */
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
    NULL,	/* Low Layer Compatibility */
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
    de_gmm_cause,	/* GMM Cause */
    de_gmm_rai,	/* Routing Area Identification */
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
    /* Short Message Service Information Elements [5] 8.2 */
    de_rp_message_ref,	/* RP-Message Reference */
    de_rp_orig_addr,	/* RP-Origination Address */
    de_rp_dest_addr,	/* RP-Destination Address */
    de_rp_user_data,	/* RP-User Data */
    de_rp_cause,	/* RP-Cause */
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
    de_gc_spare,	/* Spare Nibble */
    NULL,	/* NONE */
};

#define	SET_ELEM_VARS(SEV_pdu_type, SEV_elem_names, SEV_elem_ett, SEV_elem_funcs) \
    switch (SEV_pdu_type) \
    { \
    case BSSAP_PDU_TYPE_BSSMAP: \
	SEV_elem_names = gsm_bssmap_elem_strings; \
	SEV_elem_ett = ett_gsm_bssmap_elem; \
	SEV_elem_funcs = bssmap_elem_fcn; \
	break; \
    case BSSAP_PDU_TYPE_DTAP: \
	SEV_elem_names = gsm_dtap_elem_strings; \
	SEV_elem_ett = ett_gsm_dtap_elem; \
	SEV_elem_funcs = dtap_elem_fcn; \
	break; \
    default: \
	proto_tree_add_text(tree, \
	    tvb, curr_offset, -1, \
	    "Unknown PDU type (%u)", SEV_pdu_type); \
	return(consumed); \
    }

/*
 * Type Length Value (TLV) element dissector
 */
static guint8
elem_tlv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len, const gchar *name_add)
{
    guint8		oct, parm_len;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

    len = len;
    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei)
    {
	parm_len = tvb_get_guint8(tvb, curr_offset + 1);

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, parm_len + 2,
		"%s%s",
		elem_names[idx].strptr,
		(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree,
	    (BSSAP_PDU_TYPE_BSSMAP == pdu_type) ? hf_gsm_a_bssmap_elem_id : hf_gsm_a_dtap_elem_id, tvb,
	    curr_offset, 1, oct);

	proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
	    curr_offset + 1, 1, parm_len);

	if (parm_len > 0)
	{
	    if (elem_funcs[idx] == NULL)
	    {
		proto_tree_add_text(subtree,
		    tvb, curr_offset + 2, parm_len,
		    "Element Value");

		consumed = parm_len;
	    }
	    else
	    {
                gchar *a_add_string;

		a_add_string=ep_alloc(1024);
		a_add_string[0] = '\0';
		consumed =
		    (*elem_funcs[idx])(tvb, subtree, curr_offset + 2,
			parm_len, a_add_string, 1024);

		if (a_add_string[0] != '\0')
		{
		    proto_item_append_text(item, "%s", a_add_string);
		}
	    }
	}

	consumed += 2;
    }

    return(consumed);
}

/*
 * Type Value (TV) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
static guint8
elem_tv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint8		oct;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei)
    {
	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, -1,
		"%s%s",
		elem_names[idx].strptr,
		(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree,
	    (BSSAP_PDU_TYPE_BSSMAP == pdu_type) ? hf_gsm_a_bssmap_elem_id : hf_gsm_a_dtap_elem_id, tvb,
	    curr_offset, 1, oct);

	if (elem_funcs[idx] == NULL)
	{
	    /* BAD THING, CANNOT DETERMINE LENGTH */

	    proto_tree_add_text(subtree,
		tvb, curr_offset + 1, 1,
		"No element dissector, rest of dissection may be incorrect");

	    consumed = 1;
	}
	else
	{
            gchar *a_add_string;

	    a_add_string=ep_alloc(1024);
	    a_add_string[0] = '\0';
	    consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset + 1, -1, a_add_string, 1024);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", a_add_string);
	    }
	}

	consumed++;

	proto_item_set_len(item, consumed);
    }

    return(consumed);
}

/*
 * Type Value (TV) element dissector
 * Where top half nibble is IEI and bottom half nibble is value.
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
static guint8
elem_tv_short(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint8		oct;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if ((oct & 0xf0) == (iei & 0xf0))
    {
	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, -1,
		"%s%s",
		elem_names[idx].strptr,
		(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Element ID",
	    a_bigbuf);

	if (elem_funcs[idx] == NULL)
	{
	    /* BAD THING, CANNOT DETERMINE LENGTH */

	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"No element dissector, rest of dissection may be incorrect");

	    consumed++;
	}
	else
	{
            gchar *a_add_string;

	    a_add_string=ep_alloc(1024);
	    a_add_string[0] = '\0';
	    consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset, -1, a_add_string, 1024);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", a_add_string);
	    }
	}

	proto_item_set_len(item, consumed);
    }

    return(consumed);
}

/*
 * Type (T) element dissector
 */
static guint8
elem_t(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint8		oct;
    guint32		curr_offset;
    guint8		consumed;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei)
    {
	proto_tree_add_uint_format(tree,
	    (BSSAP_PDU_TYPE_BSSMAP == pdu_type) ? hf_gsm_a_bssmap_elem_id : hf_gsm_a_dtap_elem_id, tvb,
	    curr_offset, 1, oct,
	    "%s%s",
	    elem_names[idx].strptr,
	    (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	consumed = 1;
    }

    return(consumed);
}

/*
 * Length Value (LV) element dissector
 */
static guint8
elem_lv(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset, guint len, const gchar *name_add)
{
    guint8		parm_len;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

    len = len;
    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    parm_len = tvb_get_guint8(tvb, curr_offset);

    item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, parm_len + 1,
	    "%s%s",
	    elem_names[idx].strptr,
	    (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

    subtree = proto_item_add_subtree(item, elem_ett[idx]);

    proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
	curr_offset, 1, parm_len);

    if (parm_len > 0)
    {
	if (elem_funcs[idx] == NULL)
	{
	    proto_tree_add_text(subtree,
		tvb, curr_offset + 1, parm_len,
		"Element Value");

	    consumed = parm_len;
	}
	else
	{
            gchar *a_add_string;

	    a_add_string=ep_alloc(1024);
	    a_add_string[0] = '\0';
	    consumed =
		(*elem_funcs[idx])(tvb, subtree, curr_offset + 1,
		    parm_len, a_add_string, 1024);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", a_add_string);
	    }
	}
    }

    return(consumed + 1);
}

/*
 * Value (V) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
static guint8
elem_v(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset)
{
    guint8		consumed;
    guint32		curr_offset;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    if (elem_funcs[idx] == NULL)
    {
	/* BAD THING, CANNOT DETERMINE LENGTH */

	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "No element dissector, rest of dissection may be incorrect");

	consumed = 1;
    }
    else
    {
        gchar *a_add_string;

	a_add_string=ep_alloc(1024);
	a_add_string[0] = '\0';
	consumed = (*elem_funcs[idx])(tvb, tree, curr_offset, -1, a_add_string, 1024);
    }

    return(consumed);
}

#define ELEM_MAND_TLV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition) \
{\
    if ((consumed = elem_tlv(tvb, tree, (guint8) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, curr_len, EMT_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    else \
    { \
	proto_tree_add_text(tree, \
	    tvb, curr_offset, 0, \
	    "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
		EMT_iei, \
		(EMT_pdu_type == BSSAP_PDU_TYPE_BSSMAP) ? \
		    gsm_bssmap_elem_strings[EMT_elem_idx].strptr : gsm_dtap_elem_strings[EMT_elem_idx].strptr, \
		(EMT_elem_name_addition == NULL) || (EMT_elem_name_addition[0] == '\0') ? "" : EMT_elem_name_addition \
	    ); \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TLV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((consumed = elem_tlv(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_TV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition) \
{\
    if ((consumed = elem_tv(tvb, tree, (guint8) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, EMT_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    else \
    { \
	proto_tree_add_text(tree, \
	    tvb, curr_offset, 0, \
	    "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
		EMT_iei, \
		(EMT_pdu_type == BSSAP_PDU_TYPE_BSSMAP) ? \
		    gsm_bssmap_elem_strings[EMT_elem_idx].strptr : gsm_dtap_elem_strings[EMT_elem_idx].strptr, \
		(EMT_elem_name_addition == NULL) || (EMT_elem_name_addition[0] == '\0') ? "" : EMT_elem_name_addition \
	    ); \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((consumed = elem_tv(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TV_SHORT(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((consumed = elem_tv_short(tvb, tree, EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_T(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((consumed = elem_t(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_LV(EML_pdu_type, EML_elem_idx, EML_elem_name_addition) \
{\
    if ((consumed = elem_lv(tvb, tree, EML_pdu_type, EML_elem_idx, curr_offset, curr_len, EML_elem_name_addition)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    else \
    { \
	/* Mandatory, but nothing we can do */ \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_V(EMV_pdu_type, EMV_elem_idx) \
{\
    if ((consumed = elem_v(tvb, tree, EMV_pdu_type, EMV_elem_idx, curr_offset)) > 0) \
    { \
	curr_offset += consumed; \
	curr_len -= consumed; \
    } \
    else \
    { \
	/* Mandatory, but nothing we can do */ \
    } \
    if (curr_len <= 0) return; \
}


/* MESSAGE FUNCTIONS */

/*
 *  [2] 3.2.1.1
 */
static void
bssmap_ass_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CHAN_TYPE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHAN_TYPE, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_L3_HEADER_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_HEADER_INFO, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_PRIO].value, BSSAP_PDU_TYPE_BSSMAP, BE_PRIO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_DOWN_DTX_FLAG].value, BSSAP_PDU_TYPE_BSSMAP, BE_DOWN_DTX_FLAG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_INT_BAND].value, BSSAP_PDU_TYPE_BSSMAP, BE_INT_BAND, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_2].value, BSSAP_PDU_TYPE_BSSMAP, BE_CM_INFO_2, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_GROUP_CALL_REF].value, BSSAP_PDU_TYPE_BSSMAP, BE_GROUP_CALL_REF, "");

    ELEM_OPT_T(gsm_bssmap_elem_strings[BE_TALKER_FLAG].value, BSSAP_PDU_TYPE_BSSMAP, BE_TALKER_FLAG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_LSA_ACC_CTRL].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_ACC_CTRL, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.2
 */
static void
bssmap_ass_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_RR_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_RR_CAUSE, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_CHAN].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_ENC_ALG].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_ENC_ALG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CCT_POOL].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_SPEECH_VER].value, BSSAP_PDU_TYPE_BSSMAP, BE_SPEECH_VER, " (Chosen)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LSA_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.3
 */
static void
bssmap_ass_failure(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_RR_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_RR_CAUSE, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CCT_POOL].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CCT_POOL_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.4
 */
static void
bssmap_block(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_T(gsm_bssmap_elem_strings[BE_CONN_REL_REQ].value, BSSAP_PDU_TYPE_BSSMAP, BE_CONN_REL_REQ, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.5
 */
static void
bssmap_block_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.6
 */
static void
bssmap_unblock(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_T(gsm_bssmap_elem_strings[BE_CONN_REL_REQ].value, BSSAP_PDU_TYPE_BSSMAP, BE_CONN_REL_REQ, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.7
 */
static void
bssmap_unblock_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.8
 */
static void
bssmap_ho_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CHAN_TYPE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHAN_TYPE, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_ENC_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_ENC_INFO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CM_INFO_1].value, BSSAP_PDU_TYPE_BSSMAP, BE_CM_INFO_1, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_2].value, BSSAP_PDU_TYPE_BSSMAP, BE_CM_INFO_2, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, " (Serving)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_PRIO].value, BSSAP_PDU_TYPE_BSSMAP, BE_PRIO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_DOWN_DTX_FLAG].value, BSSAP_PDU_TYPE_BSSMAP, BE_DOWN_DTX_FLAG, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, " (Target)");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_INT_BAND].value, BSSAP_PDU_TYPE_BSSMAP, BE_INT_BAND, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_3].value, BSSAP_PDU_TYPE_BSSMAP, BE_CM_INFO_3, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CURR_CHAN_1].value, BSSAP_PDU_TYPE_BSSMAP, BE_CURR_CHAN_1, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_SPEECH_VER].value, BSSAP_PDU_TYPE_BSSMAP, BE_SPEECH_VER, " (Used)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_GROUP_CALL_REF].value, BSSAP_PDU_TYPE_BSSMAP, BE_GROUP_CALL_REF, "");

    ELEM_OPT_T(gsm_bssmap_elem_strings[BE_TALKER_FLAG].value, BSSAP_PDU_TYPE_BSSMAP, BE_TALKER_FLAG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CONF_EVO_IND].value, BSSAP_PDU_TYPE_BSSMAP, BE_CONF_EVO_IND, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_ENC_ALG].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_ENC_ALG, " (Serving)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_OLD2NEW_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_OLD2NEW_INFO, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LSA_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_INFO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_LSA_ACC_CTRL].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_ACC_CTRL, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.9
 */
static void
bssmap_ho_reqd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_OPT_T(gsm_bssmap_elem_strings[BE_RESP_REQ].value, BSSAP_PDU_TYPE_BSSMAP, BE_RESP_REQ, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID_LIST, " (Preferred)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CCT_POOL_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL_LIST, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CURR_CHAN_1].value, BSSAP_PDU_TYPE_BSSMAP, BE_CURR_CHAN_1, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_SPEECH_VER].value, BSSAP_PDU_TYPE_BSSMAP, BE_SPEECH_VER, " (Used)");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_QUE_IND].value, BSSAP_PDU_TYPE_BSSMAP, BE_QUE_IND, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_OLD2NEW_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_OLD2NEW_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.10
 */
static void
bssmap_ho_req_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_L3_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_INFO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_CHAN].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_ENC_ALG].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_ENC_ALG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CCT_POOL].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_SPEECH_VER].value, BSSAP_PDU_TYPE_BSSMAP, BE_SPEECH_VER, " (Chosen)");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LSA_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.11
 */
static void
bssmap_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_L3_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_INFO, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.12
 */
static void
bssmap_ho_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_RR_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_RR_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.14
 */
static void
bssmap_ho_cand_enq(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_NUM_MS].value, BSSAP_PDU_TYPE_BSSMAP, BE_NUM_MS, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID_LIST, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.15
 */
static void
bssmap_ho_cand_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_NUM_MS].value, BSSAP_PDU_TYPE_BSSMAP, BE_NUM_MS, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.16
 */
static void
bssmap_ho_failure(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_RR_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_RR_CAUSE, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CCT_POOL].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CCT_POOL_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CCT_POOL_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.19
 */
static void
bssmap_paging(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_IMSI].value, BSSAP_PDU_TYPE_BSSMAP, BE_IMSI, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_TMSI].value, BSSAP_PDU_TYPE_BSSMAP, BE_TMSI, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID_LIST, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CHAN_NEEDED].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHAN_NEEDED, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_EMLPP_PRIO].value, BSSAP_PDU_TYPE_BSSMAP, BE_EMLPP_PRIO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.20
 */
static void
bssmap_clear_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.21
 */
static void
bssmap_clear_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_L3_HEADER_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_HEADER_INFO, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.23
 */
static void
bssmap_reset(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_UNKNOWN;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.25
 */
static void
bssmap_ho_performed(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_CHAN].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_ENC_ALG].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_ENC_ALG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_SPEECH_VER].value, BSSAP_PDU_TYPE_BSSMAP, BE_SPEECH_VER, " (Chosen)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LSA_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.26
 */
static void
bssmap_overload(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.29
 */
static void
bssmap_cm_upd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_2].value, BSSAP_PDU_TYPE_BSSMAP, BE_CM_INFO_2, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_3].value, BSSAP_PDU_TYPE_BSSMAP, BE_CM_INFO_3, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.30
 */
static void
bssmap_ciph_mode_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_L3_HEADER_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_HEADER_INFO, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_ENC_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_ENC_INFO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CIPH_RESP_MODE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIPH_RESP_MODE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.31
 */
static void
bssmap_ciph_mode_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_L3_MSG].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_MSG, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_ENC_ALG].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_ENC_ALG, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [2] 3.2.1.32
 */
static void
bssmap_cl3_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8	consumed;
    guint32	curr_offset;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_L3_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_L3_INFO, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_CHAN].value, BSSAP_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LSA_ID_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_APDU].value, BSSAP_PDU_TYPE_BSSMAP, BE_APDU, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [2] 3.2.1.34
 */
static void
bssmap_sapi_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8	consumed;
    guint32	curr_offset;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_DLCI].value, BSSAP_PDU_TYPE_BSSMAP, BE_DLCI, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.37
 */
static void
bssmap_ho_reqd_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.38
 */
static void
bssmap_reset_cct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.39
 */
static void
bssmap_reset_cct_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.41
 */
static void
bssmap_cct_group_block(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.42
 */
static void
bssmap_cct_group_block_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.43
 */
static void
bssmap_cct_group_unblock(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.44
 */
static void
bssmap_cct_group_unblock_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.45
 */
static void
bssmap_confusion(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_DIAG].value, BSSAP_PDU_TYPE_BSSMAP, BE_DIAG, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.47
 */
static void
bssmap_unequipped_cct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CIC_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC_LIST, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.48
 */
static void
bssmap_ciph_mode_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.49
 */
static void
bssmap_load_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_TIME_IND].value, BSSAP_PDU_TYPE_BSSMAP, BE_TIME_IND, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, "");

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID_LIST].value, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID_LIST, " (Target)");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_RES_SIT].value, BSSAP_PDU_TYPE_BSSMAP, BE_RES_SIT, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.66
 */
static void
bssmap_change_cct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.67
 */
static void
bssmap_change_cct_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(gsm_bssmap_elem_strings[BE_CIC].value, BSSAP_PDU_TYPE_BSSMAP, BE_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.69
 */
static void
bssmap_lsa_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_LSA_INFO].value, BSSAP_PDU_TYPE_BSSMAP, BE_LSA_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 *  [2] 3.2.1.70
 */
static void
bssmap_conn_oriented(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_APDU].value, BSSAP_PDU_TYPE_BSSMAP, BE_APDU, "");

    ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_SEG].value, BSSAP_PDU_TYPE_BSSMAP, BE_SEG, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

#define	NUM_GSM_BSSMAP_MSG (sizeof(gsm_a_bssmap_msg_strings)/sizeof(value_string))
static gint ett_gsm_bssmap_msg[NUM_GSM_BSSMAP_MSG];
static void (*bssmap_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
    bssmap_ass_req,	/* Assignment Request */
    bssmap_ass_complete,	/* Assignment Complete */
    bssmap_ass_failure,	/* Assignment Failure */
    bssmap_ho_req,	/* Handover Request */
    bssmap_ho_reqd,	/* Handover Required */
    bssmap_ho_req_ack,	/* Handover Request Acknowledge */
    bssmap_ho_cmd,	/* Handover Command */
    bssmap_ho_complete,	/* Handover Complete */
    NULL /* no associated data */,	/* Handover Succeeded */
    bssmap_ho_failure,	/* Handover Failure */
    bssmap_ho_performed,	/* Handover Performed */
    bssmap_ho_cand_enq,	/* Handover Candidate Enquire */
    bssmap_ho_cand_resp,	/* Handover Candidate Response */
    bssmap_ho_reqd_rej,	/* Handover Required Reject */
    NULL /* no associated data */,	/* Handover Detect */
    bssmap_clear_cmd,	/* Clear Command */
    NULL /* no associated data */,	/* Clear Complete */
    bssmap_clear_req,	/* Clear Request */
    NULL,	/* Reserved */
    NULL,	/* Reserved */
    bssmap_sapi_rej,	/* SAPI 'n' Reject */
    bssmap_confusion,	/* Confusion */
    NULL,	/* Suspend */
    NULL,	/* Resume */
    bssmap_conn_oriented,	/* Connection Oriented Information */
    NULL,	/* Perform Location Request */
    bssmap_lsa_info,	/* LSA Information */
    NULL,	/* Perform Location Response */
    NULL,	/* Perform Location Abort */
    bssmap_reset,	/* Reset */
    NULL /* no associated data */,	/* Reset Acknowledge */
    bssmap_overload,	/* Overload */
    NULL,	/* Reserved */
    bssmap_reset_cct,	/* Reset Circuit */
    bssmap_reset_cct_ack,	/* Reset Circuit Acknowledge */
    NULL,	/* MSC Invoke Trace */
    NULL,	/* BSS Invoke Trace */
    NULL,	/* Connectionless Information */
    bssmap_block,	/* Block */
    bssmap_block_ack,	/* Blocking Acknowledge */
    bssmap_unblock,	/* Unblock */
    bssmap_unblock_ack,	/* Unblocking Acknowledge */
    bssmap_cct_group_block,	/* Circuit Group Block */
    bssmap_cct_group_block_ack,	/* Circuit Group Blocking Acknowledge */
    bssmap_cct_group_unblock,	/* Circuit Group Unblock */
    bssmap_cct_group_unblock_ack,	/* Circuit Group Unblocking Acknowledge */
    bssmap_unequipped_cct,	/* Unequipped Circuit */
    bssmap_change_cct,	/* Change Circuit */
    bssmap_change_cct_ack,	/* Change Circuit Acknowledge */
    NULL,	/* Resource Request */
    NULL,	/* Resource Indication */
    bssmap_paging,	/* Paging */
    bssmap_ciph_mode_cmd,	/* Cipher Mode Command */
    bssmap_cm_upd,	/* Classmark Update */
    bssmap_ciph_mode_complete,	/* Cipher Mode Complete */
    NULL /* no associated data */,	/* Queuing Indication */
    bssmap_cl3_info,	/* Complete Layer 3 Information */
    NULL /* no associated data */,	/* Classmark Request */
    bssmap_ciph_mode_rej,	/* Cipher Mode Reject */
    bssmap_load_ind,	/* Load Indication */
    NULL,	/* VGCS/VBS Setup */
    NULL,	/* VGCS/VBS Setup Ack */
    NULL,	/* VGCS/VBS Setup Refuse */
    NULL,	/* VGCS/VBS Assignment Request */
    NULL,	/* VGCS/VBS Assignment Result */
    NULL,	/* VGCS/VBS Assignment Failure */
    NULL,	/* VGCS/VBS Queuing Indication */
    NULL,	/* Uplink Request */
    NULL,	/* Uplink Request Acknowledge */
    NULL,	/* Uplink Request Confirmation */
    NULL,	/* Uplink Release Indication */
    NULL,	/* Uplink Reject Command */
    NULL,	/* Uplink Release Command */
    NULL,	/* Uplink Seized Command */
    NULL,	/* NONE */
};

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
	    gsm_dtap_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CIPH_KEY_SEQ_NUM]);

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND);

    ELEM_OPT_TLV(0x20, BSSAP_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM);

    ELEM_OPT_TLV(0x21, BSSAP_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_REJ_CAUSE);

    ELEM_OPT_TLV(0x22, BSSAP_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, "");

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
	    gsm_dtap_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CIPH_KEY_SEQ_NUM]);

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MS_CM_2, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

    ELEM_OPT_TV(0x13, BSSAP_PDU_TYPE_DTAP, DE_LAI, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_PD_SAPI);

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_REJ_CAUSE);

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_REJ_CAUSE);

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
	    gsm_dtap_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CIPH_KEY_SEQ_NUM]);

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MS_CM_2, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

    ELEM_OPT_TV_SHORT(0x80, BSSAP_PDU_TYPE_DTAP, DE_PRIO, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_MS_CM_1);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LAI);

    ELEM_OPT_TLV(0x17, BSSAP_PDU_TYPE_DTAP, DE_MID, "");

    ELEM_OPT_T(0xa1, BSSAP_PDU_TYPE_DTAP, DE_FOP, "");

    ELEM_OPT_T(0xa2, BSSAP_PDU_TYPE_DTAP, DE_CTS_PERM, "");

    ELEM_OPT_TLV(0x4a, BSSAP_PDU_TYPE_DTAP, DE_PLMN_LIST, " Equivalent");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_REJ_CAUSE);

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
	    gsm_dtap_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CIPH_KEY_SEQ_NUM]);

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LAI);

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_MS_CM_1);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

    ELEM_OPT_TLV(0x33, BSSAP_PDU_TYPE_DTAP, DE_MS_CM_2, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.15a
 */
static void
dtap_mm_mm_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(0x43, BSSAP_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full Name");

    ELEM_OPT_TLV(0x45, BSSAP_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");

    ELEM_OPT_TV(0x46, BSSAP_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");

    ELEM_OPT_TV(0x47, BSSAP_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");

    ELEM_OPT_TLV(0x48, BSSAP_PDU_TYPE_DTAP, DE_LSA_ID, "");

    ELEM_OPT_TLV(0x49, BSSAP_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.16
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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_REJ_CAUSE);

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LAI);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * [3] 9.1.15
 */
void
dtap_rr_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;
    curr_offset = offset;
    curr_len = len;

	/* Mandatory Elemets
	 * Cell description 10.5.2.2 
	 */
	ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RR_CELL_DSC);

	/* Description of the first channel,after time
	 * Channel Description 2 10.5.2.5a
	 */
	ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RR_CH_DSC2);

	/* Handover Reference 10.5.2.15 */
	ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RR_HO_REF);

	/* Power Command and Access type 10.5.2.28a */
	ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RR_POW_CMD_AND_ACC_TYPE);

	/* optional elements */

	/* Synchronization Indication 10.5.2.39 */
	ELEM_OPT_TV_SHORT(0xD0,BSSAP_PDU_TYPE_DTAP, DE_RR_SYNC_IND,"");

	/* Frequency Short List 10.5.2.14 */
	ELEM_OPT_TV(0x02,BSSAP_PDU_TYPE_DTAP, DE_RR_FREQ_SHORT_LIST," - Frequency Short List, after time");

	/* Frequency List 10.5.2.13 */
	ELEM_OPT_TLV(0x05, BSSAP_PDU_TYPE_DTAP, DE_RR_FREQ_LIST, " - Frequency List, after time");

	/* Cell Channel Description 10.5.2.1b */
	ELEM_OPT_TV(0x62,BSSAP_PDU_TYPE_DTAP, DE_RR_CELL_CH_DSC, "");

	/* Multislot Allocation 10.5.2.21b */
	ELEM_OPT_TLV(0x10,BSSAP_PDU_TYPE_DTAP, DE_RR_MULT_ALL, "");

	/* Mode of the First Channel(Channel Set 1)) Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x63,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of the First Channel(Channel Set 1))");

	/* Mode of Channel Set 2 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x11,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 2");

	/* Mode of Channel Set 3 Channel Mode 10.5.2.6*/	
	ELEM_OPT_TV(0x13,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 3");

	/* Mode of Channel Set 4 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x14,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 4");

	/* Mode of Channel Set 5 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x15,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 5");

	/* Mode of Channel Set 6 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x16,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 6");

	/* Mode of Channel Set 7 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x17,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 7");

	/* Mode of Channel Set 8 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x18,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE, " - Mode of Channel Set 8");

	/* Description of the Second Channel, after time, Channel Description 10.5.2.5 */
	ELEM_OPT_TV(0x64,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_DSC, " - Description of the Second Channel, after time");

	/* Mode of the Second Channel, Channel Mode 2 10.5.2.7 */
	ELEM_OPT_TV(0x66,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_MODE2, " - Mode of the Second Channel");

	/* Frequency Channel Sequence, after time, Frequency Channel Sequence 10.5.2.12 */
	ELEM_OPT_TV(0x69,BSSAP_PDU_TYPE_DTAP, DE_RR_FREQ_CH_SEQ, " - Frequency Channel Sequence, after time");

	/* Mobile Allocation, after time, Mobile Allocation 10.5.2.21 */
	ELEM_OPT_TLV(0x72,BSSAP_PDU_TYPE_DTAP, DE_RR_MOB_ALL, " - Mobile Allocation, after time");
	
	/* Starting Time 10.5.2.38 */
	ELEM_OPT_TV(0x7C,BSSAP_PDU_TYPE_DTAP, DE_RR_STARTING_TIME, "");

	/* Real Time Difference, Time Difference 10.5.2.41 */
	ELEM_OPT_TV(0x7B,BSSAP_PDU_TYPE_DTAP, DE_RR_TIME_DIFF, " - Real Time Difference");

	/* Timing Advance, Timing Advance 10.5.2.40 */
	ELEM_OPT_TV(0x7D,BSSAP_PDU_TYPE_DTAP, DE_RR_TIMING_ADV, "");

	/* Frequency Short List, before time, Frequency Short List 10.5.2.14 */
	ELEM_OPT_TLV(0x19,BSSAP_PDU_TYPE_DTAP, DE_RR_FREQ_SHORT_LIST, " - Frequency Short List, before time");

	/* Frequency List, before time,	Frequency List 10.5.2.13 */
	ELEM_OPT_TV(0x12,BSSAP_PDU_TYPE_DTAP, DE_RR_FREQ_LIST, " - Frequency List, before time");

	/* Description of the First Channel, before time,	Channel Description 2 10.5.2.5a*/
	ELEM_OPT_TV(0x1c,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_DSC2, " - Description of the First Channel, before time");

	/* Description of the Second Channel, before time,	Channel Description 10.5.2.5*/
	ELEM_OPT_TV(0x1d,BSSAP_PDU_TYPE_DTAP, DE_RR_CH_DSC, " - Description of the Second Channel, before time");

	/* Frequency channel sequence before time,	Frequency channel sequence 10.5.2.12*/
	ELEM_OPT_TV(0x1e,BSSAP_PDU_TYPE_DTAP, DE_RR_FREQ_CH_SEQ, " - Frequency channel sequence before time");

	/* Mobile Allocation, before time,	Mobile Allocation 10.5.2.21*/
	ELEM_OPT_TLV(0x21,BSSAP_PDU_TYPE_DTAP, DE_RR_MOB_ALL, " - Mobile Allocation, before time");

	/* Cipher Mode Setting,	Cipher Mode Setting 10.5.2.9*/
	ELEM_OPT_TV_SHORT(0x90,BSSAP_PDU_TYPE_DTAP, DE_RR_CIP_MODE_SET, "");

	/* VGCS target mode Indication,	VGCS target mode Indication 10.5.2.42a*/
	ELEM_OPT_TLV(0x01,BSSAP_PDU_TYPE_DTAP, DE_RR_VGCS_TAR_MODE_IND, "");

	/* Multi-Rate configuration,	MultiRate configuration 10.5.2.21aa*/
	ELEM_OPT_TLV(0x03,BSSAP_PDU_TYPE_DTAP, DE_RR_MULTIRATE_CONF, "");

	/* Dynamic ARFCN Mapping,	Dynamic ARFCN Mapping 10.5.2.11b*/
	ELEM_OPT_TLV(0x76,BSSAP_PDU_TYPE_DTAP, DE_RR_DYN_ARFCN_MAP, "");

	/* VGCS Ciphering Parameters,	VGCS Ciphering Parameters 10.5.2.42b*/
	ELEM_OPT_TLV(0x04,BSSAP_PDU_TYPE_DTAP, DE_RR_VGCS_CIP_PAR, "");

	/* Dedicated Service Information,	Dedicated Service Information 10.5.2.59*/
	ELEM_OPT_TV(0x51,BSSAP_PDU_TYPE_DTAP, DE_RR_DED_SERV_INF, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * [4] 9.1.25
 */
static void
dtap_rr_paging_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
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
	    gsm_dtap_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_CIPH_KEY_SEQ_NUM]);

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MS_CM_2, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.29
 */
static void
dtap_rr_rr_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RR_CAUSE);

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

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x1e, BSSAP_PDU_TYPE_DTAP, DE_PROG_IND, "");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

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

    ELEM_OPT_TV_SHORT(0xd0, BSSAP_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x08, BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_OPT_TLV(0x15, BSSAP_PDU_TYPE_DTAP, DE_CC_CAP, "");

    ELEM_OPT_TLV(0x2d, BSSAP_PDU_TYPE_DTAP, DE_SI, "");

    ELEM_OPT_TLV(0x40, BSSAP_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

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

    ELEM_OPT_TV_SHORT(0xd0, BSSAP_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x1e, BSSAP_PDU_TYPE_DTAP, DE_PROG_IND, "");

    ELEM_OPT_TV_SHORT(0x80, BSSAP_PDU_TYPE_DTAP, DE_PRIO, "");

    ELEM_OPT_TLV(0x2f, BSSAP_PDU_TYPE_DTAP, DE_NET_CC_CAP, "");

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

    ELEM_OPT_TLV(0x08, BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

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

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x1e, BSSAP_PDU_TYPE_DTAP, DE_PROG_IND, "");

    ELEM_OPT_TLV(0x4c, BSSAP_PDU_TYPE_DTAP, DE_CONN_NUM, "");

    ELEM_OPT_TLV(0x4d, BSSAP_PDU_TYPE_DTAP, DE_CONN_SUB_ADDR, "");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

    ELEM_OPT_TLV(0x2d, BSSAP_PDU_TYPE_DTAP, DE_SI, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x1e, BSSAP_PDU_TYPE_DTAP, DE_PROG_IND, "");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    ELEM_OPT_TLV(0x7b, BSSAP_PDU_TYPE_DTAP, DE_ALLOWED_ACTIONS, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

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

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

    ELEM_OPT_TLV(0x2d, BSSAP_PDU_TYPE_DTAP, DE_SI, "");

    ELEM_OPT_TLV(0x40, BSSAP_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

    ELEM_OPT_TLV(0x2e, BSSAP_PDU_TYPE_DTAP, DE_SRVC_CAT, " Emergency");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

    ELEM_OPT_TLV(0x7c, BSSAP_PDU_TYPE_DTAP, DE_LLC, "");

    ELEM_OPT_TLV(0x7d, BSSAP_PDU_TYPE_DTAP, DE_HLC, "");

    ELEM_OPT_T(0xa3, BSSAP_PDU_TYPE_DTAP, DE_REV_CALL_SETUP_DIR, "");

    ELEM_OPT_T(0xa4, BSSAP_PDU_TYPE_DTAP, DE_IMM_MOD_IND, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

    ELEM_OPT_TLV(0x7c, BSSAP_PDU_TYPE_DTAP, DE_LLC, "");

    ELEM_OPT_TLV(0x7d, BSSAP_PDU_TYPE_DTAP, DE_HLC, "");

    ELEM_OPT_T(0xa3, BSSAP_PDU_TYPE_DTAP, DE_REV_CALL_SETUP_DIR, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_OPT_TLV(0x7c, BSSAP_PDU_TYPE_DTAP, DE_LLC, "");

    ELEM_OPT_TLV(0x7d, BSSAP_PDU_TYPE_DTAP, DE_HLC, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_NOT_IND);

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_PROG_IND, "");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_SETUP_CONTAINER, "");

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

    ELEM_OPT_TV_SHORT(0xd0, BSSAP_PDU_TYPE_DTAP, DE_REPEAT_IND, " Repeat indicator");

    ELEM_MAND_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x08, BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_OPT_TLV(0x40, BSSAP_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

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

    ELEM_OPT_TLV(0x08, BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_OPT_TLV(0x08, BSSAP_PDU_TYPE_DTAP, DE_CAUSE, " 2");

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RECALL_TYPE);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

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

    ELEM_OPT_TLV(0x08, BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.3.23
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

    ELEM_OPT_TV_SHORT(0xd0, BSSAP_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, BSSAP_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x1e, BSSAP_PDU_TYPE_DTAP, DE_PROG_IND, "");

    ELEM_OPT_TV(0x34, BSSAP_PDU_TYPE_DTAP, DE_SIGNAL, "");

    ELEM_OPT_TLV(0x5c, BSSAP_PDU_TYPE_DTAP, DE_CLG_PARTY_BCD_NUM, "");

    ELEM_OPT_TLV(0x5d, BSSAP_PDU_TYPE_DTAP, DE_CLG_PARTY_SUB_ADDR, "");

    ELEM_OPT_TLV(0x5e, BSSAP_PDU_TYPE_DTAP, DE_CLD_PARTY_BCD_NUM, "");

    ELEM_OPT_TLV(0x6d, BSSAP_PDU_TYPE_DTAP, DE_CLD_PARTY_SUB_ADDR, "");

    ELEM_OPT_TLV(0x74, BSSAP_PDU_TYPE_DTAP, DE_RED_PARTY_BCD_NUM, "");

    ELEM_OPT_TLV(0x75, BSSAP_PDU_TYPE_DTAP, DE_RED_PARTY_SUB_ADDR, "");

    ELEM_OPT_TV_SHORT(0xd0, BSSAP_PDU_TYPE_DTAP, DE_REPEAT_IND, " LLC repeat indicator");

    ELEM_OPT_TLV(0x7c, BSSAP_PDU_TYPE_DTAP, DE_LLC, " 1");

    ELEM_OPT_TLV(0x7c, BSSAP_PDU_TYPE_DTAP, DE_LLC, " 2");

    ELEM_OPT_TV_SHORT(0xd0, BSSAP_PDU_TYPE_DTAP, DE_REPEAT_IND, " HLC repeat indicator");

    ELEM_OPT_TLV(0x7d, BSSAP_PDU_TYPE_DTAP, DE_HLC, " 1");

    ELEM_OPT_TLV(0x7d, BSSAP_PDU_TYPE_DTAP, DE_HLC, " 2");

    ELEM_OPT_TLV(0x7e, BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    /* downlink only */

    ELEM_OPT_TV_SHORT(0x80, BSSAP_PDU_TYPE_DTAP, DE_PRIO, "");

    ELEM_OPT_TLV(0x19, BSSAP_PDU_TYPE_DTAP, DE_ALERT_PATTERN, "");

    ELEM_OPT_TLV(0x2f, BSSAP_PDU_TYPE_DTAP, DE_NET_CC_CAP, "");

    ELEM_OPT_TLV(0x3a, BSSAP_PDU_TYPE_DTAP, DE_CAUSE_NO_CLI, "");

    /* uplink only */

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

    ELEM_OPT_T(0xa1, BSSAP_PDU_TYPE_DTAP, DE_FOP, "");

    ELEM_OPT_T(0xa2, BSSAP_PDU_TYPE_DTAP, DE_CTS_PERM, "");

    ELEM_OPT_TLV(0x15, BSSAP_PDU_TYPE_DTAP, DE_CC_CAP, "");

    ELEM_OPT_TLV(0x1d, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, " $(CCBS)$ (advanced recall alignment)");

    ELEM_OPT_TLV(0x1b, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, " (recall alignment Not essential) $(CCBS)$");

    ELEM_OPT_TLV(0x2d, BSSAP_PDU_TYPE_DTAP, DE_SI, "");

    ELEM_OPT_TLV(0x40, BSSAP_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, "");

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

    ELEM_OPT_TLV(0x15, BSSAP_PDU_TYPE_DTAP, DE_CC_CAP, "");

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

    ELEM_MAND_TV(0x2c, BSSAP_PDU_TYPE_DTAP, DE_KEYPAD_FACILITY, "");

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

    ELEM_MAND_TV(0x2c, BSSAP_PDU_TYPE_DTAP, DE_KEYPAD_FACILITY, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CAUSE, "");

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_CALL_STATE);

    ELEM_OPT_TLV(0x24, BSSAP_PDU_TYPE_DTAP, DE_AUX_STATES, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_USER_USER, "");

    ELEM_OPT_T(0xa0, BSSAP_PDU_TYPE_DTAP, DE_MORE_DATA, "");

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

    ELEM_MAND_TLV(0x1c, BSSAP_PDU_TYPE_DTAP, DE_FACILITY, "");

    ELEM_OPT_TLV(0x7f, BSSAP_PDU_TYPE_DTAP, DE_SS_VER_IND, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_CP_USER_DATA, "");

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_CP_CAUSE);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.1.1
 */
static void
rp_data_n_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;
    g_pinfo->p2p_dir = P2P_DIR_SENT;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_ORIG_ADDR, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_DEST_ADDR, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_USER_DATA, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.1.2
 */
static void
rp_data_ms_n(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;
    g_pinfo->p2p_dir = P2P_DIR_RECV;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_ORIG_ADDR, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_DEST_ADDR, "");

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_USER_DATA, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.2
 */
static void
rp_smma(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.3
 */
static void
rp_ack_n_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;
    g_pinfo->p2p_dir = P2P_DIR_SENT;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    ELEM_OPT_TLV(0x41, BSSAP_PDU_TYPE_DTAP, DE_RP_USER_DATA, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.3
 */
static void
rp_ack_ms_n(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;
    g_pinfo->p2p_dir = P2P_DIR_RECV;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    ELEM_OPT_TLV(0x41, BSSAP_PDU_TYPE_DTAP, DE_RP_USER_DATA, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.4
 */
static void
rp_error_n_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;
    g_pinfo->p2p_dir = P2P_DIR_SENT;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_CAUSE, "");

    ELEM_OPT_TLV(0x41, BSSAP_PDU_TYPE_DTAP, DE_RP_USER_DATA, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [5] 7.3.4
 */
static void
rp_error_ms_n(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;
    g_pinfo->p2p_dir = P2P_DIR_RECV;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RP_MESSAGE_REF);

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_RP_CAUSE, "");

    ELEM_OPT_TLV(0x41, BSSAP_PDU_TYPE_DTAP, DE_RP_USER_DATA, "");

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MS_NET_CAP, "");
    
    /* Included in attach type
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_CIPH_KEY_SEQ_NUM );
    curr_offset--;
    curr_len++;
    */
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_ATTACH_TYPE );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_DRX_PARAM );
    
    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID , "" );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAI );
    
    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MS_RAD_ACC_CAP , "" );

    ELEM_OPT_TV( 0x19 , BSSAP_PDU_TYPE_DTAP, DE_P_TMSI_SIG, " - Old P-TMSI Signature");
    
    ELEM_OPT_TV( 0x17 , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Ready Timer" );
    
    ELEM_OPT_TV_SHORT( 0x90 , BSSAP_PDU_TYPE_DTAP, DE_TMSI_STAT , "" );

    ELEM_OPT_TLV( 0x33 , BSSAP_PDU_TYPE_DTAP, DE_PS_LCS_CAP , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H );
    curr_len++;
    curr_offset--;    

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_ATTACH_RES );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAD_PRIO_2 );
    curr_len++;
    curr_offset--;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAD_PRIO );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAI );
    
    ELEM_OPT_TV( 0x19 , BSSAP_PDU_TYPE_DTAP, DE_P_TMSI_SIG, "" );
    
    ELEM_OPT_TV( 0x17 , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Negotiated Ready Timer" );
    
    ELEM_OPT_TLV( 0x18 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - Allocated P-TMSI" );
    
    ELEM_OPT_TLV( 0x23 , BSSAP_PDU_TYPE_DTAP, DE_MID , "" );
    
    ELEM_OPT_TV( 0x25 , BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE , "" );
    
    ELEM_OPT_TLV( 0x2A , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );
    
    ELEM_OPT_T( 0x8C , BSSAP_PDU_TYPE_DTAP, DE_CELL_NOT , "" );
    
    ELEM_OPT_TLV( 0x4A , BSSAP_PDU_TYPE_DTAP, DE_PLMN_LIST , "" );

    ELEM_OPT_TV_SHORT( 0xB0 , BSSAP_PDU_TYPE_DTAP, DE_NET_FEAT_SUP , "" );
    
    ELEM_OPT_TLV( 0x34 , BSSAP_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE );

    ELEM_OPT_TLV( 0x2A , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H );
    /* Force to standy might be wrong - To decode it correct, we need the direction */
    curr_len++;
    curr_offset--;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_DETACH_TYPE );
    
    ELEM_OPT_TV( 0x25 , BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE , "" );
    
    ELEM_OPT_TV( 0x18 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - P-TMSI" );
    
    ELEM_OPT_TV( 0x19 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - P-TMSI Signature" );

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
        ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE_NIBBLE );
        curr_len++;
        curr_offset--;
        
        ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );
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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID , " - Allocated P-TMSI" );

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAI );

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE_NIBBLE );
    curr_len++;
    curr_offset--;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );

    ELEM_OPT_TV( 0x19 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - P-TMSI Signature" );    

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_IMEISV_REQ );
    curr_offset--;
    curr_len++;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_CIPH_ALG );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_AC_REF_NUM_H );
    curr_offset--;
    curr_len++;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );
    
    ELEM_OPT_TV( 0x21 , BSSAP_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND , "" );

#if 0    
    ELEM_OPT_TV_SHORT( 0x08 , BSSAP_PDU_TYPE_DTAP, DE_CIPH_KEY_SEQ_NUM , "" );
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
        
    ELEM_OPT_TLV( 0x28 , BSSAP_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE_NIBBLE );
    curr_offset--;
    curr_len++;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_AC_REF_NUM );
    
    ELEM_OPT_TV( 0x22 , BSSAP_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM , "" );
    
    ELEM_OPT_TLV( 0x23 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - IMEISV" );
    
    ELEM_OPT_TLV( 0x29 , BSSAP_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE );
    
    ELEM_OPT_TLV( 0x30 , BSSAP_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM , "" );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.12
 */
static void
dtap_gmm_ident_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32	curr_offset;
    guint32	consumed;
    guint	curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;
    g_pinfo->p2p_dir = P2P_DIR_SENT;

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND_H );
    curr_offset--;
    curr_len++;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_ID_TYPE_2 );

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID , "" );

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
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_CIPH_KEY_SEQ_NUM );
    curr_offset--;
    curr_len++;
    
    */
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_UPD_TYPE );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAI );
    
    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MS_RAD_ACC_CAP , "" );
    
    ELEM_OPT_TV( 0x19 , BSSAP_PDU_TYPE_DTAP, DE_P_TMSI_SIG , " - Old P-TMSI Signature" ); 
    
    ELEM_OPT_TV( 0x17 , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Requested Ready Timer" );

    ELEM_OPT_TV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_DRX_PARAM , "" );
    
    ELEM_OPT_TV_SHORT( 0x90 , BSSAP_PDU_TYPE_DTAP, DE_TMSI_STAT , "" );
    
    ELEM_OPT_TLV( 0x18 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - P-TMSI" );
    
    ELEM_OPT_TLV( 0x31 , BSSAP_PDU_TYPE_DTAP, DE_MS_NET_CAP , "" );
    
    ELEM_OPT_TLV( 0x32 , BSSAP_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );
    
    ELEM_OPT_TLV( 0x33 , BSSAP_PDU_TYPE_DTAP, DE_PS_LCS_CAP , "" );
    
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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_UPD_RES );
    curr_offset--;
    curr_len++;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAI );
    
    ELEM_OPT_TV( 0x19 , BSSAP_PDU_TYPE_DTAP, DE_P_TMSI_SIG , "" ); 
    
    ELEM_OPT_TLV( 0x18 , BSSAP_PDU_TYPE_DTAP, DE_MID , " - Allocated P-TMSI");
    
    ELEM_OPT_TLV( 0x23 , BSSAP_PDU_TYPE_DTAP, DE_MID , "" );
    
    ELEM_OPT_TLV( 0x26 , BSSAP_PDU_TYPE_DTAP, DE_REC_N_PDU_NUM_LIST , "" );
    
    ELEM_OPT_TV( 0x17 , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER , " - Negotiated Ready Timer" );
    
    ELEM_OPT_TV( 0x25 , BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE , "" );
    
    ELEM_OPT_TLV( 0x2A , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );
    
    ELEM_OPT_T( 0x8C , BSSAP_PDU_TYPE_DTAP, DE_CELL_NOT , "" );
    
    ELEM_OPT_TLV( 0x4A , BSSAP_PDU_TYPE_DTAP, DE_PLMN_LIST , "" );
    
    ELEM_OPT_TLV( 0x32 , BSSAP_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );
    
    ELEM_OPT_TV_SHORT ( 0xB0 , BSSAP_PDU_TYPE_DTAP, DE_NET_FEAT_SUP , "" );
    
    ELEM_OPT_TLV( 0x34 , BSSAP_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , "" );

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
    ELEM_OPT_TLV( 0x26 , BSSAP_PDU_TYPE_DTAP, DE_REC_N_PDU_NUM_LIST , "" );
	/* Inter RAT information container 10.5.5.24 TS 24.008 version 6.8.0 Release 6 */
	/*TO DO: Implement */
	ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_RAT_INFO_CONTAINER , "" );
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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE );
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE_NIBBLE );
    curr_offset--;
    curr_len++;
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_FORCE_TO_STAND );
    
    ELEM_OPT_TLV( 0x26 , BSSAP_PDU_TYPE_DTAP, DE_GPRS_TIMER_2 , " - T3302" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE );

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

    ELEM_OPT_TLV( 0x43 , BSSAP_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Full Name" );
    
    ELEM_OPT_TLV( 0x45 , BSSAP_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Short Name" );
    
    ELEM_OPT_TV( 0x46 , BSSAP_PDU_TYPE_DTAP, DE_TIME_ZONE , "" );
    
    ELEM_OPT_TV( 0x47 , BSSAP_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME , "" );
    
    ELEM_OPT_TLV( 0x48 , BSSAP_PDU_TYPE_DTAP, DE_LSA_ID , "" );
    
    ELEM_OPT_TLV( 0x49 , BSSAP_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME , "" );

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
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_CIPH_KEY_SEQ_NUM );
    curr_offset--;
    curr_len++;
    */
    
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SRVC_TYPE );
    
	/* P-TMSI Mobile station identity 10.5.1.4 M LV 6 */
    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_MID, "");
    
    ELEM_OPT_TLV( 0x32 , BSSAP_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , BSSAP_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

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

    ELEM_OPT_TLV( 0x32 , BSSAP_PDU_TYPE_DTAP, DE_PDP_CONTEXT_STAT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , BSSAP_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_GMM_CAUSE );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_NET_SAPI );

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_QOS , " - Requested QoS" );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , " - Requested PDP address" );

    ELEM_OPT_TLV( 0x28 , BSSAP_PDU_TYPE_DTAP, DE_ACC_POINT_NAME , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_QOS , " - Negotiated QoS" );

#if 0	
    /* This is done automatically */
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE );
    curr_offset--;
    curr_len++;
#endif

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_RAD_PRIO );

    ELEM_OPT_TLV( 0x2B , BSSAP_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

    ELEM_OPT_TLV( 0x34 , BSSAP_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SM_CAUSE );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_NET_SAPI );

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_QOS , " - Requested QoS" );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_LINKED_TI , "" );

	/* 3GPP TS 24.008 version 6.8.0 Release 6, 36 TFT Traffic Flow Template 10.5.6.12 O TLV 3-257 */
    ELEM_OPT_TLV( 0x36 , BSSAP_PDU_TYPE_DTAP, DE_TRAFFIC_FLOW_TEMPLATE , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_QOS , " - Negotiated QoS" );

#if 0	
    /* This is done automatically */
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE );
    curr_offset--;
    curr_len++;
#endif

    ELEM_OPT_TLV( 0x34 , BSSAP_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SM_CAUSE );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , " - Offered PDP address" );

    ELEM_OPT_TLV( 0x28 , BSSAP_PDU_TYPE_DTAP, DE_ACC_POINT_NAME , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SM_CAUSE );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.5.9 Modify PDP context request (Network to MS direction)
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

#if 0	
    /* This is done automatically */
    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SPARE );
    curr_offset--;
    curr_len++;
#endif

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI );

    ELEM_MAND_LV(BSSAP_PDU_TYPE_DTAP, DE_QOS , " - New QoS" );

    ELEM_OPT_TLV( 0x2B , BSSAP_PDU_TYPE_DTAP, DE_PD_PRO_ADDR , "" );

    ELEM_OPT_TLV( 0x34 , BSSAP_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_OPT_TV( 0x32 , BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI , " - Requested LLC SAPI" );

    ELEM_OPT_TLV( 0x30 , BSSAP_PDU_TYPE_DTAP, DE_QOS , " - Requested new QoS" );

    ELEM_OPT_TLV( 0x31 , BSSAP_PDU_TYPE_DTAP, DE_TRAFFIC_FLOW_TEMPLATE , " - New TFT" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_OPT_TLV( 0x30 , BSSAP_PDU_TYPE_DTAP, DE_QOS , " - Negotiated QoS" );

    ELEM_OPT_TV( 0x32 , BSSAP_PDU_TYPE_DTAP, DE_LLC_SAPI , " - Negotiated LLC SAPI" );

    ELEM_OPT_TV_SHORT ( 0x80 , BSSAP_PDU_TYPE_DTAP , DE_RAD_PRIO , " - New radio priority" );

    ELEM_OPT_TLV( 0x34 , BSSAP_PDU_TYPE_DTAP, DE_PACKET_FLOW_ID , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SM_CAUSE );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SM_CAUSE );

    ELEM_OPT_TV_SHORT( 0x90 , BSSAP_PDU_TYPE_DTAP , DE_TEAR_DOWN_IND , "" );

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , BSSAP_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

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

    ELEM_OPT_TLV( 0x27 , BSSAP_PDU_TYPE_DTAP, DE_PRO_CONF_OPT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , BSSAP_PDU_TYPE_DTAP, DE_MBMS_CTX_STATUS , "" );

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

    ELEM_MAND_V(BSSAP_PDU_TYPE_DTAP, DE_SM_CAUSE );

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

#define	NUM_GSM_DTAP_MSG_RR (sizeof(gsm_a_dtap_msg_rr_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_rr[NUM_GSM_DTAP_MSG_RR];
static void (*dtap_msg_rr_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
    NULL,	/* RR Initialisation Request */
    NULL,	/* Additional Assignment */
    NULL,	/* Immediate Assignment */
    NULL,	/* Immediate Assignment Extended */
    NULL,	/* Immediate Assignment Reject */

    NULL,	/* DTM Assignment Failure */
    NULL,	/* DTM Reject */
    NULL,	/* DTM Request */
    NULL,	/* Main DCCH Assignment Command */
    NULL,	/* Packet Assignment Command */

    NULL,	/* Ciphering Mode Command */
    NULL,	/* Ciphering Mode Complete */

    NULL,	/* Configuration Change Command */
    NULL,	/* Configuration Change Ack. */
    NULL,	/* Configuration Change Reject */

    NULL,	/* Assignment Command */
    NULL,	/* Assignment Complete */
    NULL,	/* Assignment Failure */
    dtap_rr_ho_cmd,	/* Handover Command */
    NULL,	/* Handover Complete */
    NULL,	/* Handover Failure */
    NULL,	/* Physical Information */
    NULL,	/* DTM Assignment Command */

    NULL,	/* RR-cell Change Order */
    NULL,	/* PDCH Assignment Command */

    NULL,	/* Channel Release */
    NULL,	/* Partial Release */
    NULL,	/* Partial Release Complete */

    NULL,	/* Paging Request Type 1 */
    NULL,	/* Paging Request Type 2 */
    NULL,	/* Paging Request Type 3 */
    dtap_rr_paging_resp,	/* Paging Response */
    NULL,	/* Notification/NCH */
    NULL,	/* Reserved */
    NULL,	/* Notification/Response */

    NULL,	/* Reserved */

    NULL,	/* Utran Classmark Change  */
    NULL,	/* UE RAB Preconfiguration */
    NULL,	/* cdma2000 Classmark Change */
    NULL,	/* Inter System to UTRAN Handover Command */
    NULL,	/* Inter System to cdma2000 Handover Command */

    NULL,	/* System Information Type 8 */
    NULL,	/* System Information Type 1 */
    NULL,	/* System Information Type 2 */
    NULL,	/* System Information Type 3 */
    NULL,	/* System Information Type 4 */
    NULL,	/* System Information Type 5 */
    NULL,	/* System Information Type 6 */
    NULL,	/* System Information Type 7 */

    NULL,	/* System Information Type 2bis */
    NULL,	/* System Information Type 2ter */
    NULL,	/* System Information Type 2quater */
    NULL,	/* System Information Type 5bis */
    NULL,	/* System Information Type 5ter */
    NULL,	/* System Information Type 9 */
    NULL,	/* System Information Type 13 */

    NULL,	/* System Information Type 16 */
    NULL,	/* System Information Type 17 */

    NULL,	/* System Information Type 18 */
    NULL,	/* System Information Type 19 */
    NULL,	/* System Information Type 20 */

    NULL,	/* Channel Mode Modify */
    dtap_rr_rr_status,	/* RR Status */
    NULL,	/* Channel Mode Modify Acknowledge */
    NULL,	/* Frequency Redefinition */
    NULL,	/* Measurement Report */
    NULL,	/* Classmark Change */
    NULL,	/* Classmark Enquiry */
    NULL,	/* Extended Measurement Report */
    NULL,	/* Extended Measurement Order */
    NULL,	/* GPRS Suspension Request */

    NULL,	/* VGCS Uplink Grant */
    NULL,	/* Uplink Release */
    NULL,	/* Reserved */
    NULL,	/* Uplink Busy */
    NULL,	/* Talker Indication */

    NULL,	/* UTRAN Classmark Change/Handover To UTRAN Command */	/* spec conflict */

    NULL,	/* Application Information */

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

#define	NUM_GSM_RP_MSG (sizeof(gsm_rp_msg_strings)/sizeof(value_string))
static gint ett_gsm_rp_msg[NUM_GSM_RP_MSG];
static void (*rp_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
    rp_data_ms_n,	/* RP-DATA (MS to Network) */
    rp_data_n_ms,	/* RP-DATA (Network to MS */
    rp_ack_ms_n,	/* RP-ACK (MS to Network) */
    rp_ack_n_ms,	/* RP-ACK (Network to MS) */
    rp_error_ms_n,	/* RP-ERROR (MS to Network) */
    rp_error_n_ms,	/* RP-ERROR (Network to MS) */
    rp_smma,	/* RP-SMMA (MS to Network) */
    NULL,	/* NONE */
};

/* GENERIC DISSECTOR FUNCTIONS */

static void
dissect_rp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8	oct;
    guint32	offset, saved_offset;
    guint32	len;
    gint	idx;
    proto_item	*rp_item = NULL;
    proto_tree	*rp_tree = NULL;
    const gchar	*str;


    if (check_col(pinfo->cinfo, COL_INFO))
    {
	col_append_str(pinfo->cinfo, COL_INFO, "(RP) ");
    }

    /*
     * In the interest of speed, if "tree" is NULL, don't do any work
     * not necessary to generate protocol tree items.
     */
    if (!tree)
    {
	return;
    }

    offset = 0;
    saved_offset = offset;

    g_pinfo = pinfo;
    g_tree = tree;

    len = tvb_length(tvb);

    /*
     * add RP message name
     */
    oct = tvb_get_guint8(tvb, offset++);

    str = match_strval_idx((guint32) oct, gsm_rp_msg_strings, &idx);

    /*
     * create the protocol tree
     */
    if (str == NULL)
    {
	rp_item =
	    proto_tree_add_protocol_format(tree, proto_a_rp, tvb, 0, len,
		"GSM A-I/F RP - Unknown RP Message Type (0x%02x)",
		oct);

	rp_tree = proto_item_add_subtree(rp_item, ett_rp_msg);
    }
    else
    {
	rp_item =
	    proto_tree_add_protocol_format(tree, proto_a_rp, tvb, 0, -1,
		"GSM A-I/F RP - %s",
		str);

	rp_tree = proto_item_add_subtree(rp_item, ett_gsm_rp_msg[idx]);

	if (check_col(pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);
	}
    }

    /*
     * add RP message name
     */
    proto_tree_add_uint_format(rp_tree, hf_gsm_a_rp_msg_type,
		tvb, saved_offset, 1, oct, "Message Type %s", str ? str : "(Unknown)");

    if (str == NULL) return;

    if ((len - offset) <= 0) return;

    /*
     * decode elements
     */
    if (rp_msg_fcn[idx] == NULL)
    {
	proto_tree_add_text(rp_tree,
	    tvb, offset, len - offset,
	    "Message Elements");
    }
    else
    {
	(*rp_msg_fcn[idx])(tvb, rp_tree, offset, len - offset);
    }
}


void
dissect_bssmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    static gsm_a_tap_rec_t	tap_rec[4];
    static gsm_a_tap_rec_t	*tap_p;
    static int			tap_current=0;
    guint8	oct;
    guint32	offset, saved_offset;
    guint32	len;
    gint	idx;
    proto_item	*bssmap_item = NULL;
    proto_tree	*bssmap_tree = NULL;
    const gchar	*str;


    if (check_col(pinfo->cinfo, COL_INFO))
    {
	col_append_str(pinfo->cinfo, COL_INFO, "(BSSMAP) ");
    }

    /*
     * set tap record pointer
     */
    tap_current++;
    if (tap_current == 4)
    {
	tap_current = 0;
    }
    tap_p = &tap_rec[tap_current];


    offset = 0;
    saved_offset = offset;

    g_pinfo = pinfo;
    g_tree = tree;

    len = tvb_length(tvb);

    /*
     * add BSSMAP message name
     */
    oct = tvb_get_guint8(tvb, offset++);

    str = match_strval_idx((guint32) oct, gsm_a_bssmap_msg_strings, &idx);

    /*
     * create the protocol tree
     */
    if (str == NULL)
    {
	bssmap_item =
	    proto_tree_add_protocol_format(tree, proto_a_bssmap, tvb, 0, len,
		"GSM A-I/F BSSMAP - Unknown BSSMAP Message Type (0x%02x)",
		oct);

	bssmap_tree = proto_item_add_subtree(bssmap_item, ett_bssmap_msg);
    }
    else
    {
	bssmap_item =
	    proto_tree_add_protocol_format(tree, proto_a_bssmap, tvb, 0, -1,
		"GSM A-I/F BSSMAP - %s",
		str);

	bssmap_tree = proto_item_add_subtree(bssmap_item, ett_gsm_bssmap_msg[idx]);

	if (check_col(pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);
	}
    }

    /*
     * add BSSMAP message name
     */
    proto_tree_add_uint_format(bssmap_tree, hf_gsm_a_bssmap_msg_type,
	tvb, saved_offset, 1, oct, "Message Type %s",str);

    tap_p->pdu_type = BSSAP_PDU_TYPE_BSSMAP;
    tap_p->message_type = oct;

    tap_queue_packet(gsm_a_tap, pinfo, tap_p);

    if (str == NULL) return;

    if ((len - offset) <= 0) return;

    /*
     * decode elements
     */
    if (bssmap_msg_fcn[idx] == NULL)
    {
	proto_tree_add_text(bssmap_tree,
	    tvb, offset, len - offset,
	    "Message Elements");
    }
    else
    {
	(*bssmap_msg_fcn[idx])(tvb, bssmap_tree, offset, len - offset);
    }
}


static void
dissect_dtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    static gsm_a_tap_rec_t	tap_rec[4];
    static gsm_a_tap_rec_t	*tap_p;
    static int			tap_current=0;
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
    if (tap_current == 4)
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
	msg_str = match_strval_idx((guint32) (oct & DTAP_RR_IEI_MASK), gsm_a_dtap_msg_rr_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_rr[idx];
	hf_idx = hf_gsm_a_dtap_msg_rr_type;
	msg_fcn = dtap_msg_rr_fcn[idx];
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

    default:
    /* XXX - hf_idx is still -1! this is a bug in the implementation, and I don't know how to fix it so simple return here */
    return;
	break;
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
    }
    else
    {
	dtap_item =
	    proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, -1,
		"GSM A-I/F DTAP - %s",
		msg_str);

	dtap_tree = proto_item_add_subtree(dtap_item, ett_tree);

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
	other_decode_bitfield_value(a_bigbuf, oct_2, 0x80, 8);
	proto_tree_add_text(pd_tree,
	    tvb, 1, 1,
	    "%s :  Extension",
	    a_bigbuf);

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

    tap_p->pdu_type = BSSAP_PDU_TYPE_DTAP;
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


/* Register the protocol with Ethereal */
void
proto_register_gsm_a(void)
{
    guint		i;
    guint		last_offset;

    /* Setup list of header fields */

    static hf_register_info hf[] =
    {
	{ &hf_gsm_a_bssmap_msg_type,
	    { "BSSMAP Message Type",	"gsm_a.bssmap_msgtype",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_bssmap_msg_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_mm_type,
	    { "DTAP Mobility Management Message Type",	"gsm_a.dtap_msg_mm_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_mm_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_rr_type,
	    { "DTAP Radio Resources Management Message Type",	"gsm_a.dtap_msg_rr_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_rr_strings), 0x0,
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
	{ &hf_gsm_a_rp_msg_type,
	    { "RP Message Type",	"gsm_a.rp_msg_type",
	    FT_UINT8, BASE_HEX, VALS(gsm_rp_msg_strings), 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_bssmap_elem_id,
	    { "Element ID",	"gsm_a_bssmap.elem_id",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_elem_id,
	    { "Element ID",	"gsm_a_dtap.elem_id",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_length,
	    { "Length",		"gsm_a.len",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_none,
	    { "Sub tree",	"gsm_a.none",
	    FT_NONE, 0, 0, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_imsi,
	    { "IMSI",	"gsm_a.imsi",
	    FT_STRING, BASE_DEC, 0, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_tmsi,
	    { "TMSI/P-TMSI",	"gsm_a.tmsi",
	    FT_UINT32, BASE_HEX, 0, 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_imei,
	    { "IMEI",	"gsm_a.imei",
	    FT_STRING, BASE_DEC, 0, 0,
	    "", HFILL }
	},
	{ &hf_gsm_a_imeisv,
	    { "IMEISV",	"gsm_a.imeisv",
	    FT_STRING, BASE_DEC, 0, 0,
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
	{ &hf_gsm_a_cell_ci,
	    { "Cell CI",	"gsm_a.cell_ci",
	    FT_UINT16, BASE_HEX, 0, 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_cell_lac,
	    { "Cell LAC",	"gsm_a.cell_lac",
	    FT_UINT16, BASE_HEX, 0, 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dlci_cc,
	    { "Control Channel", "bssap.dlci.cc",
	    FT_UINT8, BASE_HEX, VALS(bssap_cc_values), 0xc0,
	    "", HFILL}
	},
	{ &hf_gsm_a_dlci_spare,
	    { "Spare", "bssap.dlci.spare",
	    FT_UINT8, BASE_HEX, NULL, 0x38,
	    "", HFILL}
	},
	{ &hf_gsm_a_dlci_sapi,
	    { "SAPI", "bssap.dlci.sapi",
	    FT_UINT8, BASE_HEX, VALS(bssap_sapi_values), 0x07,
	    "", HFILL}
	},
	{ &hf_gsm_a_bssmap_cause,
	    { "BSSMAP Cause",	"gsm_a_bssmap.cause",
	    FT_UINT8, BASE_HEX, 0, 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_dtap_cause,
	    { "DTAP Cause",	"gsm_a_dtap.cause",
	    FT_UINT8, BASE_HEX, 0, 0x0,
	    "", HFILL }
	},
	{ &hf_gsm_a_MSC_rev,
		{ "Revision Level","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_msc_rev_vals), 0x60,          
		"Revision level", HFILL }
	},
	{ &hf_gsm_a_ES_IND,
		{ "ES IND","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC,  VALS(ES_IND_vals), 0x10,          
			"ES IND", HFILL }
	},
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
	{ &hf_gsm_a_A5_1_algorithm_sup,
		{ "A5/1 algorithm supported","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC,  VALS(A5_1_algorithm_sup_vals), 0x08,          
		"A5/1 algorithm supported ", HFILL }
	},
	{ &hf_gsm_a_RF_power_capability,
		{ "RF Power Capability","gsm_a.MSC2_rev",
		FT_UINT8,BASE_DEC,  VALS(RF_power_capability_vals), 0x07,          
		"RF Power Capability", HFILL }
	},
	{ &hf_gsm_a_ps_sup_cap,
		{ "PS capability (pseudo-synchronization capability)","gsm_a.ps_sup_cap",
		FT_UINT8,BASE_DEC,  VALS(ps_sup_cap_vals), 0x40,          
		"PS capability (pseudo-synchronization capability)", HFILL }
	},
	{ &hf_gsm_a_SS_screening_indicator,
		{ "SS Screening Indicator","gsm_a.SS_screening_indicator",
		FT_UINT8,BASE_DEC,  VALS(SS_screening_indicator_vals), 0x30,          
		"SS Screening Indicator", HFILL }
	},
	{ &hf_gsm_a_SM_capability,
		{ "SM capability (MT SMS pt to pt capability)","gsm_a.SM_cap",
		FT_UINT8,BASE_DEC,  VALS(SM_capability_vals), 0x08,          
		"SM capability (MT SMS pt to pt capability)", HFILL }
	},
	{ &hf_gsm_a_VBS_notification_rec,
		{ "VBS notification reception ","gsm_a.VBS_notification_rec",
		FT_UINT8,BASE_DEC,  VALS(VBS_notification_rec_vals), 0x04,          
		"VBS notification reception ", HFILL }
	},
	{ &hf_gsm_a_VGCS_notification_rec,
		{ "VGCS notification reception ","gsm_a.VGCS_notification_rec",
		FT_UINT8,BASE_DEC,  VALS(VGCS_notification_rec_vals), 0x02,          
		"VGCS notification reception", HFILL }
	},
	{ &hf_gsm_a_FC_frequency_cap,
		{ "FC Frequency Capability","gsm_a.FC_frequency_cap",
		FT_UINT8,BASE_DEC,  VALS(FC_frequency_cap_vals), 0x01,          
		"FC Frequency Capability", HFILL }
	},
	{ &hf_gsm_a_CM3,
		{ "CM3","gsm_a.CM3",
		FT_UINT8,BASE_DEC,  VALS(CM3_vals), 0x80,          
		"CM3", HFILL }
	},
	{ &hf_gsm_a_LCS_VA_cap,
		{ "LCS VA capability (LCS value added location request notification capability) ","gsm_a.LCS_VA_cap",
		FT_UINT8,BASE_DEC,  VALS(LCS_VA_cap_vals), 0x20,          
		"LCS VA capability (LCS value added location request notification capability) ", HFILL }
	},
	{ &hf_gsm_a_UCS2_treatment,
		{ "UCS2 treatment ","gsm_a.UCS2_treatment",
		FT_UINT8,BASE_DEC,  VALS(UCS2_treatment_vals), 0x10,          
		"UCS2 treatment ", HFILL }
	},
	{ &hf_gsm_a_SoLSA,
		{ "SoLSA","gsm_a.SoLSA",
		FT_UINT8,BASE_DEC,  VALS(SoLSA_vals), 0x08,          
		"SoLSA", HFILL }
	},
	{ &hf_gsm_a_CMSP,
		{ "CMSP: CM Service Prompt ","gsm_a.CMSP",
		FT_UINT8,BASE_DEC,  VALS(CMSP_vals), 0x04,          
		"CMSP: CM Service Prompt ", HFILL }
	},
	{ &hf_gsm_a_A5_3_algorithm_sup,
		{ "A5/3 algorithm supported ","gsm_a.A5_3_algorithm_sup",
		FT_UINT8,BASE_DEC,  VALS(A5_3_algorithm_sup_vals), 0x02,          
		"A5/3 algorithm supported ", HFILL }
	},
	{ &hf_gsm_a_A5_2_algorithm_sup,
		{ "A5/2 algorithm supported ","gsm_a.A5_2_algorithm_sup",
		FT_UINT8,BASE_DEC,  VALS(A5_2_algorithm_sup_vals), 0x01,          
		"A5/2 algorithm supported ", HFILL }
	},
	{ &hf_gsm_a_mobile_identity_type,
		{ "Mobile Identity Type","gsm_a.ie.mobileid.type",
		FT_UINT8, BASE_DEC, VALS(mobile_identity_type_vals), 0x07,          
		"Mobile Identity Type", HFILL }
	},
	{ &hf_gsm_a_odd_even_ind,
		{ "Odd/even indication","gsm_a.oddevenind",
		FT_UINT8, BASE_DEC, oddevenind_vals, 0x08,          
		"Mobile Identity", HFILL }
	},
	{ &hf_gsm_a_L3_protocol_discriminator,
		{ "Protocol discriminator","gsm_a.L3_protocol_discriminator",
		FT_UINT8,BASE_DEC,  VALS(protocol_discriminator_vals), 0x0f,          
		"Protocol discriminator", HFILL }
	},
	{ &hf_gsm_a_skip_ind,
		{ "Skip Indicator",           "gsm_a.skip.ind",
		FT_UINT8, BASE_DEC, NULL, 0xf0,          
		"Skip Indicator", HFILL }
	},
	{ &hf_gsm_a_bcc,
		{ "BCC","gsm_a.bcc",
		FT_UINT8,BASE_DEC,  NULL, 0x07,          
		"BCC", HFILL }
	},
	{ &hf_gsm_a_ncc,
		{ "NCC","gsm_a.ncc",
		FT_UINT8,BASE_DEC,  NULL, 0x38,          
		"NCC", HFILL }
	},
	{ &hf_gsm_a_bcch_arfcn,
		{ "BCCH ARFCN(RF channel number)","gsm_a.bcch_arfcn",
		FT_UINT16,BASE_DEC,  NULL, 0x0,          
		"BCCH ARFCN", HFILL }
	},
	{ &hf_gsm_a_rr_ho_ref_val,
		{ "Handover reference value","gsm_a.rr.ho_ref_val",
		FT_UINT8,BASE_DEC,  NULL, 0x0,          
		"Handover reference value", HFILL }
	},
        { &hf_gsm_a_b7spare,
	        { "Spare","gsm_a.spareb7",
	        FT_UINT8,BASE_DEC,  NULL, 0x40,
	        "Spare", HFILL }
	},
	{ &hf_gsm_a_b8spare,
		{ "Spare","gsm_a.spareb8",
		FT_UINT8,BASE_DEC,  NULL, 0x80,          
		"Spare", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_atc,
		{ "Spare","gsm_a.rr.pow_cmd_atc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_atc_value), 0x80,          
		"Spare", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_epc,
		{ "EPC_mode","gsm_a.rr.pow_cmd_epc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_epc_value), 0x40,          
		"EPC_mode", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_fpcepc,
		{ "FPC_EPC","gsm_a.rr.pow_cmd_fpcepc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_fpcepc_value), 0x20,          
		"FPC_EPC", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_powlev,
		{ "POWER LEVEL","sm_a.rr.pow_cmd_pow",
		FT_UINT8,BASE_DEC,  NULL, 0x1f,          
		"POWER LEVEL", HFILL }
	},
	{ &hf_gsm_a_rr_sync_ind_nci,
		{ "Normal cell indication(NCI)","gsm_a.rr.sync_ind_nci",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_sync_ind_nci_value), 0x08,          
		"Normal cell indication(NCI)", HFILL }
	},
	{ &hf_gsm_a_rr_sync_ind_rot,
		{ "Report Observed Time Difference(ROT)","gsm_a.rr.sync_ind_rot",
		FT_BOOLEAN,8,  TFS(&sm_a_rr_sync_ind_rot_value), 0x04,          
		"Report Observed Time Difference(ROT)", HFILL }
	},
	{ &hf_gsm_a_rr_sync_ind_si,
		{ "Synchronization indication(SI)","gsm_a.rr_sync_ind_si",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_sync_ind_si_vals), 0x03,          
		"Synchronization indication(SI)", HFILL }
	},
	{ &hf_gsm_a_rr_format_id,
		{ "Format Identifier","gsm_a.rr_format_id",
		FT_UINT8,BASE_HEX,  VALS(gsm_a_rr_freq_list_format_id_vals), 0xce,          
		"Format Identifier", HFILL }
	},
	{ &hf_gsm_a_rr_channel_mode,
		{ "Channel Mode","gsm_a.rr.channel_mode",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_mode_vals), 0x0,          
		"Channel Mode", HFILL }
	},
	{ &hf_gsm_a_rr_channel_mode2,
		{ "Channel Mode 2","gsm_a.rr.channel_mode2",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_mode2_vals), 0x0,          
		"Channel Mode 2", HFILL }
	},
	{ &hf_gsm_a_rr_sc,
		{ "SC","gsm_a.rr.SC",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_sc_vals), 0x1,          
		"SC", HFILL }
	},
	{ &hf_gsm_a_algorithm_id,
		{ "Algorithm identifier","gsm_a.algorithm_identifier",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_algorithm_identifier_vals), 0xe,          
		"Algorithm_identifier", HFILL }
	},

	{ &hf_gsm_a_rr_multirate_speech_ver,
		{ "Multirate speech version","gsm_a.rr.multirate_speech_ver",
		FT_UINT8,BASE_DEC,  VALS(multirate_speech_ver_vals), 0xe0,          
		"Multirate speech version", HFILL }
	},
	{ &hf_gsm_a_rr_NCSB,
		{ "NSCB: Noise Suppression Control Bit","gsm_a.rr.NCSB",
		FT_UINT8,BASE_DEC,  VALS(NSCB_vals), 0x10,          
		"NSCB: Noise Suppression Control Bit", HFILL }
	},
	{ &hf_gsm_a_rr_ICMI,
		{ "ICMI: Initial Codec Mode Indicator","gsm_a.rr.ICMI",
		FT_UINT8,BASE_DEC,  VALS(ICMI_vals), 0x8,          
		"ICMI: Initial Codec Mode Indicator", HFILL }
	},
	{ &hf_gsm_a_rr_start_mode,
		{ "Start Mode","gsm_a.rr.start_mode",
		FT_UINT8,BASE_DEC,  NULL, 0x3,          
		"Start Mode", HFILL }
	},
	{ &hf_gsm_a_rr_timing_adv,
		{ "Timing advance value","gsm_a.rr.timing_adv",
		FT_UINT8,BASE_DEC,  NULL, 0x0,          
		"Timing advance value", HFILL }
	},
	{ &hf_gsm_a_rr_time_diff,
		{ "Time difference value","gsm_a.rr.time_diff",
		FT_UINT8,BASE_DEC,  NULL, 0x0,          
		"Time difference value", HFILL }
	},
	{ &hf_gsm_a_rr_tlli,
		{ "TLLI","gsm_a.rr.tlli",
		FT_UINT32,BASE_HEX,  NULL, 0x0,          
		"TLLI", HFILL }
	},
	{ &hf_gsm_a_rr_target_mode,
		{ "Target mode","gsm_a.rr.target_mode",
		FT_UINT8,BASE_DEC,  NULL, 0xc0,          
		"Target mode", HFILL }
	},
	{ &hf_gsm_a_rr_group_cipher_key_number,
		{ "Group cipher key number","gsm_a.rr.Group_cipher_key_number",
		FT_UINT8,BASE_DEC,  NULL, 0x3c,          
		"Group cipher key number", HFILL }
	},
	{ &hf_gsm_a_rr_last_segment,
		{ "Last Segment","gsm_a.rr.last_segment",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_last_segment_value), 0x01,          
		"Last Segment", HFILL }
	},
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
	{ &hf_gsm_a_rr_RR_cause,
		{ "RR cause value","gsm_a.rr.RRcause",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_RR_cause_vals), 0x0,          
		"RR cause value", HFILL }
		},
	{ &hf_gsm_a_be_cell_id_disc,
		{ "Cell identification discriminator","gsm_a.be.cell_id_disc",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_cell_id_disc_vals), 0x0f,          
		"Cell identificationdiscriminator", HFILL }
	},
	{ &hf_gsm_a_be_rnc_id,
		{ "RNC-ID","gsm_a.be.rnc_id",
		FT_UINT16,BASE_DEC,  NULL, 0x0,          
		"RNC-ID", HFILL }
	},
	{ &hf_gsm_a_rr_cm_cng_msg_req, 
		{ "CLASSMARK CHANGE","gsm_a.rr_cm_cng_msg_req",
		FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x80,          
		"CLASSMARK CHANGE ", HFILL }
	},
	{ &hf_gsm_a_rr_utran_cm_cng_msg_req,
		{ "UTRAN CLASSMARK CHANGE","gsm_a.rr_utran_cm_cng_msg_req",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_utran_cm_cng_msg_req_vals), 0x70,          
		"UTRAN CLASSMARK CHANGE", HFILL }
	},
	{ &hf_gsm_a_rr_cdma200_cm_cng_msg_req,
		{ "CDMA2000 CLASSMARK CHANGE ","gsm_a.rr_cdma200_cm_cng_msg_req",
		FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x08,          
		"CDMA2000 CLASSMARK CHANGE ", HFILL }
	},
	{ &hf_gsm_a_rr_geran_iu_cm_cng_msg_req,
		{ "GERAN IU MODE CLASSMARK CHANGE","gsm_a.rr_geran_iu_cm_cng_msg_req",
		FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x04,          
		"GERAN IU MODE CLASSMARK CHANGE", HFILL }
	},
	{ &hf_gsm_a_rr_suspension_cause,
		{ "Suspension cause value","gsm_a.rr.suspension_cause",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_suspension_cause_vals), 0x0,          
		"Suspension cause value", HFILL }
	},
    { &hf_ROS_component,
      { "component", "ROS.component",
        FT_UINT8, BASE_DEC, VALS(ROS_Component_vals), 0,
        "Component", HFILL }},
    { &hf_ROS_invoke,
      { "invoke", "ROS.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/invoke", HFILL }},
    { &hf_ROS_returnResultLast,
      { "returnResultLast", "ROS.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/returnResultLast", HFILL }},
    { &hf_ROS_returnError,
      { "returnError", "ROS.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/returnError", HFILL }},
    { &hf_ROS_reject,
      { "reject", "ROS.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/reject", HFILL }},
    { &hf_ROS_invokeID,
      { "invokeID", "ROS.invokeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ROS_linkedID,
      { "linkedID", "ROS.linkedID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Invoke/linkedID", HFILL }},
    { &hf_ROS_opCode,
      { "opCode", "ROS.opCode",
        FT_UINT32, BASE_DEC, VALS(ROS_OPERATION_vals), 0,
        "", HFILL }},
    { &hf_ROS_parameter,
      { "parameter", "ROS.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ROS_resultretres,
      { "resultretres", "ROS.resultretres",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult/resultretres", HFILL }},
    { &hf_ROS_errorCode,
      { "errorCode", "ROS.errorCode",
        FT_UINT32, BASE_DEC, VALS(ROS_ErrorCode_vals), 0,
        "ReturnError/errorCode", HFILL }},
    { &hf_ROS_invokeIDRej,
      { "invokeIDRej", "ROS.invokeIDRej",
        FT_UINT32, BASE_DEC, VALS(ROS_T_invokeIDRej_vals), 0,
        "Reject/invokeIDRej", HFILL }},
    { &hf_ROS_derivable,
      { "derivable", "ROS.derivable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Reject/invokeIDRej/derivable", HFILL }},
    { &hf_ROS_not_derivable,
      { "not-derivable", "ROS.not_derivable",
        FT_NONE, BASE_NONE, NULL, 0,
        "Reject/invokeIDRej/not-derivable", HFILL }},
    { &hf_ROS_problem,
      { "problem", "ROS.problem",
        FT_UINT32, BASE_DEC, VALS(ROS_T_problem_vals), 0,
        "Reject/problem", HFILL }},
    { &hf_ROS_generalProblem,
      { "generalProblem", "ROS.generalProblem",
        FT_INT32, BASE_DEC, VALS(ROS_GeneralProblem_vals), 0,
        "Reject/problem/generalProblem", HFILL }},
    { &hf_ROS_invokeProblem,
      { "invokeProblem", "ROS.invokeProblem",
        FT_INT32, BASE_DEC, VALS(ROS_InvokeProblem_vals), 0,
        "Reject/problem/invokeProblem", HFILL }},
    { &hf_ROS_returnResultProblem,
      { "returnResultProblem", "ROS.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(ROS_ReturnResultProblem_vals), 0,
        "Reject/problem/returnResultProblem", HFILL }},
    { &hf_ROS_returnErrorProblem,
      { "returnErrorProblem", "ROS.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(ROS_ReturnErrorProblem_vals), 0,
        "Reject/problem/returnErrorProblem", HFILL }},
    { &hf_ROS_localValue,
      { "localValue", "ROS.localValue",
        FT_INT32, BASE_DEC, VALS(gsm_ss_opr_code_strings), 0,
        "", HFILL }},
    { &hf_ROS_globalValue,
      { "globalValue", "ROS.globalValue",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ROS_nationaler,
      { "nationaler", "ROS.nationaler",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ErrorCode/nationaler", HFILL }},
    { &hf_ROS_privateer,
      { "privateer", "ROS.privateer",
        FT_INT32, BASE_DEC, NULL, 0,
        "ErrorCode/privateer", HFILL }},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8,
      { "12,2 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b8",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x80,          
		"12,2 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7,
      { "10,2 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b7",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x40,          
		"10,2 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6,
      { "7,95 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b6",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x20,          
		"7,95 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5,
      { "7,40 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b5",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x10,          
		"7,40 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4,
      { "6,70 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b4",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x08,          
		"6,70 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3,
      { "5,90 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b3",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x04,          
		"5,90 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2,
      { "5,15 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b2",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x02,          
		"5,15 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1,
      { "4,75 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b1",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x01,          
		"4,75 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5,
      { "23,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b5",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x10,          
		"23,85 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4,
      { "15,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b4",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x08,          
		"15,85 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3,
      { "12,65 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b3",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x04,          
		"12,65 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2,
      { "8,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b2",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x02,          
		"8,85 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1,
      { "6,60 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b1",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x01,          
		"6,60 kbit/s codec rate", HFILL }
	},

    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	50
    static gint *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSMAP_MSG +
			NUM_GSM_DTAP_MSG_MM + NUM_GSM_DTAP_MSG_RR + NUM_GSM_DTAP_MSG_CC +
			NUM_GSM_DTAP_MSG_GMM + NUM_GSM_DTAP_MSG_SMS +
			NUM_GSM_DTAP_MSG_SM + NUM_GSM_DTAP_MSG_SS + NUM_GSM_RP_MSG +
			NUM_GSM_BSSMAP_ELEM + NUM_GSM_DTAP_ELEM];

    ett[0] = &ett_bssmap_msg;
    ett[1] = &ett_dtap_msg;
    ett[2] = &ett_rp_msg;
    ett[3] = &ett_elems;
    ett[4] = &ett_elem;
    ett[5] = &ett_dtap_oct_1;
    ett[6] = &ett_cm_srvc_type;
    ett[7] = &ett_gsm_enc_info;
    ett[8] = &ett_cell_list;
    ett[9] = &ett_dlci;
    ett[10] = &ett_bc_oct_3a;
    ett[11] = &ett_bc_oct_4;
    ett[12] = &ett_bc_oct_5;
    ett[13] = &ett_bc_oct_5a;
    ett[14] = &ett_bc_oct_5b;
    ett[15] = &ett_bc_oct_6;
    ett[16] = &ett_bc_oct_6a;
    ett[17] = &ett_bc_oct_6b;
    ett[18] = &ett_bc_oct_6c;
    ett[19] = &ett_bc_oct_6d;
    ett[20] = &ett_bc_oct_6e;
    ett[21] = &ett_bc_oct_6f;
    ett[22] = &ett_bc_oct_6g;
    ett[23] = &ett_bc_oct_7;

    ett[24] = &ett_tc_component;
    ett[25] = &ett_tc_invoke_id;
    ett[26] = &ett_tc_linked_id;
    ett[27] = &ett_tc_opr_code;
    ett[28] = &ett_tc_err_code;
    ett[29] = &ett_tc_prob_code;
    ett[30] = &ett_tc_sequence;
    
    ett[31] = &ett_gmm_drx;
    ett[32] = &ett_gmm_detach_type;
    ett[33] = &ett_gmm_attach_type;
    ett[34] = &ett_gmm_context_stat;
    ett[35] = &ett_gmm_update_type;
    ett[36] = &ett_gmm_radio_cap;

    ett[37] = &ett_sm_tft;

    ett[38] = &ett_ros,
    ett[39] = &ett_ROS_Component,
    ett[40] = &ett_ROS_Invoke,
    ett[41] = &ett_ROS_ReturnResult,
    ett[42] = &ett_ROS_T_resultretres,
    ett[43] = &ett_ROS_ReturnError,
    ett[44] = &ett_ROS_Reject,
    ett[45] = &ett_ROS_T_invokeIDRej,
    ett[46] = &ett_ROS_T_problem,
    ett[47] = &ett_ROS_OPERATION,
    ett[48] = &ett_ROS_ERROR,
    ett[49] = &ett_ROS_ErrorCode,

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_GSM_BSSMAP_MSG; i++, last_offset++)
    {
	ett_gsm_bssmap_msg[i] = -1;
	ett[last_offset] = &ett_gsm_bssmap_msg[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_MM; i++, last_offset++)
    {
	ett_gsm_dtap_msg_mm[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_mm[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_RR; i++, last_offset++)
    {
	ett_gsm_dtap_msg_rr[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_msg_rr[i];
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

    for (i=0; i < NUM_GSM_RP_MSG; i++, last_offset++)
    {
	ett_gsm_rp_msg[i] = -1;
	ett[last_offset] = &ett_gsm_rp_msg[i];
    }

    for (i=0; i < NUM_GSM_BSSMAP_ELEM; i++, last_offset++)
    {
	ett_gsm_bssmap_elem[i] = -1;
	ett[last_offset] = &ett_gsm_bssmap_elem[i];
    }

    for (i=0; i < NUM_GSM_DTAP_ELEM; i++, last_offset++)
    {
	ett_gsm_dtap_elem[i] = -1;
	ett[last_offset] = &ett_gsm_dtap_elem[i];
    }


    /* Register the protocol name and description */

    proto_a_bssmap =
	proto_register_protocol("GSM A-I/F BSSMAP", "GSM BSSMAP", "gsm_a_bssmap");

    proto_register_field_array(proto_a_bssmap, hf, array_length(hf));

    proto_a_dtap =
	proto_register_protocol("GSM A-I/F DTAP", "GSM DTAP", "gsm_a_dtap");

    proto_a_rp =
	proto_register_protocol("GSM A-I/F RP", "GSM RP", "gsm_a_rp");

    sms_dissector_table =
	register_dissector_table("gsm_a.sms_tpdu", "GSM SMS TPDU",
	FT_UINT8, BASE_DEC);

    proto_register_subtree_array(ett, array_length(ett));

    /* subdissector code */
    gprs_sm_pco_subdissector_table = register_dissector_table("sm_pco.protocol",
    	"GPRS SM PCO PPP protocol", FT_UINT16, BASE_HEX);

    gsm_a_tap = register_tap("gsm_a");
	
	register_dissector("gsm_a_dtap", dissect_dtap, proto_a_dtap);
}


void
proto_reg_handoff_gsm_a(void)
{

    bssmap_handle = create_dissector_handle(dissect_bssmap, proto_a_bssmap);
    dtap_handle = find_dissector("gsm_a_dtap");
    rp_handle = create_dissector_handle(dissect_rp, proto_a_rp);

    dissector_add("bssap.pdu_type",  BSSAP_PDU_TYPE_BSSMAP, bssmap_handle);
    dissector_add("bssap.pdu_type",  BSSAP_PDU_TYPE_DTAP, dtap_handle);
    dissector_add("ranap.nas_pdu",  BSSAP_PDU_TYPE_DTAP, dtap_handle);
    dissector_add("llcgprs.sapi", 1 , dtap_handle);
    data_handle = find_dissector("data");
}

