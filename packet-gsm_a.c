/* packet-gsm_a.c
 * Routines for GSM A Interface (BSSMAP/DTAP) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
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
 *
 *   Reference [4]
 *   Mobile radio interface layer 3 specification;
 *   Radio Resource Control Protocol
 *   (GSM 04.18 version 8.4.1 Release 1999)
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
 * $Id: packet-gsm_a.c,v 1.10 2003/12/21 04:31:56 jmayer Exp $
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
#include "prefs.h"
#include "tap.h"

#include "packet-bssap.h"
#include "packet-gsm_a.h"

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

/*    { 0xc0,	"Utran Classmark Change" }, CONFLICTS WITH Handover To UTRAN Command */
    { 0xc1,	"UE RAB Preconfiguration" },
    { 0xc2,	"cdma2000 Classmark Change" },

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
    { 0x32,	"Queueing Indicator" },
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
    { 0x00,	"RR Cause" },
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
    { 0x00,	"TMSI Status" },
    { 0x00,	"Detach Type" },
    { 0x00,	"DRX Parameter" },
    { 0x00,	"Force to Standby" },
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
    { 0x00,	"A&C Reference Number" },
    { 0x00,	"Service Type" },
    { 0x00,	"Cell Notification" },
    { 0x00,	"Network Feature Support" },
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

static const value_string bssap_cc_values[] = {
    { 0x00,		"not further specified" },
    { 0x80,		"FACCH or SDCCH" },
    { 0xc0,		"SACCH" },
    { 0,		NULL } };

static const value_string bssap_sapi_values[] = {
    { 0x00,		"RR/MM/CC" },
    { 0x03,		"SMS" },
    { 0,		NULL } };

static const gchar *cell_disc_str[] = {
    "The whole Cell Global Identification, CGI, is used to identify the cells",
    "Location Area Code, LAC, and Cell Identify, CI, is used to identify the cells",
    "Cell Identity, CI, is used to identify the cells",
    "No cell is associated with the transaction",
    "Location Area Identification, LAI, is used to identify all cells within a Location Area",
    "Location Area Code, LAC, is used to identify all cells within a location area",
    "All cells on the BSS are identified"
};
#define	NUM_CELL_DISC_STR	(sizeof(cell_disc_str)/sizeof(gchar *))

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

static char a_bigbuf[1024];
static gchar a_add_string[1024];

static dissector_handle_t data_handle;
static dissector_handle_t bssmap_handle;
static dissector_handle_t dtap_handle;
static dissector_handle_t rp_handle;
static dissector_table_t sms_dissector_table;	/* SMS TPDU */

static packet_info *g_pinfo;
static proto_tree *g_tree;

/*
 * current RP message type
 */
static gint gsm_a_rp_type;

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

static gchar *
my_match_strval(guint32 val, const value_string *vs, gint *idx)
{
    gint i = 0;

    while (vs[i].strptr)
    {
	if (vs[i].value == val)
	{
	    *idx = i;
	    return(vs[i].strptr);
	}

	i++;
    }

    *idx = -1;
    return(NULL);
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
be_cic(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
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

    sprintf(add_string, " - (%u) (0x%04x)", value, value);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.5
 */
static guint8
be_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	value;
    guint32	curr_offset;
    gchar	*str = NULL;

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

	    strcpy(add_string, " - (National Cause)");
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
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Cause: (%u) %s",
	    a_bigbuf,
	    oct & 0x7f,
	    str);

	curr_offset++;

	sprintf(add_string, " - (%u) %s", oct & 0x7f, str);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.7
 */
static guint8
be_tmsi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;
    guint32	value;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_uint(tree, hf_gsm_a_tmsi,
	tvb, curr_offset, 4,
	value);

    sprintf(add_string, " - (0x%04x)", value);

    curr_offset += 4;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.9
 */
static guint8
be_l3_header_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;

    add_string = add_string;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, DTAP_PD_MASK, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Protocol Discriminator: %s",
	a_bigbuf,
	gsm_a_pd_str[oct & DTAP_PD_MASK]);

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
be_enc_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	mask;
    guint8	alg_id;
    guint32	curr_offset;

    add_string = add_string;
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
be_chan_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	sdi;
    guint8	num_chan;
    guint32	curr_offset;
    gchar	*str;

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

    sprintf(add_string, " - (%s)", str);

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
be_cell_id_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, guint8 disc)
{
    guint8	octs[3];
    guint32	value;
    guint32	curr_offset;
    gchar	mcc[4];
    gchar	mnc[4];

    add_string[0] = '\0';
    curr_offset = offset;

    switch (disc)
    {
    case 0x00:
	/* FALLTHRU */

    case 0x04:
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

	/* LAC */

	value = tvb_get_ntohs(tvb, curr_offset);

	proto_tree_add_uint(tree, hf_gsm_a_cell_lac, tvb,
	    curr_offset, 2, value);

	curr_offset += 2;

	sprintf(add_string, " - LAC (0x%04x)", value);

	if ((disc == 0x04) || (disc == 0x05)) break;

	/* FALLTHRU */

    case 0x02:

	/* CI */

	value = tvb_get_ntohs(tvb, curr_offset);

	proto_tree_add_uint(tree, hf_gsm_a_cell_ci, tvb,
	    curr_offset, 2, value);

	curr_offset += 2;

	if (add_string[0] == '\0')
	{
	    sprintf(add_string, " - CI (%u)", value);
	}
	else
	{
	    sprintf(add_string, "%s/CI (%u)", add_string, value);
	}
	break;

    default:
	proto_tree_add_text(tree, tvb, curr_offset, len - 1,
	    "Cell ID - Unknown format");

	curr_offset += (len - 1);
	break;
    }

    return(curr_offset - offset);
}

static guint8
be_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	disc;
    guint32	curr_offset;
    const gchar	*str = NULL;

    len = len;
    add_string = add_string;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    disc = oct & 0x0f;

    if (disc >= (gint) NUM_CELL_DISC_STR)
    {
	str = "Unknown";
    }
    else
    {
	str = cell_disc_str[disc];
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Cell Identification Discriminator: (%u) %s",
	a_bigbuf,
	disc,
	str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    curr_offset +=
	be_cell_id_aux(tvb, tree, curr_offset, len - (curr_offset - offset), add_string, disc);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.18
 */
static guint8
be_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

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

    sprintf(add_string, " - (%u)", (oct & 0x3c) >> 2);

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
be_l3_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;
    tvbuff_t	*l3_tvb;

    add_string = add_string;
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
be_dlci(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    proto_item	*item = NULL;
    proto_tree	*subtree = NULL;

    len = len;
    add_string = add_string;
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
be_down_dtx_flag(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint	oct;
    guint32	curr_offset;

    len = len;
    add_string = add_string;
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
static guint8
be_cell_id_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	consumed;
    guint8	disc;
    guint8	num_cells;
    guint32	curr_offset;
    proto_item	*item = NULL;
    proto_tree	*subtree = NULL;
    const gchar	*str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    disc = oct & 0x0f;

    if (disc >= (gint) NUM_CELL_DISC_STR)
    {
	str = "Unknown";
    }
    else
    {
	str = cell_disc_str[disc];
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Cell Identification Discriminator: (%u) %s",
	a_bigbuf,
	disc,
	str);

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

	add_string[0] = '\0';
	consumed =
	    be_cell_id_aux(tvb, subtree, curr_offset, len - (curr_offset - offset), add_string, disc);

	if (add_string[0] != '\0')
	{
	    proto_item_append_text(item, add_string);
	}

	proto_item_set_len(item, consumed);

	curr_offset += consumed;

	num_cells++;
    }
    while ((len - (curr_offset - offset)) > 0);

    sprintf(add_string, " - %u cell%s",
	num_cells, plurality(num_cells, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.33
 */
static guint8
be_chosen_chan(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str = NULL;

    len = len;
    add_string = add_string;
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
be_ciph_resp_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    add_string = add_string;
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
be_l3_msg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;
    tvbuff_t	*l3_tvb;

    add_string = add_string;
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
be_for_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str = NULL;

    len = len;
    add_string = add_string;
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
be_chosen_enc_alg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str = NULL;

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

    sprintf(add_string, " - %s", str);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.45
 */
static guint8
be_cct_pool(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str = NULL;

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

    sprintf(add_string, " - (%u)", oct);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.49
 */
static guint8
be_curr_chan_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    add_string = add_string;
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
be_que_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    add_string = add_string;
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
be_speech_ver(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str = NULL;
    gchar	*short_str = NULL;

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

    sprintf(add_string, " - (%s)", short_str);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [2] 3.2.2.68
 */
static guint8
be_apdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    add_string = add_string;
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
    /* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1 */
    DE_RR_CAUSE,	/* RR Cause */
    /* Mobility Management Information Elements 10.5.3 */
    DE_AUTH_PARAM_RAND,	/* Authentication Parameter RAND */
    DE_AUTH_PARAM_AUTN,	/* Authentication Parameter AUTN (UMTS authentication challenge only) */
    DE_AUTH_RESP_PARAM,	/* Authentication Response Parameter */
    DE_AUTH_RESP_PARAM_EXT,	/* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
    DE_AUTH_FAIL_PARAM,	/* Authentication Failure Parameter (UMTS authentication challenge only) */
    DE_CM_SRVC_TYPE,	/* CM Service Type */
    DE_ID_TYPE,	/* Identity Type */
    DE_LOC_UPD_TYPE,	/* Location Updating Type */
    DE_NETWORK_NAME,	/* Network Name */
    DE_REJ_CAUSE,	/* Reject Cause */
    DE_FOP,	/* Follow-on Proceed */
    DE_TIME_ZONE,	/* Time Zone */
    DE_TIME_ZONE_TIME,	/* Time Zone and Time */
    DE_CTS_PERM,	/* CTS Permission */
    DE_LSA_ID,	/* LSA Identifier */
    DE_DAY_SAVING_TIME,	/* Daylight Saving Time */
    /* Call Control Information Elements 10.5.4 */
    DE_AUX_STATES,	/* Auxiliary States */
    DE_BEARER_CAP,	/* Bearer Capability */
    DE_CC_CAP,	/* Call Control Capabilities */
    DE_CALL_STATE,	/* Call State */
    DE_CLD_PARTY_BCD_NUM,	/* Called Party BCD Number */
    DE_CLD_PARTY_SUB_ADDR,	/* Called Party Subaddress */
    DE_CLG_PARTY_BCD_NUM,	/* Calling Party BCD Number */
    DE_CLG_PARTY_SUB_ADDR,	/* Calling Party Subaddress */
    DE_CAUSE,	/* Cause */
    DE_CLIR_SUP,	/* CLIR Suppression */
    DE_CLIR_INV,	/* CLIR Invocation */
    DE_CONGESTION,	/* Congestion Level */
    DE_CONN_NUM,	/* Connected Number */
    DE_CONN_SUB_ADDR,	/* Connected Subaddress */
    DE_FACILITY,	/* Facility */
    DE_HLC,	/* High Layer Compatibility */
    DE_KEYPAD_FACILITY,	/* Keypad Facility */
    DE_LLC,	/* Low Layer Compatibility */
    DE_MORE_DATA,	/* More Data */
    DE_NOT_IND,	/* Notification Indicator */
    DE_PROG_IND,	/* Progress Indicator */
    DE_RECALL_TYPE,	/* Recall type $(CCBS)$ */
    DE_RED_PARTY_BCD_NUM,	/* Redirecting Party BCD Number */
    DE_RED_PARTY_SUB_ADDR,	/* Redirecting Party Subaddress */
    DE_REPEAT_IND,	/* Repeat Indicator */
    DE_REV_CALL_SETUP_DIR,	/* Reverse Call Setup Direction */
    DE_SETUP_CONTAINER,	/* SETUP Container $(CCBS)$ */
    DE_SIGNAL,	/* Signal */
    DE_SS_VER_IND,	/* SS Version Indicator */
    DE_USER_USER,	/* User-user */
    DE_ALERT_PATTERN,	/* Alerting Pattern $(NIA)$ */
    DE_ALLOWED_ACTIONS,	/* Allowed Actions $(CCBS)$ */
    DE_SI,	/* Stream Identifier */
    DE_NET_CC_CAP,	/* Network Call Control Capabilities */
    DE_CAUSE_NO_CLI,	/* Cause of No CLI */
    DE_IMM_MOD_IND,	/* Immediate Modification Indicator */
    DE_SUP_CODEC_LIST,	/* Supported Codec List */
    DE_SRVC_CAT,	/* Service Category */
    /* GPRS Mobility Management Information Elements 10.5.5 */
    DE_ATTACH_RES,	/* Attach Result */
    DE_ATTACH_TYPE,	/* Attach Type */
    DE_TMSI_STAT,	/* TMSI Status */
    DE_DETACH_TYPE,	/* Detach Type */
    DE_DRX_PARAM,	/* DRX Parameter */
    DE_FORCE_TO_STAND,	/* Force to Standby */
    DE_P_TMSI_SIG,	/* P-TMSI Signature */
    DE_P_TMSI_SIG_2,	/* P-TMSI Signature 2 */
    DE_ID_TYPE_2,	/* Identity Type 2 */
    DE_IMEISV_REQ,	/* IMEISV Request */
    DE_REC_N_PDU_NUM_LIST,	/* Receive N-PDU Numbers List */
    DE_MS_NET_CAP,	/* MS Network Capability */
    DE_MS_RAD_ACC_CAP,	/* MS Radio Access Capability */
    DE_GMM_CAUSE,	/* GMM Cause */
    DE_RAI,	/* Routing Area Identification */
    DE_UPD_RES,	/* Update Result */
    DE_AC_REF_NUM,	/* A&C Reference Number */
    DE_SRVC_TYPE,	/* Service Type */
    DE_CELL_NOT,	/* Cell Notification */
    DE_NET_FEAT_SUP,	/* Network Feature Support */
    /* Short Message Service Information Elements [5] 8.1.4 */
    DE_CP_USER_DATA,	/* CP-User Data */
    DE_CP_CAUSE,	/* CP-Cause */
    /* Short Message Service Information Elements [5] 8.2 */
    DE_RP_MESSAGE_REF,	/* RP-Message Reference */
    DE_RP_ORIG_ADDR,	/* RP-Origination Address */
    DE_RP_DEST_ADDR,	/* RP-Destination Address */
    DE_RP_USER_DATA,	/* RP-User Data */
    DE_RP_CAUSE,	/* RP-Cause */
    /* Session Management Information Elements 10.5.6 */
    DE_ACC_POINT_NAME,	/* Access Point Name */
    DE_NET_SAPI,	/* Network Service Access Point Identifier */
    DE_PRO_CONF_OPT,	/* Protocol Configuration Options */
    DE_PD_PRO_ADDR,	/* Packet Data Protocol Address */
    DE_QOS,	/* Quality Of Service */
    DE_SM_CAUSE,	/* SM Cause */
    DE_LINKED_TI,	/* Linked TI */
    DE_LLC_SAPI,	/* LLC Service Access Point Identifier */
    DE_TEAR_DOWN_IND,	/* Tear Down Indicator */
    DE_PACKET_FLOW_ID,	/* Packet Flow Identifier */
    DE_TRAFFIC_FLOW_TEMPLATE,	/* Traffic Flow Template */
    /* GPRS Common Information Elements 10.5.7 */
    DE_PDP_CONTEXT_STAT,	/* PDP Context Status */
    DE_RAD_PRIO,	/* Radio Priority */
    DE_GPRS_TIMER,	/* GPRS Timer */
    DE_GPRS_TIMER_2,	/* GPRS Timer 2 */
    DE_NONE	/* NONE */
}
dtap_elem_idx_t;

#define	NUM_GSM_DTAP_ELEM (sizeof(gsm_dtap_elem_strings)/sizeof(value_string))
static gint ett_gsm_dtap_elem[NUM_GSM_DTAP_ELEM];

/*
 * [3] 10.5.1.1
 */
static guint8
de_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    curr_offset = offset;

    curr_offset +=
	be_cell_id_aux(tvb, tree, offset, len, add_string, 0x02);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.3
 */
static guint8
de_lai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	octs[3];
    guint16	value;
    guint32	curr_offset;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	mcc[4];
    gchar	mnc[4];

    len = len;
    add_string = add_string;
    curr_offset = offset;

    octs[0] = tvb_get_guint8(tvb, curr_offset);
    octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
    octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

    mcc_mnc_aux(octs, mcc, mnc);

    item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, 5,
	    gsm_dtap_elem_strings[DE_LAI].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_LAI]);

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
static guint8
de_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
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

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Odd/Even Indicator: %s",
	    a_bigbuf,
	    (oct & 0x08) ? "ODD" : "EVEN");

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Type of Identity: No Identity Code",
	    a_bigbuf);

	strcpy(add_string, " - No Identity Code");

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

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Odd/Even Indicator: %s",
	    a_bigbuf,
	    odd ? "ODD" : "EVEN");

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Type of Identity: %s",
	    a_bigbuf,
	    ((oct & 0x07) == 3) ? "IMEISV" : "IMSI");

	a_bigbuf[0] = Dgt_msid.out[(oct & 0xf0) >> 4];
	curr_offset++;

	poctets = tvb_get_string(tvb, curr_offset, len - (curr_offset - offset));

	my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
	    &Dgt_msid);
	g_free(poctets);

	proto_tree_add_string_format(tree,
	    ((oct & 0x07) == 3) ? hf_gsm_a_imeisv : hf_gsm_a_imsi,
	    tvb, curr_offset, len - (curr_offset - offset),
	    a_bigbuf,
	    "BCD Digits: %s",
	    a_bigbuf);

	sprintf(add_string, " - %s (%s)",
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

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Odd/Even Indicator: %s",
	    a_bigbuf,
	    (oct & 0x08) ? "ODD" : "EVEN");

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Type of Identity: IMEI",
	    a_bigbuf);

	a_bigbuf[0] = Dgt_msid.out[(oct & 0xf0) >> 4];
	curr_offset++;

	poctets = tvb_get_string(tvb, curr_offset, len - (curr_offset - offset));

	my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
	    &Dgt_msid);
	g_free(poctets);

	proto_tree_add_string_format(tree,
	    hf_gsm_a_imei,
	    tvb, curr_offset, len - (curr_offset - offset),
	    a_bigbuf,
	    "BCD Digits: %s",
	    a_bigbuf);

	sprintf(add_string, " - IMEI (%s)", a_bigbuf);

	curr_offset += len - (curr_offset - offset);
	break;

    case 4:	/* TMSI/P-TMSI */
	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Unused",
	    a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Odd/Even Indicator: %s",
	    a_bigbuf,
	    (oct & 0x08) ? "ODD" : "EVEN");

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "%s :  Type of Identity: TMSI/P-TMSI",
	    a_bigbuf);

	curr_offset++;

	value = tvb_get_ntohl(tvb, curr_offset);

	proto_tree_add_uint(tree, hf_gsm_a_tmsi,
	    tvb, curr_offset, 4,
	    value);

	sprintf(add_string, " - TMSI/P-TMSI (0x%04x)", value);

	curr_offset += 4;
	break;

    default:	/* Reserved */
	proto_tree_add_text(tree, tvb, curr_offset, len,
	    "Format Unknown");

	strcpy(add_string, " - Format Unknown");

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
de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	*str;

    len = len;
    add_string = add_string;
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

    switch ((oct & 0x60) >> 5)
    {
    case 0: str = "Reserved for GSM phase 1"; break;
    case 1: str = "Used by GSM phase 2 mobile stations"; break;
    case 2: str = "Used by mobile stations supporting R99 or later versions of the protocol"; break;
    default:
	str = "Reserved for future use";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
    proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  Revision Level: %s",
	a_bigbuf,
	str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  ES IND: Controlled Early Classmark Sending is %simplemented",
	a_bigbuf,
	(oct & 0x10) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  A5/1: encryption algorithm A5/1 %savailable",
	a_bigbuf,
	(oct & 0x08) ? "not " : "");

    switch (oct & 0x07)
    {
    case 0: str = "Class 1"; break;
    case 1: str = "Class 2"; break;
    case 2: str = "Class 3"; break;
    case 3: str = "Class 4"; break;
    case 4: str = "Class 5"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(subtree,
	tvb, curr_offset, 1,
	"%s :  RF power capability: %s",
	a_bigbuf,
	str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.6
 */
static guint8
de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    switch ((oct & 0x60) >> 5)
    {
    case 0: str = "Reserved for GSM phase 1"; break;
    case 1: str = "Used by GSM phase 2 mobile stations"; break;
    case 2: str = "Used by mobile stations supporting R99 or later versions of the protocol"; break;
    default:
	str = "Reserved for future use";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Revision Level: %s",
	a_bigbuf,
	str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  ES IND: Controlled Early Classmark Sending is %simplemented",
	a_bigbuf,
	(oct & 0x10) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  A5/1: encryption algorithm A5/1 %savailable",
	a_bigbuf,
	(oct & 0x08) ? "not " : "");

    switch (oct & 0x07)
    {
    case 0: str = "Class 1"; break;
    case 1: str = "Class 2"; break;
    case 2: str = "Class 3"; break;
    case 3: str = "Class 4"; break;
    case 4: str = "Class 5"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  RF power capability: %s",
	a_bigbuf,
	str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  PS capability (pseudo-synchronization capability): %spresent",
	a_bigbuf,
	(oct & 0x40) ? "" : "not ");

    switch ((oct & 0x30) >> 4)
    {
    case 0: str = "Default value for phase 1"; break;
    case 1: str = "Capability of handling of ellipsis notation and phase 2 error handling"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  SS Screening Indicator: %s",
	a_bigbuf,
	str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  SM capability (MT SMS pt to pt capability): MS %s MT SMS",
	a_bigbuf,
	(oct & 0x08) ? "supports" : "does not support");

    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  VBS notification reception: %s",
	a_bigbuf,
	(oct & 0x04) ?  "VBS capability and notifications wanted" :
	    "no VBS capability or no notifications wanted");

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  VGCS notification reception: %s",
	a_bigbuf,
	(oct & 0x02) ?  "VGCS capability and notifications wanted" :
	    "no VGCS capability or no notifications wanted");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  FC Frequency Capability",
	a_bigbuf);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  CM3: %s",
	a_bigbuf,
	(oct & 0x80) ?
	    "The MS supports options that are indicated in classmark 3 IE" :
	    "The MS does not support any options that are indicated in CM3");

    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  LCS VA capability: LCS value added location request notification capability %ssupported",
	a_bigbuf,
	(oct & 0x20) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  UCS2 treatment: %s",
	a_bigbuf,
	(oct & 0x10) ?
	    "the ME has no preference between the use of the default alphabet and the use of UCS2" :
	    "the ME has a preference for the default alphabet (defined in 3GPP TS 03.38) over UCS2");

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  SoLSA: the ME %s SoLSA",
	a_bigbuf,
	(oct & 0x08) ? "supports" : "does not support");

    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  CMSP (CM Service Prompt): %s",
	a_bigbuf,
	(oct & 0x04) ?
	    "'Network initiated MO CM connection request' supported for at least one CM protocol" :
	    "'Network initiated MO CM connection request' not supported");

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  A5/3: encryption algorithm A5/3 %savailable",
	a_bigbuf,
	(oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  A5/2: encryption algorithm A5/2 %savailable",
	a_bigbuf,
	(oct & 0x01) ? "" : "not ");

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.9
 */
static guint8
de_d_gb_call_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	value;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    add_string = add_string;
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
de_pd_sapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	*str;

    len = len;
    add_string = add_string;
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

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
	"%s :  PD (Protocol Discriminator): %s",
	a_bigbuf,
	gsm_a_pd_str[oct & 0x0f]);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.11
 */
static guint8
de_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    add_string = add_string;
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
de_plmn_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	octs[3];
    guint32	curr_offset;
    gchar	mcc[4];
    gchar	mnc[4];
    guint8	num_plmn;

    add_string = add_string;
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

    sprintf(add_string, " - %u PLMN%s",
	num_plmn, plurality(num_plmn, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.31
 */
static guint8
de_rr_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    add_string = add_string;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0x00: str = "Normal event"; break;
    case 0x01: str = "Abnormal release, unspecified"; break;
    case 0x02: str = "Abnormal release, channel unacceptable"; break;
    case 0x03: str = "Abnormal release, timer expired"; break;
    case 0x04: str = "Abnormal release, no activity on the radio path"; break;
    case 0x05: str = "Preemptive release"; break;
    case 0x08: str = "Handover impossible, timing advance out of range"; break;
    case 0x09: str = "Channel mode unacceptable"; break;
    case 0x0a: str = "Frequency not implemented"; break;
    case 0x41: str = "Call already cleared"; break;
    case 0x5f: str = "Semantically incorrect message"; break;
    case 0x60: str = "Invalid mandatory information"; break;
    case 0x61: str = "Message type non-existent or not implemented"; break;
    case 0x62: str = "Message type not compatible with protocol state"; break;
    case 0x64: str = "Conditional IE error"; break;
    case 0x65: str = "No cell allocation available"; break;
    case 0x6f: str = "Protocol error unspecified"; break;
    default:
	str = "Reserved, treat as Normal event";
	break;
    }

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"RR Cause value: 0x%02x (%u) %s",
	oct,
	oct,
	str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.3.1
 */
static guint8
de_auth_param_rand(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    len = len;
    add_string = add_string;
    curr_offset = offset;

/*
 * 12 octets == 128 bits
 */
#define	AUTH_PARAM_RAND_LEN	12

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
de_auth_param_autn(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    add_string = add_string;
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
de_auth_resp_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    len = len;
    add_string = add_string;
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
de_auth_resp_param_ext(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    add_string = add_string;
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
de_auth_fail_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    add_string = add_string;
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
de_network_name(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
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
de_rej_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    add_string = add_string;
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
de_time_zone(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    add_string = add_string;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Time Zone: 0x%02x (%u)",
	oct,
	oct);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.3.9
 */
static guint8
de_time_zone_time(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct, oct2, oct3;
    guint32	curr_offset;

    len = len;
    add_string = add_string;
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

    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"Time Zone: 0x%02x (%u)",
	oct,
	oct);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.3.11
 */
static guint8
de_lsa_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;

    add_string = add_string;
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
de_day_saving_time(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
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
de_aux_states(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
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
de_bearer_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	itc;
    gboolean	extended;
    guint32	curr_offset;
    guint32	saved_offset;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	*str;

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

    sprintf(add_string, " - (%s)", str);

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
de_cc_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;

    add_string = add_string;
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
de_call_state(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	*str;

    len = len;
    add_string = add_string;
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
de_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	ton;
    guint8	*poctets;
    guint32	curr_offset;
    gchar	*str;

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

    poctets = tvb_get_string(tvb, curr_offset, len - (curr_offset - offset));

    my_dgt_tbcd_unpack(a_bigbuf, poctets, len - (curr_offset - offset),
	&Dgt_mbcd);
    g_free(poctets);

    proto_tree_add_string_format(tree, hf_gsm_a_cld_party_bcd_num,
	tvb, curr_offset, len - (curr_offset - offset),
	a_bigbuf,
	"BCD Digits: %s",
	a_bigbuf);

    curr_offset += len - (curr_offset - offset);

    sprintf(add_string, " - (%s)", a_bigbuf);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.4.8
 */
static guint8
de_cld_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
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
de_clg_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	ton;
    guint8	*poctets;
    guint32	curr_offset;
    gchar	*str;

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

    poctets = tvb_get_string(tvb, curr_offset, len - (curr_offset - offset));

    my_dgt_tbcd_unpack(a_bigbuf, poctets, len - (curr_offset - offset),
	&Dgt_mbcd);
    g_free(poctets);

    proto_tree_add_string_format(tree, hf_gsm_a_clg_party_bcd_num,
	tvb, curr_offset, len - (curr_offset - offset),
	a_bigbuf,
	"BCD Digits: %s",
	a_bigbuf);

    curr_offset += len - (curr_offset - offset);

    sprintf(add_string, " - (%s)", a_bigbuf);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.4.10
 */
static guint8
de_clg_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
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
de_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint8	cause;
    guint32	curr_offset;
    gchar	*str;

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
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Cause: (%u) %s",
	a_bigbuf,
	cause,
	str);

    curr_offset++;

    sprintf(add_string, " - (%u) %s", cause, str);

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Diagnostics");

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.4.17
 */
static guint8
de_keypad_facility(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

    switch ((oct & 0x60) >> 5)
    {
    case 0: str = "Coding as specified in ITU-T Rec. Q.931"; break;
    case 1: str = "Reserved for other international standards"; break;
    case 2: str = "National standard"; break;
    default:
	str = "Standard defined for the GSM PLMNS";
	break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Keypad information: %c",
	a_bigbuf,
	oct & 0x7f);

    curr_offset++;

    sprintf(add_string, " - %c", oct & 0x7f);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.4.22
 */
static guint8
de_repeat_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    len = len;
    add_string = add_string;
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
de_ss_ver_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

    add_string = add_string;
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
de_cp_user_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;
    tvbuff_t	*rp_tvb;

    add_string = add_string;
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
de_cp_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

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

    sprintf(add_string, " - (%u) %s", oct, str);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [5] 8.2.3
 */
static guint8
de_rp_message_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;

    len = len;
    add_string = add_string;
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
de_rp_orig_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    return(de_cld_party_bcd_num(tvb, tree, offset, len, add_string));
}

/*
 * [5] 8.2.5.2
 */
static guint8
de_rp_dest_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    return(de_cld_party_bcd_num(tvb, tree, offset, len, add_string));
}

/*
 * [5] 8.2.5.3
 */
static guint8
de_rp_user_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint32	curr_offset;
    tvbuff_t	*tpdu_tvb;

    add_string = add_string;
    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
	"TPDU");

    /*
     * dissect the embedded TPDU message
     */
    tpdu_tvb = tvb_new_subset(tvb, curr_offset, len, len);

    dissector_try_port(sms_dissector_table, gsm_a_rp_type, tpdu_tvb, g_pinfo, g_tree);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * [5] 8.2.5.4
 */
static guint8
de_rp_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string)
{
    guint8	oct;
    guint32	curr_offset;
    gchar	*str;

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

    sprintf(add_string, " - (%u) %s", oct & 0x7f, str);

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_text(tree,
	tvb, curr_offset, len - (curr_offset - offset),
	"Diagnostic field");

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

static guint8 (*bssmap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string) = {
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

static guint8 (*dtap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string) = {
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
    /* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1 */
    de_rr_cause,	/* RR Cause */
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
    NULL,	/* Facility */
    NULL,	/* High Layer Compatibility */
    de_keypad_facility,	/* Keypad Facility */
    NULL,	/* Low Layer Compatibility */
    NULL,	/* More Data */
    NULL,	/* Notification Indicator */
    NULL,	/* Progress Indicator */
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
    NULL,	/* Attach Result */
    NULL,	/* Attach Type */
    NULL,	/* TMSI Status */
    NULL,	/* Detach Type */
    NULL,	/* DRX Parameter */
    NULL,	/* Force to Standby */
    NULL,	/* P-TMSI Signature */
    NULL,	/* P-TMSI Signature 2 */
    NULL,	/* Identity Type 2 */
    NULL,	/* IMEISV Request */
    NULL,	/* Receive N-PDU Numbers List */
    NULL,	/* MS Network Capability */
    NULL,	/* MS Radio Access Capability */
    NULL,	/* GMM Cause */
    NULL,	/* Routing Area Identification */
    NULL,	/* Update Result */
    NULL,	/* A&C Reference Number */
    NULL,	/* Service Type */
    NULL,	/* Cell Notification */
    NULL,	/* Network Feature Support */
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
    NULL,	/* Access Point Name */
    NULL,	/* Network Service Access Point Identifier */
    NULL,	/* Protocol Configuration Options */
    NULL,	/* Packet Data Protocol Address */
    NULL,	/* Quality Of Service */
    NULL,	/* SM Cause */
    NULL,	/* Linked TI */
    NULL,	/* LLC Service Access Point Identifier */
    NULL,	/* Tear Down Indicator */
    NULL,	/* Packet Flow Identifier */
    NULL,	/* Traffic Flow Template */
    /* GPRS Common Information Elements 10.5.7 */
    NULL,	/* PDP Context Status */
    NULL,	/* Radio Priority */
    NULL,	/* GPRS Timer */
    NULL,	/* GPRS Timer 2 */
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
elem_tlv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len, gchar *name_add)
{
    guint8		oct, parm_len;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string);

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
		a_add_string[0] = '\0';
		consumed =
		    (*elem_funcs[idx])(tvb, subtree, curr_offset + 2,
			parm_len, a_add_string);

		if (a_add_string[0] != '\0')
		{
		    proto_item_append_text(item, a_add_string);
		    a_add_string[0] = '\0';
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
elem_tv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, gchar *name_add)
{
    guint8		oct;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string);

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
	    a_add_string[0] = '\0';
	    consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset + 1, -1, a_add_string);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, a_add_string);
		a_add_string[0] = '\0';
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
elem_tv_short(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, gchar *name_add)
{
    guint8		oct;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string);

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
	    a_add_string[0] = '\0';
	    consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset, -1, a_add_string);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, a_add_string);
		a_add_string[0] = '\0';
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
elem_t(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, gchar *name_add)
{
    guint8		oct;
    guint32		curr_offset;
    guint8		consumed;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string);

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
elem_lv(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset, guint len, gchar *name_add)
{
    guint8		parm_len;
    guint8		consumed;
    guint32		curr_offset;
    proto_tree		*subtree;
    proto_item		*item;
    const value_string	*elem_names;
    gint		*elem_ett;
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string);

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
	    a_add_string[0] = '\0';
	    consumed =
		(*elem_funcs[idx])(tvb, subtree, curr_offset + 1,
		    parm_len, a_add_string);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, a_add_string);
		a_add_string[0] = '\0';
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
    guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string);

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
	a_add_string[0] = '\0';
	consumed = (*elem_funcs[idx])(tvb, tree, curr_offset, -1, a_add_string);
	a_add_string[0] = '\0';
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
    gchar	*str;

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
    gchar	*str;

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
    gchar	*str;

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
    gchar	*str;

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
    NULL,	/* Handover Command */
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

/*    NULL,	* Utran Classmark Change * CONFLICTS WITH Handover To UTRAN Command */
    NULL,	/* UE RAB Preconfiguration */
    NULL,	/* cdma2000 Classmark Change */

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
    NULL,	/* Attach Request */
    NULL,	/* Attach Accept */
    NULL,	/* Attach Complete */
    NULL,	/* Attach Reject */
    NULL,	/* Detach Request */
    NULL,	/* Detach Accept */
    NULL,	/* Routing Area Update Request */
    NULL,	/* Routing Area Update Accept */
    NULL,	/* Routing Area Update Complete */
    NULL,	/* Routing Area Update Reject */
    NULL,	/* Service Request */
    NULL,	/* Service Accept */
    NULL,	/* Service Reject */
    NULL,	/* P-TMSI Reallocation Command */
    NULL,	/* P-TMSI Reallocation Complete */
    NULL,	/* Authentication and Ciphering Req */
    NULL,	/* Authentication and Ciphering Resp */
    NULL,	/* Authentication and Ciphering Rej */
    NULL,	/* Authentication and Ciphering Failure */
    NULL,	/* Identity Request */
    NULL,	/* Identity Response */
    NULL,	/* GMM Status */
    NULL,	/* GMM Information */
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
    NULL,	/* Activate PDP Context Request */
    NULL,	/* Activate PDP Context Accept */
    NULL,	/* Activate PDP Context Reject */
    NULL,	/* Request PDP Context Activation */
    NULL,	/* Request PDP Context Activation rej. */
    NULL,	/* Deactivate PDP Context Request */
    NULL,	/* Deactivate PDP Context Accept */
    NULL,	/* Modify PDP Context Request(Network to MS direction) */
    NULL,	/* Modify PDP Context Accept (MS to network direction) */
    NULL,	/* Modify PDP Context Request(MS to network direction) */
    NULL,	/* Modify PDP Context Accept (Network to MS direction) */
    NULL,	/* Modify PDP Context Reject */
    NULL,	/* Activate Secondary PDP Context Request */
    NULL,	/* Activate Secondary PDP Context Accept */
    NULL,	/* Activate Secondary PDP Context Reject */
    NULL,	/* Reserved: was allocated in earlier phases of the protocol */
    NULL,	/* Reserved: was allocated in earlier phases of the protocol */
    NULL,	/* Reserved: was allocated in earlier phases of the protocol */
    NULL,	/* Reserved: was allocated in earlier phases of the protocol */
    NULL,	/* Reserved: was allocated in earlier phases of the protocol */
    NULL,	/* SM Status */
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
    gchar	*str;


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

    str = my_match_strval((guint32) oct, gsm_rp_msg_strings, &idx);

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
	gsm_a_rp_type = oct;

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
	tvb, saved_offset, 1, oct, "Message Type");

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


static void
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
    gchar	*str;


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

    str = my_match_strval((guint32) oct, gsm_a_bssmap_msg_strings, &idx);

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
	tvb, saved_offset, 1, oct, "Message Type");

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
    gchar			*msg_str;
    const gchar			*str;
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

    /*
     * octet 1
     */
    switch (pd)
    {
    case 3:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_CC_IEI_MASK), gsm_a_dtap_msg_cc_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_cc[idx];
	hf_idx = hf_gsm_a_dtap_msg_cc_type;
	msg_fcn = dtap_msg_cc_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	nsd = TRUE;
	break;

    case 5:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_MM_IEI_MASK), gsm_a_dtap_msg_mm_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_mm[idx];
	hf_idx = hf_gsm_a_dtap_msg_mm_type;
	msg_fcn = dtap_msg_mm_fcn[idx];
	nsd = TRUE;
	break;

    case 6:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_RR_IEI_MASK), gsm_a_dtap_msg_rr_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_rr[idx];
	hf_idx = hf_gsm_a_dtap_msg_rr_type;
	msg_fcn = dtap_msg_rr_fcn[idx];
	break;

    case 8:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_GMM_IEI_MASK), gsm_a_dtap_msg_gmm_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_gmm[idx];
	hf_idx = hf_gsm_a_dtap_msg_gmm_type;
	msg_fcn = dtap_msg_gmm_fcn[idx];
	break;

    case 9:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_SMS_IEI_MASK), gsm_a_dtap_msg_sms_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_sms[idx];
	hf_idx = hf_gsm_a_dtap_msg_sms_type;
	msg_fcn = dtap_msg_sms_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	break;

    case 10:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_SM_IEI_MASK), gsm_a_dtap_msg_sm_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_sm[idx];
	hf_idx = hf_gsm_a_dtap_msg_sm_type;
	msg_fcn = dtap_msg_sm_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	break;

    case 11:
	str = gsm_a_pd_str[pd];
	msg_str = my_match_strval((guint32) (oct & DTAP_SS_IEI_MASK), gsm_a_dtap_msg_ss_strings, &idx);
	ett_tree = ett_gsm_dtap_msg_ss[idx];
	hf_idx = hf_gsm_a_dtap_msg_ss_type;
	msg_fcn = dtap_msg_ss_fcn[idx];
	ti = (oct_1 & DTAP_TI_MASK) >> 4;
	nsd = TRUE;
	break;

    default:
	str = gsm_a_pd_str[pd];
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
	    str);

    pd_tree = proto_item_add_subtree(oct_1_item, ett_dtap_oct_1);

    if (ti == -1)
    {
	other_decode_bitfield_value(a_bigbuf, oct_1, 0xf0, 8);
	proto_tree_add_text(pd_tree,
	    tvb, 0, 1,
	    "%s :  Skip Indicator",
	    a_bigbuf);
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

    other_decode_bitfield_value(a_bigbuf, oct_1, DTAP_PD_MASK, 8);
    proto_tree_add_text(pd_tree,
	tvb, 0, 1,
	"%s :  Protocol Discriminator: %u",
	a_bigbuf,
	pd);

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
	"Message Type");

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
	    "", HFILL}},
	{ &hf_gsm_a_dlci_spare,
	    { "Spare", "bssap.dlci.spare",
	    FT_UINT8, BASE_HEX, NULL, 0x38,
	    "", HFILL}},
	{ &hf_gsm_a_dlci_sapi,
	    { "SAPI", "bssap.dlci.sapi",
	    FT_UINT8, BASE_HEX, VALS(bssap_sapi_values), 0x07,
	    "", HFILL}},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	24
    static gint *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSMAP_MSG +
			NUM_GSM_DTAP_MSG_MM + NUM_GSM_DTAP_MSG_RR + NUM_GSM_DTAP_MSG_CC +
			NUM_GSM_DTAP_MSG_GMM + NUM_GSM_DTAP_MSG_SMS +
			NUM_GSM_DTAP_MSG_SM + NUM_GSM_DTAP_MSG_SS + NUM_GSM_RP_MSG +
			NUM_GSM_BSSMAP_ELEM + NUM_GSM_DTAP_ELEM];

    memset((void *) ett, -1, sizeof(ett));

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

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_GSM_BSSMAP_MSG; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_bssmap_msg[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_MM; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_mm[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_RR; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_rr[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_CC; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_cc[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_GMM; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_gmm[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_SMS; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_sms[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_SM; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_sm[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_SS; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_dtap_msg_ss[i];
    }

    for (i=0; i < NUM_GSM_RP_MSG; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_rp_msg[i];
    }

    for (i=0; i < NUM_GSM_BSSMAP_ELEM; i++, last_offset++)
    {
	ett[last_offset] = &ett_gsm_bssmap_elem[i];
    }

    for (i=0; i < NUM_GSM_DTAP_ELEM; i++, last_offset++)
    {
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

    gsm_a_tap = register_tap("gsm_a");
}


void
proto_reg_handoff_gsm_a(void)
{

    bssmap_handle = create_dissector_handle(dissect_bssmap, proto_a_bssmap);
    dtap_handle = create_dissector_handle(dissect_dtap, proto_a_dtap);
    rp_handle = create_dissector_handle(dissect_rp, proto_a_rp);

    dissector_add("bssap.pdu_type",  BSSAP_PDU_TYPE_BSSMAP, bssmap_handle);
    dissector_add("bssap.pdu_type",  BSSAP_PDU_TYPE_DTAP, dtap_handle);
    dissector_add("ranap.nas_pdu",  BSSAP_PDU_TYPE_DTAP, dtap_handle);

    data_handle = find_dissector("data");
}
